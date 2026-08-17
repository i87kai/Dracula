#include "core/dynamic_vm_analyzer.h"
#include "common/config.h"
#include "common/paths.h"
#include "host/guest_session_handoff.h"
#include <iostream>
#include <filesystem>
#include <thread>
#include <chrono>

namespace Sandbox {

    DynamicVMAnalyzer::DynamicVMAnalyzer() {
        m_report.analysisType = "Dynamic QEMU Hardware Sandbox (Automated Snapshot Isolation)";
    }

    DynamicVMAnalyzer::~DynamicVMAnalyzer() {
        StopAnalysis();
    }

    bool DynamicVMAnalyzer::Initialize(const VMConfig& vmConfig, const TraceOptions& options) {
        std::lock_guard<std::mutex> lock(m_reportMutex);
        m_vmConfig = vmConfig;
        m_options = options;
        m_report.events.clear();
        m_report.totalProcessesCreated = 0;
        m_report.totalFilesModified = 0;
        m_report.totalNetworkConnections = 0;
        m_report.totalRegistryChanges = 0;

        const auto& qemuCfg = ConfigManager::Instance().GetQemuConfig();
        m_qemu = std::make_unique<QemuManager>(qemuCfg);
        m_tcpServer = std::make_unique<LiveTcpServer>(m_vmConfig.hostListenIp, m_vmConfig.hostPort);

        // Port policy comes from configuration. The default prefers the
        // configured port, so a guest image provisioned with a fixed port keeps
        // working, and only moves elsewhere when that port is genuinely taken.
        PortRequest request;
        request.listenIp = m_vmConfig.hostListenIp;
        request.preferredPort = m_vmConfig.hostPort;
        request.rangeBegin = m_vmConfig.portRangeBegin;
        request.rangeEnd = m_vmConfig.portRangeEnd;
        request.strategy = m_vmConfig.portStrategy;
        m_tcpServer->SetPortRequest(request);

        return true;
    }

    void DynamicVMAnalyzer::SetEventCallback(EventCallback callback) {
        std::lock_guard<std::mutex> lock(m_reportMutex);
        m_callback = std::move(callback);
    }

    void DynamicVMAnalyzer::HandleIncomingEvent(const TraceEvent& event) {
        EventCallback cbCopy;
        {
            std::lock_guard<std::mutex> lock(m_reportMutex);
            m_report.events.push_back(event);

            switch (event.type) {
                case EventType::ProcessCreated:
                    if (event.role != ProcessRole::Target && event.message.find("Target Process") == std::string::npos) {
                        m_report.totalProcessesCreated++;
                    }
                    break;
                case EventType::FileCreated:
                case EventType::FileModified:
                case EventType::FileDeleted:
                    m_report.totalFilesModified++;
                    break;
                case EventType::NetworkConnect:
                    m_report.totalNetworkConnections++;
                    break;
                case EventType::RegistryKeyCreated:
                case EventType::RegistryValueSet:
                    m_report.totalRegistryChanges++;
                    break;
                case EventType::ProcessTerminated:
                case EventType::ExecutionFinished:
                    m_isRunning = false;
                    break;
                default:
                    break;
            }

            cbCopy = m_callback;
        }

        if (cbCopy) {
            cbCopy(event);
        }
    }

    bool DynamicVMAnalyzer::RunAnalysis(const std::string& executablePath) {
        if (!m_qemu || !m_tcpServer) {
            std::cerr << "[DynamicVMAnalyzer] QEMU Analyzer not initialized." << std::endl;
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(m_reportMutex);
            m_isRunning = true;
            m_report.targetExecutable = executablePath;
            m_report.startTime = std::chrono::system_clock::now();
        }

        auto emitLocal = [this](EventType type, const std::string& cat, const std::string& msg) {
            TraceEvent evt;
            evt.type = type;
            evt.timestampMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
            evt.category = cat;
            evt.message = msg;
            HandleIncomingEvent(evt);
        };

        emitLocal(EventType::Info, "QemuHost", "Starting dynamic analysis session for: " + executablePath);

        // The ordering below is load bearing.
        //
        //   1. Bind the host listener first, because only then is the actual
        //      port known -- it may not be the configured one.
        //   2. Stage the sample AND write the session handoff into the share,
        //      because QEMU snapshots that directory into a read-only FAT drive
        //      at launch. Anything written afterwards the guest cannot see.
        //   3. Only then launch QEMU.

        // Step 1: bind the telemetry listener and learn the real port.
        if (!m_tcpServer->Start([this](const TraceEvent& evt) { HandleIncomingEvent(evt); }, m_options)) {
            emitLocal(EventType::Error, "Network",
                      "Failed to start the host telemetry listener: " + m_tcpServer->LastError());
            m_isRunning = false;
            return false;
        }

        const uint16_t boundPort = m_tcpServer->ActualPort();
        if (m_tcpServer->UsedPreferredPort()) {
            emitLocal(EventType::Info, "Network",
                      "Host telemetry listener bound on the configured port " + std::to_string(boundPort));
        } else {
            emitLocal(EventType::Info, "Network",
                      "Configured port " + std::to_string(m_vmConfig.hostPort) +
                      " was unavailable; the host telemetry listener bound port " +
                      std::to_string(boundPort) + " instead and the guest will be told to use it");
        }

        // Everything below must release the listener on the way out.
        struct ServerGuard {
            LiveTcpServer* server;
            bool armed = true;
            ~ServerGuard() { if (armed && server) server->Stop(); }
        } serverGuard{m_tcpServer.get()};

        // Step 2: stage the sample and the session handoff into a per-session temporary directory.
        const auto& qemuCfg = m_qemu->GetConfig();
        std::string baseShareDir = qemuCfg.guestShareDir;
        if (baseShareDir.empty() || !std::filesystem::exists(baseShareDir)) {
            std::string resolved = Dracula::Paths::ResolveResource("guest_share");
            if (!resolved.empty()) baseShareDir = resolved;
        }

        GuestSessionHandoff handoff;
        handoff.hostIp = "10.0.2.2";       // SLIRP gateway alias for the host
        handoff.hostPort = boundPort;
        handoff.timeoutSeconds = m_options.executionTimeoutSeconds;
        handoff.sessionId = std::to_string(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());

        std::error_code tempEc;
        std::filesystem::path tempRoot = std::filesystem::temp_directory_path(tempEc) / "Dracula";
        std::filesystem::path stagingShareDir = tempRoot / ("session_" + handoff.sessionId);

        struct StagingGuard {
            std::filesystem::path dir;
            ~StagingGuard() {
                if (!dir.empty()) {
                    std::error_code ec;
                    std::filesystem::remove_all(dir, ec);
                }
            }
        } stagingGuard{stagingShareDir};

        try {
            std::filesystem::create_directories(stagingShareDir, tempEc);

            // Copy base guest share files if available
            if (!baseShareDir.empty() && std::filesystem::exists(baseShareDir, tempEc)) {
                for (const auto& entry : std::filesystem::directory_iterator(baseShareDir, tempEc)) {
                    if (tempEc) break;
                    const auto name = entry.path().filename().string();
                    if (name == "$recycle.bin" || name == "$RECYCLE.BIN") continue;
                    if (name == "target_sample.exe" || name == "dracula_session.ini") continue;
                    std::filesystem::copy(entry.path(), stagingShareDir / name,
                                          std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing,
                                          tempEc);
                }
            }

            const std::string destPath = (stagingShareDir / "target_sample.exe").string();
            std::filesystem::copy_file(executablePath, destPath,
                                       std::filesystem::copy_options::overwrite_existing, tempEc);
            emitLocal(EventType::Info, "Sandbox", "Staged target binary into temporary guest share: " + destPath);
        } catch (const std::exception& ex) {
            emitLocal(EventType::Error, "Sandbox",
                      std::string("Failed to stage binary for QEMU: ") + ex.what());
        }

        std::string handoffError;
        if (WriteGuestSessionHandoff(stagingShareDir.string(), handoff, handoffError)) {
            emitLocal(EventType::Info, "Sandbox",
                      "Wrote guest session handoff (host " + handoff.hostIp + ":" +
                      std::to_string(handoff.hostPort) + ") into the temporary staging share");
        } else {
            emitLocal(EventType::Error, "Sandbox",
                      "Could not write the guest session handoff: " + handoffError +
                      ". A guest provisioned with a fixed port will still connect.");
        }

        m_qemu->SetGuestShareDir(stagingShareDir.string());

        // Step 3: launch QEMU. No inbound port forwarding is requested, so
        // nothing here can contend with the listener bound in step 1.
        emitLocal(EventType::Info, "QEMU",
                  "Launching isolated QEMU sandbox with in-memory -snapshot protection...");
        if (!m_qemu->StartQemu(m_vmConfig.headlessMode)) {
            emitLocal(EventType::Error, "QEMU", "Failed to start QEMU: " + m_qemu->LastError());
            m_isRunning = false;
            return false;   // serverGuard releases the listener
        }

        emitLocal(EventType::ExecutionStarted, "QEMU",
                  "QEMU guest running. Awaiting the GuestAgent connection on port " +
                  std::to_string(boundPort) + "...");

        // Step 4: wait for the guest.
        //
        // Two independent budgets, because booting and running are different
        // things. The connect budget covers boot and auto-login and runs from
        // launch; the execution budget covers the sample itself and only starts
        // once the agent is actually on the line. Sharing one budget would mean
        // a 60 second execution limit silently capping a four minute boot.
        const auto launchTime = std::chrono::steady_clock::now();
        auto connectedTime = std::chrono::steady_clock::time_point{};
        const uint32_t executionTimeoutSec = m_options.executionTimeoutSeconds;
        const uint32_t connectTimeoutSec = m_vmConfig.guestConnectTimeoutSeconds;
        bool qemuDied = false;

        while (m_isRunning) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

            if (!m_qemu->IsRunning()) {
                emitLocal(EventType::Error, "QEMU",
                          "QEMU exited unexpectedly (exit code " + std::to_string(m_qemu->ExitCode()) + ").");
                qemuDied = true;
                break;
            }

            const bool connected = m_tcpServer->EverConnected();
            if (connected && connectedTime == std::chrono::steady_clock::time_point{}) {
                connectedTime = std::chrono::steady_clock::now();
                const auto bootSeconds = std::chrono::duration_cast<std::chrono::seconds>(
                    connectedTime - launchTime).count();
                emitLocal(EventType::Info, "Network",
                          "GuestAgent connected after " + std::to_string(bootSeconds) +
                          "s. Live telemetry is flowing.");
            }

            if (!connected) {
                const auto waiting = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - launchTime).count();
                if (connectTimeoutSec > 0 && static_cast<uint32_t>(waiting) >= connectTimeoutSec) {
                    std::string reason =
                        "No GuestAgent connection within " + std::to_string(connectTimeoutSec) +
                        "s. The host listener on port " + std::to_string(boundPort) +
                        " stayed available for the whole wait.";

                    if (!m_tcpServer->UsedPreferredPort()) {
                        // The likely cause is knowable, so say it rather than
                        // leaving the analyst to guess.
                        reason += " The listener had to move off the configured port " +
                                  std::to_string(m_vmConfig.hostPort) +
                                  " because something else holds it. A guest provisioned before "
                                  "the session handoff existed dials the configured port directly "
                                  "and cannot follow the move: either free port " +
                                  std::to_string(m_vmConfig.hostPort) +
                                  " on the host, or re-run setup_lab.bat inside the guest to "
                                  "install a startup script that reads " +
                                  std::string(kGuestSessionFileName) + " from the shared drive.";
                    } else {
                        reason += " The guest may still be booting, or its startup script may not "
                                  "be launching GuestAgent.";
                    }
                    emitLocal(EventType::Error, "Network", reason);
                    break;
                }
                continue;   // still booting; the execution budget has not started
            }

            const auto running = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - connectedTime).count();
            if (executionTimeoutSec > 0 && static_cast<uint32_t>(running) >= executionTimeoutSec) {
                emitLocal(EventType::Info, "QemuHost",
                          "Execution timeout reached (" + std::to_string(executionTimeoutSec) +
                          "s after the agent connected). Stopping session.");
                break;
            }
        }

        // Step 5: terminate QEMU. The in-memory -snapshot delta is discarded and
        // the base disk image is left untouched, so the guest rolls back.
        if (!qemuDied) {
            emitLocal(EventType::Info, "QEMU",
                      "Stopping QEMU and discarding all sandbox disk modifications...");
        }
        m_qemu->StopQemu();

        emitLocal(EventType::Info, "Network",
                  "Telemetry summary: " +
                  std::string(m_tcpServer->EverConnected() ? "agent connected" : "agent never connected") +
                  ", " + std::to_string(m_tcpServer->BytesReceived()) + " byte(s) on the wire, " +
                  std::to_string(m_tcpServer->EventsReceived()) + " event(s) decoded, " +
                  std::to_string(m_tcpServer->FramingErrors()) + " framing resync(s).");

        serverGuard.armed = false;
        m_tcpServer->Stop();

        {
            std::lock_guard<std::mutex> lock(m_reportMutex);
            m_report.endTime = std::chrono::system_clock::now();
            m_isRunning = false;
        }

        emitLocal(EventType::ExecutionFinished, "QemuHost", "Sandbox session completed. System reverted to clean state in 0 seconds.");
        return true;
    }

    void DynamicVMAnalyzer::StopAnalysis() {
        m_isRunning = false;
        if (m_qemu) {
            m_qemu->StopQemu();
        }
        if (m_tcpServer) {
            m_tcpServer->Stop();
        }
    }

    AnalysisReport DynamicVMAnalyzer::GetReport() const {
        std::lock_guard<std::mutex> lock(m_reportMutex);
        return m_report;
    }

} // namespace Sandbox
