#include "core/dynamic_vm_analyzer.h"
#include "common/config.h"
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
                    m_report.totalProcessesCreated++;
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

        // Step 1: Start Host TCP Server
        emitLocal(EventType::Info, "Network", "Starting TCP Live Stream Receiver on port " + std::to_string(m_vmConfig.hostPort));
        if (!m_tcpServer->Start([this](const TraceEvent& evt) { HandleIncomingEvent(evt); }, m_options)) {
            emitLocal(EventType::Error, "Network", "Failed to start Host TCP Server on port " + std::to_string(m_vmConfig.hostPort));
            return false;
        }

        // Step 2: Stage target binary into guest_share directory
        const auto& qemuCfg = m_qemu->GetConfig();
        std::string shareDir = qemuCfg.guestShareDir;
        try {
            std::filesystem::create_directories(shareDir);
            std::string destPath = shareDir + "/target_sample.exe";
            std::filesystem::copy_file(executablePath, destPath, std::filesystem::copy_options::overwrite_existing);
            emitLocal(EventType::Info, "Sandbox", "Staged target binary into " + destPath);
        } catch (const std::exception& ex) {
            emitLocal(EventType::Error, "Sandbox", std::string("Failed to copy binary to guest_share: ") + ex.what());
        }

        // Step 3: Launch QEMU with non-destructive in-memory -snapshot mode
        emitLocal(EventType::Info, "QEMU", "Launching isolated QEMU sandbox with in-memory -snapshot protection...");
        if (!m_qemu->StartQemu(m_vmConfig.headlessMode, m_vmConfig.hostPort)) {
            emitLocal(EventType::Error, "QEMU", "Failed to start QEMU hypervisor process.");
            m_tcpServer->Stop();
            return false;
        }

        emitLocal(EventType::ExecutionStarted, "QEMU", "QEMU Guest running. Awaiting live telemetry connection from GuestAgent...");

        // Step 4: Wait for guest execution completion or timeout
        auto startTime = std::chrono::steady_clock::now();
        uint32_t timeoutSec = m_options.executionTimeoutSeconds;

        while (m_isRunning) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

            if (!m_qemu->IsRunning()) {
                emitLocal(EventType::Info, "QEMU", "QEMU instance exited.");
                break;
            }

            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - startTime).count();

            if (elapsed >= timeoutSec) {
                emitLocal(EventType::Info, "QemuHost", "Execution timeout reached (" + std::to_string(timeoutSec) + "s). Stopping session.");
                break;
            }
        }

        // Step 5: Terminate QEMU (Automatically purges in-memory delta, base disk remains untouched)
        emitLocal(EventType::Info, "QEMU", "Stopping QEMU and discarding all sandbox disk modifications...");
        m_qemu->StopQemu();
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
