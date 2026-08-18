#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "guest/process_spawner.h"
#include "guest/system_tracer.h"
#include "guest/tcp_emitter.h"
#include "common/types.h"
#include "host/guest_session_handoff.h"
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: GuestAgent <target_executable.exe> [--host-ip <IP>] [--host-port <Port>]" << std::endl;
        return 1;
    }

    std::string targetExe = argv[1];
    std::string hostIp = "10.0.2.2"; // QEMU SLIRP gateway alias for the host
    uint16_t hostPort = 8899;
    bool portFromArgs = false;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--host-ip" && i + 1 < argc) {
            hostIp = argv[++i];
        } else if (arg == "--host-port" && i + 1 < argc) {
            try {
                const int parsed = std::stoi(argv[++i]);
                if (parsed > 0 && parsed <= 65535) {
                    hostPort = static_cast<uint16_t>(parsed);
                    portFromArgs = true;
                }
            } catch (...) {
                std::cerr << "[GuestAgent] Ignoring unparseable --host-port value." << std::endl;
            }
        }
    }

    // The host picks its port at runtime and may not get the configured one, so
    // it leaves a handoff file on the shared drive. An explicit --host-port
    // still wins, which keeps a guest provisioned with a fixed port working.
    std::string handoffNonce;
    if (!portFromArgs) {
        const char* candidateDrives[] = { "E:\\", "D:\\", "F:\\", "G:\\", "." };
        for (const char* drive : candidateDrives) {
            const std::string path = std::string(drive) + Sandbox::kGuestSessionFileName;
            Sandbox::GuestSessionHandoff handoff;
            if (Sandbox::ReadGuestSessionHandoff(path, handoff)) {
                hostIp = handoff.hostIp;
                hostPort = handoff.hostPort;
                handoffNonce = handoff.sessionNonce;
                std::cout << "[GuestAgent] Read session handoff from " << path
                          << " (host " << hostIp << ":" << hostPort << ")" << std::endl;
                break;
            }
        }
    }

    std::cout << "[GuestAgent] Target: " << targetExe << std::endl;
    std::cout << "[GuestAgent] Connecting to Host Controller at " << hostIp << ":" << hostPort << "..." << std::endl;

    Sandbox::Guest::TcpEmitter emitter(hostIp, hostPort);
    Sandbox::TraceOptions options;

    if (!emitter.Connect(options)) {
        std::cerr << "[GuestAgent] Failed to connect to Host Controller at " << hostIp << ":" << hostPort << std::endl;
        // Even if connection fails, we continue local logging
    } else {
        std::cout << "[GuestAgent] Connected to Host Controller. Received trace configuration." << std::endl;
    }

    auto emitTrace = [&](Sandbox::EventType type, const std::string& category, const std::string& msg, const std::string& details = "") {
        Sandbox::TraceEvent evt;
        evt.type = type;
        evt.timestampMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        evt.category = category;
        evt.message = msg;
        evt.details = details;

        emitter.SendEvent(evt);
    };

    if (!handoffNonce.empty()) {
        emitTrace(Sandbox::EventType::Info, "Handshake", "Session Nonce Authentication", "Nonce:" + handoffNonce);
    }

    emitTrace(Sandbox::EventType::Info, "GuestAgent", "Guest Agent started execution of: " + targetExe);

    uint32_t agentPid = 0;
#ifdef _WIN32
    agentPid = static_cast<uint32_t>(GetCurrentProcessId());
#endif

    Sandbox::Guest::ProcessSpawner spawner;

    auto outCallback = [&](bool isStderr, const std::string& line) {
        if (!options.monitorConsoleOutput) return;
        emitTrace(isStderr ? Sandbox::EventType::Stderr : Sandbox::EventType::Stdout,
                  isStderr ? "Stderr" : "Stdout",
                  line);
    };

    auto exitCallback = [&](uint32_t exitCode) {
        Sandbox::TraceEvent evt;
        evt.type = Sandbox::EventType::ProcessTerminated;
        evt.timestampMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        evt.pid = spawner.GetProcessId();
        evt.parentPid = agentPid;
        evt.role = Sandbox::ProcessRole::Target;
        evt.processName = targetExe;
        evt.category = "Process";
        evt.message = "Target Process Exited with Code: " + std::to_string(exitCode);
        evt.details = "Exit Code: " + std::to_string(exitCode);
        emitter.SendEvent(evt);
    };

    if (!spawner.Launch(targetExe, "", outCallback, exitCallback)) {
        emitTrace(Sandbox::EventType::Error, "GuestAgent", "Failed to launch target executable: " + targetExe);
        return 1;
    }

    uint32_t pid = spawner.GetProcessId();
    {
        Sandbox::TraceEvent evt;
        evt.type = Sandbox::EventType::ProcessCreated;
        evt.timestampMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        evt.pid = pid;
        evt.parentPid = agentPid;
        evt.role = Sandbox::ProcessRole::Target;
        evt.processName = targetExe;
        evt.commandLine = targetExe;
        evt.category = "Process";
        evt.message = "Target Process Started: " + targetExe + " (PID: " + std::to_string(pid) + ")";
        evt.details = "Parent PID: " + std::to_string(agentPid);
        emitter.SendEvent(evt);
    }

    // Start background system tracer for child processes, files, and network
    Sandbox::Guest::SystemTracer tracer(options, pid);
    tracer.Start([&](const Sandbox::TraceEvent& evt) {
        emitter.SendEvent(evt);
    });

    // Wait while target process is running
    while (spawner.IsRunning()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Give remaining events time to flush
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    tracer.Stop();

    emitTrace(Sandbox::EventType::ExecutionFinished, "GuestAgent", "Target execution completed.");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    emitter.Disconnect();
    std::cout << "[GuestAgent] Finished session successfully." << std::endl;
    return 0;
}
