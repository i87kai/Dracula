#include "guest/process_spawner.h"
#include "guest/system_tracer.h"
#include "guest/tcp_emitter.h"
#include "common/types.h"
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
    std::string hostIp = "10.0.2.2"; // Default VirtualBox NAT Host gateway IP
    uint16_t hostPort = 8899;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--host-ip" && i + 1 < argc) {
            hostIp = argv[++i];
        } else if (arg == "--host-port" && i + 1 < argc) {
            hostPort = static_cast<uint16_t>(std::stoi(argv[++i]));
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

    emitTrace(Sandbox::EventType::Info, "GuestAgent", "Guest Agent started execution of: " + targetExe);

    Sandbox::Guest::ProcessSpawner spawner;

    auto outCallback = [&](bool isStderr, const std::string& line) {
        if (!options.monitorConsoleOutput) return;
        emitTrace(isStderr ? Sandbox::EventType::Stderr : Sandbox::EventType::Stdout,
                  isStderr ? "Stderr" : "Stdout",
                  line);
    };

    auto exitCallback = [&](uint32_t exitCode) {
        emitTrace(Sandbox::EventType::ProcessTerminated, "Process",
                  "Target Process Exited with Code: " + std::to_string(exitCode));
    };

    if (!spawner.Launch(targetExe, "", outCallback, exitCallback)) {
        emitTrace(Sandbox::EventType::Error, "GuestAgent", "Failed to launch target executable: " + targetExe);
        return 1;
    }

    uint32_t pid = spawner.GetProcessId();
    emitTrace(Sandbox::EventType::ProcessCreated, "Process", "Target Process Spawned (PID: " + std::to_string(pid) + ")");

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
