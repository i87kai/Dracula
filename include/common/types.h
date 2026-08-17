#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <cstdint>

namespace Sandbox {

    // Trace options configurable by the user before running the target binary
    struct TraceOptions {
        bool monitorConsoleOutput = true;      // Capture stdout and stderr streams
        bool monitorProcesses     = true;      // Track process creation and child processes
        bool monitorFiles         = true;      // Track file creation, modifications, and deletions
        bool monitorRegistry      = true;      // Track Windows registry modifications
        bool monitorNetwork       = true;      // Track network sockets and outbound connections
        uint32_t executionTimeoutSeconds = 60; // Max execution timeout before stopping
    };

    // VirtualBox environment and VM configuration
    struct VMConfig {
        std::string vmName         = "WinLab";         // VirtualBox VM Name
        std::string snapshotName   = "Clean_State";    // Clean snapshot name
        std::string guestUsername  = "user";           // Guest OS username
        std::string guestPassword  = "123456";         // Guest OS password
        std::string guestTargetDir = "C:\\Sandbox\\";  // Guest path to deploy and run the binary
        std::string hostListenIp   = "0.0.0.0";        // Host TCP listening IP
        uint16_t hostPort          = 8899;             // Host TCP listening port
        bool headlessMode          = false;            // Run VM in headless mode
    };

    // Categorized event types emitted during runtime tracing
    enum class EventType : uint32_t {
        Info = 0,
        Stdout,
        Stderr,
        ProcessCreated,
        ProcessTerminated,
        FileCreated,
        FileModified,
        FileDeleted,
        RegistryKeyCreated,
        RegistryValueSet,
        NetworkConnect,
        ExecutionStarted,
        ExecutionFinished,
        Error
    };

    // Data structure representing a single trace event
    struct TraceEvent {
        EventType type;
        uint64_t timestampMs;
        std::string category;
        std::string message;
        std::string details;
    };

    // Comprehensive session report
    struct AnalysisReport {
        std::string targetExecutable;
        std::string analysisType;
        std::chrono::system_clock::time_point startTime;
        std::chrono::system_clock::time_point endTime;
        uint32_t exitCode = 0;
        std::vector<TraceEvent> events;
        size_t totalProcessesCreated = 0;
        size_t totalFilesModified = 0;
        size_t totalNetworkConnections = 0;
        size_t totalRegistryChanges = 0;
    };

    // Result of emulating an isolated in-memory instruction buffer via UnicornAnalyzer::EmulateBuffer
    struct FunctionEmulationResult {
        bool success = false;
        std::string errorMessage;          // Populated when success == false
        uint64_t stopAddress = 0;          // RIP/EIP at emulation stop
        uint64_t instructionsExecuted = 0;
        std::unordered_map<std::string, uint64_t> registers; // Named output register values (e.g. "RAX")

        // Exact termination reason from uc_emu_start, retained even when success == true.
        // Stored as uint32_t (not uc_err) so this header stays free of Unicorn includes
        // for the guest-agent and GUI translation units that do not link Unicorn.
        // 0 == UC_ERR_OK. Non-zero with success == true means a benign truncated stop
        // (e.g. UC_ERR_FETCH_UNMAPPED when a routine RETs into unmapped memory).
        uint32_t rawErrorCode = 0;
        std::string errorName;             // uc_strerror() text for rawErrorCode

        // True only when emulation terminated with UC_ERR_OK, i.e. the routine ran to
        // its stop address without faulting. Use this (not success) to distinguish a
        // clean completion from a tolerated truncated stop.
        bool CompletedCleanly() const { return success && rawErrorCode == 0; }
    };

} // namespace Sandbox
