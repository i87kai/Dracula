#include "host/console_ui.h"
#include <iostream>
#include <iomanip>
#include <ctime>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace Sandbox {

    void ConsoleUI::InitializeConsole() {
        std::cout << std::unitbuf;
        std::cerr << std::unitbuf;
#ifdef _WIN32
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD dwMode = 0;
            if (GetConsoleMode(hOut, &dwMode)) {
                dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                SetConsoleMode(hOut, dwMode);
            }
        }
#endif
    }

    void ConsoleUI::PrintBanner() {
        std::cout << COLOR_BRIGHT_CYAN << COLOR_BOLD;
        std::cout << R"(
  =============================================================
     SANDBOX ORCHESTRATOR & DYNAMIC PROGRAM EXECUTION TRACER   
  =============================================================
  [+] QEMU Native Hypervisor Engine & Automated Snapshot State 
  [+] High-Speed TCP Live Event Streamer & Telemetry Pipeline
  [+] Native Unicorn Engine 2 CPU Emulation & Instruction Tracing
  =============================================================
)" << COLOR_RESET << std::endl;
    }

    void ConsoleUI::RenderEvent(const TraceEvent& event) {
        // Format timestamp
        std::time_t timeSec = static_cast<std::time_t>(event.timestampMs / 1000);
        std::tm localTm;
#ifdef _WIN32
        localtime_s(&localTm, &timeSec);
#else
        localtime_r(&timeSec, &localTm);
#endif
        char timeStr[16];
        std::strftime(timeStr, sizeof(timeStr), "%H:%M:%S", &localTm);

        std::string badgeColor = COLOR_WHITE;
        std::string badgeText = "EVENT";

        switch (event.type) {
            case EventType::Info:
                badgeColor = COLOR_CYAN;
                badgeText = "INFO";
                break;
            case EventType::Stdout:
                badgeColor = COLOR_GREEN;
                badgeText = "STDOUT";
                break;
            case EventType::Stderr:
                badgeColor = COLOR_YELLOW;
                badgeText = "STDERR";
                break;
            case EventType::ProcessCreated:
                badgeColor = COLOR_MAGENTA;
                badgeText = "PROCESS";
                break;
            case EventType::ProcessTerminated:
                badgeColor = COLOR_MAGENTA;
                badgeText = "TERMINATE";
                break;
            case EventType::FileCreated:
            case EventType::FileModified:
            case EventType::FileDeleted:
                badgeColor = COLOR_BLUE;
                badgeText = "FILE";
                break;
            case EventType::RegistryKeyCreated:
            case EventType::RegistryValueSet:
                badgeColor = COLOR_BRIGHT_BLUE;
                badgeText = "REGISTRY";
                break;
            case EventType::NetworkConnect:
                badgeColor = COLOR_BRIGHT_CYAN;
                badgeText = "NETWORK";
                break;
            case EventType::ExecutionStarted:
                badgeColor = COLOR_GREEN;
                badgeText = "START";
                break;
            case EventType::ExecutionFinished:
                badgeColor = COLOR_GREEN;
                badgeText = "FINISH";
                break;
            case EventType::Error:
                badgeColor = COLOR_RED;
                badgeText = "ERROR";
                break;
        }

        std::cout << COLOR_WHITE << "[" << timeStr << "] "
                  << badgeColor << COLOR_BOLD << "[" << std::setw(9) << std::left << badgeText << "]" << COLOR_RESET << " "
                  << COLOR_BOLD << "[" << event.category << "]" << COLOR_RESET << " "
                  << event.message;

        if (!event.details.empty()) {
            std::cout << " " << COLOR_WHITE << "(" << event.details << ")" << COLOR_RESET;
        }
        std::cout << std::endl;
    }

    void ConsoleUI::PromptUserConfiguration(TraceOptions& options, VMConfig& vmConfig, std::string& targetExe) {
        std::cout << COLOR_BOLD << COLOR_BRIGHT_BLUE << ">> CONFIGURATION SETUP <<" << COLOR_RESET << "\n\n";

        std::cout << "Enter Target Executable Path (or drag & drop): ";
        std::getline(std::cin, targetExe);

        // Strip quotes if user dragged and dropped
        if (!targetExe.empty() && targetExe.front() == '"' && targetExe.back() == '"') {
            targetExe = targetExe.substr(1, targetExe.length() - 2);
        }

        std::cout << "Enter VirtualBox VM Name [" << vmConfig.vmName << "]: ";
        std::string input;
        std::getline(std::cin, input);
        if (!input.empty()) vmConfig.vmName = input;

        std::cout << "Enter Clean Snapshot Name [" << vmConfig.snapshotName << "]: ";
        std::getline(std::cin, input);
        if (!input.empty()) vmConfig.snapshotName = input;

        std::cout << "\n" << COLOR_BOLD << ">> SELECT TRACE FILTERS (Y/n):" << COLOR_RESET << "\n";

        auto askBool = [](const std::string& label, bool defaultVal) -> bool {
            std::cout << label << " [" << (defaultVal ? "Y/n" : "y/N") << "]: ";
            std::string line;
            std::getline(std::cin, line);
            if (line.empty()) return defaultVal;
            return (line[0] == 'y' || line[0] == 'Y' || line[0] == '1');
        };

        options.monitorConsoleOutput = askBool(" - Monitor Console Output (stdout/stderr)", true);
        options.monitorProcesses     = askBool(" - Monitor Child Processes (Process tree)", true);
        options.monitorFiles         = askBool(" - Monitor File System activity", true);
        options.monitorRegistry      = askBool(" - Monitor Windows Registry keys", true);
        options.monitorNetwork       = askBool(" - Monitor Outbound Network Sockets", true);

        std::cout << "\nEnter Execution Timeout (seconds) [" << options.executionTimeoutSeconds << "]: ";
        std::getline(std::cin, input);
        if (!input.empty()) {
            try {
                options.executionTimeoutSeconds = static_cast<uint32_t>(std::stoul(input));
            } catch (...) {}
        }

        std::cout << "\n" << COLOR_GREEN << "[+] Configuration ready. Initializing analysis session..." << COLOR_RESET << "\n\n";
    }

} // namespace Sandbox
