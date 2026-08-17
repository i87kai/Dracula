// ============================================================================
//  main.cpp  –  HostController.exe  –  All-in-One Sandbox & Injector
//
//  Interactive numbered menu:
//    [1] QEMU Native Hardware Sandbox
//    [2] Unicorn CPU Emulation  (analyze an EXE file)
//    [3] Attach to Process & Resolve Offsets  (read-only, live memory)
//    [4] DLL Injection & Live Analysis        (inject + Named Pipe results)
//    [5] Custom AOB Pattern Scan              (manual hex pattern)
//    [0] Exit
// ============================================================================

#include "common/types.h"
#include "common/config.h"
#include "core/dynamic_vm_analyzer.h"
#include "core/unicorn_analyzer.h"
#include "host/console_ui.h"
#include "host/report_writer.h"
#include "host/process_inspector.h"

#include <iostream>
#include <iomanip>
#include <memory>
#include <filesystem>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <thread>
#include <atomic>
#include <vector>
#include <string>

// ============================================================================
//  Helper: pretty separator lines
// ============================================================================
namespace {

using namespace Sandbox;

static void PrintSep(const std::string& color = ConsoleUI::COLOR_WHITE) {
    std::cout << color
              << "  ──────────────────────────────────────────────────────────\n"
              << ConsoleUI::COLOR_RESET;
}

static void PrintHeader(const std::string& title) {
    std::cout << "\n" << ConsoleUI::COLOR_BOLD << ConsoleUI::COLOR_BRIGHT_CYAN;
    std::cout << "  ╔══════════════════════════════════════════════════════════╗\n";
    std::cout << "  ║  " << std::left << std::setw(57) << title << "║\n";
    std::cout << "  ╚══════════════════════════════════════════════════════════╝\n";
    std::cout << ConsoleUI::COLOR_RESET;
}

// ============================================================================
//  Pick a process from the list by number
// ============================================================================
static uint32_t PickProcessInteractive() {
    auto procs = ProcessInspector::ListAllProcesses();
    if (procs.empty()) {
        std::cerr << ConsoleUI::COLOR_RED << "[-] No running processes found.\n"
                  << ConsoleUI::COLOR_RESET;
        return 0;
    }

    std::cout << "\n" << ConsoleUI::COLOR_GREEN
              << "[+] Running Processes (" << procs.size() << " total):\n"
              << ConsoleUI::COLOR_RESET;
    std::cout << ConsoleUI::COLOR_WHITE
              << "  #    PID        Process Name\n"
              << "  ─────────────────────────────────────────────────────────\n"
              << ConsoleUI::COLOR_RESET;

    for (size_t i = 0; i < procs.size(); ++i) {
        std::cout << ConsoleUI::COLOR_CYAN
                  << "  [" << std::setw(3) << std::right << (i + 1) << "] "
                  << ConsoleUI::COLOR_RESET
                  << std::left << std::setw(10) << procs[i].pid
                  << procs[i].exeName << "\n";
    }

    std::cout << "\n" << ConsoleUI::COLOR_BOLD
              << "  Enter process number [1-" << procs.size() << "], PID, or name: "
              << ConsoleUI::COLOR_RESET;

    std::string sel;
    std::getline(std::cin, sel);
    if (sel.empty()) return 0;

    // Try as list index
    bool isNum = !sel.empty() &&
                 std::all_of(sel.begin(), sel.end(), [](unsigned char c){ return std::isdigit(c); });
    if (isNum) {
        size_t idx = static_cast<size_t>(std::stoul(sel));
        // Is it a valid list index?
        if (idx >= 1 && idx <= procs.size()) {
            return procs[idx - 1].pid;
        }
        // Otherwise treat as raw PID
        return static_cast<uint32_t>(idx);
    }

    // Name lookup
    auto matches = ProcessInspector::FindProcessesByName(sel);
    if (matches.empty()) {
        std::cerr << ConsoleUI::COLOR_RED << "[-] No process named '" << sel << "'.\n"
                  << ConsoleUI::COLOR_RESET;
        return 0;
    }
    if (matches.size() == 1) return matches[0].pid;

    std::cout << ConsoleUI::COLOR_YELLOW << "[*] Multiple matches:\n" << ConsoleUI::COLOR_RESET;
    for (size_t i = 0; i < matches.size(); ++i) {
        std::cout << "  [" << (i + 1) << "] PID " << matches[i].pid
                  << "  (" << matches[i].exeName << ")\n";
    }
    std::cout << "  Select [1-" << matches.size() << "]: ";
    std::string idxStr; std::getline(std::cin, idxStr);
    size_t idx = 0;
    try { idx = static_cast<size_t>(std::stoul(idxStr)); } catch (...) {}
    if (idx < 1 || idx > matches.size()) return 0;
    return matches[idx - 1].pid;
}

// ============================================================================
//  [3] Attach & Resolve Offsets  (read-only)
// ============================================================================
static int RunProcessInspectionFlow(uint32_t targetPid = 0) {
    PrintHeader("Attach to Process  &  Resolve Offsets");

    uint32_t pid = targetPid;
    if (pid == 0) {
        std::cout << "\n  Enter target name, PID, or 'list' to list all processes: ";
        std::string selector;
        std::getline(std::cin, selector);
        if (selector.empty()) return 1;

        if (_stricmp(selector.c_str(), "list") == 0 ||
            _stricmp(selector.c_str(), "ls")   == 0 ||
            _stricmp(selector.c_str(), "ps")   == 0) {
            pid = PickProcessInteractive();
            if (!pid) return 1;
        } else {
            bool isNumeric = !selector.empty() &&
                             std::all_of(selector.begin(), selector.end(),
                                         [](unsigned char c){ return std::isdigit(c); });
            if (isNumeric) {
                pid = static_cast<uint32_t>(std::stoul(selector));
            } else {
                auto matches = ProcessInspector::FindProcessesByName(selector);
                if (matches.empty()) {
                    std::cerr << ConsoleUI::COLOR_RED << "[-] No process: " << selector
                              << ConsoleUI::COLOR_RESET << "\n";
                    return 1;
                }
                pid = matches[0].pid;
            }
        }
    }

    std::string err;
    void* handle = ProcessInspector::OpenReadOnly(pid, err);
    if (!handle) {
        std::cerr << ConsoleUI::COLOR_RED << "[-] " << err << ConsoleUI::COLOR_RESET << "\n";
        return 1;
    }

    std::cout << ConsoleUI::COLOR_GREEN << "[+] Attached (read-only) to PID " << pid
              << ConsoleUI::COLOR_RESET << "\n";

    auto modInfo = ProcessInspector::ResolveMainModule(handle, pid, err);
    if (!modInfo) {
        std::cerr << ConsoleUI::COLOR_RED << "[-] " << err << ConsoleUI::COLOR_RESET << "\n";
        ProcessInspector::Close(handle);
        return 1;
    }

    std::cout << ConsoleUI::COLOR_CYAN
              << "    Module : " << modInfo->modulePath << "\n"
              << "    Base   : 0x" << std::hex << std::uppercase << modInfo->baseAddress << "\n"
              << "    Size   : 0x" << modInfo->sizeOfImage << std::dec
              << ConsoleUI::COLOR_RESET << "\n";

    PrintSep();
    std::cout << "\n" << ConsoleUI::COLOR_BOLD << "  Inspector Sub-Menu:\n"
              << ConsoleUI::COLOR_RESET;
    std::cout << "    [1] Emulate Memory Window (Unicorn Engine)\n";
    std::cout << "    [2] Resolve Exported Symbols (PE Export Directory)\n";
    std::cout << "    [3] AOB Signature Scan (with wildcards)\n";
    std::cout << "    [4] List All Loaded DLLs / Modules\n";
    std::cout << "\n  Enter Choice [1]: ";

    std::string actionChoice;
    std::getline(std::cin, actionChoice);

    if (actionChoice == "4") {
        auto mods = ProcessInspector::ResolveAllModules(handle, pid, err);
        ProcessInspector::Close(handle);
        std::cout << ConsoleUI::COLOR_GREEN << "[+] " << mods.size()
                  << " loaded modules:\n" << ConsoleUI::COLOR_RESET;
        std::cout << std::left << std::setw(20) << "Base"
                  << std::setw(14) << "Size" << "Path\n";
        PrintSep();
        for (const auto& m : mods) {
            std::cout << "0x" << std::setw(18) << std::hex << std::uppercase << m.baseAddress
                      << "0x" << std::setw(12) << m.sizeOfImage
                      << std::dec << m.modulePath << "\n";
        }
        return 0;
    }

    if (actionChoice == "2") {
        auto exports = ProcessInspector::ResolveExportedSymbols(handle, modInfo->baseAddress, err);
        ProcessInspector::Close(handle);
        std::cout << ConsoleUI::COLOR_GREEN << "[+] " << exports.size()
                  << " exported symbols:\n" << ConsoleUI::COLOR_RESET;
        std::cout << std::left << std::setw(8) << "Ord"
                  << std::setw(18) << "RVA"
                  << std::setw(20) << "VA"
                  << "Name\n";
        PrintSep();
        for (const auto& sym : exports) {
            std::cout << std::left << std::setw(8) << sym.ordinal
                      << "0x" << std::setw(16) << std::hex << std::uppercase << sym.rva
                      << "0x" << std::setw(18) << sym.absoluteAddress
                      << std::dec << sym.name << "\n";
        }
        return 0;
    }

    if (actionChoice == "3") {
        std::cout << "\n  Enter Hex Pattern (e.g. 48 89 5C 24 ?? 48 89): ";
        std::string pat; std::getline(std::cin, pat);
        if (pat.empty()) { ProcessInspector::Close(handle); return 1; }
        auto hits = ProcessInspector::FindPattern(handle, modInfo->baseAddress,
                                                  static_cast<size_t>(modInfo->sizeOfImage),
                                                  pat, err);
        ProcessInspector::Close(handle);
        if (hits.empty()) {
            std::cout << ConsoleUI::COLOR_YELLOW << "[!] Pattern not found.\n"
                      << ConsoleUI::COLOR_RESET;
            return 0;
        }
        std::cout << ConsoleUI::COLOR_GREEN << "[+] " << hits.size() << " match(es):\n"
                  << ConsoleUI::COLOR_RESET;
        for (size_t i = 0; i < hits.size(); ++i) {
            uint64_t rva = hits[i] - modInfo->baseAddress;
            std::cout << "  [" << (i+1) << "] 0x" << std::hex << std::uppercase << hits[i]
                      << "  (Base + 0x" << rva << ")\n" << std::dec;
        }
        return 0;
    }

    // Default: option 1 – Unicorn emulation
    std::cout << "\n  Offset from module base (hex, e.g. 0x1000): ";
    std::string offStr; std::getline(std::cin, offStr);
    uint64_t offset = 0;
    try { offset = std::stoull(offStr, nullptr, 16); } catch (...) {}

    std::cout << "  Byte length to read (hex, e.g. 0x200): ";
    std::string lenStr; std::getline(std::cin, lenStr);
    uint64_t length = 0;
    try { length = std::stoull(lenStr, nullptr, 16); } catch (...) {}

    if (length == 0 || length > 0x100000ULL) {
        std::cerr << ConsoleUI::COLOR_RED << "[-] Invalid length.\n" << ConsoleUI::COLOR_RESET;
        ProcessInspector::Close(handle);
        return 1;
    }

    uint64_t targetVa = modInfo->baseAddress + offset;
    size_t got = 0;
    auto buf = ProcessInspector::ReadMemory(handle, targetVa, static_cast<size_t>(length), got, err);
    ProcessInspector::Close(handle);

    if (buf.empty()) {
        std::cerr << ConsoleUI::COLOR_RED << "[-] " << err << ConsoleUI::COLOR_RESET << "\n";
        return 1;
    }

    std::cout << ConsoleUI::COLOR_GREEN << "[+] Read 0x" << std::hex << got
              << " bytes from 0x" << std::uppercase << targetVa << std::dec
              << ConsoleUI::COLOR_RESET << "\n\n";

    UnicornAnalyzer analyzer;
    analyzer.SetEventCallback([](const TraceEvent& e){ ConsoleUI::RenderEvent(e); });

    std::cout << ConsoleUI::COLOR_BOLD << ConsoleUI::COLOR_BRIGHT_BLUE
              << "================== UNICORN EMULATION ==================\n"
              << ConsoleUI::COLOR_RESET << "\n";

    auto result = analyzer.EmulateBuffer(buf, targetVa);

    std::cout << "\n" << ConsoleUI::COLOR_BOLD << "--- Emulation Result ---\n"
              << ConsoleUI::COLOR_RESET
              << "  PID            : " << pid << "\n"
              << "  Range          : 0x" << std::hex << std::uppercase
              << targetVa << " – 0x" << (targetVa + got) << std::dec << "\n"
              << "  Success        : " << (result.success ? "YES" : "NO") << "\n"
              << "  Clean Stop     : " << (result.CompletedCleanly() ? "YES" : "NO") << "\n"
              << "  Termination    : " << result.errorName
              << " (" << result.rawErrorCode << ")\n"
              << "  Instructions   : " << result.instructionsExecuted << "\n"
              << "  Stop RIP       : 0x" << std::hex << std::uppercase
              << result.stopAddress << std::dec << "\n"
              << "  Registers:\n";
    for (const auto& [name, val] : result.registers) {
        std::cout << "    " << std::setw(6) << std::left << name
                  << " = 0x" << std::hex << std::uppercase << val << std::dec << "\n";
    }

    return result.success ? 0 : 1;
}

// ============================================================================
//  [4]  DLL Injection + Live Named Pipe Analysis
// ============================================================================
static int RunDLLInjectionFlow(uint32_t targetPid = 0) {
    PrintHeader("DLL Injection  &  Live Analysis via Named Pipe");

    std::cout << "\n" << ConsoleUI::COLOR_YELLOW
              << "  [!] This feature requires ADMINISTRATOR privileges.\n"
              << "      The injected DLL will scan for named offsets +\n"
              << "      run Unicorn emulation inside the target process.\n"
              << ConsoleUI::COLOR_RESET << "\n";

    // Pick process
    uint32_t pid = targetPid;
    if (pid == 0) {
        pid = PickProcessInteractive();
    }
    if (!pid) return 1;

    // Extract embedded DLL
    std::cout << "\n" << ConsoleUI::COLOR_CYAN
              << "[*] Extracting embedded InjectableDLL from EXE resources...\n"
              << ConsoleUI::COLOR_RESET;

    std::string dllPath, extractErr;
    if (!ProcessInspector::ExtractEmbeddedDLL(dllPath, extractErr)) {
        std::cerr << ConsoleUI::COLOR_RED << "[-] " << extractErr
                  << ConsoleUI::COLOR_RESET << "\n";
        return 1;
    }
    std::cout << ConsoleUI::COLOR_GREEN << "[+] DLL extracted to: " << dllPath
              << ConsoleUI::COLOR_RESET << "\n";

    // Start Named Pipe server BEFORE injection so the pipe exists
    // when the DLL's DllMain thread tries to connect.
    std::cout << "\n" << ConsoleUI::COLOR_CYAN
              << "[*] Creating Named Pipe server (Phase 1)...\n"
              << ConsoleUI::COLOR_RESET;

    void* pipeHandle = ProcessInspector::CreateInjectionPipe();
    if (!pipeHandle) {
        std::cerr << ConsoleUI::COLOR_RED
                  << "[-] Failed to create Named Pipe server.\n"
                  << ConsoleUI::COLOR_RESET;
        return 1;
    }
    std::cout << ConsoleUI::COLOR_GREEN
              << "[+] Pipe server ready. Injecting DLL...\n"
              << ConsoleUI::COLOR_RESET;

    std::atomic<bool> pipeDone{false};
    int foundOffsetCount   = 0;
    int unicornResultCount = 0;
    int moduleCount        = 0;

    // Start drain thread (Phase 2) – will block on ConnectNamedPipe until DLL connects
    std::thread pipeThread([&]() {
        ProcessInspector::DrainInjectionPipe(
            pipeHandle, 30000,

            // Status messages (progress log from DLL)
            [](const std::string& msg) {
                std::cout << ConsoleUI::COLOR_WHITE << "  [DLL] " << msg
                          << ConsoleUI::COLOR_RESET << "\n";
            },

            // Found Offsets – the most important result
            [&](const InjectMsg_FoundOffset& fo) {
                foundOffsetCount++;
                std::cout << "\n"
                          << ConsoleUI::COLOR_GREEN << ConsoleUI::COLOR_BOLD
                          << "  ┌─ FOUND OFFSET #" << foundOffsetCount << " ─────────────────────────────\n"
                          << ConsoleUI::COLOR_RESET
                          << ConsoleUI::COLOR_BRIGHT_CYAN
                          << "  │  Name       : " << ConsoleUI::COLOR_BOLD << fo.offsetName << "\n"
                          << ConsoleUI::COLOR_RESET
                          << "  │  Module     : " << fo.moduleName << "\n"
                          << "  │  Abs Addr   : 0x" << std::hex << std::uppercase
                                                     << fo.absoluteAddress << std::dec << "\n"
                          << "  │  RVA        : 0x" << std::hex << fo.rva << std::dec << "\n"
                          << "  │  Module Base: 0x" << std::hex << fo.moduleBase << std::dec << "\n"
                          << "  │  Pattern    : " << fo.patternHex << "\n"
                          << "  │  Deref Chain: " << fo.derefChain << "\n"
                          << "  │  Writable   : " << (fo.isWritable   ? "YES" : "NO") << "\n"
                          << "  │  Executable : " << (fo.isExecutable ? "YES" : "NO") << "\n"
                          << ConsoleUI::COLOR_GREEN
                          << "  └─────────────────────────────────────────────────\n"
                          << ConsoleUI::COLOR_RESET;
            },

            // Register values (CPU state snapshot from Unicorn)
            [&](const InjectMsg_RegisterValues& rv) {
                std::cout << "\n" << ConsoleUI::COLOR_MAGENTA << ConsoleUI::COLOR_BOLD
                          << "  ┌─ CPU REGISTER STATE (Unicorn) ──────────────────\n"
                          << ConsoleUI::COLOR_RESET
                          << "  │  Emulated @ 0x" << std::hex << std::uppercase
                                                   << rv.emulationBaseAddr << std::dec
                          << "  (" << rv.instructionsExecuted << " instructions)\n"
                          << "  │  Termination: " << rv.terminationReason << "\n"
                          << "  │\n"
                          << "  │  RAX=0x" << std::hex << std::setw(16) << rv.rax
                          << "  RBX=0x" << std::setw(16) << rv.rbx << "\n"
                          << "  │  RCX=0x" << std::setw(16) << rv.rcx
                          << "  RDX=0x" << std::setw(16) << rv.rdx << "\n"
                          << "  │  RSI=0x" << std::setw(16) << rv.rsi
                          << "  RDI=0x" << std::setw(16) << rv.rdi << "\n"
                          << "  │  RSP=0x" << std::setw(16) << rv.rsp
                          << "  RBP=0x" << std::setw(16) << rv.rbp << "\n"
                          << "  │  RIP=0x" << std::setw(16) << rv.rip << std::dec << "\n"
                          << ConsoleUI::COLOR_MAGENTA
                          << "  └─────────────────────────────────────────────────\n"
                          << ConsoleUI::COLOR_RESET;
            },

            // Module list
            [&](const InjectMsg_ModuleEntry& me) {
                moduleCount++;
                std::string mainTag = me.isMainModule
                    ? (std::string(ConsoleUI::COLOR_YELLOW) + " [MAIN]" + ConsoleUI::COLOR_RESET)
                    : "";
                std::cout << ConsoleUI::COLOR_BLUE
                          << "  [MOD] 0x" << std::hex << std::uppercase << me.baseAddress
                          << std::dec << "  " << me.moduleName << mainTag << "\n"
                          << ConsoleUI::COLOR_RESET;
            },

            // Unicorn result summary
            [&](const InjectMsg_UnicornResult& ur) {
                unicornResultCount++;
                std::string statusColor = ur.success
                    ? ConsoleUI::COLOR_GREEN : ConsoleUI::COLOR_RED;
                std::cout << "\n" << statusColor << ConsoleUI::COLOR_BOLD
                          << "  ┌─ UNICORN EMULATION RESULT #" << unicornResultCount
                          << " ─────────────────\n"
                          << ConsoleUI::COLOR_RESET
                          << "  │  Address    : 0x" << std::hex << std::uppercase
                                                     << ur.emulatedAddress << std::dec << "\n"
                          << "  │  Size       : 0x" << std::hex << ur.emulatedSize
                                                     << std::dec << " bytes\n"
                          << "  │  Instructions: " << ur.instructionsExecuted << "\n"
                          << "  │  Stop RIP   : 0x" << std::hex << std::uppercase
                                                     << ur.stopRip << std::dec << "\n"
                          << "  │  Success    : " << (ur.success ? "YES" : "NO") << "\n"
                          << "  │  Clean Stop : " << (ur.completedCleanly ? "YES" : "NO") << "\n"
                          << "  │  Reason     : " << ur.terminationReason
                                                   << " (" << ur.rawErrorCode << ")\n"
                          << "  │  RAX=0x" << std::hex << ur.rax
                          << "  RCX=0x" << ur.rcx
                          << "  RDX=0x" << ur.rdx << std::dec << "\n"
                          << statusColor
                          << "  └─────────────────────────────────────────────────\n"
                          << ConsoleUI::COLOR_RESET;
            },

            // Pattern match
            [](const InjectMsg_PatternMatch& pm) {
                std::cout << ConsoleUI::COLOR_BRIGHT_CYAN
                          << "  [AOB] " << pm.patternDescription
                          << " @ 0x" << std::hex << std::uppercase << pm.matchAddress
                          << " (RVA 0x" << pm.rva << ")"
                          << std::dec << ConsoleUI::COLOR_RESET << "\n";
            },

            // Math result
            [](const InjectMsg_MathResult& mr) {
                std::cout << ConsoleUI::COLOR_BRIGHT_CYAN
                          << "  [MATH] " << mr.label << " = " << mr.valueInt
                          << " " << mr.unit
                          << "  (" << mr.formula << ")\n"
                          << ConsoleUI::COLOR_RESET;
            }
        ); // DrainInjectionPipe
        pipeDone = true;
    });

    // Inject the DLL – pipe already exists, so DLL can connect immediately
    std::cout << ConsoleUI::COLOR_CYAN
              << "[*] Injecting DLL into PID " << pid << "...\n"
              << ConsoleUI::COLOR_RESET;

    std::string injectErr;
    void* hProc = ProcessInspector::OpenForInjection(pid, injectErr);
    if (!hProc) {
        std::cerr << ConsoleUI::COLOR_RED << "[-] " << injectErr
                  << ConsoleUI::COLOR_RESET << "\n";
        HANDLE dummy = CreateFileW(INJECT_PIPE_NAME, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (dummy != INVALID_HANDLE_VALUE) CloseHandle(dummy);
        if (pipeThread.joinable()) pipeThread.join();
        return 1;
    }

    bool injected = ProcessInspector::InjectDLL(hProc, dllPath, injectErr);
    ProcessInspector::Close(hProc);

    if (!injected) {
        std::cerr << ConsoleUI::COLOR_RED << "[-] Injection failed: " << injectErr
                  << ConsoleUI::COLOR_RESET << "\n";
        HANDLE dummy = CreateFileW(INJECT_PIPE_NAME, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (dummy != INVALID_HANDLE_VALUE) CloseHandle(dummy);
        if (pipeThread.joinable()) pipeThread.join();
        return 1;
    }

    std::cout << ConsoleUI::COLOR_GREEN
              << "[+] DLL injected successfully. Waiting for analysis results...\n"
              << ConsoleUI::COLOR_RESET;

    PrintSep(ConsoleUI::COLOR_BRIGHT_BLUE);
    std::cout << ConsoleUI::COLOR_BOLD << ConsoleUI::COLOR_BRIGHT_BLUE
              << "  ============  LIVE ANALYSIS RESULTS STREAM  ============\n"
              << ConsoleUI::COLOR_RESET;

    // Wait for pipe thread to finish
    pipeThread.join();

    PrintSep(ConsoleUI::COLOR_BRIGHT_BLUE);
    std::cout << "\n" << ConsoleUI::COLOR_BOLD << ConsoleUI::COLOR_GREEN
              << "  ★  INJECTION ANALYSIS COMPLETE  ★\n"
              << ConsoleUI::COLOR_RESET
              << "  Modules enumerated : " << moduleCount << "\n"
              << "  Named offsets found: " << ConsoleUI::COLOR_BRIGHT_CYAN
              << foundOffsetCount << ConsoleUI::COLOR_RESET << "\n"
              << "  Unicorn emulations : " << unicornResultCount << "\n\n";

    // Clean up temp DLL
    DeleteFileA(dllPath.c_str());

    return 0;
}

// ============================================================================
//  [5]  Custom AOB Pattern Scan  (read-only, manual pattern entry)
// ============================================================================
static int RunCustomAobScan() {
    PrintHeader("Custom AOB Pattern Scan");

    uint32_t pid = PickProcessInteractive();
    if (!pid) return 1;

    std::string err;
    void* handle = ProcessInspector::OpenReadOnly(pid, err);
    if (!handle) {
        std::cerr << ConsoleUI::COLOR_RED << "[-] " << err << ConsoleUI::COLOR_RESET << "\n";
        return 1;
    }

    auto modInfo = ProcessInspector::ResolveMainModule(handle, pid, err);
    if (!modInfo) {
        std::cerr << ConsoleUI::COLOR_RED << "[-] " << err << ConsoleUI::COLOR_RESET << "\n";
        ProcessInspector::Close(handle);
        return 1;
    }

    std::cout << ConsoleUI::COLOR_CYAN
              << "\n  Module : " << modInfo->modulePath
              << "\n  Base   : 0x" << std::hex << std::uppercase << modInfo->baseAddress
              << "\n  Size   : 0x" << modInfo->sizeOfImage << std::dec << "\n\n"
              << ConsoleUI::COLOR_RESET;

    std::cout << "  Enter hex pattern with ?? wildcards\n"
              << "  Example: 48 8B 05 ?? ?? ?? ?? 48 85 C0\n\n"
              << "  Pattern: ";
    std::string pattern; std::getline(std::cin, pattern);

    if (pattern.empty()) {
        ProcessInspector::Close(handle);
        return 1;
    }

    std::cout << "\n" << ConsoleUI::COLOR_CYAN
              << "[*] Scanning 0x" << std::hex << modInfo->sizeOfImage
              << " bytes..." << std::dec << ConsoleUI::COLOR_RESET << "\n";

    auto hits = ProcessInspector::FindPattern(handle, modInfo->baseAddress,
                                              static_cast<size_t>(modInfo->sizeOfImage),
                                              pattern, err);
    ProcessInspector::Close(handle);

    if (hits.empty()) {
        std::cout << ConsoleUI::COLOR_YELLOW << "[!] Pattern not found in main module.\n"
                  << ConsoleUI::COLOR_RESET;
        return 0;
    }

    std::cout << "\n" << ConsoleUI::COLOR_GREEN << ConsoleUI::COLOR_BOLD
              << "[+] Found " << hits.size() << " match(es):\n"
              << ConsoleUI::COLOR_RESET;

    PrintSep(ConsoleUI::COLOR_GREEN);
    std::cout << std::left << std::setw(6) << "#"
              << std::setw(22) << "Absolute Address"
              << std::setw(20) << "RVA (Base+offset)"
              << "\n";
    PrintSep();

    for (size_t i = 0; i < hits.size(); ++i) {
        uint64_t rva = hits[i] - modInfo->baseAddress;
        std::cout << ConsoleUI::COLOR_CYAN
                  << "  [" << std::setw(2) << (i + 1) << "] "
                  << ConsoleUI::COLOR_RESET
                  << "0x" << std::hex << std::uppercase << std::setw(16) << hits[i]
                  << "  Base + 0x" << rva << std::dec << "\n";
    }
    PrintSep();

    // Optionally emulate the first match with Unicorn
    if (!hits.empty()) {
        std::cout << "\n  Run Unicorn emulation on first match? [Y/n]: ";
        std::string ans; std::getline(std::cin, ans);
        if (ans.empty() || ans[0] == 'Y' || ans[0] == 'y') {
            // Re-open for reading
            handle = ProcessInspector::OpenReadOnly(pid, err);
            if (handle) {
                size_t got = 0;
                auto buf = ProcessInspector::ReadMemory(handle, hits[0], 128, got, err);
                ProcessInspector::Close(handle);
                if (!buf.empty()) {
                    UnicornAnalyzer ua;
                    ua.SetEventCallback([](const TraceEvent& e){ ConsoleUI::RenderEvent(e); });
                    std::cout << "\n" << ConsoleUI::COLOR_BRIGHT_BLUE << ConsoleUI::COLOR_BOLD
                              << "=== Unicorn Emulation @ 0x" << std::hex << std::uppercase
                              << hits[0] << std::dec << " ===\n"
                              << ConsoleUI::COLOR_RESET;
                    auto res = ua.EmulateBuffer(buf, hits[0]);
                    std::cout << "  Instructions: " << res.instructionsExecuted
                              << "  Stop RIP: 0x" << std::hex << std::uppercase
                              << res.stopAddress << std::dec << "\n";
                    for (const auto& [n, v] : res.registers) {
                        std::cout << "  " << std::setw(5) << n
                                  << " = 0x" << std::hex << std::uppercase << v
                                  << std::dec << "\n";
                    }
                }
            }
        }
    }

    return 0;
}

// ============================================================================
//  Main interactive menu
// ============================================================================
static void PrintMainMenu() {
    std::cout << "\n"
              << ConsoleUI::COLOR_BOLD << ConsoleUI::COLOR_BRIGHT_CYAN
              << "  ┌──────────────────────────────────────────────────────────┐\n"
              << "  │                       What do you want?                  │\n"
              << "  └──────────────────────────────────────────────────────────┘\n"
              << ConsoleUI::COLOR_RESET
              << "\n"
              << ConsoleUI::COLOR_GREEN  << "  [1]" << ConsoleUI::COLOR_RESET
              << "  QEMU Native Hardware Sandbox (VM Snapshot + Live Stream)\n"
              << ConsoleUI::COLOR_GREEN  << "  [2]" << ConsoleUI::COLOR_RESET
              << "  Unicorn CPU Emulation  –  Analyze an EXE File\n"
              << ConsoleUI::COLOR_BRIGHT_CYAN << "  [3]" << ConsoleUI::COLOR_RESET
              << "  Attach to Process & Resolve Offsets  (Read-Only)\n"
              << ConsoleUI::COLOR_YELLOW << "  [4]" << ConsoleUI::COLOR_RESET << ConsoleUI::COLOR_BOLD
              << "  ★  DLL Injection & Live Unicorn Analysis  ★\n"
              << ConsoleUI::COLOR_RESET
              << ConsoleUI::COLOR_CYAN   << "  [5]" << ConsoleUI::COLOR_RESET
              << "  Custom AOB Pattern Scan  (hex + wildcards)\n"
              << ConsoleUI::COLOR_RED    << "  [0]" << ConsoleUI::COLOR_RESET
              << "  Exit\n\n"
              << ConsoleUI::COLOR_BOLD   << "  Enter choice: "
              << ConsoleUI::COLOR_RESET;
}

} // anonymous namespace

// ============================================================================
//  main()
// ============================================================================
int main(int argc, char* argv[]) {
    Sandbox::ConsoleUI::InitializeConsole();
    Sandbox::ConsoleUI::PrintBanner();

    // Load configuration file
    std::string configFile = "config/config.ini";
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--config" && i + 1 < argc) {
            configFile = argv[++i];
        }
    }
    Sandbox::ConfigManager::Instance().LoadFromFile(configFile);

    // Command-line shortcuts:
    if (argc > 1) {
        std::string arg1 = argv[1];

        // Mode 4 / --inject <PID or Name>
        if (arg1 == "4" || arg1 == "--inject" || arg1 == "-i") {
            uint32_t targetPid = 0;
            if (argc > 2) {
                std::string sel = argv[2];
                bool isNum = !sel.empty() && std::all_of(sel.begin(), sel.end(), [](unsigned char c){ return std::isdigit(c); });
                if (isNum) {
                    targetPid = static_cast<uint32_t>(std::stoul(sel));
                } else {
                    auto matches = ProcessInspector::FindProcessesByName(sel);
                    if (!matches.empty()) targetPid = matches[0].pid;
                }
            }
            return RunDLLInjectionFlow(targetPid);
        }

        // Mode 3 / --attach <PID or Name>
        if (arg1 == "3" || arg1 == "--attach" || arg1 == "-a") {
            uint32_t targetPid = 0;
            if (argc > 2) {
                std::string sel = argv[2];
                bool isNum = !sel.empty() && std::all_of(sel.begin(), sel.end(), [](unsigned char c){ return std::isdigit(c); });
                if (isNum) {
                    targetPid = static_cast<uint32_t>(std::stoul(sel));
                } else {
                    auto matches = ProcessInspector::FindProcessesByName(sel);
                    if (!matches.empty()) targetPid = matches[0].pid;
                }
            }
            return RunProcessInspectionFlow(targetPid);
        }

        // Mode 5 / --scan
        if (arg1 == "5" || arg1 == "--scan" || arg1 == "-s") {
            return RunCustomAobScan();
        }

        // Otherwise treat argv[1] as executable path for Unicorn emulation
        std::string targetExe = argv[1];
        Sandbox::UnicornAnalyzer analyzer;
        analyzer.SetEventCallback([](const Sandbox::TraceEvent& e){
            Sandbox::ConsoleUI::RenderEvent(e);
        });

        Sandbox::TraceOptions opts;
        Sandbox::VMConfig     vmCfg;
        if (!analyzer.Initialize(vmCfg, opts)) return 1;
        bool ok = analyzer.RunAnalysis(targetExe);

        auto report = analyzer.GetReport();
        Sandbox::ReportWriter::SaveReportToFile(report, "sandbox_report.txt");
        return ok ? 0 : 1;
    }

    // ── Interactive loop ──────────────────────────────────────────────────
    while (true) {
        PrintMainMenu();

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "0" || choice == "q" || choice == "exit") {
            std::cout << Sandbox::ConsoleUI::COLOR_GREEN
                      << "\n  [+] Goodbye!\n\n"
                      << Sandbox::ConsoleUI::COLOR_RESET;
            break;
        }

        if (choice == "4") {
            RunDLLInjectionFlow();
            continue;
        }

        if (choice == "3") {
            RunProcessInspectionFlow();
            continue;
        }

        if (choice == "5") {
            RunCustomAobScan();
            continue;
        }

        // ── Choices 1 & 2 require a target executable ─────────────────────
        Sandbox::TraceOptions options = Sandbox::ConfigManager::Instance().GetTraceOptions();
        Sandbox::VMConfig     vmConfig = Sandbox::ConfigManager::Instance().GetVMConfig();
        std::string           targetExe;
        std::string           engineChoice = choice;

        if (choice == "2") {
            std::cout << "\n  Enter Target EXE path: ";
            std::getline(std::cin, targetExe);
            // Strip quotes
            if (!targetExe.empty() && targetExe.front() == '"' && targetExe.back() == '"') {
                targetExe = targetExe.substr(1, targetExe.size() - 2);
            }
        } else {
            Sandbox::ConsoleUI::PromptUserConfiguration(options, vmConfig, targetExe);
        }

        if (targetExe.empty()) {
            std::cerr << Sandbox::ConsoleUI::COLOR_RED
                      << "[-] No target specified.\n"
                      << Sandbox::ConsoleUI::COLOR_RESET;
            continue;
        }

        std::unique_ptr<Sandbox::IAnalyzer> analyzer;
        if (engineChoice == "2") {
            analyzer = std::make_unique<Sandbox::UnicornAnalyzer>();
        } else {
            analyzer = std::make_unique<Sandbox::DynamicVMAnalyzer>();
        }

        if (!analyzer->Initialize(vmConfig, options)) {
            std::cerr << Sandbox::ConsoleUI::COLOR_RED
                      << "[-] Analyzer init failed.\n"
                      << Sandbox::ConsoleUI::COLOR_RESET;
            continue;
        }

        analyzer->SetEventCallback([](const Sandbox::TraceEvent& event) {
            Sandbox::ConsoleUI::RenderEvent(event);
        });

        std::cout << "\n" << Sandbox::ConsoleUI::COLOR_BOLD
                  << Sandbox::ConsoleUI::COLOR_BRIGHT_BLUE
                  << "=================== LIVE EXECUTION LOG ===================\n"
                  << Sandbox::ConsoleUI::COLOR_RESET << "\n";

        bool ok = analyzer->RunAnalysis(targetExe);

        std::cout << "\n" << Sandbox::ConsoleUI::COLOR_BOLD
                  << Sandbox::ConsoleUI::COLOR_BRIGHT_BLUE
                  << "=================== ANALYSIS SESSION END =================\n"
                  << Sandbox::ConsoleUI::COLOR_RESET << "\n";

        auto report = analyzer->GetReport();
        std::string reportFile = "sandbox_report.txt";
        if (Sandbox::ReportWriter::SaveReportToFile(report, reportFile)) {
            std::cout << Sandbox::ConsoleUI::COLOR_GREEN
                      << "[+] Report saved: "
                      << std::filesystem::absolute(reportFile).string() << "\n"
                      << Sandbox::ConsoleUI::COLOR_RESET;
        }

        // Ask if user wants to re-run or go back to menu
        std::cout << "\n  Press Enter to return to menu...\n";
        std::string dummy; std::getline(std::cin, dummy);
    }

    return 0;
}
