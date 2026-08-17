#include "cli/dracula_shell.h"
#include "host/report_writer.h"
#include "host/console_ui.h"
#include "mcp/mcp_server.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <filesystem>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace Dracula {

    static void StripQuotes(std::string& s) {
        if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
            s = s.substr(1, s.size() - 2);
        }
    }

    DraculaShell::DraculaShell() = default;
    DraculaShell::~DraculaShell() = default;

    void DraculaShell::PrintBanner() {
#ifdef _WIN32
        // Enable ANSI virtual terminal processing on Windows console
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD dwMode = 0;
            if (GetConsoleMode(hOut, &dwMode)) {
                SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
#endif
        std::cout << "\033[1;91m"
                  << "  ██████╗ ██████╗  █████╗  ██████╗██╗   ██╗██╗      █████╗ \n"
                  << "  ██╔══██╗██╔══██╗██╔══██╗██╔════╝██║   ██║██║     ██╔══██╗\n"
                  << "  ██║  ██║██████╔╝███████║██║     ██║   ██║██║     ███████║\n"
                  << "  ██║  ██║██╔══██╗██╔══██║██║     ██║   ██║██║     ██╔══██║\n"
                  << "  ██████╔╝██║  ██║██║  ██║╚██████╗╚██████╔╝███████╗██║  ██║\n"
                  << "  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝\n"
                  << "\033[0m"
                  << "\033[1;36m  🧛 Unified Binary Analysis & Reverse-Engineering Intelligence Platform\033[0m\n"
                  << "\033[90m  v2.0.0 | High-Level Unicorn 2 Emulation | Safe PE Parser | MCP Server\033[0m\n\n"
                  << "  Type \033[1;33m/help\033[0m to list available interactive commands or \033[1;33m/exit\033[0m to quit.\n\n";
    }

    void DraculaShell::PrintVersion() {
        std::cout << "Dracula Binary Intelligence Platform v2.0.0 (x86_64-w64-mingw32)\n";
    }

    void DraculaShell::PrintHelp() {
        std::cout << "\n\033[1;36m======================================================================\033[0m\n";
        std::cout << "\033[1m 🧛 DRACULA INTERACTIVE COMMAND REFERENCE\033[0m\n";
        std::cout << "\033[1;36m======================================================================\033[0m\n";
        std::cout << "  \033[1;33m/analyze <file>\033[0m          Run complete static, entropy, & emulation pipeline\n";
        std::cout << "  \033[1;33m/emulate <file>\033[0m          Run Unicorn 2 CPU emulation with Win32 HLE & registers\n";
        std::cout << "  \033[1;33m/disasm <file> [rva]\033[0m     Disassemble machine code at entrypoint or target RVA\n";
        std::cout << "  \033[1;33m/cfg <file> [rva]\033[0m        Build and visualize function Control Flow Graph\n";
        std::cout << "  \033[1;33m/headers <file>\033[0m          Inspect DOS/NT/Optional headers and section tables\n";
        std::cout << "  \033[1;33m/security <file>\033[0m         Audit ASLR, DEP, CFG, SEH, and Authenticode mitigations\n";
        std::cout << "  \033[1;33m/imports <file>\033[0m          List imported DLLs and flag sensitive APIs\n";
        std::cout << "  \033[1;33m/exports <file>\033[0m          List exported symbols and function RVAs\n";
        std::cout << "  \033[1;33m/strings <file> [len]\033[0m    Extract & classify ASCII and Unicode strings\n";
        std::cout << "  \033[1;33m/entropy <file>\033[0m          Calculate section-by-section Shannon entropy & packer\n";
        std::cout << "  \033[1;33m/scan <file> <pat>\033[0m       Scan for wildcard hex patterns (e.g. '48 8B ?" "? ?" "?')\n";
        std::cout << "  \033[1;33m/sandbox <file>\033[0m          Run dynamic VM isolation inside QEMU with live telemetry\n";
        std::cout << "  \033[1;33m/findings\033[0m                Display structured findings from active session\n";
        std::cout << "  \033[1;33m/report [json|md|txt]\033[0m    Export current session report to file\n";
        std::cout << "  \033[1;33m/session\033[0m                 Display active session status and metadata\n";
        std::cout << "  \033[1;33m/mcp\033[0m                     Start Model Context Protocol (MCP) stdio server\n";
        std::cout << "  \033[1;33m/clear\033[0m                   Clear terminal screen\n";
        std::cout << "  \033[1;33m/exit\033[0m                    Exit Dracula interactive shell\n";
        std::cout << "\033[1;36m======================================================================\033[0m\n\n";
    }

    std::string DraculaShell::ResolveTargetFile(const std::vector<std::string>& args, size_t index) {
        if (args.size() > index) {
            std::string path = args[index];
            StripQuotes(path);
            m_activeFile = path;
            return path;
        }
        return m_activeFile;
    }

    int DraculaShell::RunInteractive() {
        PrintBanner();
        m_running = true;

        while (m_running) {
            std::cout << "\033[1;91m⚰️ dracula\033[0m \033[1;36m❯\033[0m ";
            std::string line;
            if (!std::getline(std::cin, line)) break;

            if (line.empty()) continue;
            ExecuteCommand(line);
        }

        std::cout << "\n\033[1;32m[+] Dracula session terminated cleanly. Goodbye!\033[0m\n\n";
        return 0;
    }

    bool DraculaShell::ExecuteCommand(const std::string& commandLine) {
        std::istringstream ss(commandLine);
        std::vector<std::string> tokens;
        std::string token;
        while (ss >> token) tokens.push_back(token);

        if (tokens.empty()) return true;

        std::string cmd = tokens[0];
        if (cmd.front() == '/') cmd = cmd.substr(1);
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

        std::vector<std::string> args(tokens.begin() + 1, tokens.end());

        if (cmd == "help" || cmd == "?") {
            PrintHelp();
        } else if (cmd == "exit" || cmd == "quit" || cmd == "q") {
            m_running = false;
        } else if (cmd == "clear" || cmd == "cls") {
#ifdef _WIN32
            system("cls");
#else
            system("clear");
#endif
        } else if (cmd == "analyze" || cmd == "a") {
            HandleAnalyze(args);
        } else if (cmd == "emulate" || cmd == "emu" || cmd == "e") {
            HandleEmulate(args);
        } else if (cmd == "disasm" || cmd == "dis" || cmd == "d") {
            HandleDisasm(args);
        } else if (cmd == "cfg") {
            HandleCfg(args);
        } else if (cmd == "headers" || cmd == "hdr") {
            HandleHeaders(args);
        } else if (cmd == "security" || cmd == "sec") {
            HandleSecurity(args);
        } else if (cmd == "imports" || cmd == "imp") {
            HandleImports(args);
        } else if (cmd == "exports" || cmd == "exp") {
            HandleExports(args);
        } else if (cmd == "strings" || cmd == "str") {
            HandleStrings(args);
        } else if (cmd == "entropy" || cmd == "ent") {
            HandleEntropy(args);
        } else if (cmd == "sandbox" || cmd == "vm") {
            HandleSandbox(args);
        } else if (cmd == "scan") {
            HandleScan(args);
        } else if (cmd == "findings") {
            HandleFindings(args);
        } else if (cmd == "report") {
            HandleReport(args);
        } else if (cmd == "session") {
            HandleSession(args);
        } else if (cmd == "mcp") {
            McpServer mcp;
            mcp.RunStdio();
        } else {
            std::cerr << "\033[91m[-] Unknown command: '" << tokens[0] << "'. Type /help for assistance.\033[0m\n";
        }

        return true;
    }

    void DraculaShell::HandleAnalyze(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << "\033[91m[-] Usage: /analyze <path/to/binary.exe>\033[0m\n";
            return;
        }

        std::cout << "\033[90m[*] Running Dracula intelligence pipeline on " << file << "...\033[0m\n";
        OrchestratorOptions opts;
        opts.enableEmulation = true;
        auto res = m_orchestrator.AnalyzeFile(file, opts);

        m_sessionResult = std::make_unique<UnifiedAnalysisResult>(res);
        std::cout << res.ToAnsiSummary();
    }

    void DraculaShell::HandleEmulate(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << "\033[91m[-] Usage: /emulate <path/to/binary.exe>\033[0m\n";
            return;
        }

        UnicornAnalyzer emu;
        EmulationOptions opts;
        opts.maxInstructions = 10000;
        opts.strictSandbox = false;

        std::vector<Finding> findings;
        auto res = emu.EmulatePE(file, opts, &findings);

        std::cout << "\n\033[1;36m======================================================================\033[0m\n";
        std::cout << "\033[1m ⚙️ UNICORN 2 CPU EMULATION EXECUTION\033[0m\n";
        std::cout << "\033[1;36m======================================================================\033[0m\n";
        std::cout << " Status:       " << (res.success ? "\033[32mOK\033[0m" : "\033[31mFAULT / HALTED\033[0m") << "\n";
        std::cout << " Stop Reason:  " << StopReasonToString(res.stopReason) << "\n";
        std::cout << " Instructions: " << res.instructionsExecuted << "\n";
        std::cout << " Start Address: 0x" << std::hex << res.startAddress << "\n";
        std::cout << " Stop Address:  0x" << std::hex << res.stopAddress << std::dec << "\n\n";

        std::cout << " \033[1mRegisters:\033[0m\n";
        int col = 0;
        for (const auto& [name, val] : res.registers) {
            std::cout << "   " << std::setw(5) << name << ": 0x" << std::hex << std::setw(16) << std::setfill('0') << val << std::dec << "  ";
            col++;
            if (col % 2 == 0) std::cout << "\n";
        }
        if (col % 2 != 0) std::cout << "\n";

        if (!res.hleCalls.empty()) {
            std::cout << "\n \033[1mWin32 HLE Calls (" << res.hleCalls.size() << "):\033[0m\n";
            for (const auto& c : res.hleCalls) {
                std::cout << "   \033[32m" << c.library << "!" << c.apiName << "\033[0m -> Ret: 0x" << std::hex << c.returnValue << std::dec << " (" << c.details << ")\n";
            }
        }
        std::cout << "\033[1;36m======================================================================\033[0m\n\n";
    }

    void DraculaShell::HandleDisasm(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << "\033[91m[-] Usage: /disasm <path/to/binary.exe> [rva] [count]\033[0m\n";
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            std::cerr << "\033[91m[-] PE parse error: " << err << "\033[0m\n";
            return;
        }

        uint64_t targetRva = inspector.GetMetadata().entryPointRva;
        if (args.size() > 1) {
            try { targetRva = std::stoull(args[1], nullptr, 0); } catch (...) {}
        }

        size_t count = 30;
        if (args.size() > 2) {
            try { count = std::stoul(args[2]); } catch (...) {}
        }

        uint64_t fileOffset = inspector.RvaToFileOffset(targetRva);
        if (fileOffset >= inspector.GetBufferSize()) {
            std::cerr << "\033[91m[-] Invalid RVA 0x" << std::hex << targetRva << "\033[0m\n";
            return;
        }

        Disassembler disasm(inspector.GetMetadata().is64Bit ? Architecture::X86_64 : Architecture::X86_32);
        size_t codeSize = std::min<size_t>(count * 15, inspector.GetBufferSize() - fileOffset);
        auto instructions = disasm.Disassemble(inspector.GetBuffer() + fileOffset, codeSize, inspector.GetMetadata().imageBase + targetRva, targetRva);

        std::cout << "\n\033[1;36m======================================================================\033[0m\n";
        std::cout << " DISASSEMBLY @ RVA 0x" << std::hex << targetRva << " (VA 0x" << (inspector.GetMetadata().imageBase + targetRva) << ")\n";
        std::cout << "\033[1;36m======================================================================\033[0m\n";
        for (size_t i = 0; i < std::min(count, instructions.size()); ++i) {
            std::cout << Disassembler::FormatInstruction(instructions[i], true) << "\n";
        }
        std::cout << "\033[1;36m======================================================================\033[0m\n\n";
    }

    void DraculaShell::HandleCfg(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << "\033[91m[-] Usage: /cfg <path/to/binary.exe> [rva]\033[0m\n";
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            std::cerr << "\033[91m[-] PE parse error: " << err << "\033[0m\n";
            return;
        }

        uint64_t targetRva = inspector.GetMetadata().entryPointRva;
        if (args.size() > 1) {
            try { targetRva = std::stoull(args[1], nullptr, 0); } catch (...) {}
        }

        uint64_t fileOffset = inspector.RvaToFileOffset(targetRva);
        if (fileOffset >= inspector.GetBufferSize()) {
            std::cerr << "\033[91m[-] Invalid RVA 0x" << std::hex << targetRva << "\033[0m\n";
            return;
        }

        CfgAnalyzer cfg;
        Architecture arch = inspector.GetMetadata().is64Bit ? Architecture::X86_64 : Architecture::X86_32;
        size_t codeSize = std::min<size_t>(0x2000, inspector.GetBufferSize() - fileOffset);
        auto graph = cfg.BuildFunctionGraph(inspector.GetBuffer() + fileOffset, codeSize, inspector.GetMetadata().imageBase + targetRva, targetRva, arch, 500);

        std::cout << CfgAnalyzer::RenderGraph(graph, true);
    }

    void DraculaShell::HandleHeaders(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << "\033[91m[-] Usage: /headers <path/to/binary.exe>\033[0m\n";
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            std::cerr << "\033[91m[-] PE parse error: " << err << "\033[0m\n";
            return;
        }

        const auto& m = inspector.GetMetadata();
        std::cout << "\n\033[1;36m======================================================================\033[0m\n";
        std::cout << " PE HEADERS & METADATA: " << m.fileName << "\n";
        std::cout << "\033[1;36m======================================================================\033[0m\n";
        std::cout << "  File Size:     " << m.fileSize << " bytes\n";
        std::cout << "  Architecture:  " << m.architecture << "\n";
        std::cout << "  Subsystem:     " << m.subsystem << "\n";
        std::cout << "  Image Base:    0x" << std::hex << m.imageBase << "\n";
        std::cout << "  Entry Point:   0x" << std::hex << m.entryPointRva << " (VA: 0x" << (m.imageBase + m.entryPointRva) << ")\n";
        std::cout << "  Sections:      " << std::dec << m.sectionCount << "\n";
        std::cout << "  Is DLL:        " << (m.isDll ? "YES" : "NO") << "\n\n";

        std::cout << " \033[1mSection Table:\033[0m\n";
        std::cout << "  Name     VirtualAddr  VirtualSize  RawSize     Entropy   Perms\n";
        std::cout << "  ────────────────────────────────────────────────────────────\n";
        for (const auto& s : inspector.GetSections()) {
            std::string p = "";
            if (s.isReadable) p += "R";
            if (s.isWritable) p += "W";
            if (s.isExecutable) p += "X";
            std::cout << "  " << std::setw(8) << std::left << s.name
                      << " 0x" << std::hex << std::setw(10) << s.virtualAddress
                      << " 0x" << std::setw(10) << s.virtualSize
                      << " 0x" << std::setw(10) << s.rawSize << std::dec
                      << " " << std::fixed << std::setprecision(2) << s.entropy
                      << (s.isHighEntropy ? " 🔥" : "  ")
                      << "  " << p << "\n";
        }
        std::cout << "\033[1;36m======================================================================\033[0m\n\n";
    }

    void DraculaShell::HandleSecurity(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << "\033[91m[-] Usage: /security <path/to/binary.exe>\033[0m\n";
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            std::cerr << "\033[91m[-] PE parse error: " << err << "\033[0m\n";
            return;
        }

        const auto& sec = inspector.GetMitigations();
        std::cout << "\n\033[1;36m======================================================================\033[0m\n";
        std::cout << " 🛡️ SECURITY MITIGATION AUDIT\033[0m\n";
        std::cout << "\033[1;36m======================================================================\033[0m\n";
        std::cout << "  ASLR (Dynamic Base):       " << (sec.hasAslr ? "\033[32m[PASS] Enabled\033[0m" : "\033[31m[FAIL] Disabled\033[0m") << "\n";
        std::cout << "  High Entropy ASLR (64-bit): " << (sec.hasHighEntropyAslr ? "\033[32m[PASS] Enabled\033[0m" : "\033[33m[WARN] Disabled\033[0m") << "\n";
        std::cout << "  DEP / NX Compatibility:    " << (sec.hasDep ? "\033[32m[PASS] Enabled\033[0m" : "\033[31m[FAIL] Disabled\033[0m") << "\n";
        std::cout << "  Control Flow Guard (CFG):  " << (sec.hasCfg ? "\033[32m[PASS] Enabled\033[0m" : "\033[33m[WARN] Disabled\033[0m") << "\n";
        std::cout << "  SEH Exception Handling:    " << (sec.hasSeh ? "\033[32m[PASS] Enabled\033[0m" : "\033[33m[WARN] Disabled\033[0m") << "\n";
        std::cout << "  Authenticode Signature:    " << (sec.hasAuthenticode ? "\033[32m[PASS] Signed\033[0m" : "\033[33m[WARN] Unsigned\033[0m") << "\n";
        std::cout << "  RWX Section Presence:      " << (sec.hasRwxSections ? "\033[31m[CRITICAL] Detected RWX Section!\033[0m" : "\033[32m[PASS] None\033[0m") << "\n";
        std::cout << "  .NET Managed Binary:       " << (sec.isDotNet ? "YES" : "NO") << "\n";
        std::cout << "\033[1;36m======================================================================\033[0m\n\n";
    }

    void DraculaShell::HandleImports(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << "\033[91m[-] Usage: /imports <path/to/binary.exe>\033[0m\n";
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            std::cerr << "\033[91m[-] PE parse error: " << err << "\033[0m\n";
            return;
        }

        const auto& imports = inspector.GetImports();
        std::cout << "\n\033[1;36m======================================================================\033[0m\n";
        std::cout << " IMPORTED FUNCTIONS & LIBRARIES (" << imports.size() << " total)\n";
        std::cout << "\033[1;36m======================================================================\033[0m\n";
        for (const auto& imp : imports) {
            if (imp.isDangerous) {
                std::cout << "  \033[1;31m[DANGEROUS]\033[0m " << imp.dllName << "!" << imp.functionName
                          << " \033[90m(IAT RVA: 0x" << std::hex << imp.iatRva << ")\033[0m\n"
                          << "     -> " << imp.riskDescription << "\n";
            } else {
                std::cout << "  " << imp.dllName << "!" << imp.functionName
                          << " \033[90m(IAT RVA: 0x" << std::hex << imp.iatRva << ")\033[0m\n";
            }
        }
        std::cout << "\033[1;36m======================================================================\033[0m\n\n";
    }

    void DraculaShell::HandleExports(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << "\033[91m[-] Usage: /exports <path/to/binary.exe>\033[0m\n";
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            std::cerr << "\033[91m[-] PE parse error: " << err << "\033[0m\n";
            return;
        }

        const auto& exports = inspector.GetExports();
        std::cout << "\n\033[1;36m======================================================================\033[0m\n";
        std::cout << " EXPORTED FUNCTIONS (" << exports.size() << " total)\n";
        std::cout << "\033[1;36m======================================================================\033[0m\n";
        for (const auto& exp : exports) {
            std::cout << "  Ordinal " << std::dec << exp.ordinal << ": \033[32m" << exp.functionName << "\033[0m @ RVA 0x" << std::hex << exp.rva;
            if (!exp.forwarderName.empty()) std::cout << " -> " << exp.forwarderName;
            std::cout << "\n";
        }
        std::cout << "\033[1;36m======================================================================\033[0m\n\n";
    }

    void DraculaShell::HandleStrings(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << "\033[91m[-] Usage: /strings <path/to/binary.exe> [min_length]\033[0m\n";
            return;
        }

        size_t minLen = 5;
        if (args.size() > 1) {
            try { minLen = std::stoul(args[1]); } catch (...) {}
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            std::cerr << "\033[91m[-] PE parse error: " << err << "\033[0m\n";
            return;
        }

        StringsAnalyzer sa;
        auto strings = sa.ExtractStrings(inspector.GetBuffer(), inspector.GetBufferSize(), minLen);

        std::cout << "\n\033[1;36m======================================================================\033[0m\n";
        std::cout << " EXTRACTED STRINGS (" << strings.size() << " strings found, minLen=" << minLen << ")\n";
        std::cout << "\033[1;36m======================================================================\033[0m\n";
        for (const auto& s : strings) {
            if (s.category != StringCategory::Generic) {
                std::cout << "  \033[1;33m[" << StringCategoryToString(s.category) << "]\033[0m "
                          << "\033[90m(0x" << std::hex << s.fileOffset << ")\033[0m " << s.value << "\n";
            }
        }
        std::cout << "\033[1;36m======================================================================\033[0m\n\n";
    }

    void DraculaShell::HandleEntropy(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << "\033[91m[-] Usage: /entropy <path/to/binary.exe>\033[0m\n";
            return;
        }

        auto info = EntropyAnalyzer::AnalyzeBinary(file);
        std::cout << "\n\033[1;36m======================================================================\033[0m\n";
        std::cout << " SHANNON ENTROPY AUDIT: " << file << "\n";
        std::cout << "\033[1;36m======================================================================\033[0m\n";
        std::cout << " Overall File Entropy: " << std::fixed << std::setprecision(2) << info.overallEntropy << " / 8.00\n";
        std::cout << " Packing Verdict:     " << (info.isPacked ? "\033[1;31mPACKED / ENCRYPTED\033[0m" : "\033[32mNORMAL (Unpacked)\033[0m") << "\n";
        if (!info.detectedPacker.empty()) {
            std::cout << " Detected Packer:     \033[1;33m" << info.detectedPacker << "\033[0m\n";
        }
        std::cout << "\n \033[1mSection Entropies:\033[0m\n";
        for (const auto& s : info.sections) {
            int barLen = static_cast<int>((s.entropy / 8.0) * 20.0);
            std::string bar(barLen, '#');
            std::string pad(20 - barLen, '-');
            std::cout << "  " << std::setw(8) << std::left << s.name
                      << " [" << bar << pad << "] "
                      << std::fixed << std::setprecision(2) << s.entropy
                      << (s.isPacked ? " \033[31m[HIGH]\033[0m" : "") << "\n";
        }
        std::cout << "\033[1;36m======================================================================\033[0m\n\n";
    }

    void DraculaShell::HandleSandbox(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << "\033[91m[-] Usage: /sandbox <path/to/binary.exe>\033[0m\n";
            return;
        }

        std::cout << "\033[1;36m[*] Launching QEMU Dynamic Hardware Sandbox for " << file << "...\033[0m\n";
        auto res = m_orchestrator.RunDynamicSandbox(file, 60);
        m_sessionResult = std::make_unique<UnifiedAnalysisResult>(res);
        std::cout << res.ToAnsiSummary();
    }

    void DraculaShell::HandleScan(const std::vector<std::string>& args) {
        if (args.size() < 2) {
            std::cerr << "\033[91m[-] Usage: /scan <path/to/binary.exe> <hex_pattern>\n"
                      << "    Example: /scan sample.exe \"48 8B 05 ?? ?? ?? ?? 48 85 C0\"\033[0m\n";
            return;
        }

        std::string file = args[0];
        StripQuotes(file);

        std::string pattern = args[1];
        for (size_t i = 2; i < args.size(); ++i) pattern += " " + args[i];
        StripQuotes(pattern);

        auto matches = PatternScanner::ScanFile(file, pattern);
        std::cout << "\n\033[1;36m======================================================================\033[0m\n";
        std::cout << " PATTERN SCAN RESULTS (" << matches.size() << " matches)\n";
        std::cout << " Pattern: " << pattern << "\n";
        std::cout << "\033[1;36m======================================================================\033[0m\n";
        for (size_t offset : matches) {
            std::cout << "  Match at File Offset: \033[32m0x" << std::hex << offset << "\033[0m\n";
        }
        std::cout << "\033[1;36m======================================================================\033[0m\n\n";
    }

    void DraculaShell::HandleFindings(const std::vector<std::string>& args) {
        if (!m_sessionResult) {
            std::cerr << "\033[91m[-] No active analysis session. Run /analyze <file> first.\033[0m\n";
            return;
        }

        std::cout << "\n\033[1;36m======================================================================\033[0m\n";
        std::cout << " ACTIVE SESSION FINDINGS (" << m_sessionResult->findings.size() << " total)\n";
        std::cout << "\033[1;36m======================================================================\033[0m\n";
        for (const auto& f : m_sessionResult->findings) {
            std::string badge;
            switch (f.severity) {
                case FindingSeverity::Critical: badge = "\033[1;91m[CRITICAL]\033[0m"; break;
                case FindingSeverity::High:     badge = "\033[91m[HIGH]\033[0m"; break;
                case FindingSeverity::Medium:   badge = "\033[93m[MEDIUM]\033[0m"; break;
                case FindingSeverity::Low:      badge = "\033[94m[LOW]\033[0m"; break;
                default:                        badge = "\033[90m[INFO]\033[0m"; break;
            }
            std::cout << "  " << badge << " \033[1m" << f.title << "\033[0m (" << f.id << ")\n"
                      << "     Category: " << f.category << " | Source: " << f.source << "\n"
                      << "     Evidence: " << f.evidence << "\n\n";
        }
        std::cout << "\033[1;36m======================================================================\033[0m\n\n";
    }

    void DraculaShell::HandleReport(const std::vector<std::string>& args) {
        if (!m_sessionResult) {
            std::cerr << "\033[91m[-] No active analysis session. Run /analyze <file> first.\033[0m\n";
            return;
        }

        std::string format = "json";
        if (!args.empty()) format = args[0];

        std::string outFile = "dracula_report." + format;
        if (args.size() > 1) outFile = args[1];

        if (ReportWriter::SaveReport(*m_sessionResult, outFile, format)) {
            std::cout << "\033[32m[+] Successfully saved report to: " << std::filesystem::absolute(outFile).string() << "\033[0m\n";
        } else {
            std::cerr << "\033[91m[-] Failed to write report to: " << outFile << "\033[0m\n";
        }
    }

    void DraculaShell::HandleSession(const std::vector<std::string>& args) {
        if (!m_sessionResult) {
            std::cout << "\033[33m[*] No active session. Analyze a binary with /analyze <file>.\033[0m\n";
            return;
        }

        const auto& s = m_sessionResult->sample;
        std::cout << "\n\033[1;36m======================================================================\033[0m\n";
        std::cout << " ACTIVE SESSION: " << s.fileName << "\n";
        std::cout << "\033[1;36m======================================================================\033[0m\n";
        std::cout << "  File Path:    " << s.filePath << "\n";
        std::cout << "  Size:         " << s.fileSize << " bytes\n";
        std::cout << "  SHA-256:      " << s.sha256 << "\n";
        std::cout << "  Architecture: " << s.architecture << "\n";
        std::cout << "  Threat Score: " << m_sessionResult->threatScore << " / 100 (" << m_sessionResult->threatLevel << ")\n";
        std::cout << "  Findings:     " << m_sessionResult->findings.size() << " recorded\n";
        std::cout << "\033[1;36m======================================================================\033[0m\n\n";
    }

    int DraculaShell::ProcessArgs(int argc, char* argv[]) {
        if (argc <= 1) {
            return RunInteractive();
        }

        std::string arg1 = argv[1];

        if (arg1 == "--help" || arg1 == "-h") {
            PrintBanner();
            PrintHelp();
            return 0;
        }

        if (arg1 == "--version" || arg1 == "-v") {
            PrintVersion();
            return 0;
        }

        if (arg1 == "--mcp") {
            McpServer mcp;
            mcp.RunStdio();
            return 0;
        }

        std::string command;
        std::vector<std::string> cmdArgs;

        if (arg1 == "--analyze" || arg1 == "-a") command = "analyze";
        else if (arg1 == "--emulate" || arg1 == "-e") command = "emulate";
        else if (arg1 == "--disasm" || arg1 == "-d") command = "disasm";
        else if (arg1 == "--cfg") command = "cfg";
        else if (arg1 == "--headers") command = "headers";
        else if (arg1 == "--security") command = "security";
        else if (arg1 == "--imports") command = "imports";
        else if (arg1 == "--exports") command = "exports";
        else if (arg1 == "--strings") command = "strings";
        else if (arg1 == "--entropy") command = "entropy";
        else if (arg1 == "--sandbox") command = "sandbox";
        else if (arg1 == "--scan") command = "scan";
        else {
            // Default: treat argv[1] as binary to analyze
            command = "analyze";
            cmdArgs.push_back(arg1);
        }

        for (int i = 2; i < argc; ++i) {
            cmdArgs.push_back(argv[i]);
        }

        std::string cmdLine = "/" + command;
        for (const auto& a : cmdArgs) cmdLine += " \"" + a + "\"";

        ExecuteCommand(cmdLine);
        return 0;
    }

} // namespace Dracula
