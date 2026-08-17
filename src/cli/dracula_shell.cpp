#include "cli/dracula_shell.h"
#include "cli/terminal.h"
#include "common/version.h"
#include "host/report_writer.h"
#include "mcp/mcp_server.h"
#include "core/pe_inspector.h"
#include "core/disassembler.h"
#include "core/cfg_analyzer.h"
#include "core/xref_analyzer.h"
#include "core/entropy_analyzer.h"
#include "core/strings_analyzer.h"
#include "core/pattern_scanner.h"
#include "core/unicorn_analyzer.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <filesystem>
#include <fstream>

namespace Dracula {

    static void StripQuotes(std::string& s) {
        if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
            s = s.substr(1, s.size() - 2);
        }
    }

    DraculaShell::DraculaShell() = default;
    DraculaShell::~DraculaShell() = default;

    std::string DraculaShell::GetVersion() {
        return Version::String;
    }

    void DraculaShell::PrintVersion() {
        std::cout << Terminal::Color(ColorRole::Primary) << "Dracula v" << Version::String << Terminal::Color(ColorRole::Reset)
                  << " (" << Version::BuildTarget << ")\n"
                  << "Architecture: " << "x86_64\n"
                  << "Build:        " << "Release\n"
                  << "Release Date: " << Version::ReleaseDate << "\n"
                  << "Engines:      Capstone 5.0.1 | Unicorn 2 | Win32 HLE | Safe PE | MCP Server\n";
    }

    void DraculaShell::PrintBanner() {
        int termWidth = Terminal::GetWidth();
        int boxWidth = std::clamp(termWidth - 4, 48, 74);
        int innerWidth = boxWidth - 4;

        std::string title = " Dracula ";
        std::string line1 = "Binary Intelligence & Reverse Engineering Platform";
        std::string line2 = std::string("v") + Version::String + " (" + Version::BuildTarget + ")";
        std::string line3 = "Capstone 5.0 • Unicorn 2 • Safe PE • Win32 HLE • CFG • MCP";

        std::string borderCol = Terminal::Color(ColorRole::Border);
        std::string resetCol  = Terminal::Color(ColorRole::Reset);
        std::string primCol   = Terminal::Color(ColorRole::Primary);
        std::string secCol    = Terminal::Color(ColorRole::Secondary);
        std::string mutCol    = Terminal::Color(ColorRole::Muted);
        std::string cmdCol    = Terminal::Color(ColorRole::Command);

        // Top border with embedded title
        std::cout << "\n " << borderCol << Terminal::BoxTL() << Terminal::BoxH() << resetCol
                  << primCol << title << resetCol
                  << borderCol;
        int topRemaining = boxWidth - 3 - static_cast<int>(title.size());
        for (int i = 0; i < topRemaining; ++i) std::cout << Terminal::BoxH();
        std::cout << Terminal::BoxTR() << resetCol << "\n";

        // Line 1: Subtitle
        std::cout << " " << borderCol << Terminal::BoxV() << resetCol << "  "
                  << secCol << line1 << resetCol;
        int pad1 = innerWidth - static_cast<int>(line1.size());
        if (pad1 > 0) std::cout << std::string(pad1, ' ');
        std::cout << " " << borderCol << Terminal::BoxV() << resetCol << "\n";

        // Line 2: Version
        std::cout << " " << borderCol << Terminal::BoxV() << resetCol << "  "
                  << mutCol << line2 << resetCol;
        int pad2 = innerWidth - static_cast<int>(line2.size());
        if (pad2 > 0) std::cout << std::string(pad2, ' ');
        std::cout << " " << borderCol << Terminal::BoxV() << resetCol << "\n";

        // Line 3: Blank separator
        std::cout << " " << borderCol << Terminal::BoxV() << resetCol
                  << std::string(boxWidth - 2, ' ')
                  << borderCol << Terminal::BoxV() << resetCol << "\n";

        // Line 4: Capabilities
        std::cout << " " << borderCol << Terminal::BoxV() << resetCol << "  "
                  << mutCol << line3 << resetCol;
        int pad3 = innerWidth - static_cast<int>(line3.size());
        if (pad3 > 0) std::cout << std::string(pad3, ' ');
        std::cout << " " << borderCol << Terminal::BoxV() << resetCol << "\n";

        // Bottom border
        std::cout << " " << borderCol << Terminal::BoxBL();
        for (int i = 0; i < boxWidth - 2; ++i) std::cout << Terminal::BoxH();
        std::cout << Terminal::BoxBR() << resetCol << "\n\n";

        // Working directory & hint
        try {
            std::string cwd = std::filesystem::current_path().string();
            std::cout << "  " << mutCol << "Working directory: " << resetCol << cwd << "\n";
        } catch (...) {}

        std::cout << "  " << mutCol << "Type " << resetCol
                  << secCol << "/" << resetCol
                  << mutCol << " for command palette " << resetCol
                  << mutCol << Terminal::Bullet() << " " << resetCol
                  << secCol << "/help" << resetCol
                  << mutCol << " for command reference" << resetCol << "\n\n";
    }

    void DraculaShell::PrintHelp(const std::string& specificCommand) {
        auto& registry = CommandRegistry::Instance();

        if (!specificCommand.empty()) {
            const auto* cmd = registry.Find(specificCommand);
            if (!cmd) {
                std::cerr << Terminal::Color(ColorRole::Error) << "[-] Unknown command: '" << specificCommand << "'\n" << Terminal::Color(ColorRole::Reset);
                return;
            }

            std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
            std::cout << " " << Terminal::Color(ColorRole::Primary) << "COMMAND: /" << cmd->name << Terminal::Color(ColorRole::Reset) << "\n";
            std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
            std::cout << "  " << Terminal::Color(ColorRole::Muted) << "Category:    " << Terminal::Color(ColorRole::Reset) << cmd->category << "\n";
            std::cout << "  " << Terminal::Color(ColorRole::Muted) << "Usage:       " << Terminal::Color(ColorRole::Secondary) << cmd->usage << Terminal::Color(ColorRole::Reset) << "\n";
            if (!cmd->aliases.empty()) {
                std::cout << "  " << Terminal::Color(ColorRole::Muted) << "Aliases:     " << Terminal::Color(ColorRole::Reset);
                for (size_t i = 0; i < cmd->aliases.size(); ++i) {
                    std::cout << "/" << cmd->aliases[i] << (i + 1 < cmd->aliases.size() ? ", " : "");
                }
                std::cout << "\n";
            }
            std::cout << "  " << Terminal::Color(ColorRole::Muted) << "Description: " << Terminal::Color(ColorRole::Reset) << cmd->description << "\n\n";
            if (!cmd->detailedHelp.empty()) {
                std::cout << "  " << cmd->detailedHelp << "\n\n";
            }
            if (!cmd->examples.empty()) {
                std::cout << "  " << Terminal::Color(ColorRole::Muted) << "Examples:\n" << Terminal::Color(ColorRole::Reset);
                for (const auto& ex : cmd->examples) {
                    std::cout << "    " << Terminal::Color(ColorRole::Secondary) << ex << Terminal::Color(ColorRole::Reset) << "\n";
                }
                std::cout << "\n";
            }
            std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " " << Terminal::Color(ColorRole::Primary) << "DRACULA COMMAND REFERENCE" << Terminal::Color(ColorRole::Reset) << "\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);

        auto categories = registry.GetCategories();
        for (const auto& cat : categories) {
            std::cout << "\n " << Terminal::Color(ColorRole::Accent) << "--- " << cat << " ---" << Terminal::Color(ColorRole::Reset) << "\n";
            auto cmds = registry.GetCommandsByCategory(cat);
            for (const auto* cmd : cmds) {
                std::string cmdName = "/" + cmd->name;
                std::cout << "  " << Terminal::Color(ColorRole::Secondary) << std::setw(15) << std::left << cmdName << Terminal::Color(ColorRole::Reset)
                          << " " << cmd->description << "\n";
            }
        }

        std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " " << Terminal::Color(ColorRole::Muted) << "Interactive Palette:" << Terminal::Color(ColorRole::Reset) << " Type " << Terminal::Color(ColorRole::Secondary) << "/" << Terminal::Color(ColorRole::Reset) << " to open palette, " << Terminal::Color(ColorRole::Secondary) << "Up/Down" << Terminal::Color(ColorRole::Reset) << " to navigate, " << Terminal::Color(ColorRole::Secondary) << "TAB" << Terminal::Color(ColorRole::Reset) << " to accept.\n";
        std::cout << " " << Terminal::Color(ColorRole::Muted) << "Detailed Help:" << Terminal::Color(ColorRole::Reset) << " Type " << Terminal::Color(ColorRole::Secondary) << "/help <command>" << Terminal::Color(ColorRole::Reset) << " for specific syntax and examples.\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n\n" << Terminal::Color(ColorRole::Reset);
    }

    std::string DraculaShell::ResolveTargetFile(const std::vector<std::string>& args, size_t index) {
        if (args.size() > index && !args[index].empty()) {
            std::string path = args[index];
            StripQuotes(path);
            m_activeFile = path;
            return path;
        }
        return m_activeFile;
    }

    void DraculaShell::SetActiveSession(const std::string& file, std::unique_ptr<UnifiedAnalysisResult> result) {
        m_activeFile = file;
        m_sessionResult = std::move(result);
    }

    int DraculaShell::RunInteractive() {
        PrintBanner();
        m_running = true;

        while (m_running) {
            std::string prompt = Terminal::DraculaPrompt();
            std::string line;

            if (!m_editor.ReadLine(prompt, line)) {
                break; // EOF
            }

            if (line.empty()) continue;
            ExecuteCommand(line);
        }

        std::cout << "\n" << Terminal::Color(ColorRole::Success) << "[+] Dracula session terminated cleanly. Goodbye!\n\n" << Terminal::Color(ColorRole::Reset);
        return 0;
    }

    bool DraculaShell::ExecuteCommand(const std::string& commandLine) {
        // Parse tokens handling quoted arguments
        std::vector<std::string> tokens;
        std::string current;
        bool inQuotes = false;

        for (size_t i = 0; i < commandLine.size(); ++i) {
            char c = commandLine[i];
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ' ' && !inQuotes) {
                if (!current.empty()) {
                    tokens.push_back(current);
                    current.clear();
                }
            } else {
                current += c;
            }
        }
        if (!current.empty()) {
            tokens.push_back(current);
        }

        if (tokens.empty()) return true;

        std::string cmdName = tokens[0];
        if (!cmdName.empty() && cmdName.front() == '/') {
            cmdName = cmdName.substr(1);
        }

        std::vector<std::string> args;
        for (size_t i = 1; i < tokens.size(); ++i) {
            std::string a = tokens[i];
            StripQuotes(a);
            args.push_back(a);
        }

        const auto* cmdDef = CommandRegistry::Instance().Find(cmdName);
        if (cmdDef && cmdDef->handler) {
            cmdDef->handler(*this, args);
        } else {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Unknown command: '" << tokens[0] << "'. Type /help for reference.\n" << Terminal::Color(ColorRole::Reset);
        }

        return true;
    }

    void DraculaShell::HandleAnalyze(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Usage: /analyze <path/to/binary.exe>\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        std::cout << Terminal::Color(ColorRole::Muted) << "[*] Running Dracula intelligence pipeline on " << file << "...\n" << Terminal::Color(ColorRole::Reset);
        OrchestratorOptions opts;
        opts.enableEmulation = true;
        auto res = m_orchestrator.AnalyzeFile(file, opts);

        m_sessionResult = std::make_unique<UnifiedAnalysisResult>(res);
        std::cout << res.ToAnsiSummary();
    }

    void DraculaShell::HandleEmulate(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Usage: /emulate [file] [--policy bypass|realistic|neutral]\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        UnicornAnalyzer emu;
        EmulationOptions opts;
        opts.maxInstructions = 10000;
        opts.strictSandbox = false;

        // Check for --policy argument
        for (size_t i = 0; i < args.size(); ++i) {
            if (args[i] == "--policy" && i + 1 < args.size()) {
                std::string pol = args[i + 1];
                if (pol == "bypass") opts.antiDebugPolicy = AntiDebugPolicy::Bypass;
                else if (pol == "realistic") opts.antiDebugPolicy = AntiDebugPolicy::Realistic;
                else if (pol == "neutral") opts.antiDebugPolicy = AntiDebugPolicy::Neutral;
            }
        }

        std::vector<Finding> findings;
        auto res = emu.EmulatePE(file, opts, &findings);

        std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " " << Terminal::Color(ColorRole::Primary) << "UNICORN 2 CPU EMULATION EXECUTION" << Terminal::Color(ColorRole::Reset) << "\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " Status:        " << (res.success ? (Terminal::Color(ColorRole::Success) + "OK") : (Terminal::Color(ColorRole::Error) + "FAULT / HALTED")) << Terminal::Color(ColorRole::Reset) << "\n";
        std::cout << " Stop Reason:   " << StopReasonToString(res.stopReason) << "\n";
        std::cout << " Instructions:  " << res.instructionsExecuted << "\n";
        std::cout << " Start Address: 0x" << std::hex << res.startAddress << "\n";
        std::cout << " Stop Address:  0x" << std::hex << res.stopAddress << std::dec << "\n\n";

        std::cout << " " << Terminal::Color(ColorRole::Command) << "Registers:\n" << Terminal::Color(ColorRole::Reset);
        int col = 0;
        for (const auto& [name, val] : res.registers) {
            std::cout << "   " << std::setw(5) << name << ": 0x" << std::hex << std::setw(16) << std::setfill('0') << val << std::dec << "  ";
            col++;
            if (col % 2 == 0) std::cout << "\n";
        }
        if (col % 2 != 0) std::cout << "\n";

        if (!res.hleCalls.empty()) {
            std::cout << "\n " << Terminal::Color(ColorRole::Command) << "Win32 HLE Calls (" << res.hleCalls.size() << "):\n" << Terminal::Color(ColorRole::Reset);
            for (const auto& c : res.hleCalls) {
                std::cout << "   " << Terminal::Color(ColorRole::Success) << c.library << "!" << c.apiName << Terminal::Color(ColorRole::Reset)
                          << " -> Ret: 0x" << std::hex << c.returnValue << std::dec << " (" << c.details << ")\n";
            }
        }
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n\n" << Terminal::Color(ColorRole::Reset);
    }

    void DraculaShell::HandleDisasm(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Usage: /disasm [file] [rva] [count]\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] PE parse error: " << err << "\n" << Terminal::Color(ColorRole::Reset);
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
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Invalid RVA 0x" << std::hex << targetRva << "\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        Disassembler disasm(inspector.GetMetadata().is64Bit ? Architecture::X86_64 : Architecture::X86_32);
        size_t codeSize = std::min<size_t>(count * 15, inspector.GetBufferSize() - fileOffset);
        auto instructions = disasm.Disassemble(inspector.GetBuffer() + fileOffset, codeSize, inspector.GetMetadata().imageBase + targetRva, targetRva);

        std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " DISASSEMBLY @ RVA 0x" << std::hex << targetRva << " (VA 0x" << (inspector.GetMetadata().imageBase + targetRva) << ")\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        for (size_t i = 0; i < std::min(count, instructions.size()); ++i) {
            std::cout << Disassembler::FormatInstruction(instructions[i], Terminal::SupportsColor()) << "\n";
        }
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n\n" << Terminal::Color(ColorRole::Reset);
    }

    void DraculaShell::HandleCfg(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Usage: /cfg [file] [rva]\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] PE parse error: " << err << "\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        uint64_t targetRva = inspector.GetMetadata().entryPointRva;
        if (args.size() > 1) {
            try { targetRva = std::stoull(args[1], nullptr, 0); } catch (...) {}
        }

        uint64_t fileOffset = inspector.RvaToFileOffset(targetRva);
        if (fileOffset >= inspector.GetBufferSize()) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Invalid RVA 0x" << std::hex << targetRva << "\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        CfgAnalyzer cfg;
        Architecture arch = inspector.GetMetadata().is64Bit ? Architecture::X86_64 : Architecture::X86_32;
        size_t codeSize = std::min<size_t>(0x2000, inspector.GetBufferSize() - fileOffset);
        auto graph = cfg.BuildFunctionGraph(inspector.GetBuffer() + fileOffset, codeSize, inspector.GetMetadata().imageBase + targetRva, targetRva, arch, 500);

        std::cout << CfgAnalyzer::RenderGraph(graph, Terminal::SupportsColor());
    }

    void DraculaShell::HandleHeaders(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Usage: /headers [file]\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] PE parse error: " << err << "\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        const auto& m = inspector.GetMetadata();
        std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " PE HEADERS & METADATA: " << m.fileName << "\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << "  File Size:     " << m.fileSize << " bytes\n";
        std::cout << "  Architecture:  " << m.architecture << "\n";
        std::cout << "  Subsystem:     " << m.subsystem << "\n";
        std::cout << "  Image Base:    0x" << std::hex << m.imageBase << "\n";
        std::cout << "  Entry Point:   0x" << std::hex << m.entryPointRva << " (VA: 0x" << (m.imageBase + m.entryPointRva) << ")\n";
        std::cout << "  Sections:      " << std::dec << m.sectionCount << "\n";
        std::cout << "  Is DLL:        " << (m.isDll ? "YES" : "NO") << "\n\n";

        std::cout << " " << Terminal::Color(ColorRole::Command) << "Section Table:\n" << Terminal::Color(ColorRole::Reset);
        std::cout << "  Name     VirtualAddr  VirtualSize  RawSize     Entropy   Perms\n";
        std::cout << "  " << Terminal::DrawHorizontalLine(58) << "\n";
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
                      << (s.isHighEntropy ? " [HIGH]" : "       ")
                      << "  " << p << "\n";
        }
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n\n" << Terminal::Color(ColorRole::Reset);
    }

    void DraculaShell::HandleSecurity(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Usage: /security [file]\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] PE parse error: " << err << "\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        const auto& sec = inspector.GetMitigations();
        std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " SECURITY MITIGATION AUDIT\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << "  ASLR (Dynamic Base):        " << (sec.hasAslr ? (Terminal::Color(ColorRole::Success) + "[PASS] Enabled") : (Terminal::Color(ColorRole::Error) + "[FAIL] Disabled")) << Terminal::Color(ColorRole::Reset) << "\n";
        std::cout << "  High Entropy ASLR (64-bit):  " << (sec.hasHighEntropyAslr ? (Terminal::Color(ColorRole::Success) + "[PASS] Enabled") : (Terminal::Color(ColorRole::Warning) + "[WARN] Disabled")) << Terminal::Color(ColorRole::Reset) << "\n";
        std::cout << "  DEP / NX Compatibility:     " << (sec.hasDep ? (Terminal::Color(ColorRole::Success) + "[PASS] Enabled") : (Terminal::Color(ColorRole::Error) + "[FAIL] Disabled")) << Terminal::Color(ColorRole::Reset) << "\n";
        std::cout << "  Control Flow Guard (CFG):   " << (sec.hasCfg ? (Terminal::Color(ColorRole::Success) + "[PASS] Enabled") : (Terminal::Color(ColorRole::Warning) + "[WARN] Disabled")) << Terminal::Color(ColorRole::Reset) << "\n";
        std::cout << "  SEH Exception Handling:     " << (sec.hasSeh ? (Terminal::Color(ColorRole::Success) + "[PASS] Enabled") : (Terminal::Color(ColorRole::Warning) + "[WARN] Disabled")) << Terminal::Color(ColorRole::Reset) << "\n";
        std::cout << "  Authenticode Signature:     " << (sec.hasAuthenticode ? (Terminal::Color(ColorRole::Success) + "[PASS] Signed") : (Terminal::Color(ColorRole::Warning) + "[WARN] Unsigned")) << Terminal::Color(ColorRole::Reset) << "\n";
        std::cout << "  RWX Section Presence:       " << (sec.hasRwxSections ? (Terminal::Color(ColorRole::Error) + "[CRITICAL] Detected RWX Section!") : (Terminal::Color(ColorRole::Success) + "[PASS] None")) << Terminal::Color(ColorRole::Reset) << "\n";
        std::cout << "  .NET Managed Binary:        " << (sec.isDotNet ? "YES" : "NO") << "\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n\n" << Terminal::Color(ColorRole::Reset);
    }

    void DraculaShell::HandleImports(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Usage: /imports [file]\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] PE parse error: " << err << "\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        const auto& imports = inspector.GetImports();
        std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " IMPORTED FUNCTIONS & LIBRARIES (" << imports.size() << " total)\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        for (const auto& imp : imports) {
            if (imp.isDangerous) {
                std::cout << "  " << Terminal::Color(ColorRole::Error) << "[DANGEROUS]" << Terminal::Color(ColorRole::Reset)
                          << " " << imp.dllName << "!" << imp.functionName
                          << " " << Terminal::Color(ColorRole::Muted) << "(IAT RVA: 0x" << std::hex << imp.iatRva << ")" << Terminal::Color(ColorRole::Reset) << "\n"
                          << "     -> " << imp.riskDescription << "\n";
            } else {
                std::cout << "  " << imp.dllName << "!" << imp.functionName
                          << " " << Terminal::Color(ColorRole::Muted) << "(IAT RVA: 0x" << std::hex << imp.iatRva << ")" << Terminal::Color(ColorRole::Reset) << "\n";
            }
        }
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n\n" << Terminal::Color(ColorRole::Reset);
    }

    void DraculaShell::HandleExports(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Usage: /exports [file]\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] PE parse error: " << err << "\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        const auto& exports = inspector.GetExports();
        std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " EXPORTED FUNCTIONS (" << exports.size() << " total)\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        for (const auto& exp : exports) {
            std::cout << "  Ordinal " << std::dec << exp.ordinal << ": "
                      << Terminal::Color(ColorRole::Success) << exp.functionName << Terminal::Color(ColorRole::Reset)
                      << " @ RVA 0x" << std::hex << exp.rva;
            if (!exp.forwarderName.empty()) std::cout << " -> " << exp.forwarderName;
            std::cout << "\n";
        }
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n\n" << Terminal::Color(ColorRole::Reset);
    }

    void DraculaShell::HandleStrings(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Usage: /strings [file] [min_length]\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        size_t minLen = 5;
        if (args.size() > 1) {
            try { minLen = std::stoul(args[1]); } catch (...) {}
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] PE parse error: " << err << "\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        StringsAnalyzer sa;
        auto strings = sa.ExtractStrings(inspector.GetBuffer(), inspector.GetBufferSize(), minLen);

        std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " EXTRACTED STRINGS (" << strings.size() << " strings found, minLen=" << minLen << ")\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        for (const auto& s : strings) {
            if (s.category != StringCategory::Generic) {
                std::cout << "  " << Terminal::Color(ColorRole::Warning) << "[" << StringCategoryToString(s.category) << "]" << Terminal::Color(ColorRole::Reset)
                          << " " << Terminal::Color(ColorRole::Muted) << "(0x" << std::hex << s.fileOffset << ")" << Terminal::Color(ColorRole::Reset) << " " << s.value << "\n";
            }
        }
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n\n" << Terminal::Color(ColorRole::Reset);
    }

    void DraculaShell::HandleEntropy(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Usage: /entropy [file]\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        auto info = EntropyAnalyzer::AnalyzeBinary(file);
        std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " SHANNON ENTROPY AUDIT: " << file << "\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " Overall File Entropy: " << std::fixed << std::setprecision(2) << info.overallEntropy << " / 8.00\n";
        std::cout << " Packing Verdict:      " << (info.isPacked ? (Terminal::Color(ColorRole::Error) + "PACKED / ENCRYPTED") : (Terminal::Color(ColorRole::Success) + "NORMAL (Unpacked)")) << Terminal::Color(ColorRole::Reset) << "\n";
        if (!info.detectedPacker.empty()) {
            std::cout << " Detected Packer:      " << Terminal::Color(ColorRole::Warning) << info.detectedPacker << Terminal::Color(ColorRole::Reset) << "\n";
        }
        std::cout << "\n " << Terminal::Color(ColorRole::Command) << "Section Entropies:\n" << Terminal::Color(ColorRole::Reset);
        for (const auto& s : info.sections) {
            int barLen = static_cast<int>((s.entropy / 8.0) * 20.0);
            std::string bar(barLen, '#');
            std::string pad(20 - barLen, '-');
            std::cout << "  " << std::setw(8) << std::left << s.name
                      << " [" << bar << pad << "] "
                      << std::fixed << std::setprecision(2) << s.entropy
                      << (s.isPacked ? (Terminal::Color(ColorRole::Error) + " [HIGH]" + Terminal::Color(ColorRole::Reset)) : "") << "\n";
        }
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n\n" << Terminal::Color(ColorRole::Reset);
    }

    void DraculaShell::HandleScan(const std::vector<std::string>& args) {
        if (args.size() < 2 && (args.empty() || m_activeFile.empty())) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Usage: /scan [file] <hex_pattern>\n"
                      << "    Example: /scan sample.exe \"48 8B 05 ?? ?? ?? ?? 48 85 C0\"\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        std::string file;
        std::string pattern;

        if (args.size() >= 2) {
            file = args[0];
            StripQuotes(file);
            pattern = args[1];
            for (size_t i = 2; i < args.size(); ++i) pattern += " " + args[i];
        } else {
            file = m_activeFile;
            pattern = args[0];
        }
        StripQuotes(pattern);

        auto matches = PatternScanner::ScanFile(file, pattern);
        std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " PATTERN SCAN RESULTS (" << matches.size() << " matches)\n";
        std::cout << " Pattern: " << pattern << "\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        for (size_t offset : matches) {
            std::cout << "  Match at File Offset: " << Terminal::Color(ColorRole::Success) << "0x" << std::hex << offset << Terminal::Color(ColorRole::Reset) << "\n";
        }
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n\n" << Terminal::Color(ColorRole::Reset);
    }

    void DraculaShell::HandleSandbox(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Usage: /sandbox <path/to/binary.exe>\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        std::cout << Terminal::Color(ColorRole::Secondary) << "[*] Launching QEMU Dynamic Hardware Sandbox for " << file << "...\n" << Terminal::Color(ColorRole::Reset);
        auto res = m_orchestrator.RunDynamicSandbox(file, 60);
        m_sessionResult = std::make_unique<UnifiedAnalysisResult>(res);
        std::cout << res.ToAnsiSummary();
    }

    void DraculaShell::HandleFunctions(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Usage: /functions [file]\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] PE parse error: " << err << "\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " DISCOVERED FUNCTIONS: " << file << "\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << "  Entrypoint Function: 0x" << std::hex << inspector.GetMetadata().entryPointRva
                  << " (VA: 0x" << (inspector.GetMetadata().imageBase + inspector.GetMetadata().entryPointRva) << ")\n";

        for (const auto& exp : inspector.GetExports()) {
            std::cout << "  Export Function:     0x" << std::hex << exp.rva << " -> " << exp.functionName << "\n";
        }
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n\n" << Terminal::Color(ColorRole::Reset);
    }

    void DraculaShell::HandleXrefs(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Usage: /xrefs [file] [rva]\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] PE parse error: " << err << "\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        uint64_t epRva = inspector.GetMetadata().entryPointRva;
        if (args.size() > 1) {
            try { epRva = std::stoull(args[1], nullptr, 0); } catch (...) {}
        }

        uint64_t epOffset = inspector.RvaToFileOffset(epRva);
        std::vector<XRefEntry> xrefs;
        if (epOffset < inspector.GetBufferSize()) {
            size_t epCodeSize = std::min<size_t>(0x2000, inspector.GetBufferSize() - epOffset);
            Architecture arch = inspector.GetMetadata().is64Bit ? Architecture::X86_64 : Architecture::X86_32;
            uint64_t epVa = inspector.GetMetadata().imageBase + epRva;
            Disassembler disasm(arch);
            auto instructions = disasm.Disassemble(inspector.GetBuffer() + epOffset, epCodeSize, epVa, epRva);
            StringsAnalyzer sa;
            auto strings = sa.ExtractStrings(inspector.GetBuffer(), inspector.GetBufferSize(), 5);
            xrefs = XrefAnalyzer::ExtractXrefs(instructions, inspector, strings);
        }

        std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " CROSS REFERENCES (" << xrefs.size() << " total references)\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        for (size_t i = 0; i < std::min<size_t>(50, xrefs.size()); ++i) {
            const auto& x = xrefs[i];
            std::cout << "  0x" << std::hex << x.fromRva << " [" << XRefTypeToString(x.type) << "] -> 0x" << x.toRva;
            if (!x.targetName.empty()) std::cout << " (" << x.targetName << ")";
            std::cout << "\n";
        }
        if (xrefs.size() > 50) {
            std::cout << "  ... (" << (xrefs.size() - 50) << " more xrefs)\n";
        }
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n\n" << Terminal::Color(ColorRole::Reset);
    }

    void DraculaShell::HandleFindings(const std::vector<std::string>& args) {
        if (!m_sessionResult) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] No active analysis session. Run /analyze <file> first.\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " ACTIVE SESSION FINDINGS (" << m_sessionResult->findings.size() << " total)\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        for (const auto& f : m_sessionResult->findings) {
            std::string badge;
            switch (f.severity) {
                case FindingSeverity::Critical: badge = Terminal::Color(ColorRole::Error) + "[CRITICAL]"; break;
                case FindingSeverity::High:     badge = Terminal::Color(ColorRole::Error) + "[HIGH]"; break;
                case FindingSeverity::Medium:   badge = Terminal::Color(ColorRole::Warning) + "[MEDIUM]"; break;
                case FindingSeverity::Low:      badge = Terminal::Color(ColorRole::Secondary) + "[LOW]"; break;
                default:                        badge = Terminal::Color(ColorRole::Muted) + "[INFO]"; break;
            }
            std::cout << "  " << badge << Terminal::Color(ColorRole::Reset) << " " << Terminal::Color(ColorRole::Command) << f.title << Terminal::Color(ColorRole::Reset) << " (" << f.id << ")\n"
                      << "     Category: " << f.category << " | Source: " << f.source << "\n"
                      << "     Evidence: " << f.evidence << "\n\n";
        }
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n\n" << Terminal::Color(ColorRole::Reset);
    }

    void DraculaShell::HandleReport(const std::vector<std::string>& args) {
        if (!m_sessionResult) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] No active analysis session. Run /analyze <file> first.\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        std::string format = "json";
        if (!args.empty()) format = args[0];

        std::string outFile = "dracula_report." + format;
        if (args.size() > 1) outFile = args[1];

        if (ReportWriter::SaveReport(*m_sessionResult, outFile, format)) {
            std::cout << Terminal::Color(ColorRole::Success) << "[+] Successfully saved report to: " << std::filesystem::absolute(outFile).string() << "\n" << Terminal::Color(ColorRole::Reset);
        } else {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Failed to write report to: " << outFile << "\n" << Terminal::Color(ColorRole::Reset);
        }
    }

    void DraculaShell::HandleSession(const std::vector<std::string>& args) {
        if (!m_sessionResult) {
            std::cout << Terminal::Color(ColorRole::Warning) << "[*] No active session. Analyze a binary with /analyze <file>.\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        const auto& s = m_sessionResult->sample;
        std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " ACTIVE SESSION: " << s.fileName << "\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << "  File Path:    " << s.filePath << "\n";
        std::cout << "  Size:         " << s.fileSize << " bytes\n";
        std::cout << "  SHA-256:      " << s.sha256 << "\n";
        std::cout << "  Architecture: " << s.architecture << "\n";
        std::cout << "  Threat Score: " << m_sessionResult->threatScore << " / 100 (" << m_sessionResult->threatLevel << ")\n";
        std::cout << "  Findings:     " << m_sessionResult->findings.size() << " recorded\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n\n" << Terminal::Color(ColorRole::Reset);
    }

    void DraculaShell::HandleMcp(const std::vector<std::string>& args) {
        McpServer mcp;
        mcp.RunStdio();
    }

    void DraculaShell::HandleChangelog(const std::vector<std::string>& args) {
        std::vector<std::string> candidates = {
            "CHANGELOG.txt",
            "../CHANGELOG.txt",
            "../../CHANGELOG.txt"
        };

        std::string changelogPath;
        for (const auto& c : candidates) {
            if (std::filesystem::exists(c)) {
                changelogPath = c;
                break;
            }
        }

        if (changelogPath.empty()) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] CHANGELOG.txt not found in current directory.\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        std::ifstream file(changelogPath);
        if (!file.is_open()) {
            std::cerr << Terminal::Color(ColorRole::Error) << "[-] Could not open " << changelogPath << "\n" << Terminal::Color(ColorRole::Reset);
            return;
        }

        std::string filterVer = args.empty() ? "" : args[0];
        if (!filterVer.empty() && filterVer.front() == 'v') filterVer = filterVer.substr(1);

        std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n" << Terminal::Color(ColorRole::Reset);
        std::cout << " " << Terminal::Color(ColorRole::Primary) << "DRACULA VERSION HISTORY & RELEASE NOTES" << Terminal::Color(ColorRole::Reset) << "\n";
        std::cout << Terminal::Color(ColorRole::Border) << "======================================================================\n\n" << Terminal::Color(ColorRole::Reset);

        std::string line;
        bool inTargetSection = filterVer.empty();
        while (std::getline(file, line)) {
            if (!filterVer.empty()) {
                if (line.find("Dracula v" + filterVer) != std::string::npos) {
                    inTargetSection = true;
                } else if (inTargetSection && line.find("Dracula v") != std::string::npos) {
                    break;
                }
            }

            if (inTargetSection) {
                if (line.find("=====") != std::string::npos) {
                    std::cout << Terminal::Color(ColorRole::Border) << line << Terminal::Color(ColorRole::Reset) << "\n";
                } else if (line.find("Dracula v") != std::string::npos) {
                    std::cout << Terminal::Color(ColorRole::Primary) << line << Terminal::Color(ColorRole::Reset) << "\n";
                } else if (line == "Added" || line == "Changed" || line == "Fixed" || line == "Verified") {
                    std::cout << Terminal::Color(ColorRole::Accent) << line << Terminal::Color(ColorRole::Reset) << "\n";
                } else {
                    std::cout << line << "\n";
                }
            }
        }
        std::cout << "\n" << Terminal::Color(ColorRole::Border) << "======================================================================\n\n" << Terminal::Color(ColorRole::Reset);
    }

    void DraculaShell::HandleVersion(const std::vector<std::string>& args) {
        PrintVersion();
    }

    void DraculaShell::HandleClear(const std::vector<std::string>& args) {
#ifdef _WIN32
        system("cls");
#else
        system("clear");
#endif
    }

    void DraculaShell::HandleHelp(const std::vector<std::string>& args) {
        std::string specific = args.empty() ? "" : args[0];
        PrintHelp(specific);
    }

    void DraculaShell::HandleExit(const std::vector<std::string>& args) {
        m_running = false;
    }

    int DraculaShell::ProcessArgs(int argc, char* argv[]) {
        TerminalGuard termGuard;

        // Check for global flags like --no-color
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--no-color") {
                Terminal::SetColorEnabled(false);
            }
            if (arg == "--no-unicode") {
                Terminal::SetUnicodeEnabled(false);
            }
        }

        if (argc <= 1) {
            return RunInteractive();
        }

        std::string arg1 = argv[1];

        // MCP stdio mode must be completely clean (no banners, no colors)
        if (arg1 == "--mcp") {
            McpServer mcp;
            mcp.RunStdio();
            return 0;
        }

        if (arg1 == "--help" || arg1 == "-h") {
            PrintHelp("");
            return 0;
        }

        if (arg1 == "--version" || arg1 == "-v") {
            PrintVersion();
            return 0;
        }

        if (arg1 == "--changelog") {
            HandleChangelog({});
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
        else if (arg1 == "--functions") command = "functions";
        else if (arg1 == "--xrefs") command = "xrefs";
        else if (arg1 == "--findings") command = "findings";
        else if (arg1 == "--report") command = "report";
        else if (arg1 == "--session") command = "session";
        else if (arg1 == "--no-color" || arg1 == "--no-unicode") {
            // If only flag provided without command, run interactive
            if (argc == 2) return RunInteractive();
            return 0;
        } else {
            // Default: treat argv[1] as binary to analyze
            command = "analyze";
            cmdArgs.push_back(arg1);
        }

        for (int i = 2; i < argc; ++i) {
            std::string a = argv[i];
            if (a != "--no-color" && a != "--no-unicode") {
                cmdArgs.push_back(a);
            }
        }

        std::string cmdLine = "/" + command;
        for (const auto& a : cmdArgs) cmdLine += " \"" + a + "\"";

        ExecuteCommand(cmdLine);
        return 0;
    }

} // namespace Dracula
