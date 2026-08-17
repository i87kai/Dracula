#include "cli/dracula_shell.h"
#include "cli/terminal.h"
#include "cli/text_layout.h"
#include "cli/startup_card.h"
#include "cli/ui.h"
#include "common/version.h"
#include "common/paths.h"
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

    namespace {

        void StripQuotes(std::string& s) {
            if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
                s = s.substr(1, s.size() - 2);
            }
        }

        std::string C(ColorRole role) { return Terminal::Color(role); }
        std::string R() { return Terminal::Color(ColorRole::Reset); }

        const CommandDefinition* Cmd(const std::string& name) {
            return CommandRegistry::Instance().Find(name);
        }

        // Report a missing target file consistently for every inspection
        // command, using the command's own registry metadata.
        void ReportMissingTarget(const std::string& commandName) {
            const auto* def = Cmd(commandName);
            const std::string reason =
                "No file given and no active sample. Run /analyze <file> first, "
                "or pass a path.";
            if (def) {
                Ui::MissingArgument(*def, reason);
            } else {
                Ui::UsageHint(reason, "/" + commandName + " [file]");
            }
        }

        std::string Hex(uint64_t v) {
            std::ostringstream ss;
            ss << "0x" << std::hex << v;
            return ss.str();
        }

        std::string Fixed(double v, int precision = 2) {
            std::ostringstream ss;
            ss << std::fixed << std::setprecision(precision) << v;
            return ss.str();
        }

        // Preferred display order for the command palette and /help.
        int CategoryRank(const std::string& category) {
            if (category == "Analysis")   return 0;
            if (category == "Inspection") return 1;
            if (category == "Emulation")  return 2;
            if (category == "Session")    return 3;
            if (category == "System")     return 4;
            return 5;
        }

    } // namespace

    DraculaShell::DraculaShell() = default;
    DraculaShell::~DraculaShell() = default;

    std::string DraculaShell::GetVersion() {
        return Version::String;
    }

    void DraculaShell::PrintVersion() {
        std::cout << C(ColorRole::Title) << "Dracula v" << Version::String << R()
                  << C(ColorRole::Muted) << "  " << Version::BuildTarget << R() << "\n\n";
        Ui::KeyValue("Architecture", "x86_64");
        Ui::KeyValue("Build", "Release");
        Ui::KeyValue("Release date", Version::ReleaseDate);
        Ui::KeyValue("Engines", "Capstone 5.0.1, Unicorn 2, Win32 HLE, Safe PE, MCP Server");
        std::cout << "\n";
    }

    void DraculaShell::PrintBanner() {
        // Artwork belongs to a real console. When stdout is redirected the REPL
        // announces itself with a single plain line instead.
        if (!Terminal::IsInteractive()) {
            PrintCompactHeader();
            return;
        }

        const int width = Terminal::GetWidth();
        for (const auto& line : StartupCard::Render(width, StartupInfo::Detect())) {
            std::cout << line << "\n";
        }
        std::cout << std::flush;
    }

    void DraculaShell::PrintCompactHeader() {
        std::cout << "\n " << C(ColorRole::Title) << "Dracula" << R()
                  << C(ColorRole::Muted) << "  v" << Version::String
                  << "   " << Terminal::Bullet() << "   Type / to browse commands"
                  << R() << "\n\n";
    }

    void DraculaShell::PrintHelp(const std::string& specificCommand) {
        auto& registry = CommandRegistry::Instance();

        // ── Detailed help for one command ───────────────────────────────────
        if (!specificCommand.empty()) {
            const auto* cmd = registry.Find(specificCommand);
            if (!cmd) {
                Ui::Error("Unknown command: '" + specificCommand + "'");
                Ui::Note("Type /help for the full command reference.");
                return;
            }

            std::cout << "\n  " << C(ColorRole::Command) << "/" << cmd->name << R()
                      << C(ColorRole::Muted) << "   " << cmd->category << R() << "\n\n";
            std::cout << "  " << C(ColorRole::Text) << cmd->description << R() << "\n";

            if (!cmd->detailedHelp.empty()) {
                std::cout << "\n";
                for (const auto& line : Text::Wrap(cmd->detailedHelp, Ui::ContentWidth() - 2)) {
                    std::cout << "  " << C(ColorRole::Muted) << line << R() << "\n";
                }
            }

            std::cout << "\n  " << C(ColorRole::Muted) << "Usage" << R() << "\n"
                      << "    " << C(ColorRole::Technical) << cmd->usage << R() << "\n";

            if (!cmd->aliases.empty()) {
                std::string aliases;
                for (size_t i = 0; i < cmd->aliases.size(); ++i) {
                    if (i) aliases += ", ";
                    aliases += "/" + cmd->aliases[i];
                }
                std::cout << "\n  " << C(ColorRole::Muted) << "Aliases" << R() << "\n"
                          << "    " << C(ColorRole::Secondary) << aliases << R() << "\n";
            }

            // Arguments section, generated entirely from registry metadata.
            std::vector<std::pair<std::string, std::string>> arguments;
            if (cmd->takesFilePath) {
                arguments.emplace_back("file", "Optional when an active sample exists");
            }
            {
                // Positional values only: entries that are really flags are
                // documented by their own row below.
                std::string values;
                for (const auto& v : cmd->argCompletions) {
                    bool isFlag = false;
                    for (const auto& [flag, _] : cmd->flagCompletions) {
                        if (flag == v) isFlag = true;
                    }
                    if (isFlag) continue;
                    if (!values.empty()) values += " | ";
                    values += v;
                }
                if (!values.empty()) arguments.emplace_back("values", values);
            }
            for (const auto& [flag, values] : cmd->flagCompletions) {
                std::string joined;
                for (size_t i = 0; i < values.size(); ++i) {
                    if (i) joined += " | ";
                    joined += values[i];
                }
                arguments.emplace_back(flag, joined);
            }

            if (!arguments.empty()) {
                std::cout << "\n  " << C(ColorRole::Muted) << "Arguments" << R() << "\n";
                size_t nameCol = 0;
                for (const auto& [name, _] : arguments) {
                    nameCol = std::max(nameCol, Text::VisibleWidth(name));
                }
                nameCol += 3;
                for (const auto& [name, detail] : arguments) {
                    std::cout << "    " << C(ColorRole::Technical) << Text::PadRight(name, nameCol) << R()
                              << C(ColorRole::Muted)
                              << Text::Truncate(detail, Ui::ContentWidth() - nameCol - 6) << R() << "\n";
                }
            }

            if (!cmd->examples.empty()) {
                std::cout << "\n  " << C(ColorRole::Muted) << "Examples" << R() << "\n";
                for (const auto& ex : cmd->examples) {
                    std::cout << "    " << C(ColorRole::Technical) << ex << R() << "\n";
                }
            }
            std::cout << "\n";
            return;
        }

        // ── Grouped overview ────────────────────────────────────────────────
        std::cout << "\n  " << C(ColorRole::Title) << "Dracula" << R()
                  << C(ColorRole::Muted) << "  command reference   " << Terminal::Bullet()
                  << "   v" << Version::String << R() << "\n";

        auto categories = registry.GetCategories();
        std::sort(categories.begin(), categories.end(),
                  [](const std::string& a, const std::string& b) {
                      int ra = CategoryRank(a), rb = CategoryRank(b);
                      return ra != rb ? ra < rb : a < b;
                  });

        // Align every description at the same column across all groups.
        size_t nameWidth = 0;
        for (const auto& cmd : registry.GetAllCommands()) {
            nameWidth = std::max(nameWidth, Text::VisibleWidth("/" + cmd.name));
        }
        nameWidth += 3;

        const size_t descWidth = Ui::ContentWidth() > nameWidth + 6
                               ? Ui::ContentWidth() - nameWidth - 6
                               : 20;

        for (const auto& cat : categories) {
            std::cout << "\n  " << C(ColorRole::Accent) << cat << R() << "\n";
            for (const auto* cmd : registry.GetCommandsByCategory(cat)) {
                std::cout << "    "
                          << C(ColorRole::Command)
                          << Text::PadRight("/" + cmd->name, nameWidth) << R()
                          << C(ColorRole::Muted)
                          << Text::Truncate(cmd->description, descWidth) << R() << "\n";
            }
        }

        std::cout << "\n  " << C(ColorRole::Muted) << "Type " << R()
                  << C(ColorRole::Primary) << "/" << R()
                  << C(ColorRole::Muted) << " to browse commands interactively   "
                  << Terminal::Bullet() << "   " << R()
                  << C(ColorRole::Technical) << "/help <command>" << R()
                  << C(ColorRole::Muted) << " for details" << R() << "\n\n";
    }

    std::string DraculaShell::ResolveTargetFile(const std::vector<std::string>& args, size_t index) {
        if (args.size() > index && !args[index].empty() && args[index].rfind("--", 0) != 0) {
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

    std::string DraculaShell::SessionStatusLine() const {
        if (m_activeFile.empty()) return "";

        std::string name;
        try {
            name = std::filesystem::path(m_activeFile).filename().string();
        } catch (...) {
            name = m_activeFile;
        }
        if (name.empty()) name = m_activeFile;

        std::string line = "sample: " + name;
        if (m_sessionResult) {
            if (!m_sessionResult->sample.architecture.empty()) {
                line += "  " + Terminal::Bullet() + "  " + m_sessionResult->sample.architecture;
            }
            line += "  " + Terminal::Bullet() + "  " +
                    std::to_string(m_sessionResult->findings.size()) + " findings";
            line += "  " + Terminal::Bullet() + "  score " +
                    std::to_string(m_sessionResult->threatScore);
        }
        return line;
    }

    int DraculaShell::RunInteractive() {
        PrintBanner();
        m_running = true;

        std::string lastStatus;

        while (m_running) {
            // Subtle, non-repeating session status directly above the prompt.
            std::string status = SessionStatusLine();
            if (!status.empty() && status != lastStatus) {
                std::cout << " " << C(ColorRole::Muted)
                          << Text::Truncate(status, Ui::ContentWidth())
                          << R() << "\n";
            }
            lastStatus = status;

            std::string prompt = Terminal::DraculaPrompt();
            std::string line;

            if (!m_editor.ReadLine(prompt, line)) {
                break; // EOF
            }

            if (line.empty()) continue;

            try {
                ExecuteCommand(line);
            } catch (const std::exception& ex) {
                Ui::Error(std::string("Command failed: ") + ex.what());
            } catch (...) {
                Ui::Error("Command failed with an unknown error.");
            }
            // Whatever a command printed, the console returns to a known state.
            Console::ResetStyle();
        }

        Console::ResetStyle();
        std::cout << "\n " << C(ColorRole::Muted) << "Session closed." << R() << "\n\n";
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
            Ui::Error("Unknown command: '" + tokens[0] + "'");
            Ui::Note("Type / to browse commands, or /help for the full reference.");
        }

        return true;
    }

    // ─── Analysis ───────────────────────────────────────────────────────────

    void DraculaShell::HandleAnalyze(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            const auto* def = Cmd("analyze");
            if (def) {
                Ui::MissingArgument(*def, "Missing target binary.",
                                    "Pass a path to a PE file to start a session.");
            }
            return;
        }

        Ui::Info("Running the Dracula pipeline on " + file);

        OrchestratorOptions opts;
        opts.enableEmulation = true;
        auto res = m_orchestrator.AnalyzeFile(file, opts);

        m_sessionResult = std::make_unique<UnifiedAnalysisResult>(res);
        std::cout << res.ToAnsiSummary();
        Ui::Success("Active sample set to " + file);
    }

    void DraculaShell::HandleEmulate(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            ReportMissingTarget("emulate");
            return;
        }

        UnicornAnalyzer emu;
        EmulationOptions opts;
        opts.maxInstructions = 10000;
        opts.strictSandbox = false;

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

        Ui::Section("CPU Emulation", "Unicorn 2");
        Ui::KeyState("Status", res.success ? Ui::State::Good : Ui::State::Bad,
                     res.success ? "Completed" : "Faulted / halted");
        Ui::KeyValue("Stop reason", StopReasonToString(res.stopReason));
        Ui::KeyValue("Instructions", Ui::Number(res.instructionsExecuted));
        Ui::KeyValue("Start address", Hex(res.startAddress));
        Ui::KeyValue("Stop address", Hex(res.stopAddress));

        if (!res.registers.empty()) {
            Ui::Group("Registers");
            Text::Table table({{"", 5, 6, false}, {"", 18, 18, false},
                               {"", 5, 6, false}, {"", 18, 18, false}});
            std::vector<std::string> pending;
            for (const auto& [name, val] : res.registers) {
                pending.push_back(name);
                std::ostringstream ss;
                ss << "0x" << std::hex << std::setw(16) << std::setfill('0') << val;
                pending.push_back(ss.str());
                if (pending.size() == 4) {
                    table.AddRow(pending);
                    pending.clear();
                }
            }
            if (!pending.empty()) table.AddRow(pending);
            Ui::Lines(table.Render(Ui::ContentWidth()));
        }

        if (!res.hleCalls.empty()) {
            Ui::Group("Win32 HLE calls (" + std::to_string(res.hleCalls.size()) + ")");
            Text::Table table({{"API", 24, 40, false},
                               {"Return", 10, 20, false},
                               {"Detail", 10, 0, false}});
            for (const auto& c : res.hleCalls) {
                table.AddRow({c.library + "!" + c.apiName, Hex(c.returnValue), c.details});
            }
            Ui::Lines(table.Render(Ui::ContentWidth(), C(ColorRole::Muted), R()));
        }
        std::cout << "\n";
    }

    void DraculaShell::HandleDisasm(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            ReportMissingTarget("disasm");
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            Ui::Error("PE parse error: " + err);
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
            Ui::Error("Invalid RVA " + Hex(targetRva) + " for this image.");
            return;
        }

        Disassembler disasm(inspector.GetMetadata().is64Bit ? Architecture::X86_64 : Architecture::X86_32);
        size_t codeSize = std::min<size_t>(count * 15, inspector.GetBufferSize() - fileOffset);
        auto instructions = disasm.Disassemble(inspector.GetBuffer() + fileOffset, codeSize,
                                               inspector.GetMetadata().imageBase + targetRva, targetRva);

        Ui::Section("Disassembly",
                    "RVA " + Hex(targetRva) + "  " + Terminal::Bullet() + "  VA " +
                    Hex(inspector.GetMetadata().imageBase + targetRva));

        size_t shown = std::min(count, instructions.size());
        for (size_t i = 0; i < shown; ++i) {
            std::cout << "  " << Disassembler::FormatInstruction(instructions[i], Terminal::SupportsColor()) << "\n";
        }
        Ui::Truncated(shown, instructions.size(), "instructions",
                      "/disasm [file] [rva] [count]");
        std::cout << "\n";
    }

    void DraculaShell::HandleCfg(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            ReportMissingTarget("cfg");
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            Ui::Error("PE parse error: " + err);
            return;
        }

        uint64_t targetRva = inspector.GetMetadata().entryPointRva;
        if (args.size() > 1) {
            try { targetRva = std::stoull(args[1], nullptr, 0); } catch (...) {}
        }

        uint64_t fileOffset = inspector.RvaToFileOffset(targetRva);
        if (fileOffset >= inspector.GetBufferSize()) {
            Ui::Error("Invalid RVA " + Hex(targetRva) + " for this image.");
            return;
        }

        CfgAnalyzer cfg;
        Architecture arch = inspector.GetMetadata().is64Bit ? Architecture::X86_64 : Architecture::X86_32;
        size_t codeSize = std::min<size_t>(0x2000, inspector.GetBufferSize() - fileOffset);
        auto graph = cfg.BuildFunctionGraph(inspector.GetBuffer() + fileOffset, codeSize,
                                            inspector.GetMetadata().imageBase + targetRva,
                                            targetRva, arch, 500);

        Ui::Section("Control Flow Graph", "RVA " + Hex(targetRva));
        std::cout << CfgAnalyzer::RenderGraph(graph, Terminal::SupportsColor());
    }

    // ─── Inspection ─────────────────────────────────────────────────────────

    void DraculaShell::HandleHeaders(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            ReportMissingTarget("headers");
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            Ui::Error("PE parse error: " + err);
            return;
        }

        const auto& m = inspector.GetMetadata();
        Ui::Section("PE Headers", m.fileName);
        Ui::KeyValue("File size", Ui::Number(m.fileSize) + " bytes");
        Ui::KeyValue("Architecture", m.architecture);
        Ui::KeyValue("Subsystem", m.subsystem);
        Ui::KeyValue("Image base", Hex(m.imageBase));
        Ui::KeyValue("Entry point", Hex(m.entryPointRva) + "   VA " + Hex(m.imageBase + m.entryPointRva));
        Ui::KeyValue("Sections", std::to_string(m.sectionCount));
        Ui::KeyValue("Type", m.isDll ? "DLL" : "Executable");

        Ui::Group("Sections");
        Text::Table table({{"Name", 8, 16, false},
                           {"Virtual", 12, 14, false},
                           {"VSize", 10, 12, false},
                           {"RawSize", 10, 12, false},
                           {"Entropy", 7, 9, true},
                           {"Perms", 5, 6, false}});
        for (const auto& s : inspector.GetSections()) {
            std::string perms;
            perms += s.isReadable ? "R" : "-";
            perms += s.isWritable ? "W" : "-";
            perms += s.isExecutable ? "X" : "-";
            table.AddRow({s.name, Hex(s.virtualAddress), Hex(s.virtualSize),
                          Hex(s.rawSize),
                          Fixed(s.entropy) + (s.isHighEntropy ? "!" : " "),
                          perms});
        }
        Ui::Lines(table.Render(Ui::ContentWidth(), C(ColorRole::Muted), R()));
        std::cout << "\n";
    }

    void DraculaShell::HandleSecurity(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            ReportMissingTarget("security");
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            Ui::Error("PE parse error: " + err);
            return;
        }

        const auto& sec = inspector.GetMitigations();
        Ui::Section("Security Mitigations", inspector.GetMetadata().fileName);

        Ui::KeyState("ASLR", sec.hasAslr ? Ui::State::Good : Ui::State::Bad,
                     sec.hasAslr ? "Enabled" : "Disabled");
        Ui::KeyState("High-entropy ASLR", sec.hasHighEntropyAslr ? Ui::State::Good : Ui::State::Warn,
                     sec.hasHighEntropyAslr ? "Enabled" : "Disabled");
        Ui::KeyState("DEP / NX", sec.hasDep ? Ui::State::Good : Ui::State::Bad,
                     sec.hasDep ? "Enabled" : "Disabled");
        Ui::KeyState("Control Flow Guard", sec.hasCfg ? Ui::State::Good : Ui::State::Warn,
                     sec.hasCfg ? "Enabled" : "Disabled");
        Ui::KeyState("SEH", sec.hasSeh ? Ui::State::Good : Ui::State::Warn,
                     sec.hasSeh ? "Enabled" : "Disabled");
        Ui::KeyState("Authenticode", sec.hasAuthenticode ? Ui::State::Good : Ui::State::Warn,
                     sec.hasAuthenticode ? "Signed" : "Unsigned");
        Ui::KeyState("RWX sections", sec.hasRwxSections ? Ui::State::Bad : Ui::State::Good,
                     sec.hasRwxSections ? "Present" : "None");
        Ui::KeyState(".NET managed", Ui::State::Neutral, sec.isDotNet ? "Yes" : "No");
        std::cout << "\n";
    }

    void DraculaShell::HandleImports(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            ReportMissingTarget("imports");
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            Ui::Error("PE parse error: " + err);
            return;
        }

        const auto& imports = inspector.GetImports();
        Ui::Section("Imports", Ui::Number(imports.size()) + " entries");

        constexpr size_t kLimit = 80;
        Text::Table table({{"DLL", 14, 24, false},
                           {"Function", 20, 38, false},
                           {"IAT", 10, 12, false},
                           {"Risk", 4, 0, false}});
        size_t shown = std::min(kLimit, imports.size());
        for (size_t i = 0; i < shown; ++i) {
            const auto& imp = imports[i];
            std::string risk = imp.isDangerous
                             ? C(ColorRole::Warning) + imp.riskDescription + R()
                             : "";
            table.AddRow({imp.dllName, imp.functionName, Hex(imp.iatRva), risk});
        }
        Ui::Lines(table.Render(Ui::ContentWidth(), C(ColorRole::Muted), R()));
        Ui::Truncated(shown, imports.size(), "imports");
        std::cout << "\n";
    }

    void DraculaShell::HandleExports(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            ReportMissingTarget("exports");
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            Ui::Error("PE parse error: " + err);
            return;
        }

        const auto& exports = inspector.GetExports();
        Ui::Section("Exports", Ui::Number(exports.size()) + " entries");

        if (exports.empty()) {
            Ui::Note("This image exports no symbols.");
            std::cout << "\n";
            return;
        }

        constexpr size_t kLimit = 100;
        Text::Table table({{"Ordinal", 7, 9, true},
                           {"Name", 24, 44, false},
                           {"RVA", 10, 12, false},
                           {"Forwarder", 10, 0, false}});
        size_t shown = std::min(kLimit, exports.size());
        for (size_t i = 0; i < shown; ++i) {
            const auto& e = exports[i];
            table.AddRow({std::to_string(e.ordinal), e.functionName, Hex(e.rva), e.forwarderName});
        }
        Ui::Lines(table.Render(Ui::ContentWidth(), C(ColorRole::Muted), R()));
        Ui::Truncated(shown, exports.size(), "exports");
        std::cout << "\n";
    }

    void DraculaShell::HandleStrings(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            ReportMissingTarget("strings");
            return;
        }

        bool showAll = false;
        size_t minLen = 5;
        for (size_t i = 0; i < args.size(); ++i) {
            if (args[i] == "--all") { showAll = true; continue; }
            if (i == 0) continue;   // the file argument
            try { minLen = std::stoul(args[i]); } catch (...) {}
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            Ui::Error("PE parse error: " + err);
            return;
        }

        StringsAnalyzer sa;
        auto strings = sa.ExtractStrings(inspector.GetBuffer(), inspector.GetBufferSize(), minLen);

        // Interesting (classified) strings first: those are the ones an analyst
        // actually wants to see.
        std::vector<const ExtractedString*> interesting;
        for (const auto& s : strings) {
            if (showAll || s.category != StringCategory::Generic) {
                interesting.push_back(&s);
            }
        }

        Ui::Section("Strings",
                    Ui::Number(strings.size()) + " extracted   " + Terminal::Bullet() +
                    "   min length " + std::to_string(minLen));

        const size_t limit = showAll ? 200 : 50;
        const size_t shown = std::min(limit, interesting.size());

        Text::Table table({{"Category", 12, 16, false},
                           {"Offset", 10, 12, false},
                           {"Value", 20, 0, false}});
        for (size_t i = 0; i < shown; ++i) {
            table.AddRow({StringCategoryToString(interesting[i]->category),
                          Hex(interesting[i]->fileOffset),
                          interesting[i]->value});
        }
        Ui::Lines(table.Render(Ui::ContentWidth(), C(ColorRole::Muted), R()));
        Ui::Truncated(shown, interesting.size(),
                      showAll ? "strings" : "classified strings",
                      showAll ? "" : "/strings --all for everything");
        std::cout << "\n";
    }

    void DraculaShell::HandleEntropy(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            ReportMissingTarget("entropy");
            return;
        }

        auto info = EntropyAnalyzer::AnalyzeBinary(file);
        Ui::Section("Entropy", "Shannon, 0.00 - 8.00");
        Ui::KeyValue("Overall entropy", Fixed(info.overallEntropy) + " / 8.00");
        Ui::KeyState("Verdict", info.isPacked ? Ui::State::Bad : Ui::State::Good,
                     info.isPacked ? "Packed or encrypted" : "Normal (unpacked)");
        if (!info.detectedPacker.empty()) {
            Ui::KeyState("Detected packer", Ui::State::Warn, info.detectedPacker);
        }

        Ui::Group("Sections");
        for (const auto& s : info.sections) {
            int barLen = static_cast<int>((s.entropy / 8.0) * 24.0);
            barLen = std::clamp(barLen, 0, 24);
            const std::string filled = Terminal::SupportsUnicode() ? "\xE2\x96\x88" : "#";
            const std::string empty  = Terminal::SupportsUnicode() ? "\xE2\x96\x91" : ".";

            std::string bar = C(s.isPacked ? ColorRole::Warning : ColorRole::Technical) +
                              Text::Repeat(filled, static_cast<size_t>(barLen)) + R() +
                              C(ColorRole::Border) +
                              Text::Repeat(empty, static_cast<size_t>(24 - barLen)) + R();

            std::cout << "  " << C(ColorRole::Muted) << Text::PadRight(s.name, 12) << R()
                      << bar << "  " << C(ColorRole::Text) << Fixed(s.entropy) << R() << "\n";
        }
        std::cout << "\n";
    }

    void DraculaShell::HandleScan(const std::vector<std::string>& args) {
        const auto* def = Cmd("scan");

        std::string file;
        std::string pattern;

        // Accept: /scan <pattern>            (active sample)
        //         /scan <file> <pattern>
        if (args.empty()) {
            if (def) {
                Ui::MissingArgument(*def, "Missing hex pattern.");
            }
            return;
        }

        if (args.size() == 1) {
            file = m_activeFile;
            pattern = args[0];
            if (file.empty()) {
                if (def) {
                    Ui::MissingArgument(*def,
                        "No active sample, so both a file and a pattern are required.");
                }
                return;
            }
        } else {
            file = args[0];
            StripQuotes(file);
            pattern = args[1];
            for (size_t i = 2; i < args.size(); ++i) pattern += " " + args[i];
            m_activeFile = file;
        }
        StripQuotes(pattern);

        auto matches = PatternScanner::ScanFile(file, pattern);
        Ui::Section("Pattern Scan", Ui::Number(matches.size()) + " matches");
        Ui::KeyValue("Pattern", pattern);
        Ui::KeyValue("File", file);

        if (matches.empty()) {
            Ui::Note("No occurrences of this pattern were found.");
            std::cout << "\n";
            return;
        }

        Ui::Group("Matches");
        constexpr size_t kLimit = 100;
        size_t shown = std::min(kLimit, matches.size());
        for (size_t i = 0; i < shown; ++i) {
            std::cout << "  " << C(ColorRole::Muted) << "file offset  " << R()
                      << C(ColorRole::Technical) << Hex(matches[i]) << R() << "\n";
        }
        Ui::Truncated(shown, matches.size(), "matches");
        std::cout << "\n";
    }

    void DraculaShell::HandleSandbox(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            ReportMissingTarget("sandbox");
            return;
        }

        Ui::Info("Launching the QEMU hardware sandbox for " + file);
        auto res = m_orchestrator.RunDynamicSandbox(file, 60);
        m_sessionResult = std::make_unique<UnifiedAnalysisResult>(res);
        std::cout << res.ToAnsiSummary();
    }

    void DraculaShell::HandleFunctions(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            ReportMissingTarget("functions");
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            Ui::Error("PE parse error: " + err);
            return;
        }

        const auto& m = inspector.GetMetadata();
        Ui::Section("Functions", m.fileName);

        Text::Table table({{"Kind", 10, 12, false},
                           {"RVA", 10, 12, false},
                           {"VA", 18, 20, false},
                           {"Name", 10, 0, false}});
        table.AddRow({"entry", Hex(m.entryPointRva), Hex(m.imageBase + m.entryPointRva), "EntryPoint"});
        for (const auto& exp : inspector.GetExports()) {
            table.AddRow({"export", Hex(exp.rva), Hex(m.imageBase + exp.rva), exp.functionName});
        }
        Ui::Lines(table.Render(Ui::ContentWidth(), C(ColorRole::Muted), R()));
        std::cout << "\n";
    }

    void DraculaShell::HandleXrefs(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            ReportMissingTarget("xrefs");
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            Ui::Error("PE parse error: " + err);
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

        Ui::Section("Cross References", Ui::Number(xrefs.size()) + " references");

        constexpr size_t kLimit = 50;
        size_t shown = std::min(kLimit, xrefs.size());
        Text::Table table({{"From", 10, 12, false},
                           {"Type", 8, 14, false},
                           {"To", 10, 12, false},
                           {"Target", 10, 0, false}});
        for (size_t i = 0; i < shown; ++i) {
            const auto& x = xrefs[i];
            table.AddRow({Hex(x.fromRva), XRefTypeToString(x.type), Hex(x.toRva), x.targetName});
        }
        Ui::Lines(table.Render(Ui::ContentWidth(), C(ColorRole::Muted), R()));
        Ui::Truncated(shown, xrefs.size(), "cross references");
        std::cout << "\n";
    }

    // ─── Session ────────────────────────────────────────────────────────────

    void DraculaShell::HandleFindings(const std::vector<std::string>& args) {
        if (!m_sessionResult) {
            Ui::UsageHint("No active analysis session.",
                          "/findings",
                          "/analyze samples\\test_sample.exe",
                          "Run /analyze <file> first to populate the session.");
            return;
        }

        const auto& findings = m_sessionResult->findings;
        Ui::Section("Findings", Ui::Number(findings.size()) + " recorded");

        if (findings.empty()) {
            Ui::Note("The pipeline produced no findings for this sample.");
            std::cout << "\n";
            return;
        }

        for (const auto& f : findings) {
            ColorRole role = ColorRole::Muted;
            std::string label = "INFO";
            switch (f.severity) {
                case FindingSeverity::Critical: role = ColorRole::Error;   label = "CRITICAL"; break;
                case FindingSeverity::High:     role = ColorRole::Error;   label = "HIGH";     break;
                case FindingSeverity::Medium:   role = ColorRole::Warning; label = "MEDIUM";   break;
                case FindingSeverity::Low:      role = ColorRole::Info;    label = "LOW";      break;
                default:                        role = ColorRole::Muted;   label = "INFO";     break;
            }

            std::cout << "  " << C(role) << Text::PadRight(label, 9) << R()
                      << C(ColorRole::Command) << f.title << R()
                      << C(ColorRole::Muted) << "   " << f.id << R() << "\n";
            std::cout << "  " << std::string(9, ' ') << C(ColorRole::Muted)
                      << f.category << " " << Terminal::Bullet() << " " << f.source << R() << "\n";
            for (const auto& line : Text::Wrap(f.evidence, Ui::ContentWidth() - 11)) {
                std::cout << "  " << std::string(9, ' ') << C(ColorRole::Text) << line << R() << "\n";
            }
            std::cout << "\n";
        }
    }

    void DraculaShell::HandleReport(const std::vector<std::string>& args) {
        if (!m_sessionResult) {
            Ui::UsageHint("No active analysis session to export.",
                          "/report [json|md|txt] [output_path]",
                          "/report md report.md",
                          "Run /analyze <file> first to populate the session.");
            return;
        }

        std::string format = args.empty() ? "json" : args[0];
        std::string outFile = "dracula_report." + format;
        if (args.size() > 1) outFile = args[1];

        if (ReportWriter::SaveReport(*m_sessionResult, outFile, format)) {
            Ui::Success("Report written to " + std::filesystem::absolute(outFile).string());
        } else {
            Ui::Error("Failed to write report to " + outFile);
        }
    }

    void DraculaShell::HandleSession(const std::vector<std::string>& args) {
        if (!m_sessionResult) {
            if (!m_activeFile.empty()) {
                Ui::Section("Session", "no analysis result");
                Ui::KeyValue("Active sample", m_activeFile);
                Ui::Note("Run /analyze to populate findings for this sample.");
                std::cout << "\n";
                return;
            }
            Ui::UsageHint("No active session.",
                          "/analyze <file>",
                          "/analyze samples\\test_sample.exe",
                          "Inspection commands reuse the active sample once one is set.");
            return;
        }

        const auto& s = m_sessionResult->sample;
        Ui::Section("Session", s.fileName);
        Ui::KeyValue("File path", s.filePath);
        Ui::KeyValue("Size", Ui::Number(s.fileSize) + " bytes");
        Ui::KeyValue("SHA-256", s.sha256);
        Ui::KeyValue("Architecture", s.architecture);
        Ui::KeyValue("Threat score", std::to_string(m_sessionResult->threatScore) + " / 100   " +
                                     m_sessionResult->threatLevel);
        Ui::KeyValue("Findings", Ui::Number(m_sessionResult->findings.size()));
        std::cout << "\n";
    }

    // ─── System ─────────────────────────────────────────────────────────────

    void DraculaShell::HandleMcp(const std::vector<std::string>& args) {
        McpServer mcp;
        mcp.RunStdio();
    }

    void DraculaShell::HandleChangelog(const std::vector<std::string>& args) {
        // Resolved relative to the executable / install root, never relative to
        // whatever directory the user happened to launch Dracula from.
        std::string changelogPath = Paths::ResolveResource("CHANGELOG.txt");

        if (changelogPath.empty()) {
            Ui::Error("CHANGELOG.txt could not be located.");
            Ui::Note("Searched the working directory, the install root and the executable directory.");
            return;
        }

        std::ifstream file(changelogPath);
        if (!file.is_open()) {
            Ui::Error("Could not open " + changelogPath);
            return;
        }

        std::string filterVer = args.empty() ? "" : args[0];
        if (!filterVer.empty() && filterVer.front() == 'v') filterVer = filterVer.substr(1);

        Ui::Section("Changelog", filterVer.empty() ? changelogPath : ("v" + filterVer));

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
            if (!inTargetSection) continue;

            if (line.find("=====") != std::string::npos ||
                line.find("-----") != std::string::npos) {
                std::cout << "  " << C(ColorRole::Border)
                          << Text::Truncate(line, Ui::ContentWidth() - 2) << R() << "\n";
            } else if (line.find("Dracula v") != std::string::npos) {
                std::cout << "  " << C(ColorRole::Title) << line << R() << "\n";
            } else if (line == "Added" || line == "Changed" || line == "Fixed" || line == "Verified") {
                std::cout << "  " << C(ColorRole::Accent) << line << R() << "\n";
            } else {
                std::cout << "  " << C(ColorRole::Text)
                          << Text::Truncate(line, Ui::ContentWidth() - 2) << R() << "\n";
            }
        }
        std::cout << "\n";
    }

    void DraculaShell::HandleVersion(const std::vector<std::string>& args) {
        PrintVersion();
    }

    void DraculaShell::HandleClear(const std::vector<std::string>& args) {
        // Clears the viewport only. The analysis session, active sample and
        // command history are deliberately preserved.
        Console::ClearScreen();
        PrintCompactHeader();
    }

    void DraculaShell::HandleHelp(const std::vector<std::string>& args) {
        std::string specific = args.empty() ? "" : args[0];
        PrintHelp(specific);
    }

    void DraculaShell::HandleExit(const std::vector<std::string>& args) {
        m_running = false;
    }

    // ─── Entry point ────────────────────────────────────────────────────────

    int DraculaShell::ProcessArgs(int argc, char* argv[]) {
        // MCP stdio mode must be completely clean: no terminal initialization,
        // no colours, no artwork, nothing but JSON-RPC on stdout.
        for (int i = 1; i < argc; ++i) {
            if (std::string(argv[i]) == "--mcp") {
                McpServer mcp;
                mcp.RunStdio();
                return 0;
            }
        }

        TerminalGuard termGuard;

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
            if (argc == 2) return RunInteractive();
            return 0;
        } else {
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
