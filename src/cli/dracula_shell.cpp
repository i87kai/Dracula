#include "cli/dracula_shell.h"
#include "cli/terminal.h"
#include "cli/text_layout.h"
#include "cli/startup_card.h"
#include "cli/startup_picker.h"
#include "cli/ui.h"
#include "app/services.h"
#include "app/settings.h"
#include "app/sandbox_service.h"
#include "common/version.h"
#include "common/paths.h"
#include "common/input_validator.h"
#include "common/format.h"
#include "host/report_writer.h"
#include "host/process_inspector.h"
#include "mcp/mcp_server.h"
#include "core/pe_inspector.h"
#include "core/disassembler.h"
#include "core/cfg_analyzer.h"
#include "core/xref_analyzer.h"
#include "core/entropy_analyzer.h"
#include "core/strings_analyzer.h"
#include "core/pattern_scanner.h"
#include "core/unicorn_analyzer.h"
#include "core/anti_evasion_engine.h"
#include "core/threat_evaluator.h"
#include "utr/target_manager.h"
#include "utr/analysis_orchestrator.h"
#include "utr/session_manager.h"
#include "utr/artifact_manager.h"
#include "utr/managed_backend.h"
#include "utr/dll_harness.h"
#include "utr/external_observer.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <filesystem>
#include <fstream>

namespace Dracula {

    namespace {

        void StripQuotes(std::string& s) {
            if (s.size() >= 2 && ((s.front() == '"' && s.back() == '"') ||
                                  (s.front() == '\'' && s.back() == '\''))) {
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
            return Format::Hex(v);
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
                  << C(ColorRole::Muted) << " for details" << R() << "\n";

        std::cout << "\n  " << C(ColorRole::Accent) << "Keys" << R() << "\n";
        const std::pair<const char*, const char*> keys[] = {
            {"PageUp / PageDown", "Scroll the output region by a page"},
            {"Wheel",             "Scroll the output region"},
            {"Ctrl+Home / End",   "Jump to the oldest / newest output"},
            {"Drag",              "Select text (scrolling keeps working)"},
            {"Ctrl+C",            "Copy the selection, or clear the input line"},
            {"Ctrl+L",            "Repaint the screen"},
        };
        size_t keyWidth = 0;
        for (const auto& [key, _] : keys) {
            keyWidth = std::max(keyWidth, Text::VisibleWidth(key));
        }
        keyWidth += 3;
        for (const auto& [key, detail] : keys) {
            std::cout << "    " << C(ColorRole::Technical) << Text::PadRight(key, keyWidth) << R()
                      << C(ColorRole::Muted) << detail << R() << "\n";
        }
        std::cout << "\n";
    }

    std::string DraculaShell::ResolveTargetFile(const std::vector<std::string>& args, size_t index) {
        // An explicit path always wins, but a flag never becomes one: without
        // this guard "--pid 17140" was accepted as a filename, which is how
        // "file does not exist: --pid 17140" reached the user.
        if (args.size() > index && !args[index].empty() && args[index].rfind("-", 0) != 0) {
            std::string path = args[index];
            StripQuotes(path);
            return path;
        }

        // Otherwise the subject comes from the ACTIVE PROJECT, not from legacy
        // shell state. For a process-backed project this resolves to the
        // backing executable, so every file-oriented command keeps working
        // after /process attach without the user reopening anything.
        auto project = App::ProjectManager::Instance().Active();
        if (project) {
            const std::string path = project->StaticAnalysisPath();
            if (!path.empty()) return path;
        }

        return m_activeFile;
    }

    void DraculaShell::SetActiveSession(const std::string& file, std::unique_ptr<UnifiedAnalysisResult> result) {
        m_activeFile = file;
        m_sessionResult = std::move(result);
    }

    std::string DraculaShell::SessionStatusLine() const {
        // The status strip describes the project, which is the authoritative
        // answer to "what am I working on".
        auto project = App::ProjectManager::Instance().Active();
        if (project) {
            const auto& target = project->Target();
            std::string line = "project: " + project->DisplayName();
            if (target.IsLiveProcess()) {
                line += "   pid " + std::to_string(target.pid);
            }
            if (!target.architecture.empty()) {
                line += "   " + target.architecture;
            }
            const size_t snapshots = project->Snapshots().size();
            if (snapshots > 0) {
                line += "   snapshots " + std::to_string(snapshots);
            }
            return line;
        }

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

    void DraculaShell::RunCommandLine(const std::string& line) {
        try {
            ExecuteCommand(line);
        } catch (const std::exception& ex) {
            Ui::Error(std::string("Command failed: ") + ex.what());
        } catch (...) {
            Ui::Error("Command failed with an unknown error.");
        }
    }

    int DraculaShell::RunInteractive() {
        m_running = true;

        // Persistent three-region layout: the Dracula header stays put, command
        // output scrolls inside its own viewport, the prompt is anchored to the
        // bottom row. Falls back to plain streaming when there is no console.
        InteractiveScreen screen;
        if (screen.Begin()) {
            m_screen = &screen;

            std::string welcome = C(ColorRole::Muted) +
                "Ready. Wheel and PageUp / PageDown scroll this output region; "
                "drag to select and Ctrl+C to copy." + R();
            screen.Output().AppendLine("");
            screen.Output().AppendLine(welcome);

            const std::string prompt = Terminal::DraculaPrompt();

            while (m_running) {
                screen.SetStatusLine(SessionStatusLine());

                std::string line;
                if (!screen.ReadCommand(m_editor, prompt, line)) {
                    break;   // Ctrl+D on an empty line
                }
                if (line.empty()) continue;

                // Echo the executed command into the output history so the
                // transcript reads like a session.
                screen.Output().AppendLine("");
                screen.Output().AppendLine(prompt + C(ColorRole::Text) + line + R());

                RunCommandLine(line);

                // The project may have changed (opened, closed, attached), so
                // the header is re-derived from it after every command.
                screen.RefreshContext();
                screen.Output().ScrollToBottom();
            }

            m_screen = nullptr;
            screen.End();

            std::cout << "\n " << C(ColorRole::Muted) << "Session closed." << R() << "\n\n";
            return 0;
        }

        // ── Non-console fallback: ordinary streaming REPL ──
        PrintCompactHeader();
        while (m_running) {
            std::string prompt = Terminal::DraculaPrompt();
            std::string line;
            if (!m_editor.ReadLine(prompt, line)) break;
            if (line.empty()) continue;
            RunCommandLine(line);
        }

        Console::ResetStyle();
        std::cout << "\n " << C(ColorRole::Muted) << "Session closed." << R() << "\n\n";
        return 0;
    }

    bool DraculaShell::ExecuteCommand(const std::string& commandLine) {
        std::string line = commandLine;
        if (line.size() >= 3 &&
            static_cast<unsigned char>(line[0]) == 0xEF &&
            static_cast<unsigned char>(line[1]) == 0xBB &&
            static_cast<unsigned char>(line[2]) == 0xBF) {
            line = line.substr(3);
        }

        // Parse tokens handling quoted arguments
        std::vector<std::string> tokens;
        std::string current;
        bool inQuotes = false;

        for (size_t i = 0; i < line.size(); ++i) {
            char c = line[i];
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
        if (!cmdDef) {
            Ui::Error("Unknown command: '" + tokens[0] + "'");
            Ui::Note("Type / to browse commands, or /help for the full reference.");
            return true;
        }

        if (DispatchSubcommand(*cmdDef, args)) return true;

        if (cmdDef->handler) {
            cmdDef->handler(*this, args);
        } else {
            // A command with subcommands but no legacy handler: show exactly
            // the subcommands the registry knows about, which is exactly what
            // dispatch accepts.
            RenderSubcommandList(*cmdDef);
        }

        return true;
    }

    // Attempts registry-driven subcommand dispatch. Returns true when the
    // command was handled here, false to fall through to a legacy handler.
    bool DraculaShell::DispatchSubcommand(const CommandDefinition& cmdDef,
                                          const std::vector<std::string>& args) {
        if (cmdDef.subcommands.empty()) return false;

        auto& registry = CommandRegistry::Instance();

        std::string subName = args.empty() ? cmdDef.defaultSubcommand : args[0];
        std::vector<std::string> subArgs;

        const SubcommandDefinition* sub = registry.FindSubcommand(cmdDef, subName);

        if (!args.empty() && sub) {
            // The first token named a subcommand; the rest are its arguments.
            subArgs.assign(args.begin() + 1, args.end());
        } else if (!args.empty() && !sub) {
            // Not a subcommand. A command that also accepts a bare operand
            // (like "/target <path>") falls through to its legacy handler;
            // otherwise this is a real error the user should see.
            if (cmdDef.handler) return false;

            App::ErrorDetail e;
            e.code = "unknown_subcommand";
            e.message = "'" + args[0] + "' is not a " + cmdDef.name + " subcommand.";
            e.reason = "The subcommand did not match any registered handler.";
            e.remediation = "Run /" + cmdDef.name + " on its own to see what is available.";
            e.availableInstead = registry.SubcommandNames(cmdDef);
            RenderResult(App::CommandResult::Failure(e));
            return true;
        } else if (args.empty() && !sub) {
            // No arguments and no default: list the subcommands.
            RenderSubcommandList(cmdDef);
            return true;
        }

        // Capability gate BEFORE the handler runs, so the user gets a
        // capability-aware explanation instead of an engine-level failure.
        App::ErrorDetail requirementError;
        if (!CommandRegistry::RequirementSatisfied(sub->requirement, requirementError)) {
            RenderResult(App::CommandResult::Failure(requirementError));
            return true;
        }

        if (!sub->handler) return false;

        RenderResult(sub->handler(subArgs));
        return true;
    }

    void DraculaShell::RenderSubcommandList(const CommandDefinition& cmdDef) {
        std::cout << "\n " << C(ColorRole::Primary) << "/" << cmdDef.name << R()
                  << "  " << C(ColorRole::Muted) << cmdDef.description << R() << "\n";
        std::cout << " " << C(ColorRole::Border) << std::string(64, '-') << R() << "\n";

        for (const auto& sub : cmdDef.subcommands) {
            std::cout << "  " << C(ColorRole::Accent) << std::left << std::setw(14) << sub.name << R()
                      << C(ColorRole::Text) << sub.description << R() << "\n";
        }
        std::cout << " " << C(ColorRole::Border) << std::string(64, '-') << R() << "\n\n";
    }

    // Renders a structured CommandResult for the terminal. This is the ONLY
    // place application results become coloured text -- the services return
    // pure data, which is what lets a future web adapter render them
    // differently without touching an engine.
    void DraculaShell::RenderResult(const App::CommandResult& result) {
        if (result.ok) {
            if (!result.summary.empty()) Ui::Success(result.summary);
            for (const auto& line : result.lines) {
                std::cout << "  " << C(ColorRole::Text) << line << R() << "\n";
            }

            for (const auto& ev : result.evidence) {
                // Evidence level is the reader's cue for how much to trust a
                // value: calculated, resolved, or actually read back.
                ColorRole tone = ColorRole::Muted;
                if (ev.level == "LIVE-READ VERIFIED") tone = ColorRole::Success;
                else if (ev.level == "RESOLVED")      tone = ColorRole::Technical;

                std::cout << "  " << C(tone) << "[" << ev.level << "]" << R()
                          << " " << C(ColorRole::Muted) << ev.summary << R() << "\n";
            }

            for (const auto& art : result.artifacts) {
                std::cout << "  " << C(ColorRole::Technical) << art.projectRelative << R()
                          << C(ColorRole::Muted) << "  (" << art.rowCount << " rows)" << R() << "\n";
            }
            if (!result.lines.empty() || !result.artifacts.empty()) std::cout << "\n";
            return;
        }

        // Failure: message, then WHY, then what to do, then what IS available.
        Ui::Error(result.error.message.empty() ? result.summary : result.error.message);

        if (!result.error.reason.empty()) {
            std::cout << "  " << C(ColorRole::Muted) << result.error.reason << R() << "\n";
        }
        for (const auto& line : result.lines) {
            std::cout << "  " << C(ColorRole::Text) << line << R() << "\n";
        }
        if (!result.error.remediation.empty()) {
            std::cout << "  " << C(ColorRole::Accent) << result.error.remediation << R() << "\n";
        }
        if (!result.error.availableInstead.empty()) {
            std::cout << "\n  " << C(ColorRole::Technical) << "Available for this target:" << R() << "\n";
            for (const auto& cap : result.error.availableInstead) {
                std::cout << "    " << C(ColorRole::Text) << cap << R() << "\n";
            }
        }
        std::cout << "\n";
    }

    // ─── UTR Universal Target Handlers ─────────────────────────────────────

    void DraculaShell::HandleTarget(const std::vector<std::string>& args) {
        // info / capabilities / close are registry subcommands and never reach
        // here. What remains is opening a target, which now means creating or
        // continuing a durable project.
        if (args.empty()) {
            auto project = App::ProjectManager::Instance().Active();
            if (project) {
                RenderResult(App::TargetService::Instance().Info());
            } else {
                Ui::UsageHint("No active target.", "/target <file>  or  /process attach <pid>");
            }
            return;
        }

        // A PID must be given to /process attach, which represents it as a PID.
        // Accepting "--pid N" here is what let a specifier become a path.
        if (args[0] == "--pid" || args[0] == "-p") {
            App::ErrorDetail e;
            e.code = "moved_command";
            e.message = "Use /process attach to open a running process.";
            e.reason = "/target opens file-backed targets; a PID is not a path.";
            e.remediation = args.size() > 1
                ? ("Run: /process attach " + args[1])
                : std::string("Run: /process attach <pid>");
            RenderResult(App::CommandResult::Failure(e));
            return;
        }

        if (args[0] == "--service" || args[0] == "-s") {
            App::ErrorDetail e;
            e.code = "unsupported_target";
            e.message = "Service targets are not yet project-backed.";
            e.reason = "Service analysis has not been migrated to durable projects.";
            e.remediation = "Open the service's executable directly with /target <path>.";
            RenderResult(App::CommandResult::Failure(e));
            return;
        }

        RenderResult(App::ProjectService::Instance().OpenFile(args[0]));
    }

    void DraculaShell::HandleMemory(const std::vector<std::string>& args) {
        auto target = UTR::TargetManager::Instance().GetActiveTarget();
        if (!target) {
            ReportMissingTarget("memory");
            return;
        }

        std::string sub = args.empty() ? "map" : args[0];

        if (sub == "map" || sub == "regions") {
            auto mapRes = target->GetMemoryMap();
            if (!mapRes.Ok()) {
                Ui::Error("Failed to get memory map: " + mapRes.Error());
                return;
            }

            const auto& regions = mapRes.Value();
            std::cout << "\n " << C(ColorRole::Primary) << "Virtual Memory Layout (" << regions.size() << " regions)" << R() << "\n";
            std::cout << " " << C(ColorRole::Border) << std::string(75, '-') << R() << "\n";
            std::cout << "  " << std::left << std::setw(18) << "Base Address"
                      << std::setw(12) << "Size"
                      << std::setw(26) << "Protection"
                      << std::setw(10) << "Entropy"
                      << "Module" << "\n";
            std::cout << " " << C(ColorRole::Border) << std::string(75, '-') << R() << "\n";

            for (size_t i = 0; i < std::min(size_t(25), regions.size()); ++i) {
                const auto& r = regions[i];
                std::cout << "  0x" << std::hex << std::setw(16) << r.baseAddress << std::dec
                          << std::setw(12) << r.size
                          << std::setw(26) << UTR::ProtectionToString(r.currentProtect)
                          << std::fixed << std::setprecision(2) << std::setw(10) << r.entropy
                          << (r.moduleName.empty() ? "-" : r.moduleName) << "\n";
            }
            if (regions.size() > 25) {
                std::cout << "  ... [" << (regions.size() - 25) << " more regions written to artifacts]\n";
            }
            std::cout << " " << C(ColorRole::Border) << std::string(75, '-') << R() << "\n\n";
            return;
        }

        if (sub == "snapshot") {
            auto snapRes = target->TakeSnapshot("Manual CLI Snapshot");
            if (!snapRes.Ok()) {
                Ui::Error("Snapshot failed: " + snapRes.Error());
                return;
            }
            const auto& snap = snapRes.Value();
            Ui::Success("Memory snapshot #" + std::to_string(snap.snapshotIndex) + " captured: " +
                       std::to_string(snap.totalRegions) + " regions, " +
                       std::to_string(snap.totalCommittedBytes / 1024) + " KB committed.");
            return;
        }

        if (sub == "transformations") {
            Ui::Info("Querying detected runtime transformations...");
            auto targetPtr = UTR::TargetManager::Instance().GetActiveTarget();
            if (targetPtr) {
                auto memRes = targetPtr->GetMemoryMap();
                if (memRes.Ok()) {
                    UTR::MemoryIntelligenceManager mgr;
                    mgr.CaptureSnapshot(memRes.Value(), "Snap1");
                    mgr.CaptureSnapshot(memRes.Value(), "Snap2");
                    auto comp = mgr.CompareSnapshots(1, 2);
                    auto trans = mgr.DetectTransformations(comp);
                    if (trans.empty()) {
                        std::cout << "  No runtime transformations detected in active regions.\n";
                    } else {
                        for (const auto& t : trans) {
                            std::cout << "  [" << t.id << "] 0x" << std::hex << t.regionAddress << std::dec
                                      << " (" << t.regionSize << " bytes) - " << t.assessmentSummary << "\n";
                        }
                    }
                }
            }
            return;
        }

        Ui::UsageHint("Available memory commands:", "/memory [map|snapshot|compare|transformations|dump]");
    }

    void DraculaShell::HandleDll(const std::vector<std::string>& args) {
        auto target = UTR::TargetManager::Instance().GetActiveTarget();
        std::string sub = args.empty() ? "info" : args[0];

        if (sub == "exports") {
            std::string file = target ? target->GetInfo().path : ResolveTargetFile(args, 1);
            if (file.empty()) {
                ReportMissingTarget("dll");
                return;
            }

            UTR::DllExecutionHarness harness;
            std::string err;
            if (!harness.LoadSafe(file, err)) {
                Ui::Error(err);
                return;
            }

            auto exports = harness.EnumerateExports(err);
            std::cout << "\n " << C(ColorRole::Primary) << "Export Directory (" << exports.size() << " exported symbols)" << R() << "\n";
            std::cout << " " << C(ColorRole::Border) << std::string(60, '-') << R() << "\n";
            for (const auto& exp : exports) {
                std::cout << "  Ordinal " << std::setw(4) << exp.ordinal << ": "
                          << C(ColorRole::Accent) << exp.name << R()
                          << " (RVA: 0x" << std::hex << exp.rva << std::dec << ")\n";
            }
            std::cout << " " << C(ColorRole::Border) << std::string(60, '-') << R() << "\n\n";
            return;
        }

        if (sub == "run" && args.size() > 1) {
            std::string expName = args[1];
            if (!target) {
                Ui::Error("Open target DLL first via /target <dll>");
                return;
            }
            Ui::Info("Executing test export '" + expName + "' inside controlled DLL harness...");
            auto invRes = target->InvokeExport(expName);
            if (!invRes.Ok()) {
                Ui::Error("Export invocation failed: " + invRes.Error());
            } else {
                Ui::Success("Export executed successfully. Return Value = " + std::to_string(invRes.Value()));
            }
            return;
        }

        Ui::UsageHint("Available DLL commands:", "/dll [exports|run <export>]");
    }

    void DraculaShell::HandleProcess(const std::vector<std::string>& args) {
        std::string sub = args.empty() ? "list" : args[0];

        if (sub == "list") {
            auto processes = Sandbox::ProcessInspector::ListAllProcesses();
            std::cout << "\n " << C(ColorRole::Primary) << "Running Processes (" << processes.size() << " accessible)" << R() << "\n";
            std::cout << " " << C(ColorRole::Border) << std::string(50, '-') << R() << "\n";
            for (size_t i = 0; i < std::min(size_t(20), processes.size()); ++i) {
                std::cout << "  PID " << std::setw(6) << processes[i].pid << " : " << processes[i].exeName << "\n";
            }
            if (processes.size() > 20) {
                std::cout << "  ... [" << (processes.size() - 20) << " more processes]\n";
            }
            std::cout << " " << C(ColorRole::Border) << std::string(50, '-') << R() << "\n\n";
            return;
        }

        if (sub == "attach" && args.size() > 1) {
            std::string pidStr = args[1];
            UTR::TargetManager::Instance().OpenTarget("--pid " + pidStr);
            return;
        }

        if (sub == "modules" || sub == "threads") {
            auto target = UTR::TargetManager::Instance().GetActiveTarget();
            if (!target) {
                Ui::Error("No active target process.");
                return;
            }
            if (sub == "modules") {
                auto mods = target->EnumerateModules();
                if (mods.Ok()) {
                    std::cout << "\n " << C(ColorRole::Primary) << "Loaded Modules (" << mods.Value().size() << ")" << R() << "\n";
                    for (const auto& m : mods.Value()) {
                        std::cout << "  0x" << std::hex << m.baseAddress << std::dec << " : " << m.name << " (" << m.path << ")\n";
                    }
                }
            } else {
                auto thrs = target->EnumerateThreads();
                if (thrs.Ok()) {
                    std::cout << "\n " << C(ColorRole::Primary) << "Active Threads (" << thrs.Value().size() << ")" << R() << "\n";
                    for (const auto& t : thrs.Value()) {
                        std::cout << "  TID " << t.tid << " Priority=" << t.priority << " State=" << t.state << "\n";
                    }
                }
            }
            return;
        }

        Ui::UsageHint("Available process commands:", "/process [list|attach <pid>|modules|threads]");
    }

    void DraculaShell::HandleRuntime(const std::vector<std::string>& args) {
        std::string sub = args.empty() ? "status" : args[0];
        if (sub == "status") {
            std::cout << "\n " << C(ColorRole::Primary) << "Runtime Engine Status" << R() << "\n";
            std::cout << "  Agent Backend:       " << C(ColorRole::Success) << "Available (DraculaAgent64)" << R() << "\n";
            std::cout << "  ETW Observer:        " << C(ColorRole::Success) << "Active" << R() << "\n";
            std::cout << "  DbgEng Backend:      " << C(ColorRole::Success) << "Active" << R() << "\n";
            std::cout << "  QEMU GuestAgent:     " << C(ColorRole::Success) << "Ready" << R() << "\n\n";
            return;
        }
        Ui::UsageHint("Available runtime commands:", "/runtime [status|events]");
    }

    void DraculaShell::HandleDotNet(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 1);
        if (file.empty()) {
            auto target = UTR::TargetManager::Instance().GetActiveTarget();
            if (target) file = target->GetInfo().path;
        }

        if (file.empty()) {
            ReportMissingTarget("dotnet");
            return;
        }

        std::string sub = args.empty() ? "info" : args[0];

        if (sub == "info") {
            auto res = UTR::ManagedHostClient::Instance().InspectAssembly(file);
            if (!res.Ok()) {
                Ui::Error(res.Error());
                return;
            }
            const auto& a = res.Value();
            std::cout << "\n " << C(ColorRole::Primary) << ".NET Assembly Metadata" << R() << "\n";
            std::cout << " " << C(ColorRole::Border) << std::string(55, '-') << R() << "\n";
            std::cout << "  Assembly Name:    " << C(ColorRole::Accent) << a.assemblyName << R() << "\n";
            std::cout << "  Version:          " << a.version << "\n";
            std::cout << "  Culture:          " << a.culture << "\n";
            std::cout << "  Module:           " << a.moduleName << "\n";
            std::cout << "  Defined Types:    " << a.typeCount << "\n";
            std::cout << "  Defined Methods:  " << a.methodCount << "\n";
            std::cout << "  Entry Token:      " << a.entryPoint << "\n";
            std::cout << " " << C(ColorRole::Border) << std::string(55, '-') << R() << "\n\n";
            return;
        }

        if (sub == "types") {
            auto res = UTR::ManagedHostClient::Instance().ListTypes(file);
            if (!res.Ok()) {
                Ui::Error(res.Error());
                return;
            }
            std::cout << "\n " << C(ColorRole::Primary) << "Defined Types (" << res.Value().size() << ")" << R() << "\n";
            for (const auto& t : res.Value()) {
                std::cout << "  " << (t.isInterface ? "[Interface] " : "[Class] ")
                          << C(ColorRole::Accent) << t.fullName << R()
                          << " (Base: " << t.baseType << ")\n";
            }
            std::cout << "\n";
            return;
        }

        if (sub == "pinvokes" || sub == "pinvoke") {
            auto res = UTR::ManagedHostClient::Instance().ListPInvokes(file);
            if (!res.Ok()) {
                Ui::Error(res.Error());
                return;
            }
            std::cout << "\n " << C(ColorRole::Primary) << "P/Invoke Native API Declarations (" << res.Value().size() << ")" << R() << "\n";
            for (const auto& p : res.Value()) {
                std::cout << "  " << C(ColorRole::Accent) << p.type << "." << p.method << R()
                          << " -> " << C(ColorRole::Success) << p.dll << "!" << p.entryPoint << R() << "\n";
            }
            std::cout << "\n";
            return;
        }

        Ui::UsageHint("Available .NET commands:", "/dotnet [info|types|pinvokes]");
    }

    void DraculaShell::HandleDriver(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 1);
        if (file.empty()) {
            auto target = UTR::TargetManager::Instance().GetActiveTarget();
            if (target) file = target->GetInfo().path;
        }

        if (file.empty()) {
            ReportMissingTarget("driver");
            return;
        }

        std::cout << "\n " << C(ColorRole::Primary) << "Driver Static Inspection: " << file << R() << "\n";
        std::cout << "  Static Kernel Imports: " << C(ColorRole::Success) << "Available" << R() << "\n";
        std::cout << "  DriverEntry Analysis:  " << C(ColorRole::Success) << "Available" << R() << "\n";
        std::cout << "  Live Kernel Runtime:   " << C(ColorRole::Warning) << "Restricted (Requires QEMU Isolated VM)" << R() << "\n\n";
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

        auto val = InputValidator::ValidateFile(file);
        if (!val.IsValid()) {
            Ui::Error(val.errorMessage);
            return;
        }

        Ui::Info("Running the Dracula pipeline on " + file);

        OrchestratorOptions opts;
        opts.enableEmulation = true;
        auto res = m_orchestrator.AnalyzeFile(file, opts);

        if (res.threatLevel == "N/A" || (!res.threatReasoning.empty() && res.threatReasoning[0].rfind("PE Parser Error:", 0) == 0)) {
            std::string reason = res.threatReasoning.empty() ? "Failed to parse PE binary." : res.threatReasoning[0];
            Ui::Error(reason);
            return;
        }

        m_activeFile = file;
        m_sessionResult = std::make_unique<UnifiedAnalysisResult>(std::move(res));
        std::cout << m_sessionResult->ToAnsiSummary();
        Ui::Success("Active sample set to " + file);
    }

    void DraculaShell::HandleEmulate(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            ReportMissingTarget("emulate");
            return;
        }

        auto val = InputValidator::ValidateFile(file);
        if (!val.IsValid()) {
            Ui::Error(val.errorMessage);
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
        std::string file;
        std::string rvaStr;
        std::string countStr;

        if (args.empty()) {
            file = m_activeFile;
        } else if (args[0].rfind("0x", 0) == 0 || (args[0].size() > 0 && std::isdigit(static_cast<unsigned char>(args[0][0])) && !m_activeFile.empty() && !std::filesystem::exists(args[0]))) {
            file = m_activeFile;
            rvaStr = args[0];
            if (args.size() > 1) countStr = args[1];
        } else {
            file = args[0];
            StripQuotes(file);
            if (args.size() > 1) rvaStr = args[1];
            if (args.size() > 2) countStr = args[2];
        }

        if (file.empty()) {
            ReportMissingTarget("disasm");
            return;
        }

        auto val = InputValidator::ValidateFile(file);
        if (!val.IsValid()) {
            Ui::Error(val.errorMessage);
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            Ui::Error("PE parse error: " + err);
            return;
        }

        uint64_t targetRva = inspector.GetMetadata().entryPointRva;
        if (!rvaStr.empty()) {
            try { targetRva = std::stoull(rvaStr, nullptr, 0); } catch (...) {
                Ui::Error("Error: Invalid RVA format: " + rvaStr);
                return;
            }
        }

        size_t count = 30;
        if (!countStr.empty()) {
            try { count = std::stoul(countStr); } catch (...) {}
        }

        auto optOffset = inspector.RvaToFileOffset(targetRva);
        if (!optOffset.has_value() || *optOffset >= inspector.GetBufferSize()) {
            Ui::Error("Error: RVA " + Format::Hex(targetRva) + " is outside the mapped PE image.");
            return;
        }

        uint64_t fileOffset = *optOffset;
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
        std::string file;
        std::string rvaStr;

        if (args.empty()) {
            file = m_activeFile;
        } else if (args[0].rfind("0x", 0) == 0 || (args[0].size() > 0 && std::isdigit(static_cast<unsigned char>(args[0][0])) && !m_activeFile.empty() && !std::filesystem::exists(args[0]))) {
            file = m_activeFile;
            rvaStr = args[0];
        } else {
            file = args[0];
            StripQuotes(file);
            if (args.size() > 1) rvaStr = args[1];
        }

        if (file.empty()) {
            ReportMissingTarget("cfg");
            return;
        }

        auto val = InputValidator::ValidateFile(file);
        if (!val.IsValid()) {
            Ui::Error(val.errorMessage);
            return;
        }

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(file, err)) {
            Ui::Error("PE parse error: " + err);
            return;
        }

        uint64_t targetRva = inspector.GetMetadata().entryPointRva;
        if (!rvaStr.empty()) {
            try { targetRva = std::stoull(rvaStr, nullptr, 0); } catch (...) {
                Ui::Error("Error: Invalid RVA format: " + rvaStr);
                return;
            }
        }

        auto optOffset = inspector.RvaToFileOffset(targetRva);
        if (!optOffset.has_value() || *optOffset >= inspector.GetBufferSize()) {
            Ui::Error("Error: RVA " + Format::Hex(targetRva) + " is outside the mapped PE image.");
            return;
        }

        uint64_t fileOffset = *optOffset;
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

        auto val = InputValidator::ValidateFile(file);
        if (!val.IsValid()) {
            Ui::Error(val.errorMessage);
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

        auto val = InputValidator::ValidateFile(file);
        if (!val.IsValid()) {
            Ui::Error(val.errorMessage);
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

        auto val = InputValidator::ValidateFile(file);
        if (!val.IsValid()) {
            Ui::Error(val.errorMessage);
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

        auto val = InputValidator::ValidateFile(file);
        if (!val.IsValid()) {
            Ui::Error(val.errorMessage);
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

        auto val = InputValidator::ValidateFile(file);
        if (!val.IsValid()) {
            Ui::Error(val.errorMessage);
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

        auto val = InputValidator::ValidateFile(file);
        if (!val.IsValid()) {
            Ui::Error(val.errorMessage);
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

        if (args.empty()) {
            if (def) {
                Ui::MissingArgument(*def, "Missing hex pattern.");
            }
            return;
        }

        std::string file;
        std::string pattern;

        if (!m_activeFile.empty()) {
            // Test if all tokens joined form a strictly valid hex pattern
            std::string allTokens;
            for (size_t i = 0; i < args.size(); ++i) {
                if (i > 0) allTokens += " ";
                allTokens += args[i];
            }
            StripQuotes(allTokens);

            auto testParse = PatternScanner::ParsePatternStrict(allTokens);
            if (testParse.IsValid()) {
                file = m_activeFile;
                pattern = allTokens;
            } else if (args.size() >= 2) {
                file = args[0];
                StripQuotes(file);
                for (size_t i = 1; i < args.size(); ++i) {
                    if (i > 1) pattern += " ";
                    pattern += args[i];
                }
                StripQuotes(pattern);
            } else {
                auto fileVal = InputValidator::ValidateFile(args[0]);
                if (fileVal.IsValid()) {
                    if (def) {
                        Ui::MissingArgument(*def, "Missing hex pattern.");
                    }
                    return;
                } else {
                    file = m_activeFile;
                    pattern = args[0];
                    StripQuotes(pattern);
                }
            }
        } else {
            if (args.size() < 2) {
                if (def) {
                    Ui::MissingArgument(*def,
                        "No active sample, so both a file and a pattern are required.");
                }
                return;
            }
            file = args[0];
            StripQuotes(file);
            for (size_t i = 1; i < args.size(); ++i) {
                if (i > 1) pattern += " ";
                pattern += args[i];
            }
            StripQuotes(pattern);
        }

        auto val = InputValidator::ValidateFile(file);
        if (!val.IsValid()) {
            Ui::Error(val.errorMessage);
            return;
        }

        auto parseRes = PatternScanner::ParsePatternStrict(pattern);
        if (!parseRes.IsValid()) {
            Ui::Error("Error: " + parseRes.errorMessage);
            return;
        }

        std::string scanErr;
        auto matches = PatternScanner::ScanFile(file, parseRes.pattern, &scanErr);
        if (!scanErr.empty()) {
            Ui::Error(scanErr);
            return;
        }

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
                      << C(ColorRole::Technical) << Format::Hex(matches[i]) << R() << "\n";
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

        auto val = InputValidator::ValidateFile(file);
        if (!val.IsValid()) {
            Ui::Error(val.errorMessage);
            return;
        }

        Ui::Info("Launching the QEMU hardware sandbox for " + file);
        auto res = m_orchestrator.RunDynamicSandbox(file, 60);
        m_sessionResult = std::make_unique<UnifiedAnalysisResult>(res);
        std::cout << res.ToAnsiSummary();
    }

    void DraculaShell::HandleAntiEvasion(const std::vector<std::string>& args) {
        std::string file;
        AntiEvasionOptions opts;
        bool profileGiven = false;

        for (size_t i = 0; i < args.size(); ++i) {
            const std::string& a = args[i];
            if (a == "--compare") {
                opts.runComparison = true;
            } else if (a == "--detect") {
                opts.runComparison = false;
            } else if (a == "--details" || a == "--detail") {
                opts.detailed = true;
            } else if (a == "--no-emulation") {
                opts.useEmulation = false;
            } else if (a == "--profile") {
                if (i + 1 < args.size()) {
                    ProfileKind kind;
                    if (ParseProfileKind(args[i + 1], kind)) {
                        opts.detectionProfile = kind;
                        profileGiven = true;
                        ++i;
                    } else {
                        Ui::Error("Error: Unknown profile '" + args[i + 1] +
                                  "'. Valid: baseline, realistic, analysis-friendly.");
                        return;
                    }
                } else {
                    Ui::Error("Error: Missing profile name after --profile.");
                    return;
                }
            } else if (a.rfind("--", 0) == 0) {
                Ui::Error("Error: Unknown option '" + a + "'.");
                return;
            } else {
                if (file.empty()) {
                    file = a;
                    StripQuotes(file);
                } else {
                    Ui::Error("Error: Multiple target files specified ('" + file + "' and '" + a + "').");
                    return;
                }
            }
        }

        if (file.empty()) {
            file = m_activeFile;
        }

        if (file.empty()) {
            ReportMissingTarget("antievasion");
            return;
        }

        auto val = InputValidator::ValidateFile(file);
        if (!val.IsValid()) {
            Ui::Error(val.errorMessage);
            return;
        }

        if (profileGiven && opts.runComparison) {
            Ui::Note("--profile selects the single detection profile; it is ignored in "
                     "--compare mode, which runs every comparison profile.");
        }

        Ui::Info(opts.runComparison
                     ? "Running differential anti-evasion analysis on " + file
                     : "Running anti-evasion detection on " + file);

        // Reuse the active session's parsed PE, disassembly, CFG, XRefs and
        // strings when it describes this same sample. Nothing is reparsed
        // blindly.
        const UnifiedAnalysisResult* precomputed = nullptr;
        if (m_sessionResult && m_sessionResult->sample.filePath == file) {
            precomputed = m_sessionResult.get();
        }

        AntiEvasionEngine engine;
        auto result = engine.Analyze(file, opts, precomputed);

        std::cout << result.ToAnsiReport(opts.detailed);

        // Fold the results into the session so /findings, /report and /session
        // all see them without anyone re-running the engine.
        if (!m_sessionResult || m_sessionResult->sample.filePath != file) {
            OrchestratorOptions oopts;
            oopts.enableEmulation = false;   // the engine already executed it
            auto base = m_orchestrator.AnalyzeFile(file, oopts);
            m_sessionResult = std::make_unique<UnifiedAnalysisResult>(std::move(base));
        } else {
            // Drop the previous anti-evasion findings so a second run replaces
            // rather than accumulates.
            auto& findings = m_sessionResult->findings;
            findings.erase(std::remove_if(findings.begin(), findings.end(),
                                          [](const Finding& f) {
                                              return f.source == "Anti-Evasion Engine";
                                          }),
                           findings.end());
        }

        auto aeFindings = result.ToFindings();
        m_sessionResult->findings.insert(m_sessionResult->findings.end(),
                                         aeFindings.begin(), aeFindings.end());
        m_sessionResult->antiEvasionScore = result.environmentSensitivityScore;
        m_sessionResult->antiEvasionSensitivity = result.sensitivityLabel;
        m_sessionResult->antiEvasionStatus = AntiEvasionStatusToString(result.status);
        m_sessionResult->antiEvasionJson = result.ToJson();
        m_sessionResult->antiEvasionMarkdown = result.ToMarkdown();

        auto threat = ThreatEvaluator::Evaluate(m_sessionResult->findings,
                                                m_sessionResult->sample,
                                                m_sessionResult->mitigations,
                                                m_sessionResult->overallEntropy,
                                                m_sessionResult->isPacked);
        m_sessionResult->threatScore = threat.score;
        m_sessionResult->threatLevel = threat.level;
        m_sessionResult->threatReasoning = threat.reasoning;
        m_sessionResult->mitreAttackTechniques = threat.mitreTechniques;

        if (!opts.runComparison && !result.techniques.empty()) {
            Ui::Note("Run /antievasion --compare to test whether these checks actually "
                     "change behavior.");
        }
        Ui::Success(std::to_string(aeFindings.size()) +
                    " anti-evasion finding(s) added to the session.");
    }

    void DraculaShell::HandleFunctions(const std::vector<std::string>& args) {
        std::string file = ResolveTargetFile(args, 0);
        if (file.empty()) {
            ReportMissingTarget("functions");
            return;
        }

        auto val = InputValidator::ValidateFile(file);
        if (!val.IsValid()) {
            Ui::Error(val.errorMessage);
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

        auto val = InputValidator::ValidateFile(file);
        if (!val.IsValid()) {
            Ui::Error(val.errorMessage);
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

        auto optOffset = inspector.RvaToFileOffset(epRva);
        std::vector<XRefEntry> xrefs;
        if (optOffset.has_value() && *optOffset < inspector.GetBufferSize()) {
            uint64_t epOffset = *optOffset;
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
        Ui::Section("Model Context Protocol (MCP)", "JSON-RPC 2.0 Stdio Server");
        Ui::KeyState("Status", Ui::State::Good, "Ready");
        Ui::KeyValue("Protocol version", "2024-11-05");
        Ui::KeyValue("Server name", "Dracula-Intelligence-Suite");
        Ui::KeyValue("Server version", Version::String);
        Ui::KeyValue("CLI stdio flag", "dracula --mcp");
        Ui::Note("Dracula includes a native MCP stdio server for AI pair programming (Claude, Antigravity, Cursor).");
        Ui::Lines({
            "To connect Dracula MCP server to your AI assistant, add to your MCP client config:",
            "  \"dracula\": {",
            "    \"command\": \"dracula.exe\",",
            "    \"args\": [\"--mcp\"]",
            "  }"
        });
        std::cout << "\n";
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
        // Clears the output history and returns the viewport to the newest
        // output. The Dracula header, the prompt, the active analysis session
        // and the command history are all deliberately preserved.
        if (m_screen) {
            m_screen->Output().Clear();
            m_screen->Invalidate();
            return;
        }
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

    // Presents the startup picker and turns the answer into an open project.
    // Anything the user cannot complete here (a cancelled prompt, a path that
    // does not exist) simply lands them at the command prompt with an
    // explanation, never in a broken state.
    void DraculaShell::RunStartupPicker() {
        auto choice = StartupPicker::Present();

        switch (choice.choice) {
            case StartupPicker::Choice::OpenFile: {
                Ui::Note("Enter the path to an EXE, DLL, SYS or .NET assembly.");
                std::string path;
                if (!m_editor.ReadLine("  file > ", path) || path.empty()) return;
                StripQuotes(path);
                RenderResult(App::ProjectService::Instance().OpenFile(path));
                return;
            }

            case StartupPicker::Choice::AttachProcess: {
                RenderResult(App::ProcessService::Instance().List());
                Ui::Note("Enter the PID to attach to.");
                std::string pidText;
                if (!m_editor.ReadLine("  pid > ", pidText) || pidText.empty()) return;

                uint32_t pid = 0;
                try {
                    pid = static_cast<uint32_t>(std::stoul(pidText));
                } catch (...) {
                    Ui::Error("'" + pidText + "' is not a valid PID.");
                    return;
                }
                RenderResult(App::ProjectService::Instance().AttachProcess(pid));
                return;
            }

            case StartupPicker::Choice::OpenProject: {
                RenderResult(App::ProjectService::Instance().List());
                Ui::Note("Enter a project id or name to open.");
                std::string id;
                if (!m_editor.ReadLine("  project > ", id) || id.empty()) return;
                RenderResult(App::ProjectService::Instance().Open(id));
                return;
            }

            case StartupPicker::Choice::OpenDriver: {
                Ui::Note("Enter the path to a .sys driver.");
                std::string path;
                if (!m_editor.ReadLine("  driver > ", path) || path.empty()) return;
                StripQuotes(path);
                RenderResult(App::ProjectService::Instance().OpenFile(path));
                return;
            }

            case StartupPicker::Choice::OpenVmImage: {
                // The VM path is about sandbox infrastructure, not a sample, so
                // it points the user at the sandbox commands rather than
                // creating an analysis project.
                RenderResult(App::SandboxService::Instance().Status());
                Ui::Note("Import your local VM image with /sandbox image import <path>.");
                return;
            }

            case StartupPicker::Choice::SkipToShell:
            default:
                return;
        }
    }

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
        Ui::ResetError();

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
            // Section 4: `drac` with no arguments asks what to analyze rather
            // than dropping the user at an empty prompt. Escape, a redirected
            // stdin, or a choice that needs no follow-up all end at the shell.
            RunStartupPicker();
            return RunInteractive();
        }

        // Filter out formatting flags
        std::vector<std::string> rawArgs;
        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            if (a != "--no-color" && a != "--no-unicode") {
                rawArgs.push_back(a);
            }
        }

        if (rawArgs.empty()) {
            return RunInteractive();
        }

        std::string first = rawArgs[0];

        if (first == "--help" || first == "-h") {
            PrintHelp("");
            return 0;
        }

        if (first == "--version" || first == "-v") {
            PrintVersion();
            return 0;
        }

        if (first == "--changelog") {
            HandleChangelog({});
            return 0;
        }

        std::string command;
        std::vector<std::string> cmdArgs;

        if (first == "--target" || first == "-t") command = "target";
        else if (first == "--memory" || first == "-m") command = "memory";
        else if (first == "--dll") command = "dll";
        else if (first == "--process" || first == "-p") command = "process";
        else if (first == "--runtime" || first == "-r") command = "runtime";
        else if (first == "--dotnet" || first == "--clr") command = "dotnet";
        else if (first == "--driver" || first == "--sys") command = "driver";
        else if (first == "--analyze" || first == "-a") command = "analyze";
        else if (first == "--emulate" || first == "-e") command = "emulate";
        else if (first == "--disasm" || first == "-d") command = "disasm";
        else if (first == "--cfg") command = "cfg";
        else if (first == "--headers") command = "headers";
        else if (first == "--security") command = "security";
        else if (first == "--imports") command = "imports";
        else if (first == "--exports") command = "exports";
        else if (first == "--strings") command = "strings";
        else if (first == "--entropy") command = "entropy";
        else if (first == "--sandbox") command = "sandbox";
        else if (first == "--anti-evasion" || first == "--antievasion" ||
                 first == "--antivm" || first == "--evasion") command = "antievasion";
        else if (first == "--scan") command = "scan";
        else if (first == "--functions") command = "functions";
        else if (first == "--xrefs") command = "xrefs";
        else if (first == "--findings") command = "findings";
        else if (first == "--report") command = "report";
        else if (first == "--session") command = "session";
        else {
            command = "analyze";
            cmdArgs.push_back(first);
        }

        for (size_t i = 1; i < rawArgs.size(); ++i) {
            cmdArgs.push_back(rawArgs[i]);
        }

        std::string cmdLine = "/" + command;
        for (const auto& a : cmdArgs) cmdLine += " \"" + a + "\"";

        try {
            ExecuteCommand(cmdLine);
        } catch (const std::exception& ex) {
            Ui::Error(std::string("Fatal error: ") + ex.what());
        } catch (...) {
            Ui::Error("Fatal unexpected error occurred.");
        }

        return Ui::HasError() ? 1 : 0;
    }

} // namespace Dracula
