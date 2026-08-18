#include "cli/command_registry.h"
#include "cli/dracula_shell.h"
#include "app/services.h"
#include "app/settings.h"
#include "app/sandbox_service.h"

#include <algorithm>
#include <cctype>

namespace Dracula {

    CommandRegistry& CommandRegistry::Instance() {
        static CommandRegistry instance;
        if (!instance.m_initialized) {
            instance.InitializeDefaultCommands();
        }
        return instance;
    }

    void CommandRegistry::Register(const CommandDefinition& cmd) {
        m_commands.push_back(cmd);
    }

    const CommandDefinition* CommandRegistry::Find(const std::string& nameOrAlias) const {
        std::string query = nameOrAlias;
        if (!query.empty() && query.front() == '/') {
            query = query.substr(1);
        }
        std::transform(query.begin(), query.end(), query.begin(), ::tolower);

        for (const auto& cmd : m_commands) {
            if (cmd.name == query) return &cmd;
            for (const auto& alias : cmd.aliases) {
                if (alias == query) return &cmd;
            }
        }
        return nullptr;
    }

    const CommandDefinition* CommandRegistry::FindExact(const std::string& name) const {
        std::string query = name;
        if (!query.empty() && query.front() == '/') {
            query = query.substr(1);
        }
        std::transform(query.begin(), query.end(), query.begin(), ::tolower);

        for (const auto& cmd : m_commands) {
            if (cmd.name == query) return &cmd;
        }
        return nullptr;
    }

    std::vector<const CommandDefinition*> CommandRegistry::FilterByPrefix(const std::string& prefix) const {
        std::string query = prefix;
        if (!query.empty() && query.front() == '/') {
            query = query.substr(1);
        }
        std::transform(query.begin(), query.end(), query.begin(), ::tolower);

        std::vector<const CommandDefinition*> matches;
        for (const auto& cmd : m_commands) {
            if (query.empty() || cmd.name.rfind(query, 0) == 0) {
                matches.push_back(&cmd);
            }
        }
        return matches;
    }

    const SubcommandDefinition* CommandRegistry::FindSubcommand(const CommandDefinition& cmd,
                                                                const std::string& name) const {
        if (name.empty()) return nullptr;

        std::string query = name;
        std::transform(query.begin(), query.end(), query.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        for (const auto& sub : cmd.subcommands) {
            if (sub.name == query) return &sub;
        }

        // Unambiguous prefix, so "/memory snap" reaches "snapshot". An
        // ambiguous prefix resolves to nothing rather than to a guess.
        const SubcommandDefinition* match = nullptr;
        for (const auto& sub : cmd.subcommands) {
            if (sub.name.rfind(query, 0) == 0) {
                if (match) return nullptr;
                match = &sub;
            }
        }
        return match;
    }

    std::vector<std::string> CommandRegistry::SubcommandNames(const CommandDefinition& cmd) const {
        std::vector<std::string> names;
        names.reserve(cmd.subcommands.size());
        for (const auto& sub : cmd.subcommands) names.push_back(sub.name);
        return names;
    }

    std::string CommandRegistry::DescribeRequirement(CommandRequirement req) {
        switch (req) {
            case CommandRequirement::None:          return "always available";
            case CommandRequirement::ActiveProject: return "an open project";
            case CommandRequirement::FileBacking:   return "a file-backed target";
            case CommandRequirement::LiveProcess:   return "a running process";
            case CommandRequirement::ManagedTarget: return "a .NET target";
        }
        return "unknown";
    }

    bool CommandRegistry::RequirementSatisfied(CommandRequirement req, App::ErrorDetail& errorOut) {
        using namespace Dracula::App;

        if (req == CommandRequirement::None) return true;

        auto project = ProjectManager::Instance().Active();
        if (!project) {
            errorOut = NoActiveProjectError();
            return false;
        }
        if (req == CommandRequirement::ActiveProject) return true;

        const auto& target = project->Target();
        switch (req) {
            case CommandRequirement::FileBacking:
                if (!project->StaticAnalysisPath().empty()) return true;
                errorOut = CapabilityError(*project, "This command",
                    target.IsLiveProcess()
                        ? "The live process backing executable could not be resolved."
                        : "The project sample is no longer on disk.");
                return false;

            case CommandRequirement::LiveProcess:
                if (target.IsLiveProcess()) return true;
                errorOut = CapabilityError(*project, "This command",
                    "It requires a running process; this project is backed by a file on disk.");
                return false;

            case CommandRequirement::ManagedTarget:
                if (target.isDotNet ||
                    target.kind == UTR::TargetKind::ManagedExe ||
                    target.kind == UTR::TargetKind::ManagedDll) {
                    return true;
                }
                errorOut = CapabilityError(*project, ".NET metadata analysis",
                    "This target is native code; it carries no .NET metadata.");
                return false;

            default:
                return true;
        }
    }

    const std::vector<CommandDefinition>& CommandRegistry::GetAllCommands() const {
        return m_commands;
    }

    std::vector<std::string> CommandRegistry::GetCategories() const {
        std::vector<std::string> categories;
        for (const auto& cmd : m_commands) {
            if (std::find(categories.begin(), categories.end(), cmd.category) == categories.end()) {
                categories.push_back(cmd.category);
            }
        }
        return categories;
    }

    std::vector<const CommandDefinition*> CommandRegistry::GetCommandsByCategory(const std::string& category) const {
        std::vector<const CommandDefinition*> result;
        for (const auto& cmd : m_commands) {
            if (cmd.category == category) {
                result.push_back(&cmd);
            }
        }
        return result;
    }

    void CommandRegistry::InitializeDefaultCommands() {
        if (m_initialized) return;
        m_commands.clear();

        // --- Project & Session --------------------------------------------
        // Sessions are a user-friendly view over the SAME durable projects.
        // There is exactly one persistence system.
        Register({
            .name = "project",
            .aliases = {"proj"},
            .description = "Manage durable analysis projects",
            .usage = "/project [info|list|open|new|close|storage|cleanup|delete]",
            .category = "Project",
            .detailedHelp = "A project is Dracula's durable workspace: the immutable original sample, "
                            "static and runtime artifacts, memory snapshots, reports and logs. Projects "
                            "survive exit and are reopened by ID or name.",
            .examples = {"/project info", "/project list", "/project open 7f31", "/project storage",
                         "/project cleanup", "/project delete 7f31 --force"},
            .requirement = CommandRequirement::None,
            .subcommands = {
                {"info", "Show the active project", "/project info",
                 {}, CommandRequirement::ActiveProject, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::ProjectService::Instance().Info(); }},

                {"list", "List all durable projects", "/project list",
                 {}, CommandRequirement::None, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::ProjectService::Instance().List(); }},

                {"open", "Open a project by ID or name", "/project open <id|name>",
                 {}, CommandRequirement::None, CommandSafety::Safe,
                 [](const std::vector<std::string>& a) {
                     return App::ProjectService::Instance().Open(a.empty() ? "" : a[0]);
                 }},

                {"new", "Create an independent project for a file", "/project new <path>",
                 {}, CommandRequirement::None, CommandSafety::Mutating,
                 [](const std::vector<std::string>& a) {
                     if (a.empty()) {
                         return App::CommandResult::Failure("missing_argument",
                             "No file specified.", "/project new needs a path.");
                     }
                     // forceNew: always an independent project, even for a
                     // sample that already has one.
                     return App::ProjectService::Instance().OpenFile(a[0], true);
                 }},

                {"close", "Close the active project", "/project close",
                 {}, CommandRequirement::ActiveProject, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::ProjectService::Instance().Close(); }},

                {"storage", "Show measured disk usage", "/project storage",
                 {}, CommandRequirement::ActiveProject, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::ProjectService::Instance().Storage(); }},

                {"cleanup", "Remove disposable data, keep evidence", "/project cleanup [id|name]",
                 {}, CommandRequirement::None, CommandSafety::Mutating,
                 [](const std::vector<std::string>& a) {
                     return App::ProjectService::Instance().Cleanup(a.empty() ? "" : a[0]);
                 }},

                {"delete", "Delete a project workspace", "/project delete <id|name> [--force]",
                 {"--force"}, CommandRequirement::None, CommandSafety::Mutating,
                 [](const std::vector<std::string>& a) {
                     std::string id;
                     bool force = false;
                     for (const auto& arg : a) {
                         if (arg == "--force" || arg == "-f") force = true;
                         else if (id.empty()) id = arg;
                     }
                     return App::ProjectService::Instance().Delete(id, force);
                 }},
            },
            .defaultSubcommand = "info",
            .argCompletions = {"info", "list", "open", "new", "close", "storage", "cleanup", "delete"},
        });

        Register({
            .name = "session",
            .aliases = {"sess"},
            .description = "Work with saved sessions (a view over durable projects)",
            .usage = "/session [list|use|info|cleanup|delete]",
            .category = "Project",
            .detailedHelp = "Sessions and projects are the same durable workspaces. These subcommands "
                            "are provided for convenience and operate on exactly the same storage as "
                            "/project, so there is never conflicting state.",
            .examples = {"/session list", "/session use 7f31", "/session cleanup", "/session delete 7f31"},
            .requirement = CommandRequirement::None,
            .subcommands = {
                {"list", "List saved sessions", "/session list",
                 {}, CommandRequirement::None, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::ProjectService::Instance().List(); }},

                {"use", "Switch to a session", "/session use <id|name>",
                 {}, CommandRequirement::None, CommandSafety::Safe,
                 [](const std::vector<std::string>& a) {
                     return App::ProjectService::Instance().Open(a.empty() ? "" : a[0]);
                 }},

                {"info", "Show the active session", "/session info",
                 {}, CommandRequirement::ActiveProject, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::ProjectService::Instance().Info(); }},

                {"cleanup", "Remove disposable data", "/session cleanup [id|name]",
                 {}, CommandRequirement::None, CommandSafety::Mutating,
                 [](const std::vector<std::string>& a) {
                     return App::ProjectService::Instance().Cleanup(a.empty() ? "" : a[0]);
                 }},

                {"delete", "Delete a session workspace", "/session delete <id|name> [--force]",
                 {"--force"}, CommandRequirement::None, CommandSafety::Mutating,
                 [](const std::vector<std::string>& a) {
                     std::string id;
                     bool force = false;
                     for (const auto& arg : a) {
                         if (arg == "--force" || arg == "-f") force = true;
                         else if (id.empty()) id = arg;
                     }
                     return App::ProjectService::Instance().Delete(id, force);
                 }},
            },
            .defaultSubcommand = "list",
            .argCompletions = {"list", "use", "info", "cleanup", "delete"},
        });

        // --- Target -------------------------------------------------------
        Register({
            .name = "target",
            .aliases = {"t", "tgt"},
            .description = "Open a target, or inspect the active one",
            .usage = "/target <path> | /target [info|capabilities|close]",
            .category = "Target",
            .detailedHelp = "Opening a target creates or continues a durable project for it. "
                            "A PID is recorded as a PID and its backing executable resolved separately, "
                            "so a target specifier is never stored as a file path.",
            .examples = {"/target samples\\test_sample.exe", "/target info", "/target capabilities"},
            .takesFilePath = true,
            .requirement = CommandRequirement::None,
            .subcommands = {
                {"info", "Show the active target", "/target info",
                 {}, CommandRequirement::ActiveProject, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::TargetService::Instance().Info(); }},

                {"capabilities", "Show what this target supports", "/target capabilities",
                 {}, CommandRequirement::ActiveProject, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::TargetService::Instance().Capabilities(); }},

                {"close", "Close the active target and project", "/target close",
                 {}, CommandRequirement::ActiveProject, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::ProjectService::Instance().Close(); }},
            },
            .argCompletions = {"info", "capabilities", "close"},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleTarget(args);
            }
        });

        // --- Static analysis ----------------------------------------------
        // Works on a process project too: it resolves the backing executable.
        Register({
            .name = "static",
            .aliases = {"st"},
            .description = "Static analysis of the project's image",
            .usage = "/static [info|sections|imports|exports|strings]",
            .category = "Analysis",
            .detailedHelp = "Static analysis always runs against the project's file backing. For a "
                            "process-backed project that is the resolved backing executable, so /static "
                            "works without reopening anything.",
            .examples = {"/static", "/static sections", "/static imports", "/static strings"},
            .requirement = CommandRequirement::FileBacking,
            .subcommands = {
                {"info", "Headers, entry point and mitigations", "/static info",
                 {}, CommandRequirement::FileBacking, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::StaticService::Instance().Info(); }},

                {"sections", "Section table with entropy", "/static sections",
                 {}, CommandRequirement::FileBacking, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::StaticService::Instance().Sections(); }},

                {"imports", "Imported symbols", "/static imports",
                 {}, CommandRequirement::FileBacking, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::StaticService::Instance().Imports(); }},

                {"exports", "Exported symbols", "/static exports",
                 {}, CommandRequirement::FileBacking, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::StaticService::Instance().Exports(); }},

                {"strings", "Extracted and classified strings", "/static strings [minlen]",
                 {}, CommandRequirement::FileBacking, CommandSafety::Safe,
                 [](const std::vector<std::string>& a) {
                     size_t minLen = 4;
                     if (!a.empty()) {
                         try { minLen = static_cast<size_t>(std::stoul(a[0])); } catch (...) {}
                     }
                     return App::StaticService::Instance().Strings(minLen);
                 }},
            },
            .defaultSubcommand = "info",
            .argCompletions = {"info", "sections", "imports", "exports", "strings"},
        });

        // --- Memory -------------------------------------------------------
        Register({
            .name = "memory",
            .aliases = {"mem", "m"},
            .description = "Inspect virtual memory, capture snapshots and diff them",
            .usage = "/memory [map|read|snapshot|snapshots|compare]",
            .category = "Memory",
            .detailedHelp = "Memory Intelligence. Snapshot IDs are allocated from the project and "
                            "persist across restarts, so /memory compare works on snapshots captured "
                            "in an earlier session.",
            .examples = {"/memory map", "/memory read 0x7FF000 256", "/memory snapshot before",
                         "/memory compare before after"},
            .requirement = CommandRequirement::LiveProcess,
            .subcommands = {
                {"map", "Summarize the memory map", "/memory map",
                 {}, CommandRequirement::LiveProcess, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::MemoryService::Instance().Map(); }},

                {"read", "Read and hex-dump memory", "/memory read <address> <size>",
                 {}, CommandRequirement::LiveProcess, CommandSafety::Safe,
                 [](const std::vector<std::string>& a) {
                     if (a.size() < 2) {
                         return App::CommandResult::Failure("missing_argument",
                             "Address and size are required.",
                             "/memory read takes an address and a byte count.",
                             "Example: /memory read 0x7FFE8FD0000 256");
                     }
                     uint64_t address = 0;
                     size_t size = 0;
                     try {
                         address = std::stoull(a[0], nullptr, 0);
                         size = static_cast<size_t>(std::stoull(a[1], nullptr, 0));
                     } catch (...) {
                         return App::CommandResult::Failure("invalid_argument",
                             "Could not parse the address or size.",
                             "Both must be numeric; 0x-prefixed hex is accepted.");
                     }
                     return App::MemoryService::Instance().Read(address, size);
                 }},

                {"snapshot", "Capture a memory snapshot", "/memory snapshot [name]",
                 {}, CommandRequirement::LiveProcess, CommandSafety::Mutating,
                 [](const std::vector<std::string>& a) {
                     return App::MemoryService::Instance().Snapshot(a.empty() ? "" : a[0]);
                 }},

                {"snapshots", "List captured snapshots", "/memory snapshots",
                 {}, CommandRequirement::ActiveProject, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::MemoryService::Instance().ListSnapshots(); }},

                {"compare", "Diff two snapshots", "/memory compare <a> <b>",
                 {}, CommandRequirement::ActiveProject, CommandSafety::Safe,
                 [](const std::vector<std::string>& a) {
                     if (a.size() < 2) {
                         return App::CommandResult::Failure("missing_argument",
                             "Two snapshots are required.",
                             "/memory compare takes two snapshot IDs or labels.",
                             "List them with /memory snapshots.");
                     }
                     return App::MemoryService::Instance().Compare(a[0], a[1]);
                 }},
            },
            .defaultSubcommand = "map",
            .argCompletions = {"map", "read", "snapshot", "snapshots", "compare"},
        });

        // --- DLL ----------------------------------------------------------
        // Every advertised subcommand below is dispatchable. The v1.2.4
        // palette listed "info|imports|trace" while only "exports|run" worked.
        Register({
            .name = "dll",
            .aliases = {},
            .description = "Correlate a DLL's on-disk image with its loaded module",
            .usage = "/dll [info|exports|imports|functions] [name]",
            .category = "DLL",
            .detailedHelp = "Resolves a module within the ACTIVE project without replacing its target. "
                            "When the module is loaded, static RVAs are correlated to live virtual "
                            "addresses and a sample of them is verified by real memory reads.",
            .examples = {"/dll info windowscodecs.dll", "/dll exports windowscodecs.dll",
                         "/dll functions windowscodecs.dll"},
            .requirement = CommandRequirement::ActiveProject,
            .subcommands = {
                {"info", "Module identity and load state", "/dll info [name]",
                 {}, CommandRequirement::ActiveProject, CommandSafety::Safe,
                 [](const std::vector<std::string>& a) {
                     return App::DllService::Instance().Info(a.empty() ? "" : a[0]);
                 }},

                {"exports", "Exports with static/live correlation", "/dll exports [name]",
                 {}, CommandRequirement::ActiveProject, CommandSafety::Safe,
                 [](const std::vector<std::string>& a) {
                     return App::DllService::Instance().Exports(a.empty() ? "" : a[0]);
                 }},

                {"imports", "Imported symbols", "/dll imports [name]",
                 {}, CommandRequirement::ActiveProject, CommandSafety::Safe,
                 [](const std::vector<std::string>& a) {
                     return App::DllService::Instance().Imports(a.empty() ? "" : a[0]);
                 }},

                {"functions", "Discovered functions with runtime addresses", "/dll functions [name]",
                 {}, CommandRequirement::ActiveProject, CommandSafety::Safe,
                 [](const std::vector<std::string>& a) {
                     return App::DllService::Instance().Functions(a.empty() ? "" : a[0]);
                 }},
            },
            .defaultSubcommand = "info",
            .argCompletions = {"info", "exports", "imports", "functions"},
        });

        // --- Process ------------------------------------------------------
        Register({
            .name = "process",
            .aliases = {"proc", "ps"},
            .description = "Inspect live processes, modules and threads",
            .usage = "/process [list|attach <pid>|info|modules|threads]",
            .category = "Process",
            .detailedHelp = "Attaching resolves the process's backing executable and copies it into the "
                            "project, so static analysis keeps working after the process exits.",
            .examples = {"/process list", "/process attach 17140", "/process modules", "/process threads"},
            .requirement = CommandRequirement::None,
            .subcommands = {
                {"list", "List accessible processes", "/process list",
                 {}, CommandRequirement::None, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::ProcessService::Instance().List(); }},

                {"attach", "Attach to a running process", "/process attach <pid>",
                 {}, CommandRequirement::None, CommandSafety::Mutating,
                 [](const std::vector<std::string>& a) {
                     if (a.empty()) {
                         return App::CommandResult::Failure("missing_argument",
                             "No PID specified.", "/process attach needs a numeric PID.",
                             "List candidates with /process list.");
                     }
                     uint32_t pid = 0;
                     try {
                         pid = static_cast<uint32_t>(std::stoul(a[0]));
                     } catch (...) {
                         return App::CommandResult::Failure("invalid_argument",
                             "'" + a[0] + "' is not a valid PID.",
                             "A PID is a positive integer.");
                     }
                     return App::ProjectService::Instance().AttachProcess(pid);
                 }},

                {"info", "Show the attached process", "/process info",
                 {}, CommandRequirement::LiveProcess, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::ProcessService::Instance().Info(); }},

                {"modules", "List loaded modules", "/process modules",
                 {}, CommandRequirement::LiveProcess, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::ProcessService::Instance().Modules(); }},

                {"threads", "List threads", "/process threads",
                 {}, CommandRequirement::LiveProcess, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::ProcessService::Instance().Threads(); }},
            },
            .defaultSubcommand = "list",
            .argCompletions = {"list", "attach", "info", "modules", "threads"},
        });

        // --- Runtime ------------------------------------------------------
        Register({
            .name = "runtime",
            .aliases = {"rt"},
            .description = "Runtime backend status and recorded events",
            .usage = "/runtime [status|events]",
            .category = "Runtime",
            .detailedHelp = "Status reports the state each backend can actually prove. A binary that is "
                            "merely installed reports Installed, never Ready, and a guest agent reports "
                            "Connected only when a VM session exists.",
            .examples = {"/runtime status", "/runtime events"},
            .requirement = CommandRequirement::None,
            .subcommands = {
                {"status", "Truthful backend readiness", "/runtime status",
                 {}, CommandRequirement::None, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::RuntimeService::Instance().Status(); }},

                {"events", "Recorded runtime events", "/runtime events",
                 {}, CommandRequirement::ActiveProject, CommandSafety::Safe,
                 [](const std::vector<std::string>&) { return App::RuntimeService::Instance().Events(); }},
            },
            .defaultSubcommand = "status",
            .argCompletions = {"status", "events"},
        });

        // --- Settings -----------------------------------------------------
        Register({
            .name = "settings",
            .aliases = {"set"},
            .description = "View and change Dracula settings",
            .usage = "/settings [list|set <key> <value>]",
            .category = "System",
            .detailedHelp = "Persistent user preferences such as report auto-open and default format.",
            .examples = {"/settings list", "/settings set reports.auto_open true"},
            .requirement = CommandRequirement::None,
            .subcommands = {
                {"list", "Show all settings", "/settings list",
                 {}, CommandRequirement::None, CommandSafety::Safe,
                 [](const std::vector<std::string>&) {
                     auto r = App::CommandResult::Success("Settings");
                     for (const auto& e : App::Settings::Instance().Describe()) {
                         r.Line(e.key + " = " + e.value);
                         r.Line("    " + e.description);
                     }
                     r.Line("Stored in " + App::Settings::Instance().Path());
                     return r;
                 }},

                {"set", "Change a setting", "/settings set <key> <value>",
                 {}, CommandRequirement::None, CommandSafety::Mutating,
                 [](const std::vector<std::string>& a) {
                     if (a.size() < 2) {
                         return App::CommandResult::Failure("missing_argument",
                             "A key and a value are required.",
                             "/settings set takes a setting name and its new value.",
                             "List available settings with /settings list.");
                     }
                     if (!App::Settings::IsKnown(a[0])) {
                         App::ErrorDetail e;
                         e.code = "unknown_setting";
                         e.message = "'" + a[0] + "' is not a known setting.";
                         e.reason = "Unknown keys are rejected so a typo cannot become a dead setting.";
                         e.remediation = "List available settings with /settings list.";
                         for (const auto& known : App::Settings::Instance().Describe()) {
                             e.availableInstead.push_back(known.key);
                         }
                         return App::CommandResult::Failure(e);
                     }
                     App::Settings::Instance().SetString(a[0], a[1]);
                     std::string error;
                     if (!App::Settings::Instance().Save(error)) {
                         return App::CommandResult::Failure("settings_save_failed",
                             "Could not save settings.", error);
                     }
                     return App::CommandResult::Success(a[0] + " = " + a[1]);
                 }},
            },
            .defaultSubcommand = "list",
            .argCompletions = {"list", "set"},
        });

        // --- Artifacts ----------------------------------------------------
        Register({
            .name = "artifacts",
            .aliases = {"art"},
            .description = "List generated project artifacts",
            .usage = "/artifacts",
            .category = "Project",
            .detailedHelp = "Every large report Dracula generates is stored inside the project and "
                            "listed here with its project-relative path.",
            .examples = {"/artifacts"},
            .requirement = CommandRequirement::ActiveProject,
            .subcommands = {
                {"list", "List project artifacts", "/artifacts list",
                 {}, CommandRequirement::ActiveProject, CommandSafety::Safe,
                 [](const std::vector<std::string>&) {
                     auto project = App::ProjectManager::Instance().Active();
                     if (!project) {
                         return App::CommandResult::Failure(App::NoActiveProjectError());
                     }
                     const auto& artifacts = project->Artifacts();
                     if (artifacts.empty()) {
                         auto r = App::CommandResult::Success("No artifacts generated yet.");
                         r.Line("Commands that produce large tables write one automatically.");
                         return r;
                     }
                     auto r = App::CommandResult::Success(
                         std::to_string(artifacts.size()) + " artifact" +
                         (artifacts.size() == 1 ? "" : "s") + ".");
                     for (const auto& a : artifacts) {
                         r.Line(a.createdAt + "  " + a.kind + "  " + a.relativePath +
                                "  (" + App::FormatBytes(a.sizeBytes) + ")");
                     }
                     return r;
                 }},
            },
            .defaultSubcommand = "list",
            .argCompletions = {"list"},
        });

        // 0f. /dotnet
        Register({
            .name = "dotnet",
            .aliases = {"clr", "net"},
            .description = "Inspect .NET managed assemblies, types, methods, IL, and P/Invokes",
            .usage = "/dotnet [info|types|method <Type> <Method>|strings|pinvokes]",
            .category = "DotNet",
            .detailedHelp = "ManagedHost .NET inspection. Parses assembly metadata, AppDomains, types, IL bytecode disassembly, and P/Invoke signatures.",
            .examples = {"/dotnet info", "/dotnet types", "/dotnet method SecurityManager Authenticate", "/dotnet pinvokes"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {"info", "types", "method", "strings", "pinvokes"},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleDotNet(args);
            }
        });

        // 0g. /driver
        Register({
            .name = "driver",
            .aliases = {"drv"},
            .description = "Inspect Windows kernel drivers (.sys) and QEMU kernel isolation",
            .usage = "/driver [info|imports|sections|runtime]",
            .category = "Driver",
            .detailedHelp = "Static kernel driver inspection (DriverEntry, sections, IRP handlers). Runtime observation is safely isolated to QEMU.",
            .examples = {"/driver info", "/driver imports", "/driver sections"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {"info", "imports", "sections", "runtime"},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleDriver(args);
            }
        });

        // 1. /analyze
        Register({
            .name = "analyze",
            .aliases = {"a"},
            .description = "Analyze a PE using the complete Dracula pipeline",
            .usage = "/analyze <file>",
            .category = "Analysis",
            .detailedHelp = "Runs complete static inspection, entropy profiling, Capstone disassembly, CFG generation, and Unicorn 2 CPU emulation on target PE.",
            .examples = {"/analyze samples\\test_sample.exe", "/analyze target.dll"},
            .takesFilePath = true,
            .requiresArgs = true,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleAnalyze(args);
            }
        });

        // 2. /disasm
        Register({
            .name = "disasm",
            .aliases = {"dis", "d"},
            .description = "Disassemble executable code using Capstone",
            .usage = "/disasm [file] [rva] [count]",
            .category = "Inspection",
            .detailedHelp = "Disassembles x86/x64 instructions at the entrypoint or specified target RVA using Capstone 5.0.1 engine.",
            .examples = {"/disasm", "/disasm samples\\test_sample.exe", "/disasm samples\\test_sample.exe 0x1000 50"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleDisasm(args);
            }
        });

        // 3. /headers
        Register({
            .name = "headers",
            .aliases = {"hdr"},
            .description = "Inspect PE headers, metadata, and section tables",
            .usage = "/headers [file]",
            .category = "Inspection",
            .detailedHelp = "Parses and displays DOS header, NT headers, Optional header fields, entry point, and section table permissions.",
            .examples = {"/headers", "/headers sample.exe"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleHeaders(args);
            }
        });

        // 4. /security
        Register({
            .name = "security",
            .aliases = {"sec"},
            .description = "Audit PE security mitigations (ASLR, DEP, CFG, SEH)",
            .usage = "/security [file]",
            .category = "Inspection",
            .detailedHelp = "Audits exploit mitigations including Dynamic Base (ASLR), High Entropy ASLR, DEP/NX, Control Flow Guard (CFG), SEH, and Authenticode.",
            .examples = {"/security", "/security sample.exe"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleSecurity(args);
            }
        });

        // 5. /imports
        Register({
            .name = "imports",
            .aliases = {"imp"},
            .description = "Show imported DLLs and sensitive API calls",
            .usage = "/imports [file]",
            .category = "Inspection",
            .detailedHelp = "Inspects the Import Address Table (IAT) and flags high-risk APIs (process injection, memory manipulation, evasion).",
            .examples = {"/imports", "/imports sample.exe"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleImports(args);
            }
        });

        // 6. /exports
        Register({
            .name = "exports",
            .aliases = {"exp"},
            .description = "Show exported functions and symbol RVAs",
            .usage = "/exports [file]",
            .category = "Inspection",
            .detailedHelp = "Lists exported symbols, ordinal numbers, RVAs, and forwarders from the Export Address Table (EAT).",
            .examples = {"/exports", "/exports target.dll"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleExports(args);
            }
        });

        // 7. /strings
        Register({
            .name = "strings",
            .aliases = {"str"},
            .description = "Extract and classify ASCII & UTF-16 strings",
            .usage = "/strings [file] [min_length]",
            .category = "Inspection",
            .detailedHelp = "Extracts strings with category classification (URLs, IPs, file paths, registry keys, DLLs, suspicious commands).",
            .examples = {"/strings", "/strings sample.exe 6", "/strings --all"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {"--all"},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleStrings(args);
            }
        });

        // 8. /entropy
        Register({
            .name = "entropy",
            .aliases = {"ent"},
            .description = "Analyze Shannon entropy & detect packers",
            .usage = "/entropy [file]",
            .category = "Analysis",
            .detailedHelp = "Calculates mathematical Shannon entropy per section to detect packing, encryption, or compression (UPX, ASPack, Themida, etc.).",
            .examples = {"/entropy", "/entropy sample.exe"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleEntropy(args);
            }
        });

        // 9. /emulate
        Register({
            .name = "emulate",
            .aliases = {"emu", "e"},
            .description = "Run lightweight Unicorn 2 CPU emulation with Win32 HLE",
            .usage = "/emulate [file] [--policy bypass|realistic|neutral]",
            .category = "Emulation",
            .detailedHelp = "Emulates CPU instructions in isolated memory with synthetic Win32 HLE thunks, mock TEB/PEB, and register inspection.",
            .examples = {"/emulate", "/emulate sample.exe", "/emulate sample.exe --policy bypass"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {"--policy"},
            .flagCompletions = {{"--policy", {"bypass", "realistic", "neutral"}}},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleEmulate(args);
            }
        });

        // 10. /sandbox
        Register({
            .name = "sandbox",
            .aliases = {"vm"},
            .description = "Isolated QEMU runtime, its immutable base and disposable overlays",
            .usage = "/sandbox [status|image|overlays|reset]",
            .category = "Sandbox",
            .detailedHelp = "Dracula runs untrusted samples inside a QEMU guest built from an "
                            "immutable, integrity-checked .draculaimg base. Each run gets a "
                            "disposable overlay that is deleted afterwards, on success and on "
                            "failure alike, so the base is never contaminated. QEMU stays stopped "
                            "until an analysis genuinely needs it.",
            .examples = {"/sandbox status", "/sandbox image import D:\\VirtualMachines\\win10.vdi",
                         "/sandbox image verify", "/sandbox image restore", "/sandbox reset"},
            .requirement = CommandRequirement::None,
            .subcommands = {
                {"status", "Factual QEMU environment state", "/sandbox status",
                 {}, CommandRequirement::None, CommandSafety::Safe,
                 [](const std::vector<std::string>&) {
                     return App::SandboxService::Instance().Status();
                 }},

                {"image", "Manage the .draculaimg VM package", "/sandbox image [info|import|verify|restore]",
                 {"info", "import", "verify", "restore"}, CommandRequirement::None, CommandSafety::Mutating,
                 [](const std::vector<std::string>& a) {
                     auto& sandbox = App::SandboxService::Instance();
                     const std::string action = a.empty() ? "info" : a[0];

                     if (action == "info")   return sandbox.ImageInfo();
                     if (action == "verify") return sandbox.ImageVerify(true);
                     if (action == "import") {
                         return sandbox.ImageImport(a.size() > 1 ? a[1] : "");
                     }
                     if (action == "restore") {
                         const bool force = std::any_of(a.begin(), a.end(),
                             [](const std::string& s) { return s == "--force" || s == "-f"; });
                         return sandbox.ImageRestore(force);
                     }

                     App::ErrorDetail e;
                     e.code = "unknown_subcommand";
                     e.message = "'" + action + "' is not a /sandbox image action.";
                     e.reason = "The action did not match a registered handler.";
                     e.remediation = "Run /sandbox image on its own to see what is available.";
                     e.availableInstead = {"info", "import", "verify", "restore"};
                     return App::CommandResult::Failure(e);
                 }},

                {"overlays", "List and clean disposable run overlays", "/sandbox overlays [clean]",
                 {"clean"}, CommandRequirement::None, CommandSafety::Mutating,
                 [](const std::vector<std::string>& a) {
                     auto& sandbox = App::SandboxService::Instance();

                     if (!a.empty() && (a[0] == "clean" || a[0] == "cleanup")) {
                         std::vector<std::string> removed;
                         auto swept = sandbox.SweepStaleOverlays(removed);
                         auto r = App::CommandResult::Success(
                             removed.empty()
                                 ? "No stale overlays to remove."
                                 : ("Removed " + std::to_string(removed.size()) + " overlay(s), " +
                                    App::FormatBytes(swept.Ok() ? swept.Value() : 0) + " reclaimed."));
                         for (const auto& id : removed) r.Line("Removed " + id);
                         r.Line("Overlays owned by a running QEMU process are never removed.");
                         return r;
                     }

                     auto overlays = sandbox.ListOverlays();
                     if (overlays.empty()) {
                         auto r = App::CommandResult::Success("No overlays present.");
                         r.Line("Each isolated run creates one and deletes it when finished.");
                         return r;
                     }

                     auto r = App::CommandResult::Success(
                         std::to_string(overlays.size()) + " overlay(s).");
                     for (const auto& overlay : overlays) {
                         r.Line(overlay.id + "  " + App::FormatBytes(overlay.sizeBytes) +
                                (overlay.active
                                     ? ("  ACTIVE (pid " + std::to_string(overlay.ownerPid) + ")")
                                     : "  stale"));
                     }
                     return r;
                 }},

                {"reset", "Stop, clean overlays, verify and rebuild the base", "/sandbox reset",
                 {}, CommandRequirement::None, CommandSafety::Mutating,
                 [](const std::vector<std::string>&) {
                     return App::SandboxService::Instance().Reset();
                 }},
            },
            .defaultSubcommand = "status",
            .argCompletions = {"status", "image", "overlays", "reset"},
        });

        // 10b. /antievasion
        Register({
            .name = "antievasion",
            .aliases = {"antivm", "evasion", "ae"},
            .description = "Detect and analyze anti-VM / anti-sandbox behavior",
            .usage = "/antievasion [file] [--detect|--compare] [--profile <name>] [--details]",
            .category = "Analysis",
            .detailedHelp =
                "Finds code that changes what it does when it believes it is being analyzed, "
                "shows where that code is, and can prove whether the check actually matters.\n"
                "\n"
                "MODES\n"
                "  --detect    (default) Static detection plus one controlled emulation run. "
                "Cheap. Reports what the sample inspects and whether the value reaches a branch.\n"
                "  --compare   Differential execution. Runs the sample under several environment "
                "profiles and compares reached blocks, functions, branches, API calls and "
                "termination. This is the only mode that can PROVE behavior is environment-"
                "sensitive rather than merely infer it.\n"
                "  --details   Full evidence: every observation, the provenance chain, and the "
                "complete normalization audit trail.\n"
                "\n"
                "PROFILES\n"
                "  Baseline          Dracula's default environment. Honest about being an "
                "analysis environment: hypervisor bit set, virtual device metadata, frozen clock.\n"
                "  Realistic         Ordinary desktop characteristics (8 CPUs, 32 GB, a clock "
                "that advances, sleeps that elapse) with virtualization evidence left intact.\n"
                "  AnalysisFriendly  Selected analysis indicators normalized so environment-gated "
                "code paths become reachable. Every normalized value is recorded.\n"
                "\n"
                "CONFIDENCE\n"
                "  Low        a suspicious string, nothing more\n"
                "  Medium     an environment API or instruction pattern is present\n"
                "  High       the value is compared and controls a branch\n"
                "  Very High  differential execution proved behavior changed\n"
                "\n"
                "OBSERVED vs INFERRED\n"
                "  Each technique states how it was established: detected statically, modelled in "
                "Unicorn, observed in QEMU, or verified differentially. Static detection says a "
                "check EXISTS; only differential execution says it MATTERS.\n"
                "\n"
                "EVIDENCE AND AUDIT\n"
                "  Every value Dracula supplies that differs from Baseline appears in the "
                "normalization trail with its baseline value, supplied value and reason. Dracula "
                "never changes what a sample sees without saying so.\n"
                "\n"
                "IMPORTANT\n"
                "  Detecting a virtual environment is NOT evidence of malice. Development tools, "
                "games, licensing systems and enterprise software all do it legitimately, so "
                "environment sensitivity is scored on its own axis and contributes only a small, "
                "capped amount to the threat score. No virtual environment can be made "
                "indistinguishable from physical hardware, and Dracula does not claim otherwise.",
            .examples = {
                "/antievasion",
                "/antievasion samples\\antievasion\\ae_cpuid_gate.exe",
                "/antievasion --compare",
                "/antievasion sample.exe --compare --details",
                "/antievasion sample.exe --profile analysis-friendly"
            },
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {"--detect", "--compare", "--details", "--profile"},
            .flagCompletions = {{"--profile", {"baseline", "realistic", "analysis-friendly"}}},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleAntiEvasion(args);
            }
        });

        // 11. /scan
        Register({
            .name = "scan",
            .aliases = {},
            .description = "Scan a file using a hex/AOB wildcard pattern",
            .usage = "/scan [file] <pattern>",
            .category = "Analysis",
            .detailedHelp = "Searches for bytecode patterns with wildcards (e.g. '48 8B 05 ?? ?? ?? ?? 48 85 C0').",
            .examples = {"/scan sample.exe \"48 8B ?? ?? ?? ??\"", "/scan \"E8 ?? ?? ?? ??\""},
            .takesFilePath = true,
            .requiresArgs = true,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleScan(args);
            }
        });

        // 12. /functions
        Register({
            .name = "functions",
            .aliases = {"funcs", "fn"},
            .description = "Show discovered functions and entrypoints",
            .usage = "/functions [file]",
            .category = "Inspection",
            .detailedHelp = "Lists all identified function entry points, sizes, and basic block counts in the active binary.",
            .examples = {"/functions", "/functions sample.exe"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleFunctions(args);
            }
        });

        // 13. /cfg
        Register({
            .name = "cfg",
            .aliases = {},
            .description = "Show Control-Flow Graph for target function",
            .usage = "/cfg [file] [rva]",
            .category = "Inspection",
            .detailedHelp = "Constructs and renders the control-flow basic block topology with conditional branch pathways.",
            .examples = {"/cfg", "/cfg sample.exe", "/cfg sample.exe 0x1000"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleCfg(args);
            }
        });

        // 14. /xrefs
        Register({
            .name = "xrefs",
            .aliases = {"xref", "x"},
            .description = "Show cross references to code, strings, and imports",
            .usage = "/xrefs [file] [rva]",
            .category = "Inspection",
            .detailedHelp = "Analyzes CALL/JMP targets and data references across the binary to build cross-reference graphs.",
            .examples = {"/xrefs", "/xrefs sample.exe", "/xrefs sample.exe 0x1000"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleXrefs(args);
            }
        });

        // 15. /findings
        Register({
            .name = "findings",
            .aliases = {},
            .description = "Show findings and evidence from the active session",
            .usage = "/findings",
            .category = "Session",
            .detailedHelp = "Displays all structured security, threat, and mitigation findings collected during analysis.",
            .examples = {"/findings"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleFindings(args);
            }
        });

        // 16. /report
        Register({
            .name = "report",
            .aliases = {},
            .description = "Export current analysis to JSON, Markdown, or TXT",
            .usage = "/report [json|md|txt] [output_path]",
            .category = "Session",
            .detailedHelp = "Serializes the active session analysis results to standard machine-readable JSON, Markdown documentation, or summary TXT.",
            .examples = {"/report json", "/report md report.md", "/report txt summary.txt"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {"json", "md", "txt", "markdown"},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleReport(args);
            }
        });

        // 18. /mcp
        Register({
            .name = "mcp",
            .aliases = {},
            .description = "Start Model Context Protocol (MCP) stdio server",
            .usage = "/mcp",
            .category = "System",
            .detailedHelp = "Launches native JSON-RPC 2.0 stdio server for AI pair-programming and tool invocation.",
            .examples = {"/mcp"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleMcp(args);
            }
        });

        // 19. /changelog
        Register({
            .name = "changelog",
            .aliases = {"changes", "cl"},
            .description = "Show Dracula version history and release notes",
            .usage = "/changelog [version]",
            .category = "System",
            .detailedHelp = "Reads and displays entries from CHANGELOG.txt. Optionally pass a version number to inspect specific release.",
            .examples = {"/changelog", "/changelog 1.0.0"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {"1.0.0"},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleChangelog(args);
            }
        });

        // 20. /version
        Register({
            .name = "version",
            .aliases = {"v"},
            .description = "Show Dracula version, build architecture, and engines",
            .usage = "/version",
            .category = "System",
            .detailedHelp = "Prints central authoritative version string, compiler toolchain, and integrated engine versions.",
            .examples = {"/version"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleVersion(args);
            }
        });

        // 21. /clear
        Register({
            .name = "clear",
            .aliases = {"cls"},
            .description = "Clear terminal screen and reset viewport",
            .usage = "/clear",
            .category = "System",
            .detailedHelp = "Clears the active console screen buffer and returns cursor to top-left position.",
            .examples = {"/clear"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleClear(args);
            }
        });

        // 22. /help
        Register({
            .name = "help",
            .aliases = {"?", "h"},
            .description = "Show interactive command overview or detailed command help",
            .usage = "/help [command]",
            .category = "System",
            .detailedHelp = "Displays complete command reference organized by category, or detailed syntax for a specific command.",
            .examples = {"/help", "/help analyze", "/help emulate"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {"analyze", "disasm", "headers", "security", "imports", "exports", "strings", "entropy", "emulate", "sandbox", "antievasion", "scan", "functions", "cfg", "xrefs", "findings", "report", "session", "mcp", "changelog", "version", "clear", "help", "exit"},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleHelp(args);
            }
        });

        // 23. /exit
        Register({
            .name = "exit",
            .aliases = {"quit", "q"},
            .description = "Exit Dracula interactive shell",
            .usage = "/exit",
            .category = "System",
            .detailedHelp = "Saves command history and terminates the interactive shell session cleanly.",
            .examples = {"/exit"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleExit(args);
            }
        });

        m_initialized = true;
    }

} // namespace Dracula
