//
// Command registry consistency suite (v1.3.0 milestone, sections 12/13/41).
//
// The defect this prevents: the palette advertised
//   /dll [info|exports|imports|run <export>|trace]
// while the handler only implemented "exports" and "run". Anything the UI
// offers must resolve to a real handler, and every command in the tree must be
// reachable.
//

#include "cli/command_registry.h"
#include "app/services.h"
#include "app/settings.h"
#include "common/paths.h"

#include <iostream>
#include <filesystem>
#include <set>
#include <cstdlib>

namespace fs = std::filesystem;
using namespace Dracula;

static int g_checks = 0;

static void Check(bool condition, const std::string& what) {
    ++g_checks;
    if (!condition) {
        std::cerr << "  FAILED: " << what << "\n";
        std::exit(1);
    }
}

static void Report(const std::string& what) {
    std::cout << "  ok: " << what << "\n";
}

int main() {
    std::cout << "[Test] Running Command Registry Suite...\n";

    // Isolate so probing commands cannot touch real projects.
    fs::path sandbox = fs::temp_directory_path() / "dracula_registry_test";
    std::error_code ec;
    fs::remove_all(sandbox, ec);
    Paths::SetInstallRoot(sandbox.string());

    auto& registry = CommandRegistry::Instance();
    const auto& commands = registry.GetAllCommands();

    Check(!commands.empty(), "registry is populated");
    Report("registry is populated (" + std::to_string(commands.size()) + " commands)");

    // --- No duplicate names or aliases --------------------------------------
    {
        std::set<std::string> seen;
        for (const auto& cmd : commands) {
            Check(seen.insert(cmd.name).second,
                  "command '" + cmd.name + "' is registered exactly once");
            for (const auto& alias : cmd.aliases) {
                Check(seen.insert(alias).second,
                      "alias '" + alias + "' (" + cmd.name + ") is unique");
            }
        }
        Report("no duplicate command names or aliases");
    }

    // --- Every command is dispatchable --------------------------------------
    {
        for (const auto& cmd : commands) {
            const bool dispatchable = cmd.handler || !cmd.subcommands.empty();
            Check(dispatchable,
                  "command '" + cmd.name + "' has a handler or subcommands");
        }
        Report("every command is dispatchable");
    }

    // --- THE core invariant: advertised == implemented ----------------------
    // Everything the palette shows must resolve to a handler.
    {
        size_t subcommandCount = 0;
        for (const auto& cmd : commands) {
            for (const auto& sub : cmd.subcommands) {
                ++subcommandCount;

                Check(static_cast<bool>(sub.handler),
                      "/" + cmd.name + " " + sub.name + " has a real handler");
                Check(!sub.description.empty(),
                      "/" + cmd.name + " " + sub.name + " has a description");
                Check(!sub.usage.empty(),
                      "/" + cmd.name + " " + sub.name + " has a usage string");

                // The palette renders SubcommandNames(); dispatch resolves via
                // FindSubcommand(). They must agree for every entry.
                const auto* resolved = registry.FindSubcommand(cmd, sub.name);
                Check(resolved != nullptr,
                      "/" + cmd.name + " " + sub.name + " resolves through dispatch");
                Check(resolved == &sub,
                      "/" + cmd.name + " " + sub.name + " resolves to itself");
            }
        }
        Report("all " + std::to_string(subcommandCount) +
               " advertised subcommands resolve to real handlers");
    }

    // --- Palette names match dispatch exactly -------------------------------
    {
        for (const auto& cmd : commands) {
            auto names = registry.SubcommandNames(cmd);
            Check(names.size() == cmd.subcommands.size(),
                  "/" + cmd.name + " palette lists every subcommand");
            for (const auto& name : names) {
                Check(registry.FindSubcommand(cmd, name) != nullptr,
                      "/" + cmd.name + " palette entry '" + name + "' is dispatchable");
            }
        }
        Report("palette names match dispatch exactly");
    }

    // --- argCompletions must not advertise phantom subcommands --------------
    // This is precisely how "/dll ... trace" became visible without existing.
    {
        for (const auto& cmd : commands) {
            if (cmd.subcommands.empty()) continue;
            for (const auto& completion : cmd.argCompletions) {
                if (!completion.empty() && completion[0] == '-') continue;  // a flag
                Check(registry.FindSubcommand(cmd, completion) != nullptr,
                      "/" + cmd.name + " completion '" + completion + "' is a real subcommand");
            }
        }
        Report("no completion advertises a non-existent subcommand");
    }

    // --- The default subcommand must exist ----------------------------------
    {
        for (const auto& cmd : commands) {
            if (cmd.defaultSubcommand.empty()) continue;
            Check(registry.FindSubcommand(cmd, cmd.defaultSubcommand) != nullptr,
                  "/" + cmd.name + " default subcommand '" + cmd.defaultSubcommand + "' exists");
        }
        Report("default subcommands exist");
    }

    // --- Specific regressions from manual testing ---------------------------
    {
        const auto* dll = registry.Find("dll");
        Check(dll != nullptr, "/dll is registered");
        for (const char* name : {"info", "exports", "imports", "functions"}) {
            const auto* sub = registry.FindSubcommand(*dll, name);
            Check(sub && sub->handler,
                  std::string("/dll ") + name + " is implemented (palette/handler agreement)");
        }
        // "trace" was advertised but never implemented; it must now be absent
        // rather than silently shown.
        Check(registry.FindSubcommand(*dll, "trace") == nullptr,
              "/dll trace is no longer advertised (it was never implemented)");
        Report("/dll palette and handlers agree");

        const auto* runtime = registry.Find("runtime");
        Check(runtime != nullptr, "/runtime is registered");
        const auto* events = registry.FindSubcommand(*runtime, "events");
        Check(events && events->handler,
              "/runtime events is implemented (it returned usage in v1.2.4)");
        Report("/runtime events is dispatchable");

        const auto* session = registry.Find("session");
        Check(session != nullptr, "/session is registered");
        const auto* del = registry.FindSubcommand(*session, "delete");
        Check(del && del->handler, "/session delete exists and is implemented");
        for (const char* name : {"list", "use", "info", "cleanup"}) {
            Check(registry.FindSubcommand(*session, name) != nullptr,
                  std::string("/session ") + name + " exists");
        }
        Report("/session list/use/info/cleanup/delete all exist");

        const auto* project = registry.Find("project");
        Check(project != nullptr, "/project is registered");
        for (const char* name : {"info", "list", "open", "close", "storage", "cleanup", "delete"}) {
            Check(registry.FindSubcommand(*project, name) != nullptr,
                  std::string("/project ") + name + " exists");
        }
        Report("/project subcommands all exist");

        const auto* stat = registry.Find("static");
        Check(stat != nullptr, "/static is registered");
        for (const char* name : {"info", "sections", "imports", "exports", "strings"}) {
            Check(registry.FindSubcommand(*stat, name) != nullptr,
                  std::string("/static ") + name + " exists");
        }
        Report("/static subcommands all exist");

        const auto* mem = registry.Find("memory");
        Check(mem != nullptr, "/memory is registered");
        for (const char* name : {"map", "read", "snapshot", "snapshots", "compare"}) {
            Check(registry.FindSubcommand(*mem, name) != nullptr,
                  std::string("/memory ") + name + " exists");
        }
        Report("/memory subcommands all exist");

        const auto* proc = registry.Find("process");
        Check(proc != nullptr, "/process is registered");
        for (const char* name : {"list", "attach", "info", "modules", "threads"}) {
            Check(registry.FindSubcommand(*proc, name) != nullptr,
                  std::string("/process ") + name + " exists");
        }
        Report("/process subcommands all exist");
    }

    // --- Prefix resolution ---------------------------------------------------
    {
        const auto* mem = registry.Find("memory");
        const auto* snap = registry.FindSubcommand(*mem, "snap");
        // "snap" is a prefix of both "snapshot" and "snapshots", so it is
        // ambiguous and must resolve to nothing rather than to a guess.
        Check(snap == nullptr, "ambiguous subcommand prefix resolves to nothing");

        const auto* compare = registry.FindSubcommand(*mem, "comp");
        Check(compare != nullptr && compare->name == "compare",
              "unambiguous subcommand prefix resolves");
        Report("prefix resolution is unambiguous or refuses");
    }

    // --- Aliases resolve -----------------------------------------------------
    {
        Check(registry.Find("proj") == registry.Find("project"), "/proj aliases /project");
        Check(registry.Find("mem") == registry.Find("memory"), "/mem aliases /memory");
        Check(registry.Find("ps") == registry.Find("process"), "/ps aliases /process");
        Check(registry.Find("/project") == registry.Find("project"),
              "leading slash is accepted");
        Report("aliases and slash-prefixed names resolve");
    }

    // --- Capability requirements are enforced without a project -------------
    {
        App::ErrorDetail error;

        Check(CommandRegistry::RequirementSatisfied(CommandRequirement::None, error),
              "None requirement is always satisfied");

        error = App::ErrorDetail{};
        Check(!CommandRegistry::RequirementSatisfied(CommandRequirement::ActiveProject, error),
              "ActiveProject requirement fails with no project open");
        Check(error.code == "no_active_project", "failure carries a machine-readable code");
        Check(!error.message.empty() && !error.reason.empty() && !error.remediation.empty(),
              "capability failure explains itself and says what to do");

        error = App::ErrorDetail{};
        Check(!CommandRegistry::RequirementSatisfied(CommandRequirement::LiveProcess, error),
              "LiveProcess requirement fails with no project open");
        Report("capability requirements are enforced with useful errors");
    }

    // --- Requirements are described, never blank ----------------------------
    {
        for (auto req : {CommandRequirement::None, CommandRequirement::ActiveProject,
                         CommandRequirement::FileBacking, CommandRequirement::LiveProcess,
                         CommandRequirement::ManagedTarget}) {
            Check(!CommandRegistry::DescribeRequirement(req).empty(),
                  "every requirement has a human description");
        }
        Report("all requirements are describable");
    }

    // --- Metadata quality ----------------------------------------------------
    {
        for (const auto& cmd : commands) {
            Check(!cmd.description.empty(), "/" + cmd.name + " has a description");
            Check(!cmd.usage.empty(), "/" + cmd.name + " has a usage string");
            Check(!cmd.category.empty(), "/" + cmd.name + " has a category");
        }
        Report("every command carries complete help metadata");
    }

    fs::remove_all(sandbox, ec);

    std::cout << "[Test] Command Registry Suite PASSED (" << g_checks << " checks).\n";
    return 0;
}
