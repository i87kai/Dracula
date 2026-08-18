//
// Command regression suite (v1.3.0 milestone, section 41).
//
// Each check here corresponds to a defect found by manual testing of v1.2.4.
// The single theme: a command must resolve its subject from the active
// project, and a PID must never be interpreted as a filesystem path.
//
// Commands are driven through DraculaShell::ExecuteCommand with stdout
// captured, so these are end-to-end assertions about what the user sees, not
// unit tests of a service in isolation.
//

#include "cli/dracula_shell.h"
#include "cli/command_registry.h"
#include "app/services.h"
#include "app/project_manager.h"
#include "common/paths.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <algorithm>
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
    std::cout << "  ok: " << what << "\n";
}

// Runs a command and returns everything it printed.
static std::string Run(DraculaShell& shell, const std::string& command) {
    std::ostringstream captured;
    std::streambuf* saved = std::cout.rdbuf(captured.rdbuf());
    std::streambuf* savedErr = std::cerr.rdbuf(captured.rdbuf());
    shell.ExecuteCommand(command);
    std::cout.rdbuf(saved);
    std::cerr.rdbuf(savedErr);
    return captured.str();
}

static bool Contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

// The specific failure mode being guarded against: a specifier fragment
// surfacing anywhere in output, which only happens if it was treated as a path.
static void CheckNoPidAsPath(const std::string& output, const std::string& command) {
    Check(!Contains(output, "--pid"),
          command + " never echoes '--pid' (it is not a path)");
    Check(!Contains(output, "file does not exist: -"),
          command + " never reports a flag as a missing file");
    Check(!Contains(output, "does not exist: 17140") &&
          !Contains(output, "does not exist: 4820"),
          command + " never treats a bare PID as a path");
}

int main() {
    std::cout << "[Test] Running Command Regression Suite...\n";

    fs::path sandbox = fs::temp_directory_path() / "dracula_cmd_regression";
    std::error_code ec;
    fs::remove_all(sandbox, ec);
    fs::create_directories(sandbox);
    Paths::SetInstallRoot((sandbox / "root").string());

    // A benign fixture. It need not be a valid PE: these tests are about
    // subject resolution, not parsing.
    fs::path samples = sandbox / "samples";
    fs::create_directories(samples);
    const fs::path fixture = samples / "regression_fixture.exe";
    {
        std::ofstream out(fixture, std::ios::binary | std::ios::trunc);
        out << "MZ" << std::string(2048, '\0');
    }

    DraculaShell shell;
    App::ProjectManager& pm = App::ProjectManager::Instance();
    std::string error;
    pm.LoadIndex(error);

    // --- A file-backed project -----------------------------------------------
    {
        std::string out = Run(shell, "/target " + fixture.string());
        Check(Contains(out, "project") || Contains(out, "Created") || Contains(out, "Continued"),
              "/target <file> creates a durable project");
        Check(pm.Active() != nullptr, "the project becomes active");
    }

    // --- Commands that used to reparse a path now use the project ------------
    {
        // /static must not require a path argument.
        std::string out = Run(shell, "/static");
        Check(!Contains(out, "Unknown command"), "/static is a real command");
        Check(!Contains(out, "Missing target"), "/static uses the active project, not an argument");
        CheckNoPidAsPath(out, "/static");
    }

    // --- Simulated process project (no live PID required) --------------------
    // Building the project directly keeps this test deterministic and free of
    // any dependency on a particular process being running.
    {
        auto project = std::make_shared<App::Project>();
        project->InitializeNew("regressionpid",
                               "regression_proc",
                               (fs::path(Paths::ProjectsDir()) / "regression_proc").string());
        Check(project->EnsureLayout(error), "process project layout created");

        // Give it a real backing image: its own copy of the fixture.
        const fs::path copy = fs::path(project->OriginalDir()) / "regression_fixture.exe";
        fs::copy_file(fixture, copy, fs::copy_options::overwrite_existing, ec);

        auto& target = project->Target();
        target.kind = UTR::TargetKind::RunningProcess;
        target.name = "regression_fixture.exe";
        target.pid = 17140;
        target.backingExecutable = fixture.string();
        target.projectCopyRelative = "original/regression_fixture.exe";
        target.architecture = "x64";

        Check(project->Save(error), "process project saved");
        pm.SetActive(project);
        App::TargetBinding::Instance().Invalidate();

        // THE regression: the PID never becomes a path, in any of these.
        const char* commands[] = {
            "/static", "/static info", "/static sections", "/static imports",
            "/functions", "/analyze", "/report", "/antievasion",
            "/sandbox", "/dotnet", "/driver", "/headers", "/security",
            "/target info", "/target capabilities", "/project info",
        };

        for (const char* command : commands) {
            std::string out = Run(shell, command);
            Check(!Contains(out, "Unknown command"),
                  std::string(command) + " is a registered command");
            CheckNoPidAsPath(out, command);
        }

        // The backing image is what static analysis resolves to.
        auto resolved = App::StaticService::Instance().ResolveStaticPath();
        Check(resolved.Ok(), "static analysis resolves a path for a PID-backed project");
        Check(!Contains(resolved.Value(), "--pid") &&
              !Contains(resolved.Value(), "17140"),
              "the resolved static path is a real file, not a PID");
        Check(Contains(resolved.Value(), "regression_fixture.exe"),
              "the resolved static path is the backing executable");
    }

    // --- /runtime events answers instead of printing usage -------------------
    {
        std::string out = Run(shell, "/runtime events");
        Check(!Contains(out, "Available runtime commands"),
              "/runtime events does not return a usage hint for a valid command");
        Check(Contains(out, "event") || Contains(out, "No runtime events"),
              "/runtime events reports the event state");
    }

    // --- /runtime status is truthful -----------------------------------------
    {
        std::string out = Run(shell, "/runtime status");
        // The v1.2.4 output claimed "QEMU GuestAgent: Ready" with no VM at all.
        Check(!Contains(out, "GuestAgent:     Ready") && !Contains(out, "GuestAgent: Ready"),
              "/runtime status never claims the guest agent is Ready without a VM");
        Check(Contains(out, "QEMU"), "/runtime status reports QEMU");
        Check(Contains(out, "GuestAgent"), "/runtime status reports the guest agent");
    }

    // --- /dll palette and handler agree --------------------------------------
    {
        for (const char* sub : {"info", "exports", "imports", "functions"}) {
            std::string out = Run(shell, std::string("/dll ") + sub);
            Check(!Contains(out, "is not a dll subcommand"),
                  std::string("/dll ") + sub + " is accepted by dispatch");
            Check(!Contains(out, "Available DLL commands"),
                  std::string("/dll ") + sub + " does not fall back to a usage hint");
        }
    }

    // --- An unknown subcommand explains itself and lists the real ones -------
    {
        std::string out = Run(shell, "/dll definitely_not_a_subcommand");
        Check(Contains(out, "not a dll subcommand"),
              "an unknown subcommand is reported clearly");
        Check(Contains(out, "exports") && Contains(out, "functions"),
              "the error lists the subcommands that DO exist");
    }

    // --- Memory commands on a non-live project fail with capability info -----
    // Created through ProjectManager so it is indexed and therefore resolvable
    // by name, which the deletion check below relies on.
    std::string deletableId;
    {
        auto created = pm.CreateFromFile(fixture.string());
        Check(created.Ok(), "file-backed project created through the manager");
        deletableId = created.Value().project->Id();
        App::TargetBinding::Instance().Invalidate();

        std::string out = Run(shell, "/memory map");
        Check(!Contains(out, "Unknown command"), "/memory map is a real command");
        // The failure explains the capability, it does not report a bad path.
        Check(!Contains(out, "file does not exist"),
              "/memory map on a file target does not produce a path error");
        Check(Contains(out, "live target") || Contains(out, "Available for this target") ||
              Contains(out, "requires"),
              "/memory map explains why it is unavailable and what is");
    }

    // --- /session delete exists and is safe ----------------------------------
    {
        std::string out = Run(shell, "/session delete " + deletableId);
        Check(!Contains(out, "Unknown command"), "/session delete exists");
        // Without --force it must confirm rather than act.
        Check(Contains(out, "Confirm") || Contains(out, "confirmation") ||
              Contains(out, "Delete") || Contains(out, "removes"),
              "/session delete asks for confirmation before removing anything");
        Check(fs::exists(fixture), "the user's original file is untouched by a delete attempt");
    }

    // --- /session list reflects durable workspaces ----------------------------
    {
        std::string out = Run(shell, "/session list");
        Check(!Contains(out, "Unknown command"), "/session list exists");
        Check(!Contains(out, "no analysis result"),
              "/session list no longer reports the legacy 'no analysis result' state");
    }

    pm.CloseActive();
    App::TargetBinding::Instance().Invalidate();
    fs::remove_all(sandbox, ec);

    std::cout << "[Test] Command Regression Suite PASSED (" << g_checks << " checks).\n";
    return 0;
}
