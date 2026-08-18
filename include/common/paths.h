#pragma once

//
// Path resolution for Dracula.
//
// Dracula distinguishes three different roots that are frequently NOT the same
// directory:
//
//   * the current working directory  - where the user launched the shell
//   * the executable directory       - where Dracula.exe physically lives
//   * the resource root              - the install/project directory that owns
//                                      CHANGELOG.txt, config/ and rules/
//
// Resources are located relative to the executable (walking up out of build
// trees), never relative to the working directory, so a released Dracula.exe
// behaves identically wherever it is launched from.
//

#include <string>
#include <vector>

namespace Dracula {
namespace Paths {

    // Absolute path of the running executable's directory ("" if unavailable).
    std::string ExecutableDir();

    // Absolute current working directory ("" if unavailable).
    std::string CurrentWorkingDir();

    // Directory that owns Dracula's shipped resources. Determined once by
    // probing the executable directory and its ancestors for a marker file.
    std::string ResourceRoot();

    // User data directory: %LOCALAPPDATA%\Dracula (or ~/.local/share/dracula on POSIX).
    std::string AppDataDir();

    // ─── Dracula Install Root ──────────────────────────────────────────────
    // The root of a Dracula installation, owning the layout described in the
    // v1.3.0 workspace milestone:
    //
    //   <root>\bin  tools  brain  runtime  vm{base,overlays,cache}
    //          projects  cache  logs  config
    //
    // Resolution order: SetInstallRoot() override, then the DRACULA_ROOT
    // environment variable, then the install marker written by the bootstrap
    // installer next to the executable, then AppDataDir() as the portable
    // fallback. Never throws; always returns a usable directory.
    std::string InstallRoot();

    // Override the install root (bootstrap installer, tests, portable mode).
    void SetInstallRoot(const std::string& path);

    // Subdirectories of InstallRoot(). Each is created on first access.
    std::string ProjectsDir();     // <root>\projects  - durable project workspaces
    std::string BrainDir();        // <root>\brain     - reserved for future intelligence assets
    std::string RuntimeDir();      // <root>\runtime
    std::string ToolsDir();        // <root>\tools
    std::string BinDir();          // <root>\bin
    std::string ConfigDir();       // <root>\config
    std::string LogsDir();         // <root>\logs
    std::string CacheDir();        // <root>\cache
    std::string VmDir();           // <root>\vm
    std::string VmBaseDir();       // <root>\vm\base      - immutable .draculaimg bases
    std::string VmOverlaysDir();   // <root>\vm\overlays  - disposable per-run overlays
    std::string VmCacheDir();      // <root>\vm\cache

    // Directory for persistent session databases: %LOCALAPPDATA%\Dracula\sessions
    std::string SessionsDir();

    // Directory for structured analysis artifacts: %LOCALAPPDATA%\Dracula\artifacts
    std::string ArtifactsDir();

    // Directory for temporary runtime data: %TEMP%\Dracula
    std::string TempDir();

    // Override the base data directory (for tests or custom workspace configurations).
    void SetCustomDataDir(const std::string& path);

    // Locate a shipped resource by relative name (e.g. "CHANGELOG.txt" or
    // "config/config.ini"). Search order: working directory, resource root,
    // executable directory, then executable ancestors. Returns "" when the
    // resource cannot be found.
    std::string ResolveResource(const std::string& relativeName);

} // namespace Paths
} // namespace Dracula
