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

    // Locate a shipped resource by relative name (e.g. "CHANGELOG.txt" or
    // "config/config.ini"). Search order: working directory, resource root,
    // executable directory, then executable ancestors. Returns "" when the
    // resource cannot be found.
    std::string ResolveResource(const std::string& relativeName);

} // namespace Paths
} // namespace Dracula
