#pragma once

//
// The Dracula identity header.
//
// There is one header design, not a splash screen plus a shrunken imitation of
// it: the vampire artwork on the left, the identity / engines / working
// directory beside it, closed by a horizontal divider. A windowed terminal and a
// fullscreen terminal therefore show the same structure; only the size of the
// output region below it changes.
//
// The artwork itself comes from the project asset "Vampire Dracula ASCII
// Art.txt" via Art::Vampire(); see cli/ascii_art.h.
//
// Rendering is a pure function of (terminal width, environment info) so it can
// be unit tested at any width without a real console attached. Every row is
// composed through Text:: primitives, which is what guarantees alignment, and
// no row ever reaches the terminal's final column.
//

#include <string>
#include <vector>

namespace Dracula {

    struct StartupInfo {
        std::string version;
        std::string buildTarget;
        std::string architecture;
        std::string buildMode;
        std::string workingDirectory;

        // Engine inventory. Kept for /about and diagnostics, but deliberately
        // NOT shown in the persistent header: "Capstone 5 - Unicorn 2 - Safe PE"
        // is implementation detail that told the user nothing about their work
        // and crowded out what did (section 24).
        std::vector<std::string> engines;

        // What the header actually shows: the state of the current work.
        // Empty strings are omitted rather than rendered as placeholders.
        std::string projectName;
        std::string targetSummary;   // "Native DLL - x64"
        std::string runtimeState;    // "Idle", "PID 17140"
        std::string sandboxState;    // "Available", "Stopped"
        std::string statusText;      // "Ready"

        // Contextual tips. `tipIndex` selects which one is shown; the shell
        // advances it once per executed command. Rotating inside the renderer
        // would change the tip on every keystroke and make a repaint
        // non-deterministic.
        std::vector<std::string> tips;
        size_t tipIndex = 0;

        // Populate from the compiled-in version constants and the process
        // environment.
        static StartupInfo Detect();

        // Refresh projectName / targetSummary / runtimeState / statusText and
        // choose tips appropriate to the current context.
        void RefreshContext();
    };

    // How much vertical space the persistent header claims. Standard is the
    // design; the narrower variants exist only so a genuinely cramped terminal
    // still carries the Dracula identity instead of dropping it.
    enum class HeaderVariant {
        Standard,   // blank + artwork beside identity/engines/cwd + divider
        Compact,    // blank + identity + engines + divider (4 rows)
        Minimal,    // identity + divider (2 rows)
        None        // no header at all (extremely short terminals)
    };

    class StartupCard {
    public:
        // Width thresholds (display cells) at which the header variant changes.
        // Below kCompactMinWidth only the Minimal variant is legible.
        static constexpr int kStandardMinWidth = 44;
        static constexpr int kCompactMinWidth  = 30;

        // The richest variant the given WIDTH can carry, taking Unicode support
        // into account (the artwork is Braille). The screen model then degrades
        // further if the terminal is too short.
        static HeaderVariant SelectVariant(int terminalWidth);

        // The persistent header, including its own left padding and its closing
        // divider. Returns an empty vector for HeaderVariant::None. No row is
        // ever wider than `terminalWidth - 1` cells.
        static std::vector<std::string> RenderHeader(int terminalWidth,
                                                     HeaderVariant variant,
                                                     const StartupInfo& info);

        // The header a given width would pick, ready to render.
        static std::vector<std::string> RenderHeader(int terminalWidth,
                                                    const StartupInfo& info);

        // The streaming (non-persistent) presentation used when Dracula runs
        // without an interactive screen: the same header plus a hint line.
        static std::vector<std::string> Render(int terminalWidth, const StartupInfo& info);
    };

} // namespace Dracula
