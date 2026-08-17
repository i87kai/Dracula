#pragma once

//
// The Dracula startup card.
//
// Rendering is a pure function of (terminal width, environment info) so that it
// can be unit tested at any width without a real console attached. Every row it
// produces is composed through Text:: primitives, which is what guarantees the
// borders line up.
//

#include <string>
#include <vector>

namespace Dracula {

    enum class StartupLayout {
        Large,     // two-column card: Vampire art beside the information column
        Stacked,   // full art above the information block
        Compact,   // small ASCII mark above a condensed information block
        Minimal    // three lines of text, no artwork
    };

    struct StartupInfo {
        std::string version;
        std::string buildTarget;
        std::string architecture;
        std::string buildMode;
        std::vector<std::string> engines;
        std::string workingDirectory;
        std::vector<std::string> tips;

        // Populate from the compiled-in version constants and the process
        // environment.
        static StartupInfo Detect();
    };

    class StartupCard {
    public:
        // Width thresholds (display cells) at which the layout changes.
        static constexpr int kLargeMinWidth   = 100;
        static constexpr int kStackedMinWidth = 62;
        static constexpr int kCompactMinWidth = 44;

        static StartupLayout SelectLayout(int terminalWidth);

        // Render the complete startup presentation, including the trailing
        // hint line. Never returns rows wider than `terminalWidth`.
        static std::vector<std::string> Render(int terminalWidth, const StartupInfo& info);

        // The card box only (no trailing hint), used by layout tests.
        static std::vector<std::string> RenderCard(int terminalWidth, const StartupInfo& info);

        // Outer width of the card box at a given terminal width.
        static int CardWidth(int terminalWidth);
    };

} // namespace Dracula
