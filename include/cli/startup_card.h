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

    // How much vertical space the persistent header is allowed to claim.
    // Chosen from the terminal HEIGHT, after the width has chosen the artwork
    // layout. Decorative detail is sacrificed before output rows are.
    enum class HeaderVariant {
        Full,        // the approved card, artwork + information + tips
        FullNoTips,  // the same card without the tips block
        Compact,     // four rows: two-row vampire mark + identity + engines
        Minimal,     // two text rows plus a rule
        None         // no header at all (extremely short terminals)
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

        // The card box in an explicitly chosen layout. The persistent header
        // uses this to degrade richness when the terminal is short, rather than
        // dropping the Dracula identity entirely.
        static std::vector<std::string> RenderCardMode(int terminalWidth,
                                                       StartupLayout layout,
                                                       const StartupInfo& info,
                                                       bool includeTips = true);

        // The persistent header in a given height variant. Returns an empty
        // vector for HeaderVariant::None.
        static std::vector<std::string> RenderHeader(int terminalWidth,
                                                     HeaderVariant variant,
                                                     const StartupInfo& info);

        // Outer width of the card box at a given terminal width.
        static int CardWidth(int terminalWidth);
    };

} // namespace Dracula
