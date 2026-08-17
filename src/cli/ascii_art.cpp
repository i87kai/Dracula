#include "cli/ascii_art.h"
#include "cli/text_layout.h"
#include "cli/terminal.h"

#include <algorithm>

namespace Dracula {
namespace Art {

    // The Dracula bat: wings out to the sides, ears and face in the middle.
    // Every row is padded to exactly 15 cells so the block has no ragged edge
    // and can be composed as a fixed-width column without measurement games.
    const std::vector<std::string>& Bat() {
        static const std::vector<std::string> kArt = {
            R"( /\  /\_/\  /\ )",
            R"(/  \( o.o )/  \)",
            R"(\__/ '---' \__/)",
        };
        return kArt;
    }

    size_t MaxWidth(const std::vector<std::string>& art) {
        size_t w = 0;
        for (const auto& row : art) {
            w = std::max(w, Text::VisibleWidth(row));
        }
        return w;
    }

    std::vector<std::string> Colorize(const std::vector<std::string>& art) {
        std::vector<std::string> out;
        out.reserve(art.size());

        const std::string base  = Terminal::Color(ColorRole::Primary);
        const std::string reset = Terminal::Color(ColorRole::Reset);

        // A single crimson base tone. No per-character gradient: coloring must
        // never influence layout measurement, and a rainbow would fight the
        // hierarchy the header establishes.
        for (const auto& row : art) {
            if (base.empty()) {
                out.push_back(row);
            } else {
                out.push_back(base + row + reset);
            }
        }
        return out;
    }

} // namespace Art
} // namespace Dracula
