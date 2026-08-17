#include "cli/ascii_art.h"
#include "cli/text_layout.h"
#include "cli/terminal.h"
#include "cli/dracula_art_data.h"   // generated from the project artwork asset

#include <algorithm>

namespace Dracula {
namespace Art {

    namespace {

        // The Braille blank. Padding with U+2800 rather than a space keeps the
        // block visually uniform - a real space renders differently from a blank
        // Braille cell in many fonts.
        constexpr const char* kBrailleBlank = "\xE2\xA0\x80";

        std::vector<std::string> LoadEmbeddedVampire() {
            std::vector<std::string> rows;
            rows.reserve(static_cast<size_t>(Embedded::kVampireRowCount));
            for (int i = 0; i < Embedded::kVampireRowCount; ++i) {
                rows.emplace_back(Embedded::kVampireRows[i]);
            }

            // The asset may have a ragged right edge; the layout engine needs a
            // rectangular block, so short rows are padded with blank cells.
            size_t widest = 0;
            for (const auto& row : rows) {
                widest = std::max(widest, Text::VisibleWidth(row));
            }
            for (auto& row : rows) {
                for (size_t w = Text::VisibleWidth(row); w < widest; ++w) {
                    row += kBrailleBlank;
                }
            }
            return rows;
        }

    } // namespace

    const std::vector<std::string>& Vampire() {
        static const std::vector<std::string> kArt = LoadEmbeddedVampire();
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
