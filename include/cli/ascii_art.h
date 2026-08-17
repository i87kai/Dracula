#pragma once

//
// Dracula UI assets.
//
// Dracula has exactly ONE piece of identity artwork: the compact bat mark. It
// is small enough (3 rows) to sit beside the identity text in the persistent
// header at any terminal size, which is what lets the windowed and fullscreen
// layouts look the same.
//
// The mark is compiled directly into the executable rather than loaded from a
// file at runtime, so a released Dracula.exe renders identically no matter
// which directory it is launched from. It is pure ASCII, so it also renders
// identically with --no-unicode.
//

#include <string>
#include <vector>

namespace Dracula {
namespace Art {

    // The Dracula bat mark: 3 rows x 15 display cells, pure ASCII.
    // Deliberately the only artwork in the product - there is no large splash
    // variant to fall back to or degrade from.
    const std::vector<std::string>& Bat();

    // Maximum visible width of an art block, in display cells.
    size_t MaxWidth(const std::vector<std::string>& art);

    // Apply the Dracula crimson base tone to every row. The returned rows have
    // exactly the same visible width as the input rows.
    std::vector<std::string> Colorize(const std::vector<std::string>& art);

} // namespace Art
} // namespace Dracula
