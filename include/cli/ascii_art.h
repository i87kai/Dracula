#pragma once

//
// Dracula UI assets.
//
// The Vampire Dracula artwork is compiled directly into the executable as a
// constexpr asset. It is deliberately NOT loaded from a file at runtime so a
// released Dracula.exe renders identically no matter which directory it is
// launched from.
//

#include <string>
#include <vector>

namespace Dracula {
namespace Art {

    // The supplied Vampire Dracula artwork, one entry per row.
    // 16 rows x 52 display cells (U+28xx Braille, single width each).
    const std::vector<std::string>& Vampire();

    // A small ASCII-only vampire mark for narrow terminals.
    const std::vector<std::string>& VampireCompact();

    // A two-row vampire mark for short terminals, where the full artwork
    // cannot be shown without starving the output viewport.
    const std::vector<std::string>& VampireMini();

    // Maximum visible width of an art block, in display cells.
    size_t MaxWidth(const std::vector<std::string>& art);

    // Apply the Dracula crimson base tone to every row. The returned rows have
    // exactly the same visible width as the input rows.
    std::vector<std::string> Colorize(const std::vector<std::string>& art);

} // namespace Art
} // namespace Dracula
