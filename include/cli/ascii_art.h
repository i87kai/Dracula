#pragma once

//
// Dracula UI assets.
//
// Dracula has exactly ONE piece of identity artwork: the vampire mark supplied
// in the project asset
//
//     Vampire Dracula ASCII Art.txt
//
// which is the authoritative source. cmake/EmbedArt.cmake reads that file at
// build time and generates cli/dracula_art_data.h holding its bytes as explicit
// escapes, so a released Dracula.exe renders identically no matter which
// directory it is launched from and never reads the asset from disk.
//
// The artwork is Braille (U+28xx), one display cell per glyph. Rows are padded
// to a uniform width so the block can be composed as a fixed-width column
// without measurement games.
//

#include <string>
#include <vector>

namespace Dracula {
namespace Art {

    // The supplied vampire artwork, one entry per row, padded to a uniform
    // width. Deliberately the only artwork in the product.
    const std::vector<std::string>& Vampire();

    // Maximum visible width of an art block, in display cells.
    size_t MaxWidth(const std::vector<std::string>& art);

    // Apply the Dracula crimson base tone to every row. The returned rows have
    // exactly the same visible width as the input rows.
    std::vector<std::string> Colorize(const std::vector<std::string>& art);

} // namespace Art
} // namespace Dracula
