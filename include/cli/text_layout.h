#pragma once

//
// Dracula Terminal Layout Primitives
// ----------------------------------
// Central, ANSI-aware and UTF-8-aware text measurement / composition layer.
//
// Every border, box, column and table in Dracula is generated through these
// primitives. No command may compute padding from std::string::size() because
// that counts raw bytes (UTF-8 multi-byte glyphs and ANSI escape sequences
// would corrupt every alignment calculation).
//

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace Dracula {
namespace Text {

    // ─── Measurement ────────────────────────────────────────────────────────

    // Remove every CSI / OSC escape sequence.
    std::string StripAnsi(const std::string& text);

    // Number of display cells a UTF-8 string occupies once ANSI styling
    // (which occupies zero columns) has been discarded.
    size_t VisibleWidth(const std::string& text);

    // Display width of a single Unicode code point (0, 1 or 2).
    int CodePointWidth(uint32_t cp);

    // Decode the UTF-8 sequence starting at index i, advancing i.
    uint32_t DecodeUtf8(const std::string& s, size_t& i);

    // ─── Composition ────────────────────────────────────────────────────────

    std::string Repeat(const std::string& unit, size_t count);

    // Pad to `width` display cells. Never truncates; returns text unchanged if
    // it is already wider.
    std::string PadRight(const std::string& text, size_t width, char fill = ' ');
    std::string PadLeft(const std::string& text, size_t width, char fill = ' ');
    std::string Center(const std::string& text, size_t width, char fill = ' ');

    // Truncate to at most `width` display cells, appending an ellipsis when
    // the text had to be cut. ANSI sequences are preserved and a reset is
    // appended when styling was active.
    std::string Truncate(const std::string& text, size_t width);

    // Force to exactly `width` cells (truncate then pad).
    std::string Fit(const std::string& text, size_t width);

    // Greedy word wrap on display width. Never returns an empty vector.
    std::vector<std::string> Wrap(const std::string& text, size_t width);

    // ─── Frames ─────────────────────────────────────────────────────────────

    // A horizontal rule of `width` display cells built from the active box
    // drawing glyph (or '-' in ASCII mode).
    std::string HorizontalRule(size_t width);

    // Rows fed to BoxBuilder. Content may contain ANSI styling.
    class BoxBuilder {
    public:
        // totalWidth is the OUTER width in display cells, borders included.
        explicit BoxBuilder(size_t totalWidth, size_t padding = 1);

        BoxBuilder& Title(const std::string& title);   // embedded in the top rule
        BoxBuilder& AddLine(const std::string& content);
        BoxBuilder& AddBlank();
        BoxBuilder& AddDivider();
        BoxBuilder& AddLines(const std::vector<std::string>& lines);

        size_t InnerWidth() const { return m_innerWidth; }
        size_t TotalWidth() const { return m_totalWidth; }

        // Render into individual rows. Every returned row is guaranteed to
        // have VisibleWidth() == TotalWidth().
        std::vector<std::string> Build() const;

    private:
        struct Row { enum Kind { Content, Divider } kind; std::string text; };

        size_t m_totalWidth;
        size_t m_padding;
        size_t m_innerWidth;
        std::string m_title;
        std::vector<Row> m_rows;
    };

    // Join blocks of text side by side. Each block is padded to its column
    // width so that the resulting rows are rectangular. Shorter blocks are
    // padded with blank rows.
    std::vector<std::string> RenderColumns(
        const std::vector<std::vector<std::string>>& blocks,
        const std::vector<size_t>& widths,
        size_t gap = 3);

    // ─── Tables ─────────────────────────────────────────────────────────────

    struct TableColumn {
        std::string header;
        size_t minWidth = 0;
        size_t maxWidth = 0;      // 0 = unbounded
        bool rightAlign = false;
    };

    class Table {
    public:
        explicit Table(std::vector<TableColumn> columns);

        void AddRow(std::vector<std::string> cells);
        size_t RowCount() const { return m_rows.size(); }

        // Render with a 2-space indent, fitting into `availableWidth` cells.
        std::vector<std::string> Render(size_t availableWidth,
                                        const std::string& headerColor = "",
                                        const std::string& resetColor = "") const;

    private:
        std::vector<TableColumn> m_columns;
        std::vector<std::vector<std::string>> m_rows;
    };

} // namespace Text
} // namespace Dracula
