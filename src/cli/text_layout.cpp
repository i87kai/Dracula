#include "cli/text_layout.h"
#include "cli/terminal.h"

#include <algorithm>
#include <sstream>

namespace Dracula {
namespace Text {

    // ─── UTF-8 decoding ─────────────────────────────────────────────────────

    uint32_t DecodeUtf8(const std::string& s, size_t& i) {
        if (i >= s.size()) return 0;
        unsigned char c = static_cast<unsigned char>(s[i]);

        auto cont = [&](size_t k) -> bool {
            return i + k < s.size() &&
                   (static_cast<unsigned char>(s[i + k]) & 0xC0) == 0x80;
        };

        if ((c & 0x80) == 0) {
            i += 1;
            return c;
        }
        if ((c & 0xE0) == 0xC0 && cont(1)) {
            uint32_t cp = ((c & 0x1Fu) << 6) |
                          (static_cast<unsigned char>(s[i + 1]) & 0x3Fu);
            i += 2;
            return cp;
        }
        if ((c & 0xF0) == 0xE0 && cont(1) && cont(2)) {
            uint32_t cp = ((c & 0x0Fu) << 12) |
                          ((static_cast<unsigned char>(s[i + 1]) & 0x3Fu) << 6) |
                          (static_cast<unsigned char>(s[i + 2]) & 0x3Fu);
            i += 3;
            return cp;
        }
        if ((c & 0xF8) == 0xF0 && cont(1) && cont(2) && cont(3)) {
            uint32_t cp = ((c & 0x07u) << 18) |
                          ((static_cast<unsigned char>(s[i + 1]) & 0x3Fu) << 12) |
                          ((static_cast<unsigned char>(s[i + 2]) & 0x3Fu) << 6) |
                          (static_cast<unsigned char>(s[i + 3]) & 0x3Fu);
            i += 4;
            return cp;
        }

        // Invalid / truncated sequence: consume a single byte defensively so
        // iteration always terminates.
        i += 1;
        return 0xFFFDu;
    }

    int CodePointWidth(uint32_t cp) {
        if (cp == 0) return 0;

        // C0 / C1 control characters occupy no columns.
        if (cp < 0x20 || (cp >= 0x7F && cp < 0xA0)) return 0;

        // Combining marks and zero width joiners / variation selectors.
        if ((cp >= 0x0300 && cp <= 0x036F) ||
            (cp >= 0x200B && cp <= 0x200F) ||
            (cp >= 0xFE00 && cp <= 0xFE0F) ||
            (cp >= 0x20D0 && cp <= 0x20F0) ||
            cp == 0xFEFF) {
            return 0;
        }

        // East Asian Wide / Fullwidth ranges plus common emoji planes.
        if ((cp >= 0x1100 && cp <= 0x115F) ||   // Hangul Jamo
            (cp >= 0x2E80 && cp <= 0x303E) ||   // CJK radicals / punctuation
            (cp >= 0x3041 && cp <= 0x33FF) ||   // Kana, CJK compat
            (cp >= 0x3400 && cp <= 0x4DBF) ||   // CJK ext A
            (cp >= 0x4E00 && cp <= 0x9FFF) ||   // CJK unified
            (cp >= 0xA000 && cp <= 0xA4CF) ||   // Yi
            (cp >= 0xAC00 && cp <= 0xD7A3) ||   // Hangul syllables
            (cp >= 0xF900 && cp <= 0xFAFF) ||   // CJK compat ideographs
            (cp >= 0xFE30 && cp <= 0xFE6F) ||   // CJK compat forms
            (cp >= 0xFF00 && cp <= 0xFF60) ||   // Fullwidth forms
            (cp >= 0xFFE0 && cp <= 0xFFE6) ||
            (cp >= 0x1F300 && cp <= 0x1F64F) || // Emoji / pictographs
            (cp >= 0x1F900 && cp <= 0x1F9FF) ||
            (cp >= 0x20000 && cp <= 0x3FFFD)) {
            return 2;
        }

        // Everything else (including U+2800 Braille, box drawing, and the
        // Dracula glyph set) is a single cell.
        return 1;
    }

    // ─── ANSI handling ──────────────────────────────────────────────────────

    // Returns the byte length of the escape sequence starting at `i`, or 0 if
    // `i` does not start an escape sequence.
    static size_t AnsiSequenceLength(const std::string& s, size_t i) {
        if (i >= s.size() || s[i] != '\033') return 0;
        if (i + 1 >= s.size()) return 1;

        char c1 = s[i + 1];
        if (c1 == '[') {
            size_t j = i + 2;
            while (j < s.size() && ((s[j] >= '0' && s[j] <= '9') ||
                                    s[j] == ';' || s[j] == ':' ||
                                    s[j] == '?' || s[j] == '<' ||
                                    s[j] == '>' || s[j] == '=' ||
                                    s[j] == ' ')) {
                ++j;
            }
            if (j < s.size()) ++j;   // final byte
            return j - i;
        }
        if (c1 == ']') {
            // OSC ... terminated by BEL or ST (ESC \)
            size_t j = i + 2;
            while (j < s.size()) {
                if (s[j] == '\a') { ++j; break; }
                if (s[j] == '\033' && j + 1 < s.size() && s[j + 1] == '\\') { j += 2; break; }
                ++j;
            }
            return j - i;
        }
        // Two byte escape (e.g. ESC M, ESC 7)
        return 2;
    }

    std::string StripAnsi(const std::string& text) {
        std::string out;
        out.reserve(text.size());
        for (size_t i = 0; i < text.size();) {
            size_t esc = AnsiSequenceLength(text, i);
            if (esc > 0) { i += esc; continue; }
            out += text[i];
            ++i;
        }
        return out;
    }

    size_t VisibleWidth(const std::string& text) {
        size_t width = 0;
        for (size_t i = 0; i < text.size();) {
            size_t esc = AnsiSequenceLength(text, i);
            if (esc > 0) { i += esc; continue; }
            uint32_t cp = DecodeUtf8(text, i);
            width += static_cast<size_t>(CodePointWidth(cp));
        }
        return width;
    }

    // ─── Composition ────────────────────────────────────────────────────────

    std::string Repeat(const std::string& unit, size_t count) {
        if (unit.empty() || count == 0) return "";
        std::string out;
        out.reserve(unit.size() * count);
        for (size_t i = 0; i < count; ++i) out += unit;
        return out;
    }

    std::string PadRight(const std::string& text, size_t width, char fill) {
        size_t w = VisibleWidth(text);
        if (w >= width) return text;
        return text + std::string(width - w, fill);
    }

    std::string PadLeft(const std::string& text, size_t width, char fill) {
        size_t w = VisibleWidth(text);
        if (w >= width) return text;
        return std::string(width - w, fill) + text;
    }

    std::string Center(const std::string& text, size_t width, char fill) {
        size_t w = VisibleWidth(text);
        if (w >= width) return text;
        size_t total = width - w;
        size_t left = total / 2;
        size_t right = total - left;
        return std::string(left, fill) + text + std::string(right, fill);
    }

    std::string Truncate(const std::string& text, size_t width) {
        if (VisibleWidth(text) <= width) return text;
        if (width == 0) return "";

        const std::string ellipsis = Terminal::SupportsUnicode() ? "\xE2\x80\xA6" : "..";
        const size_t ellipsisWidth = VisibleWidth(ellipsis);
        const size_t budget = width > ellipsisWidth ? width - ellipsisWidth : 0;

        std::string out;
        size_t used = 0;
        bool sawAnsi = false;

        for (size_t i = 0; i < text.size();) {
            size_t esc = AnsiSequenceLength(text, i);
            if (esc > 0) {
                out.append(text, i, esc);
                sawAnsi = true;
                i += esc;
                continue;
            }
            size_t start = i;
            uint32_t cp = DecodeUtf8(text, i);
            size_t cw = static_cast<size_t>(CodePointWidth(cp));
            if (used + cw > budget) break;
            out.append(text, start, i - start);
            used += cw;
        }

        out += ellipsis;
        if (sawAnsi) out += Terminal::Color(ColorRole::Reset);
        return out;
    }

    std::string Fit(const std::string& text, size_t width) {
        return PadRight(Truncate(text, width), width);
    }

    std::vector<std::string> Wrap(const std::string& text, size_t width) {
        std::vector<std::string> lines;
        if (width == 0) { lines.push_back(""); return lines; }

        std::istringstream ss(StripAnsi(text));
        std::string word;
        std::string current;

        while (ss >> word) {
            if (current.empty()) {
                current = word;
            } else if (VisibleWidth(current) + 1 + VisibleWidth(word) <= width) {
                current += " " + word;
            } else {
                lines.push_back(current);
                current = word;
            }

            // A single word longer than the line must be hard split.
            while (VisibleWidth(current) > width) {
                std::string head;
                size_t used = 0;
                size_t i = 0;
                while (i < current.size()) {
                    size_t start = i;
                    uint32_t cp = DecodeUtf8(current, i);
                    size_t cw = static_cast<size_t>(CodePointWidth(cp));
                    if (used + cw > width) { i = start; break; }
                    head.append(current, start, i - start);
                    used += cw;
                }
                if (head.empty()) break;   // defensive: cannot make progress
                lines.push_back(head);
                current = current.substr(head.size());
            }
        }

        if (!current.empty() || lines.empty()) lines.push_back(current);
        return lines;
    }

    std::string HorizontalRule(size_t width) {
        return Repeat(Terminal::BoxH(), width);
    }

    // ─── BoxBuilder ─────────────────────────────────────────────────────────

    BoxBuilder::BoxBuilder(size_t totalWidth, size_t padding)
        : m_totalWidth(totalWidth), m_padding(padding) {
        // Two border cells plus padding on each side.
        size_t chrome = 2 + m_padding * 2;
        m_innerWidth = m_totalWidth > chrome ? m_totalWidth - chrome : 1;
        if (m_totalWidth < chrome + 1) {
            m_totalWidth = chrome + 1;
        }
    }

    BoxBuilder& BoxBuilder::Title(const std::string& title) {
        m_title = title;
        return *this;
    }

    BoxBuilder& BoxBuilder::AddLine(const std::string& content) {
        m_rows.push_back({Row::Content, content});
        return *this;
    }

    BoxBuilder& BoxBuilder::AddBlank() {
        m_rows.push_back({Row::Content, ""});
        return *this;
    }

    BoxBuilder& BoxBuilder::AddDivider() {
        m_rows.push_back({Row::Divider, ""});
        return *this;
    }

    BoxBuilder& BoxBuilder::AddLines(const std::vector<std::string>& lines) {
        for (const auto& l : lines) AddLine(l);
        return *this;
    }

    std::vector<std::string> BoxBuilder::Build() const {
        const std::string border = Terminal::Color(ColorRole::Border);
        const std::string reset  = Terminal::Color(ColorRole::Reset);
        const std::string pad(m_padding, ' ');
        const size_t ruleWidth = m_totalWidth - 2;

        std::vector<std::string> out;

        // Top rule (optionally carrying a title).
        {
            std::string rule;
            if (m_title.empty()) {
                rule = HorizontalRule(ruleWidth);
            } else {
                std::string label = " " + m_title + " ";
                size_t labelW = VisibleWidth(label);
                if (labelW + 4 > ruleWidth) {
                    rule = HorizontalRule(ruleWidth);
                } else {
                    size_t lead = 2;
                    size_t trail = ruleWidth - lead - labelW;
                    rule = HorizontalRule(lead) + reset +
                           Terminal::Color(ColorRole::Primary) + label + reset +
                           border + HorizontalRule(trail);
                }
            }
            out.push_back(border + Terminal::BoxTL() + rule + Terminal::BoxTR() + reset);
        }

        for (const auto& row : m_rows) {
            if (row.kind == Row::Divider) {
                out.push_back(border + Terminal::BoxTeeL() +
                              HorizontalRule(ruleWidth) +
                              Terminal::BoxTeeR() + reset);
            } else {
                std::string body = Fit(row.text, m_innerWidth);
                out.push_back(border + Terminal::BoxV() + reset +
                              pad + body + pad +
                              border + Terminal::BoxV() + reset);
            }
        }

        out.push_back(border + Terminal::BoxBL() +
                      HorizontalRule(ruleWidth) +
                      Terminal::BoxBR() + reset);
        return out;
    }

    // ─── Columns ────────────────────────────────────────────────────────────

    std::vector<std::string> RenderColumns(
        const std::vector<std::vector<std::string>>& blocks,
        const std::vector<size_t>& widths,
        size_t gap) {

        std::vector<std::string> out;
        if (blocks.empty()) return out;

        size_t rows = 0;
        for (const auto& b : blocks) rows = std::max(rows, b.size());

        const std::string spacer(gap, ' ');

        for (size_t r = 0; r < rows; ++r) {
            std::string line;
            for (size_t c = 0; c < blocks.size(); ++c) {
                size_t w = c < widths.size() ? widths[c] : 0;
                std::string cell = r < blocks[c].size() ? blocks[c][r] : std::string();
                bool last = (c + 1 == blocks.size());
                if (last) {
                    line += Truncate(cell, w);
                } else {
                    line += Fit(cell, w) + spacer;
                }
            }
            out.push_back(line);
        }
        return out;
    }

    // ─── Table ──────────────────────────────────────────────────────────────

    Table::Table(std::vector<TableColumn> columns)
        : m_columns(std::move(columns)) {}

    void Table::AddRow(std::vector<std::string> cells) {
        cells.resize(m_columns.size());
        m_rows.push_back(std::move(cells));
    }

    std::vector<std::string> Table::Render(size_t availableWidth,
                                           const std::string& headerColor,
                                           const std::string& resetColor) const {
        std::vector<std::string> out;
        if (m_columns.empty()) return out;

        const size_t indent = 2;
        const size_t gap = 2;

        // Natural widths from content.
        std::vector<size_t> widths(m_columns.size(), 0);
        for (size_t c = 0; c < m_columns.size(); ++c) {
            widths[c] = std::max(m_columns[c].minWidth,
                                 VisibleWidth(m_columns[c].header));
        }
        for (const auto& row : m_rows) {
            for (size_t c = 0; c < m_columns.size() && c < row.size(); ++c) {
                widths[c] = std::max(widths[c], VisibleWidth(row[c]));
            }
        }
        for (size_t c = 0; c < m_columns.size(); ++c) {
            if (m_columns[c].maxWidth > 0) {
                widths[c] = std::min(widths[c], m_columns[c].maxWidth);
            }
        }

        // Shrink from the widest column until the table fits.
        auto totalWidth = [&]() {
            size_t t = indent;
            for (size_t c = 0; c < widths.size(); ++c) {
                t += widths[c];
                if (c + 1 < widths.size()) t += gap;
            }
            return t;
        };
        while (totalWidth() > availableWidth) {
            size_t widest = 0;
            for (size_t c = 1; c < widths.size(); ++c) {
                if (widths[c] > widths[widest]) widest = c;
            }
            if (widths[widest] <= 4) break;
            widths[widest] -= 1;
        }

        const std::string pad(indent, ' ');
        const std::string spacer(gap, ' ');

        auto renderRow = [&](const std::vector<std::string>& cells,
                             const std::string& color) {
            std::string line = pad;
            for (size_t c = 0; c < m_columns.size(); ++c) {
                std::string cell = c < cells.size() ? cells[c] : std::string();
                cell = Truncate(cell, widths[c]);
                bool last = (c + 1 == m_columns.size());
                if (m_columns[c].rightAlign) {
                    line += color + PadLeft(cell, widths[c]) + (color.empty() ? "" : resetColor);
                } else if (last) {
                    line += color + cell + (color.empty() ? "" : resetColor);
                } else {
                    line += color + PadRight(cell, widths[c]) + (color.empty() ? "" : resetColor);
                }
                if (!last) line += spacer;
            }
            return line;
        };

        bool hasHeader = false;
        for (const auto& col : m_columns) {
            if (!col.header.empty()) { hasHeader = true; break; }
        }

        if (hasHeader) {
            std::vector<std::string> headers;
            for (const auto& col : m_columns) headers.push_back(col.header);
            out.push_back(renderRow(headers, headerColor));
        }

        for (const auto& row : m_rows) {
            out.push_back(renderRow(row, ""));
        }
        return out;
    }

} // namespace Text
} // namespace Dracula
