#include "cli/screen.h"
#include "cli/line_editor.h"
#include "cli/terminal.h"
#include "cli/text_layout.h"

#include <algorithm>
#include <iostream>

namespace Dracula {

    namespace {
        // Left margin shared by the header, the output region, the prompt and the
        // footer, so every region's text starts on the same column.
        constexpr size_t kIndent = 2;
    }

    // ─── Region arithmetic ──────────────────────────────────────────────────

    int ScreenModel::HeaderRows(int terminalWidth, HeaderVariant variant,
                                const StartupInfo& info) {
        if (variant == HeaderVariant::None) return 0;
        return static_cast<int>(
            StartupCard::RenderHeader(terminalWidth, variant, info).size());
    }

    ScreenLayout ScreenModel::Compute(int terminalWidth, int terminalHeight,
                                      int suggestionCount, const StartupInfo& info) {
        ScreenLayout layout;

        const int W = std::max(terminalWidth, 20);
        const int H = std::max(terminalHeight, 3);

        // 1. The bottom chrome is laid out first, from the last row upwards, so
        //    the prompt strip can never be squeezed out by anything above it.
        //    On a very short terminal the footer goes first and the divider
        //    second; the prompt row itself always survives.
        const int footerRows = H >= kFooterMinHeight ? 1 : 0;
        const int ruleRows   = H >= kRuleMinHeight   ? 1 : 0;

        layout.footer    = Rect{H - footerRows, 0, W, footerRows};
        layout.input     = Rect{H - 1 - footerRows, 0, W, 1};
        layout.inputRule = Rect{layout.input.top - ruleRows, 0, W, ruleRows};

        // Rows above the bottom chrome, shared by header, output and palette.
        const int above = std::max(0, layout.inputRule.top);

        // 2. The header variant is chosen from the terminal geometry ALONE.
        //    It deliberately does not depend on whether the palette is open:
        //    a header that resized every time the user typed "/" would be
        //    unusable. The palette takes its rows from the output region.
        //    The WIDTH sets the ceiling; the HEIGHT may degrade further.
        std::vector<HeaderVariant> variants;
        switch (StartupCard::SelectVariant(W)) {
            case HeaderVariant::Standard: variants.push_back(HeaderVariant::Standard); [[fallthrough]];
            case HeaderVariant::Compact:  variants.push_back(HeaderVariant::Compact);  [[fallthrough]];
            default:                      variants.push_back(HeaderVariant::Minimal);  break;
        }

        // 3. Pick the richest header that still leaves a usable output region.
        //    The preferred floor is tried first across every header variant, so
        //    a tall header is given up before output rows are.
        static const int kFloors[] = {kPreferredOutputRows, 6, 5, kMinOutputRows, 2, 1};

        int headerRows = 0;
        HeaderVariant chosen = HeaderVariant::None;
        bool found = false;

        for (int floor : kFloors) {
            for (HeaderVariant variant : variants) {
                const int rows = HeaderRows(W, variant, info);
                if (above - rows >= floor) {
                    headerRows = rows;
                    chosen = variant;
                    found = true;
                    break;
                }
            }
            if (found) break;
        }

        if (!found) {
            // Extremely short terminal: drop the header entirely rather than
            // the prompt or the last usable output rows.
            headerRows = 0;
            chosen = HeaderVariant::None;
        }

        layout.hasHeader = (chosen != HeaderVariant::None);
        layout.headerVariant = chosen;
        layout.header = Rect{0, 0, W, headerRows};

        // 4. Rows the output and the palette share, below the header.
        const int available = std::max(1, above - headerRows);

        // 5. Size the palette out of that shared space. It first tries to leave
        //    the output its preferred height, and only encroaches on the
        //    minimum when the terminal is genuinely short. The list scrolls in
        //    whatever viewport it is given, so shrinking it costs nothing.
        int paletteItems = 0;
        if (suggestionCount > 0) {
            const int preferred = std::min(suggestionCount, kPreferredPaletteItems);
            int budget = available - kPreferredOutputRows - 2;   // 2 = footer + spacer
            paletteItems = std::min(preferred, budget);

            if (paletteItems < kMinPaletteItems) {
                budget = available - kMinOutputRows - 2;
                paletteItems = std::min(preferred, budget);
            }
            if (paletteItems < 1) paletteItems = 0;   // no room at all
        }
        const int paletteRows = paletteItems > 0 ? paletteItems + 2 : 0;

        int outputRows = available - paletteRows;
        if (outputRows < 1) outputRows = 1;

        layout.output = Rect{headerRows, 0, W, outputRows};
        layout.palette = Rect{layout.inputRule.top - paletteRows, 0, W, paletteRows};
        layout.paletteItems = paletteItems;

        return layout;
    }

    // ─── OutputBuffer ───────────────────────────────────────────────────────

    void OutputBuffer::AppendLine(const std::string& line) {
        m_lines.push_back(line);
        Trim();
        if (m_follow) ScrollToBottom();
    }

    void OutputBuffer::Write(const std::string& text) {
        for (char c : text) {
            if (c == '\n') {
                m_lines.push_back(m_pending);
                m_pending.clear();
                Trim();
            } else if (c == '\r') {
                continue;   // would corrupt absolute row placement
            } else if (c == '\t') {
                m_pending += "    ";
            } else {
                m_pending += c;
            }
        }
        if (m_follow) ScrollToBottom();
    }

    void OutputBuffer::Trim() {
        while (m_lines.size() > kMaxLines) {
            m_lines.pop_front();
            if (m_anchor > 0) --m_anchor;
        }
    }

    void OutputBuffer::Clear() {
        m_lines.clear();
        m_pending.clear();
        m_anchor = 0;
        m_follow = true;
    }

    size_t OutputBuffer::RowsFor(const std::string& line, int width) const {
        const size_t w = static_cast<size_t>(std::max(width, 1));
        const size_t cells = Text::VisibleWidth(line);
        if (cells <= w) return 1;
        return (cells + w - 1) / w;
    }

    // Walk backwards from the newest line until `height` display rows are
    // accounted for; that logical line is the top of the "follow" viewport.
    size_t OutputBuffer::FirstVisible(int height, int width) const {
        const size_t h = static_cast<size_t>(std::max(height, 1));
        if (m_lines.empty()) return 0;

        if (m_follow) {
            size_t rows = 0;
            size_t index = m_lines.size();
            while (index > 0) {
                const size_t need = RowsFor(m_lines[index - 1], width);
                if (rows + need > h && rows > 0) break;
                rows += need;
                --index;
                if (rows >= h) break;
            }
            return index;
        }
        return std::min(m_anchor, m_lines.empty() ? size_t{0} : m_lines.size() - 1);
    }

    void OutputBuffer::SetScrollAnchor(size_t anchor) {
        m_anchor = m_lines.empty() ? 0 : std::min(anchor, m_lines.size() - 1);
        m_follow = false;
    }

    void OutputBuffer::ScrollToBottom() {
        m_follow = true;
        m_anchor = m_lines.empty() ? 0 : m_lines.size() - 1;
    }

    void OutputBuffer::ScrollToTop() {
        if (m_lines.empty()) { ScrollToBottom(); return; }
        m_follow = false;
        m_anchor = 0;
    }

    void OutputBuffer::ScrollUp(int height, int lines) {
        if (lines <= 0 || m_lines.empty()) return;

        size_t current = FirstVisible(height, 0x7fffffff);
        if (m_follow) current = FirstVisible(height, 0x7fffffff);

        const size_t step = static_cast<size_t>(lines);
        // Unsigned-safe: clamp at the oldest line instead of wrapping around.
        current = current > step ? current - step : 0;

        m_anchor = current;
        m_follow = false;
    }

    void OutputBuffer::ScrollDown(int height, int lines) {
        if (lines <= 0 || m_lines.empty()) return;

        const size_t h = static_cast<size_t>(std::max(height, 1));
        if (m_lines.size() <= h) { ScrollToBottom(); return; }

        const size_t bottomAnchor = m_lines.size() - h;
        size_t current = m_follow ? bottomAnchor : m_anchor;
        current += static_cast<size_t>(lines);

        if (current >= bottomAnchor) { ScrollToBottom(); return; }
        m_anchor = current;
        m_follow = false;
    }

    void OutputBuffer::ScrollPageUp(int height) {
        ScrollUp(height, std::max(height - 1, 1));
    }

    void OutputBuffer::ScrollPageDown(int height) {
        ScrollDown(height, std::max(height - 1, 1));
    }

    std::vector<std::string> OutputBuffer::VisibleRows(int height, int width) const {
        std::vector<std::string> rows;
        const size_t h = static_cast<size_t>(std::max(height, 1));
        const int w = std::max(width, 1);

        // Logical lines are wrapped for the CURRENT width, so a resize reflows
        // the history instead of leaving rows sized for the old geometry.
        for (size_t i = FirstVisible(height, w); i < m_lines.size() && rows.size() < h; ++i) {
            for (auto& row : Text::WrapCells(m_lines[i], static_cast<size_t>(w))) {
                if (rows.size() >= h) break;
                rows.push_back(std::move(row));
            }
        }
        return rows;
    }

    void OutputBuffer::VisibleRange(int height, int width,
                                    size_t& first, size_t& last) const {
        if (m_lines.empty()) { first = 0; last = 0; return; }

        const size_t h = static_cast<size_t>(std::max(height, 1));
        const int w = std::max(width, 1);
        const size_t start = FirstVisible(height, w);

        size_t rows = 0;
        size_t index = start;
        while (index < m_lines.size() && rows < h) {
            rows += RowsFor(m_lines[index], w);
            ++index;
        }

        first = start + 1;
        last = index;
    }

    bool OutputBuffer::HasOlderAbove(int height, int width) const {
        return FirstVisible(height, width) > 0;
    }

    bool OutputBuffer::HasNewerBelow(int height, int width) const {
        size_t first = 0, last = 0;
        VisibleRange(height, width, first, last);
        return last < m_lines.size();
    }

    // ─── OutputSink ─────────────────────────────────────────────────────────

    int OutputSink::overflow(int ch) {
        if (ch != traits_type::eof()) {
            m_buffer.Write(std::string(1, static_cast<char>(ch)));
        }
        return ch;
    }

    std::streamsize OutputSink::xsputn(const char* s, std::streamsize count) {
        if (count > 0) {
            m_buffer.Write(std::string(s, static_cast<size_t>(count)));
        }
        return count;
    }

    // ─── InteractiveScreen ──────────────────────────────────────────────────

    InteractiveScreen::InteractiveScreen() {
        m_info = StartupInfo::Detect();
    }

    InteractiveScreen::~InteractiveScreen() {
        End();
    }

    bool InteractiveScreen::Begin() {
        if (m_active) return true;
        if (!Terminal::IsInteractive()) return false;
        if (!Console::EnterAlternateScreen()) return false;

        Console::EnableInteractiveInput(true);

        m_sink = std::make_unique<OutputSink>(m_output);
        m_savedCout = std::cout.rdbuf(m_sink.get());
        m_savedCerr = std::cerr.rdbuf(m_sink.get());

        m_active = true;
        Invalidate();
        return true;
    }

    void InteractiveScreen::RestoreStreams() {
        if (m_savedCout) { std::cout.rdbuf(m_savedCout); m_savedCout = nullptr; }
        if (m_savedCerr) { std::cerr.rdbuf(m_savedCerr); m_savedCerr = nullptr; }
        m_sink.reset();
    }

    // --- Text selection ---------------------------------------------------
    //
    // Dracula tracks the selection itself. The console keeps ENABLE_MOUSE_INPUT
    // for the whole session, so the wheel never stops scrolling, and there is
    // no mode to enter or leave in order to copy.

    void InteractiveScreen::BeginSelection(int row, int column) {
        const Rect& out = m_layout.output;
        // Only the output region is selectable; a click on the header or the
        // prompt simply clears any existing selection.
        if (out.Empty() || row < out.top || row >= out.Bottom()) {
            ClearSelection();
            return;
        }

        m_selAnchorRow = row;
        m_selAnchorCol = column;
        m_selCursorRow = row;
        m_selCursorCol = column;
        m_selecting = true;
    }

    void InteractiveScreen::ExtendSelection(int row, int column) {
        if (!m_selecting || m_selAnchorRow < 0) return;

        const Rect& out = m_layout.output;
        if (out.Empty()) return;

        // Clamp to the output region so dragging past its edge selects to the
        // boundary instead of losing the drag.
        if (row < out.top) row = out.top;
        if (row >= out.Bottom()) row = out.Bottom() - 1;

        m_selCursorRow = row;
        m_selCursorCol = column;
    }

    void InteractiveScreen::EndSelection() {
        m_selecting = false;

        // A click without a drag is a dismissal, not a zero-width selection.
        if (m_selAnchorRow == m_selCursorRow && m_selAnchorCol == m_selCursorCol) {
            ClearSelection();
        }
    }

    void InteractiveScreen::ClearSelection() {
        m_selAnchorRow = -1;
        m_selCursorRow = -1;
        m_selAnchorCol = 0;
        m_selCursorCol = 0;
        m_selecting = false;
    }

    bool InteractiveScreen::HasSelection() const {
        return m_selAnchorRow >= 0 && m_selCursorRow >= 0 &&
               !(m_selAnchorRow == m_selCursorRow && m_selAnchorCol == m_selCursorCol);
    }

    bool InteractiveScreen::SelectionBounds(int& startRow, int& startCol,
                                            int& endRow, int& endCol) const {
        if (!HasSelection()) return false;

        startRow = m_selAnchorRow;
        startCol = m_selAnchorCol;
        endRow = m_selCursorRow;
        endCol = m_selCursorCol;

        // Normalize so the caller always walks forwards.
        if (endRow < startRow || (endRow == startRow && endCol < startCol)) {
            std::swap(startRow, endRow);
            std::swap(startCol, endCol);
        }
        return true;
    }

    std::string InteractiveScreen::SelectedText() const {
        int startRow = 0, startCol = 0, endRow = 0, endCol = 0;
        if (!SelectionBounds(startRow, startCol, endRow, endCol)) return "";

        std::string text;
        for (int row = startRow; row <= endRow; ++row) {
            if (row < 0 || row >= static_cast<int>(m_plainRows.size())) continue;

            const std::string& line = m_plainRows[static_cast<size_t>(row)];
            const int lineLen = static_cast<int>(line.size());

            // A multi-row selection takes whole lines except at its two ends.
            int from = (row == startRow) ? startCol : 0;
            int to   = (row == endRow) ? endCol : lineLen;

            from = std::max(0, std::min(from, lineLen));
            to   = std::max(0, std::min(to, lineLen));
            if (to <= from) {
                if (row != endRow) text += "\n";
                continue;
            }

            std::string piece = line.substr(static_cast<size_t>(from),
                                            static_cast<size_t>(to - from));
            // Trailing padding is layout, not content.
            while (!piece.empty() && piece.back() == ' ') piece.pop_back();

            text += piece;
            if (row != endRow) text += "\n";
        }
        return text;
    }

    bool InteractiveScreen::CopySelection() {
        const std::string text = SelectedText();
        if (text.empty()) return false;
        return Console::CopyToClipboard(text);
    }

    void InteractiveScreen::End() {
        if (!m_active) { RestoreStreams(); return; }
        RestoreStreams();
        ClearSelection();
        Console::EnableInteractiveInput(false);
        Console::ShowCursor();
        Console::LeaveAlternateScreen();
        Terminal::SetContentWidth(0);
        m_active = false;
    }

    void InteractiveScreen::RefreshContext() {
        ++m_info.tipIndex;
        m_info.RefreshContext();
        // The header's height can change when the context does, so the cached
        // rows must be rebuilt rather than reused.
        Invalidate();
    }

    void InteractiveScreen::SetHeaderInfo(const StartupInfo& info) {
        m_info = info;
        m_cachedHeaderWidth = -1;
    }

    void InteractiveScreen::SetStatusLine(const std::string& status) {
        m_status = status;
    }

    void InteractiveScreen::Invalidate() {
        m_lastFrame.clear();
    }

    void InteractiveScreen::Relayout(int suggestionCount) {
        const int width = Terminal::GetWidth();
        const int height = Terminal::GetHeight();

        if (width != m_lastWidth || height != m_lastHeight) {
            // Resize: everything is recomputed and repainted from retained
            // state. The scroll anchor is a logical line index, so it survives
            // a width change; the input text and palette selection live in the
            // editor and are never touched here.
            m_cachedHeaderWidth = -1;
            Invalidate();
            m_lastWidth = width;
            m_lastHeight = height;
        }

        m_layout = ScreenModel::Compute(width, height, suggestionCount, m_info);

        // Commands render into the output region, never the raw console width.
        Terminal::SetContentWidth(
            std::max(m_layout.output.width - static_cast<int>(kIndent) - 2, 20));

        if (m_layout.hasHeader &&
            (m_cachedHeaderWidth != m_layout.header.width ||
             m_cachedHeaderVariant != m_layout.headerVariant)) {
            m_headerCache = StartupCard::RenderHeader(m_layout.header.width,
                                                      m_layout.headerVariant, m_info);
            m_cachedHeaderWidth = m_layout.header.width;
            m_cachedHeaderVariant = m_layout.headerVariant;
        }
        if (!m_layout.hasHeader) {
            m_headerCache.clear();
            m_cachedHeaderVariant = HeaderVariant::None;
        }
    }

    std::vector<std::string> InteractiveScreen::PreviewFrame(int width, int height,
                                                             const LineEditor& editor,
                                                             const std::string& prompt) {
        m_layout = ScreenModel::Compute(width, height,
                                        static_cast<int>(editor.GetSuggestions().size()),
                                        m_info);
        m_headerCache = m_layout.hasHeader
                      ? StartupCard::RenderHeader(m_layout.header.width,
                                                  m_layout.headerVariant, m_info)
                      : std::vector<std::string>{};
        m_cachedHeaderWidth = -1;   // force a real repaint to recache

        int row = 0, column = 0;
        return ComposeFrame(editor, prompt, row, column);
    }

    std::vector<std::string> InteractiveScreen::ComposeFrame(const LineEditor& editor,
                                                             const std::string& prompt,
                                                             int& outCursorRow,
                                                             int& outCursorColumn) const {
        // The frame is the whole screen: the footer, when present, owns the row
        // below the prompt.
        const int H = std::max(m_layout.footer.Bottom(), m_layout.input.Bottom());
        const int W = m_layout.input.width;
        std::vector<std::string> frame(static_cast<size_t>(std::max(H, 1)));

        const std::string reset = Terminal::Color(ColorRole::Reset);
        const std::string muted = Terminal::Color(ColorRole::Muted);

        auto put = [&](int row, const std::string& content) {
            if (row < 0 || row >= H) return;
            frame[static_cast<size_t>(row)] =
                Text::Truncate(content, static_cast<size_t>(std::max(W - 1, 1)));
        };

        const std::string border = Terminal::Color(ColorRole::Border);
        const std::string rule   = border +
            Text::HorizontalRule(static_cast<size_t>(std::max(W - 1, 1))) + reset;

        // Header - UI chrome, never part of the output history. The rows already
        // carry their own indentation and closing divider.
        if (m_layout.hasHeader) {
            for (size_t i = 0; i < m_headerCache.size(); ++i) {
                put(m_layout.header.top + static_cast<int>(i), m_headerCache[i]);
            }
        }

        // Output viewport, wrapped for the current width. One extra column is
        // reserved on the right for the scrollbar track so text never collides
        // with it.
        const int outputWidth =
            std::max(m_layout.output.width - static_cast<int>(kIndent) - 2, 10);
        {
            const int viewportRows = m_layout.output.height;
            const auto rows = m_output.VisibleRows(viewportRows, outputWidth);

            // Scrollbar geometry. The track occupies the rightmost cell of the
            // output region and is drawn whenever the history exceeds one
            // viewport, so the user can always see where they are.
            const size_t totalLines = m_output.LineCount();
            const bool scrollable = totalLines > static_cast<size_t>(viewportRows);

            int thumbTop = 0, thumbSize = 0;
            if (scrollable && viewportRows > 0) {
                // Thumb size is proportional to the visible fraction, with a
                // one-row floor so it never vanishes on a long history.
                thumbSize = std::max(1, static_cast<int>(
                    (static_cast<double>(viewportRows) / static_cast<double>(totalLines)) *
                    viewportRows));
                thumbSize = std::min(thumbSize, viewportRows);

                const size_t firstVisible = m_output.FirstVisible(viewportRows, outputWidth);
                const size_t maxFirst = totalLines > static_cast<size_t>(viewportRows)
                                      ? totalLines - static_cast<size_t>(viewportRows) : 0;
                const double progress = maxFirst > 0
                    ? static_cast<double>(firstVisible) / static_cast<double>(maxFirst) : 1.0;

                thumbTop = static_cast<int>(progress * (viewportRows - thumbSize) + 0.5);
                thumbTop = std::max(0, std::min(thumbTop, viewportRows - thumbSize));
            }

            const std::string trackGlyph = Terminal::UnicodeEnabled() ? "\xe2\x94\x82" : "|";
            const std::string thumbGlyph = Terminal::UnicodeEnabled() ? "\xe2\x96\x88" : "#";
            const std::string barDim = Terminal::Color(ColorRole::Border);
            const std::string barLit = Terminal::Color(ColorRole::Accent);

            m_plainRows.assign(static_cast<size_t>(H), std::string());

            for (int i = 0; i < viewportRows; ++i) {
                const int row = m_layout.output.top + i;
                std::string body = (static_cast<size_t>(i) < rows.size())
                                 ? rows[static_cast<size_t>(i)] : std::string();

                std::string line = std::string(kIndent, ' ') + body;

                // Remember the escape-free text so a copied selection contains
                // what the user saw and not a wall of colour codes.
                if (row >= 0 && row < H) {
                    m_plainRows[static_cast<size_t>(row)] = Text::StripAnsi(line);
                }

                if (scrollable) {
                    // put() truncates to W-1 visible cells, so the text is
                    // padded to W-2 and the bar occupies the final cell.
                    const bool onThumb = (i >= thumbTop && i < thumbTop + thumbSize);
                    line = Text::PadRight(line, static_cast<size_t>(std::max(W - 2, 0)));
                    line += (onThumb ? barLit + thumbGlyph : barDim + trackGlyph) + reset;
                }

                put(row, line);
            }
        }

        // Palette - transient rows above the prompt. It shrinks its own
        // viewport rather than eating the output region or moving the header.
        if (m_layout.palette.height > 0 && m_layout.paletteItems > 0) {
            auto rows = editor.BuildPopupRows(static_cast<size_t>(std::max(W - 2, 10)),
                                              static_cast<size_t>(m_layout.paletteItems));
            const int start = m_layout.palette.top + 1;
            for (size_t i = 0; i < rows.size(); ++i) {
                const int row = start + static_cast<int>(i);
                if (row >= m_layout.input.top) break;
                put(row, rows[i]);
            }
        }

        // Divider above the prompt: the output region ends here, the input
        // strip begins.
        if (m_layout.inputRule.height > 0) {
            put(m_layout.inputRule.top, rule);
        }

        // Input, in its own strip and on the same left margin as everything else.
        {
            const size_t promptWidth = Text::VisibleWidth(prompt) + kIndent;
            const size_t available = static_cast<size_t>(W) > promptWidth + 2
                                   ? static_cast<size_t>(W) - promptWidth - 2
                                   : 10;
            size_t cursorOffset = 0;
            const std::string visible = editor.VisibleInput(available, cursorOffset);

            put(m_layout.input.top,
                std::string(kIndent, ' ') + prompt +
                Terminal::Color(ColorRole::Text) + visible + reset);

            outCursorRow = m_layout.input.top;
            outCursorColumn = static_cast<int>(promptWidth + cursorOffset);
        }

        // Footer: session state and scroll position on the left/right of one
        // quiet strip, with the standing hints when there is nothing to report.
        if (m_layout.footer.height > 0) {
            const size_t inner = static_cast<size_t>(std::max(W - 1 - static_cast<int>(kIndent), 10));

            std::string right;
            if (m_output.LineCount() > 0 &&
                (m_output.HasOlderAbove(m_layout.output.height, outputWidth) ||
                 m_output.HasNewerBelow(m_layout.output.height, outputWidth))) {
                size_t first = 0, last = 0;
                m_output.VisibleRange(m_layout.output.height, outputWidth, first, last);
                right = "output " + std::to_string(first) + "-" + std::to_string(last) +
                        " / " + std::to_string(m_output.LineCount());

                // Scrolled back: report how much has arrived since, rather than
                // yanking the viewport to the bottom under the user.
                if (!m_output.IsFollowing()) {
                    const size_t unseen = m_output.LineCount() > last
                                        ? m_output.LineCount() - last : 0;
                    const std::string arrow = Terminal::UnicodeEnabled() ? "\xe2\x86\x93" : "v";
                    if (unseen > 0) {
                        right = arrow + " " + std::to_string(unseen) + " new line" +
                                (unseen == 1 ? "" : "s") + "   Ctrl+End for latest";
                    } else {
                        right += "   Ctrl+End for latest";
                    }
                }
            }

            // Session state earns the left of the strip; the standing hints only
            // take the space that is actually left over, so the footer never
            // shows a half-truncated hint.
            const std::string sep = "   " + Terminal::Bullet() + "   ";

            // Two lengths of the same hint. The short form still names the key,
            // because a keybinding nobody can discover may as well not exist -
            // so it is the last thing dropped, not the first.
            const bool selected = HasSelection();
            const std::string hints = selected
                ? std::string("Ctrl+C copies the selection") + sep + "click to dismiss"
                : "/ browse commands" + sep + "PageUp / PageDown scroll" +
                  sep + "drag to select, Ctrl+C to copy";
            const std::string hintsShort = selected
                ? "Ctrl+C copies"
                : "drag to select";
            const size_t rightBudget =
                right.empty() ? inner
                              : (inner > Text::VisibleWidth(right) + 3
                                 ? inner - Text::VisibleWidth(right) - 3 : 0);

            // With an active selection the copy hint is the important thing on
            // the strip; normally the session state is.
            std::string left = selected ? hints : m_status;
            const std::string secondary = selected ? m_status : hints;
            const std::string secondaryShort = selected ? m_status : hintsShort;

            auto fits = [&](const std::string& tail) {
                return !tail.empty() &&
                       Text::VisibleWidth(left) + Text::VisibleWidth(sep) +
                       Text::VisibleWidth(tail) <= rightBudget;
            };

            if (left.empty()) {
                left = secondary;
            } else if (fits(secondary)) {
                left += sep + secondary;
            } else if (fits(secondaryShort)) {
                left += sep + secondaryShort;
            }

            std::string body = Text::Truncate(left, inner);
            if (!right.empty()) {
                const size_t rightW = Text::VisibleWidth(right);
                if (Text::VisibleWidth(body) + rightW + 3 <= inner) {
                    body = Text::PadRight(body, inner - rightW) + right;
                } else {
                    body = Text::PadRight(Text::Truncate(left, inner - rightW - 3),
                                          inner - rightW) + right;
                }
            }
            // An active selection is a state the user must not lose track of,
            // so the strip is lifted out of the muted grey while it lasts.
            const std::string tone = selected
                                   ? Terminal::Color(ColorRole::Warning) : muted;
            put(m_layout.footer.top, std::string(kIndent, ' ') + tone + body + reset);
        }

        return frame;
    }

    void InteractiveScreen::ApplySelectionHighlight(std::vector<std::string>& frame) const {
        int startRow = 0, startCol = 0, endRow = 0, endCol = 0;
        if (!SelectionBounds(startRow, startCol, endRow, endCol)) return;

        // Repaint the selected span from the stored plain text in reverse
        // video. Rebuilding from plain text (rather than splicing into the
        // coloured row) keeps the highlight rectangular and avoids having to
        // parse escape sequences to find cell boundaries.
        const std::string reverseOn = "\033[7m";
        const std::string reverseOff = "\033[27m";
        const std::string reset = Terminal::Color(ColorRole::Reset);

        for (int row = startRow; row <= endRow; ++row) {
            if (row < 0 || row >= static_cast<int>(frame.size())) continue;
            if (row >= static_cast<int>(m_plainRows.size())) continue;

            const std::string& plain = m_plainRows[static_cast<size_t>(row)];
            if (plain.empty()) continue;

            const int len = static_cast<int>(plain.size());
            int from = (row == startRow) ? startCol : 0;
            int to   = (row == endRow) ? endCol : len;

            from = std::max(0, std::min(from, len));
            to   = std::max(0, std::min(to, len));
            if (to <= from) continue;

            frame[static_cast<size_t>(row)] =
                plain.substr(0, static_cast<size_t>(from)) +
                reverseOn +
                plain.substr(static_cast<size_t>(from), static_cast<size_t>(to - from)) +
                reverseOff + reset +
                plain.substr(static_cast<size_t>(to));
        }
    }

    void InteractiveScreen::Render(const LineEditor& editor, const std::string& prompt) {
        if (!m_active) return;

        Relayout(static_cast<int>(editor.GetSuggestions().size()));

        int cursorRow = m_layout.input.top;
        int cursorColumn = 0;
        auto frame = ComposeFrame(editor, prompt, cursorRow, cursorColumn);

        // The highlight is applied to the composed frame, so a selection
        // survives repaints instead of being wiped by them.
        ApplySelectionHighlight(frame);

        // Dirty-row update: only rows whose content actually changed are
        // rewritten, so typing a character repaints one line and a wheel notch
        // repaints only the output region. No full-screen clear, no flicker.
        const bool full = m_lastFrame.size() != frame.size();
        std::string out;
        out.reserve(4096);
        out += "\033[?25l";

        for (size_t row = 0; row < frame.size(); ++row) {
            if (!full && m_lastFrame[row] == frame[row]) continue;
            out += "\033[" + std::to_string(row + 1) + ";1H\033[2K";
            out += frame[row];
        }

        out += "\033[" + std::to_string(cursorRow + 1) + ";" +
               std::to_string(cursorColumn + 1) + "H";
        out += "\033[?25h";

        if (m_savedCout) {
            std::ostream console(m_savedCout);
            console << out << std::flush;
        }

        m_lastFrame = std::move(frame);
    }

    bool InteractiveScreen::ReadCommand(LineEditor& editor,
                                        const std::string& prompt,
                                        std::string& outLine) {
        editor.ResetBuffer();
        Render(editor, prompt);

        InputEvent event;
        while (Console::ReadInput(event)) {
            // Mouse selection is handled here rather than in the editor: it
            // concerns screen geometry, which the editor knows nothing about.
            // The frame keeps repainting throughout, because Dracula draws the
            // highlight itself instead of relying on the console.
            if (event.key == Key::MousePress) {
                BeginSelection(event.mouseRow, event.mouseColumn);
                Render(editor, prompt);
                continue;
            }
            if (event.key == Key::MouseDrag) {
                ExtendSelection(event.mouseRow, event.mouseColumn);
                Render(editor, prompt);
                continue;
            }
            if (event.key == Key::MouseRelease) {
                EndSelection();
                Render(editor, prompt);
                continue;
            }

            // Ctrl+C copies when something is selected, and only falls through
            // to "cancel the current line" when nothing is.
            if (event.key == Key::CtrlC && HasSelection()) {
                CopySelection();
                ClearSelection();
                Render(editor, prompt);
                continue;
            }

            // Any other keystroke dismisses a stale selection so the highlight
            // never lingers over text the user has moved past.
            if (HasSelection() && event.key != Key::Resize) {
                ClearSelection();
            }

            const auto action = editor.HandleKey(event);
            const int viewport = m_layout.output.height;

            switch (action) {
                case LineEditor::EditAction::Submit:
                    outLine = editor.GetBuffer();
                    return true;

                case LineEditor::EditAction::Eof:
                    return false;

                case LineEditor::EditAction::Cancel:
                    outLine.clear();
                    break;

                case LineEditor::EditAction::ScrollPageUp:
                    m_output.ScrollPageUp(viewport);
                    break;

                case LineEditor::EditAction::ScrollPageDown:
                    m_output.ScrollPageDown(viewport);
                    break;

                case LineEditor::EditAction::ScrollLineUp:
                    m_output.ScrollUp(viewport, OutputBuffer::kWheelLines);
                    break;

                case LineEditor::EditAction::ScrollLineDown:
                    m_output.ScrollDown(viewport, OutputBuffer::kWheelLines);
                    break;

                case LineEditor::EditAction::ScrollTop:
                    m_output.ScrollToTop();
                    break;

                case LineEditor::EditAction::ScrollBottom:
                    m_output.ScrollToBottom();
                    break;

                case LineEditor::EditAction::ClearScreen:
                case LineEditor::EditAction::Resize:
                    Invalidate();
                    break;

                case LineEditor::EditAction::Continue:
                default:
                    break;
            }

            Render(editor, prompt);
        }

        return false;
    }

} // namespace Dracula
