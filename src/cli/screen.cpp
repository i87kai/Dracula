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

    void InteractiveScreen::End() {
        if (!m_active) { RestoreStreams(); return; }
        RestoreStreams();
        Console::EnableInteractiveInput(false);
        Console::ShowCursor();
        Console::LeaveAlternateScreen();
        Terminal::SetContentWidth(0);
        m_active = false;
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

        // Output viewport, wrapped for the current width.
        const int outputWidth =
            std::max(m_layout.output.width - static_cast<int>(kIndent) - 1, 10);
        {
            const auto rows = m_output.VisibleRows(m_layout.output.height, outputWidth);
            for (size_t i = 0; i < rows.size(); ++i) {
                put(m_layout.output.top + static_cast<int>(i),
                    std::string(kIndent, ' ') + rows[i]);
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
                if (!m_output.IsFollowing()) right += "   PageDown to follow";
            }

            // Session state earns the left of the strip; the standing hints only
            // take the space that is actually left over, so the footer never
            // shows a half-truncated hint.
            const std::string sep = "   " + Terminal::Bullet() + "   ";
            const std::string hints = "/ browse commands" + sep + "PageUp / PageDown scroll";
            const size_t rightBudget =
                right.empty() ? inner
                              : (inner > Text::VisibleWidth(right) + 3
                                 ? inner - Text::VisibleWidth(right) - 3 : 0);

            std::string left = m_status;
            if (left.empty()) {
                left = hints;
            } else if (Text::VisibleWidth(left) + Text::VisibleWidth(sep) +
                       Text::VisibleWidth(hints) <= rightBudget) {
                left += sep + hints;
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
            put(m_layout.footer.top, std::string(kIndent, ' ') + muted + body + reset);
        }

        return frame;
    }

    void InteractiveScreen::Render(const LineEditor& editor, const std::string& prompt) {
        if (!m_active) return;

        Relayout(static_cast<int>(editor.GetSuggestions().size()));

        int cursorRow = m_layout.input.top;
        int cursorColumn = 0;
        auto frame = ComposeFrame(editor, prompt, cursorRow, cursorColumn);

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
