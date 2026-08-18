#pragma once

//
// Dracula persistent interactive screen.
//
// The terminal is divided into fixed regions recomputed from the live terminal
// size and repainted from retained state. Top to bottom:
//
//   HeaderRegion   the Dracula artwork + identity, closed by a divider
//   OutputRegion   a scrollable viewport over the session's output history
//   PaletteRegion  transient rows reserved above the input while the palette
//                  is open; never written into the output history
//   InputRule      the divider that separates the output from the prompt
//   InputRegion    the prompt, in its own strip
//   FooterRegion   one status / hint strip on the very last row
//
// The three bottom rows are fixed chrome, so the prompt never looks glued to
// the output and the structure is identical in a small window and fullscreen -
// only the number of output rows changes.
//
// Region arithmetic lives in ScreenModel and is a pure function of
// (width, height, suggestion count) so it can be tested without a console.
//
// The sizing rule is a strict priority order, not a leftover calculation:
//
//   1. the prompt strip is always visible
//   2. the output viewport keeps a usable minimum
//   3. the palette fits (shrinking its own viewport if it must)
//   4. only then does the header claim what is left, degrading through
//      Standard -> Compact -> Minimal -> None
//
// Command implementations know nothing about any of this: they print normally
// and an OutputSink streambuf routes it into OutputBuffer.
//

#include <cstddef>
#include <deque>
#include <memory>
#include <streambuf>
#include <string>
#include <vector>

#include "cli/startup_card.h"

namespace Dracula {

    class LineEditor;

    struct Rect {
        int top = 0;
        int left = 0;
        int width = 0;
        int height = 0;

        bool Empty() const { return width <= 0 || height <= 0; }
        int Bottom() const { return top + height; }   // exclusive
    };

    struct ScreenLayout {
        Rect header;      // includes its closing divider
        Rect output;
        Rect palette;
        Rect inputRule;   // divider between the output region and the prompt
        Rect input;
        Rect footer;      // status / hint strip on the last row
        HeaderVariant headerVariant = HeaderVariant::Standard;
        int paletteItems = 0;     // suggestion rows the palette may display
        bool hasHeader = false;
    };

    class ScreenModel {
    public:
        // The output viewport we try to guarantee before the header may grow.
        static constexpr int kPreferredOutputRows = 8;

        // Absolute floor. Below this the header is dropped entirely, and below
        // that the palette is dropped too - the prompt always survives.
        static constexpr int kMinOutputRows = 3;

        // Shortest terminal that still gets the divider above the prompt, and
        // the one that still gets the footer strip. Below these the chrome is
        // given up one row at a time so the prompt itself never is.
        static constexpr int kRuleMinHeight   = 6;
        static constexpr int kFooterMinHeight = 8;

        // Palette sizing: preferred item rows, and the fewest worth showing.
        static constexpr int kPreferredPaletteItems = 8;
        static constexpr int kMinPaletteItems = 3;

        // Pure region arithmetic. `suggestionCount` is 0 when the palette is
        // closed. `headerRowsFor` reports how many rows a header variant needs
        // at this width (injected so the model stays testable and cheap).
        static ScreenLayout Compute(int terminalWidth, int terminalHeight,
                                    int suggestionCount, const StartupInfo& info);

        // Rows a header variant occupies at a given width, including its
        // leading blank row and its closing divider.
        static int HeaderRows(int terminalWidth, HeaderVariant variant,
                              const StartupInfo& info);
    };

    // ─── Output history ─────────────────────────────────────────────────────

    // Logical output lines, rendered for whatever width the output region has
    // at paint time. Storing logical content (not physical rows produced for an
    // old width) is what makes resize reflow correctly.
    class OutputBuffer {
    public:
        // Presentation history only; analysis data lives in the AnalysisSession.
        static constexpr size_t kMaxLines = 20000;

        // Lines moved per mouse wheel notch.
        static constexpr int kWheelLines = 3;

        void Write(const std::string& text);
        void AppendLine(const std::string& line);
        void Clear();

        size_t LineCount() const { return m_lines.size(); }
        const std::string& LineAt(size_t index) const { return m_lines[index]; }

        // Scrolling. `height` is the current viewport height in rows.
        void ScrollUp(int height, int lines);
        void ScrollDown(int height, int lines);
        void ScrollPageUp(int height);
        void ScrollPageDown(int height);
        void ScrollToTop();
        void ScrollToBottom();

        bool IsFollowing() const { return m_follow; }
        size_t ScrollAnchor() const { return m_anchor; }
        void SetScrollAnchor(size_t anchor);

        // Index of the first visible logical line for a viewport of `height`
        // rows and `width` cells (wrapping is taken into account).
        size_t FirstVisible(int height, int width) const;

        // The display rows currently visible, already wrapped to `width`.
        std::vector<std::string> VisibleRows(int height, int width) const;

        // 1-based inclusive range of logical lines on screen, for the indicator.
        void VisibleRange(int height, int width, size_t& first, size_t& last) const;

        bool HasOlderAbove(int height, int width) const;
        bool HasNewerBelow(int height, int width) const;

    private:
        void Trim();
        size_t RowsFor(const std::string& line, int width) const;

        std::deque<std::string> m_lines;
        std::string m_pending;      // partial line awaiting its newline
        size_t m_anchor = 0;        // first visible logical line when not following
        bool m_follow = true;
    };

    // std::streambuf that redirects everything a command prints into an
    // OutputBuffer. Commands call std::cout / Ui::* exactly as before and never
    // learn about screen rows.
    class OutputSink : public std::streambuf {
    public:
        explicit OutputSink(OutputBuffer& buffer) : m_buffer(buffer) {}

    protected:
        int overflow(int ch) override;
        std::streamsize xsputn(const char* s, std::streamsize count) override;

    private:
        OutputBuffer& m_buffer;
    };

    // ─── The screen ─────────────────────────────────────────────────────────

    class InteractiveScreen {
    public:
        InteractiveScreen();
        ~InteractiveScreen();

        InteractiveScreen(const InteractiveScreen&) = delete;
        InteractiveScreen& operator=(const InteractiveScreen&) = delete;

        bool Begin();
        void End();
        bool Active() const { return m_active; }

        OutputBuffer& Output() { return m_output; }

        void SetHeaderInfo(const StartupInfo& info);
        void SetStatusLine(const std::string& status);

        // Read one command line. Returns false on EOF (Ctrl+D on an empty line).
        bool ReadCommand(LineEditor& editor, const std::string& prompt, std::string& outLine);

        void Render(const LineEditor& editor, const std::string& prompt);
        void Invalidate();

        // --- Text selection ------------------------------------------------
        // Dracula owns selection rather than delegating to the console's
        // quick-edit mode, so the wheel keeps scrolling the viewport while the
        // mouse is free to select. There is no mode to enter or leave.
        //
        // Coordinates are absolute console cells; only cells inside the output
        // region participate.
        void BeginSelection(int row, int column);
        void ExtendSelection(int row, int column);
        void EndSelection();
        void ClearSelection();
        bool HasSelection() const;

        // The selected text, with rows joined by newlines and trailing spaces
        // trimmed. Empty when there is no selection.
        std::string SelectedText() const;

        // Copies the current selection to the clipboard. False when there is
        // nothing selected or the clipboard could not be opened.
        bool CopySelection();

        const ScreenLayout& Layout() const { return m_layout; }
        void Relayout(int suggestionCount);

        // Compose the frame for an explicit geometry, without a console
        // attached. This is the same composition the real paint uses, so the
        // layout tests can verify the painted regions and not just the
        // rectangles. It leaves the screen laid out for that geometry.
        std::vector<std::string> PreviewFrame(int width, int height,
                                              const LineEditor& editor,
                                              const std::string& prompt);

    private:
        void RestoreStreams();
        std::vector<std::string> ComposeFrame(const LineEditor& editor,
                                              const std::string& prompt,
                                              int& outCursorRow,
                                              int& outCursorColumn) const;

        OutputBuffer m_output;
        std::unique_ptr<OutputSink> m_sink;
        std::streambuf* m_savedCout = nullptr;
        std::streambuf* m_savedCerr = nullptr;

        StartupInfo m_info;
        std::string m_status;

        ScreenLayout m_layout;
        std::vector<std::string> m_headerCache;
        int m_cachedHeaderWidth = -1;
        HeaderVariant m_cachedHeaderVariant = HeaderVariant::None;

        // Applies the selection highlight to a composed frame. Kept separate
        // from composition so PreviewFrame and the real paint share it.
        void ApplySelectionHighlight(std::vector<std::string>& frame) const;

        // Normalized selection bounds (start before end). Returns false when
        // nothing is selected.
        bool SelectionBounds(int& startRow, int& startCol,
                             int& endRow, int& endCol) const;

        std::vector<std::string> m_lastFrame;

        // Plain (escape-free) text of the last painted output region, indexed
        // by absolute console row. Selection copies from this, so what lands on
        // the clipboard is exactly what the user saw, without colour codes.
        // Mutable because it is a by-product of composing a frame, which is
        // logically a const operation.
        mutable std::vector<std::string> m_plainRows;

        bool m_active = false;
        int m_lastWidth = 0;
        int m_lastHeight = 0;

        // Selection anchor and cursor, in absolute console cells. Row -1 means
        // "no selection".
        int  m_selAnchorRow = -1;
        int  m_selAnchorCol = 0;
        int  m_selCursorRow = -1;
        int  m_selCursorCol = 0;
        bool m_selecting = false;
    };

} // namespace Dracula
