#pragma once

#include <string>
#include <vector>
#include <deque>
#include <memory>
#include "cli/command_registry.h"
#include "cli/terminal.h"

namespace Dracula {

    // What the suggestion popup below the prompt is currently offering.
    enum class SuggestionKind {
        None,
        Command,    // slash command palette
        Argument,   // command-declared argument values
        Path        // filesystem completion
    };

    struct Suggestion {
        std::string value;        // text inserted when accepted
        std::string label;        // text shown in the popup
        std::string description;  // right-hand hint
        std::string group;        // category, used for subtle grouping
    };

    class LineEditor {
    public:
        LineEditor();
        ~LineEditor();

        // Configure history
        void SetHistoryFilePath(const std::string& path);
        void SetMaxHistorySize(size_t maxSize);
        void LoadHistory();
        void SaveHistory();
        void AddHistory(const std::string& line);
        const std::deque<std::string>& GetHistory() const { return m_history; }

        // Plain, non-interactive read (redirected stdin/stdout). The
        // persistent interactive layout drives HandleKey instead.
        bool ReadLine(const std::string& prompt, std::string& outLine);

        // What the caller should do after feeding an event to the editor.
        enum class EditAction {
            Continue,     // state changed, repaint
            Submit,       // the buffer is a completed command line
            Cancel,       // Ctrl+C: discard the line, repaint
            Eof,          // Ctrl+D on an empty line
            ScrollPageUp,   // PageUp: scroll the output viewport by a page
            ScrollPageDown, // PageDown
            ScrollLineUp,   // mouse wheel up
            ScrollLineDown, // mouse wheel down
            ScrollTop,      // Ctrl+Home: oldest output
            ScrollBottom,   // Ctrl+End: newest output
            ClearScreen,  // Ctrl+L
            Resize        // terminal geometry changed
        };

        // Apply one normalized input event to the editor state. Performs no
        // rendering: the screen owns every cursor movement.
        EditAction HandleKey(const InputEvent& event);

        // The slice of the input buffer that fits in `available` cells, and the
        // cursor's column offset within that slice.
        std::string VisibleInput(size_t available, size_t& cursorOffset) const;

        // Core line editing logic exposed for testing
        void ResetBuffer();
        void InsertChar(char c);
        void InsertString(const std::string& s);
        void DeleteCharBeforeCursor();
        void DeleteCharAtCursor();
        void MoveCursorLeft();
        void MoveCursorRight();
        void MoveCursorHome();
        void MoveCursorEnd();
        void ClearToEndOfLine();
        void ClearLine();

        // Slash command palette logic exposed for testing
        void UpdatePalette();
        void PaletteMoveUp();
        void PaletteMoveDown();
        bool PaletteAccept(std::string& acceptedCommand);
        void PaletteDismiss();

        // Autocompletion
        bool CompleteCurrentToken();

        // Getters for inspection/testing
        const std::string& GetBuffer() const { return m_buffer; }
        size_t GetCursorPos() const { return m_cursorPos; }
        bool IsPaletteActive() const { return m_kind == SuggestionKind::Command; }
        bool IsSuggestionActive() const { return m_kind != SuggestionKind::None; }
        SuggestionKind GetSuggestionKind() const { return m_kind; }
        size_t GetPaletteSelection() const { return m_selection; }
        const std::vector<Suggestion>& GetSuggestions() const { return m_suggestions; }
        const std::vector<const CommandDefinition*>& GetFilteredCommands() const { return m_filteredCommands; }

        // Preferred popup height. The screen may hand down fewer rows when the
        // terminal is short; the list scrolls in whatever it is given.
        static constexpr size_t kViewportRows = 8;
        size_t ViewportOffset(size_t visibleRows = kViewportRows) const;

        // Compose the popup rows for the current state. Pure - used by tests to
        // verify rendering without a console attached.
        std::vector<std::string> BuildPopupRows(size_t width,
                                                size_t visibleRows = kViewportRows) const;

    private:
        void SetSuggestions(SuggestionKind kind, std::vector<Suggestion> items);
        void ClearSuggestions();
        bool AcceptSuggestion();

        // Completion sources
        std::vector<Suggestion> CollectPathSuggestions(const std::string& partial) const;
        std::vector<Suggestion> CollectArgumentSuggestions(const std::string& partial) const;
        std::string CompletePath(const std::string& partial);

        // Current token under the cursor (start offset and text).
        void CurrentToken(size_t& start, std::string& text) const;

        std::string m_buffer;
        size_t m_cursorPos = 0;

        // History
        std::deque<std::string> m_history;
        size_t m_maxHistorySize = 500;
        std::string m_historyFilePath;
        int m_historyIndex = -1;
        std::string m_savedCurrentLine;

        // Suggestion popup state
        SuggestionKind m_kind = SuggestionKind::None;
        size_t m_selection = 0;
        std::vector<Suggestion> m_suggestions;
        std::vector<const CommandDefinition*> m_filteredCommands;

        // Horizontal scroll offset used when the input exceeds the line width.
        mutable size_t m_scrollOffset = 0;
    };

} // namespace Dracula
