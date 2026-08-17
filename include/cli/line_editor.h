#pragma once

#include <string>
#include <vector>
#include <deque>
#include <memory>
#include "cli/command_registry.h"

namespace Dracula {

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

        // Read a line with full interactive line editing and slash palette
        bool ReadLine(const std::string& prompt, std::string& outLine);

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
        bool IsPaletteActive() const { return m_paletteActive; }
        size_t GetPaletteSelection() const { return m_paletteSelection; }
        const std::vector<const CommandDefinition*>& GetFilteredCommands() const { return m_filteredCommands; }

    private:
        void Redraw(const std::string& prompt);
        void ClearRenderedPalette();
        std::string CompletePath(const std::string& partial);

        std::string m_buffer;
        size_t m_cursorPos = 0;

        // History
        std::deque<std::string> m_history;
        size_t m_maxHistorySize = 500;
        std::string m_historyFilePath;
        int m_historyIndex = -1;
        std::string m_savedCurrentLine;

        // Slash palette state
        bool m_paletteActive = false;
        size_t m_paletteSelection = 0;
        std::vector<const CommandDefinition*> m_filteredCommands;
        size_t m_renderedPaletteLines = 0;
    };

} // namespace Dracula
