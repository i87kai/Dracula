#include "cli/line_editor.h"
#include "cli/terminal.h"

#include <iostream>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <sstream>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <conio.h>
#include <io.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace Dracula {

    LineEditor::LineEditor() {
        // Set default history path
        std::string homeDir;
#ifdef _WIN32
        const char* appData = std::getenv("APPDATA");
        if (appData && appData[0] != '\0') {
            homeDir = appData;
            m_historyFilePath = homeDir + "\\Dracula\\history.txt";
        } else {
            const char* userProfile = std::getenv("USERPROFILE");
            if (userProfile && userProfile[0] != '\0') {
                m_historyFilePath = std::string(userProfile) + "\\.dracula_history";
            } else {
                m_historyFilePath = ".dracula_history";
            }
        }
#else
        const char* home = std::getenv("HOME");
        if (home && home[0] != '\0') {
            m_historyFilePath = std::string(home) + "/.dracula_history";
        } else {
            m_historyFilePath = ".dracula_history";
        }
#endif
        LoadHistory();
    }

    LineEditor::~LineEditor() {
        SaveHistory();
    }

    void LineEditor::SetHistoryFilePath(const std::string& path) {
        m_historyFilePath = path;
    }

    void LineEditor::SetMaxHistorySize(size_t maxSize) {
        m_maxHistorySize = maxSize;
    }

    void LineEditor::LoadHistory() {
        m_history.clear();
        if (m_historyFilePath.empty()) return;

        std::ifstream file(m_historyFilePath);
        if (!file.is_open()) return;

        std::string line;
        while (std::getline(file, line)) {
            // Strip CR
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (!line.empty()) {
                m_history.push_back(line);
                if (m_history.size() > m_maxHistorySize) {
                    m_history.pop_front();
                }
            }
        }
    }

    void LineEditor::SaveHistory() {
        if (m_historyFilePath.empty()) return;

        try {
            std::filesystem::path p(m_historyFilePath);
            if (p.has_parent_path()) {
                std::filesystem::create_directories(p.parent_path());
            }

            std::ofstream file(m_historyFilePath, std::ios::trunc);
            if (!file.is_open()) return;

            for (const auto& line : m_history) {
                file << line << "\n";
            }
        } catch (...) {
            // Suppress filesystem errors gracefully
        }
    }

    void LineEditor::AddHistory(const std::string& line) {
        if (line.empty()) return;
        // Avoid adding duplicate consecutive commands
        if (!m_history.empty() && m_history.back() == line) {
            return;
        }
        m_history.push_back(line);
        if (m_history.size() > m_maxHistorySize) {
            m_history.pop_front();
        }
    }

    void LineEditor::ResetBuffer() {
        m_buffer.clear();
        m_cursorPos = 0;
        m_paletteActive = false;
        m_paletteSelection = 0;
        m_filteredCommands.clear();
        m_historyIndex = -1;
        m_savedCurrentLine.clear();
    }

    void LineEditor::InsertChar(char c) {
        m_buffer.insert(m_cursorPos, 1, c);
        m_cursorPos++;
        UpdatePalette();
    }

    void LineEditor::InsertString(const std::string& s) {
        m_buffer.insert(m_cursorPos, s);
        m_cursorPos += s.size();
        UpdatePalette();
    }

    void LineEditor::DeleteCharBeforeCursor() {
        if (m_cursorPos > 0) {
            m_buffer.erase(m_cursorPos - 1, 1);
            m_cursorPos--;
            UpdatePalette();
        }
    }

    void LineEditor::DeleteCharAtCursor() {
        if (m_cursorPos < m_buffer.size()) {
            m_buffer.erase(m_cursorPos, 1);
            UpdatePalette();
        }
    }

    void LineEditor::MoveCursorLeft() {
        if (m_cursorPos > 0) m_cursorPos--;
    }

    void LineEditor::MoveCursorRight() {
        if (m_cursorPos < m_buffer.size()) m_cursorPos++;
    }

    void LineEditor::MoveCursorHome() {
        m_cursorPos = 0;
    }

    void LineEditor::MoveCursorEnd() {
        m_cursorPos = m_buffer.size();
    }

    void LineEditor::ClearToEndOfLine() {
        if (m_cursorPos < m_buffer.size()) {
            m_buffer.erase(m_cursorPos);
            UpdatePalette();
        }
    }

    void LineEditor::ClearLine() {
        m_buffer.clear();
        m_cursorPos = 0;
        UpdatePalette();
    }

    void LineEditor::UpdatePalette() {
        // Active when buffer starts with '/' and does not contain space
        if (!m_buffer.empty() && m_buffer.front() == '/' && m_buffer.find(' ') == std::string::npos) {
            m_filteredCommands = CommandRegistry::Instance().FilterByPrefix(m_buffer);
            if (!m_filteredCommands.empty()) {
                m_paletteActive = true;
                if (m_paletteSelection >= m_filteredCommands.size()) {
                    m_paletteSelection = 0;
                }
            } else {
                m_paletteActive = false;
            }
        } else {
            m_paletteActive = false;
        }
    }

    void LineEditor::PaletteMoveUp() {
        if (!m_paletteActive || m_filteredCommands.empty()) return;
        if (m_paletteSelection == 0) {
            m_paletteSelection = m_filteredCommands.size() - 1; // Wrap to bottom
        } else {
            m_paletteSelection--;
        }
    }

    void LineEditor::PaletteMoveDown() {
        if (!m_paletteActive || m_filteredCommands.empty()) return;
        if (m_paletteSelection + 1 >= m_filteredCommands.size()) {
            m_paletteSelection = 0; // Wrap to top
        } else {
            m_paletteSelection++;
        }
    }

    bool LineEditor::PaletteAccept(std::string& acceptedCommand) {
        if (!m_paletteActive || m_filteredCommands.empty()) return false;

        const auto* cmd = m_filteredCommands[m_paletteSelection];
        acceptedCommand = cmd->name;

        m_buffer = "/" + cmd->name + " ";
        m_cursorPos = m_buffer.size();
        m_paletteActive = false;
        return true;
    }

    void LineEditor::PaletteDismiss() {
        m_paletteActive = false;
    }

    std::string LineEditor::CompletePath(const std::string& partial) {
        try {
            std::string clean = partial;
            // Handle quotes
            bool hasQuote = false;
            if (!clean.empty() && clean.front() == '"') {
                hasQuote = true;
                clean = clean.substr(1);
            }

            std::filesystem::path searchPath(clean);
            std::filesystem::path parentDir = searchPath.has_parent_path() ? searchPath.parent_path() : ".";
            std::string stem = searchPath.filename().string();

            if (!std::filesystem::exists(parentDir)) return "";

            std::vector<std::string> matches;
            for (const auto& entry : std::filesystem::directory_iterator(parentDir)) {
                std::string filename = entry.path().filename().string();
                if (stem.empty() || filename.rfind(stem, 0) == 0) {
                    std::string matchPath = (searchPath.has_parent_path() ? (parentDir / filename).string() : filename);
                    if (entry.is_directory()) {
                        matchPath += "\\";
                    }
                    matches.push_back(matchPath);
                }
            }

            if (matches.empty()) return "";

            if (matches.size() == 1) {
                std::string res = matches[0];
                if (hasQuote && res.back() != '\\') res += "\"";
                return res;
            }

            // Find common prefix
            std::string common = matches[0];
            for (size_t i = 1; i < matches.size(); ++i) {
                size_t j = 0;
                while (j < common.size() && j < matches[i].size() && common[j] == matches[i][j]) {
                    j++;
                }
                common = common.substr(0, j);
            }
            return common;
        } catch (...) {
            return "";
        }
    }

    bool LineEditor::CompleteCurrentToken() {
        if (m_buffer.empty()) return false;

        // Find current token before cursor
        size_t lastSpace = m_buffer.rfind(' ', m_cursorPos > 0 ? m_cursorPos - 1 : 0);
        std::string prefix;
        size_t tokenStart = 0;
        if (lastSpace != std::string::npos) {
            tokenStart = lastSpace + 1;
            prefix = m_buffer.substr(tokenStart, m_cursorPos - tokenStart);
        } else {
            tokenStart = 0;
            prefix = m_buffer.substr(0, m_cursorPos);
        }

        // 1. If at the first token and starts with '/', complete command
        if (tokenStart == 0 && !prefix.empty() && prefix[0] == '/') {
            auto matches = CommandRegistry::Instance().FilterByPrefix(prefix);
            if (!matches.empty()) {
                m_buffer = "/" + matches[0]->name + " ";
                m_cursorPos = m_buffer.size();
                m_paletteActive = false;
                return true;
            }
            return false;
        }

        // 2. Extract command name from buffer to check argument completion
        std::istringstream ss(m_buffer);
        std::string cmdName;
        ss >> cmdName;
        if (!cmdName.empty() && cmdName.front() == '/') {
            cmdName = cmdName.substr(1);
        }

        const auto* cmdDef = CommandRegistry::Instance().Find(cmdName);
        if (cmdDef) {
            // Check static argument completions first
            for (const auto& arg : cmdDef->argCompletions) {
                if (prefix.empty() || arg.rfind(prefix, 0) == 0) {
                    m_buffer.replace(tokenStart, m_cursorPos - tokenStart, arg + " ");
                    m_cursorPos = tokenStart + arg.size() + 1;
                    return true;
                }
            }

            // If command takes file path, try filesystem completion
            if (cmdDef->takesFilePath) {
                std::string completed = CompletePath(prefix);
                if (!completed.empty() && completed != prefix) {
                    m_buffer.replace(tokenStart, m_cursorPos - tokenStart, completed);
                    m_cursorPos = tokenStart + completed.size();
                    return true;
                }
            }
        }

        // General path completion fallback
        std::string completed = CompletePath(prefix);
        if (!completed.empty() && completed != prefix) {
            m_buffer.replace(tokenStart, m_cursorPos - tokenStart, completed);
            m_cursorPos = tokenStart + completed.size();
            return true;
        }

        return false;
    }

    void LineEditor::ClearRenderedPalette() {
        if (m_renderedPaletteLines == 0) return;

        // Erase rendered palette lines below current prompt
        for (size_t i = 0; i < m_renderedPaletteLines; ++i) {
            std::cout << "\n\033[2K";
        }
        // Move cursor back up
        std::cout << "\033[" << m_renderedPaletteLines << "A";
        m_renderedPaletteLines = 0;
        std::cout << std::flush;
    }

    void LineEditor::Redraw(const std::string& prompt) {
        // Clear previous palette lines first
        ClearRenderedPalette();

        // 1. Move to start of prompt line and clear it
        std::cout << "\r\033[2K";

        // 2. Print prompt and current buffer
        std::cout << prompt << m_buffer;

        // 3. Render palette below if active
        if (m_paletteActive && !m_filteredCommands.empty()) {
            size_t maxDisplay = 7;
            size_t total = m_filteredCommands.size();
            size_t count = std::min(maxDisplay, total);

            // Compute scroll offset to keep selection visible
            size_t offset = 0;
            if (m_paletteSelection >= maxDisplay) {
                offset = m_paletteSelection - maxDisplay + 1;
            }

            for (size_t i = 0; i < count; ++i) {
                size_t idx = offset + i;
                if (idx >= total) break;

                const auto* cmd = m_filteredCommands[idx];
                bool isSelected = (idx == m_paletteSelection);

                std::cout << "\n\033[2K"; // newline and clear line

                std::string prefixMark = isSelected ? "> " : "  ";
                std::string cmdName = "/" + cmd->name;

                // Format command and description aligned
                std::string lineStr;
                if (isSelected) {
                    lineStr += Terminal::Color(ColorRole::Selection);
                    lineStr += prefixMark + cmdName;
                    // Pad command name to column 16
                    if (cmdName.size() < 14) {
                        lineStr += std::string(14 - cmdName.size(), ' ');
                    } else {
                        lineStr += "  ";
                    }
                    lineStr += cmd->description;
                    lineStr += Terminal::Color(ColorRole::Reset);
                } else {
                    lineStr += Terminal::Color(ColorRole::Muted) + prefixMark + Terminal::Color(ColorRole::Reset);
                    lineStr += Terminal::Color(ColorRole::Secondary) + cmdName + Terminal::Color(ColorRole::Reset);
                    if (cmdName.size() < 14) {
                        lineStr += std::string(14 - cmdName.size(), ' ');
                    } else {
                        lineStr += "  ";
                    }
                    lineStr += Terminal::Color(ColorRole::Muted) + cmd->description + Terminal::Color(ColorRole::Reset);
                }

                std::cout << lineStr;
                m_renderedPaletteLines++;
            }

            if (total > count && offset + count < total) {
                std::cout << "\n\033[2K" << Terminal::Color(ColorRole::Muted) << "    ... (" << (total - offset - count) << " more commands)" << Terminal::Color(ColorRole::Reset);
                m_renderedPaletteLines++;
            }

            // Move cursor back up to the prompt line
            if (m_renderedPaletteLines > 0) {
                std::cout << "\033[" << m_renderedPaletteLines << "A";
            }
        }

        // 4. Position cursor accurately inside the buffer
        size_t promptLen = Terminal::VisibleLength(prompt);
        size_t targetCol = promptLen + m_cursorPos + 1;
        std::cout << "\r\033[" << targetCol << "C" << std::flush;
    }

    bool LineEditor::ReadLine(const std::string& prompt, std::string& outLine) {
        ResetBuffer();

        // Non-interactive fallback
        if (!Terminal::IsInteractive() || !Terminal::SupportsColor()) {
            std::cout << prompt << std::flush;
            if (!std::getline(std::cin, outLine)) {
                return false;
            }
            return true;
        }

#ifdef _WIN32
        Redraw(prompt);

        while (true) {
            wint_t ch = _getwch();

            // Extended key prefix
            if (ch == 0 || ch == 0xE0) {
                wint_t ext = _getwch();
                switch (ext) {
                    case 72: // UP ARROW
                        if (m_paletteActive) {
                            PaletteMoveUp();
                        } else if (!m_history.empty()) {
                            if (m_historyIndex == -1) {
                                m_savedCurrentLine = m_buffer;
                                m_historyIndex = static_cast<int>(m_history.size()) - 1;
                            } else if (m_historyIndex > 0) {
                                m_historyIndex--;
                            }
                            if (m_historyIndex >= 0 && m_historyIndex < static_cast<int>(m_history.size())) {
                                m_buffer = m_history[m_historyIndex];
                                m_cursorPos = m_buffer.size();
                            }
                        }
                        break;

                    case 80: // DOWN ARROW
                        if (m_paletteActive) {
                            PaletteMoveDown();
                        } else if (m_historyIndex != -1) {
                            if (m_historyIndex + 1 < static_cast<int>(m_history.size())) {
                                m_historyIndex++;
                                m_buffer = m_history[m_historyIndex];
                                m_cursorPos = m_buffer.size();
                            } else {
                                m_historyIndex = -1;
                                m_buffer = m_savedCurrentLine;
                                m_cursorPos = m_buffer.size();
                            }
                        }
                        break;

                    case 75: // LEFT ARROW
                        MoveCursorLeft();
                        break;

                    case 77: // RIGHT ARROW
                        MoveCursorRight();
                        break;

                    case 71: // HOME
                        MoveCursorHome();
                        break;

                    case 79: // END
                        MoveCursorEnd();
                        break;

                    case 83: // DELETE
                        DeleteCharAtCursor();
                        break;

                    default:
                        break;
                }
                Redraw(prompt);
                continue;
            }

            // Normal control / character keys
            if (ch == 13 || ch == 10) { // ENTER
                ClearRenderedPalette();
                if (m_paletteActive && !m_filteredCommands.empty()) {
                    const auto* cmd = m_filteredCommands[m_paletteSelection];
                    if (cmd->requiresArgs) {
                        m_buffer = "/" + cmd->name + " ";
                        m_cursorPos = m_buffer.size();
                        m_paletteActive = false;
                        Redraw(prompt);
                        continue;
                    } else {
                        m_buffer = "/" + cmd->name;
                        m_paletteActive = false;
                    }
                }
                std::cout << "\n" << std::flush;
                outLine = m_buffer;
                if (!outLine.empty()) {
                    AddHistory(outLine);
                }
                return true;
            }

            if (ch == 9) { // TAB
                if (m_paletteActive) {
                    std::string accepted;
                    PaletteAccept(accepted);
                } else {
                    CompleteCurrentToken();
                }
                Redraw(prompt);
                continue;
            }

            if (ch == 27) { // ESCAPE
                if (m_paletteActive) {
                    PaletteDismiss();
                }
                Redraw(prompt);
                continue;
            }

            if (ch == 8 || ch == 127) { // BACKSPACE
                DeleteCharBeforeCursor();
                Redraw(prompt);
                continue;
            }

            if (ch == 3) { // Ctrl+C
                ClearRenderedPalette();
                std::cout << "^C\n" << std::flush;
                outLine.clear();
                return true;
            }

            if (ch == 4) { // Ctrl+D (EOF)
                if (m_buffer.empty()) {
                    ClearRenderedPalette();
                    return false;
                }
            }

            if (ch == 1) { // Ctrl+A (Home)
                MoveCursorHome();
                Redraw(prompt);
                continue;
            }

            if (ch == 5) { // Ctrl+E (End)
                MoveCursorEnd();
                Redraw(prompt);
                continue;
            }

            if (ch == 11) { // Ctrl+K (Clear to end)
                ClearToEndOfLine();
                Redraw(prompt);
                continue;
            }

            if (ch == 21) { // Ctrl+U (Clear line)
                ClearLine();
                Redraw(prompt);
                continue;
            }

            // Printable characters
            if (ch >= 32 && ch <= 126) {
                InsertChar(static_cast<char>(ch));
                Redraw(prompt);
                continue;
            }

            // Extended Unicode character (UTF-8 multi-byte conversion)
            if (ch > 126) {
                char utf8[8] = {0};
                int bytes = WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<LPCWCH>(&ch), 1, utf8, sizeof(utf8), nullptr, nullptr);
                if (bytes > 0) {
                    InsertString(std::string(utf8, bytes));
                    Redraw(prompt);
                }
                continue;
            }
        }
#else
        // POSIX fallback
        std::cout << prompt << std::flush;
        if (!std::getline(std::cin, outLine)) return false;
        if (!outLine.empty()) AddHistory(outLine);
        return true;
#endif
    }

} // namespace Dracula
