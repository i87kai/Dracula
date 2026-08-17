#include "cli/line_editor.h"
#include "cli/terminal.h"
#include "cli/text_layout.h"

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

    namespace {

        std::string C(ColorRole role) { return Terminal::Color(role); }
        std::string R() { return Terminal::Color(ColorRole::Reset); }

        int CategoryRank(const std::string& category) {
            if (category == "Analysis")   return 0;
            if (category == "Inspection") return 1;
            if (category == "Emulation")  return 2;
            if (category == "Session")    return 3;
            if (category == "System")     return 4;
            return 5;
        }

        std::string CommonPrefix(const std::vector<Suggestion>& items) {
            if (items.empty()) return "";
            std::string common = items[0].value;
            for (size_t i = 1; i < items.size(); ++i) {
                size_t j = 0;
                while (j < common.size() && j < items[i].value.size() &&
                       common[j] == items[i].value[j]) {
                    ++j;
                }
                common = common.substr(0, j);
            }
            return common;
        }

        // A path token needs quoting once it contains a space.
        std::string QuoteIfNeeded(const std::string& path) {
            if (path.find(' ') == std::string::npos) return path;
            return "\"" + path + "\"";
        }

    } // namespace

    LineEditor::LineEditor() {
#ifdef _WIN32
        const char* appData = std::getenv("APPDATA");
        if (appData && appData[0] != '\0') {
            m_historyFilePath = std::string(appData) + "\\Dracula\\history.txt";
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

    // ─── History ────────────────────────────────────────────────────────────

    void LineEditor::SetHistoryFilePath(const std::string& path) {
        // Pointing at a different history file must not leave entries loaded
        // from the previous one in memory.
        m_historyFilePath = path;
        LoadHistory();
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
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!line.empty()) {
                m_history.push_back(line);
                if (m_history.size() > m_maxHistorySize) m_history.pop_front();
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
            for (const auto& line : m_history) file << line << "\n";
        } catch (...) {
            // History is best effort; never fail a session over it.
        }
    }

    void LineEditor::AddHistory(const std::string& line) {
        if (line.empty()) return;
        if (!m_history.empty() && m_history.back() == line) return;
        m_history.push_back(line);
        if (m_history.size() > m_maxHistorySize) m_history.pop_front();
    }

    // ─── Buffer editing ─────────────────────────────────────────────────────

    void LineEditor::ResetBuffer() {
        m_buffer.clear();
        m_cursorPos = 0;
        m_historyIndex = -1;
        m_savedCurrentLine.clear();
        m_scrollOffset = 0;
        ClearSuggestions();
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

    void LineEditor::MoveCursorLeft()  { if (m_cursorPos > 0) m_cursorPos--; }
    void LineEditor::MoveCursorRight() { if (m_cursorPos < m_buffer.size()) m_cursorPos++; }
    void LineEditor::MoveCursorHome()  { m_cursorPos = 0; }
    void LineEditor::MoveCursorEnd()   { m_cursorPos = m_buffer.size(); }

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

    // ─── Suggestion model ───────────────────────────────────────────────────

    void LineEditor::ClearSuggestions() {
        m_kind = SuggestionKind::None;
        m_suggestions.clear();
        m_filteredCommands.clear();
        m_selection = 0;
    }

    void LineEditor::SetSuggestions(SuggestionKind kind, std::vector<Suggestion> items) {
        if (items.empty()) {
            ClearSuggestions();
            return;
        }
        m_kind = kind;
        m_suggestions = std::move(items);
        if (m_selection >= m_suggestions.size()) m_selection = 0;
    }

    void LineEditor::UpdatePalette() {
        // The slash palette owns the popup while the first token is being typed.
        const bool firstTokenSlash =
            !m_buffer.empty() && m_buffer.front() == '/' &&
            m_buffer.find(' ') == std::string::npos;

        if (!firstTokenSlash) {
            // Editing arguments invalidates a command palette, but an argument
            // or path popup stays valid until the token changes; it is rebuilt
            // explicitly on Tab.
            if (m_kind == SuggestionKind::Command) ClearSuggestions();
            return;
        }

        auto matches = CommandRegistry::Instance().FilterByPrefix(m_buffer);

        // Present in a deliberate order: Analysis, Inspection, Emulation,
        // Session, System - and alphabetically inside each group.
        std::stable_sort(matches.begin(), matches.end(),
            [](const CommandDefinition* a, const CommandDefinition* b) {
                int ra = CategoryRank(a->category), rb = CategoryRank(b->category);
                if (ra != rb) return ra < rb;
                return a->name < b->name;
            });

        m_filteredCommands = matches;

        std::vector<Suggestion> items;
        items.reserve(matches.size());
        for (const auto* cmd : matches) {
            items.push_back({cmd->name, "/" + cmd->name, cmd->description, cmd->category});
        }

        size_t previous = m_selection;
        SetSuggestions(SuggestionKind::Command, std::move(items));
        if (m_kind == SuggestionKind::Command && previous < m_suggestions.size()) {
            m_selection = previous;
        }
    }

    void LineEditor::PaletteMoveUp() {
        if (m_suggestions.empty()) return;
        m_selection = (m_selection == 0) ? m_suggestions.size() - 1 : m_selection - 1;
    }

    void LineEditor::PaletteMoveDown() {
        if (m_suggestions.empty()) return;
        m_selection = (m_selection + 1 >= m_suggestions.size()) ? 0 : m_selection + 1;
    }

    bool LineEditor::PaletteAccept(std::string& acceptedCommand) {
        if (m_kind != SuggestionKind::Command || m_suggestions.empty()) return false;
        if (m_selection >= m_suggestions.size()) m_selection = 0;

        acceptedCommand = m_suggestions[m_selection].value;
        m_buffer = "/" + acceptedCommand + " ";
        m_cursorPos = m_buffer.size();
        ClearSuggestions();
        return true;
    }

    void LineEditor::PaletteDismiss() {
        ClearSuggestions();
    }

    size_t LineEditor::ViewportOffset(size_t visibleRows) const {
        if (visibleRows == 0) visibleRows = 1;
        if (m_suggestions.size() <= visibleRows) return 0;
        if (m_selection < visibleRows) return 0;
        size_t offset = m_selection - visibleRows + 1;
        size_t maxOffset = m_suggestions.size() - visibleRows;
        return std::min(offset, maxOffset);
    }

    // ─── Token analysis ─────────────────────────────────────────────────────

    void LineEditor::CurrentToken(size_t& start, std::string& text) const {
        start = 0;
        bool inQuotes = false;
        for (size_t i = 0; i < m_cursorPos && i < m_buffer.size(); ++i) {
            char c = m_buffer[i];
            if (c == '"') inQuotes = !inQuotes;
            else if (c == ' ' && !inQuotes) start = i + 1;
        }
        text = m_buffer.substr(start, m_cursorPos - start);
    }

    // ─── Completion sources ─────────────────────────────────────────────────

    std::vector<Suggestion> LineEditor::CollectPathSuggestions(const std::string& partial) const {
        std::vector<Suggestion> out;
        try {
            std::string clean = partial;
            if (!clean.empty() && clean.front() == '"') clean = clean.substr(1);
            if (!clean.empty() && clean.back() == '"') clean.pop_back();

            std::filesystem::path searchPath(clean);

            // A trailing separator means "list this directory".
            bool listDir = !clean.empty() &&
                           (clean.back() == '\\' || clean.back() == '/');

            std::filesystem::path parentDir;
            std::string stem;
            if (listDir) {
                parentDir = searchPath;
            } else if (searchPath.has_parent_path()) {
                parentDir = searchPath.parent_path();
                stem = searchPath.filename().string();
            } else {
                parentDir = ".";
                stem = clean;
            }
            if (parentDir.empty()) parentDir = ".";
            if (!std::filesystem::exists(parentDir) ||
                !std::filesystem::is_directory(parentDir)) {
                return out;
            }

            for (const auto& entry : std::filesystem::directory_iterator(parentDir)) {
                std::string filename = entry.path().filename().string();
                if (!stem.empty() && filename.rfind(stem, 0) != 0) continue;

                bool isDir = entry.is_directory();
                std::string value;
                if (listDir) {
                    value = clean + filename;
                } else if (searchPath.has_parent_path()) {
                    value = (parentDir / filename).string();
                } else {
                    value = filename;
                }
                if (isDir) value += "\\";

                out.push_back({value, filename + (isDir ? "\\" : ""),
                               isDir ? "directory" : "file",
                               isDir ? "Directories" : "Files"});
            }

            std::sort(out.begin(), out.end(), [](const Suggestion& a, const Suggestion& b) {
                if (a.group != b.group) return a.group < b.group;   // Directories first
                return a.label < b.label;
            });
        } catch (...) {
            out.clear();
        }
        return out;
    }

    std::vector<Suggestion> LineEditor::CollectArgumentSuggestions(const std::string& partial) const {
        std::vector<Suggestion> out;

        std::istringstream ss(m_buffer);
        std::string cmdName;
        ss >> cmdName;
        if (!cmdName.empty() && cmdName.front() == '/') cmdName = cmdName.substr(1);

        const auto* def = CommandRegistry::Instance().Find(cmdName);
        if (!def) return out;

        // Which token immediately precedes the one being completed?
        std::vector<std::string> before;
        {
            std::istringstream ts(m_buffer.substr(0, m_cursorPos));
            std::string t;
            while (ts >> t) before.push_back(t);
            if (!partial.empty() && !before.empty()) before.pop_back();
        }
        const std::string previous = before.empty() ? "" : before.back();

        // 1. Values declared for the preceding flag.
        for (const auto& [flag, values] : def->flagCompletions) {
            if (previous == flag) {
                for (const auto& v : values) {
                    if (partial.empty() || v.rfind(partial, 0) == 0) {
                        out.push_back({v, v, flag + " value", "Values"});
                    }
                }
                return out;
            }
        }

        // 2. Positional value suggestions declared by the command.
        for (const auto& v : def->argCompletions) {
            if (partial.empty() || v.rfind(partial, 0) == 0) {
                out.push_back({v, v, "", "Values"});
            }
        }
        return out;
    }

    std::string LineEditor::CompletePath(const std::string& partial) {
        auto matches = CollectPathSuggestions(partial);
        if (matches.empty()) return "";
        if (matches.size() == 1) return matches[0].value;
        return CommonPrefix(matches);
    }

    bool LineEditor::CompleteCurrentToken() {
        size_t tokenStart = 0;
        std::string prefix;
        CurrentToken(tokenStart, prefix);

        auto replaceToken = [&](const std::string& replacement, bool addSpace) {
            std::string text = replacement + (addSpace ? " " : "");
            m_buffer.replace(tokenStart, m_cursorPos - tokenStart, text);
            m_cursorPos = tokenStart + text.size();
        };

        // 1. First token starting with '/': complete the command name.
        if (tokenStart == 0 && !prefix.empty() && prefix[0] == '/') {
            auto matches = CommandRegistry::Instance().FilterByPrefix(prefix);
            if (matches.empty()) return false;
            m_buffer = "/" + matches[0]->name + " ";
            m_cursorPos = m_buffer.size();
            ClearSuggestions();
            return true;
        }

        // 2. Argument values declared by the command metadata.
        auto argMatches = CollectArgumentSuggestions(prefix);
        if (argMatches.size() == 1) {
            replaceToken(argMatches[0].value, true);
            ClearSuggestions();
            return true;
        }
        if (argMatches.size() > 1) {
            std::string common = CommonPrefix(argMatches);
            if (common.size() > prefix.size()) replaceToken(common, false);
            SetSuggestions(SuggestionKind::Argument, std::move(argMatches));
            return true;
        }

        // 3. Filesystem completion.
        auto pathMatches = CollectPathSuggestions(prefix);
        if (pathMatches.size() == 1) {
            const std::string& value = pathMatches[0].value;
            bool isDir = !value.empty() && value.back() == '\\';
            replaceToken(QuoteIfNeeded(value), !isDir);
            ClearSuggestions();
            return true;
        }
        if (pathMatches.size() > 1) {
            std::string common = CommonPrefix(pathMatches);
            if (common.size() > prefix.size()) replaceToken(QuoteIfNeeded(common), false);
            SetSuggestions(SuggestionKind::Path, std::move(pathMatches));
            return true;
        }

        return false;
    }

    bool LineEditor::AcceptSuggestion() {
        if (m_suggestions.empty()) return false;
        if (m_selection >= m_suggestions.size()) m_selection = 0;

        if (m_kind == SuggestionKind::Command) {
            std::string accepted;
            return PaletteAccept(accepted);
        }

        size_t tokenStart = 0;
        std::string prefix;
        CurrentToken(tokenStart, prefix);

        const std::string& value = m_suggestions[m_selection].value;
        bool isDir = (m_kind == SuggestionKind::Path) && !value.empty() && value.back() == '\\';
        std::string text = QuoteIfNeeded(value) + (isDir ? "" : " ");

        m_buffer.replace(tokenStart, m_cursorPos - tokenStart, text);
        m_cursorPos = tokenStart + text.size();
        ClearSuggestions();
        return true;
    }

    // ─── Popup rendering ────────────────────────────────────────────────────

    std::vector<std::string> LineEditor::BuildPopupRows(size_t width,
                                                        size_t visibleRows) const {
        std::vector<std::string> rows;
        if (m_suggestions.empty()) return rows;
        if (visibleRows == 0) visibleRows = 1;

        const size_t total = m_suggestions.size();
        const size_t offset = ViewportOffset(visibleRows);
        const size_t count = std::min(visibleRows, total - offset);

        size_t labelWidth = 0;
        for (size_t i = 0; i < count; ++i) {
            labelWidth = std::max(labelWidth, Text::VisibleWidth(m_suggestions[offset + i].label));
        }
        labelWidth = std::min(labelWidth + 2, width > 24 ? width / 2 : width);

        const std::string marker = Terminal::SupportsUnicode() ? "\xE2\x9D\xAF" : ">";

        // Both states occupy exactly the same geometry: a 4-cell gutter plus a
        // body of fixed width. That is what makes the selection read as a solid
        // bar instead of shifting the row sideways.
        const size_t bodyWidth = width > 6 ? width - 5 : 8;
        const size_t descWidth = bodyWidth > labelWidth ? bodyWidth - labelWidth : 4;

        for (size_t i = 0; i < count; ++i) {
            const size_t idx = offset + i;
            const auto& item = m_suggestions[idx];
            const bool selected = (idx == m_selection);

            const std::string label = Text::Fit(item.label, labelWidth);
            const std::string desc  = Text::Fit(item.description, descWidth);

            std::string row;
            if (selected) {
                row = "  " + C(ColorRole::Primary) + marker + " " + R() +
                      C(ColorRole::Selection) + label + desc + R();
            } else {
                row = "    " +
                      C(ColorRole::Command) + label + R() +
                      C(ColorRole::Muted) + desc + R();
            }
            rows.push_back(row);
        }

        // Footer: position within the list, and the usage of the selection.
        std::string footer = "  " + C(ColorRole::Muted) +
                             std::to_string(m_selection + 1) + " of " +
                             std::to_string(total) + " " +
                             (m_kind == SuggestionKind::Command ? "commands"
                              : m_kind == SuggestionKind::Path ? "paths" : "values");

        // When the list is taller than the rows we were given, say so: the
        // palette shrinks on short terminals and still scrolls.
        if (total > count) {
            footer += "   " + Terminal::Bullet() + "   " +
                      (Terminal::SupportsUnicode() ? "\xE2\x86\x91\xE2\x86\x93 browse"
                                                   : "Up/Down browse");
        }

        if (m_kind == SuggestionKind::Command && m_selection < m_filteredCommands.size()) {
            footer += "   " + Terminal::Bullet() + "   " + m_filteredCommands[m_selection]->usage;
        }
        footer += R();
        rows.push_back(Text::Truncate(footer, width));

        return rows;
    }


    // ─── Input slice ────────────────────────────────────────────────────────

    std::string LineEditor::VisibleInput(size_t available, size_t& cursorOffset) const {
        if (available == 0) available = 1;

        // Horizontal scrolling keeps the input on a single physical row, which
        // is what makes the fixed input region reliable.
        if (m_buffer.size() <= available) {
            m_scrollOffset = 0;
        } else {
            if (m_cursorPos < m_scrollOffset) {
                m_scrollOffset = m_cursorPos;
            }
            if (m_cursorPos - m_scrollOffset > available) {
                m_scrollOffset = m_cursorPos - available;
            }
            if (m_scrollOffset > m_buffer.size()) m_scrollOffset = m_buffer.size();
        }

        std::string visible = m_buffer.substr(std::min(m_scrollOffset, m_buffer.size()));
        if (visible.size() > available) visible = visible.substr(0, available);

        cursorOffset = m_cursorPos - std::min(m_scrollOffset, m_cursorPos);
        if (cursorOffset > available) cursorOffset = available;
        return visible;
    }

    // ─── Event handling ─────────────────────────────────────────────────────

    LineEditor::EditAction LineEditor::HandleKey(const InputEvent& event) {
        switch (event.key) {
            case Key::Resize:
                return EditAction::Resize;

            case Key::Up:
                // Palette navigation wins while the popup is open; otherwise
                // Up/Down belong to command history.
                if (IsSuggestionActive()) {
                    PaletteMoveUp();
                } else if (!m_history.empty()) {
                    if (m_historyIndex == -1) {
                        m_savedCurrentLine = m_buffer;
                        m_historyIndex = static_cast<int>(m_history.size()) - 1;
                    } else if (m_historyIndex > 0) {
                        m_historyIndex--;
                    }
                    if (m_historyIndex >= 0 && m_historyIndex < static_cast<int>(m_history.size())) {
                        m_buffer = m_history[static_cast<size_t>(m_historyIndex)];
                        m_cursorPos = m_buffer.size();
                    }
                }
                return EditAction::Continue;

            case Key::Down:
                if (IsSuggestionActive()) {
                    PaletteMoveDown();
                } else if (m_historyIndex != -1) {
                    if (m_historyIndex + 1 < static_cast<int>(m_history.size())) {
                        m_historyIndex++;
                        m_buffer = m_history[static_cast<size_t>(m_historyIndex)];
                    } else {
                        m_historyIndex = -1;
                        m_buffer = m_savedCurrentLine;
                    }
                    m_cursorPos = m_buffer.size();
                }
                return EditAction::Continue;

            // Output-viewport scrolling. Deliberately never bound to Up/Down,
            // which belong to the palette and the command history.
            case Key::PageUp:    return EditAction::ScrollPageUp;
            case Key::PageDown:  return EditAction::ScrollPageDown;
            case Key::WheelUp:   return EditAction::ScrollLineUp;
            case Key::WheelDown: return EditAction::ScrollLineDown;
            case Key::CtrlHome:  return EditAction::ScrollTop;
            case Key::CtrlEnd:   return EditAction::ScrollBottom;

            // Selection mode leaves the input buffer and the palette untouched:
            // it only changes who owns the mouse.
            case Key::ToggleSelection: return EditAction::ToggleSelection;

            case Key::Left:      MoveCursorLeft();      return EditAction::Continue;
            case Key::Right:     MoveCursorRight();     return EditAction::Continue;
            case Key::Home:
            case Key::CtrlA:     MoveCursorHome();      return EditAction::Continue;
            case Key::End:
            case Key::CtrlE:     MoveCursorEnd();       return EditAction::Continue;
            case Key::Delete:    DeleteCharAtCursor();  return EditAction::Continue;
            case Key::Backspace: DeleteCharBeforeCursor(); return EditAction::Continue;
            case Key::CtrlK:     ClearToEndOfLine();    return EditAction::Continue;
            case Key::CtrlU:     ClearLine();           return EditAction::Continue;
            case Key::CtrlL:     return EditAction::ClearScreen;

            case Key::Escape:
                // Close the popup, keep the typed input.
                ClearSuggestions();
                return EditAction::Continue;

            case Key::Tab:
                if (IsSuggestionActive()) {
                    AcceptSuggestion();
                } else {
                    CompleteCurrentToken();
                }
                return EditAction::Continue;

            case Key::Enter: {
                if (m_kind == SuggestionKind::Command && !m_suggestions.empty()) {
                    const auto* cmd = m_selection < m_filteredCommands.size()
                                    ? m_filteredCommands[m_selection] : nullptr;
                    if (cmd && cmd->requiresArgs) {
                        // The command still needs arguments: accept it into the
                        // buffer instead of executing it.
                        m_buffer = "/" + cmd->name + " ";
                        m_cursorPos = m_buffer.size();
                        ClearSuggestions();
                        return EditAction::Continue;
                    }
                    if (cmd) {
                        m_buffer = "/" + cmd->name;
                        m_cursorPos = m_buffer.size();
                    }
                    ClearSuggestions();
                } else if (IsSuggestionActive()) {
                    AcceptSuggestion();
                    return EditAction::Continue;
                }
                if (!m_buffer.empty()) AddHistory(m_buffer);
                return EditAction::Submit;
            }

            case Key::CtrlC:
                ClearSuggestions();
                m_buffer.clear();
                m_cursorPos = 0;
                m_scrollOffset = 0;
                m_historyIndex = -1;
                return EditAction::Cancel;

            case Key::CtrlD:
                if (m_buffer.empty()) return EditAction::Eof;
                DeleteCharAtCursor();
                return EditAction::Continue;

            case Key::Char:
                InsertString(event.utf8);
                return EditAction::Continue;

            case Key::None:
            default:
                return EditAction::Continue;
        }
    }

    // ─── Non-interactive read ───────────────────────────────────────────────

    bool LineEditor::ReadLine(const std::string& prompt, std::string& outLine) {
        ResetBuffer();

        // Redirected stdin/stdout must stay plain: no ANSI, no popups, no
        // cursor movement. The persistent screen drives HandleKey instead.
        std::cout << Terminal::StripAnsi(prompt) << std::flush;
        if (!std::getline(std::cin, outLine)) return false;
        if (!outLine.empty() && outLine.back() == '\r') outLine.pop_back();
        if (!outLine.empty()) AddHistory(outLine);
        return true;
    }

} // namespace Dracula
