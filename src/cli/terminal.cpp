#include "cli/terminal.h"
#include "cli/text_layout.h"

#include <cstdlib>
#include <algorithm>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/ioctl.h>
#endif

namespace Dracula {

    bool Terminal::s_initialized = false;
    bool Terminal::s_colorEnabled = true;
    bool Terminal::s_unicodeEnabled = true;
    bool Terminal::s_isInteractive = true;

#ifdef _WIN32
    unsigned long Terminal::s_originalOutMode = 0;
    unsigned long Terminal::s_originalInMode = 0;
    unsigned int Terminal::s_originalOutputCP = 0;
    unsigned int Terminal::s_originalInputCP = 0;
#endif

    void Terminal::Initialize() {
        if (s_initialized) return;

        // 1. Check NO_COLOR environment variable (https://no-color.org)
        const char* noColorEnv = std::getenv("NO_COLOR");
        if (noColorEnv != nullptr && noColorEnv[0] != '\0') {
            s_colorEnabled = false;
        }

        // 2. Check interactive console
#ifdef _WIN32
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        HANDLE hIn  = GetStdHandle(STD_INPUT_HANDLE);

        s_originalOutputCP = GetConsoleOutputCP();
        s_originalInputCP  = GetConsoleCP();

        DWORD outMode = 0;
        if (hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &outMode)) {
            s_originalOutMode = outMode;
            s_isInteractive = true;

            // Enable ANSI / Virtual Terminal processing
            DWORD targetMode = outMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT;
            if (!SetConsoleMode(hOut, targetMode)) {
                // If VT processing failed, disable color if console is limited
                s_colorEnabled = false;
            }
        } else {
            // Not a console (redirected to file or pipe)
            s_isInteractive = false;
            s_colorEnabled = false;
            s_unicodeEnabled = false;
        }

        DWORD inMode = 0;
        if (hIn != INVALID_HANDLE_VALUE && GetConsoleMode(hIn, &inMode)) {
            s_originalInMode = inMode;
            // The line editor reads keys through _getwch(), which expects the
            // classic 0x00 / 0xE0 extended-key protocol. Leaving
            // ENABLE_VIRTUAL_TERMINAL_INPUT on makes the console deliver VT
            // escape sequences (including focus-in/out reports) instead, which
            // arrive as phantom ESC keystrokes.
            SetConsoleMode(hIn, inMode & ~static_cast<DWORD>(ENABLE_VIRTUAL_TERMINAL_INPUT));
        }

        // Set UTF-8 code pages
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);

#else
        s_isInteractive = isatty(fileno(stdout));
        if (!s_isInteractive) {
            s_colorEnabled = false;
            s_unicodeEnabled = false;
        }
#endif

        s_initialized = true;
    }

    void Terminal::Restore() {
        if (!s_initialized) return;

#ifdef _WIN32
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE && s_originalOutMode != 0) {
            SetConsoleMode(hOut, s_originalOutMode);
        }
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        if (hIn != INVALID_HANDLE_VALUE && s_originalInMode != 0) {
            SetConsoleMode(hIn, s_originalInMode);
        }
        if (s_originalOutputCP != 0) {
            SetConsoleOutputCP(s_originalOutputCP);
        }
        if (s_originalInputCP != 0) {
            SetConsoleCP(s_originalInputCP);
        }
#endif
        s_initialized = false;
    }

    bool Terminal::IsInteractive() {
        if (!s_initialized) Initialize();
        return s_isInteractive;
    }

    bool Terminal::SupportsColor() {
        if (!s_initialized) Initialize();
        return s_colorEnabled;
    }

    bool Terminal::SupportsUnicode() {
        if (!s_initialized) Initialize();
        return s_unicodeEnabled;
    }

    void Terminal::SetColorEnabled(bool enabled) {
        s_colorEnabled = enabled;
    }

    void Terminal::SetUnicodeEnabled(bool enabled) {
        s_unicodeEnabled = enabled;
    }

    static int s_contentWidthOverride = 0;

    void Terminal::SetContentWidth(int width) {
        s_contentWidthOverride = width > 0 ? width : 0;
    }

    int Terminal::ContentWidth() {
        if (s_contentWidthOverride > 0) return s_contentWidthOverride;
        int w = GetWidth();
        if (w < 20) w = 20;
        return std::min(w - 2, 118);
    }

    int Terminal::GetWidth() {
        // Redirected output has no window to measure. Reporting a generous
        // fixed width keeps piped/redirected reports from being truncated to an
        // arbitrary 80 columns.
        if (s_initialized && !s_isInteractive) return 120;
#ifdef _WIN32
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            CONSOLE_SCREEN_BUFFER_INFO csbi;
            if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
                int width = csbi.srWindow.Right - csbi.srWindow.Left + 1;
                return width > 0 ? width : 80;
            }
        }
        return 80;
#else
        struct winsize ws;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
            return ws.ws_col;
        }
        return 80;
#endif
    }

    int Terminal::GetHeight() {
#ifdef _WIN32
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            CONSOLE_SCREEN_BUFFER_INFO csbi;
            if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
                int height = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
                return height > 0 ? height : 24;
            }
        }
        return 24;
#else
        struct winsize ws;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0) {
            return ws.ws_row;
        }
        return 24;
#endif
    }

    const char* Terminal::ColorRaw(ColorRole role) {
        if (!s_colorEnabled) return "";

        // The Dracula palette. Deliberately darker and more restrained than the
        // basic 16-colour ANSI set: crimson for identity, violet for structure,
        // cyan for technical detail, gray for everything secondary.
        switch (role) {
            case ColorRole::Title:       return "\033[1;38;5;160m";       // Dark crimson, bold
            case ColorRole::Primary:     return "\033[38;5;167m";         // Blood red
            case ColorRole::Secondary:   return "\033[38;5;141m";         // Muted violet
            case ColorRole::Accent:      return "\033[1;38;5;98m";        // Deep violet label
            case ColorRole::Technical:   return "\033[38;5;80m";          // Cool cyan
            case ColorRole::Text:        return "\033[38;5;252m";         // Soft white
            case ColorRole::Muted:       return "\033[38;5;245m";         // Gray
            case ColorRole::Success:     return "\033[38;5;71m";          // Restrained green
            case ColorRole::Warning:     return "\033[38;5;179m";         // Amber
            case ColorRole::Error:       return "\033[1;38;5;160m";       // Red
            case ColorRole::Info:        return "\033[38;5;110m";         // Steel blue
            case ColorRole::Selection:   return "\033[48;5;53;38;5;231m"; // Violet bg, white fg
            case ColorRole::Border:      return "\033[38;5;238m";         // Dark gray frame
            case ColorRole::Command:     return "\033[1;38;5;255m";       // Bright white
            case ColorRole::Description: return "\033[38;5;249m";         // Soft gray text
            case ColorRole::Bold:        return "\033[1m";                // Bold
            case ColorRole::Dim:         return "\033[2m";                // Dim
            case ColorRole::Reset:       return "\033[0m";                // Reset
            default:                     return "";
        }
    }

    std::string Terminal::Color(ColorRole role) {
        return ColorRaw(role);
    }

    // Measurement lives in the layout primitives; Terminal simply forwards so
    // that there is exactly one implementation of "how wide is this text".
    std::string Terminal::StripAnsi(const std::string& text) {
        return Text::StripAnsi(text);
    }

    size_t Terminal::VisibleLength(const std::string& text) {
        return Text::VisibleWidth(text);
    }

    std::string Terminal::PromptGlyph() {
        return s_unicodeEnabled ? "❯" : ">";
    }

    std::string Terminal::DraculaPrompt() {
        // Always terminated by a Reset so the rest of the console can never
        // inherit the prompt's styling.
        std::string p;
        p += Color(ColorRole::Title);
        p += "dracula";
        p += Color(ColorRole::Reset);
        p += " ";
        p += Color(ColorRole::Primary);
        p += PromptGlyph();
        p += Color(ColorRole::Reset);
        p += " ";
        return p;
    }

    std::string Terminal::Bullet() {
        return s_unicodeEnabled ? "•" : "*";
    }

    std::string Terminal::Pointer() {
        return ">";
    }

    std::string Terminal::Checkmark() {
        return s_unicodeEnabled ? "✓" : "+";
    }

    std::string Terminal::Crossmark() {
        return s_unicodeEnabled ? "✗" : "x";
    }

    std::string Terminal::WarningIcon() {
        return s_unicodeEnabled ? "⚠" : "!";
    }

    bool Terminal::UnicodeEnabled() {
        return s_unicodeEnabled;
    }

    std::string Terminal::BoxH() {
        return s_unicodeEnabled ? "─" : "-";
    }

    std::string Terminal::BoxV() {
        return s_unicodeEnabled ? "│" : "|";
    }

    std::string Terminal::BoxTL() {
        return s_unicodeEnabled ? "┌" : "+";
    }

    std::string Terminal::BoxTR() {
        return s_unicodeEnabled ? "┐" : "+";
    }

    std::string Terminal::BoxBL() {
        return s_unicodeEnabled ? "└" : "+";
    }

    std::string Terminal::BoxBR() {
        return s_unicodeEnabled ? "┘" : "+";
    }

    std::string Terminal::BoxTeeL() {
        return s_unicodeEnabled ? "├" : "+";
    }

    std::string Terminal::BoxTeeR() {
        return s_unicodeEnabled ? "┤" : "+";
    }

    std::string Terminal::DrawHorizontalLine(int width) {
        if (width <= 0) return "";
        return Text::Repeat(BoxH(), static_cast<size_t>(width));
    }

    // ─── Console redraw primitives ──────────────────────────────────────────

    void Console::HideCursor() {
        if (!Terminal::IsInteractive()) return;
        std::cout << "\033[?25l" << std::flush;
    }

    void Console::ShowCursor() {
        if (!Terminal::IsInteractive()) return;
        std::cout << "\033[?25h" << std::flush;
    }

    void Console::CarriageReturn() {
        std::cout << "\r";
    }

    void Console::ClearLine() {
        if (!Terminal::IsInteractive()) return;
        std::cout << "\033[2K";
    }

    void Console::ClearToEndOfScreen() {
        if (!Terminal::IsInteractive()) return;
        std::cout << "\033[J";
    }

    void Console::ClearScreen() {
        if (!Terminal::IsInteractive()) {
            std::cout << "\n";
            return;
        }
        std::cout << "\033[2J\033[3J\033[H" << std::flush;
    }

    void Console::MoveUp(int lines) {
        if (lines <= 0 || !Terminal::IsInteractive()) return;
        std::cout << "\033[" << lines << "A";
    }

    void Console::MoveDown(int lines) {
        if (lines <= 0 || !Terminal::IsInteractive()) return;
        std::cout << "\033[" << lines << "B";
    }

    void Console::MoveRight(int columns) {
        if (columns <= 0 || !Terminal::IsInteractive()) return;
        std::cout << "\033[" << columns << "C";
    }

    void Console::MoveToColumn(int zeroBasedColumn) {
        if (!Terminal::IsInteractive()) return;
        if (zeroBasedColumn < 0) zeroBasedColumn = 0;
        // CHA is 1-based.
        std::cout << "\033[" << (zeroBasedColumn + 1) << "G";
    }

    void Console::MoveTo(int row, int column) {
        if (!Terminal::IsInteractive()) return;
        if (row < 0) row = 0;
        if (column < 0) column = 0;
        std::cout << "\033[" << (row + 1) << ";" << (column + 1) << "H";
    }

    void Console::ResetStyle() {
        if (!Terminal::IsInteractive()) return;
        std::cout << "\033[0m\033[?25h" << std::flush;
    }

    // ─── Alternate screen ───────────────────────────────────────────────────

    static bool s_inAlternateScreen = false;

    bool Console::EnterAlternateScreen() {
        if (s_inAlternateScreen) return true;
        if (!Terminal::IsInteractive() || !Terminal::SupportsColor()) return false;
        // 1049 saves the cursor, switches buffer and clears it in one sequence.
        std::cout << "\033[?1049h\033[H\033[2J" << std::flush;
        s_inAlternateScreen = true;
        return true;
    }

    void Console::LeaveAlternateScreen() {
        if (!s_inAlternateScreen) return;
        std::cout << "\033[0m\033[?25h\033[?1049l" << std::flush;
        s_inAlternateScreen = false;
    }

    bool Console::InAlternateScreen() {
        return s_inAlternateScreen;
    }

    // ─── Normalized input ───────────────────────────────────────────────────

#ifdef _WIN32
    static bool MapKeyEvent(const KEY_EVENT_RECORD& key, InputEvent& out) {
        if (!key.bKeyDown) return false;

        const bool ctrl = (key.dwControlKeyState &
                           (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) != 0;

        switch (key.wVirtualKeyCode) {
            case VK_RETURN: out.key = Key::Enter;     return true;
            case VK_TAB:    out.key = Key::Tab;       return true;
            case VK_ESCAPE: out.key = Key::Escape;    return true;
            case VK_BACK:   out.key = Key::Backspace; return true;
            case VK_DELETE: out.key = Key::Delete;    return true;
            case VK_LEFT:   out.key = Key::Left;      return true;
            case VK_RIGHT:  out.key = Key::Right;     return true;
            case VK_UP:     out.key = Key::Up;        return true;
            case VK_DOWN:   out.key = Key::Down;      return true;
            case VK_HOME:   out.key = ctrl ? Key::CtrlHome : Key::Home; return true;
            case VK_END:    out.key = ctrl ? Key::CtrlEnd  : Key::End;  return true;
            case VK_PRIOR:  out.key = Key::PageUp;    return true;
            case VK_NEXT:   out.key = Key::PageDown;  return true;
            case VK_SHIFT:
            case VK_CONTROL:
            case VK_MENU:
            case VK_CAPITAL:
            case VK_NUMLOCK:
            case VK_SCROLL:
                return false;
            default:
                break;
        }

        wchar_t ch = key.uChar.UnicodeChar;
        if (ch == 0) return false;

        if (ch == L'\r' || ch == L'\n') {
            out.key = Key::Enter;
            return true;
        }
        if (ch == L'\t') {
            out.key = Key::Tab;
            return true;
        }
        if (ch == L'\b' || ch == 127) {
            out.key = Key::Backspace;
            return true;
        }
        if (ch == 27) {
            out.key = Key::Escape;
            return true;
        }

        if (ctrl && ch < 32) {
            switch (ch) {
                case 1:  out.key = Key::CtrlA; return true;
                case 3:  out.key = Key::CtrlC; return true;
                case 4:  out.key = Key::CtrlD; return true;
                case 5:  out.key = Key::CtrlE; return true;
                case 11: out.key = Key::CtrlK; return true;
                case 12: out.key = Key::CtrlL; return true;
                case 21: out.key = Key::CtrlU; return true;
                default: return false;
            }
        }
        if (ch < 32) return false;

        char utf8[8] = {0};
        int bytes = WideCharToMultiByte(CP_UTF8, 0, &ch, 1, utf8, sizeof(utf8), nullptr, nullptr);
        if (bytes <= 0) return false;

        out.key = Key::Char;
        out.utf8.assign(utf8, static_cast<size_t>(bytes));
        return true;
    }
#endif

    void Console::EnableInteractiveInput(bool enable) {
#ifdef _WIN32
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        if (hIn == INVALID_HANDLE_VALUE) return;

        DWORD mode = 0;
        if (!GetConsoleMode(hIn, &mode)) return;

        if (enable) {
            // ENABLE_EXTENDED_FLAGS is required for ENABLE_QUICK_EDIT_MODE to be
            // honoured at all; quick-edit must be off or a wheel/drag turns into
            // a text selection instead of an input event.
            mode |= ENABLE_EXTENDED_FLAGS | ENABLE_MOUSE_INPUT | ENABLE_WINDOW_INPUT;
            mode &= ~static_cast<DWORD>(ENABLE_QUICK_EDIT_MODE);
            // VT input would deliver escape sequences (and focus reports) into
            // the key stream; the event reader wants raw key records.
            mode &= ~static_cast<DWORD>(ENABLE_VIRTUAL_TERMINAL_INPUT);
            mode &= ~static_cast<DWORD>(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
        } else {
            mode &= ~static_cast<DWORD>(ENABLE_MOUSE_INPUT | ENABLE_WINDOW_INPUT);
            mode |= ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT
                  | ENABLE_QUICK_EDIT_MODE;
        }
        SetConsoleMode(hIn, mode);
#else
        (void)enable;
#endif
    }

    bool Console::CopyToClipboard(const std::string& text) {
#ifdef _WIN32
        if (!OpenClipboard(nullptr)) return false;

        bool ok = false;
        if (EmptyClipboard()) {
            // Convert to UTF-16 so non-ASCII output copies correctly.
            int wideLen = MultiByteToWideChar(CP_UTF8, 0, text.c_str(),
                                              static_cast<int>(text.size()), nullptr, 0);
            HGLOBAL handle = GlobalAlloc(GMEM_MOVEABLE,
                                         (static_cast<size_t>(wideLen) + 1) * sizeof(wchar_t));
            if (handle) {
                auto* dest = static_cast<wchar_t*>(GlobalLock(handle));
                if (dest) {
                    if (wideLen > 0) {
                        MultiByteToWideChar(CP_UTF8, 0, text.c_str(),
                                            static_cast<int>(text.size()), dest, wideLen);
                    }
                    dest[wideLen] = L'\0';
                    GlobalUnlock(handle);
                    ok = SetClipboardData(CF_UNICODETEXT, handle) != nullptr;
                }
                // On success the clipboard owns the handle; on failure we do.
                if (!ok) GlobalFree(handle);
            }
        }
        CloseClipboard();
        return ok;
#else
        (void)text;
        return false;
#endif
    }

    bool Console::ReadInput(InputEvent& out) {
#ifdef _WIN32
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        if (hIn == INVALID_HANDLE_VALUE) return false;

        INPUT_RECORD record{};
        DWORD read = 0;
        while (true) {
            if (!ReadConsoleInputW(hIn, &record, 1, &read) || read == 0) {
                return false;
            }
            if (record.EventType == WINDOW_BUFFER_SIZE_EVENT) {
                out = InputEvent{};
                out.key = Key::Resize;
                return true;
            }
            if (record.EventType == KEY_EVENT) {
                out = InputEvent{};
                if (MapKeyEvent(record.Event.KeyEvent, out)) return true;
                continue;
            }
            if (record.EventType == MOUSE_EVENT) {
                const auto& mouse = record.Event.MouseEvent;

                if (mouse.dwEventFlags == MOUSE_WHEELED) {
                    // The high word of dwButtonState is a signed wheel delta;
                    // positive means the wheel rotated away from the user.
                    const short delta = static_cast<short>(HIWORD(mouse.dwButtonState));
                    out = InputEvent{};
                    out.key = delta > 0 ? Key::WheelUp : Key::WheelDown;
                    return true;
                }

                // Left-button press / drag / release drive Dracula's own text
                // selection. Tracking it here (rather than delegating to the
                // console's quick-edit mode) is what lets selection and wheel
                // scrolling coexist without a mode key.
                const bool leftDown = (mouse.dwButtonState & FROM_LEFT_1ST_BUTTON_PRESSED) != 0;

                if (mouse.dwEventFlags == 0 || mouse.dwEventFlags == MOUSE_MOVED) {
                    out = InputEvent{};
                    out.mouseRow = mouse.dwMousePosition.Y;
                    out.mouseColumn = mouse.dwMousePosition.X;

                    if (mouse.dwEventFlags == 0) {
                        // A button state change.
                        out.key = leftDown ? Key::MousePress : Key::MouseRelease;
                        return true;
                    }
                    if (leftDown) {
                        out.key = Key::MouseDrag;
                        return true;
                    }
                }
                continue;
            }
            // Focus and menu events are intentionally ignored.
        }
#else
        (void)out;
        return false;
#endif
    }

} // namespace Dracula
