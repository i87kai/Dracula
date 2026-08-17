#include "cli/terminal.h"

#include <cstdlib>
#include <regex>
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
            // Enable Virtual Terminal input if supported
            SetConsoleMode(hIn, inMode | ENABLE_VIRTUAL_TERMINAL_INPUT);
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

    int Terminal::GetWidth() {
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

        switch (role) {
            case ColorRole::Primary:     return "\033[1;91m";             // Bold Crimson / Red
            case ColorRole::Secondary:   return "\033[1;36m";             // Bold Cyan / Aqua
            case ColorRole::Accent:      return "\033[1;35m";             // Bold Violet / Purple
            case ColorRole::Success:     return "\033[1;32m";             // Bold Green
            case ColorRole::Warning:     return "\033[1;33m";             // Bold Amber / Yellow
            case ColorRole::Error:       return "\033[1;91m";             // Bright Red
            case ColorRole::Muted:       return "\033[90m";               // Dim Gray
            case ColorRole::Selection:   return "\033[7m";                // Inverted / Highlight
            case ColorRole::Border:      return "\033[90m";               // Frame Border
            case ColorRole::Command:     return "\033[1;97m";             // Bold Bright White
            case ColorRole::Description: return "\033[37m";               // Normal Gray
            case ColorRole::Bold:        return "\033[1m";                // Bold
            case ColorRole::Dim:         return "\033[2m";                // Dim
            case ColorRole::Reset:       return "\033[0m";                // Reset
            default:                     return "";
        }
    }

    std::string Terminal::Color(ColorRole role) {
        return ColorRaw(role);
    }

    std::string Terminal::StripAnsi(const std::string& text) {
        static const std::regex ansiRegex("\033\\[[0-9;?]*[a-zA-Z]");
        return std::regex_replace(text, ansiRegex, "");
    }

    size_t Terminal::VisibleLength(const std::string& text) {
        std::string plain = StripAnsi(text);
        size_t count = 0;
        for (size_t i = 0; i < plain.size();) {
            unsigned char c = static_cast<unsigned char>(plain[i]);
            if ((c & 0x80) == 0) {
                i += 1;
            } else if ((c & 0xE0) == 0xC0) {
                i += 2;
            } else if ((c & 0xF0) == 0xE0) {
                i += 3;
            } else if ((c & 0xF8) == 0xF0) {
                i += 4;
            } else {
                i += 1;
            }
            count++;
        }
        return count;
    }

    std::string Terminal::PromptGlyph() {
        return s_unicodeEnabled ? "❯" : ">";
    }

    std::string Terminal::DraculaPrompt() {
        std::string p;
        p += Color(ColorRole::Primary);
        p += "dracula";
        p += Color(ColorRole::Reset);
        p += " ";
        p += Color(ColorRole::Secondary);
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
        return s_unicodeEnabled ? "✓" : "[+]";
    }

    std::string Terminal::Crossmark() {
        return s_unicodeEnabled ? "✗" : "[-]";
    }

    std::string Terminal::WarningIcon() {
        return s_unicodeEnabled ? "⚠" : "[!]";
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
        std::string line;
        std::string h = BoxH();
        for (int i = 0; i < width; ++i) {
            line += h;
        }
        return line;
    }

} // namespace Dracula
