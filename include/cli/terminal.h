#pragma once

#include <string>
#include <cstdint>
#include <iostream>

namespace Dracula {

    // Semantic colour roles. Commands must never emit raw ANSI colour
    // literals; every colour in Dracula is requested through a role so the
    // palette stays consistent and --no-color works everywhere.
    enum class ColorRole {
        Title,       // Dracula wordmark - dark crimson
        Primary,     // Blood red - primary accent
        Secondary,   // Muted violet - secondary accent
        Accent,      // Deep violet - section labels
        Technical,   // Cool cyan - engines, versions, identifiers
        Text,        // Soft white - normal body text
        Muted,       // Gray - secondary information
        Success,     // Restrained green
        Warning,     // Amber
        Error,       // Red
        Info,        // Steel blue
        Selection,   // High contrast selection background
        Border,      // Dark gray frame border
        Command,     // Bold command text
        Description, // Soft description text
        Bold,        // Bold modifier
        Dim,         // Dim modifier
        Reset        // Reset styling
    };

    class Terminal {
    public:
        // Global initialization & cleanup
        static void Initialize();
        static void Restore();

        // Capability queries & overrides
        static bool IsInteractive();
        static bool SupportsColor();
        static bool SupportsUnicode();
        static void SetColorEnabled(bool enabled);
        static void SetUnicodeEnabled(bool enabled);

        // Terminal dimensions
        static int GetWidth();
        static int GetHeight();

        // Width available to command output. In the persistent interactive
        // layout this is the output region's width, not the console width, so
        // no command ever draws behind the frame. 0 restores automatic sizing.
        static void SetContentWidth(int width);
        static int ContentWidth();

        // Semantic color formatter
        static std::string Color(ColorRole role);
        static const char* ColorRaw(ColorRole role);

        // Utility: Strip ANSI escape sequences
        static std::string StripAnsi(const std::string& text);
        static size_t VisibleLength(const std::string& text);

        // Glyphs with safe ASCII fallback
        static std::string PromptGlyph();
        static std::string DraculaPrompt();
        static std::string Bullet();
        static std::string Pointer();
        static std::string Checkmark();
        static std::string Crossmark();
        static std::string WarningIcon();

        // Box characters
        static std::string BoxH();
        static std::string BoxV();
        static std::string BoxTL();
        static std::string BoxTR();
        static std::string BoxBL();
        static std::string BoxBR();
        static std::string BoxTeeL();
        static std::string BoxTeeR();

        // Frame rendering helper
        static std::string DrawHorizontalLine(int width);

    private:
        static bool s_initialized;
        static bool s_colorEnabled;
        static bool s_unicodeEnabled;
        static bool s_isInteractive;
#ifdef _WIN32
        static unsigned long s_originalOutMode;
        static unsigned long s_originalInMode;
        static unsigned int s_originalOutputCP;
        static unsigned int s_originalInputCP;
#endif
    };

    // ─── Input events ───────────────────────────────────────────────────────
    //
    // The interactive shell consumes normalized events rather than raw console
    // codes. Reading through the console input queue (instead of _getwch) is
    // what makes WINDOW_BUFFER_SIZE_EVENT - terminal resize - observable.
    //
    enum class Key {
        None, Char, Enter, Tab, Escape, Backspace, Delete,
        Left, Right, Up, Down, Home, End, PageUp, PageDown,
        CtrlA, CtrlC, CtrlD, CtrlE, CtrlK, CtrlL, CtrlU,
        CtrlHome, CtrlEnd,
        WheelUp, WheelDown,
        ToggleSelection,   // F2: hand the mouse back to the terminal
        Resize
    };

    struct InputEvent {
        Key key = Key::None;
        std::string utf8;   // populated for Key::Char
    };

    // ─── Centralized redraw primitives ──────────────────────────────────────
    //
    // All cursor movement and line erasing goes through Console. No source file
    // outside this class may emit raw "\033[A" / "\033[K" style sequences: that
    // is how the previous implementation accumulated inconsistent redraw logic
    // and left the cursor in a broken state.
    //
    class Console {
    public:
        static void HideCursor();
        static void ShowCursor();

        static void CarriageReturn();
        static void ClearLine();          // erase the entire current line
        static void ClearToEndOfScreen();
        static void ClearScreen();        // clear + home

        static void MoveUp(int lines);
        static void MoveDown(int lines);
        static void MoveRight(int columns);
        static void MoveToColumn(int zeroBasedColumn);

        // Position the cursor absolutely (0-based row/column).
        static void MoveTo(int row, int column);

        // Alternate screen buffer. Dracula's persistent interactive layout owns
        // its own screen so it never contaminates the user's scrollback, and
        // the original buffer is restored untouched on exit.
        static bool EnterAlternateScreen();
        static void LeaveAlternateScreen();
        static bool InAlternateScreen();

        // Blocking read of one normalized input event. Returns false on EOF or
        // console error.
        static bool ReadInput(InputEvent& out);

        // Configure the console input queue for the interactive screen: mouse
        // wheel and resize notifications on, quick-edit selection and VT input
        // translation off (both of those corrupt the key stream).
        static void EnableInteractiveInput(bool enable);

        // Selection mode. ENABLE_MOUSE_INPUT and ENABLE_QUICK_EDIT_MODE are
        // mutually exclusive on Windows: an application that consumes mouse
        // events takes click-drag selection away from the console. This hands the
        // mouse back to the terminal so the user can select and copy, at the cost
        // of wheel scrolling until it is switched off again. Key events keep
        // arriving either way, so the toggle key still works.
        static void SetSelectionMode(bool enable);
        static bool InSelectionMode();

        // Reset colours, show the cursor and flush. Safe to call repeatedly.
        static void ResetStyle();
    };

    // RAII guard for terminal setup
    class TerminalGuard {
    public:
        TerminalGuard() { Terminal::Initialize(); }
        ~TerminalGuard() {
            Console::LeaveAlternateScreen();
            Console::ResetStyle();
            Terminal::Restore();
        }
    };

    // RAII guard that hides the cursor for the duration of a redraw and always
    // restores it, including when an exception unwinds through the caller.
    class CursorGuard {
    public:
        CursorGuard() { Console::HideCursor(); }
        ~CursorGuard() { Console::ShowCursor(); }
        CursorGuard(const CursorGuard&) = delete;
        CursorGuard& operator=(const CursorGuard&) = delete;
    };

} // namespace Dracula
