#pragma once

#include <string>
#include <cstdint>
#include <iostream>

namespace Dracula {

    enum class ColorRole {
        Primary,     // Crimson / Dracula Red
        Secondary,   // Cool Cyan / Aqua
        Accent,      // Muted Purple / Violet
        Success,     // Emerald Green
        Warning,     // Amber / Yellow
        Error,       // Bright Red
        Muted,       // Cool Gray / Slate
        Selection,   // Highlight / Inverted background
        Border,      // Frame border
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

    // RAII guard for terminal setup
    class TerminalGuard {
    public:
        TerminalGuard() { Terminal::Initialize(); }
        ~TerminalGuard() { Terminal::Restore(); }
    };

} // namespace Dracula
