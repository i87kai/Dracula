#pragma once

#include "../common/types.h"
#include <string>

namespace Sandbox {

    class ConsoleUI {
    public:
        // Initialize terminal colors (Virtual Terminal Processing on Windows)
        static void InitializeConsole();

        // Print modern banner
        static void PrintBanner();

        // Print formatted live event to console with color badges
        static void RenderEvent(const TraceEvent& event);

        // Prompt user interactively for options
        static void PromptUserConfiguration(TraceOptions& options, VMConfig& vmConfig, std::string& targetExe);

        // ANSI Color codes
        static constexpr const char* COLOR_RESET       = "\033[0m";
        static constexpr const char* COLOR_BOLD        = "\033[1m";
        static constexpr const char* COLOR_RED         = "\033[31m";
        static constexpr const char* COLOR_GREEN       = "\033[32m";
        static constexpr const char* COLOR_YELLOW      = "\033[33m";
        static constexpr const char* COLOR_BLUE        = "\033[34m";
        static constexpr const char* COLOR_MAGENTA     = "\033[35m";
        static constexpr const char* COLOR_CYAN        = "\033[36m";
        static constexpr const char* COLOR_WHITE       = "\033[37m";
        static constexpr const char* COLOR_BRIGHT_BLUE = "\033[94m";
        static constexpr const char* COLOR_BRIGHT_CYAN = "\033[96m";
    };

} // namespace Sandbox
