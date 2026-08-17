#pragma once

#include "imgui.h"
#include <string>

namespace Sandbox::GUI {

    class GlassTheme {
    public:
        // Load custom bundled fonts
        static void LoadFonts(const std::string& fontDir = "assets/fonts");

        // Apply modern frosted glassmorphism dark theme
        static void ApplyTheme();

        // Custom Font pointers
        static inline ImFont* FontTitle = nullptr;
        static inline ImFont* FontMain  = nullptr;
        static inline ImFont* FontMono  = nullptr;
        static inline ImFont* FontSmall = nullptr;

        // Custom Color Palette
        static constexpr ImVec4 NeonCyan       = ImVec4(0.00f, 0.90f, 1.00f, 1.00f);
        static constexpr ImVec4 NeonBlue       = ImVec4(0.18f, 0.55f, 1.00f, 1.00f);
        static constexpr ImVec4 EmeraldGreen   = ImVec4(0.12f, 0.90f, 0.55f, 1.00f);
        static constexpr ImVec4 AmberYellow    = ImVec4(1.00f, 0.78f, 0.15f, 1.00f);
        static constexpr ImVec4 CoralRed       = ImVec4(1.00f, 0.28f, 0.38f, 1.00f);
        static constexpr ImVec4 PurpleViolet   = ImVec4(0.70f, 0.38f, 1.00f, 1.00f);
        static constexpr ImVec4 GlassBg        = ImVec4(0.07f, 0.08f, 0.11f, 0.85f);
        static constexpr ImVec4 GlassCardBg    = ImVec4(0.11f, 0.13f, 0.18f, 0.65f);
        static constexpr ImVec4 GlassBorder    = ImVec4(0.24f, 0.30f, 0.44f, 0.45f);
        static constexpr ImVec4 TextMuted      = ImVec4(0.55f, 0.62f, 0.75f, 1.00f);

        // Helper UI components
        static void RenderBadge(const char* label, const ImVec4& color);
        static void RenderMetricCard(const char* title, const char* value, const char* subtitle, const ImVec4& accentColor, float width = 160.0f);
        static bool NeonButton(const char* label, const ImVec4& color, const ImVec2& size = ImVec2(0, 0));
        static void BeginGlassChild(const char* id, const ImVec2& size = ImVec2(0, 0), bool border = true);
        static void EndGlassChild();
    };

} // namespace Sandbox::GUI
