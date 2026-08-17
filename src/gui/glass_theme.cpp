#include "gui/glass_theme.h"
#include "imgui_internal.h"
#include <filesystem>
#include <iostream>
#include <vector>

namespace Sandbox::GUI {

    void GlassTheme::LoadFonts(const std::string& fontDir) {
        ImGuiIO& io = ImGui::GetIO();
        io.Fonts->Clear();

        std::vector<std::string> searchPaths = {
            fontDir,
            "assets/fonts",
            "../assets/fonts",
            "../../assets/fonts"
        };

        std::string mainFontPath;
        std::string monoFontPath;

        for (const auto& path : searchPaths) {
            std::string mainCandidate = path + "/Roboto-Medium.ttf";
            std::string monoCandidate = path + "/JetBrainsMono-Bold.ttf";

            if (std::filesystem::exists(mainCandidate)) {
                mainFontPath = mainCandidate;
                monoFontPath = monoCandidate;
                break;
            }
        }

        if (!mainFontPath.empty() && std::filesystem::exists(mainFontPath)) {
            FontMain  = io.Fonts->AddFontFromFileTTF(mainFontPath.c_str(), 16.5f);
            FontTitle = io.Fonts->AddFontFromFileTTF(mainFontPath.c_str(), 23.0f);
            FontSmall = io.Fonts->AddFontFromFileTTF(mainFontPath.c_str(), 13.0f);
        } else {
            FontMain  = io.Fonts->AddFontDefault();
            FontTitle = FontMain;
            FontSmall = FontMain;
        }

        if (!monoFontPath.empty() && std::filesystem::exists(monoFontPath)) {
            FontMono = io.Fonts->AddFontFromFileTTF(monoFontPath.c_str(), 14.5f);
        } else {
            FontMono = FontMain;
        }
    }

    void GlassTheme::ApplyTheme() {
        ImGuiStyle& style = ImGui::GetStyle();

        // Roundings
        style.WindowRounding    = 10.0f;
        style.ChildRounding     = 8.0f;
        style.FrameRounding     = 6.0f;
        style.PopupRounding     = 8.0f;
        style.ScrollbarRounding = 6.0f;
        style.GrabRounding      = 6.0f;
        style.TabRounding       = 6.0f;

        // Borders & Spacing
        style.WindowBorderSize = 1.0f;
        style.ChildBorderSize  = 1.0f;
        style.PopupBorderSize  = 1.0f;
        style.FrameBorderSize  = 1.0f;
        style.TabBorderSize    = 0.0f;

        style.WindowPadding    = ImVec2(16.0f, 16.0f);
        style.FramePadding     = ImVec2(10.0f, 6.0f);
        style.ItemSpacing      = ImVec2(10.0f, 8.0f);
        style.ItemInnerSpacing = ImVec2(8.0f, 6.0f);
        style.IndentSpacing    = 20.0f;
        style.ScrollbarSize    = 12.0f;

        // Custom Glass Color Palette
        ImVec4* colors = style.Colors;
        colors[ImGuiCol_Text]                  = ImVec4(0.95f, 0.96f, 0.98f, 1.00f);
        colors[ImGuiCol_TextDisabled]          = TextMuted;
        colors[ImGuiCol_WindowBg]              = ImVec4(0.06f, 0.07f, 0.10f, 0.96f);
        colors[ImGuiCol_ChildBg]               = GlassCardBg;
        colors[ImGuiCol_PopupBg]               = ImVec4(0.08f, 0.10f, 0.14f, 0.98f);
        colors[ImGuiCol_Border]                = GlassBorder;
        colors[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
        colors[ImGuiCol_FrameBg]               = ImVec4(0.12f, 0.15f, 0.22f, 0.60f);
        colors[ImGuiCol_FrameBgHovered]        = ImVec4(0.16f, 0.20f, 0.30f, 0.80f);
        colors[ImGuiCol_FrameBgActive]         = ImVec4(0.20f, 0.26f, 0.40f, 0.90f);
        colors[ImGuiCol_TitleBg]               = ImVec4(0.05f, 0.06f, 0.09f, 1.00f);
        colors[ImGuiCol_TitleBgActive]         = ImVec4(0.08f, 0.10f, 0.15f, 1.00f);
        colors[ImGuiCol_TitleBgCollapsed]      = ImVec4(0.04f, 0.05f, 0.07f, 0.75f);
        colors[ImGuiCol_MenuBarBg]             = ImVec4(0.08f, 0.10f, 0.14f, 0.90f);
        colors[ImGuiCol_ScrollbarBg]           = ImVec4(0.05f, 0.06f, 0.09f, 0.50f);
        colors[ImGuiCol_ScrollbarGrab]         = ImVec4(0.25f, 0.32f, 0.45f, 0.60f);
        colors[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.35f, 0.45f, 0.65f, 0.80f);
        colors[ImGuiCol_ScrollbarGrabActive]   = NeonCyan;
        colors[ImGuiCol_CheckMark]             = NeonCyan;
        colors[ImGuiCol_SliderGrab]            = NeonCyan;
        colors[ImGuiCol_SliderGrabActive]      = ImVec4(0.30f, 0.95f, 1.00f, 1.00f);
        colors[ImGuiCol_Button]                = ImVec4(0.14f, 0.18f, 0.26f, 0.75f);
        colors[ImGuiCol_ButtonHovered]         = ImVec4(0.20f, 0.28f, 0.42f, 0.90f);
        colors[ImGuiCol_ButtonActive]          = ImVec4(0.00f, 0.70f, 0.85f, 0.80f);
        colors[ImGuiCol_Header]                = ImVec4(0.15f, 0.20f, 0.30f, 0.70f);
        colors[ImGuiCol_HeaderHovered]         = ImVec4(0.22f, 0.30f, 0.45f, 0.85f);
        colors[ImGuiCol_HeaderActive]          = ImVec4(0.00f, 0.65f, 0.80f, 0.90f);
        colors[ImGuiCol_Separator]             = GlassBorder;
        colors[ImGuiCol_SeparatorHovered]      = NeonCyan;
        colors[ImGuiCol_SeparatorActive]       = NeonCyan;
        colors[ImGuiCol_ResizeGrip]            = ImVec4(0.20f, 0.25f, 0.35f, 0.40f);
        colors[ImGuiCol_ResizeGripHovered]     = NeonCyan;
        colors[ImGuiCol_ResizeGripActive]      = NeonCyan;
        colors[ImGuiCol_Tab]                   = ImVec4(0.10f, 0.12f, 0.18f, 0.80f);
        colors[ImGuiCol_TabHovered]            = ImVec4(0.18f, 0.24f, 0.36f, 0.90f);
        colors[ImGuiCol_TabActive]             = ImVec4(0.14f, 0.22f, 0.35f, 1.00f);
        colors[ImGuiCol_TabUnfocused]          = ImVec4(0.08f, 0.10f, 0.14f, 0.80f);
        colors[ImGuiCol_TabUnfocusedActive]   = ImVec4(0.12f, 0.16f, 0.24f, 0.90f);
        colors[ImGuiCol_TableHeaderBg]         = ImVec4(0.09f, 0.11f, 0.16f, 0.95f);
        colors[ImGuiCol_TableBorderStrong]     = GlassBorder;
        colors[ImGuiCol_TableBorderLight]      = ImVec4(0.18f, 0.22f, 0.30f, 0.40f);
        colors[ImGuiCol_TableRowBg]            = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
        colors[ImGuiCol_TableRowBgAlt]         = ImVec4(0.08f, 0.10f, 0.15f, 0.30f);
    }

    void GlassTheme::RenderBadge(const char* label, const ImVec4& color) {
        ImVec2 p = ImGui::GetCursorScreenPos();
        ImDrawList* drawList = ImGui::GetWindowDrawList();

        ImVec2 textSize = ImGui::CalcTextSize(label);
        ImVec2 padding(8.0f, 3.0f);
        ImVec2 boxSize(textSize.x + padding.x * 2.0f, textSize.y + padding.y * 2.0f);

        ImU32 bgCol = ImGui::ColorConvertFloat4ToU32(ImVec4(color.x, color.y, color.z, 0.18f));
        ImU32 borderCol = ImGui::ColorConvertFloat4ToU32(ImVec4(color.x, color.y, color.z, 0.70f));
        ImU32 textCol = ImGui::ColorConvertFloat4ToU32(ImVec4(color.x, color.y, color.z, 1.00f));

        drawList->AddRectFilled(p, ImVec2(p.x + boxSize.x, p.y + boxSize.y), bgCol, 5.0f);
        drawList->AddRect(p, ImVec2(p.x + boxSize.x, p.y + boxSize.y), borderCol, 5.0f, 0, 1.0f);
        drawList->AddText(ImVec2(p.x + padding.x, p.y + padding.y), textCol, label);

        ImGui::Dummy(boxSize);
    }

    void GlassTheme::RenderMetricCard(const char* title, const char* value, const char* subtitle, const ImVec4& accentColor, float width) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.10f, 0.12f, 0.17f, 0.75f));
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.0f, 10.0f));

        std::string cardId = "card_" + std::string(title);
        ImGui::BeginChild(cardId.c_str(), ImVec2(width, 78.0f), true, ImGuiWindowFlags_NoScrollbar);

        // Accent top indicator bar
        ImVec2 p = ImGui::GetCursorScreenPos();
        ImDrawList* drawList = ImGui::GetWindowDrawList();
        drawList->AddRectFilled(p, ImVec2(p.x + width - 24.0f, p.y + 2.5f), ImGui::ColorConvertFloat4ToU32(accentColor), 2.0f);
        ImGui::Dummy(ImVec2(0, 4.0f));

        // Title
        ImGui::PushFont(FontSmall ? FontSmall : ImGui::GetFont());
        ImGui::TextColored(TextMuted, "%s", title);
        ImGui::PopFont();

        // Value
        ImGui::PushFont(FontTitle ? FontTitle : ImGui::GetFont());
        ImGui::TextColored(accentColor, "%s", value);
        ImGui::PopFont();

        ImGui::EndChild();
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor();
    }

    bool GlassTheme::NeonButton(const char* label, const ImVec4& color, const ImVec2& size) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(color.x * 0.25f, color.y * 0.25f, color.z * 0.25f, 0.65f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(color.x * 0.45f, color.y * 0.45f, color.z * 0.45f, 0.85f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(color.x, color.y, color.z, 0.80f));
        ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(color.x, color.y, color.z, 0.60f));

        bool clicked = ImGui::Button(label, size);

        ImGui::PopStyleColor(4);
        return clicked;
    }

    void GlassTheme::BeginGlassChild(const char* id, const ImVec2& size, bool border) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, GlassCardBg);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
        ImGui::BeginChild(id, size, border);
    }

    void GlassTheme::EndGlassChild() {
        ImGui::EndChild();
        ImGui::PopStyleVar();
        ImGui::PopStyleColor();
    }

} // namespace Sandbox::GUI
