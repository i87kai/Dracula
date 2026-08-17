#include "cli/startup_card.h"
#include "cli/ascii_art.h"
#include "cli/text_layout.h"
#include "cli/terminal.h"
#include "common/version.h"
#include "common/paths.h"

#include <algorithm>

namespace Dracula {

    namespace {

        constexpr int kMaxCardWidth = 118;
        constexpr int kBoxPadding   = 2;
        constexpr int kColumnGap    = 3;

        std::string Muted()   { return Terminal::Color(ColorRole::Muted); }
        std::string Reset()   { return Terminal::Color(ColorRole::Reset); }
        std::string Primary() { return Terminal::Color(ColorRole::Primary); }
        std::string Title()   { return Terminal::Color(ColorRole::Title); }
        std::string Tech()    { return Terminal::Color(ColorRole::Technical); }
        std::string Accent()  { return Terminal::Color(ColorRole::Accent); }
        std::string Textual() { return Terminal::Color(ColorRole::Text); }

        std::string Label(const std::string& text) {
            return Accent() + text + Reset();
        }

        // Shorten a filesystem path so it fits, keeping the tail (which is the
        // part a human recognises).
        std::string ShortenPath(const std::string& path, size_t width) {
            if (Text::VisibleWidth(path) <= width || width < 8) {
                return Text::Truncate(path, width);
            }
            const std::string head = Terminal::SupportsUnicode() ? "\xE2\x80\xA6" : "...";
            size_t keep = width - Text::VisibleWidth(head);

            // Take the last `keep` cells.
            std::string tail;
            size_t used = 0;
            for (size_t i = path.size(); i > 0;) {
                // Step back to the start of the previous UTF-8 sequence.
                size_t j = i - 1;
                while (j > 0 && (static_cast<unsigned char>(path[j]) & 0xC0) == 0x80) --j;
                std::string ch = path.substr(j, i - j);
                size_t cw = Text::VisibleWidth(ch);
                if (used + cw > keep) break;
                tail = ch + tail;
                used += cw;
                i = j;
            }
            return head + tail;
        }

        std::vector<std::string> InformationBlock(const StartupInfo& info,
                                                  size_t width,
                                                  bool rich) {
            std::vector<std::string> lines;

            lines.push_back(Title() + "Dracula" + Reset());
            lines.push_back(Textual() + "Binary Intelligence & Reverse Engineering" + Reset());
            lines.push_back("");

            std::string build = "v" + info.version;
            if (!info.architecture.empty()) build += "  " + Terminal::Bullet() + "  " + info.architecture;
            if (!info.buildMode.empty())    build += "  " + Terminal::Bullet() + "  " + info.buildMode;
            lines.push_back(Muted() + build + Reset());

            if (rich) {
                lines.push_back("");
                lines.push_back(Label("Engines"));

                // Two engine names per row keeps the block compact without
                // cramming everything onto a single line.
                size_t colWidth = std::max<size_t>(14, width / 2);
                for (size_t i = 0; i < info.engines.size(); i += 2) {
                    std::string row = Tech() + Text::PadRight(info.engines[i], colWidth) + Reset();
                    if (i + 1 < info.engines.size()) {
                        row += Tech() + info.engines[i + 1] + Reset();
                    }
                    lines.push_back(row);
                }

                lines.push_back("");
                lines.push_back(Label("Working directory"));
                lines.push_back(Muted() + ShortenPath(info.workingDirectory, width) + Reset());
            } else {
                std::string joined;
                for (size_t i = 0; i < info.engines.size(); ++i) {
                    if (i) joined += "  " + Terminal::Bullet() + "  ";
                    joined += info.engines[i];
                }
                lines.push_back("");
                lines.push_back(Tech() + Text::Truncate(joined, width) + Reset());
                lines.push_back("");
                lines.push_back(Muted() + "Working directory" + Reset());
                lines.push_back(Muted() + ShortenPath(info.workingDirectory, width) + Reset());
            }

            return lines;
        }

        std::vector<std::string> TipLines(const StartupInfo& info, size_t width) {
            std::vector<std::string> lines;
            for (const auto& tip : info.tips) {
                lines.push_back(Muted() + Terminal::Bullet() + " " + Reset() +
                                Textual() + Text::Truncate(tip, width - 2) + Reset());
            }
            return lines;
        }

    } // namespace

    StartupInfo StartupInfo::Detect() {
        StartupInfo info;
        info.version      = Version::String;
        info.buildTarget  = Version::BuildTarget;
        info.architecture = "x64";
        info.buildMode    = "Release";
        info.engines      = {
            "Capstone 5", "Unicorn 2",
            "Safe PE",    "CFG / XRefs",
            "Win32 HLE",  "MCP Server"
        };
        info.workingDirectory = Paths::CurrentWorkingDir();
        info.tips = {
            "Type / to browse commands, Tab to accept the selection",
            "Start with /analyze <file>, then /headers, /strings or /cfg reuse it"
        };
        return info;
    }

    StartupLayout StartupCard::SelectLayout(int terminalWidth) {
        // The supplied artwork is Braille (U+28xx). Without Unicode support the
        // ASCII mark is used instead, so the whole card drops to the compact
        // layout rather than mixing ASCII frames with Unicode art.
        if (!Terminal::SupportsUnicode()) {
            return terminalWidth >= kCompactMinWidth ? StartupLayout::Compact
                                                     : StartupLayout::Minimal;
        }
        if (terminalWidth >= kLargeMinWidth)   return StartupLayout::Large;
        if (terminalWidth >= kStackedMinWidth) return StartupLayout::Stacked;
        if (terminalWidth >= kCompactMinWidth) return StartupLayout::Compact;
        return StartupLayout::Minimal;
    }

    int StartupCard::CardWidth(int terminalWidth) {
        int width = std::min(terminalWidth - 2, kMaxCardWidth);
        return std::max(width, 30);
    }

    std::vector<std::string> StartupCard::RenderCard(int terminalWidth, const StartupInfo& info) {
        const StartupLayout layout = SelectLayout(terminalWidth);

        if (layout == StartupLayout::Minimal) {
            std::vector<std::string> lines;
            size_t w = static_cast<size_t>(std::max(terminalWidth - 1, 10));
            lines.push_back(Text::Truncate(Title() + "Dracula v" + info.version + Reset(), w));
            lines.push_back(Text::Truncate(Textual() + "Binary Intelligence & Reverse Engineering" + Reset(), w));
            return lines;
        }

        const int cardWidth = CardWidth(terminalWidth);
        Text::BoxBuilder box(static_cast<size_t>(cardWidth), kBoxPadding);
        const size_t inner = box.InnerWidth();

        box.AddBlank();

        if (layout == StartupLayout::Large) {
            const auto& art = Art::Vampire();
            const size_t artWidth = Art::MaxWidth(art);
            const size_t rightWidth = inner > artWidth + kColumnGap
                                    ? inner - artWidth - kColumnGap
                                    : 20;

            auto artBlock = Art::Colorize(art);
            auto infoBlock = InformationBlock(info, rightWidth, true);

            // Vertically centre the shorter information column against the art.
            if (infoBlock.size() < artBlock.size()) {
                size_t offset = (artBlock.size() - infoBlock.size()) / 2;
                infoBlock.insert(infoBlock.begin(), offset, "");
            }

            box.AddLines(Text::RenderColumns({artBlock, infoBlock},
                                             {artWidth, rightWidth},
                                             kColumnGap));
        } else {
            const auto& art = (layout == StartupLayout::Stacked)
                            ? Art::Vampire()
                            : Art::VampireCompact();
            const size_t artWidth = Art::MaxWidth(art);

            if (artWidth <= inner) {
                size_t indent = (inner - artWidth) / 2;
                for (const auto& row : Art::Colorize(art)) {
                    box.AddLine(std::string(indent, ' ') + row);
                }
                box.AddBlank();
            }

            box.AddLines(InformationBlock(info, inner, layout == StartupLayout::Stacked));
        }

        box.AddBlank();

        auto tips = TipLines(info, inner);
        if (!tips.empty()) {
            box.AddDivider();
            box.AddLines(tips);
        }

        return box.Build();
    }

    std::vector<std::string> StartupCard::Render(int terminalWidth, const StartupInfo& info) {
        const StartupLayout layout = SelectLayout(terminalWidth);
        std::vector<std::string> out;

        auto card = RenderCard(terminalWidth, info);

        const std::string margin = (layout == StartupLayout::Minimal) ? "" : " ";
        out.push_back("");
        for (const auto& row : card) {
            out.push_back(margin + row);
        }
        out.push_back("");

        std::string hint = margin + "  " + Muted() + "Type " + Reset() +
                           Primary() + "/" + Reset() +
                           Muted() + " to browse commands" + Reset() +
                           Muted() + "   " + Terminal::Bullet() + "   " + Reset() +
                           Tech() + "/help" + Reset() +
                           Muted() + " for the full reference" + Reset();
        // One cell short of the terminal width: writing into the final column
        // makes some terminals emit a spurious wrap.
        out.push_back(Text::Truncate(hint, static_cast<size_t>(std::max(terminalWidth - 1, 10))));
        out.push_back("");

        return out;
    }

} // namespace Dracula
