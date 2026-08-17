#include "cli/startup_card.h"
#include "cli/ascii_art.h"
#include "cli/text_layout.h"
#include "cli/terminal.h"
#include "common/version.h"
#include "common/paths.h"

#include <algorithm>

namespace Dracula {

    namespace {

        // Left margin shared by the header, the output region and the prompt, so
        // every region's text starts on the same column.
        constexpr size_t kIndent    = 2;
        constexpr size_t kColumnGap = 3;

        std::string Muted()   { return Terminal::Color(ColorRole::Muted); }
        std::string Reset()   { return Terminal::Color(ColorRole::Reset); }
        std::string Primary() { return Terminal::Color(ColorRole::Primary); }
        std::string Title()   { return Terminal::Color(ColorRole::Title); }
        std::string Tech()    { return Terminal::Color(ColorRole::Technical); }
        std::string Border()  { return Terminal::Color(ColorRole::Border); }

        // Usable width: one cell short of the terminal, because writing into the
        // final column makes some terminals emit a spurious wrap.
        size_t Usable(int terminalWidth) {
            return static_cast<size_t>(std::max(terminalWidth - 1, 12));
        }

        std::string Sep() { return "  " + Terminal::Bullet() + "  "; }

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

        // "Dracula  v1.0.3  •  x64  •  Release"
        std::string IdentityRow(const StartupInfo& info) {
            std::string row = Title() + "Dracula" + Reset() + Muted() + "  v" + info.version;
            if (!info.architecture.empty()) row += Sep() + info.architecture;
            if (!info.buildMode.empty())    row += Sep() + info.buildMode;
            row += Reset();
            return row;
        }

        std::string EngineRow(const StartupInfo& info, size_t width) {
            std::string joined;
            for (size_t i = 0; i < info.engines.size(); ++i) {
                if (i) joined += Sep();
                joined += info.engines[i];
            }
            return Tech() + Text::Truncate(joined, width) + Reset();
        }

        // The full-bleed rule that closes the header region.
        std::string Divider(int terminalWidth) {
            return Border() + Text::HorizontalRule(Usable(terminalWidth)) + Reset();
        }

        std::string Indent(const std::string& body) {
            return std::string(kIndent, ' ') + body;
        }

    } // namespace

    StartupInfo StartupInfo::Detect() {
        StartupInfo info;
        info.version      = Version::String;
        info.buildTarget  = Version::BuildTarget;
        info.architecture = "x64";
        info.buildMode    = "Release";
        info.engines      = {
            "Capstone 5", "Unicorn 2", "Safe PE",
            "CFG / XRefs", "Win32 HLE", "MCP Server"
        };
        info.workingDirectory = Paths::CurrentWorkingDir();
        info.tips = {
            "Type / to browse commands, Tab to accept the selection",
            "Start with /analyze <file>, then /headers, /strings or /cfg reuse it"
        };
        return info;
    }

    HeaderVariant StartupCard::SelectVariant(int terminalWidth) {
        // The artwork is Braille, so a terminal that cannot render Unicode gets
        // the text-only header rather than a field of replacement glyphs.
        const bool canDrawArt = Terminal::SupportsUnicode();

        if (terminalWidth >= kStandardMinWidth && canDrawArt) return HeaderVariant::Standard;
        if (terminalWidth >= kCompactMinWidth)                return HeaderVariant::Compact;
        return HeaderVariant::Minimal;
    }

    std::vector<std::string> StartupCard::RenderHeader(int terminalWidth,
                                                       const StartupInfo& info) {
        return RenderHeader(terminalWidth, SelectVariant(terminalWidth), info);
    }

    std::vector<std::string> StartupCard::RenderHeader(int terminalWidth,
                                                       HeaderVariant variant,
                                                       const StartupInfo& info) {
        if (variant == HeaderVariant::None) return {};

        const size_t usable = Usable(terminalWidth);
        std::vector<std::string> rows;

        // A narrow terminal cannot fit the art column plus a legible text
        // column, so it renders the text-only variant regardless of the request.
        // The same applies when the terminal cannot draw the Braille artwork.
        const size_t artWidth = Art::MaxWidth(Art::Vampire());
        const size_t textWidth = usable > kIndent + artWidth + kColumnGap + 16
                               ? usable - kIndent - artWidth - kColumnGap
                               : 0;
        if (variant == HeaderVariant::Standard &&
            (textWidth == 0 || !Terminal::SupportsUnicode())) {
            variant = HeaderVariant::Compact;
        }

        switch (variant) {
            case HeaderVariant::Standard: {
                std::vector<std::string> text = {
                    Text::Truncate(IdentityRow(info), textWidth),
                    EngineRow(info, textWidth),
                    Muted() + ShortenPath(info.workingDirectory, textWidth) + Reset()
                };

                auto art = Art::Colorize(Art::Vampire());

                // Centre the shorter information column against the artwork, so
                // the text sits beside the vampire rather than at its shoulder.
                if (text.size() < art.size()) {
                    text.insert(text.begin(), (art.size() - text.size()) / 2, "");
                }

                rows.push_back("");
                for (const auto& row : Text::RenderColumns({art, text},
                                                           {artWidth, textWidth},
                                                           kColumnGap)) {
                    rows.push_back(Indent(row));
                }
                break;
            }

            case HeaderVariant::Compact: {
                const size_t textW = usable > kIndent ? usable - kIndent : usable;
                rows.push_back("");
                rows.push_back(Indent(Text::Truncate(IdentityRow(info), textW)));
                rows.push_back(Indent(EngineRow(info, textW)));
                break;
            }

            case HeaderVariant::Minimal:
            default: {
                const size_t textW = usable > kIndent ? usable - kIndent : usable;
                rows.push_back(Indent(Text::Truncate(IdentityRow(info), textW)));
                break;
            }
        }

        rows.push_back(Divider(terminalWidth));
        return rows;
    }

    std::vector<std::string> StartupCard::Render(int terminalWidth, const StartupInfo& info) {
        std::vector<std::string> out = RenderHeader(terminalWidth, info);

        const std::string hint =
            Indent(Muted() + "Type " + Reset() +
                   Primary() + "/" + Reset() +
                   Muted() + " to browse commands" + Reset() +
                   Muted() + Sep() + Reset() +
                   Tech() + "/help" + Reset() +
                   Muted() + " for the full reference" + Reset());

        out.push_back("");
        out.push_back(Text::Truncate(hint, Usable(terminalWidth)));
        out.push_back("");
        return out;
    }

} // namespace Dracula
