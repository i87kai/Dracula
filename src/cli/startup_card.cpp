#include "cli/startup_card.h"
#include "cli/ascii_art.h"
#include "cli/text_layout.h"
#include "cli/terminal.h"
#include "common/version.h"
#include "common/paths.h"
#include "app/project_manager.h"

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

        // The row that replaced the engine inventory: what is loaded, what
        // state it is in. When nothing is open it invites the user to open
        // something rather than listing libraries at them.
        std::string ContextRow(const StartupInfo& info, size_t width) {
            std::vector<std::pair<std::string, std::string>> fields;
            if (!info.projectName.empty())   fields.emplace_back("Project", info.projectName);
            if (!info.targetSummary.empty()) fields.emplace_back("Target", info.targetSummary);
            if (!info.runtimeState.empty())  fields.emplace_back("Runtime", info.runtimeState);
            if (!info.sandboxState.empty())  fields.emplace_back("Sandbox", info.sandboxState);
            if (!info.statusText.empty())    fields.emplace_back("Status", info.statusText);

            if (fields.empty()) {
                return Muted() + Text::Truncate("No project open", width) + Reset();
            }

            std::string joined;
            for (size_t i = 0; i < fields.size(); ++i) {
                if (i) joined += Muted() + Sep() + Reset();
                joined += Muted() + fields[i].first + " " + Reset() + Tech() + fields[i].second + Reset();
            }
            return Text::Truncate(joined, width);
        }

        // The currently selected tip. Selection is stable for a given
        // StartupInfo, so repainting the same state paints the same rows.
        std::string TipRow(const StartupInfo& info, size_t width) {
            if (info.tips.empty()) return "";
            const std::string& tip = info.tips[info.tipIndex % info.tips.size()];
            return Muted() + Text::Truncate("Tip: " + tip, width) + Reset();
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
        // Retained for /about and diagnostics only; the header no longer
        // renders this (section 24).
        info.engines      = {
            "Capstone 5", "Unicorn 2", "Safe PE",
            "CFG / XRefs", "Win32 HLE", "MCP Server"
        };
        info.workingDirectory = Paths::CurrentWorkingDir();
        info.RefreshContext();
        return info;
    }

    void StartupInfo::RefreshContext() {
        projectName.clear();
        targetSummary.clear();
        runtimeState.clear();
        statusText.clear();
        tips.clear();
        // tipIndex is deliberately preserved across refreshes: it belongs to
        // the session, not to the context being described.

        // QEMU stays lazy, so the sandbox is reported as available rather than
        // running unless something actually started it (section 27).
        sandboxState = "Available";

        auto project = App::ProjectManager::Instance().Active();

        if (!project) {
            statusText = "Idle";
            tips = {
                "Type / to browse commands.",
                "/target <file> creates a durable project for a sample.",
                "/process attach <pid> analyzes a running process.",
                "/project list shows every project you have created.",
            };
            return;
        }

        const auto& target = project->Target();
        projectName = project->DisplayName();
        targetSummary = std::string(UTR::TargetKindToString(target.kind)) +
                        (target.architecture.empty() ? "" : (" - " + target.architecture));

        if (target.IsLiveProcess()) {
            runtimeState = "PID " + std::to_string(target.pid);
            tips = {
                "/memory snapshot before records the current memory state.",
                "/dll <name> correlates a loaded module with its on-disk image.",
                "/process modules lists what is loaded in the target.",
                "Large tables are written to HTML reports inside the project.",
                "/memory compare before after diffs two snapshots.",
            };
        } else {
            runtimeState = "Idle";
            tips = {
                "/static sections shows the section table with entropy.",
                "/project storage shows exactly what this project is using.",
                "/session cleanup removes disposable data without deleting the project.",
                "Large tables are written to HTML reports inside the project.",
            };
        }

        statusText = "Ready";
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
                    ContextRow(info, textWidth),
                    TipRow(info, textWidth)
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
                rows.push_back(Indent(ContextRow(info, textW)));
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
