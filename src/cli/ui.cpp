#include "cli/ui.h"
#include "cli/terminal.h"
#include "cli/text_layout.h"
#include "cli/command_registry.h"

#include <algorithm>
#include <iostream>
#include <sstream>

namespace Dracula {
namespace Ui {

    namespace {
        std::string C(ColorRole role) { return Terminal::Color(role); }
        std::string R() { return Terminal::Color(ColorRole::Reset); }
    }

    size_t ContentWidth() {
        // Terminal owns the answer: in the persistent interactive layout it is
        // the output region's width, otherwise the console width.
        return static_cast<size_t>(Terminal::ContentWidth());
    }

    void Blank() {
        std::cout << "\n";
    }

    void Lines(const std::vector<std::string>& lines) {
        for (const auto& l : lines) std::cout << l << "\n";
    }

    static void Message(ColorRole role, const std::string& glyph,
                        const std::string& message, std::ostream& os) {
        os << "  " << C(role) << glyph << R() << " "
           << C(ColorRole::Text) << message << R() << "\n";
    }

    static bool s_errorOccurred = false;

    bool HasError() { return s_errorOccurred; }
    void ResetError() { s_errorOccurred = false; }
    void SetError() { s_errorOccurred = true; }

    void Success(const std::string& message) {
        Message(ColorRole::Success, Terminal::Checkmark(), message, std::cout);
    }

    void Warning(const std::string& message) {
        Message(ColorRole::Warning, Terminal::WarningIcon(), message, std::cout);
    }

    void Error(const std::string& message) {
        s_errorOccurred = true;
        Message(ColorRole::Error, Terminal::Crossmark(), message, std::cerr);
    }

    void Info(const std::string& message) {
        Message(ColorRole::Info, Terminal::SupportsUnicode() ? "\xE2\x80\xA2" : "i",
                message, std::cout);
    }

    void Note(const std::string& message) {
        std::cout << "  " << C(ColorRole::Muted) << message << R() << "\n";
    }

    void Section(const std::string& title, const std::string& subtitle) {
        const size_t width = ContentWidth();
        std::string heading = C(ColorRole::Accent) + title + R();
        if (!subtitle.empty()) {
            heading += C(ColorRole::Muted) + "   " + subtitle + R();
        }

        std::cout << "\n"
                  << Text::Truncate(heading, width) << "\n"
                  << C(ColorRole::Border)
                  << Text::HorizontalRule(std::min<size_t>(width, 72))
                  << R() << "\n";
    }

    void Group(const std::string& label) {
        std::cout << "\n  " << C(ColorRole::Secondary) << label << R() << "\n";
    }

    void KeyValue(const std::string& key, const std::string& value, size_t keyWidth) {
        std::cout << "  " << C(ColorRole::Muted) << Text::PadRight(key, keyWidth) << R()
                  << C(ColorRole::Text)
                  << Text::Truncate(value, ContentWidth() - keyWidth - 2)
                  << R() << "\n";
    }

    void KeyState(const std::string& key, State state, const std::string& value,
                  size_t keyWidth) {
        ColorRole role = ColorRole::Text;
        switch (state) {
            case State::Good:    role = ColorRole::Success; break;
            case State::Bad:     role = ColorRole::Error;   break;
            case State::Warn:    role = ColorRole::Warning; break;
            case State::Neutral: role = ColorRole::Muted;   break;
        }
        std::cout << "  " << C(ColorRole::Muted) << Text::PadRight(key, keyWidth) << R()
                  << C(role) << value << R() << "\n";
    }

    std::string Number(unsigned long long value) {
        std::string digits = std::to_string(value);
        std::string out;
        int count = 0;
        for (size_t i = digits.size(); i > 0; --i) {
            out.insert(out.begin(), digits[i - 1]);
            if (++count % 3 == 0 && i > 1) out.insert(out.begin(), ',');
        }
        return out;
    }

    void Truncated(size_t shown, size_t total, const std::string& noun,
                   const std::string& allHint) {
        if (shown >= total) return;
        std::string line = "Showing " + Number(shown) + " of " + Number(total) + " " + noun;
        if (!allHint.empty()) {
            line += "   " + Terminal::Bullet() + "   " + allHint;
        }
        std::cout << "\n  " << C(ColorRole::Muted) << line << R() << "\n";
    }

    void UsageHint(const std::string& reason, const std::string& usage,
                   const std::string& example, const std::string& tip) {
        std::cout << "\n  " << C(ColorRole::Warning) << Terminal::WarningIcon() << R()
                  << " " << C(ColorRole::Text) << reason << R() << "\n";

        if (!usage.empty()) {
            std::cout << "\n  " << C(ColorRole::Muted) << "Usage" << R() << "\n"
                      << "    " << C(ColorRole::Technical) << usage << R() << "\n";
        }
        if (!example.empty()) {
            std::cout << "\n  " << C(ColorRole::Muted) << "Example" << R() << "\n"
                      << "    " << C(ColorRole::Technical) << example << R() << "\n";
        }
        if (!tip.empty()) {
            std::cout << "\n  " << C(ColorRole::Muted) << "Tip" << R() << "\n"
                      << "    " << C(ColorRole::Muted) << tip << R() << "\n";
        }
        std::cout << "\n";
    }

    void MissingArgument(const CommandDefinition& cmd, const std::string& reason,
                         const std::string& tip) {
        s_errorOccurred = true;
        std::string example = cmd.examples.empty() ? "" : cmd.examples.front();
        std::string effectiveTip = tip;
        if (effectiveTip.empty() && cmd.takesFilePath) {
            effectiveTip = "If a sample is active, the file argument can be omitted.";
        }
        UsageHint(reason, cmd.usage, example, effectiveTip);
    }

} // namespace Ui
} // namespace Dracula
