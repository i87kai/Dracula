#include "cli/startup_picker.h"
#include "cli/terminal.h"
#include "cli/text_layout.h"
#include "cli/ui.h"
#include "app/project_manager.h"

#include <iostream>
#include <iomanip>

namespace Dracula {

    namespace {
        std::string C(ColorRole role) { return Terminal::Color(role); }
        std::string R() { return Terminal::Color(ColorRole::Reset); }
    }

    std::vector<std::pair<StartupPicker::Choice, std::string>>
    StartupPicker::MenuEntries(bool hasProjects) {
        std::vector<std::pair<Choice, std::string>> entries;

        // Recent work first when there is any: reopening is the common case
        // once a user has been analyzing something.
        if (hasProjects) {
            entries.emplace_back(Choice::OpenProject, "Open Existing Project");
        }
        entries.emplace_back(Choice::OpenFile,      "Open File");
        entries.emplace_back(Choice::AttachProcess, "Attach to Process");
        entries.emplace_back(Choice::OpenDriver,    "Driver");
        entries.emplace_back(Choice::OpenVmImage,   "VM / Disk Image");
        return entries;
    }

    std::vector<std::string> StartupPicker::RenderMenu(int width, size_t selected,
                                                       bool hasProjects) {
        std::vector<std::string> rows;
        const auto entries = MenuEntries(hasProjects);

        rows.push_back("");
        rows.push_back("  " + C(ColorRole::Primary) + "DRACULA" + R());
        rows.push_back("");
        rows.push_back("  " + C(ColorRole::Text) + "What do you want to analyze?" + R());
        rows.push_back("");

        for (size_t i = 0; i < entries.size(); ++i) {
            const bool active = (i == selected);
            std::string row = active
                ? ("  " + C(ColorRole::Accent) + "> " + entries[i].second + R())
                : ("    " + C(ColorRole::Muted) + entries[i].second + R());
            rows.push_back(Text::Truncate(row, static_cast<size_t>(std::max(width - 1, 10))));
        }

        rows.push_back("");
        rows.push_back("  " + C(ColorRole::Muted) +
                       "Up/Down then Enter" + "   Esc for the command prompt" + R());
        rows.push_back("");
        return rows;
    }

    StartupPicker::Result StartupPicker::Present() {
        Result result;

        // A redirected or non-interactive session must behave exactly as it did
        // before: straight to the prompt, no menu, nothing to answer.
        if (!Terminal::IsInteractive()) {
            result.choice = Choice::SkipToShell;
            return result;
        }

        std::string indexError;
        App::ProjectManager::Instance().LoadIndex(indexError);
        const bool hasProjects = !App::ProjectManager::Instance().ListProjects().empty();

        const auto entries = MenuEntries(hasProjects);
        size_t selected = 0;
        bool firstDraw = true;
        size_t lastRowCount = 0;

        while (true) {
            auto rows = RenderMenu(Terminal::GetWidth(), selected, hasProjects);

            if (!firstDraw) {
                // Redraw in place rather than scrolling a new menu each time.
                Console::MoveUp(static_cast<int>(lastRowCount));
            }
            firstDraw = false;

            for (const auto& row : rows) {
                Console::ClearLine();
                std::cout << "\r" << row << "\n";
            }
            std::cout << std::flush;
            lastRowCount = rows.size();

            InputEvent event;
            if (!Console::ReadInput(event)) {
                result.choice = Choice::SkipToShell;
                return result;
            }

            switch (event.key) {
                case Key::Up:
                    if (selected > 0) --selected;
                    break;

                case Key::Down:
                    if (selected + 1 < entries.size()) ++selected;
                    break;

                case Key::Escape:
                case Key::CtrlC:
                    result.choice = Choice::SkipToShell;
                    result.cancelled = true;
                    return result;

                case Key::CtrlD:
                    result.choice = Choice::SkipToShell;
                    result.cancelled = true;
                    return result;

                case Key::Enter:
                    result.choice = entries[selected].first;
                    return result;

                case Key::Char: {
                    // Numeric shortcuts, so a user who knows the menu can skip
                    // the arrow keys entirely.
                    if (event.utf8.size() == 1 && event.utf8[0] >= '1' && event.utf8[0] <= '9') {
                        const size_t index = static_cast<size_t>(event.utf8[0] - '1');
                        if (index < entries.size()) {
                            result.choice = entries[index].first;
                            return result;
                        }
                    }
                    break;
                }

                default:
                    break;
            }
        }
    }

} // namespace Dracula
