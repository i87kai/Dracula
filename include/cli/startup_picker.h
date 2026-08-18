#pragma once

//
// First-run startup picker (milestone section 4).
//
// Typing `drac` with no arguments must not drop the user into an empty
// command environment. It asks the one question that matters -- what do you
// want to analyze -- and turns the answer into an open project.
//
// The picker is deliberately small: arrow keys, Enter, Escape and numeric
// shortcuts. It never asks the user to understand Dracula's engine hierarchy;
// target type is detected from what they choose.
//

#include <string>
#include <vector>

namespace Dracula {

    class StartupPicker {
    public:
        enum class Choice {
            OpenFile,
            AttachProcess,
            OpenProject,
            OpenDriver,
            OpenVmImage,
            SkipToShell,     // Escape: go straight to the prompt
        };

        struct Result {
            Choice      choice = Choice::SkipToShell;
            std::string argument;   // path, PID or project id, when supplied
            bool        cancelled = false;
        };

        // Presents the picker and collects the user's answer. Returns
        // SkipToShell when there is no interactive console, so a piped or
        // redirected session behaves exactly as before.
        static Result Present();

        // Renders the menu rows for a given width. Exposed so the layout can
        // be asserted on without a console attached.
        static std::vector<std::string> RenderMenu(int width, size_t selected,
                                                   bool hasProjects);

        // The menu entries, in display order. The project entry is only
        // offered when at least one project exists.
        static std::vector<std::pair<Choice, std::string>> MenuEntries(bool hasProjects);
    };

} // namespace Dracula
