//
// Renders real terminal frames and prints them, so the scrollback chrome can
// be inspected as output rather than only asserted on.
//
// This is an evidence tool, not a test: it exists so the scrollbar, the
// new-output indicator and the selection highlight can be seen exactly as
// InteractiveScreen composes them, without a console attached.
//

#include "cli/screen.h"
#include "cli/line_editor.h"
#include "cli/terminal.h"
#include "cli/text_layout.h"

#include <iostream>
#include <string>

using namespace Dracula;

static void Dump(const std::string& title,
                 const std::vector<std::string>& frame,
                 const ScreenLayout& layout) {
    std::cout << "\n--- " << title << " ---\n";
    for (size_t row = 0; row < frame.size(); ++row) {
        const std::string plain = Text::StripAnsi(frame[row]);

        // Label the regions so the structure is readable at a glance.
        std::string tag = "     ";
        if (layout.hasHeader && static_cast<int>(row) < layout.header.Bottom()) tag = "hdr  ";
        else if (static_cast<int>(row) >= layout.output.top &&
                 static_cast<int>(row) < layout.output.Bottom())               tag = "out  ";
        else if (static_cast<int>(row) == layout.inputRule.top)                tag = "rule ";
        else if (static_cast<int>(row) == layout.input.top)                    tag = "in   ";
        else if (static_cast<int>(row) == layout.footer.top)                   tag = "foot ";

        std::cout << tag << "|" << plain << "|\n";
    }
}

int main() {
    Terminal::SetColorEnabled(false);
    Terminal::SetUnicodeEnabled(false);   // ASCII chrome, so it is readable here

    InteractiveScreen screen;
    LineEditor editor;
    const std::string prompt = "dracula > ";

    // Fill the history well past one viewport.
    for (int i = 1; i <= 120; ++i) {
        screen.Output().AppendLine("  line " + std::to_string(i) +
                                   "  memory region 0x00007FF" +
                                   std::to_string(100000 + i) + "  PAGE_READWRITE");
    }

    const int width = 88;
    const int height = 24;

    // 1. Following the tail: scrollbar thumb should sit at the bottom.
    screen.Output().ScrollToBottom();
    auto tail = screen.PreviewFrame(width, height, editor, prompt);
    Dump("At the newest output (following)", tail, screen.Layout());

    // 2. Scrolled to the top: thumb at the top, and the footer should report
    //    the new lines below rather than snapping back.
    screen.Output().ScrollToTop();
    auto top = screen.PreviewFrame(width, height, editor, prompt);
    Dump("Scrolled to the oldest output", top, screen.Layout());

    // 3. New output arriving while scrolled back must NOT move the viewport.
    const size_t anchorBefore = screen.Output().ScrollAnchor();
    for (int i = 121; i <= 138; ++i) {
        screen.Output().AppendLine("  line " + std::to_string(i) + "  NEW OUTPUT");
    }
    const size_t anchorAfter = screen.Output().ScrollAnchor();

    auto withNew = screen.PreviewFrame(width, height, editor, prompt);
    Dump("18 new lines arrived while scrolled back", withNew, screen.Layout());

    std::cout << "\n  viewport anchor before new output: " << anchorBefore << "\n";
    std::cout << "  viewport anchor after  new output: " << anchorAfter << "\n";
    std::cout << "  viewport held steady: "
              << (anchorBefore == anchorAfter ? "YES" : "NO") << "\n";

    // 4. A drag selection, highlighted in place.
    const auto layout = screen.Layout();
    screen.BeginSelection(layout.output.top + 2, 4);
    screen.ExtendSelection(layout.output.top + 4, 30);
    auto selected = screen.PreviewFrame(width, height, editor, prompt);
    Dump("Text selected by dragging (rows 3-5 of the output region)", selected, layout);

    std::cout << "\n  selection active: " << (screen.HasSelection() ? "YES" : "NO") << "\n";
    std::cout << "  copied text:\n";
    const std::string copied = screen.SelectedText();
    size_t start = 0;
    while (start <= copied.size()) {
        const size_t end = copied.find('\n', start);
        std::cout << "    >" << copied.substr(start, end - start) << "<\n";
        if (end == std::string::npos) break;
        start = end + 1;
    }
    std::cout << "  contains escape sequences: "
              << (copied.find('\033') == std::string::npos ? "NO" : "YES") << "\n\n";

    return 0;
}
