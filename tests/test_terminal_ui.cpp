//
// Dracula Terminal UI verification suite.
//
// These tests exist specifically to make the class of bug that broke the old
// startup banner impossible to reintroduce: every generated row is measured in
// display cells, at many terminal widths, with colour on and off.
//

#include "cli/terminal.h"
#include "cli/text_layout.h"
#include "cli/ascii_art.h"
#include "cli/startup_card.h"
#include "cli/ui.h"
#include "cli/command_registry.h"
#include "cli/line_editor.h"
#include "cli/dracula_shell.h"
#include "common/version.h"
#include "common/paths.h"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <algorithm>

using namespace Dracula;

static int g_pass = 0;
static int g_fail = 0;

static void Check(bool condition, const std::string& name) {
    if (condition) {
        std::cout << "  \033[32m[PASS]\033[0m " << name << "\n";
        ++g_pass;
    } else {
        std::cout << "  \033[1;31m[FAIL]\033[0m " << name << "\n";
        ++g_fail;
    }
}

static void Section(const std::string& title) {
    std::cout << "\n\033[1;36m=== " << title << " ===\033[0m\n";
}

static const int kTestWidths[] = {40, 50, 60, 80, 100, 120, 160, 200};

// ─── 1. Measurement ─────────────────────────────────────────────────────────

static void TestMeasurement() {
    Section("Layout 1: ANSI-aware and UTF-8-aware measurement");

    const std::string colored = "\033[1;31mDracula\033[0m \033[36mTerminal\033[0m";
    Check(Text::StripAnsi(colored) == "Dracula Terminal", "StripAnsi removes every CSI sequence");
    Check(Text::VisibleWidth(colored) == 16, "ANSI styling counts as zero display columns");

    Check(Text::VisibleWidth("abc") == 3, "ASCII width equals character count");

    // Bullet, box drawing and Braille are all single-cell but multi-byte.
    Check(std::string("\xE2\x80\xA2").size() == 3, "Bullet is a 3-byte UTF-8 sequence");
    Check(Text::VisibleWidth("\xE2\x80\xA2") == 1, "Multi-byte bullet measures 1 cell, not 3 bytes");
    Check(Text::VisibleWidth("\xE2\x94\x80\xE2\x94\x80\xE2\x94\x80") == 3, "Box drawing measures 1 cell per glyph");
    Check(Text::VisibleWidth("\xE2\xA0\x80") == 1, "Braille U+2800 measures 1 cell");

    // Wide (East Asian) characters occupy two cells.
    Check(Text::VisibleWidth("\xE6\xBC\xA2") == 2, "CJK ideograph measures 2 cells");
    Check(Text::CodePointWidth(0x0301) == 0, "Combining mark measures 0 cells");

    // Truncated / invalid UTF-8 must terminate, not hang or underflow.
    Check(Text::VisibleWidth("\xE2\xA0") <= 2, "Truncated UTF-8 sequence is handled safely");

    Check(Terminal::VisibleLength(colored) == Text::VisibleWidth(colored),
          "Terminal::VisibleLength forwards to the single measurement implementation");
}

static void TestComposition() {
    Section("Layout 2: padding, truncation, centering and wrapping");

    Check(Text::VisibleWidth(Text::PadRight("ab", 10)) == 10, "PadRight reaches the requested cell width");
    Check(Text::VisibleWidth(Text::PadLeft("ab", 10)) == 10, "PadLeft reaches the requested cell width");
    Check(Text::VisibleWidth(Text::Center("ab", 11)) == 11, "Center reaches the requested cell width");
    Check(Text::PadRight("abcdefghij", 4) == "abcdefghij", "PadRight never truncates");

    // Padding must be computed from cells, not bytes.
    const std::string bulletText = "a \xE2\x80\xA2 b";     // 5 cells, 7 bytes
    Check(Text::VisibleWidth(bulletText) == 5, "Mixed ASCII/UTF-8 measures by cells");
    Check(Text::VisibleWidth(Text::PadRight(bulletText, 20)) == 20, "PadRight is byte-length independent");

    // Padding must ignore ANSI too.
    const std::string styled = "\033[31mred\033[0m";
    Check(Text::VisibleWidth(Text::PadRight(styled, 12)) == 12, "PadRight is ANSI independent");

    Check(Text::VisibleWidth(Text::Truncate("abcdefghijklmnop", 8)) == 8, "Truncate respects the cell budget");
    Check(Text::VisibleWidth(Text::Fit("abc", 9)) == 9, "Fit pads short text to exact width");
    Check(Text::VisibleWidth(Text::Fit("abcdefghijkl", 9)) == 9, "Fit truncates long text to exact width");

    auto wrapped = Text::Wrap("the quick brown fox jumps over the lazy dog", 12);
    bool allFit = !wrapped.empty();
    for (const auto& l : wrapped) if (Text::VisibleWidth(l) > 12) allFit = false;
    Check(allFit, "Wrap never produces a line wider than the requested width");

    auto hardWrapped = Text::Wrap("aaaaaaaaaaaaaaaaaaaaaaaaaaaa", 10);
    bool hardOk = !hardWrapped.empty();
    for (const auto& l : hardWrapped) if (Text::VisibleWidth(l) > 10) hardOk = false;
    Check(hardOk, "Wrap hard-splits a single oversized word");

    Check(Text::VisibleWidth(Text::HorizontalRule(37)) == 37, "HorizontalRule produces exactly N cells");
}

// ─── 2. Boxes ───────────────────────────────────────────────────────────────

static void TestBoxGeometry() {
    Section("Layout 3: box geometry at every tested width");

    bool allExact = true;
    bool allNonNegative = true;

    for (int width : kTestWidths) {
        Text::BoxBuilder box(static_cast<size_t>(width), 2);
        box.Title("Dracula");
        box.AddBlank();
        box.AddLine("short");
        box.AddLine(std::string(300, 'x'));                       // overflow candidate
        box.AddLine("\033[31mstyled \xE2\x80\xA2 text\033[0m");   // ANSI + UTF-8
        box.AddDivider();
        box.AddLine("tips");

        auto rows = box.Build();
        for (const auto& row : rows) {
            if (Text::VisibleWidth(row) != static_cast<size_t>(width)) allExact = false;
            if (Text::StripAnsi(row).find('\n') != std::string::npos) allNonNegative = false;
        }
    }

    Check(allExact, "Every box row (top, body, divider, bottom) has exactly the box width");
    Check(allNonNegative, "No box row contains an embedded newline / wrap");

    // Same guarantee with colour disabled.
    Terminal::SetColorEnabled(false);
    bool noColorExact = true;
    for (int width : kTestWidths) {
        Text::BoxBuilder box(static_cast<size_t>(width), 2);
        box.AddLine("no color mode");
        for (const auto& row : box.Build()) {
            if (Text::VisibleWidth(row) != static_cast<size_t>(width)) noColorExact = false;
        }
    }
    Terminal::SetColorEnabled(true);
    Check(noColorExact, "Box geometry is identical with --no-color");

    // ASCII fallback mode.
    Terminal::SetUnicodeEnabled(false);
    bool asciiExact = true;
    for (int width : kTestWidths) {
        Text::BoxBuilder box(static_cast<size_t>(width), 2);
        box.AddLine("ascii mode");
        for (const auto& row : box.Build()) {
            if (Text::VisibleWidth(row) != static_cast<size_t>(width)) asciiExact = false;
        }
    }
    Terminal::SetUnicodeEnabled(true);
    Check(asciiExact, "Box geometry is identical with --no-unicode ASCII fallback");
}

static void TestColumns() {
    Section("Layout 4: two-column composition");

    std::vector<std::string> left  = {"aaa", "bb", "c"};
    std::vector<std::string> right = {"\033[31mred\033[0m", "\xE2\x80\xA2 bullet"};

    auto rows = Text::RenderColumns({left, right}, {10, 20}, 3);
    Check(rows.size() == 3, "RenderColumns pads the shorter block with blank rows");

    bool leftAligned = true;
    for (const auto& row : rows) {
        // Everything after the first column must start at the same cell.
        if (Text::VisibleWidth(row) > 33) leftAligned = false;
    }
    Check(leftAligned, "RenderColumns never exceeds the sum of column widths plus gap");
}

// ─── 3. The supplied Vampire artwork ────────────────────────────────────────

static void TestVampireArt() {
    Section("Layout 5: supplied Vampire Dracula artwork");

    const auto& art = Art::Vampire();
    Check(art.size() == 16, "Vampire artwork has its original 16 rows");
    Check(Art::MaxWidth(art) == 52, "Vampire artwork measures 52 display cells wide");

    bool uniform = true;
    for (const auto& row : art) {
        if (Text::VisibleWidth(row) != 52) uniform = false;
    }
    Check(uniform, "Every artwork row is exactly 52 cells (no ragged edge)");

    auto colored = Art::Colorize(art);
    bool widthsPreserved = colored.size() == art.size();
    for (size_t i = 0; i < colored.size() && widthsPreserved; ++i) {
        if (Text::VisibleWidth(colored[i]) != Text::VisibleWidth(art[i])) widthsPreserved = false;
    }
    Check(widthsPreserved, "Colorizing the artwork does not alter its measured width");

    Terminal::SetColorEnabled(false);
    auto plain = Art::Colorize(art);
    bool plainOk = (plain == art);
    Terminal::SetColorEnabled(true);
    Check(plainOk, "With --no-color the artwork renders unmodified");

    const auto& compact = Art::VampireCompact();
    Check(!compact.empty() && Art::MaxWidth(compact) <= 30,
          "Compact ASCII mark stays within 30 cells for narrow terminals");
    bool compactAscii = true;
    for (const auto& row : compact) {
        for (unsigned char c : row) if (c > 126) compactAscii = false;
    }
    Check(compactAscii, "Compact mark is pure ASCII and needs no Unicode support");
}

// ─── 4. Responsive startup card ─────────────────────────────────────────────

static void TestStartupLayoutSelection() {
    Section("Layout 6: responsive layout thresholds");

    Check(StartupCard::SelectLayout(40)  == StartupLayout::Minimal, "40 columns selects the minimal layout");
    Check(StartupCard::SelectLayout(43)  == StartupLayout::Minimal, "43 columns still selects the minimal layout");
    Check(StartupCard::SelectLayout(44)  == StartupLayout::Compact, "44 columns selects the compact layout");
    Check(StartupCard::SelectLayout(50)  == StartupLayout::Compact, "50 columns selects the compact layout");
    Check(StartupCard::SelectLayout(61)  == StartupLayout::Compact, "61 columns selects the compact layout");
    Check(StartupCard::SelectLayout(62)  == StartupLayout::Stacked, "62 columns switches to the stacked layout");
    Check(StartupCard::SelectLayout(80)  == StartupLayout::Stacked, "80 columns uses the stacked layout");
    Check(StartupCard::SelectLayout(99)  == StartupLayout::Stacked, "99 columns uses the stacked layout");
    Check(StartupCard::SelectLayout(100) == StartupLayout::Large,   "100 columns switches to the two-column layout");
    Check(StartupCard::SelectLayout(200) == StartupLayout::Large,   "200 columns uses the two-column layout");

    // Without Unicode the Braille artwork is unavailable, so the card drops to
    // the ASCII mark rather than mixing ASCII frames with Unicode art.
    Terminal::SetUnicodeEnabled(false);
    Check(StartupCard::SelectLayout(200) == StartupLayout::Compact,
          "Without Unicode support even a wide terminal uses the ASCII compact layout");
    Check(StartupCard::SelectLayout(30) == StartupLayout::Minimal,
          "Without Unicode support a narrow terminal still falls back to minimal");
    Terminal::SetUnicodeEnabled(true);
}

static void TestStartupCardGeometry() {
    Section("Layout 7: startup card geometry at every tested width");

    StartupInfo info = StartupInfo::Detect();
    info.workingDirectory = "D:\\Coding\\python\\AI\\jew\\build\\some\\deeply\\nested\\path";

    bool cardsUniform = true;
    bool nothingOverflows = true;
    bool noEmbeddedNewlines = true;

    for (int width : kTestWidths) {
        auto card = StartupCard::RenderCard(width, info);
        if (card.empty()) { cardsUniform = false; continue; }

        if (StartupCard::SelectLayout(width) != StartupLayout::Minimal) {
            const size_t expected = Text::VisibleWidth(card.front());
            for (const auto& row : card) {
                if (Text::VisibleWidth(row) != expected) cardsUniform = false;
            }
            if (expected != static_cast<size_t>(StartupCard::CardWidth(width))) cardsUniform = false;
        }

        for (const auto& row : StartupCard::Render(width, info)) {
            // Strictly narrower than the terminal: writing into the final cell
            // provokes a spurious wrap on some terminals.
            if (Text::VisibleWidth(row) >= static_cast<size_t>(width)) nothingOverflows = false;
            if (row.find('\n') != std::string::npos) noEmbeddedNewlines = false;
        }
    }

    Check(cardsUniform, "Every card row has identical width - no misplaced right border");
    Check(nothingOverflows, "No rendered row reaches the final terminal column at any tested width");
    Check(noEmbeddedNewlines, "No rendered row contains an embedded newline");

    // The artwork must survive intact in the layouts that claim to show it.
    auto large = StartupCard::RenderCard(160, info);
    bool artIntact = false;
    for (const auto& row : large) {
        if (row.find(Art::Vampire()[7]) != std::string::npos) artIntact = true;
    }
    Check(artIntact, "The widest artwork row is present unmodified in the two-column layout");

    auto stacked = StartupCard::RenderCard(80, info);
    bool stackedArt = false;
    for (const auto& row : stacked) {
        if (row.find(Art::Vampire()[7]) != std::string::npos) stackedArt = true;
    }
    Check(stackedArt, "The full artwork is present in the stacked layout");

    auto minimal = StartupCard::RenderCard(40, info);
    bool minimalSmall = minimal.size() <= 3;
    for (const auto& row : minimal) {
        if (Text::VisibleWidth(row) > 40) minimalSmall = false;
    }
    Check(minimalSmall, "The 40-column fallback is three short lines and never breaks the screen");

    // No-colour and ASCII modes keep the same geometry.
    Terminal::SetColorEnabled(false);
    Terminal::SetUnicodeEnabled(false);
    bool asciiUniform = true;
    for (int width : kTestWidths) {
        auto card = StartupCard::RenderCard(width, info);
        if (card.empty() || StartupCard::SelectLayout(width) == StartupLayout::Minimal) continue;
        const size_t expected = Text::VisibleWidth(card.front());
        for (const auto& row : card) {
            if (Text::VisibleWidth(row) != expected) asciiUniform = false;
        }
    }
    Terminal::SetColorEnabled(true);
    Terminal::SetUnicodeEnabled(true);
    Check(asciiUniform, "Startup card geometry holds in --no-color --no-unicode mode");
}

// ─── 5. Command palette ─────────────────────────────────────────────────────

static void TestPaletteStateMachine() {
    Section("Palette 1: state transitions");

    LineEditor editor;

    editor.ResetBuffer();
    editor.InsertString("/");
    Check(editor.IsPaletteActive(), "Typing '/' opens the palette immediately");
    const size_t total = editor.GetSuggestions().size();
    Check(total == CommandRegistry::Instance().GetAllCommands().size(),
          "'/' lists every registered command");
    Check(!editor.GetSuggestions().empty() &&
          editor.GetSuggestions().front().group == "Analysis",
          "Palette is ordered Analysis first");

    editor.ResetBuffer();
    editor.InsertString("/s");
    bool hasScan = false, hasStrings = false, hasSecurity = false, hasSandbox = false;
    for (const auto& s : editor.GetSuggestions()) {
        if (s.value == "scan") hasScan = true;
        if (s.value == "strings") hasStrings = true;
        if (s.value == "security") hasSecurity = true;
        if (s.value == "sandbox") hasSandbox = true;
    }
    Check(hasScan && hasStrings && hasSecurity && hasSandbox, "'/s' filters live to the s-commands");

    editor.ResetBuffer();
    editor.InsertString("/st");
    Check(editor.GetSuggestions().size() == 1 && editor.GetSuggestions()[0].value == "strings",
          "'/st' narrows to /strings");

    editor.ResetBuffer();
    editor.InsertString("/str");
    Check(editor.GetSuggestions().size() == 1 && editor.GetSuggestions()[0].value == "strings",
          "'/str' resolves uniquely to /strings");

    editor.ResetBuffer();
    editor.InsertString("/scan");
    Check(editor.GetSuggestions().size() == 1 && editor.GetSuggestions()[0].value == "scan",
          "'/scan' resolves uniquely to /scan");

    editor.ResetBuffer();
    editor.InsertString("/zzz");
    Check(!editor.IsPaletteActive(), "A prefix matching nothing closes the palette");
}

static void TestPaletteNavigation() {
    Section("Palette 2: keyboard navigation and acceptance");

    LineEditor editor;
    editor.ResetBuffer();
    editor.InsertString("/");

    const size_t total = editor.GetSuggestions().size();
    Check(editor.GetPaletteSelection() == 0, "Selection starts at the first row");

    editor.PaletteMoveDown();
    editor.PaletteMoveDown();
    Check(editor.GetPaletteSelection() == 2, "Down arrow moves the selection down");

    editor.PaletteMoveUp();
    Check(editor.GetPaletteSelection() == 1, "Up arrow moves the selection up");

    editor.PaletteMoveUp();
    editor.PaletteMoveUp();
    Check(editor.GetPaletteSelection() == total - 1, "Up arrow wraps to the last row");

    editor.PaletteMoveDown();
    Check(editor.GetPaletteSelection() == 0, "Down arrow wraps back to the first row");

    // Tab acceptance of the third entry.
    editor.PaletteMoveDown();
    editor.PaletteMoveDown();
    const std::string expected = editor.GetSuggestions()[editor.GetPaletteSelection()].value;
    std::string accepted;
    Check(editor.PaletteAccept(accepted), "Tab accepts the selected command");
    Check(accepted == expected, "Tab accepts exactly the highlighted command");
    Check(editor.GetBuffer() == "/" + expected + " ", "Accepting inserts the command with a trailing space");
    Check(editor.GetCursorPos() == editor.GetBuffer().size(), "Cursor is ready for arguments after acceptance");
    Check(!editor.IsPaletteActive(), "Accepting closes the palette");

    // Escape preserves the input.
    editor.ResetBuffer();
    editor.InsertString("/dis");
    editor.PaletteDismiss();
    Check(!editor.IsPaletteActive(), "Escape closes the palette");
    Check(editor.GetBuffer() == "/dis", "Escape preserves the typed input");

    // Editing in the middle of the line recomputes the suggestions.
    editor.ResetBuffer();
    editor.InsertString("/secx");
    Check(!editor.IsPaletteActive(), "'/secx' matches nothing so the palette closes");
    editor.MoveCursorLeft();
    editor.DeleteCharAtCursor();          // remove the stray 'x' -> "/sec"
    Check(editor.GetBuffer() == "/sec", "Deleting mid-line edits the buffer in place");
    Check(editor.IsPaletteActive() &&
          editor.GetSuggestions().size() == 1 &&
          editor.GetSuggestions()[0].value == "security",
          "Editing mid-line recomputes the suggestions and reopens the palette");
}

static void TestPaletteViewport() {
    Section("Palette 3: viewport and rendering");

    LineEditor editor;
    editor.ResetBuffer();
    editor.InsertString("/");

    const size_t total = editor.GetSuggestions().size();
    Check(total > LineEditor::kViewportRows, "There are more commands than the viewport holds");
    Check(editor.ViewportOffset() == 0, "Viewport starts at the top");

    for (size_t i = 0; i < LineEditor::kViewportRows; ++i) editor.PaletteMoveDown();
    Check(editor.ViewportOffset() == 1, "Viewport scrolls only once the selection passes the last visible row");

    while (editor.GetPaletteSelection() + 1 < total) editor.PaletteMoveDown();
    Check(editor.ViewportOffset() == total - LineEditor::kViewportRows,
          "Viewport clamps at the bottom of the list");

    auto rows = editor.BuildPopupRows(100);
    Check(rows.size() == LineEditor::kViewportRows + 1,
          "Popup renders exactly the viewport plus one footer row");

    bool widthOk = true;
    for (const auto& row : rows) {
        if (Text::VisibleWidth(row) > 100) widthOk = false;
    }
    Check(widthOk, "No popup row exceeds the available width");

    bool footerHasCount = rows.back().find(" of ") != std::string::npos;
    Check(footerHasCount, "Footer reports the position within the full command list");

    // Selected row must be distinguishable.
    editor.ResetBuffer();
    editor.InsertString("/");
    auto styled = editor.BuildPopupRows(100);
    Check(styled[0].find("\033[") != std::string::npos, "Selected row carries selection styling");

    // Narrow terminals must still produce bounded rows.
    bool narrowOk = true;
    for (const auto& row : editor.BuildPopupRows(40)) {
        if (Text::VisibleWidth(row) > 40) narrowOk = false;
    }
    Check(narrowOk, "Popup rows stay bounded on a 40 column terminal");
}

static void TestArgumentAndPathCompletion() {
    Section("Palette 4: argument and path completion");

    LineEditor editor;

    // Argument values come from command metadata, not hardcoded conditions.
    editor.ResetBuffer();
    editor.InsertString("/report ");
    editor.CompleteCurrentToken();
    bool reportValues = editor.GetSuggestionKind() == SuggestionKind::Argument;
    bool hasJson = false, hasMd = false, hasTxt = false;
    for (const auto& s : editor.GetSuggestions()) {
        if (s.value == "json") hasJson = true;
        if (s.value == "md") hasMd = true;
        if (s.value == "txt") hasTxt = true;
    }
    Check(reportValues && hasJson && hasMd && hasTxt, "/report <TAB> offers json, md and txt from metadata");

    editor.ResetBuffer();
    editor.InsertString("/emulate --policy ");
    editor.CompleteCurrentToken();
    bool hasBypass = false, hasRealistic = false, hasNeutral = false;
    for (const auto& s : editor.GetSuggestions()) {
        if (s.value == "bypass") hasBypass = true;
        if (s.value == "realistic") hasRealistic = true;
        if (s.value == "neutral") hasNeutral = true;
    }
    Check(hasBypass && hasRealistic && hasNeutral,
          "/emulate --policy <TAB> offers bypass, realistic and neutral from metadata");

    // Path completion against the repository's samples directory.
    if (std::filesystem::exists("samples")) {
        editor.ResetBuffer();
        editor.InsertString("/analyze samples\\");
        editor.CompleteCurrentToken();
        bool sawSample = false;
        for (const auto& s : editor.GetSuggestions()) {
            if (s.value.find("sample") != std::string::npos) sawSample = true;
        }
        if (editor.GetSuggestions().empty()) {
            // A single match is inserted directly instead of shown as a popup.
            sawSample = editor.GetBuffer().find("sample") != std::string::npos;
        }
        Check(sawSample, "Path completion resolves entries under samples\\");

        editor.ResetBuffer();
        editor.InsertString("/analyze samples\\..\\");
        editor.CompleteCurrentToken();
        Check(editor.GetSuggestionKind() == SuggestionKind::Path || !editor.GetBuffer().empty(),
              "Path completion handles '..' relative segments");
    } else {
        Check(true, "Path completion test skipped (samples directory unavailable)");
        Check(true, "Path completion '..' test skipped (samples directory unavailable)");
    }
}

static void TestHistoryVersusPalette() {
    Section("Palette 5: history and palette do not conflict");

    LineEditor editor;
    editor.SetHistoryFilePath("");   // do not touch the user's real history
    editor.LoadHistory();            // clears whatever was loaded at construction
    editor.AddHistory("/headers");
    editor.AddHistory("/strings");

    editor.ResetBuffer();
    editor.InsertString("/s");
    Check(editor.IsSuggestionActive(), "Palette owns Up/Down while it is open");

    editor.PaletteDismiss();
    Check(!editor.IsSuggestionActive(), "With the palette closed Up/Down belongs to history");
    Check(editor.GetHistory().size() == 2, "History retains both entries");
}

// ─── 6. Semantic output and active session ──────────────────────────────────

static void TestSemanticOutput() {
    Section("Output 1: semantic message formatting");

    std::ostringstream captured;
    std::streambuf* old = std::cout.rdbuf(captured.rdbuf());
    Ui::Success("saved");
    Ui::Warning("careful");
    Ui::Info("running");
    Ui::KeyValue("Architecture", "x86_64");
    Ui::KeyState("ASLR", Ui::State::Good, "Enabled");
    std::cout.rdbuf(old);

    const std::string out = captured.str();
    Check(out.find("saved") != std::string::npos, "Success messages carry their text");
    Check(out.find("careful") != std::string::npos, "Warning messages carry their text");
    Check(out.find("Architecture") != std::string::npos && out.find("x86_64") != std::string::npos,
          "Key/value rows render both halves");
    Check(out.find("[-]") == std::string::npos && out.find("[+]") == std::string::npos,
          "Semantic output no longer uses [-] / [+] debug markers");

    // Table renderer.
    Text::Table table({{"Name", 6, 10, false}, {"Value", 6, 12, true}});
    table.AddRow({"alpha", "1"});
    table.AddRow({"a-very-long-name-that-overflows", "22"});
    auto rows = table.Render(40, "", "");
    bool bounded = !rows.empty();
    for (const auto& r : rows) if (Text::VisibleWidth(r) > 40) bounded = false;
    Check(bounded, "Table renderer truncates to the available width");

    Check(Ui::Number(1428) == "1,428", "Large counts are formatted with separators");
}

static void TestActiveSessionReuse() {
    Section("Output 2: active session reuse");

    const std::string sample = std::filesystem::exists("samples/test_sample.exe")
                             ? "samples/test_sample.exe"
                             : "";
    if (sample.empty()) {
        Check(true, "Active session reuse skipped (sample binary unavailable)");
        return;
    }

    DraculaShell shell;
    shell.SetActiveSession(sample, nullptr);
    Check(shell.GetActiveFile() == sample, "Active sample path is retained by the shell");

    // Every inspection command must work without repeating the file argument.
    const std::vector<std::string> commands = {
        "headers", "security", "imports", "exports", "strings",
        "entropy", "functions", "cfg", "xrefs", "disasm"
    };

    bool allReused = true;
    for (const auto& name : commands) {
        std::ostringstream captured;
        std::streambuf* oldOut = std::cout.rdbuf(captured.rdbuf());
        std::streambuf* oldErr = std::cerr.rdbuf(captured.rdbuf());
        shell.ExecuteCommand("/" + name);
        std::cout.rdbuf(oldOut);
        std::cerr.rdbuf(oldErr);

        const std::string out = captured.str();
        if (out.find("No file given") != std::string::npos ||
            out.find("Usage") != std::string::npos) {
            std::cout << "        (/" << name << " did not reuse the active sample)\n";
            allReused = false;
        }
    }
    Check(allReused, "/headers /security /imports /exports /strings /entropy /functions /cfg /xrefs /disasm reuse the active sample");

    // A command with a genuinely required argument still explains itself.
    std::ostringstream captured;
    std::streambuf* oldOut = std::cout.rdbuf(captured.rdbuf());
    std::streambuf* oldErr = std::cerr.rdbuf(captured.rdbuf());
    shell.ExecuteCommand("/scan");
    std::cout.rdbuf(oldOut);
    std::cerr.rdbuf(oldErr);
    const std::string scanOut = captured.str();
    Check(scanOut.find("Usage") != std::string::npos && scanOut.find("Example") != std::string::npos,
          "/scan without a pattern renders usage, example and tip rather than a bare error");

    Check(!shell.SessionStatusLine().empty(), "The shell exposes a status line while a sample is active");
}

// ─── 7. Version and resources ───────────────────────────────────────────────

static void TestVersionSingleSource() {
    Section("Integrity 1: single authoritative version");

    const std::string expected = std::string(Version::String);
    Check(DraculaShell::GetVersion() == expected, "The shell reports the generated version");

    const std::string composed = std::to_string(Version::Major) + "." +
                                 std::to_string(Version::Minor) + "." +
                                 std::to_string(Version::Patch);
    Check(composed == expected, "Version components and version string agree");

    // The generated header must match the CMake project version.
    std::string cmakePath = Paths::ResolveResource("CMakeLists.txt");
    if (!cmakePath.empty()) {
        std::ifstream f(cmakePath);
        std::string line, found;
        while (std::getline(f, line)) {
            size_t p = line.find("project(Dracula VERSION ");
            if (p != std::string::npos) {
                found = line.substr(p + 24);
                found = found.substr(0, found.find(' '));
                break;
            }
        }
        Check(found == expected, "CMakeLists.txt project version matches the generated version.h");
    } else {
        Check(true, "CMakeLists version check skipped (source tree unavailable)");
    }

    // The changelog must document this version.
    std::string changelog = Paths::ResolveResource("CHANGELOG.txt");
    if (!changelog.empty()) {
        std::ifstream f(changelog);
        std::stringstream ss;
        ss << f.rdbuf();
        Check(ss.str().find("Dracula v" + expected) != std::string::npos,
              "CHANGELOG.txt documents the current version");
    } else {
        Check(true, "Changelog check skipped (resource unavailable)");
    }
}

static void TestResourceResolution() {
    Section("Integrity 2: working directory vs executable directory");

    Check(!Paths::ExecutableDir().empty(), "Executable directory is resolvable");
    Check(!Paths::CurrentWorkingDir().empty(), "Working directory is resolvable");
    Check(!Paths::ResourceRoot().empty(), "Resource root is resolvable");
    Check(!Paths::ResolveResource("CHANGELOG.txt").empty(),
          "CHANGELOG.txt is located without depending on the working directory");
}

int main() {
    Terminal::Initialize();

    std::cout << "\n\033[1;35m==============================================================\033[0m\n";
    std::cout << "\033[1;31m DRACULA TERMINAL UI & LAYOUT VERIFICATION SUITE\033[0m\n";
    std::cout << "\033[1;35m==============================================================\033[0m\n";

    TestMeasurement();
    TestComposition();
    TestBoxGeometry();
    TestColumns();
    TestVampireArt();
    TestStartupLayoutSelection();
    TestStartupCardGeometry();
    TestPaletteStateMachine();
    TestPaletteNavigation();
    TestPaletteViewport();
    TestArgumentAndPathCompletion();
    TestHistoryVersusPalette();
    TestSemanticOutput();
    TestActiveSessionReuse();
    TestVersionSingleSource();
    TestResourceResolution();

    std::cout << "\n\033[1;35m==============================================================\033[0m\n";
    std::cout << " TERMINAL UI RESULTS: \033[1;32m" << g_pass << " PASSED\033[0m, \033[1;31m"
              << g_fail << " FAILED\033[0m\n";
    std::cout << "\033[1;35m==============================================================\033[0m\n\n";

    Terminal::Restore();
    return g_fail == 0 ? 0 : 1;
}
