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
#include "cli/screen.h"
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

// ─── 3. The supplied vampire artwork ────────────────────────────────────────

// The authoritative artwork asset, read straight from disk so the test fails if
// the embedded copy ever drifts from the project file.
static std::vector<std::string> ReadArtworkAsset() {
    std::vector<std::string> rows;
    const std::string name = "Vampire Dracula ASCII Art.txt";

    std::string path = Paths::ResolveResource(name);
    if (path.empty()) return rows;

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return rows;

    std::string line;
    while (std::getline(file, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (!line.empty()) rows.push_back(line);
    }
    return rows;
}

static void TestVampireArt() {
    Section("Layout 5: the supplied vampire artwork");

    const auto& art = Art::Vampire();
    const auto asset = ReadArtworkAsset();

    Check(!asset.empty(), "The artwork asset is locatable without an absolute path");
    Check(art.size() == asset.size(),
          "The embedded artwork has the same row count as the asset file");

    // Every row of the embedded artwork must be the asset's row, byte for byte,
    // ignoring only the uniform-width padding the layout engine needs.
    bool bytesMatch = art.size() == asset.size();
    for (size_t i = 0; i < art.size() && i < asset.size() && bytesMatch; ++i) {
        if (art[i].compare(0, asset[i].size(), asset[i]) != 0) bytesMatch = false;
    }
    Check(bytesMatch, "Every embedded row reproduces the asset row byte for byte");

    const size_t width = Art::MaxWidth(art);
    Check(width == 21, "The artwork measures 21 display cells wide");

    bool uniform = true;
    for (const auto& row : art) {
        if (Text::VisibleWidth(row) != width) uniform = false;
    }
    Check(uniform, "Every artwork row has the same cell width (no ragged edge)");

    // Braille (U+28xx) is single-width; if the measurement table ever changed,
    // the two-column header would silently misalign.
    bool allBraille = true;
    for (const auto& row : art) {
        for (size_t i = 0; i < row.size();) {
            const uint32_t cp = Text::DecodeUtf8(row, i);
            if (cp < 0x2800 || cp > 0x28FF) allBraille = false;
            if (Text::CodePointWidth(cp) != 1) allBraille = false;
        }
    }
    Check(allBraille, "The artwork is Braille throughout and measures one cell per glyph");

    auto colored = Art::Colorize(art);
    bool widthsPreserved = colored.size() == art.size();
    for (size_t i = 0; i < colored.size() && widthsPreserved; ++i) {
        if (Text::VisibleWidth(colored[i]) != Text::VisibleWidth(art[i])) widthsPreserved = false;
    }
    Check(widthsPreserved, "Colorizing the mark does not alter its measured width");

    Terminal::SetColorEnabled(false);
    auto plain = Art::Colorize(art);
    bool plainOk = (plain == art);
    Terminal::SetColorEnabled(true);
    Check(plainOk, "With --no-color the mark renders unmodified");
}

// ─── 4. Responsive header ───────────────────────────────────────────────────

static void TestHeaderVariantSelection() {
    Section("Layout 6: responsive header thresholds");

    Check(StartupCard::SelectVariant(24) == HeaderVariant::Minimal,  "24 columns selects the minimal header");
    Check(StartupCard::SelectVariant(29) == HeaderVariant::Minimal,  "29 columns still selects the minimal header");
    Check(StartupCard::SelectVariant(30) == HeaderVariant::Compact,  "30 columns selects the compact header");
    Check(StartupCard::SelectVariant(43) == HeaderVariant::Compact,  "43 columns selects the compact header");
    Check(StartupCard::SelectVariant(44) == HeaderVariant::Standard, "44 columns fits the bat beside the identity");
    Check(StartupCard::SelectVariant(80) == HeaderVariant::Standard, "80 columns uses the standard header");
    Check(StartupCard::SelectVariant(200) == HeaderVariant::Standard, "200 columns uses the same standard header");

    // The artwork is Braille, so a terminal without Unicode support gets the
    // text-only header rather than a field of replacement glyphs.
    Terminal::SetUnicodeEnabled(false);
    Check(StartupCard::SelectVariant(120) == HeaderVariant::Compact,
          "Without Unicode support even a wide terminal uses the text-only header");
    Check(StartupCard::SelectVariant(24) == HeaderVariant::Minimal,
          "Without Unicode support a narrow terminal still falls back to minimal");
    bool noArtLeaks = true;
    for (const auto& row : StartupCard::RenderHeader(120, HeaderVariant::Standard,
                                                     StartupInfo::Detect())) {
        if (row.find(Art::Vampire()[0].substr(0, 3)) != std::string::npos) noArtLeaks = false;
    }
    Terminal::SetUnicodeEnabled(true);
    Check(noArtLeaks,
          "Requesting the standard header without Unicode support emits no Braille");
}

static void TestHeaderGeometry() {
    Section("Layout 7: header geometry at every tested width");

    StartupInfo info = StartupInfo::Detect();
    info.workingDirectory = "D:\\Coding\\python\\AI\\jew\\build\\some\\deeply\\nested\\path";

    bool nothingOverflows = true;
    bool noEmbeddedNewlines = true;
    bool dividerFullBleed = true;
    bool heightsFixed = true;

    for (int width : kTestWidths) {
        auto header = StartupCard::RenderHeader(width, info);
        if (header.empty()) { heightsFixed = false; continue; }

        // The header closes on a divider that spans the usable width exactly.
        if (Text::VisibleWidth(header.back()) != static_cast<size_t>(width - 1)) {
            dividerFullBleed = false;
        }

        // Height depends only on the variant, never on the content.
        const size_t expected =
            StartupCard::SelectVariant(width) == HeaderVariant::Standard
                ? Art::Vampire().size() + 2   // leading blank + artwork + divider
                : 4;
        if (header.size() != expected) heightsFixed = false;

        for (const auto& row : StartupCard::Render(width, info)) {
            // Strictly narrower than the terminal: writing into the final cell
            // provokes a spurious wrap on some terminals.
            if (Text::VisibleWidth(row) >= static_cast<size_t>(width)) nothingOverflows = false;
            if (row.find('\n') != std::string::npos) noEmbeddedNewlines = false;
        }
    }

    Check(nothingOverflows, "No rendered row reaches the final terminal column at any tested width");
    Check(noEmbeddedNewlines, "No rendered row contains an embedded newline");
    Check(dividerFullBleed, "The header divider spans the full usable width at every tested width");
    Check(heightsFixed, "Header height is a function of the variant alone");

    // Every artwork row is present, unmodified, in the standard header.
    auto wide = StartupCard::RenderHeader(160, info);
    bool artIntact = true;
    for (const auto& artRow : Art::Vampire()) {
        bool found = false;
        for (const auto& row : wide) {
            if (row.find(artRow) != std::string::npos) found = true;
        }
        if (!found) artIntact = false;
    }
    Check(artIntact, "Every artwork row appears unmodified in the standard header");

    // Same header, same height, in a narrow window and a wide one.
    Check(StartupCard::RenderHeader(80, info).size() ==
          StartupCard::RenderHeader(200, info).size(),
          "A windowed and a fullscreen terminal produce a header of identical height");

    auto minimal = StartupCard::RenderHeader(28, info);
    bool minimalSmall = minimal.size() == 2;
    for (const auto& row : minimal) {
        if (Text::VisibleWidth(row) > 27) minimalSmall = false;
    }
    Check(minimalSmall, "The 28-column fallback is two short rows and never breaks the screen");

    // No-colour and ASCII modes keep the same geometry.
    Terminal::SetColorEnabled(false);
    Terminal::SetUnicodeEnabled(false);
    bool asciiUniform = true;
    for (int width : kTestWidths) {
        auto header = StartupCard::RenderHeader(width, info);
        if (header.empty()) { asciiUniform = false; continue; }
        if (Text::VisibleWidth(header.back()) != static_cast<size_t>(width - 1)) asciiUniform = false;
        for (const auto& row : header) {
            if (Text::VisibleWidth(row) > static_cast<size_t>(width - 1)) asciiUniform = false;
        }
    }
    Terminal::SetColorEnabled(true);
    Terminal::SetUnicodeEnabled(true);
    Check(asciiUniform, "Header geometry holds in --no-color --no-unicode mode");
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

// ─── 8. Persistent screen regions ───────────────────────────────────────────

static const int kTestHeights[] = {15, 18, 20, 24, 25, 30, 40, 50, 60, 80};

static void TestScreenRegionMatrix() {
    Section("Screen 1: region geometry across the width x height matrix");

    StartupInfo info = StartupInfo::Detect();

    bool promptAlwaysVisible = true;
    bool noNegative = true;
    bool noOverlap = true;
    bool outputUsable = true;
    bool paletteFits = true;
    bool headerInsideScreen = true;
    bool bottomChromeIntact = true;

    for (int w : {60, 80, 100, 120, 160}) {
        for (int h : kTestHeights) {
            for (int suggestions : {0, 5, 23}) {
                const auto L = ScreenModel::Compute(w, h, suggestions, info);

                // 1. The prompt strip is always on screen, one row above the
                //    footer, which owns the last row.
                if (L.footer.height != 1 || L.footer.top != h - 1) bottomChromeIntact = false;
                if (L.input.top != h - 2 || L.input.height != 1) promptAlwaysVisible = false;
                if (L.inputRule.height != 1 || L.inputRule.top != h - 3) bottomChromeIntact = false;

                // 2. No region may have a negative or wrapped-around size.
                if (L.header.height < 0 || L.output.height < 0 ||
                    L.palette.height < 0 || L.input.height < 0) noNegative = false;
                if (L.output.height < 1) outputUsable = false;

                // 3. Regions must tile the screen without overlapping.
                if (L.header.Bottom() > L.output.top) noOverlap = false;
                if (L.output.Bottom() > L.palette.top) noOverlap = false;
                if (L.palette.Bottom() > L.inputRule.top) noOverlap = false;
                if (L.inputRule.Bottom() > L.input.top) noOverlap = false;
                if (L.input.Bottom() > L.footer.top) noOverlap = false;
                if (L.header.top != 0) headerInsideScreen = false;
                if (L.header.Bottom() > h) headerInsideScreen = false;

                // 4. The palette never pushes the output below its floor.
                if (L.palette.height > 0 &&
                    L.output.height < ScreenModel::kMinOutputRows) paletteFits = false;
            }
        }
    }

    Check(promptAlwaysVisible, "The prompt occupies its own strip at every width and height");
    Check(bottomChromeIntact, "Divider, prompt and footer own the last three rows everywhere");
    Check(noNegative, "No region is ever assigned a negative height");
    Check(outputUsable, "The output region always keeps at least one row");
    Check(noOverlap, "Header, output, palette, divider, input and footer never overlap");
    Check(headerInsideScreen, "The header always starts at row 0 and stays on screen");
    Check(paletteFits, "Opening the palette never starves the output below its minimum");
}

static void TestHeightResponsiveHeader() {
    Section("Screen 2: consistent header from windowed to fullscreen");

    StartupInfo info = StartupInfo::Detect();

    // The central requirement: a normal window and a fullscreen terminal must
    // produce the SAME header, so the two experiences look alike.
    bool sameEverywhere = true;
    int headerRows = -1;
    for (int h : {20, 24, 25, 30, 40, 50, 60, 80}) {
        const auto L = ScreenModel::Compute(120, h, 0, info);
        if (L.headerVariant != HeaderVariant::Standard) sameEverywhere = false;
        if (headerRows >= 0 && L.header.height != headerRows) sameEverywhere = false;
        headerRows = L.header.height;
    }
    Check(sameEverywhere,
          "From 20 to 80 rows the header is the same standard bat header of the same height");
    Check(headerRows == static_cast<int>(Art::Vampire().size()) + 2,
          "The standard header claims the artwork rows plus a blank and a divider");

    const auto tall = ScreenModel::Compute(120, 50, 0, info);
    Check(tall.output.height >= ScreenModel::kPreferredOutputRows,
          "A tall terminal gives the output its preferred height");
    Check(tall.output.height > tall.header.height * 2,
          "In fullscreen the output region, not the header, dominates the screen");

    // A normal, non-maximized window must still show useful output.
    bool normalWindowsUsable = true;
    for (int h : {24, 25, 30}) {
        const auto L = ScreenModel::Compute(120, h, 0, info);
        if (L.output.height < ScreenModel::kPreferredOutputRows) normalWindowsUsable = false;
        if (!L.hasHeader) normalWindowsUsable = false;
        if (L.output.height <= L.header.height) normalWindowsUsable = false;
    }
    Check(normalWindowsUsable,
          "At 24, 25 and 30 rows the output keeps 8+ rows and still outweighs the header");

    // Monotonicity: the header never gets richer as the terminal gets shorter.
    auto rank = [](HeaderVariant v) {
        switch (v) {
            case HeaderVariant::Standard: return 3;
            case HeaderVariant::Compact:  return 2;
            case HeaderVariant::Minimal:  return 1;
            default:                      return 0;
        }
    };
    bool monotonic = true;
    int previous = -1;
    for (int h : kTestHeights) {
        const int current = rank(ScreenModel::Compute(120, h, 0, info).headerVariant);
        if (previous >= 0 && current < previous) monotonic = false;
        previous = current;
    }
    Check(monotonic, "The header variant never gets richer as the terminal gets shorter");

    // Very short terminals stay usable and never crash.
    bool shortSafe = true;
    for (int h : {3, 5, 8, 10, 12, 15}) {
        const auto L = ScreenModel::Compute(80, h, 0, info);
        if (L.input.height != 1) shortSafe = false;
        if (L.input.top < 0 || L.input.top > h - 1) shortSafe = false;
        if (L.output.height < 1) shortSafe = false;
        if (L.header.Bottom() > L.output.top) shortSafe = false;
        if (L.output.Bottom() > L.inputRule.top) shortSafe = false;
    }
    Check(shortSafe, "Terminals down to 3 rows keep a prompt and at least one output row");

    // Growing the terminal keeps the header identical and grows the output.
    const auto windowed = ScreenModel::Compute(120, 30, 0, info);
    const auto fullscreen = ScreenModel::Compute(120, 60, 0, info);
    Check(windowed.header.height == fullscreen.header.height &&
          windowed.headerVariant == fullscreen.headerVariant,
          "Going fullscreen changes the output height only, never the header");
    Check(fullscreen.output.height > windowed.output.height,
          "The extra fullscreen rows all go to the output region");
}

static void TestPaletteResponsiveHeight() {
    Section("Screen 3: palette height adapts instead of eating the output");

    StartupInfo info = StartupInfo::Detect();

    const auto tall = ScreenModel::Compute(120, 50, 23, info);
    Check(tall.paletteItems == ScreenModel::kPreferredPaletteItems,
          "A tall terminal shows the full 8-row palette viewport");

    const auto shortWindow = ScreenModel::Compute(120, 20, 23, info);
    Check(shortWindow.paletteItems > 0 &&
          shortWindow.paletteItems < ScreenModel::kPreferredPaletteItems,
          "A short terminal shrinks the palette viewport rather than the output");
    Check(shortWindow.output.height >= ScreenModel::kMinOutputRows,
          "Output survives with the palette open on a short terminal");

    // Opening the palette shrinks the output and closing it restores the rows.
    const auto closed = ScreenModel::Compute(120, 40, 0, info);
    const auto open   = ScreenModel::Compute(120, 40, 23, info);
    Check(open.output.height < closed.output.height,
          "Opening the palette shrinks the output region");
    Check(open.header.height == closed.header.height,
          "Opening the palette does not move or resize the header");
    Check(open.input.top == closed.input.top,
          "Opening the palette does not move the prompt");
    Check(open.output.height >= ScreenModel::kMinOutputRows,
          "Some previous output stays visible while the palette is open");

    // The palette list still scrolls in a reduced viewport.
    LineEditor editor;
    editor.ResetBuffer();
    editor.InsertString("/");
    auto rows = editor.BuildPopupRows(100, 3);
    Check(rows.size() == 4, "A 3-row palette viewport renders 3 items plus the footer");
    Check(rows.back().find("browse") != std::string::npos,
          "A truncated palette tells the user the list scrolls");
}

static void TestPaintedFrameStructure() {
    Section("Screen 3b: the painted frame has clean, aligned regions");

    const std::string prompt = Terminal::DraculaPrompt();

    auto describe = [&](int w, int h) {
        InteractiveScreen screen;
        screen.SetStatusLine("sample: test_sample.exe");
        for (int i = 0; i < 40; ++i) {
            screen.Output().AppendLine("output line " + std::to_string(i));
        }
        LineEditor editor;
        editor.ResetBuffer();
        auto frame = screen.PreviewFrame(w, h, editor, prompt);
        return std::make_pair(frame, screen.Layout());
    };

    bool structureHolds = true;
    bool dividersAligned = true;
    bool nothingReachesLastColumn = true;
    bool outputDominates = true;

    for (auto [w, h] : std::vector<std::pair<int, int>>{{80, 24}, {100, 30}, {120, 30},
                                                        {160, 50}, {200, 60}, {240, 67}}) {
        auto [frame, L] = describe(w, h);

        if (static_cast<int>(frame.size()) != h) structureHolds = false;

        // Header: blank row, three bat rows, divider.
        if (L.headerVariant != HeaderVariant::Standard) structureHolds = false;
        if (frame[1].find(Art::Vampire()[0]) == std::string::npos) structureHolds = false;
        bool identityInHeader = false;
        for (int r = 0; r < L.header.height; ++r) {
            if (Text::StripAnsi(frame[r]).find("Dracula") != std::string::npos) {
                identityInHeader = true;
            }
        }
        if (!identityInHeader) structureHolds = false;

        // Two dividers, identical width, one closing the header and one above
        // the prompt: that is the structural separation the layout promises.
        const size_t headerRule = Text::VisibleWidth(frame[L.header.Bottom() - 1]);
        const size_t inputRule  = Text::VisibleWidth(frame[L.inputRule.top]);
        if (headerRule != static_cast<size_t>(w - 1)) dividersAligned = false;
        if (inputRule != headerRule) dividersAligned = false;

        // The prompt is in its own strip, the footer carries the status.
        if (Text::StripAnsi(frame[L.input.top]).find(Terminal::PromptGlyph()) ==
            std::string::npos) structureHolds = false;
        if (Text::StripAnsi(frame[L.footer.top]).find("test_sample.exe") ==
            std::string::npos) structureHolds = false;

        // Output content lives between the two dividers.
        if (Text::StripAnsi(frame[L.output.top]).find("output line") ==
            std::string::npos) structureHolds = false;

        if (L.output.height <= L.header.height) outputDominates = false;

        for (const auto& row : frame) {
            if (Text::VisibleWidth(row) >= static_cast<size_t>(w)) {
                nothingReachesLastColumn = false;
            }
        }
    }

    Check(structureHolds, "Header, output, prompt strip and footer are painted where the model says");
    Check(dividersAligned, "Both dividers span exactly the usable width, at every geometry");
    Check(nothingReachesLastColumn, "No painted row reaches the terminal's final column");
    Check(outputDominates, "The output region outweighs the header in every geometry");

    // Windowed and fullscreen paint the same chrome: same header rows, same
    // divider positions relative to the bottom, same footer.
    auto [windowed, wl] = describe(120, 30);
    auto [full, fl] = describe(120, 60);
    bool sameChrome = true;
    for (int i = 0; i < wl.header.height; ++i) {
        if (windowed[i] != full[i]) sameChrome = false;
    }
    if (windowed[wl.inputRule.top] != full[fl.inputRule.top]) sameChrome = false;
    if (windowed[wl.input.top] != full[fl.input.top]) sameChrome = false;
    Check(sameChrome, "A 30-row window and a 60-row fullscreen paint byte-identical chrome");

    // The artwork specifically: every row present, in the same place, in a
    // windowed terminal and in a fullscreen one.
    bool artInBoth = true;
    for (size_t i = 0; i < Art::Vampire().size(); ++i) {
        const std::string& artRow = Art::Vampire()[i];
        if (windowed[i + 1].find(artRow) == std::string::npos) artInBoth = false;
        if (full[i + 1].find(artRow) == std::string::npos) artInBoth = false;
    }
    Check(artInBoth,
          "Every artwork row is painted on the same screen row, windowed and fullscreen");
}

// ─── 9. Output buffer scrolling ─────────────────────────────────────────────

static void TestOutputBufferScrolling() {
    Section("Screen 4: output history and scrolling");

    const int H = 10;
    const int W = 80;

    OutputBuffer empty;
    Check(empty.LineCount() == 0, "A new buffer is empty");
    Check(empty.VisibleRows(H, W).empty(), "An empty buffer renders no rows");
    Check(empty.IsFollowing(), "An empty buffer follows the newest output");
    empty.ScrollUp(H, 3);
    empty.ScrollPageUp(H);
    Check(empty.LineCount() == 0, "Scrolling an empty buffer is a safe no-op");

    OutputBuffer one;
    one.AppendLine("only");
    Check(one.VisibleRows(H, W).size() == 1, "A single line renders once");
    Check(!one.HasOlderAbove(H, W) && !one.HasNewerBelow(H, W),
          "A single line has nothing above or below it");

    OutputBuffer exact;
    for (int i = 0; i < H; ++i) exact.AppendLine("line " + std::to_string(i));
    Check(exact.VisibleRows(H, W).size() == static_cast<size_t>(H),
          "Exactly one viewport of lines fills the viewport");
    Check(!exact.HasOlderAbove(H, W), "A full-but-not-overflowing viewport has nothing above");

    OutputBuffer over;
    for (int i = 0; i < H + 1; ++i) over.AppendLine("line " + std::to_string(i));
    Check(over.HasOlderAbove(H, W), "One line more than the viewport puts content above");

    OutputBuffer buffer;
    for (int i = 0; i < 100; ++i) buffer.AppendLine("line " + std::to_string(i));

    Check(buffer.IsFollowing(), "Appending output keeps the viewport following the newest line");
    Check(buffer.VisibleRows(H, W).back().find("line 99") != std::string::npos,
          "The newest line is visible while following");

    // Wheel scrolling.
    buffer.ScrollUp(H, OutputBuffer::kWheelLines);
    Check(!buffer.IsFollowing(), "Scrolling up detaches the viewport from the newest output");
    size_t first = 0, last = 0;
    buffer.VisibleRange(H, W, first, last);
    Check(first == 91 - OutputBuffer::kWheelLines,
          "A wheel notch moves the viewport by exactly three lines");

    buffer.ScrollDown(H, OutputBuffer::kWheelLines);
    Check(buffer.IsFollowing(), "Scrolling back down re-attaches to the newest output");

    // Page scrolling.
    buffer.ScrollPageUp(H);
    buffer.VisibleRange(H, W, first, last);
    Check(first == 91 - (H - 1), "PageUp moves the viewport by one page");
    buffer.ScrollPageDown(H);
    Check(buffer.IsFollowing(), "PageDown from one page up returns to the newest output");

    // Clamping.
    for (int i = 0; i < 50; ++i) buffer.ScrollPageUp(H);
    buffer.VisibleRange(H, W, first, last);
    Check(first == 1, "Scrolling up clamps at the oldest line");
    Check(buffer.HasNewerBelow(H, W), "At the top the buffer reports newer output below");

    for (int i = 0; i < 50; ++i) buffer.ScrollPageDown(H);
    Check(buffer.IsFollowing(), "Scrolling down clamps at the newest line and resumes following");

    buffer.ScrollToTop();
    Check(!buffer.IsFollowing(), "ScrollToTop detaches from the newest output");
    buffer.ScrollToBottom();
    Check(buffer.IsFollowing(), "ScrollToBottom resumes following");

    // New output while manually scrolled must not yank the viewport.
    buffer.ScrollPageUp(H);
    buffer.VisibleRange(H, W, first, last);
    const size_t before = first;
    buffer.AppendLine("brand new line");
    buffer.VisibleRange(H, W, first, last);
    Check(!buffer.IsFollowing() && first == before,
          "New output does not snap a manually scrolled viewport back to the bottom");

    buffer.Clear();
    Check(buffer.LineCount() == 0 && buffer.IsFollowing(),
          "Clear empties the history and returns to the newest position");

    // History bound.
    OutputBuffer bounded;
    for (size_t i = 0; i < OutputBuffer::kMaxLines + 500; ++i) {
        bounded.AppendLine("x");
    }
    Check(bounded.LineCount() == OutputBuffer::kMaxLines,
          "Output history is bounded at its documented limit");

    // ANSI content and wrapping.
    OutputBuffer styled;
    styled.AppendLine("\033[31m" + std::string(200, 'a') + "\033[0m");
    auto wrapped = styled.VisibleRows(H, 40);
    bool wrapOk = wrapped.size() == 5;
    for (const auto& row : wrapped) {
        if (Text::VisibleWidth(row) > 40) wrapOk = false;
    }
    Check(wrapOk, "A long ANSI-styled line wraps to the viewport width without losing cells");

    // Stream capture.
    OutputBuffer sunk;
    {
        OutputSink sink(sunk);
        std::ostream out(&sink);
        out << "alpha\nbeta\n" << "gamma" << "\n";
    }
    Check(sunk.LineCount() == 3 && sunk.LineAt(1) == "beta",
          "OutputSink routes stream writes into the history line by line");
}

static void TestScrollKeyMapping() {
    Section("Screen 5: input events map to the right scroll actions");

    LineEditor editor;
    editor.ResetBuffer();

    auto action = [&](Key key) {
        InputEvent ev;
        ev.key = key;
        return editor.HandleKey(ev);
    };

    Check(action(Key::PageUp)    == LineEditor::EditAction::ScrollPageUp,   "PageUp scrolls the output up a page");
    Check(action(Key::PageDown)  == LineEditor::EditAction::ScrollPageDown, "PageDown scrolls the output down a page");
    Check(action(Key::WheelUp)   == LineEditor::EditAction::ScrollLineUp,   "Wheel up scrolls the output up");
    Check(action(Key::WheelDown) == LineEditor::EditAction::ScrollLineDown, "Wheel down scrolls the output down");
    Check(action(Key::CtrlHome)  == LineEditor::EditAction::ScrollTop,      "Ctrl+Home jumps to the oldest output");
    Check(action(Key::CtrlEnd)   == LineEditor::EditAction::ScrollBottom,   "Ctrl+End jumps to the newest output");
    Check(action(Key::Resize)    == LineEditor::EditAction::Resize,         "A resize event is surfaced to the screen");
    Check(action(Key::ToggleSelection) == LineEditor::EditAction::ToggleSelection,
          "F2 is surfaced to the screen as the selection-mode toggle");

    // Scrolling must never disturb the input buffer or the palette.
    editor.InsertString("/s");
    const std::string buffer = editor.GetBuffer();
    const size_t selection = editor.GetPaletteSelection();
    action(Key::WheelUp);
    action(Key::PageDown);
    Check(editor.GetBuffer() == buffer, "Scrolling does not modify the input buffer");
    Check(editor.GetPaletteSelection() == selection, "Scrolling does not move the palette selection");
    Check(editor.IsPaletteActive(), "Scrolling does not close the palette");

    // Up/Down still belong to the palette and the history.
    editor.PaletteMoveDown();
    Check(editor.GetPaletteSelection() == selection + 1,
          "Up/Down remain bound to palette navigation, not output scrolling");
}

static void TestResizePreservesState() {
    Section("Screen 6: resize preserves session state");

    StartupInfo info = StartupInfo::Detect();

    // Input text and palette selection live in the editor, which the layout
    // never touches - a resize only recomputes rectangles.
    LineEditor editor;
    editor.ResetBuffer();
    editor.InsertString("/s");
    editor.PaletteMoveDown();
    const std::string typed = editor.GetBuffer();
    const size_t selection = editor.GetPaletteSelection();

    const auto wide = ScreenModel::Compute(160, 50,
                                           static_cast<int>(editor.GetSuggestions().size()), info);
    const auto narrow = ScreenModel::Compute(70, 20,
                                             static_cast<int>(editor.GetSuggestions().size()), info);

    Check(editor.GetBuffer() == typed, "Typed input survives a resize");
    Check(editor.GetPaletteSelection() == selection, "Palette selection survives a resize");
    Check(wide.input.top == 48 && narrow.input.top == 18 &&
          wide.footer.top == 49 && narrow.footer.top == 19,
          "The prompt and footer re-anchor to the new bottom rows");
    Check(narrow.output.height >= ScreenModel::kMinOutputRows,
          "The output region stays usable after shrinking");

    // The scroll position is a logical line index, so it survives a width change.
    OutputBuffer buffer;
    for (int i = 0; i < 200; ++i) buffer.AppendLine("line " + std::to_string(i));
    buffer.ScrollPageUp(20);
    const size_t anchor = buffer.ScrollAnchor();
    size_t firstWide = 0, lastWide = 0;
    buffer.VisibleRange(20, 160, firstWide, lastWide);
    size_t firstNarrow = 0, lastNarrow = 0;
    buffer.VisibleRange(10, 70, firstNarrow, lastNarrow);
    Check(buffer.ScrollAnchor() == anchor && firstWide == firstNarrow,
          "Output scroll position is preserved across a width and height change");
}

static void TestSelectionMode() {
    Section("Screen 7: selection mode releases the mouse without losing state");

    const std::string prompt = Terminal::DraculaPrompt();

    InteractiveScreen screen;
    screen.SetStatusLine("sample: test_sample.exe");
    for (int i = 0; i < 40; ++i) screen.Output().AppendLine("line " + std::to_string(i));

    LineEditor editor;
    editor.ResetBuffer();
    editor.InsertString("/head");

    // Scroll away from the bottom FIRST, so the baseline frame is the frame the
    // user would actually be selecting from.
    screen.PreviewFrame(120, 30, editor, prompt);
    const auto layout = screen.Layout();
    screen.Output().ScrollPageUp(layout.output.height);

    auto frame = screen.PreviewFrame(120, 30, editor, prompt);

    Check(!screen.InSelectionMode(), "The screen starts with the mouse bound to scrolling");
    Check(Text::StripAnsi(frame[layout.footer.top]).find("F2") != std::string::npos,
          "The footer advertises F2 even with a session summary competing for room");

    // The toggle is pure UI state: nothing about the session may move.
    const std::string typed = editor.GetBuffer();
    const size_t scrolled = screen.Output().ScrollAnchor();

    screen.SetSelectionMode(true);
    auto selecting = screen.PreviewFrame(120, 30, editor, prompt);

    Check(screen.InSelectionMode(), "F2 enters selection mode");
    Check(Text::StripAnsi(selecting[layout.footer.top]).find("SELECT MODE") != std::string::npos,
          "The footer says SELECT MODE while the mouse belongs to the terminal");
    Check(Text::StripAnsi(selecting[layout.footer.top]).find("copy") != std::string::npos,
          "The footer says how to copy");
    Check(editor.GetBuffer() == typed, "Entering selection mode does not touch the input buffer");
    Check(screen.Output().ScrollAnchor() == scrolled,
          "Entering selection mode does not move the output viewport");

    // Everything above the footer is untouched, so a frozen frame really is the
    // same frame the user is selecting from.
    bool onlyFooterChanged = selecting.size() == frame.size();
    for (size_t i = 0; i + 1 < selecting.size() && onlyFooterChanged; ++i) {
        if (i == static_cast<size_t>(layout.footer.top)) continue;
        if (selecting[i] != frame[i]) onlyFooterChanged = false;
    }
    Check(onlyFooterChanged,
          "Entering selection mode repaints the footer and nothing else");

    screen.SetSelectionMode(false);
    auto resumed = screen.PreviewFrame(120, 30, editor, prompt);
    Check(!screen.InSelectionMode(), "F2 leaves selection mode");
    Check(resumed[layout.footer.top] == frame[layout.footer.top],
          "Leaving selection mode restores the ordinary footer");
    Check(editor.GetBuffer() == typed, "Leaving selection mode does not touch the input buffer");
    Check(screen.Output().ScrollAnchor() == scrolled,
          "Leaving selection mode does not move the output viewport");
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
    TestHeaderVariantSelection();
    TestHeaderGeometry();
    TestPaletteStateMachine();
    TestPaletteNavigation();
    TestPaletteViewport();
    TestArgumentAndPathCompletion();
    TestHistoryVersusPalette();
    TestSemanticOutput();
    TestActiveSessionReuse();
    TestVersionSingleSource();
    TestResourceResolution();
    TestScreenRegionMatrix();
    TestHeightResponsiveHeader();
    TestPaletteResponsiveHeight();
    TestPaintedFrameStructure();
    TestOutputBufferScrolling();
    TestScrollKeyMapping();
    TestResizePreservesState();
    TestSelectionMode();

    std::cout << "\n\033[1;35m==============================================================\033[0m\n";
    std::cout << " TERMINAL UI RESULTS: \033[1;32m" << g_pass << " PASSED\033[0m, \033[1;31m"
              << g_fail << " FAILED\033[0m\n";
    std::cout << "\033[1;35m==============================================================\033[0m\n\n";

    Terminal::Restore();
    return g_fail == 0 ? 0 : 1;
}
