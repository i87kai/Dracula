#pragma once

//
// Self-contained HTML report generation for project artifacts.
//
// Large tabular analysis output (memory maps with thousands of regions,
// twenty thousand functions, export tables) must not be dumped into the
// terminal. It is written here instead, as a standalone HTML file inside the
// project (section 21).
//
// Constraints:
//   * no external CDN, font or script dependency -- CSS and JS are inlined
//   * search, sort and filter work offline
//   * addresses render monospace; evidence levels render as badges
//
// This is STATIC project reporting. It is NOT the future Local Web GUI.
//

#include <string>
#include <vector>
#include <cstdint>

namespace Dracula {
namespace App {

    class HtmlReport {
    public:
        enum class Align { Left, Right };

        struct Column {
            std::string title;
            Align       align = Align::Left;
            bool        monospace = false;
            bool        numeric = false;   // sort numerically rather than lexically
        };

        // A cell may carry a badge class ("static", "resolved", "live",
        // "warn", "error", "ok") which renders as a coloured pill.
        struct Cell {
            std::string text;
            std::string badge;
        };

        HtmlReport(const std::string& title, const std::string& subtitle = "");

        // Key/value facts rendered above the table (region counts, totals).
        void AddSummary(const std::string& label, const std::string& value);

        // A free-text note, e.g. a truncation reason.
        void AddNote(const std::string& note);

        void SetColumns(const std::vector<Column>& columns);
        void AddRow(const std::vector<Cell>& cells);
        void AddRow(const std::vector<std::string>& cells);

        size_t RowCount() const { return m_rows.size(); }

        std::string Render() const;

        // Renders and writes atomically. Returns false with `error` set on
        // failure; the caller keeps the path either way so a failed auto-open
        // never invalidates a successfully generated report.
        bool Write(const std::string& path, std::string& error) const;

        static std::string EscapeHtml(const std::string& s);

    private:
        std::string m_title;
        std::string m_subtitle;
        std::vector<std::pair<std::string, std::string>> m_summary;
        std::vector<std::string> m_notes;
        std::vector<Column> m_columns;
        std::vector<std::vector<Cell>> m_rows;
    };

} // namespace App
} // namespace Dracula
