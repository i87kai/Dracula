#include "app/html_report.h"
#include "app/project.h"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace Dracula {
namespace App {

    HtmlReport::HtmlReport(const std::string& title, const std::string& subtitle)
        : m_title(title), m_subtitle(subtitle) {}

    std::string HtmlReport::EscapeHtml(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&':  out += "&amp;";  break;
                case '<':  out += "&lt;";   break;
                case '>':  out += "&gt;";   break;
                case '"':  out += "&quot;"; break;
                case '\'': out += "&#39;";  break;
                default:   out += c;
            }
        }
        return out;
    }

    void HtmlReport::AddSummary(const std::string& label, const std::string& value) {
        m_summary.emplace_back(label, value);
    }

    void HtmlReport::AddNote(const std::string& note) {
        m_notes.push_back(note);
    }

    void HtmlReport::SetColumns(const std::vector<Column>& columns) {
        m_columns = columns;
    }

    void HtmlReport::AddRow(const std::vector<Cell>& cells) {
        m_rows.push_back(cells);
    }

    void HtmlReport::AddRow(const std::vector<std::string>& cells) {
        std::vector<Cell> row;
        row.reserve(cells.size());
        for (const auto& c : cells) row.push_back(Cell{c, ""});
        m_rows.push_back(row);
    }

    // The stylesheet is deliberately small and dependency-free. It follows
    // Dracula's identity (crimson accents, cyan technical values) while keeping
    // body text at readable contrast in both light and dark rendering.
    static const char* kStyle = R"CSS(
:root{color-scheme:dark;--bg:#14101a;--panel:#1c1725;--border:#332b42;--text:#e6e1ef;
--muted:#9c93ad;--accent:#c62839;--tech:#5bc8d6;--label:#b48ce0;--ok:#5fd68a;--warn:#e0b341;--err:#ff6b6b}
*{box-sizing:border-box}
body{margin:0;padding:24px;background:var(--bg);color:var(--text);
font:14px/1.5 "Segoe UI",system-ui,sans-serif}
h1{margin:0 0 4px;font-size:22px;color:var(--accent);letter-spacing:.5px}
.sub{color:var(--muted);margin-bottom:20px;font-size:13px}
.summary{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:10px 14px;min-width:140px}
.card .k{color:var(--label);font-size:11px;text-transform:uppercase;letter-spacing:.6px}
.card .v{color:var(--tech);font-size:17px;font-family:Consolas,"Courier New",monospace;margin-top:2px}
.note{background:#2a2033;border-left:3px solid var(--warn);padding:8px 12px;margin-bottom:12px;color:#e8d9a8;font-size:13px}
.controls{display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap}
input,select{background:var(--panel);border:1px solid var(--border);color:var(--text);
padding:7px 10px;border-radius:5px;font-size:13px}
input{flex:1;min-width:200px}
input:focus,select:focus{outline:none;border-color:var(--tech)}
.wrap{overflow-x:auto;border:1px solid var(--border);border-radius:6px}
table{border-collapse:collapse;width:100%;font-size:13px}
th{background:var(--panel);color:var(--label);text-align:left;padding:9px 12px;
position:sticky;top:0;cursor:pointer;user-select:none;white-space:nowrap;border-bottom:1px solid var(--border)}
th:hover{color:var(--tech)}
th.r,td.r{text-align:right}
td{padding:7px 12px;border-bottom:1px solid #241d2e;white-space:nowrap}
tr:hover td{background:#221b2c}
td.m{font-family:Consolas,"Courier New",monospace;color:var(--tech)}
.badge{display:inline-block;padding:1px 7px;border-radius:9px;font-size:11px;font-weight:600}
.badge.static{background:#3a3350;color:#c3b6e0}
.badge.resolved{background:#1f4a52;color:#7fdcea}
.badge.live{background:#1d4a30;color:#7ce8a4}
.badge.ok{background:#1d4a30;color:#7ce8a4}
.badge.warn{background:#4a3c17;color:#f0d182}
.badge.error{background:#4d1f1f;color:#ff9b9b}
.foot{color:var(--muted);font-size:12px;margin-top:12px}
.hidden{display:none}
)CSS";

    // Sorting and filtering run entirely in the page. Numeric columns are
    // compared as numbers (hex addresses included) so 0x100 sorts after 0x20.
    static const char* kScript = R"JS(
(function(){
var table=document.getElementById('t'),tbody=table.tBodies[0];
var rows=Array.prototype.slice.call(tbody.rows);
var search=document.getElementById('q'),colSel=document.getElementById('col');
var count=document.getElementById('count'),total=rows.length;

function num(s){
  s=s.trim();
  if(/^0x[0-9a-f]+$/i.test(s))return parseInt(s,16);
  var v=parseFloat(s.replace(/[, ]/g,''));
  return isNaN(v)?-Infinity:v;
}
function apply(){
  var q=search.value.toLowerCase();
  var ci=parseInt(colSel.value,10);
  var shown=0;
  for(var i=0;i<rows.length;i++){
    var r=rows[i],hit=!q;
    if(q){
      if(ci<0){hit=r.textContent.toLowerCase().indexOf(q)>=0;}
      else{var c=r.cells[ci];hit=c&&c.textContent.toLowerCase().indexOf(q)>=0;}
    }
    r.className=hit?'':'hidden';
    if(hit)shown++;
  }
  count.textContent=shown+' of '+total+' rows';
}
search.addEventListener('input',apply);
colSel.addEventListener('change',apply);

var dir={};
Array.prototype.forEach.call(table.tHead.rows[0].cells,function(th,i){
  th.addEventListener('click',function(){
    var isNum=th.getAttribute('data-num')==='1';
    dir[i]=!dir[i];
    var sign=dir[i]?1:-1;
    rows.sort(function(a,b){
      var x=a.cells[i]?a.cells[i].textContent:'',y=b.cells[i]?b.cells[i].textContent:'';
      if(isNum){var d=num(x)-num(y);return d===0?0:(d<0?-sign:sign);}
      return x.localeCompare(y)*sign;
    });
    rows.forEach(function(r){tbody.appendChild(r);});
  });
});
apply();
})();
)JS";

    std::string HtmlReport::Render() const {
        std::ostringstream o;
        o << "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
          << "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
          << "<title>" << EscapeHtml(m_title) << " - Dracula</title>\n"
          << "<style>" << kStyle << "</style>\n</head>\n<body>\n";

        o << "<h1>" << EscapeHtml(m_title) << "</h1>\n";
        if (!m_subtitle.empty()) {
            o << "<div class=\"sub\">" << EscapeHtml(m_subtitle) << "</div>\n";
        }

        if (!m_summary.empty()) {
            o << "<div class=\"summary\">\n";
            for (const auto& kv : m_summary) {
                o << "<div class=\"card\"><div class=\"k\">" << EscapeHtml(kv.first)
                  << "</div><div class=\"v\">" << EscapeHtml(kv.second) << "</div></div>\n";
            }
            o << "</div>\n";
        }

        for (const auto& n : m_notes) {
            o << "<div class=\"note\">" << EscapeHtml(n) << "</div>\n";
        }

        if (!m_columns.empty()) {
            o << "<div class=\"controls\">\n"
              << "<input id=\"q\" type=\"search\" placeholder=\"Filter rows...\">\n"
              << "<select id=\"col\"><option value=\"-1\">All columns</option>\n";
            for (size_t i = 0; i < m_columns.size(); ++i) {
                o << "<option value=\"" << i << "\">" << EscapeHtml(m_columns[i].title) << "</option>\n";
            }
            o << "</select>\n<span id=\"count\" class=\"foot\"></span>\n</div>\n";

            o << "<div class=\"wrap\">\n<table id=\"t\">\n<thead>\n<tr>";
            for (const auto& c : m_columns) {
                o << "<th" << (c.align == Align::Right ? " class=\"r\"" : "")
                  << (c.numeric ? " data-num=\"1\"" : "")
                  << " title=\"Click to sort\">" << EscapeHtml(c.title) << "</th>";
            }
            o << "</tr>\n</thead>\n<tbody>\n";

            for (const auto& row : m_rows) {
                o << "<tr>";
                for (size_t i = 0; i < row.size(); ++i) {
                    const bool mono  = i < m_columns.size() && m_columns[i].monospace;
                    const bool right = i < m_columns.size() && m_columns[i].align == Align::Right;

                    std::string cls;
                    if (mono)  cls += "m";
                    if (right) cls += cls.empty() ? "r" : " r";

                    o << "<td" << (cls.empty() ? "" : (" class=\"" + cls + "\"")) << ">";
                    if (row[i].badge.empty()) {
                        o << EscapeHtml(row[i].text);
                    } else {
                        o << "<span class=\"badge " << EscapeHtml(row[i].badge) << "\">"
                          << EscapeHtml(row[i].text) << "</span>";
                    }
                    o << "</td>";
                }
                o << "</tr>\n";
            }
            o << "</tbody>\n</table>\n</div>\n";
        }

        o << "<div class=\"foot\">Generated by Dracula &middot; " << EscapeHtml(NowIso8601())
          << "</div>\n";

        if (!m_columns.empty()) {
            o << "<script>" << kScript << "</script>\n";
        }
        o << "</body>\n</html>\n";
        return o.str();
    }

    bool HtmlReport::Write(const std::string& path, std::string& error) const {
        const std::string content = Render();
        try {
            fs::create_directories(fs::path(path).parent_path());
            const std::string tmp = path + ".tmp";
            {
                std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
                if (!out.is_open()) {
                    error = "could not open " + path + " for writing";
                    return false;
                }
                out.write(content.data(), static_cast<std::streamsize>(content.size()));
                out.flush();
                if (!out.good()) {
                    error = "write failed for " + path;
                    return false;
                }
            }
            std::error_code ec;
            fs::remove(path, ec);
            fs::rename(tmp, path, ec);
            if (ec) {
                error = "could not commit report: " + ec.message();
                return false;
            }
            return true;
        } catch (const std::exception& e) {
            error = std::string("writing report failed: ") + e.what();
            return false;
        }
    }

} // namespace App
} // namespace Dracula
