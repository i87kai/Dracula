#include "app/json.h"

#include <cmath>
#include <cctype>
#include <cstring>
#include <cstdio>

namespace Dracula {
namespace App {

    std::string Json::EscapeString(const std::string& s) {
        std::string out;
        out.reserve(s.size() + 8);
        for (unsigned char c : s) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                case '\b': out += "\\b";  break;
                case '\f': out += "\\f";  break;
                default:
                    if (c < 0x20) {
                        // Control characters must be escaped; everything else,
                        // including UTF-8 continuation bytes, passes through.
                        char buf[8];
                        std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                        out += buf;
                    } else {
                        out += static_cast<char>(c);
                    }
            }
        }
        return out;
    }

    // Numbers are emitted as integers when they are exactly integral, so IDs
    // and byte counts do not acquire a spurious ".000000" in project.json.
    static std::string FormatNumber(double n) {
        if (std::isfinite(n) && n == std::floor(n) && std::fabs(n) < 9.0e15) {
            std::ostringstream oss;
            oss << static_cast<long long>(n);
            return oss.str();
        }
        std::ostringstream oss;
        oss << std::setprecision(17) << n;
        return oss.str();
    }

    std::string Json::Dump(int indent, int depth) const {
        const bool pretty = indent > 0;
        const std::string pad    = pretty ? std::string((depth + 1) * indent, ' ') : std::string();
        const std::string padEnd = pretty ? std::string(depth * indent, ' ')       : std::string();
        const std::string nl     = pretty ? "\n" : "";

        switch (m_type) {
            case Type::Null:   return "null";
            case Type::Bool:   return m_bool ? "true" : "false";
            case Type::Number: return FormatNumber(m_number);
            case Type::String: return "\"" + EscapeString(m_string) + "\"";

            case Type::Array: {
                if (m_array.empty()) return "[]";
                std::string out = "[" + nl;
                for (size_t i = 0; i < m_array.size(); ++i) {
                    out += pad + m_array[i].Dump(indent, depth + 1);
                    if (i + 1 < m_array.size()) out += ",";
                    out += nl;
                }
                out += padEnd + "]";
                return out;
            }

            case Type::Object: {
                if (m_object.empty()) return "{}";
                std::string out = "{" + nl;
                size_t i = 0;
                for (const auto& kv : m_object) {
                    out += pad + "\"" + EscapeString(kv.first) + "\":";
                    if (pretty) out += " ";
                    out += kv.second.Dump(indent, depth + 1);
                    if (++i < m_object.size()) out += ",";
                    out += nl;
                }
                out += padEnd + "}";
                return out;
            }
        }
        return "null";
    }

    // --- Parser ---------------------------------------------------------------

    class JsonParser {
    public:
        JsonParser(const std::string& text) : m_text(text), m_pos(0) {}

        bool ParseValue(Json& out) {
            SkipWhitespace();
            if (m_pos >= m_text.size()) return Fail("unexpected end of input");

            char c = m_text[m_pos];
            switch (c) {
                case '{': return ParseObject(out);
                case '[': return ParseArray(out);
                case '"': {
                    std::string s;
                    if (!ParseString(s)) return false;
                    out = Json(s);
                    return true;
                }
                case 't':
                    if (!Literal("true")) return false;
                    out = Json(true);
                    return true;
                case 'f':
                    if (!Literal("false")) return false;
                    out = Json(false);
                    return true;
                case 'n':
                    if (!Literal("null")) return false;
                    out = Json();
                    return true;
                default:
                    return ParseNumber(out);
            }
        }

        void SkipWhitespace() {
            while (m_pos < m_text.size()) {
                char c = m_text[m_pos];
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++m_pos;
                else break;
            }
        }

        bool AtEndAfterWhitespace() {
            SkipWhitespace();
            return m_pos >= m_text.size();
        }

        const std::string& Error() const { return m_error; }

    private:
        bool Fail(const std::string& msg) {
            if (m_error.empty()) {
                m_error = msg + " at offset " + std::to_string(m_pos);
            }
            return false;
        }

        bool Literal(const char* lit) {
            size_t n = std::strlen(lit);
            if (m_text.compare(m_pos, n, lit) != 0) return Fail("invalid literal");
            m_pos += n;
            return true;
        }

        bool ParseObject(Json& out) {
            out = Json::Object();
            ++m_pos; // '{'
            SkipWhitespace();
            if (m_pos < m_text.size() && m_text[m_pos] == '}') { ++m_pos; return true; }

            while (true) {
                SkipWhitespace();
                std::string key;
                if (!ParseString(key)) return false;
                SkipWhitespace();
                if (m_pos >= m_text.size() || m_text[m_pos] != ':') return Fail("expected ':'");
                ++m_pos;

                Json value;
                if (!ParseValue(value)) return false;
                out.Set(key, value);

                SkipWhitespace();
                if (m_pos >= m_text.size()) return Fail("unterminated object");
                if (m_text[m_pos] == ',') { ++m_pos; continue; }
                if (m_text[m_pos] == '}') { ++m_pos; return true; }
                return Fail("expected ',' or '}'");
            }
        }

        bool ParseArray(Json& out) {
            out = Json::Array();
            ++m_pos; // '['
            SkipWhitespace();
            if (m_pos < m_text.size() && m_text[m_pos] == ']') { ++m_pos; return true; }

            while (true) {
                Json value;
                if (!ParseValue(value)) return false;
                out.Push(value);

                SkipWhitespace();
                if (m_pos >= m_text.size()) return Fail("unterminated array");
                if (m_text[m_pos] == ',') { ++m_pos; continue; }
                if (m_text[m_pos] == ']') { ++m_pos; return true; }
                return Fail("expected ',' or ']'");
            }
        }

        bool ParseString(std::string& out) {
            if (m_pos >= m_text.size() || m_text[m_pos] != '"') return Fail("expected string");
            ++m_pos;
            out.clear();

            while (m_pos < m_text.size()) {
                char c = m_text[m_pos++];
                if (c == '"') return true;
                if (c != '\\') { out += c; continue; }

                if (m_pos >= m_text.size()) return Fail("unterminated escape");
                char esc = m_text[m_pos++];
                switch (esc) {
                    case '"':  out += '"';  break;
                    case '\\': out += '\\'; break;
                    case '/':  out += '/';  break;
                    case 'n':  out += '\n'; break;
                    case 'r':  out += '\r'; break;
                    case 't':  out += '\t'; break;
                    case 'b':  out += '\b'; break;
                    case 'f':  out += '\f'; break;
                    case 'u': {
                        if (m_pos + 4 > m_text.size()) return Fail("truncated \\u escape");
                        unsigned int cp = 0;
                        for (int i = 0; i < 4; ++i) {
                            char h = m_text[m_pos + i];
                            cp <<= 4;
                            if (h >= '0' && h <= '9')      cp |= static_cast<unsigned>(h - '0');
                            else if (h >= 'a' && h <= 'f') cp |= static_cast<unsigned>(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') cp |= static_cast<unsigned>(h - 'A' + 10);
                            else return Fail("bad hex in \\u escape");
                        }
                        m_pos += 4;
                        // Encode as UTF-8. Surrogate halves are passed through
                        // individually; Dracula never emits them itself.
                        if (cp < 0x80) {
                            out += static_cast<char>(cp);
                        } else if (cp < 0x800) {
                            out += static_cast<char>(0xC0 | (cp >> 6));
                            out += static_cast<char>(0x80 | (cp & 0x3F));
                        } else {
                            out += static_cast<char>(0xE0 | (cp >> 12));
                            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                            out += static_cast<char>(0x80 | (cp & 0x3F));
                        }
                        break;
                    }
                    default: return Fail("invalid escape");
                }
            }
            return Fail("unterminated string");
        }

        bool ParseNumber(Json& out) {
            size_t start = m_pos;
            if (m_pos < m_text.size() && (m_text[m_pos] == '-' || m_text[m_pos] == '+')) ++m_pos;
            bool anyDigit = false;
            while (m_pos < m_text.size()) {
                char c = m_text[m_pos];
                if (std::isdigit(static_cast<unsigned char>(c))) { anyDigit = true; ++m_pos; }
                else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') { ++m_pos; }
                else break;
            }
            if (!anyDigit) return Fail("invalid number");

            try {
                out = Json(std::stod(m_text.substr(start, m_pos - start)));
            } catch (...) {
                return Fail("number out of range");
            }
            return true;
        }

        const std::string& m_text;
        size_t             m_pos;
        std::string        m_error;
    };

    bool Json::Parse(const std::string& text, Json& out, std::string* error) {
        JsonParser parser(text);
        Json value;
        if (!parser.ParseValue(value)) {
            if (error) *error = parser.Error();
            return false;
        }
        if (!parser.AtEndAfterWhitespace()) {
            if (error) *error = "trailing content after JSON value";
            return false;
        }
        out = value;
        return true;
    }

} // namespace App
} // namespace Dracula
