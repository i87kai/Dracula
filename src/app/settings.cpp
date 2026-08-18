#include "app/settings.h"
#include "app/json.h"
#include "common/paths.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>

namespace fs = std::filesystem;

namespace Dracula {
namespace App {

    // The authoritative list of settings. Anything not here is rejected by
    // /settings set, so a typo cannot silently become a dead key.
    struct SettingSpec {
        const char* key;
        const char* defaultValue;
        const char* description;
    };

    static const SettingSpec kSettings[] = {
        {"reports.auto_open",     "false", "Open generated HTML reports in the default browser."},
        {"reports.format",        "html",  "Default format for large reports (html, json, txt, md)."},
        {"memory.max_read_bytes", "1048576", "Maximum bytes a single /memory read will return."},
        {"palette.enabled",       "true",  "Show the hierarchical command palette while typing."},
        {"tips.enabled",          "true",  "Show contextual tips in the header."},
        {"sandbox.auto_cleanup",  "true",  "Delete temporary VM overlays after every run."},
    };

    Settings& Settings::Instance() {
        static Settings instance;
        if (!instance.m_loaded) instance.Load();
        return instance;
    }

    std::string Settings::Path() const {
        return (fs::path(Paths::ConfigDir()) / "settings.json").string();
    }

    bool Settings::IsKnown(const std::string& key) {
        for (const auto& s : kSettings) {
            if (key == s.key) return true;
        }
        return false;
    }

    bool Settings::Load() {
        m_loaded = true;
        m_values.clear();

        const std::string path = Path();
        std::error_code ec;
        if (!fs::exists(path, ec)) return true;  // defaults only

        std::ifstream in(path, std::ios::binary);
        if (!in.is_open()) return false;
        std::stringstream ss;
        ss << in.rdbuf();

        Json j;
        if (!Json::Parse(ss.str(), j, nullptr) || !j.IsObject()) return false;

        for (const auto& s : kSettings) {
            if (j.Has(s.key)) {
                const Json& v = j[s.key];
                switch (v.GetType()) {
                    case Json::Type::Bool:   m_values[s.key] = v.AsBool() ? "true" : "false"; break;
                    case Json::Type::Number: m_values[s.key] = std::to_string(v.AsUInt());    break;
                    default:                 m_values[s.key] = v.AsString();                  break;
                }
            }
        }
        return true;
    }

    bool Settings::Save(std::string& error) const {
        Json j = Json::Object();
        for (const auto& kv : m_values) j.Set(kv.first, Json(kv.second));

        const std::string text = j.Dump(2);
        const fs::path target = Path();
        const fs::path tmp = fs::path(target.string() + ".tmp");

        try {
            fs::create_directories(target.parent_path());
            {
                std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
                if (!out.is_open()) {
                    error = "could not write settings";
                    return false;
                }
                out.write(text.data(), static_cast<std::streamsize>(text.size()));
                out.flush();
                if (!out.good()) {
                    error = "settings write failed";
                    return false;
                }
            }
            std::error_code ec;
            fs::remove(target, ec);
            fs::rename(tmp, target, ec);
            if (ec) {
                error = "could not commit settings: " + ec.message();
                return false;
            }
            return true;
        } catch (const std::exception& e) {
            error = std::string("saving settings failed: ") + e.what();
            return false;
        }
    }

    static std::string DefaultFor(const std::string& key) {
        for (const auto& s : kSettings) {
            if (key == s.key) return s.defaultValue;
        }
        return "";
    }

    std::string Settings::GetString(const std::string& key, const std::string& fallback) const {
        auto it = m_values.find(key);
        if (it != m_values.end()) return it->second;
        const std::string def = DefaultFor(key);
        return def.empty() ? fallback : def;
    }

    bool Settings::GetBool(const std::string& key, bool fallback) const {
        const std::string v = GetString(key, fallback ? "true" : "false");
        std::string lower = v;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return lower == "true" || lower == "1" || lower == "yes" || lower == "on";
    }

    int64_t Settings::GetInt(const std::string& key, int64_t fallback) const {
        const std::string v = GetString(key, "");
        if (v.empty()) return fallback;
        try {
            return std::stoll(v);
        } catch (...) {
            return fallback;
        }
    }

    void Settings::SetString(const std::string& key, const std::string& value) {
        m_values[key] = value;
    }

    void Settings::SetBool(const std::string& key, bool value) {
        m_values[key] = value ? "true" : "false";
    }

    void Settings::SetInt(const std::string& key, int64_t value) {
        m_values[key] = std::to_string(value);
    }

    std::vector<Settings::Entry> Settings::Describe() const {
        std::vector<Entry> out;
        for (const auto& s : kSettings) {
            Entry e;
            e.key = s.key;
            e.value = GetString(s.key, s.defaultValue);
            e.description = s.description;
            out.push_back(e);
        }
        return out;
    }

} // namespace App
} // namespace Dracula
