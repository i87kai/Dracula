#pragma once

//
// Dracula application settings.
//
// A small persistent key/value store for user preferences that are not part of
// any single project: report auto-open, default report format, palette
// behaviour. Backed by <InstallRoot>\config\settings.json.
//
// The existing Sandbox::ConfigManager stays as-is -- it models the fixed VM/QEMU
// configuration schema and is not a general settings bag.
//

#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace Dracula {
namespace App {

    class Settings {
    public:
        static Settings& Instance();

        // Loads from disk. Safe to call repeatedly; a missing file is not an
        // error, it just means every value is still at its default.
        bool Load();
        bool Save(std::string& error) const;

        bool        GetBool(const std::string& key, bool fallback) const;
        std::string GetString(const std::string& key, const std::string& fallback) const;
        int64_t     GetInt(const std::string& key, int64_t fallback) const;

        void SetBool(const std::string& key, bool value);
        void SetString(const std::string& key, const std::string& value);
        void SetInt(const std::string& key, int64_t value);

        // Every known setting, with its current value, for /settings.
        struct Entry {
            std::string key;
            std::string value;
            std::string description;
        };
        std::vector<Entry> Describe() const;

        // True when `key` is a recognized setting name.
        static bool IsKnown(const std::string& key);

        std::string Path() const;

    private:
        Settings() = default;

        std::map<std::string, std::string> m_values;
        bool m_loaded = false;
    };

} // namespace App
} // namespace Dracula
