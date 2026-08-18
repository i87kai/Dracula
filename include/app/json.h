#pragma once

//
// Minimal JSON value type for Dracula's application layer.
//
// Dracula previously only ever *emitted* JSON, so hand-rolled string building
// was sufficient. Durable projects must round-trip: project.json and the
// project index are written and then read back on the next launch. That needs
// a real parser, so this header provides a small dependency-free one.
//
// Scope is deliberately narrow -- it parses what Dracula writes (objects,
// arrays, strings, numbers, bools, null) with correct string escaping and
// UTF-8 passthrough. It is not a general-purpose validating JSON library.
//

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <iomanip>

namespace Dracula {
namespace App {

    class Json {
    public:
        enum class Type { Null, Bool, Number, String, Array, Object };

        Json() : m_type(Type::Null) {}
        Json(bool b) : m_type(Type::Bool), m_bool(b) {}
        Json(double n) : m_type(Type::Number), m_number(n) {}
        Json(int n) : m_type(Type::Number), m_number(static_cast<double>(n)) {}
        Json(uint32_t n) : m_type(Type::Number), m_number(static_cast<double>(n)) {}
        Json(uint64_t n) : m_type(Type::Number), m_number(static_cast<double>(n)) {}
        Json(int64_t n) : m_type(Type::Number), m_number(static_cast<double>(n)) {}
        Json(const char* s) : m_type(Type::String), m_string(s ? s : "") {}
        Json(const std::string& s) : m_type(Type::String), m_string(s) {}

        static Json Array()  { Json j; j.m_type = Type::Array;  return j; }
        static Json Object() { Json j; j.m_type = Type::Object; return j; }

        Type GetType() const { return m_type; }
        bool IsNull()   const { return m_type == Type::Null; }
        bool IsObject() const { return m_type == Type::Object; }
        bool IsArray()  const { return m_type == Type::Array; }

        // --- Typed accessors with defaults -----------------------------------
        // A missing or wrongly-typed field yields the fallback rather than
        // throwing, so a partially-corrupt project still loads (section 44).
        std::string AsString(const std::string& fallback = "") const {
            return m_type == Type::String ? m_string : fallback;
        }
        double AsNumber(double fallback = 0.0) const {
            return m_type == Type::Number ? m_number : fallback;
        }
        uint64_t AsUInt(uint64_t fallback = 0) const {
            return m_type == Type::Number ? static_cast<uint64_t>(m_number) : fallback;
        }
        uint32_t AsUInt32(uint32_t fallback = 0) const {
            return m_type == Type::Number ? static_cast<uint32_t>(m_number) : fallback;
        }
        bool AsBool(bool fallback = false) const {
            return m_type == Type::Bool ? m_bool : fallback;
        }

        // --- Object access ----------------------------------------------------
        bool Has(const std::string& key) const {
            return m_type == Type::Object && m_object.find(key) != m_object.end();
        }
        const Json& operator[](const std::string& key) const {
            static const Json kNull;
            if (m_type != Type::Object) return kNull;
            auto it = m_object.find(key);
            return it == m_object.end() ? kNull : it->second;
        }
        void Set(const std::string& key, const Json& value) {
            m_type = Type::Object;
            m_object[key] = value;
        }

        // --- Array access -----------------------------------------------------
        size_t Size() const {
            if (m_type == Type::Array)  return m_array.size();
            if (m_type == Type::Object) return m_object.size();
            return 0;
        }
        const Json& At(size_t i) const {
            static const Json kNull;
            return (m_type == Type::Array && i < m_array.size()) ? m_array[i] : kNull;
        }
        void Push(const Json& value) {
            m_type = Type::Array;
            m_array.push_back(value);
        }
        const std::vector<Json>& Items() const { return m_array; }

        // --- Serialization ----------------------------------------------------
        std::string Dump(int indent = 2, int depth = 0) const;

        // --- Parsing ----------------------------------------------------------
        // Returns false and leaves `out` untouched on malformed input.
        static bool Parse(const std::string& text, Json& out, std::string* error = nullptr);

        static std::string EscapeString(const std::string& s);

    private:
        Type        m_type;
        bool        m_bool = false;
        double      m_number = 0.0;
        std::string m_string;
        std::vector<Json> m_array;
        std::map<std::string, Json> m_object;

        friend class JsonParser;
    };

} // namespace App
} // namespace Dracula
