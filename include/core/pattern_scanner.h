#pragma once

#include "common/findings.h"
#include <string>
#include <vector>
#include <cstdint>

namespace Dracula {

    struct PatternByte {
        uint8_t value = 0;
        bool    isWildcard = false;
    };

    enum class PatternParseStatus {
        Valid,
        EmptyPattern,
        InvalidToken,
        InvalidTokenLength,
        InvalidHexDigit
    };

    struct PatternParseResult {
        PatternParseStatus status = PatternParseStatus::Valid;
        std::string errorMessage;
        size_t errorTokenIndex = 0; // 1-based index
        std::string errorToken;
        std::vector<PatternByte> pattern;

        bool IsValid() const { return status == PatternParseStatus::Valid; }
        explicit operator bool() const { return IsValid(); }
    };

    class PatternScanner {
    public:
        PatternScanner();
        ~PatternScanner();

        // Strict pattern parser returning detailed error information
        static PatternParseResult ParsePatternStrict(const std::string& patternStr);

        // Parse a pattern string like "48 8B 05 ?? ?? ?? ?? 48 85 C0" (backward compatibility)
        static bool ParsePattern(const std::string& patternStr, std::vector<PatternByte>& outPattern);

        // Scan a buffer for all occurrences of the pattern
        static std::vector<size_t> Scan(const uint8_t* data, size_t size, const std::string& patternStr, std::string* outError = nullptr);

        // Scan a buffer with a pre-parsed pattern
        static std::vector<size_t> Scan(const uint8_t* data, size_t size, const std::vector<PatternByte>& pattern);

        // Scan a file on disk
        static std::vector<size_t> ScanFile(const std::string& filePath, const std::string& patternStr, std::string* outError = nullptr);
        static std::vector<size_t> ScanFile(const std::string& filePath, const std::vector<PatternByte>& pattern, std::string* outError = nullptr);
    };

} // namespace Dracula
