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

    class PatternScanner {
    public:
        PatternScanner();
        ~PatternScanner();

        // Parse a pattern string like "48 8B 05 ?? ?? ?? ?? 48 85 C0"
        static bool ParsePattern(const std::string& patternStr, std::vector<PatternByte>& outPattern);

        // Scan a buffer for all occurrences of the pattern
        static std::vector<size_t> Scan(const uint8_t* data, size_t size, const std::string& patternStr);

        // Scan a buffer with a pre-parsed pattern
        static std::vector<size_t> Scan(const uint8_t* data, size_t size, const std::vector<PatternByte>& pattern);

        // Scan a file on disk
        static std::vector<size_t> ScanFile(const std::string& filePath, const std::string& patternStr);
    };

} // namespace Dracula
