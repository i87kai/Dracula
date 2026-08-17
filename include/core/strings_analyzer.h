#pragma once

#include "common/findings.h"
#include <string>
#include <vector>
#include <cstdint>

namespace Dracula {

    class StringsAnalyzer {
    public:
        StringsAnalyzer();
        ~StringsAnalyzer();

        // Extract both ASCII and Unicode strings from a buffer
        std::vector<ExtractedString> ExtractStrings(const uint8_t* data, size_t size, size_t minLength = 4);

        // Extract from a vector
        std::vector<ExtractedString> ExtractStrings(const std::vector<uint8_t>& buffer, size_t minLength = 4);

        // Classify an individual string
        static StringCategory ClassifyString(const std::string& str);

        // Generate findings based on high-risk extracted strings
        std::vector<Finding> GenerateFindings(const std::vector<ExtractedString>& strings) const;
    };

} // namespace Dracula
