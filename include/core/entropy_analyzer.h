#pragma once

#include "common/findings.h"
#include <string>
#include <vector>
#include <cstdint>

namespace Dracula {

    struct PESectionEntropy {
        std::string name;
        uint32_t    virtualAddress = 0;
        uint32_t    virtualSize = 0;
        uint32_t    rawSize = 0;
        double      entropy = 0.0;
        bool        isExecutable = false;
        bool        isWritable = false;
        bool        isPacked = false;
    };

    struct BinaryPackingAnalysis {
        double overallEntropy = 0.0;
        bool isPacked = false;
        std::string detectedPacker;
        std::vector<PESectionEntropy> sections;
        std::vector<std::string> indicators;
        std::vector<Finding> findings;
    };

    class EntropyAnalyzer {
    public:
        static double CalculateShannonEntropy(const uint8_t* data, size_t length);
        static double CalculateFileEntropy(const std::string& filePath);
        static BinaryPackingAnalysis AnalyzeBinary(const std::string& filePath);
        static BinaryPackingAnalysis AnalyzeBuffer(const uint8_t* data, size_t size);
        static std::string RunYaraScan(const std::string& binaryPath, const std::string& yaraRulePath = "rules/packers.yar");
    };

} // namespace Dracula

namespace Sandbox {
    using PESectionEntropy = Dracula::PESectionEntropy;
    using BinaryPackingAnalysis = Dracula::BinaryPackingAnalysis;
    using EntropyAnalyzer = Dracula::EntropyAnalyzer;
}
