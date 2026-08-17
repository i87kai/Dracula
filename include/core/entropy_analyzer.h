#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace Sandbox {

    struct PESectionEntropy {
        std::string name;
        uint32_t virtualAddress;
        uint32_t virtualSize;
        uint32_t rawSize;
        double entropy;
        bool isExecutable;
        bool isWritable;
        bool isPacked;
    };

    struct BinaryPackingAnalysis {
        double overallEntropy = 0.0;
        bool isPacked = false;
        std::string detectedPacker;
        std::vector<PESectionEntropy> sections;
        std::vector<std::string> indicators;
    };

    class EntropyAnalyzer {
    public:
        static double CalculateShannonEntropy(const uint8_t* data, size_t length);
        static BinaryPackingAnalysis AnalyzeBinary(const std::string& filePath);
        static std::string RunYaraScan(const std::string& binaryPath, const std::string& yaraRulePath = "rules/packers.yar");
    };

} // namespace Sandbox
