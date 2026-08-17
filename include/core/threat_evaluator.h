#pragma once

#include "common/types.h"
#include "core/entropy_analyzer.h"
#include <string>
#include <vector>

namespace Sandbox {

    struct MitreTechnique {
        std::string id;
        std::string name;
        std::string tactic;
        std::string evidence;
    };

    struct ThreatAssessment {
        int threatScore = 0; // 0 to 100
        std::string verdict; // "CLEAN", "SUSPICIOUS", "MALICIOUS"
        std::vector<std::string> highlights;
        std::vector<MitreTechnique> mitreTechniques;
    };

    class ThreatEvaluator {
    public:
        static ThreatAssessment Evaluate(const AnalysisReport& report, const BinaryPackingAnalysis& packing);
    };

} // namespace Sandbox
