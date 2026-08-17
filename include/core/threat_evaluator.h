#pragma once

#include "common/findings.h"
#include "common/types.h"
#include <string>
#include <vector>

namespace Dracula {

    struct ThreatScoreResult {
        int                      score = 0; // 0 - 100
        std::string              level = "Clean"; // Clean, Low, Medium, High, Critical
        std::vector<std::string> reasoning;
        std::vector<std::string> mitreTechniques;
    };

    class ThreatEvaluator {
    public:
        ThreatEvaluator();
        ~ThreatEvaluator();

        // Evaluate complete unified findings to generate evidence-based threat score
        static ThreatScoreResult Evaluate(
            const std::vector<Finding>& findings,
            const SampleMetadata& meta,
            const SecurityMitigations& mitigations,
            double overallEntropy,
            bool isPacked
        );

        // Normalize sandbox trace events into findings
        static std::vector<Finding> NormalizeSandboxEvents(const std::vector<Sandbox::TraceEvent>& events);
    };

} // namespace Dracula

namespace Sandbox {
    using ThreatEvaluator = Dracula::ThreatEvaluator;
}
