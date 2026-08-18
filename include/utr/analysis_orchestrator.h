#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

#include "utr/types.h"
#include "utr/target.h"
#include "utr/evidence_graph.h"
#include "utr/function_intelligence.h"
#include "utr/memory_intelligence.h"
#include "common/findings.h"

namespace Dracula {
namespace UTR {

    enum class AnalysisLevel {
        Quick,
        Deep,
        Runtime,
        Full
    };

    inline const char* AnalysisLevelToString(AnalysisLevel lvl) {
        switch (lvl) {
            case AnalysisLevel::Quick:   return "Quick";
            case AnalysisLevel::Deep:    return "Deep";
            case AnalysisLevel::Runtime: return "Runtime";
            case AnalysisLevel::Full:    return "Full";
            default:                     return "Quick";
        }
    }

    inline AnalysisLevel StringToAnalysisLevel(const std::string& s) {
        if (s == "Deep" || s == "deep") return AnalysisLevel::Deep;
        if (s == "Runtime" || s == "runtime") return AnalysisLevel::Runtime;
        if (s == "Full" || s == "full") return AnalysisLevel::Full;
        return AnalysisLevel::Quick;
    }

    enum class AutoEscalationPolicy {
        Off,
        Safe,
        Full
    };

    inline const char* EscalationPolicyToString(AutoEscalationPolicy p) {
        switch (p) {
            case AutoEscalationPolicy::Off:  return "Off";
            case AutoEscalationPolicy::Safe: return "Safe";
            case AutoEscalationPolicy::Full: return "Full";
            default:                         return "Safe";
        }
    }

    struct UtrOrchestratorOptions {
        AnalysisLevel        level = AnalysisLevel::Quick;
        AutoEscalationPolicy autoEscalation = AutoEscalationPolicy::Safe;
        bool                 askBeforeVm = false;
        std::string          maximumBackend = "QEMU"; // "HostObserver", "Agent", "Debugger", "QEMU"
        BudgetLimits         budgetLimits;
    };

    struct UtrAnalysisResult {
        TargetInfo                   target;
        AnalysisLevel                level = AnalysisLevel::Quick;
        UnifiedAnalysisResult        staticResult;
        FunctionIntelligenceManager  functionIntelligence;
        MemoryIntelligenceManager    memoryIntelligence;
        EvidenceGraph                evidenceGraph;

        bool                         escalationOccurred = false;
        std::string                  escalationReason;
        std::string                  escalatedBackend;

        BudgetUsage                  budgetUsage;
        int64_t                      durationMs = 0;

        std::string ToJson() const;
        std::string ToMarkdown() const;
    };

    class UtrAnalysisOrchestrator {
    public:
        static UtrAnalysisOrchestrator& Instance();

        UtrAnalysisOrchestrator() = default;
        ~UtrAnalysisOrchestrator() = default;

        UtrAnalysisResult RunAnalysis(std::shared_ptr<ITarget> target,
                                      const UtrOrchestratorOptions& options = {});
    };

} // namespace UTR
} // namespace Dracula
