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

    enum class ExecutionSafetyPolicy {
        TrustedHostAllowed,
        AskBeforeHostExecution,
        IsolatedOnlyForUnknown
    };

    inline const char* SafetyPolicyToString(ExecutionSafetyPolicy p) {
        switch (p) {
            case ExecutionSafetyPolicy::TrustedHostAllowed:      return "TrustedHostAllowed";
            case ExecutionSafetyPolicy::AskBeforeHostExecution:  return "AskBeforeHostExecution";
            case ExecutionSafetyPolicy::IsolatedOnlyForUnknown:  return "IsolatedOnlyForUnknown";
            default:                                             return "IsolatedOnlyForUnknown";
        }
    }

    struct EscalationDecisionRecord {
        std::string           sourceBackend = "Static";
        std::string           requestedOperation = "Analysis";
        std::string           requiredCapability = "None";
        std::string           targetTrustClassification = "UnknownUntrusted";
        AutoEscalationPolicy  autoEscalationPolicy = AutoEscalationPolicy::Safe;
        ExecutionSafetyPolicy executionSafetyPolicy = ExecutionSafetyPolicy::IsolatedOnlyForUnknown;
        std::string           decision = "ProceedHost"; // "ProceedHost", "EscalateToQemu", "BlockedSafetyPolicy", "BlockedUserPromptRequired"
        std::string           selectedBackend = "Static";
        std::string           reason;
        bool                  confirmationRequired = false;
        uint64_t              timestamp = 0;

        std::string ToJson() const;
    };

    struct StageTelemetry {
        std::string name;
        std::string status = "Completed"; // "Started", "Completed", "Skipped", "ReusedFromCache", "Failed", "Blocked"
        int64_t     durationMs = 0;
        std::string details;
    };

    struct UtrOrchestratorOptions {
        AnalysisLevel         level = AnalysisLevel::Quick;
        AutoEscalationPolicy  autoEscalation = AutoEscalationPolicy::Safe;
        ExecutionSafetyPolicy executionSafety = ExecutionSafetyPolicy::IsolatedOnlyForUnknown;
        bool                  isTargetTrusted = false;
        bool                  askBeforeVm = false;
        std::string           maximumBackend = "QEMU"; // "HostObserver", "Agent", "Debugger", "QEMU"
        BudgetLimits          budgetLimits;
    };

    struct UtrAnalysisResult {
        TargetInfo                   target;
        AnalysisLevel                level = AnalysisLevel::Quick;
        UnifiedAnalysisResult        staticResult;
        FunctionIntelligenceManager  functionIntelligence;
        MemoryIntelligenceManager    memoryIntelligence;
        EvidenceGraph                evidenceGraph;

        EscalationDecisionRecord     escalationDecision;
        bool                         escalationOccurred = false;
        std::string                  escalationReason;
        std::string                  escalatedBackend;
        bool                         executionBlocked = false;

        std::vector<StageTelemetry>  stageHistory;
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
