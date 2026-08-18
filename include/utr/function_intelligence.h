#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <cstdint>

#include "common/findings.h"
#include "utr/types.h"
#include "utr/evidence_graph.h"

namespace Dracula {
namespace UTR {

    struct ManagedMethodInfo;
    struct ManagedPInvokeInfo;

    // ─── Function Intelligence Item ────────────────────────────────────────────
    struct FunctionIntelligenceItem {
        uint64_t    rva = 0;
        uint64_t    address = 0;
        std::string moduleName;
        std::string name;                 // e.g. "sub_180016a20" or symbol name "NetworkManager::Connect"
        std::string mangledName;
        bool        hasSymbol = false;
        std::string sourceFile;
        uint32_t    sourceLine = 0;

        // Static metrics
        uint32_t    instructionCount = 0;
        uint32_t    basicBlockCount = 0;
        uint32_t    cyclomaticComplexity = 1;
        uint32_t    callerCount = 0;
        uint32_t    calleeCount = 0;
        uint32_t    stringCount = 0;
        std::vector<std::string> referencedStrings;
        std::vector<std::string> calledApis;
        bool        callsHighRiskApis = false;

        // Runtime metrics
        bool        wasExecutedInRuntime = false;
        uint32_t    runtimeExecutionCount = 0;
        uint32_t    executionCount = 0;
        uint32_t    threadCount = 0;
        uint32_t    memoryRegionsAllocated = 0;
        uint32_t    apiEventsTriggered = 0;
        bool        triggeredRuntimeTransformation = false;

        // Investigation Priority Score (0 to 100) - STRICTLY DECOUPLED FROM THREAT SCORE
        double      interestScore = 0.0;
        std::string interestReasoning;

        // Threat Score (0 to 100) - Only increased by actual malicious behavior indicators
        double      threatScore = 0.0;
        std::string threatReasoning;

        FindingConfidence  confidence = FindingConfidence::Medium;
        EvidenceTruthLevel truthLevel = EvidenceTruthLevel::Observed;
        std::vector<std::string> tags;
    };

    // ─── Ranking Configuration ─────────────────────────────────────────────────
    struct FunctionRankingWeights {
        double weightRiskApis = 30.0;
        double weightRuntimeExecution = 25.0;
        double weightMemoryTransformation = 25.0;
        double weightControlFlowComplexity = 10.0;
        double weightXrefCentrality = 10.0;
    };

    // ─── Function Intelligence Manager ─────────────────────────────────────────
    class FunctionIntelligenceManager {
    public:
        FunctionIntelligenceManager() = default;
        ~FunctionIntelligenceManager() = default;

        void IndexStaticFunctions(const std::vector<FunctionGraph>& graphs,
                                  const std::vector<XRefEntry>& xrefs,
                                  const std::vector<ExtractedString>& strings,
                                  const std::vector<ImportEntry>& imports,
                                  const std::string& moduleName = "");

        void IndexManagedMethods(const std::vector<ManagedMethodInfo>& methods,
                                 const std::vector<ManagedPInvokeInfo>& pinvokes,
                                 const std::string& assemblyName = "");

        void CorrelateRuntimeExecutions(const std::vector<uint64_t>& executedAddresses,
                                        const std::vector<HleCallRecord>& hleCalls);

        void AddFunction(const FunctionIntelligenceItem& fn);
        void ComputeRanking(const FunctionRankingWeights& weights = {});

        const std::vector<FunctionIntelligenceItem>& GetAllFunctions() const { return m_functions; }
        std::vector<FunctionIntelligenceItem> GetTopInteresting(size_t count = 20) const;
        const FunctionIntelligenceItem* FindByRva(uint64_t rva) const;
        const FunctionIntelligenceItem* FindByName(const std::string& name) const;

        size_t TotalDiscovered() const { return m_functions.size(); }
        size_t InterestingCount(double threshold = 40.0) const;
        size_t HighInterestCount(double threshold = 70.0) const;

        void Clear();

        std::string ToJson() const;
        std::string ToMarkdownSummary(size_t topN = 10) const;

    private:
        std::vector<FunctionIntelligenceItem> m_functions;
    };

} // namespace UTR
} // namespace Dracula
