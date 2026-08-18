#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <sstream>
#include <cstdint>

#include "common/findings.h"
#include "utr/types.h"

namespace Dracula {
namespace UTR {

    // ─── Evidence Truth Classification ─────────────────────────────────────────
    enum class EvidenceTruthLevel {
        Observed,   // Directly measured / recorded by engine/backend
        Inferred,   // Strong logical deduction from direct observations
        Suspected,  // Plausible hypothesis requiring further correlation
        Unknown     // Unproven or insufficient visibility
    };

    inline const char* TruthLevelToString(EvidenceTruthLevel lvl) {
        switch (lvl) {
            case EvidenceTruthLevel::Observed:  return "Observed";
            case EvidenceTruthLevel::Inferred:  return "Inferred";
            case EvidenceTruthLevel::Suspected: return "Suspected";
            case EvidenceTruthLevel::Unknown:   return "Unknown";
            default:                            return "Unknown";
        }
    }

    inline EvidenceTruthLevel StringToTruthLevel(const std::string& s) {
        if (s == "Observed") return EvidenceTruthLevel::Observed;
        if (s == "Inferred") return EvidenceTruthLevel::Inferred;
        if (s == "Suspected") return EvidenceTruthLevel::Suspected;
        return EvidenceTruthLevel::Unknown;
    }

    // ─── Evidence Provenance ───────────────────────────────────────────────────
    struct EvidenceProvenance {
        std::string engine;       // "Capstone", "Unicorn", "ETW", "DbgEng", "Agent", "QEMU", "ClrMD", "PE-sieve", "YARA"
        std::string backend;      // "HostStatic", "HostObserver", "HostAgent", "HostDebugger", "QEMU_VM"
        uint32_t    sessionId = 0;
        std::string moduleName;
        uint64_t    address = 0;
        uint64_t    rva = 0;
        int64_t     timestampMs = 0;
        std::string rawArtifactRef;
    };

    // ─── Evidence Node ─────────────────────────────────────────────────────────
    struct EvidenceNode {
        std::string        id;
        std::string        category;
        FindingSeverity    severity = FindingSeverity::Info;
        FindingConfidence  confidence = FindingConfidence::Medium;
        EvidenceTruthLevel truthLevel = EvidenceTruthLevel::Observed;

        std::string        title;
        std::string        description;
        std::string        evidenceData;
        EvidenceProvenance provenance;
        std::vector<std::string> tags;
    };

    // ─── Behavior Chain ────────────────────────────────────────────────────────
    struct BehaviorChain {
        std::string        chainId;
        std::string        name;            // e.g. "Runtime Code Transformation", "Process Injection Chain"
        std::string        description;
        uint64_t           originRva = 0;
        std::string        originFunction;
        EvidenceTruthLevel truthLevel = EvidenceTruthLevel::Inferred;
        FindingConfidence  confidence = FindingConfidence::High;
        std::vector<std::string> evidenceNodeIds;
        std::vector<std::string> steps;     // Ordered sequence of events
    };

    // ─── Evidence Graph ────────────────────────────────────────────────────────
    class EvidenceGraph {
    public:
        EvidenceGraph() = default;
        ~EvidenceGraph() = default;

        void AddEvidence(const EvidenceNode& node);
        void AddBehaviorChain(const BehaviorChain& chain);

        const std::vector<EvidenceNode>& GetNodes() const { return m_nodes; }
        const std::vector<BehaviorChain>& GetChains() const { return m_chains; }

        std::vector<EvidenceNode> GetByTruthLevel(EvidenceTruthLevel level) const;
        std::vector<EvidenceNode> GetByCategory(const std::string& category) const;

        void Clear();

        std::string ToJson() const;
        std::string ToMarkdown() const;

    private:
        std::vector<EvidenceNode>  m_nodes;
        std::vector<BehaviorChain> m_chains;
    };

} // namespace UTR
} // namespace Dracula
