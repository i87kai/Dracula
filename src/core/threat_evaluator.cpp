#include "core/threat_evaluator.h"
#include <algorithm>
#include <set>

namespace Dracula {

    ThreatEvaluator::ThreatEvaluator() = default;
    ThreatEvaluator::~ThreatEvaluator() = default;

    ThreatScoreResult ThreatEvaluator::Evaluate(
        const std::vector<Finding>& findings,
        const SampleMetadata& meta,
        const SecurityMitigations& mitigations,
        double overallEntropy,
        bool isPacked
    ) {
        ThreatScoreResult res;
        int rawScore = 0;
        std::set<std::string> mitreSet;
        std::set<std::string> uniqueCategories;

        // Anti-VM is not malware. Development tools, games, licensing systems
        // and enterprise software all inspect their environment for entirely
        // legitimate reasons, so evasion evidence is weighted by CONTEXT:
        //
        //   * on its own it is heavily discounted and hard-capped, so no amount
        //     of virtualization detection can carry a verdict by itself;
        //   * alongside genuinely malicious evidence it counts in full, because
        //     that is precisely when evading analysis is meaningful.
        //
        // It remains a corroborating signal either way, never a deciding one.
        int evasionScore = 0;
        bool hasOtherMaliciousEvidence = false;
        auto isEvasionFinding = [](const Finding& f) {
            return f.source == "Anti-Evasion Engine" ||
                   f.source == "Environment Coherence Validator" ||
                   f.category.rfind("AntiAnalysis", 0) == 0;
        };

        for (const auto& f : findings) {
            const bool evasion = isEvasionFinding(f);
            uniqueCategories.insert(f.category);
            if (!evasion && f.severity >= FindingSeverity::Medium) {
                hasOtherMaliciousEvidence = true;
            }

            int weight = 0;
            switch (f.severity) {
                case FindingSeverity::Critical: weight = 30; break;
                case FindingSeverity::High:     weight = 20; break;
                case FindingSeverity::Medium:   weight = 10; break;
                case FindingSeverity::Low:      weight = 4;  break;
                case FindingSeverity::Info:     weight = 0;  break;
            }
            if (evasion) {
                evasionScore += weight;
            } else {
                rawScore += weight;
            }

            for (const auto& tag : f.tags) {
                if (tag.rfind("MITRE:", 0) == 0) {
                    mitreSet.insert(tag.substr(6));
                }
            }

            if (f.severity >= FindingSeverity::Medium) {
                res.reasoning.push_back("[" + std::string(SeverityToString(f.severity)) + "] " + f.title + " (" + f.evidence + ")");
            }
        }

        if (evasionScore > 0) {
            constexpr int kEvasionCapCorroborated = 25;
            constexpr int kEvasionCapAlone        = 15;

            int applied;
            if (hasOtherMaliciousEvidence) {
                applied = std::min(evasionScore, kEvasionCapCorroborated);
                res.reasoning.push_back(
                    "[ANTI-ANALYSIS] Environment-sensitive behaviour contributed " +
                    std::to_string(applied) + " points, corroborated by independent "
                    "malicious evidence.");
            } else {
                applied = std::min(evasionScore / 2, kEvasionCapAlone);
                res.reasoning.push_back(
                    "[ANTI-ANALYSIS] Environment-sensitive behaviour contributed " +
                    std::to_string(applied) + " points (discounted and capped at " +
                    std::to_string(kEvasionCapAlone) + "): with no other malicious evidence, "
                    "detecting a virtual environment is not by itself suspicious.");
            }
            rawScore += applied;
        }

        // Multi-signal corroboration bonus: if multiple distinct categories flagged, add corroboration weight
        if (uniqueCategories.size() >= 3) {
            rawScore += 10;
            res.reasoning.push_back("[CORROBORATION] Multiple independent attack categories flagged (" + std::to_string(uniqueCategories.size()) + " categories)");
        }

        // Mitigation penalties
        if (!mitigations.hasDep && !mitigations.hasAslr) {
            rawScore += 5;
            res.reasoning.push_back("[SECURITY] Lacks both ASLR and DEP memory exploit mitigations");
        }

        if (mitigations.hasRwxSections) {
            rawScore += 15;
            res.reasoning.push_back("[PACKING] Section header contains writable and executable (RWX) memory pages");
        }

        if (isPacked || overallEntropy >= 7.5) {
            rawScore += 10;
            res.reasoning.push_back("[ENTROPY] High file entropy (> 7.50) indicating encrypted payload or obfuscation");
        }

        res.score = std::clamp(rawScore, 0, 100);

        if (res.score >= 75) {
            res.level = "Critical Threat";
        } else if (res.score >= 45) {
            res.level = "Suspicious";
        } else if (res.score >= 25) {
            res.level = "Low Risk";
        } else {
            res.level = "Clean / Benign";
        }

        res.mitreTechniques.assign(mitreSet.begin(), mitreSet.end());
        return res;
    }

    std::vector<Finding> ThreatEvaluator::NormalizeSandboxEvents(const std::vector<Sandbox::TraceEvent>& events) {
        std::vector<Finding> findings;

        for (const auto& e : events) {
            if (e.type == Sandbox::EventType::Process) {
                Finding f;
                f.id = "SBX_PROCESS_SPAWNED";
                f.category = "Runtime Execution";
                f.severity = FindingSeverity::Medium;
                f.confidence = FindingConfidence::High;
                f.title = "Child Process Spawned in Sandbox: " + e.message;
                f.description = "The target binary launched a child process during dynamic VM execution.";
                f.evidence = e.message + " (PID: " + std::to_string(e.pid) + ") " + e.details;
                f.source = "QEMU Sandbox Tracer";
                f.tags = {"Execution", "ProcessCreation", "MITRE:T1059"};
                findings.push_back(f);
            } else if (e.type == Sandbox::EventType::Network) {
                Finding f;
                f.id = "SBX_NETWORK_ACTIVITY";
                f.category = "Runtime Network";
                f.severity = FindingSeverity::High;
                f.confidence = FindingConfidence::High;
                f.title = "Outbound Network Socket Connection: " + e.message;
                f.description = "Observed outbound socket connection initiated from guest VM.";
                f.evidence = e.message + " " + e.details;
                f.source = "QEMU Sandbox Tracer";
                f.tags = {"Network", "C2", "MITRE:T1071"};
                findings.push_back(f);
            } else if (e.type == Sandbox::EventType::File) {
                Finding f;
                f.id = "SBX_FILE_ACTIVITY";
                f.category = "Persistence / Dropper";
                f.severity = FindingSeverity::Medium;
                f.confidence = FindingConfidence::High;
                f.title = "File System Modification: " + e.message;
                f.description = "Observed file creation or drop inside guest environment.";
                f.evidence = e.message + " " + e.details;
                f.source = "QEMU Sandbox Tracer";
                f.tags = {"FileDrop", "Dropper", "MITRE:T1105"};
                findings.push_back(f);
            } else if (e.type == Sandbox::EventType::Registry) {
                Finding f;
                f.id = "SBX_REGISTRY_MODIFIED";
                f.category = "Persistence";
                f.severity = FindingSeverity::High;
                f.confidence = FindingConfidence::High;
                f.title = "Registry Key Modification: " + e.message;
                f.description = "Observed persistent Windows registry key modification.";
                f.evidence = e.message + " " + e.details;
                f.source = "QEMU Sandbox Tracer";
                f.tags = {"Persistence", "Registry", "MITRE:T1547"};
                findings.push_back(f);
            }
        }

        return findings;
    }

} // namespace Dracula
