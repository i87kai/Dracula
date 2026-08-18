#include "utr/analysis_orchestrator.h"
#include "core/analysis_orchestrator.h"
#include "core/anti_evasion_engine.h"
#include "utr/session_manager.h"
#include "utr/artifact_manager.h"
#include "utr/managed_backend.h"

#include <chrono>
#include <iostream>
#include <sstream>
#include <iomanip>

namespace Dracula {
namespace UTR {

    static std::string EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            if (c == '"') o << "\\\"";
            else if (c == '\\') o << "\\\\";
            else if (c == '\n') o << "\\n";
            else if (c == '\r') o << "\\r";
            else if (c == '\t') o << "\\t";
            else o << c;
        }
        return o.str();
    }

    UtrAnalysisOrchestrator& UtrAnalysisOrchestrator::Instance() {
        static UtrAnalysisOrchestrator instance;
        return instance;
    }

    UtrAnalysisResult UtrAnalysisOrchestrator::RunAnalysis(
        std::shared_ptr<ITarget> target,
        const UtrOrchestratorOptions& options)
    {
        auto startTime = std::chrono::steady_clock::now();
        UtrAnalysisResult result;
        if (!target) return result;

        result.target = target->GetInfo();
        result.level = options.level;

        // ─── 1. QUICK ANALYSIS PASS ─────────────────────────────────────────
        AnalysisOrchestrator legacyOrchestrator;
        OrchestratorOptions legacyOpts;
        legacyOpts.enableEmulation = (options.level != AnalysisLevel::Quick);

        if (result.target.kind == TargetKind::NativeExe ||
            result.target.kind == TargetKind::NativeDll ||
            result.target.kind == TargetKind::Driver)
        {
            result.staticResult = legacyOrchestrator.AnalyzeFile(result.target.path, legacyOpts);
        }

        // Populate initial Evidence Graph nodes from static findings
        for (const auto& f : result.staticResult.findings) {
            EvidenceNode node;
            node.id = f.id;
            node.category = f.category;
            node.severity = f.severity;
            node.confidence = f.confidence;
            node.truthLevel = EvidenceTruthLevel::Observed;
            node.title = f.title;
            node.description = f.description;
            node.evidenceData = f.evidence;
            node.provenance.engine = f.source;
            node.provenance.address = f.virtualAddress;
            node.provenance.rva = f.rva;
            node.tags = f.tags;
            result.evidenceGraph.AddEvidence(node);
        }

        // ─── 2. DEEP ANALYSIS PASS ──────────────────────────────────────────
        if (options.level >= AnalysisLevel::Deep) {
            result.functionIntelligence.IndexStaticFunctions(
                result.staticResult.functions,
                result.staticResult.xrefs,
                result.staticResult.strings,
                result.staticResult.imports,
                result.target.name
            );

            // Enumerate functions directly from target backend
            auto funcsRes = target->EnumerateFunctions();
            if (funcsRes.Ok()) {
                for (const auto& fn : funcsRes.Value()) {
                    if (!result.functionIntelligence.FindByRva(fn.rva) && !result.functionIntelligence.FindByName(fn.name)) {
                        result.functionIntelligence.AddFunction(fn);
                    }

                    if (result.target.kind == TargetKind::ManagedExe || result.target.kind == TargetKind::ManagedDll) {
                        EvidenceNode node;
                        node.id = "MGD_" + fn.name;
                        node.category = "ManagedIntelligence";
                        node.severity = FindingSeverity::Info;
                        node.confidence = FindingConfidence::High;
                        node.truthLevel = EvidenceTruthLevel::Observed;
                        node.title = "Managed Method Indexed";
                        node.description = fn.interestReasoning;
                        node.provenance.engine = "ManagedHost";
                        node.tags = {"Managed", ".NET", "Metadata"};
                        result.evidenceGraph.AddEvidence(node);
                    }
                }
            }
        }

        // ─── 3. RUNTIME ANALYSIS PASS ───────────────────────────────────────
        if (options.level >= AnalysisLevel::Runtime) {
            auto memMapRes = target->GetMemoryMap();
            if (memMapRes.Ok()) {
                auto snap1 = result.memoryIntelligence.CaptureSnapshot(memMapRes.Value(), "Pre-Execution Baseline");
                (void)snap1;

                // Correlate runtime addresses
                std::vector<uint64_t> execAddresses;
                for (const auto& block : result.staticResult.emulation.coverage.basicBlocks) {
                    execAddresses.push_back(block);
                }
                result.functionIntelligence.CorrelateRuntimeExecutions(execAddresses, result.staticResult.emulation.hleCalls);

                auto snap2 = result.memoryIntelligence.CaptureSnapshot(memMapRes.Value(), "Post-Execution State");
                auto comp = result.memoryIntelligence.CompareSnapshots(1, 2);
                auto transformations = result.memoryIntelligence.DetectTransformations(comp, execAddresses);
                result.memoryIntelligence.CorrelateWithEvidenceGraph(result.evidenceGraph, transformations);
            }
        }

        // ─── 4. FULL ANALYSIS PASS & ESCALATION ─────────────────────────────
        if (options.level == AnalysisLevel::Full) {
            // Run Anti-Evasion Engine
            if (!result.target.path.empty()) {
                AntiEvasionEngine aeEngine;
                AntiEvasionOptions aeOpts;
                aeOpts.runComparison = true;
                aeOpts.useEmulation = true;
                auto aeRes = aeEngine.Analyze(result.target.path, aeOpts, &result.staticResult);

                result.staticResult.antiEvasionScore = aeRes.environmentSensitivityScore;
                result.staticResult.antiEvasionSensitivity = aeRes.sensitivityLabel;
                result.staticResult.antiEvasionJson = aeRes.ToJson();
                result.staticResult.antiEvasionMarkdown = aeRes.ToMarkdown();

                // Escalation check
                if (options.autoEscalation != AutoEscalationPolicy::Off) {
                    if (aeRes.environmentSensitivityScore >= 60 || result.target.kind == TargetKind::Driver) {
                        result.escalationOccurred = true;
                        result.escalatedBackend = "QEMU_Sandbox";
                        result.escalationReason = (result.target.kind == TargetKind::Driver) ?
                            "Kernel driver runtime observation requires QEMU isolation." :
                            "High anti-evasion sensitivity detected (Score: " + std::to_string(aeRes.environmentSensitivityScore) + "); full environment validation recommended in QEMU.";
                    }
                }
            }
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime).count();
        result.durationMs = elapsed;

        // Persist to session and structured artifacts
        uint32_t activeSessionId = SessionManager::Instance().GetActiveSessionId();
        if (activeSessionId > 0) {
            SessionManager::Instance().SaveSession(activeSessionId, &result.staticResult, &result.evidenceGraph, &result.functionIntelligence, &result.memoryIntelligence);
            ArtifactManager::Instance().WriteSessionArtifacts(activeSessionId, result.target, &result.staticResult, &result.evidenceGraph, &result.functionIntelligence, &result.memoryIntelligence);
        }

        return result;
    }

    std::string UtrAnalysisResult::ToJson() const {
        std::ostringstream oss;
        oss << "{\n";
        oss << "  \"target\": \"" << EscapeJson(target.name) << "\",\n";
        oss << "  \"kind\": \"" << TargetKindToString(target.kind) << "\",\n";
        oss << "  \"analysis_level\": \"" << AnalysisLevelToString(level) << "\",\n";
        oss << "  \"duration_ms\": " << durationMs << ",\n";
        oss << "  \"escalation\": {\n";
        oss << "    \"occurred\": " << (escalationOccurred ? "true" : "false") << ",\n";
        oss << "    \"backend\": \"" << EscapeJson(escalatedBackend) << "\",\n";
        oss << "    \"reason\": \"" << EscapeJson(escalationReason) << "\"\n";
        oss << "  },\n";
        oss << "  \"functions_discovered\": " << functionIntelligence.TotalDiscovered() << ",\n";
        oss << "  \"interesting_functions\": " << functionIntelligence.InterestingCount() << ",\n";
        oss << "  \"evidence_nodes\": " << evidenceGraph.GetNodes().size() << ",\n";
        oss << "  \"behavior_chains\": " << evidenceGraph.GetChains().size() << "\n";
        oss << "}\n";
        return oss.str();
    }

    std::string UtrAnalysisResult::ToMarkdown() const {
        std::ostringstream oss;
        oss << "# Dracula UTR Analysis Report: " << target.name << "\n\n";
        oss << "**Target Kind**: `" << TargetKindToString(target.kind) << "` | **Analysis Level**: `"
            << AnalysisLevelToString(level) << "` | **Duration**: " << durationMs << " ms\n\n";

        if (escalationOccurred) {
            oss << "> [!IMPORTANT]\n";
            oss << "> **Automated Escalation**: Escalated to `" << escalatedBackend << "`.\n";
            oss << "> **Reason**: " << escalationReason << "\n\n";
        }

        oss << functionIntelligence.ToMarkdownSummary(10) << "\n\n";
        oss << evidenceGraph.ToMarkdown() << "\n";
        return oss.str();
    }

} // namespace UTR
} // namespace Dracula
