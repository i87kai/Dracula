#include "core/threat_evaluator.h"

namespace Sandbox {

    ThreatAssessment ThreatEvaluator::Evaluate(const AnalysisReport& report, const BinaryPackingAnalysis& packing) {
        ThreatAssessment assessment;
        int score = 0;

        // 1. Evaluate Packing and Entropy
        if (packing.isPacked) {
            score += 25;
            assessment.highlights.push_back("Binary is Packed / Protected (" + packing.detectedPacker + ") - High Entropy: " + std::to_string(packing.overallEntropy));
            assessment.mitreTechniques.push_back({"T1027.002", "Software Packing", "Defense Evasion", packing.detectedPacker});
        }

        // 2. Evaluate Network Connections
        if (report.totalNetworkConnections > 0) {
            score += 25;
            assessment.highlights.push_back("Outbound C2 / Network Socket Connections Established: " + std::to_string(report.totalNetworkConnections));
            assessment.mitreTechniques.push_back({"T1071.001", "Web Protocols / C2 Connection", "Command and Control", "Outbound socket connect"});
        }

        // 3. Evaluate Child Process Creation
        for (const auto& evt : report.events) {
            if (evt.type == EventType::Stdout || evt.type == EventType::ProcessCreated) {
                if (evt.message.find("cmd.exe") != std::string::npos || evt.message.find("whoami") != std::string::npos || evt.message.find("powershell") != std::string::npos) {
                    score += 25;
                    assessment.highlights.push_back("Suspicious Command Execution / Reconnaissance (" + evt.message + ")");
                    assessment.mitreTechniques.push_back({"T1059.003", "Windows Command Shell", "Execution", evt.message});
                    break;
                }
            }
        }

        // 4. Evaluate File Operations
        for (const auto& evt : report.events) {
            if (evt.type == EventType::Stdout || evt.type == EventType::FileCreated || evt.type == EventType::FileModified) {
                if (evt.message.find("Temp") != std::string::npos || evt.message.find("dropped") != std::string::npos || evt.message.find("payload") != std::string::npos) {
                    score += 15;
                    assessment.highlights.push_back("Dropped Payload / Suspicious File Write in Temp Directory: " + evt.message);
                    assessment.mitreTechniques.push_back({"T1070", "Indicator Removal / Payload Staging", "Defense Evasion", evt.message});
                    break;
                }
            }
        }

        // 5. Evaluate Registry Changes
        if (report.totalRegistryChanges > 0) {
            score += 20;
            assessment.highlights.push_back("Registry Persistence / Startup Modification Detected.");
            assessment.mitreTechniques.push_back({"T1547.001", "Registry Run Keys / Startup Folder", "Persistence", "Registry persistence mod"});
        }

        if (score > 100) score = 100;
        assessment.threatScore = score;

        if (score >= 60) {
            assessment.verdict = "HIGH RISK - MALICIOUS";
        } else if (score >= 20) {
            assessment.verdict = "MEDIUM RISK - SUSPICIOUS";
        } else {
            assessment.verdict = "LOW RISK - BENIGN / CLEAN";
        }

        return assessment;
    }

} // namespace Sandbox
