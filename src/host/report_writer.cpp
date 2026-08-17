#include "host/report_writer.h"
#include "core/entropy_analyzer.h"
#include "core/threat_evaluator.h"
#include <sstream>
#include <fstream>
#include <iomanip>
#include <ctime>

namespace Sandbox {

    std::string ReportWriter::GenerateTextReport(const AnalysisReport& report) {
        std::ostringstream ss;

        auto formatTime = [](std::chrono::system_clock::time_point tp) -> std::string {
            std::time_t t = std::chrono::system_clock::to_time_t(tp);
            std::tm localTm;
#ifdef _WIN32
            localtime_s(&localTm, &t);
#else
            localtime_r(&t, &localTm);
#endif
            char buf[64];
            std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &localTm);
            return buf;
        };

        // Run Entropy & Packing Analysis
        BinaryPackingAnalysis packing = EntropyAnalyzer::AnalyzeBinary(report.targetExecutable);
        ThreatAssessment threat = ThreatEvaluator::Evaluate(report, packing);

        ss << "================================================================================\n";
        ss << "                      SANDBOX ADVANCED ANALYSIS & THREAT REPORT                \n";
        ss << "================================================================================\n";
        ss << "Target Executable : " << report.targetExecutable << "\n";
        ss << "Analysis Engine   : " << report.analysisType << "\n";
        ss << "Start Time        : " << formatTime(report.startTime) << "\n";
        ss << "End Time          : " << formatTime(report.endTime) << "\n";
        ss << "Exit Code         : " << report.exitCode << "\n";
        ss << "--------------------------------------------------------------------------------\n";
        ss << "SECURITY VERDICT & THREAT SCORING:\n";
        ss << " [!] Final Threat Verdict : " << threat.verdict << "\n";
        ss << " [!] Threat Score         : " << threat.threatScore << " / 100\n";
        ss << " [!] Packing / Crypter    : " << packing.detectedPacker << " (Entropy: " << std::fixed << std::setprecision(2) << packing.overallEntropy << " / 8.00)\n";
        ss << "--------------------------------------------------------------------------------\n";
        ss << "ACTIVITY SUMMARY STATISTICS:\n";
        ss << " - Processes Spawned   : " << report.totalProcessesCreated << "\n";
        ss << " - Files Modified      : " << report.totalFilesModified << "\n";
        ss << " - Network Connections : " << report.totalNetworkConnections << "\n";
        ss << " - Registry Changes    : " << report.totalRegistryChanges << "\n";
        ss << " - Total Events Logged : " << report.events.size() << "\n";
        ss << "================================================================================\n\n";

        // Section Breakdown & Entropy
        ss << "PE SECTION ENTROPY & PACKER AUDIT:\n";
        ss << "--------------------------------------------------------------------------------\n";
        ss << std::left << std::setw(10) << "Section"
           << std::setw(14) << "VirtSize"
           << std::setw(14) << "RawSize"
           << std::setw(12) << "Entropy"
           << std::setw(12) << "Flags"
           << "Status\n";
        ss << "--------------------------------------------------------------------------------\n";
        for (const auto& sec : packing.sections) {
            std::string flags = "";
            if (sec.isExecutable && sec.isWritable) flags = "RWX";
            else if (sec.isExecutable) flags = "RX";
            else if (sec.isWritable) flags = "RW";
            else flags = "R";

            std::string status = sec.isPacked ? "PACKED / CRYPT" : "NORMAL";

            ss << std::left << std::setw(10) << sec.name
               << std::setw(14) << sec.virtualSize
               << std::setw(14) << sec.rawSize
               << std::setw(12) << std::fixed << std::setprecision(2) << sec.entropy
               << std::setw(12) << flags
               << status << "\n";
        }
        ss << "================================================================================\n\n";

        // MITRE ATT&CK Techniques Mapped
        if (!threat.mitreTechniques.empty()) {
            ss << "MITRE ATT&CK THREAT MATRIX MAPPING:\n";
            ss << "--------------------------------------------------------------------------------\n";
            for (const auto& m : threat.mitreTechniques) {
                ss << " [" << m.id << "] " << std::setw(28) << std::left << m.name 
                   << " | Tactic: " << std::setw(18) << m.tactic 
                   << " | " << m.evidence << "\n";
            }
            ss << "================================================================================\n\n";
        }

        // Chronological Event Log
        ss << "CHRONOLOGICAL RUNTIME EVENT LOG:\n";
        ss << "--------------------------------------------------------------------------------\n";
        for (const auto& evt : report.events) {
            std::time_t timeSec = static_cast<std::time_t>(evt.timestampMs / 1000);
            std::tm localTm;
#ifdef _WIN32
            localtime_s(&localTm, &timeSec);
#else
            localtime_r(&timeSec, &localTm);
#endif
            char timeBuf[16];
            std::strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", &localTm);

            ss << "[" << timeBuf << "] [" << std::setw(12) << std::left << evt.category << "] " << evt.message;
            if (!evt.details.empty()) {
                ss << " (" << evt.details << ")";
            }
            ss << "\n";
        }
        ss << "================================================================================\n";

        return ss.str();
    }

    bool ReportWriter::SaveReportToFile(const AnalysisReport& report, const std::string& filePath) {
        std::ofstream ofs(filePath);
        if (!ofs.is_open()) return false;
        ofs << GenerateTextReport(report);
        return true;
    }

} // namespace Sandbox
