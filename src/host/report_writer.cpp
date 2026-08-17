#include "host/report_writer.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>

namespace Dracula {

    std::string ReportWriter::ToJson(const UnifiedAnalysisResult& result) {
        return result.ToJson();
    }

    std::string ReportWriter::ToMarkdown(const UnifiedAnalysisResult& result) {
        return result.ToMarkdown();
    }

    std::string ReportWriter::ToText(const UnifiedAnalysisResult& result) {
        return result.ToAnsiSummary();
    }

    bool ReportWriter::SaveReport(const UnifiedAnalysisResult& result, const std::string& outputPath, const std::string& format) {
        std::string chosenFmt = format;
        if (chosenFmt == "auto") {
            std::string ext = std::filesystem::path(outputPath).extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (ext == ".json") chosenFmt = "json";
            else if (ext == ".md" || ext == ".markdown") chosenFmt = "md";
            else chosenFmt = "txt";
        }

        std::string content;
        if (chosenFmt == "json") content = ToJson(result);
        else if (chosenFmt == "md") content = ToMarkdown(result);
        else content = ToText(result);

        std::ofstream file(outputPath);
        if (!file.is_open()) return false;
        file << content;
        return true;
    }

    std::string ReportWriter::GenerateTextReport(const Sandbox::AnalysisReport& report) {
        std::ostringstream ss;
        ss << "======================================================================\n";
        ss << " SANDBOX ANALYSIS REPORT\n";
        ss << " Type: " << report.analysisType << "\n";
        ss << " Events Recorded: " << report.events.size() << "\n";
        ss << " Threat Score: " << report.threatScore << " / 100\n";
        ss << "======================================================================\n";
        for (const auto& e : report.events) {
            ss << "[" << e.category << "] " << e.message;
            if (!e.details.empty()) ss << " (" << e.details << ")";
            ss << "\n";
        }
        return ss.str();
    }

    bool ReportWriter::SaveReportToFile(const Sandbox::AnalysisReport& report, const std::string& outputPath) {
        std::ofstream file(outputPath);
        if (!file.is_open()) return false;
        file << GenerateTextReport(report);
        return true;
    }

} // namespace Dracula
