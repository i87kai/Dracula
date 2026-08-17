#pragma once

#include "common/types.h"
#include "common/findings.h"
#include <string>

namespace Dracula {

    class ReportWriter {
    public:
        // Save Unified Analysis Result to disk in chosen format
        static bool SaveReport(const UnifiedAnalysisResult& result, const std::string& outputPath, const std::string& format = "auto");

        // Format helpers
        static std::string ToJson(const UnifiedAnalysisResult& result);
        static std::string ToMarkdown(const UnifiedAnalysisResult& result);
        static std::string ToText(const UnifiedAnalysisResult& result);

        // Legacy compatibility
        static std::string GenerateTextReport(const Sandbox::AnalysisReport& report);
        static bool SaveReportToFile(const Sandbox::AnalysisReport& report, const std::string& outputPath);
    };

} // namespace Dracula

namespace Sandbox {
    using ReportWriter = Dracula::ReportWriter;
}
