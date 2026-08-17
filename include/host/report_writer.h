#pragma once

#include "../common/types.h"
#include <string>

namespace Sandbox {

    class ReportWriter {
    public:
        // Format report into a detailed human-readable text document
        static std::string GenerateTextReport(const AnalysisReport& report);

        // Save report to disk as a text file
        static bool SaveReportToFile(const AnalysisReport& report, const std::string& outputPath);
    };

} // namespace Sandbox
