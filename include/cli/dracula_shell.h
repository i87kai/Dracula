#pragma once

#include "common/findings.h"
#include "core/analysis_orchestrator.h"
#include <string>
#include <vector>
#include <memory>

namespace Dracula {

    class DraculaShell {
    public:
        DraculaShell();
        ~DraculaShell();

        // Run interactive REPL loop
        int RunInteractive();

        // Execute a single command line (for scripted/REPL dispatch)
        bool ExecuteCommand(const std::string& commandLine);

        // Process non-interactive command line arguments
        int ProcessArgs(int argc, char* argv[]);

        // Banner and help
        static void PrintBanner();
        static void PrintHelp();
        static void PrintVersion();

    private:
        void HandleAnalyze(const std::vector<std::string>& args);
        void HandleEmulate(const std::vector<std::string>& args);
        void HandleDisasm(const std::vector<std::string>& args);
        void HandleCfg(const std::vector<std::string>& args);
        void HandleHeaders(const std::vector<std::string>& args);
        void HandleSecurity(const std::vector<std::string>& args);
        void HandleImports(const std::vector<std::string>& args);
        void HandleExports(const std::vector<std::string>& args);
        void HandleStrings(const std::vector<std::string>& args);
        void HandleEntropy(const std::vector<std::string>& args);
        void HandleSandbox(const std::vector<std::string>& args);
        void HandleScan(const std::vector<std::string>& args);
        void HandleFindings(const std::vector<std::string>& args);
        void HandleReport(const std::vector<std::string>& args);
        void HandleSession(const std::vector<std::string>& args);

        std::string ResolveTargetFile(const std::vector<std::string>& args, size_t index = 0);

        AnalysisOrchestrator m_orchestrator;
        std::unique_ptr<UnifiedAnalysisResult> m_sessionResult;
        std::string m_activeFile;
        bool m_running = true;
    };

} // namespace Dracula
