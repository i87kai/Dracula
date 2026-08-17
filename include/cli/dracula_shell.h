#pragma once

#include "common/findings.h"
#include "core/analysis_orchestrator.h"
#include "cli/command_registry.h"
#include "cli/line_editor.h"
#include "cli/terminal.h"
#include <string>
#include <vector>
#include <memory>

namespace Dracula {

    class DraculaShell {
    public:
        DraculaShell();
        ~DraculaShell();

        // Run interactive REPL loop with line editor and slash palette
        int RunInteractive();

        // Execute a single command line (for scripted/REPL dispatch)
        bool ExecuteCommand(const std::string& commandLine);

        // Process non-interactive command line arguments
        int ProcessArgs(int argc, char* argv[]);

        // Version & Banner
        static std::string GetVersion();
        static void PrintBanner();
        static void PrintCompactHeader();
        static void PrintHelp(const std::string& specificCommand = "");
        static void PrintVersion();

        // Subtle one-line description of the active session ("" when none).
        std::string SessionStatusLine() const;

        // Public Command Handlers
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
        void HandleFunctions(const std::vector<std::string>& args);
        void HandleXrefs(const std::vector<std::string>& args);
        void HandleFindings(const std::vector<std::string>& args);
        void HandleReport(const std::vector<std::string>& args);
        void HandleSession(const std::vector<std::string>& args);
        void HandleMcp(const std::vector<std::string>& args);
        void HandleChangelog(const std::vector<std::string>& args);
        void HandleVersion(const std::vector<std::string>& args);
        void HandleClear(const std::vector<std::string>& args);
        void HandleHelp(const std::vector<std::string>& args);
        void HandleExit(const std::vector<std::string>& args);

        // Active session state access
        const std::string& GetActiveFile() const { return m_activeFile; }
        const UnifiedAnalysisResult* GetSessionResult() const { return m_sessionResult.get(); }
        void SetActiveSession(const std::string& file, std::unique_ptr<UnifiedAnalysisResult> result);

    private:
        std::string ResolveTargetFile(const std::vector<std::string>& args, size_t index = 0);

        AnalysisOrchestrator m_orchestrator;
        std::unique_ptr<UnifiedAnalysisResult> m_sessionResult;
        std::string m_activeFile;
        LineEditor m_editor;
        bool m_running = true;
    };

} // namespace Dracula
