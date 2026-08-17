#pragma once

#include "core/analysis_orchestrator.h"
#include <string>
#include <vector>

namespace Dracula {

    class McpServer {
    public:
        McpServer();
        ~McpServer();

        // Run stdio JSON-RPC 2.0 loop until EOF or shutdown
        void RunStdio();

        // Process a single JSON-RPC request and return the JSON-RPC response
        std::string ProcessMessage(const std::string& requestJson);

    private:
        AnalysisOrchestrator m_orchestrator;
    };

} // namespace Dracula
