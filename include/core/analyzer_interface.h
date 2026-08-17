#pragma once

#include "common/types.h"
#include <functional>
#include <memory>

namespace Sandbox {

    // Callback type for receiving live stream events in real time
    using EventCallback = std::function<void(const TraceEvent&)>;

    // Abstract Analyzer Interface
    class IAnalyzer {
    public:
        virtual ~IAnalyzer() = default;

        // Initialize analyzer configuration and environments
        virtual bool Initialize(const VMConfig& vmConfig, const TraceOptions& options) = 0;

        // Register a callback to receive events as they occur in real time
        virtual void SetEventCallback(EventCallback callback) = 0;

        // Start the analysis session on the specified target executable
        virtual bool RunAnalysis(const std::string& executablePath) = 0;

        // Stop or cancel an ongoing analysis session
        virtual void StopAnalysis() = 0;

        // Retrieve the generated session report
        virtual AnalysisReport GetReport() const = 0;
    };

} // namespace Sandbox
