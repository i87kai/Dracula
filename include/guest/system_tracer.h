#pragma once

#include "common/types.h"
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <set>
#include <string>

namespace Sandbox::Guest {

    using TraceEventCallback = std::function<void(const TraceEvent&)>;

    class SystemTracer {
    public:
        SystemTracer(const TraceOptions& options, uint32_t targetPid, const std::string& watchDir = "C:\\Sandbox");
        ~SystemTracer();

        // Start background monitoring loops based on enabled TraceOptions
        void Start(TraceEventCallback callback);

        // Stop all background monitoring
        void Stop();

    private:
        void MonitorProcessesLoop();
        void MonitorNetworkLoop();
        void MonitorFileSystemLoop();

        TraceOptions m_options;
        uint32_t m_targetPid;
        std::string m_watchDir;
        TraceEventCallback m_callback;
        std::atomic<bool> m_isRunning{false};

        std::thread m_processThread;
        std::thread m_networkThread;
        std::thread m_fileThread;

        std::mutex m_pidsMutex;
        std::set<uint32_t> m_knownPids;
        std::set<std::string> m_knownConnections;
    };

} // namespace Sandbox::Guest
