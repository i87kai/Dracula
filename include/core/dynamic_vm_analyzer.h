#pragma once

#include "analyzer_interface.h"
#include "../host/qemu_manager.h"
#include "../host/live_tcp_server.h"
#include <atomic>
#include <mutex>
#include <memory>

namespace Sandbox {

    /**
     * @brief Automated Dynamic Sandbox Execution Engine powered by QEMU Hypervisor
     */
    class DynamicVMAnalyzer : public IAnalyzer {
    public:
        DynamicVMAnalyzer();
        virtual ~DynamicVMAnalyzer() override;

        bool Initialize(const VMConfig& vmConfig, const TraceOptions& options) override;
        void SetEventCallback(EventCallback callback) override;
        bool RunAnalysis(const std::string& executablePath) override;
        void StopAnalysis() override;
        AnalysisReport GetReport() const override;

    private:
        void HandleIncomingEvent(const TraceEvent& event);

        VMConfig m_vmConfig;
        TraceOptions m_options;
        EventCallback m_callback;
        AnalysisReport m_report;
        
        std::unique_ptr<QemuManager> m_qemu;
        std::unique_ptr<LiveTcpServer> m_tcpServer;

        std::atomic<bool> m_isRunning{false};
        mutable std::mutex m_reportMutex;
    };

} // namespace Sandbox
