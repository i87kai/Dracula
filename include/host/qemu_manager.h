#pragma once

#include "common/types.h"
#include "common/config.h"
#include <string>
#include <vector>

namespace Sandbox {

    /**
     * @brief Manages QEMU Hypervisor lifecycle with automated -snapshot and port forwarding
     */
    class QemuManager {
    public:
        explicit QemuManager(const QemuConfig& config = ConfigManager::Instance().GetQemuConfig());
        explicit QemuManager(const std::string& diskPath);
        ~QemuManager();

        // Check if QEMU executable exists
        bool CheckQemuInstallation();

        // Start QEMU in background mode with -snapshot (non-destructive)
        bool StartQemu(bool headless = false, uint16_t hostPort = 8899);

        // Terminate QEMU process
        void StopQemu();

        // Check if QEMU process is currently running
        bool IsRunning() const;

        const QemuConfig& GetConfig() const { return m_config; }

    private:
        QemuConfig m_config;
        void* m_hProcess = nullptr;
        uint32_t m_processId = 0;
    };

} // namespace Sandbox
