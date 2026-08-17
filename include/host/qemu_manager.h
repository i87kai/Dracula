#pragma once

#include "common/types.h"
#include "common/config.h"
#include <string>
#include <vector>

namespace Sandbox {

    /**
     * @brief Manages QEMU Hypervisor lifecycle with automated -snapshot rollback.
     *
     * Networking note, because this used to be wrong:
     *
     *   The guest dials OUT to the host through the SLIRP gateway alias
     *   10.0.2.2, which user-mode networking provides for free. The host never
     *   connects INTO the guest, so no `hostfwd` rule is required. Asking QEMU
     *   to forward an inbound host port made it try to bind the same port
     *   Dracula's telemetry listener already held, and QEMU exited before the
     *   guest booted. Outbound-only is both simpler and conflict-free.
     */
    class QemuManager {
    public:
        explicit QemuManager(const QemuConfig& config = ConfigManager::Instance().GetQemuConfig());
        explicit QemuManager(const std::string& diskPath);
        ~QemuManager();

        // Check if QEMU executable exists
        bool CheckQemuInstallation();

        // Build the exact command line StartQemu would run. Exposed so the
        // launch arguments can be asserted on without booting a guest.
        std::string BuildCommandLine(bool headless) const;

        // Start QEMU in background mode with -snapshot (non-destructive).
        // Verifies the process is still alive after a short settle window, so a
        // QEMU that rejects its arguments is reported as a failure here rather
        // than surfacing later as a mysteriously silent guest.
        bool StartQemu(bool headless = false);

        // Terminate QEMU process
        void StopQemu();

        // Check if QEMU process is currently running
        bool IsRunning() const;

        // Exit code of the QEMU process once it has exited (0 while running).
        uint32_t ExitCode() const;

        // Why the last StartQemu failed, including anything QEMU printed on
        // stderr before giving up.
        const std::string& LastError() const { return m_lastError; }

        const QemuConfig& GetConfig() const { return m_config; }

    private:
        void DrainDiagnostics();
        void CloseDiagnosticPipe();

        QemuConfig  m_config;
        void*       m_hProcess = nullptr;
        uint32_t    m_processId = 0;
        std::string m_lastError;
        std::string m_diagnostics;

        void* m_stderrRead = nullptr;
        void* m_stderrWrite = nullptr;
    };

} // namespace Sandbox
