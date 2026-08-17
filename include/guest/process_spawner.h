#pragma once

#include "common/types.h"
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>

namespace Sandbox::Guest {

    using OutputCallback = std::function<void(bool isStderr, const std::string& line)>;
    using ExitCallback = std::function<void(uint32_t exitCode)>;

    class ProcessSpawner {
    public:
        ProcessSpawner();
        ~ProcessSpawner();

        // Launch target executable with redirected pipes
        bool Launch(const std::string& exePath, const std::string& commandLineArgs,
                    OutputCallback outCb, ExitCallback exitCb);

        // Terminate the process and clean up threads
        void Terminate();

        // Check if process is still running
        bool IsRunning() const;

        // Get Process ID
        uint32_t GetProcessId() const { return m_processId; }

    private:
        void ReadPipeLoop(void* pipeHandle, bool isStderr);
        void WaitForExitLoop();
        void CleanupHandles();

        uint32_t m_processId = 0;
        void* m_hProcess = nullptr;
        void* m_hThread = nullptr;
        void* m_hStdOutRead = nullptr;
        void* m_hStdErrRead = nullptr;

        OutputCallback m_outCallback;
        ExitCallback m_exitCallback;
        std::atomic<bool> m_isRunning{false};

        std::mutex m_joinMutex;
        std::thread m_stdoutThread;
        std::thread m_stderrThread;
        std::thread m_waitThread;
    };

} // namespace Sandbox::Guest
