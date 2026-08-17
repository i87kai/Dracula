#include "guest/process_spawner.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include <iostream>
#include <vector>

namespace Sandbox::Guest {

    ProcessSpawner::ProcessSpawner() = default;

    ProcessSpawner::~ProcessSpawner() {
        Terminate();
    }

    bool ProcessSpawner::Launch(const std::string& exePath, const std::string& commandLineArgs,
                               OutputCallback outCb, ExitCallback exitCb) {
#ifdef _WIN32
        Terminate(); // Ensure any previous session is cleaned up

        m_outCallback = std::move(outCb);
        m_exitCallback = std::move(exitCb);

        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = nullptr;

        HANDLE hStdOutRead = nullptr, hStdOutWrite = nullptr;
        HANDLE hStdErrRead = nullptr, hStdErrWrite = nullptr;

        if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) return false;
        SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);

        if (!CreatePipe(&hStdErrRead, &hStdErrWrite, &sa, 0)) {
            CloseHandle(hStdOutRead);
            CloseHandle(hStdOutWrite);
            return false;
        }
        SetHandleInformation(hStdErrRead, HANDLE_FLAG_INHERIT, 0);

        m_hStdOutRead = hStdOutRead;
        m_hStdErrRead = hStdErrRead;

        STARTUPINFOA si;
        ZeroMemory(&si, sizeof(STARTUPINFOA));
        si.cb = sizeof(STARTUPINFOA);
        si.hStdOutput = hStdOutWrite;
        si.hStdError = hStdErrWrite;
        si.dwFlags |= STARTF_USESTDHANDLES;

        PROCESS_INFORMATION pi;
        ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

        std::string cmdLine = "\"" + exePath + "\" " + commandLineArgs;
        std::vector<char> cmdVec(cmdLine.begin(), cmdLine.end());
        cmdVec.push_back('\0');

        BOOL success = CreateProcessA(
            nullptr,
            cmdVec.data(),
            nullptr,
            nullptr,
            TRUE,
            0,
            nullptr,
            nullptr,
            &si,
            &pi
        );

        // Close write handles in parent process so EOF can be reached
        CloseHandle(hStdOutWrite);
        CloseHandle(hStdErrWrite);

        if (!success) {
            CloseHandle(hStdOutRead);
            CloseHandle(hStdOutRead);
            m_hStdOutRead = nullptr;
            m_hStdErrRead = nullptr;
            return false;
        }

        m_processId = pi.dwProcessId;
        m_hProcess = pi.hProcess;
        m_hThread = pi.hThread;
        m_isRunning = true;

        // Launch reader threads for stdout and stderr
        m_stdoutThread = std::thread(&ProcessSpawner::ReadPipeLoop, this, m_hStdOutRead, false);
        m_stderrThread = std::thread(&ProcessSpawner::ReadPipeLoop, this, m_hStdErrRead, true);
        m_waitThread = std::thread(&ProcessSpawner::WaitForExitLoop, this);

        return true;
#else
        return false;
#endif
    }

    void ProcessSpawner::ReadPipeLoop(void* pipeHandle, bool isStderr) {
#ifdef _WIN32
        HANDLE hPipe = static_cast<HANDLE>(pipeHandle);
        char buffer[1024];
        DWORD bytesRead = 0;
        std::string currentLine;

        while (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            for (DWORD i = 0; i < bytesRead; ++i) {
                if (buffer[i] == '\r') continue;
                if (buffer[i] == '\n') {
                    if (m_outCallback && !currentLine.empty()) {
                        m_outCallback(isStderr, currentLine);
                    }
                    currentLine.clear();
                } else {
                    currentLine += buffer[i];
                }
            }
        }

        if (!currentLine.empty() && m_outCallback) {
            m_outCallback(isStderr, currentLine);
        }
#endif
    }

    void ProcessSpawner::WaitForExitLoop() {
#ifdef _WIN32
        HANDLE hProc = static_cast<HANDLE>(m_hProcess);
        if (hProc) {
            WaitForSingleObject(hProc, INFINITE);

            DWORD exitCode = 0;
            GetExitCodeProcess(hProc, &exitCode);

            m_isRunning = false;

            if (m_exitCallback) {
                m_exitCallback(exitCode);
            }
        }
#endif
    }

    void ProcessSpawner::CleanupHandles() {
#ifdef _WIN32
        if (m_hStdOutRead) {
            CloseHandle(static_cast<HANDLE>(m_hStdOutRead));
            m_hStdOutRead = nullptr;
        }
        if (m_hStdErrRead) {
            CloseHandle(static_cast<HANDLE>(m_hStdErrRead));
            m_hStdErrRead = nullptr;
        }
        if (m_hThread) {
            CloseHandle(static_cast<HANDLE>(m_hThread));
            m_hThread = nullptr;
        }
        if (m_hProcess) {
            CloseHandle(static_cast<HANDLE>(m_hProcess));
            m_hProcess = nullptr;
        }
#endif
    }

    void ProcessSpawner::Terminate() {
#ifdef _WIN32
        if (m_isRunning.load() && m_hProcess) {
            TerminateProcess(static_cast<HANDLE>(m_hProcess), 1);
            m_isRunning = false;
        }

        std::lock_guard<std::mutex> lock(m_joinMutex);
        if (m_waitThread.joinable()) {
            m_waitThread.join();
        }
        if (m_stdoutThread.joinable()) {
            m_stdoutThread.join();
        }
        if (m_stderrThread.joinable()) {
            m_stderrThread.join();
        }

        CleanupHandles();
#endif
    }

    bool ProcessSpawner::IsRunning() const {
        return m_isRunning.load();
    }

} // namespace Sandbox::Guest
