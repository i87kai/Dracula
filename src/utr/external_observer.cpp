#include "utr/external_observer.h"

#include <chrono>
#include <iostream>
#include <algorithm>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#endif

namespace Dracula {
namespace UTR {

    EtwObserver::EtwObserver() = default;
    EtwObserver::~EtwObserver() {
        StopObserving();
    }

    bool EtwObserver::StartObserving(uint32_t pid, std::string& outError) {
        m_targetPid = pid;
#ifdef _WIN32
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) {
            outError = "Cannot observe PID " + std::to_string(pid) + ": Access denied or invalid PID.";
            return false;
        }
        CloseHandle(hProcess);
        m_active = true;

        UtrRuntimeEvent ev;
        ev.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        ev.pid = pid;
        ev.eventType = "PROCESS_ATTACH_OBSERVER";
        ev.sourceBackend = "ETW/ExternalObserver";
        ev.details = "Non-invasive external observation started for PID " + std::to_string(pid);
        m_queuedEvents.push_back(ev);

        return true;
#else
        outError = "ETW Observer requires Windows host.";
        return false;
#endif
    }

    void EtwObserver::StopObserving() {
        m_active = false;
    }

    std::vector<UtrRuntimeEvent> EtwObserver::PollEvents() {
        std::vector<UtrRuntimeEvent> events;
        if (!m_active) return events;

        events = std::move(m_queuedEvents);
        m_queuedEvents.clear();

#ifdef _WIN32
        // Check if process is still alive
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_targetPid);
        if (hProcess) {
            DWORD exitCode = 0;
            if (GetExitCodeProcess(hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
                UtrRuntimeEvent ev;
                ev.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                ev.pid = m_targetPid;
                ev.eventType = "PROCESS_EXIT";
                ev.sourceBackend = "ETW/ExternalObserver";
                ev.details = "Process terminated with exit code " + std::to_string(exitCode);
                events.push_back(ev);
                m_active = false;
            }
            CloseHandle(hProcess);
        } else {
            m_active = false;
        }
#endif
        return events;
    }

} // namespace UTR
} // namespace Dracula
