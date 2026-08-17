#include "guest/system_tracer.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#endif

#include <chrono>
#include <sstream>
#include <iostream>
#include <filesystem>

namespace Sandbox::Guest {

    SystemTracer::SystemTracer(const TraceOptions& options, uint32_t targetPid, const std::string& watchDir)
        : m_options(options), m_targetPid(targetPid), m_watchDir(watchDir) {}

    SystemTracer::~SystemTracer() {
        Stop();
    }

    void SystemTracer::Start(TraceEventCallback callback) {
        m_callback = std::move(callback);
        m_isRunning = true;

        if (m_options.monitorProcesses) {
            m_processThread = std::thread(&SystemTracer::MonitorProcessesLoop, this);
        }
        if (m_options.monitorNetwork) {
            m_networkThread = std::thread(&SystemTracer::MonitorNetworkLoop, this);
        }
        if (m_options.monitorFiles) {
            m_fileThread = std::thread(&SystemTracer::MonitorFileSystemLoop, this);
        }
    }

    void SystemTracer::Stop() {
        m_isRunning = false;
        if (m_processThread.joinable()) m_processThread.join();
        if (m_networkThread.joinable()) m_networkThread.join();
        if (m_fileThread.joinable()) m_fileThread.join();
    }

    void SystemTracer::MonitorProcessesLoop() {
#ifdef _WIN32
        {
            std::lock_guard<std::mutex> lock(m_pidsMutex);
            m_knownPids.insert(m_targetPid);
        }

        while (m_isRunning) {
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe;
                pe.dwSize = sizeof(PROCESSENTRY32);

                if (Process32First(hSnap, &pe)) {
                    do {
                        bool isNewChild = false;
                        {
                            std::lock_guard<std::mutex> lock(m_pidsMutex);
                            if (m_knownPids.count(pe.th32ParentProcessID) && !m_knownPids.count(pe.th32ProcessID)) {
                                m_knownPids.insert(pe.th32ProcessID);
                                isNewChild = true;
                            }
                        }

                        if (isNewChild && m_callback) {
                            TraceEvent evt;
                            evt.type = EventType::ProcessCreated;
                            evt.timestampMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch()).count());
                            evt.category = "Process";
                            evt.message = "Child Process Spawned: " + std::string(pe.szExeFile) + " (PID: " + std::to_string(pe.th32ProcessID) + ")";
                            evt.details = "Parent PID: " + std::to_string(pe.th32ParentProcessID);
                            m_callback(evt);
                        }
                    } while (Process32Next(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
#endif
    }

    void SystemTracer::MonitorNetworkLoop() {
#ifdef _WIN32
        while (m_isRunning) {
            ULONG size = 0;
            if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
                std::vector<uint8_t> buffer(size);
                auto pTcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

                if (GetExtendedTcpTable(pTcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                    for (DWORD i = 0; i < pTcpTable->dwNumEntries; ++i) {
                        DWORD pid = pTcpTable->table[i].dwOwningPid;
                        bool isTrackedPid = false;
                        {
                            std::lock_guard<std::mutex> lock(m_pidsMutex);
                            isTrackedPid = (m_knownPids.count(pid) > 0 || pid == m_targetPid);
                        }

                        if (isTrackedPid) {
                            in_addr remoteAddr;
                            remoteAddr.s_addr = pTcpTable->table[i].dwRemoteAddr;
                            uint16_t remotePort = ntohs(static_cast<u_short>(pTcpTable->table[i].dwRemotePort));

                            std::string remoteIp = inet_ntoa(remoteAddr);
                            std::string connKey = std::to_string(pid) + ":" + remoteIp + ":" + std::to_string(remotePort);

                            if (remotePort > 0 && !m_knownConnections.count(connKey)) {
                                m_knownConnections.insert(connKey);

                                if (m_callback) {
                                    TraceEvent evt;
                                    evt.type = EventType::NetworkConnect;
                                    evt.timestampMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch()).count());
                                    evt.category = "Network";
                                    evt.message = "Outbound TCP Connection to " + remoteIp + ":" + std::to_string(remotePort);
                                    evt.details = "PID: " + std::to_string(pid);
                                    m_callback(evt);
                                }
                            }
                        }
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
#endif
    }

    void SystemTracer::MonitorFileSystemLoop() {
#ifdef _WIN32
        std::string targetDir = m_watchDir;
        if (!std::filesystem::exists(targetDir)) {
            char tempPath[MAX_PATH];
            if (GetTempPathA(MAX_PATH, tempPath) > 0) {
                targetDir = tempPath;
            } else {
                return;
            }
        }

        HANDLE hDir = CreateFileA(
            targetDir.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            nullptr
        );

        if (hDir == INVALID_HANDLE_VALUE) return;

        char buffer[2048];
        DWORD bytesReturned = 0;

        while (m_isRunning) {
            if (ReadDirectoryChangesW(
                hDir,
                buffer,
                sizeof(buffer),
                TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
                &bytesReturned,
                nullptr,
                nullptr
            ) && bytesReturned > 0) {
                
                auto pNotify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);
                while (pNotify) {
                    std::wstring fileName(pNotify->FileName, pNotify->FileNameLength / sizeof(WCHAR));
                    std::string narrowName(fileName.begin(), fileName.end());

                    EventType fType = EventType::FileModified;
                    std::string actionName = "Modified";

                    switch (pNotify->Action) {
                        case FILE_ACTION_ADDED:
                            fType = EventType::FileCreated;
                            actionName = "Created";
                            break;
                        case FILE_ACTION_REMOVED:
                            fType = EventType::FileDeleted;
                            actionName = "Deleted";
                            break;
                        case FILE_ACTION_MODIFIED:
                            fType = EventType::FileModified;
                            actionName = "Modified";
                            break;
                        default:
                            break;
                    }

                    if (m_callback && !narrowName.empty()) {
                        TraceEvent evt;
                        evt.type = fType;
                        evt.timestampMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count());
                        evt.category = "FileSystem";
                        evt.message = "File " + actionName + ": " + narrowName;
                        evt.details = "Directory: " + targetDir + "\\" + narrowName;
                        m_callback(evt);
                    }

                    if (pNotify->NextEntryOffset == 0) break;
                    pNotify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                        reinterpret_cast<uint8_t*>(pNotify) + pNotify->NextEntryOffset);
                }
            }
        }
        CloseHandle(hDir);
#endif
    }

} // namespace Sandbox::Guest
