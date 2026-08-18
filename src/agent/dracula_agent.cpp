#include "agent/dracula_agent.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#endif

#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <mutex>
#include <cstring>

static std::atomic<bool> g_running(false);
static HANDLE g_hPipe = INVALID_HANDLE_VALUE;
static std::mutex g_eventMutex;
static std::vector<std::string> g_eventLog;

extern "C" {

    DRACULA_AGENT_API uint32_t DraculaAgentGetVersion() {
        return 0x00010201; // v1.2.1
    }

    DRACULA_AGENT_API const char* DraculaAgentGetEngineName() {
        return "Dracula Custom Minimal Telemetry Instrumentation";
    }

    DRACULA_AGENT_API bool DraculaAgentInitialize(const char* pipeName) {
        if (g_running) return true;
        g_running = true;

#ifdef _WIN32
        std::string pName = pipeName ? pipeName : "\\\\.\\pipe\\DraculaAgentPipe";
        g_hPipe = CreateFileA(pName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        // Note: Pipe server might not be listening yet, which is handled gracefully
#endif
        std::lock_guard<std::mutex> lock(g_eventMutex);
        g_eventLog.push_back("{\"event\":\"AGENT_INITIALIZED\",\"version\":\"1.2.1\"}");
        return true;
    }

    DRACULA_AGENT_API bool DraculaAgentSendEvent(const char* eventJson) {
        if (!eventJson) return false;
        std::lock_guard<std::mutex> lock(g_eventMutex);
        g_eventLog.push_back(eventJson);

#ifdef _WIN32
        if (g_hPipe != INVALID_HANDLE_VALUE) {
            DWORD bytesWritten = 0;
            DWORD len = static_cast<DWORD>(strlen(eventJson));
            WriteFile(g_hPipe, eventJson, len, &bytesWritten, nullptr);
        }
#endif
        return true;
    }

    DRACULA_AGENT_API uint32_t DraculaAgentEnumerateModules(char* outBuffer, uint32_t maxLen) {
        if (!outBuffer || maxLen == 0) return 0;
        std::ostringstream oss;
        oss << "[";

#ifdef _WIN32
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me;
            me.dwSize = sizeof(me);
            bool first = true;
            if (Module32FirstW(hSnap, &me)) {
                do {
                    std::wstring ws(me.szModule);
                    std::string modName(ws.begin(), ws.end());
                    if (!first) oss << ",";
                    first = false;
                    oss << "{\"name\":\"" << modName << "\",\"base\":\"0x" << std::hex << reinterpret_cast<uint64_t>(me.modBaseAddr) << std::dec << "\"}";
                } while (Module32NextW(hSnap, &me));
            }
            CloseHandle(hSnap);
        }
#endif
        oss << "]";
        std::string res = oss.str();
        uint32_t copied = static_cast<uint32_t>(res.length() < maxLen - 1 ? res.length() : maxLen - 1);
        std::memcpy(outBuffer, res.c_str(), copied);
        outBuffer[copied] = '\0';
        return copied;
    }

    DRACULA_AGENT_API bool DraculaAgentRecordMemoryProtection(uint64_t address, uint64_t size, uint32_t newProtect) {
        std::ostringstream oss;
        oss << "{\"event\":\"MEM_PROTECT\",\"address\":\"0x" << std::hex << address
            << "\",\"size\":" << std::dec << size
            << ",\"new_protect\":\"0x" << std::hex << newProtect << "\"}";
        return DraculaAgentSendEvent(oss.str().c_str());
    }

    DRACULA_AGENT_API void DraculaAgentShutdown() {
        g_running = false;
#ifdef _WIN32
        if (g_hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(g_hPipe);
            g_hPipe = INVALID_HANDLE_VALUE;
        }
#endif
        std::lock_guard<std::mutex> lock(g_eventMutex);
        g_eventLog.push_back("{\"event\":\"AGENT_SHUTDOWN\"}");
    }

} // extern "C"

#ifdef _WIN32
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL; (void)lpvReserved;
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            DraculaAgentShutdown();
            break;
    }
    return TRUE;
}
#endif
