#include "agent/dracula_agent.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#endif

#include <iostream>
#include <string>
#include <thread>
#include <atomic>

static std::atomic<bool> g_running(false);
static HANDLE g_hPipe = INVALID_HANDLE_VALUE;

extern "C" {

    DRACULA_AGENT_API uint32_t DraculaAgentGetVersion() {
        return 0x00010200; // v1.2.0
    }

    DRACULA_AGENT_API bool DraculaAgentInitialize(const char* pipeName) {
        if (g_running) return true;
        g_running = true;

#ifdef _WIN32
        std::string pName = pipeName ? pipeName : "\\\\.\\pipe\\DraculaAgentPipe";
        g_hPipe = CreateFileA(pName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (g_hPipe == INVALID_HANDLE_VALUE) {
            // Pipe server might not be listening yet, which is expected
        }
#endif
        return true;
    }

    DRACULA_AGENT_API void DraculaAgentShutdown() {
        g_running = false;
#ifdef _WIN32
        if (g_hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(g_hPipe);
            g_hPipe = INVALID_HANDLE_VALUE;
        }
#endif
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
