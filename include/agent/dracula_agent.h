#pragma once

#include <cstdint>

#ifdef _WIN32
#ifdef DRACULA_AGENT_EXPORTS
#define DRACULA_AGENT_API __declspec(dllexport)
#else
#define DRACULA_AGENT_API __declspec(dllimport)
#endif
#else
#define DRACULA_AGENT_API
#endif

extern "C" {
    // Dracula In-Process Telemetry Agent API
    // Instrumentation Engine: Custom Minimal Win32 Telemetry Instrumentation
    DRACULA_AGENT_API uint32_t    DraculaAgentGetVersion();
    DRACULA_AGENT_API const char* DraculaAgentGetEngineName();
    DRACULA_AGENT_API bool        DraculaAgentInitialize(const char* pipeName);
    DRACULA_AGENT_API bool        DraculaAgentSendEvent(const char* eventJson);
    DRACULA_AGENT_API uint32_t    DraculaAgentEnumerateModules(char* outBuffer, uint32_t maxLen);
    DRACULA_AGENT_API bool        DraculaAgentRecordMemoryProtection(uint64_t address, uint64_t size, uint32_t newProtect);
    DRACULA_AGENT_API void        DraculaAgentShutdown();
}
