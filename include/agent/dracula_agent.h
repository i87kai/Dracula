#pragma once

#include <cstdint>
#include <string>

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
    DRACULA_AGENT_API uint32_t DraculaAgentGetVersion();
    DRACULA_AGENT_API bool DraculaAgentInitialize(const char* pipeName);
    DRACULA_AGENT_API void DraculaAgentShutdown();
}
