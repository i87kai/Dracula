#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

#include "utr/types.h"

namespace Dracula {
namespace UTR {

    struct UtrRuntimeEvent {
        int64_t     timestampMs = 0;
        uint32_t    pid = 0;
        uint32_t    tid = 0;
        std::string eventType;      // "PROCESS_CREATE", "THREAD_CREATE", "MODULE_LOAD", "MEM_ALLOC", "MEM_PROTECT", "API_CALL", "EXCEPTION"
        std::string moduleName;
        uint64_t    address = 0;
        std::string details;
        std::string sourceBackend;  // "ETW", "DbgEng", "Agent"
    };

    class IExternalObserver {
    public:
        virtual ~IExternalObserver() = default;

        virtual bool StartObserving(uint32_t pid, std::string& outError) = 0;
        virtual void StopObserving() = 0;
        virtual std::vector<UtrRuntimeEvent> PollEvents() = 0;
        virtual bool IsActive() const = 0;
    };

    class EtwObserver : public IExternalObserver {
    public:
        EtwObserver();
        ~EtwObserver() override;

        bool StartObserving(uint32_t pid, std::string& outError) override;
        void StopObserving() override;
        std::vector<UtrRuntimeEvent> PollEvents() override;
        bool IsActive() const override { return m_active; }

    private:
        uint32_t m_targetPid = 0;
        bool     m_active = false;
        std::vector<UtrRuntimeEvent> m_queuedEvents;
    };

    // DbgHelp / DbgEng Process & Symbol Backend
    // Implements: DbgHelp Symbol Resolution (SymInitialize, SymFromAddr, SymGetModuleInfo64) & Process Memory Reading (ReadProcessMemory)
    class DbgEngBackend {
    public:
        DbgEngBackend();
        ~DbgEngBackend();

        bool Initialize(std::string& outError);
        bool AttachProcess(uint32_t pid, std::string& outError);
        void Detach();

        Result<std::vector<UtrModuleInfo>> EnumerateModules();
        Result<std::vector<UtrThreadInfo>> EnumerateThreads();
        Result<std::vector<uint8_t>> ReadMemory(uint64_t address, size_t size);
        Result<std::string> ResolveSymbol(uint64_t address);

        bool IsAttached() const { return m_attached; }

    private:
        void*    m_hDbgEngDll = nullptr;
        void*    m_hDbgHelpDll = nullptr;
        void*    m_processHandle = nullptr;
        uint32_t m_targetPid = 0;
        bool     m_initialized = false;
        bool     m_attached = false;
    };

    // Primary name representing the actual dbghelp.dll symbol & memory integration
    using DbgHelpBackend = DbgEngBackend;

} // namespace UTR
} // namespace Dracula
