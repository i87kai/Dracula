#pragma once

#include "analyzer_interface.h"
#include "common/findings.h"
#include "core/win32_hle.h"
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>
#include <string>
#include <vector>
#include <span>
#include <mutex>
#include <cstdint>
#include <unordered_map>
#include <memory>

namespace Dracula {

    struct EmulationOptions {
        uint64_t maxInstructions = 10000;
        uint64_t timeoutMicros = 5000000; // 5 seconds
        bool     strictSandbox = false;
        AntiDebugPolicy antiDebugPolicy = AntiDebugPolicy::Bypass;
        bool     traceInstructions = true;
    };

    class UnicornAnalyzer : public Sandbox::IAnalyzer {
    public:
        UnicornAnalyzer();
        virtual ~UnicornAnalyzer() override;

        // Legacy IAnalyzer interface
        bool Initialize(const Sandbox::VMConfig& vmConfig, const Sandbox::TraceOptions& options) override;
        void SetEventCallback(Sandbox::EventCallback callback) override;
        bool RunAnalysis(const std::string& executablePath) override;
        void StopAnalysis() override;
        Sandbox::AnalysisReport GetReport() const override;

        // Modern structured emulation pipeline
        EmulationResult EmulatePE(
            const std::string& pePath,
            const EmulationOptions& opts = {},
            std::vector<Finding>* outFindings = nullptr
        );

        // In-memory buffer emulation with legacy signature
        Sandbox::FunctionEmulationResult EmulateBuffer(
            std::span<const uint8_t> code,
            uint64_t baseAddress,
            const std::unordered_map<uc_x86_reg, uint64_t>& initialRegs = {},
            const std::vector<std::string>& outputRegNames = { "RAX", "RBX", "RCX", "RDX" },
            bool is64Bit = true,
            uint64_t maxInstructions = 1000,
            uint64_t stopAddress = 0,
            uint64_t timeoutMicros = 0
        );

        Win32Hle& GetHle() { return m_hle; }

    private:
        static bool ReadNamedRegister(uc_engine* uc, bool is64Bit, const std::string& name, uint64_t& outValue);

        bool LoadAndMapPE(const std::string& filePath, uint64_t& outEntryPoint, uint64_t& outEndAddress, bool& outIs64Bit, uint64_t& outImageBase);
        bool SetupVirtualMemoryAndStack(bool is64Bit, uint64_t& outStackTop);
        void RegisterHooks(bool strict);

        static void HookCodeCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
        static void HookMemWriteCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
        static bool HookMemUnmappedCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);

        void OnInstructionExecuted(uint64_t address, uint32_t size);
        void OnMemoryWrite(uint64_t address, int size, int64_t value);
        void EmitEvent(Sandbox::EventType type, const std::string& category, const std::string& msg, const std::string& details = "");

        uc_engine* m_uc = nullptr;
        uc_hook m_codeHook = 0;
        uc_hook m_memWriteHook = 0;
        uc_hook m_unmappedHook = 0;

        Win32Hle m_hle;
        EmulationOptions m_emuOptions;
        EmulationResult m_currentEmulationResult;
        std::vector<Finding>* m_currentFindingsPtr = nullptr;

        Sandbox::TraceOptions m_options;
        Sandbox::EventCallback m_callback;
        Sandbox::AnalysisReport m_report;
        bool m_isRunning = false;
        bool m_is64Bit = true;
        uint64_t m_instructionCount = 0;
        mutable std::mutex m_mutex;
    };

} // namespace Dracula

namespace Sandbox {
    using UnicornAnalyzer = Dracula::UnicornAnalyzer;
}
