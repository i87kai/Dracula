#pragma once

#include "analyzer_interface.h"
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>
#include <string>
#include <vector>
#include <span>
#include <mutex>
#include <cstdint>
#include <unordered_map>

namespace Sandbox {

    /**
     * @brief High-performance CPU & Instruction-level Emulation Analyzer using Unicorn Engine 2
     */
    class UnicornAnalyzer : public IAnalyzer {
    public:
        UnicornAnalyzer();
        virtual ~UnicornAnalyzer() override;

        bool Initialize(const VMConfig& vmConfig, const TraceOptions& options) override;
        void SetEventCallback(EventCallback callback) override;
        bool RunAnalysis(const std::string& executablePath) override;
        void StopAnalysis() override;
        AnalysisReport GetReport() const override;

        /**
         * @brief Emulate an isolated in-memory instruction buffer to resolve runtime
         *        offsets/pointers without requiring a full PE load from disk.
         *
         * Spins up a dedicated Unicorn context (independent of RunAnalysis's context),
         * maps the buffer page-aligned at baseAddress, seeds initial register state,
         * runs bounded emulation, and returns the requested output registers.
         *
         * Thread-safe: safe to call concurrently with RunAnalysis/StopAnalysis on the
         * same UnicornAnalyzer instance, and safe to call from multiple threads on
         * distinct UnicornAnalyzer instances.
         *
         * @param code            Raw instruction bytes to emulate.
         * @param baseAddress     Virtual address the buffer should be mapped at (need not be page-aligned).
         * @param initialRegs     Optional initial register values (e.g. {UC_X86_REG_RCX, 0x1000}).
         * @param outputRegNames  Register names to read back after emulation (e.g. {"RAX", "RBX"}).
         * @param is64Bit         Selects UC_MODE_64 vs UC_MODE_32.
         * @param maxInstructions Bounded instruction count (0 = library default of 1000).
         * @param stopAddress     Optional absolute address to stop emulation at; 0 = run to end of buffer.
         * @param timeoutMicros   Optional wall-clock timeout in microseconds; 0 = no timeout.
         */
        FunctionEmulationResult EmulateBuffer(
            std::span<const uint8_t> code,
            uint64_t baseAddress,
            const std::unordered_map<uc_x86_reg, uint64_t>& initialRegs = {},
            const std::vector<std::string>& outputRegNames = { "RAX", "RBX", "RCX", "RDX" },
            bool is64Bit = true,
            uint64_t maxInstructions = 1000,
            uint64_t stopAddress = 0,
            uint64_t timeoutMicros = 0);

    private:
        static bool ReadNamedRegister(uc_engine* uc, bool is64Bit, const std::string& name, uint64_t& outValue);

        // PE Header loading & memory layout
        bool LoadAndMapPE(const std::string& filePath, uint64_t& outEntryPoint, uint64_t& outEndAddress, bool& outIs64Bit);
        bool SetupVirtualMemoryAndStack(bool is64Bit, uint64_t& outStackTop);
        void RegisterHooks();

        // Hook callbacks
        static void HookCodeCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
        static void HookMemWriteCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
        static bool HookMemUnmappedCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);

        void OnInstructionExecuted(uint64_t address, uint32_t size);
        void OnMemoryWrite(uint64_t address, int size, int64_t value);

        void EmitEvent(EventType type, const std::string& category, const std::string& msg, const std::string& details = "");

        uc_engine* m_uc = nullptr;
        uc_hook m_codeHook = 0;
        uc_hook m_memWriteHook = 0;
        uc_hook m_unmappedHook = 0;

        TraceOptions m_options;
        EventCallback m_callback;
        AnalysisReport m_report;
        bool m_isRunning = false;
        bool m_is64Bit = true;
        uint64_t m_instructionCount = 0;
        mutable std::mutex m_mutex;
    };

} // namespace Sandbox
