#pragma once

#include "analyzer_interface.h"
#include "common/findings.h"
#include "core/win32_hle.h"
#include "core/virtual_time.h"
#include "core/branch_influence.h"
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>
#include <string>
#include <vector>
#include <span>
#include <mutex>
#include <cstdint>
#include <unordered_map>
#include <map>
#include <set>
#include <memory>

namespace Dracula {

    struct EmulationOptions {
        uint64_t maxInstructions = 10000;
        uint64_t timeoutMicros = 5000000; // 5 seconds
        bool     strictSandbox = false;
        AntiDebugPolicy antiDebugPolicy = AntiDebugPolicy::Bypass;
        bool     traceInstructions = true;

        // The controlled environment this run executes under. Baseline
        // reproduces Dracula's historical behaviour.
        EnvironmentProfile environmentProfile = EnvironmentProfile::Baseline();

        // Anti-evasion instrumentation. Off by default so ordinary /analyze and
        // /emulate runs pay nothing for it.
        bool recordCoverage = false;       // basic blocks, functions, branches
        bool trackBranchInfluence = false; // bounded environment provenance
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
        EnvironmentRuntime& GetEnvironment() { return m_env; }

    public:
        static bool ReadNamedRegister(uc_engine* uc, bool is64Bit, const std::string& name, uint64_t& outValue);

    private:

        bool LoadAndMapPE(const std::string& filePath, uint64_t& outEntryPoint, uint64_t& outEndAddress, bool& outIs64Bit, uint64_t& outImageBase);
        bool SetupVirtualMemoryAndStack(bool is64Bit, uint64_t& outStackTop);
        void RegisterHooks(bool strict);

        static void HookCodeCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
        static void HookBlockCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
        static void HookMemWriteCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
        static bool HookMemUnmappedCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
        static int  HookCpuidCallback(uc_engine* uc, void* user_data);

    public:
        // Answers CPUID from the active EnvironmentProfile. Public so buffer
        // level machine-code tests exercise exactly the same code path as a
        // full PE run.
        void OnCpuid(uc_engine* uc);

        // Timestamp-counter instructions are intercepted from the code hook:
        // Unicorn has no RDTSC instruction hook, so the encoding is recognised,
        // the registers are written from the virtual clock, and the program
        // counter is stepped past the instruction.
        bool InterceptEnvironmentInstruction(uc_engine* uc, uint64_t address, uint32_t size);

        // Install CPUID / timestamp interception on an arbitrary engine.
        void InstallEnvironmentHooks(uc_engine* uc, uc_hook& outCpuidHook, uc_hook& outCodeHook);

    private:

        void RecordCoverage(uint64_t address, uint32_t size);
        void UpdateBranchTracking(uint64_t address);

        void OnInstructionExecuted(uint64_t address, uint32_t size);
        void OnMemoryWrite(uint64_t address, int size, int64_t value);
        void EmitEvent(Sandbox::EventType type, const std::string& category, const std::string& msg, const std::string& details = "");

        uc_engine* m_uc = nullptr;
        uc_hook m_codeHook = 0;
        uc_hook m_blockHook = 0;
        uc_hook m_memWriteHook = 0;
        uc_hook m_unmappedHook = 0;
        uc_hook m_cpuidHook = 0;

        // ── Anti-evasion instrumentation state ──
        EnvironmentRuntime      m_env;
        BranchInfluenceTracker  m_taint;
        uint64_t                m_imageBase = 0;
        uint64_t                m_currentBlock = 0;

        // A conditional branch that just executed; resolved on the next
        // instruction, when the actual destination is known.
        struct PendingBranch {
            bool     active = false;
            uint64_t address = 0;
            uint64_t rva = 0;
            uint64_t takenTarget = 0;
            uint64_t fallthrough = 0;
            std::string mnemonic;
        } m_pendingBranch;

        std::map<uint64_t, BranchObservation> m_branches;
        std::set<uint64_t> m_uniqueAddresses;
        bool m_pendingCall = false;

        // Decoded once per address, then reused: an emulated loop must not pay
        // for Capstone on every iteration.
        struct DecodedInsn {
            uint32_t size = 0;
            unsigned id = 0;
            std::string text;
            std::vector<unsigned> readRegs;
            std::vector<unsigned> writtenRegs;
            bool writesFlags = false;
            bool readsFlags = false;
            bool isConditionalBranch = false;
            bool isCall = false;
            bool isReturn = false;
            bool isUnconditionalJump = false;
            uint64_t immediateTarget = 0;

            // A memory source operand, so provenance can follow an environment
            // value out of a structure an API filled in.
            bool     readsMemory = false;
            unsigned memBase = 0;
            unsigned memIndex = 0;
            int      memScale = 1;
            int64_t  memDisp = 0;

            bool valid = false;
        };
        std::map<uint64_t, DecodedInsn> m_decodeCache;
        const DecodedInsn* DecodeAt(uint64_t address);

        // Resolve a memory operand's effective address from live registers.
        bool EffectiveAddress(uc_engine* uc, const DecodedInsn& insn, uint64_t address,
                              uint64_t& outAddress) const;

        // Capstone handle used for register-access analysis during execution.
        uint64_t m_csHandle = 0;
        bool     m_csValid = false;
        void OpenDecoder(bool is64Bit);
        void CloseDecoder();

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
