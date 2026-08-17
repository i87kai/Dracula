#include "core/unicorn_analyzer.h"
#include "core/pe_inspector.h"
#include "core/disassembler.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace Dracula {

    static constexpr uint64_t STACK_BASE_64 = 0x7FFF00100000ULL;
    static constexpr size_t   STACK_SIZE_64 = 0x00100000ULL; // 1 MB stack

    UnicornAnalyzer::UnicornAnalyzer() = default;

    UnicornAnalyzer::~UnicornAnalyzer() {
        StopAnalysis();
    }

    bool UnicornAnalyzer::Initialize(const Sandbox::VMConfig& vmConfig, const Sandbox::TraceOptions& options) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_options = options;
        m_report = Sandbox::AnalysisReport();
        m_report.analysisType = "Unicorn Engine 2 CPU Emulation (Native Instruction Tracing)";
        m_instructionCount = 0;
        return true;
    }

    void UnicornAnalyzer::SetEventCallback(Sandbox::EventCallback callback) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_callback = callback;
    }

    void UnicornAnalyzer::StopAnalysis() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_isRunning = false;
        if (m_uc) {
            uc_emu_stop(m_uc);
            uc_close(m_uc);
            m_uc = nullptr;
        }
    }

    Sandbox::AnalysisReport UnicornAnalyzer::GetReport() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_report;
    }

    void UnicornAnalyzer::EmitEvent(Sandbox::EventType type, const std::string& category, const std::string& msg, const std::string& details) {
        Sandbox::TraceEvent event;
        event.type = type;
        event.category = category;
        event.message = msg;
        event.details = details;
        event.pid = 0x1337;
        event.processName = "UnicornEmu";
        event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        if (m_callback) {
            m_callback(event);
        }
        m_report.events.push_back(event);
    }

    bool UnicornAnalyzer::ReadNamedRegister(uc_engine* uc, bool is64Bit, const std::string& name, uint64_t& outValue) {
        std::string upper = name;
        std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

        int regId = -1;
        if (is64Bit) {
            if (upper == "RAX") regId = UC_X86_REG_RAX;
            else if (upper == "RBX") regId = UC_X86_REG_RBX;
            else if (upper == "RCX") regId = UC_X86_REG_RCX;
            else if (upper == "RDX") regId = UC_X86_REG_RDX;
            else if (upper == "RSI") regId = UC_X86_REG_RSI;
            else if (upper == "RDI") regId = UC_X86_REG_RDI;
            else if (upper == "RBP") regId = UC_X86_REG_RBP;
            else if (upper == "RSP") regId = UC_X86_REG_RSP;
            else if (upper == "RIP") regId = UC_X86_REG_RIP;
            else if (upper == "R8")  regId = UC_X86_REG_R8;
            else if (upper == "R9")  regId = UC_X86_REG_R9;
            else if (upper == "R10") regId = UC_X86_REG_R10;
            else if (upper == "R11") regId = UC_X86_REG_R11;
            else if (upper == "R12") regId = UC_X86_REG_R12;
            else if (upper == "R13") regId = UC_X86_REG_R13;
            else if (upper == "R14") regId = UC_X86_REG_R14;
            else if (upper == "R15") regId = UC_X86_REG_R15;
            else if (upper == "EFLAGS") regId = UC_X86_REG_EFLAGS;
        } else {
            if (upper == "EAX" || upper == "RAX") regId = UC_X86_REG_EAX;
            else if (upper == "EBX" || upper == "RBX") regId = UC_X86_REG_EBX;
            else if (upper == "ECX" || upper == "RCX") regId = UC_X86_REG_ECX;
            else if (upper == "EDX" || upper == "RDX") regId = UC_X86_REG_EDX;
            else if (upper == "ESI" || upper == "RSI") regId = UC_X86_REG_ESI;
            else if (upper == "EDI" || upper == "RDI") regId = UC_X86_REG_EDI;
            else if (upper == "EBP" || upper == "RBP") regId = UC_X86_REG_EBP;
            else if (upper == "ESP" || upper == "RSP") regId = UC_X86_REG_ESP;
            else if (upper == "EIP" || upper == "RIP") regId = UC_X86_REG_EIP;
            else if (upper == "EFLAGS") regId = UC_X86_REG_EFLAGS;
        }

        if (regId == -1) return false;
        return uc_reg_read(uc, regId, &outValue) == UC_ERR_OK;
    }

    bool UnicornAnalyzer::LoadAndMapPE(const std::string& filePath, uint64_t& outEntryPoint, uint64_t& outEndAddress, bool& outIs64Bit, uint64_t& outImageBase) {
        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(filePath, err)) {
            EmitEvent(Sandbox::EventType::Error, "Loader", "PE Parse Failed", err);
            return false;
        }

        const auto& meta = inspector.GetMetadata();
        outIs64Bit = meta.is64Bit;
        outImageBase = meta.imageBase ? meta.imageBase : 0x140000000ULL;
        outEntryPoint = outImageBase + meta.entryPointRva;
        outEndAddress = outEntryPoint + 0x10000;

        const auto& sections = inspector.GetSections();
        const uint8_t* rawData = inspector.GetBuffer();
        size_t rawSize = inspector.GetBufferSize();

        // Map PE sections into Unicorn
        for (const auto& sec : sections) {
            uint64_t secVa = outImageBase + sec.virtualAddress;
            size_t secSize = (sec.virtualSize + 0xFFF) & ~0xFFFULL;
            if (secSize == 0) secSize = 0x1000;

            uint32_t ucProt = UC_PROT_READ;
            if (sec.isWritable) ucProt |= UC_PROT_WRITE;
            if (sec.isExecutable) ucProt |= UC_PROT_EXEC;

            uc_err mapErr = uc_mem_map(m_uc, secVa, secSize, ucProt);
            if (mapErr != UC_ERR_OK && mapErr != UC_ERR_MAP) {
                EmitEvent(Sandbox::EventType::Error, "Loader", "Failed to map section " + sec.name, uc_strerror(mapErr));
                continue;
            }

            if (sec.rawAddress < rawSize && sec.rawSize > 0) {
                size_t copySize = std::min<size_t>(sec.rawSize, rawSize - sec.rawAddress);
                copySize = std::min<size_t>(copySize, secSize);
                uc_mem_write(m_uc, secVa, rawData + sec.rawAddress, copySize);
            }
        }

        // Patch Imports with Synthetic HLE Thunk Pointers
        const auto& imports = inspector.GetImports();
        for (const auto& imp : imports) {
            uint64_t thunkAddr = m_hle.GetOrCreateApiThunk(imp.dllName, imp.functionName);
            uint64_t iatVa = outImageBase + imp.iatRva;

            if (outIs64Bit) {
                uc_mem_write(m_uc, iatVa, &thunkAddr, sizeof(thunkAddr));
            } else {
                uint32_t thunk32 = static_cast<uint32_t>(thunkAddr);
                uc_mem_write(m_uc, iatVa, &thunk32, sizeof(thunk32));
            }
        }

        return true;
    }

    bool UnicornAnalyzer::SetupVirtualMemoryAndStack(bool is64Bit, uint64_t& outStackTop) {
        uc_err err = uc_mem_map(m_uc, STACK_BASE_64, STACK_SIZE_64, UC_PROT_READ | UC_PROT_WRITE);
        if (err != UC_ERR_OK && err != UC_ERR_MAP) {
            EmitEvent(Sandbox::EventType::Error, "Memory", "Failed to map shadow stack", uc_strerror(err));
            return false;
        }

        outStackTop = STACK_BASE_64 + STACK_SIZE_64 - 0x1000;

        if (is64Bit) {
            uc_reg_write(m_uc, UC_X86_REG_RSP, &outStackTop);
            uc_reg_write(m_uc, UC_X86_REG_RBP, &outStackTop);
        } else {
            uint32_t sp32 = static_cast<uint32_t>(outStackTop);
            uc_reg_write(m_uc, UC_X86_REG_ESP, &sp32);
            uc_reg_write(m_uc, UC_X86_REG_EBP, &sp32);
        }

        return true;
    }

    void UnicornAnalyzer::RegisterHooks(bool strict) {
        uc_hook_add(m_uc, &m_codeHook, UC_HOOK_CODE, reinterpret_cast<void*>(HookCodeCallback), this, 1, 0);
        uc_hook_add(m_uc, &m_memWriteHook, UC_HOOK_MEM_WRITE, reinterpret_cast<void*>(HookMemWriteCallback), this, 1, 0);
        uc_hook_add(m_uc, &m_unmappedHook, UC_HOOK_MEM_UNMAPPED, reinterpret_cast<void*>(HookMemUnmappedCallback), this, 1, 0);
    }

    void UnicornAnalyzer::HookCodeCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
        auto* self = static_cast<UnicornAnalyzer*>(user_data);
        self->OnInstructionExecuted(address, size);
    }

    void UnicornAnalyzer::HookMemWriteCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {
        auto* self = static_cast<UnicornAnalyzer*>(user_data);
        self->OnMemoryWrite(address, size, value);
    }

    bool UnicornAnalyzer::HookMemUnmappedCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {
        auto* self = static_cast<UnicornAnalyzer*>(user_data);
        if (self->m_emuOptions.strictSandbox) {
            self->EmitEvent(Sandbox::EventType::Error, "UnmappedMemory", "Strict Sandbox: Fault at unmapped address", "0x" + std::to_string(address));
            return false;
        }

        // On-demand page mapping (4KB aligned)
        uint64_t pageAddr = address & ~0xFFFULL;
        uc_err err = uc_mem_map(uc, pageAddr, 0x1000, UC_PROT_ALL);
        return (err == UC_ERR_OK || err == UC_ERR_MAP);
    }

    void UnicornAnalyzer::OnInstructionExecuted(uint64_t address, uint32_t size) {
        m_instructionCount++;

        // 1. Check if execution jumped to synthetic HLE thunk
        if (address >= Win32Hle::kHleThunkBase && address < Win32Hle::kHleThunkBase + 0x20000) {
            std::string lib, api;
            if (m_hle.ResolveThunk(address, lib, api)) {
                HleCallContext ctx;
                ctx.library = lib;
                ctx.apiName = api;
                ctx.is64Bit = m_is64Bit;
                ctx.antiDebugPolicy = m_emuOptions.antiDebugPolicy;

                // Read arguments and caller return address from registers / stack
                uint64_t retAddr = 0;
                if (m_is64Bit) {
                    uint64_t rcx = 0, rdx = 0, r8 = 0, r9 = 0, rsp = 0;
                    uc_reg_read(m_uc, UC_X86_REG_RCX, &rcx);
                    uc_reg_read(m_uc, UC_X86_REG_RDX, &rdx);
                    uc_reg_read(m_uc, UC_X86_REG_R8, &r8);
                    uc_reg_read(m_uc, UC_X86_REG_R9, &r9);
                    uc_reg_read(m_uc, UC_X86_REG_RSP, &rsp);
                    ctx.args = { rcx, rdx, r8, r9 };

                    // Read return address from [RSP]
                    uc_mem_read(m_uc, rsp, &retAddr, sizeof(retAddr));
                    ctx.callerAddress = retAddr;
                } else {
                    uint32_t esp = 0;
                    uc_reg_read(m_uc, UC_X86_REG_ESP, &esp);
                    uint32_t ret32 = 0;
                    uc_mem_read(m_uc, esp, &ret32, sizeof(ret32));
                    retAddr = ret32;
                    ctx.callerAddress = retAddr;

                    uint32_t arg1 = 0, arg2 = 0, arg3 = 0, arg4 = 0;
                    uc_mem_read(m_uc, esp + 4, &arg1, 4);
                    uc_mem_read(m_uc, esp + 8, &arg2, 4);
                    uc_mem_read(m_uc, esp + 12, &arg3, 4);
                    uc_mem_read(m_uc, esp + 16, &arg4, 4);
                    ctx.args = { arg1, arg2, arg3, arg4 };
                }

                uint64_t retVal = 0;
                std::string details;
                std::vector<Finding> hleFindings;
                m_hle.HandleCall(m_uc, address, ctx, retVal, details, hleFindings);

                if (m_currentFindingsPtr) {
                    m_currentFindingsPtr->insert(m_currentFindingsPtr->end(), hleFindings.begin(), hleFindings.end());
                }

                // Write return value to RAX / EAX
                if (m_is64Bit) {
                    uc_reg_write(m_uc, UC_X86_REG_RAX, &retVal);
                } else {
                    uint32_t rax32 = static_cast<uint32_t>(retVal);
                    uc_reg_write(m_uc, UC_X86_REG_EAX, &rax32);
                }

                HleCallRecord rec;
                rec.library = lib;
                rec.apiName = api;
                rec.callerAddress = retAddr;
                rec.arguments = ctx.args;
                rec.returnValue = retVal;
                rec.wasHandled = true;
                rec.details = details;
                m_currentEmulationResult.hleCalls.push_back(rec);

                EmitEvent(Sandbox::EventType::Process, "HLE_Call", lib + "!" + api, details);
            }
        }
    }

    void UnicornAnalyzer::OnMemoryWrite(uint64_t address, int size, int64_t value) {
        if (m_options.enableMemoryDumps) {
            std::ostringstream ss;
            ss << "Addr=0x" << std::hex << address << " Size=" << std::dec << size << " Val=0x" << std::hex << value;
            EmitEvent(Sandbox::EventType::Memory, "MemWrite", "Memory Write Hook", ss.str());
        }
    }

    EmulationResult UnicornAnalyzer::EmulatePE(const std::string& pePath, const EmulationOptions& opts, std::vector<Finding>* outFindings) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_emuOptions = opts;
        m_currentFindingsPtr = outFindings;
        m_currentEmulationResult = EmulationResult();

        uc_mode mode = UC_MODE_64;
        uc_err err = uc_open(UC_ARCH_X86, mode, &m_uc);
        if (err != UC_ERR_OK) {
            m_currentEmulationResult.errorMessage = "Failed to initialize Unicorn engine: " + std::string(uc_strerror(err));
            return m_currentEmulationResult;
        }

        uint64_t entryPoint = 0, endAddress = 0, imageBase = 0;
        bool is64 = true;
        if (!LoadAndMapPE(pePath, entryPoint, endAddress, is64, imageBase)) {
            m_currentEmulationResult.errorMessage = "Failed to load and map PE binary into Unicorn";
            uc_close(m_uc);
            m_uc = nullptr;
            return m_currentEmulationResult;
        }

        m_is64Bit = is64;
        uint64_t stackTop = 0;
        SetupVirtualMemoryAndStack(is64, stackTop);

        std::string tebErr;
        m_hle.SetupMockEnvironment(m_uc, imageBase, is64, opts.antiDebugPolicy, tebErr);

        RegisterHooks(opts.strictSandbox);

        m_currentEmulationResult.startAddress = entryPoint;
        uint64_t maxInstructions = opts.maxInstructions ? opts.maxInstructions : 10000;

        err = uc_emu_start(m_uc, entryPoint, 0, opts.timeoutMicros, maxInstructions);

        uint64_t stopRip = 0;
        ReadNamedRegister(m_uc, is64, is64 ? "RIP" : "EIP", stopRip);
        m_currentEmulationResult.stopAddress = stopRip;
        m_currentEmulationResult.instructionsExecuted = m_instructionCount;

        if (err == UC_ERR_OK) {
            m_currentEmulationResult.success = true;
            m_currentEmulationResult.stopReason = EmulationStopReason::NormalExit;
        } else if (err == UC_ERR_INSN_INVALID) {
            m_currentEmulationResult.stopReason = EmulationStopReason::UnhandledException;
            m_currentEmulationResult.errorMessage = "Invalid Instruction (UC_ERR_INSN_INVALID)";
        } else if (err == UC_ERR_READ_UNMAPPED || err == UC_ERR_WRITE_UNMAPPED || err == UC_ERR_FETCH_UNMAPPED) {
            m_currentEmulationResult.stopReason = EmulationStopReason::InvalidMemory;
            m_currentEmulationResult.errorMessage = "Unmapped Memory Access (" + std::string(uc_strerror(err)) + ")";
        } else {
            m_currentEmulationResult.stopReason = EmulationStopReason::Timeout;
            m_currentEmulationResult.errorMessage = uc_strerror(err);
        }

        // Read register state
        std::vector<std::string> regNames = { "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "RIP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "EFLAGS" };
        for (const auto& rName : regNames) {
            uint64_t val = 0;
            if (ReadNamedRegister(m_uc, is64, rName, val)) {
                m_currentEmulationResult.registers[rName] = val;
            }
        }

        uc_close(m_uc);
        m_uc = nullptr;

        return m_currentEmulationResult;
    }

    bool UnicornAnalyzer::RunAnalysis(const std::string& executablePath) {
        EmulationOptions opts;
        opts.maxInstructions = 10000;
        opts.timeoutMicros = static_cast<uint64_t>(m_options.executionTimeoutSeconds) * 1000000ULL;
        opts.strictSandbox = false;

        auto result = EmulatePE(executablePath, opts, nullptr);
        return result.success;
    }

    Sandbox::FunctionEmulationResult UnicornAnalyzer::EmulateBuffer(
        std::span<const uint8_t> code,
        uint64_t baseAddress,
        const std::unordered_map<uc_x86_reg, uint64_t>& initialRegs,
        const std::vector<std::string>& outputRegNames,
        bool is64Bit,
        uint64_t maxInstructions,
        uint64_t stopAddress,
        uint64_t timeoutMicros
    ) {
        Sandbox::FunctionEmulationResult out;
        if (code.empty()) {
            out.success = false;
            out.rawErrorCode = UC_ERR_ARG;
            out.errorName = uc_strerror(UC_ERR_ARG);
            out.errorMessage = "Empty code buffer passed to EmulateBuffer";
            return out;
        }

        uc_engine* uc = nullptr;
        uc_mode mode = is64Bit ? UC_MODE_64 : UC_MODE_32;
        uc_err err = uc_open(UC_ARCH_X86, mode, &uc);
        if (err != UC_ERR_OK) {
            out.success = false;
            out.errorMessage = "uc_open failed: " + std::string(uc_strerror(err));
            return out;
        }

        // Map code page
        uint64_t pageBase = baseAddress & ~0xFFFULL;
        size_t totalBytes = (baseAddress - pageBase) + code.size();
        size_t mapSize = (totalBytes + 0xFFF) & ~0xFFFULL;
        if (mapSize == 0) mapSize = 0x1000;

        err = uc_mem_map(uc, pageBase, mapSize, UC_PROT_ALL);
        if (err != UC_ERR_OK) {
            out.success = false;
            out.errorMessage = "uc_mem_map failed: " + std::string(uc_strerror(err));
            uc_close(uc);
            return out;
        }

        uc_mem_write(uc, baseAddress, code.data(), code.size());

        // Map stack
        uint64_t stackBase = STACK_BASE_64;
        uc_mem_map(uc, stackBase, STACK_SIZE_64, UC_PROT_READ | UC_PROT_WRITE);
        uint64_t stackTop = stackBase + STACK_SIZE_64 - 0x1000;

        if (is64Bit) {
            uc_reg_write(uc, UC_X86_REG_RSP, &stackTop);
            uc_reg_write(uc, UC_X86_REG_RBP, &stackTop);
        } else {
            uint32_t sp32 = static_cast<uint32_t>(stackTop);
            uc_reg_write(uc, UC_X86_REG_ESP, &sp32);
            uc_reg_write(uc, UC_X86_REG_EBP, &sp32);
        }

        // Seed registers
        for (const auto& [reg, val] : initialRegs) {
            uc_reg_write(uc, reg, &val);
        }

        uint64_t instrCount = 0;
        uc_hook countHook = 0;
        uc_hook_add(uc, &countHook, UC_HOOK_CODE, reinterpret_cast<void*>(+[](uc_engine* u, uint64_t addr, uint32_t sz, void* user){
            auto* count = static_cast<uint64_t*>(user);
            (*count)++;
        }), &instrCount, 1, 0);

        uint64_t stopAt = stopAddress ? stopAddress : (baseAddress + code.size());
        err = uc_emu_start(uc, baseAddress, stopAt, timeoutMicros, maxInstructions ? maxInstructions : 1000);

        out.rawErrorCode = static_cast<int>(err);
        out.errorName = uc_strerror(err);
        out.instructionsExecuted = instrCount;

        uint64_t stopRip = 0;
        ReadNamedRegister(uc, is64Bit, is64Bit ? "RIP" : "EIP", stopRip);
        out.stopAddress = stopRip;

        if (err == UC_ERR_OK || err == UC_ERR_FETCH_UNMAPPED) {
            out.success = true;
        } else {
            out.success = false;
            out.errorMessage = uc_strerror(err);
        }

        for (const auto& rName : outputRegNames) {
            uint64_t val = 0;
            if (ReadNamedRegister(uc, is64Bit, rName, val)) {
                out.registers[rName] = val;
            }
        }

        uc_close(uc);

        // AnalysisReport event for compatibility
        std::lock_guard<std::mutex> lock(m_mutex);
        Sandbox::TraceEvent e;
        e.type = Sandbox::EventType::Info;
        e.category = "UnicornEmulateBuffer";
        e.message = "EmulateBuffer completed at base 0x" + std::to_string(baseAddress);
        m_report.events.push_back(e);

        return out;
    }

} // namespace Dracula
