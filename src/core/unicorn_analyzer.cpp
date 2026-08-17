#include "core/unicorn_analyzer.h"
#include "core/pe_inspector.h"
#include "core/disassembler.h"

#include <capstone/capstone.h>

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

    namespace {

        // Capstone reports EAX, AX and AL as distinct registers. Provenance is
        // only meaningful at the architectural register level, so everything is
        // folded onto its 64-bit parent before being tracked.
        unsigned CanonicalRegister(unsigned reg) {
            switch (reg) {
                case X86_REG_AL: case X86_REG_AH: case X86_REG_AX: case X86_REG_EAX: case X86_REG_RAX: return X86_REG_RAX;
                case X86_REG_BL: case X86_REG_BH: case X86_REG_BX: case X86_REG_EBX: case X86_REG_RBX: return X86_REG_RBX;
                case X86_REG_CL: case X86_REG_CH: case X86_REG_CX: case X86_REG_ECX: case X86_REG_RCX: return X86_REG_RCX;
                case X86_REG_DL: case X86_REG_DH: case X86_REG_DX: case X86_REG_EDX: case X86_REG_RDX: return X86_REG_RDX;
                case X86_REG_SIL: case X86_REG_SI: case X86_REG_ESI: case X86_REG_RSI: return X86_REG_RSI;
                case X86_REG_DIL: case X86_REG_DI: case X86_REG_EDI: case X86_REG_RDI: return X86_REG_RDI;
                case X86_REG_BPL: case X86_REG_BP: case X86_REG_EBP: case X86_REG_RBP: return X86_REG_RBP;
                case X86_REG_SPL: case X86_REG_SP: case X86_REG_ESP: case X86_REG_RSP: return X86_REG_RSP;
                case X86_REG_R8B: case X86_REG_R8W: case X86_REG_R8D: case X86_REG_R8: return X86_REG_R8;
                case X86_REG_R9B: case X86_REG_R9W: case X86_REG_R9D: case X86_REG_R9: return X86_REG_R9;
                case X86_REG_R10B: case X86_REG_R10W: case X86_REG_R10D: case X86_REG_R10: return X86_REG_R10;
                case X86_REG_R11B: case X86_REG_R11W: case X86_REG_R11D: case X86_REG_R11: return X86_REG_R11;
                case X86_REG_R12B: case X86_REG_R12W: case X86_REG_R12D: case X86_REG_R12: return X86_REG_R12;
                case X86_REG_R13B: case X86_REG_R13W: case X86_REG_R13D: case X86_REG_R13: return X86_REG_R13;
                case X86_REG_R14B: case X86_REG_R14W: case X86_REG_R14D: case X86_REG_R14: return X86_REG_R14;
                case X86_REG_R15B: case X86_REG_R15W: case X86_REG_R15D: case X86_REG_R15: return X86_REG_R15;
                default: return reg;
            }
        }

        // Pack four bytes of a string (zero padded) into a CPUID register.
        uint32_t PackRegister(const std::string& s, size_t offset) {
            uint32_t v = 0;
            for (size_t i = 0; i < 4; ++i) {
                const size_t idx = offset + i;
                const uint8_t c = idx < s.size() ? static_cast<uint8_t>(s[idx]) : 0;
                v |= static_cast<uint32_t>(c) << (8 * i);
            }
            return v;
        }

    } // namespace

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

        // CPUID is answered from the active EnvironmentProfile rather than by
        // whatever the emulator's own CPU model happens to report, so that a
        // run is reproducible and the answers are attributable to a profile.
        uc_hook_add(m_uc, &m_cpuidHook, UC_HOOK_INSN, reinterpret_cast<void*>(HookCpuidCallback),
                    this, 1, 0, static_cast<int>(UC_X86_INS_CPUID));

        if (m_emuOptions.recordCoverage) {
            uc_hook_add(m_uc, &m_blockHook, UC_HOOK_BLOCK, reinterpret_cast<void*>(HookBlockCallback), this, 1, 0);
        }
    }

    void UnicornAnalyzer::HookCodeCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
        auto* self = static_cast<UnicornAnalyzer*>(user_data);
        self->OnInstructionExecuted(address, size);
    }

    void UnicornAnalyzer::HookBlockCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
        auto* self = static_cast<UnicornAnalyzer*>(user_data);
        self->m_currentBlock = address;
        auto& blocks = self->m_currentEmulationResult.coverage.basicBlocks;
        if (blocks.size() < 200000) blocks.insert(address);
    }

    int UnicornAnalyzer::HookCpuidCallback(uc_engine* uc, void* user_data) {
        auto* self = static_cast<UnicornAnalyzer*>(user_data);
        self->OnCpuid(uc);
        return 1;   // handled: do not execute the emulator's own CPUID
    }

    // ─── CPUID answered from the environment profile ────────────────────────

    void UnicornAnalyzer::OnCpuid(uc_engine* uc) {
        uint32_t leaf = 0, subleaf = 0;
        uc_reg_read(uc, UC_X86_REG_EAX, &leaf);
        uc_reg_read(uc, UC_X86_REG_ECX, &subleaf);

        uint64_t rip = 0;
        uc_reg_read(uc, m_is64Bit ? UC_X86_REG_RIP : UC_X86_REG_EIP, &rip);

        const auto& cpu  = m_env.profile.cpu;
        const auto& base = m_env.baseline.cpu;

        uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
        std::string property = "CPUID leaf 0x" + [&]{
            std::ostringstream o; o << std::hex << leaf; return o.str();
        }();
        std::string supplied, baselineValue;

        switch (leaf) {
            case 0x0: {
                eax = cpu.maxBasicLeaf;
                ebx = PackRegister(cpu.vendor, 0);
                edx = PackRegister(cpu.vendor, 4);
                ecx = PackRegister(cpu.vendor, 8);
                property = "CPU vendor string";
                supplied = cpu.vendor;
                baselineValue = base.vendor;
                break;
            }
            case 0x1: {
                eax = ((cpu.family >> 4) << 20) | ((cpu.model >> 4) << 16) |
                      ((cpu.family & 0xF) << 8) | ((cpu.model & 0xF) << 4) | (cpu.stepping & 0xF);
                ebx = (cpu.logicalProcessors << 16) | (0x08 << 8);
                edx = 0x078BFBFF;   // ordinary desktop feature set
                ecx = 0x7FFAFBBF;
                if (cpu.hypervisorPresent) ecx |= (1u << 31);
                property = "Hypervisor presence";
                supplied = cpu.hypervisorPresent ? "hypervisor bit set" : "hypervisor bit clear";
                baselineValue = base.hypervisorPresent ? "hypervisor bit set" : "hypervisor bit clear";
                break;
            }
            case 0x4: {   // deterministic cache parameters: topology lives here too
                if (subleaf == 0) {
                    eax = 0x1C004121 | ((cpu.logicalProcessors > 0 ? (cpu.logicalProcessors - 1) : 0) << 26);
                }
                property = "CPU topology (cache parameters)";
                supplied = std::to_string(cpu.logicalProcessors) + " logical processors";
                baselineValue = std::to_string(base.logicalProcessors) + " logical processors";
                break;
            }
            case 0xB: {   // extended topology enumeration
                if (subleaf == 0) { eax = 1; ebx = 1; ecx = 0x0100; }
                else              { eax = 4; ebx = cpu.logicalProcessors; ecx = 0x0201; }
                property = "CPU topology (extended enumeration)";
                supplied = std::to_string(cpu.logicalProcessors) + " logical processors";
                baselineValue = std::to_string(base.logicalProcessors) + " logical processors";
                break;
            }
            case 0x40000000: {
                if (cpu.hypervisorLeavesExposed) {
                    eax = 0x40000001;
                    ebx = PackRegister(cpu.hypervisorVendor, 0);
                    ecx = PackRegister(cpu.hypervisorVendor, 4);
                    edx = PackRegister(cpu.hypervisorVendor, 8);
                    supplied = cpu.hypervisorVendor.empty() ? "(exposed, empty)" : cpu.hypervisorVendor;
                } else {
                    // Not exposed: answer as an unsupported leaf.
                    supplied = "(leaf not answered)";
                }
                property = "Hypervisor vendor leaf";
                baselineValue = base.hypervisorLeavesExposed
                                    ? base.hypervisorVendor : "(leaf not answered)";
                break;
            }
            case 0x80000000: {
                eax = 0x80000008;
                property = "Maximum extended CPUID leaf";
                supplied = baselineValue = "0x80000008";
                break;
            }
            case 0x80000002:
            case 0x80000003:
            case 0x80000004: {
                const size_t chunk = (leaf - 0x80000002) * 16;
                eax = PackRegister(cpu.brand, chunk);
                ebx = PackRegister(cpu.brand, chunk + 4);
                ecx = PackRegister(cpu.brand, chunk + 8);
                edx = PackRegister(cpu.brand, chunk + 12);
                property = "CPU brand string";
                supplied = cpu.brand;
                baselineValue = base.brand;
                break;
            }
            default:
                supplied = baselineValue = "0";
                break;
        }

        uc_reg_write(uc, UC_X86_REG_EAX, &eax);
        uc_reg_write(uc, UC_X86_REG_EBX, &ebx);
        uc_reg_write(uc, UC_X86_REG_ECX, &ecx);
        uc_reg_write(uc, UC_X86_REG_EDX, &edx);

        const uint32_t obs = m_env.Observe("CPUID", property, rip,
                                           rip >= m_imageBase ? rip - m_imageBase : rip,
                                           leaf, supplied, baselineValue);

        if (m_emuOptions.trackBranchInfluence) {
            OriginMark mark;
            mark.origin = EnvironmentOrigin::Cpuid;
            mark.producedAt = rip;
            mark.producedRva = rip >= m_imageBase ? rip - m_imageBase : rip;
            mark.property = property;
            mark.observationId = obs;
            for (unsigned r : { X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX }) {
                m_taint.MarkRegister(r, mark);
            }
        }
    }

    // ─── Timestamp counters and descriptor-table reads ──────────────────────

    bool UnicornAnalyzer::InterceptEnvironmentInstruction(uc_engine* uc, uint64_t address, uint32_t size) {
        uint8_t b[4] = {0};
        if (uc_mem_read(uc, address, b, sizeof(b)) != UC_ERR_OK) return false;
        if (b[0] != 0x0F) return false;

        const uint64_t rva = address >= m_imageBase ? address - m_imageBase : address;

        // RDTSC (0F 31) and RDTSCP (0F 01 F9). Unicorn provides no instruction
        // hook for either, so the encoding is recognised here, the registers are
        // filled from the coherent virtual clock and RIP is stepped past it.
        const bool isRdtsc  = (b[1] == 0x31);
        const bool isRdtscp = (b[1] == 0x01 && b[2] == 0xF9);

        if (isRdtsc || isRdtscp) {
            const uint64_t tsc = m_env.clock.Tsc();
            uint32_t lo = static_cast<uint32_t>(tsc & 0xFFFFFFFFULL);
            uint32_t hi = static_cast<uint32_t>(tsc >> 32);
            uc_reg_write(uc, UC_X86_REG_EAX, &lo);
            uc_reg_write(uc, UC_X86_REG_EDX, &hi);
            if (isRdtscp) {
                uint32_t aux = 0;   // IA32_TSC_AUX: processor 0, no NUMA node
                uc_reg_write(uc, UC_X86_REG_ECX, &aux);
            }

            std::ostringstream sv;
            sv << "TSC = " << tsc;
            const uint32_t obs = m_env.Observe(isRdtscp ? "RDTSCP" : "RDTSC",
                                               "Timestamp counter", address, rva, 0,
                                               sv.str(), "TSC = 0 (frozen baseline clock)");

            if (m_emuOptions.trackBranchInfluence) {
                OriginMark mark;
                mark.origin = EnvironmentOrigin::Timestamp;
                mark.producedAt = address;
                mark.producedRva = rva;
                mark.property = "Timestamp counter";
                mark.observationId = obs;
                m_taint.MarkRegister(X86_REG_RAX, mark);
                m_taint.MarkRegister(X86_REG_RDX, mark);
                if (isRdtscp) m_taint.MarkRegister(X86_REG_RCX, mark);
            }

            uint64_t next = address + (isRdtsc ? 2 : 3);
            uc_reg_write(uc, m_is64Bit ? UC_X86_REG_RIP : UC_X86_REG_EIP, &next);
            return true;
        }

        // Descriptor-table reads (SIDT/SGDT/SLDT/STR) and SMSW. These are
        // recorded as evidence but left to execute normally: Dracula models
        // what they reveal, it does not fabricate descriptor tables.
        if (b[1] == 0x01 || b[1] == 0x00) {
            const uint8_t modrm = b[2];
            const uint8_t reg = (modrm >> 3) & 0x7;
            const char* name = nullptr;
            if (b[1] == 0x01) {
                if (reg == 0) name = "SGDT";
                else if (reg == 1) name = "SIDT";
                else if (reg == 4) name = "SMSW";
            } else {
                if (reg == 0) name = "SLDT";
                else if (reg == 1) name = "STR";
            }
            if (name) {
                m_env.Observe(name, "Descriptor table / machine status", address, rva, 0,
                              "executed natively (not modelled)",
                              "executed natively (not modelled)");
            }
        }
        return false;
    }

    void UnicornAnalyzer::InstallEnvironmentHooks(uc_engine* uc, uc_hook& outCpuidHook,
                                                  uc_hook& outCodeHook) {
        uc_hook_add(uc, &outCpuidHook, UC_HOOK_INSN,
                    reinterpret_cast<void*>(+[](uc_engine* u, void* user) -> int {
                        static_cast<UnicornAnalyzer*>(user)->OnCpuid(u);
                        return 1;
                    }), this, 1, 0, UC_X86_INS_CPUID);

        uc_hook_add(uc, &outCodeHook, UC_HOOK_CODE,
                    reinterpret_cast<void*>(+[](uc_engine* u, uint64_t addr, uint32_t sz, void* user) {
                        auto* self = static_cast<UnicornAnalyzer*>(user);
                        self->GetEnvironment().clock.OnInstructionsRetired(1);
                        self->InterceptEnvironmentInstruction(u, addr, sz);
                    }), this, 1, 0);
    }

    // ─── Coverage and branch behaviour ──────────────────────────────────────

    void UnicornAnalyzer::OpenDecoder(bool is64Bit) {
        CloseDecoder();
        csh h = 0;
        if (cs_open(CS_ARCH_X86, is64Bit ? CS_MODE_64 : CS_MODE_32, &h) == CS_ERR_OK) {
            cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
            m_csHandle = static_cast<uint64_t>(h);
            m_csValid = true;
        }
    }

    void UnicornAnalyzer::CloseDecoder() {
        if (m_csValid && m_csHandle) {
            csh h = static_cast<csh>(m_csHandle);
            cs_close(&h);
        }
        m_csHandle = 0;
        m_csValid = false;
        m_decodeCache.clear();
    }

    const UnicornAnalyzer::DecodedInsn* UnicornAnalyzer::DecodeAt(uint64_t address) {
        auto cached = m_decodeCache.find(address);
        if (cached != m_decodeCache.end()) {
            return cached->second.valid ? &cached->second : nullptr;
        }
        if (!m_csValid) return nullptr;

        // Bounded: a pathological self-modifying sample must not grow this
        // without limit. Past the cap, provenance simply stops learning.
        if (m_decodeCache.size() > 100000) return nullptr;

        DecodedInsn out;
        uint8_t bytes[16] = {0};
        if (uc_mem_read(m_uc, address, bytes, sizeof(bytes)) != UC_ERR_OK) {
            m_decodeCache[address] = out;
            return nullptr;
        }

        csh h = static_cast<csh>(m_csHandle);
        cs_insn* insn = nullptr;
        const size_t count = cs_disasm(h, bytes, sizeof(bytes), address, 1, &insn);
        if (count == 0 || !insn) {
            m_decodeCache[address] = out;
            return nullptr;
        }

        out.valid = true;
        out.size = insn->size;
        out.id = insn->id;
        out.text = std::string(insn->mnemonic) + (insn->op_str[0] ? std::string(" ") + insn->op_str : "");

        cs_regs readRegs, writeRegs;
        uint8_t readCount = 0, writeCount = 0;
        if (cs_regs_access(h, insn, readRegs, &readCount, writeRegs, &writeCount) == CS_ERR_OK) {
            for (uint8_t i = 0; i < readCount; ++i) {
                if (readRegs[i] == X86_REG_EFLAGS) { out.readsFlags = true; continue; }
                out.readRegs.push_back(CanonicalRegister(readRegs[i]));
            }
            for (uint8_t i = 0; i < writeCount; ++i) {
                if (writeRegs[i] == X86_REG_EFLAGS) { out.writesFlags = true; continue; }
                out.writtenRegs.push_back(CanonicalRegister(writeRegs[i]));
            }
        }

        if (insn->detail) {
            const bool jump = cs_insn_group(h, insn, CS_GRP_JUMP);
            out.isCall   = cs_insn_group(h, insn, CS_GRP_CALL);
            out.isReturn = cs_insn_group(h, insn, CS_GRP_RET);
            if (jump) {
                if (insn->id == X86_INS_JMP) out.isUnconditionalJump = true;
                else                          out.isConditionalBranch = true;
            }
            if (insn->detail->x86.op_count > 0 &&
                insn->detail->x86.operands[0].type == X86_OP_IMM) {
                out.immediateTarget = static_cast<uint64_t>(insn->detail->x86.operands[0].imm);
            }

            // Record the first readable memory operand so provenance can follow
            // a value out of a structure an environment API filled in.
            for (int op = 0; op < insn->detail->x86.op_count; ++op) {
                const auto& operand = insn->detail->x86.operands[op];
                if (operand.type != X86_OP_MEM) continue;
                if ((operand.access & CS_AC_READ) == 0) continue;
                out.readsMemory = true;
                out.memBase = operand.mem.base;
                out.memIndex = operand.mem.index;
                out.memScale = operand.mem.scale;
                out.memDisp = operand.mem.disp;
                break;
            }
        }

        cs_free(insn, count);
        auto [it, _] = m_decodeCache.insert({address, std::move(out)});
        return it->second.valid ? &it->second : nullptr;
    }

    bool UnicornAnalyzer::EffectiveAddress(uc_engine* uc, const DecodedInsn& insn,
                                           uint64_t address, uint64_t& outAddress) const {
        if (!insn.readsMemory) return false;

        uint64_t base = 0;
        if (insn.memBase == X86_REG_RIP || insn.memBase == X86_REG_EIP) {
            base = address + insn.size;
        } else if (insn.memBase != X86_REG_INVALID && insn.memBase != 0) {
            if (uc_reg_read(uc, static_cast<int>(insn.memBase), &base) != UC_ERR_OK) return false;
        }

        uint64_t index = 0;
        if (insn.memIndex != X86_REG_INVALID && insn.memIndex != 0) {
            if (uc_reg_read(uc, static_cast<int>(insn.memIndex), &index) != UC_ERR_OK) return false;
        }

        outAddress = base + index * static_cast<uint64_t>(insn.memScale) +
                     static_cast<uint64_t>(insn.memDisp);
        return true;
    }

    void UnicornAnalyzer::RecordCoverage(uint64_t address, uint32_t size) {
        auto& cov = m_currentEmulationResult.coverage;
        if (m_uniqueAddresses.size() < 500000) m_uniqueAddresses.insert(address);

        if (m_pendingCall) {
            m_pendingCall = false;
            if (cov.functions.size() < 20000) cov.functions.insert(address);
        }
    }

    void UnicornAnalyzer::UpdateBranchTracking(uint64_t address) {
        // Resolve the branch recorded on the previous instruction: whichever
        // address we have arrived at tells us which way it went.
        if (!m_pendingBranch.active) return;

        const bool taken = (address == m_pendingBranch.takenTarget) &&
                           (m_pendingBranch.takenTarget != m_pendingBranch.fallthrough);

        auto it = m_branches.find(m_pendingBranch.address);
        if (it == m_branches.end() && m_branches.size() < 4096) {
            BranchObservation b;
            b.address = m_pendingBranch.address;
            b.rva = m_pendingBranch.rva;
            b.mnemonic = m_pendingBranch.mnemonic;
            b.takenTarget = m_pendingBranch.takenTarget;
            b.fallthrough = m_pendingBranch.fallthrough;
            it = m_branches.emplace(m_pendingBranch.address, b).first;
        }
        if (it != m_branches.end()) {
            if (taken) it->second.timesTaken++;
            else       it->second.timesNotTaken++;
        }

        if (m_emuOptions.trackBranchInfluence) {
            m_taint.OnConditionalBranch(m_pendingBranch.address, m_pendingBranch.rva,
                                        m_pendingBranch.mnemonic,
                                        m_pendingBranch.takenTarget,
                                        m_pendingBranch.fallthrough, taken);
        }

        m_pendingBranch.active = false;
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

        // 0a. Resolve the conditional branch recorded on the previous step now
        //     that the destination is known.
        if (m_emuOptions.recordCoverage) {
            UpdateBranchTracking(address);
            RecordCoverage(address, size);
        }

        // 0b. Charge the coherent virtual clock. Every exposed timer derives
        //     from this, so they cannot disagree with each other.
        m_env.clock.OnInstructionsRetired(1);

        // 0c. Environment-revealing instructions Unicorn offers no hook for.
        if (InterceptEnvironmentInstruction(m_uc, address, size)) {
            return;   // RIP was moved past the instruction; nothing else applies
        }

        // 0d. Bounded environment provenance and branch bookkeeping.
        if (m_emuOptions.recordCoverage || m_emuOptions.trackBranchInfluence) {
            if (const DecodedInsn* insn = DecodeAt(address)) {
                if (m_emuOptions.trackBranchInfluence) {
                    // A load out of a region an environment API filled in
                    // carries that provenance into the destination register.
                    OriginMark fromMemory;
                    if (insn->readsMemory) {
                        uint64_t effective = 0;
                        if (EffectiveAddress(m_uc, *insn, address, effective)) {
                            fromMemory = m_taint.MemoryMark(effective);
                        }
                    }

                    if (insn->writesFlags) {
                        if (fromMemory.Valid()) {
                            // The compare read the marked memory directly, so
                            // the flags inherit from it.
                            m_taint.MarkRegister(X86_REG_INVALID, fromMemory);
                            m_taint.OnFlagsWritten({static_cast<unsigned>(X86_REG_INVALID)}, address,
                                                   address >= m_imageBase ? address - m_imageBase : address,
                                                   insn->text);
                            m_taint.ClearRegister(X86_REG_INVALID);
                        } else {
                            m_taint.OnFlagsWritten(insn->readRegs, address,
                                                   address >= m_imageBase ? address - m_imageBase : address,
                                                   insn->text);
                        }
                    }
                    if (!insn->writtenRegs.empty() && !insn->isCall && !insn->isReturn) {
                        if (fromMemory.Valid()) {
                            for (unsigned w : insn->writtenRegs) m_taint.MarkRegister(w, fromMemory);
                        } else {
                            m_taint.OnDataFlow(insn->readRegs, insn->writtenRegs);
                        }
                    }
                }
                if (insn->isCall) {
                    m_pendingCall = true;
                }
                if (insn->isConditionalBranch) {
                    m_pendingBranch.active = true;
                    m_pendingBranch.address = address;
                    m_pendingBranch.rva = address >= m_imageBase ? address - m_imageBase : address;
                    m_pendingBranch.mnemonic = insn->text;
                    m_pendingBranch.takenTarget = insn->immediateTarget;
                    m_pendingBranch.fallthrough = address + insn->size;
                }
            }
        }

        // 1. Check if execution jumped to synthetic HLE thunk
        if (address >= Win32Hle::kHleThunkBase && address < Win32Hle::kHleThunkBase + 0x20000) {
            std::string lib, api;
            if (m_hle.ResolveThunk(address, lib, api)) {
                HleCallContext ctx;
                ctx.library = lib;
                ctx.apiName = api;
                ctx.is64Bit = m_is64Bit;
                ctx.antiDebugPolicy = m_emuOptions.antiDebugPolicy;
                ctx.env = &m_env;

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
                ctx.callerRva = retAddr >= m_imageBase ? retAddr - m_imageBase : retAddr;
                const size_t observationsBefore = m_env.observations.size();
                m_env.ClearOutputBuffer();
                m_hle.HandleCall(m_uc, address, ctx, retVal, details, hleFindings);

                // If the API answered an environment question, the answer
                // carries that provenance into wherever it landed: the return
                // register, and any output structure the handler filled in.
                if (m_emuOptions.trackBranchInfluence &&
                    m_env.observations.size() > observationsBefore) {
                    const auto& obs = m_env.observations.back();
                    OriginMark mark;
                    mark.origin = EnvironmentOrigin::EnvironmentApi;
                    mark.producedAt = retAddr;
                    mark.producedRva = ctx.callerRva;
                    mark.property = obs.property;
                    mark.observationId = static_cast<uint32_t>(m_env.observations.size() - 1);
                    m_taint.MarkRegister(X86_REG_RAX, mark);
                    if (m_env.pendingOutput.valid()) {
                        m_taint.MarkMemory(m_env.pendingOutput.address,
                                           m_env.pendingOutput.size, mark);
                    }
                }
                m_env.ClearOutputBuffer();

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

        // Bind the controlled environment for this run. Everything the sample
        // can observe about its host comes from here and nowhere else.
        m_env.ApplyProfile(opts.environmentProfile);
        m_env.baseline = EnvironmentProfile::Baseline();
        m_hle.SetEnvironmentRuntime(&m_env);
        m_taint.Reset();
        m_branches.clear();
        m_uniqueAddresses.clear();
        m_pendingBranch = PendingBranch{};
        m_pendingCall = false;
        m_instructionCount = 0;
        m_currentEmulationResult.profileName = m_env.profile.name;

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
        m_imageBase = imageBase;
        uint64_t stackTop = 0;
        SetupVirtualMemoryAndStack(is64, stackTop);

        std::string tebErr;
        m_hle.SetupMockEnvironment(m_uc, imageBase, is64, opts.antiDebugPolicy, tebErr);

        if (opts.recordCoverage || opts.trackBranchInfluence) {
            OpenDecoder(is64);
            m_currentEmulationResult.coverage.functions.insert(entryPoint);
        }

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

        // ── Publish the anti-evasion instrumentation ──
        auto& cov = m_currentEmulationResult.coverage;
        cov.instructionsExecuted = m_instructionCount;
        cov.uniqueInstructionAddresses = m_uniqueAddresses.size();

        m_currentEmulationResult.environmentObservations = m_env.observations;
        m_currentEmulationResult.timeWasNormalized = m_env.clock.WasNormalized();
        m_currentEmulationResult.logicalElapsedMs = m_env.clock.ElapsedMillis();

        // Merge observed branch directions with the provenance attribution.
        const auto& influenced = m_taint.InfluencedBranches();
        m_currentEmulationResult.branches.reserve(m_branches.size());
        for (auto& [addr, obs] : m_branches) {
            BranchObservation b = obs;
            auto inf = influenced.find(addr);
            if (inf != influenced.end() && inf->second.origin.Valid()) {
                b.environmentInfluenced = true;
                b.influenceOrigin = EnvironmentOriginToString(inf->second.origin.origin);
                b.influenceProperty = inf->second.origin.property;
                b.influenceProducedAt = inf->second.origin.producedAt;
                b.influenceProducedRva = inf->second.origin.producedRva;
                b.compareText = inf->second.compareText;
            }
            m_currentEmulationResult.branches.push_back(std::move(b));
        }

        CloseDecoder();
        m_hle.SetEnvironmentRuntime(nullptr);

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

        // Setup Mock TEB/PEB and HLE Thunk space
        std::string hleErr;
        m_env.ApplyProfile(m_env.profile);
        m_hle.SetEnvironmentRuntime(&m_env);
        m_hle.SetupMockEnvironment(uc, baseAddress, is64Bit, AntiDebugPolicy::Bypass, hleErr);

        // Machine-code buffers get the same CPUID and timestamp interception a
        // full PE run does, so a buffer-level test proves the real code path.
        uc_hook bufCpuidHook = 0, bufEnvHook = 0;
        InstallEnvironmentHooks(uc, bufCpuidHook, bufEnvHook);

        struct BufferHookCtx {
            UnicornAnalyzer* self;
            bool is64;
        } bCtx = { this, is64Bit };

        uc_hook hleHook = 0;
        uc_hook_add(uc, &hleHook, UC_HOOK_CODE, reinterpret_cast<void*>(+[](uc_engine* u, uint64_t addr, uint32_t sz, void* user){
            auto* ctx = static_cast<BufferHookCtx*>(user);
            if (addr >= Win32Hle::kHleThunkBase && addr < Win32Hle::kHleThunkBase + 0x20000) {
                std::string lib, api;
                if (ctx->self->GetHle().ResolveThunk(addr, lib, api)) {
                    HleCallContext hCtx;
                    hCtx.library = lib;
                    hCtx.apiName = api;
                    hCtx.is64Bit = ctx->is64;
                    hCtx.env = &ctx->self->GetEnvironment();
                    if (ctx->is64) {
                        uint64_t rcx = 0, rdx = 0, r8 = 0, r9 = 0;
                        uc_reg_read(u, UC_X86_REG_RCX, &rcx);
                        uc_reg_read(u, UC_X86_REG_RDX, &rdx);
                        uc_reg_read(u, UC_X86_REG_R8, &r8);
                        uc_reg_read(u, UC_X86_REG_R9, &r9);
                        hCtx.args = { rcx, rdx, r8, r9 };
                    }
                    uint64_t ret = 0;
                    std::string details;
                    std::vector<Finding> f;
                    ctx->self->GetHle().HandleCall(u, addr, hCtx, ret, details, f);
                    if (ctx->is64) {
                        uc_reg_write(u, UC_X86_REG_RAX, &ret);
                    } else {
                        uint32_t ret32 = static_cast<uint32_t>(ret);
                        uc_reg_write(u, UC_X86_REG_EAX, &ret32);
                    }
                }
            }
        }), &bCtx, Win32Hle::kHleThunkBase, Win32Hle::kHleThunkBase + 0x20000);

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
