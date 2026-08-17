#include "core/unicorn_analyzer.h"
#include <chrono>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstring>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace Sandbox {

    UnicornAnalyzer::UnicornAnalyzer() {
        m_report.analysisType = "Unicorn Engine 2 CPU Emulation (Native Instruction Tracing)";
    }

    UnicornAnalyzer::~UnicornAnalyzer() {
        StopAnalysis();
    }

    bool UnicornAnalyzer::Initialize(const VMConfig& /*vmConfig*/, const TraceOptions& options) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_options = options;
        m_report.events.clear();
        m_report.totalProcessesCreated = 0;
        m_report.totalFilesModified = 0;
        m_report.totalNetworkConnections = 0;
        m_report.totalRegistryChanges = 0;
        m_instructionCount = 0;
        return true;
    }

    void UnicornAnalyzer::SetEventCallback(EventCallback callback) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_callback = std::move(callback);
    }

    void UnicornAnalyzer::HookCodeCallback(uc_engine* /*uc*/, uint64_t address, uint32_t size, void* user_data) {
        auto self = static_cast<UnicornAnalyzer*>(user_data);
        if (self) {
            self->OnInstructionExecuted(address, size);
        }
    }

    void UnicornAnalyzer::HookMemWriteCallback(uc_engine* /*uc*/, uc_mem_type /*type*/, uint64_t address, int size, int64_t value, void* user_data) {
        auto self = static_cast<UnicornAnalyzer*>(user_data);
        if (self) {
            self->OnMemoryWrite(address, size, value);
        }
    }

    bool UnicornAnalyzer::HookMemUnmappedCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t /*value*/, void* user_data) {
        auto self = static_cast<UnicornAnalyzer*>(user_data);
        if (!self) return false;

        // Align page to 4KB boundary
        uint64_t pageBase = address & ~0xFFFULL;
        uint64_t pageSize = 0x10000; // Map 64KB page on-demand

        uc_err err = uc_mem_map(uc, pageBase, pageSize, UC_PROT_ALL);
        if (err == UC_ERR_OK) {
            std::ostringstream ss;
            ss << "Dynamically mapped unmapped memory page at 0x" 
               << std::hex << std::uppercase << pageBase 
               << " (Access type: " << (type == UC_MEM_WRITE_UNMAPPED ? "WRITE" : "READ") << ", Size: " << std::dec << size << ")";
            self->EmitEvent(EventType::Info, "UnicornMemory", ss.str());
            return true; // Successfully handled, retry instruction
        }

        return false;
    }

    void UnicornAnalyzer::OnInstructionExecuted(uint64_t address, uint32_t size) {
        m_instructionCount++;

        // Read instruction bytes
        std::vector<uint8_t> codeBuf(size);
        std::string hexBytes;
        if (uc_mem_read(m_uc, address, codeBuf.data(), size) == UC_ERR_OK) {
            std::ostringstream ssHex;
            for (uint32_t i = 0; i < size; ++i) {
                ssHex << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << static_cast<int>(codeBuf[i]) << " ";
            }
            hexBytes = ssHex.str();
        }

        // Read registers
        std::ostringstream ssRegs;
        if (m_is64Bit) {
            uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0, rsp = 0, rbp = 0, rsi = 0, rdi = 0;
            uc_reg_read(m_uc, UC_X86_REG_RAX, &rax);
            uc_reg_read(m_uc, UC_X86_REG_RBX, &rbx);
            uc_reg_read(m_uc, UC_X86_REG_RCX, &rcx);
            uc_reg_read(m_uc, UC_X86_REG_RDX, &rdx);
            uc_reg_read(m_uc, UC_X86_REG_RSP, &rsp);
            uc_reg_read(m_uc, UC_X86_REG_RBP, &rbp);
            uc_reg_read(m_uc, UC_X86_REG_RSI, &rsi);
            uc_reg_read(m_uc, UC_X86_REG_RDI, &rdi);

            ssRegs << "RAX=" << std::hex << "0x" << rax << " "
                   << "RBX=0x" << rbx << " "
                   << "RCX=0x" << rcx << " "
                   << "RDX=0x" << rdx << " "
                   << "RSP=0x" << rsp << " "
                   << "RBP=0x" << rbp;
        } else {
            uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0, esp = 0, ebp = 0;
            uc_reg_read(m_uc, UC_X86_REG_EAX, &eax);
            uc_reg_read(m_uc, UC_X86_REG_EBX, &ebx);
            uc_reg_read(m_uc, UC_X86_REG_ECX, &ecx);
            uc_reg_read(m_uc, UC_X86_REG_EDX, &edx);
            uc_reg_read(m_uc, UC_X86_REG_ESP, &esp);
            uc_reg_read(m_uc, UC_X86_REG_EBP, &ebp);

            ssRegs << "EAX=" << std::hex << "0x" << eax << " "
                   << "EBX=0x" << ebx << " "
                   << "ECX=0x" << ecx << " "
                   << "EDX=0x" << edx << " "
                   << "ESP=0x" << esp << " "
                   << "EBP=0x" << ebp;
        }

        std::ostringstream ssMsg;
        ssMsg << "0x" << std::hex << std::uppercase << address 
              << ": [" << std::setw(15) << std::left << hexBytes << "] (Length: " << std::dec << size << " bytes)";

        EmitEvent(EventType::Info, "Disassembly", ssMsg.str(), ssRegs.str());
    }

    void UnicornAnalyzer::OnMemoryWrite(uint64_t address, int size, int64_t value) {
        if (!m_options.monitorFiles && !m_options.monitorProcesses) {
            // Memory writes logged under general telemetry
        }

        std::ostringstream ss;
        ss << "Memory Write at 0x" << std::hex << std::uppercase << address 
           << " (Size: " << std::dec << size << " bytes, Value: 0x" << std::hex << value << ")";
        EmitEvent(EventType::FileModified, "Memory", ss.str());
    }

    bool UnicornAnalyzer::LoadAndMapPE(const std::string& filePath, uint64_t& outEntryPoint, uint64_t& outEndAddress, bool& outIs64Bit) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            EmitEvent(EventType::Error, "Unicorn", "Failed to open file: " + filePath);
            return false;
        }

        std::streamsize fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<uint8_t> buffer(fileSize);
        if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
            EmitEvent(EventType::Error, "Unicorn", "Failed to read binary file into memory buffer.");
            return false;
        }

        // Check DOS header
        if (fileSize < static_cast<std::streamsize>(sizeof(IMAGE_DOS_HEADER))) {
            // Raw flat binary fallback
            outIs64Bit = true;
            m_is64Bit = true;
            uint64_t base = 0x0000000000400000ULL;
            uint64_t alignSize = (fileSize + 0xFFFULL) & ~0xFFFULL;

            uc_open(UC_ARCH_X86, UC_MODE_64, &m_uc);
            uc_mem_map(m_uc, base, alignSize, UC_PROT_ALL);
            uc_mem_write(m_uc, base, buffer.data(), fileSize);

            outEntryPoint = base;
            outEndAddress = base + fileSize;
            EmitEvent(EventType::Info, "UnicornPE", "Loaded raw flat binary at 0x" + std::to_string(base));
            return true;
        }

        auto pDos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE || pDos->e_lfanew <= 0 || static_cast<size_t>(pDos->e_lfanew) >= buffer.size()) {
            // Raw flat code fallback
            outIs64Bit = true;
            m_is64Bit = true;
            uint64_t base = 0x0000000000400000ULL;
            uint64_t alignSize = (fileSize + 0xFFFULL) & ~0xFFFULL;

            uc_open(UC_ARCH_X86, UC_MODE_64, &m_uc);
            uc_mem_map(m_uc, base, alignSize, UC_PROT_ALL);
            uc_mem_write(m_uc, base, buffer.data(), fileSize);

            outEntryPoint = base;
            outEndAddress = base + fileSize;
            EmitEvent(EventType::Info, "UnicornPE", "Loaded flat code (Non-PE) at address 0x00400000");
            return true;
        }

        auto pNtSignature = reinterpret_cast<const DWORD*>(buffer.data() + pDos->e_lfanew);
        if (*pNtSignature != IMAGE_NT_SIGNATURE) {
            EmitEvent(EventType::Error, "UnicornPE", "Invalid PE NT signature.");
            return false;
        }

        auto pFileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(buffer.data() + pDos->e_lfanew + sizeof(DWORD));
        outIs64Bit = (pFileHeader->Machine == IMAGE_FILE_MACHINE_AMD64);
        m_is64Bit = outIs64Bit;

        uc_err openErr = uc_open(UC_ARCH_X86, m_is64Bit ? UC_MODE_64 : UC_MODE_32, &m_uc);
        if (openErr != UC_ERR_OK) {
            EmitEvent(EventType::Error, "Unicorn", "Failed to initialize Unicorn engine: " + std::string(uc_strerror(openErr)));
            return false;
        }

        uint64_t imageBase = 0;
        uint32_t entryPointRva = 0;
        uint32_t sizeOfImage = 0;
        uint32_t sizeOfHeaders = 0;
        uint16_t numSections = pFileHeader->NumberOfSections;
        const IMAGE_SECTION_HEADER* pSections = nullptr;

        if (m_is64Bit) {
            auto pOpt64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(
                buffer.data() + pDos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
            imageBase = pOpt64->ImageBase;
            entryPointRva = pOpt64->AddressOfEntryPoint;
            sizeOfImage = pOpt64->SizeOfImage;
            sizeOfHeaders = pOpt64->SizeOfHeaders;
            pSections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
                reinterpret_cast<const uint8_t*>(pOpt64) + pFileHeader->SizeOfOptionalHeader);
        } else {
            auto pOpt32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(
                buffer.data() + pDos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
            imageBase = pOpt32->ImageBase;
            entryPointRva = pOpt32->AddressOfEntryPoint;
            sizeOfImage = pOpt32->SizeOfImage;
            sizeOfHeaders = pOpt32->SizeOfHeaders;
            pSections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
                reinterpret_cast<const uint8_t*>(pOpt32) + pFileHeader->SizeOfOptionalHeader);
        }

        // Align image size to 64KB boundary for Unicorn paging
        uint64_t alignedImageSize = (sizeOfImage + 0xFFFFULL) & ~0xFFFFULL;
        if (alignedImageSize == 0) alignedImageSize = 0x200000; // 2MB default

        std::ostringstream ssBase;
        ssBase << "Mapping PE Image Base 0x" << std::hex << std::uppercase << imageBase 
               << " (Size: 0x" << alignedImageSize << " bytes, Arch: " << (m_is64Bit ? "x64" : "x86") << ")";
        EmitEvent(EventType::ProcessCreated, "PE Loader", ssBase.str());

        uc_err mapErr = uc_mem_map(m_uc, imageBase, alignedImageSize, UC_PROT_ALL);
        if (mapErr != UC_ERR_OK) {
            EmitEvent(EventType::Error, "Unicorn", "Failed to map PE Image memory: " + std::string(uc_strerror(mapErr)));
            return false;
        }

        // Write PE Headers
        uc_mem_write(m_uc, imageBase, buffer.data(), std::min<size_t>(sizeOfHeaders, buffer.size()));

        // Map and write each section (.text, .data, .rdata, etc.)
        for (uint16_t i = 0; i < numSections; ++i) {
            const auto& sec = pSections[i];
            char secName[9] = {0};
            std::memcpy(secName, sec.Name, 8);

            uint64_t secVirtualAddr = imageBase + sec.VirtualAddress;
            uint32_t rawSize = sec.SizeOfRawData;
            uint32_t rawOffset = sec.PointerToRawData;

            if (rawOffset < buffer.size() && rawSize > 0) {
                uint32_t toCopy = std::min<uint32_t>(rawSize, static_cast<uint32_t>(buffer.size() - rawOffset));
                uc_mem_write(m_uc, secVirtualAddr, buffer.data() + rawOffset, toCopy);

                std::ostringstream ssSec;
                ssSec << "Mapped Section [" << secName << "] at 0x" 
                      << std::hex << std::uppercase << secVirtualAddr 
                      << " (Raw Size: 0x" << rawSize << ", Virtual Size: 0x" << sec.Misc.VirtualSize << ")";
                EmitEvent(EventType::Info, "PE Loader", ssSec.str());
            }
        }

        outEntryPoint = imageBase + entryPointRva;
        outEndAddress = imageBase + alignedImageSize;

        std::ostringstream ssEntry;
        ssEntry << "Calculated EntryPoint: 0x" << std::hex << std::uppercase << outEntryPoint;
        EmitEvent(EventType::Info, "PE Loader", ssEntry.str());

        return true;
    }

    bool UnicornAnalyzer::SetupVirtualMemoryAndStack(bool is64Bit, uint64_t& outStackTop) {
        uint64_t stackBase = is64Bit ? 0x00007FFF00000000ULL : 0x70000000ULL;
        uint64_t stackSize = 0x200000ULL; // 2MB Stack

        uc_err mapErr = uc_mem_map(m_uc, stackBase, stackSize, UC_PROT_ALL);
        if (mapErr != UC_ERR_OK) {
            EmitEvent(EventType::Error, "Unicorn", "Failed to map Virtual Stack: " + std::string(uc_strerror(mapErr)));
            return false;
        }

        outStackTop = stackBase + stackSize - 0x1000; // Leave 4KB headroom

        if (is64Bit) {
            uc_reg_write(m_uc, UC_X86_REG_RSP, &outStackTop);
            uc_reg_write(m_uc, UC_X86_REG_RBP, &outStackTop);
        } else {
            uint32_t esp = static_cast<uint32_t>(outStackTop);
            uc_reg_write(m_uc, UC_X86_REG_ESP, &esp);
            uc_reg_write(m_uc, UC_X86_REG_EBP, &esp);
        }

        std::ostringstream ss;
        ss << "Initialized Virtual Stack at 0x" << std::hex << std::uppercase << outStackTop;
        EmitEvent(EventType::Info, "CPU Context", ss.str());

        return true;
    }

    void UnicornAnalyzer::RegisterHooks() {
        // 1. Instruction code hook (executed before each CPU instruction)
        uc_hook_add(m_uc, &m_codeHook, UC_HOOK_CODE, reinterpret_cast<void*>(HookCodeCallback), this, 1, 0);

        // 2. Memory write hook (tracks all in-memory modifications)
        uc_hook_add(m_uc, &m_memWriteHook, UC_HOOK_MEM_WRITE, reinterpret_cast<void*>(HookMemWriteCallback), this, 1, 0);

        // 3. Unmapped memory access hook (auto page mapping / telemetry)
        uc_hook_add(m_uc, &m_unmappedHook, UC_HOOK_MEM_UNMAPPED, reinterpret_cast<void*>(HookMemUnmappedCallback), this, 1, 0);

        EmitEvent(EventType::Info, "Unicorn", "CPU Instruction & Memory access hooks installed.");
    }

    bool UnicornAnalyzer::RunAnalysis(const std::string& executablePath) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_isRunning = true;
            m_report.targetExecutable = executablePath;
            m_report.startTime = std::chrono::system_clock::now();
        }

        EmitEvent(EventType::Info, "Unicorn", "Initializing Unicorn Engine 2 for target: " + executablePath);

        uint64_t entryPoint = 0, endAddress = 0, stackTop = 0;
        bool is64Bit = true;

        if (!LoadAndMapPE(executablePath, entryPoint, endAddress, is64Bit)) {
            EmitEvent(EventType::Error, "Unicorn", "Failed to load and map binary into virtual memory.");
            return false;
        }

        if (!SetupVirtualMemoryAndStack(is64Bit, stackTop)) {
            EmitEvent(EventType::Error, "Unicorn", "Failed to setup CPU stack.");
            return false;
        }

        RegisterHooks();

        EmitEvent(EventType::ExecutionStarted, "Unicorn", "Starting native CPU instruction emulation...");

        // Limit execution count or timeout to prevent infinite loops (e.g. 500 instructions or timeout)
        uint64_t maxInstructions = 1000;
        uint64_t timeoutMicroseconds = static_cast<uint64_t>(m_options.executionTimeoutSeconds) * 1000000ULL;

        uc_err emuErr = uc_emu_start(m_uc, entryPoint, endAddress, timeoutMicroseconds, maxInstructions);

        if (emuErr != UC_ERR_OK && emuErr != UC_ERR_READ_UNMAPPED && emuErr != UC_ERR_WRITE_UNMAPPED) {
            std::ostringstream ssErr;
            ssErr << "Unicorn emulation stopped: " << uc_strerror(emuErr) << " (Code: " << emuErr << ")";
            EmitEvent(EventType::Info, "Unicorn", ssErr.str());
        }

        std::ostringstream ssSummary;
        ssSummary << "Emulation finished. Total native CPU instructions traced: " << m_instructionCount;
        EmitEvent(EventType::ExecutionFinished, "Unicorn", ssSummary.str());

        // Cleanup engine handle
        if (m_uc) {
            uc_close(m_uc);
            m_uc = nullptr;
        }

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_report.endTime = std::chrono::system_clock::now();
            m_report.exitCode = (emuErr == UC_ERR_OK ? 0 : static_cast<uint32_t>(emuErr));
            m_isRunning = false;
        }

        return true;
    }

    void UnicornAnalyzer::StopAnalysis() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_isRunning = false;
        if (m_uc) {
            uc_emu_stop(m_uc);
        }
    }

    AnalysisReport UnicornAnalyzer::GetReport() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_report;
    }

    namespace {
        // Maps a 64-bit register name to its 32-bit counterpart for UC_MODE_32 lookups.
        struct RegPair { uc_x86_reg reg64; uc_x86_reg reg32; };

        const std::unordered_map<std::string, RegPair>& NamedRegisterTable() {
            static const std::unordered_map<std::string, RegPair> table = {
                { "RAX", { UC_X86_REG_RAX, UC_X86_REG_EAX } },
                { "RBX", { UC_X86_REG_RBX, UC_X86_REG_EBX } },
                { "RCX", { UC_X86_REG_RCX, UC_X86_REG_ECX } },
                { "RDX", { UC_X86_REG_RDX, UC_X86_REG_EDX } },
                { "RSI", { UC_X86_REG_RSI, UC_X86_REG_ESI } },
                { "RDI", { UC_X86_REG_RDI, UC_X86_REG_EDI } },
                { "RSP", { UC_X86_REG_RSP, UC_X86_REG_ESP } },
                { "RBP", { UC_X86_REG_RBP, UC_X86_REG_EBP } },
                { "RIP", { UC_X86_REG_RIP, UC_X86_REG_EIP } },
                { "R8",  { UC_X86_REG_R8,  UC_X86_REG_INVALID } },
                { "R9",  { UC_X86_REG_R9,  UC_X86_REG_INVALID } },
                { "R10", { UC_X86_REG_R10, UC_X86_REG_INVALID } },
                { "R11", { UC_X86_REG_R11, UC_X86_REG_INVALID } },
                { "R12", { UC_X86_REG_R12, UC_X86_REG_INVALID } },
                { "R13", { UC_X86_REG_R13, UC_X86_REG_INVALID } },
                { "R14", { UC_X86_REG_R14, UC_X86_REG_INVALID } },
                { "R15", { UC_X86_REG_R15, UC_X86_REG_INVALID } },
            };
            return table;
        }
    } // namespace

    bool UnicornAnalyzer::ReadNamedRegister(uc_engine* uc, bool is64Bit, const std::string& name, uint64_t& outValue) {
        const auto& table = NamedRegisterTable();
        auto it = table.find(name);
        if (it == table.end()) {
            return false;
        }

        uc_x86_reg regId = is64Bit ? it->second.reg64 : it->second.reg32;
        if (regId == UC_X86_REG_INVALID) {
            return false; // e.g. R8-R15 have no 32-bit alias
        }

        if (is64Bit) {
            uint64_t value = 0;
            if (uc_reg_read(uc, regId, &value) != UC_ERR_OK) return false;
            outValue = value;
        } else {
            uint32_t value = 0;
            if (uc_reg_read(uc, regId, &value) != UC_ERR_OK) return false;
            outValue = static_cast<uint64_t>(value);
        }
        return true;
    }

    FunctionEmulationResult UnicornAnalyzer::EmulateBuffer(
        std::span<const uint8_t> code,
        uint64_t baseAddress,
        const std::unordered_map<uc_x86_reg, uint64_t>& initialRegs,
        const std::vector<std::string>& outputRegNames,
        bool is64Bit,
        uint64_t maxInstructions,
        uint64_t stopAddress,
        uint64_t timeoutMicros) {

        FunctionEmulationResult result;

        if (code.empty()) {
            result.errorMessage = "Instruction buffer is empty.";
            result.rawErrorCode = static_cast<uint32_t>(UC_ERR_ARG);
            result.errorName = uc_strerror(UC_ERR_ARG);
            return result;
        }

        constexpr uint64_t kPageSize = 0x1000ULL;

        // Isolated engine instance — independent of m_uc used by RunAnalysis, so this
        // is safe to call concurrently with a full-binary analysis session.
        uc_engine* uc = nullptr;
        uc_err err = uc_open(UC_ARCH_X86, is64Bit ? UC_MODE_64 : UC_MODE_32, &uc);
        if (err != UC_ERR_OK) {
            result.errorMessage = std::string("uc_open failed: ") + uc_strerror(err);
            result.rawErrorCode = static_cast<uint32_t>(err);
            result.errorName = uc_strerror(err);
            return result;
        }

        // Page-align the mapping to cover [baseAddress, baseAddress + code.size()).
        uint64_t pageBase = baseAddress & ~(kPageSize - 1);
        uint64_t alignedEnd = (baseAddress + code.size() + kPageSize - 1) & ~(kPageSize - 1);
        uint64_t mapSize = alignedEnd - pageBase;

        err = uc_mem_map(uc, pageBase, mapSize, UC_PROT_ALL);
        if (err != UC_ERR_OK) {
            result.errorMessage = std::string("uc_mem_map failed: ") + uc_strerror(err);
            result.rawErrorCode = static_cast<uint32_t>(err);
            result.errorName = uc_strerror(err);
            uc_close(uc);
            return result;
        }

        err = uc_mem_write(uc, baseAddress, code.data(), code.size());
        if (err != UC_ERR_OK) {
            result.errorMessage = std::string("uc_mem_write failed: ") + uc_strerror(err);
            result.rawErrorCode = static_cast<uint32_t>(err);
            result.errorName = uc_strerror(err);
            uc_mem_unmap(uc, pageBase, mapSize);
            uc_close(uc);
            return result;
        }

        // Minimal shadow stack so CALL/PUSH/RET-bearing routines don't fault immediately.
        uint64_t stackBase = is64Bit ? 0x0000700000000000ULL : 0x60000000ULL;
        uint64_t stackSize = 0x10000ULL; // 64KB
        err = uc_mem_map(uc, stackBase, stackSize, UC_PROT_ALL);
        if (err != UC_ERR_OK) {
            result.errorMessage = std::string("uc_mem_map (stack) failed: ") + uc_strerror(err);
            result.rawErrorCode = static_cast<uint32_t>(err);
            result.errorName = uc_strerror(err);
            uc_mem_unmap(uc, pageBase, mapSize);
            uc_close(uc);
            return result;
        }
        uint64_t stackTop = stackBase + stackSize - 0x1000;

        if (is64Bit) {
            uc_reg_write(uc, UC_X86_REG_RSP, &stackTop);
            uc_reg_write(uc, UC_X86_REG_RBP, &stackTop);
        } else {
            uint32_t esp = static_cast<uint32_t>(stackTop);
            uc_reg_write(uc, UC_X86_REG_ESP, &esp);
            uc_reg_write(uc, UC_X86_REG_EBP, &esp);
        }

        // Lightweight per-call instruction counter, scoped to this emulation only
        // (independent of m_instructionCount, which belongs to RunAnalysis).
        uint64_t executedCount = 0;
        uc_hook countHook = 0;
        auto countCallback = [](uc_engine*, uint64_t, uint32_t, void* user_data) {
            (*static_cast<uint64_t*>(user_data))++;
        };
        uc_hook_add(uc, &countHook, UC_HOOK_CODE,
                    reinterpret_cast<void*>(+countCallback), &executedCount, 1, 0);

        // Seed caller-supplied initial register state.
        for (const auto& [regId, value] : initialRegs) {
            uint64_t v = value;
            uc_reg_write(uc, regId, &v);
        }

        // Instruction pointer starts at the emulation target.
        if (is64Bit) {
            uc_reg_write(uc, UC_X86_REG_RIP, &baseAddress);
        } else {
            uint32_t eip = static_cast<uint32_t>(baseAddress);
            uc_reg_write(uc, UC_X86_REG_EIP, &eip);
        }

        uint64_t effectiveMaxInstr = (maxInstructions == 0) ? 1000ULL : maxInstructions;
        uint64_t effectiveStop = (stopAddress != 0) ? stopAddress : (baseAddress + code.size());

        err = uc_emu_start(uc, baseAddress, effectiveStop, timeoutMicros, effectiveMaxInstr);

        // Retain the exact termination reason for diagnostics, including on the
        // benign-stop paths where success remains true.
        result.rawErrorCode = static_cast<uint32_t>(err);
        result.errorName = uc_strerror(err);

        // UC_ERR_OK plus benign "ran out of bounded work" outcomes are treated as
        // a completed (if truncated) emulation rather than a hard failure.
        bool hardFailure = (err != UC_ERR_OK &&
                             err != UC_ERR_READ_UNMAPPED &&
                             err != UC_ERR_WRITE_UNMAPPED &&
                             err != UC_ERR_FETCH_UNMAPPED);

        uint64_t finalRip = 0;
        if (is64Bit) {
            uc_reg_read(uc, UC_X86_REG_RIP, &finalRip);
        } else {
            uint32_t eip = 0;
            uc_reg_read(uc, UC_X86_REG_EIP, &eip);
            finalRip = eip;
        }

        result.stopAddress = finalRip;
        result.instructionsExecuted = executedCount;

        if (hardFailure) {
            result.success = false;
            result.errorMessage = std::string("uc_emu_start failed: ") + uc_strerror(err);
        } else {
            result.success = true;
            for (const auto& name : outputRegNames) {
                uint64_t value = 0;
                if (ReadNamedRegister(uc, is64Bit, name, value)) {
                    result.registers[name] = value;
                }
            }
        }

        uc_mem_unmap(uc, pageBase, mapSize);
        uc_mem_unmap(uc, stackBase, stackSize);
        uc_close(uc);

        {
            std::ostringstream ss;
            ss << "EmulateBuffer " << (result.CompletedCleanly() ? "completed"
                                        : (result.success ? "truncated" : "failed"))
               << " at base 0x" << std::hex << std::uppercase << baseAddress
               << ", stop RIP 0x" << finalRip
               << ", instructions " << std::dec << result.instructionsExecuted
               << ", termination: " << result.errorName
               << " (" << result.rawErrorCode << ")";
            EmitEvent(result.success ? EventType::Info : EventType::Error, "UnicornEmulateBuffer", ss.str());
        }

        return result;
    }

    void UnicornAnalyzer::EmitEvent(EventType type, const std::string& category, const std::string& msg, const std::string& details) {
        TraceEvent evt;
        evt.type = type;
        evt.timestampMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        evt.category = category;
        evt.message = msg;
        evt.details = details;

        EventCallback cbCopy;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_report.events.push_back(evt);
            cbCopy = m_callback;
        }

        if (cbCopy) {
            cbCopy(evt);
        }
    }

} // namespace Sandbox
