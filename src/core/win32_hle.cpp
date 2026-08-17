#include "core/win32_hle.h"
#include "common/format.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <iostream>

#include "unicorn/unicorn.h"
#include "unicorn/x86.h"

namespace Dracula {

    // Record one answered environment query against the run's controlled
    // environment. A no-op for legacy callers that bound no runtime.
    static uint32_t ObserveEnv(const HleCallContext& ctx, const std::string& property,
                               const std::string& supplied, const std::string& baseline) {
        if (!ctx.env) return 0;
        return ctx.env->Observe("Win32 HLE", property, ctx.callerAddress, ctx.callerRva,
                                0, supplied, baseline);
    }

    static std::string ToLower(const std::string& s) {
        std::string res = s;
        std::transform(res.begin(), res.end(), res.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
        return res;
    }

    Win32Hle::Win32Hle() {
        InitializeDefaultHandlers();
    }

    Win32Hle::~Win32Hle() = default;

    void Win32Hle::RegisterApi(const std::string& library, const std::string& apiName, HleHandlerFunc handler) {
        std::string key = ToLower(library) + "!" + ToLower(apiName);
        m_handlers[key] = handler;
    }

    uint64_t Win32Hle::GetOrCreateApiThunk(const std::string& library, const std::string& apiName) {
        std::string key = ToLower(library) + "!" + ToLower(apiName);
        auto it = m_apiToThunk.find(key);
        if (it != m_apiToThunk.end()) {
            return it->second;
        }

        uint64_t thunkAddr = m_nextThunkAddress;
        m_nextThunkAddress += 0x100; // 256 bytes between synthetic thunks

        m_apiToThunk[key] = thunkAddr;
        m_thunkMap[thunkAddr] = { library, apiName };
        return thunkAddr;
    }

    bool Win32Hle::ResolveThunk(uint64_t thunkAddress, std::string& outLibrary, std::string& outApiName) const {
        uint64_t alignedThunk = thunkAddress & ~0xFFULL;
        auto it = m_thunkMap.find(alignedThunk);
        if (it != m_thunkMap.end()) {
            outLibrary = it->second.first;
            outApiName = it->second.second;
            return true;
        }
        return false;
    }

    bool Win32Hle::SetupMockEnvironment(uc_engine* uc, uint64_t imageBase, bool is64Bit, AntiDebugPolicy policy, std::string& outError) {
        m_policy = policy;

        uint64_t tebAddr = is64Bit ? kMockTeb64 : kMockTeb32;
        uint64_t pebAddr = is64Bit ? kMockPeb64 : kMockPeb32;

        // 1. Map Mock TEB & PEB Pages
        uc_err err = uc_mem_map(uc, tebAddr, 0x1000, UC_PROT_READ | UC_PROT_WRITE);
        if (err != UC_ERR_OK && err != UC_ERR_MAP) {
            outError = "Failed to map mock TEB page: " + std::string(uc_strerror(err));
            return false;
        }

        err = uc_mem_map(uc, pebAddr, 0x1000, UC_PROT_READ | UC_PROT_WRITE);
        if (err != UC_ERR_OK && err != UC_ERR_MAP) {
            outError = "Failed to map mock PEB page: " + std::string(uc_strerror(err));
            return false;
        }

        // 2. Map Synthetic HLE Thunk Space
        err = uc_mem_map(uc, kHleThunkBase, 0x20000, UC_PROT_READ | UC_PROT_EXEC);
        if (err != UC_ERR_OK && err != UC_ERR_MAP) {
            outError = "Failed to map synthetic HLE thunk page: " + std::string(uc_strerror(err));
            return false;
        }

        // Fill HLE thunk space with RET instructions (0xC3) so synthetic calls return cleanly
        std::vector<uint8_t> retCode(0x20000, 0xC3);
        uc_mem_write(uc, kHleThunkBase, retCode.data(), retCode.size());

        // 3. Construct Mock PEB Structure
        uint8_t pebBuf[0x1000] = {0};
        uint8_t beingDebugged = (policy == AntiDebugPolicy::Realistic) ? 1 : 0;
        pebBuf[0x02] = beingDebugged; // PEB.BeingDebugged

        if (is64Bit) {
            *reinterpret_cast<uint64_t*>(pebBuf + 0x10) = imageBase; // PEB.ImageBaseAddress
            *reinterpret_cast<uint64_t*>(pebBuf + 0x20) = tebAddr + 0x500; // PEB.ProcessParameters
            if (policy == AntiDebugPolicy::Realistic) {
                *reinterpret_cast<uint32_t*>(pebBuf + 0xBC) = 0x70; // PEB.NtGlobalFlag (FLG_HEAP_ENABLE_TAIL_CHECK | etc)
            }
        } else {
            *reinterpret_cast<uint32_t*>(pebBuf + 0x08) = static_cast<uint32_t>(imageBase);
            *reinterpret_cast<uint32_t*>(pebBuf + 0x10) = static_cast<uint32_t>(tebAddr + 0x500);
            if (policy == AntiDebugPolicy::Realistic) {
                *reinterpret_cast<uint32_t*>(pebBuf + 0x68) = 0x70; // 32-bit NtGlobalFlag
            }
        }
        uc_mem_write(uc, pebAddr, pebBuf, sizeof(pebBuf));

        // 4. Construct Mock TEB Structure
        uint8_t tebBuf[0x1000] = {0};
        if (is64Bit) {
            *reinterpret_cast<uint64_t*>(tebBuf + 0x30) = tebAddr; // TEB.Self
            *reinterpret_cast<uint64_t*>(tebBuf + 0x60) = pebAddr; // TEB.ProcessEnvironmentBlock (gs:[0x60])
            
            // Set GS_BASE register in Unicorn so gs:[offset] reads resolve accurately
            uc_reg_write(uc, UC_X86_REG_GS_BASE, &tebAddr);
        } else {
            *reinterpret_cast<uint32_t*>(tebBuf + 0x18) = static_cast<uint32_t>(tebAddr); // TEB.Self (fs:[0x18])
            *reinterpret_cast<uint32_t*>(tebBuf + 0x30) = static_cast<uint32_t>(pebAddr); // (fs:[0x30])

            // Set FS_BASE register in Unicorn for x86
            uc_reg_write(uc, UC_X86_REG_FS_BASE, &tebAddr);
        }
        uc_mem_write(uc, tebAddr, tebBuf, sizeof(tebBuf));

        return true;
    }

    bool Win32Hle::HandleCall(
        uc_engine* uc,
        uint64_t syntheticAddress,
        const HleCallContext& ctx,
        uint64_t& outReturnValue,
        std::string& outDetails,
        std::vector<Finding>& outFindings
    ) {
        std::string key = ToLower(ctx.library) + "!" + ToLower(ctx.apiName);
        auto it = m_handlers.find(key);
        if (it != m_handlers.end()) {
            outReturnValue = it->second(uc, ctx, outDetails, outFindings);
            return true;
        }

        // Generic fallback for unregistered APIs
        outReturnValue = 0;
        outDetails = "Unregistered Win32 HLE API: " + ctx.library + "!" + ctx.apiName + " (Returned 0)";

        std::string findId = "EMU_UNREGISTERED_HLE_CALL_" + ctx.apiName;
        bool alreadyLogged = false;
        for (const auto& existing : outFindings) {
            if (existing.id == findId) { alreadyLogged = true; break; }
        }

        if (!alreadyLogged) {
            Finding f;
            f.id = findId;
            f.category = "Emulation";
            f.severity = FindingSeverity::Info;
            f.confidence = FindingConfidence::High;
            f.rva = ctx.callerRva;
            f.title = "Call to Unimplemented HLE API: " + ctx.apiName;
            f.description = "Emulated code called " + ctx.library + "!" + ctx.apiName + " which is handled by generic fallback returning 0.";
            f.evidence = ctx.library + "!" + ctx.apiName;
            f.source = "Win32 HLE";
            outFindings.push_back(f);
        }

        return false;
    }

    void Win32Hle::InitializeDefaultHandlers() {
        // ── VirtualAlloc ──────────────────────────────────────────────────────
        RegisterApi("kernel32.dll", "VirtualAlloc", [this](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            uint64_t lpAddress = (!ctx.args.empty()) ? ctx.args[0] : 0;
            uint64_t dwSize    = (ctx.args.size() > 1) ? ctx.args[1] : 0x1000;
            uint64_t flAlloc   = (ctx.args.size() > 2) ? ctx.args[2] : 0x3000;
            uint64_t flProtect = (ctx.args.size() > 3) ? ctx.args[3] : 0x40; // PAGE_EXECUTE_READWRITE

            size_t alignedSize = (dwSize + 0xFFF) & ~0xFFFULL;
            if (alignedSize == 0) alignedSize = 0x1000;

            uint64_t allocAddr = (lpAddress != 0) ? lpAddress : m_nextDynamicAlloc;
            m_nextDynamicAlloc += alignedSize;

            uint32_t ucProt = UC_PROT_READ | UC_PROT_WRITE;
            if (flProtect == 0x20 || flProtect == 0x40) { // PAGE_EXECUTE_READ or PAGE_EXECUTE_READWRITE
                ucProt |= UC_PROT_EXEC;
            }

            uc_err err = uc_mem_map(uc, allocAddr, alignedSize, ucProt);
            std::ostringstream ss;
            ss << "Allocated 0x" << std::hex << alignedSize << " bytes at 0x" << allocAddr << " (prot=0x" << flProtect << ")";
            outDetails = ss.str();

            if (flProtect == 0x40) { // PAGE_EXECUTE_READWRITE finding
                Finding f;
                f.id = "EMU_ALLOC_RWX_MEMORY";
                f.category = "Injection / Evasion";
                f.severity = FindingSeverity::Medium;
                f.confidence = FindingConfidence::High;
                f.rva = ctx.callerRva;
                f.title = "Dynamic Allocation of RWX (PAGE_EXECUTE_READWRITE) Memory";
                f.description = "Emulated code called VirtualAlloc requesting RWX page permissions (size: " + std::to_string(alignedSize) + " bytes).";
                f.evidence = "VirtualAlloc(size=" + Format::Hex(alignedSize) + ", protect=PAGE_EXECUTE_READWRITE)";
                f.source = "Win32 HLE";
                f.tags = {"VirtualAlloc", "RWX", "MITRE:T1055"};
                findings.push_back(f);
            }

            return allocAddr;
        });

        // ── VirtualFree ───────────────────────────────────────────────────────
        RegisterApi("kernel32.dll", "VirtualFree", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            outDetails = "VirtualFree succeeded (Simulated)";
            return 1;
        });

        // ── VirtualProtect ────────────────────────────────────────────────────
        RegisterApi("kernel32.dll", "VirtualProtect", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            uint64_t lpAddress = (!ctx.args.empty()) ? ctx.args[0] : 0;
            uint64_t dwSize = (ctx.args.size() > 1) ? ctx.args[1] : 0;
            uint64_t flNewProtect = (ctx.args.size() > 2) ? ctx.args[2] : 0;
            uint64_t lpflOldProtect = (ctx.args.size() > 3) ? ctx.args[3] : 0;

            if (lpflOldProtect != 0) {
                uint32_t oldProtect = 0x04; // PAGE_READWRITE
                uc_mem_write(uc, lpflOldProtect, &oldProtect, sizeof(oldProtect));
            }

            std::ostringstream ss;
            ss << "VirtualProtect address 0x" << std::hex << lpAddress << " size 0x" << dwSize << " newProt=0x" << flNewProtect;
            outDetails = ss.str();
            return 1;
        });

        // ── IsDebuggerPresent ─────────────────────────────────────────────────
        RegisterApi("kernel32.dll", "IsDebuggerPresent", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            uint64_t retVal = (ctx.antiDebugPolicy == AntiDebugPolicy::Realistic) ? 1 : 0;
            std::ostringstream ss;
            ss << "IsDebuggerPresent called; returned " << retVal << " (Policy: "
               << (ctx.antiDebugPolicy == AntiDebugPolicy::Bypass ? "Bypass" : (ctx.antiDebugPolicy == AntiDebugPolicy::Realistic ? "Realistic" : "Neutral")) << ")";
            outDetails = ss.str();

            ObserveEnv(ctx, "Debugger presence",
                       retVal ? "debugger present" : "no debugger present",
                       "no debugger present");

            if (ctx.antiDebugPolicy != AntiDebugPolicy::Neutral) {
                Finding f;
                f.id = "EMU_ANTI_DEBUG_CHECK";
                f.category = "AntiAnalysis";
                f.severity = FindingSeverity::Medium;
                f.confidence = FindingConfidence::High;
                f.rva = ctx.callerRva;
                f.title = "Anti-Debugging Check (IsDebuggerPresent)";
                f.description = "Emulated code checked for active debugger presence via IsDebuggerPresent API.";
                f.evidence = "Returned " + std::to_string(retVal) + " under " + (ctx.antiDebugPolicy == AntiDebugPolicy::Bypass ? "Bypass" : "Realistic") + " policy";
                f.source = "Win32 HLE";
                f.tags = {"AntiDebug", "MITRE:T1497"};
                findings.push_back(f);
            }

            return retVal;
        });

        // ── CheckRemoteDebuggerPresent ────────────────────────────────────────
        RegisterApi("kernel32.dll", "CheckRemoteDebuggerPresent", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            uint64_t pbDebuggerPresent = (ctx.args.size() > 1) ? ctx.args[1] : 0;
            if (pbDebuggerPresent != 0) {
                uint32_t isPresent = (ctx.antiDebugPolicy == AntiDebugPolicy::Realistic) ? 1 : 0;
                uc_mem_write(uc, pbDebuggerPresent, &isPresent, sizeof(isPresent));
            }
            outDetails = "CheckRemoteDebuggerPresent succeeded";
            return 1;
        });

        // ── GetModuleHandleA & W ──────────────────────────────────────────────
        RegisterApi("kernel32.dll", "GetModuleHandleA", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            outDetails = "GetModuleHandleA returned module base 0x7FFF10000000";
            return 0x7FFF10000000ULL;
        });
        RegisterApi("kernel32.dll", "GetModuleHandleW", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            outDetails = "GetModuleHandleW returned module base 0x7FFF10000000";
            return 0x7FFF10000000ULL;
        });

        // ── LoadLibraryA & W ──────────────────────────────────────────────────
        RegisterApi("kernel32.dll", "LoadLibraryA", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            outDetails = "LoadLibraryA simulated module handle 0x7FFF10000000";
            return 0x7FFF10000000ULL;
        });
        RegisterApi("kernel32.dll", "LoadLibraryW", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            outDetails = "LoadLibraryW simulated module handle 0x7FFF10000000";
            return 0x7FFF10000000ULL;
        });

        // ── GetProcAddress ────────────────────────────────────────────────────
        RegisterApi("kernel32.dll", "GetProcAddress", [this](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            uint64_t thunk = GetOrCreateApiThunk("kernel32.dll", "DynamicApi");
            outDetails = "GetProcAddress returned synthetic thunk " + Format::Hex(thunk);
            return thunk;
        });

        // ── ExitProcess & TerminateProcess ────────────────────────────────────
        RegisterApi("kernel32.dll", "ExitProcess", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            outDetails = "ExitProcess requested clean process exit";
            uc_emu_stop(uc);
            return 0;
        });
        RegisterApi("kernel32.dll", "TerminateProcess", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            outDetails = "TerminateProcess requested process termination";
            uc_emu_stop(uc);
            return 1;
        });

        // ── GetLastError & SetLastError ───────────────────────────────────────
        RegisterApi("kernel32.dll", "GetLastError", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            outDetails = "GetLastError returned 0 (ERROR_SUCCESS)";
            return 0;
        });
        RegisterApi("kernel32.dll", "SetLastError", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            outDetails = "SetLastError called";
            return 0;
        });

        // ── Process & Thread Identification ──────────────────────────────────
        RegisterApi("kernel32.dll", "GetCurrentProcess", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            return 0xFFFFFFFFFFFFFFFFULL; // (HANDLE)-1
        });
        RegisterApi("kernel32.dll", "GetCurrentProcessId", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            return 1337;
        });
        RegisterApi("kernel32.dll", "GetCurrentThreadId", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            return 2048;
        });

        // ── Timers & Sleep ────────────────────────────────────────────────────
        //
        // Every clock below reads the same VirtualTimeState, so a sample that
        // cross-checks GetTickCount against QueryPerformanceCounter against
        // RDTSC gets three mutually consistent answers. Under Baseline the
        // clock is frozen, which reproduces Dracula's historical behaviour.

        RegisterApi("kernel32.dll", "Sleep", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            const uint64_t millis = ctx.args.empty() ? 0 : (ctx.args[0] & 0xFFFFFFFFULL);
            if (ctx.env && ctx.env->profile.timing.sleepAdvancesClock) {
                ctx.env->clock.AdvanceMillis(millis,
                    "Sleep(" + std::to_string(millis) + ") accelerated: logical time advanced "
                    "without spending wall-clock time", "kernel32!Sleep");
                outDetails = "Sleep(" + std::to_string(millis) + " ms) accelerated; every "
                             "modelled clock advanced by " + std::to_string(millis) + " ms";
            } else {
                outDetails = "Sleep(" + std::to_string(millis) + " ms) returned immediately; "
                             "the Baseline clock does not advance";
            }
            ObserveEnv(ctx, "Sleep duration", outDetails,
                       "Sleep returned immediately without advancing the clock");
            return 0;
        });
        RegisterApi("kernel32.dll", "SleepEx", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            const uint64_t millis = ctx.args.empty() ? 0 : (ctx.args[0] & 0xFFFFFFFFULL);
            if (ctx.env && ctx.env->profile.timing.sleepAdvancesClock) {
                ctx.env->clock.AdvanceMillis(millis, "SleepEx accelerated", "kernel32!SleepEx");
            }
            outDetails = "SleepEx(" + std::to_string(millis) + " ms)";
            return 0;
        });

        RegisterApi("kernel32.dll", "GetTickCount", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            const uint64_t ticks = ctx.env ? ctx.env->clock.TickCount32() : 50000;
            outDetails = "GetTickCount = " + std::to_string(ticks) + " ms";
            ObserveEnv(ctx, "Tick count", std::to_string(ticks) + " ms", "50000 ms");
            return ticks;
        });
        RegisterApi("kernel32.dll", "GetTickCount64", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            const uint64_t ticks = ctx.env ? ctx.env->clock.TickCount64() : 50000;
            outDetails = "GetTickCount64 = " + std::to_string(ticks) + " ms";
            ObserveEnv(ctx, "Tick count", std::to_string(ticks) + " ms", "50000 ms");
            return ticks;
        });
        RegisterApi("winmm.dll", "timeGetTime", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            const uint64_t ticks = ctx.env ? ctx.env->clock.TickCount32() : 50000;
            outDetails = "timeGetTime = " + std::to_string(ticks) + " ms";
            ObserveEnv(ctx, "Tick count", std::to_string(ticks) + " ms", "50000 ms");
            return ticks;
        });

        RegisterApi("kernel32.dll", "QueryPerformanceCounter", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            const uint64_t lpCount = (!ctx.args.empty()) ? ctx.args[0] : 0;
            const uint64_t counter = ctx.env ? ctx.env->clock.QpcCounter() : 1000000;
            if (lpCount != 0) {
                uc_mem_write(uc, lpCount, &counter, sizeof(counter));
                if (ctx.env) ctx.env->NoteOutputBuffer(lpCount, sizeof(counter));
            }
            outDetails = "QueryPerformanceCounter = " + std::to_string(counter);
            ObserveEnv(ctx, "Performance counter", std::to_string(counter), "1000000");
            return 1;
        });
        RegisterApi("kernel32.dll", "QueryPerformanceFrequency", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            const uint64_t lpFreq = (!ctx.args.empty()) ? ctx.args[0] : 0;
            const uint64_t freq = ctx.env ? ctx.env->clock.QpcFrequency() : 10000000;
            if (lpFreq != 0) {
                uc_mem_write(uc, lpFreq, &freq, sizeof(freq));
            }
            outDetails = "QueryPerformanceFrequency = " + std::to_string(freq) + " Hz";
            return 1;
        });

        // ── Environment discovery ─────────────────────────────────────────────
        //
        // These are ordinary Windows APIs. Installers, inventory tools, games
        // and licensing systems call them for entirely legitimate reasons, so
        // answering one is recorded as an observation and NOT, by itself,
        // treated as evidence of evasion. What matters is whether the answer
        // goes on to steer control flow.

        RegisterApi("kernel32.dll", "GetSystemInfo", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            const uint64_t out = ctx.args.empty() ? 0 : ctx.args[0];
            const uint32_t cpus = ctx.env ? ctx.env->profile.host.processorCount : 2;
            const uint32_t baseCpus = ctx.env ? ctx.env->baseline.host.processorCount : 2;
            if (out != 0) {
                uint8_t si[48] = {0};
                *reinterpret_cast<uint32_t*>(si + 0x04) = 0x1000;      // dwPageSize
                *reinterpret_cast<uint64_t*>(si + 0x08) = 0x10000;     // lpMinimumApplicationAddress
                *reinterpret_cast<uint64_t*>(si + 0x10) = 0x7FFFFFFEFFFFULL;
                *reinterpret_cast<uint64_t*>(si + 0x18) =
                    (cpus >= 64) ? ~0ULL : ((1ULL << cpus) - 1);       // dwActiveProcessorMask
                *reinterpret_cast<uint32_t*>(si + 0x20) = cpus;        // dwNumberOfProcessors
                *reinterpret_cast<uint32_t*>(si + 0x24) = 8664;        // dwProcessorType
                *reinterpret_cast<uint32_t*>(si + 0x28) = 0x10000;     // dwAllocationGranularity
                uc_mem_write(uc, out, si, sizeof(si));
                if (ctx.env) ctx.env->NoteOutputBuffer(out, sizeof(si));
            }
            outDetails = "GetSystemInfo reported " + std::to_string(cpus) + " processors";
            ObserveEnv(ctx, "Processor count", std::to_string(cpus), std::to_string(baseCpus));
            return 0;
        });
        RegisterApi("kernel32.dll", "GetNativeSystemInfo", [this](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            auto it = m_handlers.find("kernel32.dll!getsysteminfo");
            if (it != m_handlers.end()) return it->second(uc, ctx, outDetails, findings);
            return 0;
        });

        RegisterApi("kernel32.dll", "GlobalMemoryStatusEx", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            const uint64_t out = ctx.args.empty() ? 0 : ctx.args[0];
            const uint64_t total = ctx.env ? ctx.env->profile.host.physicalMemoryBytes
                                           : (4ULL * 1024 * 1024 * 1024);
            const uint64_t baseTotal = ctx.env ? ctx.env->baseline.host.physicalMemoryBytes
                                               : (4ULL * 1024 * 1024 * 1024);
            if (out != 0) {
                uint8_t ms[64] = {0};
                *reinterpret_cast<uint32_t*>(ms + 0x00) = 64;          // dwLength
                *reinterpret_cast<uint32_t*>(ms + 0x04) = 38;          // dwMemoryLoad
                *reinterpret_cast<uint64_t*>(ms + 0x08) = total;       // ullTotalPhys
                *reinterpret_cast<uint64_t*>(ms + 0x10) = total / 2;   // ullAvailPhys
                *reinterpret_cast<uint64_t*>(ms + 0x18) = total * 2;
                *reinterpret_cast<uint64_t*>(ms + 0x20) = total;
                *reinterpret_cast<uint64_t*>(ms + 0x28) = 0x7FFFFFFEFFFFULL;
                *reinterpret_cast<uint64_t*>(ms + 0x30) = 0x7FFFFFFE0000ULL;
                uc_mem_write(uc, out, ms, sizeof(ms));
                if (ctx.env) ctx.env->NoteOutputBuffer(out, sizeof(ms));
            }
            const std::string gb = std::to_string(total / (1024ULL * 1024 * 1024)) + " GB";
            outDetails = "GlobalMemoryStatusEx reported " + gb + " physical memory";
            ObserveEnv(ctx, "Physical memory", gb,
                       std::to_string(baseTotal / (1024ULL * 1024 * 1024)) + " GB");
            return 1;
        });
        RegisterApi("kernel32.dll", "GetPhysicallyInstalledSystemMemory", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            const uint64_t out = ctx.args.empty() ? 0 : ctx.args[0];
            const uint64_t total = ctx.env ? ctx.env->profile.host.physicalMemoryBytes
                                           : (4ULL * 1024 * 1024 * 1024);
            const uint64_t kb = total / 1024;
            if (out != 0) {
                uc_mem_write(uc, out, &kb, sizeof(kb));
                if (ctx.env) ctx.env->NoteOutputBuffer(out, sizeof(kb));
            }
            outDetails = "GetPhysicallyInstalledSystemMemory = " + std::to_string(kb) + " KB";
            ObserveEnv(ctx, "Physical memory", std::to_string(kb) + " KB", "4194304 KB");
            return 1;
        });

        RegisterApi("user32.dll", "GetSystemMetrics", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            const uint64_t index = ctx.args.empty() ? 0 : (ctx.args[0] & 0xFFFFFFFFULL);
            const auto& host = ctx.env ? ctx.env->profile.host : EnvironmentProfile::Baseline().host;
            uint64_t value = 0;
            std::string what = "System metric " + std::to_string(index);
            if (index == 0)      { value = host.screenWidth;  what = "Screen width"; }
            else if (index == 1) { value = host.screenHeight; what = "Screen height"; }
            outDetails = "GetSystemMetrics(" + std::to_string(index) + ") = " + std::to_string(value);
            if (index == 0 || index == 1) {
                const auto& base = ctx.env ? ctx.env->baseline.host : host;
                ObserveEnv(ctx, what, std::to_string(value),
                           std::to_string(index == 0 ? base.screenWidth : base.screenHeight));
            }
            return value;
        });

        RegisterApi("user32.dll", "GetLastInputInfo", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            const uint64_t out = ctx.args.empty() ? 0 : ctx.args[0];
            const uint64_t now = ctx.env ? ctx.env->clock.TickCount64() : 50000;
            const uint32_t idle = ctx.env ? ctx.env->profile.host.lastInputIdleMs : 0;
            const uint32_t lastInput = (now > idle) ? static_cast<uint32_t>(now - idle) : 0;
            if (out != 0) {
                uint32_t cb = 8;
                uc_mem_write(uc, out, &cb, sizeof(cb));
                uc_mem_write(uc, out + 4, &lastInput, sizeof(lastInput));
                if (ctx.env) ctx.env->NoteOutputBuffer(out, 8);
            }
            outDetails = "GetLastInputInfo: last input " + std::to_string(idle) + " ms ago";
            ObserveEnv(ctx, "User input activity",
                       idle == 0 ? "no input activity modelled" : std::to_string(idle) + " ms ago",
                       "no input activity modelled");
            return 1;
        });

        auto computerName = [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            const std::string name = ctx.env ? ctx.env->profile.host.computerName : "SANDBOX-PC";
            const uint64_t buf = ctx.args.empty() ? 0 : ctx.args[0];
            const uint64_t sizePtr = ctx.args.size() > 1 ? ctx.args[1] : 0;
            if (buf) uc_mem_write(uc, buf, name.c_str(), name.size() + 1);
            if (sizePtr) {
                uint32_t len = static_cast<uint32_t>(name.size());
                uc_mem_write(uc, sizePtr, &len, sizeof(len));
            }
            outDetails = "Computer name = " + name;
            ObserveEnv(ctx, "Computer name", name,
                       ctx.env ? ctx.env->baseline.host.computerName : "SANDBOX-PC");
            return 1;
        };
        RegisterApi("kernel32.dll", "GetComputerNameA", computerName);
        RegisterApi("kernel32.dll", "GetComputerNameW", computerName);

        auto userName = [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            const std::string name = ctx.env ? ctx.env->profile.host.userName : "sandbox";
            const uint64_t buf = ctx.args.empty() ? 0 : ctx.args[0];
            if (buf) uc_mem_write(uc, buf, name.c_str(), name.size() + 1);
            outDetails = "User name = " + name;
            ObserveEnv(ctx, "User name", name,
                       ctx.env ? ctx.env->baseline.host.userName : "sandbox");
            return 1;
        };
        RegisterApi("advapi32.dll", "GetUserNameA", userName);
        RegisterApi("advapi32.dll", "GetUserNameW", userName);

        auto diskSpace = [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            const uint64_t total = ctx.env ? ctx.env->profile.host.diskSizeBytes
                                           : (64ULL * 1024 * 1024 * 1024);
            const uint64_t baseTotal = ctx.env ? ctx.env->baseline.host.diskSizeBytes
                                               : (64ULL * 1024 * 1024 * 1024);
            const uint64_t freeToCaller = ctx.args.size() > 1 ? ctx.args[1] : 0;
            const uint64_t totalPtr     = ctx.args.size() > 2 ? ctx.args[2] : 0;
            const uint64_t freePtr      = ctx.args.size() > 3 ? ctx.args[3] : 0;
            const uint64_t freeBytes = total / 3;
            if (freeToCaller) uc_mem_write(uc, freeToCaller, &freeBytes, sizeof(freeBytes));
            if (totalPtr)     uc_mem_write(uc, totalPtr, &total, sizeof(total));
            if (freePtr)      uc_mem_write(uc, freePtr, &freeBytes, sizeof(freeBytes));
            const std::string gb = std::to_string(total / (1024ULL * 1024 * 1024)) + " GB";
            outDetails = "GetDiskFreeSpaceEx reported a " + gb + " volume";
            ObserveEnv(ctx, "Disk size", gb,
                       std::to_string(baseTotal / (1024ULL * 1024 * 1024)) + " GB");
            return 1;
        };
        RegisterApi("kernel32.dll", "GetDiskFreeSpaceExA", diskSpace);
        RegisterApi("kernel32.dll", "GetDiskFreeSpaceExW", diskSpace);

        RegisterApi("kernel32.dll", "GetSystemFirmwareTable", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            const auto& host = ctx.env ? ctx.env->profile.host : EnvironmentProfile::Baseline().host;
            const std::string blob = host.firmwareVendor + "\0" + host.firmwareProduct;
            const uint64_t buf = ctx.args.size() > 2 ? ctx.args[2] : 0;
            const uint64_t size = ctx.args.size() > 3 ? ctx.args[3] : 0;
            const size_t n = host.firmwareVendor.size() + host.firmwareProduct.size() + 2;
            if (buf && size >= n) {
                uc_mem_write(uc, buf, host.firmwareVendor.c_str(), host.firmwareVendor.size() + 1);
                uc_mem_write(uc, buf + host.firmwareVendor.size() + 1,
                             host.firmwareProduct.c_str(), host.firmwareProduct.size() + 1);
            }
            outDetails = "Firmware table: " + host.firmwareVendor + " / " + host.firmwareProduct;
            ObserveEnv(ctx, "Firmware vendor", host.firmwareVendor,
                       ctx.env ? ctx.env->baseline.host.firmwareVendor : "QEMU");
            return static_cast<uint64_t>(n);
        });

        auto regOpen = [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            // Read the subkey path so the answer depends on what was asked for.
            std::string subkey;
            const uint64_t subkeyPtr = ctx.args.size() > 1 ? ctx.args[1] : 0;
            if (subkeyPtr) {
                char c = 0;
                for (int i = 0; i < 256; ++i) {
                    if (uc_mem_read(uc, subkeyPtr + i, &c, 1) != UC_ERR_OK || c == 0) break;
                    subkey += c;
                }
            }
            const auto& host = ctx.env ? ctx.env->profile.host : EnvironmentProfile::Baseline().host;
            bool present = false;
            for (const auto& artifact : host.registryArtifacts) {
                if (!subkey.empty() && artifact.find(subkey) != std::string::npos) { present = true; break; }
                if (!subkey.empty() && subkey.find(artifact) != std::string::npos) { present = true; break; }
            }
            outDetails = "RegOpenKeyEx(\"" + subkey + "\") -> " +
                         (present ? "ERROR_SUCCESS" : "ERROR_FILE_NOT_FOUND");
            if (!subkey.empty()) {
                ObserveEnv(ctx, "Registry key " + subkey,
                           present ? "present" : "absent",
                           present ? "present" : "absent");
            }
            return present ? 0 : 2;   // ERROR_SUCCESS / ERROR_FILE_NOT_FOUND
        };
        RegisterApi("advapi32.dll", "RegOpenKeyExA", regOpen);
        RegisterApi("advapi32.dll", "RegOpenKeyExW", regOpen);

        // ── MSVCRT / C Runtime Stubs ──────────────────────────────────────────
        auto crtIobHandler = [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            outDetails = "__iob_func simulated stdout/stderr stream";
            return 0x7FFE0800ULL; // Synthetic stdout stream pointer
        };
        RegisterApi("msvcrt.dll", "__iob_func", crtIobHandler);
        RegisterApi("api-ms-win-crt-stdio-l1-1-0.dll", "__acrt_iob_func", crtIobHandler);

        auto crtPrintHandler = [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            outDetails = "CRT print/format executed";
            return 1;
        };
        RegisterApi("msvcrt.dll", "printf", crtPrintHandler);
        RegisterApi("msvcrt.dll", "fprintf", crtPrintHandler);
        RegisterApi("msvcrt.dll", "vfprintf", crtPrintHandler);
        RegisterApi("msvcrt.dll", "puts", crtPrintHandler);
        RegisterApi("msvcrt.dll", "putchar", crtPrintHandler);
        RegisterApi("msvcrt.dll", "__main", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            return 0;
        });
        RegisterApi("msvcrt.dll", "setvbuf", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            outDetails = "setvbuf stream buffer set";
            return 0;
        });
        RegisterApi("msvcrt.dll", "atexit", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            outDetails = "atexit registered exit callback";
            return 0;
        });
        RegisterApi("msvcrt.dll", "__cxa_atexit", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            outDetails = "__cxa_atexit registered exit callback";
            return 0;
        });
        RegisterApi("msvcrt.dll", "signal", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            outDetails = "signal handler installed";
            return 0;
        });
        RegisterApi("msvcrt.dll", "memset", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            uint64_t dest = ctx.args.size() > 0 ? ctx.args[0] : 0;
            uint8_t val = ctx.args.size() > 1 ? static_cast<uint8_t>(ctx.args[1]) : 0;
            size_t count = ctx.args.size() > 2 ? static_cast<size_t>(ctx.args[2]) : 0;
            if (dest != 0 && count > 0 && count < 0x100000) {
                std::vector<uint8_t> fill(count, val);
                uc_mem_write(uc, dest, fill.data(), count);
            }
            return dest;
        });
        RegisterApi("msvcrt.dll", "memcpy", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            uint64_t dest = ctx.args.size() > 0 ? ctx.args[0] : 0;
            uint64_t src = ctx.args.size() > 1 ? ctx.args[1] : 0;
            size_t count = ctx.args.size() > 2 ? static_cast<size_t>(ctx.args[2]) : 0;
            if (dest != 0 && src != 0 && count > 0 && count < 0x100000) {
                std::vector<uint8_t> buf(count);
                if (uc_mem_read(uc, src, buf.data(), count) == UC_ERR_OK) {
                    uc_mem_write(uc, dest, buf.data(), count);
                }
            }
            return dest;
        });
        RegisterApi("msvcrt.dll", "strlen", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            uint64_t strPtr = ctx.args.size() > 0 ? ctx.args[0] : 0;
            if (strPtr == 0) return 0;
            uint64_t len = 0;
            char c = 0;
            while (len < 4096 && uc_mem_read(uc, strPtr + len, &c, 1) == UC_ERR_OK && c != 0) {
                len++;
            }
            return len;
        });
        RegisterApi("msvcrt.dll", "abort", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            outDetails = "CRT abort requested clean termination";
            uc_emu_stop(uc);
            return 0;
        });
    }

} // namespace Dracula
