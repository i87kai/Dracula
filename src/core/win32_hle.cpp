#include "core/win32_hle.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <iostream>

#include "unicorn/unicorn.h"
#include "unicorn/x86.h"

namespace Dracula {

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
                f.evidence = "VirtualAlloc(size=0x" + std::to_string(alignedSize) + ", protect=PAGE_EXECUTE_READWRITE)";
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
            outDetails = "GetProcAddress returned synthetic thunk 0x" + std::to_string(thunk);
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
        RegisterApi("kernel32.dll", "Sleep", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            outDetails = "Sleep completed (Instant simulated clock)";
            return 0;
        });
        RegisterApi("kernel32.dll", "GetTickCount", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            return 50000;
        });
        RegisterApi("kernel32.dll", "QueryPerformanceCounter", [](uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& findings) -> uint64_t {
            uint64_t lpCount = (!ctx.args.empty()) ? ctx.args[0] : 0;
            if (lpCount != 0) {
                uint64_t counter = 1000000;
                uc_mem_write(uc, lpCount, &counter, sizeof(counter));
            }
            return 1;
        });

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
