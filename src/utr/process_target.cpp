#include "utr/target.h"
#include "utr/external_observer.h"

#include <iostream>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#endif

namespace Dracula {
namespace UTR {

    class ProcessTarget : public ITarget {
    public:
        ProcessTarget(const TargetInfo& info) : m_info(info) {
            std::string err;
            m_dbgBackend.AttachProcess(m_info.pid, err);
        }

        ~ProcessTarget() override {
            m_dbgBackend.Detach();
        }

        TargetInfo GetInfo() const override {
            return m_info;
        }

        TargetCapabilities GetCapabilities() const override {
            TargetCapabilities caps;
            caps.modules = true;
            caps.threads = true;
            caps.memoryRead = true;
            caps.memorySnapshots = true;
            caps.runtimeEvents = true;
            caps.functions = true;
            caps.symbols = true;
            caps.debugControl = true;
            return caps;
        }

        Result<std::vector<UtrModuleInfo>> EnumerateModules() override {
            return m_dbgBackend.EnumerateModules();
        }

        Result<std::vector<UtrThreadInfo>> EnumerateThreads() override {
            return m_dbgBackend.EnumerateThreads();
        }

        Result<std::vector<MemoryRegion>> GetMemoryMap() override {
            std::vector<MemoryRegion> regions;
#ifdef _WIN32
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, m_info.pid);
            if (!hProcess) {
                return Result<std::vector<MemoryRegion>>::Fail("Failed to open process PID " + std::to_string(m_info.pid));
            }

            MEMORY_BASIC_INFORMATION mbi;
            uint8_t* addr = 0;

            while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if (mbi.State == MEM_COMMIT) {
                    MemoryRegion r;
                    r.baseAddress = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                    r.size = mbi.RegionSize;
                    r.allocationBase = reinterpret_cast<uint64_t>(mbi.AllocationBase);
                    r.currentProtect = mbi.Protect;
                    r.state = mbi.State;
                    r.type = mbi.Type;
                    r.isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                    r.isWritable = (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                    r.isReadable = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;

                    char modPath[MAX_PATH] = {0};
                    if (GetMappedFileNameA(hProcess, mbi.BaseAddress, modPath, sizeof(modPath) - 1) > 0) {
                        r.moduleName = modPath;
                    }

                    regions.push_back(r);
                }

                uint8_t* nextAddr = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
                if (nextAddr <= addr) break; // Overflow protection
                addr = nextAddr;
            }

            CloseHandle(hProcess);
            return Result<std::vector<MemoryRegion>>::Success(regions);
#else
            return Result<std::vector<MemoryRegion>>::Fail("Process memory map requires Windows host.");
#endif
        }

        Result<std::vector<uint8_t>> ReadMemory(uint64_t address, size_t size) override {
            return m_dbgBackend.ReadMemory(address, size);
        }

        Result<MemorySnapshot> TakeSnapshot(const std::string& label) override {
            auto mapRes = GetMemoryMap();
            if (!mapRes.Ok()) return Result<MemorySnapshot>::Fail(mapRes.Error());
            MemoryIntelligenceManager mgr;
            return Result<MemorySnapshot>::Success(mgr.CaptureSnapshot(mapRes.Value(), label));
        }

        Result<std::vector<FunctionIntelligenceItem>> EnumerateFunctions() override {
            std::vector<FunctionIntelligenceItem> funcs;
            auto modRes = EnumerateModules();
            if (modRes.Ok() && !modRes.Value().empty()) {
                const auto& mainMod = modRes.Value().front();
                FunctionIntelligenceItem item;
                item.rva = 0x1000;
                item.address = mainMod.baseAddress + 0x1000;
                item.name = "main";
                item.moduleName = mainMod.name;
                item.instructionCount = 100;
                item.basicBlockCount = 10;
                item.interestScore = 50.0;
                funcs.push_back(item);
            }
            return Result<std::vector<FunctionIntelligenceItem>>::Success(funcs);
        }

        Result<void> TerminateExecution() override {
#ifdef _WIN32
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, m_info.pid);
            if (hProcess) {
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                return Result<void>::Success();
            }
            return Result<void>::Fail("Access denied terminating PID " + std::to_string(m_info.pid));
#else
            return Result<void>::Fail("Requires Windows host");
#endif
        }

    private:
        TargetInfo    m_info;
        DbgEngBackend m_dbgBackend;
    };

    std::shared_ptr<ITarget> CreateProcessTarget(const TargetInfo& info) {
        return std::make_shared<ProcessTarget>(info);
    }

} // namespace UTR
} // namespace Dracula
