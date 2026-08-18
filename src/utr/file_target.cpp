#include "utr/target.h"
#include "core/pe_inspector.h"
#include "core/analysis_orchestrator.h"
#include "core/disassembler.h"
#include "core/cfg_analyzer.h"
#include "core/xref_analyzer.h"
#include "utr/dll_harness.h"

#include <fstream>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

namespace Dracula {
namespace UTR {

    class FileTarget : public ITarget {
    public:
        FileTarget(const TargetInfo& info) : m_info(info) {}
        ~FileTarget() override = default;

        TargetInfo GetInfo() const override {
            return m_info;
        }

        TargetCapabilities GetCapabilities() const override {
            TargetCapabilities caps;
            caps.staticAnalysis = true;
            caps.functions = true;
            caps.memoryRead = true; // Can read file image bytes
            caps.symbols = true;
            caps.sandboxExecution = true;
            if (m_info.kind == TargetKind::NativeDll) {
                caps.modules = true;
                caps.debugControl = true; // Safe export invocation
            }
            return caps;
        }

        Result<std::vector<UtrModuleInfo>> EnumerateModules() override {
            std::vector<UtrModuleInfo> mods;
            UtrModuleInfo mainMod;
            mainMod.baseAddress = m_info.imageBase;
            mainMod.size = m_info.size;
            mainMod.name = m_info.name;
            mainMod.path = m_info.path;
            mainMod.checksum = m_info.sha256;
            mainMod.isMainModule = true;
            mods.push_back(mainMod);
            return Result<std::vector<UtrModuleInfo>>::Success(mods);
        }

        Result<std::vector<UtrThreadInfo>> EnumerateThreads() override {
            return Result<std::vector<UtrThreadInfo>>::Success({});
        }

        Result<std::vector<MemoryRegion>> GetMemoryMap() override {
            std::vector<MemoryRegion> regions;
            // Parse section headers as mapped memory regions
            PeInspector inspector;
            std::string err;
            if (inspector.LoadFromFile(m_info.path, err)) {
                auto sections = inspector.GetSections();
                for (const auto& s : sections) {
                    MemoryRegion r;
                    r.baseAddress = m_info.imageBase + s.virtualAddress;
                    r.size = s.virtualSize;
                    r.currentProtect = s.isExecutable ? (s.isWritable ? 0x40 /* RWX */ : 0x20 /* RX */) : (s.isWritable ? 0x04 /* RW */ : 0x02 /* R */);
                    r.entropy = s.entropy;
                    r.isExecutable = s.isExecutable;
                    r.isWritable = s.isWritable;
                    r.isReadable = s.isReadable;
                    r.moduleName = m_info.name;
                    regions.push_back(r);
                }
            }
            return Result<std::vector<MemoryRegion>>::Success(regions);
        }

        Result<std::vector<uint8_t>> ReadMemory(uint64_t address, size_t size) override {
            std::ifstream file(m_info.path, std::ios::binary);
            if (!file.is_open()) {
                return Result<std::vector<uint8_t>>::Fail("Failed to open file: " + m_info.path);
            }

            // Map image RVA to file offset
            PeInspector inspector;
            std::string err;
            if (inspector.LoadFromFile(m_info.path, err)) {
                uint64_t rva = (address >= m_info.imageBase) ? (address - m_info.imageBase) : address;
                auto offsetOpt = inspector.RvaToFileOffset(rva);
                if (offsetOpt.has_value()) {
                    file.seekg(static_cast<std::streamoff>(offsetOpt.value()));
                    std::vector<uint8_t> buffer(size);
                    file.read(reinterpret_cast<char*>(buffer.data()), size);
                    buffer.resize(file.gcount());
                    return Result<std::vector<uint8_t>>::Success(buffer);
                }
            }

            return Result<std::vector<uint8_t>>::Fail("Failed to map address to file offset");
        }

        Result<MemorySnapshot> TakeSnapshot(const std::string& label) override {
            auto mapRes = GetMemoryMap();
            if (!mapRes.Ok()) return Result<MemorySnapshot>::Fail(mapRes.Error());
            MemoryIntelligenceManager mgr;
            return Result<MemorySnapshot>::Success(mgr.CaptureSnapshot(mapRes.Value(), label));
        }

        Result<std::vector<FunctionIntelligenceItem>> EnumerateFunctions() override {
            AnalysisOrchestrator orchestrator;
            OrchestratorOptions opts;
            opts.enableEmulation = false;
            auto res = orchestrator.AnalyzeFile(m_info.path, opts);

            FunctionIntelligenceManager fnMgr;
            fnMgr.IndexStaticFunctions(res.functions, res.xrefs, res.strings, res.imports, m_info.name);
            return Result<std::vector<FunctionIntelligenceItem>>::Success(fnMgr.GetAllFunctions());
        }

        Result<uint64_t> InvokeExport(const std::string& exportName, const std::vector<uint64_t>& args) override {
            if (m_info.kind != TargetKind::NativeDll) {
                return Result<uint64_t>::Fail("InvokeExport only valid for Native DLL targets");
            }

            DllExecutionHarness harness;
            std::string err;
            if (!harness.LoadSafe(m_info.path, err)) {
                return Result<uint64_t>::Fail("Failed to load DLL in harness: " + err);
            }

            auto invRes = harness.InvokeTestExport(exportName, args);
            if (!invRes.success) {
                return Result<uint64_t>::Fail(invRes.errorMessage);
            }
            return Result<uint64_t>::Success(invRes.returnValue);
        }

    private:
        TargetInfo m_info;
    };

    std::shared_ptr<ITarget> CreateFileTarget(const TargetInfo& info) {
        return std::make_shared<FileTarget>(info);
    }

} // namespace UTR
} // namespace Dracula
