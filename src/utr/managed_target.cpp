#include "utr/target.h"
#include "utr/managed_backend.h"
#include "utr/function_intelligence.h"

#include <iostream>
#include <vector>

namespace Dracula {
namespace UTR {

    class ManagedTarget : public ITarget {
    public:
        ManagedTarget(const TargetInfo& info) : m_info(info) {}
        ~ManagedTarget() override = default;

        TargetInfo GetInfo() const override {
            return m_info;
        }

        TargetCapabilities GetCapabilities() const override {
            TargetCapabilities caps;
            caps.staticAnalysis = true;
            caps.modules = true;
            caps.functions = true;
            caps.managedMetadata = true;
            caps.symbols = true;
            return caps;
        }

        Result<std::vector<UtrModuleInfo>> EnumerateModules() override {
            auto res = ManagedHostClient::Instance().InspectAssembly(m_info.path);
            if (!res.Ok()) return Result<std::vector<UtrModuleInfo>>::Fail(res.Error());

            std::vector<UtrModuleInfo> mods;
            UtrModuleInfo mod;
            mod.name = res.Value().assemblyName;
            mod.path = m_info.path;
            mod.isMainModule = true;
            mods.push_back(mod);
            return Result<std::vector<UtrModuleInfo>>::Success(mods);
        }

        Result<std::vector<UtrThreadInfo>> EnumerateThreads() override {
            return Result<std::vector<UtrThreadInfo>>::Success({});
        }

        Result<std::vector<MemoryRegion>> GetMemoryMap() override {
            return Result<std::vector<MemoryRegion>>::Success({});
        }

        Result<std::vector<uint8_t>> ReadMemory(uint64_t address, size_t size) override {
            (void)address; (void)size;
            return Result<std::vector<uint8_t>>::Fail("Direct memory read not supported on offline managed assembly.");
        }

        Result<MemorySnapshot> TakeSnapshot(const std::string& label) override {
            (void)label;
            return Result<MemorySnapshot>::Fail("Memory snapshotting not supported on offline managed assembly.");
        }

        Result<std::vector<FunctionIntelligenceItem>> EnumerateFunctions() override {
            auto methodsRes = ManagedHostClient::Instance().ListAllMethods(m_info.path);
            if (!methodsRes.Ok()) {
                // Fallback to ListTypes if ListAllMethods encounters an error
                auto typesRes = ManagedHostClient::Instance().ListTypes(m_info.path);
                if (!typesRes.Ok()) return Result<std::vector<FunctionIntelligenceItem>>::Fail(typesRes.Error());

                std::vector<FunctionIntelligenceItem> funcs;
                for (const auto& type : typesRes.Value()) {
                    FunctionIntelligenceItem item;
                    item.name = type.fullName;
                    item.moduleName = m_info.name;
                    item.instructionCount = type.methodCount * 20;
                    item.basicBlockCount = type.methodCount * 3;
                    item.interestScore = (type.methodCount > 5) ? 60.0 : 30.0;
                    item.interestReasoning = "[Managed Type: " + type.fullName + "]";
                    funcs.push_back(item);
                }
                return Result<std::vector<FunctionIntelligenceItem>>::Success(funcs);
            }

            auto pinvokesRes = ManagedHostClient::Instance().ListPInvokes(m_info.path);
            std::vector<ManagedPInvokeInfo> pinvokes = pinvokesRes.Ok() ? pinvokesRes.Value() : std::vector<ManagedPInvokeInfo>{};

            FunctionIntelligenceManager mgr;
            mgr.IndexManagedMethods(methodsRes.Value(), pinvokes, m_info.name);
            return Result<std::vector<FunctionIntelligenceItem>>::Success(mgr.GetAllFunctions());
        }

    private:
        TargetInfo m_info;
    };

    std::shared_ptr<ITarget> CreateManagedTarget(const TargetInfo& info) {
        return std::make_shared<ManagedTarget>(info);
    }

} // namespace UTR
} // namespace Dracula
