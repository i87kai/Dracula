#include "utr/target.h"
#include "core/analysis_orchestrator.h"

#include <iostream>
#include <vector>

namespace Dracula {
namespace UTR {

    std::shared_ptr<ITarget> CreateFileTarget(const TargetInfo& info);

    class DriverTarget : public ITarget {
    public:
        DriverTarget(const TargetInfo& info) : m_info(info) {
            m_fileTarget = CreateFileTarget(m_info);
        }

        ~DriverTarget() override = default;

        TargetInfo GetInfo() const override {
            TargetInfo info = m_info;
            info.statusDetails = "Driver Static Analysis Active. Live kernel instrumentation restricted to QEMU.";
            return info;
        }

        TargetCapabilities GetCapabilities() const override {
            TargetCapabilities caps;
            caps.staticAnalysis = true;
            caps.functions = true;
            caps.symbols = true;
            caps.kernelObservation = false; // Truthful: host kernel observation not attached
            caps.sandboxExecution = true;   // Can run in isolated QEMU
            return caps;
        }

        Result<std::vector<UtrModuleInfo>> EnumerateModules() override {
            return m_fileTarget->EnumerateModules();
        }

        Result<std::vector<UtrThreadInfo>> EnumerateThreads() override {
            return Result<std::vector<UtrThreadInfo>>::Success({});
        }

        Result<std::vector<MemoryRegion>> GetMemoryMap() override {
            return m_fileTarget->GetMemoryMap();
        }

        Result<std::vector<uint8_t>> ReadMemory(uint64_t address, size_t size) override {
            return m_fileTarget->ReadMemory(address, size);
        }

        Result<MemorySnapshot> TakeSnapshot(const std::string& label) override {
            return m_fileTarget->TakeSnapshot(label);
        }

        Result<std::vector<FunctionIntelligenceItem>> EnumerateFunctions() override {
            return m_fileTarget->EnumerateFunctions();
        }

    private:
        TargetInfo               m_info;
        std::shared_ptr<ITarget> m_fileTarget;
    };

    std::shared_ptr<ITarget> CreateDriverTarget(const TargetInfo& info) {
        return std::make_shared<DriverTarget>(info);
    }

} // namespace UTR
} // namespace Dracula
