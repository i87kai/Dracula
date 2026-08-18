#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

#include "utr/types.h"
#include "utr/memory_intelligence.h"
#include "utr/function_intelligence.h"
#include "utr/evidence_graph.h"

namespace Dracula {
namespace UTR {

    // ─── Universal Target Interface ────────────────────────────────────────────
    class ITarget {
    public:
        virtual ~ITarget() = default;

        // Target Identification & Capabilities
        virtual TargetInfo GetInfo() const = 0;
        virtual TargetCapabilities GetCapabilities() const = 0;

        // Modules & Threads
        virtual Result<std::vector<UtrModuleInfo>> EnumerateModules() = 0;
        virtual Result<std::vector<UtrThreadInfo>> EnumerateThreads() = 0;

        // Virtual Memory
        virtual Result<std::vector<MemoryRegion>> GetMemoryMap() = 0;
        virtual Result<std::vector<uint8_t>> ReadMemory(uint64_t address, size_t size) = 0;
        virtual Result<MemorySnapshot> TakeSnapshot(const std::string& label = "") = 0;

        // Function Discovery & Intelligence
        virtual Result<std::vector<FunctionIntelligenceItem>> EnumerateFunctions() = 0;

        // Controlled Runtime Target Interaction (Auditable & Capability-Gated)
        virtual Result<void> StartExecution() { return Result<void>::Fail("StartExecution not supported on this target"); }
        virtual Result<void> PauseExecution() { return Result<void>::Fail("PauseExecution not supported on this target"); }
        virtual Result<void> ResumeExecution() { return Result<void>::Fail("ResumeExecution not supported on this target"); }
        virtual Result<void> TerminateExecution() { return Result<void>::Fail("TerminateExecution not supported on this target"); }
        virtual Result<uint64_t> InvokeExport(const std::string& exportName, const std::vector<uint64_t>& args = {}) {
            (void)exportName; (void)args;
            return Result<uint64_t>::Fail("InvokeExport not supported on this target");
        }
    };

} // namespace UTR
} // namespace Dracula
