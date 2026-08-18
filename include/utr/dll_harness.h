#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

#include "utr/types.h"

namespace Dracula {
namespace UTR {

    struct DllExportSymbol {
        std::string name;
        uint32_t    ordinal = 0;
        uint64_t    rva = 0;
        uint64_t    absoluteAddress = 0;
        bool        isForwarder = false;
        std::string forwarderTarget;
    };

    struct DllInvocationResult {
        bool        success = false;
        uint64_t    returnValue = 0;
        std::string errorMessage;
        uint32_t    exceptionCode = 0;
        int64_t     executionTimeMs = 0;
    };

    class DllExecutionHarness {
    public:
        DllExecutionHarness() = default;
        ~DllExecutionHarness();

        bool LoadSafe(const std::string& dllPath, std::string& outError);
        void Unload();

        std::vector<DllExportSymbol> EnumerateExports(std::string& outError);

        // Safe capability-gated export invocation for known test fixtures
        DllInvocationResult InvokeTestExport(const std::string& exportName,
                                             const std::vector<uint64_t>& args = {});

        bool IsLoaded() const { return m_hModule != nullptr; }
        std::string GetLoadedPath() const { return m_dllPath; }

    private:
        void*       m_hModule = nullptr;
        std::string m_dllPath;
    };

} // namespace UTR
} // namespace Dracula
