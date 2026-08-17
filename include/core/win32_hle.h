#pragma once

#include "common/findings.h"
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <cstdint>
#include <memory>

// Forward declaration of unicorn engine handle
typedef struct uc_struct uc_engine;

namespace Dracula {

    enum class AntiDebugPolicy {
        Bypass,     // Returns 0 (no debugger) and records evidence finding
        Realistic,  // Returns 1 (debugger present) to observe evasive divergence
        Neutral,    // Returns 0 silently
        Strict      // Fails or diagnoses in strict sandbox mode
    };

    struct HleCallContext {
        std::string library;
        std::string apiName;
        uint64_t    callerAddress = 0;
        uint64_t    callerRva = 0;
        std::vector<uint64_t> args;
        AntiDebugPolicy antiDebugPolicy = AntiDebugPolicy::Bypass;
        bool        is64Bit = true;
    };

    using HleHandlerFunc = std::function<uint64_t(uc_engine* uc, const HleCallContext& ctx, std::string& outDetails, std::vector<Finding>& outFindings)>;

    class Win32Hle {
    public:
        Win32Hle();
        ~Win32Hle();

        // Register API handler
        void RegisterApi(const std::string& library, const std::string& apiName, HleHandlerFunc handler);

        // Setup mock TEB and PEB structures inside Unicorn address space
        bool SetupMockEnvironment(uc_engine* uc, uint64_t imageBase, bool is64Bit, AntiDebugPolicy policy, std::string& outError);

        // Handle a synthetic HLE call
        bool HandleCall(uc_engine* uc, uint64_t syntheticAddress, const HleCallContext& ctx, uint64_t& outReturnValue, std::string& outDetails, std::vector<Finding>& outFindings);

        // Allocate synthetic trampoline / thunk address for an API
        uint64_t GetOrCreateApiThunk(const std::string& library, const std::string& apiName);

        // Lookup API name from synthetic thunk address
        bool ResolveThunk(uint64_t thunkAddress, std::string& outLibrary, std::string& outApiName) const;

        // Set policy
        void SetAntiDebugPolicy(AntiDebugPolicy policy) { m_policy = policy; }
        AntiDebugPolicy GetAntiDebugPolicy() const { return m_policy; }

        // Constants
        static constexpr uint64_t kHleThunkBase = 0x7FFF80000000ULL;
        static constexpr uint64_t kMockTeb64    = 0x7FFDF0000000ULL;
        static constexpr uint64_t kMockPeb64    = 0x7FFDF0010000ULL;
        static constexpr uint64_t kMockTeb32    = 0x7FFDE000ULL;
        static constexpr uint64_t kMockPeb32    = 0x7FFDF000ULL;
        static constexpr uint64_t kMockHeapBase = 0x10000000ULL;
        static constexpr uint64_t kMockTebAddress = kMockTeb64;
        static constexpr uint64_t kMockPebAddress = kMockPeb64;

    private:
        void InitializeDefaultHandlers();

        AntiDebugPolicy m_policy = AntiDebugPolicy::Bypass;
        std::map<std::string, HleHandlerFunc> m_handlers; // Key: "library!api" (lowercase)
        std::map<uint64_t, std::pair<std::string, std::string>> m_thunkMap;
        std::map<std::string, uint64_t> m_apiToThunk;
        uint64_t m_nextThunkAddress = kHleThunkBase;
        uint64_t m_nextDynamicAlloc = kMockHeapBase;
    };

} // namespace Dracula
