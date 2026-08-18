#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstdint>
#include <chrono>
#include <optional>
#include <functional>
#include <memory>

namespace Dracula {
namespace UTR {

    // ─── Target Kinds ──────────────────────────────────────────────────────────
    enum class TargetKind {
        NativeExe,
        NativeDll,
        RunningProcess,
        ManagedExe,
        ManagedDll,
        Service,
        Driver,
        VmTarget,
        Unknown
    };

    inline const char* TargetKindToString(TargetKind k) {
        switch (k) {
            case TargetKind::NativeExe:      return "Native EXE";
            case TargetKind::NativeDll:      return "Native DLL";
            case TargetKind::RunningProcess: return "Running Process";
            case TargetKind::ManagedExe:     return "Managed .NET EXE";
            case TargetKind::ManagedDll:     return "Managed .NET DLL";
            case TargetKind::Service:        return "Windows Service";
            case TargetKind::Driver:         return "Kernel Driver";
            case TargetKind::VmTarget:       return "QEMU VM Target";
            default:                         return "Unknown";
        }
    }

    inline TargetKind StringToTargetKind(const std::string& str) {
        if (str == "Native EXE" || str == "exe") return TargetKind::NativeExe;
        if (str == "Native DLL" || str == "dll") return TargetKind::NativeDll;
        if (str == "Running Process" || str == "pid" || str == "process") return TargetKind::RunningProcess;
        if (str == "Managed .NET EXE" || str == "dotnet_exe") return TargetKind::ManagedExe;
        if (str == "Managed .NET DLL" || str == "dotnet_dll") return TargetKind::ManagedDll;
        if (str == "Windows Service" || str == "service") return TargetKind::Service;
        if (str == "Kernel Driver" || str == "driver" || str == "sys") return TargetKind::Driver;
        if (str == "QEMU VM Target" || str == "vm") return TargetKind::VmTarget;
        return TargetKind::Unknown;
    }

    // ─── Target Capabilities ───────────────────────────────────────────────────
    struct TargetCapabilities {
        bool staticAnalysis = false;
        bool modules = false;
        bool threads = false;
        bool memoryRead = false;
        bool memorySnapshots = false;
        bool runtimeEvents = false;
        bool functions = false;
        bool symbols = false;
        bool managedMetadata = false;
        bool debugControl = false;
        bool sandboxExecution = false;
        bool kernelObservation = false;

        std::string Summary() const {
            std::string s;
            if (staticAnalysis) s += "Static ";
            if (modules) s += "Modules ";
            if (threads) s += "Threads ";
            if (memoryRead) s += "MemRead ";
            if (memorySnapshots) s += "Snapshots ";
            if (runtimeEvents) s += "Events ";
            if (functions) s += "Funcs ";
            if (symbols) s += "Symbols ";
            if (managedMetadata) s += "Managed ";
            if (debugControl) s += "Debug ";
            if (sandboxExecution) s += "Sandbox ";
            if (kernelObservation) s += "Kernel ";
            return s.empty() ? "None" : s;
        }
    };

    // ─── Target Information ────────────────────────────────────────────────────
    struct TargetInfo {
        TargetKind   kind = TargetKind::Unknown;
        std::string  path;
        std::string  name;
        uint64_t     size = 0;
        std::string  sha256;
        std::string  md5;
        std::string  architecture = "x64"; // "x86", "x64", "ARM64"
        std::string  subsystem = "Console";
        uint64_t     entryPointRva = 0;
        uint64_t     imageBase = 0;
        uint32_t     pid = 0;
        std::string  serviceName;
        std::string  serviceDisplayName;
        std::string  serviceState;
        bool         is64Bit = true;
        bool         isDotNet = false;
        bool         isPacked = false;
        std::string  activeBackend = "Static";
        std::string  visibility = "Full";
        std::string  statusDetails;
    };

    // ─── Target Module & Thread Metadata ───────────────────────────────────────
    struct UtrModuleInfo {
        uint64_t    baseAddress = 0;
        uint64_t    size = 0;
        std::string name;
        std::string path;
        std::string checksum;
        bool        isMainModule = false;
    };

    struct UtrThreadInfo {
        uint32_t    tid = 0;
        uint64_t    startAddress = 0;
        std::string state;
        int32_t     priority = 0;
        uint64_t    tebAddress = 0;
    };

    // ─── Resource Budgets & Limits ─────────────────────────────────────────────
    struct BudgetLimits {
        uint32_t maxRuntimeDurationSec = 120;
        uint32_t maxTraceEvents = 20000;
        uint32_t maxQueuedRuntimeEvents = 50000;
        uint64_t maxSnapshotBytes = 256 * 1024 * 1024;    // 256 MB
        uint64_t maxBytesPerRegion = 32 * 1024 * 1024;    // 32 MB
        uint64_t maxTotalSessionDiskBytes = 1024 * 1024 * 1024; // 1 GB
        uint64_t maxArtifactBytes = 64 * 1024 * 1024;     // 64 MB
        uint32_t maxFunctionIndexingCount = 100000;
        uint32_t maxDeepAnalysisInstructions = 50000;
        uint64_t maxMcpResponseBytes = 8 * 1024 * 1024;   // 8 MB
        uint64_t maxManagedHostResponseBytes = 16 * 1024 * 1024; // 16 MB
        uint32_t maxManagedHostTimeoutMs = 5000;          // 5s
        uint32_t maxConcurrentWorkers = 4;
    };

    struct BudgetUsage {
        uint32_t runtimeDurationSec = 0;
        uint32_t traceEvents = 0;
        uint32_t queuedEvents = 0;
        uint64_t snapshotBytes = 0;
        uint64_t totalSessionDiskBytes = 0;
        uint32_t indexedFunctions = 0;
        bool     truncated = false;
        std::string truncationReason;
    };

    // ─── Generic Result Type ───────────────────────────────────────────────────
    template<typename T>
    class Result {
    public:
        Result() : m_hasValue(false) {}

        bool Ok() const { return m_hasValue; }
        const T& Value() const { return m_value; }
        T& Value() { return m_value; }
        const std::string& Error() const { return m_error; }

        static Result<T> Success(const T& val) {
            Result<T> r;
            r.m_value = val;
            r.m_hasValue = true;
            return r;
        }

        static Result<T> Success(T&& val) {
            Result<T> r;
            r.m_value = std::move(val);
            r.m_hasValue = true;
            return r;
        }

        static Result<T> Fail(const std::string& err) {
            Result<T> r;
            r.m_error = err;
            r.m_hasValue = false;
            return r;
        }

    private:
        T           m_value{};
        std::string m_error;
        bool        m_hasValue = false;
    };

    template<>
    class Result<void> {
    public:
        Result() : m_hasValue(true) {}
        Result(const std::string& err) : m_error(err), m_hasValue(false) {}
        Result(const char* err) : m_error(err), m_hasValue(false) {}

        bool Ok() const { return m_hasValue; }
        const std::string& Error() const { return m_error; }

        static Result<void> Success() { return Result<void>(); }
        static Result<void> Fail(const std::string& err) { return Result<void>(err); }

    private:
        std::string m_error;
        bool        m_hasValue = false;
    };

} // namespace UTR
} // namespace Dracula
