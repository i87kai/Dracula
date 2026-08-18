#include "app/services.h"
#include "utr/target_manager.h"

#include <filesystem>

namespace fs = std::filesystem;

namespace Dracula {
namespace App {

    TargetBinding& TargetBinding::Instance() {
        static TargetBinding instance;
        return instance;
    }

    UTR::TargetInfo TargetBinding::BuildTargetInfo(const Project& project) {
        const TargetIdentity& id = project.Target();

        UTR::TargetInfo info;
        info.kind = id.kind;
        info.name = id.name;
        info.sha256 = id.sha256;
        info.size = id.sizeBytes;
        info.architecture = id.architecture;
        info.is64Bit = id.is64Bit;
        info.isDotNet = id.isDotNet;
        info.imageBase = id.imageBase;
        info.entryPointRva = id.entryPointRva;
        info.serviceName = id.serviceName;

        // The PID travels in the PID field. `path` carries a real filesystem
        // path or nothing at all -- never a specifier fragment.
        info.pid = id.pid;
        info.path = project.StaticAnalysisPath();

        switch (id.kind) {
            case UTR::TargetKind::RunningProcess:
                info.activeBackend = "ProcessTarget";
                break;
            case UTR::TargetKind::ManagedExe:
            case UTR::TargetKind::ManagedDll:
                info.activeBackend = "ManagedHost (.NET)";
                break;
            case UTR::TargetKind::Service:
                info.activeBackend = "ServiceManager";
                break;
            case UTR::TargetKind::Driver:
                info.activeBackend = "DriverStatic";
                break;
            case UTR::TargetKind::NativeDll:
                info.activeBackend = "Static / DllHarness";
                break;
            default:
                info.activeBackend = "Static";
                break;
        }
        return info;
    }

    UTR::TargetCapabilities TargetBinding::DeriveCapabilities(const Project& project) {
        const TargetIdentity& id = project.Target();
        UTR::TargetCapabilities caps;

        // Anything with a readable file backing supports static analysis. For a
        // process that means its resolved backing image -- which is exactly why
        // /static works on a PID-backed project.
        const bool hasFile = !project.StaticAnalysisPath().empty();
        caps.staticAnalysis = hasFile;
        caps.functions = hasFile;
        caps.symbols = hasFile;

        if (id.IsLiveProcess()) {
            caps.modules = true;
            caps.threads = true;
            caps.memoryRead = true;
            caps.memorySnapshots = true;
            caps.runtimeEvents = true;
            caps.debugControl = true;
        }

        if (id.isDotNet ||
            id.kind == UTR::TargetKind::ManagedExe ||
            id.kind == UTR::TargetKind::ManagedDll) {
            caps.managedMetadata = true;
        }

        if (id.kind == UTR::TargetKind::Driver) {
            caps.kernelObservation = true;
        }

        // Executable samples can be detonated under QEMU isolation; a live
        // process on the host is already running and is not re-detonated.
        if (id.kind == UTR::TargetKind::NativeExe ||
            id.kind == UTR::TargetKind::ManagedExe ||
            id.kind == UTR::TargetKind::Driver) {
            caps.sandboxExecution = hasFile;
        }

        return caps;
    }

    void TargetBinding::Invalidate() {
        m_target.reset();
        m_boundProjectId.clear();
        m_boundPid = 0;
    }

    UTR::Result<std::shared_ptr<UTR::ITarget>> TargetBinding::Resolve() {
        auto project = ProjectManager::Instance().Active();
        if (!project) {
            return UTR::Result<std::shared_ptr<UTR::ITarget>>::Fail(
                "no active project; open one with /project open <id> or /target <file>");
        }

        // Reuse the cached backend only while it still describes the same
        // project AND the same live PID. Re-attaching to a different PID must
        // rebuild the backend rather than silently inspect the old process.
        if (m_target &&
            m_boundProjectId == project->Id() &&
            m_boundPid == project->Target().pid) {
            return UTR::Result<std::shared_ptr<UTR::ITarget>>::Success(m_target);
        }

        UTR::TargetInfo info = BuildTargetInfo(*project);

        // A file-backed project with no readable file cannot produce a backend.
        if (!project->Target().IsLiveProcess() && info.path.empty()) {
            return UTR::Result<std::shared_ptr<UTR::ITarget>>::Fail(
                "the project's sample could not be located on disk");
        }

        auto opened = UTR::TargetManager::Instance().OpenTargetFromInfo(info);
        if (!opened.Ok()) {
            return UTR::Result<std::shared_ptr<UTR::ITarget>>::Fail(opened.Error());
        }

        m_target = opened.Value();
        m_boundProjectId = project->Id();
        m_boundPid = project->Target().pid;
        return UTR::Result<std::shared_ptr<UTR::ITarget>>::Success(m_target);
    }

    // --- Shared error helpers -------------------------------------------------

    ErrorDetail NoActiveProjectError() {
        ErrorDetail e;
        e.code = "no_active_project";
        e.message = "No active project.";
        e.reason = "Dracula commands operate on a project, and none is open.";
        e.remediation = "Open one with /target <file>, /process attach <pid>, or /project open <id>.";
        return e;
    }

    // Lists the capabilities a target genuinely has, so the user is told what
    // they CAN do instead of only what failed.
    static std::vector<std::string> AvailableCapabilityNames(const UTR::TargetCapabilities& caps) {
        std::vector<std::string> names;
        if (caps.staticAnalysis)   names.push_back("Static analysis");
        if (caps.modules)          names.push_back("Modules");
        if (caps.threads)          names.push_back("Threads");
        if (caps.memoryRead)       names.push_back("Memory read");
        if (caps.memorySnapshots)  names.push_back("Memory snapshots");
        if (caps.runtimeEvents)    names.push_back("Runtime events");
        if (caps.functions)        names.push_back("Function intelligence");
        if (caps.managedMetadata)  names.push_back(".NET metadata");
        if (caps.kernelObservation) names.push_back("Kernel observation");
        if (caps.sandboxExecution) names.push_back("Sandbox execution");
        return names;
    }

    ErrorDetail CapabilityError(const Project& project,
                                const std::string& capability,
                                const std::string& reason) {
        ErrorDetail e;
        e.code = "capability_unavailable";
        e.message = capability + " is unavailable for this target.";
        e.reason = reason;
        e.availableInstead = AvailableCapabilityNames(TargetBinding::DeriveCapabilities(project));

        if (e.availableInstead.empty()) {
            e.remediation = "This project has no usable analysis backend; check that its sample still exists.";
        }
        return e;
    }

} // namespace App
} // namespace Dracula
