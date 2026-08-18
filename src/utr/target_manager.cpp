#include "utr/target_manager.h"
#include "core/pe_inspector.h"
#include "common/paths.h"

#include <filesystem>
#include <iostream>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace Dracula {
namespace UTR {

    // Forward declarations of factory functions
    std::shared_ptr<ITarget> CreateFileTarget(const TargetInfo& info);
    std::shared_ptr<ITarget> CreateProcessTarget(const TargetInfo& info);
    std::shared_ptr<ITarget> CreateManagedTarget(const TargetInfo& info);
    std::shared_ptr<ITarget> CreateServiceTarget(const TargetInfo& info);
    std::shared_ptr<ITarget> CreateDriverTarget(const TargetInfo& info);

    TargetManager& TargetManager::Instance() {
        static TargetManager instance;
        return instance;
    }

    TargetManager::~TargetManager() {
        CloseActiveTarget();
    }

    TargetInfo TargetManager::Fingerprint(const std::string& targetSpecifier, const std::string& typeHint) {
        TargetInfo info;
        info.path = targetSpecifier;

        // 1. Check PID target
        if (targetSpecifier.rfind("--pid", 0) == 0 || targetSpecifier.rfind("-p", 0) == 0) {
            std::string pidStr = targetSpecifier.substr(targetSpecifier.find_first_of("0123456789"));
            try {
                info.pid = std::stoul(pidStr);
            } catch (...) {}
            info.kind = TargetKind::RunningProcess;
            info.name = "PID_" + std::to_string(info.pid);
            info.activeBackend = "DbgEng/ExternalObserver";
            return info;
        }

        // Check if pure numeric PID
        if (!targetSpecifier.empty() && std::all_of(targetSpecifier.begin(), targetSpecifier.end(), ::isdigit)) {
            try {
                info.pid = std::stoul(targetSpecifier);
                info.kind = TargetKind::RunningProcess;
                info.name = "PID_" + std::to_string(info.pid);
                info.activeBackend = "DbgEng/ExternalObserver";
                return info;
            } catch (...) {}
        }

        // 2. Check Service target
        if (targetSpecifier.rfind("--service", 0) == 0 || targetSpecifier.rfind("-s", 0) == 0) {
            size_t spacePos = targetSpecifier.find(' ');
            std::string svcName = (spacePos != std::string::npos) ? targetSpecifier.substr(spacePos + 1) : targetSpecifier;
            info.kind = TargetKind::Service;
            info.serviceName = svcName;
            info.name = "Service:" + svcName;
            info.activeBackend = "ServiceManager";
            return info;
        }

        // 3. Check VM Target
        if (targetSpecifier == "--vm" || targetSpecifier == "vm") {
            info.kind = TargetKind::VmTarget;
            info.name = "QEMU_VM_Guest";
            info.activeBackend = "QEMU_Sandbox";
            return info;
        }

        // 4. File-based target (EXE, DLL, SYS, Managed)
        std::string resolvedPath = Paths::ResolveResource(targetSpecifier);
        if (resolvedPath.empty()) {
            resolvedPath = targetSpecifier;
        }
        info.path = resolvedPath;
        info.name = fs::path(resolvedPath).filename().string();

        try {
            if (fs::exists(resolvedPath)) {
                info.size = fs::file_size(resolvedPath);
            }
        } catch (...) {}

        std::string ext = fs::path(resolvedPath).extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

        PeInspector inspector;
        std::string err;
        if (inspector.LoadFromFile(resolvedPath, err)) {
            auto meta = inspector.GetMetadata();
            auto mitigations = inspector.GetMitigations();
            info.sha256 = meta.sha256;
            info.md5 = meta.md5;
            info.architecture = meta.architecture;
            info.is64Bit = meta.is64Bit;
            info.isDotNet = mitigations.isDotNet;
            info.entryPointRva = meta.entryPointRva;
            info.imageBase = meta.imageBase;

            if (mitigations.isDotNet) {
                info.kind = meta.isDll ? TargetKind::ManagedDll : TargetKind::ManagedExe;
                info.activeBackend = "ManagedHost (.NET)";
            } else if (ext == ".sys") {
                info.kind = TargetKind::Driver;
                info.activeBackend = "DriverStatic / QEMU";
            } else if (meta.isDll || ext == ".dll") {
                info.kind = TargetKind::NativeDll;
                info.activeBackend = "Static / DllHarness";
            } else {
                info.kind = TargetKind::NativeExe;
                info.activeBackend = "Static / Unicorn";
            }
        } else {
            // Non-PE or unknown
            if (ext == ".dll") info.kind = TargetKind::NativeDll;
            else if (ext == ".sys") info.kind = TargetKind::Driver;
            else info.kind = TargetKind::NativeExe;
            info.activeBackend = "Static";
        }

        if (!typeHint.empty()) {
            info.kind = StringToTargetKind(typeHint);
        }

        return info;
    }

    // Instantiates the concrete backend for an already-classified target.
    static std::shared_ptr<ITarget> InstantiateTarget(const TargetInfo& info) {
        switch (info.kind) {
            case TargetKind::NativeExe:
            case TargetKind::NativeDll:
                return CreateFileTarget(info);
            case TargetKind::RunningProcess:
                return CreateProcessTarget(info);
            case TargetKind::ManagedExe:
            case TargetKind::ManagedDll:
                return CreateManagedTarget(info);
            case TargetKind::Service:
                return CreateServiceTarget(info);
            case TargetKind::Driver:
                return CreateDriverTarget(info);
            case TargetKind::VmTarget:
            default:
                return CreateFileTarget(info);
        }
    }

    Result<std::shared_ptr<ITarget>> TargetManager::OpenTargetFromInfo(const TargetInfo& info) {
        std::lock_guard<std::mutex> lock(m_mutex);
        CloseActiveTarget();

        std::shared_ptr<ITarget> target = InstantiateTarget(info);
        if (!target) {
            return Result<std::shared_ptr<ITarget>>::Fail(
                std::string("could not instantiate a ") + TargetKindToString(info.kind) + " backend");
        }

        m_activeTarget = target;
        m_evidenceGraph.Clear();
        return Result<std::shared_ptr<ITarget>>::Success(m_activeTarget);
    }

    Result<std::shared_ptr<ITarget>> TargetManager::OpenTarget(
        const std::string& targetSpecifier,
        const std::string& typeHint)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        CloseActiveTarget();

        TargetInfo info = Fingerprint(targetSpecifier, typeHint);
        std::shared_ptr<ITarget> target = nullptr;

        switch (info.kind) {
            case TargetKind::NativeExe:
            case TargetKind::NativeDll:
                target = CreateFileTarget(info);
                break;
            case TargetKind::RunningProcess:
                target = CreateProcessTarget(info);
                break;
            case TargetKind::ManagedExe:
            case TargetKind::ManagedDll:
                target = CreateManagedTarget(info);
                break;
            case TargetKind::Service:
                target = CreateServiceTarget(info);
                break;
            case TargetKind::Driver:
                target = CreateDriverTarget(info);
                break;
            case TargetKind::VmTarget:
            default:
                target = CreateFileTarget(info);
                break;
        }

        if (!target) {
            return Result<std::shared_ptr<ITarget>>::Fail("Failed to instantiate target for " + targetSpecifier);
        }

        m_activeTarget = target;
        m_evidenceGraph.Clear();

        // Create persistent session
        uint32_t sessionId = SessionManager::Instance().CreateSession(info);
        (void)sessionId;

        return Result<std::shared_ptr<ITarget>>::Success(m_activeTarget);
    }

    std::shared_ptr<ITarget> TargetManager::GetActiveTarget() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_activeTarget;
    }

    TargetInfo TargetManager::GetActiveTargetInfo() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_activeTarget) return m_activeTarget->GetInfo();
        TargetInfo empty;
        empty.name = "No target loaded";
        return empty;
    }

    TargetCapabilities TargetManager::GetActiveCapabilities() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_activeTarget) return m_activeTarget->GetCapabilities();
        return TargetCapabilities();
    }

    void TargetManager::CloseActiveTarget() {
        m_activeTarget.reset();
        m_evidenceGraph.Clear();
    }

} // namespace UTR
} // namespace Dracula
