#pragma once

//
// Dracula Application Services.
//
// This is the operation API. Every command the user can invoke -- from the CLI
// today, from a Local Web GUI later, or from MCP -- resolves to a method here.
// Services take their subject from the ACTIVE PROJECT, never from a re-parsed
// command string, and return structured CommandResult/DTO values that contain
// no terminal formatting.
//
// Services must not include anything from cli/.
//

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

#include "app/dto.h"
#include "app/project.h"
#include "app/project_manager.h"
#include "utr/target.h"

namespace Dracula {
namespace App {

    // --- Target binding -------------------------------------------------------
    // Materializes (and caches) the concrete UTR target backing the active
    // project. This is where a TargetIdentity becomes a live ITarget without
    // any specifier string ever being constructed.
    class TargetBinding {
    public:
        static TargetBinding& Instance();

        // Returns the ITarget for the active project, opening it on first use.
        // Fails with a capability-aware error when the project has no target
        // that can be materialized.
        UTR::Result<std::shared_ptr<UTR::ITarget>> Resolve();

        // Builds the UTR TargetInfo for a project from its stored identity.
        static UTR::TargetInfo BuildTargetInfo(const Project& project);

        // Capabilities derived from the project identity alone, available even
        // when no backend has been instantiated yet (used for /target
        // capabilities and for capability-aware error messages).
        static UTR::TargetCapabilities DeriveCapabilities(const Project& project);

        void Invalidate();

    private:
        std::shared_ptr<UTR::ITarget> m_target;
        std::string m_boundProjectId;
        uint32_t    m_boundPid = 0;
    };

    // --- Shared helpers -------------------------------------------------------
    // Produces the standard "no active project" error.
    ErrorDetail NoActiveProjectError();

    // Produces a capability-aware error listing what the target CAN do
    // (section 15), instead of a bare path/file error.
    ErrorDetail CapabilityError(const Project& project,
                                const std::string& capability,
                                const std::string& reason);

    // Human-readable byte count ("622.0 MB"). Shared by every service that
    // reports sizes.
    std::string FormatBytes(uint64_t bytes);

    // Records a generated file as a project artifact and returns a reference to
    // it. Keeps <project>/project.json and the on-disk artifact in step, so
    // every important output has exactly one predictable home (section 35).
    ArtifactReference PublishArtifact(Project& project,
                                      const std::string& absolutePath,
                                      const std::string& kind,
                                      const std::string& format,
                                      const std::string& title,
                                      uint64_t rowCount = 0);

    // Opens a generated report in the system default handler when the
    // reports.auto_open setting is enabled. A failure to open is never treated
    // as a failure of the report itself (section 36).
    bool MaybeAutoOpen(const std::string& path);

    // --- ProjectService -------------------------------------------------------
    class ProjectService {
    public:
        static ProjectService& Instance();

        CommandResult OpenFile(const std::string& path, bool forceNew = false);
        CommandResult AttachProcess(uint32_t pid, bool forceNew = false);

        CommandResult Info() const;
        CommandResult List() const;
        CommandResult Open(const std::string& idOrName);
        CommandResult Close();
        CommandResult Storage() const;
        CommandResult Cleanup(const std::string& idOrName = "");
        CommandResult Delete(const std::string& idOrName, bool force);

        // Persists whatever the active project currently holds.
        bool SaveActive(std::string& error) const;
    };

    // --- TargetService --------------------------------------------------------
    class TargetService {
    public:
        static TargetService& Instance();

        CommandResult Info() const;
        CommandResult Capabilities() const;
    };

    // --- StaticService --------------------------------------------------------
    // Static analysis always runs against the project's file backing. For a
    // process-backed project that is the resolved backing executable, so
    // /static works on a PID project without the user reopening anything.
    class StaticService {
    public:
        static StaticService& Instance();

        // Resolves the file static analysis should use, or a capability-aware
        // error explaining why none exists.
        UTR::Result<std::string> ResolveStaticPath() const;

        CommandResult Info() const;
        CommandResult Sections() const;
        CommandResult Imports() const;
        CommandResult Exports() const;
        CommandResult Strings(size_t minLength = 4) const;
    };

    // --- ProcessService -------------------------------------------------------
    class ProcessService {
    public:
        static ProcessService& Instance();

        CommandResult List() const;
        CommandResult Info() const;
        CommandResult Modules() const;
        CommandResult Threads() const;
    };

    // --- DllService -----------------------------------------------------------
    // Correlates a loaded module with its on-disk image inside the SAME
    // project (sections 9, 10). Opening a DLL never replaces the project's
    // target.
    class DllService {
    public:
        static DllService& Instance();

        // A module resolved within the active project's context.
        struct ResolvedModule {
            std::string name;
            std::string backingPath;   // on-disk image
            uint64_t    loadedBase = 0; // 0 when not loaded in the live process
            uint64_t    imageSize = 0;
            bool        isLoaded = false;
        };

        UTR::Result<ResolvedModule> ResolveModule(const std::string& nameOrPath) const;

        CommandResult Info(const std::string& nameOrPath) const;
        CommandResult Exports(const std::string& nameOrPath) const;
        CommandResult Imports(const std::string& nameOrPath) const;
        CommandResult Functions(const std::string& nameOrPath) const;
    };

    // --- MemoryService --------------------------------------------------------
    class MemoryService {
    public:
        static MemoryService& Instance();

        CommandResult Map() const;
        CommandResult Read(uint64_t address, size_t size) const;
        CommandResult Snapshot(const std::string& label);
        CommandResult ListSnapshots() const;
        CommandResult Compare(const std::string& fromIdOrLabel,
                              const std::string& toIdOrLabel) const;
    };

    // --- RuntimeService -------------------------------------------------------
    // Reports what is ACTUALLY true (section 18). Nothing here reports Ready
    // because a file exists.
    class RuntimeService {
    public:
        static RuntimeService& Instance();

        RuntimeStatus QueryStatus() const;
        CommandResult Status() const;
        CommandResult Events() const;

        // Appends an event to the active project's runtime log.
        void RecordEvent(const std::string& category,
                         const std::string& message,
                         const std::string& severity = "info",
                         const std::string& detail = "");

        std::vector<RuntimeEvent> LoadEvents() const;
    };

} // namespace App
} // namespace Dracula
