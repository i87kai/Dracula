#pragma once

//
// SandboxService -- the immutable VM base, its disposable overlays, and the
// .draculaimg package that backs them (sections 30-33).
//
// The lifecycle this enforces:
//
//     windows10.draculaimg          immutable, integrity-checked package
//              |
//              v
//     verified read-only base       <root>\vm\base\<name>.<ext>
//              |
//              v
//     per-run overlay               <root>\vm\overlays\run_<id>.qcow2
//              |
//              v
//     analysis  ->  evidence retained in the project
//              |
//              v
//     overlay deleted               on success AND on failure
//
// Nothing here boots a VM as a side effect. QEMU stays stopped until an
// operation genuinely needs it (section 27).
//

#include <string>
#include <vector>
#include <cstdint>

#include "app/dto.h"
#include "app/dracula_image.h"

namespace Dracula {
namespace App {

    // A temporary per-run disk overlay over the immutable base.
    struct OverlayRecord {
        std::string id;
        std::string path;
        std::string createdAt;
        uint64_t    sizeBytes = 0;
        uint32_t    ownerPid = 0;      // QEMU process that owns it, 0 if none
        bool        active = false;    // an owning process is still alive
    };

    // Everything the sandbox can prove about its own state.
    struct SandboxState {
        BackendState qemuBinary = BackendState::Unsupported;
        std::string  qemuPath;
        std::string  qemuVersion;

        BackendState packageState = BackendState::Unsupported;
        std::string  packagePath;
        DraculaImageInfo packageInfo;

        BackendState baseImageState = BackendState::Unsupported;
        std::string  baseImagePath;
        uint64_t     baseImageBytes = 0;

        BackendState firmwareState = BackendState::Unsupported;
        std::string  firmwarePath;

        BackendState guestAgentState = BackendState::Unsupported;
        std::string  guestAgentPath;

        BackendState vmState = BackendState::Stopped;
        BackendState guestAgentSession = BackendState::Stopped;

        std::vector<OverlayRecord> overlays;
        uint64_t overlayBytes = 0;
    };

    class SandboxService {
    public:
        static SandboxService& Instance();

        // --- State ------------------------------------------------------------
        SandboxState QueryState() const;
        CommandResult Status() const;

        // --- Package management (section 28) ----------------------------------
        // Packages the user's own local VM image into <root>\vm\base.
        CommandResult ImageImport(const std::string& sourcePath);
        CommandResult ImageInfo() const;
        CommandResult ImageVerify(bool deep = true) const;

        // Rebuilds the operational base from the immutable package.
        CommandResult ImageRestore(bool overwrite = false);

        // --- Overlay lifecycle (sections 30, 32) ------------------------------
        // Creates a disposable overlay over the verified base. The base itself
        // is never written to.
        UTR::Result<OverlayRecord> CreateOverlay(const std::string& runId);

        // Removes one overlay. Refuses while an owning QEMU process is alive.
        UTR::Result<uint64_t> ReleaseOverlay(const std::string& overlayId);

        // Removes every overlay with no living owner. Called on startup to
        // recover from a previous crash, and after any failed run.
        UTR::Result<uint64_t> SweepStaleOverlays(std::vector<std::string>& removed);

        std::vector<OverlayRecord> ListOverlays() const;

        // --- Recovery (section 31) --------------------------------------------
        // Stops QEMU, clears overlays, verifies the package, restores the base
        // if needed, and reports exactly what state everything ended in.
        CommandResult Reset();

        // Path of the operational base image, or "" when none exists.
        std::string BaseImagePath() const;

        // Path of the .draculaimg package, or "" when none exists.
        std::string PackagePath() const;
    };

} // namespace App
} // namespace Dracula
