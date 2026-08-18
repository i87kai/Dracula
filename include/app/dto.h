#pragma once

//
// Dracula Application-Layer Data Transfer Objects.
//
// Every application service returns these structures. They carry DATA ONLY:
// no ANSI escapes, no column padding, no terminal width assumptions. The CLI
// adapter formats them for a console; a future Local Web GUI adapter will
// serialize the same objects to JSON without touching an analysis engine.
//
// Rule for this header: it may include the UTR types it describes, but it must
// never include anything from cli/.
//

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

#include "utr/types.h"

namespace Dracula {
namespace App {

    // --- Errors ---------------------------------------------------------------
    // A failure always carries a machine-readable code, a human reason, and --
    // where the failure is a capability mismatch -- what the target CAN do, so
    // the presentation layer can render the capability-aware errors of section
    // 15 instead of a bare "file does not exist".
    struct ErrorDetail {
        std::string code;              // e.g. "no_active_project", "capability_unavailable"
        std::string message;           // one-line summary
        std::string reason;            // why it failed, in full
        std::string remediation;       // what the user can do about it
        std::vector<std::string> availableInstead; // capabilities that ARE available

        bool Empty() const { return code.empty() && message.empty(); }
    };

    // --- Artifacts & Evidence -------------------------------------------------
    // Detailed output is written to project storage and referenced here rather
    // than flooding the terminal (section 20).
    struct ArtifactReference {
        std::string id;
        std::string kind;              // "memory-map", "functions", "runtime-events", ...
        std::string format;            // "html", "json", "txt", "md"
        std::string path;              // absolute path on disk
        std::string projectRelative;   // path relative to the project root
        uint64_t    sizeBytes = 0;
        std::string createdAt;
        std::string title;
        uint64_t    rowCount = 0;      // for tabular artifacts
    };

    struct EvidenceReference {
        std::string id;
        std::string kind;
        std::string summary;
        // How strongly this is established (section 10): STATIC calculation
        // only, RESOLVED against a live module base, or verified by a real read.
        std::string level;             // "STATIC" | "RESOLVED" | "LIVE-READ VERIFIED"
        std::string source;
    };

    // --- Command Result -------------------------------------------------------
    // The universal envelope returned by the operation API.
    struct CommandResult {
        bool                            ok = true;
        std::string                     summary;
        std::vector<std::string>        lines;
        std::vector<ArtifactReference>  artifacts;
        std::vector<EvidenceReference>  evidence;
        ErrorDetail                     error;

        static CommandResult Success(const std::string& summary = "") {
            CommandResult r;
            r.ok = true;
            r.summary = summary;
            return r;
        }

        static CommandResult Failure(const ErrorDetail& err) {
            CommandResult r;
            r.ok = false;
            r.error = err;
            r.summary = err.message;
            return r;
        }

        static CommandResult Failure(const std::string& code, const std::string& message,
                                     const std::string& reason = "",
                                     const std::string& remediation = "") {
            ErrorDetail e;
            e.code = code;
            e.message = message;
            e.reason = reason;
            e.remediation = remediation;
            return Failure(e);
        }

        CommandResult& Line(const std::string& l) { lines.push_back(l); return *this; }
    };

    // --- Project & Target Summaries -------------------------------------------
    struct TargetSummary {
        UTR::TargetKind kind = UTR::TargetKind::Unknown;
        std::string     kindLabel;
        std::string     name;
        std::string     architecture;
        std::string     sha256;
        uint64_t        sizeBytes = 0;

        // A running-process target keeps its PID as a PID. backingExecutable is
        // the resolved on-disk image, which is what static analysis uses -- the
        // PID is NEVER used as a path (section 11).
        bool            isLiveProcess = false;
        uint32_t        pid = 0;
        std::string     backingExecutable;

        std::string     originalSourcePath;  // where the user's file came from
        std::string     projectCopyPath;     // Dracula's immutable copy
        bool            isDotNet = false;
        UTR::TargetCapabilities capabilities;
    };

    struct ProjectSummary {
        std::string   id;              // stable project identifier
        std::string   displayName;
        std::string   directory;
        std::string   createdAt;
        std::string   lastOpenedAt;
        std::string   draculaVersion;
        TargetSummary target;
        uint64_t      totalBytes = 0;
        bool          isActive = false;
    };

    // --- Storage Accounting (section 8) ---------------------------------------
    struct StorageEntry {
        std::string category;           // "Original sample", "Memory snapshots", ...
        uint64_t    bytes = 0;
        bool        disposable = false; // reclaimable by cleanup without data loss
    };

    struct StorageReport {
        std::vector<StorageEntry> entries;
        uint64_t totalBytes = 0;
        uint64_t diskFreeBytes = 0;
        uint64_t disposableBytes = 0;
        std::string projectId;
        std::string projectDirectory;
    };

    // --- Memory ---------------------------------------------------------------
    struct MemoryMapSummary {
        uint64_t regionCount = 0;
        uint64_t committedBytes = 0;
        uint64_t executableRegions = 0;
        uint64_t readWriteRegions = 0;
        uint64_t readOnlyRegions = 0;
        uint64_t guardRegions = 0;
        uint64_t privateRegions = 0;
        uint64_t imageRegions = 0;
    };

    struct SnapshotSummary {
        uint32_t    id = 0;            // project-local, monotonic, persisted (section 16)
        std::string label;
        std::string capturedAt;
        uint32_t    pid = 0;
        uint64_t    regionCount = 0;
        uint64_t    committedBytes = 0;
        uint64_t    retainedBytes = 0;
        std::string status;            // "Complete", "Truncated", "Failed"
        std::string truncationReason;
        std::string identityHash;
    };

    struct SnapshotDiffSummary {
        uint32_t fromId = 0;
        uint32_t toId = 0;
        std::string fromLabel;
        std::string toLabel;
        uint64_t addedRegions = 0;
        uint64_t removedRegions = 0;
        uint64_t changedRegions = 0;
        uint64_t protectionChanges = 0;
        int64_t  bytesDelta = 0;
    };

    // --- Functions (section 10) -----------------------------------------------
    struct FunctionSummary {
        std::string name;
        uint64_t    staticRva = 0;
        uint64_t    preferredVa = 0;   // imageBase + rva
        uint64_t    loadedBase = 0;    // 0 when the module is not loaded
        uint64_t    liveVa = 0;        // loadedBase + rva; 0 when unresolved
        bool        liveReadVerified = false;
        std::string moduleName;
        double      interestScore = 0.0;
        uint64_t    sizeBytes = 0;
        std::string evidenceLevel;     // STATIC | RESOLVED | LIVE-READ VERIFIED
    };

    // --- Runtime (sections 17, 18) --------------------------------------------
    // Readiness is a spectrum, not a boolean. A backend that is merely present
    // on disk reports Installed -- never Ready (section 18).
    enum class BackendState {
        Unsupported,
        NotRequired,
        Installed,
        Available,
        Initialized,
        Active,
        Connected,
        Authenticated,
        Partial,
        Stopped,
        Failed
    };

    inline const char* BackendStateToString(BackendState s) {
        switch (s) {
            case BackendState::Unsupported:   return "Unsupported";
            case BackendState::NotRequired:   return "Not Required";
            case BackendState::Installed:     return "Installed";
            case BackendState::Available:     return "Available";
            case BackendState::Initialized:   return "Initialized";
            case BackendState::Active:        return "Active";
            case BackendState::Connected:     return "Connected";
            case BackendState::Authenticated: return "Authenticated";
            case BackendState::Partial:       return "Partial";
            case BackendState::Stopped:       return "Stopped";
            case BackendState::Failed:        return "Failed";
        }
        return "Unknown";
    }

    struct BackendStatus {
        std::string  name;
        BackendState state = BackendState::Unsupported;
        std::string  detail;           // qualifier, e.g. "Partial capability"
        std::string  reason;           // populated on Failed/Unsupported
    };

    struct RuntimeStatus {
        std::vector<BackendStatus> backends;
        bool     runtimeActive = false;
        uint32_t eventCount = 0;
        uint32_t livePid = 0;
        std::string sessionIdentity;
    };

    struct RuntimeEvent {
        uint64_t    sequence = 0;
        std::string timestamp;
        std::string category;          // "QEMU", "AGENT", "TARGET", "IMAGE", ...
        std::string severity;          // "info", "warn", "error"
        std::string message;
        std::string detail;
    };

} // namespace App
} // namespace Dracula
