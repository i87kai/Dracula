#pragma once

//
// Dracula Project -- the durable, authoritative analysis workspace.
//
// A Project is the single source of truth for "what am I analyzing". Before
// v1.3.0 the answer was scattered across TargetManager's active target, the
// shell's active sample string and a SQLite session row, which is how a PID
// specifier could end up stored as a file path. Every command now resolves its
// subject through the active Project instead of reparsing a command string.
//
// The Project owns a directory on disk. It survives process exit; reopening
// Dracula restores it exactly.
//

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <cstdint>

#include "utr/types.h"
#include "app/dto.h"
#include "app/json.h"

namespace Dracula {
namespace App {

    // Local timestamp in ISO-8601 form ("2026-08-18T10:12:04"), used for every
    // created_at / captured_at field Dracula persists.
    std::string NowIso8601();

    // --- Target Identity ------------------------------------------------------
    // The identity of what a project analyzes. A running process keeps its PID
    // in `pid` and its on-disk image in `backingExecutable`; the two are never
    // conflated, and `pid` is never written into any path-shaped field.
    struct TargetIdentity {
        UTR::TargetKind kind = UTR::TargetKind::Unknown;
        std::string     name;

        // File-backed identity. `originalSourcePath` is the user's file, which
        // Dracula reads but never modifies or deletes. `projectCopyRelative` is
        // the immutable copy inside the project (e.g. "original/test.exe").
        std::string     originalSourcePath;
        std::string     projectCopyRelative;
        std::string     sha256;
        uint64_t        sizeBytes = 0;

        std::string     architecture = "x64";
        bool            is64Bit = true;
        bool            isDotNet = false;
        uint64_t        imageBase = 0;
        uint64_t        entryPointRva = 0;

        // Live-process identity. Zero/empty for a purely file-backed project.
        uint32_t        pid = 0;
        std::string     backingExecutable;

        // Service identity.
        std::string     serviceName;

        bool IsLiveProcess() const { return kind == UTR::TargetKind::RunningProcess; }
        bool HasFileBacking() const {
            return !projectCopyRelative.empty() || !backingExecutable.empty();
        }

        Json ToJson() const;
        static TargetIdentity FromJson(const Json& j);
    };

    // --- Snapshot bookkeeping (section 16) ------------------------------------
    // Snapshot IDs are allocated from a counter persisted in project.json, so
    // they stay unique and monotonic across restarts rather than resetting to
    // #1 on every capture.
    struct SnapshotRecord {
        uint32_t    id = 0;
        std::string label;
        std::string capturedAt;
        uint32_t    pid = 0;
        uint64_t    regionCount = 0;
        uint64_t    committedBytes = 0;
        uint64_t    retainedBytes = 0;
        std::string status = "Complete";
        std::string truncationReason;
        std::string identityHash;
        std::string dataRelativePath;

        Json ToJson() const;
        static SnapshotRecord FromJson(const Json& j);
    };

    struct ArtifactRecord {
        std::string id;
        std::string kind;
        std::string format;
        std::string relativePath;
        std::string title;
        std::string createdAt;
        uint64_t    sizeBytes = 0;
        uint64_t    rowCount = 0;

        Json ToJson() const;
        static ArtifactRecord FromJson(const Json& j);
    };

    // --- Project --------------------------------------------------------------
    class Project {
    public:
        Project() = default;

        // --- Identity ---------------------------------------------------------
        const std::string& Id() const { return m_id; }
        const std::string& DisplayName() const { return m_displayName; }
        const std::string& Root() const { return m_root; }
        const std::string& CreatedAt() const { return m_createdAt; }
        const std::string& LastOpenedAt() const { return m_lastOpenedAt; }
        const std::string& DraculaVersion() const { return m_draculaVersion; }

        TargetIdentity& Target() { return m_target; }
        const TargetIdentity& Target() const { return m_target; }

        // --- Directory layout (section 5) -------------------------------------
        std::string OriginalDir() const;
        std::string StaticDir() const;
        std::string FunctionsDir() const;
        std::string ModulesDir() const;
        std::string MemoryDir() const;
        std::string MemoryMapsDir() const;
        std::string MemorySnapshotsDir() const;
        std::string MemoryDumpsDir() const;
        std::string RuntimeDir() const;
        std::string SandboxDir() const;
        std::string ReportsDir() const;
        std::string ArtifactsDir() const;
        std::string LogsDir() const;
        std::string OverlaysDir() const;
        std::string CacheDir() const;

        // Creates the full directory tree. Idempotent.
        bool EnsureLayout(std::string& error);

        // Absolute path of the project's immutable copy of the sample, or "".
        std::string OriginalSamplePath() const;

        // The path static analysis should use for this project: the project's
        // own copy when present, else the resolved process backing image.
        // Returns "" when the target genuinely has no file backing -- callers
        // then produce a capability-aware error rather than a path error.
        std::string StaticAnalysisPath() const;

        // --- Persistence (section 44: atomic, crash-safe) ---------------------
        bool Save(std::string& error) const;
        static bool Load(const std::string& projectDir, Project& out, std::string& error);

        void TouchLastOpened();

        // --- Snapshots --------------------------------------------------------
        uint32_t AllocateSnapshotId();
        void AddSnapshot(const SnapshotRecord& rec);
        const std::vector<SnapshotRecord>& Snapshots() const { return m_snapshots; }
        // Resolves "3", "before" or an exact label to a snapshot. Null if absent.
        const SnapshotRecord* FindSnapshot(const std::string& idOrLabel) const;

        // --- Artifacts --------------------------------------------------------
        // Allocates the next numbered path for an artifact kind, e.g.
        // ("memory-map", "map", "html") -> <project>\memory\maps\map_0003.html
        std::string NextArtifactPath(const std::string& subdir,
                                     const std::string& stem,
                                     const std::string& extension);
        void AddArtifact(const ArtifactRecord& rec);
        const std::vector<ArtifactRecord>& Artifacts() const { return m_artifacts; }

        // --- Summaries for the presentation layer -----------------------------
        ProjectSummary Summarize() const;
        TargetSummary  SummarizeTarget() const;
        StorageReport  ComputeStorage() const;

        // Removes disposable data (overlays, scratch, caches) while retaining
        // the original sample, metadata, reports and retained snapshots.
        uint64_t Cleanup(std::vector<std::string>& removedDescriptions);

        // --- Construction (used by ProjectManager) ----------------------------
        void InitializeNew(const std::string& id,
                           const std::string& displayName,
                           const std::string& root);

    private:
        std::string m_id;
        std::string m_displayName;
        std::string m_root;
        std::string m_createdAt;
        std::string m_lastOpenedAt;
        std::string m_draculaVersion;

        TargetIdentity m_target;

        uint32_t m_nextSnapshotId = 1;
        std::vector<SnapshotRecord> m_snapshots;
        std::vector<ArtifactRecord> m_artifacts;

        mutable std::mutex m_mutex;
    };

} // namespace App
} // namespace Dracula
