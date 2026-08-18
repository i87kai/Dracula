#pragma once

//
// ProjectManager -- creates, indexes, opens and deletes Dracula projects.
//
// It owns the durable project index (section 48) so that listing projects and
// detecting an already-analyzed sample never require walking every project
// directory on startup.
//

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <optional>

#include "app/project.h"
#include "app/dto.h"
#include "utr/types.h"

namespace Dracula {
namespace App {

    // A lightweight index entry. Enough to render /project list and to detect
    // an existing project by content hash without opening each project.json.
    struct ProjectIndexEntry {
        std::string     id;
        std::string     displayName;
        std::string     directory;
        std::string     sha256;
        std::string     originalSourcePath;
        UTR::TargetKind kind = UTR::TargetKind::Unknown;
        std::string     architecture;
        std::string     createdAt;
        std::string     lastOpenedAt;
        uint32_t        pid = 0;
        std::string     state = "Ready";

        Json ToJson() const;
        static ProjectIndexEntry FromJson(const Json& j);
    };

    // What happened when a target was opened, so the presentation layer can
    // offer "Continue project" vs "Start new project" (section 6).
    struct OpenOutcome {
        std::shared_ptr<Project> project;
        bool existingProjectFound = false;   // a project for this SHA-256 already existed
        bool reusedExisting = false;         // ... and we opened it rather than creating
        std::vector<ProjectIndexEntry> candidates;
    };

    class ProjectManager {
    public:
        static ProjectManager& Instance();

        ProjectManager() = default;

        // --- Index ------------------------------------------------------------
        // Path of the durable index: <InstallRoot>\config\projects.json
        std::string IndexPath() const;
        bool LoadIndex(std::string& error);
        bool SaveIndex(std::string& error) const;
        std::vector<ProjectIndexEntry> ListProjects() const;

        // Resolves an exact ID, a unique ID prefix, or a display name.
        std::optional<ProjectIndexEntry> Resolve(const std::string& idOrName) const;

        // --- Creation ---------------------------------------------------------
        // Creates a durable project for a file on disk. The original file is
        // copied into <project>\original and never modified.
        // `forceNew` skips existing-project detection.
        UTR::Result<OpenOutcome> CreateFromFile(const std::string& filePath, bool forceNew = false);

        // Creates a durable project for a running process. The PID is recorded
        // as a PID; the backing executable is resolved and copied when readable.
        UTR::Result<OpenOutcome> CreateFromProcess(uint32_t pid, bool forceNew = false);

        // --- Open / close -----------------------------------------------------
        UTR::Result<std::shared_ptr<Project>> OpenById(const std::string& idOrName);
        void CloseActive();

        std::shared_ptr<Project> Active() const;
        bool HasActive() const;
        void SetActive(std::shared_ptr<Project> project);

        // --- Destructive ------------------------------------------------------
        // Removes ONLY Dracula's project workspace. The user's original file
        // outside the project is never touched.
        UTR::Result<uint64_t> DeleteProject(const std::string& idOrName);

        // Finds projects whose sample hash matches, for existing-project detection.
        std::vector<ProjectIndexEntry> FindBySha256(const std::string& sha256) const;

    private:
        void UpsertIndexEntry(const Project& project);
        std::string AllocateProjectDirectory(const std::string& displayName,
                                             const std::string& stableId) const;

        mutable std::mutex m_mutex;
        std::vector<ProjectIndexEntry> m_index;
        bool m_indexLoaded = false;
        std::shared_ptr<Project> m_active;
    };

} // namespace App
} // namespace Dracula
