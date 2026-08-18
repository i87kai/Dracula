#include "app/services.h"
#include "common/paths.h"
#include "utr/target_manager.h"

#include <filesystem>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace fs = std::filesystem;

namespace Dracula {
namespace App {

    // Human-readable byte count. Storage figures are read by people, and raw
    // byte counts for a 622 MB snapshot directory are unreadable.
    std::string FormatBytes(uint64_t bytes) {
        static const char* units[] = {"B", "KB", "MB", "GB", "TB"};
        double value = static_cast<double>(bytes);
        int unit = 0;
        while (value >= 1024.0 && unit < 4) {
            value /= 1024.0;
            ++unit;
        }
        std::ostringstream oss;
        if (unit == 0) {
            oss << static_cast<uint64_t>(value) << " " << units[unit];
        } else {
            oss << std::fixed << std::setprecision(1) << value << " " << units[unit];
        }
        return oss.str();
    }

    ProjectService& ProjectService::Instance() {
        static ProjectService instance;
        return instance;
    }

    bool ProjectService::SaveActive(std::string& error) const {
        auto project = ProjectManager::Instance().Active();
        if (!project) {
            error = "no active project";
            return false;
        }
        return project->Save(error);
    }

    CommandResult ProjectService::OpenFile(const std::string& path, bool forceNew) {
        auto created = ProjectManager::Instance().CreateFromFile(path, forceNew);
        if (!created.Ok()) {
            return CommandResult::Failure("open_failed",
                                          "Could not open '" + path + "'.",
                                          created.Error(),
                                          "Check that the file exists and is readable.");
        }

        const OpenOutcome& outcome = created.Value();
        auto project = outcome.project;
        TargetBinding::Instance().Invalidate();

        CommandResult r = CommandResult::Success(
            outcome.reusedExisting
                ? ("Continued existing project '" + project->DisplayName() + "'.")
                : ("Created project '" + project->DisplayName() + "'."));

        if (outcome.reusedExisting) {
            // Section 6: tell the user this sample was already analyzed, and
            // how to start fresh instead of silently continuing.
            r.Line("An existing Dracula project matched this sample by SHA-256.");
            r.Line("Last opened: " + project->LastOpenedAt());
            r.Line("Start an independent project instead with: /project new " + path);
        }

        r.Line("Target:  " + project->Target().name +
               " (" + UTR::TargetKindToString(project->Target().kind) + ")");
        r.Line("Project: " + project->Root());
        return r;
    }

    CommandResult ProjectService::AttachProcess(uint32_t pid, bool forceNew) {
        auto created = ProjectManager::Instance().CreateFromProcess(pid, forceNew);
        if (!created.Ok()) {
            // The PID is reported as a PID even in the failure path.
            return CommandResult::Failure("attach_failed",
                                          "Could not attach to PID " + std::to_string(pid) + ".",
                                          created.Error(),
                                          "Check the process still exists; elevated targets may require running Dracula as Administrator.");
        }

        auto project = created.Value().project;
        TargetBinding::Instance().Invalidate();

        CommandResult r = CommandResult::Success(
            "Attached to PID " + std::to_string(pid) + " (" + project->Target().name + ").");

        const std::string backing = project->Target().backingExecutable;
        if (!backing.empty()) {
            r.Line("Backing executable: " + backing);
            if (!project->Target().projectCopyRelative.empty()) {
                r.Line("Copied into the project, so static analysis stays available after the process exits.");
            }
        } else {
            r.Line("Backing executable could not be resolved; static analysis will be unavailable.");
        }
        r.Line("Project: " + project->Root());
        return r;
    }

    CommandResult ProjectService::Info() const {
        auto project = ProjectManager::Instance().Active();
        if (!project) return CommandResult::Failure(NoActiveProjectError());

        ProjectSummary s = project->Summarize();
        CommandResult r = CommandResult::Success("Project " + s.displayName);
        r.Line("ID:           " + s.id);
        r.Line("Directory:    " + s.directory);
        r.Line("Created:      " + s.createdAt);
        r.Line("Last opened:  " + s.lastOpenedAt);
        r.Line("Dracula:      v" + s.draculaVersion);
        r.Line("Target:       " + s.target.name + " (" + s.target.kindLabel + ", " + s.target.architecture + ")");

        if (s.target.isLiveProcess) {
            r.Line("Live PID:     " + std::to_string(s.target.pid));
            if (!s.target.backingExecutable.empty()) {
                r.Line("Backing:      " + s.target.backingExecutable);
            }
        }
        if (!s.target.sha256.empty()) r.Line("SHA-256:      " + s.target.sha256);
        r.Line("Snapshots:    " + std::to_string(project->Snapshots().size()));
        r.Line("Artifacts:    " + std::to_string(project->Artifacts().size()));
        r.Line("Storage:      " + FormatBytes(s.totalBytes));
        return r;
    }

    CommandResult ProjectService::List() const {
        ProjectManager& pm = ProjectManager::Instance();
        std::string error;
        pm.LoadIndex(error);

        auto projects = pm.ListProjects();
        auto active = pm.Active();

        if (projects.empty()) {
            CommandResult r = CommandResult::Success("No projects yet.");
            r.Line("Create one with /target <file> or /process attach <pid>.");
            return r;
        }

        CommandResult r = CommandResult::Success(
            std::to_string(projects.size()) + " project" + (projects.size() == 1 ? "" : "s") + ".");

        for (const auto& p : projects) {
            const bool isActive = active && active->Id() == p.id;
            std::ostringstream line;
            line << (isActive ? "* " : "  ")
                 << std::left << std::setw(10) << p.id.substr(0, 8) << "  "
                 << std::setw(24) << p.displayName.substr(0, 24) << "  "
                 << std::setw(16) << UTR::TargetKindToString(p.kind);
            if (p.pid != 0) line << "  PID " << p.pid;
            line << "  " << p.lastOpenedAt;
            r.Line(line.str());
        }
        return r;
    }

    CommandResult ProjectService::Open(const std::string& idOrName) {
        if (idOrName.empty()) {
            return CommandResult::Failure("missing_argument",
                                          "No project specified.",
                                          "/project open needs a project ID or name.",
                                          "List available projects with /project list.");
        }

        auto opened = ProjectManager::Instance().OpenById(idOrName);
        if (!opened.Ok()) {
            return CommandResult::Failure("open_failed",
                                          "Could not open project '" + idOrName + "'.",
                                          opened.Error(),
                                          "List available projects with /project list.");
        }

        TargetBinding::Instance().Invalidate();
        auto project = opened.Value();

        CommandResult r = CommandResult::Success("Opened project '" + project->DisplayName() + "'.");
        r.Line("Target:  " + project->Target().name);
        r.Line("Project: " + project->Root());

        // A live PID recorded in a previous run is almost certainly stale.
        if (project->Target().IsLiveProcess()) {
            r.Line("Recorded PID " + std::to_string(project->Target().pid) +
                   " is from a previous session; re-attach with /process attach <pid> for live work.");
        }
        return r;
    }

    CommandResult ProjectService::Close() {
        auto project = ProjectManager::Instance().Active();
        if (!project) return CommandResult::Failure(NoActiveProjectError());

        const std::string name = project->DisplayName();
        std::string error;
        project->Save(error);

        TargetBinding::Instance().Invalidate();
        UTR::TargetManager::Instance().CloseActiveTarget();
        ProjectManager::Instance().CloseActive();

        CommandResult r = CommandResult::Success("Closed project '" + name + "'.");
        r.Line("The project remains on disk and can be reopened with /project open " + name + ".");
        return r;
    }

    CommandResult ProjectService::Storage() const {
        auto project = ProjectManager::Instance().Active();
        if (!project) return CommandResult::Failure(NoActiveProjectError());

        StorageReport report = project->ComputeStorage();

        CommandResult r = CommandResult::Success("Project storage");
        for (const auto& e : report.entries) {
            // Every figure here is measured from disk, never estimated.
            std::ostringstream line;
            line << std::left << std::setw(22) << e.category
                 << std::right << std::setw(12) << FormatBytes(e.bytes);
            if (e.disposable && e.bytes > 0) line << "   (disposable)";
            r.Line(line.str());
        }

        std::ostringstream total;
        total << std::left << std::setw(22) << "Total"
              << std::right << std::setw(12) << FormatBytes(report.totalBytes);
        r.Line(total.str());

        std::ostringstream free;
        free << std::left << std::setw(22) << "Disk free"
             << std::right << std::setw(12) << FormatBytes(report.diskFreeBytes);
        r.Line(free.str());

        if (report.disposableBytes > 0) {
            r.Line("Reclaimable by /project cleanup: " + FormatBytes(report.disposableBytes));
        }
        return r;
    }

    CommandResult ProjectService::Cleanup(const std::string& idOrName) {
        std::shared_ptr<Project> project;

        if (idOrName.empty()) {
            project = ProjectManager::Instance().Active();
            if (!project) return CommandResult::Failure(NoActiveProjectError());
        } else {
            auto entry = ProjectManager::Instance().Resolve(idOrName);
            if (!entry) {
                return CommandResult::Failure("unknown_project",
                                              "No project matches '" + idOrName + "'.",
                                              "The identifier did not match an ID, short ID or name.",
                                              "List available projects with /project list.");
            }
            project = std::make_shared<Project>();
            std::string error;
            if (!Project::Load(entry->directory, *project, error)) {
                return CommandResult::Failure("load_failed",
                                              "Could not load project '" + idOrName + "'.", error);
            }
        }

        std::vector<std::string> removed;
        uint64_t reclaimed = project->Cleanup(removed);

        std::string error;
        project->Save(error);

        CommandResult r = CommandResult::Success(
            reclaimed > 0 ? ("Reclaimed " + FormatBytes(reclaimed) + ".")
                          : "Nothing to clean up.");
        for (const auto& d : removed) r.Line("Removed " + d);
        r.Line("Retained: original sample, project metadata, reports, snapshots and logs.");
        return r;
    }

    CommandResult ProjectService::Delete(const std::string& idOrName, bool force) {
        ProjectManager& pm = ProjectManager::Instance();

        std::string targetId = idOrName;
        if (targetId.empty()) {
            auto active = pm.Active();
            if (!active) return CommandResult::Failure(NoActiveProjectError());
            targetId = active->Id();
        }

        auto entry = pm.Resolve(targetId);
        if (!entry) {
            return CommandResult::Failure("unknown_project",
                                          "No project matches '" + idOrName + "'.",
                                          "The identifier did not match an ID, short ID or name.",
                                          "List available projects with /project list.");
        }

        // Without --force this is a dry run: report exactly what would go, and
        // what would NOT, so the caller can confirm (section 7).
        if (!force) {
            Project preview;
            uint64_t size = 0;
            std::string error;
            if (Project::Load(entry->directory, preview, error)) {
                size = preview.ComputeStorage().totalBytes;
            }

            CommandResult r = CommandResult::Success("Confirm deletion");
            r.ok = false;
            r.error.code = "confirmation_required";
            r.error.message = "Deletion requires confirmation.";
            r.Line("Project:         " + entry->displayName);
            r.Line("ID:              " + entry->id);
            r.Line("Directory:       " + entry->directory);
            r.Line("Project storage: " + FormatBytes(size));
            r.Line("");
            r.Line("This removes Dracula's project copy, runtime data, reports,");
            r.Line("snapshots and project artifacts.");
            if (!entry->originalSourcePath.empty()) {
                r.Line("The original external file will NOT be deleted:");
                r.Line("  " + entry->originalSourcePath);
            }
            return r;
        }

        auto deleted = pm.DeleteProject(targetId);
        if (!deleted.Ok()) {
            return CommandResult::Failure("delete_failed",
                                          "Could not delete project '" + idOrName + "'.",
                                          deleted.Error());
        }

        TargetBinding::Instance().Invalidate();

        CommandResult r = CommandResult::Success(
            "Deleted project '" + entry->displayName + "' (" + FormatBytes(deleted.Value()) + " freed).");
        if (!entry->originalSourcePath.empty()) {
            std::error_code ec;
            if (fs::exists(entry->originalSourcePath, ec)) {
                r.Line("The original file is untouched: " + entry->originalSourcePath);
            }
        }
        return r;
    }

    // --- TargetService --------------------------------------------------------

    TargetService& TargetService::Instance() {
        static TargetService instance;
        return instance;
    }

    CommandResult TargetService::Info() const {
        auto project = ProjectManager::Instance().Active();
        if (!project) return CommandResult::Failure(NoActiveProjectError());

        TargetSummary t = project->SummarizeTarget();
        CommandResult r = CommandResult::Success("Target " + t.name);
        r.Line("Kind:         " + t.kindLabel);
        r.Line("Architecture: " + t.architecture);

        // A process target shows a PID line and a separate backing-image line.
        // These are never collapsed into one "path" field.
        if (t.isLiveProcess) {
            r.Line("PID:          " + std::to_string(t.pid));
            r.Line("Backing:      " + (t.backingExecutable.empty() ? std::string("<unresolved>")
                                                                   : t.backingExecutable));
        }
        if (!t.projectCopyPath.empty())    r.Line("Project copy: " + t.projectCopyPath);
        if (!t.originalSourcePath.empty()) r.Line("Original:     " + t.originalSourcePath);
        if (t.sizeBytes > 0)               r.Line("Size:         " + FormatBytes(t.sizeBytes));
        if (!t.sha256.empty())             r.Line("SHA-256:      " + t.sha256);

        auto caps = TargetBinding::DeriveCapabilities(*project);
        r.Line("Capabilities: " + caps.Summary());
        return r;
    }

    CommandResult TargetService::Capabilities() const {
        auto project = ProjectManager::Instance().Active();
        if (!project) return CommandResult::Failure(NoActiveProjectError());

        auto caps = TargetBinding::DeriveCapabilities(*project);

        struct Row { const char* label; bool value; };
        const Row rows[] = {
            {"Static analysis",    caps.staticAnalysis},
            {"Module enumeration", caps.modules},
            {"Thread visibility",  caps.threads},
            {"Memory read",        caps.memoryRead},
            {"Memory snapshots",   caps.memorySnapshots},
            {"Runtime events",     caps.runtimeEvents},
            {"Function graph",     caps.functions},
            {"Symbols & PDB",      caps.symbols},
            {"Managed .NET meta",  caps.managedMetadata},
            {"Debug control",      caps.debugControl},
            {"Sandbox execution",  caps.sandboxExecution},
            {"Kernel observation", caps.kernelObservation},
        };

        CommandResult r = CommandResult::Success("Target capabilities");
        for (const auto& row : rows) {
            std::ostringstream line;
            line << std::left << std::setw(20) << row.label << (row.value ? "yes" : "no");
            r.Line(line.str());
        }
        return r;
    }

} // namespace App
} // namespace Dracula
