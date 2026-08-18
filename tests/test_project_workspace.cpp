//
// Project workspace regression suite (v1.3.0 milestone, sections 1/5/6/7/16/41).
//
// These tests pin down the behaviours that manual testing found broken:
//   * a PID is never stored in, or interpreted as, a path
//   * projects survive process exit and reload exactly
//   * the same sample is detected by SHA-256, not by filename
//   * snapshot IDs increment and persist instead of resetting to #1
//   * deleting a project removes Dracula's workspace but NOT the user's file
//
// Everything runs against a temporary install root, so a developer's real
// projects are never touched.
//

#include "app/project.h"
#include "app/project_manager.h"
#include "app/json.h"
#include "common/paths.h"

#include <iostream>
#include <fstream>
#include <filesystem>
#include <cassert>
#include <cstdlib>

namespace fs = std::filesystem;
using namespace Dracula;
using namespace Dracula::App;

static int g_checks = 0;

static void Check(bool condition, const std::string& what) {
    ++g_checks;
    if (!condition) {
        std::cerr << "  FAILED: " << what << "\n";
        std::exit(1);
    }
    std::cout << "  ok: " << what << "\n";
}

// Writes a small benign PE-shaped fixture. It does not need to be a valid PE:
// the project layer must handle unparseable files without failing.
static std::string WriteFixture(const fs::path& dir, const std::string& name,
                                const std::string& body) {
    fs::create_directories(dir);
    fs::path p = dir / name;
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out << "MZ" << body;
    out.close();
    return p.string();
}

int main() {
    std::cout << "[Test] Running Project Workspace Suite...\n";

    // --- Isolated install root ---------------------------------------------
    fs::path sandbox = fs::temp_directory_path() / "dracula_project_test";
    std::error_code ec;
    fs::remove_all(sandbox, ec);
    fs::create_directories(sandbox);

    Paths::SetInstallRoot((sandbox / "root").string());
    Check(fs::exists(Paths::ProjectsDir()), "projects directory is created under the install root");
    Check(fs::exists(Paths::BrainDir()), "reserved 'brain' directory exists (section 3)");

    fs::path samples = sandbox / "samples";
    const std::string sampleA = WriteFixture(samples, "test.exe", "sample-A-contents");
    const std::string sampleB = WriteFixture(samples, "other.exe", "sample-B-contents");

    ProjectManager& pm = ProjectManager::Instance();
    std::string err;
    Check(pm.LoadIndex(err), "empty project index loads cleanly on first run");

    // --- Project creation from a file --------------------------------------
    auto createdA = pm.CreateFromFile(sampleA);
    Check(createdA.Ok(), std::string("project created from file") +
                         (createdA.Ok() ? "" : (": " + createdA.Error())));
    auto projectA = createdA.Value().project;
    Check(projectA != nullptr, "created project is non-null");
    Check(!createdA.Value().existingProjectFound, "no pre-existing project detected for a fresh sample");

    const std::string projectARoot = projectA->Root();
    const std::string projectAId = projectA->Id();

    Check(fs::exists(fs::path(projectARoot) / "project.json"), "project.json written");
    Check(fs::exists(fs::path(projectARoot) / "original" / "test.exe"),
          "original sample copied into <project>/original");
    Check(fs::exists(fs::path(projectARoot) / "memory" / "snapshots"),
          "full project directory layout created");

    // The user's file must be untouched by project creation.
    Check(fs::exists(sampleA), "user's original file still exists after project creation");
    {
        std::ifstream in(sampleA, std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        Check(content == "MZsample-A-contents", "user's original file is byte-identical (not modified)");
    }

    Check(!projectA->Target().sha256.empty(), "sample SHA-256 recorded");
    Check(projectA->Target().originalSourcePath == fs::absolute(sampleA, ec).string(),
          "original source path recorded");
    Check(projectA->StaticAnalysisPath() == (fs::path(projectARoot) / "original" / "test.exe").string(),
          "static analysis resolves to the project's immutable copy");

    // --- Existing-project detection by hash, not filename -------------------
    // Same bytes under a different name must resolve to the SAME project.
    const std::string renamed = WriteFixture(samples / "renamed", "totally_different_name.exe",
                                             "sample-A-contents");
    auto reopened = pm.CreateFromFile(renamed);
    Check(reopened.Ok(), "reopening identical content succeeds");
    Check(reopened.Value().existingProjectFound,
          "existing project detected by SHA-256 despite a different filename (section 6)");
    Check(reopened.Value().reusedExisting, "existing project was continued, not duplicated");
    Check(reopened.Value().project->Id() == projectAId, "continued project has the same ID");

    // A different sample must NOT collide with it.
    auto createdB = pm.CreateFromFile(sampleB);
    Check(createdB.Ok(), "second, distinct project created");
    Check(!createdB.Value().existingProjectFound, "distinct content does not match an existing project");
    Check(createdB.Value().project->Id() != projectAId, "distinct sample gets a distinct project ID");

    Check(pm.ListProjects().size() == 2, "index lists exactly two projects");

    // --- Snapshot identity (section 16) -------------------------------------
    // The observed bug was every capture reporting "#1". IDs must increment.
    uint32_t id1 = projectA->AllocateSnapshotId();
    uint32_t id2 = projectA->AllocateSnapshotId();
    Check(id1 == 1 && id2 == 2, "snapshot IDs increment (#1 then #2), they do not repeat");

    SnapshotRecord s1;
    s1.id = id1;
    s1.label = "before";
    s1.capturedAt = NowIso8601();
    s1.regionCount = 1732;
    s1.committedBytes = 614912ull * 1024;
    projectA->AddSnapshot(s1);

    SnapshotRecord s2;
    s2.id = id2;
    s2.label = "after";
    s2.capturedAt = NowIso8601();
    s2.regionCount = 1749;
    s2.committedBytes = 620000ull * 1024;
    projectA->AddSnapshot(s2);

    Check(projectA->Save(err), "project with snapshots saves");

    // --- Persistence across "restart" ---------------------------------------
    // Simulate a full Dracula exit and relaunch: drop all in-memory state and
    // reload from disk only.
    pm.CloseActive();
    Check(pm.LoadIndex(err), "index reloads after restart");
    Check(pm.ListProjects().size() == 2, "both projects survive restart");

    auto restored = pm.OpenById(projectAId);
    Check(restored.Ok(), std::string("project reopens by ID") +
                         (restored.Ok() ? "" : (": " + restored.Error())));
    auto reloadedA = restored.Value();

    Check(reloadedA->Target().sha256 == projectA->Target().sha256, "target hash persisted");
    Check(reloadedA->Snapshots().size() == 2, "both snapshots persisted");
    Check(reloadedA->Snapshots()[0].label == "before", "snapshot labels persisted");
    Check(reloadedA->Snapshots()[1].regionCount == 1749, "snapshot region counts persisted");

    // The counter must continue past the persisted maximum, never restart at 1.
    uint32_t id3 = reloadedA->AllocateSnapshotId();
    Check(id3 == 3, "snapshot counter continues across restart (#3, not #1)");

    // Named lookup, as used by "/memory compare before after".
    const SnapshotRecord* byLabel = reloadedA->FindSnapshot("before");
    const SnapshotRecord* byId = reloadedA->FindSnapshot("2");
    Check(byLabel != nullptr && byLabel->id == 1, "snapshot resolvable by label");
    Check(byId != nullptr && byId->label == "after", "snapshot resolvable by numeric ID");
    Check(reloadedA->FindSnapshot("nonexistent") == nullptr, "unknown snapshot resolves to null");

    // --- Short-ID and name resolution (section 49) --------------------------
    Check(pm.Resolve(projectAId.substr(0, 8)).has_value(), "project resolves by unique short ID");
    Check(pm.Resolve("test").has_value(), "project resolves by display name");
    Check(!pm.Resolve("no-such-project").has_value(), "unknown identifier resolves to nothing");

    // --- PID is a PID, never a path (sections 11, 41) -----------------------
    // The architectural bug was `Path = "--pid 17140"`. A process-backed target
    // stores the number in `pid` and leaves path fields free of it.
    {
        Project processProject;
        processProject.InitializeNew("pidtest", "notepad", (sandbox / "root" / "projects" / "pidtest").string());
        Check(processProject.EnsureLayout(err), "process project layout created");

        TargetIdentity& t = processProject.Target();
        t.kind = UTR::TargetKind::RunningProcess;
        t.name = "notepad.exe";
        t.pid = 17140;
        t.backingExecutable = "C:\\Windows\\System32\\notepad.exe";

        Check(t.IsLiveProcess(), "process target reports as a live process");
        Check(t.pid == 17140, "PID stored as a numeric PID");
        Check(t.originalSourcePath.find("--pid") == std::string::npos,
              "originalSourcePath never contains '--pid'");
        Check(t.projectCopyRelative.find("--pid") == std::string::npos,
              "projectCopyRelative never contains '--pid'");
        Check(t.backingExecutable.find("--pid") == std::string::npos,
              "backingExecutable never contains '--pid'");

        // Static analysis on a PID-backed project resolves the backing image.
        Check(processProject.StaticAnalysisPath().find("--pid") == std::string::npos,
              "static analysis path never contains '--pid' (regression: 'file does not exist: --pid 17140')");

        // Round-trip must preserve the distinction.
        Check(processProject.Save(err), "process project saves");
        Project roundTripped;
        Check(Project::Load(processProject.Root(), roundTripped, err), "process project reloads");
        Check(roundTripped.Target().pid == 17140, "PID survives round-trip as a number");
        Check(roundTripped.Target().kind == UTR::TargetKind::RunningProcess,
              "RunningProcess kind survives round-trip");
        Check(roundTripped.Target().backingExecutable == "C:\\Windows\\System32\\notepad.exe",
              "backing executable survives round-trip");
    }

    // --- Storage accounting (section 8) -------------------------------------
    {
        StorageReport report = reloadedA->ComputeStorage();
        Check(!report.entries.empty(), "storage report has categories");
        Check(report.totalBytes > 0, "storage report totals real bytes");

        bool sawOriginal = false, sawOverlays = false;
        for (const auto& e : report.entries) {
            if (e.category == "Original sample") { sawOriginal = true; Check(e.bytes > 0, "original sample size is measured"); }
            if (e.category == "VM overlays") { sawOverlays = true; Check(e.disposable, "VM overlays are marked disposable"); }
        }
        Check(sawOriginal && sawOverlays, "storage report covers original sample and overlays");
    }

    // --- Cleanup keeps the sample, drops disposables (section 7) ------------
    {
        // Plant a fake overlay and a cache file, plus a report that must survive.
        std::ofstream(fs::path(reloadedA->OverlaysDir()) / "run_0001.qcow2", std::ios::binary)
            << std::string(4096, 'x');
        std::ofstream(fs::path(reloadedA->CacheDir()) / "scratch.bin", std::ios::binary)
            << std::string(2048, 'y');
        std::ofstream(fs::path(reloadedA->ReportsDir()) / "keep_me.html", std::ios::binary)
            << "<html>report</html>";

        std::vector<std::string> removed;
        uint64_t reclaimed = reloadedA->Cleanup(removed);
        Check(reclaimed >= 6144, "cleanup reclaims the disposable bytes");
        Check(!fs::exists(fs::path(reloadedA->OverlaysDir()) / "run_0001.qcow2"), "overlay removed by cleanup");
        Check(!fs::exists(fs::path(reloadedA->CacheDir()) / "scratch.bin"), "cache scratch removed by cleanup");
        Check(fs::exists(fs::path(reloadedA->ReportsDir()) / "keep_me.html"), "reports survive cleanup");
        Check(fs::exists(reloadedA->OriginalSamplePath()), "original sample survives cleanup");
        Check(fs::exists(fs::path(reloadedA->Root()) / "project.json"), "project metadata survives cleanup");
    }

    // --- Corruption recovery (section 44) -----------------------------------
    {
        // A torn write leaves project.json unreadable; the .bak copy recovers it.
        fs::path meta = fs::path(reloadedA->Root()) / "project.json";
        Check(reloadedA->Save(err), "save creates a backup copy");
        Check(fs::exists(fs::path(reloadedA->Root()) / "project.json.bak"), "project.json.bak exists");

        std::ofstream(meta, std::ios::binary | std::ios::trunc) << "{ this is not valid json";
        Project recovered;
        std::string recoveryNote;
        bool loaded = Project::Load(reloadedA->Root(), recovered, recoveryNote);
        Check(loaded, "corrupted project.json recovers from the backup copy");
        Check(recovered.Id() == projectAId, "recovered project keeps its identity");
        Check(!recoveryNote.empty(), "recovery is reported, not silent");

        // Restore a good primary file for the deletion test below.
        Check(recovered.Save(err), "recovered project re-saves cleanly");
    }

    // --- Deletion removes the workspace only (section 7) --------------------
    {
        const std::string dirBefore = reloadedA->Root();
        Check(fs::exists(dirBefore), "project directory exists before deletion");

        auto deleted = pm.DeleteProject(projectAId);
        Check(deleted.Ok(), std::string("project deleted") +
                            (deleted.Ok() ? "" : (": " + deleted.Error())));
        Check(!fs::exists(dirBefore), "Dracula's project workspace is removed");

        // The whole point: the user's file outside Dracula is untouched.
        Check(fs::exists(sampleA), "user's ORIGINAL file outside Dracula is NOT deleted");
        Check(fs::exists(renamed), "the renamed copy outside Dracula is NOT deleted");

        Check(pm.ListProjects().size() == 1, "index updated after deletion");
        Check(!pm.Resolve(projectAId).has_value(), "deleted project no longer resolves");

        // Deletion must survive a restart, i.e. the index was really committed.
        Check(pm.LoadIndex(err), "index reloads after deletion");
        Check(pm.ListProjects().size() == 1, "deletion persisted across reload");
    }

    // --- Deletion refuses paths outside the projects root -------------------
    {
        auto missing = pm.DeleteProject("no-such-project");
        Check(!missing.Ok(), "deleting an unknown project fails with a reason");
        Check(!missing.Error().empty(), "deletion failure carries a useful reason");
    }

    // --- JSON round-trip edge cases -----------------------------------------
    {
        Json j = Json::Object();
        j.Set("path", Json(std::string("C:\\Program Files\\a\"b\\c.exe")));
        j.Set("count", Json(static_cast<uint64_t>(1749)));
        j.Set("flag", Json(true));
        j.Set("empty", Json());

        Json parsed;
        std::string parseErr;
        Check(Json::Parse(j.Dump(2), parsed, &parseErr), "JSON round-trips");
        Check(parsed["path"].AsString() == "C:\\Program Files\\a\"b\\c.exe",
              "backslashes and quotes survive JSON round-trip");
        Check(parsed["count"].AsUInt() == 1749, "integers round-trip without precision loss");
        Check(parsed["flag"].AsBool(), "booleans round-trip");
        Check(parsed["empty"].IsNull(), "nulls round-trip");
        Check(parsed["absent"].AsString("fallback") == "fallback", "missing keys yield the fallback");

        Json broken;
        Check(!Json::Parse("{\"a\": }", broken, &parseErr), "malformed JSON is rejected");
        Check(!parseErr.empty(), "JSON parse failure explains itself");
    }

    fs::remove_all(sandbox, ec);

    std::cout << "[Test] Project Workspace Suite PASSED (" << g_checks << " checks).\n";
    return 0;
}
