#include "app/project.h"
#include "common/paths.h"
#include "common/version.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <cctype>

namespace fs = std::filesystem;

namespace Dracula {
namespace App {

    // --- Small helpers --------------------------------------------------------

    std::string NowIso8601() {
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm tmv{};
#ifdef _WIN32
        localtime_s(&tmv, &t);
#else
        localtime_r(&t, &tmv);
#endif
        std::ostringstream oss;
        oss << std::put_time(&tmv, "%Y-%m-%dT%H:%M:%S");
        return oss.str();
    }

    // Recursively sums regular-file sizes. Missing directories contribute 0 so
    // storage accounting works on a partially-built project.
    static uint64_t DirectorySize(const fs::path& dir) {
        uint64_t total = 0;
        std::error_code ec;
        if (!fs::exists(dir, ec)) return 0;
        for (fs::recursive_directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end;
             it != end; it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            std::error_code fec;
            if (fs::is_regular_file(it->path(), fec)) {
                auto sz = fs::file_size(it->path(), fec);
                if (!fec) total += sz;
            }
        }
        return total;
    }

    // --- TargetIdentity -------------------------------------------------------

    Json TargetIdentity::ToJson() const {
        Json j = Json::Object();
        j.Set("kind", Json(std::string(UTR::TargetKindToString(kind))));
        j.Set("name", Json(name));
        j.Set("original_source_path", Json(originalSourcePath));
        j.Set("project_copy_relative", Json(projectCopyRelative));
        j.Set("sha256", Json(sha256));
        j.Set("size_bytes", Json(sizeBytes));
        j.Set("architecture", Json(architecture));
        j.Set("is_64bit", Json(is64Bit));
        j.Set("is_dotnet", Json(isDotNet));
        j.Set("image_base", Json(imageBase));
        j.Set("entry_point_rva", Json(entryPointRva));
        j.Set("pid", Json(pid));
        j.Set("backing_executable", Json(backingExecutable));
        j.Set("service_name", Json(serviceName));
        return j;
    }

    TargetIdentity TargetIdentity::FromJson(const Json& j) {
        TargetIdentity t;
        t.kind = UTR::StringToTargetKind(j["kind"].AsString());
        t.name = j["name"].AsString();
        t.originalSourcePath = j["original_source_path"].AsString();
        t.projectCopyRelative = j["project_copy_relative"].AsString();
        t.sha256 = j["sha256"].AsString();
        t.sizeBytes = j["size_bytes"].AsUInt();
        t.architecture = j["architecture"].AsString("x64");
        t.is64Bit = j["is_64bit"].AsBool(true);
        t.isDotNet = j["is_dotnet"].AsBool(false);
        t.imageBase = j["image_base"].AsUInt();
        t.entryPointRva = j["entry_point_rva"].AsUInt();
        t.pid = j["pid"].AsUInt32();
        t.backingExecutable = j["backing_executable"].AsString();
        t.serviceName = j["service_name"].AsString();
        return t;
    }

    // --- SnapshotRecord -------------------------------------------------------

    Json SnapshotRecord::ToJson() const {
        Json j = Json::Object();
        j.Set("id", Json(id));
        j.Set("label", Json(label));
        j.Set("captured_at", Json(capturedAt));
        j.Set("pid", Json(pid));
        j.Set("region_count", Json(regionCount));
        j.Set("committed_bytes", Json(committedBytes));
        j.Set("retained_bytes", Json(retainedBytes));
        j.Set("status", Json(status));
        j.Set("truncation_reason", Json(truncationReason));
        j.Set("identity_hash", Json(identityHash));
        j.Set("data_relative_path", Json(dataRelativePath));
        return j;
    }

    SnapshotRecord SnapshotRecord::FromJson(const Json& j) {
        SnapshotRecord s;
        s.id = j["id"].AsUInt32();
        s.label = j["label"].AsString();
        s.capturedAt = j["captured_at"].AsString();
        s.pid = j["pid"].AsUInt32();
        s.regionCount = j["region_count"].AsUInt();
        s.committedBytes = j["committed_bytes"].AsUInt();
        s.retainedBytes = j["retained_bytes"].AsUInt();
        s.status = j["status"].AsString("Complete");
        s.truncationReason = j["truncation_reason"].AsString();
        s.identityHash = j["identity_hash"].AsString();
        s.dataRelativePath = j["data_relative_path"].AsString();
        return s;
    }

    // --- ArtifactRecord -------------------------------------------------------

    Json ArtifactRecord::ToJson() const {
        Json j = Json::Object();
        j.Set("id", Json(id));
        j.Set("kind", Json(kind));
        j.Set("format", Json(format));
        j.Set("relative_path", Json(relativePath));
        j.Set("title", Json(title));
        j.Set("created_at", Json(createdAt));
        j.Set("size_bytes", Json(sizeBytes));
        j.Set("row_count", Json(rowCount));
        return j;
    }

    ArtifactRecord ArtifactRecord::FromJson(const Json& j) {
        ArtifactRecord a;
        a.id = j["id"].AsString();
        a.kind = j["kind"].AsString();
        a.format = j["format"].AsString();
        a.relativePath = j["relative_path"].AsString();
        a.title = j["title"].AsString();
        a.createdAt = j["created_at"].AsString();
        a.sizeBytes = j["size_bytes"].AsUInt();
        a.rowCount = j["row_count"].AsUInt();
        return a;
    }

    // --- Project: layout ------------------------------------------------------

    static std::string Sub(const std::string& root, const char* rel) {
        if (root.empty()) return "";
        return (fs::path(root) / rel).string();
    }

    std::string Project::OriginalDir()          const { return Sub(m_root, "original"); }
    std::string Project::StaticDir()            const { return Sub(m_root, "static"); }
    std::string Project::FunctionsDir()         const { return Sub(m_root, "functions"); }
    std::string Project::ModulesDir()           const { return Sub(m_root, "modules"); }
    std::string Project::MemoryDir()            const { return Sub(m_root, "memory"); }
    std::string Project::MemoryMapsDir()        const { return Sub(m_root, "memory/maps"); }
    std::string Project::MemorySnapshotsDir()   const { return Sub(m_root, "memory/snapshots"); }
    std::string Project::MemoryDumpsDir()       const { return Sub(m_root, "memory/dumps"); }
    std::string Project::RuntimeDir()           const { return Sub(m_root, "runtime"); }
    std::string Project::SandboxDir()           const { return Sub(m_root, "sandbox"); }
    std::string Project::ReportsDir()           const { return Sub(m_root, "reports"); }
    std::string Project::ArtifactsDir()         const { return Sub(m_root, "artifacts"); }
    std::string Project::LogsDir()              const { return Sub(m_root, "logs"); }
    std::string Project::OverlaysDir()          const { return Sub(m_root, "overlays"); }
    std::string Project::CacheDir()             const { return Sub(m_root, "cache"); }

    bool Project::EnsureLayout(std::string& error) {
        static const char* kDirs[] = {
            "original", "static", "functions", "modules",
            "memory", "memory/maps", "memory/snapshots", "memory/dumps",
            "runtime", "sandbox", "reports", "artifacts",
            "logs", "overlays", "cache"
        };
        try {
            fs::create_directories(m_root);
            for (const char* d : kDirs) {
                fs::create_directories(fs::path(m_root) / d);
            }
            return true;
        } catch (const std::exception& e) {
            error = std::string("could not create project layout: ") + e.what();
            return false;
        }
    }

    std::string Project::OriginalSamplePath() const {
        if (m_target.projectCopyRelative.empty()) return "";
        // projectCopyRelative is stored in generic form ("original/test.exe") so
        // project.json stays portable; callers always get a native path back.
        return (fs::path(m_root) / m_target.projectCopyRelative).make_preferred().string();
    }

    std::string Project::StaticAnalysisPath() const {
        // Preference order matters: the project's own immutable copy is stable
        // even if the user moves or deletes the original, so it wins.
        std::string copy = OriginalSamplePath();
        std::error_code ec;
        if (!copy.empty() && fs::exists(copy, ec)) return copy;

        if (!m_target.backingExecutable.empty() && fs::exists(m_target.backingExecutable, ec)) {
            return m_target.backingExecutable;
        }
        if (!m_target.originalSourcePath.empty() && fs::exists(m_target.originalSourcePath, ec)) {
            return m_target.originalSourcePath;
        }
        return "";
    }

    void Project::InitializeNew(const std::string& id,
                                const std::string& displayName,
                                const std::string& root) {
        m_id = id;
        m_displayName = displayName;
        m_root = root;
        m_createdAt = NowIso8601();
        m_lastOpenedAt = m_createdAt;
        m_draculaVersion = DRACULA_VERSION_STRING;
        m_nextSnapshotId = 1;
    }

    void Project::TouchLastOpened() {
        m_lastOpenedAt = NowIso8601();
    }

    // --- Project: persistence -------------------------------------------------

    bool Project::Save(std::string& error) const {
        std::lock_guard<std::mutex> lock(m_mutex);

        Json j = Json::Object();
        j.Set("schema_version", Json(1));
        j.Set("id", Json(m_id));
        j.Set("display_name", Json(m_displayName));
        j.Set("created_at", Json(m_createdAt));
        j.Set("last_opened_at", Json(m_lastOpenedAt));
        j.Set("dracula_version", Json(m_draculaVersion));
        j.Set("target", m_target.ToJson());
        j.Set("next_snapshot_id", Json(m_nextSnapshotId));

        Json snaps = Json::Array();
        for (const auto& s : m_snapshots) snaps.Push(s.ToJson());
        j.Set("snapshots", snaps);

        Json arts = Json::Array();
        for (const auto& a : m_artifacts) arts.Push(a.ToJson());
        j.Set("artifacts", arts);

        const std::string text = j.Dump(2);
        const fs::path target = fs::path(m_root) / "project.json";
        const fs::path tmp    = fs::path(m_root) / "project.json.tmp";
        const fs::path backup = fs::path(m_root) / "project.json.bak";

        try {
            fs::create_directories(m_root);

            // Atomic replace: write a temp file, flush it to disk, keep the
            // previous good copy as .bak, then rename into place. A crash at
            // any point leaves either the old or the new file intact.
            {
                std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
                if (!out.is_open()) {
                    error = "could not open " + tmp.string() + " for writing";
                    return false;
                }
                out.write(text.data(), static_cast<std::streamsize>(text.size()));
                out.flush();
                if (!out.good()) {
                    error = "write failed for " + tmp.string();
                    return false;
                }
            }

            std::error_code ec;
            if (fs::exists(target, ec)) {
                fs::remove(backup, ec);
                fs::copy_file(target, backup, fs::copy_options::overwrite_existing, ec);
            }
            fs::rename(tmp, target, ec);
            if (ec) {
                // Cross-device or locked destination: fall back to remove+rename.
                fs::remove(target, ec);
                fs::rename(tmp, target, ec);
                if (ec) {
                    error = "could not commit project.json: " + ec.message();
                    return false;
                }
            }
            return true;
        } catch (const std::exception& e) {
            error = std::string("saving project failed: ") + e.what();
            return false;
        }
    }

    bool Project::Load(const std::string& projectDir, Project& out, std::string& error) {
        const fs::path primary = fs::path(projectDir) / "project.json";
        const fs::path backup  = fs::path(projectDir) / "project.json.bak";

        // Try the primary file, then the backup, so a torn write does not cost
        // the user their project (section 44).
        for (int attempt = 0; attempt < 2; ++attempt) {
            const fs::path& src = (attempt == 0) ? primary : backup;
            std::error_code ec;
            if (!fs::exists(src, ec)) continue;

            std::ifstream in(src, std::ios::binary);
            if (!in.is_open()) continue;
            std::stringstream ss;
            ss << in.rdbuf();

            Json j;
            std::string parseError;
            if (!Json::Parse(ss.str(), j, &parseError) || !j.IsObject()) {
                error = "project metadata corrupted (" + src.filename().string() + "): " + parseError;
                continue;
            }

            out.m_root = projectDir;
            out.m_id = j["id"].AsString();
            out.m_displayName = j["display_name"].AsString();
            out.m_createdAt = j["created_at"].AsString();
            out.m_lastOpenedAt = j["last_opened_at"].AsString();
            out.m_draculaVersion = j["dracula_version"].AsString();
            out.m_target = TargetIdentity::FromJson(j["target"]);
            out.m_nextSnapshotId = j["next_snapshot_id"].AsUInt32(1);

            out.m_snapshots.clear();
            for (const auto& s : j["snapshots"].Items()) {
                out.m_snapshots.push_back(SnapshotRecord::FromJson(s));
            }
            out.m_artifacts.clear();
            for (const auto& a : j["artifacts"].Items()) {
                out.m_artifacts.push_back(ArtifactRecord::FromJson(a));
            }

            if (out.m_id.empty()) {
                error = "project metadata missing an id";
                continue;
            }

            // Repair the snapshot counter if metadata was written by an older
            // build or truncated: it must always exceed every existing ID.
            for (const auto& s : out.m_snapshots) {
                if (s.id >= out.m_nextSnapshotId) out.m_nextSnapshotId = s.id + 1;
            }

            error.clear();
            if (attempt == 1) {
                error = "recovered project metadata from backup copy";
            }
            return true;
        }

        if (error.empty()) {
            error = "no project metadata found in " + projectDir;
        }
        return false;
    }

    // --- Project: snapshots ---------------------------------------------------

    uint32_t Project::AllocateSnapshotId() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_nextSnapshotId++;
    }

    void Project::AddSnapshot(const SnapshotRecord& rec) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_snapshots.push_back(rec);
        if (rec.id >= m_nextSnapshotId) m_nextSnapshotId = rec.id + 1;
    }

    const SnapshotRecord* Project::FindSnapshot(const std::string& idOrLabel) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (idOrLabel.empty()) return nullptr;

        // Exact label match first: a user who names a snapshot "2" means that
        // label, not snapshot ID 2.
        for (const auto& s : m_snapshots) {
            if (!s.label.empty() && s.label == idOrLabel) return &s;
        }

        const bool numeric = std::all_of(idOrLabel.begin(), idOrLabel.end(),
                                         [](unsigned char c) { return std::isdigit(c) != 0; });
        if (numeric) {
            uint32_t wanted = 0;
            try { wanted = static_cast<uint32_t>(std::stoul(idOrLabel)); } catch (...) { return nullptr; }
            for (const auto& s : m_snapshots) {
                if (s.id == wanted) return &s;
            }
            return nullptr;
        }

        // Case-insensitive label fallback.
        std::string wanted = idOrLabel;
        std::transform(wanted.begin(), wanted.end(), wanted.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        for (const auto& s : m_snapshots) {
            std::string label = s.label;
            std::transform(label.begin(), label.end(), label.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (label == wanted) return &s;
        }
        return nullptr;
    }

    // --- Project: artifacts ---------------------------------------------------

    std::string Project::NextArtifactPath(const std::string& subdir,
                                          const std::string& stem,
                                          const std::string& extension) {
        std::lock_guard<std::mutex> lock(m_mutex);
        fs::path dir = fs::path(m_root) / subdir;
        std::error_code ec;
        fs::create_directories(dir, ec);

        // Scan for the highest existing index so numbering never collides even
        // if project.json was lost.
        for (uint32_t index = 1; index < 100000; ++index) {
            std::ostringstream name;
            name << stem << "_" << std::setw(4) << std::setfill('0') << index << "." << extension;
            fs::path candidate = dir / name.str();
            if (!fs::exists(candidate, ec)) return candidate.string();
        }
        return (dir / (stem + "." + extension)).string();
    }

    void Project::AddArtifact(const ArtifactRecord& rec) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_artifacts.push_back(rec);
    }

    // --- Project: summaries ---------------------------------------------------

    TargetSummary Project::SummarizeTarget() const {
        TargetSummary s;
        s.kind = m_target.kind;
        s.kindLabel = UTR::TargetKindToString(m_target.kind);
        s.name = m_target.name;
        s.architecture = m_target.architecture;
        s.sha256 = m_target.sha256;
        s.sizeBytes = m_target.sizeBytes;
        s.isLiveProcess = m_target.IsLiveProcess();
        s.pid = m_target.pid;
        s.backingExecutable = m_target.backingExecutable;
        s.originalSourcePath = m_target.originalSourcePath;
        s.projectCopyPath = OriginalSamplePath();
        s.isDotNet = m_target.isDotNet;
        return s;
    }

    ProjectSummary Project::Summarize() const {
        ProjectSummary p;
        p.id = m_id;
        p.displayName = m_displayName;
        p.directory = m_root;
        p.createdAt = m_createdAt;
        p.lastOpenedAt = m_lastOpenedAt;
        p.draculaVersion = m_draculaVersion;
        p.target = SummarizeTarget();
        p.totalBytes = DirectorySize(m_root);
        return p;
    }

    StorageReport Project::ComputeStorage() const {
        StorageReport r;
        r.projectId = m_id;
        r.projectDirectory = m_root;

        // `disposable` marks what /project cleanup is allowed to reclaim.
        struct Entry { const char* label; const char* rel; bool disposable; };
        static const Entry kEntries[] = {
            {"Original sample",  "original",          false},
            {"Static artifacts", "static",            false},
            {"Functions",        "functions",         false},
            {"Modules",          "modules",           false},
            {"Memory maps",      "memory/maps",       false},
            {"Memory snapshots", "memory/snapshots",  false},
            {"Dumps",            "memory/dumps",      true},
            {"Runtime",          "runtime",           false},
            {"Sandbox",          "sandbox",           false},
            {"Reports",          "reports",           false},
            {"Artifacts",        "artifacts",         false},
            {"Logs",             "logs",              false},
            {"VM overlays",      "overlays",          true},
            {"Cache",            "cache",             true},
        };

        for (const auto& e : kEntries) {
            StorageEntry se;
            se.category = e.label;
            se.bytes = DirectorySize(fs::path(m_root) / e.rel);
            se.disposable = e.disposable;
            r.totalBytes += se.bytes;
            if (se.disposable) r.disposableBytes += se.bytes;
            r.entries.push_back(se);
        }

        std::error_code ec;
        auto space = fs::space(m_root, ec);
        r.diskFreeBytes = ec ? 0 : static_cast<uint64_t>(space.available);
        return r;
    }

    uint64_t Project::Cleanup(std::vector<std::string>& removedDescriptions) {
        // Only disposable categories are touched. The original sample, project
        // metadata, reports, retained snapshots and logs are never removed.
        static const char* kDisposable[] = { "overlays", "cache", "memory/dumps" };

        uint64_t reclaimed = 0;
        for (const char* rel : kDisposable) {
            fs::path dir = fs::path(m_root) / rel;
            std::error_code ec;
            if (!fs::exists(dir, ec)) continue;

            uint64_t before = DirectorySize(dir);
            if (before == 0) continue;

            // Remove the directory contents, then recreate the empty directory
            // so the project layout stays intact.
            for (fs::directory_iterator it(dir, ec), end; it != end; it.increment(ec)) {
                if (ec) { ec.clear(); break; }
                std::error_code rec;
                fs::remove_all(it->path(), rec);
            }
            uint64_t after = DirectorySize(dir);
            uint64_t freed = (before > after) ? (before - after) : 0;
            if (freed > 0) {
                reclaimed += freed;
                removedDescriptions.push_back(std::string(rel) + " (" + std::to_string(freed) + " bytes)");
            }
        }
        return reclaimed;
    }

} // namespace App
} // namespace Dracula
