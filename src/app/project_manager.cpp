#include "app/project_manager.h"
#include "common/paths.h"
#include "core/pe_inspector.h"
#include "host/process_inspector.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace fs = std::filesystem;

namespace Dracula {
namespace App {

    using UTR::Result;

    // --- Helpers --------------------------------------------------------------

    // A filesystem-safe slug derived from a display name, so project
    // directories stay human-recognizable ("windowscodecs_3f2a1c88").
    static std::string Slugify(const std::string& name) {
        std::string out;
        for (unsigned char c : name) {
            if (std::isalnum(c)) {
                out += static_cast<char>(std::tolower(c));
            } else if (c == '.' || c == '-' || c == '_' || c == ' ') {
                if (!out.empty() && out.back() != '_') out += '_';
            }
        }
        while (!out.empty() && out.back() == '_') out.pop_back();
        if (out.empty()) out = "target";
        if (out.size() > 40) out.resize(40);
        return out;
    }

    static std::string ReadFileBytes(const std::string& path, std::vector<uint8_t>& data) {
        std::ifstream in(path, std::ios::binary);
        if (!in.is_open()) return "could not open " + path;
        in.seekg(0, std::ios::end);
        std::streamoff size = in.tellg();
        if (size < 0) return "could not size " + path;
        in.seekg(0, std::ios::beg);
        data.resize(static_cast<size_t>(size));
        if (size > 0) in.read(reinterpret_cast<char*>(data.data()), size);
        if (!in.good() && !in.eof()) return "read failed for " + path;
        return "";
    }

    static std::string HashFile(const std::string& path, uint64_t& sizeOut) {
        std::vector<uint8_t> data;
        if (!ReadFileBytes(path, data).empty()) return "";
        sizeOut = data.size();
        return PeInspector::ComputeSha256(data.data(), data.size());
    }

    // --- ProjectIndexEntry ----------------------------------------------------

    Json ProjectIndexEntry::ToJson() const {
        Json j = Json::Object();
        j.Set("id", Json(id));
        j.Set("display_name", Json(displayName));
        j.Set("directory", Json(directory));
        j.Set("sha256", Json(sha256));
        j.Set("original_source_path", Json(originalSourcePath));
        j.Set("kind", Json(std::string(UTR::TargetKindToString(kind))));
        j.Set("architecture", Json(architecture));
        j.Set("created_at", Json(createdAt));
        j.Set("last_opened_at", Json(lastOpenedAt));
        j.Set("pid", Json(pid));
        j.Set("state", Json(state));
        return j;
    }

    ProjectIndexEntry ProjectIndexEntry::FromJson(const Json& j) {
        ProjectIndexEntry e;
        e.id = j["id"].AsString();
        e.displayName = j["display_name"].AsString();
        e.directory = j["directory"].AsString();
        e.sha256 = j["sha256"].AsString();
        e.originalSourcePath = j["original_source_path"].AsString();
        e.kind = UTR::StringToTargetKind(j["kind"].AsString());
        e.architecture = j["architecture"].AsString();
        e.createdAt = j["created_at"].AsString();
        e.lastOpenedAt = j["last_opened_at"].AsString();
        e.pid = j["pid"].AsUInt32();
        e.state = j["state"].AsString("Ready");
        return e;
    }

    // --- ProjectManager: index ------------------------------------------------

    ProjectManager& ProjectManager::Instance() {
        static ProjectManager instance;
        return instance;
    }

    std::string ProjectManager::IndexPath() const {
        return (fs::path(Paths::ConfigDir()) / "projects.json").string();
    }

    bool ProjectManager::LoadIndex(std::string& error) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_index.clear();
        m_indexLoaded = true;

        const std::string path = IndexPath();
        std::error_code ec;
        if (!fs::exists(path, ec)) return true;  // first run: an empty index is valid

        std::ifstream in(path, std::ios::binary);
        if (!in.is_open()) {
            error = "could not open project index: " + path;
            return false;
        }
        std::stringstream ss;
        ss << in.rdbuf();

        Json j;
        std::string parseError;
        if (!Json::Parse(ss.str(), j, &parseError)) {
            error = "project index corrupted: " + parseError;
            return false;
        }

        for (const auto& item : j["projects"].Items()) {
            ProjectIndexEntry e = ProjectIndexEntry::FromJson(item);
            // Drop entries whose directory has been removed behind Dracula's
            // back, so a stale index never advertises a missing project.
            if (e.id.empty()) continue;
            if (!e.directory.empty() && !fs::exists(e.directory, ec)) continue;
            m_index.push_back(e);
        }
        return true;
    }

    bool ProjectManager::SaveIndex(std::string& error) const {
        // Callers must not already hold m_mutex; every call site releases it
        // before committing the index to disk.
        std::lock_guard<std::mutex> lock(m_mutex);

        Json list = Json::Array();
        for (const auto& e : m_index) list.Push(e.ToJson());

        Json root = Json::Object();
        root.Set("schema_version", Json(1));
        root.Set("projects", list);

        const std::string text = root.Dump(2);
        const fs::path target = IndexPath();
        const fs::path tmp = fs::path(target.string() + ".tmp");

        try {
            fs::create_directories(target.parent_path());
            {
                std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
                if (!out.is_open()) {
                    error = "could not write project index";
                    return false;
                }
                out.write(text.data(), static_cast<std::streamsize>(text.size()));
                out.flush();
                if (!out.good()) {
                    error = "project index write failed";
                    return false;
                }
            }
            std::error_code ec;
            fs::remove(target, ec);
            fs::rename(tmp, target, ec);
            if (ec) {
                error = "could not commit project index: " + ec.message();
                return false;
            }
            return true;
        } catch (const std::exception& e) {
            error = std::string("saving project index failed: ") + e.what();
            return false;
        }
    }

    void ProjectManager::EnsureIndexLoaded() const {
        if (m_indexLoaded) return;
        // LoadIndex takes the lock itself, so this must run before any caller
        // acquires it.
        std::string error;
        const_cast<ProjectManager*>(this)->LoadIndex(error);
    }

    std::vector<ProjectIndexEntry> ProjectManager::ListProjects() const {
        EnsureIndexLoaded();
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<ProjectIndexEntry> copy = m_index;
        // Most recently used first -- that is the order both /project list and
        // a future "Recent Projects" picker want.
        std::sort(copy.begin(), copy.end(),
                  [](const ProjectIndexEntry& a, const ProjectIndexEntry& b) {
                      return a.lastOpenedAt > b.lastOpenedAt;
                  });
        return copy;
    }

    std::vector<ProjectIndexEntry> ProjectManager::FindBySha256(const std::string& sha256) const {
        EnsureIndexLoaded();
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<ProjectIndexEntry> hits;
        if (sha256.empty()) return hits;
        for (const auto& e : m_index) {
            if (!e.sha256.empty() && e.sha256 == sha256) hits.push_back(e);
        }
        return hits;
    }

    std::optional<ProjectIndexEntry> ProjectManager::Resolve(const std::string& idOrName) const {
        EnsureIndexLoaded();
        std::lock_guard<std::mutex> lock(m_mutex);
        if (idOrName.empty()) return std::nullopt;

        for (const auto& e : m_index) {
            if (e.id == idOrName) return e;
        }
        for (const auto& e : m_index) {
            if (e.displayName == idOrName) return e;
        }

        // Unique ID prefix, e.g. "7f31" for "7f31a9c4...". Ambiguous prefixes
        // resolve to nothing rather than to an arbitrary project.
        const ProjectIndexEntry* match = nullptr;
        for (const auto& e : m_index) {
            if (e.id.rfind(idOrName, 0) == 0) {
                if (match) return std::nullopt;
                match = &e;
            }
        }
        if (match) return *match;
        return std::nullopt;
    }

    void ProjectManager::UpsertIndexEntry(const Project& project) {
        ProjectIndexEntry e;
        e.id = project.Id();
        e.displayName = project.DisplayName();
        e.directory = project.Root();
        e.sha256 = project.Target().sha256;
        e.originalSourcePath = project.Target().originalSourcePath;
        e.kind = project.Target().kind;
        e.architecture = project.Target().architecture;
        e.createdAt = project.CreatedAt();
        e.lastOpenedAt = project.LastOpenedAt();
        e.pid = project.Target().pid;

        for (auto& existing : m_index) {
            if (existing.id == e.id) { existing = e; return; }
        }
        m_index.push_back(e);
    }

    std::string ProjectManager::AllocateProjectDirectory(const std::string& displayName,
                                                         const std::string& stableId) const {
        const std::string slug = Slugify(displayName);
        // The short hash suffix keeps same-named samples in distinct
        // directories (section 49: filenames alone are not identity).
        const std::string suffix = stableId.substr(0, 8);
        return (fs::path(Paths::ProjectsDir()) / (slug + "_" + suffix)).string();
    }

    // --- ProjectManager: creation ---------------------------------------------

    UTR::Result<OpenOutcome> ProjectManager::CreateFromFile(const std::string& filePath, bool forceNew) {
        std::error_code ec;
        std::string resolved = Paths::ResolveResource(filePath);
        if (resolved.empty() || !fs::exists(resolved, ec)) resolved = filePath;

        if (!fs::exists(resolved, ec)) {
            return Result<OpenOutcome>::Fail("file does not exist: " + filePath);
        }
        if (!fs::is_regular_file(resolved, ec)) {
            return Result<OpenOutcome>::Fail("not a regular file: " + resolved);
        }

        uint64_t size = 0;
        const std::string sha256 = HashFile(resolved, size);
        if (sha256.empty()) {
            return Result<OpenOutcome>::Fail("could not read target for hashing: " + resolved);
        }

        if (!m_indexLoaded) { std::string e; LoadIndex(e); }

        OpenOutcome outcome;
        outcome.candidates = FindBySha256(sha256);
        outcome.existingProjectFound = !outcome.candidates.empty();

        // Existing-project detection is by content hash, never filename (section 6).
        if (outcome.existingProjectFound && !forceNew) {
            auto opened = OpenById(outcome.candidates.front().id);
            if (opened.Ok()) {
                outcome.project = opened.Value();
                outcome.reusedExisting = true;
                return Result<OpenOutcome>::Success(outcome);
            }
            // Fall through and create a fresh project if the indexed one is
            // unreadable; the stale entry is reported through the new project.
        }

        const std::string displayName = fs::path(resolved).stem().string();
        const std::string projectId = sha256;  // content hash is the stable ID
        std::string root = AllocateProjectDirectory(displayName, projectId);

        // A forced new project needs its own directory even for the same hash.
        if (fs::exists(root, ec)) {
            for (int n = 2; n < 1000; ++n) {
                std::string candidate = root + "_" + std::to_string(n);
                if (!fs::exists(candidate, ec)) { root = candidate; break; }
            }
        }

        auto project = std::make_shared<Project>();
        // When forcing a new project for an already-known sample the ID must
        // stay unique, so the directory name disambiguates it.
        std::string uniqueId = projectId;
        if (forceNew && outcome.existingProjectFound) {
            uniqueId = projectId.substr(0, 56) + Slugify(fs::path(root).filename().string()).substr(0, 8);
        }
        project->InitializeNew(uniqueId, displayName, root);

        std::string error;
        if (!project->EnsureLayout(error)) {
            return Result<OpenOutcome>::Fail(error);
        }

        // Copy the sample into the project. The user's original is only read.
        const std::string fileName = fs::path(resolved).filename().string();
        const fs::path copyTarget = fs::path(project->OriginalDir()) / fileName;
        fs::copy_file(resolved, copyTarget, fs::copy_options::overwrite_existing, ec);
        if (ec) {
            return Result<OpenOutcome>::Fail("could not copy sample into project: " + ec.message());
        }

        TargetIdentity& t = project->Target();
        t.name = fileName;
        t.originalSourcePath = fs::absolute(resolved, ec).string();
        t.projectCopyRelative = (fs::path("original") / fileName).generic_string();
        t.sha256 = sha256;
        t.sizeBytes = size;

        // Classify the sample. PE metadata drives kind/architecture; a file we
        // cannot parse stays Unknown rather than being guessed at.
        PeInspector inspector;
        std::string peError;
        if (inspector.LoadFromFile(copyTarget.string(), peError)) {
            auto meta = inspector.GetMetadata();
            auto mitigations = inspector.GetMitigations();
            t.architecture = meta.architecture;
            t.is64Bit = meta.is64Bit;
            t.isDotNet = mitigations.isDotNet;
            t.imageBase = meta.imageBase;
            t.entryPointRva = meta.entryPointRva;

            std::string ext = fs::path(fileName).extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (mitigations.isDotNet) {
                t.kind = meta.isDll ? UTR::TargetKind::ManagedDll : UTR::TargetKind::ManagedExe;
            } else if (ext == ".sys") {
                t.kind = UTR::TargetKind::Driver;
            } else if (meta.isDll || ext == ".dll") {
                t.kind = UTR::TargetKind::NativeDll;
            } else {
                t.kind = UTR::TargetKind::NativeExe;
            }
        }

        if (!project->Save(error)) {
            return Result<OpenOutcome>::Fail(error);
        }

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            UpsertIndexEntry(*project);
        }
        std::string indexError;
        SaveIndex(indexError);

        SetActive(project);
        outcome.project = project;
        return Result<OpenOutcome>::Success(outcome);
    }

    UTR::Result<OpenOutcome> ProjectManager::CreateFromProcess(uint32_t pid, bool forceNew) {
        if (pid == 0) {
            return Result<OpenOutcome>::Fail("invalid PID: 0");
        }

        // Resolve the backing image BEFORE creating anything, so a project is
        // only created for a process Dracula can actually inspect.
        std::string openError;
        void* handle = Sandbox::ProcessInspector::OpenReadOnly(pid, openError);
        if (!handle) {
            return Result<OpenOutcome>::Fail(
                "could not open process " + std::to_string(pid) + ": " +
                (openError.empty() ? "access denied or no such process" : openError));
        }

        std::string moduleError;
        auto mainModule = Sandbox::ProcessInspector::ResolveMainModule(handle, pid, moduleError);
        std::string backingPath = mainModule ? mainModule->modulePath : "";
        Sandbox::ProcessInspector::Close(handle);

        if (!m_indexLoaded) { std::string e; LoadIndex(e); }

        std::error_code ec;
        uint64_t size = 0;
        std::string sha256;
        if (!backingPath.empty() && fs::exists(backingPath, ec)) {
            sha256 = HashFile(backingPath, size);
        }

        OpenOutcome outcome;
        if (!sha256.empty()) {
            outcome.candidates = FindBySha256(sha256);
            outcome.existingProjectFound = !outcome.candidates.empty();
        }

        // Reopening the same executable reuses its project and simply rebinds
        // the live PID, instead of creating a duplicate workspace per launch.
        if (outcome.existingProjectFound && !forceNew) {
            auto opened = OpenById(outcome.candidates.front().id);
            if (opened.Ok()) {
                auto project = opened.Value();
                TargetIdentity& t = project->Target();
                t.kind = UTR::TargetKind::RunningProcess;
                t.pid = pid;
                t.backingExecutable = backingPath;

                std::string error;
                project->Save(error);
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    UpsertIndexEntry(*project);
                }
                std::string indexError;
                SaveIndex(indexError);

                outcome.project = project;
                outcome.reusedExisting = true;
                return Result<OpenOutcome>::Success(outcome);
            }
        }

        const std::string exeName = backingPath.empty()
            ? ("pid_" + std::to_string(pid))
            : fs::path(backingPath).filename().string();
        const std::string displayName = backingPath.empty()
            ? exeName
            : fs::path(backingPath).stem().string();

        // With no readable backing image the PID itself provides identity --
        // but it is stored as a PID, never as a path.
        const std::string projectId = !sha256.empty()
            ? sha256
            : ("pid" + std::to_string(pid) + "_" + Slugify(NowIso8601()));

        std::string root = AllocateProjectDirectory(displayName, projectId);
        if (fs::exists(root, ec)) {
            for (int n = 2; n < 1000; ++n) {
                std::string candidate = root + "_" + std::to_string(n);
                if (!fs::exists(candidate, ec)) { root = candidate; break; }
            }
        }

        auto project = std::make_shared<Project>();
        project->InitializeNew(projectId, displayName, root);

        std::string error;
        if (!project->EnsureLayout(error)) {
            return Result<OpenOutcome>::Fail(error);
        }

        TargetIdentity& t = project->Target();
        t.kind = UTR::TargetKind::RunningProcess;
        t.name = exeName;
        t.pid = pid;
        t.backingExecutable = backingPath;
        t.sha256 = sha256;
        t.sizeBytes = size;

        // Copy the backing executable in so static analysis keeps working after
        // the process exits (section 11).
        if (!backingPath.empty() && fs::exists(backingPath, ec)) {
            const fs::path copyTarget = fs::path(project->OriginalDir()) / exeName;
            std::error_code copyEc;
            fs::copy_file(backingPath, copyTarget, fs::copy_options::overwrite_existing, copyEc);
            if (!copyEc) {
                t.originalSourcePath = backingPath;
                t.projectCopyRelative = (fs::path("original") / exeName).generic_string();

                PeInspector inspector;
                std::string peError;
                if (inspector.LoadFromFile(copyTarget.string(), peError)) {
                    auto meta = inspector.GetMetadata();
                    auto mitigations = inspector.GetMitigations();
                    t.architecture = meta.architecture;
                    t.is64Bit = meta.is64Bit;
                    t.isDotNet = mitigations.isDotNet;
                    t.imageBase = meta.imageBase;
                    t.entryPointRva = meta.entryPointRva;
                }
            }
        }

        if (!project->Save(error)) {
            return Result<OpenOutcome>::Fail(error);
        }

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            UpsertIndexEntry(*project);
        }
        std::string indexError;
        SaveIndex(indexError);

        SetActive(project);
        outcome.project = project;
        return Result<OpenOutcome>::Success(outcome);
    }

    // --- ProjectManager: open / close -----------------------------------------

    UTR::Result<std::shared_ptr<Project>> ProjectManager::OpenById(const std::string& idOrName) {
        if (!m_indexLoaded) { std::string e; LoadIndex(e); }

        auto entry = Resolve(idOrName);
        if (!entry) {
            return Result<std::shared_ptr<Project>>::Fail(
                "no project matches '" + idOrName + "'");
        }

        auto project = std::make_shared<Project>();
        std::string error;
        if (!Project::Load(entry->directory, *project, error)) {
            return Result<std::shared_ptr<Project>>::Fail(
                "could not open project '" + entry->displayName + "': " + error);
        }

        std::string layoutError;
        project->EnsureLayout(layoutError);
        project->TouchLastOpened();

        std::string saveError;
        project->Save(saveError);
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            UpsertIndexEntry(*project);
        }
        std::string indexError;
        SaveIndex(indexError);

        SetActive(project);
        return Result<std::shared_ptr<Project>>::Success(project);
    }

    void ProjectManager::CloseActive() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_active.reset();
    }

    std::shared_ptr<Project> ProjectManager::Active() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_active;
    }

    bool ProjectManager::HasActive() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return static_cast<bool>(m_active);
    }

    void ProjectManager::SetActive(std::shared_ptr<Project> project) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_active = std::move(project);
    }

    // --- ProjectManager: deletion ---------------------------------------------

    UTR::Result<uint64_t> ProjectManager::DeleteProject(const std::string& idOrName) {
        if (!m_indexLoaded) { std::string e; LoadIndex(e); }

        auto entry = Resolve(idOrName);
        if (!entry) {
            return Result<uint64_t>::Fail("no project matches '" + idOrName + "'");
        }

        // Refuse to delete anything that is not actually a project directory --
        // a corrupted index must never turn into an arbitrary recursive delete.
        std::error_code ec;
        const fs::path dir = entry->directory;
        const fs::path projectsRoot = fs::path(Paths::ProjectsDir());
        const fs::path canonicalDir = fs::weakly_canonical(dir, ec);
        const fs::path canonicalRoot = fs::weakly_canonical(projectsRoot, ec);

        const std::string dirStr = canonicalDir.string();
        const std::string rootStr = canonicalRoot.string();
        if (dirStr.empty() || rootStr.empty() || dirStr.rfind(rootStr, 0) != 0 || dirStr == rootStr) {
            return Result<uint64_t>::Fail(
                "refusing to delete '" + dir.string() + "': not inside the Dracula projects directory");
        }

        // Release the active project first so no handle keeps the tree open.
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_active && m_active->Id() == entry->id) m_active.reset();
        }

        uint64_t freed = 0;
        if (fs::exists(dir, ec)) {
            auto project = std::make_shared<Project>();
            std::string loadError;
            if (Project::Load(dir.string(), *project, loadError)) {
                freed = project->ComputeStorage().totalBytes;
            }
            fs::remove_all(dir, ec);
            if (ec) {
                return Result<uint64_t>::Fail("could not remove project directory: " + ec.message());
            }
        }

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_index.erase(std::remove_if(m_index.begin(), m_index.end(),
                                         [&](const ProjectIndexEntry& e) { return e.id == entry->id; }),
                          m_index.end());
        }
        std::string indexError;
        if (!SaveIndex(indexError)) {
            return Result<uint64_t>::Fail("project removed but index update failed: " + indexError);
        }

        return Result<uint64_t>::Success(freed);
    }

} // namespace App
} // namespace Dracula
