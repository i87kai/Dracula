#include "common/paths.h"

#include <filesystem>
#include <fstream>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <limits.h>
#endif

namespace fs = std::filesystem;

namespace Dracula {
namespace Paths {

    std::string ExecutableDir() {
        static std::string cached = []() -> std::string {
#ifdef _WIN32
            char buf[MAX_PATH * 4] = {0};
            DWORD n = GetModuleFileNameA(nullptr, buf, sizeof(buf) - 1);
            if (n == 0) return "";
            try {
                return fs::path(std::string(buf, n)).parent_path().string();
            } catch (...) {
                return "";
            }
#else
            char buf[PATH_MAX] = {0};
            ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
            if (n <= 0) return "";
            try {
                return fs::path(std::string(buf, static_cast<size_t>(n))).parent_path().string();
            } catch (...) {
                return "";
            }
#endif
        }();
        return cached;
    }

    std::string CurrentWorkingDir() {
        try {
            return fs::current_path().string();
        } catch (...) {
            return "";
        }
    }

    // Files that identify a Dracula install / project root.
    static const char* kRootMarkers[] = {"CHANGELOG.txt", "config", "rules"};

    std::string ResourceRoot() {
        static std::string cached = []() -> std::string {
            try {
                fs::path dir = ExecutableDir();
                if (dir.empty()) return "";

                // Walk up a bounded number of levels so an out-of-source build
                // directory still resolves back to the project root, without
                // ever escaping into unrelated parts of the filesystem.
                for (int depth = 0; depth < 4; ++depth) {
                    for (const char* marker : kRootMarkers) {
                        if (fs::exists(dir / marker)) {
                            return dir.string();
                        }
                    }
                    if (!dir.has_parent_path() || dir.parent_path() == dir) break;
                    dir = dir.parent_path();
                }
                return ExecutableDir();
            } catch (...) {
                return "";
            }
        }();
        return cached;
    }

    static std::string g_customDataDir = "";

    void SetCustomDataDir(const std::string& path) {
        g_customDataDir = path;
    }

    std::string AppDataDir() {
        if (!g_customDataDir.empty()) {
            try {
                fs::create_directories(g_customDataDir);
                return g_customDataDir;
            } catch (...) {}
        }
        std::string base = "";
#ifdef _WIN32
        char buf[MAX_PATH] = {0};
        DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", buf, sizeof(buf) - 1);
        if (n > 0) {
            base = (fs::path(buf) / "Dracula").string();
        } else {
            base = (fs::path(ExecutableDir()) / "data").string();
        }
#else
        const char* home = getenv("HOME");
        if (home) {
            base = (fs::path(home) / ".local" / "share" / "dracula").string();
        } else {
            base = (fs::path(ExecutableDir()) / "data").string();
        }
#endif
        try {
            fs::create_directories(base);
        } catch (...) {}
        return base;
    }

    // ─── Dracula Install Root ──────────────────────────────────────────────

    static std::string g_installRoot = "";

    void SetInstallRoot(const std::string& path) {
        g_installRoot = path;
    }

    // Reads the install marker (a single line holding the root path) that the
    // bootstrap installer drops beside the executable. Returns "" when absent
    // or unreadable, so a portable/dev tree simply falls through.
    static std::string ReadInstallMarker() {
        try {
            fs::path exeDir = ExecutableDir();
            if (exeDir.empty()) return "";
            // The marker sits either next to the exe (<root>\bin\) or one level
            // up (<root>\), covering both installed and in-place layouts.
            for (int level = 0; level < 2; ++level) {
                fs::path marker = exeDir / ".dracula_root";
                if (fs::exists(marker)) {
                    std::ifstream in(marker);
                    std::string line;
                    if (std::getline(in, line)) {
                        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' ||
                                                 line.back() == ' '  || line.back() == '\t')) {
                            line.pop_back();
                        }
                        if (!line.empty() && fs::exists(line)) return line;
                    }
                }
                if (!exeDir.has_parent_path() || exeDir.parent_path() == exeDir) break;
                exeDir = exeDir.parent_path();
            }
        } catch (...) {}
        return "";
    }

    std::string InstallRoot() {
        std::string base;

        if (!g_installRoot.empty()) {
            base = g_installRoot;
        } else {
#ifdef _WIN32
            char buf[MAX_PATH * 4] = {0};
            DWORD n = GetEnvironmentVariableA("DRACULA_ROOT", buf, sizeof(buf) - 1);
            if (n > 0 && n < sizeof(buf)) base = std::string(buf, n);
#else
            const char* env = getenv("DRACULA_ROOT");
            if (env && *env) base = env;
#endif
            if (base.empty()) base = ReadInstallMarker();
            // Portable fallback: behave exactly as pre-1.3.0 Dracula did.
            if (base.empty()) base = AppDataDir();
        }

        try { fs::create_directories(base); } catch (...) {}
        return base;
    }

    // All install subdirectories share this shape: resolve, create, return.
    static std::string InstallSubdir(const std::string& relative) {
        try {
            fs::path dir = fs::path(InstallRoot()) / relative;
            fs::create_directories(dir);
            return dir.string();
        } catch (...) {
            return InstallRoot();
        }
    }

    std::string ProjectsDir()   { return InstallSubdir("projects"); }
    std::string BrainDir()      { return InstallSubdir("brain"); }
    std::string RuntimeDir()    { return InstallSubdir("runtime"); }
    std::string ToolsDir()      { return InstallSubdir("tools"); }
    std::string BinDir()        { return InstallSubdir("bin"); }
    std::string ConfigDir()     { return InstallSubdir("config"); }
    std::string LogsDir()       { return InstallSubdir("logs"); }
    std::string CacheDir()      { return InstallSubdir("cache"); }
    std::string VmDir()         { return InstallSubdir("vm"); }
    std::string VmBaseDir()     { return InstallSubdir("vm/base"); }
    std::string VmOverlaysDir() { return InstallSubdir("vm/overlays"); }
    std::string VmCacheDir()    { return InstallSubdir("vm/cache"); }

    std::string SessionsDir() {
        std::string dir = (fs::path(AppDataDir()) / "sessions").string();
        try { fs::create_directories(dir); } catch (...) {}
        return dir;
    }

    std::string ArtifactsDir() {
        std::string dir = (fs::path(AppDataDir()) / "artifacts").string();
        try { fs::create_directories(dir); } catch (...) {}
        return dir;
    }

    std::string TempDir() {
        std::string base = "";
#ifdef _WIN32
        char buf[MAX_PATH] = {0};
        DWORD n = GetEnvironmentVariableA("TEMP", buf, sizeof(buf) - 1);
        if (n > 0) {
            base = (fs::path(buf) / "Dracula").string();
        } else {
            base = (fs::path(AppDataDir()) / "temp").string();
        }
#else
        base = "/tmp/dracula";
#endif
        try { fs::create_directories(base); } catch (...) {}
        return base;
    }

    std::string ResolveResource(const std::string& relativeName) {
        std::vector<std::string> roots;
        roots.push_back(CurrentWorkingDir());
        roots.push_back(ResourceRoot());
        roots.push_back(ExecutableDir());

        try {
            fs::path dir = ExecutableDir();
            for (int depth = 0; depth < 4 && !dir.empty(); ++depth) {
                if (!dir.has_parent_path() || dir.parent_path() == dir) break;
                dir = dir.parent_path();
                roots.push_back(dir.string());
            }
        } catch (...) {
        }

        for (const auto& root : roots) {
            if (root.empty()) continue;
            try {
                fs::path candidate = fs::path(root) / relativeName;
                if (fs::exists(candidate)) {
                    return candidate.string();
                }
            } catch (...) {
            }
        }
        return "";
    }

} // namespace Paths
} // namespace Dracula
