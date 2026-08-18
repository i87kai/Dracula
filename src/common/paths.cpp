#include "common/paths.h"

#include <filesystem>

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
