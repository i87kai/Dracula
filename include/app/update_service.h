#pragma once

//
// Dracula auto-update service.
//
// Checks the GitHub Releases API for a newer version, downloads the release
// zip into a temporary directory, verifies the SHA-256 digest, backs up the
// current installation, and replaces it in-place.
//
// The service is intentionally thin: it talks HTTP via WinINet (already a
// Windows dependency), JSON via the project's own Json class, and hashing via
// the project's own Hasher.  No third-party HTTP library is needed.
//
// All public methods are synchronous and safe to call from any thread.
// Long-running operations report progress via an optional ProgressCallback.
//

#include <string>
#include <functional>
#include <cstdint>

namespace Dracula {
namespace App {

    struct UpdateInfo {
        std::string tag;           // e.g. "v1.3.1"
        std::string version;       // e.g. "1.3.1"
        std::string releaseUrl;    // HTML URL to the GitHub release page
        std::string downloadUrl;   // Direct .zip download URL
        std::string sha256Url;     // URL to the .sha256 file
        std::string body;          // Release notes (markdown)
        bool        prerelease = false;
    };

    enum class UpdateStatus {
        Unknown,        // Not yet checked
        UpToDate,       // Running the latest version
        Available,      // A newer version exists
        Downloading,    // Download in progress
        Verifying,      // SHA-256 check in progress
        Installing,     // Swapping files in place
        Installed,      // Newly installed; restart required
        Error,          // Something went wrong; see lastError
    };

    class UpdateService {
    public:
        using ProgressCallback = std::function<void(const std::string& stage,
                                                    uint64_t done,
                                                    uint64_t total)>;

        static UpdateService& Instance();

        // ── Check ────────────────────────────────────────────────────────────
        // Queries the GitHub Releases API.  Returns true and populates `info`
        // on success.  `channel` is "stable" (default) or "prerelease".
        bool Check(const std::string& channel,
                   UpdateInfo&        info,
                   std::string&       error);

        // Convenience: checks according to settings, caches the result.
        bool CheckDefault(std::string& error);

        // ── Install ──────────────────────────────────────────────────────────
        // Downloads, verifies, and installs the release described by `info`.
        // The caller's executable directory is used as the install root.
        bool Install(const UpdateInfo&       info,
                     const ProgressCallback& progress,
                     std::string&            error);

        // ── Status ───────────────────────────────────────────────────────────
        UpdateStatus        GetStatus()    const;
        const UpdateInfo&   GetLastInfo()  const;
        const std::string&  GetLastError() const;

        // True when the last Check() found a newer version.
        bool IsUpdateAvailable() const;

        // Human-readable status string for /update status.
        std::string StatusLine() const;

    private:
        UpdateService() = default;

        bool DownloadFile(const std::string& url,
                          const std::string& dest,
                          const ProgressCallback& progress,
                          std::string& error);

        bool VerifySha256(const std::string& filePath,
                          const std::string& expectedHex,
                          std::string&       error);

        bool ParseReleaseJson(const std::string& json,
                              const std::string& channel,
                              UpdateInfo&        out,
                              std::string&       error);

        UpdateStatus m_status    = UpdateStatus::Unknown;
        UpdateInfo   m_lastInfo;
        std::string  m_lastError;
    };

} // namespace App
} // namespace Dracula
