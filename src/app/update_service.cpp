#include "app/update_service.h"
#include "app/json.h"
#include "app/hasher.h"
#include "app/settings.h"
#include "common/paths.h"
#include "common/version.h"

#include <windows.h>
#include <wininet.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>

namespace fs = std::filesystem;

namespace Dracula {
namespace App {

    namespace {
        const std::string kGitHubApiReleases = std::string("https://api.github.com/repos/") + Version::GitHubRepo + "/releases";

        // Simple semver parse: returns major, minor, patch as ints
        struct SemVer {
            int major = 0;
            int minor = 0;
            int patch = 0;

            static SemVer Parse(const std::string& str) {
                SemVer v;
                std::string s = str;
                if (!s.empty() && (s[0] == 'v' || s[0] == 'V')) {
                    s = s.substr(1);
                }
                // strip any suffix like -beta
                size_t dash = s.find('-');
                if (dash != std::string::npos) {
                    s = s.substr(0, dash);
                }
                std::stringstream ss(s);
                char dot;
                ss >> v.major >> dot >> v.minor >> dot >> v.patch;
                return v;
            }

            bool operator>(const SemVer& o) const {
                if (major != o.major) return major > o.major;
                if (minor != o.minor) return minor > o.minor;
                return patch > o.patch;
            }
        };

        std::string Trim(const std::string& s) {
            auto wsfront = std::find_if_not(s.begin(), s.end(), [](int c){return std::isspace(c);});
            auto wsback = std::find_if_not(s.rbegin(), s.rend(), [](int c){return std::isspace(c);}).base();
            return (wsback <= wsfront ? std::string() : std::string(wsfront, wsback));
        }

        std::string ToLower(std::string s) {
            std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            return s;
        }
    } // namespace

    UpdateService& UpdateService::Instance() {
        static UpdateService instance;
        return instance;
    }

    UpdateStatus UpdateService::GetStatus() const {
        return m_status;
    }

    const UpdateInfo& UpdateService::GetLastInfo() const {
        return m_lastInfo;
    }

    const std::string& UpdateService::GetLastError() const {
        return m_lastError;
    }

    bool UpdateService::IsUpdateAvailable() const {
        return m_status == UpdateStatus::Available;
    }

    std::string UpdateService::StatusLine() const {
        switch (m_status) {
            case UpdateStatus::Unknown:
                return "Not checked for updates yet. Use '/update check'.";
            case UpdateStatus::UpToDate:
                return "Dracula is up to date (" DRACULA_VERSION_STRING ").";
            case UpdateStatus::Available:
                return "Update available: " + m_lastInfo.tag + " (Current: v" DRACULA_VERSION_STRING "). Use '/update install'.";
            case UpdateStatus::Downloading:
                return "Downloading update...";
            case UpdateStatus::Verifying:
                return "Verifying update package signature...";
            case UpdateStatus::Installing:
                return "Installing update...";
            case UpdateStatus::Installed:
                return "Update installed successfully (" + m_lastInfo.tag + "). Please restart Dracula.";
            case UpdateStatus::Error:
                return "Update check failed: " + m_lastError;
        }
        return "Unknown status";
    }

    bool UpdateService::CheckDefault(std::string& error) {
        std::string channel = Settings::Instance().GetString("update.channel", "stable");
        return Check(channel, m_lastInfo, error);
    }

    bool UpdateService::Check(const std::string& channel, UpdateInfo& info, std::string& error) {
        m_lastError.clear();

        // Download releases JSON
        std::string jsonResponse;
        HINTERNET hInternet = InternetOpenA("Dracula-AutoUpdater/" DRACULA_VERSION_STRING,
                                            INTERNET_OPEN_TYPE_PRECONFIG,
                                            NULL, NULL, 0);
        if (!hInternet) {
            error = "Failed to initialize WinINet for update check (Error: " + std::to_string(::GetLastError()) + ")";
            m_status = UpdateStatus::Error;
            m_lastError = error;
            return false;
        }

        // Add GitHub headers
        const char* headers = "Accept: application/vnd.github.v3+json\r\n";
        HINTERNET hUrl = InternetOpenUrlA(hInternet,
                                         kGitHubApiReleases.c_str(),
                                         headers,
                                         static_cast<DWORD>(strlen(headers)),
                                         INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE,
                                         0);
        if (!hUrl) {
            DWORD err = ::GetLastError();
            InternetCloseHandle(hInternet);
            error = "Could not reach GitHub Releases API (WinINet error " + std::to_string(err) + ")";
            m_status = UpdateStatus::Error;
            m_lastError = error;
            return false;
        }

        char buffer[8192];
        DWORD bytesRead = 0;
        std::string response;
        while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            response.append(buffer, bytesRead);
        }

        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);

        if (response.empty()) {
            error = "Empty response received from GitHub Releases API";
            m_status = UpdateStatus::Error;
            m_lastError = error;
            return false;
        }

        if (!ParseReleaseJson(response, channel, info, error)) {
            m_status = UpdateStatus::Error;
            m_lastError = error;
            return false;
        }

        m_lastInfo = info;

        SemVer currentVer = SemVer::Parse(DRACULA_VERSION_STRING);
        SemVer remoteVer = SemVer::Parse(info.version);

        if (remoteVer > currentVer) {
            m_status = UpdateStatus::Available;
        } else {
            m_status = UpdateStatus::UpToDate;
        }

        return true;
    }

    bool UpdateService::ParseReleaseJson(const std::string& jsonStr,
                                        const std::string& channel,
                                        UpdateInfo& out,
                                        std::string& error) {
        Json root;
        if (!Json::Parse(jsonStr, root, nullptr)) {
            error = "Failed to parse releases JSON from GitHub API";
            return false;
        }

        if (!root.IsArray() || root.Size() == 0) {
            error = "No releases found on GitHub repository";
            return false;
        }

        bool allowPrerelease = (channel == "prerelease" || channel == "beta" || channel == "nightly");

        const Json* targetRelease = nullptr;
        for (size_t i = 0; i < root.Size(); ++i) {
            const Json& rel = root.At(i);
            if (!rel.IsObject()) continue;

            bool isDraft = rel.Has("draft") && rel["draft"].AsBool();
            if (isDraft) continue;

            bool isPre = rel.Has("prerelease") && rel["prerelease"].AsBool();
            if (isPre && !allowPrerelease) continue;

            targetRelease = &rel;
            break;
        }

        if (!targetRelease) {
            error = "No suitable releases found matching channel '" + channel + "'";
            return false;
        }

        const Json& rel = *targetRelease;
        out.tag = rel.Has("tag_name") ? rel["tag_name"].AsString() : "";
        out.releaseUrl = rel.Has("html_url") ? rel["html_url"].AsString() : "";
        out.body = rel.Has("body") ? rel["body"].AsString() : "";
        out.prerelease = rel.Has("prerelease") && rel["prerelease"].AsBool();

        out.version = out.tag;
        if (!out.version.empty() && (out.version[0] == 'v' || out.version[0] == 'V')) {
            out.version = out.version.substr(1);
        }

        out.downloadUrl.clear();
        out.sha256Url.clear();

        if (rel.Has("assets") && rel["assets"].IsArray()) {
            const Json& assets = rel["assets"];
            for (size_t i = 0; i < assets.Size(); ++i) {
                const Json& asset = assets.At(i);
                if (!asset.IsObject() || !asset.Has("name") || !asset.Has("browser_download_url")) continue;

                std::string name = ToLower(asset["name"].AsString());
                std::string url = asset["browser_download_url"].AsString();

                if (name.find("windows-x64.zip") != std::string::npos || (name.find(".zip") != std::string::npos && name.find(".sha256") == std::string::npos)) {
                    out.downloadUrl = url;
                } else if (name.find(".sha256") != std::string::npos) {
                    out.sha256Url = url;
                }
            }
        }

        if (out.downloadUrl.empty()) {
            error = "Release " + out.tag + " does not contain a suitable Windows x64 binary archive asset";
            return false;
        }

        return true;
    }

    bool UpdateService::DownloadFile(const std::string& url,
                                    const std::string& dest,
                                    const ProgressCallback& progress,
                                    std::string& error) {
        HINTERNET hInternet = InternetOpenA("Dracula-AutoUpdater/" DRACULA_VERSION_STRING,
                                            INTERNET_OPEN_TYPE_PRECONFIG,
                                            NULL, NULL, 0);
        if (!hInternet) {
            error = "WinINet open failed";
            return false;
        }

        HINTERNET hUrl = InternetOpenUrlA(hInternet,
                                         url.c_str(),
                                         NULL, 0,
                                         INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE,
                                         0);
        if (!hUrl) {
            DWORD err = ::GetLastError();
            InternetCloseHandle(hInternet);
            error = "Failed to connect to download URL: " + url + " (Error: " + std::to_string(err) + ")";
            return false;
        }

        DWORD contentLength = 0;
        DWORD bufferSize = sizeof(contentLength);
        DWORD headerIndex = 0;
        HttpQueryInfoA(hUrl, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
                       &contentLength, &bufferSize, &headerIndex);

        std::ofstream out(dest, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInternet);
            error = "Failed to create destination file: " + dest;
            return false;
        }

        char buffer[16384];
        DWORD bytesRead = 0;
        uint64_t totalRead = 0;

        while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            out.write(buffer, bytesRead);
            totalRead += bytesRead;
            if (progress) {
                progress("Downloading", totalRead, contentLength > 0 ? contentLength : totalRead);
            }
        }

        out.close();
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);

        return true;
    }

    bool UpdateService::VerifySha256(const std::string& filePath,
                                    const std::string& expectedHex,
                                    std::string& error) {
        std::string computed = Sha256Stream::OfFile(filePath);
        if (computed.empty()) {
            error = "Could not compute SHA-256 for downloaded package";
            return false;
        }

        std::string exp = ToLower(Trim(expectedHex));
        // If the sha256 file contains "hash  filename", extract just the hash
        size_t firstSpace = exp.find_first_of(" \t\r\n");
        if (firstSpace != std::string::npos) {
            exp = exp.substr(0, firstSpace);
        }

        if (computed != exp) {
            error = "SHA-256 mismatch: expected " + exp + ", computed " + computed;
            return false;
        }

        return true;
    }

    bool UpdateService::Install(const UpdateInfo& info,
                               const ProgressCallback& progress,
                               std::string& error) {
        m_status = UpdateStatus::Downloading;
        if (progress) progress("Initializing update", 0, 100);

        std::string tempDir = Paths::TempDir();
        std::error_code ec;
        fs::create_directories(tempDir, ec);

        std::string zipPath = (fs::path(tempDir) / ("Dracula-" + info.tag + ".zip")).string();
        std::string shaPath = zipPath + ".sha256";

        // Download package
        if (!DownloadFile(info.downloadUrl, zipPath, progress, error)) {
            m_status = UpdateStatus::Error;
            m_lastError = error;
            return false;
        }

        // Verify hash if available
        if (!info.sha256Url.empty()) {
            m_status = UpdateStatus::Verifying;
            if (progress) progress("Verifying checksum", 0, 100);

            std::string shaError;
            if (DownloadFile(info.sha256Url, shaPath, nullptr, shaError)) {
                std::ifstream shaIn(shaPath);
                if (shaIn.is_open()) {
                    std::string expectedSha;
                    std::getline(shaIn, expectedSha);
                    shaIn.close();

                    if (!VerifySha256(zipPath, expectedSha, error)) {
                        m_status = UpdateStatus::Error;
                        m_lastError = error;
                        return false;
                    }
                }
            }
        }

        m_status = UpdateStatus::Installing;
        if (progress) progress("Unpacking update package", 50, 100);

        std::string installRoot = Paths::InstallRoot();
        std::string stageDir = (fs::path(tempDir) / ("stage_" + info.tag)).string();
        fs::remove_all(stageDir, ec);
        fs::create_directories(stageDir, ec);

        // Unpack zip using powershell Expand-Archive
        std::string extractCmd = "powershell -NoProfile -NonInteractive -Command \"Expand-Archive -LiteralPath '" +
                                zipPath + "' -DestinationPath '" + stageDir + "' -Force\"";

        int res = std::system(extractCmd.c_str());
        if (res != 0) {
            error = "Failed to extract update package archive";
            m_status = UpdateStatus::Error;
            m_lastError = error;
            return false;
        }

        // Locate files inside stageDir (it may have a subfolder or root files)
        fs::path copySource = stageDir;
        for (const auto& entry : fs::directory_iterator(stageDir)) {
            if (entry.is_directory() && (entry.path().filename().string().find("Dracula") != std::string::npos)) {
                copySource = entry.path();
                break;
            }
        }

        // Backup existing bin and tools to <InstallRoot>\backup\vX.X.X
        std::string backupDir = (fs::path(installRoot) / "backup" / ("v" DRACULA_VERSION_STRING)).string();
        fs::create_directories(backupDir, ec);

        try {
            // Copy stage contents into installRoot preserving user projects/logs/config
            for (const auto& item : fs::recursive_directory_iterator(copySource)) {
                auto rel = fs::relative(item.path(), copySource);
                fs::path destItem = fs::path(installRoot) / rel;

                // Never overwrite user projects, custom configs or logs
                std::string firstComp = rel.begin()->string();
                if (firstComp == "projects" || firstComp == "logs" || firstComp == "cache") {
                    continue;
                }

                if (item.is_directory()) {
                    fs::create_directories(destItem, ec);
                } else if (item.is_regular_file()) {
                    fs::create_directories(destItem.parent_path(), ec);
                    // If target file exists and is executable, backup first
                    if (fs::exists(destItem, ec)) {
                        fs::path backupItem = fs::path(backupDir) / rel;
                        fs::create_directories(backupItem.parent_path(), ec);
                        fs::copy_file(destItem, backupItem, fs::copy_options::overwrite_existing, ec);
                    }
                    fs::copy_file(item.path(), destItem, fs::copy_options::overwrite_existing, ec);
                }
            }
        } catch (const std::exception& e) {
            error = std::string("Error writing update files: ") + e.what();
            m_status = UpdateStatus::Error;
            m_lastError = error;
            return false;
        }

        m_status = UpdateStatus::Installed;
        if (progress) progress("Update completed", 100, 100);

        return true;
    }

} // namespace App
} // namespace Dracula
