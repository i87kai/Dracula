#include "app/sandbox_service.h"
#include "app/services.h"
#include "app/settings.h"
#include "app/hasher.h"
#include "common/paths.h"
#include "common/config.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstdlib>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace Dracula {
namespace App {

    namespace {

        // The canonical package name. One base per installation keeps the
        // lifecycle unambiguous.
        constexpr const char* kPackageName = "windows10.draculaimg";
        constexpr const char* kBaseName    = "windows10";

        // Sidecar recording which QEMU process owns an overlay, so a crashed
        // run can be told apart from a live one on the next launch.
        std::string OwnerFilePath(const std::string& overlayPath) {
            return overlayPath + ".owner";
        }

        bool ProcessAlive(uint32_t pid) {
            if (pid == 0) return false;
#ifdef _WIN32
            HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!handle) return false;
            DWORD exitCode = 0;
            const bool alive = GetExitCodeProcess(handle, &exitCode) && exitCode == STILL_ACTIVE;
            CloseHandle(handle);
            return alive;
#else
            return false;
#endif
        }

        uint32_t ReadOwnerPid(const std::string& overlayPath) {
            std::ifstream in(OwnerFilePath(overlayPath));
            if (!in.is_open()) return 0;
            uint32_t pid = 0;
            in >> pid;
            return pid;
        }

        std::string QemuImgPath() {
            const auto& cfg = ConfigManager::Instance().GetQemuConfig();
            if (cfg.qemuExecutable.empty()) return "";

            // qemu-img lives beside qemu-system-x86_64 in every standard
            // install layout.
            fs::path candidate = fs::path(cfg.qemuExecutable).parent_path() / "qemu-img.exe";
            std::error_code ec;
            if (fs::exists(candidate, ec)) return candidate.string();

            candidate = fs::path(cfg.qemuExecutable).parent_path() / "qemu-img";
            if (fs::exists(candidate, ec)) return candidate.string();
            return "";
        }

        // Runs a command and captures its combined output.
        int RunCapture(const std::string& commandLine, std::string& output) {
            output.clear();
            std::string full = "\"" + commandLine + "\" 2>&1";
            FILE* pipe = _popen(full.c_str(), "r");
            if (!pipe) return -1;

            char buffer[512];
            while (fgets(buffer, sizeof(buffer), pipe)) output += buffer;
            return _pclose(pipe);
        }

        std::string Quote(const std::string& s) {
            return "\"" + s + "\"";
        }

        uint64_t FileSizeOf(const fs::path& p) {
            std::error_code ec;
            const uint64_t size = static_cast<uint64_t>(fs::file_size(p, ec));
            return ec ? 0 : size;
        }

    } // namespace

    SandboxService& SandboxService::Instance() {
        static SandboxService instance;
        return instance;
    }

    std::string SandboxService::PackagePath() const {
        const fs::path candidate = fs::path(Paths::VmBaseDir()) / kPackageName;
        std::error_code ec;
        return fs::exists(candidate, ec) ? candidate.string() : "";
    }

    std::string SandboxService::BaseImagePath() const {
        std::error_code ec;
        const fs::path dir = Paths::VmBaseDir();
        if (!fs::exists(dir, ec)) return "";

        // The operational base is whatever <name>.<disk-ext> exists beside the
        // package. Its format follows whatever the user packaged.
        for (const char* ext : {".qcow2", ".vdi", ".raw", ".img", ".vmdk", ".vhd", ".vhdx"}) {
            const fs::path candidate = dir / (std::string(kBaseName) + ext);
            if (fs::exists(candidate, ec)) return candidate.string();
        }
        return "";
    }

    SandboxState SandboxService::QueryState() const {
        SandboxState state;
        std::error_code ec;

        // --- QEMU binary ---
        const auto& cfg = ConfigManager::Instance().GetQemuConfig();
        state.qemuPath = cfg.qemuExecutable;
        if (!cfg.qemuExecutable.empty() && fs::exists(cfg.qemuExecutable, ec)) {
            state.qemuBinary = BackendState::Installed;

            // cmd.exe strips one outer quote pair, so the executable path is
            // quoted here and RunCapture wraps the whole command line again.
            std::string output;
            if (RunCapture(Quote(cfg.qemuExecutable) + " --version", output) == 0 &&
                !output.empty()) {
                const size_t newline = output.find('\n');
                state.qemuVersion = output.substr(0, newline == std::string::npos ? output.size() : newline);
                while (!state.qemuVersion.empty() &&
                       (state.qemuVersion.back() == '\r' || state.qemuVersion.back() == ' ')) {
                    state.qemuVersion.pop_back();
                }
            }
        }

        // --- Package ---
        state.packagePath = PackagePath();
        if (!state.packagePath.empty()) {
            state.packageInfo = DraculaImage::Inspect(state.packagePath);
            // Present and parseable is "Installed"; only a verification run can
            // upgrade that claim, so nothing here says Verified.
            state.packageState = state.packageInfo.valid
                               ? BackendState::Installed
                               : BackendState::Failed;
        }

        // --- Operational base ---
        state.baseImagePath = BaseImagePath();
        if (!state.baseImagePath.empty()) {
            state.baseImageState = BackendState::Available;
            state.baseImageBytes = FileSizeOf(state.baseImagePath);
        } else if (!state.packagePath.empty()) {
            // Recoverable: the package can rebuild it.
            state.baseImageState = BackendState::Stopped;
        }

        // --- Firmware ---
        state.firmwarePath = cfg.biosPath;
        if (!cfg.biosPath.empty() && fs::exists(cfg.biosPath, ec)) {
            state.firmwareState = BackendState::Available;
        }

        // --- Guest agent payload ---
        for (const std::string& dir : {Paths::BinDir(), Paths::ExecutableDir(), Paths::ResourceRoot()}) {
            if (dir.empty()) continue;
            const fs::path candidate = fs::path(dir) / "GuestAgent.exe";
            if (fs::exists(candidate, ec)) {
                state.guestAgentState = BackendState::Available;
                state.guestAgentPath = candidate.string();
                break;
            }
        }

        // --- Overlays ---
        state.overlays = ListOverlays();
        for (const auto& overlay : state.overlays) state.overlayBytes += overlay.sizeBytes;

        // --- VM / session ---
        // A VM is only Running if an overlay has a living owner. Nothing here
        // infers a running guest from configuration existing.
        const bool anyActive = std::any_of(state.overlays.begin(), state.overlays.end(),
                                           [](const OverlayRecord& o) { return o.active; });
        state.vmState = anyActive ? BackendState::Active : BackendState::Stopped;
        state.guestAgentSession = anyActive ? BackendState::Initialized : BackendState::Stopped;

        return state;
    }

    std::vector<OverlayRecord> SandboxService::ListOverlays() const {
        std::vector<OverlayRecord> overlays;
        std::error_code ec;

        const fs::path dir = Paths::VmOverlaysDir();
        if (!fs::exists(dir, ec)) return overlays;

        for (fs::directory_iterator it(dir, ec), end; it != end; it.increment(ec)) {
            if (ec) { ec.clear(); break; }
            if (!fs::is_regular_file(it->path(), ec)) continue;

            const std::string ext = it->path().extension().string();
            if (ext == ".owner") continue;   // sidecar, not an overlay

            OverlayRecord record;
            record.id = it->path().stem().string();
            record.path = it->path().string();
            record.sizeBytes = FileSizeOf(it->path());
            record.ownerPid = ReadOwnerPid(record.path);
            record.active = ProcessAlive(record.ownerPid);

            const auto writeTime = fs::last_write_time(it->path(), ec);
            (void)writeTime;
            record.createdAt = NowIso8601();

            overlays.push_back(record);
        }
        return overlays;
    }

    UTR::Result<OverlayRecord> SandboxService::CreateOverlay(const std::string& runId) {
        const std::string base = BaseImagePath();
        if (base.empty()) {
            return UTR::Result<OverlayRecord>::Fail(
                "no operational VM base; import one with /sandbox image import <path>");
        }

        const std::string qemuImg = QemuImgPath();
        if (qemuImg.empty()) {
            return UTR::Result<OverlayRecord>::Fail(
                "qemu-img was not found beside the configured QEMU executable");
        }

        std::error_code ec;
        const fs::path dir = Paths::VmOverlaysDir();
        fs::create_directories(dir, ec);

        const fs::path overlayPath = dir / ("run_" + runId + ".qcow2");
        fs::remove(overlayPath, ec);

        // A qcow2 overlay with the base as its backing file. Every guest write
        // lands in the overlay, so the base is physically never modified.
        std::ostringstream command;
        command << Quote(qemuImg) << " create -f qcow2 -F "
                << fs::path(base).extension().string().substr(1)
                << " -b " << Quote(base) << " " << Quote(overlayPath.string());

        std::string output;
        const int rc = RunCapture(command.str(), output);
        if (rc != 0 || !fs::exists(overlayPath, ec)) {
            return UTR::Result<OverlayRecord>::Fail(
                "qemu-img could not create the overlay: " +
                (output.empty() ? std::string("no output") : output));
        }

        OverlayRecord record;
        record.id = overlayPath.stem().string();
        record.path = overlayPath.string();
        record.createdAt = NowIso8601();
        record.sizeBytes = FileSizeOf(overlayPath);

        RuntimeService::Instance().RecordEvent("QEMU", "Overlay created", "info", record.path);
        return UTR::Result<OverlayRecord>::Success(record);
    }

    UTR::Result<uint64_t> SandboxService::ReleaseOverlay(const std::string& overlayId) {
        std::error_code ec;
        const fs::path dir = Paths::VmOverlaysDir();

        fs::path target;
        for (const auto& overlay : ListOverlays()) {
            if (overlay.id == overlayId) {
                if (overlay.active) {
                    // Never delete an overlay a live QEMU is still writing to.
                    return UTR::Result<uint64_t>::Fail(
                        "overlay " + overlayId + " is still owned by running QEMU process " +
                        std::to_string(overlay.ownerPid));
                }
                target = overlay.path;
                break;
            }
        }

        if (target.empty()) {
            return UTR::Result<uint64_t>::Fail("no overlay named '" + overlayId + "'");
        }

        const uint64_t freed = FileSizeOf(target);
        fs::remove(target, ec);
        if (ec) {
            return UTR::Result<uint64_t>::Fail("could not remove overlay: " + ec.message());
        }
        fs::remove(OwnerFilePath(target.string()), ec);

        RuntimeService::Instance().RecordEvent("QEMU", "Overlay released", "info", target.string());
        return UTR::Result<uint64_t>::Success(freed);
    }

    UTR::Result<uint64_t> SandboxService::SweepStaleOverlays(std::vector<std::string>& removed) {
        uint64_t freed = 0;
        std::error_code ec;

        for (const auto& overlay : ListOverlays()) {
            // An overlay whose owner is gone belongs to a crashed or completed
            // run; an overlay with a live owner is left strictly alone.
            if (overlay.active) continue;

            const uint64_t size = overlay.sizeBytes;
            fs::remove(overlay.path, ec);
            if (ec) { ec.clear(); continue; }
            fs::remove(OwnerFilePath(overlay.path), ec);

            freed += size;
            removed.push_back(overlay.id);
        }

        if (!removed.empty()) {
            RuntimeService::Instance().RecordEvent(
                "QEMU", "Swept " + std::to_string(removed.size()) + " stale overlay(s)", "info");
        }
        return UTR::Result<uint64_t>::Success(freed);
    }

    // --- Commands -------------------------------------------------------------

    CommandResult SandboxService::Status() const {
        SandboxState state = QueryState();

        CommandResult r = CommandResult::Success("QEMU environment");

        auto row = [&](const char* label, BackendState value, const std::string& detail) {
            std::ostringstream line;
            line << std::left << std::setw(20) << label
                 << std::setw(16) << BackendStateToString(value);
            if (!detail.empty()) line << detail;
            r.Line(line.str());
        };

        row("Binary", state.qemuBinary,
            state.qemuVersion.empty() ? state.qemuPath : state.qemuVersion);
        row("Package", state.packageState,
            state.packagePath.empty() ? "no .draculaimg imported" : state.packagePath);
        row("Base image", state.baseImageState,
            state.baseImagePath.empty()
                ? (state.packagePath.empty() ? "none" : "restorable from package")
                : (state.baseImagePath + "  " + FormatBytes(state.baseImageBytes)));
        row("Firmware", state.firmwareState, state.firmwarePath);
        row("GuestAgent package", state.guestAgentState, state.guestAgentPath);
        row("VM", state.vmState, "");
        row("GuestAgent session", state.guestAgentSession,
            state.guestAgentSession == BackendState::Stopped ? "not connected" : "");

        r.Line("");
        if (state.overlays.empty()) {
            r.Line("Overlays: none");
        } else {
            r.Line("Overlays: " + std::to_string(state.overlays.size()) +
                   "  (" + FormatBytes(state.overlayBytes) + ")");
            for (const auto& overlay : state.overlays) {
                r.Line("  " + overlay.id + "  " + FormatBytes(overlay.sizeBytes) +
                       (overlay.active
                            ? ("  ACTIVE (pid " + std::to_string(overlay.ownerPid) + ")")
                            : "  stale"));
            }
        }
        return r;
    }

    CommandResult SandboxService::ImageImport(const std::string& sourcePath) {
        if (sourcePath.empty()) {
            return CommandResult::Failure("missing_argument",
                                          "No source image specified.",
                                          "/sandbox image import needs a path to your VM disk image.",
                                          "Example: /sandbox image import C:\\VMs\\win10.vdi");
        }

        std::error_code ec;
        if (!fs::exists(sourcePath, ec)) {
            return CommandResult::Failure("source_missing",
                                          "Source image not found.",
                                          sourcePath + " does not exist.",
                                          "Check the path to your local VM image.");
        }

        const fs::path packagePath = fs::path(Paths::VmBaseDir()) / kPackageName;
        const uint64_t sourceSize = FileSizeOf(sourcePath);

        CommandResult r = CommandResult::Success("Packaging VM image");
        r.Line("Source:  " + sourcePath + "  (" + FormatBytes(sourceSize) + ")");
        r.Line("Package: " + packagePath.string());
        r.Line("");

        RuntimeService::Instance().RecordEvent("IMAGE", "Packaging started", "info", sourcePath);

        auto result = DraculaImage::Package(sourcePath, packagePath.string(), 9, nullptr);
        if (!result.ok) {
            RuntimeService::Instance().RecordEvent("IMAGE", "Packaging failed", "error", result.error);
            return CommandResult::Failure("package_failed",
                                          "Could not package the VM image.",
                                          result.error);
        }

        std::ostringstream ratio;
        ratio << std::fixed << std::setprecision(1) << (result.CompressionRatio() * 100.0) << "%";

        r.Line("Original size:    " + FormatBytes(result.originalSize));
        r.Line("Package size:     " + FormatBytes(result.packagedSize));
        r.Line("Compression:      " + ratio.str() + " of original");
        r.Line("Chunks:           " + std::to_string(result.chunkCount));
        r.Line("Duration:         " + std::to_string(result.durationMs / 1000) + " s");
        r.Line("Original SHA-256: " + result.originalSha256);
        r.Line("Package SHA-256:  " + result.packageSha256);
        r.Line("");
        r.Line("The source image was only read; it has not been modified or moved.");
        r.Line("Verify it with /sandbox image verify, then build the operational base");
        r.Line("with /sandbox image restore.");

        RuntimeService::Instance().RecordEvent("IMAGE", "Packaging complete", "info",
                                               packagePath.string());
        return r;
    }

    CommandResult SandboxService::ImageInfo() const {
        const std::string packagePath = PackagePath();
        if (packagePath.empty()) {
            return CommandResult::Failure("no_package",
                                          "No VM image package has been imported.",
                                          "There is no " + std::string(kPackageName) +
                                          " in " + Paths::VmBaseDir() + ".",
                                          "Import your local VM with /sandbox image import <path>.");
        }

        auto info = DraculaImage::Inspect(packagePath);
        if (!info.valid) {
            return CommandResult::Failure("package_invalid",
                                          "The package header could not be read.",
                                          packagePath + " is not a valid .draculaimg file.",
                                          "Re-import the image with /sandbox image import <path>.");
        }

        std::ostringstream ratio;
        ratio << std::fixed << std::setprecision(1) << (info.CompressionRatio() * 100.0) << "%";

        CommandResult r = CommandResult::Success("VM image package");
        r.Line("Path:            " + packagePath);
        r.Line("Format version:  " + std::to_string(info.formatVersion));
        r.Line("Source:          " + info.sourceName + "  (" + info.sourceFormat + ")");
        r.Line("Original size:   " + FormatBytes(info.originalSize));
        r.Line("Package size:    " + FormatBytes(info.packagedSize));
        r.Line("Compression:     " + ratio.str() + " of original");
        r.Line("Chunks:          " + std::to_string(info.chunkCount) +
               "  (" + FormatBytes(info.chunkSize) + " each)");
        r.Line("Created:         " + info.createdAt);
        r.Line("Dracula:         v" + info.draculaVersion);
        r.Line("Original SHA-256:" + info.originalSha256);
        return r;
    }

    CommandResult SandboxService::ImageVerify(bool deep) const {
        const std::string packagePath = PackagePath();
        if (packagePath.empty()) {
            return CommandResult::Failure("no_package",
                                          "No VM image package has been imported.",
                                          "There is nothing to verify.",
                                          "Import your local VM with /sandbox image import <path>.");
        }

        RuntimeService::Instance().RecordEvent("IMAGE", "Verification started", "info", packagePath);

        auto verification = DraculaImage::Verify(packagePath, deep, nullptr);
        if (!verification.ok) {
            RuntimeService::Instance().RecordEvent("IMAGE", "Verification failed", "error",
                                                   verification.error);
            ErrorDetail e;
            e.code = "package_corrupt";
            e.message = "Package verification failed.";
            e.reason = verification.error;
            e.remediation = "Re-import the image from your local VM with /sandbox image import <path>.";
            CommandResult r = CommandResult::Failure(e);
            r.Line("Header:  " + std::string(verification.headerValid ? "VERIFIED" : "FAILED"));
            r.Line("Chunks:  " + std::to_string(verification.chunksChecked) + " checked");
            if (!verification.chunksValid) {
                r.Line("First bad chunk: " + std::to_string(verification.firstBadChunk));
            }
            return r;
        }

        RuntimeService::Instance().RecordEvent("IMAGE", "Verification passed", "info", packagePath);

        CommandResult r = CommandResult::Success("Package verified");
        r.Line("Header:           VERIFIED");
        r.Line("Chunks:           VERIFIED  (" + std::to_string(verification.chunksChecked) + ")");
        r.Line(std::string("Content hash:     ") +
               (verification.contentVerified ? "VERIFIED" : "not checked (shallow verify)"));
        if (verification.contentVerified) {
            r.Line("SHA-256:          " + verification.actualSha256);
        }
        r.Line("Original size:    " + FormatBytes(verification.info.originalSize));
        r.Line("Package size:     " + FormatBytes(verification.info.packagedSize));
        return r;
    }

    CommandResult SandboxService::ImageRestore(bool overwrite) {
        const std::string packagePath = PackagePath();
        if (packagePath.empty()) {
            return CommandResult::Failure("no_package",
                                          "No VM image package has been imported.",
                                          "There is nothing to restore from.",
                                          "Import your local VM with /sandbox image import <path>.");
        }

        auto info = DraculaImage::Inspect(packagePath);
        if (!info.valid) {
            return CommandResult::Failure("package_invalid",
                                          "The package could not be read.",
                                          packagePath + " is not a valid .draculaimg file.");
        }

        const std::string extension =
            info.sourceFormat.empty() ? "raw" : info.sourceFormat;
        const fs::path outputPath =
            fs::path(Paths::VmBaseDir()) / (std::string(kBaseName) + "." + extension);

        RuntimeService::Instance().RecordEvent("IMAGE", "Base restore started", "info",
                                               outputPath.string());

        auto result = DraculaImage::Restore(packagePath, outputPath.string(), overwrite, nullptr);
        if (!result.ok) {
            RuntimeService::Instance().RecordEvent("IMAGE", "Base restore failed", "error",
                                                   result.error);
            return CommandResult::Failure("restore_failed",
                                          "Could not restore the operational base.",
                                          result.error,
                                          result.error.find("overwrite") != std::string::npos
                                              ? "Pass --force to replace the existing base."
                                              : "");
        }

        RuntimeService::Instance().RecordEvent("IMAGE", "Base restored", "info",
                                               outputPath.string());

        CommandResult r = CommandResult::Success("Operational base restored");
        r.Line("Base image:   " + outputPath.string());
        r.Line("Size:         " + FormatBytes(result.originalSize));
        r.Line("SHA-256:      " + result.originalSha256);
        r.Line("Duration:     " + std::to_string(result.durationMs / 1000) + " s");
        r.Line("");
        r.Line("The base is immutable analysis infrastructure: every run writes to a");
        r.Line("disposable overlay instead, and the base is never modified.");
        return r;
    }

    CommandResult SandboxService::Reset() {
        CommandResult r = CommandResult::Success("Sandbox reset");

        // 1. Nothing may be running.
        SandboxState before = QueryState();
        if (before.vmState == BackendState::Active) {
            r.Line("Active QEMU session detected; stop it before resetting.");
            return CommandResult::Failure("vm_active",
                                          "A VM session is still running.",
                                          "Reset would destroy an overlay a live QEMU process is writing to.",
                                          "Stop the running analysis, then run /sandbox reset again.");
        }

        // 2. Clear disposable overlays.
        std::vector<std::string> removed;
        auto swept = SweepStaleOverlays(removed);
        r.Line("Overlays removed:  " + std::to_string(removed.size()) +
               "  (" + FormatBytes(swept.Ok() ? swept.Value() : 0) + " reclaimed)");

        // 3. Verify the immutable package.
        const std::string packagePath = PackagePath();
        if (packagePath.empty()) {
            r.Line("Package:           NONE  (import one with /sandbox image import <path>)");
            r.Line("Base image:        cannot be rebuilt without a package");
            return r;
        }

        auto verification = DraculaImage::Verify(packagePath, true, nullptr);
        if (!verification.ok) {
            r.Line("Package:           FAILED  (" + verification.error + ")");
            r.Line("Base image:        left untouched; the package must be re-imported first");
            return r;
        }
        r.Line("Package:           VERIFIED  (" + std::to_string(verification.chunksChecked) + " chunks)");

        // 4. Rebuild the base only if it is missing or no longer matches.
        const std::string basePath = BaseImagePath();
        bool needsRestore = basePath.empty();

        if (!needsRestore) {
            const std::string actual = Sha256Stream::OfFile(basePath);
            if (actual != verification.info.originalSha256) {
                r.Line("Base image:        MODIFIED  (hash differs from the package)");
                needsRestore = true;
            } else {
                r.Line("Base image:        VERIFIED  (matches the package byte for byte)");
            }
        } else {
            r.Line("Base image:        MISSING");
        }

        if (needsRestore) {
            auto restored = ImageRestore(true);
            if (!restored.ok) {
                r.Line("Base image:        RESTORE FAILED  (" + restored.error.reason + ")");
                return r;
            }
            r.Line("Base image:        RESTORED from the verified package");
        }

        // 5. Report the remaining infrastructure honestly.
        SandboxState after = QueryState();
        r.Line("QEMU binary:       " + std::string(BackendStateToString(after.qemuBinary)));
        r.Line("Firmware:          " + std::string(BackendStateToString(after.firmwareState)));
        r.Line("GuestAgent:        " + std::string(BackendStateToString(after.guestAgentState)));
        r.Line("VM:                " + std::string(BackendStateToString(after.vmState)));

        RuntimeService::Instance().RecordEvent("QEMU", "Sandbox reset complete", "info");
        return r;
    }

} // namespace App
} // namespace Dracula
