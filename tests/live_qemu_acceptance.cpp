//
// LIVE QEMU acceptance (v1.3.0 milestone, sections 30-33 and 40-I).
//
// This exercises REAL infrastructure: the actual qemu-system binary, the
// actual operational base restored from the user's .draculaimg, a real qcow2
// overlay, and a real booted guest.
//
// It is deliberately NOT part of the default ctest run, because it depends on
// an environment that only exists on a machine where the user has imported
// their own VM. When that environment is absent it reports BLOCKED and exits
// zero -- it never substitutes a simulation for live evidence.
//
// Run with:
//     DRACULA_ROOT=<install root> live_qemu_acceptance
//

#include "app/sandbox_service.h"
#include "app/services.h"
#include "app/hasher.h"
#include "common/paths.h"
#include "common/config.h"

#include <iostream>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <thread>
#include <cstdlib>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace fs = std::filesystem;
using namespace Dracula;
using namespace Dracula::App;

static int g_checks = 0;
static int g_failures = 0;

static void Check(bool condition, const std::string& what) {
    ++g_checks;
    if (condition) {
        std::cout << "  [PASS] " << what << "\n";
    } else {
        ++g_failures;
        std::cout << "  [FAIL] " << what << "\n";
    }
}

static void Blocked(const std::string& why) {
    std::cout << "\n  [BLOCKED] " << why << "\n";
    std::cout << "  This environment cannot run the live QEMU acceptance.\n";
    std::cout << "  It has NOT been replaced by a simulated result.\n\n";
}

static uint64_t FileSizeOf(const fs::path& p) {
    std::error_code ec;
    const uint64_t size = static_cast<uint64_t>(fs::file_size(p, ec));
    return ec ? 0 : size;
}

static std::string Timestamp() {
    return NowIso8601();
}

int main() {
    std::cout << "\n=== Dracula LIVE QEMU Acceptance ===\n\n";

    // The QEMU configuration (firmware, UEFI variable store, accelerators)
    // lives in config.ini. Without loading it the defaults are unresolved
    // relative paths, and a Windows guest will not boot without its firmware.
    const std::string configPath = Paths::ResolveResource("config/config.ini");
    if (!configPath.empty()) {
        ConfigManager::Instance().LoadFromFile(configPath);
        std::cout << "  Config:       " << configPath << "\n";
    } else {
        std::cout << "  Config:       <not found, using defaults>\n";
    }

    std::cout << "  Install root: " << Paths::InstallRoot() << "\n";
    std::cout << "  Started:      " << Timestamp() << "\n\n";

    auto& sandbox = SandboxService::Instance();
    SandboxState state = sandbox.QueryState();

    // --- Environment gate ---------------------------------------------------
    std::cout << "  QEMU binary:  " << BackendStateToString(state.qemuBinary)
              << "  " << state.qemuVersion << "\n";
    std::cout << "  QEMU path:    " << state.qemuPath << "\n";
    std::cout << "  Package:      " << BackendStateToString(state.packageState)
              << "  " << state.packagePath << "\n";
    std::cout << "  Base image:   " << BackendStateToString(state.baseImageState)
              << "  " << state.baseImagePath << "\n\n";

    if (state.qemuBinary == BackendState::Unsupported) {
        Blocked("qemu-system-x86_64 is not installed or not configured.");
        return 0;
    }
    if (state.baseImagePath.empty()) {
        Blocked("No operational VM base. Import and restore one first:\n"
                "            /sandbox image import <your vm image>\n"
                "            /sandbox image restore");
        return 0;
    }

    const fs::path basePath = state.baseImagePath;
    const uint64_t baseSizeBefore = FileSizeOf(basePath);

    std::cout << "  Hashing the base image to prove immutability (this takes a while)...\n";
    const auto hashStart = std::chrono::steady_clock::now();
    const std::string baseHashBefore = Sha256Stream::OfFile(basePath.string());
    const auto hashSeconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - hashStart).count();

    std::cout << "  Base SHA-256: " << baseHashBefore << "\n";
    std::cout << "  Base size:    " << baseSizeBefore << " bytes\n";
    std::cout << "  Hash time:    " << hashSeconds << " s\n\n";
    Check(!baseHashBefore.empty(), "base image hashed");

    // --- Overlay creation ---------------------------------------------------
    std::cout << "  --- Overlay lifecycle ---\n";

    const std::string runId = "acceptance";
    auto created = sandbox.CreateOverlay(runId);
    Check(created.Ok(), std::string("overlay created over the immutable base") +
                        (created.Ok() ? "" : (": " + created.Error())));
    if (!created.Ok()) {
        std::cout << "\n  Cannot continue without an overlay.\n";
        return 1;
    }

    const OverlayRecord overlay = created.Value();
    std::cout << "  Overlay:      " << overlay.path << "\n";
    const uint64_t overlayInitial = FileSizeOf(overlay.path);
    std::cout << "  Initial size: " << overlayInitial << " bytes\n";

    // A fresh qcow2 overlay is tiny: it holds no data, only a reference to its
    // backing file. That is the proof it is an overlay and not a copy.
    Check(fs::exists(overlay.path), "overlay file exists on disk");
    Check(overlayInitial < baseSizeBefore / 100,
          "overlay is a thin qcow2 layer, not a copy of the base");

    // --- Live boot ----------------------------------------------------------
    std::cout << "\n  --- Live QEMU boot ---\n";

    const auto& cfg = ConfigManager::Instance().GetQemuConfig();

    // Mirrors the verified QemuManager launch configuration, with two
    // deliberate differences: the disk is the OVERLAY rather than the
    // configured base, and -snapshot is omitted. -snapshot would divert guest
    // writes to a throwaway temp file, which would defeat the very thing being
    // proven here -- that writes land in the overlay.
    std::string commandLine = "\"" + cfg.qemuExecutable + "\"";
    commandLine += " -M q35,accel=" + cfg.accelerators;
    commandLine += " -cpu qemu64 -m " + cfg.memory;
    commandLine += " -smp " + std::to_string(cfg.smpCores);

    // UEFI firmware: read-only code plus a writable variable store. Booting a
    // Windows guest without both is what makes QEMU exit immediately.
    if (!cfg.biosPath.empty() && fs::exists(cfg.biosPath)) {
        commandLine += " -drive if=pflash,format=raw,unit=0,readonly=on,file=\"" +
                       cfg.biosPath + "\"";
    }
    if (!cfg.uefiVarsPath.empty() && fs::exists(cfg.uefiVarsPath)) {
        commandLine += " -drive if=pflash,format=raw,unit=1,file=\"" +
                       cfg.uefiVarsPath + "\"";
    }

    commandLine += " -drive file=\"" + overlay.path + "\",format=qcow2,if=virtio";

    // Isolated: user-mode networking only, no inbound forwarding, no display.
    commandLine += " -net user -net nic,model=virtio";
    commandLine += " -device usb-ehci,id=ehci -device usb-tablet";
    commandLine += " -display none";

    std::cout << "  Command:      " << commandLine << "\n";

    uint32_t qemuPid = 0;
    bool launched = false;

#ifdef _WIN32
    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};

    std::string mutableCommand = commandLine;
    launched = CreateProcessA(nullptr, mutableCommand.data(), nullptr, nullptr, FALSE,
                              CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process) != 0;
    if (launched) {
        qemuPid = process.dwProcessId;
        CloseHandle(process.hThread);
    }
#endif

    Check(launched, "qemu-system process launched");
    if (!launched) {
        sandbox.ReleaseOverlay(overlay.id);
        std::cout << "\n  Boot could not be started; overlay released.\n";
        return 1;
    }

    std::cout << "  QEMU PID:     " << qemuPid << "\n";
    std::cout << "  Launched:     " << Timestamp() << "\n";

    // Record ownership so a crash leaves a recoverable, attributable overlay.
    {
        std::ofstream owner(overlay.path + ".owner");
        owner << qemuPid;
    }

    // Let the guest boot far enough to write to its disk.
    const int bootSeconds = 90;
    std::cout << "  Booting for " << bootSeconds << " s...\n";

    uint64_t overlayPeak = overlayInitial;
    bool stayedAlive = true;

    for (int elapsed = 0; elapsed < bootSeconds; elapsed += 5) {
        std::this_thread::sleep_for(std::chrono::seconds(5));

        const uint64_t current = FileSizeOf(overlay.path);
        if (current > overlayPeak) overlayPeak = current;

#ifdef _WIN32
        DWORD exitCode = 0;
        if (GetExitCodeProcess(process.hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
            stayedAlive = false;
            std::cout << "  QEMU exited early after " << elapsed << " s (code "
                      << exitCode << ")\n";
            break;
        }
#endif
        std::cout << "    " << elapsed + 5 << "s  overlay " << current << " bytes\n";
    }

    Check(stayedAlive, "QEMU stayed alive through the boot window");
    std::cout << "  Overlay peak: " << overlayPeak << " bytes\n";

    // Guest writes landing in the overlay is the whole point of the design.
    Check(overlayPeak > overlayInitial,
          "guest writes went into the overlay (it grew during boot)");

    // --- Shutdown -----------------------------------------------------------
    std::cout << "\n  --- Shutdown and cleanup ---\n";
#ifdef _WIN32
    TerminateProcess(process.hProcess, 0);
    WaitForSingleObject(process.hProcess, 15000);
    CloseHandle(process.hProcess);
#endif
    std::cout << "  Terminated:   " << Timestamp() << "\n";

    // Give Windows a moment to release the file handle.
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // --- The base must be untouched ----------------------------------------
    const uint64_t baseSizeAfter = FileSizeOf(basePath);
    Check(baseSizeAfter == baseSizeBefore, "base image size unchanged after a live boot");

    std::cout << "  Re-hashing the base image...\n";
    const std::string baseHashAfter = Sha256Stream::OfFile(basePath.string());
    std::cout << "  Base SHA-256: " << baseHashAfter << "\n";

    Check(baseHashAfter == baseHashBefore,
          "base image is byte-identical after the guest booted and wrote to disk");

    // --- Overlay cleanup ----------------------------------------------------
    {
        std::error_code ec;
        fs::remove(overlay.path + ".owner", ec);
    }

    auto released = sandbox.ReleaseOverlay(overlay.id);
    Check(released.Ok(), std::string("overlay released") +
                         (released.Ok() ? "" : (": " + released.Error())));
    Check(!fs::exists(overlay.path), "overlay file removed after the run");

    // --- Failure-path cleanup ------------------------------------------------
    std::cout << "\n  --- Failure-path cleanup ---\n";
    {
        auto orphan = sandbox.CreateOverlay("orphaned");
        Check(orphan.Ok(), "second overlay created to simulate a crashed run");

        if (orphan.Ok()) {
            // An owner PID that is definitely not running: exactly the state a
            // crashed Dracula leaves behind.
            std::ofstream owner(orphan.Value().path + ".owner");
            owner << 0xFFFFFFFEu;
            owner.close();

            std::vector<std::string> removed;
            auto swept = sandbox.SweepStaleOverlays(removed);
            Check(swept.Ok(), "stale overlay sweep ran");
            Check(!fs::exists(orphan.Value().path),
                  "an overlay from a crashed run is cleaned up on sweep");
        }
    }

    // Nothing may be left behind.
    auto remaining = sandbox.ListOverlays();
    Check(remaining.empty(), "no overlays remain after the acceptance run");

    // --- Summary ------------------------------------------------------------
    std::cout << "\n=== LIVE QEMU Acceptance: " << (g_checks - g_failures)
              << "/" << g_checks << " passed ===\n";
    std::cout << "  Finished:     " << Timestamp() << "\n\n";

    return g_failures == 0 ? 0 : 1;
}
