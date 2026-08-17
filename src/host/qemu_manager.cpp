#include "host/qemu_manager.h"
#include <chrono>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace Sandbox {

    QemuManager::QemuManager(const QemuConfig& config) : m_config(config) {
        CheckQemuInstallation();
    }

    QemuManager::QemuManager(const std::string& diskPath) {
        m_config = ConfigManager::Instance().GetQemuConfig();
        m_config.diskPath = diskPath;
        CheckQemuInstallation();
    }

    QemuManager::~QemuManager() {
        StopQemu();
        CloseDiagnosticPipe();
    }

    bool QemuManager::CheckQemuInstallation() {
        if (std::filesystem::exists(m_config.qemuExecutable)) {
            return true;
        }

#ifdef _WIN32
        char foundPath[MAX_PATH];
        if (SearchPathA(nullptr, "qemu-system-x86_64.exe", nullptr, MAX_PATH, foundPath, nullptr) > 0) {
            m_config.qemuExecutable = foundPath;
            return true;
        }
#endif
        return false;
    }

    std::string QemuManager::BuildCommandLine(bool headless) const {
        std::ostringstream ss;
        ss << "\"" << m_config.qemuExecutable << "\""
           << " -M q35,accel=" << m_config.accelerators
           << " -cpu qemu64 -m " << m_config.memory
           << " -smp " << m_config.smpCores;

        if (std::filesystem::exists(m_config.biosPath)) {
            ss << " -drive if=pflash,format=raw,unit=0,readonly=on,file=\"" << m_config.biosPath << "\"";
        }
        if (std::filesystem::exists(m_config.uefiVarsPath)) {
            ss << " -drive if=pflash,format=raw,unit=1,file=\"" << m_config.uefiVarsPath << "\"";
        }
        if (std::filesystem::exists(m_config.diskPath)) {
            ss << " -drive file=\"" << m_config.diskPath << "\",format=vdi,if=virtio";
        }
        if (std::filesystem::exists(m_config.guestShareDir)) {
            ss << " -drive file=fat:ro:" << m_config.guestShareDir << ",format=raw";
        }

        ss << " -snapshot";

        // User-mode networking, OUTBOUND ONLY.
        //
        // SLIRP hands the guest a NAT with the host reachable at 10.0.2.2, which
        // is all the telemetry link needs: the GuestAgent connects out to the
        // host's listener. There is deliberately no `hostfwd` rule here. An
        // inbound forward would make QEMU bind a host port, and the only port it
        // would ever be pointed at is the one Dracula's listener is already
        // holding, which is exactly how QEMU used to die on startup.
        ss << " -net user -net nic,model=virtio"
           << " -device usb-ehci,id=ehci -device usb-tablet";

        if (headless) {
            ss << " -display none";
        } else {
            ss << " -vga std";
        }

        return ss.str();
    }

    bool QemuManager::StartQemu(bool headless) {
#ifdef _WIN32
        m_lastError.clear();
        m_diagnostics.clear();

        if (!CheckQemuInstallation()) {
            m_lastError = "QEMU executable not found at: " + m_config.qemuExecutable;
            return false;
        }
        if (!std::filesystem::exists(m_config.diskPath)) {
            m_lastError = "Guest disk image not found at: " + m_config.diskPath;
            return false;
        }

        const std::string cmdLine = BuildCommandLine(headless);
        std::vector<char> cmdVec(cmdLine.begin(), cmdLine.end());
        cmdVec.push_back('\0');

        // Capture QEMU's stderr. Without this, an argument QEMU rejects is
        // printed to a console nobody is reading and the failure looks like a
        // guest that simply never booted.
        CloseDiagnosticPipe();
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = nullptr;

        HANDLE readPipe = nullptr, writePipe = nullptr;
        const bool havePipe = CreatePipe(&readPipe, &writePipe, &sa, 64 * 1024) != 0;
        if (havePipe) {
            SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);
            m_stderrRead = readPipe;
            m_stderrWrite = writePipe;
        }

        STARTUPINFOA si{};
        si.cb = sizeof(STARTUPINFOA);
        if (havePipe) {
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdError = writePipe;
            si.hStdOutput = writePipe;
            si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        }

        PROCESS_INFORMATION pi{};
        const DWORD creationFlags = headless ? CREATE_NO_WINDOW : 0;

        const BOOL ok = CreateProcessA(
            nullptr, cmdVec.data(), nullptr, nullptr,
            havePipe ? TRUE : FALSE,
            creationFlags, nullptr, nullptr, &si, &pi);

        if (!ok) {
            const DWORD err = GetLastError();
            std::ostringstream ss;
            ss << "failed to launch QEMU (CreateProcess error " << err << "): " << cmdLine;
            m_lastError = ss.str();
            CloseDiagnosticPipe();
            return false;
        }

        m_hProcess = pi.hProcess;
        m_processId = pi.dwProcessId;
        CloseHandle(pi.hThread);

        // The parent must drop its copy of the write end, otherwise reading the
        // pipe would never see EOF.
        if (m_stderrWrite) {
            CloseHandle(static_cast<HANDLE>(m_stderrWrite));
            m_stderrWrite = nullptr;
        }

        // Settle window. QEMU validates its arguments during startup, so a
        // configuration it refuses shows up as an exit within the first second
        // or so. Catching it here turns a silent non-boot into a real error.
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1500);
        while (std::chrono::steady_clock::now() < deadline) {
            if (!IsRunning()) {
                DrainDiagnostics();
                std::ostringstream ss;
                ss << "QEMU exited immediately after launch (exit code " << ExitCode() << ")";
                if (!m_diagnostics.empty()) {
                    ss << ": " << m_diagnostics;
                }
                m_lastError = ss.str();
                StopQemu();
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        return true;
#else
        (void)headless;
        m_lastError = "the QEMU sandbox is only implemented for Windows hosts";
        return false;
#endif
    }

    void QemuManager::DrainDiagnostics() {
#ifdef _WIN32
        if (!m_stderrRead) return;

        HANDLE readPipe = static_cast<HANDLE>(m_stderrRead);
        std::string collected;
        char buffer[1024];

        for (;;) {
            DWORD available = 0;
            if (!PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available, nullptr) || available == 0) {
                break;
            }
            DWORD read = 0;
            const DWORD want = (available < sizeof(buffer)) ? available : static_cast<DWORD>(sizeof(buffer));
            if (!ReadFile(readPipe, buffer, want, &read, nullptr) || read == 0) {
                break;
            }
            collected.append(buffer, read);
            if (collected.size() > 8192) break;
        }

        // Collapse to a single readable line for the error message.
        std::string flattened;
        for (char c : collected) {
            if (c == '\r') continue;
            flattened += (c == '\n') ? ' ' : c;
        }
        while (!flattened.empty() && flattened.back() == ' ') flattened.pop_back();
        m_diagnostics = flattened;
#endif
    }

    void QemuManager::CloseDiagnosticPipe() {
#ifdef _WIN32
        if (m_stderrRead) {
            CloseHandle(static_cast<HANDLE>(m_stderrRead));
            m_stderrRead = nullptr;
        }
        if (m_stderrWrite) {
            CloseHandle(static_cast<HANDLE>(m_stderrWrite));
            m_stderrWrite = nullptr;
        }
#endif
    }

    void QemuManager::StopQemu() {
#ifdef _WIN32
        if (m_hProcess) {
            // Terminating discards the in-memory -snapshot delta; the base disk
            // image is never written, so the guest rolls back automatically.
            if (IsRunning()) {
                TerminateProcess(static_cast<HANDLE>(m_hProcess), 0);
                WaitForSingleObject(static_cast<HANDLE>(m_hProcess), 5000);
            }
            CloseHandle(static_cast<HANDLE>(m_hProcess));
            m_hProcess = nullptr;
            m_processId = 0;
        }
        CloseDiagnosticPipe();
#endif
    }

    bool QemuManager::IsRunning() const {
#ifdef _WIN32
        if (!m_hProcess) return false;
        DWORD exitCode = 0;
        if (GetExitCodeProcess(static_cast<HANDLE>(m_hProcess), &exitCode)) {
            return exitCode == STILL_ACTIVE;
        }
        return false;
#else
        return false;
#endif
    }

    uint32_t QemuManager::ExitCode() const {
#ifdef _WIN32
        if (!m_hProcess) return 0;
        DWORD exitCode = 0;
        if (GetExitCodeProcess(static_cast<HANDLE>(m_hProcess), &exitCode)) {
            return (exitCode == STILL_ACTIVE) ? 0 : static_cast<uint32_t>(exitCode);
        }
        return 0;
#else
        return 0;
#endif
    }

} // namespace Sandbox
