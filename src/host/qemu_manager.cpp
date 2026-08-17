#include "host/qemu_manager.h"
#include <iostream>
#include <sstream>
#include <filesystem>

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
    }

    bool QemuManager::CheckQemuInstallation() {
        if (std::filesystem::exists(m_config.qemuExecutable)) {
            return true;
        }

        // Try searching in standard PATH
#ifdef _WIN32
        char foundPath[MAX_PATH];
        if (SearchPathA(nullptr, "qemu-system-x86_64.exe", nullptr, MAX_PATH, foundPath, nullptr) > 0) {
            m_config.qemuExecutable = foundPath;
            return true;
        }
#endif
        return false;
    }

    bool QemuManager::StartQemu(bool headless, uint16_t hostPort) {
#ifdef _WIN32
        if (!CheckQemuInstallation()) {
            std::cerr << "[-] QEMU executable not found at: " << m_config.qemuExecutable << std::endl;
            return false;
        }

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

        ss << " -snapshot"
           << " -net user,hostfwd=tcp::" << hostPort << "-:" << hostPort << " -net nic,model=virtio"
           << " -device usb-ehci,id=ehci -device usb-tablet";

        if (headless) {
            ss << " -display none";
        } else {
            ss << " -vga std";
        }

        std::string cmdLine = ss.str();
        std::vector<char> cmdVec(cmdLine.begin(), cmdLine.end());
        cmdVec.push_back('\0');

        STARTUPINFOA si;
        ZeroMemory(&si, sizeof(STARTUPINFOA));
        si.cb = sizeof(STARTUPINFOA);

        PROCESS_INFORMATION pi;
        ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

        DWORD creationFlags = headless ? CREATE_NO_WINDOW : 0;

        BOOL ok = CreateProcessA(
            nullptr,
            cmdVec.data(),
            nullptr,
            nullptr,
            FALSE,
            creationFlags,
            nullptr,
            nullptr,
            &si,
            &pi
        );

        if (!ok) {
            std::cerr << "[-] Failed to launch QEMU process." << std::endl;
            return false;
        }

        m_hProcess = pi.hProcess;
        m_processId = pi.dwProcessId;
        CloseHandle(pi.hThread);

        return true;
#else
        return false;
#endif
    }

    void QemuManager::StopQemu() {
#ifdef _WIN32
        if (m_hProcess) {
            TerminateProcess(static_cast<HANDLE>(m_hProcess), 0);
            CloseHandle(static_cast<HANDLE>(m_hProcess));
            m_hProcess = nullptr;
            m_processId = 0;
        }
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

} // namespace Sandbox
