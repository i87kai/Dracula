#include "common/config.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>

namespace Sandbox {

    std::string ConfigManager::Trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(" \t\r\n");
        return str.substr(first, (last - first + 1));
    }

    ConfigManager::ConfigManager(const std::string& configFilePath) {
        ApplyDefaults();
        LoadFromFile(configFilePath);
    }

    void ConfigManager::ApplyDefaults() {
        // Trace defaults
        m_traceOptions.monitorConsoleOutput = true;
        m_traceOptions.monitorProcesses = true;
        m_traceOptions.monitorFiles = true;
        m_traceOptions.monitorRegistry = true;
        m_traceOptions.monitorNetwork = true;
        m_traceOptions.executionTimeoutSeconds = 60;

        // VM defaults
        m_vmConfig.hostListenIp = "0.0.0.0";
        m_vmConfig.hostPort = 8899;
        m_vmConfig.guestTargetDir = "C:\\Sandbox\\";
        m_vmConfig.headlessMode = false;

        // QEMU defaults
        m_qemuConfig.qemuExecutable = "C:\\Program Files\\qemu\\qemu-system-x86_64.exe";
        m_qemuConfig.biosPath = "C:\\Program Files\\qemu\\share\\edk2-x86_64-code.fd";
        m_qemuConfig.uefiVarsPath = "uefi_vars.fd";
        m_qemuConfig.diskPath = "win10.vdi";
        m_qemuConfig.guestShareDir = "guest_share";
        m_qemuConfig.memory = "4G";
        m_qemuConfig.smpCores = 2;
        m_qemuConfig.accelerators = "whpx:tcg";
        m_qemuConfig.headless = false;

        // Tools defaults
        m_toolsConfig.yaraExecutable = "tools/yara64.exe";
        m_toolsConfig.yaraRulesPath = "rules/packers.yar";
        m_toolsConfig.peSievePath = "tools/pe-sieve64.exe";
        m_toolsConfig.defaultReport = "sandbox_report.txt";
    }

    ConfigManager& ConfigManager::Instance() {
        static ConfigManager s_instance;
        return s_instance;
    }

    bool ConfigManager::LoadFromFile(const std::string& configFilePath) {
        std::ifstream file(configFilePath);
        if (!file.is_open()) {
            return false;
        }

        std::string line;
        std::string currentSection;

        while (std::getline(file, line)) {
            line = Trim(line);
            if (line.empty() || line[0] == ';' || line[0] == '#') {
                continue;
            }

            if (line.front() == '[' && line.back() == ']') {
                currentSection = line.substr(1, line.length() - 2);
                std::transform(currentSection.begin(), currentSection.end(), currentSection.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                continue;
            }

            size_t eqPos = line.find('=');
            if (eqPos == std::string::npos) continue;

            std::string key = Trim(line.substr(0, eqPos));
            std::string val = Trim(line.substr(eqPos + 1));
            std::transform(key.begin(), key.end(), key.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            auto parseBool = [](const std::string& v) -> bool {
                std::string s = v;
                std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                return (s == "true" || s == "1" || s == "yes" || s == "on");
            };

            if (currentSection == "qemu") {
                if (key == "qemu_executable" || key == "executable") m_qemuConfig.qemuExecutable = val;
                else if (key == "bios_path" || key == "bios") m_qemuConfig.biosPath = val;
                else if (key == "uefi_vars_path" || key == "uefi_vars") m_qemuConfig.uefiVarsPath = val;
                else if (key == "disk_path" || key == "disk") m_qemuConfig.diskPath = val;
                else if (key == "guest_share_dir" || key == "share_dir") m_qemuConfig.guestShareDir = val;
                else if (key == "memory") m_qemuConfig.memory = val;
                else if (key == "smp_cores" || key == "smp") {
                    try { m_qemuConfig.smpCores = static_cast<uint32_t>(std::stoul(val)); } catch (...) {}
                }
                else if (key == "accelerators" || key == "accel") m_qemuConfig.accelerators = val;
                else if (key == "headless") {
                    m_qemuConfig.headless = parseBool(val);
                    m_vmConfig.headlessMode = m_qemuConfig.headless;
                }
            } else if (currentSection == "network") {
                if (key == "host_listen_ip" || key == "listen_ip" || key == "ip") m_vmConfig.hostListenIp = val;
                else if (key == "host_listen_port" || key == "port") {
                    try { m_vmConfig.hostPort = static_cast<uint16_t>(std::stoul(val)); } catch (...) {}
                }
            } else if (currentSection == "tracing") {
                if (key == "monitor_stdout") m_traceOptions.monitorConsoleOutput = parseBool(val);
                else if (key == "monitor_processes") m_traceOptions.monitorProcesses = parseBool(val);
                else if (key == "monitor_files") m_traceOptions.monitorFiles = parseBool(val);
                else if (key == "monitor_registry") m_traceOptions.monitorRegistry = parseBool(val);
                else if (key == "monitor_network") m_traceOptions.monitorNetwork = parseBool(val);
                else if (key == "execution_timeout_seconds" || key == "timeout") {
                    try { m_traceOptions.executionTimeoutSeconds = static_cast<uint32_t>(std::stoul(val)); } catch (...) {}
                }
                else if (key == "guest_target_dir") m_vmConfig.guestTargetDir = val;
            } else if (currentSection == "tools") {
                if (key == "yara_executable" || key == "yara") m_toolsConfig.yaraExecutable = val;
                else if (key == "yara_rules_path" || key == "yara_rules") m_toolsConfig.yaraRulesPath = val;
                else if (key == "pe_sieve_path" || key == "pe_sieve") m_toolsConfig.peSievePath = val;
                else if (key == "default_report" || key == "report") m_toolsConfig.defaultReport = val;
            }
        }

        return true;
    }

    bool ConfigManager::SaveToFile(const std::string& configFilePath) const {
        std::ofstream file(configFilePath);
        if (!file.is_open()) return false;

        file << "; ============================================================================\n"
             << ";  Sandbox Orchestrator & Dynamic Execution Tracer Configuration\n"
             << "; ============================================================================\n\n"
             << "[QEMU]\n"
             << "qemu_executable = " << m_qemuConfig.qemuExecutable << "\n"
             << "bios_path = " << m_qemuConfig.biosPath << "\n"
             << "uefi_vars_path = " << m_qemuConfig.uefiVarsPath << "\n"
             << "disk_path = " << m_qemuConfig.diskPath << "\n"
             << "guest_share_dir = " << m_qemuConfig.guestShareDir << "\n"
             << "memory = " << m_qemuConfig.memory << "\n"
             << "smp_cores = " << m_qemuConfig.smpCores << "\n"
             << "accelerators = " << m_qemuConfig.accelerators << "\n"
             << "headless = " << (m_qemuConfig.headless ? "true" : "false") << "\n\n"
             << "[Network]\n"
             << "host_listen_ip = " << m_vmConfig.hostListenIp << "\n"
             << "host_listen_port = " << m_vmConfig.hostPort << "\n\n"
             << "[Tracing]\n"
             << "monitor_stdout = " << (m_traceOptions.monitorConsoleOutput ? "true" : "false") << "\n"
             << "monitor_processes = " << (m_traceOptions.monitorProcesses ? "true" : "false") << "\n"
             << "monitor_files = " << (m_traceOptions.monitorFiles ? "true" : "false") << "\n"
             << "monitor_registry = " << (m_traceOptions.monitorRegistry ? "true" : "false") << "\n"
             << "monitor_network = " << (m_traceOptions.monitorNetwork ? "true" : "false") << "\n"
             << "execution_timeout_seconds = " << m_traceOptions.executionTimeoutSeconds << "\n"
             << "guest_target_dir = " << m_vmConfig.guestTargetDir << "\n\n"
             << "[Tools]\n"
             << "yara_executable = " << m_toolsConfig.yaraExecutable << "\n"
             << "yara_rules_path = " << m_toolsConfig.yaraRulesPath << "\n"
             << "pe_sieve_path = " << m_toolsConfig.peSievePath << "\n"
             << "default_report = " << m_toolsConfig.defaultReport << "\n";

        return true;
    }

} // namespace Sandbox
