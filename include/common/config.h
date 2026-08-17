#pragma once

#include "types.h"
#include <string>
#include <unordered_map>
#include <filesystem>

namespace Sandbox {

    struct QemuConfig {
        std::string qemuExecutable = "C:\\Program Files\\qemu\\qemu-system-x86_64.exe";
        std::string biosPath       = "C:\\Program Files\\qemu\\share\\edk2-x86_64-code.fd";
        std::string uefiVarsPath   = "uefi_vars.fd";
        std::string diskPath       = "win10.vdi";
        std::string guestShareDir  = "guest_share";
        std::string memory         = "4G";
        uint32_t    smpCores       = 2;
        std::string accelerators   = "whpx:tcg";
        bool        headless       = false;
    };

    struct ToolsConfig {
        std::string yaraExecutable = "tools/yara64.exe";
        std::string yaraRulesPath  = "rules/packers.yar";
        std::string peSievePath    = "tools/pe-sieve64.exe";
        std::string defaultReport  = "sandbox_report.txt";
    };

    class ConfigManager {
    public:
        ConfigManager() = default;
        explicit ConfigManager(const std::string& configFilePath);

        bool LoadFromFile(const std::string& configFilePath);
        bool SaveToFile(const std::string& configFilePath) const;

        const VMConfig& GetVMConfig() const { return m_vmConfig; }
        VMConfig& GetVMConfig() { return m_vmConfig; }

        const TraceOptions& GetTraceOptions() const { return m_traceOptions; }
        TraceOptions& GetTraceOptions() { return m_traceOptions; }

        const QemuConfig& GetQemuConfig() const { return m_qemuConfig; }
        QemuConfig& GetQemuConfig() { return m_qemuConfig; }

        const ToolsConfig& GetToolsConfig() const { return m_toolsConfig; }
        ToolsConfig& GetToolsConfig() { return m_toolsConfig; }

        static ConfigManager& Instance();

    private:
        VMConfig     m_vmConfig;
        TraceOptions m_traceOptions;
        QemuConfig   m_qemuConfig;
        ToolsConfig  m_toolsConfig;

        void ApplyDefaults();
        static std::string Trim(const std::string& str);
    };

} // namespace Sandbox
