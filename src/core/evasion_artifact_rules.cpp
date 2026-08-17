#include "core/evasion_artifact_rules.h"
#include <algorithm>

namespace Dracula {

    namespace {
        std::string Lower(std::string s) {
            std::transform(s.begin(), s.end(), s.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return s;
        }
    }

    const char* ArtifactTypeToString(ArtifactType type) {
        switch (type) {
            case ArtifactType::Vendor:         return "vendor";
            case ArtifactType::Process:        return "process";
            case ArtifactType::Driver:         return "driver";
            case ArtifactType::Service:        return "service";
            case ArtifactType::DeviceName:     return "device";
            case ArtifactType::RegistryKey:    return "registry";
            case ArtifactType::FirmwareString: return "firmware";
            case ArtifactType::MacPrefix:      return "mac";
            case ArtifactType::AnalysisTool:   return "analysis tool";
            case ArtifactType::Username:       return "username";
            case ArtifactType::FilePath:       return "path";
        }
        return "unknown";
    }

    const std::vector<ArtifactRule>& EvasionArtifactRules() {
        static const std::vector<ArtifactRule> rules = {
            // ── Bare vendor names ───────────────────────────────────────────
            // Low on their own: documentation, driver packages, hypervisor
            // management tools and countless legitimate programs contain them.
            {"vmware",      "VMware",     ArtifactType::Vendor, EvasionCategory::AntiVmDevice,
             FindingConfidence::Low, "A bare vendor name. Appears in ordinary software that merely supports the platform."},
            {"virtualbox",  "VirtualBox", ArtifactType::Vendor, EvasionCategory::AntiVmDevice,
             FindingConfidence::Low, "A bare vendor name."},
            {"vbox",        "VirtualBox", ArtifactType::Vendor, EvasionCategory::AntiVmDevice,
             FindingConfidence::Low, "A bare vendor name."},
            {"qemu",        "QEMU",       ArtifactType::Vendor, EvasionCategory::AntiVmDevice,
             FindingConfidence::Low, "A bare vendor name."},
            {"innotek",     "VirtualBox", ArtifactType::Vendor, EvasionCategory::AntiVmSmbios,
             FindingConfidence::Medium, "VirtualBox's original SMBIOS manufacturer; rare outside firmware checks."},
            {"parallels",   "Parallels",  ArtifactType::Vendor, EvasionCategory::AntiVmDevice,
             FindingConfidence::Low, "A bare vendor name."},
            {"xen",         "Xen",        ArtifactType::Vendor, EvasionCategory::AntiVmDevice,
             FindingConfidence::Low, "Short and highly collision-prone; weak on its own."},
            {"bochs",       "Bochs",      ArtifactType::Vendor, EvasionCategory::AntiVmSmbios,
             FindingConfidence::Medium, "Rare outside emulator detection."},

            // ── CPUID hypervisor vendor signatures ──────────────────────────
            // These 12-byte strings exist for exactly one purpose.
            {"kvmkvmkvm",     "KVM",        ArtifactType::FirmwareString, EvasionCategory::AntiVmHypervisorVendor,
             FindingConfidence::High, "CPUID leaf 0x40000000 hypervisor signature; no legitimate non-detection use."},
            {"vmwarevmware",  "VMware",     ArtifactType::FirmwareString, EvasionCategory::AntiVmHypervisorVendor,
             FindingConfidence::High, "CPUID hypervisor signature."},
            {"vboxvboxvbox",  "VirtualBox", ArtifactType::FirmwareString, EvasionCategory::AntiVmHypervisorVendor,
             FindingConfidence::High, "CPUID hypervisor signature."},
            {"microsoft hv",  "Hyper-V",    ArtifactType::FirmwareString, EvasionCategory::AntiVmHypervisorVendor,
             FindingConfidence::High, "CPUID hypervisor signature."},
            {"xenvmmxenvmm",  "Xen",        ArtifactType::FirmwareString, EvasionCategory::AntiVmHypervisorVendor,
             FindingConfidence::High, "CPUID hypervisor signature."},
            {"prl hyperv",    "Parallels",  ArtifactType::FirmwareString, EvasionCategory::AntiVmHypervisorVendor,
             FindingConfidence::High, "CPUID hypervisor signature."},
            {"tcgtcgtcgtcg",  "QEMU TCG",   ArtifactType::FirmwareString, EvasionCategory::AntiVmHypervisorVendor,
             FindingConfidence::High, "QEMU's software-emulation CPUID signature."},

            // ── Guest tooling processes ─────────────────────────────────────
            {"vmtoolsd.exe",     "VMware",     ArtifactType::Process, EvasionCategory::AntiVmProcess,
             FindingConfidence::Medium, "VMware guest tools daemon."},
            {"vmwaretray.exe",   "VMware",     ArtifactType::Process, EvasionCategory::AntiVmProcess,
             FindingConfidence::Medium, "VMware guest tools."},
            {"vmwareuser.exe",   "VMware",     ArtifactType::Process, EvasionCategory::AntiVmProcess,
             FindingConfidence::Medium, "VMware guest tools."},
            {"vboxservice.exe",  "VirtualBox", ArtifactType::Process, EvasionCategory::AntiVmProcess,
             FindingConfidence::Medium, "VirtualBox guest additions service."},
            {"vboxtray.exe",     "VirtualBox", ArtifactType::Process, EvasionCategory::AntiVmProcess,
             FindingConfidence::Medium, "VirtualBox guest additions."},
            {"qemu-ga.exe",      "QEMU",       ArtifactType::Process, EvasionCategory::AntiVmProcess,
             FindingConfidence::Medium, "QEMU guest agent."},
            {"prl_tools.exe",    "Parallels",  ArtifactType::Process, EvasionCategory::AntiVmProcess,
             FindingConfidence::Medium, "Parallels guest tools."},
            {"xenservice.exe",   "Xen",        ArtifactType::Process, EvasionCategory::AntiVmProcess,
             FindingConfidence::Medium, "Xen guest service."},

            // ── Guest drivers ───────────────────────────────────────────────
            {"vmhgfs.sys",   "VMware",     ArtifactType::Driver, EvasionCategory::AntiVmDriver,
             FindingConfidence::Medium, "VMware shared folders driver."},
            {"vmmouse.sys",  "VMware",     ArtifactType::Driver, EvasionCategory::AntiVmDriver,
             FindingConfidence::Medium, "VMware pointing device driver."},
            {"vmci.sys",     "VMware",     ArtifactType::Driver, EvasionCategory::AntiVmDriver,
             FindingConfidence::Medium, "VMware VMCI driver."},
            {"vboxguest.sys","VirtualBox", ArtifactType::Driver, EvasionCategory::AntiVmDriver,
             FindingConfidence::Medium, "VirtualBox guest driver."},
            {"vboxsf.sys",   "VirtualBox", ArtifactType::Driver, EvasionCategory::AntiVmDriver,
             FindingConfidence::Medium, "VirtualBox shared folders driver."},
            {"vboxmouse.sys","VirtualBox", ArtifactType::Driver, EvasionCategory::AntiVmDriver,
             FindingConfidence::Medium, "VirtualBox pointing device driver."},
            {"vioscsi.sys",  "QEMU",       ArtifactType::Driver, EvasionCategory::AntiVmDriver,
             FindingConfidence::Medium, "VirtIO SCSI driver."},
            {"netkvm.sys",   "KVM",        ArtifactType::Driver, EvasionCategory::AntiVmDriver,
             FindingConfidence::Medium, "VirtIO network driver."},
            {"balloon.sys",  "QEMU",       ArtifactType::Driver, EvasionCategory::AntiVmDriver,
             FindingConfidence::Medium, "VirtIO balloon driver."},

            // ── Services ────────────────────────────────────────────────────
            {"vmtools",   "VMware",     ArtifactType::Service, EvasionCategory::AntiVmService,
             FindingConfidence::Medium, "VMware tools service name."},
            {"vboxservice", "VirtualBox", ArtifactType::Service, EvasionCategory::AntiVmService,
             FindingConfidence::Medium, "VirtualBox guest additions service name."},
            {"vmicheartbeat", "Hyper-V", ArtifactType::Service, EvasionCategory::AntiVmService,
             FindingConfidence::Medium, "Hyper-V integration service."},

            // ── Device / disk identifiers ───────────────────────────────────
            {"qemu harddisk",   "QEMU",       ArtifactType::DeviceName, EvasionCategory::AntiVmDisk,
             FindingConfidence::High, "Storage product id unique to QEMU virtual disks."},
            {"vbox harddisk",   "VirtualBox", ArtifactType::DeviceName, EvasionCategory::AntiVmDisk,
             FindingConfidence::High, "VirtualBox virtual disk product id."},
            {"vmware virtual",  "VMware",     ArtifactType::DeviceName, EvasionCategory::AntiVmDisk,
             FindingConfidence::High, "VMware virtual device identifier."},
            {"virtual hd",      "Generic",    ArtifactType::DeviceName, EvasionCategory::AntiVmDisk,
             FindingConfidence::Medium, "Generic virtual disk identifier."},
            {"\\\\.\\vboxguest","VirtualBox", ArtifactType::DeviceName, EvasionCategory::AntiVmDevice,
             FindingConfidence::High, "Direct device object open; only used to detect the hypervisor."},
            {"\\\\.\\vmci",     "VMware",     ArtifactType::DeviceName, EvasionCategory::AntiVmDevice,
             FindingConfidence::High, "Direct device object open."},
            {"\\\\.\\hgfs",     "VMware",     ArtifactType::DeviceName, EvasionCategory::AntiVmDevice,
             FindingConfidence::High, "Direct device object open."},

            // ── Registry keys ───────────────────────────────────────────────
            {"hardware\\acpi\\dsdt\\vbox__", "VirtualBox", ArtifactType::RegistryKey, EvasionCategory::AntiVmAcpi,
             FindingConfidence::High, "ACPI DSDT table name; queried only to fingerprint the platform."},
            {"hardware\\acpi\\dsdt\\qemu",   "QEMU",       ArtifactType::RegistryKey, EvasionCategory::AntiVmAcpi,
             FindingConfidence::High, "ACPI DSDT table name."},
            {"software\\oracle\\virtualbox guest additions", "VirtualBox", ArtifactType::RegistryKey, EvasionCategory::AntiVmRegistry,
             FindingConfidence::High, "Guest additions registry key."},
            {"software\\vmware, inc.\\vmware tools", "VMware", ArtifactType::RegistryKey, EvasionCategory::AntiVmRegistry,
             FindingConfidence::High, "VMware tools registry key."},
            {"system\\currentcontrolset\\services\\disk\\enum", "Generic", ArtifactType::RegistryKey, EvasionCategory::AntiVmDisk,
             FindingConfidence::Medium, "Enumerating disk device ids is a common way to read the virtual disk model."},
            {"hardware\\description\\system\\systembiosversion", "Generic", ArtifactType::RegistryKey, EvasionCategory::AntiVmSmbios,
             FindingConfidence::Medium, "BIOS version string, frequently compared against hypervisor values."},

            // ── MAC prefixes ────────────────────────────────────────────────
            {"00:05:69", "VMware",     ArtifactType::MacPrefix, EvasionCategory::AntiVmMacOui,
             FindingConfidence::Medium, "VMware OUI."},
            {"00:0c:29", "VMware",     ArtifactType::MacPrefix, EvasionCategory::AntiVmMacOui,
             FindingConfidence::Medium, "VMware OUI."},
            {"00:1c:14", "VMware",     ArtifactType::MacPrefix, EvasionCategory::AntiVmMacOui,
             FindingConfidence::Medium, "VMware OUI."},
            {"00:50:56", "VMware",     ArtifactType::MacPrefix, EvasionCategory::AntiVmMacOui,
             FindingConfidence::Medium, "VMware OUI."},
            {"08:00:27", "VirtualBox", ArtifactType::MacPrefix, EvasionCategory::AntiVmMacOui,
             FindingConfidence::Medium, "VirtualBox OUI."},
            {"52:54:00", "QEMU",       ArtifactType::MacPrefix, EvasionCategory::AntiVmMacOui,
             FindingConfidence::Medium, "QEMU/KVM OUI."},
            {"00:15:5d", "Hyper-V",    ArtifactType::MacPrefix, EvasionCategory::AntiVmMacOui,
             FindingConfidence::Medium, "Hyper-V OUI."},
            {"00:1c:42", "Parallels",  ArtifactType::MacPrefix, EvasionCategory::AntiVmMacOui,
             FindingConfidence::Medium, "Parallels OUI."},

            // ── Analysis and instrumentation tooling ────────────────────────
            {"ollydbg.exe",   "Analysis", ArtifactType::AnalysisTool, EvasionCategory::AntiDebugProcessCheck,
             FindingConfidence::Medium, "Debugger process name."},
            {"x64dbg.exe",    "Analysis", ArtifactType::AnalysisTool, EvasionCategory::AntiDebugProcessCheck,
             FindingConfidence::Medium, "Debugger process name."},
            {"x32dbg.exe",    "Analysis", ArtifactType::AnalysisTool, EvasionCategory::AntiDebugProcessCheck,
             FindingConfidence::Medium, "Debugger process name."},
            {"ida.exe",       "Analysis", ArtifactType::AnalysisTool, EvasionCategory::AntiDebugProcessCheck,
             FindingConfidence::Low, "Disassembler process name; short and collision-prone."},
            {"ida64.exe",     "Analysis", ArtifactType::AnalysisTool, EvasionCategory::AntiDebugProcessCheck,
             FindingConfidence::Medium, "Disassembler process name."},
            {"windbg.exe",    "Analysis", ArtifactType::AnalysisTool, EvasionCategory::AntiDebugProcessCheck,
             FindingConfidence::Medium, "Debugger process name."},
            {"procmon.exe",   "Analysis", ArtifactType::AnalysisTool, EvasionCategory::AntiSandboxEnvironment,
             FindingConfidence::Medium, "Monitoring tool process name."},
            {"procexp.exe",   "Analysis", ArtifactType::AnalysisTool, EvasionCategory::AntiSandboxEnvironment,
             FindingConfidence::Medium, "Monitoring tool process name."},
            {"wireshark.exe", "Analysis", ArtifactType::AnalysisTool, EvasionCategory::AntiSandboxEnvironment,
             FindingConfidence::Medium, "Network capture tool process name."},
            {"fiddler.exe",   "Analysis", ArtifactType::AnalysisTool, EvasionCategory::AntiSandboxEnvironment,
             FindingConfidence::Medium, "Proxy tool process name."},
            {"pin.exe",       "Analysis", ArtifactType::AnalysisTool, EvasionCategory::AntiInstrumentationCheck,
             FindingConfidence::Low, "Intel Pin instrumentation driver; short and collision-prone."},
            {"pinvm.dll",     "Analysis", ArtifactType::AnalysisTool, EvasionCategory::AntiInstrumentationCheck,
             FindingConfidence::High, "Intel Pin runtime module; checked only to detect instrumentation."},
            {"frida",         "Analysis", ArtifactType::AnalysisTool, EvasionCategory::AntiInstrumentationCheck,
             FindingConfidence::Medium, "Dynamic instrumentation framework."},
            {"sbiedll.dll",   "Sandboxie",ArtifactType::AnalysisTool, EvasionCategory::AntiSandboxEnvironment,
             FindingConfidence::High, "Sandboxie module; loaded only inside that sandbox."},
            {"dbghelp.dll",   "Analysis", ArtifactType::AnalysisTool, EvasionCategory::AntiDebugApi,
             FindingConfidence::Low, "Ordinary debugging helper library; used legitimately for crash reporting."},

            // ── Sandbox-typical identities ──────────────────────────────────
            {"sandbox",    "Generic", ArtifactType::Username, EvasionCategory::AntiSandboxEnvironment,
             FindingConfidence::Low, "Common sandbox account name; also an ordinary English word."},
            {"malware",    "Generic", ArtifactType::Username, EvasionCategory::AntiSandboxEnvironment,
             FindingConfidence::Low, "Common analysis account name."},
            {"virus",      "Generic", ArtifactType::Username, EvasionCategory::AntiSandboxEnvironment,
             FindingConfidence::Low, "Common analysis account name."},
            {"cuckoo",     "Cuckoo",  ArtifactType::AnalysisTool, EvasionCategory::AntiSandboxEnvironment,
             FindingConfidence::Medium, "Cuckoo Sandbox."},
            {"c:\\analysis","Generic", ArtifactType::FilePath, EvasionCategory::AntiSandboxFileArtifact,
             FindingConfidence::Medium, "Analysis working directory."},
            {"\\sample.exe","Generic", ArtifactType::FilePath, EvasionCategory::AntiSandboxFileArtifact,
             FindingConfidence::Medium, "Sandboxes commonly rename the sample; checking for it is a sandbox test."},
        };
        return rules;
    }

    const ArtifactRule* MatchArtifact(const std::string& candidate) {
        if (candidate.size() < 3) return nullptr;
        const std::string needle = Lower(candidate);

        // Longest pattern wins so "qemu harddisk" is not reported as "qemu".
        const ArtifactRule* best = nullptr;
        for (const auto& rule : EvasionArtifactRules()) {
            if (needle.find(rule.pattern) == std::string::npos) continue;
            if (!best || rule.pattern.size() > best->pattern.size()) best = &rule;
        }
        return best;
    }

    const std::vector<EnvironmentApiRule>& EnvironmentApiRules() {
        static const std::vector<EnvironmentApiRule> rules = {
            // Timing
            {"QueryPerformanceCounter", "kernel32.dll", EvasionCategory::AntiVmTiming, "High resolution time", false},
            {"GetTickCount",            "kernel32.dll", EvasionCategory::AntiVmTiming, "Millisecond tick count", false},
            {"GetTickCount64",          "kernel32.dll", EvasionCategory::AntiVmTiming, "Millisecond tick count", false},
            {"timeGetTime",             "winmm.dll",    EvasionCategory::AntiVmTiming, "Millisecond tick count", false},
            {"GetSystemTimeAsFileTime", "kernel32.dll", EvasionCategory::AntiVmTiming, "Wall clock", false},
            {"Sleep",                   "kernel32.dll", EvasionCategory::AntiSandboxSleep, "Execution delay", false},
            {"SleepEx",                 "kernel32.dll", EvasionCategory::AntiSandboxSleep, "Execution delay", false},
            {"NtDelayExecution",        "ntdll.dll",    EvasionCategory::AntiSandboxSleep, "Execution delay", true},
            {"WaitForSingleObject",     "kernel32.dll", EvasionCategory::AntiSandboxSleep, "Execution delay", false},

            // Resources and topology
            {"GetSystemInfo",           "kernel32.dll", EvasionCategory::AntiVmCpuTopology, "Processor count", false},
            {"GetNativeSystemInfo",     "kernel32.dll", EvasionCategory::AntiVmCpuTopology, "Processor count", false},
            {"GetActiveProcessorCount", "kernel32.dll", EvasionCategory::AntiVmCpuTopology, "Processor count", false},
            {"GlobalMemoryStatusEx",    "kernel32.dll", EvasionCategory::AntiVmMemory, "Physical memory", false},
            {"GetPhysicallyInstalledSystemMemory", "kernel32.dll", EvasionCategory::AntiVmMemory, "Physical memory", false},
            {"GetDiskFreeSpaceExA",     "kernel32.dll", EvasionCategory::AntiVmDisk, "Disk size", false},
            {"GetDiskFreeSpaceExW",     "kernel32.dll", EvasionCategory::AntiVmDisk, "Disk size", false},

            // Firmware and devices
            {"GetSystemFirmwareTable",  "kernel32.dll", EvasionCategory::AntiVmSmbios, "Firmware tables", true},
            {"EnumSystemFirmwareTables","kernel32.dll", EvasionCategory::AntiVmSmbios, "Firmware tables", true},
            {"SetupDiGetClassDevsA",    "setupapi.dll", EvasionCategory::AntiVmDevice, "Device enumeration", false},
            {"SetupDiEnumDeviceInfo",   "setupapi.dll", EvasionCategory::AntiVmDevice, "Device enumeration", false},
            {"GetAdaptersInfo",         "iphlpapi.dll", EvasionCategory::AntiVmMacOui, "Network adapter MAC", false},
            {"GetAdaptersAddresses",    "iphlpapi.dll", EvasionCategory::AntiVmMacOui, "Network adapter MAC", false},

            // Enumeration
            {"CreateToolhelp32Snapshot","kernel32.dll", EvasionCategory::AntiVmProcess, "Process list", false},
            {"Process32First",          "kernel32.dll", EvasionCategory::AntiVmProcess, "Process list", false},
            {"Process32Next",           "kernel32.dll", EvasionCategory::AntiVmProcess, "Process list", false},
            {"EnumServicesStatusExA",   "advapi32.dll", EvasionCategory::AntiVmService, "Service list", false},
            {"EnumDeviceDrivers",       "psapi.dll",    EvasionCategory::AntiVmDriver, "Driver list", false},
            {"RegOpenKeyExA",           "advapi32.dll", EvasionCategory::AntiVmRegistry, "Registry", false},
            {"RegOpenKeyExW",           "advapi32.dll", EvasionCategory::AntiVmRegistry, "Registry", false},
            {"RegQueryValueExA",        "advapi32.dll", EvasionCategory::AntiVmRegistry, "Registry", false},

            // User presence and display
            {"GetLastInputInfo",        "user32.dll",   EvasionCategory::AntiVmInputActivity, "User input activity", true},
            {"GetCursorPos",            "user32.dll",   EvasionCategory::AntiVmInputActivity, "Pointer position", false},
            {"GetSystemMetrics",        "user32.dll",   EvasionCategory::AntiVmScreen, "Screen dimensions", false},
            {"EnumDisplayDevicesA",     "user32.dll",   EvasionCategory::AntiVmScreen, "Display devices", false},
            {"GetForegroundWindow",     "user32.dll",   EvasionCategory::AntiSandboxUserActivity, "Foreground window", false},

            // Uptime and identity
            {"GetComputerNameA",        "kernel32.dll", EvasionCategory::AntiSandboxEnvironment, "Computer name", false},
            {"GetComputerNameW",        "kernel32.dll", EvasionCategory::AntiSandboxEnvironment, "Computer name", false},
            {"GetUserNameA",            "advapi32.dll", EvasionCategory::AntiSandboxEnvironment, "User name", false},
            {"GetUserNameW",            "advapi32.dll", EvasionCategory::AntiSandboxEnvironment, "User name", false},

            // Debugger state
            {"IsDebuggerPresent",         "kernel32.dll", EvasionCategory::AntiDebugApi, "Debugger presence", true},
            {"CheckRemoteDebuggerPresent","kernel32.dll", EvasionCategory::AntiDebugApi, "Debugger presence", true},
            {"NtQueryInformationProcess", "ntdll.dll",    EvasionCategory::AntiDebugApi, "Debugger presence", true},
            {"OutputDebugStringA",        "kernel32.dll", EvasionCategory::AntiDebugApi, "Debugger presence", false},
            {"GetThreadContext",          "kernel32.dll", EvasionCategory::AntiDebugHardwareBreakpoint, "Hardware breakpoint registers", false},
            {"NtSetInformationThread",    "ntdll.dll",    EvasionCategory::AntiDebugApi, "Debugger detachment", true},
            {"AddVectoredExceptionHandler","kernel32.dll",EvasionCategory::AntiDebugException, "Exception handling", false},
            {"SetUnhandledExceptionFilter","kernel32.dll",EvasionCategory::AntiDebugException, "Exception handling", false},
        };
        return rules;
    }

    const EnvironmentApiRule* MatchEnvironmentApi(const std::string& apiName) {
        const std::string needle = Lower(apiName);
        for (const auto& rule : EnvironmentApiRules()) {
            if (Lower(rule.api) == needle) return &rule;
        }
        return nullptr;
    }

} // namespace Dracula
