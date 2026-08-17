#include "core/environment_profile.h"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace Dracula {

    namespace {

        std::string Lower(std::string s) {
            std::transform(s.begin(), s.end(), s.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return s;
        }

        std::string BoolText(bool v) { return v ? "true" : "false"; }

        std::string Bytes(uint64_t b) {
            std::ostringstream ss;
            ss << (b / (1024ULL * 1024 * 1024)) << " GB";
            return ss.str();
        }

        void AddNormalization(std::vector<NormalizationRecord>& out,
                              const std::string& profile,
                              const std::string& property,
                              const std::string& baseline,
                              const std::string& supplied,
                              const std::string& reason,
                              const std::string& source) {
            if (baseline == supplied) return;
            out.push_back({property, baseline, supplied, reason, profile, source});
        }

    } // namespace

    const char* ProfileKindToString(ProfileKind kind) {
        switch (kind) {
            case ProfileKind::Baseline:         return "Baseline";
            case ProfileKind::Realistic:        return "Realistic";
            case ProfileKind::AnalysisFriendly: return "AnalysisFriendly";
        }
        return "Unknown";
    }

    bool ParseProfileKind(const std::string& name, ProfileKind& out) {
        const std::string n = Lower(name);
        if (n == "baseline" || n == "default") { out = ProfileKind::Baseline; return true; }
        if (n == "realistic")                  { out = ProfileKind::Realistic; return true; }
        if (n == "analysis-friendly" || n == "analysisfriendly" ||
            n == "analysis_friendly" || n == "friendly") {
            out = ProfileKind::AnalysisFriendly;
            return true;
        }
        return false;
    }

    const char* ClaimChannelToString(ClaimChannel channel) {
        switch (channel) {
            case ClaimChannel::CpuidLeaf:          return "CPUID";
            case ClaimChannel::OsApi:              return "OS API";
            case ClaimChannel::FirmwareTable:      return "Firmware";
            case ClaimChannel::DeviceMetadata:     return "Device";
            case ClaimChannel::TimingModel:        return "Timing";
            case ClaimChannel::ProfileDeclaration: return "Profile";
        }
        return "Unknown";
    }

    // ─── Profiles ───────────────────────────────────────────────────────────

    EnvironmentProfile EnvironmentProfile::Baseline() {
        EnvironmentProfile p;
        p.kind = ProfileKind::Baseline;
        p.name = "Baseline";
        p.description =
            "Dracula's default analysis environment. Honest about being one: the "
            "hypervisor bit is set, hypervisor vendor leaves answer, device and "
            "firmware metadata are virtual, and the clock only advances as "
            "instructions retire.";

        p.cpu.vendor = "GenuineIntel";
        p.cpu.hypervisorPresent = true;
        p.cpu.hypervisorLeavesExposed = true;
        p.cpu.hypervisorVendor = "KVMKVMKVM";
        p.cpu.logicalProcessors = 2;

        // The legacy Dracula clock: it barely moves, and a sleep is a no-op.
        p.timing.nanosPerInstruction = 0;
        p.timing.sleepAdvancesClock = false;
        p.timing.tscBase = 0;
        p.timing.tickCountBaseMs = 50000;   // matches the historical GetTickCount
        p.timing.bootUptimeMs = 50000;

        p.host.processorCount = 2;
        p.host.physicalMemoryBytes = 4ULL * 1024 * 1024 * 1024;
        p.host.diskSizeBytes = 64ULL * 1024 * 1024 * 1024;
        p.host.diskModel = "QEMU HARDDISK";
        p.host.firmwareVendor = "QEMU";
        p.host.firmwareProduct = "Standard PC (Q35 + ICH9, 2009)";
        p.host.macOui = "52:54:00";
        p.host.nicDescription = "Red Hat VirtIO Ethernet Adapter";
        p.host.screenWidth = 1024;
        p.host.screenHeight = 768;
        p.host.lastInputIdleMs = 0;
        p.host.userName = "sandbox";
        p.host.computerName = "SANDBOX-PC";
        p.host.runningProcesses = { "vmtoolsd.exe" };
        p.host.loadedDrivers = { "vioscsi.sys" };
        p.host.registryArtifacts = { "HARDWARE\\ACPI\\DSDT\\QEMU" };
        return p;
    }

    EnvironmentProfile EnvironmentProfile::Realistic() {
        EnvironmentProfile p = Baseline();
        p.kind = ProfileKind::Realistic;
        p.name = "Realistic";
        p.description =
            "Plausible desktop characteristics with the evidence left intact. "
            "Topology, memory and the clock look like a real workstation, but "
            "the hypervisor bit and virtual device metadata are NOT hidden: this "
            "profile makes the environment ordinary, it does not make it lie.";

        p.cpu.logicalProcessors = 8;
        p.cpu.hypervisorPresent = true;          // still honest
        p.cpu.hypervisorLeavesExposed = true;

        // A clock that behaves like a real 3.6 GHz machine: instructions cost
        // time, and a sleep really does elapse.
        p.timing.nanosPerInstruction = 1;        // ~1 GHz effective retire rate
        p.timing.sleepAdvancesClock = true;
        p.timing.tickCountBaseMs = 3600000;      // one hour of uptime
        p.timing.bootUptimeMs = 3600000;
        p.timing.tscBase = 3600000ULL * 3600000ULL; // uptime * tscHz/1000

        p.host.processorCount = 8;
        p.host.physicalMemoryBytes = 32ULL * 1024 * 1024 * 1024;
        p.host.diskSizeBytes = 1024ULL * 1024 * 1024 * 1024;
        p.host.screenWidth = 1920;
        p.host.screenHeight = 1080;
        p.host.lastInputIdleMs = 4200;           // a user was recently active
        p.host.userName = "adammiller";
        p.host.computerName = "DESKTOP-K7F2Q1L";
        return p;
    }

    EnvironmentProfile EnvironmentProfile::AnalysisFriendly() {
        EnvironmentProfile p = Realistic();
        p.kind = ProfileKind::AnalysisFriendly;
        p.name = "AnalysisFriendly";
        p.description =
            "Selected analysis-environment indicators are normalized so that "
            "environment-gated code paths can be reached and studied. Every "
            "normalized value is recorded in the audit trail; nothing is hidden "
            "silently.";

        p.cpu.hypervisorPresent = false;
        p.cpu.hypervisorLeavesExposed = false;
        p.cpu.hypervisorVendor.clear();

        p.host.diskModel = "Samsung SSD 980 PRO 1TB";
        p.host.firmwareVendor = "American Megatrends Inc.";
        p.host.firmwareProduct = "B550 AORUS ELITE";
        p.host.macOui = "3C:7C:3F";
        p.host.nicDescription = "Realtek PCIe GbE Family Controller";
        p.host.beingDebugged = false;
        p.host.ntGlobalFlag = 0;
        p.host.runningProcesses.clear();
        p.host.loadedDrivers.clear();
        p.host.registryArtifacts.clear();
        return p;
    }

    EnvironmentProfile EnvironmentProfile::FromKind(ProfileKind kind) {
        switch (kind) {
            case ProfileKind::Realistic:        return Realistic();
            case ProfileKind::AnalysisFriendly: return AnalysisFriendly();
            case ProfileKind::Baseline:         break;
        }
        return Baseline();
    }

    std::vector<NormalizationRecord> EnvironmentProfile::NormalizationsAgainstBaseline() const {
        std::vector<NormalizationRecord> out;
        if (kind == ProfileKind::Baseline) return out;

        const EnvironmentProfile base = EnvironmentProfile::Baseline();
        const std::string reasonRealistic =
            "Realistic profile exposes ordinary desktop characteristics without "
            "suppressing virtualization evidence.";
        const std::string reasonFriendly =
            "AnalysisFriendly profile normalizes this indicator so environment-"
            "gated code paths become reachable.";
        const std::string& reason =
            (kind == ProfileKind::AnalysisFriendly) ? reasonFriendly : reasonRealistic;

        AddNormalization(out, name, "CPUID.HypervisorPresent",
                         BoolText(base.cpu.hypervisorPresent),
                         BoolText(cpu.hypervisorPresent), reason, "CPUID leaf 1 ECX[31]");
        AddNormalization(out, name, "CPUID.HypervisorVendorLeaves",
                         BoolText(base.cpu.hypervisorLeavesExposed),
                         BoolText(cpu.hypervisorLeavesExposed), reason, "CPUID leaf 0x40000000");
        AddNormalization(out, name, "CPUID.LogicalProcessors",
                         std::to_string(base.cpu.logicalProcessors),
                         std::to_string(cpu.logicalProcessors), reason, "CPUID leaf 1 EBX[23:16]");
        AddNormalization(out, name, "System.ProcessorCount",
                         std::to_string(base.host.processorCount),
                         std::to_string(host.processorCount), reason, "kernel32!GetSystemInfo");
        AddNormalization(out, name, "System.PhysicalMemory",
                         Bytes(base.host.physicalMemoryBytes),
                         Bytes(host.physicalMemoryBytes), reason, "kernel32!GlobalMemoryStatusEx");
        AddNormalization(out, name, "Disk.Model", base.host.diskModel, host.diskModel,
                         reason, "Device metadata");
        AddNormalization(out, name, "Firmware.Vendor", base.host.firmwareVendor,
                         host.firmwareVendor, reason, "SMBIOS");
        AddNormalization(out, name, "Firmware.Product", base.host.firmwareProduct,
                         host.firmwareProduct, reason, "SMBIOS");
        AddNormalization(out, name, "Nic.MacOui", base.host.macOui, host.macOui,
                         reason, "Adapter metadata");
        AddNormalization(out, name, "Screen.Resolution",
                         std::to_string(base.host.screenWidth) + "x" + std::to_string(base.host.screenHeight),
                         std::to_string(host.screenWidth) + "x" + std::to_string(host.screenHeight),
                         reason, "user32!GetSystemMetrics");
        AddNormalization(out, name, "Timing.SleepAdvancesClock",
                         BoolText(base.timing.sleepAdvancesClock),
                         BoolText(timing.sleepAdvancesClock),
                         "Accelerated sleeps advance every modelled clock together so "
                         "the timing sources stay mutually consistent.",
                         "Timing model");
        AddNormalization(out, name, "Timing.NanosPerInstruction",
                         std::to_string(base.timing.nanosPerInstruction),
                         std::to_string(timing.nanosPerInstruction),
                         "Instruction retirement charges logical time so measured "
                         "durations are non-zero.",
                         "Timing model");
        AddNormalization(out, name, "System.LastInputIdle",
                         std::to_string(base.host.lastInputIdleMs) + " ms",
                         std::to_string(host.lastInputIdleMs) + " ms", reason,
                         "user32!GetLastInputInfo");
        return out;
    }

    // ─── Consistency graph ──────────────────────────────────────────────────

    namespace {

        void Claim(EnvironmentConsistencyGraph& g, const std::string& property,
                   const std::string& value, ClaimChannel channel,
                   const std::string& origin, bool virtualization) {
            g.claims.push_back({property, value, channel, origin, virtualization});
        }

        const EnvironmentClaim* FindClaim(const EnvironmentConsistencyGraph& g,
                                          const std::string& property,
                                          ClaimChannel channel) {
            for (const auto& c : g.claims) {
                if (c.property == property && c.channel == channel) return &c;
            }
            return nullptr;
        }

        void Contradict(EnvironmentConsistencyGraph& g, const std::string& property,
                        const EnvironmentClaim* a, const EnvironmentClaim* b,
                        const std::string& explanation, FindingSeverity sev) {
            if (!a || !b) return;
            g.contradictions.push_back({property, *a, *b, explanation, sev});
        }

        bool LooksVirtualString(const std::string& s) {
            static const char* kMarkers[] = {
                "qemu", "kvm", "vmware", "virtualbox", "vbox", "virtio", "xen",
                "bochs", "parallels", "hyper-v", "microsoft corporation", "innotek"
            };
            const std::string l = Lower(s);
            for (const char* m : kMarkers) {
                if (l.find(m) != std::string::npos) return true;
            }
            return false;
        }

    } // namespace

    EnvironmentConsistencyGraph BuildConsistencyGraph(const EnvironmentProfile& profile) {
        EnvironmentConsistencyGraph g;
        g.profileName = profile.name;

        // ── Claims ──────────────────────────────────────────────────────────
        Claim(g, "Cpu.Virtualized", profile.cpu.hypervisorPresent ? "true" : "false",
              ClaimChannel::CpuidLeaf, "CPUID leaf 1 ECX bit 31",
              profile.cpu.hypervisorPresent);

        Claim(g, "Cpu.HypervisorVendorLeaf",
              profile.cpu.hypervisorLeavesExposed
                  ? (profile.cpu.hypervisorVendor.empty() ? "(exposed, empty)"
                                                          : profile.cpu.hypervisorVendor)
                  : "(not exposed)",
              ClaimChannel::CpuidLeaf, "CPUID leaf 0x40000000",
              profile.cpu.hypervisorLeavesExposed);

        Claim(g, "Cpu.LogicalProcessors", std::to_string(profile.cpu.logicalProcessors),
              ClaimChannel::CpuidLeaf, "CPUID leaf 1 EBX[23:16]", false);
        Claim(g, "Cpu.LogicalProcessors", std::to_string(profile.host.processorCount),
              ClaimChannel::OsApi, "kernel32!GetSystemInfo", false);

        Claim(g, "System.PhysicalMemory", Bytes(profile.host.physicalMemoryBytes),
              ClaimChannel::OsApi, "kernel32!GlobalMemoryStatusEx",
              profile.host.physicalMemoryBytes < (2ULL * 1024 * 1024 * 1024));

        Claim(g, "Firmware.Vendor", profile.host.firmwareVendor,
              ClaimChannel::FirmwareTable, "SMBIOS system manufacturer",
              LooksVirtualString(profile.host.firmwareVendor));
        Claim(g, "Firmware.Product", profile.host.firmwareProduct,
              ClaimChannel::FirmwareTable, "SMBIOS product name",
              LooksVirtualString(profile.host.firmwareProduct));

        Claim(g, "Disk.Model", profile.host.diskModel, ClaimChannel::DeviceMetadata,
              "Storage device product id", LooksVirtualString(profile.host.diskModel));
        Claim(g, "Nic.Vendor", profile.host.nicDescription, ClaimChannel::DeviceMetadata,
              "Network adapter description", LooksVirtualString(profile.host.nicDescription));
        Claim(g, "Nic.MacOui", profile.host.macOui, ClaimChannel::DeviceMetadata,
              "Adapter MAC prefix",
              profile.host.macOui == "52:54:00" || profile.host.macOui == "00:0C:29" ||
              profile.host.macOui == "08:00:27" || profile.host.macOui == "00:05:69" ||
              profile.host.macOui == "00:1C:42" || profile.host.macOui == "00:15:5D");

        for (const auto& proc : profile.host.runningProcesses) {
            Claim(g, "Process.GuestTooling", proc, ClaimChannel::DeviceMetadata,
                  "Process list", true);
        }
        for (const auto& drv : profile.host.loadedDrivers) {
            Claim(g, "Driver.GuestTooling", drv, ClaimChannel::DeviceMetadata,
                  "Loaded driver list", true);
        }
        for (const auto& key : profile.host.registryArtifacts) {
            Claim(g, "Registry.VirtualizationKey", key, ClaimChannel::DeviceMetadata,
                  "Registry", true);
        }

        Claim(g, "Timing.Model",
              profile.timing.nanosPerInstruction == 0 ? "frozen" : "advancing",
              ClaimChannel::TimingModel, "Virtual clock policy",
              profile.timing.nanosPerInstruction == 0);
        Claim(g, "Timing.SleepAdvancesClock",
              profile.timing.sleepAdvancesClock ? "true" : "false",
              ClaimChannel::TimingModel, "Sleep policy",
              !profile.timing.sleepAdvancesClock);

        Claim(g, "User.InputActivity",
              profile.host.lastInputIdleMs == 0 ? "none modelled"
                                                : std::to_string(profile.host.lastInputIdleMs) + " ms",
              ClaimChannel::OsApi, "user32!GetLastInputInfo",
              profile.host.lastInputIdleMs == 0);

        Claim(g, "Environment.Intent",
              profile.kind == ProfileKind::AnalysisFriendly
                  ? "present as physical hardware"
                  : (profile.kind == ProfileKind::Realistic ? "present as an ordinary desktop"
                                                            : "present as an analysis environment"),
              ClaimChannel::ProfileDeclaration, "Profile kind", false);

        // ── Contradictions ──────────────────────────────────────────────────

        // CPU topology reported two different ways.
        {
            const auto* cpuid = FindClaim(g, "Cpu.LogicalProcessors", ClaimChannel::CpuidLeaf);
            const auto* api   = FindClaim(g, "Cpu.LogicalProcessors", ClaimChannel::OsApi);
            if (cpuid && api && cpuid->value != api->value) {
                Contradict(g, "Cpu.LogicalProcessors", cpuid, api,
                           "CPUID reports " + cpuid->value + " logical processors but the OS "
                           "API reports " + api->value + ". A sample that reads both can tell "
                           "the topology is synthetic.",
                           FindingSeverity::High);
            }
        }

        // Hypervisor bit cleared while the hypervisor vendor leaf still answers.
        if (!profile.cpu.hypervisorPresent && profile.cpu.hypervisorLeavesExposed) {
            Contradict(g, "Cpu.Virtualized",
                       FindClaim(g, "Cpu.Virtualized", ClaimChannel::CpuidLeaf),
                       FindClaim(g, "Cpu.HypervisorVendorLeaf", ClaimChannel::CpuidLeaf),
                       "CPUID claims no hypervisor is present, but the hypervisor vendor "
                       "leaf at 0x40000000 still answers. Reading both is a one-instruction "
                       "test that the environment is lying.",
                       FindingSeverity::Critical);
        }

        // Claims to be physical while virtual firmware / devices remain visible.
        if (!profile.cpu.hypervisorPresent) {
            const char* virtualProps[] = { "Firmware.Vendor", "Firmware.Product",
                                           "Disk.Model", "Nic.Vendor", "Nic.MacOui" };
            for (const char* prop : virtualProps) {
                for (const auto& c : g.claims) {
                    if (c.property == prop && c.indicatesVirtualization) {
                        Contradict(g, prop,
                                   FindClaim(g, "Cpu.Virtualized", ClaimChannel::CpuidLeaf), &c,
                                   std::string("The profile presents as physical hardware but ") +
                                   prop + " still reports \"" + c.value + "\", which is a "
                                   "virtualization artifact.",
                                   FindingSeverity::High);
                        break;
                    }
                }
            }
            for (const auto& c : g.claims) {
                if ((c.property == "Process.GuestTooling" ||
                     c.property == "Driver.GuestTooling" ||
                     c.property == "Registry.VirtualizationKey")) {
                    Contradict(g, c.property,
                               FindClaim(g, "Cpu.Virtualized", ClaimChannel::CpuidLeaf), &c,
                               "The profile presents as physical hardware but guest tooling "
                               "artifact \"" + c.value + "\" is still enumerable.",
                               FindingSeverity::High);
                }
            }
        }

        // A clock that never advances is impossible on real hardware.
        if (profile.timing.nanosPerInstruction == 0 && profile.timing.sleepAdvancesClock) {
            Contradict(g, "Timing.Model",
                       FindClaim(g, "Timing.Model", ClaimChannel::TimingModel),
                       FindClaim(g, "Timing.SleepAdvancesClock", ClaimChannel::TimingModel),
                       "Sleeps advance the clock but retiring instructions cost no time at "
                       "all, so any code that measures work between two sleeps sees a "
                       "physically impossible result.",
                       FindingSeverity::Medium);
        }
        if (!profile.cpu.hypervisorPresent && profile.timing.nanosPerInstruction == 0) {
            Contradict(g, "Timing.Model",
                       FindClaim(g, "Cpu.Virtualized", ClaimChannel::CpuidLeaf),
                       FindClaim(g, "Timing.Model", ClaimChannel::TimingModel),
                       "The profile presents as physical hardware, but the clock does not "
                       "advance as instructions retire. Any timing measurement returns zero.",
                       FindingSeverity::High);
        }
        if (profile.timing.tscHz == 0 || profile.timing.qpcHz == 0) {
            Contradict(g, "Timing.Model",
                       FindClaim(g, "Timing.Model", ClaimChannel::TimingModel),
                       FindClaim(g, "Timing.SleepAdvancesClock", ClaimChannel::TimingModel),
                       "A timing source is configured with a zero frequency, which no real "
                       "clock can have.",
                       FindingSeverity::High);
        }

        // Physical presentation with no user ever having touched the machine.
        if (!profile.cpu.hypervisorPresent && profile.host.lastInputIdleMs == 0) {
            Contradict(g, "User.InputActivity",
                       FindClaim(g, "Cpu.Virtualized", ClaimChannel::CpuidLeaf),
                       FindClaim(g, "User.InputActivity", ClaimChannel::OsApi),
                       "The profile presents as an ordinary desktop but models no user input "
                       "activity at all, which is itself a well-known sandbox tell.",
                       FindingSeverity::Medium);
        }

        // ── Fingerprintability ──────────────────────────────────────────────
        int virtualizationMarkers = 0;
        for (const auto& c : g.claims) {
            if (c.indicatesVirtualization) virtualizationMarkers++;
        }

        // Visible markers make the environment detectable. Contradictions are
        // worse than markers: they prove the environment is actively lying,
        // which no ordinary machine ever does.
        int score = virtualizationMarkers * 7;
        for (const auto& c : g.contradictions) {
            switch (c.severity) {
                case FindingSeverity::Critical: score += 30; break;
                case FindingSeverity::High:     score += 18; break;
                case FindingSeverity::Medium:   score += 10; break;
                default:                        score += 5;  break;
            }
        }
        g.fingerprintability = std::clamp(score, 0, 100);
        if (g.fingerprintability >= 70)      g.fingerprintabilityLabel = "High";
        else if (g.fingerprintability >= 40) g.fingerprintabilityLabel = "Moderate";
        else if (g.fingerprintability >= 15) g.fingerprintabilityLabel = "Low";
        else                                 g.fingerprintabilityLabel = "Minimal";

        return g;
    }

    std::vector<Finding> EnvironmentConsistencyGraph::ToFindings() const {
        std::vector<Finding> out;
        for (const auto& c : contradictions) {
            Finding f;
            f.id = "PROFILE_COHERENCE_WARNING";
            f.category = "AntiAnalysis / Environment";
            f.severity = c.severity;
            f.confidence = FindingConfidence::High;
            f.title = "Environment profile contradicts itself: " + c.property;
            f.description = c.explanation;
            f.evidence = std::string(ClaimChannelToString(c.first.channel)) + " says \"" +
                         c.first.value + "\" (" + c.first.origin + ") but " +
                         ClaimChannelToString(c.second.channel) + " says \"" +
                         c.second.value + "\" (" + c.second.origin + ")";
            f.source = "Environment Coherence Validator";
            f.tags = { "AntiEvasion", "ProfileCoherence", profileName };
            out.push_back(f);
        }
        return out;
    }

} // namespace Dracula
