#pragma once

//
// Dracula controlled analysis-environment profiles.
//
// An EnvironmentProfile is the single place that decides what a sample running
// inside a Dracula analysis environment is allowed to observe about its host:
// CPU identity, CPUID answers, topology, memory, disk, firmware, timing policy
// and debugger state. Nothing else in the tree may invent environment values.
//
// Two hard rules, enforced by the types below:
//
//   1. Every value Dracula supplies that differs from the Baseline default is
//      recorded as a NormalizationRecord. Dracula never silently changes what a
//      sample sees.
//   2. A profile is validated before use. Hiding one virtualization marker while
//      exposing a contradictory one makes an environment MORE fingerprintable,
//      not less, so contradictions are reported rather than ignored.
//
// This models a controlled analysis environment. It is not, and cannot be, a
// guarantee that a virtual environment is indistinguishable from real hardware.
//

#include "common/findings.h"
#include <string>
#include <vector>
#include <cstdint>

namespace Dracula {

    // ─── Profile kinds ──────────────────────────────────────────────────────

    enum class ProfileKind {
        Baseline,          // Dracula's default analysis environment
        Realistic,         // Plausible desktop characteristics, evidence intact
        AnalysisFriendly   // Selected analysis indicators normalized (recorded)
    };

    const char* ProfileKindToString(ProfileKind kind);
    bool ParseProfileKind(const std::string& name, ProfileKind& out);

    // ─── CPU identity and CPUID behaviour ───────────────────────────────────

    struct CpuIdentityModel {
        std::string vendor = "GenuineIntel";      // leaf 0: EBX/EDX/ECX
        std::string brand  = "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz"; // leaves 0x8000000[234]
        uint32_t    maxBasicLeaf    = 0x16;
        uint32_t    family          = 6;
        uint32_t    model           = 158;
        uint32_t    stepping        = 13;
        uint32_t    logicalProcessors = 8;        // leaf 1 EBX[23:16], leaf 0xB

        // Hypervisor exposure. hypervisorPresent drives leaf 1 ECX bit 31;
        // hypervisorLeavesExposed drives whether leaf 0x40000000 answers at all.
        bool        hypervisorPresent       = true;
        bool        hypervisorLeavesExposed = true;
        std::string hypervisorVendor        = "KVMKVMKVM\0\0\0";
    };

    // ─── Timing policy ──────────────────────────────────────────────────────
    //
    // Every clock Dracula exposes is derived from one logical nanosecond
    // counter (see VirtualTimeState), so the policy only chooses rates and
    // whether sleeping advances logical time. It cannot desynchronize clocks.

    struct TimingPolicy {
        uint64_t tscHz  = 3600000000ULL;   // timestamp counter rate
        uint64_t qpcHz  = 10000000ULL;     // QueryPerformanceFrequency (10 MHz)
        uint64_t nanosPerInstruction = 0;  // logical time charged per instruction
        uint64_t tscBase = 0;              // TSC value at logical time zero
        uint64_t tickCountBaseMs = 0;      // GetTickCount at logical time zero
        uint64_t bootUptimeMs = 0;         // system uptime at logical time zero

        // When true a simulated Sleep(n) advances logical time by n ms instead
        // of being a no-op. This keeps every clock consistent with the sleep.
        bool     sleepAdvancesClock = false;
    };

    // ─── Host environment model ─────────────────────────────────────────────

    struct HostEnvironmentModel {
        uint64_t    physicalMemoryBytes = 4ULL * 1024 * 1024 * 1024;
        uint32_t    processorCount      = 2;      // what the OS APIs report
        uint64_t    diskSizeBytes       = 64ULL * 1024 * 1024 * 1024;
        std::string diskModel           = "QEMU HARDDISK";
        std::string firmwareVendor      = "QEMU";
        std::string firmwareProduct     = "Standard PC (Q35 + ICH9, 2009)";
        std::string macOui              = "52:54:00";   // QEMU/KVM OUI
        std::string nicDescription      = "Red Hat VirtIO Ethernet Adapter";
        uint32_t    screenWidth         = 1024;
        uint32_t    screenHeight        = 768;
        uint32_t    lastInputIdleMs     = 0;       // 0 == no user activity modelled
        bool        beingDebugged       = false;
        uint32_t    ntGlobalFlag        = 0;
        std::string userName            = "sandbox";
        std::string computerName        = "SANDBOX-PC";

        // Environment artifacts a guest could enumerate. Modelled so the
        // coherence validator can reason about them; not all are observable
        // from every backend.
        std::vector<std::string> runningProcesses = { "vmtoolsd.exe" };
        std::vector<std::string> loadedDrivers    = { "vioscsi.sys" };
        std::vector<std::string> registryArtifacts = {
            "HARDWARE\\ACPI\\DSDT\\QEMU"
        };
    };

    // ─── Audit trail for supplied values ────────────────────────────────────

    struct NormalizationRecord {
        std::string property;        // "CPUID.HypervisorPresent"
        std::string observedValue;   // what Baseline would have shown
        std::string suppliedValue;   // what this profile actually supplies
        std::string reason;          // why the profile does this
        std::string profile;         // profile name
        std::string source;          // "CPUID", "Win32 HLE", "Timing model"
    };

    // ─── The profile ────────────────────────────────────────────────────────

    struct EnvironmentProfile {
        ProfileKind          kind = ProfileKind::Baseline;
        std::string          name = "Baseline";
        std::string          description;
        CpuIdentityModel     cpu;
        TimingPolicy         timing;
        HostEnvironmentModel host;

        static EnvironmentProfile Baseline();
        static EnvironmentProfile Realistic();
        static EnvironmentProfile AnalysisFriendly();
        static EnvironmentProfile FromKind(ProfileKind kind);

        // Every value this profile supplies that differs from Baseline.
        std::vector<NormalizationRecord> NormalizationsAgainstBaseline() const;
    };

    // ─── Environment consistency graph ──────────────────────────────────────
    //
    // Environment facts are modelled as claims made by a particular observable
    // channel. Two claims about the same property from different channels that
    // disagree are a contradiction: a sample that reads both channels can tell
    // it is being analysed, regardless of what either channel says on its own.

    enum class ClaimChannel {
        CpuidLeaf,          // what CPUID answers
        OsApi,              // what a Win32 API reports
        FirmwareTable,      // SMBIOS / ACPI style data
        DeviceMetadata,     // disk model, NIC vendor, driver names
        TimingModel,        // clock behaviour
        ProfileDeclaration  // the profile's own stated intent
    };

    const char* ClaimChannelToString(ClaimChannel channel);

    struct EnvironmentClaim {
        std::string  property;   // "Cpu.Virtualized", "Cpu.LogicalProcessors"
        std::string  value;
        ClaimChannel channel = ClaimChannel::ProfileDeclaration;
        std::string  origin;     // "CPUID leaf 1 ECX bit 31"
        bool         indicatesVirtualization = false;
    };

    struct CoherenceContradiction {
        std::string      property;
        EnvironmentClaim first;
        EnvironmentClaim second;
        std::string      explanation;
        FindingSeverity  severity = FindingSeverity::Medium;
    };

    struct EnvironmentConsistencyGraph {
        std::string                          profileName;
        std::vector<EnvironmentClaim>        claims;
        std::vector<CoherenceContradiction>  contradictions;

        // 0-100. How easily a sample could tell this environment apart from
        // ordinary hardware, counting both virtualization markers left visible
        // and self-contradictions introduced by hiding some but not others.
        int         fingerprintability = 0;
        std::string fingerprintabilityLabel = "Unknown";

        bool IsCoherent() const { return contradictions.empty(); }
        std::vector<Finding> ToFindings() const;
    };

    // Build the claim graph for a profile and detect contradictions.
    EnvironmentConsistencyGraph BuildConsistencyGraph(const EnvironmentProfile& profile);

} // namespace Dracula
