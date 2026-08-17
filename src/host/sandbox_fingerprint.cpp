#include "host/sandbox_fingerprint.h"
#include "common/paths.h"
#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
#include <sstream>

namespace Dracula {

    namespace {

        void Add(SandboxEnvironmentFingerprint& fp, const char* channel, const char* property,
                 const std::string& value, bool reveals, const char* note) {
            fp.observables.push_back({channel, property, value, reveals, note});
        }

        std::string RunAndCapture(const std::string& command) {
            std::string out;
#ifdef _WIN32
            FILE* pipe = _popen(command.c_str(), "r");
#else
            FILE* pipe = popen(command.c_str(), "r");
#endif
            if (!pipe) return out;
            std::array<char, 256> buf{};
            while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
                out += buf.data();
                if (out.size() > 4096) break;
            }
#ifdef _WIN32
            _pclose(pipe);
#else
            pclose(pipe);
#endif
            return out;
        }

    } // namespace

    SandboxEnvironmentFingerprint InspectSandboxEnvironment(const Sandbox::QemuConfig& config) {
        SandboxEnvironmentFingerprint fp;
        fp.qemuExecutable = config.qemuExecutable;
        fp.diskImage = config.diskPath;
        fp.firmware = config.biosPath;
        fp.memory = config.memory;
        fp.smpCores = config.smpCores;
        fp.accelerators = config.accelerators;
        fp.configured = !config.qemuExecutable.empty() && !config.diskPath.empty();

        std::error_code ec;
        const bool haveQemu = std::filesystem::exists(config.qemuExecutable, ec);
        const bool haveDisk = std::filesystem::exists(config.diskPath, ec);

        fp.available = haveQemu && haveDisk;
        if (!haveQemu) {
            fp.unavailableReason = "QEMU executable not found at " + config.qemuExecutable;
        } else if (!haveDisk) {
            fp.unavailableReason = "Guest disk image not found at " + config.diskPath;
        }

        if (haveQemu) {
            const std::string version = RunAndCapture("\"" + config.qemuExecutable + "\" --version 2>&1");
            const size_t nl = version.find('\n');
            fp.qemuVersion = nl == std::string::npos ? version : version.substr(0, nl);
            while (!fp.qemuVersion.empty() &&
                   (fp.qemuVersion.back() == '\r' || fp.qemuVersion.back() == ' ')) {
                fp.qemuVersion.pop_back();
            }
        }

        // What the guest can see. These are properties of how Dracula launches
        // QEMU, stated plainly rather than asserted to be hidden.
        Add(fp, "CPUID", "Hypervisor bit",
            config.accelerators.find("whpx") != std::string::npos
                ? "set (Windows Hypervisor Platform)" : "set (TCG or KVM)",
            true, "QEMU sets CPUID leaf 1 ECX bit 31 unless explicitly configured otherwise.");
        Add(fp, "CPUID", "Hypervisor vendor leaf",
            config.accelerators.find("tcg") != std::string::npos ? "TCGTCGTCGTCG" : "hypervisor signature",
            true, "Leaf 0x40000000 answers with the accelerator's signature.");
        Add(fp, "CPUID", "CPU topology", std::to_string(config.smpCores) + " logical processors",
            config.smpCores <= 2,
            "Two or fewer processors is itself a common sandbox heuristic.");
        Add(fp, "SMBIOS", "System manufacturer", "QEMU", true,
            "Default SMBIOS strings identify the emulator.");
        Add(fp, "SMBIOS", "Product name", "Standard PC (Q35 + ICH9, 2009)", true,
            "Default machine type string.");
        Add(fp, "Firmware", "BIOS image", config.biosPath,
            config.biosPath.find("edk2") != std::string::npos,
            "EDK II OVMF firmware is identifiable from inside the guest.");
        Add(fp, "Disk", "Storage product id", "QEMU HARDDISK", true,
            "Virtual disk product string.");
        Add(fp, "Device", "Network adapter", "virtio / e1000", true,
            "Paravirtual or emulated NIC models are identifiable.");
        Add(fp, "Device", "MAC prefix", "52:54:00", true, "QEMU's registered OUI.");
        Add(fp, "Memory", "Physical memory", config.memory,
            config.memory == "1G" || config.memory == "2G",
            "Small memory sizes are a common sandbox heuristic.");
        Add(fp, "Guest", "Dracula GuestAgent", "GuestAgent.exe present in the guest share",
            true, "Dracula's own telemetry agent is visible to anything enumerating processes.");
        Add(fp, "Guest", "Shared folder", config.guestShareDir, true,
            "The host share is enumerable from inside the guest.");

        int revealing = 0;
        for (const auto& o : fp.observables) if (o.revealsVirtualization) revealing++;
        fp.fingerprintability =
            fp.observables.empty() ? 0
                                   : std::clamp((revealing * 100) / static_cast<int>(fp.observables.size()), 0, 100);
        if (fp.fingerprintability >= 70)      fp.fingerprintabilityLabel = "High";
        else if (fp.fingerprintability >= 40) fp.fingerprintabilityLabel = "Moderate";
        else if (fp.fingerprintability > 0)   fp.fingerprintabilityLabel = "Low";
        else                                  fp.fingerprintabilityLabel = "Minimal";

        return fp;
    }

    SandboxEnvironmentFingerprint InspectSandboxEnvironment() {
        // Resolve the shipped configuration the same way every other Dracula
        // resource is resolved, so the fingerprint describes the guest the user
        // actually configured rather than the built-in defaults. Callers that
        // already loaded it lose nothing: the load is idempotent.
        const std::string configPath = Paths::ResolveResource("config/config.ini");
        if (!configPath.empty()) {
            Sandbox::ConfigManager::Instance().LoadFromFile(configPath);
        }
        return InspectSandboxEnvironment(Sandbox::ConfigManager::Instance().GetQemuConfig());
    }

    EnvironmentProfile SandboxEnvironmentFingerprint::ToProfile() const {
        // The QEMU sandbox as an EnvironmentProfile, so the same coherence
        // validator can reason about it alongside the Unicorn profiles.
        EnvironmentProfile p = EnvironmentProfile::Baseline();
        p.name = "QemuSandbox";
        p.description = "The configured QEMU guest as observed from inside it.";
        p.cpu.logicalProcessors = smpCores ? smpCores : 2;
        p.host.processorCount = p.cpu.logicalProcessors;
        p.cpu.hypervisorPresent = true;
        p.cpu.hypervisorLeavesExposed = true;
        p.host.firmwareVendor = "QEMU";
        p.host.diskModel = "QEMU HARDDISK";
        p.host.macOui = "52:54:00";

        // Parse "4G" / "2048M" style memory strings.
        if (!memory.empty()) {
            try {
                const uint64_t n = std::stoull(memory);
                const char unit = memory.back();
                if (unit == 'G' || unit == 'g')      p.host.physicalMemoryBytes = n * 1024ULL * 1024 * 1024;
                else if (unit == 'M' || unit == 'm') p.host.physicalMemoryBytes = n * 1024ULL * 1024;
            } catch (...) {
                // Leave the default when the string is not a size.
            }
        }
        return p;
    }

} // namespace Dracula
