#pragma once

//
// What Dracula's QEMU sandbox actually looks like from inside the guest.
//
// The honest position: a general-purpose virtual machine cannot be made
// indistinguishable from physical hardware, and pretending otherwise would make
// every conclusion drawn from it untrustworthy. What Dracula can do is state
// precisely which observable properties its configured guest exposes, so an
// analyst knows exactly what a sample running inside it could have noticed.
//

#include "common/config.h"
#include "core/environment_profile.h"
#include <string>
#include <vector>

namespace Dracula {

    struct ObservableProperty {
        std::string channel;   // "CPUID", "SMBIOS", "Device", "Disk", "NIC"
        std::string property;
        std::string value;
        bool        revealsVirtualization = false;
        std::string note;
    };

    struct SandboxEnvironmentFingerprint {
        bool        configured = false;   // a guest image is configured
        bool        available = false;    // the guest image and QEMU both exist
        std::string unavailableReason;

        std::string qemuExecutable;
        std::string qemuVersion;
        std::string diskImage;
        std::string firmware;
        std::string memory;
        uint32_t    smpCores = 0;
        std::string accelerators;

        std::vector<ObservableProperty> observables;

        // How many observables reveal virtualization, as a 0-100 score.
        int         fingerprintability = 0;
        std::string fingerprintabilityLabel = "Unknown";

        // Derive the equivalent EnvironmentProfile view of this sandbox so the
        // coherence validator can reason about it alongside Unicorn profiles.
        EnvironmentProfile ToProfile() const;
    };

    // Inspect the configured QEMU sandbox without booting it. Reports exactly
    // what is present; never claims verification it has not performed.
    SandboxEnvironmentFingerprint InspectSandboxEnvironment(
        const Sandbox::QemuConfig& config);
    SandboxEnvironmentFingerprint InspectSandboxEnvironment();

} // namespace Dracula
