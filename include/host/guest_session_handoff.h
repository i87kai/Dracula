#pragma once

//
// How the host tells the guest where to connect.
//
// The port is chosen on the host, at runtime, and may not be the configured
// one. The guest therefore cannot have it compiled in. It is written into the
// shared folder as a small key/value file BEFORE QEMU is launched, which is the
// only correct ordering: QEMU snapshots the share directory into a read-only
// FAT drive at launch, so anything written afterwards is invisible to the guest.
//
//     host binds a port  ->  writes the handoff file  ->  launches QEMU
//                                                          |
//                                        guest boots, reads the file off the
//                                        share, dials 10.0.2.2:<port> outbound
//
// GuestAgent prefers an explicit --host-port argument and falls back to this
// file, so an already-provisioned guest whose startup script passes a fixed
// port keeps working unchanged.
//

#include <cstdint>
#include <string>

namespace Sandbox {

    struct GuestSessionHandoff {
        std::string hostIp = "10.0.2.2";   // SLIRP gateway alias for the host
        uint16_t    hostPort = 0;          // the port the host ACTUALLY bound
        std::string sessionId;             // identifies one sandbox run
        std::string targetFileName = "target_sample.exe";
        uint32_t    timeoutSeconds = 60;

        // Serialize to the key/value form written into the share.
        std::string ToIni() const;
        static bool FromIni(const std::string& text, GuestSessionHandoff& out);
    };

    // The file name looked for on every candidate drive inside the guest.
    inline constexpr const char* kGuestSessionFileName = "dracula_session.ini";

    // Write the handoff into the share directory. Returns false with a reason
    // when the directory is not writable.
    bool WriteGuestSessionHandoff(const std::string& shareDirectory,
                                  const GuestSessionHandoff& handoff,
                                  std::string& outError);

    // Read a handoff file from a path (used by GuestAgent inside the guest).
    bool ReadGuestSessionHandoff(const std::string& filePath, GuestSessionHandoff& out);

} // namespace Sandbox
