#pragma once

#include <cstdint>
#include <string>

namespace Sandbox {

    struct GuestSessionHandoff {
        std::string hostIp = "10.0.2.2";   // SLIRP gateway alias for the host
        uint16_t    hostPort = 0;          // the port the host ACTUALLY bound
        std::string sessionId;             // identifies one sandbox run
        std::string sessionNonce;          // 128-bit cryptographically random ephemeral session nonce
        std::string targetFileName = "target_sample.exe";
        uint32_t    timeoutSeconds = 60;

        // Serialize to the key/value form written into the share.
        std::string ToIni() const;
        static bool FromIni(const std::string& text, GuestSessionHandoff& out);
    };

    // The file name looked for on every candidate drive inside the guest.
    inline constexpr const char* kGuestSessionFileName = "dracula_session.ini";

    // Generate 128-bit cryptographically random session nonce
    std::string GenerateCryptographicNonce();

    // Write the handoff into the share directory. Returns false with a reason
    // when the directory is not writable.
    bool WriteGuestSessionHandoff(const std::string& shareDirectory,
                                  const GuestSessionHandoff& handoff,
                                  std::string& outError);

    // Read a handoff file from a path (used by GuestAgent inside the guest).
    bool ReadGuestSessionHandoff(const std::string& filePath, GuestSessionHandoff& out);

} // namespace Sandbox
