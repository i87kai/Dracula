#include "host/guest_session_handoff.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#endif

namespace Sandbox {

    namespace {
        std::string Trim(const std::string& s) {
            const size_t first = s.find_first_not_of(" \t\r\n");
            if (first == std::string::npos) return "";
            const size_t last = s.find_last_not_of(" \t\r\n");
            return s.substr(first, last - first + 1);
        }

        std::string Lower(std::string s) {
            std::transform(s.begin(), s.end(), s.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return s;
        }
    }

    std::string GenerateCryptographicNonce() {
        // This nonce authenticates a guest session to its host listener, so it
        // must come from a real CSPRNG. It previously came from two Mersenne
        // Twisters seeded from std::random_device: MT19937 is a predictable
        // generator whose internal state can be recovered from its output, and
        // std::random_device is not guaranteed to be non-deterministic. Neither
        // is acceptable for a value labelled cryptographic.
        uint8_t bytes[16] = {0};
        bool filled = false;

#ifdef _WIN32
        // BCRYPT_USE_SYSTEM_PREFERRED_RNG uses the OS CSPRNG without having to
        // open an algorithm provider handle.
        if (BCryptGenRandom(nullptr, bytes, sizeof(bytes),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0) {
            filled = true;
        }
#endif

        if (!filled) {
            // No silent downgrade to a weak generator: a caller that cannot get
            // real entropy must find out, not receive a guessable nonce.
            throw std::runtime_error(
                "the platform cryptographic RNG is unavailable; refusing to "
                "generate a session nonce from a non-cryptographic source");
        }

        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t b : bytes) {
            ss << std::setw(2) << static_cast<unsigned>(b);
        }
        return ss.str();
    }

    std::string GuestSessionHandoff::ToIni() const {
        std::ostringstream ss;
        ss << "; Dracula sandbox session handoff\n"
           << "; Written by the host before QEMU starts. The guest reads this to\n"
           << "; learn which host port to dial. Do not edit by hand.\n"
           << "[Session]\n"
           << "session_id = " << sessionId << "\n"
           << "session_nonce = " << sessionNonce << "\n"
           << "host_ip = " << hostIp << "\n"
           << "host_port = " << hostPort << "\n"
           << "target = " << targetFileName << "\n"
           << "timeout_seconds = " << timeoutSeconds << "\n";
        return ss.str();
    }

    bool GuestSessionHandoff::FromIni(const std::string& text, GuestSessionHandoff& out) {
        std::istringstream in(text);
        std::string line;
        bool sawPort = false;

        while (std::getline(in, line)) {
            line = Trim(line);
            if (line.empty() || line[0] == ';' || line[0] == '#' || line[0] == '[') continue;

            const size_t eq = line.find('=');
            if (eq == std::string::npos) continue;

            const std::string key = Lower(Trim(line.substr(0, eq)));
            const std::string value = Trim(line.substr(eq + 1));

            if (key == "host_ip") {
                out.hostIp = value;
            } else if (key == "host_port") {
                try {
                    const unsigned long port = std::stoul(value);
                    if (port > 0 && port <= 65535) {
                        out.hostPort = static_cast<uint16_t>(port);
                        sawPort = true;
                    }
                } catch (...) {
                    // A malformed port leaves the default in place.
                }
            } else if (key == "session_id") {
                out.sessionId = value;
            } else if (key == "session_nonce") {
                out.sessionNonce = value;
            } else if (key == "target") {
                out.targetFileName = value;
            } else if (key == "timeout_seconds") {
                try { out.timeoutSeconds = static_cast<uint32_t>(std::stoul(value)); } catch (...) {}
            }
        }

        // A handoff without a usable port tells the guest nothing.
        return sawPort;
    }

    bool WriteGuestSessionHandoff(const std::string& shareDirectory,
                                  const GuestSessionHandoff& handoff,
                                  std::string& outError) {
        if (handoff.hostPort == 0) {
            outError = "refusing to write a session handoff with no bound port";
            return false;
        }

        try {
            std::filesystem::create_directories(shareDirectory);
            const std::filesystem::path path =
                std::filesystem::path(shareDirectory) / kGuestSessionFileName;

            std::ofstream file(path, std::ios::binary | std::ios::trunc);
            if (!file.is_open()) {
                outError = "could not open " + path.string() + " for writing";
                return false;
            }

            // CRLF so the file is readable by the guest's cmd.exe `for /f` parsing.
            const std::string ini = handoff.ToIni();
            for (char c : ini) {
                if (c == '\n') file.put('\r');
                file.put(c);
            }
            return true;
        } catch (const std::exception& ex) {
            outError = ex.what();
            return false;
        }
    }

    bool ReadGuestSessionHandoff(const std::string& filePath, GuestSessionHandoff& out) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) return false;

        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        return GuestSessionHandoff::FromIni(content, out);
    }

} // namespace Sandbox
