#include "host/guest_session_handoff.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>

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

    std::string GuestSessionHandoff::ToIni() const {
        std::ostringstream ss;
        ss << "; Dracula sandbox session handoff\n"
           << "; Written by the host before QEMU starts. The guest reads this to\n"
           << "; learn which host port to dial. Do not edit by hand.\n"
           << "[Session]\n"
           << "session_id = " << sessionId << "\n"
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
                if (c == '\n') file << '\r';
                file << c;
            }
            file.flush();
            if (!file) {
                outError = "failed while writing " + path.string();
                return false;
            }
            return true;
        } catch (const std::exception& ex) {
            outError = std::string("could not write the session handoff: ") + ex.what();
            return false;
        }
    }

    bool ReadGuestSessionHandoff(const std::string& filePath, GuestSessionHandoff& out) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) return false;

        std::ostringstream buffer;
        buffer << file.rdbuf();
        return GuestSessionHandoff::FromIni(buffer.str(), out);
    }

} // namespace Sandbox
