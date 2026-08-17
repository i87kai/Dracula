#include "host/port_allocator.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <algorithm>
#include <cctype>
#include <sstream>

namespace Sandbox {

    const char* PortStrategyToString(PortStrategy strategy) {
        switch (strategy) {
            case PortStrategy::Fixed:              return "fixed";
            case PortStrategy::PreferredThenRange: return "preferred-then-range";
            case PortStrategy::Ephemeral:          return "ephemeral";
        }
        return "unknown";
    }

    bool ParsePortStrategy(const std::string& name, PortStrategy& out) {
        std::string n = name;
        std::transform(n.begin(), n.end(), n.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (n == "fixed" || n == "strict") { out = PortStrategy::Fixed; return true; }
        if (n == "preferred-then-range" || n == "preferred" || n == "auto" || n == "range") {
            out = PortStrategy::PreferredThenRange;
            return true;
        }
        if (n == "ephemeral" || n == "any" || n == "os") { out = PortStrategy::Ephemeral; return true; }
        return false;
    }

    // ─── Winsock lifetime ───────────────────────────────────────────────────

    WinsockGuard::WinsockGuard() {
#ifdef _WIN32
        WSADATA wsaData;
        m_ok = (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);
#else
        m_ok = true;
#endif
    }

    WinsockGuard::~WinsockGuard() {
#ifdef _WIN32
        if (m_ok) WSACleanup();
#endif
    }

    void CloseListeningSocket(uintptr_t socketHandle) {
#ifdef _WIN32
        if (socketHandle != 0 && socketHandle != static_cast<uintptr_t>(INVALID_SOCKET)) {
            closesocket(static_cast<SOCKET>(socketHandle));
        }
#else
        (void)socketHandle;
#endif
    }

    namespace {

        // Winsock must be initialised before any socket call, and a caller that
        // forgets gets WSANOTINITIALISED, which reads like a port conflict but
        // is not one. These entry points therefore initialise it themselves,
        // once per process, rather than depending on the caller. WSAStartup is
        // reference counted, so this composes with any caller-held guard.
        void EnsureWinsock() {
            static WinsockGuard processGuard;
            (void)processGuard;
        }

#ifdef _WIN32

        std::string LastSocketError() {
            const int code = WSAGetLastError();
            std::ostringstream ss;
            switch (code) {
                case WSAEADDRINUSE:
                    ss << "port already in use (WSAEADDRINUSE)";
                    break;
                case WSAEACCES:
                    ss << "access denied binding the port; it may be reserved by the system "
                          "or held with exclusive access (WSAEACCES)";
                    break;
                case WSAEADDRNOTAVAIL:
                    ss << "the listen address is not available on this host (WSAEADDRNOTAVAIL)";
                    break;
                default:
                    ss << "winsock error " << code;
                    break;
            }
            return ss.str();
        }

        // Try to bind and listen on exactly one port. Returns the live socket on
        // success and leaves nothing open on failure.
        //
        // SO_EXCLUSIVEADDRUSE, not SO_REUSEADDR: on Windows SO_REUSEADDR lets a
        // second socket bind an address another socket is already using, which
        // is precisely the collision this allocator exists to detect. Asking for
        // exclusive use makes a conflict an honest failure instead of a silent
        // double bind.
        bool TryBindOne(const std::string& listenIp, uint16_t port, int backlog,
                        uintptr_t& outSocket, uint16_t& outActualPort, std::string& outError) {
            SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) {
                outError = "could not create socket: " + LastSocketError();
                return false;
            }

            int exclusive = 1;
            setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                       reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            if (listenIp.empty() || listenIp == "0.0.0.0") {
                addr.sin_addr.s_addr = INADDR_ANY;
            } else if (inet_pton(AF_INET, listenIp.c_str(), &addr.sin_addr) != 1) {
                closesocket(sock);
                outError = "invalid listen address '" + listenIp + "'";
                return false;
            }

            if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
                outError = LastSocketError();
                closesocket(sock);
                return false;
            }

            if (listen(sock, backlog) == SOCKET_ERROR) {
                outError = "listen failed: " + LastSocketError();
                closesocket(sock);
                return false;
            }

            // Ask the socket what it actually got. This matters for the
            // ephemeral strategy, where the requested port was 0.
            sockaddr_in bound{};
            int boundLen = sizeof(bound);
            if (getsockname(sock, reinterpret_cast<sockaddr*>(&bound), &boundLen) == SOCKET_ERROR) {
                outError = "getsockname failed: " + LastSocketError();
                closesocket(sock);
                return false;
            }

            outSocket = static_cast<uintptr_t>(sock);
            outActualPort = ntohs(bound.sin_port);
            return true;
        }

#endif // _WIN32

    } // namespace

    PortBinding BindListeningPort(const PortRequest& request, int backlog) {
        PortBinding result;
        EnsureWinsock();

#ifdef _WIN32
        std::string lastError = "no port was attempted";

        auto attempt = [&](uint16_t port, bool isPreferred) -> bool {
            result.attemptsMade++;
            uintptr_t sock = 0;
            uint16_t actual = 0;
            std::string error;
            if (!TryBindOne(request.listenIp, port, backlog, sock, actual, error)) {
                lastError = error;
                return false;
            }
            result.valid = true;
            result.socketHandle = sock;
            result.port = actual;
            result.usedPreferredPort = isPreferred;
            return true;
        };

        switch (request.strategy) {
            case PortStrategy::Ephemeral:
                // Port 0 asks the OS for any free port, which cannot collide.
                attempt(0, false);
                break;

            case PortStrategy::Fixed:
                attempt(request.preferredPort, true);
                break;

            case PortStrategy::PreferredThenRange: {
                // The preferred port first, so an already-provisioned guest that
                // was configured with a fixed port keeps working untouched.
                if (attempt(request.preferredPort, true)) break;

                const uint16_t begin = std::min(request.rangeBegin, request.rangeEnd);
                const uint16_t end   = std::max(request.rangeBegin, request.rangeEnd);
                bool bound = false;
                for (uint32_t port = begin; port <= end; ++port) {
                    if (port == request.preferredPort) continue;   // already tried
                    if (port == 0) continue;
                    if (attempt(static_cast<uint16_t>(port), false)) { bound = true; break; }
                }

                // Every configured port is taken. Rather than fail the session,
                // fall back to an OS-assigned port and let the handoff file tell
                // the guest where to connect.
                if (!bound) attempt(0, false);
                break;
            }
        }

        if (!result.valid) {
            std::ostringstream ss;
            ss << "could not bind a listening port using the "
               << PortStrategyToString(request.strategy) << " strategy";
            if (request.strategy == PortStrategy::Fixed) {
                ss << " on port " << request.preferredPort;
            } else {
                ss << " (preferred " << request.preferredPort
                   << ", range " << request.rangeBegin << "-" << request.rangeEnd << ")";
            }
            ss << " after " << result.attemptsMade << " attempt(s): " << lastError;
            result.error = ss.str();
        }
#else
        result.error = "TCP port allocation is only implemented for Windows hosts";
#endif

        return result;
    }

    bool IsPortAvailable(uint16_t port, const std::string& listenIp) {
        EnsureWinsock();
#ifdef _WIN32
        uintptr_t sock = 0;
        uint16_t actual = 0;
        std::string error;
        if (!TryBindOne(listenIp, port, 1, sock, actual, error)) {
            return false;
        }
        CloseListeningSocket(sock);
        return true;
#else
        (void)port; (void)listenIp;
        return false;
#endif
    }

} // namespace Sandbox
