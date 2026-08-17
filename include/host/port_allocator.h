#pragma once

//
// Collision-safe TCP port allocation for the Dracula sandbox.
//
// The telemetry link has exactly two roles, and keeping them straight is what
// makes the port question simple:
//
//     HOST  = server.  Binds and listens.
//     GUEST = client.  Dials out to the host through the QEMU SLIRP gateway
//                      at 10.0.2.2, which needs no port forwarding at all.
//
// Because the guest only ever connects outbound, QEMU must NOT be asked to
// forward an inbound host port. Doing so made QEMU try to bind the very port
// Dracula's listener already held, and QEMU exited before the guest booted.
//
// Allocation here is bind-and-hold: the port is claimed by an actual bind() and
// the live socket is handed to the caller. There is no "check then bind" window
// for another process to slip through, and the caller always learns the port
// that was ACTUALLY bound rather than the one that was requested.
//

#include "../common/types.h"   // PortStrategy
#include <cstdint>
#include <string>

namespace Sandbox {

    const char* PortStrategyToString(PortStrategy strategy);
    bool ParsePortStrategy(const std::string& name, PortStrategy& out);

    struct PortRequest {
        std::string  listenIp = "0.0.0.0";
        uint16_t     preferredPort = 8899;
        uint16_t     rangeBegin = 8899;
        uint16_t     rangeEnd = 8999;
        PortStrategy strategy = PortStrategy::PreferredThenRange;
    };

    // A successfully bound, listening socket plus the port it actually got.
    // The caller takes ownership of `socketHandle` and must close it.
    struct PortBinding {
        bool        valid = false;
        uintptr_t   socketHandle = 0;
        uint16_t    port = 0;
        bool        usedPreferredPort = false;
        uint16_t    attemptsMade = 0;
        std::string error;      // populated only when valid == false
    };

    // Bind and listen according to the request. On success the socket is live
    // and already in the listening state; on failure nothing is left open.
    PortBinding BindListeningPort(const PortRequest& request, int backlog = 4);

    // Whether a port can be bound right now. Used for diagnostics and tests.
    // This deliberately performs a real bind, because on Windows nothing else
    // gives a truthful answer.
    bool IsPortAvailable(uint16_t port, const std::string& listenIp = "0.0.0.0");

    // Close a socket handed out by BindListeningPort. Safe to call with 0.
    void CloseListeningSocket(uintptr_t socketHandle);

    // Winsock has to be initialised before any of the above is used and the
    // initialisation is reference counted, so every component that touches a
    // socket keeps one of these alive for as long as it needs sockets.
    class WinsockGuard {
    public:
        WinsockGuard();
        ~WinsockGuard();
        WinsockGuard(const WinsockGuard&) = delete;
        WinsockGuard& operator=(const WinsockGuard&) = delete;

        bool Ok() const { return m_ok; }

    private:
        bool m_ok = false;
    };

} // namespace Sandbox
