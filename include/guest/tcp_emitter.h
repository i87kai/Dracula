#pragma once

#include "../common/types.h"
#include "../common/protocol.h"
#include <string>
#include <mutex>
#include <atomic>

namespace Sandbox::Guest {

    class TcpEmitter {
    public:
        TcpEmitter(const std::string& hostIp, uint16_t hostPort);
        ~TcpEmitter();

        // Connect to Host Controller TCP Server and receive TraceOptions
        bool Connect(TraceOptions& outReceivedOptions);

        // Send a TraceEvent to the Host Controller
        bool SendEvent(const TraceEvent& event);

        // Disconnect and clean up sockets
        void Disconnect();

        bool IsConnected() const { return m_isConnected.load(); }

    private:
        std::string m_hostIp;
        uint16_t m_hostPort;
        uintptr_t m_socket = 0;
        std::atomic<bool> m_isConnected{false};
        std::mutex m_sendMutex;
    };

} // namespace Sandbox::Guest
