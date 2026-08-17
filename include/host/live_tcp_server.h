#pragma once

#include "../common/types.h"
#include "../common/protocol.h"
#include <functional>
#include <thread>
#include <atomic>
#include <vector>

namespace Sandbox {

    using LiveEventCallback = std::function<void(const TraceEvent&)>;

    class LiveTcpServer {
    public:
        LiveTcpServer(const std::string& listenIp, uint16_t port);
        ~LiveTcpServer();

        // Start server in a background thread
        bool Start(LiveEventCallback callback, const TraceOptions& options);

        // Stop server and close connections
        void Stop();

        // Check if currently connected to Guest Agent
        bool IsClientConnected() const { return m_isConnected.load(); }

    private:
        void ServerWorker(const TraceOptions& options);
        void HandleClient(uintptr_t clientSocket, const TraceOptions& options);

        std::string m_listenIp;
        uint16_t m_port;
        LiveEventCallback m_callback;
        std::atomic<bool> m_isRunning{false};
        std::atomic<bool> m_isConnected{false};
        std::thread m_workerThread;
        uintptr_t m_serverSocket = 0; // SOCKET representation
    };

} // namespace Sandbox
