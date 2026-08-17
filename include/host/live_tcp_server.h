#pragma once

#include "../common/types.h"
#include "../common/protocol.h"
#include "port_allocator.h"
#include <functional>
#include <thread>
#include <atomic>
#include <string>
#include <vector>

namespace Sandbox {

    using LiveEventCallback = std::function<void(const TraceEvent&)>;

    // The host half of the telemetry link: a listening server the GuestAgent
    // dials out to. It never initiates a connection into the guest, which is why
    // the sandbox needs no inbound port forwarding.
    class LiveTcpServer {
    public:
        LiveTcpServer(const std::string& listenIp, uint16_t port);
        ~LiveTcpServer();

        LiveTcpServer(const LiveTcpServer&) = delete;
        LiveTcpServer& operator=(const LiveTcpServer&) = delete;

        // Choose how the listening port is selected. Must be called before
        // Start(). Without it the server uses the constructor's port as the
        // preferred one and falls back to a scan.
        void SetPortRequest(const PortRequest& request) { m_portRequest = request; }
        const PortRequest& GetPortRequest() const { return m_portRequest; }

        // Bind, listen and begin accepting in a background thread. On failure
        // no socket is left open and LastError() explains why.
        bool Start(LiveEventCallback callback, const TraceOptions& options);

        // Stop accepting, drop any live client and join the worker. Safe to call
        // more than once, and safe to call while a client is connected but idle.
        void Stop();

        bool IsClientConnected() const { return m_isConnected.load(); }
        bool IsRunning() const { return m_isRunning.load(); }

        // The port that was ACTUALLY bound, which may differ from the requested
        // one. Zero until Start() succeeds.
        uint16_t ActualPort() const { return m_actualPort.load(); }
        bool UsedPreferredPort() const { return m_usedPreferredPort; }

        // Whether a GuestAgent has connected at any point in this session, and
        // how many telemetry events were accepted.
        bool EverConnected() const { return m_everConnected.load(); }
        uint64_t EventsReceived() const { return m_eventsReceived.load(); }

        // Raw bytes read off the wire, and packets whose magic never matched.
        // These separate "the agent sent nothing" from "the agent sent
        // something the host could not decode", which are very different faults.
        uint64_t BytesReceived() const { return m_bytesReceived.load(); }
        uint64_t FramingErrors() const { return m_framingErrors.load(); }

        const std::string& LastError() const { return m_lastError; }

    private:
        void ServerWorker(TraceOptions options);
        void HandleClient(uintptr_t clientSocket, const TraceOptions& options);
        void CloseClientSocket();

        std::string       m_listenIp;
        PortRequest       m_portRequest;
        LiveEventCallback m_callback;
        std::string       m_lastError;

        std::atomic<bool>     m_isRunning{false};
        std::atomic<bool>     m_isConnected{false};
        std::atomic<bool>     m_everConnected{false};
        std::atomic<uint16_t> m_actualPort{0};
        std::atomic<uint64_t> m_eventsReceived{0};
        std::atomic<uint64_t> m_bytesReceived{0};
        std::atomic<uint64_t> m_framingErrors{0};
        bool                  m_usedPreferredPort = false;

        std::thread m_workerThread;

        // Both sockets are tracked so shutdown can close them from the caller's
        // thread; a worker parked in recv() on an idle client would otherwise
        // never return and Stop() would deadlock on join().
        std::atomic<uintptr_t> m_serverSocket{0};
        std::atomic<uintptr_t> m_clientSocket{0};

        WinsockGuard m_winsock;
    };

} // namespace Sandbox
