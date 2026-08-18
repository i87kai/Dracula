#include "host/live_tcp_server.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <iostream>
#include <vector>

namespace Sandbox {

    LiveTcpServer::LiveTcpServer(const std::string& listenIp, uint16_t port)
        : m_listenIp(listenIp) {
        // The constructor's port becomes the preferred one. Callers that want a
        // different policy override it with SetPortRequest before Start().
        m_portRequest.listenIp = listenIp;
        m_portRequest.preferredPort = port;
        m_portRequest.rangeBegin = port;
        m_portRequest.rangeEnd = static_cast<uint16_t>(
            (port > 65435) ? 65535 : static_cast<uint16_t>(port + 100));
        m_portRequest.strategy = PortStrategy::PreferredThenRange;
    }

    LiveTcpServer::~LiveTcpServer() {
        Stop();
    }

    bool LiveTcpServer::Start(LiveEventCallback callback, const TraceOptions& options) {
        if (m_isRunning.load()) {
            m_lastError = "the telemetry server is already running";
            return false;
        }

#ifdef _WIN32
        m_lastError.clear();
        m_eventsReceived = 0;
        m_bytesReceived = 0;
        m_framingErrors = 0;
        m_everConnected = false;

        // Bind-and-hold: the port is claimed by a real bind, and we are told
        // which port we actually got rather than assuming we got the one asked
        // for. Nothing else can take it between here and accept().
        PortRequest request = m_portRequest;
        request.listenIp = m_listenIp;
        const PortBinding binding = BindListeningPort(request);

        if (!binding.valid) {
            m_lastError = binding.error;
            return false;
        }

        m_serverSocket = binding.socketHandle;
        m_actualPort = binding.port;
        m_usedPreferredPort = binding.usedPreferredPort;

        m_callback = std::move(callback);
        m_isRunning = true;

        try {
            m_workerThread = std::thread(&LiveTcpServer::ServerWorker, this, options);
        } catch (const std::exception& ex) {
            // Never leave the socket dangling because a thread could not start.
            m_isRunning = false;
            CloseListeningSocket(m_serverSocket.exchange(0));
            m_actualPort = 0;
            m_lastError = std::string("could not start the telemetry worker thread: ") + ex.what();
            return false;
        }

        return true;
#else
        m_lastError = "the telemetry server is only implemented for Windows hosts";
        return false;
#endif
    }

    void LiveTcpServer::ServerWorker(TraceOptions options) {
#ifdef _WIN32
        while (m_isRunning.load()) {
            const uintptr_t handle = m_serverSocket.load();
            if (handle == 0) break;
            const SOCKET listenSock = static_cast<SOCKET>(handle);

            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(listenSock, &readSet);

            timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 250000;   // 250 ms, so Stop() is noticed promptly

            const int ready = select(0, &readSet, nullptr, nullptr, &tv);
            if (ready == SOCKET_ERROR) {
                break;   // the listening socket was closed by Stop()
            }
            if (ready <= 0 || !FD_ISSET(listenSock, &readSet)) {
                continue;
            }

            sockaddr_in clientAddr{};
            int clientAddrLen = sizeof(clientAddr);
            const SOCKET clientSock =
                accept(listenSock, reinterpret_cast<sockaddr*>(&clientAddr), &clientAddrLen);

            if (clientSock == INVALID_SOCKET) {
                continue;
            }

            m_clientSocket = static_cast<uintptr_t>(clientSock);
            m_isConnected = true;
            m_everConnected = true;

            HandleClient(static_cast<uintptr_t>(clientSock), options);

            m_isConnected = false;
            CloseClientSocket();
        }
#else
        (void)options;
#endif
    }

    void LiveTcpServer::HandleClient(uintptr_t clientSocket, const TraceOptions& options) {
#ifdef _WIN32
        const SOCKET clientSock = static_cast<SOCKET>(clientSocket);

        // 1. Hand the guest its trace configuration.
        const std::string optStr = Protocol::SerializeOptions(options);
        send(clientSock, optStr.c_str(), static_cast<int>(optStr.length()), 0);

        // 2. Read the framed packet stream. The framing is unchanged: a
        //    PacketHeader carrying a magic value and a payload length, followed
        //    by that many payload bytes, reassembled across arbitrary splits.
        std::vector<uint8_t> recvBuffer;
        char tempBuf[4096];

        while (m_isRunning.load()) {
            // A blocking recv on an idle client would keep this thread parked
            // forever and make Stop() hang on join, so the read is polled.
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(clientSock, &readSet);

            timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 250000;

            const int ready = select(0, &readSet, nullptr, nullptr, &tv);
            if (ready == SOCKET_ERROR) break;      // socket closed under us
            if (ready == 0) continue;              // idle, check m_isRunning again
            if (!FD_ISSET(clientSock, &readSet)) continue;

            const int bytesReceived = recv(clientSock, tempBuf, sizeof(tempBuf), 0);
            if (bytesReceived <= 0) {
                break;   // the guest closed the connection
            }

            m_bytesReceived += static_cast<uint64_t>(bytesReceived);
            recvBuffer.insert(recvBuffer.end(), tempBuf, tempBuf + bytesReceived);

            while (recvBuffer.size() >= sizeof(Protocol::PacketHeader)) {
                auto pHeader = reinterpret_cast<const Protocol::PacketHeader*>(recvBuffer.data());
                if (pHeader->magic != Protocol::MAGIC_HEADER) {
                    // Out of sync: discard a single byte and resynchronise.
                    m_framingErrors++;
                    recvBuffer.erase(recvBuffer.begin());
                    continue;
                }

                const uint32_t totalPacketSize =
                    static_cast<uint32_t>(sizeof(Protocol::PacketHeader)) + pHeader->payloadLength;
                if (recvBuffer.size() < totalPacketSize) {
                    break;   // wait for the rest of the payload
                }

                std::string payload(
                    reinterpret_cast<const char*>(recvBuffer.data() + sizeof(Protocol::PacketHeader)),
                    pHeader->payloadLength
                );

                TraceEvent event;
                if (Protocol::DeserializeEvent(payload, event)) {
                    if (!m_expectedNonce.empty() && !m_isAuthenticated.load()) {
                        const bool hasNonce = (event.details == "Nonce:" + m_expectedNonce) ||
                                              (event.details.find(m_expectedNonce) != std::string::npos) ||
                                              (event.message.find(m_expectedNonce) != std::string::npos);
                        if (hasNonce) {
                            m_isAuthenticated = true;
                            m_authenticatedNonce = m_expectedNonce;
                        } else {
                            m_lastError = "Unauthorized GuestAgent: session nonce mismatch";
                            m_isAuthenticated = false;
                            break;
                        }
                    }

                    m_eventsReceived++;
                    if (m_callback) {
                        m_callback(event);
                    }
                }

                recvBuffer.erase(recvBuffer.begin(), recvBuffer.begin() + totalPacketSize);
            }
        }
#else
        (void)clientSocket;
        (void)options;
#endif
    }

    void LiveTcpServer::CloseClientSocket() {
        const uintptr_t client = m_clientSocket.exchange(0);
        if (client != 0) {
            CloseListeningSocket(client);   // closesocket, name notwithstanding
        }
    }

    void LiveTcpServer::Stop() {
        const bool wasRunning = m_isRunning.exchange(false);

        // Close both sockets from this thread. Closing the client is what
        // unblocks a worker sitting on a live connection; closing the listener
        // is what unblocks one waiting for a connection that never comes.
        CloseClientSocket();
        CloseListeningSocket(m_serverSocket.exchange(0));

        if (m_workerThread.joinable()) {
            m_workerThread.join();
        }

        m_isConnected = false;
        if (wasRunning) {
            m_actualPort = 0;
        }
    }

} // namespace Sandbox
