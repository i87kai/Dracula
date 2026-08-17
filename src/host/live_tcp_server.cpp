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
        : m_listenIp(listenIp), m_port(port) {
#ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    }

    LiveTcpServer::~LiveTcpServer() {
        Stop();
#ifdef _WIN32
        WSACleanup();
#endif
    }

    bool LiveTcpServer::Start(LiveEventCallback callback, const TraceOptions& options) {
        m_callback = std::move(callback);
        m_isRunning = true;

#ifdef _WIN32
        SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSock == INVALID_SOCKET) {
            m_isRunning = false;
            return false;
        }

        int optVal = 1;
        setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&optVal), sizeof(optVal));

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(m_port);
        serverAddr.sin_addr.s_addr = INADDR_ANY;

        if (bind(listenSock, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
            closesocket(listenSock);
            m_isRunning = false;
            return false;
        }

        if (listen(listenSock, 1) == SOCKET_ERROR) {
            closesocket(listenSock);
            m_isRunning = false;
            return false;
        }

        m_serverSocket = listenSock;
        m_workerThread = std::thread(&LiveTcpServer::ServerWorker, this, options);
        return true;
#else
        return false;
#endif
    }

    void LiveTcpServer::ServerWorker(const TraceOptions& options) {
#ifdef _WIN32
        SOCKET listenSock = static_cast<SOCKET>(m_serverSocket);

        while (m_isRunning) {
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(listenSock, &readSet);

            timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 300000; // 300ms timeout for non-blocking loop

            int selectRes = select(0, &readSet, nullptr, nullptr, &tv);
            if (selectRes > 0 && FD_ISSET(listenSock, &readSet)) {
                sockaddr_in clientAddr;
                int clientAddrLen = sizeof(clientAddr);
                SOCKET clientSock = accept(listenSock, reinterpret_cast<sockaddr*>(&clientAddr), &clientAddrLen);

                if (clientSock != INVALID_SOCKET) {
                    m_isConnected = true;
                    HandleClient(clientSock, options);
                    m_isConnected = false;
                }
            }
        }
#endif
    }

    void LiveTcpServer::HandleClient(uintptr_t clientSocket, const TraceOptions& options) {
#ifdef _WIN32
        SOCKET clientSock = static_cast<SOCKET>(clientSocket);

        // 1. Send configured TraceOptions to Guest Agent
        std::string optStr = Protocol::SerializeOptions(options);
        send(clientSock, optStr.c_str(), static_cast<int>(optStr.length()), 0);

        // 2. Read incoming packet stream
        std::vector<uint8_t> recvBuffer;
        char tempBuf[4096];

        while (m_isRunning) {
            int bytesReceived = recv(clientSock, tempBuf, sizeof(tempBuf), 0);
            if (bytesReceived <= 0) {
                break; // Client disconnected
            }

            recvBuffer.insert(recvBuffer.end(), tempBuf, tempBuf + bytesReceived);

            // Parse complete packets
            while (recvBuffer.size() >= sizeof(Protocol::PacketHeader)) {
                auto pHeader = reinterpret_cast<const Protocol::PacketHeader*>(recvBuffer.data());
                if (pHeader->magic != Protocol::MAGIC_HEADER) {
                    // Out of sync: discard single byte and retry
                    recvBuffer.erase(recvBuffer.begin());
                    continue;
                }

                uint32_t totalPacketSize = sizeof(Protocol::PacketHeader) + pHeader->payloadLength;
                if (recvBuffer.size() < totalPacketSize) {
                    break; // Wait for remainder of packet payload
                }

                std::string payload(
                    reinterpret_cast<const char*>(recvBuffer.data() + sizeof(Protocol::PacketHeader)),
                    pHeader->payloadLength
                );

                TraceEvent event;
                if (Protocol::DeserializeEvent(payload, event)) {
                    if (m_callback) {
                        m_callback(event);
                    }
                }

                recvBuffer.erase(recvBuffer.begin(), recvBuffer.begin() + totalPacketSize);
            }
        }

        closesocket(clientSock);
#endif
    }

    void LiveTcpServer::Stop() {
#ifdef _WIN32
        m_isRunning = false;
        if (m_serverSocket != 0) {
            closesocket(static_cast<SOCKET>(m_serverSocket));
            m_serverSocket = 0;
        }

        if (m_workerThread.joinable()) {
            m_workerThread.join();
        }
#endif
    }

} // namespace Sandbox
