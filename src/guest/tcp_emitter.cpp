#include "guest/tcp_emitter.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>

namespace Sandbox::Guest {

    TcpEmitter::TcpEmitter(const std::string& hostIp, uint16_t hostPort)
        : m_hostIp(hostIp), m_hostPort(hostPort) {
#ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    }

    TcpEmitter::~TcpEmitter() {
        Disconnect();
#ifdef _WIN32
        WSACleanup();
#endif
    }

    bool TcpEmitter::Connect(TraceOptions& outReceivedOptions) {
#ifdef _WIN32
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return false;

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(m_hostPort);
        inet_pton(AF_INET, m_hostIp.c_str(), &serverAddr.sin_addr);

        // Attempt connect with retry
        bool connected = false;
        for (int retry = 0; retry < 10; ++retry) {
            if (connect(s, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == 0) {
                connected = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }

        if (!connected) {
            closesocket(s);
            return false;
        }

        m_socket = s;
        m_isConnected = true;

        // Receive initial TraceOptions configuration string from Host
        char optBuffer[512];
        int bytes = recv(s, optBuffer, sizeof(optBuffer) - 1, 0);
        if (bytes > 0) {
            optBuffer[bytes] = '\0';
            Protocol::DeserializeOptions(optBuffer, outReceivedOptions);
        }

        return true;
#else
        return false;
#endif
    }

    bool TcpEmitter::SendEvent(const TraceEvent& event) {
#ifdef _WIN32
        if (!m_isConnected) return false;

        std::string payload = Protocol::SerializeEvent(event);

        Protocol::PacketHeader header;
        header.magic = Protocol::MAGIC_HEADER;
        header.payloadLength = static_cast<uint32_t>(payload.size());
        header.eventType = static_cast<uint32_t>(event.type);
        header.timestamp = event.timestampMs;

        std::vector<uint8_t> buffer(sizeof(Protocol::PacketHeader) + payload.size());
        std::memcpy(buffer.data(), &header, sizeof(Protocol::PacketHeader));
        if (!payload.empty()) {
            std::memcpy(buffer.data() + sizeof(Protocol::PacketHeader), payload.data(), payload.size());
        }

        std::lock_guard<std::mutex> lock(m_sendMutex);
        int totalSent = 0;
        int toSend = static_cast<int>(buffer.size());
        SOCKET s = static_cast<SOCKET>(m_socket);

        while (totalSent < toSend) {
            int sent = send(s, reinterpret_cast<const char*>(buffer.data() + totalSent), toSend - totalSent, 0);
            if (sent <= 0) {
                m_isConnected = false;
                return false;
            }
            totalSent += sent;
        }

        return true;
#else
        return false;
#endif
    }

    void TcpEmitter::Disconnect() {
#ifdef _WIN32
        if (m_isConnected && m_socket != 0) {
            closesocket(static_cast<SOCKET>(m_socket));
            m_socket = 0;
            m_isConnected = false;
        }
#endif
    }

} // namespace Sandbox::Guest
