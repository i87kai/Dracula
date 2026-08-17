#pragma once

#include "types.h"
#include <string>
#include <vector>
#include <sstream>
#include <cstring>
#include <cstdint>

namespace Sandbox::Protocol {

    // Magic identifier for communication packets: 'SAND'
    constexpr uint32_t MAGIC_HEADER = 0x53414E44;

    // Packet Header (Wire format)
    #pragma pack(push, 1)
    struct PacketHeader {
        uint32_t magic = MAGIC_HEADER;
        uint32_t payloadLength = 0;
        uint32_t eventType = 0;
        uint64_t timestamp = 0;
    };
    #pragma pack(pop)

    // Helper: append length-prefixed string
    inline void AppendString(std::vector<uint8_t>& buf, const std::string& str) {
        uint32_t len = static_cast<uint32_t>(str.size());
        uint8_t lenBytes[4];
        std::memcpy(lenBytes, &len, 4);
        buf.insert(buf.end(), lenBytes, lenBytes + 4);
        if (len > 0) {
            buf.insert(buf.end(), str.begin(), str.end());
        }
    }

    // Helper: read length-prefixed string
    inline bool ReadString(const uint8_t* data, size_t totalLen, size_t& offset, std::string& outStr) {
        if (offset + 4 > totalLen) return false;
        uint32_t len = 0;
        std::memcpy(&len, data + offset, 4);
        offset += 4;
        if (offset + len > totalLen) return false;
        outStr.assign(reinterpret_cast<const char*>(data + offset), len);
        offset += len;
        return true;
    }

    // Robust binary serialization of TraceEvent (handles newlines, pipe characters, etc.)
    inline std::vector<uint8_t> SerializeEventBinary(const TraceEvent& event) {
        std::vector<uint8_t> buffer;
        uint32_t t = static_cast<uint32_t>(event.type);
        uint64_t ts = event.timestampMs;

        uint8_t tBytes[4];
        std::memcpy(tBytes, &t, 4);
        buffer.insert(buffer.end(), tBytes, tBytes + 4);

        uint8_t tsBytes[8];
        std::memcpy(tsBytes, &ts, 8);
        buffer.insert(buffer.end(), tsBytes, tsBytes + 8);

        AppendString(buffer, event.category);
        AppendString(buffer, event.message);
        AppendString(buffer, event.details);

        return buffer;
    }

    inline bool DeserializeEventBinary(const uint8_t* data, size_t length, TraceEvent& outEvent) {
        if (!data || length < 12) return false;
        size_t offset = 0;

        uint32_t t = 0;
        std::memcpy(&t, data + offset, 4);
        offset += 4;
        outEvent.type = static_cast<EventType>(t);

        uint64_t ts = 0;
        std::memcpy(&ts, data + offset, 8);
        offset += 8;
        outEvent.timestampMs = ts;

        if (!ReadString(data, length, offset, outEvent.category)) return false;
        if (!ReadString(data, length, offset, outEvent.message)) return false;
        if (!ReadString(data, length, offset, outEvent.details)) return false;

        return true;
    }

    // String compatibility wrappers
    inline std::string SerializeEvent(const TraceEvent& event) {
        auto bin = SerializeEventBinary(event);
        return std::string(reinterpret_cast<const char*>(bin.data()), bin.size());
    }

    inline bool DeserializeEvent(const std::string& data, TraceEvent& outEvent) {
        return DeserializeEventBinary(reinterpret_cast<const uint8_t*>(data.data()), data.size(), outEvent);
    }

    // Helper to serialize TraceOptions sent from Host to Guest
    inline std::string SerializeOptions(const TraceOptions& options) {
        std::ostringstream ss;
        ss << "OPT:"
           << (options.monitorConsoleOutput ? "1" : "0") << ","
           << (options.monitorProcesses ? "1" : "0") << ","
           << (options.monitorFiles ? "1" : "0") << ","
           << (options.monitorRegistry ? "1" : "0") << ","
           << (options.monitorNetwork ? "1" : "0") << ","
           << options.executionTimeoutSeconds;
        return ss.str();
    }

    inline bool DeserializeOptions(const std::string& data, TraceOptions& outOptions) {
        if (data.rfind("OPT:", 0) != 0) return false;
        std::string content = data.substr(4);
        std::istringstream ss(content);
        std::string cOut, proc, files, reg, net, timeout;

        if (std::getline(ss, cOut, ',') &&
            std::getline(ss, proc, ',') &&
            std::getline(ss, files, ',') &&
            std::getline(ss, reg, ',') &&
            std::getline(ss, net, ',') &&
            std::getline(ss, timeout, ',')) {
            
            outOptions.monitorConsoleOutput = (cOut == "1");
            outOptions.monitorProcesses = (proc == "1");
            outOptions.monitorFiles = (files == "1");
            outOptions.monitorRegistry = (reg == "1");
            outOptions.monitorNetwork = (net == "1");
            try {
                outOptions.executionTimeoutSeconds = static_cast<uint32_t>(std::stoul(timeout));
            } catch (...) {
                outOptions.executionTimeoutSeconds = 60;
            }
            return true;
        }
        return false;
    }

} // namespace Sandbox::Protocol
