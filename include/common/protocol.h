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
    //
    // Wire layout:
    //     uint32  event type
    //     uint64  timestamp (ms)
    //     string  category
    //     string  message
    //     string  details
    //     -- everything below is OPTIONAL and read only if present --
    //     uint32  pid
    //     string  process name
    //     uint32  parent pid
    //     string  command line
    //     uint32  process role
    //
    // The trailing fields were added after the original format shipped. They are
    // appended rather than inserted, and the reader treats them as optional, so
    // an older GuestAgent that does not send them still deserializes correctly
    // instead of having every one of its events rejected.
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

        // Without these the host received every event with pid 0 and no process
        // name, which made the sandbox process tree unattributable.
        uint8_t pidBytes[4];
        uint32_t pid = event.pid;
        std::memcpy(pidBytes, &pid, 4);
        buffer.insert(buffer.end(), pidBytes, pidBytes + 4);

        AppendString(buffer, event.processName);

        // Lineage extensions: parent PID, command line, and process role
        uint8_t ppidBytes[4];
        uint32_t ppid = event.parentPid;
        std::memcpy(ppidBytes, &ppid, 4);
        buffer.insert(buffer.end(), ppidBytes, ppidBytes + 4);

        AppendString(buffer, event.commandLine);

        uint8_t roleBytes[4];
        uint32_t role = static_cast<uint32_t>(event.role);
        std::memcpy(roleBytes, &role, 4);
        buffer.insert(buffer.end(), roleBytes, roleBytes + 4);

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

        // Optional trailing fields. Their absence is not an error: it just means
        // the sender predates them.
        if (offset + 4 <= length) {
            uint32_t pid = 0;
            std::memcpy(&pid, data + offset, 4);
            offset += 4;
            outEvent.pid = pid;

            std::string processName;
            if (ReadString(data, length, offset, processName)) {
                outEvent.processName = processName;
            }
        }

        if (offset + 4 <= length) {
            uint32_t ppid = 0;
            std::memcpy(&ppid, data + offset, 4);
            offset += 4;
            outEvent.parentPid = ppid;

            std::string cmdLine;
            if (ReadString(data, length, offset, cmdLine)) {
                outEvent.commandLine = cmdLine;
            }
        }

        if (offset + 4 <= length) {
            uint32_t role = 0;
            std::memcpy(&role, data + offset, 4);
            offset += 4;
            outEvent.role = static_cast<ProcessRole>(role);
        }

        return true;
    }

    // ─── Legacy pipe-delimited payload ──────────────────────────────────────
    //
    // Before the binary payload existed, events were sent as text:
    //
    //     type|timestampMs|category|message|details
    //
    // GuestAgent binaries deployed into an existing guest image still emit it,
    // and re-provisioning a guest is not something the host can assume. The
    // packet framing is identical in both versions, so a legacy agent's events
    // arrive perfectly framed and then fail to decode, which looks exactly like
    // a silent guest. The host therefore accepts both encodings.

    inline bool LooksLikeLegacyTextPayload(const uint8_t* data, size_t length) {
        if (!data || length < 4) return false;

        // The binary form starts with a little-endian uint32 event type, so its
        // second byte is always zero for any real event type. The text form has
        // a digit or the separator there. That single byte tells them apart.
        const bool firstIsDigit = (data[0] >= '0' && data[0] <= '9');
        if (!firstIsDigit) return false;
        const bool secondIsTextual =
            (data[1] >= '0' && data[1] <= '9') || data[1] == '|';
        if (!secondIsTextual) return false;

        // A separator must appear early, as the type field is short.
        const size_t scan = (length < 16) ? length : 16;
        for (size_t i = 0; i < scan; ++i) {
            if (data[i] == '|') return true;
        }
        return false;
    }

    // The legacy agent numbers its event types sequentially, from before the
    // enum gained explicit values (Process = 38, File = 40, ...). Its numbers
    // therefore mean something different now: a legacy "4" is a process exit,
    // but 4 maps to nothing in the current enum, so a finished sample looked
    // like no event at all and the session ran until it timed out.
    inline EventType MapLegacyEventType(uint32_t legacy) {
        switch (legacy) {
            case 0:  return EventType::Info;
            case 1:  return EventType::Stdout;
            case 2:  return EventType::Stderr;
            case 3:  return EventType::ProcessCreated;
            case 4:  return EventType::ProcessTerminated;
            case 5:  return EventType::FileCreated;
            case 6:  return EventType::FileModified;
            case 7:  return EventType::FileDeleted;
            case 8:  return EventType::RegistryKeyCreated;
            case 9:  return EventType::RegistryValueSet;
            case 10: return EventType::NetworkConnect;
            case 11: return EventType::ExecutionStarted;
            case 12: return EventType::ExecutionFinished;
            case 13: return EventType::Error;
            default: break;
        }
        // Anything already carrying a modern explicit value is left alone.
        return static_cast<EventType>(legacy);
    }

    inline bool DeserializeEventLegacyText(const std::string& text, TraceEvent& outEvent) {
        const size_t p1 = text.find('|');
        if (p1 == std::string::npos) return false;
        const size_t p2 = text.find('|', p1 + 1);
        if (p2 == std::string::npos) return false;
        const size_t p3 = text.find('|', p2 + 1);
        if (p3 == std::string::npos) return false;

        try {
            outEvent.type = MapLegacyEventType(
                static_cast<uint32_t>(std::stoul(text.substr(0, p1))));
            outEvent.timestampMs = std::stoull(text.substr(p1 + 1, p2 - p1 - 1));
        } catch (...) {
            return false;
        }

        outEvent.category = text.substr(p2 + 1, p3 - p2 - 1);

        // Details is the final field, so it is taken from the right. A message
        // containing a pipe then still survives, which parsing left to right
        // would not manage.
        const size_t last = text.rfind('|');
        if (last <= p3) {
            outEvent.message = text.substr(p3 + 1);
            outEvent.details.clear();
        } else {
            outEvent.message = text.substr(p3 + 1, last - p3 - 1);
            outEvent.details = text.substr(last + 1);
        }

        // Recover process identity and role from legacy text if present
        if (outEvent.pid == 0) {
            size_t pidPos = outEvent.message.find("PID: ");
            if (pidPos != std::string::npos) {
                try {
                    outEvent.pid = static_cast<uint32_t>(std::stoul(outEvent.message.substr(pidPos + 5)));
                } catch (...) {}
            }
        }
        if (outEvent.parentPid == 0) {
            size_t ppidPos = outEvent.details.find("Parent PID: ");
            if (ppidPos != std::string::npos) {
                try {
                    outEvent.parentPid = static_cast<uint32_t>(std::stoul(outEvent.details.substr(ppidPos + 12)));
                } catch (...) {}
            }
        }
        if (outEvent.role == ProcessRole::Unspecified) {
            if (outEvent.message.find("Target Process") != std::string::npos) {
                outEvent.role = ProcessRole::Target;
            } else if (outEvent.message.find("Child Process") != std::string::npos) {
                outEvent.role = ProcessRole::Child;
            }
        }

        return true;
    }

    // String compatibility wrappers
    inline std::string SerializeEvent(const TraceEvent& event) {
        auto bin = SerializeEventBinary(event);
        return std::string(reinterpret_cast<const char*>(bin.data()), bin.size());
    }

    inline bool DeserializeEvent(const std::string& data, TraceEvent& outEvent) {
        const auto* bytes = reinterpret_cast<const uint8_t*>(data.data());
        if (LooksLikeLegacyTextPayload(bytes, data.size())) {
            if (DeserializeEventLegacyText(data, outEvent)) return true;
            // Fall through: a payload that merely looked textual still gets the
            // binary reader rather than being discarded.
        }
        return DeserializeEventBinary(bytes, data.size(), outEvent);
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
