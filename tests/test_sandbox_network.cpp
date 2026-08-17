//
// Dracula sandbox networking verification suite.
//
// Covers the port allocation and conflict handling that the QEMU sandbox
// depends on, the guest session handoff that carries the chosen port across to
// the guest, the telemetry framing, and the QEMU command line itself.
//
// The regression this suite exists to prevent: Dracula bound host port 8899 for
// its telemetry listener and then asked QEMU to forward the same host port
// inbound, so QEMU could not bind it and exited before the guest booted.
//

#include "common/types.h"
#include "common/protocol.h"
#include "common/config.h"
#include "host/port_allocator.h"
#include "host/guest_session_handoff.h"
#include "host/live_tcp_server.h"
#include "host/qemu_manager.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace Sandbox;

static int g_pass = 0;
static int g_fail = 0;

static void Check(bool condition, const std::string& name) {
    if (condition) {
        std::cout << "  \033[32m[PASS]\033[0m " << name << "\n";
        g_pass++;
    } else {
        std::cout << "  \033[1;31m[FAIL]\033[0m " << name << "\n";
        g_fail++;
    }
}

static void Section(const std::string& title) {
    std::cout << "\n\033[1;36m=== " << title << " ===\033[0m\n";
}

// A stand-in for "some other process is holding this port". Uses the same
// exclusive bind the allocator uses, so the contention is real.
class PortSquatter {
public:
    explicit PortSquatter(uint16_t port) {
        PortRequest req;
        req.preferredPort = port;
        req.strategy = PortStrategy::Fixed;
        m_binding = BindListeningPort(req);
    }
    ~PortSquatter() { Release(); }

    void Release() {
        if (m_binding.valid) {
            CloseListeningSocket(m_binding.socketHandle);
            m_binding.valid = false;
        }
    }

    bool Held() const { return m_binding.valid; }
    uint16_t Port() const { return m_binding.port; }

private:
    PortBinding m_binding;
};

// Find a port that is free right now, for use as a test fixture.
static uint16_t FindFreePort() {
    PortRequest req;
    req.strategy = PortStrategy::Ephemeral;
    PortBinding b = BindListeningPort(req);
    if (!b.valid) return 0;
    const uint16_t port = b.port;
    CloseListeningSocket(b.socketHandle);
    return port;
}

// ─── 1. Port availability and allocation ────────────────────────────────────

static void TestPortAllocation() {
    Section("1. Collision-safe port allocation");

    const uint16_t freePort = FindFreePort();
    Check(freePort != 0, "An ephemeral bind yields a usable free port");
    Check(IsPortAvailable(freePort), "A free port reports as available");

    // Holding the port must make availability report false. On Windows this is
    // only true because the allocator asks for exclusive use; with SO_REUSEADDR
    // a second bind would silently succeed and the conflict would go unnoticed.
    {
        PortSquatter squatter(freePort);
        Check(squatter.Held(), "The squatter binds the free port");
        Check(!IsPortAvailable(freePort), "An occupied port reports as unavailable");
    }
    Check(IsPortAvailable(freePort), "The port is available again once released");

    // Fixed strategy: an occupied port is a hard, explained failure.
    {
        const uint16_t port = FindFreePort();
        PortSquatter squatter(port);
        PortRequest req;
        req.preferredPort = port;
        req.strategy = PortStrategy::Fixed;

        PortBinding binding = BindListeningPort(req);
        Check(!binding.valid, "Fixed strategy fails when the port is taken");
        Check(binding.socketHandle == 0, "A failed fixed bind leaves no socket open");
        Check(binding.error.find("in use") != std::string::npos ||
                  binding.error.find("access denied") != std::string::npos,
              "The failure explains that the port is in use: " + binding.error);
        if (binding.valid) CloseListeningSocket(binding.socketHandle);
    }

    // Fixed strategy on a free port uses exactly that port.
    {
        const uint16_t port = FindFreePort();
        PortRequest req;
        req.preferredPort = port;
        req.strategy = PortStrategy::Fixed;

        PortBinding binding = BindListeningPort(req);
        Check(binding.valid && binding.port == port,
              "Fixed strategy binds exactly the requested port when it is free");
        Check(binding.usedPreferredPort, "It reports that the preferred port was used");
        CloseListeningSocket(binding.socketHandle);
    }
}

static void TestPortFallback() {
    Section("2. Conflict fallback");

    // Preferred-then-range: the preferred port is taken, so a different port in
    // the range is chosen and reported.
    {
        const uint16_t preferred = FindFreePort();
        PortSquatter squatter(preferred);

        PortRequest req;
        req.preferredPort = preferred;
        req.rangeBegin = preferred;
        req.rangeEnd = static_cast<uint16_t>(preferred + 20);
        req.strategy = PortStrategy::PreferredThenRange;

        PortBinding binding = BindListeningPort(req);
        Check(binding.valid, "Preferred-then-range still binds when the preferred port is taken");
        Check(binding.port != preferred, "It moves off the occupied port");
        Check(!binding.usedPreferredPort, "It reports that the preferred port was NOT used");
        Check(binding.port >= req.rangeBegin && binding.port <= req.rangeEnd,
              "The chosen port is inside the configured range");
        Check(binding.attemptsMade >= 2, "It recorded more than one attempt");
        CloseListeningSocket(binding.socketHandle);
    }

    // The preferred port being free means it is used, so an already-provisioned
    // guest with a fixed port keeps working.
    {
        const uint16_t preferred = FindFreePort();
        PortRequest req;
        req.preferredPort = preferred;
        req.rangeBegin = preferred;
        req.rangeEnd = static_cast<uint16_t>(preferred + 20);
        req.strategy = PortStrategy::PreferredThenRange;

        PortBinding binding = BindListeningPort(req);
        Check(binding.valid && binding.port == preferred && binding.usedPreferredPort,
              "The preferred port is used whenever it is free");
        Check(binding.attemptsMade == 1, "No extra attempts are made when the first one works");
        CloseListeningSocket(binding.socketHandle);
    }

    // A fully occupied range must still produce a working listener rather than
    // failing the session outright.
    {
        const uint16_t base = FindFreePort();
        PortSquatter s1(base);
        PortSquatter s2(static_cast<uint16_t>(base + 1));
        PortSquatter s3(static_cast<uint16_t>(base + 2));

        PortRequest req;
        req.preferredPort = base;
        req.rangeBegin = base;
        req.rangeEnd = static_cast<uint16_t>(base + 2);
        req.strategy = PortStrategy::PreferredThenRange;

        PortBinding binding = BindListeningPort(req);
        Check(binding.valid, "An exhausted range falls back to an OS-assigned port");
        Check(binding.port != base && binding.port != base + 1 && binding.port != base + 2,
              "The fallback port is none of the occupied ones");
        CloseListeningSocket(binding.socketHandle);
    }

    // Ephemeral never collides, even repeatedly.
    {
        PortRequest req;
        req.strategy = PortStrategy::Ephemeral;
        PortBinding a = BindListeningPort(req);
        PortBinding b = BindListeningPort(req);
        Check(a.valid && b.valid, "Two ephemeral allocations both succeed");
        Check(a.port != b.port, "Two ephemeral allocations never collide");
        CloseListeningSocket(a.socketHandle);
        CloseListeningSocket(b.socketHandle);
    }

    // Strategy names round-trip through configuration.
    {
        PortStrategy s;
        Check(ParsePortStrategy("fixed", s) && s == PortStrategy::Fixed, "Strategy 'fixed' parses");
        Check(ParsePortStrategy("ephemeral", s) && s == PortStrategy::Ephemeral, "Strategy 'ephemeral' parses");
        Check(ParsePortStrategy("preferred-then-range", s) && s == PortStrategy::PreferredThenRange,
              "Strategy 'preferred-then-range' parses");
        Check(!ParsePortStrategy("nonsense", s), "An unknown strategy name is rejected");
    }
}

// ─── 3. The listener ────────────────────────────────────────────────────────

static void TestLiveTcpServer() {
    Section("3. Telemetry listener lifecycle");

    const uint16_t freePort = FindFreePort();

    // Binds the configured port when it is free, and reports it.
    {
        LiveTcpServer server("0.0.0.0", freePort);
        TraceOptions opts;
        const bool started = server.Start([](const TraceEvent&) {}, opts);
        Check(started, "The listener starts on a free port");
        Check(server.ActualPort() == freePort, "It reports the port it actually bound");
        Check(server.UsedPreferredPort(), "It reports that the configured port was used");
        Check(!IsPortAvailable(freePort), "The port is genuinely held while the listener runs");
        server.Stop();
        Check(IsPortAvailable(freePort), "The port is released when the listener stops");
    }

    // Falls back when the configured port is occupied, and says so.
    {
        const uint16_t occupied = FindFreePort();
        PortSquatter squatter(occupied);

        LiveTcpServer server("0.0.0.0", occupied);
        TraceOptions opts;
        const bool started = server.Start([](const TraceEvent&) {}, opts);
        Check(started, "The listener still starts when the configured port is taken");
        Check(server.ActualPort() != 0 && server.ActualPort() != occupied,
              "It binds a different port and reports it");
        Check(!server.UsedPreferredPort(), "It reports that it did not get the configured port");
        server.Stop();
    }

    // A fixed strategy that cannot bind must fail loudly, not silently.
    {
        const uint16_t occupied = FindFreePort();
        PortSquatter squatter(occupied);

        LiveTcpServer server("0.0.0.0", occupied);
        PortRequest req;
        req.preferredPort = occupied;
        req.strategy = PortStrategy::Fixed;
        server.SetPortRequest(req);

        TraceOptions opts;
        const bool started = server.Start([](const TraceEvent&) {}, opts);
        Check(!started, "A fixed-strategy listener fails when its port is taken");
        Check(!server.LastError().empty(), "The failure carries an explanation: " + server.LastError());
        Check(server.ActualPort() == 0, "No port is reported after a failed start");
    }

    // Stop() must return promptly even with a connected but silent client.
    // Before the fix the worker parked in a blocking recv and join() hung.
    {
        LiveTcpServer server("0.0.0.0", 0);
        PortRequest req;
        req.strategy = PortStrategy::Ephemeral;
        server.SetPortRequest(req);

        TraceOptions opts;
        Check(server.Start([](const TraceEvent&) {}, opts), "Ephemeral listener starts");
        const uint16_t port = server.ActualPort();

#ifdef _WIN32
        SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        const bool connected = connect(client, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
        Check(connected, "A client can connect to the listener");

        // Connected and deliberately silent.
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        Check(server.IsClientConnected(), "The listener reports the live connection");

        const auto begin = std::chrono::steady_clock::now();
        server.Stop();
        const auto tookMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - begin).count();

        Check(tookMs < 3000, "Stop() returns promptly with an idle client attached (" +
                                 std::to_string(tookMs) + " ms)");
        closesocket(client);
#endif
    }
}

// ─── 4. Telemetry framing across the link ───────────────────────────────────

static void TestTelemetryFraming() {
    Section("4. Telemetry protocol framing");

#ifdef _WIN32
    std::atomic<int> received{0};
    std::vector<TraceEvent> events;
    std::mutex eventMutex;

    LiveTcpServer server("0.0.0.0", 0);
    PortRequest req;
    req.strategy = PortStrategy::Ephemeral;
    server.SetPortRequest(req);

    TraceOptions opts;
    opts.monitorFiles = true;
    opts.executionTimeoutSeconds = 42;

    if (!server.Start([&](const TraceEvent& e) {
            std::lock_guard<std::mutex> lock(eventMutex);
            events.push_back(e);
            received++;
        }, opts)) {
        Check(false, "Listener started for the framing test");
        return;
    }

    const uint16_t port = server.ActualPort();

    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    Check(connect(client, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0,
          "Client connects to the ephemeral listener");

    // The server sends the trace options first, exactly as the guest expects.
    char optBuf[512] = {0};
    const int optBytes = recv(client, optBuf, sizeof(optBuf) - 1, 0);
    Check(optBytes > 0, "The server pushes trace options to the client on connect");

    TraceOptions roundTripped;
    Check(Protocol::DeserializeOptions(std::string(optBuf, optBytes), roundTripped),
          "The pushed options deserialize");
    Check(roundTripped.executionTimeoutSeconds == 42,
          "The options survive the round trip unchanged");

    // Build two framed packets and deliberately send them in awkward chunks so
    // reassembly across split reads is exercised.
    auto buildPacket = [](const std::string& message) {
        TraceEvent e;
        e.type = EventType::FileCreated;
        e.timestampMs = 1234;
        e.pid = 4242;
        e.category = "File";
        e.message = message;
        e.details = "detail";

        const std::string payload = Protocol::SerializeEvent(e);
        Protocol::PacketHeader header;
        header.magic = Protocol::MAGIC_HEADER;
        header.payloadLength = static_cast<uint32_t>(payload.size());
        header.eventType = static_cast<uint32_t>(e.type);
        header.timestamp = e.timestampMs;

        std::vector<uint8_t> buf(sizeof(header) + payload.size());
        std::memcpy(buf.data(), &header, sizeof(header));
        std::memcpy(buf.data() + sizeof(header), payload.data(), payload.size());
        return buf;
    };

    const auto packetA = buildPacket("alpha_event");
    const auto packetB = buildPacket("beta_event");

    std::vector<uint8_t> stream;
    stream.insert(stream.end(), packetA.begin(), packetA.end());
    stream.insert(stream.end(), packetB.begin(), packetB.end());

    // Send one byte at a time for the first header, then the rest in a lump.
    const size_t drip = sizeof(Protocol::PacketHeader) + 3;
    for (size_t i = 0; i < drip && i < stream.size(); ++i) {
        send(client, reinterpret_cast<const char*>(&stream[i]), 1, 0);
    }
    if (stream.size() > drip) {
        send(client, reinterpret_cast<const char*>(stream.data() + drip),
             static_cast<int>(stream.size() - drip), 0);
    }

    for (int i = 0; i < 100 && received.load() < 2; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    Check(received.load() == 2, "Both framed events are reassembled across split reads");
    {
        std::lock_guard<std::mutex> lock(eventMutex);
        Check(events.size() == 2 && events[0].message == "alpha_event" &&
                  events[1].message == "beta_event",
              "Event payloads arrive intact and in order");
        Check(events.size() == 2 && events[0].pid == 4242 &&
                  events[0].type == EventType::FileCreated,
              "Event fields survive serialization");
    }
    Check(server.EventsReceived() == 2, "The listener counts the events it accepted");
    Check(server.EverConnected(), "The listener records that an agent connected");

    // Backward compatibility: a payload from an older agent, which carries no
    // trailing pid or process name, must still deserialize rather than being
    // dropped wholesale.
    {
        TraceEvent legacySource;
        legacySource.type = EventType::Info;
        legacySource.timestampMs = 99;
        legacySource.category = "Legacy";
        legacySource.message = "old_agent";
        legacySource.details = "";

        // Rebuild the pre-change payload: type, timestamp, three strings, stop.
        std::vector<uint8_t> legacy;
        uint32_t t = static_cast<uint32_t>(legacySource.type);
        uint64_t ts = legacySource.timestampMs;
        legacy.insert(legacy.end(), reinterpret_cast<uint8_t*>(&t), reinterpret_cast<uint8_t*>(&t) + 4);
        legacy.insert(legacy.end(), reinterpret_cast<uint8_t*>(&ts), reinterpret_cast<uint8_t*>(&ts) + 8);
        Protocol::AppendString(legacy, legacySource.category);
        Protocol::AppendString(legacy, legacySource.message);
        Protocol::AppendString(legacy, legacySource.details);

        TraceEvent decoded;
        const bool ok = Protocol::DeserializeEventBinary(legacy.data(), legacy.size(), decoded);
        Check(ok, "A legacy payload without the trailing fields still deserializes");
        Check(ok && decoded.message == "old_agent" && decoded.category == "Legacy",
              "The legacy payload's existing fields are intact");
        Check(ok && decoded.pid == 0, "A legacy payload simply reports no pid");
    }

    // A GuestAgent deployed into an existing guest image still emits the
    // original pipe-delimited text payload. Its framing is identical, so the
    // host must decode it rather than silently discarding every event. These
    // are exact payloads captured off the wire from the real guest.
    {
        const std::string captured =
            "0|1787013201225|GuestAgent|Guest Agent started execution of: E:\\target_sample.exe|";
        TraceEvent decoded;
        const bool ok = Protocol::DeserializeEvent(captured, decoded);
        Check(ok, "A legacy pipe-delimited payload from a deployed agent decodes");
        Check(ok && decoded.type == EventType::Info, "Its event type is recovered");
        Check(ok && decoded.timestampMs == 1787013201225ULL, "Its timestamp is recovered");
        Check(ok && decoded.category == "GuestAgent", "Its category is recovered");
        Check(ok && decoded.message == "Guest Agent started execution of: E:\\target_sample.exe",
              "Its message is recovered in full");
        Check(ok && decoded.details.empty(), "Its empty trailing details field is handled");
    }
    {
        const std::string captured = "3|1787013201281|Process|Target Process Spawned (PID: 2052)|";
        TraceEvent decoded;
        const bool ok = Protocol::DeserializeEvent(captured, decoded);
        Check(ok && decoded.type == EventType::ProcessCreated,
              "A legacy process-creation event decodes to the right type");
        Check(ok && decoded.message.find("2052") != std::string::npos,
              "A legacy process event keeps its message");
    }
    {
        // A legacy "4" means the target exited. It maps to nothing in the
        // current enum, so before this mapping a finished sample was invisible
        // and every session ran until it timed out.
        const std::string captured = "4|1787013201796|Process|Target Process Exited with Code: 0|";
        TraceEvent decoded;
        const bool ok = Protocol::DeserializeEvent(captured, decoded);
        Check(ok && decoded.type == EventType::ProcessTerminated,
              "A legacy process-exit event maps onto ProcessTerminated");
        Check(Protocol::MapLegacyEventType(12) == EventType::ExecutionFinished,
              "A legacy execution-finished event maps onto ExecutionFinished");
        Check(Protocol::MapLegacyEventType(13) == EventType::Error,
              "A legacy error event maps onto Error");
        Check(Protocol::MapLegacyEventType(static_cast<uint32_t>(EventType::Registry)) ==
                  EventType::Registry,
              "A modern explicit event value is passed through unchanged");
    }
    {
        // A message containing a pipe must survive, since details is the final
        // field and is therefore taken from the right.
        const std::string tricky = "1|1000|Stdout|value=a|b|tail";
        TraceEvent decoded;
        const bool ok = Protocol::DeserializeEvent(tricky, decoded);
        Check(ok && decoded.message == "value=a|b" && decoded.details == "tail",
              "A legacy message containing a pipe is split correctly");
    }
    {
        // The discriminator must not misread a binary payload as text.
        TraceEvent source;
        source.type = EventType::Stdout;
        source.timestampMs = 7;
        source.category = "Stdout";
        source.message = "12345";      // digits, to stress the heuristic
        source.details = "";
        source.pid = 99;

        const std::string binary = Protocol::SerializeEvent(source);
        TraceEvent decoded;
        const bool ok = Protocol::DeserializeEvent(binary, decoded);
        Check(ok && decoded.message == "12345" && decoded.pid == 99,
              "A binary payload is never mistaken for the legacy text form");
    }
    {
        // Modern binary payload with process lineage and role fields
        TraceEvent lineageSource;
        lineageSource.type = EventType::ProcessCreated;
        lineageSource.timestampMs = 123456789ULL;
        lineageSource.category = "Process";
        lineageSource.message = "Target Process Started: sample.exe (PID: 1000)";
        lineageSource.details = "Parent PID: 500";
        lineageSource.pid = 1000;
        lineageSource.parentPid = 500;
        lineageSource.processName = "sample.exe";
        lineageSource.commandLine = "\"C:\\Path\\sample.exe\" --arg";
        lineageSource.role = ProcessRole::Target;

        const std::string binary = Protocol::SerializeEvent(lineageSource);
        TraceEvent decoded;
        const bool ok = Protocol::DeserializeEvent(binary, decoded);
        Check(ok, "Modern binary payload with lineage fields deserializes successfully");
        Check(ok && decoded.pid == 1000, "PID is preserved in binary serialization");
        Check(ok && decoded.parentPid == 500, "Parent PID is preserved in binary serialization");
        Check(ok && decoded.processName == "sample.exe", "Process name is preserved");
        Check(ok && decoded.commandLine == "\"C:\\Path\\sample.exe\" --arg", "Command line is preserved");
        Check(ok && decoded.role == ProcessRole::Target, "ProcessRole is preserved in binary serialization");
    }

    closesocket(client);
    server.Stop();
#endif
}

// ─── 5. The guest session handoff ───────────────────────────────────────────

static void TestSessionHandoff() {
    Section("5. Guest session handoff");

    GuestSessionHandoff handoff;
    handoff.hostIp = "10.0.2.2";
    handoff.hostPort = 51234;
    handoff.sessionId = "test-session";
    handoff.timeoutSeconds = 90;

    const std::string ini = handoff.ToIni();
    Check(ini.find("host_port = 51234") != std::string::npos,
          "The handoff carries the actual bound port");
    Check(ini.find("host_ip = 10.0.2.2") != std::string::npos,
          "The handoff names the SLIRP gateway alias for the host");

    GuestSessionHandoff parsed;
    Check(GuestSessionHandoff::FromIni(ini, parsed), "The handoff parses back");
    Check(parsed.hostPort == 51234 && parsed.hostIp == "10.0.2.2" &&
              parsed.sessionId == "test-session" && parsed.timeoutSeconds == 90,
          "Every field round-trips");

    GuestSessionHandoff empty;
    Check(!GuestSessionHandoff::FromIni("[Session]\nhost_ip = 10.0.2.2\n", empty),
          "A handoff with no port is rejected rather than silently defaulted");
    Check(!GuestSessionHandoff::FromIni("host_port = not_a_number\n", empty),
          "An unparseable port is rejected");

    // Writing into a share directory, and reading it back the way the guest does.
    const std::filesystem::path shareDir =
        std::filesystem::temp_directory_path() / "dracula_handoff_test";
    std::error_code ec;
    std::filesystem::remove_all(shareDir, ec);

    std::string error;
    Check(WriteGuestSessionHandoff(shareDir.string(), handoff, error),
          "The handoff is written into the share directory (" + error + ")");

    const std::filesystem::path written = shareDir / kGuestSessionFileName;
    Check(std::filesystem::exists(written), "The handoff file exists on disk");

    GuestSessionHandoff fromDisk;
    Check(ReadGuestSessionHandoff(written.string(), fromDisk),
          "The guest can read the handoff back off the share");
    Check(fromDisk.hostPort == 51234, "The port read from the share is the bound port");

    // cmd.exe parses this file with `for /f`, which needs CRLF line endings.
    std::ifstream raw(written, std::ios::binary);
    const std::string rawText((std::istreambuf_iterator<char>(raw)),
                              std::istreambuf_iterator<char>());
    Check(rawText.find("\r\n") != std::string::npos,
          "The handoff uses CRLF so the guest batch script can parse it");

    GuestSessionHandoff noPort;
    noPort.hostPort = 0;
    Check(!WriteGuestSessionHandoff(shareDir.string(), noPort, error),
          "Writing a handoff with no bound port is refused");

    std::filesystem::remove_all(shareDir, ec);
}

// ─── 6. The QEMU command line ───────────────────────────────────────────────

static void TestQemuCommandLine() {
    Section("6. QEMU launch arguments");

    QemuConfig cfg;
    cfg.qemuExecutable = "C:\\Program Files\\qemu\\qemu-system-x86_64.exe";
    cfg.memory = "4G";
    cfg.smpCores = 2;
    cfg.accelerators = "whpx:tcg";

    QemuManager manager(cfg);
    const std::string cmd = manager.BuildCommandLine(false);

    // The regression this whole suite exists for: QEMU must never be asked to
    // bind a host port, because the telemetry listener already owns one.
    Check(cmd.find("hostfwd") == std::string::npos,
          "The QEMU command line contains NO hostfwd rule");
    Check(cmd.find("8899") == std::string::npos,
          "The QEMU command line references no telemetry port at all");

    // User-mode networking must still be present, since that is what provides
    // the 10.0.2.2 gateway the guest dials out through.
    Check(cmd.find("-net user") != std::string::npos,
          "SLIRP user-mode networking is still configured");
    Check(cmd.find("-net nic") != std::string::npos,
          "A guest NIC is still attached");

    // Isolation must be intact.
    Check(cmd.find("-snapshot") != std::string::npos,
          "Non-destructive -snapshot mode is still requested");

    const std::string headless = manager.BuildCommandLine(true);
    Check(headless.find("-display none") != std::string::npos,
          "Headless mode disables the display");
    Check(headless.find("hostfwd") == std::string::npos,
          "The headless command line also carries no hostfwd rule");
}

// ─── 7. Configuration ───────────────────────────────────────────────────────

static void TestConfiguration() {
    Section("7. Network configuration");

    const std::filesystem::path cfgPath =
        std::filesystem::temp_directory_path() / "dracula_net_test.ini";
    {
        std::ofstream out(cfgPath);
        out << "[Network]\n"
            << "host_listen_ip = 127.0.0.1\n"
            << "host_listen_port = 9100\n"
            << "port_strategy = ephemeral\n"
            << "port_range_begin = 9100\n"
            << "port_range_end = 9200\n"
            << "guest_connect_timeout_seconds = 123\n";
    }

    ConfigManager cfg(cfgPath.string());
    const VMConfig& vm = cfg.GetVMConfig();

    Check(vm.hostPort == 9100, "The preferred port is configurable");
    Check(vm.hostListenIp == "127.0.0.1", "The listen address is configurable");
    Check(vm.portStrategy == PortStrategy::Ephemeral, "The port strategy is configurable");
    Check(vm.portRangeBegin == 9100 && vm.portRangeEnd == 9200,
          "The port range is configurable");
    Check(vm.guestConnectTimeoutSeconds == 123,
          "The guest connect timeout is configurable");

    VMConfig defaults;
    Check(defaults.portStrategy == PortStrategy::PreferredThenRange,
          "The default strategy prefers the configured port before moving");
    Check(defaults.guestConnectTimeoutSeconds > defaults.hostPort / 1000,
          "A guest connect timeout is set by default");

    std::error_code ec;
    std::filesystem::remove(cfgPath, ec);
}

// ─── 8. End to end: listener and QEMU no longer contend ─────────────────────

static void TestNoContentionWithQemu() {
    Section("8. Host listener and QEMU no longer contend for a port");

    // Bind the telemetry listener exactly as a real session does.
    LiveTcpServer server("0.0.0.0", 8899);
    TraceOptions opts;
    const bool started = server.Start([](const TraceEvent&) {}, opts);
    Check(started, "The telemetry listener binds while QEMU is about to launch");

    const uint16_t bound = server.ActualPort();
    Check(bound != 0, "A concrete port was bound: " + std::to_string(bound));

    // With the listener holding that port, the QEMU command line must not
    // mention it. This is the exact condition that used to kill QEMU.
    QemuManager manager;
    const std::string cmd = manager.BuildCommandLine(true);
    Check(cmd.find(std::to_string(bound)) == std::string::npos,
          "The QEMU command line does not reference the port the listener holds");
    Check(cmd.find("hostfwd") == std::string::npos,
          "The QEMU command line requests no host port binding whatsoever");

    // And the handoff tells the guest the port that was really bound.
    GuestSessionHandoff handoff;
    handoff.hostPort = bound;
    const std::string ini = handoff.ToIni();
    Check(ini.find("host_port = " + std::to_string(bound)) != std::string::npos,
          "The guest is told the port that was actually bound");

    server.Stop();
    Check(IsPortAvailable(bound), "The port is released after the session ends");
}

int main() {
#ifdef _WIN32
    SetConsoleOutputCP(65001);
#endif
    WinsockGuard winsock;

    std::cout << "\n\033[1;35m==============================================================\033[0m\n";
    std::cout << " DRACULA SANDBOX NETWORKING VERIFICATION\n";
    std::cout << "\033[1;35m==============================================================\033[0m\n";

    TestPortAllocation();
    TestPortFallback();
    TestLiveTcpServer();
    TestTelemetryFraming();
    TestSessionHandoff();
    TestQemuCommandLine();
    TestConfiguration();
    TestNoContentionWithQemu();

    std::cout << "\n\033[1;35m==============================================================\033[0m\n";
    std::cout << " SANDBOX NETWORK RESULTS: \033[1;32m" << g_pass << " PASSED\033[0m, "
              << "\033[1;31m" << g_fail << " FAILED\033[0m\n";
    std::cout << "\033[1;35m==============================================================\033[0m\n\n";
    return g_fail == 0 ? 0 : 1;
}
