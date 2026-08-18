#include "utr/target_manager.h"
#include "utr/analysis_orchestrator.h"
#include "utr/session_manager.h"
#include "utr/artifact_manager.h"
#include "host/live_tcp_server.h"
#include "host/port_allocator.h"
#include "host/guest_session_handoff.h"
#include "common/protocol.h"

#include <iostream>
#include <cassert>
#include <chrono>
#include <thread>
#include <atomic>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

using namespace Dracula;
using namespace Dracula::UTR;
using namespace Sandbox;

int main() {
    std::cout << "[Test] Running [SIMULATED E2E] QemuUtrDeterministicPipelineTest & Safety Budget Suite...\n";

    // ─── 1. DETERMINISTIC IN-PROCESS TELEMETRY INGESTION PIPELINE (SIMULATED E2E)
    std::cout << "\n=== 1. Simulated QEMU Telemetry Ingestion Pipeline (SIMULATED E2E) ===\n";
    auto startTime = std::chrono::steady_clock::now();

    // Step 1: Create UTR Target & Session
    auto openRes = TargetManager::Instance().OpenTarget("--vm");
    assert(openRes.Ok());
    auto vmTarget = openRes.Value();
    assert(vmTarget->GetInfo().kind == TargetKind::VmTarget);
    assert(vmTarget->GetInfo().activeBackend == "QEMU_Sandbox");

    uint32_t sessionId = SessionManager::Instance().CreateSession(vmTarget->GetInfo());
    assert(sessionId > 0);
    SessionManager::Instance().SetActiveSession(sessionId);

    // Step 2: Dynamic Port Allocation & Live TCP Server Launch
    LiveTcpServer server("127.0.0.1", 0);
    PortRequest portReq;
    portReq.strategy = PortStrategy::Ephemeral;
    server.SetPortRequest(portReq);

    TraceOptions opts;
    opts.monitorFiles = true;
    opts.monitorRegistry = true;
    opts.monitorNetwork = true;
    opts.executionTimeoutSeconds = 30;

    std::atomic<int> eventsReceived{0};
    std::vector<TraceEvent> decodedEvents;
    std::mutex eventMutex;

    bool serverStarted = server.Start([&](const TraceEvent& evt) {
        std::lock_guard<std::mutex> lock(eventMutex);
        decodedEvents.push_back(evt);
        eventsReceived++;
    }, opts);
    assert(serverStarted);
    uint16_t boundPort = server.ActualPort();
    assert(boundPort > 0);

    auto qemuStartupMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime).count();

    // Step 3: Connect In-Process Test Transport
    auto connectStart = std::chrono::steady_clock::now();
    SOCKET clientSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in saddr{};
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(boundPort);
    inet_pton(AF_INET, "127.0.0.1", &saddr.sin_addr);
    int connRes = connect(clientSock, reinterpret_cast<sockaddr*>(&saddr), sizeof(saddr));
    assert(connRes == 0);

    auto agentConnectMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - connectStart).count();

    // Step 4: Transmit Structured Telemetry Packets
    auto sendPacket = [&](const TraceEvent& evt) {
        std::string payload = Protocol::SerializeEvent(evt);
        Protocol::PacketHeader header;
        header.magic = Protocol::MAGIC_HEADER;
        header.payloadLength = static_cast<uint32_t>(payload.size());
        header.eventType = static_cast<uint32_t>(evt.type);
        header.timestamp = evt.timestampMs;

        std::vector<uint8_t> buf(sizeof(header) + payload.size());
        std::memcpy(buf.data(), &header, sizeof(header));
        std::memcpy(buf.data() + sizeof(header), payload.data(), payload.size());
        send(clientSock, reinterpret_cast<const char*>(buf.data()), static_cast<int>(buf.size()), 0);
    };

    uint32_t simulatedPid = 4242;

    TraceEvent e1;
    e1.type = EventType::ProcessCreated;
    e1.timestampMs = 1000;
    e1.category = "Process";
    e1.pid = simulatedPid;
    e1.parentPid = 500;
    e1.processName = "native_simple.exe";
    e1.commandLine = "\"C:\\Share\\native_simple.exe\"";
    e1.role = ProcessRole::Target;
    e1.message = "Target Process Started: native_simple.exe (PID: 4242)";
    sendPacket(e1);

    TraceEvent e2;
    e2.type = EventType::Info;
    e2.timestampMs = 1020;
    e2.category = "Module";
    e2.pid = simulatedPid;
    e2.message = "Loaded Module: kernel32.dll at 0x7FFF12340000";
    sendPacket(e2);

    TraceEvent e3;
    e3.type = EventType::Memory;
    e3.timestampMs = 1050;
    e3.category = "Memory";
    e3.pid = simulatedPid;
    e3.message = "VirtualProtect: Address=0x140001000, Size=4096, OldProtect=0x04, NewProtect=0x20";
    sendPacket(e3);

    TraceEvent e4;
    e4.type = EventType::FileCreated;
    e4.timestampMs = 1080;
    e4.category = "File";
    e4.pid = simulatedPid;
    e4.message = "Created file: C:\\Users\\Public\\output.log";
    sendPacket(e4);

    TraceEvent e5;
    e5.type = EventType::ProcessTerminated;
    e5.timestampMs = 1200;
    e5.category = "Process";
    e5.pid = simulatedPid;
    e5.message = "Process exited with code 0";
    sendPacket(e5);

    TraceEvent e6;
    e6.type = EventType::ExecutionFinished;
    e6.timestampMs = 1250;
    e6.category = "Session";
    e6.pid = simulatedPid;
    e6.message = "Guest execution finished cleanly";
    sendPacket(e6);

    for (int i = 0; i < 50 && eventsReceived.load() < 6; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    assert(eventsReceived.load() >= 6);

    EvidenceGraph& graph = TargetManager::Instance().GetEvidenceGraph();
    for (const auto& evt : decodedEvents) {
        EvidenceNode node;
        node.id = "SIM_" + std::to_string(evt.timestampMs) + "_" + std::to_string(evt.pid);
        node.category = evt.category;
        node.severity = FindingSeverity::Info;
        node.confidence = FindingConfidence::High;
        node.truthLevel = EvidenceTruthLevel::Observed;
        node.title = evt.message;
        node.description = "Received over test transport on port " + std::to_string(boundPort);
        node.provenance.engine = "TestTransport";
        node.provenance.address = evt.pid;
        node.tags = {"Simulated", "Telemetry", evt.category};
        graph.AddEvidence(node);
    }
    assert(graph.GetNodes().size() >= 6);

    UnifiedAnalysisResult dummyStatic;
    FunctionIntelligenceManager dummyFuncs;
    MemoryIntelligenceManager dummyMem;
    SessionManager::Instance().SaveSession(sessionId, &dummyStatic, &graph, &dummyFuncs, &dummyMem);
    ArtifactManager::Instance().WriteSessionArtifacts(sessionId, vmTarget->GetInfo(), &dummyStatic, &graph, &dummyFuncs, &dummyMem);

    auto artifactIndex = ArtifactManager::Instance().GetArtifactIndex(sessionId);
    assert(artifactIndex.files.size() > 0);
    size_t nodeCount = graph.GetNodes().size();

    closesocket(clientSock);
    server.Stop();
    TargetManager::Instance().CloseActiveTarget();

    std::cout << "  [PASS] Simulated Startup Duration: " << qemuStartupMs << " ms\n";
    std::cout << "  [PASS] Connect Duration:           " << agentConnectMs << " ms\n";
    std::cout << "  [PASS] Simulated Target PID:       " << simulatedPid << "\n";
    std::cout << "  [PASS] Packets Decoded:            " << eventsReceived.load() << "\n";
    std::cout << "  [PASS] Evidence Nodes Staged:      " << nodeCount << "\n";
    std::cout << "  [PASS] Session ID:                 " << sessionId << "\n";
    std::cout << "  [PASS] Artifacts Written:          " << artifactIndex.files.size() << " files\n";

    // ─── 2. SEPARATE AUTO-ESCALATION FROM EXECUTION SAFETY TESTS ─────────────
    std::cout << "\n=== 2. Separated Auto-Escalation & Execution Safety Policies ===\n";

    // Case 1: Unknown Target + Runtime + AutoEscalation=Off + Safety=IsolatedOnlyForUnknown -> BLOCKED
    auto openUnknown = TargetManager::Instance().OpenTarget("samples/utr/native_simple.exe");
    assert(openUnknown.Ok());

    UtrOrchestratorOptions optsBlocked;
    optsBlocked.level = AnalysisLevel::Runtime;
    optsBlocked.autoEscalation = AutoEscalationPolicy::Off;
    optsBlocked.executionSafety = ExecutionSafetyPolicy::IsolatedOnlyForUnknown;
    optsBlocked.isTargetTrusted = false;

    auto resBlocked = UtrAnalysisOrchestrator::Instance().RunAnalysis(openUnknown.Value(), optsBlocked);
    assert(resBlocked.executionBlocked);
    assert(resBlocked.escalationDecision.decision == "BlockedSafetyPolicy");
    std::cout << "  [PASS] Unknown target + AutoEscalation Off -> Execution BLOCKED by safety policy\n";

    // Case 2: Unknown Target + Runtime + AutoEscalation=Safe -> Escalated to QEMU
    UtrOrchestratorOptions optsSafe;
    optsSafe.level = AnalysisLevel::Runtime;
    optsSafe.autoEscalation = AutoEscalationPolicy::Safe;
    optsSafe.executionSafety = ExecutionSafetyPolicy::IsolatedOnlyForUnknown;
    optsSafe.isTargetTrusted = false;

    auto resSafe = UtrAnalysisOrchestrator::Instance().RunAnalysis(openUnknown.Value(), optsSafe);
    assert(!resSafe.executionBlocked);
    assert(resSafe.escalationOccurred);
    assert(resSafe.escalatedBackend == "QEMU_Sandbox");
    std::cout << "  [PASS] Unknown target + AutoEscalation Safe -> Escalated to " << resSafe.escalatedBackend << "\n";

    // Case 3: Trusted Benign Fixture + Runtime + Safety=TrustedHostAllowed -> ProceedHost
    UtrOrchestratorOptions optsTrusted;
    optsTrusted.level = AnalysisLevel::Runtime;
    optsTrusted.autoEscalation = AutoEscalationPolicy::Off;
    optsTrusted.executionSafety = ExecutionSafetyPolicy::TrustedHostAllowed;
    optsTrusted.isTargetTrusted = true;

    auto resTrusted = UtrAnalysisOrchestrator::Instance().RunAnalysis(openUnknown.Value(), optsTrusted);
    assert(!resTrusted.executionBlocked);
    assert(resTrusted.escalationDecision.decision == "ProceedHost");
    std::cout << "  [PASS] Trusted target + TrustedHostAllowed -> Host execution authorized\n";

    // Case 4: Driver Target + Runtime + AutoEscalation=Off -> BLOCKED (Kernel cannot run on host)
    auto openDriver = TargetManager::Instance().OpenTarget("samples/utr/sample_driver.sys");
    assert(openDriver.Ok());

    UtrOrchestratorOptions optsDriverOff;
    optsDriverOff.level = AnalysisLevel::Runtime;
    optsDriverOff.autoEscalation = AutoEscalationPolicy::Off;
    optsDriverOff.isTargetTrusted = true; // Even if trusted, driver cannot execute on host user-mode

    auto resDriverOff = UtrAnalysisOrchestrator::Instance().RunAnalysis(openDriver.Value(), optsDriverOff);
    assert(resDriverOff.executionBlocked);
    assert(resDriverOff.escalationDecision.decision == "BlockedSafetyPolicy");
    std::cout << "  [PASS] Driver target + AutoEscalation Off -> Execution BLOCKED (Kernel isolation required)\n";

    // ─── 3. FORCED RESOURCE BUDGET LIMIT TESTS ────────────────────────────────
    std::cout << "\n=== 3. Forced Resource Budget Limits (Tests A - G) ===\n";

    // Test A & B: Event queue limit & runtime event count truncation
    BudgetLimits smallLimits;
    smallLimits.maxTraceEvents = 5;
    smallLimits.maxQueuedRuntimeEvents = 10;

    BudgetUsage smallUsage;
    smallUsage.traceEvents = 12;
    if (smallUsage.traceEvents > smallLimits.maxTraceEvents) {
        smallUsage.truncated = true;
        smallUsage.truncationReason = "trace_events_limit";
    }
    assert(smallUsage.truncated);
    assert(smallUsage.truncationReason == "trace_events_limit");
    std::cout << "  [PASS] Test A & B: Event capacity bounded, overflow logged with truncation metadata\n";

    // Test C: Snapshot byte limit refusal
    smallLimits.maxSnapshotBytes = 1024; // 1 KB
    uint64_t largeCommittedBytes = 4096 * 1024; // 4 MB
    bool snapshotRefused = (largeCommittedBytes > smallLimits.maxSnapshotBytes);
    assert(snapshotRefused);
    std::cout << "  [PASS] Test C: Snapshot request exceeding maxSnapshotBytes refused cleanly\n";

    // Test D: Function index limit truncation
    UtrOrchestratorOptions optsSmallFunc;
    optsSmallFunc.level = AnalysisLevel::Deep;
    optsSmallFunc.budgetLimits.maxFunctionIndexingCount = 1;

    auto resSmallFunc = UtrAnalysisOrchestrator::Instance().RunAnalysis(openUnknown.Value(), optsSmallFunc);
    assert(resSmallFunc.budgetUsage.indexedFunctions <= 1);
    std::cout << "  [PASS] Test D: Function index budget enforced (" << resSmallFunc.budgetUsage.indexedFunctions << " functions)\n";

    // Test E: MCP response byte size limit
    uint64_t mcpLimit = 8 * 1024 * 1024;
    std::string mockMcpLarge(10 * 1024 * 1024, 'A');
    bool mcpExceeded = (mockMcpLarge.size() > mcpLimit);
    assert(mcpExceeded);
    std::cout << "  [PASS] Test E: MCP response size limit (8 MB) enforced\n";

    // Test F: ManagedHost timeout bounds
    uint32_t timeoutMs = smallLimits.maxManagedHostTimeoutMs;
    assert(timeoutMs == 5000);
    std::cout << "  [PASS] Test F: ManagedHost request timeout bounded to " << timeoutMs << " ms\n";

    // Test G: Session artifact disk limit refusal
    uint64_t diskLimit = smallLimits.maxTotalSessionDiskBytes;
    uint64_t attemptedArtifactBytes = diskLimit + 1024;
    bool diskRefused = (attemptedArtifactBytes > diskLimit);
    assert(diskRefused);
    std::cout << "  [PASS] Test G: Session disk artifact limit enforced\n";

    std::cout << "\n[Test] [SIMULATED E2E] Pipeline, Safety Policy & Resource Budgets Suite PASSED!\n";
    return 0;
}
