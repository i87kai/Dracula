#include "utr/memory_intelligence.h"
#include <iostream>
#include <vector>
#include <cassert>

using namespace Dracula::UTR;

int main() {
    std::cout << "[Test] Running Memory Intelligence & Transformation Test Suite...\n";

    MemoryIntelligenceManager mgr;

    // 1. Create simulated Memory Snapshot #1 (Before transformation)
    std::vector<MemoryRegion> regions1;
    MemoryRegion r1;
    r1.baseAddress = 0x10000000;
    r1.size = 4096;
    r1.currentProtect = 0x04; // PAGE_READWRITE
    r1.entropy = 0.5;
    r1.sha256 = "HASH_BEFORE_WRITE";
    r1.moduleName = "test.exe";
    regions1.push_back(r1);

    auto snap1 = mgr.CaptureSnapshot(regions1, "T0_Initial");
    assert(snap1.snapshotIndex == 1);
    assert(snap1.regions.size() == 1);

    // 2. Create simulated Memory Snapshot #2 (After payload write + VirtualProtect to RX)
    std::vector<MemoryRegion> regions2;
    MemoryRegion r2;
    r2.baseAddress = 0x10000000;
    r2.size = 4096;
    r2.currentProtect = 0x20; // PAGE_EXECUTE_READ (Transitioned from RW)
    r2.entropy = 5.8;         // Entropy increased
    r2.sha256 = "HASH_AFTER_PAYLOAD_WRITE";
    r2.moduleName = "test.exe";
    regions2.push_back(r2);

    auto snap2 = mgr.CaptureSnapshot(regions2, "T1_PostProtect");
    assert(snap2.snapshotIndex == 2);

    // 3. Diff Snapshots
    MemoryComparison comp = mgr.CompareSnapshots(1, 2);
    assert(comp.snapshotA == 1);
    assert(comp.snapshotB == 2);
    assert(comp.protectionTransitionsCount == 1);
    assert(comp.deltas.size() == 1);
    assert(comp.deltas[0].oldProtect == 0x04);
    assert(comp.deltas[0].newProtect == 0x20);

    // 4. Detect Runtime Transformations with IP Entry (e.g. execution at 0x10000004)
    std::vector<uint64_t> executedIps = { 0x10000004 };
    auto transformations = mgr.DetectTransformations(comp, executedIps);
    assert(!transformations.empty());
    assert(transformations[0].regionAddress == 0x10000000);
    assert(transformations[0].executionObserved);
    assert(transformations[0].truthLevel == EvidenceTruthLevel::Observed);

    // 5. Correlate with EvidenceGraph
    EvidenceGraph graph;
    mgr.CorrelateWithEvidenceGraph(graph, transformations);
    assert(graph.GetNodes().size() >= 1);
    assert(graph.GetChains().size() >= 1);

    std::cout << "[Test] Memory Intelligence Suite PASSED!\n";
    return 0;
}
