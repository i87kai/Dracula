#include "utr/memory_intelligence.h"
#include "zstd.h"

#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <cmath>

namespace Dracula {
namespace UTR {

    std::vector<uint8_t> MemoryIntelligenceManager::CompressZstd(const uint8_t* src, size_t srcSize, int level) {
        if (!src || srcSize == 0) return {};
        size_t maxCompressedSize = ZSTD_compressBound(srcSize);
        std::vector<uint8_t> out(maxCompressedSize);

        size_t cSize = ZSTD_compress(out.data(), maxCompressedSize, src, srcSize, level);
        if (ZSTD_isError(cSize)) {
            return {};
        }
        out.resize(cSize);
        return out;
    }

    std::vector<uint8_t> MemoryIntelligenceManager::DecompressZstd(const uint8_t* src, size_t srcSize, size_t expectedSize) {
        if (!src || srcSize == 0 || expectedSize == 0) return {};
        std::vector<uint8_t> out(expectedSize);

        size_t dSize = ZSTD_decompress(out.data(), expectedSize, src, srcSize);
        if (ZSTD_isError(dSize) || dSize != expectedSize) {
            return {};
        }
        return out;
    }

    MemorySnapshot MemoryIntelligenceManager::CaptureSnapshot(const std::vector<MemoryRegion>& rawRegions, const std::string& label) {
        MemorySnapshot snap;
        snap.snapshotIndex = static_cast<uint32_t>(m_snapshots.size() + 1);
        snap.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        snap.label = label.empty() ? ("Snapshot #" + std::to_string(snap.snapshotIndex)) : label;
        snap.regions = rawRegions;
        snap.totalRegions = static_cast<uint32_t>(rawRegions.size());

        for (const auto& r : rawRegions) {
            if (r.state == 0x1000 /* MEM_COMMIT */) {
                snap.totalCommittedBytes += r.size;
            }
            if (r.isExecutable) {
                snap.totalExecutableBytes += r.size;
            }
        }

        m_snapshots.push_back(snap);
        return snap;
    }

    const MemorySnapshot* MemoryIntelligenceManager::GetSnapshot(uint32_t index) const {
        for (const auto& s : m_snapshots) {
            if (s.snapshotIndex == index) return &s;
        }
        return nullptr;
    }

    MemoryComparison MemoryIntelligenceManager::CompareSnapshots(uint32_t indexA, uint32_t indexB) const {
        MemoryComparison comp;
        comp.snapshotA = indexA;
        comp.snapshotB = indexB;

        const MemorySnapshot* snapA = GetSnapshot(indexA);
        const MemorySnapshot* snapB = GetSnapshot(indexB);
        if (!snapA || !snapB) return comp;

        comp.intervalMs = snapB->timestampMs - snapA->timestampMs;

        std::map<uint64_t, const MemoryRegion*> mapA;
        for (const auto& r : snapA->regions) {
            mapA[r.baseAddress] = &r;
        }

        std::map<uint64_t, const MemoryRegion*> mapB;
        for (const auto& r : snapB->regions) {
            mapB[r.baseAddress] = &r;
        }

        // Check for modified, protection changed, or new regions in B
        for (const auto& kvB : mapB) {
            uint64_t addr = kvB.first;
            const MemoryRegion* regB = kvB.second;
            auto itA = mapA.find(addr);

            if (itA == mapA.end()) {
                // New region allocated
                RegionDelta delta;
                delta.baseAddress = addr;
                delta.size = regB->size;
                delta.changeType = "ALLOCATED";
                delta.oldProtect = 0;
                delta.newProtect = regB->currentProtect;
                delta.oldEntropy = 0.0;
                delta.newEntropy = regB->entropy;
                delta.newSha256 = regB->sha256;
                comp.deltas.push_back(delta);
                comp.newRegionsCount++;
            } else {
                const MemoryRegion* regA = itA->second;
                bool protectChanged = (regA->currentProtect != regB->currentProtect);
                bool hashChanged = (!regA->sha256.empty() && !regB->sha256.empty() && regA->sha256 != regB->sha256);
                bool entropyChanged = (std::abs(regA->entropy - regB->entropy) > 0.05);

                if (protectChanged || hashChanged || entropyChanged) {
                    RegionDelta delta;
                    delta.baseAddress = addr;
                    delta.size = regB->size;
                    delta.oldProtect = regA->currentProtect;
                    delta.newProtect = regB->currentProtect;
                    delta.oldEntropy = regA->entropy;
                    delta.newEntropy = regB->entropy;
                    delta.oldSha256 = regA->sha256;
                    delta.newSha256 = regB->sha256;

                    if (protectChanged) {
                        delta.changeType = "PROTECTION_CHANGED";
                        comp.protectionTransitionsCount++;
                        if (regB->currentProtect == 0x40 /* PAGE_EXECUTE_READWRITE */) {
                            comp.rwxTransitionsCount++;
                        }
                    } else {
                        delta.changeType = "MODIFIED";
                        comp.modifiedRegionsCount++;
                    }
                    comp.deltas.push_back(delta);
                }
            }
        }

        // Check for freed regions in A
        for (const auto& kvA : mapA) {
            if (mapB.find(kvA.first) == mapB.end()) {
                RegionDelta delta;
                delta.baseAddress = kvA.first;
                delta.size = kvA.second->size;
                delta.changeType = "FREED";
                delta.oldProtect = kvA.second->currentProtect;
                delta.newProtect = 0;
                delta.oldEntropy = kvA.second->entropy;
                delta.newEntropy = 0.0;
                delta.oldSha256 = kvA.second->sha256;
                comp.deltas.push_back(delta);
                comp.freedRegionsCount++;
            }
        }

        return comp;
    }

    std::vector<RuntimeTransformation> MemoryIntelligenceManager::DetectTransformations(
        const MemoryComparison& comp,
        const std::vector<uint64_t>& executedAddresses) const
    {
        std::vector<RuntimeTransformation> results;
        uint32_t idCounter = 1;

        for (const auto& d : comp.deltas) {
            // Looking for dynamic code materialization:
            // 1. RW -> RX or RW -> RWX
            // 2. Or new executable region allocated with entropy > 4.0
            bool isRwToRx = (d.oldProtect == 0x04 /* PAGE_READWRITE */ && (d.newProtect == 0x20 || d.newProtect == 0x10));
            bool isRwx = (d.newProtect == 0x40 /* PAGE_EXECUTE_READWRITE */);
            bool isNewExec = (d.changeType == "ALLOCATED" && (d.newProtect & (0x10 | 0x20 | 0x40)));

            if (isRwToRx || isRwx || isNewExec) {
                RuntimeTransformation trans;
                trans.id = "TRANS_" + std::to_string(idCounter++);
                trans.regionAddress = d.baseAddress;
                trans.regionSize = d.size;
                trans.oldProtect = d.oldProtect;
                trans.newProtect = d.newProtect;
                trans.protectionTransitioned = isRwToRx;
                trans.beforeEntropy = d.oldEntropy;
                trans.afterEntropy = d.newEntropy;
                trans.beforeHash = d.oldSha256;
                trans.afterHash = d.newSha256;
                trans.truthLevel = EvidenceTruthLevel::Observed;
                trans.confidence = FindingConfidence::High;

                std::ostringstream ss;
                ss << "Region at 0x" << std::hex << d.baseAddress << " (" << std::dec << d.size << " bytes) ";
                if (isRwToRx) {
                    ss << "transitioned protection from PAGE_READWRITE to " << ProtectionToString(d.newProtect);
                } else if (isRwx) {
                    ss << "configured with PAGE_EXECUTE_READWRITE (RWX)";
                } else {
                    ss << "allocated as executable (" << ProtectionToString(d.newProtect) << ")";
                }
                trans.assessmentSummary = ss.str();

                trans.timelineSteps.push_back("1. Memory region allocated (Base: 0x" + std::to_string(d.baseAddress) + ")");
                trans.timelineSteps.push_back("2. Bytes written to region (Entropy shift: " + std::to_string(d.oldEntropy) + " -> " + std::to_string(d.newEntropy) + ")");
                trans.timelineSteps.push_back("3. Protection modified to executable: " + ProtectionToString(d.newProtect));

                // Check if execution entered this region
                for (uint64_t ip : executedAddresses) {
                    if (ip >= d.baseAddress && ip < d.baseAddress + d.size) {
                        trans.executionEntered = true;
                        trans.entryAddress = ip;
                        trans.timelineSteps.push_back("4. Instruction pointer entered region at address 0x" + std::to_string(ip));
                        break;
                    }
                }

                results.push_back(trans);
            }
        }

        return results;
    }

    void MemoryIntelligenceManager::CorrelateWithEvidenceGraph(
        EvidenceGraph& graph,
        const std::vector<RuntimeTransformation>& transformations) const
    {
        for (const auto& t : transformations) {
            EvidenceNode node;
            node.id = t.id;
            node.category = "MemoryIntelligence";
            node.severity = t.protectionTransitioned ? FindingSeverity::High : FindingSeverity::Medium;
            node.confidence = t.confidence;
            node.truthLevel = t.truthLevel;
            node.title = "Runtime Code Transformation Observed";
            node.description = t.assessmentSummary;
            node.evidenceData = "Base: 0x" + std::to_string(t.regionAddress) + ", Size: " + std::to_string(t.regionSize) + ", NewProtect: " + ProtectionToString(t.newProtect);
            node.provenance.engine = "MemoryIntelligence";
            node.provenance.address = t.regionAddress;
            node.tags = {"Memory", "RuntimeCode", "Transformation"};
            graph.AddEvidence(node);

            BehaviorChain chain;
            chain.chainId = "CHAIN_" + t.id;
            chain.name = "Candidate Runtime Code Transformation";
            chain.description = "Correlated memory allocation, modification, protection transition and execution";
            chain.originRva = t.originRva;
            chain.originFunction = t.originFunction;
            chain.truthLevel = EvidenceTruthLevel::Inferred;
            chain.confidence = FindingConfidence::High;
            chain.evidenceNodeIds = {t.id};
            chain.steps = t.timelineSteps;
            graph.AddBehaviorChain(chain);
        }
    }

    void MemoryIntelligenceManager::Clear() {
        m_snapshots.clear();
    }

} // namespace UTR
} // namespace Dracula
