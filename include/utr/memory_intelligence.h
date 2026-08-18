#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>

#include "utr/types.h"
#include "utr/evidence_graph.h"

namespace Dracula {
namespace UTR {

    // ─── Memory Protection Constants ───────────────────────────────────────────
    inline std::string ProtectionToString(uint32_t protect) {
        std::string s;
        if (protect == 0x01) return "PAGE_NOACCESS";
        if (protect == 0x02) return "PAGE_READONLY (R)";
        if (protect == 0x04) return "PAGE_READWRITE (RW)";
        if (protect == 0x08) return "PAGE_WRITECOPY (WC)";
        if (protect == 0x10) return "PAGE_EXECUTE (X)";
        if (protect == 0x20) return "PAGE_EXECUTE_READ (RX)";
        if (protect == 0x40) return "PAGE_EXECUTE_READWRITE (RWX)";
        if (protect == 0x80) return "PAGE_EXECUTE_WRITECOPY (XWC)";
        if (protect & 0x100) s += "PAGE_GUARD ";
        if (protect & 0x200) s += "PAGE_NOCACHE ";
        if (protect & 0x400) s += "PAGE_WRITECOMBINE ";
        return s.empty() ? ("0x" + std::to_string(protect)) : s;
    }

    // ─── Virtual Memory Region ────────────────────────────────────────────────
    struct MemoryRegion {
        uint64_t    baseAddress = 0;
        uint64_t    size = 0;
        uint64_t    allocationBase = 0;
        uint32_t    initialProtect = 0;
        uint32_t    currentProtect = 0;
        uint32_t    state = 0;          // MEM_COMMIT, MEM_RESERVE, etc.
        uint32_t    type = 0;           // MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
        std::string moduleName;
        std::string sha256;
        double      entropy = 0.0;
        bool        isExecutable = false;
        bool        isWritable = false;
        bool        isReadable = false;
        std::vector<uint8_t> compressedData; // Optional Zstd chunk
    };

    // ─── Memory Snapshot ───────────────────────────────────────────────────────
    struct MemorySnapshot {
        uint32_t    snapshotIndex = 0;
        int64_t     timestampMs = 0;
        std::string label;
        std::vector<MemoryRegion> regions;
        uint64_t    totalCommittedBytes = 0;
        uint64_t    totalExecutableBytes = 0;
        uint32_t    totalRegions = 0;
    };

    // ─── Memory Region Delta ───────────────────────────────────────────────────
    struct RegionDelta {
        uint64_t    baseAddress = 0;
        uint64_t    size = 0;
        std::string changeType;        // "ALLOCATED", "FREED", "MODIFIED", "PROTECTION_CHANGED"
        uint32_t    oldProtect = 0;
        uint32_t    newProtect = 0;
        double      oldEntropy = 0.0;
        double      newEntropy = 0.0;
        std::string oldSha256;
        std::string newSha256;
        uint64_t    changedBytes = 0;
    };

    struct MemoryComparison {
        uint32_t snapshotA = 0;
        uint32_t snapshotB = 0;
        int64_t  intervalMs = 0;
        std::vector<RegionDelta> deltas;
        uint32_t newRegionsCount = 0;
        uint32_t freedRegionsCount = 0;
        uint32_t modifiedRegionsCount = 0;
        uint32_t protectionTransitionsCount = 0;
        uint32_t rwxTransitionsCount = 0;
    };

    // ─── Runtime Transformation Record ─────────────────────────────────────────
    struct RuntimeTransformation {
        std::string        id;
        uint64_t           regionAddress = 0;
        uint64_t           regionSize = 0;
        uint64_t           originRva = 0;
        std::string        originFunction;
        std::string        writerContext;
        uint64_t           modifiedByteCount = 0;
        std::string        beforeHash;
        std::string        afterHash;
        double             beforeEntropy = 0.0;
        double             afterEntropy = 0.0;
        uint32_t           oldProtect = 0;
        uint32_t           newProtect = 0;
        bool               protectionTransitioned = false; // RW -> RX, etc.
        bool               executionEntered = false;
        uint64_t           entryAddress = 0;
        EvidenceTruthLevel truthLevel = EvidenceTruthLevel::Observed;
        FindingConfidence  confidence = FindingConfidence::High;
        std::vector<std::string> timelineSteps;
        std::string        assessmentSummary;
    };

    // ─── Memory Intelligence Manager ───────────────────────────────────────────
    class MemoryIntelligenceManager {
    public:
        MemoryIntelligenceManager() = default;
        ~MemoryIntelligenceManager() = default;

        // Compression helpers using qualified Zstandard
        static std::vector<uint8_t> CompressZstd(const uint8_t* src, size_t srcSize, int level = 3);
        static std::vector<uint8_t> DecompressZstd(const uint8_t* src, size_t srcSize, size_t expectedSize);

        // Snapshot management
        MemorySnapshot CaptureSnapshot(const std::vector<MemoryRegion>& rawRegions, const std::string& label = "");
        const std::vector<MemorySnapshot>& GetSnapshots() const { return m_snapshots; }
        const MemorySnapshot* GetSnapshot(uint32_t index) const;

        // Comparison & Diffing
        MemoryComparison CompareSnapshots(uint32_t indexA, uint32_t indexB) const;

        // Runtime Transformation Detection
        std::vector<RuntimeTransformation> DetectTransformations(const MemoryComparison& comp,
                                                                 const std::vector<uint64_t>& executedAddresses = {}) const;

        // Export to Evidence Graph
        void CorrelateWithEvidenceGraph(EvidenceGraph& graph, const std::vector<RuntimeTransformation>& transformations) const;

        void Clear();

    private:
        std::vector<MemorySnapshot> m_snapshots;
    };

} // namespace UTR
} // namespace Dracula
