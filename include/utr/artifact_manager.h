#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>

#include "utr/types.h"
#include "utr/evidence_graph.h"
#include "utr/function_intelligence.h"
#include "utr/memory_intelligence.h"
#include "common/findings.h"

namespace Dracula {
namespace UTR {

    struct ArtifactFileEntry {
        std::string relativePath;
        std::string absolutePath;
        uint64_t    sizeBytes = 0;
        std::string mimeType;
        std::string description;
    };

    struct ArtifactIndex {
        uint32_t    sessionId = 0;
        std::string sessionDir;
        uint64_t    totalBytes = 0;
        std::vector<ArtifactFileEntry> files;
    };

    class ArtifactManager {
    public:
        static ArtifactManager& Instance();

        ArtifactManager() = default;
        ~ArtifactManager() = default;

        // Session directory initialization
        std::string GetSessionArtifactDir(uint32_t sessionId) const;
        bool PrepareSessionDir(uint32_t sessionId);

        // Atomic File Serialization Helpers
        static bool WriteAtomicFile(const std::string& filePath, const std::string& content);
        static bool WriteAtomicBinary(const std::string& filePath, const uint8_t* data, size_t size);

        // Structured artifact serialization
        bool WriteSessionArtifacts(uint32_t sessionId,
                                   const TargetInfo& target,
                                   const UnifiedAnalysisResult* analysisResult,
                                   const EvidenceGraph* evidenceGraph,
                                   const FunctionIntelligenceManager* functionManager,
                                   const MemoryIntelligenceManager* memoryManager);

        // Memory Snapshot serialization
        bool WriteMemorySnapshot(uint32_t sessionId, const MemorySnapshot& snapshot);
        bool WriteMemoryDelta(uint32_t sessionId, const MemoryComparison& comparison);

        // Memory Region Dump serialization
        bool WriteMemoryDump(uint32_t sessionId, uint32_t dumpIndex,
                             uint64_t address, size_t size,
                             const uint8_t* rawData,
                             const std::string& metadataJson,
                             const std::string& disassemblyTxt = "");

        // Artifact Indexing
        ArtifactIndex GetArtifactIndex(uint32_t sessionId) const;
    };

} // namespace UTR
} // namespace Dracula
