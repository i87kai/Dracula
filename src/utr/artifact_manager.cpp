#include "utr/artifact_manager.h"
#include "common/paths.h"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>

namespace fs = std::filesystem;

namespace Dracula {
namespace UTR {

    static std::string EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            if (c == '"') o << "\\\"";
            else if (c == '\\') o << "\\\\";
            else if (c == '\n') o << "\\n";
            else if (c == '\r') o << "\\r";
            else if (c == '\t') o << "\\t";
            else o << c;
        }
        return o.str();
    }

    ArtifactManager& ArtifactManager::Instance() {
        static ArtifactManager instance;
        return instance;
    }

    std::string ArtifactManager::GetSessionArtifactDir(uint32_t sessionId) const {
        std::ostringstream oss;
        oss << "session_" << std::setw(4) << std::setfill('0') << sessionId;
        return (fs::path(Paths::ArtifactsDir()) / oss.str()).string();
    }

    bool ArtifactManager::PrepareSessionDir(uint32_t sessionId) {
        try {
            std::string dir = GetSessionArtifactDir(sessionId);
            fs::create_directories(dir);
            fs::create_directories(fs::path(dir) / "memory");
            fs::create_directories(fs::path(dir) / "dumps");
            return true;
        } catch (...) {
            return false;
        }
    }

    bool ArtifactManager::WriteAtomicFile(const std::string& filePath, const std::string& content) {
        try {
            fs::create_directories(fs::path(filePath).parent_path());
            std::string tmpPath = filePath + ".tmp";
            std::ofstream out(tmpPath, std::ios::binary);
            if (!out.is_open()) return false;
            out.write(content.data(), content.size());
            out.close();

            if (fs::exists(filePath)) {
                fs::remove(filePath);
            }
            fs::rename(tmpPath, filePath);
            return true;
        } catch (...) {
            return false;
        }
    }

    bool ArtifactManager::WriteAtomicBinary(const std::string& filePath, const uint8_t* data, size_t size) {
        try {
            fs::create_directories(fs::path(filePath).parent_path());
            std::string tmpPath = filePath + ".tmp";
            std::ofstream out(tmpPath, std::ios::binary);
            if (!out.is_open()) return false;
            if (data && size > 0) {
                out.write(reinterpret_cast<const char*>(data), size);
            }
            out.close();

            if (fs::exists(filePath)) {
                fs::remove(filePath);
            }
            fs::rename(tmpPath, filePath);
            return true;
        } catch (...) {
            return false;
        }
    }

    bool ArtifactManager::WriteSessionArtifacts(
        uint32_t sessionId,
        const TargetInfo& target,
        const UnifiedAnalysisResult* analysisResult,
        const EvidenceGraph* evidenceGraph,
        const FunctionIntelligenceManager* functionManager,
        const MemoryIntelligenceManager* memoryManager)
    {
        if (!PrepareSessionDir(sessionId)) return false;
        std::string baseDir = GetSessionArtifactDir(sessionId);

        // 1. target.json
        std::ostringstream targetJson;
        targetJson << "{\n";
        targetJson << "  \"name\": \"" << EscapeJson(target.name) << "\",\n";
        targetJson << "  \"path\": \"" << EscapeJson(target.path) << "\",\n";
        targetJson << "  \"kind\": \"" << TargetKindToString(target.kind) << "\",\n";
        targetJson << "  \"architecture\": \"" << target.architecture << "\",\n";
        targetJson << "  \"sha256\": \"" << target.sha256 << "\",\n";
        targetJson << "  \"md5\": \"" << target.md5 << "\",\n";
        targetJson << "  \"size\": " << target.size << ",\n";
        targetJson << "  \"active_backend\": \"" << target.activeBackend << "\"\n";
        targetJson << "}\n";
        WriteAtomicFile((fs::path(baseDir) / "target.json").string(), targetJson.str());

        // 2. evidence.json
        if (evidenceGraph) {
            WriteAtomicFile((fs::path(baseDir) / "evidence.json").string(), evidenceGraph->ToJson());
        }

        // 3. functions.json & functions.md
        if (functionManager) {
            WriteAtomicFile((fs::path(baseDir) / "functions.json").string(), functionManager->ToJson());
            WriteAtomicFile((fs::path(baseDir) / "functions.md").string(), functionManager->ToMarkdownSummary(50));
        }

        // 4. report.md & report.json
        if (analysisResult) {
            WriteAtomicFile((fs::path(baseDir) / "report.md").string(), analysisResult->ToMarkdown());
            WriteAtomicFile((fs::path(baseDir) / "report.json").string(), analysisResult->ToJson());
        }

        // 5. session.json summary
        std::ostringstream sessionJson;
        sessionJson << "{\n";
        sessionJson << "  \"session_id\": " << sessionId << ",\n";
        sessionJson << "  \"target\": \"" << EscapeJson(target.name) << "\",\n";
        sessionJson << "  \"backend\": \"" << EscapeJson(target.activeBackend) << "\",\n";
        sessionJson << "  \"functions_count\": " << (functionManager ? functionManager->TotalDiscovered() : 0) << ",\n";
        sessionJson << "  \"evidence_nodes_count\": " << (evidenceGraph ? evidenceGraph->GetNodes().size() : 0) << ",\n";
        sessionJson << "  \"snapshots_count\": " << (memoryManager ? memoryManager->GetSnapshots().size() : 0) << "\n";
        sessionJson << "}\n";
        WriteAtomicFile((fs::path(baseDir) / "session.json").string(), sessionJson.str());

        return true;
    }

    bool ArtifactManager::WriteMemorySnapshot(uint32_t sessionId, const MemorySnapshot& snapshot) {
        if (!PrepareSessionDir(sessionId)) return false;
        std::string memDir = (fs::path(GetSessionArtifactDir(sessionId)) / "memory").string();

        std::ostringstream snapJson;
        snapJson << "{\n";
        snapJson << "  \"snapshot_index\": " << snapshot.snapshotIndex << ",\n";
        snapJson << "  \"timestamp_ms\": " << snapshot.timestampMs << ",\n";
        snapJson << "  \"label\": \"" << EscapeJson(snapshot.label) << "\",\n";
        snapJson << "  \"total_committed_bytes\": " << snapshot.totalCommittedBytes << ",\n";
        snapJson << "  \"total_executable_bytes\": " << snapshot.totalExecutableBytes << ",\n";
        snapJson << "  \"regions_count\": " << snapshot.regions.size() << ",\n";
        snapJson << "  \"regions\": [\n";

        for (size_t i = 0; i < snapshot.regions.size(); ++i) {
            const auto& r = snapshot.regions[i];
            snapJson << "    {\n";
            snapJson << "      \"base\": \"0x" << std::hex << r.baseAddress << std::dec << "\",\n";
            snapJson << "      \"size\": " << r.size << ",\n";
            snapJson << "      \"protect\": \"" << ProtectionToString(r.currentProtect) << "\",\n";
            snapJson << "      \"entropy\": " << r.entropy << ",\n";
            snapJson << "      \"sha256\": \"" << r.sha256 << "\",\n";
            snapJson << "      \"module\": \"" << EscapeJson(r.moduleName) << "\"\n";
            snapJson << "    }" << (i + 1 < snapshot.regions.size() ? "," : "") << "\n";
        }
        snapJson << "  ]\n";
        snapJson << "}\n";

        std::string jsonFile = (fs::path(memDir) / ("snapshot_" + std::to_string(snapshot.snapshotIndex) + ".json")).string();
        return WriteAtomicFile(jsonFile, snapJson.str());
    }

    bool ArtifactManager::WriteMemoryDelta(uint32_t sessionId, const MemoryComparison& comparison) {
        if (!PrepareSessionDir(sessionId)) return false;
        std::string memDir = (fs::path(GetSessionArtifactDir(sessionId)) / "memory").string();

        std::ostringstream deltaJson;
        deltaJson << "{\n";
        deltaJson << "  \"snapshot_a\": " << comparison.snapshotA << ",\n";
        deltaJson << "  \"snapshot_b\": " << comparison.snapshotB << ",\n";
        deltaJson << "  \"interval_ms\": " << comparison.intervalMs << ",\n";
        deltaJson << "  \"new_regions\": " << comparison.newRegionsCount << ",\n";
        deltaJson << "  \"freed_regions\": " << comparison.freedRegionsCount << ",\n";
        deltaJson << "  \"modified_regions\": " << comparison.modifiedRegionsCount << ",\n";
        deltaJson << "  \"protection_transitions\": " << comparison.protectionTransitionsCount << ",\n";
        deltaJson << "  \"deltas\": [\n";

        for (size_t i = 0; i < comparison.deltas.size(); ++i) {
            const auto& d = comparison.deltas[i];
            deltaJson << "    {\n";
            deltaJson << "      \"base\": \"0x" << std::hex << d.baseAddress << std::dec << "\",\n";
            deltaJson << "      \"size\": " << d.size << ",\n";
            deltaJson << "      \"change_type\": \"" << d.changeType << "\",\n";
            deltaJson << "      \"old_protect\": \"" << ProtectionToString(d.oldProtect) << "\",\n";
            deltaJson << "      \"new_protect\": \"" << ProtectionToString(d.newProtect) << "\",\n";
            deltaJson << "      \"old_entropy\": " << d.oldEntropy << ",\n";
            deltaJson << "      \"new_entropy\": " << d.newEntropy << "\n";
            deltaJson << "    }" << (i + 1 < comparison.deltas.size() ? "," : "") << "\n";
        }
        deltaJson << "  ]\n";
        deltaJson << "}\n";

        std::string deltaFile = (fs::path(memDir) / ("delta_" + std::to_string(comparison.snapshotA) + "_" + std::to_string(comparison.snapshotB) + ".json")).string();
        return WriteAtomicFile(deltaFile, deltaJson.str());
    }

    bool ArtifactManager::WriteMemoryDump(
        uint32_t sessionId, uint32_t dumpIndex,
        uint64_t address, size_t size,
        const uint8_t* rawData,
        const std::string& metadataJson,
        const std::string& disassemblyTxt)
    {
        if (!PrepareSessionDir(sessionId)) return false;
        std::string dumpDir = (fs::path(GetSessionArtifactDir(sessionId)) / "dumps" / ("dump_" + std::to_string(dumpIndex))).string();
        fs::create_directories(dumpDir);

        if (rawData && size > 0) {
            WriteAtomicBinary((fs::path(dumpDir) / "region.bin").string(), rawData, size);
        }
        if (!metadataJson.empty()) {
            WriteAtomicFile((fs::path(dumpDir) / "metadata.json").string(), metadataJson);
        }
        if (!disassemblyTxt.empty()) {
            WriteAtomicFile((fs::path(dumpDir) / "disassembly.txt").string(), disassemblyTxt);
        }

        return true;
    }

    ArtifactIndex ArtifactManager::GetArtifactIndex(uint32_t sessionId) const {
        ArtifactIndex index;
        index.sessionId = sessionId;
        index.sessionDir = GetSessionArtifactDir(sessionId);

        if (!fs::exists(index.sessionDir)) return index;

        try {
            for (const auto& entry : fs::recursive_directory_iterator(index.sessionDir)) {
                if (entry.is_regular_file()) {
                    ArtifactFileEntry fe;
                    fe.absolutePath = entry.path().string();
                    fe.relativePath = fs::relative(entry.path(), index.sessionDir).string();
                    fe.sizeBytes = entry.file_size();
                    fe.mimeType = (entry.path().extension() == ".json") ? "application/json" :
                                  ((entry.path().extension() == ".md") ? "text/markdown" : "application/octet-stream");
                    index.totalBytes += fe.sizeBytes;
                    index.files.push_back(fe);
                }
            }
        } catch (...) {}

        return index;
    }

} // namespace UTR
} // namespace Dracula
