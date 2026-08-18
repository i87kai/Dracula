#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <optional>

#include "utr/types.h"
#include "utr/evidence_graph.h"
#include "utr/function_intelligence.h"
#include "utr/memory_intelligence.h"
#include "common/findings.h"

// Forward declaration for SQLite
struct sqlite3;

namespace Dracula {
namespace UTR {

    // ─── Session Metadata Record ───────────────────────────────────────────────
    struct SessionRecord {
        uint32_t    id = 0;
        std::string targetPath;
        std::string targetName;
        TargetKind  targetKind = TargetKind::Unknown;
        std::string targetHash;
        std::string architecture;
        std::string activeBackend;
        std::string status = "Active"; // "Active", "Saved", "Closed"
        std::string createdAt;
        std::string updatedAt;
        uint32_t    findingsCount = 0;
        uint32_t    functionsCount = 0;
        uint32_t    snapshotsCount = 0;
        int         threatScore = 0;
        std::string threatLevel = "Clean";
    };

    // ─── Session Manager ───────────────────────────────────────────────────────
    class SessionManager {
    public:
        static SessionManager& Instance();

        SessionManager();
        ~SessionManager();

        bool Initialize(const std::string& dbPath = "");
        void Close();

        uint32_t CreateSession(const TargetInfo& target);
        bool SetActiveSession(uint32_t sessionId);
        std::optional<SessionRecord> GetActiveSession() const;
        uint32_t GetActiveSessionId() const { return m_activeSessionId; }

        std::vector<SessionRecord> ListSessions() const;
        std::optional<SessionRecord> GetSession(uint32_t sessionId) const;

        bool SaveSession(uint32_t sessionId,
                         const UnifiedAnalysisResult* analysisResult = nullptr,
                         const EvidenceGraph* evidenceGraph = nullptr,
                         const FunctionIntelligenceManager* functionManager = nullptr,
                         const MemoryIntelligenceManager* memoryManager = nullptr);

        bool DeleteSession(uint32_t sessionId);

        std::string GetDatabasePath() const { return m_dbPath; }

    private:
        void EnsureSchema();

        sqlite3*    m_db = nullptr;
        std::string m_dbPath;
        uint32_t    m_activeSessionId = 0;
        bool        m_initialized = false;
    };

} // namespace UTR
} // namespace Dracula
