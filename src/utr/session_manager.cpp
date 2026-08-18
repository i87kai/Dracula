#include "utr/session_manager.h"
#include "common/paths.h"
#include "sqlite3.h"

#include <iostream>
#include <sstream>
#include <filesystem>
#include <chrono>

namespace fs = std::filesystem;

namespace Dracula {
namespace UTR {

    SessionManager& SessionManager::Instance() {
        static SessionManager instance;
        return instance;
    }

    SessionManager::SessionManager() {
        Initialize();
    }

    SessionManager::~SessionManager() {
        Close();
    }

    bool SessionManager::Initialize(const std::string& dbPath) {
        if (m_initialized && m_db != nullptr) return true;

        m_dbPath = dbPath.empty() ? (fs::path(Paths::SessionsDir()) / "dracula_sessions.db").string() : dbPath;
        try {
            fs::create_directories(fs::path(m_dbPath).parent_path());
        } catch (...) {}

        int rc = sqlite3_open(m_dbPath.c_str(), &m_db);
        if (rc != SQLITE_OK) {
            if (m_db) {
                sqlite3_close(m_db);
                m_db = nullptr;
            }
            return false;
        }

        EnsureSchema();
        m_initialized = true;
        return true;
    }

    void SessionManager::Close() {
        if (m_db) {
            sqlite3_close(m_db);
            m_db = nullptr;
        }
        m_initialized = false;
    }

    void SessionManager::EnsureSchema() {
        if (!m_db) return;

        const char* schemaSql =
            "CREATE TABLE IF NOT EXISTS sessions ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  target_path TEXT,"
            "  target_name TEXT,"
            "  target_kind TEXT,"
            "  target_hash TEXT,"
            "  architecture TEXT,"
            "  active_backend TEXT,"
            "  status TEXT,"
            "  created_at TEXT,"
            "  updated_at TEXT,"
            "  findings_count INTEGER DEFAULT 0,"
            "  functions_count INTEGER DEFAULT 0,"
            "  snapshots_count INTEGER DEFAULT 0,"
            "  threat_score INTEGER DEFAULT 0,"
            "  threat_level TEXT DEFAULT 'Clean'"
            ");"
            "CREATE TABLE IF NOT EXISTS evidence_nodes ("
            "  session_id INTEGER,"
            "  node_id TEXT,"
            "  category TEXT,"
            "  severity TEXT,"
            "  confidence TEXT,"
            "  truth_level TEXT,"
            "  title TEXT,"
            "  description TEXT,"
            "  evidence_data TEXT,"
            "  PRIMARY KEY(session_id, node_id)"
            ");"
            "CREATE TABLE IF NOT EXISTS function_index ("
            "  session_id INTEGER,"
            "  rva INTEGER,"
            "  name TEXT,"
            "  interest_score REAL,"
            "  threat_score REAL,"
            "  instructions INTEGER,"
            "  basic_blocks INTEGER,"
            "  callers INTEGER,"
            "  callees INTEGER,"
            "  executions INTEGER,"
            "  PRIMARY KEY(session_id, rva)"
            ");";

        char* errMsg = nullptr;
        sqlite3_exec(m_db, schemaSql, nullptr, nullptr, &errMsg);
        if (errMsg) {
            sqlite3_free(errMsg);
        }
    }

    uint32_t SessionManager::CreateSession(const TargetInfo& target) {
        if (!m_db) Initialize();
        if (!m_db) return 0;

        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        char timeBuf[64];
        std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));

        const char* insertSql =
            "INSERT INTO sessions (target_path, target_name, target_kind, target_hash, architecture, "
            "active_backend, status, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'Active', ?, ?);";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(m_db, insertSql, -1, &stmt, nullptr) != SQLITE_OK) {
            return 0;
        }

        sqlite3_bind_text(stmt, 1, target.path.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, target.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, TargetKindToString(target.kind), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, target.sha256.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, target.architecture.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, target.activeBackend.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 7, timeBuf, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 8, timeBuf, -1, SQLITE_TRANSIENT);

        uint32_t newId = 0;
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            newId = static_cast<uint32_t>(sqlite3_last_insert_rowid(m_db));
            m_activeSessionId = newId;
        }
        sqlite3_finalize(stmt);
        return newId;
    }

    bool SessionManager::SetActiveSession(uint32_t sessionId) {
        auto s = GetSession(sessionId);
        if (s.has_value()) {
            m_activeSessionId = sessionId;
            return true;
        }
        return false;
    }

    std::optional<SessionRecord> SessionManager::GetActiveSession() const {
        if (m_activeSessionId == 0) return std::nullopt;
        return GetSession(m_activeSessionId);
    }

    std::vector<SessionRecord> SessionManager::ListSessions() const {
        std::vector<SessionRecord> list;
        if (!m_db) return list;

        const char* sql = "SELECT id, target_path, target_name, target_kind, target_hash, architecture, "
                          "active_backend, status, created_at, updated_at, findings_count, functions_count, "
                          "snapshots_count, threat_score, threat_level FROM sessions ORDER BY id ASC;";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return list;
        }

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            SessionRecord r;
            r.id = static_cast<uint32_t>(sqlite3_column_int(stmt, 0));
            r.targetPath = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1) ? sqlite3_column_text(stmt, 1) : reinterpret_cast<const unsigned char*>(""));
            r.targetName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2) ? sqlite3_column_text(stmt, 2) : reinterpret_cast<const unsigned char*>(""));
            r.targetKind = StringToTargetKind(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3) ? sqlite3_column_text(stmt, 3) : reinterpret_cast<const unsigned char*>("")));
            r.targetHash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4) ? sqlite3_column_text(stmt, 4) : reinterpret_cast<const unsigned char*>(""));
            r.architecture = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5) ? sqlite3_column_text(stmt, 5) : reinterpret_cast<const unsigned char*>(""));
            r.activeBackend = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6) ? sqlite3_column_text(stmt, 6) : reinterpret_cast<const unsigned char*>(""));
            r.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7) ? sqlite3_column_text(stmt, 7) : reinterpret_cast<const unsigned char*>(""));
            r.createdAt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8) ? sqlite3_column_text(stmt, 8) : reinterpret_cast<const unsigned char*>(""));
            r.updatedAt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9) ? sqlite3_column_text(stmt, 9) : reinterpret_cast<const unsigned char*>(""));
            r.findingsCount = static_cast<uint32_t>(sqlite3_column_int(stmt, 10));
            r.functionsCount = static_cast<uint32_t>(sqlite3_column_int(stmt, 11));
            r.snapshotsCount = static_cast<uint32_t>(sqlite3_column_int(stmt, 12));
            r.threatScore = sqlite3_column_int(stmt, 13);
            r.threatLevel = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 14) ? sqlite3_column_text(stmt, 14) : reinterpret_cast<const unsigned char*>("Clean"));
            list.push_back(r);
        }
        sqlite3_finalize(stmt);
        return list;
    }

    std::optional<SessionRecord> SessionManager::GetSession(uint32_t sessionId) const {
        if (!m_db) return std::nullopt;

        const char* sql = "SELECT id, target_path, target_name, target_kind, target_hash, architecture, "
                          "active_backend, status, created_at, updated_at, findings_count, functions_count, "
                          "snapshots_count, threat_score, threat_level FROM sessions WHERE id = ?;";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return std::nullopt;
        }

        sqlite3_bind_int(stmt, 1, static_cast<int>(sessionId));

        std::optional<SessionRecord> res = std::nullopt;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            SessionRecord r;
            r.id = static_cast<uint32_t>(sqlite3_column_int(stmt, 0));
            r.targetPath = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1) ? sqlite3_column_text(stmt, 1) : reinterpret_cast<const unsigned char*>(""));
            r.targetName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2) ? sqlite3_column_text(stmt, 2) : reinterpret_cast<const unsigned char*>(""));
            r.targetKind = StringToTargetKind(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3) ? sqlite3_column_text(stmt, 3) : reinterpret_cast<const unsigned char*>("")));
            r.targetHash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4) ? sqlite3_column_text(stmt, 4) : reinterpret_cast<const unsigned char*>(""));
            r.architecture = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5) ? sqlite3_column_text(stmt, 5) : reinterpret_cast<const unsigned char*>(""));
            r.activeBackend = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6) ? sqlite3_column_text(stmt, 6) : reinterpret_cast<const unsigned char*>(""));
            r.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7) ? sqlite3_column_text(stmt, 7) : reinterpret_cast<const unsigned char*>(""));
            r.createdAt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8) ? sqlite3_column_text(stmt, 8) : reinterpret_cast<const unsigned char*>(""));
            r.updatedAt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9) ? sqlite3_column_text(stmt, 9) : reinterpret_cast<const unsigned char*>(""));
            r.findingsCount = static_cast<uint32_t>(sqlite3_column_int(stmt, 10));
            r.functionsCount = static_cast<uint32_t>(sqlite3_column_int(stmt, 11));
            r.snapshotsCount = static_cast<uint32_t>(sqlite3_column_int(stmt, 12));
            r.threatScore = sqlite3_column_int(stmt, 13);
            r.threatLevel = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 14) ? sqlite3_column_text(stmt, 14) : reinterpret_cast<const unsigned char*>("Clean"));
            res = r;
        }
        sqlite3_finalize(stmt);
        return res;
    }

    bool SessionManager::SaveSession(
        uint32_t sessionId,
        const UnifiedAnalysisResult* analysisResult,
        const EvidenceGraph* evidenceGraph,
        const FunctionIntelligenceManager* functionManager,
        const MemoryIntelligenceManager* memoryManager)
    {
        if (!m_db) return false;

        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        char timeBuf[64];
        std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));

        uint32_t findingsCount = analysisResult ? static_cast<uint32_t>(analysisResult->findings.size()) : (evidenceGraph ? static_cast<uint32_t>(evidenceGraph->GetNodes().size()) : 0);
        uint32_t funcsCount = functionManager ? static_cast<uint32_t>(functionManager->TotalDiscovered()) : 0;
        uint32_t snapsCount = memoryManager ? static_cast<uint32_t>(memoryManager->GetSnapshots().size()) : 0;
        int threatScore = analysisResult ? analysisResult->threatScore : 0;
        std::string threatLevel = analysisResult ? analysisResult->threatLevel : "Clean";

        const char* updateSql =
            "UPDATE sessions SET updated_at = ?, status = 'Saved', findings_count = ?, functions_count = ?, "
            "snapshots_count = ?, threat_score = ?, threat_level = ? WHERE id = ?;";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(m_db, updateSql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_text(stmt, 1, timeBuf, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, static_cast<int>(findingsCount));
        sqlite3_bind_int(stmt, 3, static_cast<int>(funcsCount));
        sqlite3_bind_int(stmt, 4, static_cast<int>(snapsCount));
        sqlite3_bind_int(stmt, 5, threatScore);
        sqlite3_bind_text(stmt, 6, threatLevel.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 7, static_cast<int>(sessionId));

        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);

        // Save evidence nodes
        if (evidenceGraph) {
            const char* insertNodeSql =
                "INSERT OR REPLACE INTO evidence_nodes (session_id, node_id, category, severity, confidence, truth_level, title, description, evidence_data) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
            for (const auto& node : evidenceGraph->GetNodes()) {
                sqlite3_stmt* nStmt = nullptr;
                if (sqlite3_prepare_v2(m_db, insertNodeSql, -1, &nStmt, nullptr) == SQLITE_OK) {
                    sqlite3_bind_int(nStmt, 1, static_cast<int>(sessionId));
                    sqlite3_bind_text(nStmt, 2, node.id.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(nStmt, 3, node.category.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(nStmt, 4, SeverityToString(node.severity), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(nStmt, 5, ConfidenceToString(node.confidence), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(nStmt, 6, TruthLevelToString(node.truthLevel), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(nStmt, 7, node.title.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(nStmt, 8, node.description.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(nStmt, 9, node.evidenceData.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_step(nStmt);
                    sqlite3_finalize(nStmt);
                }
            }
        }

        return ok;
    }

    bool SessionManager::DeleteSession(uint32_t sessionId) {
        if (!m_db) return false;

        const char* delSession = "DELETE FROM sessions WHERE id = ?;";
        const char* delEvidence = "DELETE FROM evidence_nodes WHERE session_id = ?;";
        const char* delFuncs = "DELETE FROM function_index WHERE session_id = ?;";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(m_db, delSession, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, static_cast<int>(sessionId));
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }

        if (sqlite3_prepare_v2(m_db, delEvidence, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, static_cast<int>(sessionId));
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }

        if (sqlite3_prepare_v2(m_db, delFuncs, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, static_cast<int>(sessionId));
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }

        if (m_activeSessionId == sessionId) {
            m_activeSessionId = 0;
        }

        return true;
    }

} // namespace UTR
} // namespace Dracula
