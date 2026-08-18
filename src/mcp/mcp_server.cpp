#include "mcp/mcp_server.h"
#include "core/anti_evasion_engine.h"
#include "core/threat_evaluator.h"
#include "host/report_writer.h"
#include "common/version.h"
#include "utr/target_manager.h"
#include "utr/analysis_orchestrator.h"
#include "utr/session_manager.h"
#include "utr/artifact_manager.h"
#include "utr/managed_backend.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <regex>
#include <set>

namespace Dracula {

    static std::string ExtractJsonField(const std::string& json, const std::string& field) {
        std::regex re("\"" + field + "\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch match;
        if (std::regex_search(json, match, re) && match.size() > 1) {
            return match[1].str();
        }
        return "";
    }

    static int ExtractJsonInt(const std::string& json, const std::string& field, int defaultVal = 0) {
        std::regex re("\"" + field + "\"\\s*:\\s*([0-9]+)");
        std::smatch match;
        if (std::regex_search(json, match, re) && match.size() > 1) {
            try { return std::stoi(match[1].str()); } catch (...) {}
        }
        return defaultVal;
    }

    static std::string ExtractJsonId(const std::string& json) {
        std::regex re("\"id\"\\s*:\\s*([0-9]+|\"[^\"]+\")");
        std::smatch match;
        if (std::regex_search(json, match, re) && match.size() > 1) {
            return match[1].str();
        }
        return "1";
    }

    static std::string EscapeForJson(const std::string& s) {
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

    McpServer::McpServer() = default;
    McpServer::~McpServer() = default;

    void McpServer::RunStdio() {
        std::string line;
        while (std::getline(std::cin, line)) {
            if (line.empty()) continue;
            std::string response = ProcessMessage(line);
            if (!response.empty()) {
                std::cout << response << "\n" << std::flush;
            }
        }
    }

    std::string McpServer::ProcessMessage(const std::string& requestJson) {
        std::string method = ExtractJsonField(requestJson, "method");
        std::string id = ExtractJsonId(requestJson);

        if (method == "initialize") {
            return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"Dracula-Intelligence-Suite\",\"version\":\"" + std::string(Version::String) + "\"}}}";
        }

        if (method == "notifications/initialized") {
            return "";
        }

        if (method == "ping") {
            return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{}}";
        }

        if (method == "tools/list") {
            return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"tools\":["
                   // Legacy Core Tools
                   "{\"name\":\"analyze_file\",\"description\":\"Run comprehensive static, entropy, and emulation analysis on a Windows PE executable.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\",\"description\":\"Path to the binary\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"inspect_pe_headers\",\"description\":\"Inspect DOS/NT headers, optional headers, and section characteristics.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\",\"description\":\"Path to the binary\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"audit_security_mitigations\",\"description\":\"Audit ASLR, DEP/NX, Control Flow Guard (CFG), SEH, and Authenticode signatures.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\",\"description\":\"Path to the binary\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"disassemble_code\",\"description\":\"Disassemble machine code at binary entry point or specific RVA.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\",\"description\":\"Path to binary\"},\"rva\":{\"type\":\"string\",\"description\":\"Target RVA (optional)\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"extract_strings\",\"description\":\"Extract and classify ASCII and UTF-16LE Unicode strings.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\",\"description\":\"Path to binary\"},\"min_length\":{\"type\":\"number\",\"description\":\"Minimum length (default 4)\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"calculate_entropy\",\"description\":\"Compute Shannon entropy for entire binary and individual sections to detect packing/encryption.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\",\"description\":\"Path to binary\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"scan_hex_pattern\",\"description\":\"Scan binary for wildcard hex pattern (AOB).\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\"},\"pattern\":{\"type\":\"string\",\"description\":\"Hex pattern with ?? wildcards\"}},\"required\":[\"file_path\",\"pattern\"]}},"
                   "{\"name\":\"analyze_anti_evasion\",\"description\":\"Detect and explain anti-VM, anti-sandbox, anti-debug and timing evasion.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\",\"description\":\"Path to the binary\"},\"compare\":{\"type\":\"boolean\",\"description\":\"Run differential execution\"}},\"required\":[\"file_path\"]}},"
                   // UTR Universal Target Intelligence Tools
                   "{\"name\":\"target_open\",\"description\":\"Open and fingerprint target (EXE, DLL, PID, Service, .NET, Driver, VM).\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\",\"description\":\"File path, --pid <pid>, or --service <name>\"}},\"required\":[\"target\"]}},"
                   "{\"name\":\"target_close\",\"description\":\"Close active target session.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"target_info\",\"description\":\"Get metadata and active backend for the loaded target.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"target_capabilities\",\"description\":\"Get capability matrix for the loaded target.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"session_list\",\"description\":\"List persistent Dracula analysis sessions in SQLite database.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"session_use\",\"description\":\"Switch active session by ID.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"session_id\":{\"type\":\"number\"}},\"required\":[\"session_id\"]}},"
                   "{\"name\":\"analyze_quick\",\"description\":\"Run fast Quick analysis pass (fingerprint, PE, imports/exports, strings, mitigations).\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"}}}},"
                   "{\"name\":\"analyze_deep\",\"description\":\"Run Deep analysis pass (Disassembly, CFG, XRefs, Function Intelligence, ranking).\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"}}}},"
                   "{\"name\":\"analyze_runtime\",\"description\":\"Run Runtime analysis pass (modules, threads, memory map, Zstd snapshots, diffs).\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"}}}},"
                   "{\"name\":\"analyze_full\",\"description\":\"Run complete Full analysis pass (Quick + Deep + Runtime + Anti-Evasion + Escalation).\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"}}}},"
                   "{\"name\":\"list_modules\",\"description\":\"Enumerate loaded modules/DLLs in target.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"list_functions\",\"description\":\"List discovered functions and ranking in target.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"rank_functions\",\"description\":\"Get top interesting functions sorted by investigative score.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"count\":{\"type\":\"number\"}}}},"
                   "{\"name\":\"memory_map\",\"description\":\"Get virtual memory map and page protections.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"memory_snapshot\",\"description\":\"Capture Zstd-compressed memory snapshot.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"label\":{\"type\":\"string\"}}}},"
                   "{\"name\":\"memory_compare\",\"description\":\"Diff two memory snapshots to identify new/modified/transitioned pages.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"snapshot_a\":{\"type\":\"number\"},\"snapshot_b\":{\"type\":\"number\"}},\"required\":[\"snapshot_a\",\"snapshot_b\"]}},"
                   "{\"name\":\"list_runtime_transformations\",\"description\":\"Query detected runtime code transformation chains (allocation -> write -> RW->RX -> execution).\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"get_findings\",\"description\":\"Get all structured security and threat findings.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"get_evidence\",\"description\":\"Get Evidence Graph nodes and behavior chains classified by truth levels.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"get_artifact_index\",\"description\":\"Get all generated session artifact file paths and sizes.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"generate_report\",\"description\":\"Generate full analysis report in Markdown, JSON, or TXT format.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"format\":{\"type\":\"string\",\"description\":\"md, json, or txt\"}}}}"
                   "]}}";
        }

        if (method == "tools/call") {
            std::string toolName = ExtractJsonField(requestJson, "name");

            // ─── UTR Tools ───────────────────────────────────────────────
            if (toolName == "target_open") {
                std::string targetSpec = ExtractJsonField(requestJson, "target");
                if (targetSpec.empty()) {
                    targetSpec = ExtractJsonField(requestJson, "file_path");
                }
                if (targetSpec.empty()) {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32602,\"message\":\"Missing 'target' argument\"}}";
                }
                auto res = UTR::TargetManager::Instance().OpenTarget(targetSpec);
                if (!res.Ok()) {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32000,\"message\":\"" + EscapeForJson(res.Error()) + "\"}}";
                }
                auto info = res.Value()->GetInfo();
                std::string content = "Target opened: " + info.name + " (" + UTR::TargetKindToString(info.kind) + "), Backend: " + info.activeBackend;
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(content) + "\"}]}}";
            }

            if (toolName == "target_close") {
                UTR::TargetManager::Instance().CloseActiveTarget();
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"Target closed successfully.\"}]}}";
            }

            if (toolName == "target_info") {
                auto target = UTR::TargetManager::Instance().GetActiveTarget();
                if (!target) {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";
                }
                auto info = target->GetInfo();
                std::ostringstream oss;
                oss << "{\"name\":\"" << EscapeForJson(info.name) << "\",\"kind\":\"" << UTR::TargetKindToString(info.kind)
                    << "\",\"path\":\"" << EscapeForJson(info.path) << "\",\"arch\":\"" << info.architecture
                    << "\",\"backend\":\"" << info.activeBackend << "\",\"sha256\":\"" << info.sha256 << "\"}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "target_capabilities") {
                auto target = UTR::TargetManager::Instance().GetActiveTarget();
                if (!target) {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";
                }
                auto caps = target->GetCapabilities();
                std::ostringstream oss;
                oss << "{\"static\":" << (caps.staticAnalysis?"true":"false")
                    << ",\"modules\":" << (caps.modules?"true":"false")
                    << ",\"threads\":" << (caps.threads?"true":"false")
                    << ",\"memory_read\":" << (caps.memoryRead?"true":"false")
                    << ",\"snapshots\":" << (caps.memorySnapshots?"true":"false")
                    << ",\"events\":" << (caps.runtimeEvents?"true":"false")
                    << ",\"functions\":" << (caps.functions?"true":"false")
                    << ",\"symbols\":" << (caps.symbols?"true":"false")
                    << ",\"managed\":" << (caps.managedMetadata?"true":"false")
                    << ",\"debug\":" << (caps.debugControl?"true":"false")
                    << ",\"sandbox\":" << (caps.sandboxExecution?"true":"false")
                    << ",\"kernel\":" << (caps.kernelObservation?"true":"false") << "}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "session_list") {
                auto sessions = UTR::SessionManager::Instance().ListSessions();
                std::ostringstream oss;
                oss << "[";
                for (size_t i = 0; i < sessions.size(); ++i) {
                    oss << "{\"id\":" << sessions[i].id << ",\"target\":\"" << EscapeForJson(sessions[i].targetName)
                        << "\",\"kind\":\"" << UTR::TargetKindToString(sessions[i].targetKind)
                        << "\",\"status\":\"" << sessions[i].status << "\"}" << (i + 1 < sessions.size() ? "," : "");
                }
                oss << "]";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "analyze_quick" || toolName == "analyze_deep" || toolName == "analyze_runtime" || toolName == "analyze_full") {
                std::string targetSpec = ExtractJsonField(requestJson, "target");
                if (targetSpec.empty()) targetSpec = ExtractJsonField(requestJson, "file_path");

                std::shared_ptr<UTR::ITarget> target = nullptr;
                if (!targetSpec.empty()) {
                    auto openRes = UTR::TargetManager::Instance().OpenTarget(targetSpec);
                    if (openRes.Ok()) target = openRes.Value();
                } else {
                    target = UTR::TargetManager::Instance().GetActiveTarget();
                }

                if (!target) {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No target loaded or specified\"}}";
                }

                UTR::UtrOrchestratorOptions opts;
                if (toolName == "analyze_quick") opts.level = UTR::AnalysisLevel::Quick;
                else if (toolName == "analyze_deep") opts.level = UTR::AnalysisLevel::Deep;
                else if (toolName == "analyze_runtime") opts.level = UTR::AnalysisLevel::Runtime;
                else opts.level = UTR::AnalysisLevel::Full;

                auto res = UTR::UtrAnalysisOrchestrator::Instance().RunAnalysis(target, opts);
                std::string jsonContent = res.ToJson();
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(jsonContent) + "\"}]}}";
            }

            if (toolName == "rank_functions" || toolName == "list_functions") {
                auto target = UTR::TargetManager::Instance().GetActiveTarget();
                if (!target) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";

                UTR::UtrOrchestratorOptions opts;
                opts.level = UTR::AnalysisLevel::Deep;
                auto res = UTR::UtrAnalysisOrchestrator::Instance().RunAnalysis(target, opts);
                std::string funcsJson = res.functionIntelligence.ToJson();
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(funcsJson) + "\"}]}}";
            }

            if (toolName == "memory_map") {
                auto target = UTR::TargetManager::Instance().GetActiveTarget();
                if (!target) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";
                auto mapRes = target->GetMemoryMap();
                if (!mapRes.Ok()) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32002,\"message\":\"" + EscapeForJson(mapRes.Error()) + "\"}}";

                std::ostringstream oss;
                oss << "[";
                const auto& regions = mapRes.Value();
                for (size_t i = 0; i < regions.size(); ++i) {
                    oss << "{\"base\":\"0x" << std::hex << regions[i].baseAddress << std::dec
                        << "\",\"size\":" << regions[i].size
                        << ",\"protect\":\"" << UTR::ProtectionToString(regions[i].currentProtect) << "\"}"
                        << (i + 1 < regions.size() ? "," : "");
                }
                oss << "]";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "memory_snapshot") {
                auto target = UTR::TargetManager::Instance().GetActiveTarget();
                if (!target) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";
                std::string label = ExtractJsonField(requestJson, "label");
                auto snapRes = target->TakeSnapshot(label);
                if (!snapRes.Ok()) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32002,\"message\":\"" + EscapeForJson(snapRes.Error()) + "\"}}";

                std::ostringstream oss;
                oss << "{\"snapshot_index\":" << snapRes.Value().snapshotIndex
                    << ",\"regions\":" << snapRes.Value().totalRegions
                    << ",\"committed_bytes\":" << snapRes.Value().totalCommittedBytes << "}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "get_evidence") {
                auto& graph = UTR::TargetManager::Instance().GetEvidenceGraph();
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(graph.ToJson()) + "\"}]}}";
            }

            if (toolName == "get_artifact_index") {
                uint32_t sId = UTR::SessionManager::Instance().GetActiveSessionId();
                auto index = UTR::ArtifactManager::Instance().GetArtifactIndex(sId);
                std::ostringstream oss;
                oss << "{\"session_id\":" << index.sessionId << ",\"total_bytes\":" << index.totalBytes << ",\"files\":[";
                for (size_t i = 0; i < index.files.size(); ++i) {
                    oss << "{\"path\":\"" << EscapeForJson(index.files[i].relativePath)
                        << "\",\"size\":" << index.files[i].sizeBytes << "}" << (i + 1 < index.files.size() ? "," : "");
                }
                oss << "]}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "list_modules") {
                auto target = UTR::TargetManager::Instance().GetActiveTarget();
                if (!target) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";
                auto mods = target->EnumerateModules();
                if (!mods.Ok()) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32002,\"message\":\"" + EscapeForJson(mods.Error()) + "\"}}";
                std::ostringstream oss;
                oss << "[";
                for (size_t i = 0; i < mods.Value().size(); ++i) {
                    const auto& m = mods.Value()[i];
                    oss << "{\"name\":\"" << EscapeForJson(m.name) << "\",\"path\":\"" << EscapeForJson(m.path)
                        << "\",\"base\":\"0x" << std::hex << m.baseAddress << std::dec << "\"}"
                        << (i + 1 < mods.Value().size() ? "," : "");
                }
                oss << "]";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "get_findings") {
                auto target = UTR::TargetManager::Instance().GetActiveTarget();
                if (!target) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";
                UTR::UtrOrchestratorOptions opts;
                opts.level = UTR::AnalysisLevel::Quick;
                auto res = UTR::UtrAnalysisOrchestrator::Instance().RunAnalysis(target, opts);
                std::ostringstream oss;
                oss << "[";
                for (size_t i = 0; i < res.staticResult.findings.size(); ++i) {
                    const auto& f = res.staticResult.findings[i];
                    oss << "{\"id\":\"" << f.id << "\",\"title\":\"" << EscapeForJson(f.title)
                        << "\",\"severity\":\"" << SeverityToString(f.severity)
                        << "\",\"confidence\":\"" << ConfidenceToString(f.confidence)
                        << "\",\"description\":\"" << EscapeForJson(f.description) << "\"}"
                        << (i + 1 < res.staticResult.findings.size() ? "," : "");
                }
                oss << "]";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "list_runtime_transformations") {
                auto target = UTR::TargetManager::Instance().GetActiveTarget();
                if (!target) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";
                auto memRes = target->GetMemoryMap();
                if (!memRes.Ok()) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32002,\"message\":\"" + EscapeForJson(memRes.Error()) + "\"}}";
                UTR::MemoryIntelligenceManager mgr;
                mgr.CaptureSnapshot(memRes.Value(), "Snap1");
                mgr.CaptureSnapshot(memRes.Value(), "Snap2");
                auto comp = mgr.CompareSnapshots(1, 2);
                auto trans = mgr.DetectTransformations(comp);
                std::ostringstream oss;
                oss << "[";
                for (size_t i = 0; i < trans.size(); ++i) {
                    oss << "{\"id\":\"" << trans[i].id << "\",\"address\":\"0x" << std::hex << trans[i].regionAddress << std::dec
                        << "\",\"size\":" << trans[i].regionSize << ",\"summary\":\"" << EscapeForJson(trans[i].assessmentSummary) << "\"}"
                        << (i + 1 < trans.size() ? "," : "");
                }
                oss << "]";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "memory_compare") {
                int snapA = ExtractJsonInt(requestJson, "snapshot_a", 1);
                int snapB = ExtractJsonInt(requestJson, "snapshot_b", 2);
                UTR::MemoryIntelligenceManager mgr;
                auto comp = mgr.CompareSnapshots(snapA, snapB);
                std::ostringstream oss;
                oss << "{\"snapshot_a\":" << comp.snapshotA << ",\"snapshot_b\":" << comp.snapshotB
                    << ",\"deltas_count\":" << comp.deltas.size()
                    << ",\"transitions\":" << comp.protectionTransitionsCount << "}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "inspect_assembly") {
                std::string filePath = ExtractJsonField(requestJson, "file_path");
                if (filePath.empty()) {
                    auto target = UTR::TargetManager::Instance().GetActiveTarget();
                    if (target) filePath = target->GetInfo().path;
                }
                if (filePath.empty()) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32602,\"message\":\"Missing 'file_path' argument\"}}";
                auto res = UTR::ManagedHostClient::Instance().InspectAssembly(filePath);
                if (!res.Ok()) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32002,\"message\":\"" + EscapeForJson(res.Error()) + "\"}}";
                const auto& a = res.Value();
                std::ostringstream oss;
                oss << "{\"assembly_name\":\"" << EscapeForJson(a.assemblyName) << "\",\"version\":\"" << a.version
                    << "\",\"types\":" << a.typeCount << ",\"methods\":" << a.methodCount
                    << ",\"entry_point\":\"" << a.entryPoint << "\"}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "list_types") {
                std::string filePath = ExtractJsonField(requestJson, "file_path");
                if (filePath.empty()) {
                    auto target = UTR::TargetManager::Instance().GetActiveTarget();
                    if (target) filePath = target->GetInfo().path;
                }
                if (filePath.empty()) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32602,\"message\":\"Missing 'file_path' argument\"}}";
                auto res = UTR::ManagedHostClient::Instance().ListTypes(filePath);
                if (!res.Ok()) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32002,\"message\":\"" + EscapeForJson(res.Error()) + "\"}}";
                std::ostringstream oss;
                oss << "[";
                for (size_t i = 0; i < res.Value().size(); ++i) {
                    const auto& t = res.Value()[i];
                    oss << "{\"name\":\"" << EscapeForJson(t.fullName) << "\",\"base\":\"" << EscapeForJson(t.baseType)
                        << "\",\"methods\":" << t.methodCount << "}" << (i + 1 < res.Value().size() ? "," : "");
                }
                oss << "]";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "list_pinvokes") {
                std::string filePath = ExtractJsonField(requestJson, "file_path");
                if (filePath.empty()) {
                    auto target = UTR::TargetManager::Instance().GetActiveTarget();
                    if (target) filePath = target->GetInfo().path;
                }
                if (filePath.empty()) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32602,\"message\":\"Missing 'file_path' argument\"}}";
                auto res = UTR::ManagedHostClient::Instance().ListPInvokes(filePath);
                if (!res.Ok()) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32002,\"message\":\"" + EscapeForJson(res.Error()) + "\"}}";
                std::ostringstream oss;
                oss << "[";
                for (size_t i = 0; i < res.Value().size(); ++i) {
                    const auto& p = res.Value()[i];
                    oss << "{\"type\":\"" << EscapeForJson(p.type) << "\",\"method\":\"" << EscapeForJson(p.method)
                        << "\",\"dll\":\"" << EscapeForJson(p.dll) << "\",\"entry_point\":\"" << EscapeForJson(p.entryPoint) << "\"}"
                        << (i + 1 < res.Value().size() ? "," : "");
                }
                oss << "]";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "generate_report") {
                auto target = UTR::TargetManager::Instance().GetActiveTarget();
                if (!target) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";
                UTR::UtrOrchestratorOptions opts;
                opts.level = UTR::AnalysisLevel::Full;
                auto res = UTR::UtrAnalysisOrchestrator::Instance().RunAnalysis(target, opts);
                std::string rep = res.ToMarkdown();
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(rep) + "\"}]}}";
            }

            // ─── Legacy Tools Fallback ────────────────────────────────────
            static const std::set<std::string> kLegacyTools = {
                "analyze_file",
                "analyze_anti_evasion",
                "inspect_pe_headers",
                "audit_security_mitigations",
                "calculate_entropy",
                "extract_strings",
                "scan_hex_pattern"
            };

            if (kLegacyTools.find(toolName) == kLegacyTools.end()) {
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32601,\"message\":\"Unknown tool: " + EscapeForJson(toolName) + "\"}}";
            }

            std::string filePath = ExtractJsonField(requestJson, "file_path");
            if (filePath.empty()) {
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32602,\"message\":\"Missing required 'file_path' argument\"}}";
            }

            if (toolName == "analyze_file") {
                OrchestratorOptions opts;
                auto res = m_orchestrator.AnalyzeFile(filePath, opts);
                std::string jsonContent = res.ToJson();
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(jsonContent) + "\"}]}}";
            }

            if (toolName == "analyze_anti_evasion") {
                AntiEvasionOptions opts;
                std::smatch compareMatch;
                std::regex compareRe("\"compare\"\\s*:\\s*(true|false)");
                if (std::regex_search(requestJson, compareMatch, compareRe) && compareMatch.size() > 1) {
                    opts.runComparison = (compareMatch[1].str() == "true");
                }
                opts.detailed = true;
                AntiEvasionEngine engine;
                auto ae = engine.Analyze(filePath, opts);
                std::string jsonContent = ae.ToJson();
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(jsonContent) + "\"}]}}";
            }

            if (toolName == "inspect_pe_headers") {
                PeInspector inspector;
                std::string err;
                if (!inspector.LoadFromFile(filePath, err)) {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32000,\"message\":\"" + EscapeForJson(err) + "\"}}";
                }
                auto meta = inspector.GetMetadata();
                std::ostringstream oss;
                oss << "{\"architecture\":\"" << meta.architecture << "\",\"sections\":" << meta.sectionCount
                    << ",\"entry_point_rva\":\"0x" << std::hex << meta.entryPointRva << std::dec << "\"}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "audit_security_mitigations") {
                PeInspector inspector;
                std::string err;
                if (!inspector.LoadFromFile(filePath, err)) {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32000,\"message\":\"" + EscapeForJson(err) + "\"}}";
                }
                auto sec = inspector.GetMitigations();
                std::ostringstream oss;
                oss << "{\"aslr\":" << (sec.hasAslr?"true":"false") << ",\"dep\":" << (sec.hasDep?"true":"false")
                    << ",\"cfg\":" << (sec.hasCfg?"true":"false") << ",\"seh\":" << (sec.hasSeh?"true":"false") << "}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "calculate_entropy") {
                auto res = EntropyAnalyzer::AnalyzeBinary(filePath);
                std::ostringstream oss;
                oss << "{\"overall_entropy\":" << res.overallEntropy << ",\"is_packed\":" << (res.isPacked?"true":"false") << "}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "extract_strings") {
                PeInspector insp;
                std::string err;
                if (!insp.LoadFromFile(filePath, err)) {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32000,\"message\":\"" + EscapeForJson(err) + "\"}}";
                }
                StringsAnalyzer analyzer;
                auto strings = analyzer.ExtractStrings(insp.GetBuffer(), insp.GetBufferSize(), 4);
                std::ostringstream oss;
                oss << "{\"count\":" << strings.size() << "}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "scan_hex_pattern") {
                std::string pattern = ExtractJsonField(requestJson, "pattern");
                PatternScanner scanner;
                auto matches = scanner.ScanFile(filePath, pattern);
                std::ostringstream oss;
                oss << "{\"matches_count\":" << matches.size() << "}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }
        }

        return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}";
    }

} // namespace Dracula
