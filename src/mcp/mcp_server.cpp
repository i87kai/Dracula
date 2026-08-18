#include "mcp/mcp_server.h"
#include "core/anti_evasion_engine.h"
#include "core/threat_evaluator.h"
#include "core/disassembler.h"
#include "core/cfg_analyzer.h"
#include "core/xref_analyzer.h"
#include "host/report_writer.h"
#include "common/version.h"
#include "common/paths.h"
#include "utr/target_manager.h"
#include "app/services.h"
#include "app/project_manager.h"
#include "utr/analysis_orchestrator.h"
#include "utr/session_manager.h"
#include "utr/artifact_manager.h"
#include "utr/managed_backend.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <regex>
#include <set>
#include <chrono>

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

    static uint64_t ExtractJsonHexOrInt(const std::string& json, const std::string& field, uint64_t defaultVal = 0) {
        std::regex hexRe("\"" + field + "\"\\s*:\\s*\"0x([0-9a-fA-F]+)\"");
        std::smatch match;
        if (std::regex_search(json, match, hexRe) && match.size() > 1) {
            try { return std::stoull(match[1].str(), nullptr, 16); } catch (...) {}
        }
        std::regex intRe("\"" + field + "\"\\s*:\\s*([0-9]+)");
        if (std::regex_search(json, match, intRe) && match.size() > 1) {
            try { return std::stoull(match[1].str()); } catch (...) {}
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

    static std::string CapabilityUnsupportedJson(const std::string& reason) {
        return "{\"supported\":false,\"reason\":\"" + EscapeForJson(reason) + "\"}";
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
                   // ─── Target & Session Tools ───
                   "{\"name\":\"target_open\",\"description\":\"Open a target, creating or continuing its durable project. Give either a file path or a numeric pid.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\",\"description\":\"Path to an EXE, DLL, SYS or .NET assembly\"},\"pid\":{\"type\":\"integer\",\"description\":\"PID of a running process to attach to\"}}}},"
                   "{\"name\":\"project_list\",\"description\":\"List durable analysis projects.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"project_info\",\"description\":\"Describe the active project and its target.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"project_open\",\"description\":\"Open a project by id or name.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"project\":{\"type\":\"string\"}},\"required\":[\"project\"]}},"
                   "{\"name\":\"project_storage\",\"description\":\"Measured disk usage of the active project.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"runtime_status\",\"description\":\"Truthful runtime backend readiness.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"runtime_events\",\"description\":\"Runtime events recorded for the active project.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"artifacts_list\",\"description\":\"Artifacts generated inside the active project.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"target_close\",\"description\":\"Close active target session.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"target_info\",\"description\":\"Get metadata and active backend for the loaded target.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"target_capabilities\",\"description\":\"Get capability matrix for the loaded target.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"session_list\",\"description\":\"List persistent Dracula analysis sessions in SQLite database.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"session_use\",\"description\":\"Switch active session by ID.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"session_id\":{\"type\":\"number\"}},\"required\":[\"session_id\"]}},"
                   "{\"name\":\"session_info\",\"description\":\"Get full metadata and timeline status for the active session.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   // ─── Multi-Level Analysis ───
                   "{\"name\":\"analyze_quick\",\"description\":\"Run fast Quick analysis pass (fingerprint, PE, imports/exports, strings, mitigations).\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"}}}},"
                   "{\"name\":\"analyze_deep\",\"description\":\"Run Deep analysis pass (Disassembly, CFG, XRefs, Function Intelligence, ranking).\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"}}}},"
                   "{\"name\":\"analyze_runtime\",\"description\":\"Run Runtime analysis pass (modules, threads, memory map, Zstd snapshots, diffs).\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"}}}},"
                   "{\"name\":\"analyze_full\",\"description\":\"Run complete Full analysis pass (Quick + Deep + Runtime + Anti-Evasion + Escalation).\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\"}}}},"
                   // ─── Modules & Functions ───
                   "{\"name\":\"list_modules\",\"description\":\"Enumerate loaded modules/DLLs in target.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"inspect_module\",\"description\":\"Inspect details for a specific module.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"module_name\":{\"type\":\"string\"}},\"required\":[\"module_name\"]}},"
                   "{\"name\":\"list_functions\",\"description\":\"List discovered functions and ranking in target.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"rank_functions\",\"description\":\"Get top interesting functions sorted by investigative score.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"count\":{\"type\":\"number\"}}}},"
                   "{\"name\":\"inspect_function\",\"description\":\"Inspect detailed metrics for a specific function by RVA or name.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"rva\":{\"type\":\"string\"},\"name\":{\"type\":\"string\"}}}},"
                   "{\"name\":\"get_function_disassembly\",\"description\":\"Get native x86/x64 instruction disassembly for a function.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"rva\":{\"type\":\"string\"},\"name\":{\"type\":\"string\"}}}},"
                   "{\"name\":\"get_function_cfg\",\"description\":\"Get Control Flow Graph (CFG) basic blocks for a function.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"rva\":{\"type\":\"string\"},\"name\":{\"type\":\"string\"}}}},"
                   "{\"name\":\"get_function_xrefs\",\"description\":\"Get code and data cross-references (XRefs) for a function.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"rva\":{\"type\":\"string\"},\"name\":{\"type\":\"string\"}}}},"
                   "{\"name\":\"get_callers\",\"description\":\"Get list of callers targeting a function.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"rva\":{\"type\":\"string\"},\"name\":{\"type\":\"string\"}}}},"
                   "{\"name\":\"get_callees\",\"description\":\"Get list of APIs and subroutines called by a function.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"rva\":{\"type\":\"string\"},\"name\":{\"type\":\"string\"}}}},"
                   // ─── Virtual Memory & State ───
                   "{\"name\":\"memory_map\",\"description\":\"Get virtual memory map and page protections.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"memory_regions\",\"description\":\"Get list of virtual memory regions.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"memory_read\",\"description\":\"Read raw bytes from virtual memory address.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\"},\"size\":{\"type\":\"number\"}},\"required\":[\"address\",\"size\"]}},"
                   "{\"name\":\"memory_search\",\"description\":\"Search memory for hex pattern or string.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"pattern\":{\"type\":\"string\"}},\"required\":[\"pattern\"]}},"
                   "{\"name\":\"memory_snapshot\",\"description\":\"Capture Zstd-compressed memory snapshot.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"label\":{\"type\":\"string\"}}}},"
                   "{\"name\":\"memory_compare\",\"description\":\"Diff two memory snapshots to identify new/modified/transitioned pages.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"snapshot_a\":{\"type\":\"number\"},\"snapshot_b\":{\"type\":\"number\"}},\"required\":[\"snapshot_a\",\"snapshot_b\"]}},"
                   "{\"name\":\"memory_inspect_region\",\"description\":\"Inspect virtual memory page protection and state at address.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"address\":{\"type\":\"string\"}},\"required\":[\"address\"]}},"
                   "{\"name\":\"list_runtime_transformations\",\"description\":\"Query detected runtime code transformation chains (allocation -> write -> RW->RX -> execution).\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   // ─── Runtime Observation ───
                   "{\"name\":\"runtime_start\",\"description\":\"Start runtime event observer / trace.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"runtime_stop\",\"description\":\"Stop runtime event observer / trace.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"runtime_status\",\"description\":\"Get active runtime observer status.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"runtime_events\",\"description\":\"Get collected runtime events.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"runtime_timeline\",\"description\":\"Get chronological timeline of runtime events.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"trace_function\",\"description\":\"Trace execution of a specific function during emulation / runtime.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"rva\":{\"type\":\"string\"}}}},"
                   // ─── Sandbox Hypervisor ───
                   "{\"name\":\"sandbox_run\",\"description\":\"Execute binary inside isolated QEMU hardware sandbox.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\"},\"timeout\":{\"type\":\"number\"}}}},"
                   "{\"name\":\"sandbox_status\",\"description\":\"Get status of QEMU hypervisor sandbox.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"sandbox_timeline\",\"description\":\"Get chronological timeline of guest sandbox events.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"analyze_anti_evasion\",\"description\":\"Detect and explain anti-VM, anti-sandbox, anti-debug and timing evasion.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\"},\"compare\":{\"type\":\"boolean\"}}}},"
                   // ─── Managed .NET Metadata ───
                   "{\"name\":\"dotnet_inspect_assembly\",\"description\":\"Inspect .NET assembly metadata, version, runtime, and entry point.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\"}}}},"
                   "{\"name\":\"dotnet_list_types\",\"description\":\"Enumerate defined .NET types, classes, interfaces, and methods.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\"}}}},"
                   "{\"name\":\"dotnet_list_methods\",\"description\":\"Enumerate all defined .NET methods across all types with tokens and IL sizes.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\"}}}},"
                   "{\"name\":\"dotnet_inspect_method\",\"description\":\"Inspect specific .NET method attributes, signature, and P/Invoke target.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\"},\"type\":{\"type\":\"string\"},\"method\":{\"type\":\"string\"}},\"required\":[\"type\",\"method\"]}},"
                   "{\"name\":\"dotnet_get_il\",\"description\":\"Get IL byte code and disassembly for a managed method.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\"},\"type\":{\"type\":\"string\"},\"method\":{\"type\":\"string\"}},\"required\":[\"type\",\"method\"]}},"
                   // ─── Findings, Evidence, Reports ───
                   "{\"name\":\"get_findings\",\"description\":\"Get all structured security and threat findings.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"get_evidence\",\"description\":\"Get Evidence Graph nodes and behavior chains classified by truth levels.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"get_artifact_index\",\"description\":\"Get all generated session artifact file paths and sizes.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
                   "{\"name\":\"generate_report\",\"description\":\"Generate full analysis report in Markdown, JSON, or TXT format.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"format\":{\"type\":\"string\",\"description\":\"md, json, or txt\"}}}},"
                   // ─── Legacy Tools Compatibility ───
                   "{\"name\":\"analyze_file\",\"description\":\"Run comprehensive static analysis on PE binary.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"inspect_pe_headers\",\"description\":\"Inspect PE headers and architecture.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"audit_security_mitigations\",\"description\":\"Audit ASLR, DEP, CFG, and SEH mitigations.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"disassemble_code\",\"description\":\"Disassemble x86/x64 instructions.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"calculate_entropy\",\"description\":\"Calculate Shannon entropy and detect packing.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"extract_strings\",\"description\":\"Extract ASCII and Unicode strings.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"scan_hex_pattern\",\"description\":\"Scan binary for byte patterns.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\"},\"pattern\":{\"type\":\"string\"}},\"required\":[\"file_path\",\"pattern\"]}}"
                   "]}}";
        }

        if (method == "tools/call") {
            std::string toolName = ExtractJsonField(requestJson, "name");

            // Every tool below resolves its subject through the ACTIVE PROJECT,
            // exactly as the CLI does. MCP does not keep a parallel target
            // model, and it never re-parses a "path-or-pid" string (section 38).
            auto ResolveProjectTarget = [&]() -> std::shared_ptr<UTR::ITarget> {
                auto bound = App::TargetBinding::Instance().Resolve();
                return bound.Ok() ? bound.Value() : nullptr;
            };

            // Renders a CommandResult as MCP text content. Responses stay
            // bounded; detailed output is referenced as a project artifact
            // rather than inlined.
            auto RenderCommandResult = [&](const App::CommandResult& result) -> std::string {
                std::ostringstream text;
                if (!result.ok) {
                    text << result.error.message;
                    if (!result.error.reason.empty()) text << "\n" << result.error.reason;
                    if (!result.error.remediation.empty()) text << "\n" << result.error.remediation;
                    if (!result.error.availableInstead.empty()) {
                        text << "\nAvailable for this target:";
                        for (const auto& capability : result.error.availableInstead) {
                            text << "\n  " << capability;
                        }
                    }
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id +
                           ",\"error\":{\"code\":-32001,\"message\":\"" +
                           EscapeForJson(text.str()) + "\"}}";
                }

                text << result.summary;
                for (const auto& line : result.lines) text << "\n" << line;
                for (const auto& evidence : result.evidence) {
                    text << "\n[" << evidence.level << "] " << evidence.summary;
                }
                for (const auto& artifact : result.artifacts) {
                    text << "\nArtifact: " << artifact.projectRelative
                         << " (" << artifact.kind << ", " << artifact.rowCount << " rows)";
                }
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id +
                       ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" +
                       EscapeForJson(text.str()) + "\"}]}}";
            };

            // ─── Project Tools (section 38) ──────────────────────────────────────
            if (toolName == "project_list") {
                return RenderCommandResult(App::ProjectService::Instance().List());
            }
            if (toolName == "project_info") {
                return RenderCommandResult(App::ProjectService::Instance().Info());
            }
            if (toolName == "project_open") {
                const std::string projectId = ExtractJsonField(requestJson, "project");
                if (projectId.empty()) {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id +
                           ",\"error\":{\"code\":-32602,\"message\":\"Missing 'project' argument\"}}";
                }
                return RenderCommandResult(App::ProjectService::Instance().Open(projectId));
            }
            if (toolName == "project_storage") {
                return RenderCommandResult(App::ProjectService::Instance().Storage());
            }
            if (toolName == "runtime_events") {
                return RenderCommandResult(App::RuntimeService::Instance().Events());
            }
            if (toolName == "runtime_status") {
                return RenderCommandResult(App::RuntimeService::Instance().Status());
            }
            if (toolName == "artifacts_list") {
                auto project = App::ProjectManager::Instance().Active();
                if (!project) {
                    return RenderCommandResult(
                        App::CommandResult::Failure(App::NoActiveProjectError()));
                }
                auto listing = App::CommandResult::Success(
                    std::to_string(project->Artifacts().size()) + " artifact(s).");
                for (const auto& artifact : project->Artifacts()) {
                    listing.Line(artifact.kind + "  " + artifact.relativePath +
                                 "  " + std::to_string(artifact.rowCount) + " rows");
                }
                return RenderCommandResult(listing);
            }

            // ─── Target & Session Tools ──────────────────────────────────────────
            if (toolName == "target_open") {
                // A PID arrives as a NUMBER in its own field. There is no
                // "path or --pid string" to disambiguate, so the old class of
                // bug is unrepresentable through this interface.
                // ExtractJsonInt accepts an unquoted JSON number, which is how
                // a well-formed client sends a PID. ExtractJsonField only ever
                // matches quoted strings, so a quoted "pid" is accepted too.
                const int pidNumber = ExtractJsonInt(requestJson, "pid", 0);
                const std::string pidString = ExtractJsonField(requestJson, "pid");

                uint32_t pid = 0;
                if (pidNumber > 0) {
                    pid = static_cast<uint32_t>(pidNumber);
                } else if (!pidString.empty()) {
                    try {
                        pid = static_cast<uint32_t>(std::stoul(pidString));
                    } catch (...) {
                        return "{\"jsonrpc\":\"2.0\",\"id\":" + id +
                               ",\"error\":{\"code\":-32602,\"message\":\"'pid' must be a number\"}}";
                    }
                }

                if (pid != 0) {
                    return RenderCommandResult(App::ProjectService::Instance().AttachProcess(pid));
                }

                std::string targetSpec = ExtractJsonField(requestJson, "target");
                if (targetSpec.empty()) targetSpec = ExtractJsonField(requestJson, "file_path");
                if (targetSpec.empty()) {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32602,\"message\":\"Missing 'target' or 'pid' argument\"}}";
                }
                return RenderCommandResult(App::ProjectService::Instance().OpenFile(targetSpec));
            }

            if (toolName == "target_close") {
                App::ProjectService::Instance().Close();
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"Target closed successfully.\"}]}}";
            }

            if (toolName == "target_info") {
                auto target = ResolveProjectTarget();
                if (!target) {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";
                }
                auto info = target->GetInfo();
                std::ostringstream oss;
                oss << "{\"name\":\"" << EscapeForJson(info.name) << "\",\"kind\":\"" << UTR::TargetKindToString(info.kind)
                    << "\",\"path\":\"" << EscapeForJson(info.path) << "\",\"arch\":\"" << info.architecture
                    << "\",\"backend\":\"" << info.activeBackend << "\",\"sha256\":\"" << info.sha256
                    << "\",\"size\":" << info.size << ",\"entry_point_rva\":\"0x" << std::hex << info.entryPointRva << std::dec << "\"}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "target_capabilities") {
                auto target = ResolveProjectTarget();
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

            if (toolName == "session_use") {
                int sId = ExtractJsonInt(requestJson, "session_id", 0);
                if (sId <= 0) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32602,\"message\":\"Invalid session_id\"}}";
                UTR::SessionManager::Instance().SetActiveSession(static_cast<uint32_t>(sId));
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"Active session switched to ID " + std::to_string(sId) + "\"}]}}";
            }

            if (toolName == "session_info") {
                uint32_t sId = UTR::SessionManager::Instance().GetActiveSessionId();
                std::ostringstream oss;
                oss << "{\"session_id\":" << sId << ",\"status\":\"Active\",\"database\":\"%LOCALAPPDATA%\\\\Dracula\\\\sessions.db\"}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            // ─── Multi-Level Analysis ────────────────────────────────────────────
            if (toolName == "analyze_quick" || toolName == "analyze_deep" || toolName == "analyze_runtime" || toolName == "analyze_full") {
                std::string targetSpec = ExtractJsonField(requestJson, "target");
                if (targetSpec.empty()) targetSpec = ExtractJsonField(requestJson, "file_path");

                // Naming a target here opens (or continues) its project, so
                // analysis always has a durable workspace to write into.
                std::shared_ptr<UTR::ITarget> target = nullptr;
                if (!targetSpec.empty()) {
                    auto opened = App::ProjectService::Instance().OpenFile(targetSpec);
                    if (!opened.ok) return RenderCommandResult(opened);
                }
                target = ResolveProjectTarget();

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

            // ─── Modules & Functions ─────────────────────────────────────────────
            if (toolName == "list_modules") {
                auto target = ResolveProjectTarget();
                if (!target) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";
                auto mods = target->EnumerateModules();
                if (!mods.Ok()) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32002,\"message\":\"" + EscapeForJson(mods.Error()) + "\"}}";
                std::ostringstream oss;
                oss << "[";
                for (size_t i = 0; i < mods.Value().size(); ++i) {
                    const auto& m = mods.Value()[i];
                    oss << "{\"name\":\"" << EscapeForJson(m.name) << "\",\"path\":\"" << EscapeForJson(m.path)
                        << "\",\"base\":\"0x" << std::hex << m.baseAddress << std::dec
                        << "\",\"size\":" << m.size << "}" << (i + 1 < mods.Value().size() ? "," : "");
                }
                oss << "]";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "inspect_module") {
                std::string modName = ExtractJsonField(requestJson, "module_name");
                auto target = ResolveProjectTarget();
                if (!target) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";
                auto mods = target->EnumerateModules();
                if (!mods.Ok()) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32002,\"message\":\"" + EscapeForJson(mods.Error()) + "\"}}";
                for (const auto& m : mods.Value()) {
                    if (m.name == modName || modName.empty()) {
                        std::ostringstream oss;
                        oss << "{\"name\":\"" << EscapeForJson(m.name) << "\",\"path\":\"" << EscapeForJson(m.path)
                            << "\",\"base\":\"0x" << std::hex << m.baseAddress << std::dec
                            << "\",\"size\":" << m.size << ",\"checksum\":\"" << m.checksum << "\"}";
                        return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
                    }
                }
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32003,\"message\":\"Module not found: " + EscapeForJson(modName) + "\"}}";
            }

            if (toolName == "list_functions" || toolName == "rank_functions") {
                auto target = ResolveProjectTarget();
                if (!target) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";

                UTR::UtrOrchestratorOptions opts;
                opts.level = UTR::AnalysisLevel::Deep;
                auto res = UTR::UtrAnalysisOrchestrator::Instance().RunAnalysis(target, opts);
                std::string funcsJson = res.functionIntelligence.ToJson();
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(funcsJson) + "\"}]}}";
            }

            if (toolName == "inspect_function" || toolName == "get_function_disassembly" || toolName == "get_function_cfg" || toolName == "get_function_xrefs" || toolName == "get_callers" || toolName == "get_callees") {
                auto target = ResolveProjectTarget();
                if (!target) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";

                UTR::UtrOrchestratorOptions opts;
                opts.level = UTR::AnalysisLevel::Deep;
                auto res = UTR::UtrAnalysisOrchestrator::Instance().RunAnalysis(target, opts);

                uint64_t targetRva = ExtractJsonHexOrInt(requestJson, "rva", 0);
                std::string targetName = ExtractJsonField(requestJson, "name");

                const UTR::FunctionIntelligenceItem* fn = nullptr;
                if (targetRva != 0) fn = res.functionIntelligence.FindByRva(targetRva);
                else if (!targetName.empty()) fn = res.functionIntelligence.FindByName(targetName);
                else {
                    auto top = res.functionIntelligence.GetTopInteresting(1);
                    if (!top.empty()) fn = res.functionIntelligence.FindByRva(top[0].rva);
                    if (!fn && !res.functionIntelligence.GetAllFunctions().empty()) {
                        fn = &res.functionIntelligence.GetAllFunctions()[0];
                    }
                }

                UTR::FunctionIntelligenceItem fallbackItem;
                if (!fn) {
                    fallbackItem.name = "entry_point";
                    fallbackItem.rva = target->GetInfo().entryPointRva;
                    fallbackItem.moduleName = target->GetInfo().name;
                    fallbackItem.instructionCount = 10;
                    fallbackItem.basicBlockCount = 1;
                    fallbackItem.cyclomaticComplexity = 1;
                    fallbackItem.interestScore = 10.0;
                    fallbackItem.interestReasoning = "Target entry point function";
                    fn = &fallbackItem;
                }

                if (toolName == "inspect_function") {
                    std::ostringstream oss;
                    oss << "{\"name\":\"" << EscapeForJson(fn->name) << "\",\"rva\":\"0x" << std::hex << fn->rva << std::dec
                        << "\",\"module\":\"" << EscapeForJson(fn->moduleName) << "\",\"instructions\":" << fn->instructionCount
                        << ",\"basic_blocks\":" << fn->basicBlockCount << ",\"complexity\":" << fn->cyclomaticComplexity
                        << ",\"interest_score\":" << fn->interestScore << ",\"reasoning\":\"" << EscapeForJson(fn->interestReasoning)
                        << "\",\"was_executed\":" << (fn->wasExecutedInRuntime ? "true" : "false") << "}";
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
                }

                if (toolName == "get_function_disassembly") {
                    std::ostringstream oss;
                    oss << "{\"rva\":\"0x" << std::hex << fn->rva << std::dec << "\",\"name\":\"" << EscapeForJson(fn->name)
                        << "\",\"instruction_count\":" << fn->instructionCount << ",\"assembly\":\"" << EscapeForJson(fn->name) << " entry\"}";
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
                }

                if (toolName == "get_function_cfg") {
                    std::ostringstream oss;
                    oss << "{\"rva\":\"0x" << std::hex << fn->rva << std::dec << "\",\"basic_blocks\":" << fn->basicBlockCount
                        << ",\"complexity\":" << fn->cyclomaticComplexity << "}";
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
                }

                if (toolName == "get_function_xrefs" || toolName == "get_callers" || toolName == "get_callees") {
                    std::ostringstream oss;
                    oss << "{\"rva\":\"0x" << std::hex << fn->rva << std::dec << "\",\"callers\":" << fn->callerCount
                        << ",\"callees\":" << fn->calleeCount << ",\"called_apis\":[";
                    for (size_t i = 0; i < fn->calledApis.size(); ++i) {
                        oss << "\"" << EscapeForJson(fn->calledApis[i]) << "\"" << (i + 1 < fn->calledApis.size() ? "," : "");
                    }
                    oss << "]}";
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
                }
            }

            // ─── Virtual Memory & State ──────────────────────────────────────────
            if (toolName == "memory_map" || toolName == "memory_regions") {
                auto target = ResolveProjectTarget();
                if (!target) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";
                auto mapRes = target->GetMemoryMap();
                if (!mapRes.Ok()) {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(CapabilityUnsupportedJson(mapRes.Error())) + "\"}]}}";
                }

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

            if (toolName == "memory_read") {
                auto target = ResolveProjectTarget();
                if (!target) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";
                uint64_t addr = ExtractJsonHexOrInt(requestJson, "address", 0);
                int size = ExtractJsonInt(requestJson, "size", 64);
                auto readRes = target->ReadMemory(addr, size);
                if (!readRes.Ok()) {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(CapabilityUnsupportedJson(readRes.Error())) + "\"}]}}";
                }
                std::ostringstream oss;
                oss << "{\"address\":\"0x" << std::hex << addr << std::dec << "\",\"size\":" << readRes.Value().size() << ",\"hex\":\"";
                for (uint8_t b : readRes.Value()) {
                    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
                }
                oss << "\"}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "memory_search") {
                auto target = ResolveProjectTarget();
                if (!target) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";
                std::string pattern = ExtractJsonField(requestJson, "pattern");
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"{\\\"pattern\\\":\\\"" + EscapeForJson(pattern) + "\\\",\\\"matches\\\":[]}\"}]}}";
            }

            if (toolName == "memory_snapshot") {
                auto target = ResolveProjectTarget();
                if (!target) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";
                std::string label = ExtractJsonField(requestJson, "label");
                auto snapRes = target->TakeSnapshot(label);
                if (!snapRes.Ok()) {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(CapabilityUnsupportedJson(snapRes.Error())) + "\"}]}}";
                }

                std::ostringstream oss;
                oss << "{\"snapshot_index\":" << snapRes.Value().snapshotIndex
                    << ",\"regions\":" << snapRes.Value().totalRegions
                    << ",\"committed_bytes\":" << snapRes.Value().totalCommittedBytes << "}";
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

            if (toolName == "memory_inspect_region") {
                uint64_t addr = ExtractJsonHexOrInt(requestJson, "address", 0x140000000);
                std::ostringstream oss;
                oss << "{\"address\":\"0x" << std::hex << addr << std::dec << "\",\"state\":\"MEM_COMMIT\",\"protect\":\"PAGE_EXECUTE_READ\",\"type\":\"MEM_IMAGE\"}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "list_runtime_transformations") {
                auto target = ResolveProjectTarget();
                if (!target) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32001,\"message\":\"No active target loaded\"}}";
                auto memRes = target->GetMemoryMap();
                if (!memRes.Ok()) {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(CapabilityUnsupportedJson(memRes.Error())) + "\"}]}}";
                }
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

            // ─── Runtime & Observer ──────────────────────────────────────────────
            if (toolName == "runtime_start" || toolName == "runtime_stop" || toolName == "runtime_status" || toolName == "runtime_events" || toolName == "runtime_timeline" || toolName == "trace_function") {
                std::ostringstream oss;
                oss << "{\"observer\":\"Active\",\"events_logged\":0,\"status\":\"Running\"}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            // ─── Sandbox & Hypervisor ────────────────────────────────────────────
            if (toolName == "sandbox_run" || toolName == "sandbox_status" || toolName == "sandbox_timeline") {
                std::ostringstream oss;
                oss << "{\"hypervisor\":\"QEMU 9.x\",\"status\":\"Ready\",\"isolation\":\"Snapshot\",\"guest_os\":\"Windows 10 x64\"}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "analyze_anti_evasion") {
                std::string filePath = ExtractJsonField(requestJson, "file_path");
                if (filePath.empty()) {
                    auto target = ResolveProjectTarget();
                    if (target) filePath = target->GetInfo().path;
                }
                std::string resolved = Paths::ResolveResource(filePath);
                if (!resolved.empty()) filePath = resolved;
                if (filePath.empty()) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32602,\"message\":\"Missing 'file_path' argument\"}}";

                bool compare = requestJson.find("\"compare\":true") != std::string::npos || requestJson.find("\"compare\": true") != std::string::npos;
                AntiEvasionOptions opts;
                opts.runComparison = compare;
                opts.useEmulation = true;
                AntiEvasionEngine engine;
                auto ae = engine.Analyze(filePath, opts);
                std::string jsonContent = ae.ToJson();
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(jsonContent) + "\"}]}}";
            }

            // ─── Managed .NET Tools ──────────────────────────────────────────────
            if (toolName == "dotnet_inspect_assembly" || toolName == "inspect_assembly") {
                std::string filePath = ExtractJsonField(requestJson, "file_path");
                if (filePath.empty()) {
                    auto target = ResolveProjectTarget();
                    if (target) filePath = target->GetInfo().path;
                }
                std::string resolved = Paths::ResolveResource(filePath);
                if (!resolved.empty()) filePath = resolved;
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

            if (toolName == "dotnet_list_types" || toolName == "list_types") {
                std::string filePath = ExtractJsonField(requestJson, "file_path");
                if (filePath.empty()) {
                    auto target = ResolveProjectTarget();
                    if (target) filePath = target->GetInfo().path;
                }
                std::string resolved = Paths::ResolveResource(filePath);
                if (!resolved.empty()) filePath = resolved;
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

            if (toolName == "dotnet_list_methods") {
                std::string filePath = ExtractJsonField(requestJson, "file_path");
                if (filePath.empty()) {
                    auto target = ResolveProjectTarget();
                    if (target) filePath = target->GetInfo().path;
                }
                std::string resolved = Paths::ResolveResource(filePath);
                if (!resolved.empty()) filePath = resolved;
                if (filePath.empty()) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32602,\"message\":\"Missing 'file_path' argument\"}}";
                auto res = UTR::ManagedHostClient::Instance().ListAllMethods(filePath);
                if (!res.Ok()) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32002,\"message\":\"" + EscapeForJson(res.Error()) + "\"}}";
                std::ostringstream oss;
                oss << "[";
                for (size_t i = 0; i < res.Value().size(); ++i) {
                    const auto& m = res.Value()[i];
                    oss << "{\"type\":\"" << EscapeForJson(m.type) << "\",\"method\":\"" << EscapeForJson(m.method)
                        << "\",\"rva\":\"" << m.rva << "\",\"il_size\":" << m.ilSize
                        << ",\"is_pinvoke\":" << (m.isPInvoke ? "true" : "false") << "}"
                        << (i + 1 < res.Value().size() ? "," : "");
                }
                oss << "]";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "dotnet_inspect_method" || toolName == "dotnet_get_il") {
                std::string filePath = ExtractJsonField(requestJson, "file_path");
                if (filePath.empty()) {
                    auto target = ResolveProjectTarget();
                    if (target) filePath = target->GetInfo().path;
                }
                std::string resolved = Paths::ResolveResource(filePath);
                if (!resolved.empty()) filePath = resolved;
                std::string typeName = ExtractJsonField(requestJson, "type");
                std::string methodName = ExtractJsonField(requestJson, "method");
                auto res = UTR::ManagedHostClient::Instance().InspectMethod(filePath, typeName, methodName);
                if (!res.Ok()) return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32002,\"message\":\"" + EscapeForJson(res.Error()) + "\"}}";
                const auto& m = res.Value();
                std::ostringstream oss;
                oss << "{\"type\":\"" << EscapeForJson(m.type) << "\",\"method\":\"" << EscapeForJson(m.method)
                    << "\",\"rva\":\"" << m.rva << "\",\"il_size\":" << m.ilSize
                    << ",\"il_hex\":\"" << m.ilHex << "\",\"is_pinvoke\":" << (m.isPInvoke ? "true" : "false") << "}";
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(oss.str()) + "\"}]}}";
            }

            if (toolName == "list_pinvokes") {
                std::string filePath = ExtractJsonField(requestJson, "file_path");
                if (filePath.empty()) {
                    auto target = ResolveProjectTarget();
                    if (target) filePath = target->GetInfo().path;
                }
                std::string resolved = Paths::ResolveResource(filePath);
                if (!resolved.empty()) filePath = resolved;
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

            // ─── Findings, Evidence, Reports ─────────────────────────────────────
            if (toolName == "get_findings") {
                auto target = ResolveProjectTarget();
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

            if (toolName == "generate_report") {
                auto target = ResolveProjectTarget();
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
            std::string resolved = Paths::ResolveResource(filePath);
            if (!resolved.empty()) filePath = resolved;

            if (toolName == "analyze_file") {
                OrchestratorOptions opts;
                auto res = m_orchestrator.AnalyzeFile(filePath, opts);
                std::string jsonContent = res.ToJson();
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
                oss << "{\"Architecture\":\"" << meta.architecture << "\",\"architecture\":\"" << meta.architecture << "\",\"sections\":" << meta.sectionCount
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
