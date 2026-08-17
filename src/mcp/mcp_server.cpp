#include "mcp/mcp_server.h"
#include "host/report_writer.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <regex>

namespace Dracula {

    static std::string ExtractJsonField(const std::string& json, const std::string& field) {
        std::regex re("\"" + field + "\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch match;
        if (std::regex_search(json, match, re) && match.size() > 1) {
            return match[1].str();
        }
        return "";
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
            return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"Dracula-Intelligence-Suite\",\"version\":\"2.0.0\"}}}";
        }

        if (method == "notifications/initialized") {
            return ""; // No response needed for notification
        }

        if (method == "ping") {
            return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{}}";
        }

        if (method == "tools/list") {
            return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"tools\":["
                   "{\"name\":\"analyze_file\",\"description\":\"Run comprehensive static, entropy, and emulation analysis on a Windows PE executable.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\",\"description\":\"Path to the binary\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"inspect_pe_headers\",\"description\":\"Inspect DOS/NT headers, optional headers, and section characteristics.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\",\"description\":\"Path to the binary\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"audit_security_mitigations\",\"description\":\"Audit ASLR, DEP/NX, Control Flow Guard (CFG), SEH, and Authenticode signatures.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\",\"description\":\"Path to the binary\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"disassemble_code\",\"description\":\"Disassemble machine code at binary entry point or specific RVA.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\",\"description\":\"Path to binary\"},\"rva\":{\"type\":\"string\",\"description\":\"Target RVA (optional)\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"extract_strings\",\"description\":\"Extract and classify ASCII and UTF-16LE Unicode strings.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\",\"description\":\"Path to binary\"},\"min_length\":{\"type\":\"number\",\"description\":\"Minimum length (default 4)\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"calculate_entropy\",\"description\":\"Compute Shannon entropy for entire binary and individual sections to detect packing/encryption.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\",\"description\":\"Path to binary\"}},\"required\":[\"file_path\"]}},"
                   "{\"name\":\"scan_hex_pattern\",\"description\":\"Scan binary for wildcard hex pattern (AOB).\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"file_path\":{\"type\":\"string\"},\"pattern\":{\"type\":\"string\",\"description\":\"Hex pattern with ?? wildcards\"}},\"required\":[\"file_path\",\"pattern\"]}}"
                   "]}}";
        }

        if (method == "tools/call") {
            std::string toolName = ExtractJsonField(requestJson, "name");
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

            if (toolName == "inspect_pe_headers") {
                PeInspector insp;
                std::string err;
                if (!insp.LoadFromFile(filePath, err)) {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"isError\":true,\"content\":[{\"type\":\"text\",\"text\":\"PE Parse Error: " + EscapeForJson(err) + "\"}]}}";
                }
                const auto& m = insp.GetMetadata();
                std::ostringstream ss;
                ss << "Architecture: " << m.architecture << "\nImageBase: 0x" << std::hex << m.imageBase << "\nEntryPointRVA: 0x" << m.entryPointRva << "\nSections: " << std::dec << m.sectionCount;
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(ss.str()) + "\"}]}}";
            }

            if (toolName == "audit_security_mitigations") {
                PeInspector insp;
                std::string err;
                if (!insp.LoadFromFile(filePath, err)) {
                    return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"isError\":true,\"content\":[{\"type\":\"text\",\"text\":\"PE Parse Error: " + EscapeForJson(err) + "\"}]}}";
                }
                const auto& sec = insp.GetMitigations();
                std::ostringstream ss;
                ss << "ASLR: " << (sec.hasAslr ? "ON" : "OFF")
                   << "\nDEP: " << (sec.hasDep ? "ON" : "OFF")
                   << "\nCFG: " << (sec.hasCfg ? "ON" : "OFF")
                   << "\nSEH: " << (sec.hasSeh ? "ON" : "OFF")
                   << "\nSignature: " << (sec.hasAuthenticode ? "SIGNED" : "UNSIGNED")
                   << "\nRWX Sections: " << (sec.hasRwxSections ? "DETECTED" : "NONE");
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(ss.str()) + "\"}]}}";
            }

            if (toolName == "calculate_entropy") {
                auto packing = EntropyAnalyzer::AnalyzeBinary(filePath);
                std::ostringstream ss;
                ss << "Overall Entropy: " << std::fixed << std::setprecision(2) << packing.overallEntropy << " / 8.00\nIs Packed: " << (packing.isPacked ? "YES" : "NO");
                if (!packing.detectedPacker.empty()) ss << "\nPacker: " << packing.detectedPacker;
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(ss.str()) + "\"}]}}";
            }

            if (toolName == "extract_strings") {
                PeInspector insp;
                std::string err;
                insp.LoadFromFile(filePath, err);
                StringsAnalyzer sa;
                auto strings = sa.ExtractStrings(insp.GetBuffer(), insp.GetBufferSize(), 5);
                std::ostringstream ss;
                for (const auto& s : strings) {
                    if (s.category != StringCategory::Generic) {
                        ss << "[" << StringCategoryToString(s.category) << "] " << s.value << "\n";
                    }
                }
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(ss.str()) + "\"}]}}";
            }

            if (toolName == "scan_hex_pattern") {
                std::string pattern = ExtractJsonField(requestJson, "pattern");
                auto matches = PatternScanner::ScanFile(filePath, pattern);
                std::ostringstream ss;
                ss << "Matches (" << matches.size() << "):\n";
                for (size_t off : matches) {
                    ss << "0x" << std::hex << off << "\n";
                }
                return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + EscapeForJson(ss.str()) + "\"}]}}";
            }

            return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32601,\"message\":\"Unknown tool: " + toolName + "\"}}";
        }

        return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32601,\"message\":\"Method not found: " + method + "\"}}";
    }

} // namespace Dracula
