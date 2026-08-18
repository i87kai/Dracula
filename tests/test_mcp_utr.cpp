#include "mcp/mcp_server.h"
#include <iostream>
#include <cassert>

using namespace Dracula;

int main() {
    std::cout << "[Test] Running Expanded MCP Protocol UTR AI Autonomy Suite...\n";

    McpServer server;

    // 1. Initialize
    std::string initReq = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}";
    std::string initResp = server.ProcessMessage(initReq);
    assert(initResp.find("\"protocolVersion\":\"2024-11-05\"") != std::string::npos);

    // 2. Tools List
    std::string listReq = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}";
    std::string listResp = server.ProcessMessage(listReq);
    assert(listResp.find("\"target_open\"") != std::string::npos);
    assert(listResp.find("\"analyze_quick\"") != std::string::npos);
    assert(listResp.find("\"analyze_deep\"") != std::string::npos);
    assert(listResp.find("\"analyze_runtime\"") != std::string::npos);
    assert(listResp.find("\"analyze_full\"") != std::string::npos);
    assert(listResp.find("\"rank_functions\"") != std::string::npos);
    assert(listResp.find("\"inspect_function\"") != std::string::npos);
    assert(listResp.find("\"get_function_disassembly\"") != std::string::npos);
    assert(listResp.find("\"get_function_cfg\"") != std::string::npos);
    assert(listResp.find("\"get_function_xrefs\"") != std::string::npos);
    assert(listResp.find("\"memory_map\"") != std::string::npos);
    assert(listResp.find("\"memory_snapshot\"") != std::string::npos);
    assert(listResp.find("\"memory_compare\"") != std::string::npos);
    assert(listResp.find("\"dotnet_inspect_assembly\"") != std::string::npos);
    assert(listResp.find("\"dotnet_list_types\"") != std::string::npos);
    assert(listResp.find("\"dotnet_list_methods\"") != std::string::npos);
    assert(listResp.find("\"get_findings\"") != std::string::npos);
    assert(listResp.find("\"get_evidence\"") != std::string::npos);
    assert(listResp.find("\"generate_report\"") != std::string::npos);

    // 3. Target Open (Native Simple EXE)
    std::string openReq = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"target_open\",\"arguments\":{\"target\":\"samples/utr/native_simple.exe\"}}}";
    std::string openResp = server.ProcessMessage(openReq);
    assert(openResp.find("Target opened") != std::string::npos);

    // 4. Target Info & Capabilities
    std::string infoReq = "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"target_info\",\"arguments\":{}}}";
    std::string infoResp = server.ProcessMessage(infoReq);
    assert(infoResp.find("\"name\":\"native_simple.exe\"") != std::string::npos);

    std::string capsReq = "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"target_capabilities\",\"arguments\":{}}}";
    std::string capsResp = server.ProcessMessage(capsReq);
    assert(capsResp.find("\"static\":true") != std::string::npos);

    // 5. Quick, Deep, and Function Ranking Tools
    std::string quickReq = "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"analyze_quick\",\"arguments\":{}}}";
    std::string quickResp = server.ProcessMessage(quickReq);
    assert(quickResp.find("\"analysis_level\":\"Quick\"") != std::string::npos);

    std::string deepReq = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"analyze_deep\",\"arguments\":{}}}";
    std::string deepResp = server.ProcessMessage(deepReq);
    assert(deepResp.find("\"analysis_level\":\"Deep\"") != std::string::npos);

    std::string rankReq = "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\",\"params\":{\"name\":\"rank_functions\",\"arguments\":{\"count\":5}}}";
    std::string rankResp = server.ProcessMessage(rankReq);
    assert(rankResp.find("\"functions\"") != std::string::npos || rankResp.find("\"rva\"") != std::string::npos);

    std::string inspFnReq = "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"inspect_function\",\"arguments\":{}}}";
    std::string inspFnResp = server.ProcessMessage(inspFnReq);
    assert(inspFnResp.find("\"rva\"") != std::string::npos);

    // 6. Memory Map, Snapshot, and Compare Tools
    std::string memReq = "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"tools/call\",\"params\":{\"name\":\"memory_map\",\"arguments\":{}}}";
    std::string memResp = server.ProcessMessage(memReq);
    assert(memResp.find("\"base\"") != std::string::npos);

    std::string snapReq = "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/call\",\"params\":{\"name\":\"memory_snapshot\",\"arguments\":{\"label\":\"TestSnapshot\"}}}";
    std::string snapResp = server.ProcessMessage(snapReq);
    assert(snapResp.find("\"snapshot_index\"") != std::string::npos);

    std::string compReq = "{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"tools/call\",\"params\":{\"name\":\"memory_compare\",\"arguments\":{\"snapshot_a\":1,\"snapshot_b\":1}}}";
    std::string compResp = server.ProcessMessage(compReq);
    assert(compResp.find("\"deltas_count\"") != std::string::npos);

    // 7. Findings, Evidence, and Report Generation
    std::string findReq = "{\"jsonrpc\":\"2.0\",\"id\":13,\"method\":\"tools/call\",\"params\":{\"name\":\"get_findings\",\"arguments\":{}}}";
    std::string findResp = server.ProcessMessage(findReq);
    assert(findResp.find("[") != std::string::npos);

    std::string evidReq = "{\"jsonrpc\":\"2.0\",\"id\":14,\"method\":\"tools/call\",\"params\":{\"name\":\"get_evidence\",\"arguments\":{}}}";
    std::string evidResp = server.ProcessMessage(evidReq);
    assert(evidResp.find("\"nodes\"") != std::string::npos);

    std::string repReq = "{\"jsonrpc\":\"2.0\",\"id\":15,\"method\":\"tools/call\",\"params\":{\"name\":\"generate_report\",\"arguments\":{\"format\":\"md\"}}}";
    std::string repResp = server.ProcessMessage(repReq);
    assert(repResp.find("Dracula UTR Analysis Report") != std::string::npos);

    // 8. Managed .NET Tool Calls
    std::string dotInspReq = "{\"jsonrpc\":\"2.0\",\"id\":16,\"method\":\"tools/call\",\"params\":{\"name\":\"dotnet_inspect_assembly\",\"arguments\":{\"file_path\":\"samples/utr/ManagedFixture.dll\"}}}";
    std::string dotInspResp = server.ProcessMessage(dotInspReq);
    assert(dotInspResp.find("ManagedFixture") != std::string::npos);

    std::string dotTypesReq = "{\"jsonrpc\":\"2.0\",\"id\":17,\"method\":\"tools/call\",\"params\":{\"name\":\"dotnet_list_types\",\"arguments\":{\"file_path\":\"samples/utr/ManagedFixture.dll\"}}}";
    std::string dotTypesResp = server.ProcessMessage(dotTypesReq);
    assert(dotTypesResp.find("ManagedFixture") != std::string::npos);

    std::string dotMethReq = "{\"jsonrpc\":\"2.0\",\"id\":18,\"method\":\"tools/call\",\"params\":{\"name\":\"dotnet_list_methods\",\"arguments\":{\"file_path\":\"samples/utr/ManagedFixture.dll\"}}}";
    std::string dotMethResp = server.ProcessMessage(dotMethReq);
    assert(dotMethResp.find("CalculateHash") != std::string::npos || dotMethResp.find("is_pinvoke") != std::string::npos);

    // 9. Target Close Tool
    std::string closeReq = "{\"jsonrpc\":\"2.0\",\"id\":19,\"method\":\"tools/call\",\"params\":{\"name\":\"target_close\",\"arguments\":{}}}";
    std::string closeResp = server.ProcessMessage(closeReq);
    assert(closeResp.find("Target closed successfully") != std::string::npos);

    std::cout << "[Test] MCP Protocol UTR Suite PASSED! (19/19 requests validated)\n";
    return 0;
}
