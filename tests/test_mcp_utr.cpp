#include "mcp/mcp_server.h"
#include <iostream>
#include <cassert>

using namespace Dracula;

int main() {
    std::cout << "[Test] Running MCP Protocol UTR Suite...\n";

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
    assert(listResp.find("\"memory_map\"") != std::string::npos);
    assert(listResp.find("\"get_evidence\"") != std::string::npos);

    // 3. Target Open Tool
    std::string openReq = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"target_open\",\"arguments\":{\"target\":\"samples/utr/native_simple.exe\"}}}";
    std::string openResp = server.ProcessMessage(openReq);
    assert(openResp.find("Target opened") != std::string::npos);

    // 4. Target Info Tool
    std::string infoReq = "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"target_info\",\"arguments\":{}}}";
    std::string infoResp = server.ProcessMessage(infoReq);
    assert(infoResp.find("\"name\":\"native_simple.exe\"") != std::string::npos);

    // 5. Memory Map Tool
    std::string memReq = "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"memory_map\",\"arguments\":{}}}";
    std::string memResp = server.ProcessMessage(memReq);
    assert(memResp.find("\"base\"") != std::string::npos);

    // 6. Quick Analysis Tool
    std::string anaReq = "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"analyze_quick\",\"arguments\":{}}}";
    std::string anaResp = server.ProcessMessage(anaReq);
    assert(anaResp.find("\"analysis_level\":\"Quick\"") != std::string::npos);

    // 7. Target Close Tool
    std::string closeReq = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"target_close\",\"arguments\":{}}}";
    std::string closeResp = server.ProcessMessage(closeReq);
    assert(closeResp.find("Target closed successfully") != std::string::npos);

    std::cout << "[Test] MCP Protocol UTR Suite PASSED!\n";
    return 0;
}
