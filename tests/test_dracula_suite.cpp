#include "common/findings.h"
#include "core/pe_inspector.h"
#include "core/entropy_analyzer.h"
#include "core/strings_analyzer.h"
#include "core/pattern_scanner.h"
#include "core/disassembler.h"
#include "core/cfg_analyzer.h"
#include "core/win32_hle.h"
#include "core/threat_evaluator.h"
#include "core/analysis_orchestrator.h"
#include "host/report_writer.h"
#include "mcp/mcp_server.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cassert>
#include <cstring>

static int g_passCount = 0;
static int g_failCount = 0;

static void AssertTest(bool condition, const std::string& testName) {
    if (condition) {
        std::cout << "  \033[32m[PASS]\033[0m " << testName << "\n";
        g_passCount++;
    } else {
        std::cout << "  \033[1;31m[FAIL]\033[0m " << testName << "\n";
        g_failCount++;
    }
}

// ─── Synthetic Valid PE Builder Helper ──────────────────────────────────────
static std::vector<uint8_t> CreateMinimalPE64() {
    std::vector<uint8_t> buf(0x1000, 0);

    // DOS Header
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE; // "MZ"
    dos->e_lfanew = 0x80;

    // NT Signature
    *reinterpret_cast<DWORD*>(buf.data() + 0x80) = IMAGE_NT_SIGNATURE; // "PE\0\0"

    // File Header
    IMAGE_FILE_HEADER* fileHdr = reinterpret_cast<IMAGE_FILE_HEADER*>(buf.data() + 0x84);
    fileHdr->Machine = IMAGE_FILE_MACHINE_AMD64;
    fileHdr->NumberOfSections = 1;
    fileHdr->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    fileHdr->Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;

    // Optional Header 64
    IMAGE_OPTIONAL_HEADER64* optHdr = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(buf.data() + 0x84 + sizeof(IMAGE_FILE_HEADER));
    optHdr->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    optHdr->AddressOfEntryPoint = 0x1000;
    optHdr->ImageBase = 0x140000000ULL;
    optHdr->SectionAlignment = 0x1000;
    optHdr->FileAlignment = 0x200;
    optHdr->MajorSubsystemVersion = 6;
    optHdr->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    optHdr->DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_GUARD_CF;
    optHdr->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    // Section Header (.text)
    size_t secOffset = 0x84 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64);
    IMAGE_SECTION_HEADER* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(buf.data() + secOffset);
    std::memcpy(sec->Name, ".text\0\0\0", 8);
    sec->VirtualAddress = 0x1000;
    sec->Misc.VirtualSize = 0x200;
    sec->PointerToRawData = 0x400;
    sec->SizeOfRawData = 0x200;
    sec->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    // Sample code inside .text at raw offset 0x400:
    // mov rax, 0x42; ret;
    uint8_t code[] = { 0x48, 0xC7, 0xC0, 0x42, 0x00, 0x00, 0x00, 0xC3 };
    std::memcpy(buf.data() + 0x400, code, sizeof(code));

    return buf;
}

// ─── Test 1: PE Inspector & Security Mitigations ───────────────────────────
static void TestPeInspector() {
    std::cout << "\n\033[1;36m=== [TEST 1] PE Inspector & Security Mitigations ===\033[0m\n";
    auto peData = CreateMinimalPE64();
    Dracula::PeInspector inspector;
    std::string err;
    bool ok = inspector.LoadFromMemory(peData.data(), peData.size(), err);

    AssertTest(ok, "Parse minimal synthetic PE64 in memory");
    AssertTest(inspector.GetMetadata().is64Bit, "Detect x64 architecture");
    AssertTest(inspector.GetMetadata().entryPointRva == 0x1000, "Extract EntryPoint RVA (0x1000)");
    AssertTest(inspector.GetMitigations().hasAslr, "Audit ASLR (DynamicBase) enabled");
    AssertTest(inspector.GetMitigations().hasDep, "Audit DEP/NX compatibility enabled");
    AssertTest(inspector.GetMitigations().hasCfg, "Audit Control Flow Guard (CFG) enabled");
    AssertTest(!inspector.GetMitigations().hasRwxSections, "Verify no RWX sections present");

    uint64_t fileOff = inspector.RvaToFileOffset(0x1000);
    AssertTest(fileOff == 0x400, "Translate RVA 0x1000 to File Offset 0x400");
}

// ─── Test 2: Strings Analyzer & Classification ─────────────────────────────
static void TestStringsAnalyzer() {
    std::cout << "\n\033[1;36m=== [TEST 2] Strings Analyzer & Classification ===\033[0m\n";
    std::vector<uint8_t> testBlob;
    auto appendStr = [&](const std::string& str) {
        testBlob.insert(testBlob.end(), str.begin(), str.end());
        testBlob.push_back(0);
    };
    appendStr("SomeHeaderData");
    appendStr("http://c2.evil-domain.com/payload.exe");
    appendStr("C:\\Windows\\System32\\cmd.exe");
    appendStr("powershell.exe -nop -exec bypass");
    appendStr("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    appendStr("192.168.1.100");
    appendStr("kernel32.dll");

    Dracula::StringsAnalyzer sa;
    auto results = sa.ExtractStrings(testBlob.data(), testBlob.size(), 4);

    bool foundUrl = false, foundCmd = false, foundReg = false, foundIp = false, foundDll = false;
    for (const auto& s : results) {
        if (s.category == Dracula::StringCategory::Url && s.value.find("http://c2.evil-domain") != std::string::npos) foundUrl = true;
        if (s.category == Dracula::StringCategory::CommandFragment && s.value.find("powershell") != std::string::npos) foundCmd = true;
        if (s.category == Dracula::StringCategory::RegistryKey && s.value.find("Run") != std::string::npos) foundReg = true;
        if (s.category == Dracula::StringCategory::IPv4 && s.value == "192.168.1.100") foundIp = true;
        if (s.category == Dracula::StringCategory::DllName && s.value == "kernel32.dll") foundDll = true;
    }

    AssertTest(foundUrl, "Extract and classify C2 URL");
    AssertTest(foundCmd, "Extract and classify PowerShell execution fragment");
    AssertTest(foundReg, "Extract and classify Persistence Registry Key");
    AssertTest(foundIp,  "Extract and classify IPv4 address");
    AssertTest(foundDll, "Extract and classify DLL name");
}

// ─── Test 3: Shannon Entropy & Packing Detection ───────────────────────────
static void TestEntropyAnalyzer() {
    std::cout << "\n\033[1;36m=== [TEST 3] Shannon Entropy & Packing Detection ===\033[0m\n";
    // Flat buffer: all zeroes -> entropy 0.0
    std::vector<uint8_t> flat(1024, 0);
    double flatEntropy = Dracula::EntropyAnalyzer::CalculateShannonEntropy(flat.data(), flat.size());
    AssertTest(flatEntropy == 0.0, "Zeroed buffer entropy is 0.00");

    // Random byte buffer -> entropy ~8.0
    std::vector<uint8_t> randomBuf(256 * 10);
    for (size_t i = 0; i < randomBuf.size(); ++i) {
        randomBuf[i] = static_cast<uint8_t>(i % 256);
    }
    double highEntropy = Dracula::EntropyAnalyzer::CalculateShannonEntropy(randomBuf.data(), randomBuf.size());
    AssertTest(highEntropy >= 7.9, "Uniformly distributed buffer entropy >= 7.90 / 8.00");
}

// ─── Test 4: Pattern Scanner with Wildcards ────────────────────────────────
static void TestPatternScanner() {
    std::cout << "\n\033[1;36m=== [TEST 4] Pattern Scanner with Wildcards ===\033[0m\n";
    uint8_t stream[] = { 0x90, 0x48, 0x8B, 0x05, 0x12, 0x34, 0x56, 0x78, 0x48, 0x85, 0xC0, 0xC3 };
    auto matches = Dracula::PatternScanner::Scan(stream, sizeof(stream), "48 8B 05 ?? ?? ?? ?? 48 85 C0");

    AssertTest(matches.size() == 1, "Find wildcard AOB pattern match count");
    if (!matches.empty()) {
        AssertTest(matches[0] == 1, "Match offset equals 1");
    }
}

// ─── Test 5: Disassembler & Branch Classifier ──────────────────────────────
static void TestDisassembler() {
    std::cout << "\n\033[1;36m=== [TEST 5] Disassembler & Branch Classifier ===\033[0m\n";
    // Instructions:
    // 0: 48 31 C0       -> xor rax, rax
    // 3: 48 83 C0 0A    -> add rax, 0xa
    // 7: 74 05          -> jz +5 (0xE)
    // 9: E8 10 00 00 00 -> call +0x10
    // E: C3             -> ret
    uint8_t code[] = {
        0x48, 0x31, 0xC0,
        0x48, 0x83, 0xC0, 0x0A,
        0x74, 0x05,
        0xE8, 0x10, 0x00, 0x00, 0x00,
        0xC3
    };

    Dracula::Disassembler disasm(Dracula::Architecture::X86_64);
    auto insts = disasm.Disassemble(code, sizeof(code), 0x140001000ULL, 0x1000);

    AssertTest(insts.size() == 5, "Disassembled exactly 5 instructions");
    if (insts.size() >= 5) {
        AssertTest(insts[0].mnemonic == "xor", "Instruction 0 is 'xor'");
        AssertTest(insts[1].mnemonic == "add", "Instruction 1 is 'add'");
        AssertTest(insts[2].mnemonic == "jz" && insts[2].isConditional, "Instruction 2 is conditional 'jz'");
        AssertTest(insts[2].targetAddress == 0x14000100EULL, "Instruction 2 branch target resolved accurately");
        AssertTest(insts[3].isCall, "Instruction 3 is 'call'");
        AssertTest(insts[4].isReturn, "Instruction 4 is 'ret'");
    }
}

// ─── Test 6: Control Flow Graph (CFG) Recursive Traversal ──────────────────
static void TestCfgAnalyzer() {
    std::cout << "\n\033[1;36m=== [TEST 6] Control Flow Graph (CFG) Engine ===\033[0m\n";
    // 0: cmp rax, 0
    // 4: jz +6 (0xC)
    // 6: mov rbx, 1
    // A: jmp +4 (0x10)
    // C: mov rbx, 2
    // 10: ret
    uint8_t code[] = {
        0x48, 0x83, 0xF8, 0x00,             // 0x00: cmp rax, 0
        0x74, 0x06,                         // 0x04: jz +6 (to 0x0C)
        0x48, 0xC7, 0xC3, 0x01, 0x00, 0x00, 0x00, // 0x06: mov rbx, 1 (size 7) -> ends at 0x0D
        0xEB, 0x07,                         // 0x0D: jmp +7 (to 0x16)
        0x48, 0xC7, 0xC3, 0x02, 0x00, 0x00, 0x00, // 0x0F: mov rbx, 2
        0xC3                                // 0x16: ret
    };

    Dracula::CfgAnalyzer cfg;
    auto graph = cfg.BuildFunctionGraph(code, sizeof(code), 0x140001000ULL, 0x1000, Dracula::Architecture::X86_64);

    AssertTest(!graph.blocks.empty(), "Constructed basic blocks in CFG graph");
    AssertTest(graph.blocks.find(0x140001000ULL) != graph.blocks.end(), "Entry basic block exists at function start");
}

// ─── Test 7: Win32 HLE & Mock TEB/PEB Architecture ─────────────────────────
static void TestWin32Hle() {
    std::cout << "\n\033[1;36m=== [TEST 7] Win32 HLE & Anti-Debug Policies ===\033[0m\n";
    Dracula::Win32Hle hle;

    uint64_t thunk1 = hle.GetOrCreateApiThunk("kernel32.dll", "VirtualAlloc");
    uint64_t thunk2 = hle.GetOrCreateApiThunk("kernel32.dll", "IsDebuggerPresent");

    AssertTest(thunk1 >= Dracula::Win32Hle::kHleThunkBase, "Generate synthetic thunk in HLE space");
    AssertTest(thunk1 != thunk2, "Distinct APIs receive distinct thunk addresses");

    std::string lib, api;
    AssertTest(hle.ResolveThunk(thunk1, lib, api) && api == "VirtualAlloc", "Resolve thunk address back to API name");
}

// ─── Test 8: Threat Evaluator Evidence Corroboration ───────────────────────
static void TestThreatEvaluator() {
    std::cout << "\n\033[1;36m=== [TEST 8] Threat Evaluator & Scoring ===\033[0m\n";
    std::vector<Dracula::Finding> findings;

    Dracula::Finding f1;
    f1.id = "EMU_ANTI_DEBUG";
    f1.category = "AntiAnalysis";
    f1.severity = Dracula::FindingSeverity::High;
    f1.tags = {"MITRE:T1497"};
    findings.push_back(f1);

    Dracula::Finding f2;
    f2.id = "STR_C2_URL";
    f2.category = "Network / C2";
    f2.severity = Dracula::FindingSeverity::Medium;
    f2.tags = {"MITRE:T1071"};
    findings.push_back(f2);

    Dracula::SampleMetadata meta;
    Dracula::SecurityMitigations mitigations;
    mitigations.hasAslr = false;
    mitigations.hasDep = false;

    auto scoreRes = Dracula::ThreatEvaluator::Evaluate(findings, meta, mitigations, 7.8, true);

    AssertTest(scoreRes.score >= 45, "Compute multi-finding threat score (Suspicious / High)");
    AssertTest(!scoreRes.mitreTechniques.empty(), "Extract MITRE ATT&CK techniques (T1497, T1071)");
    AssertTest(!scoreRes.reasoning.empty(), "Generate human-readable score reasoning");
}

// ─── Test 9: JSON & Markdown Report Serialization ──────────────────────────
static void TestReportSerialization() {
    std::cout << "\n\033[1;36m=== [TEST 9] JSON & Markdown Serialization ===\033[0m\n";
    Dracula::UnifiedAnalysisResult res;
    res.sample.fileName = "sample_test.exe";
    res.sample.filePath = "C:\\test\\sample_test.exe";
    res.sample.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    res.threatScore = 65;
    res.threatLevel = "Suspicious";

    Dracula::Finding f;
    f.id = "TEST_FINDING";
    f.severity = Dracula::FindingSeverity::High;
    f.title = "Sample Test Finding";
    f.evidence = "Pattern matched";
    res.findings.push_back(f);

    std::string json = res.ToJson();
    AssertTest(json.find("\"dracula_version\": \"2.0.0\"") != std::string::npos, "JSON contains dracula_version header");
    AssertTest(json.find("\"sample_test.exe\"") != std::string::npos, "JSON contains sample file name");
    AssertTest(json.find("\"TEST_FINDING\"") != std::string::npos, "JSON contains structured finding ID");

    std::string md = res.ToMarkdown();
    AssertTest(md.find("# 🧛 Dracula Binary Intelligence Report") != std::string::npos, "Markdown report header verified");
}

// ─── Test 10: Model Context Protocol (MCP) Message Processor ───────────────
static void TestMcpServer() {
    std::cout << "\n\033[1;36m=== [TEST 10] Model Context Protocol (MCP) Server ===\033[0m\n";
    Dracula::McpServer mcp;

    // Test initialize
    std::string initReq = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}";
    std::string initResp = mcp.ProcessMessage(initReq);
    AssertTest(initResp.find("\"name\":\"Dracula-Intelligence-Suite\"") != std::string::npos, "MCP initialize response valid");

    // Test tools/list
    std::string listReq = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}";
    std::string listResp = mcp.ProcessMessage(listReq);
    AssertTest(listResp.find("\"name\":\"analyze_file\"") != std::string::npos, "MCP tools/list contains 'analyze_file'");
    AssertTest(listResp.find("\"name\":\"inspect_pe_headers\"") != std::string::npos, "MCP tools/list contains 'inspect_pe_headers'");
    AssertTest(listResp.find("\"name\":\"calculate_entropy\"") != std::string::npos, "MCP tools/list contains 'calculate_entropy'");

    // Test ping
    std::string pingReq = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}";
    std::string pingResp = mcp.ProcessMessage(pingReq);
    AssertTest(pingResp.find("\"result\":{}") != std::string::npos, "MCP ping response valid");
}

// ─── Test 11: Negative & Robustness Tests ──────────────────────────────────
static void TestRobustnessAndNegative() {
    std::cout << "\n\033[1;36m=== [TEST 11] Robustness & Negative Error Handling ===\033[0m\n";
    Dracula::PeInspector insp;
    std::string err;

    // Nonexistent file
    bool r1 = insp.LoadFromFile("nonexistent_phantom_file_12345.bin", err);
    AssertTest(!r1, "Reject nonexistent file safely with error message");

    // Truncated buffer (less than DOS header)
    uint8_t tiny[] = { 'M', 'Z', 0x00 };
    bool r2 = insp.LoadFromMemory(tiny, sizeof(tiny), err);
    AssertTest(!r2, "Reject truncated DOS header safely");

    // Corrupt e_lfanew
    std::vector<uint8_t> corruptPE(256, 0);
    corruptPE[0] = 'M'; corruptPE[1] = 'Z';
    *reinterpret_cast<int32_t*>(corruptPE.data() + 0x3C) = 0x7FFFFFFF; // Oversized offset
    bool r3 = insp.LoadFromMemory(corruptPE.data(), corruptPE.size(), err);
    AssertTest(!r3, "Reject corrupt e_lfanew integer overflow safely without crashing");
}

int main() {
    std::cout << "\n\033[1;35m==============================================================\033[0m\n";
    std::cout << "\033[1;31m 🧛 DRACULA COMPREHENSIVE AUTOMATED TEST SUITE\033[0m\n";
    std::cout << "\033[1;35m==============================================================\033[0m\n";

    TestPeInspector();
    TestStringsAnalyzer();
    TestEntropyAnalyzer();
    TestPatternScanner();
    TestDisassembler();
    TestCfgAnalyzer();
    TestWin32Hle();
    TestThreatEvaluator();
    TestReportSerialization();
    TestMcpServer();
    TestRobustnessAndNegative();

    std::cout << "\n\033[1;35m==============================================================\033[0m\n";
    std::cout << " TEST RESULTS: \033[1;32m" << g_passCount << " PASSED\033[0m, \033[1;31m"
              << g_failCount << " FAILED\033[0m\n";
    std::cout << "\033[1;35m==============================================================\033[0m\n\n";

    return (g_failCount == 0) ? 0 : 1;
}
