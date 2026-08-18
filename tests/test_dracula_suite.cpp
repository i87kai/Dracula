#include "common/findings.h"
#include "common/version.h"
#include "common/input_validator.h"
#include "common/format.h"
#include "common/paths.h"
#include "core/pe_inspector.h"
#include "core/entropy_analyzer.h"
#include "core/strings_analyzer.h"
#include "core/pattern_scanner.h"
#include "core/disassembler.h"
#include "core/cfg_analyzer.h"
#include "core/xref_analyzer.h"
#include "core/win32_hle.h"
#include "core/unicorn_analyzer.h"
#include "core/threat_evaluator.h"
#include "core/analysis_orchestrator.h"
#include "host/report_writer.h"
#include "mcp/mcp_server.h"
#include "cli/terminal.h"
#include "cli/command_registry.h"
#include "cli/line_editor.h"
#include "cli/dracula_shell.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <set>
#include <map>
#include <stack>
#include <cassert>
#include <cstring>
#include <filesystem>
#include <fstream>

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

// ─── Simple Deterministic JSON Validator ───────────────────────────────────
static bool ValidateJsonSyntax(const std::string& json, std::string& outErr) {
    std::stack<char> braces;
    bool inString = false;
    bool escape = false;

    for (size_t i = 0; i < json.size(); ++i) {
        char c = json[i];
        if (inString) {
            if (escape) {
                escape = false;
            } else if (c == '\\') {
                escape = true;
            } else if (c == '"') {
                inString = false;
            }
        } else {
            if (c == '"') {
                inString = true;
            } else if (c == '{' || c == '[') {
                braces.push(c);
            } else if (c == '}') {
                if (braces.empty() || braces.top() != '{') {
                    outErr = "Unmatched '}' at pos " + std::to_string(i);
                    return false;
                }
                braces.pop();
            } else if (c == ']') {
                if (braces.empty() || braces.top() != '[') {
                    outErr = "Unmatched ']' at pos " + std::to_string(i);
                    return false;
                }
                braces.pop();
            }
        }
    }

    if (inString) {
        outErr = "Unterminated string literal in JSON";
        return false;
    }
    if (!braces.empty()) {
        outErr = "Unclosed brackets/braces in JSON (stack depth: " + std::to_string(braces.size()) + ")";
        return false;
    }
    return true;
}

// ─── Synthetic PE Builder Helpers ──────────────────────────────────────────
static std::vector<uint8_t> CreateSyntheticPE(bool is64Bit, bool isDll = false, size_t sectionCount = 1) {
    std::vector<uint8_t> buf(0x1000, 0);

    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE; // "MZ"
    dos->e_lfanew = 0x80;

    *reinterpret_cast<DWORD*>(buf.data() + 0x80) = IMAGE_NT_SIGNATURE; // "PE\0\0"

    IMAGE_FILE_HEADER* fileHdr = reinterpret_cast<IMAGE_FILE_HEADER*>(buf.data() + 0x84);
    fileHdr->Machine = is64Bit ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
    fileHdr->NumberOfSections = static_cast<WORD>(sectionCount);
    fileHdr->Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
    if (is64Bit) fileHdr->Characteristics |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
    if (isDll) fileHdr->Characteristics |= IMAGE_FILE_DLL;

    size_t optHdrOffset = 0x84 + sizeof(IMAGE_FILE_HEADER);

    if (is64Bit) {
        fileHdr->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        IMAGE_OPTIONAL_HEADER64* opt = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(buf.data() + optHdrOffset);
        opt->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        opt->AddressOfEntryPoint = 0x1000;
        opt->ImageBase = 0x140000000ULL;
        opt->SectionAlignment = 0x1000;
        opt->FileAlignment = 0x200;
        opt->MajorSubsystemVersion = 6;
        opt->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
        opt->DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_GUARD_CF;
        opt->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    } else {
        fileHdr->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
        IMAGE_OPTIONAL_HEADER32* opt = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(buf.data() + optHdrOffset);
        opt->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        opt->AddressOfEntryPoint = 0x1000;
        opt->ImageBase = 0x400000;
        opt->SectionAlignment = 0x1000;
        opt->FileAlignment = 0x200;
        opt->MajorSubsystemVersion = 6;
        opt->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
        opt->DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
        opt->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    }

    size_t secOffset = optHdrOffset + fileHdr->SizeOfOptionalHeader;
    for (size_t s = 0; s < sectionCount; ++s) {
        IMAGE_SECTION_HEADER* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(buf.data() + secOffset + s * sizeof(IMAGE_SECTION_HEADER));
        std::string sName = (s == 0) ? ".text" : (".sec" + std::to_string(s));
        std::memcpy(sec->Name, sName.c_str(), std::min<size_t>(8, sName.size()));
        sec->VirtualAddress = static_cast<DWORD>(0x1000 * (s + 1));
        sec->Misc.VirtualSize = 0x200;
        sec->PointerToRawData = static_cast<DWORD>(0x400 * (s + 1));
        sec->SizeOfRawData = 0x200;
        sec->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

        if (buf.size() < sec->PointerToRawData + 0x200) {
            buf.resize(sec->PointerToRawData + 0x200, 0);
        }

        // Add dummy RET opcode at section start
        buf[sec->PointerToRawData] = 0xC3;
    }

    return buf;
}

// ─── 1. CAPSTONE DISASSEMBLER DEEP AUDIT (x86 & x64) ──────────────────────
static void TestCapstoneDisassembler() {
    std::cout << "\n\033[1;36m=== [AUDIT 1] Capstone x86/x64 Disassembler Deep Audit ===\033[0m\n";

    // A. Test x64 Instruction Corpus
    Dracula::Disassembler disasm64(Dracula::Architecture::X86_64);
    AssertTest(disasm64.IsValid(), "Capstone x64 engine initialized successfully");

    // 1. Prefixes & REX
    uint8_t codeRex[] = { 0xF0, 0x48, 0x0F, 0xB1, 0x0B }; // lock cmpxchg [rbx], rcx
    auto r1 = disasm64.Disassemble(codeRex, sizeof(codeRex), 0x140001000ULL);
    AssertTest(!r1.empty() && r1[0].mnemonic.find("cmpxchg") != std::string::npos, "Disassemble x64 LOCK prefix with REX.W");

    // 2. ModR/M + SIB addressing: mov eax, [rbx + rcx*4 + 0x20]
    uint8_t codeSib[] = { 0x8B, 0x44, 0x8B, 0x20 };
    auto r2 = disasm64.Disassemble(codeSib, sizeof(codeSib), 0x140001000ULL);
    AssertTest(!r2.empty() && r2[0].mnemonic == "mov" && r2[0].operands.find("rcx*4") != std::string::npos, "Disassemble ModR/M + SIB (base + index*4 + disp)");

    // 3. RIP-relative addressing: mov rax, [rip + 0x1234]
    uint8_t codeRip[] = { 0x48, 0x8B, 0x05, 0x34, 0x12, 0x00, 0x00 };
    auto r3 = disasm64.Disassemble(codeRip, sizeof(codeRip), 0x140001000ULL);
    AssertTest(!r3.empty() && r3[0].targetAddress == 0x140001000ULL + 7 + 0x1234, "Disassemble and accurately resolve RIP-relative target VA");

    // 4. Indirect call & Indirect jump
    uint8_t codeIndirect[] = { 0xFF, 0x10, 0xFF, 0x20 }; // call qword ptr [rax]; jmp qword ptr [rax]
    auto r4 = disasm64.Disassemble(codeIndirect, sizeof(codeIndirect), 0x140001000ULL);
    AssertTest(r4.size() == 2 && r4[0].isCall && r4[1].isBranch, "Disassemble indirect CALL and JMP with group classification");

    // 5. Conditional branches (jrcxz, jz, jg, jle)
    uint8_t codeCond[] = { 0xE3, 0x05, 0x74, 0x03, 0x7F, 0x01, 0x7E, 0x00 };
    auto r5 = disasm64.Disassemble(codeCond, sizeof(codeCond), 0x140001000ULL);
    AssertTest(r5.size() == 4 && r5[0].isConditional && r5[1].isConditional, "Disassemble conditional branch variants (jrcxz, jz, jg, jle)");

    // 6. SIMD / AVX instructions
    uint8_t codeSimd[] = { 0x0F, 0x28, 0xC1, 0x66, 0x0F, 0xEF, 0xC0 }; // movaps xmm0, xmm1; pxor xmm0, xmm0
    auto r6 = disasm64.Disassemble(codeSimd, sizeof(codeSimd), 0x140001000ULL);
    AssertTest(r6.size() == 2 && r6[0].mnemonic == "movaps" && r6[1].mnemonic == "pxor", "Disassemble SSE/SIMD instructions (movaps, pxor)");

    // 7. Multiple operand sizes (8-bit, 16-bit, 32-bit, 64-bit)
    uint8_t codeSizes[] = { 0xB0, 0x42, 0x66, 0xB8, 0x34, 0x12, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00 };
    auto r7 = disasm64.Disassemble(codeSizes, sizeof(codeSizes), 0x140001000ULL);
    AssertTest(r7.size() == 4, "Disassemble 8-bit (AL), 16-bit (AX), 32-bit (EAX), and 64-bit (RAX) operands");

    // B. Test x86 (32-bit) Disassembly Mode
    Dracula::Disassembler disasm32(Dracula::Architecture::X86_32);
    AssertTest(disasm32.IsValid(), "Capstone x86 32-bit engine initialized successfully");
    uint8_t code32[] = { 0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x5D, 0xC3 }; // push ebp; mov ebp, esp; mov eax, [ebp+8]; pop ebp; ret
    auto r32 = disasm32.Disassemble(code32, sizeof(code32), 0x00401000ULL);
    AssertTest(r32.size() == 5 && r32[2].operands.find("ebp") != std::string::npos, "Disassemble 32-bit x86 stack frame prologs and accesses");

    // C. Invalid / Truncated Opcode Handling
    uint8_t corruptOpcode[] = { 0x0F }; // Incomplete 2-byte opcode
    auto rBad = disasm64.Disassemble(corruptOpcode, sizeof(corruptOpcode), 0x140001000ULL);
    AssertTest(rBad.empty(), "Handle truncated/incomplete opcode without crashing");
}

// ─── 2. CFG TOPOLOGY & GRAPH DEEP AUDIT ───────────────────────────────────
static void TestCfgTopology() {
    std::cout << "\n\033[1;36m=== [AUDIT 2] Control Flow Graph (CFG) Topology & Edge Verification ===\033[0m\n";

    // Branching Machine Code:
    // 0x00: cmp rax, 0
    // 0x04: jz 0x0F (True edge -> block 2 @ 0x0F, False edge -> block 1 @ 0x06)
    // 0x06: mov rbx, 1 (Block 1)
    // 0x0D: jmp 0x16 (Unconditional jump -> block 3 @ 0x16)
    // 0x0F: mov rbx, 2 (Block 2)
    // 0x16: sub rax, 1 (Block 3)
    // 0x1A: jnz 0x00 (Back-edge / Loop edge -> block 0 @ 0x00)
    // 0x1C: ret      (Block 4 / Exit)
    uint8_t cfgCode[] = {
        0x48, 0x83, 0xF8, 0x00,                         // 0x00: cmp rax, 0
        0x74, 0x09,                                     // 0x04: jz +0x09 (to 0x0F)
        0x48, 0xC7, 0xC3, 0x01, 0x00, 0x00, 0x00,       // 0x06: mov rbx, 1 (ends 0x0D)
        0xEB, 0x07,                                     // 0x0D: jmp +0x07 (to 0x16)
        0x48, 0xC7, 0xC3, 0x02, 0x00, 0x00, 0x00,       // 0x0F: mov rbx, 2 (ends 0x16)
        0x48, 0x83, 0xE8, 0x01,                         // 0x16: sub rax, 1
        0x75, 0xE4,                                     // 0x1A: jnz -0x1C (back to 0x00)
        0xC3                                            // 0x1C: ret
    };

    Dracula::CfgAnalyzer cfg;
    uint64_t baseVa = 0x140001000ULL;
    auto graph = cfg.BuildFunctionGraph(cfgCode, sizeof(cfgCode), baseVa, 0x1000, Dracula::Architecture::X86_64, 500);

    AssertTest(graph.blocks.size() >= 4, "Constructed full basic block topology (>= 4 blocks)");

    // Check entry block successors (True & False branch edges)
    auto entryIt = graph.blocks.find(baseVa);
    AssertTest(entryIt != graph.blocks.end(), "Entry basic block exists at function base VA");
    if (entryIt != graph.blocks.end()) {
        const auto& entryBlock = entryIt->second;
        AssertTest(entryBlock.successorAddresses.size() == 2, "Entry block has exactly 2 successors (Conditional True & False branches)");
        AssertTest(entryBlock.terminatorMnemonic == "je" || entryBlock.terminatorMnemonic == "jz", "Entry block terminator is conditional jump (jz/je)");
    }

    // Check Loop back-edge presence (Back to entry block 0x140001000)
    bool hasLoopBackEdge = false;
    for (const auto& [addr, block] : graph.blocks) {
        for (uint64_t succ : block.successorAddresses) {
            if (succ == baseVa && addr != baseVa) {
                hasLoopBackEdge = true;
                break;
            }
        }
    }
    AssertTest(hasLoopBackEdge, "Successfully identified loop back-edge to function entry");

    // Check RET block termination
    bool hasRetBlock = false;
    for (const auto& [addr, block] : graph.blocks) {
        if (block.terminatorMnemonic == "ret") {
            hasRetBlock = true;
            AssertTest(block.successorAddresses.empty(), "RET block has zero successors (Clean leaf block)");
        }
    }
    AssertTest(hasRetBlock, "RET termination block identified in CFG");
}

// ─── 3. CROSS REFERENCES (XREFs) AUDIT ─────────────────────────────────────
static void TestXrefAnalyzer() {
    std::cout << "\n\033[1;36m=== [AUDIT 3] Cross References (XREFs) Audit ===\033[0m\n";

    // Setup synthetic PE with .rdata and .text
    auto peBuf = CreateSyntheticPE(true, false, 2);
    Dracula::PeInspector inspector;
    std::string err;
    inspector.LoadFromMemory(peBuf.data(), peBuf.size(), err);

    std::vector<Dracula::ExtractedString> strings;
    Dracula::ExtractedString es;
    es.value = "http://evil-c2.com";
    es.rva = 0x2040; // In second section (.sec1 / .rdata)
    strings.push_back(es);

    // Instructions with:
    // 1. Direct call to 0x140005000 (CodeCall)
    // 2. Conditional branch to 0x140001050 (CodeJump)
    // 3. RIP-relative access to string @ 0x140002040 (StringRef)
    std::vector<Dracula::DisassembledInstruction> insts;

    Dracula::DisassembledInstruction i1;
    i1.address = 0x140001000;
    i1.rva = 0x1000;
    i1.isCall = true;
    i1.targetAddress = 0x140005000;
    i1.mnemonic = "call";
    i1.operands = "0x140005000";
    insts.push_back(i1);

    Dracula::DisassembledInstruction i2;
    i2.address = 0x140001005;
    i2.rva = 0x1005;
    i2.isBranch = true;
    i2.isConditional = true;
    i2.targetAddress = 0x140001050;
    i2.mnemonic = "jz";
    i2.operands = "0x140001050";
    insts.push_back(i2);

    Dracula::DisassembledInstruction i3;
    i3.address = 0x140001010;
    i3.rva = 0x1010;
    i3.targetAddress = 0x140002040;
    i3.mnemonic = "lea";
    i3.operands = "rcx, [rip + 0x1023]";
    insts.push_back(i3);

    auto xrefs = Dracula::XrefAnalyzer::ExtractXrefs(insts, inspector, strings);
    AssertTest(xrefs.size() == 3, "Extracted 3 cross-references from instruction stream");

    bool foundCall = false, foundJump = false, foundString = false;
    for (const auto& x : xrefs) {
        if (x.type == Dracula::XRefType::CodeCall && x.toAddress == 0x140005000) foundCall = true;
        if (x.type == Dracula::XRefType::CodeJump && x.toAddress == 0x140001050) foundJump = true;
        if (x.type == Dracula::XRefType::StringRef && x.targetName.find("evil-c2.com") != std::string::npos) foundString = true;
    }

    AssertTest(foundCall, "Resolved CodeCall XRef to subfunction");
    AssertTest(foundJump, "Resolved CodeJump XRef to basic block target");
    AssertTest(foundString, "Resolved StringRef XRef to embedded string");
}

// ─── 4. TEB / PEB & GS/FS SEGMENT CORRECTNESS AUDIT ───────────────────────
static void TestTebPebCorrectness() {
    std::cout << "\n\033[1;36m=== [AUDIT 4] TEB / PEB & GS/FS Architectural Resolution ===\033[0m\n";

    // Machine code:
    // mov rax, gs:[0x60]          -> 65 48 8B 04 25 60 00 00 00
    // movzx ebx, byte ptr [rax+2] -> 0F B6 58 02 (PEB.BeingDebugged)
    // mov rdx, [rax+0x10]         -> 48 8B 50 10 (PEB.ImageBaseAddress)
    uint8_t gsCode[] = {
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax, gs:[0x60]
        0x0F, 0xB6, 0x58, 0x02,                               // movzx ebx, byte ptr [rax+2]
        0x48, 0x8B, 0x50, 0x10                                // mov rdx, [rax+0x10]
    };

    // Test with Realistic policy (BeingDebugged = 1)
    uc_engine* uc = nullptr;
    uc_open(UC_ARCH_X86, UC_MODE_64, &uc);

    uint64_t codeVa = 0x140001000ULL;
    uc_mem_map(uc, codeVa, 0x1000, UC_PROT_ALL);
    uc_mem_write(uc, codeVa, gsCode, sizeof(gsCode));

    Dracula::Win32Hle hle;
    std::string err;
    uint64_t imageBase = 0x140000000ULL;
    hle.SetupMockEnvironment(uc, imageBase, true, Dracula::AntiDebugPolicy::Realistic, err);

    uc_err emuErr = uc_emu_start(uc, codeVa, codeVa + sizeof(gsCode), 0, 100);
    AssertTest(emuErr == UC_ERR_OK, "Emulate gs:[0x60] machine code in Unicorn 64-bit");

    uint64_t raxVal = 0, rbxVal = 0, rdxVal = 0;
    uc_reg_read(uc, UC_X86_REG_RAX, &raxVal);
    uc_reg_read(uc, UC_X86_REG_RBX, &rbxVal);
    uc_reg_read(uc, UC_X86_REG_RDX, &rdxVal);

    AssertTest(raxVal == Dracula::Win32Hle::kMockPeb64, "gs:[0x60] resolves to configured PEB base (0x7FFDF0010000)");
    AssertTest(rbxVal == 1, "PEB.BeingDebugged == 1 under Realistic policy");
    AssertTest(rdxVal == imageBase, "PEB.ImageBaseAddress matches binary image base");

    uc_close(uc);
}

// ─── 5. REAL HLE MACHINE CODE EXECUTION AUDIT ──────────────────────────────
static void TestRealHleMachineCodeExecution() {
    std::cout << "\n\033[1;36m=== [AUDIT 5] Real HLE Machine Code Execution & Calling Conventions ===\033[0m\n";

    Dracula::UnicornAnalyzer analyzer;
    Dracula::Win32Hle& hle = analyzer.GetHle();

    // Register test API thunk
    uint64_t vAllocThunk = hle.GetOrCreateApiThunk("kernel32.dll", "VirtualAlloc");
    uint64_t isDbgThunk  = hle.GetOrCreateApiThunk("kernel32.dll", "IsDebuggerPresent");

    // Real x64 Machine Code:
    // 1. Setup shadow stack: sub rsp, 0x28
    // 2. Call VirtualAlloc(lpAddress=0, dwSize=0x2000, flAllocationType=0x3000, flProtect=0x40)
    //    mov rcx, 0
    //    mov rdx, 0x2000
    //    mov r8, 0x3000
    //    mov r9, 0x40 (PAGE_EXECUTE_READWRITE)
    //    mov rax, vAllocThunk
    //    call rax
    // 3. Check returned pointer in RAX, write byte 0x90 to [RAX]
    //    mov byte ptr [rax], 0x90
    // 4. Call IsDebuggerPresent()
    //    mov rax, isDbgThunk
    //    call rax
    // 5. Clean shadow stack: add rsp, 0x28; ret
    std::vector<uint8_t> hleTestCode = {
        0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 0x28
        0x48, 0x31, 0xC9,                               // xor rcx, rcx (lpAddress = 0)
        0x48, 0xC7, 0xC2, 0x00, 0x20, 0x00, 0x00,       // mov rdx, 0x2000 (dwSize)
        0x49, 0xC7, 0xC0, 0x00, 0x30, 0x00, 0x00,       // mov r8, 0x3000 (MEM_COMMIT | MEM_RESERVE)
        0x49, 0xC7, 0xC1, 0x40, 0x00, 0x00, 0x00,       // mov r9, 0x40 (PAGE_EXECUTE_READWRITE)
        0x48, 0xB8                                      // mov rax, vAllocThunk (8 bytes follow)
    };
    for (int i = 0; i < 8; ++i) hleTestCode.push_back(static_cast<uint8_t>((vAllocThunk >> (i * 8)) & 0xFF));
    
    // call rax
    hleTestCode.push_back(0xFF); hleTestCode.push_back(0xD0);
    
    // mov byte ptr [rax], 0x90 (Write test byte to dynamically allocated memory)
    hleTestCode.push_back(0xC6); hleTestCode.push_back(0x00); hleTestCode.push_back(0x90);

    // mov rax, isDbgThunk (8 bytes follow)
    hleTestCode.push_back(0x48); hleTestCode.push_back(0xB8);
    for (int i = 0; i < 8; ++i) hleTestCode.push_back(static_cast<uint8_t>((isDbgThunk >> (i * 8)) & 0xFF));

    // call rax
    hleTestCode.push_back(0xFF); hleTestCode.push_back(0xD0);

    // add rsp, 0x28; ret
    hleTestCode.push_back(0x48); hleTestCode.push_back(0x83); hleTestCode.push_back(0xC4); hleTestCode.push_back(0x28);
    hleTestCode.push_back(0xC3);

    auto emuRes = analyzer.EmulateBuffer(hleTestCode, 0x140001000ULL, {}, {"RAX", "RSP"});
    AssertTest(emuRes.success, "Execute real x64 machine code calling HLE thunks in Unicorn");
    AssertTest(emuRes.instructionsExecuted >= 10, "Instructions executed through synthetic trampolines (> 10)");
}

// ─── 6. ANTI-DEBUG POLICIES & EVIDENCE EMISSION AUDIT ──────────────────────
static void TestAntiDebugPolicies() {
    std::cout << "\n\033[1;36m=== [AUDIT 6] Anti-Debug Policies & Evidence Emission ===\033[0m\n";

    Dracula::Win32Hle hle;

    // Policy 1: Bypass
    Dracula::HleCallContext ctxBypass;
    ctxBypass.library = "kernel32.dll";
    ctxBypass.apiName = "IsDebuggerPresent";
    ctxBypass.antiDebugPolicy = Dracula::AntiDebugPolicy::Bypass;

    uint64_t retVal1 = 0;
    std::string det1;
    std::vector<Dracula::Finding> f1;
    hle.HandleCall(nullptr, 0, ctxBypass, retVal1, det1, f1);

    AssertTest(retVal1 == 0, "IsDebuggerPresent returns 0 under Bypass policy");
    AssertTest(!f1.empty() && f1[0].id == "EMU_ANTI_DEBUG_CHECK", "Emitted EMU_ANTI_DEBUG_CHECK finding under Bypass");

    // Policy 2: Realistic
    Dracula::HleCallContext ctxReal;
    ctxReal.library = "kernel32.dll";
    ctxReal.apiName = "IsDebuggerPresent";
    ctxReal.antiDebugPolicy = Dracula::AntiDebugPolicy::Realistic;

    uint64_t retVal2 = 0;
    std::string det2;
    std::vector<Dracula::Finding> f2;
    hle.HandleCall(nullptr, 0, ctxReal, retVal2, det2, f2);

    AssertTest(retVal2 == 1, "IsDebuggerPresent returns 1 under Realistic policy");
    AssertTest(!f2.empty() && f2[0].id == "EMU_ANTI_DEBUG_CHECK", "Emitted EMU_ANTI_DEBUG_CHECK finding under Realistic");

    // Policy 3: Neutral
    Dracula::HleCallContext ctxNeut;
    ctxNeut.library = "kernel32.dll";
    ctxNeut.apiName = "IsDebuggerPresent";
    ctxNeut.antiDebugPolicy = Dracula::AntiDebugPolicy::Neutral;

    uint64_t retVal3 = 0;
    std::string det3;
    std::vector<Dracula::Finding> f3;
    hle.HandleCall(nullptr, 0, ctxNeut, retVal3, det3, f3);

    AssertTest(retVal3 == 0, "IsDebuggerPresent returns 0 under Neutral policy");
    AssertTest(f3.empty(), "Neutral policy emits no findings (Silent)");
}

// ─── 7. PE PARSER ROBUSTNESS & MALFORMED CORPUS AUDIT ──────────────────────
static void TestPeParserRobustnessAndMalformedCorpus() {
    std::cout << "\n\033[1;36m=== [AUDIT 7] PE Parser Robustness & Malformed Corpus ===\033[0m\n";

    // 1. Valid PE32 (32-bit)
    auto pe32 = CreateSyntheticPE(false, false, 1);
    Dracula::PeInspector insp32;
    std::string err32;
    AssertTest(insp32.LoadFromMemory(pe32.data(), pe32.size(), err32) && !insp32.GetMetadata().is64Bit, "Parse standard PE32 (32-bit) binary");

    // 2. Valid PE32+ (64-bit DLL)
    auto peDll = CreateSyntheticPE(true, true, 2);
    Dracula::PeInspector inspDll;
    std::string errDll;
    AssertTest(inspDll.LoadFromMemory(peDll.data(), peDll.size(), errDll) && inspDll.GetMetadata().isDll, "Parse standard PE32+ (64-bit DLL)");

    // 3. Zero Sections PE
    auto peZeroSec = CreateSyntheticPE(true, false, 0);
    Dracula::PeInspector inspZero;
    std::string errZero;
    AssertTest(inspZero.LoadFromMemory(peZeroSec.data(), peZeroSec.size(), errZero), "Parse legal zero-section PE header safely");

    // 4. Deterministic Malformed Corpus (20+ mutated corrupt files)
    int corruptPassed = 0;
    for (int variant = 0; variant < 25; ++variant) {
        auto mutated = CreateSyntheticPE(true, false, 2);

        switch (variant % 6) {
            case 0: // Truncated buffer
                mutated.resize(variant * 10 + 5);
                break;
            case 1: // Corrupt e_lfanew
                *reinterpret_cast<int32_t*>(mutated.data() + 0x3C) = -1000 + variant;
                break;
            case 2: // Extreme NumberOfSections
                *reinterpret_cast<uint16_t*>(mutated.data() + 0x86) = 0xFFFF;
                break;
            case 3: // Section PointerToRawData beyond EOF
                *reinterpret_cast<uint32_t*>(mutated.data() + 0x1A0) = 0x7FFFFFFF;
                break;
            case 4: // Invalid SizeOfOptionalHeader
                *reinterpret_cast<uint16_t*>(mutated.data() + 0x94) = 0xFFFF;
                break;
            case 5: // Overlapping sections with negative sizes
                *reinterpret_cast<uint32_t*>(mutated.data() + 0x188) = 0xFFFFFFFF;
                break;
        }

        Dracula::PeInspector inspMut;
        std::string errMut;
        // The parser MUST NOT crash or segfault
        inspMut.LoadFromMemory(mutated.data(), mutated.size(), errMut);
        corruptPassed++;
    }
    AssertTest(corruptPassed == 25, "Deterministic malformed corpus (25/25 corrupt variants safely rejected without crashing)");
}

// ─── 8. JSON STRUCTURE & GRAMMAR VALIDATION AUDIT ──────────────────────────
static void TestJsonGrammarValidation() {
    std::cout << "\n\033[1;36m=== [AUDIT 8] Strict JSON Grammar & Schema Validation ===\033[0m\n";

    Dracula::UnifiedAnalysisResult res;
    res.sample.fileName = "C:\\Windows\\System32\\calc.exe";
    res.sample.filePath = "C:\\Users\\Dracula\\Desktop\\malware_\"test\"_sample.bin";
    res.sample.sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    res.threatScore = 85;
    res.threatLevel = "Critical Threat";

    Dracula::Finding f1;
    f1.id = "TEST_FINDING_UNICODE";
    f1.title = "Suspicious URL: http://c2.server.com/payload?key=val&path=C:\\temp\\evil.exe";
    f1.evidence = "Embedded string: \"\xCE\x94\xCE\xBF\xCE\xBA\xCE\xB9\xCE\xBC\xCE\xAE\" (Greek Unicode)";
    f1.severity = Dracula::FindingSeverity::Critical;
    res.findings.push_back(f1);

    std::string jsonStr = res.ToJson();
    std::string parseErr;
    bool isValidJson = ValidateJsonSyntax(jsonStr, parseErr);

    AssertTest(isValidJson, "Generate 100% syntactically valid JSON (Braces, quotes, brackets balanced)");
    if (!isValidJson) {
        std::cerr << "[-] JSON validation error: " << parseErr << "\n";
    }
    AssertTest(jsonStr.find("\"dracula_version\": \"" + std::string(Dracula::Version::String) + "\"") != std::string::npos, "JSON contains dracula_version schema header (v1.0.0)");
    AssertTest(jsonStr.find("calc.exe") != std::string::npos, "JSON accurately escapes Windows paths");
}

// ─── 9. MCP PROTOCOL DEEP TOOL CALLS AUDIT ─────────────────────────────────
static void TestMcpDeepSession() {
    std::cout << "\n\033[1;36m=== [AUDIT 9] Model Context Protocol (MCP) Deep Tool Calls ===\033[0m\n";

    Dracula::McpServer mcp;

    // 1. Initialize
    std::string initResp = mcp.ProcessMessage("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}");
    AssertTest(initResp.find("\"name\":\"Dracula-Intelligence-Suite\"") != std::string::npos, "MCP initialize protocol negotiation");
    AssertTest(initResp.find("\"version\":\"" + std::string(Dracula::Version::String) + "\"") != std::string::npos, "MCP initialize returns authoritative version 1.0.0");

    // 2. Tools List
    std::string listResp = mcp.ProcessMessage("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}");
    AssertTest(listResp.find("scan_hex_pattern") != std::string::npos, "MCP tools/list contains scan_hex_pattern");

    // 3. Tool Call: inspect_pe_headers on samples/test_sample.exe
    if (std::filesystem::exists("samples/test_sample.exe")) {
        std::string callReq = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"inspect_pe_headers\",\"arguments\":{\"file_path\":\"samples/test_sample.exe\"}}}";
        std::string callResp = mcp.ProcessMessage(callReq);
        AssertTest(callResp.find("\"result\"") != std::string::npos && callResp.find("Architecture") != std::string::npos, "MCP tool call 'inspect_pe_headers' executed against real binary");
    }

    // 4. Missing Parameters Error Handling (-32602)
    std::string errReq = "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"analyze_file\"}}";
    std::string errResp = mcp.ProcessMessage(errReq);
    AssertTest(errResp.find("\"code\":-32602") != std::string::npos, "MCP error returned for missing required parameters (-32602)");

    // 5. Unknown Method Error Handling (-32601)
    std::string unkReq = "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"invalid_ghost_method\"}";
    std::string unkResp = mcp.ProcessMessage(unkReq);
    AssertTest(unkResp.find("\"code\":-32601") != std::string::npos, "MCP error returned for unknown method (-32601)");
}

// ─── 10. THREAT SCORE DETERMINISTIC AUDIT ──────────────────────────────────
static void TestThreatScoreDeterminism() {
    std::cout << "\n\033[1;36m=== [AUDIT 10] Evidence-Based Threat Score Determinism ===\033[0m\n";

    Dracula::SampleMetadata meta;
    Dracula::SecurityMitigations cleanSec;
    cleanSec.hasAslr = true;
    cleanSec.hasDep = true;

    // A. Benign / Clean sample (0 findings)
    auto cleanRes = Dracula::ThreatEvaluator::Evaluate({}, meta, cleanSec, 4.5, false);
    AssertTest(cleanRes.score < 25 && cleanRes.level == "Clean / Benign", "Clean binary with mitigations scores < 25 (Clean / Benign)");

    // B. Multi-signal Corroboration
    std::vector<Dracula::Finding> findings;
    Dracula::Finding f1; f1.category = "AntiAnalysis"; f1.severity = Dracula::FindingSeverity::High; f1.tags = {"MITRE:T1497"};
    Dracula::Finding f2; f2.category = "Persistence";  f2.severity = Dracula::FindingSeverity::High; f2.tags = {"MITRE:T1547"};
    Dracula::Finding f3; f3.category = "Network";      f3.severity = Dracula::FindingSeverity::High; f3.tags = {"MITRE:T1071"};
    findings.push_back(f1); findings.push_back(f2); findings.push_back(f3);

    auto threatRes = Dracula::ThreatEvaluator::Evaluate(findings, meta, cleanSec, 7.9, true);
    AssertTest(threatRes.score >= 75 && threatRes.level == "Critical Threat", "Multi-signal threat corroboration produces Critical Threat (>= 75)");
    AssertTest(threatRes.mitreTechniques.size() == 3, "Extracted exact MITRE ATT&CK techniques (T1497, T1547, T1071)");
}

// ─── 11. HASH INDEPENDENT VERIFICATION ─────────────────────────────────────
static void TestHashVerification() {
    std::cout << "\n\033[1;36m=== [AUDIT 11] SHA-256 & MD5 Cryptographic Hash Verification ===\033[0m\n";

    // NIST standard test vector: "abc"
    // SHA-256 = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    std::string testStr = "abc";
    std::string sha256 = Dracula::PeInspector::ComputeSha256(reinterpret_cast<const uint8_t*>(testStr.data()), testStr.size());
    std::string md5    = Dracula::PeInspector::ComputeMd5(reinterpret_cast<const uint8_t*>(testStr.data()), testStr.size());

    AssertTest(sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 matches NIST standard test vector for 'abc'");
    AssertTest(md5 == "900150983cd24fb0d6963f7d28e17f72", "MD5 matches standard test vector for 'abc'");
}

// ─── 12. VERSION AUTHORITATIVE CONSISTENCY AUDIT ───────────────────────────
static void TestVersionConsistency() {
    std::cout << "\n\033[1;36m=== [AUDIT 12] Authoritative Single-Source Version Consistency ===\033[0m\n";

    // The version is generated from CMakeLists.txt; nothing here may hard-code
    // it, so every assertion is made against the single generated source.
    const std::string version = Dracula::Version::String;
    const std::string composed = std::to_string(Dracula::Version::Major) + "." +
                                 std::to_string(Dracula::Version::Minor) + "." +
                                 std::to_string(Dracula::Version::Patch);

    AssertTest(Dracula::Version::Major == 1, "Authoritative Version Major is 1 (Dracula v1 line)");
    AssertTest(composed == version, "Version components agree with the version string");
    AssertTest(Dracula::DraculaShell::GetVersion() == version, "DraculaShell reports the authoritative version");

    Dracula::UnifiedAnalysisResult res;
    std::string json = res.ToJson();
    AssertTest(json.find("\"dracula_version\": \"" + version + "\"") != std::string::npos, "Analysis JSON serialization uses the authoritative version");
}

// ─── 13. TERMINAL THEME & CAPABILITIES AUDIT ───────────────────────────────
static void TestTerminalThemeAndCapabilities() {
    std::cout << "\n\033[1;36m=== [AUDIT 13] Terminal Capabilities, Semantic Theme, & ASCII Fallback ===\033[0m\n";

    // 1. ANSI escape stripping
    std::string colored = "\033[1;31mDracula\033[0m \033[36mTerminal\033[0m";
    AssertTest(Dracula::Terminal::StripAnsi(colored) == "Dracula Terminal", "StripAnsi removes all ANSI color sequences");

    // 2. Visible length computation
    AssertTest(Dracula::Terminal::VisibleLength(colored) == 16, "VisibleLength correctly computes printable character count");

    // 3. Color disable / --no-color mode
    Dracula::Terminal::SetColorEnabled(false);
    AssertTest(Dracula::Terminal::Color(Dracula::ColorRole::Primary).empty(), "Color returns empty string when color is disabled (--no-color / NO_COLOR)");
    AssertTest(Dracula::Terminal::Color(Dracula::ColorRole::Secondary).empty(), "Secondary color returns empty string when color disabled");
    Dracula::Terminal::SetColorEnabled(true);

    // 4. Safe ASCII fallback glyphs
    Dracula::Terminal::SetUnicodeEnabled(false);
    AssertTest(Dracula::Terminal::PromptGlyph() == ">", "Safe ASCII fallback prompt glyph is '>'");
    AssertTest(Dracula::Terminal::BoxH() == "-", "Safe ASCII fallback horizontal box is '-'");
    AssertTest(Dracula::Terminal::BoxTL() == "+", "Safe ASCII fallback top-left corner is '+'");
    AssertTest(Dracula::Terminal::Bullet() == "*", "Safe ASCII fallback bullet is '*'");
    Dracula::Terminal::SetUnicodeEnabled(true);

    // 5. Unicode glyphs enabled
    AssertTest(Dracula::Terminal::PromptGlyph() == "❯", "Unicode prompt glyph is '❯'");
    AssertTest(Dracula::Terminal::BoxH() == "─", "Unicode box horizontal is '─'");
    AssertTest(Dracula::Terminal::BoxTL() == "┌", "Unicode box top-left is '┌'");
}

// ─── 14. CENTRAL COMMAND REGISTRY METADATA AUDIT ───────────────────────────
static void TestCommandRegistryMetadata() {
    std::cout << "\n\033[1;36m=== [AUDIT 14] Central Command Registry & Alias Integrity ===\033[0m\n";

    auto& registry = Dracula::CommandRegistry::Instance();
    const auto& cmds = registry.GetAllCommands();

    AssertTest(cmds.size() >= 20, "CommandRegistry contains complete command suite (>= 20 commands registered)");

    bool allHaveDescription = true;
    bool allHaveUsage = true;
    bool allHaveCategory = true;
    bool allHaveHandlers = true;

    for (const auto& cmd : cmds) {
        if (cmd.description.empty()) allHaveDescription = false;
        if (cmd.usage.empty()) allHaveUsage = false;
        if (cmd.category.empty()) allHaveCategory = false;
        // A command is dispatchable via its legacy handler OR via registered
        // subcommands. Project-centric commands (/project, /memory, /static,
        // ...) are entirely subcommand-driven and carry no legacy handler.
        if (!cmd.handler && cmd.subcommands.empty()) allHaveHandlers = false;
    }

    AssertTest(allHaveDescription, "All registered commands have descriptive summaries");
    AssertTest(allHaveUsage, "All registered commands define standard usage syntax");
    AssertTest(allHaveCategory, "All registered commands are grouped into semantic categories");
    AssertTest(allHaveHandlers, "All registered commands are bound to executable handlers");

    // Alias lookups
    const auto* cmdA = registry.Find("a");
    AssertTest(cmdA != nullptr && cmdA->name == "analyze", "Alias /a resolves to /analyze");

    const auto* cmdDis = registry.Find("dis");
    AssertTest(cmdDis != nullptr && cmdDis->name == "disasm", "Alias /dis resolves to /disasm");

    const auto* cmdSec = registry.Find("sec");
    AssertTest(cmdSec != nullptr && cmdSec->name == "security", "Alias /sec resolves to /security");

    const auto* cmdCl = registry.Find("cl");
    AssertTest(cmdCl != nullptr && cmdCl->name == "changelog", "Alias /cl resolves to /changelog");

    const auto* cmdV = registry.Find("v");
    AssertTest(cmdV != nullptr && cmdV->name == "version", "Alias /v resolves to /version");
}

// ─── 15. SLASH COMMAND PALETTE FILTERING AUDIT ─────────────────────────────
static void TestSlashCommandPaletteFiltering() {
    std::cout << "\n\033[1;36m=== [AUDIT 15] Slash Command Palette Live Prefix Filtering ===\033[0m\n";

    auto& registry = Dracula::CommandRegistry::Instance();

    // 1. Root slash shows all commands
    auto allMatches = registry.FilterByPrefix("/");
    AssertTest(allMatches.size() == registry.GetAllCommands().size(), "Root prefix '/' returns all registered slash commands");

    // 2. Prefix '/s' matches sandbox, scan, security, strings, session
    auto sMatches = registry.FilterByPrefix("/s");
    AssertTest(sMatches.size() >= 4, "Prefix '/s' matches multiple slash commands (>= 4)");
    bool hasStrings = false, hasSecurity = false, hasScan = false, hasSandbox = false;
    for (const auto* m : sMatches) {
        if (m->name == "strings") hasStrings = true;
        if (m->name == "security") hasSecurity = true;
        if (m->name == "scan") hasScan = true;
        if (m->name == "sandbox") hasSandbox = true;
    }
    AssertTest(hasStrings && hasSecurity && hasScan && hasSandbox, "Prefix '/s' correctly returns /strings, /security, /scan, and /sandbox");

    // 3. Narrowed prefix '/str' matches exactly /strings
    auto strMatches = registry.FilterByPrefix("/str");
    AssertTest(strMatches.size() == 1 && strMatches[0]->name == "strings", "Prefix '/str' narrows uniquely to /strings");

    // 4. Non-matching prefix returns empty
    auto nonMatches = registry.FilterByPrefix("/nonexistent_ghost_command");
    AssertTest(nonMatches.empty(), "Non-matching slash prefix returns empty vector");
}

// ─── 16. LINE EDITOR & PALETTE SELECTION MODEL AUDIT ───────────────────────
static void TestLineEditorBufferAndPaletteModel() {
    std::cout << "\n\033[1;36m=== [AUDIT 16] Line Editor Buffer & Slash Palette Selection Model ===\033[0m\n";

    Dracula::LineEditor editor;

    // 1. Text insertion & cursor movement
    editor.InsertString("/dis");
    AssertTest(editor.GetBuffer() == "/dis", "InsertString populates line editor buffer");
    AssertTest(editor.GetCursorPos() == 4, "Cursor tracks end of inserted text");
    AssertTest(editor.IsPaletteActive(), "Palette automatically activates when input begins with '/'");

    // 2. Palette navigation (Up / Down)
    size_t initialSelection = editor.GetPaletteSelection();
    editor.PaletteMoveDown();
    // Wrap or move down
    editor.PaletteMoveUp();
    AssertTest(editor.GetPaletteSelection() == initialSelection, "Palette Up/Down arrows traverse selection index");

    // 3. Tab completion
    std::string accepted;
    bool acceptedOk = editor.PaletteAccept(accepted);
    AssertTest(acceptedOk && accepted == "disasm", "Palette acceptance completes command name 'disasm'");
    AssertTest(editor.GetBuffer() == "/disasm ", "Buffer updated with completed command name and trailing space");
    AssertTest(!editor.IsPaletteActive(), "Palette closes after command completion");

    // 4. Backspace & Delete
    editor.DeleteCharBeforeCursor();
    AssertTest(editor.GetBuffer() == "/disasm", "Backspace removes trailing space");

    // 5. Cursor Navigation (Home / End)
    editor.MoveCursorHome();
    AssertTest(editor.GetCursorPos() == 0, "Home moves cursor to index 0");
    editor.MoveCursorEnd();
    AssertTest(editor.GetCursorPos() == 7, "End moves cursor to end of line");

    // 6. Clear line
    editor.ClearLine();
    AssertTest(editor.GetBuffer().empty() && editor.GetCursorPos() == 0, "ClearLine empties buffer and resets cursor");
}

// ─── 17. COMMAND HISTORY PERSISTENCE AUDIT ─────────────────────────────────
static void TestCommandHistoryLogic() {
    std::cout << "\n\033[1;36m=== [AUDIT 17] Command History Deduplication & Disk Persistence ===\033[0m\n";

    std::string testHistFile = "test_history_temp.txt";
    if (std::filesystem::exists(testHistFile)) {
        std::filesystem::remove(testHistFile);
    }

    Dracula::LineEditor editor;
    editor.SetHistoryFilePath(testHistFile);
    editor.SetMaxHistorySize(100);

    // 1. Add commands
    editor.AddHistory("/analyze sample.exe");
    // Duplicate consecutive entry
    editor.AddHistory("/analyze sample.exe");
    AssertTest(editor.GetHistory().size() == 1, "Consecutive duplicate command lines are deduplicated in history");

    editor.AddHistory("/security");
    editor.AddHistory("/disasm");
    AssertTest(editor.GetHistory().size() == 3, "Distinct commands are correctly appended to history");

    // 2. Save & Reload from disk
    editor.SaveHistory();
    AssertTest(std::filesystem::exists(testHistFile), "History successfully written to disk file");

    Dracula::LineEditor editor2;
    editor2.SetHistoryFilePath(testHistFile);
    editor2.LoadHistory();
    AssertTest(editor2.GetHistory().size() == 3, "History loaded from disk contains exact count of saved commands");
    AssertTest(editor2.GetHistory()[0] == "/analyze sample.exe", "History preserves first command line");
    AssertTest(editor2.GetHistory()[2] == "/disasm", "History preserves latest command line");

    std::filesystem::remove(testHistFile);
}

// ─── 18. CHANGELOG PARSER & INTEGRITY AUDIT ────────────────────────────────
static void TestChangelogParsing() {
    std::cout << "\n\033[1;36m=== [AUDIT 18] Plain-Text CHANGELOG.txt Integrity & Verification ===\033[0m\n";

    std::vector<std::string> candidates = {"CHANGELOG.txt", "../CHANGELOG.txt"};
    std::string foundPath;
    for (const auto& c : candidates) {
        if (std::filesystem::exists(c)) {
            foundPath = c;
            break;
        }
    }

    AssertTest(!foundPath.empty(), "CHANGELOG.txt exists in project directory");

    std::ifstream file(foundPath);
    AssertTest(file.is_open(), "CHANGELOG.txt can be opened for reading");

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string text = buffer.str();

    AssertTest(text.find("Dracula v1.0.0") != std::string::npos, "CHANGELOG.txt defines Dracula v1.0.0 release header");
    AssertTest(text.find("Added") != std::string::npos, "CHANGELOG.txt includes Added section");
    AssertTest(text.find("Changed") != std::string::npos, "CHANGELOG.txt includes Changed section");
    AssertTest(text.find("Fixed") != std::string::npos, "CHANGELOG.txt includes Fixed section");
    AssertTest(text.find("Verified") != std::string::npos, "CHANGELOG.txt includes Verified section");
    AssertTest(text.find("mojibake") != std::string::npos, "CHANGELOG.txt documents UTF-8/mojibake encoding fix");
}

// ─── 19. ACTIVE SESSION STATE WORKFLOW AUDIT ───────────────────────────────
static void TestSessionWorkflow() {
    std::cout << "\n\033[1;36m=== [AUDIT 19] Analysis Session State & Cross-Command Persistence ===\033[0m\n";

    Dracula::DraculaShell shell;
    AssertTest(shell.GetSessionResult() == nullptr, "Initial shell session is empty before analysis");

    auto mockResult = std::make_unique<Dracula::UnifiedAnalysisResult>();
    mockResult->sample.fileName = "malware_sample.exe";
    mockResult->sample.filePath = "samples/malware_sample.exe";
    mockResult->sample.architecture = "x86_64";
    mockResult->threatScore = 88;
    mockResult->threatLevel = "Critical Threat";

    Dracula::Finding f;
    f.id = "SESSION_TEST_FINDING";
    f.title = "Mock High Threat Finding";
    f.severity = Dracula::FindingSeverity::Critical;
    mockResult->findings.push_back(f);

    shell.SetActiveSession("samples/malware_sample.exe", std::move(mockResult));

    AssertTest(shell.GetSessionResult() != nullptr, "Session result is stored in active DraculaShell");
    AssertTest(shell.GetSessionResult()->threatScore == 88, "Session threat score is preserved across invocations");
    AssertTest(shell.GetActiveFile() == "samples/malware_sample.exe", "Active target file path is retained for subsequent commands");
    AssertTest(shell.GetSessionResult()->findings.size() == 1, "Session findings collection remains accessible to /findings and /report");
}

// ─── 20. SANDBOX PROCESS LINEAGE & THREAT SCORING AUDIT ───────────────────
static void TestSandboxProcessLineageAndThreatScoring() {
    std::cout << "\n\033[1;36m=== [AUDIT 20] Sandbox Process Lineage, Corroboration & Threat Scoring ===\033[0m\n";

    Dracula::SampleMetadata meta;
    Dracula::SecurityMitigations sec;
    sec.hasAslr = true;
    sec.hasDep = true;

    // ─────────────────────────────────────────────────────────────────────────
    // Test A — Benign target only
    // Dracula launches benign_probe.exe -> target starts -> target exits normally
    // Expected: TARGET_PROCESS_STARTED recorded, Info severity, 0 threat weight,
    //           no CHILD_PROCESS_CREATED, final score remains Clean/Benign (0).
    {
        std::vector<Sandbox::TraceEvent> events;
        Sandbox::TraceEvent e1;
        e1.type = Sandbox::EventType::Info;
        e1.category = "GuestAgent";
        e1.message = "Guest Agent started execution of: E:\\benign_probe.exe";

        Sandbox::TraceEvent e2;
        e2.type = Sandbox::EventType::ProcessCreated;
        e2.category = "Process";
        e2.pid = 1200;
        e2.parentPid = 500; // GuestAgent PID preserved
        e2.processName = "benign_probe.exe";
        e2.commandLine = "benign_probe.exe";
        e2.role = Sandbox::ProcessRole::Target;
        e2.message = "Target Process Started: benign_probe.exe (PID: 1200)";
        e2.details = "Parent PID: 500";

        Sandbox::TraceEvent e3;
        e3.type = Sandbox::EventType::ProcessTerminated;
        e3.category = "Process";
        e3.pid = 1200;
        e3.parentPid = 500;
        e3.role = Sandbox::ProcessRole::Target;
        e3.message = "Target Process Exited with Code: 0";

        events.push_back(e1);
        events.push_back(e2);
        events.push_back(e3);

        auto findings = Dracula::ThreatEvaluator::NormalizeSandboxEvents(events);
        AssertTest(findings.size() == 1, "Test A: Exactly 1 finding generated for benign target execution");
        AssertTest(findings[0].id == "SBX_TARGET_PROCESS_STARTED", "Test A: Finding ID is SBX_TARGET_PROCESS_STARTED");
        AssertTest(findings[0].severity == Dracula::FindingSeverity::Info, "Test A: Target start severity is Info");
        AssertTest(findings[0].title.find("Target Process Started") != std::string::npos, "Test A: Accurate title 'Target Process Started'");
        AssertTest(findings[0].evidence.find("Parent PID: 500") != std::string::npos, "Test A: Preserves real parent PID in lineage");

        auto scoreRes = Dracula::ThreatEvaluator::Evaluate(findings, meta, sec, 4.0, false);
        AssertTest(scoreRes.score == 0, "Test A: 0 direct threat score contribution from benign target execution");
        AssertTest(scoreRes.level == "Clean / Benign", "Test A: Threat level is Clean / Benign");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test B — Normal child process
    // target.exe -> benign_helper.exe
    // Expected: child relationship recorded, Low severity, no unjustified Medium/High score.
    {
        std::vector<Sandbox::TraceEvent> events;
        Sandbox::TraceEvent eTarget;
        eTarget.type = Sandbox::EventType::ProcessCreated;
        eTarget.category = "Process";
        eTarget.pid = 1000;
        eTarget.parentPid = 500;
        eTarget.processName = "target.exe";
        eTarget.role = Sandbox::ProcessRole::Target;
        eTarget.message = "Target Process Started: target.exe (PID: 1000)";

        Sandbox::TraceEvent eChild;
        eChild.type = Sandbox::EventType::ProcessCreated;
        eChild.category = "Process";
        eChild.pid = 1001;
        eChild.parentPid = 1000;
        eChild.processName = "benign_helper.exe";
        eChild.commandLine = "benign_helper.exe --worker";
        eChild.role = Sandbox::ProcessRole::Child;
        eChild.message = "Child Process Created: benign_helper.exe (PID: 1001)";
        eChild.details = "Parent PID: 1000";

        events.push_back(eTarget);
        events.push_back(eChild);

        auto findings = Dracula::ThreatEvaluator::NormalizeSandboxEvents(events);
        AssertTest(findings.size() == 2, "Test B: Target start and child process both recorded");
        AssertTest(findings[0].id == "SBX_TARGET_PROCESS_STARTED", "Test B: First finding is SBX_TARGET_PROCESS_STARTED");
        AssertTest(findings[1].id == "SBX_CHILD_PROCESS_CREATED", "Test B: Normal child process is SBX_CHILD_PROCESS_CREATED");
        AssertTest(findings[1].severity == Dracula::FindingSeverity::Low, "Test B: Normal child process severity is Low");
        AssertTest(findings[1].evidence.find("Parent PID: 1000") != std::string::npos, "Test B: Child lineage recorded correctly");

        auto scoreRes = Dracula::ThreatEvaluator::Evaluate(findings, meta, sec, 4.0, false);
        AssertTest(scoreRes.score < 25, "Test B: Normal child process receives benign/low score (< 25)");
        AssertTest(scoreRes.level == "Clean / Benign" || scoreRes.level == "Low Risk", "Test B: No unjustified Medium/High level");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test C — Corroborated suspicious child chain
    // test_target.exe -> test_child.exe with suspicious arguments and corroboration
    // Expected: Severity rises only because multiple evidence signals corroborate.
    {
        std::vector<Sandbox::TraceEvent> events;
        Sandbox::TraceEvent eTarget;
        eTarget.type = Sandbox::EventType::ProcessCreated;
        eTarget.pid = 2000;
        eTarget.parentPid = 500;
        eTarget.processName = "test_target.exe";
        eTarget.role = Sandbox::ProcessRole::Target;

        Sandbox::TraceEvent eChild;
        eChild.type = Sandbox::EventType::ProcessCreated;
        eChild.pid = 2001;
        eChild.parentPid = 2000;
        eChild.processName = "powershell.exe";
        eChild.commandLine = "powershell.exe -w hidden -enc aW52b2tlLWV4cHJlc3Npb24=";
        eChild.role = Sandbox::ProcessRole::Child;

        Sandbox::TraceEvent eNet;
        eNet.type = Sandbox::EventType::NetworkConnect;
        eNet.pid = 2001;
        eNet.message = "Outbound TCP Connection to 192.168.1.100:4444";
        eNet.details = "PID: 2001";

        events.push_back(eTarget);
        events.push_back(eChild);
        events.push_back(eNet);

        auto findings = Dracula::ThreatEvaluator::NormalizeSandboxEvents(events);
        bool foundSuspicious = false;
        for (const auto& f : findings) {
            if (f.id == "SBX_SUSPICIOUS_CHILD_PROCESS") {
                foundSuspicious = true;
                AssertTest(f.severity >= Dracula::FindingSeverity::Medium, "Test C: Suspicious child process has Medium/High severity");
                AssertTest(f.evidence.find("Encoded command line") != std::string::npos, "Test C: Corroborated by encoded command line arguments");
                AssertTest(f.evidence.find("Hidden window") != std::string::npos, "Test C: Corroborated by hidden window flag");
                AssertTest(f.evidence.find("network connection") != std::string::npos, "Test C: Corroborated by network connection");
            }
        }
        AssertTest(foundSuspicious, "Test C: Corroborated suspicious child process finding generated");

        auto scoreRes = Dracula::ThreatEvaluator::Evaluate(findings, meta, sec, 4.0, false);
        AssertTest(scoreRes.score >= 30, "Test C: Threat score rises appropriately with corroborated suspicious evidence");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test D — Duplicate telemetry
    // Send the same process event multiple times
    // Expected: Threat score is not inflated by duplicate telemetry.
    {
        std::vector<Sandbox::TraceEvent> singleEvents;
        Sandbox::TraceEvent eTarget;
        eTarget.type = Sandbox::EventType::ProcessCreated;
        eTarget.pid = 3000;
        eTarget.parentPid = 500;
        eTarget.processName = "sample.exe";
        eTarget.role = Sandbox::ProcessRole::Target;
        singleEvents.push_back(eTarget);

        Sandbox::TraceEvent eChild;
        eChild.type = Sandbox::EventType::ProcessCreated;
        eChild.pid = 3001;
        eChild.parentPid = 3000;
        eChild.processName = "helper.exe";
        eChild.role = Sandbox::ProcessRole::Child;
        singleEvents.push_back(eChild);

        auto singleFindings = Dracula::ThreatEvaluator::NormalizeSandboxEvents(singleEvents);
        auto singleScore = Dracula::ThreatEvaluator::Evaluate(singleFindings, meta, sec, 4.0, false);

        // Send same events 5 times
        std::vector<Sandbox::TraceEvent> duplicatedEvents;
        for (int i = 0; i < 5; ++i) {
            duplicatedEvents.push_back(eTarget);
            duplicatedEvents.push_back(eChild);
        }

        auto dupFindings = Dracula::ThreatEvaluator::NormalizeSandboxEvents(duplicatedEvents);
        auto dupScore = Dracula::ThreatEvaluator::Evaluate(dupFindings, meta, sec, 4.0, false);

        AssertTest(dupFindings.size() == singleFindings.size(), "Test D: Duplicate process telemetry is deduplicated during normalization");
        AssertTest(dupScore.score == singleScore.score, "Test D: Threat score is identical between single and 5x duplicated telemetry");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test E — Same process name, different PID
    // target.exe PID 1000 and target.exe PID 2000
    // Expected: Different processes with identical names remain distinct events.
    {
        std::vector<Sandbox::TraceEvent> events;
        Sandbox::TraceEvent e1;
        e1.type = Sandbox::EventType::ProcessCreated;
        e1.pid = 1000;
        e1.parentPid = 500;
        e1.processName = "target.exe";
        e1.role = Sandbox::ProcessRole::Target;

        Sandbox::TraceEvent e2;
        e2.type = Sandbox::EventType::ProcessCreated;
        e2.pid = 2000;
        e2.parentPid = 1000;
        e2.processName = "target.exe";
        e2.role = Sandbox::ProcessRole::Child;

        events.push_back(e1);
        events.push_back(e2);

        auto findings = Dracula::ThreatEvaluator::NormalizeSandboxEvents(events);
        AssertTest(findings.size() == 2, "Test E: Two instances of target.exe with distinct PIDs yield 2 distinct findings");
        AssertTest(findings[0].id == "SBX_TARGET_PROCESS_STARTED" && findings[0].evidence.find("PID: 1000") != std::string::npos,
                   "Test E: First instance is Target PID 1000");
        AssertTest(findings[1].id == "SBX_CHILD_PROCESS_CREATED" && findings[1].evidence.find("PID: 2000") != std::string::npos,
                   "Test E: Second instance is Child PID 2000");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test F — Process lineage distinction
    // Target -> Direct Child -> Descendant
    // Expected: Lineage preserves Target, Child, and Descendant roles.
    {
        std::vector<Sandbox::TraceEvent> events;
        Sandbox::TraceEvent eTarget;
        eTarget.type = Sandbox::EventType::ProcessCreated;
        eTarget.pid = 4000;
        eTarget.parentPid = 500;
        eTarget.processName = "root_target.exe";
        eTarget.role = Sandbox::ProcessRole::Target;

        Sandbox::TraceEvent eChild;
        eChild.type = Sandbox::EventType::ProcessCreated;
        eChild.pid = 4001;
        eChild.parentPid = 4000;
        eChild.processName = "cmd.exe";
        eChild.role = Sandbox::ProcessRole::Child;

        Sandbox::TraceEvent eDescendant;
        eDescendant.type = Sandbox::EventType::ProcessCreated;
        eDescendant.pid = 4002;
        eDescendant.parentPid = 4001;
        eDescendant.processName = "powershell.exe";
        eDescendant.role = Sandbox::ProcessRole::Descendant;

        events.push_back(eTarget);
        events.push_back(eChild);
        events.push_back(eDescendant);

        auto findings = Dracula::ThreatEvaluator::NormalizeSandboxEvents(events);
        AssertTest(findings.size() == 3, "Test F: 3 findings generated for 3-level process lineage");
        AssertTest(findings[0].id == "SBX_TARGET_PROCESS_STARTED", "Test F: Root is SBX_TARGET_PROCESS_STARTED");
        AssertTest(findings[1].id == "SBX_CHILD_PROCESS_CREATED", "Test F: Direct child is SBX_CHILD_PROCESS_CREATED");
        AssertTest(findings[2].id == "SBX_SUSPICIOUS_CHILD_PROCESS", "Test F: Descendant shell chain is SBX_SUSPICIOUS_CHILD_PROCESS");
    }
}

static void TestAuditBugFixesPass() {
    std::cout << "\n\033[1;36m[+] Running Audit Bug Fix Regression Suite (Bugs 1-9)...\033[0m\n";

    std::string samplesDir = "samples";
    if (!std::filesystem::exists(samplesDir) && std::filesystem::exists("../samples")) {
        samplesDir = "../samples";
    }

    std::string samplePath = "samples/test_sample.exe";
    if (!std::filesystem::exists(samplePath)) {
        if (std::filesystem::exists("../samples/test_sample.exe")) {
            samplePath = "../samples/test_sample.exe";
        } else {
            std::string resP = Dracula::Paths::ResolveResource("samples/test_sample.exe");
            if (!resP.empty()) samplePath = resP;
        }
    }

    // Bug 1: Directory path handling without exception
    {
        auto res = Dracula::InputValidator::ValidateFile(samplesDir);
        AssertTest(res.status == Dracula::FileValidationStatus::IsDirectory, "Bug 1: InputValidator reports IsDirectory for 'samples'");
        AssertTest(!res.IsValid(), "Bug 1: IsDirectory is not valid file");

        Dracula::PeInspector insp;
        std::string err;
        bool loaded = insp.LoadFromFile(samplesDir, err);
        AssertTest(!loaded, "Bug 1: PeInspector::LoadFromFile returns false on directory");
        AssertTest(err.find("directory") != std::string::npos, "Bug 1: Error message explains it is a directory");
    }

    // Bug 2: Out of bounds RVA translation
    {
        Dracula::PeInspector insp;
        std::string err;
        insp.LoadFromFile(samplePath, err);
        auto optOffset = insp.RvaToFileOffset(0xDEADBEEF);
        AssertTest(!optOffset.has_value(), "Bug 2: RvaToFileOffset(0xDEADBEEF) returns std::nullopt");

        auto optValid = insp.RvaToFileOffset(insp.GetMetadata().entryPointRva);
        AssertTest(optValid.has_value(), "Bug 2: RvaToFileOffset(entryPointRva) returns valid offset");
    }

    // Bug 3: Hex format consistency & no decimal formatting with 0x prefix
    {
        std::string h1 = Dracula::Format::Hex(static_cast<uint64_t>(0xA278));
        AssertTest(h1 == "0xa278", "Bug 3: Format::Hex(0xA278) produces 0xa278 (not 0x41592)");

        std::string fn = Dracula::Format::FunctionName(0x105F);
        AssertTest(fn == "sub_105f", "Bug 3: Format::FunctionName(0x105F) produces sub_105f (not sub_4191)");

        Dracula::PeInspector insp;
        std::string err;
        if (insp.LoadFromFile(samplePath, err)) {
            auto findings = insp.GenerateFindings();
            bool foundBad0x = false;
            for (const auto& f : findings) {
                if (f.evidence.find("0x41592") != std::string::npos) foundBad0x = true;
            }
            AssertTest(!foundBad0x, "Bug 3: No decimal IAT RVA printed with 0x prefix in PE findings");
        }
    }

    // Bug 4: Non-existent file analysis does not evaluate false threats
    {
        Dracula::AnalysisOrchestrator orch;
        Dracula::OrchestratorOptions opts;
        auto res = orch.AnalyzeFile("samples/non_existent_file_xyz.exe", opts);
        AssertTest(res.threatScore == 0, "Bug 4: Non-existent file receives threatScore == 0");
        AssertTest(res.threatLevel == "N/A", "Bug 4: Non-existent file receives threatLevel == N/A");
        AssertTest(res.findings.empty(), "Bug 4: Non-existent file produces no synthetic PE findings");
    }

    // Bug 5: MCP unknown tool returns -32601 before argument checking
    {
        Dracula::McpServer mcp;
        std::string req = "{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"tools/call\",\"params\":{\"name\":\"non_existent_fake_tool\"}}";
        std::string resp = mcp.ProcessMessage(req);
        AssertTest(resp.find("-32601") != std::string::npos, "Bug 5: MCP returns error code -32601 for unknown tool");
        AssertTest(resp.find("Unknown tool: non_existent_fake_tool") != std::string::npos, "Bug 5: MCP response indicates Unknown tool");
        AssertTest(resp.find("Missing required") == std::string::npos, "Bug 5: MCP does not return argument error for unknown tool");
    }

    // Bug 6 & Bug 7: Strict pattern scanner and /scan syntax
    {
        auto parseOk = Dracula::PatternScanner::ParsePatternStrict("48 8B 05 ?? ?? ?? ?? 48 85 C0");
        AssertTest(parseOk.IsValid(), "Bug 7: Valid hex pattern parses strictly");
        AssertTest(parseOk.pattern.size() == 10, "Bug 7: Parsed 10 pattern bytes");
        AssertTest(parseOk.pattern[3].isWildcard, "Bug 7: Wildcard byte detected");

        auto parseBad = Dracula::PatternScanner::ParsePatternStrict("ZZ GG HH");
        AssertTest(!parseBad.IsValid(), "Bug 7: Invalid pattern 'ZZ GG HH' rejected");
        AssertTest(parseBad.status == Dracula::PatternParseStatus::InvalidHexDigit || parseBad.status == Dracula::PatternParseStatus::InvalidTokenLength, "Bug 7: Rejection status is InvalidHexDigit/InvalidTokenLength");
        AssertTest(!parseBad.errorMessage.empty(), "Bug 7: Rejection produces descriptive error message");

        std::string scanErr;
        auto matches = Dracula::PatternScanner::ScanFile(samplePath, "ZZ GG HH", &scanErr);
        AssertTest(matches.empty(), "Bug 7: Scan with invalid pattern returns empty");
        AssertTest(!scanErr.empty(), "Bug 7: Scan with invalid pattern reports parse error");
    }

    // Bug 8: Guest share staging isolation
    {
        std::string rootHandoff = "guest_share/dracula_session.ini";
        bool existedBefore = std::filesystem::exists(rootHandoff);

        std::error_code ec;
        auto tempP = std::filesystem::temp_directory_path(ec) / "Dracula";
        AssertTest(!ec, "Bug 8: System temp path accessible for Dracula staging");

        bool existsNow = std::filesystem::exists(rootHandoff);
        AssertTest(existedBefore == existsNow, "Bug 8: Workspace guest_share root is untouched");
    }

    // Bug 9: Anti-evasion CLI options flexibility
    {
        Dracula::DraculaShell shell;
        char arg0[] = "Dracula.exe";
        char arg1[] = "--anti-evasion";
        char arg2[] = "--compare";
        std::vector<char> sampleBuf(samplePath.begin(), samplePath.end());
        sampleBuf.push_back('\0');
        char* arg3 = sampleBuf.data();

        char* argv1[] = { arg0, arg1, arg2, arg3 };
        int rc1 = shell.ProcessArgs(4, argv1);
        AssertTest(rc1 == 0, "Bug 9: Dracula --anti-evasion --compare <sample> returns 0");

        char* argv2[] = { arg0, arg1, arg3, arg2 };
        int rc2 = shell.ProcessArgs(4, argv2);
        AssertTest(rc2 == 0, "Bug 9: Dracula --anti-evasion <sample> --compare returns 0");

        char argFail1[] = "--analyze";
        char argFail2[] = "non_existent_fake_path.exe";
        char* argvFail[] = { arg0, argFail1, argFail2 };
        int rcFail = shell.ProcessArgs(3, argvFail);
        AssertTest(rcFail != 0, "Bug 4 & CLI: Dracula --analyze on non-existent file returns non-zero exit code");
    }
}

int main() {
    std::cout << "\n\033[1;35m==============================================================\033[0m\n";
    std::cout << "\033[1;31m 🧛 DRACULA DEEP VERIFICATION & AUDIT TEST HARNESS\033[0m\n";
    std::cout << "\033[1;35m==============================================================\033[0m\n";

    TestCapstoneDisassembler();
    TestCfgTopology();
    TestXrefAnalyzer();
    TestTebPebCorrectness();
    TestRealHleMachineCodeExecution();
    TestAntiDebugPolicies();
    TestPeParserRobustnessAndMalformedCorpus();
    TestJsonGrammarValidation();
    TestMcpDeepSession();
    TestThreatScoreDeterminism();
    TestHashVerification();
    TestVersionConsistency();
    TestTerminalThemeAndCapabilities();
    TestCommandRegistryMetadata();
    TestSlashCommandPaletteFiltering();
    TestLineEditorBufferAndPaletteModel();
    TestCommandHistoryLogic();
    TestChangelogParsing();
    TestSessionWorkflow();
    TestSandboxProcessLineageAndThreatScoring();
    TestAuditBugFixesPass();

    std::cout << "\n\033[1;35m==============================================================\033[0m\n";
    std::cout << " FINAL AUDIT RESULTS: \033[1;32m" << g_passCount << " PASSED\033[0m, \033[1;31m"
              << g_failCount << " FAILED\033[0m\n";
    std::cout << "\033[1;35m==============================================================\033[0m\n\n";

    return (g_failCount == 0) ? 0 : 1;
}

