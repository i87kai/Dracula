// Standalone end-to-end harness for UnicornAnalyzer::EmulateBuffer.
//
// Verifies the in-memory emulation path: page-aligned mapping, shadow stack setup,
// initial register seeding, bounded execution, exact instruction counting, and
// result extraction — without requiring a PE file on disk.

#include "core/unicorn_analyzer.h"

#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

    int g_failures = 0;

    void Check(bool condition, const std::string& what) {
        if (condition) {
            std::cout << "    [PASS] " << what << "\n";
        } else {
            std::cout << "    [FAIL] " << what << "\n";
            ++g_failures;
        }
    }

    template <typename T>
    void CheckEq(const T& actual, const T& expected, const std::string& what) {
        std::ostringstream ss;
        ss << what << " (expected 0x" << std::hex << std::uppercase << expected
           << ", got 0x" << actual << ")";
        Check(actual == expected, ss.str());
    }

    void PrintResult(const Sandbox::FunctionEmulationResult& r) {
        std::cout << "    --- FunctionEmulationResult ---\n";
        std::cout << "    success               : " << (r.success ? "true" : "false") << "\n";
        std::cout << "    errorMessage          : "
                  << (r.errorMessage.empty() ? "<none>" : r.errorMessage) << "\n";
        std::cout << "    rawErrorCode          : " << std::dec << r.rawErrorCode << "\n";
        std::cout << "    errorName             : " << r.errorName << "\n";
        std::cout << "    completedCleanly      : " << (r.CompletedCleanly() ? "true" : "false") << "\n";
        std::cout << "    instructionsExecuted  : " << std::dec << r.instructionsExecuted << "\n";
        std::cout << "    stopAddress           : 0x" << std::hex << std::uppercase
                  << r.stopAddress << "\n";
        std::cout << "    registers             : " << std::dec << r.registers.size() << " entry(ies)\n";
        for (const auto& [name, value] : r.registers) {
            std::cout << "        " << std::setw(4) << std::left << name
                      << " = 0x" << std::hex << std::uppercase << value << std::dec << "\n";
        }
        std::cout << "    -------------------------------\n";
    }

    // Emulation target base. 0x140000000 is the conventional x64 PE image base,
    // which also exercises the page-alignment path for a non-trivial address.
    constexpr uint64_t kBaseAddress = 0x140000000ULL;

    // ---------------------------------------------------------------------
    // Test 1: Basic math / "decryption" routine, no RET.
    //
    //   48 C7 C0 00 10 00 00    mov rax, 0x1000
    //   48 05 37 03 00 00       add rax, 0x337     -> 0x1337
    //   48 83 F0 55             xor rax, 0x55      -> 0x1362
    //
    // Falls off the end of the buffer, so emulation stops cleanly at
    // baseAddress + size with UC_ERR_OK. 3 instructions retired.
    // ---------------------------------------------------------------------
    bool TestMathRoutine(Sandbox::UnicornAnalyzer& analyzer) {
        std::cout << "[TEST 1] Math routine (mov / add / xor), clean fall-through stop\n";

        const std::vector<uint8_t> code = {
            0x48, 0xC7, 0xC0, 0x00, 0x10, 0x00, 0x00,  // mov rax, 0x1000
            0x48, 0x05, 0x37, 0x03, 0x00, 0x00,        // add rax, 0x337
            0x48, 0x83, 0xF0, 0x55                     // xor rax, 0x55
        };

        auto result = analyzer.EmulateBuffer(
            code,
            kBaseAddress,
            /*initialRegs=*/{},
            /*outputRegNames=*/{ "RAX", "RSP", "RIP" });

        PrintResult(result);

        Check(result.success, "result.success is true");
        Check(result.CompletedCleanly(), "CompletedCleanly() is true (ran to stop address)");
        CheckEq<uint32_t>(result.rawErrorCode, static_cast<uint32_t>(UC_ERR_OK),
                          "rawErrorCode == UC_ERR_OK");
        CheckEq<uint64_t>(result.instructionsExecuted, 3, "instructionsExecuted == 3");
        CheckEq<uint64_t>(result.stopAddress, kBaseAddress + code.size(),
                          "stopAddress == base + buffer size");

        auto it = result.registers.find("RAX");
        if (it == result.registers.end()) {
            Check(false, "RAX present in register map");
            return false;
        }
        // 0x1000 + 0x337 = 0x1337;  0x1337 ^ 0x55 = 0x1362
        CheckEq<uint64_t>(it->second, 0x1362ULL, "RAX == 0x1362");

        Check(result.registers.count("RSP") == 1, "RSP present in register map");
        Check(result.registers.count("RIP") == 1, "RIP present in register map");
        return true;
    }

    // ---------------------------------------------------------------------
    // Test 2: Same routine terminated by RET.
    //
    // The shadow stack is zero-filled, so RET pops 0 and the next fetch faults
    // at address 0. EmulateBuffer treats UC_ERR_FETCH_UNMAPPED as a normal
    // truncated stop, so success stays true and RAX is still extracted.
    // 4 instructions retired (the faulting fetch at 0 never executes).
    // ---------------------------------------------------------------------
    bool TestRoutineWithRet(Sandbox::UnicornAnalyzer& analyzer) {
        std::cout << "\n[TEST 2] Same routine terminated by RET (unmapped-return stop)\n";

        const std::vector<uint8_t> code = {
            0x48, 0xC7, 0xC0, 0x00, 0x10, 0x00, 0x00,  // mov rax, 0x1000
            0x48, 0x05, 0x37, 0x03, 0x00, 0x00,        // add rax, 0x337
            0x48, 0x83, 0xF0, 0x55,                    // xor rax, 0x55
            0xC3                                       // ret
        };

        auto result = analyzer.EmulateBuffer(code, kBaseAddress, {}, { "RAX" });
        PrintResult(result);

        Check(result.success, "result.success is true (fetch-unmapped treated as normal stop)");
        // The whole point of rawErrorCode: success is true, but this was NOT a clean run.
        Check(!result.CompletedCleanly(), "CompletedCleanly() is false (returned into unmapped memory)");
        CheckEq<uint32_t>(result.rawErrorCode, static_cast<uint32_t>(UC_ERR_FETCH_UNMAPPED),
                          "rawErrorCode == UC_ERR_FETCH_UNMAPPED");
        Check(!result.errorName.empty(), "errorName decoded from uc_strerror");
        CheckEq<uint64_t>(result.instructionsExecuted, 4, "instructionsExecuted == 4");

        auto it = result.registers.find("RAX");
        if (it == result.registers.end()) {
            Check(false, "RAX present in register map");
            return false;
        }
        CheckEq<uint64_t>(it->second, 0x1362ULL, "RAX == 0x1362 (unchanged by RET)");
        return true;
    }

    // ---------------------------------------------------------------------
    // Test 3: Initial register seeding — the dynamic offset-resolution case.
    //
    //   48 89 C8          mov rax, rcx
    //   48 83 C0 10       add rax, 0x10
    //
    // With RCX seeded to 0x1000, RAX resolves to 0x1010.
    // ---------------------------------------------------------------------
    bool TestInitialRegisterSeeding(Sandbox::UnicornAnalyzer& analyzer) {
        std::cout << "\n[TEST 3] Initial register seeding (offset resolution from RCX)\n";

        const std::vector<uint8_t> code = {
            0x48, 0x89, 0xC8,       // mov rax, rcx
            0x48, 0x83, 0xC0, 0x10  // add rax, 0x10
        };

        const std::unordered_map<uc_x86_reg, uint64_t> initialRegs = {
            { UC_X86_REG_RCX, 0x1000ULL }
        };

        auto result = analyzer.EmulateBuffer(code, kBaseAddress, initialRegs, { "RAX", "RCX" });
        PrintResult(result);

        Check(result.success, "result.success is true");
        CheckEq<uint64_t>(result.instructionsExecuted, 2, "instructionsExecuted == 2");

        auto rax = result.registers.find("RAX");
        if (rax == result.registers.end()) {
            Check(false, "RAX present in register map");
            return false;
        }
        CheckEq<uint64_t>(rax->second, 0x1010ULL, "RAX == 0x1010 (seeded RCX + 0x10)");

        auto rcx = result.registers.find("RCX");
        if (rcx != result.registers.end()) {
            CheckEq<uint64_t>(rcx->second, 0x1000ULL, "RCX preserved == 0x1000");
        }
        return true;
    }

    // ---------------------------------------------------------------------
    // Test 4: Bounded execution — instruction cap must truncate the run.
    // ---------------------------------------------------------------------
    bool TestInstructionCap(Sandbox::UnicornAnalyzer& analyzer) {
        std::cout << "\n[TEST 4] Bounded execution (maxInstructions cap)\n";

        const std::vector<uint8_t> code = {
            0x48, 0xC7, 0xC0, 0x00, 0x10, 0x00, 0x00,  // mov rax, 0x1000
            0x48, 0x05, 0x37, 0x03, 0x00, 0x00,        // add rax, 0x337
            0x48, 0x83, 0xF0, 0x55                     // xor rax, 0x55
        };

        // Cap at 2: the xor must never execute, so RAX stays at 0x1337.
        auto result = analyzer.EmulateBuffer(
            code, kBaseAddress, {}, { "RAX" },
            /*is64Bit=*/true, /*maxInstructions=*/2);

        PrintResult(result);

        Check(result.success, "result.success is true");
        CheckEq<uint64_t>(result.instructionsExecuted, 2, "instructionsExecuted == 2 (capped)");

        auto it = result.registers.find("RAX");
        if (it == result.registers.end()) {
            Check(false, "RAX present in register map");
            return false;
        }
        CheckEq<uint64_t>(it->second, 0x1337ULL, "RAX == 0x1337 (xor not reached)");
        return true;
    }

    // ---------------------------------------------------------------------
    // Test 5: Empty buffer must fail cleanly, not crash.
    // ---------------------------------------------------------------------
    bool TestEmptyBuffer(Sandbox::UnicornAnalyzer& analyzer) {
        std::cout << "\n[TEST 5] Empty buffer rejection\n";

        const std::vector<uint8_t> code;
        auto result = analyzer.EmulateBuffer(code, kBaseAddress);
        PrintResult(result);

        Check(!result.success, "result.success is false for empty buffer");
        Check(!result.CompletedCleanly(), "CompletedCleanly() is false");
        CheckEq<uint32_t>(result.rawErrorCode, static_cast<uint32_t>(UC_ERR_ARG),
                          "rawErrorCode == UC_ERR_ARG");
        Check(!result.errorMessage.empty(), "errorMessage populated");
        CheckEq<uint64_t>(result.instructionsExecuted, 0, "instructionsExecuted == 0");
        return true;
    }

    // ---------------------------------------------------------------------
    // Test 6: Repeat invocation — checks map/unmap/close lifecycle has no
    // leaked state or stale mappings across many sequential calls.
    // ---------------------------------------------------------------------
    bool TestRepeatedInvocations(Sandbox::UnicornAnalyzer& analyzer) {
        std::cout << "\n[TEST 6] Repeated invocations (resource lifecycle)\n";

        const std::vector<uint8_t> code = {
            0x48, 0xC7, 0xC0, 0x00, 0x10, 0x00, 0x00,  // mov rax, 0x1000
            0x48, 0x05, 0x37, 0x03, 0x00, 0x00,        // add rax, 0x337
            0x48, 0x83, 0xF0, 0x55                     // xor rax, 0x55
        };

        constexpr int kIterations = 256;
        int okCount = 0;
        for (int i = 0; i < kIterations; ++i) {
            auto result = analyzer.EmulateBuffer(code, kBaseAddress, {}, { "RAX" });
            auto it = result.registers.find("RAX");
            if (result.success && result.instructionsExecuted == 3 &&
                it != result.registers.end() && it->second == 0x1362ULL) {
                ++okCount;
            }
        }

        std::cout << "    completed " << okCount << "/" << kIterations
                  << " iterations with identical results\n";
        Check(okCount == kIterations, "all iterations produced correct, stable results");
        return true;
    }

} // namespace

int main() {
    std::cout << "==============================================================\n";
    std::cout << " UnicornAnalyzer::EmulateBuffer - End-to-End Test Harness\n";
    std::cout << "==============================================================\n\n";

    Sandbox::UnicornAnalyzer analyzer;

    // Route emitted trace events to stdout so the event-pipeline integration
    // is visible alongside the assertions.
    analyzer.SetEventCallback([](const Sandbox::TraceEvent& evt) {
        std::cout << "    <event> [" << evt.category << "] " << evt.message << "\n";
    });

    Sandbox::VMConfig vmConfig;
    Sandbox::TraceOptions options;
    if (!analyzer.Initialize(vmConfig, options)) {
        std::cerr << "FATAL: analyzer.Initialize() failed.\n";
        return 2;
    }

    TestMathRoutine(analyzer);
    TestRoutineWithRet(analyzer);
    TestInitialRegisterSeeding(analyzer);
    TestInstructionCap(analyzer);
    TestEmptyBuffer(analyzer);
    TestRepeatedInvocations(analyzer);

    // Confirm emitted events landed in the report pipeline.
    std::cout << "\n[REPORT] AnalysisReport integration\n";
    auto report = analyzer.GetReport();
    std::cout << "    analysisType : " << report.analysisType << "\n";
    std::cout << "    events       : " << report.events.size() << "\n";
    Check(!report.events.empty(), "EmulateBuffer events reached AnalysisReport");

    std::cout << "\n==============================================================\n";
    if (g_failures == 0) {
        std::cout << " RESULT: ALL CHECKS PASSED\n";
    } else {
        std::cout << " RESULT: " << g_failures << " CHECK(S) FAILED\n";
    }
    std::cout << "==============================================================\n";

    return g_failures == 0 ? 0 : 1;
}
