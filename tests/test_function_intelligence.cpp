#include "utr/function_intelligence.h"
#include <iostream>
#include <cassert>

using namespace Dracula;
using namespace Dracula::UTR;

int main() {
    std::cout << "[Test] Running Function Intelligence & Ranking Test Suite...\n";

    FunctionIntelligenceManager mgr;

    // Index sample functions
    std::vector<FunctionGraph> staticFuncs;
    FunctionGraph f1;
    f1.entryRva = 0x1000;
    f1.entryAddress = 0x140001000;
    f1.name = "sub_1000";
    f1.totalInstructions = 35;
    staticFuncs.push_back(f1);

    FunctionGraph f2;
    f2.entryRva = 0x2000;
    f2.entryAddress = 0x140002000;
    f2.name = "sub_2000_injector";
    f2.totalInstructions = 150;
    staticFuncs.push_back(f2);

    std::vector<XRefEntry> xrefs;
    std::vector<ExtractedString> strings;
    std::vector<ImportEntry> imports;
    ImportEntry imp;
    imp.dllName = "kernel32.dll";
    imp.functionName = "VirtualAlloc";
    imp.iatRva = 0x3000;
    imports.push_back(imp);

    mgr.IndexStaticFunctions(staticFuncs, xrefs, strings, imports, "sample.exe");
    assert(mgr.TotalDiscovered() == 2);

    // Verify Ranking
    auto ranked = mgr.GetTopInteresting(10);
    assert(ranked.size() == 2);
    assert(ranked[0].rva == 0x2000); // f2 has more instructions
    std::cout << "  Rank #1 Function: " << ranked[0].name << " (Interest Score: " << ranked[0].interestScore << ")\n";
    std::cout << "  Rank #2 Function: " << ranked[1].name << " (Interest Score: " << ranked[1].interestScore << ")\n";

    // Test Runtime Execution Correlation
    std::vector<uint64_t> execAddresses = { 0x140002000 };
    std::vector<HleCallRecord> hleCalls;
    HleCallRecord call;
    call.apiName = "VirtualAlloc";
    call.callerRva = 0x2010;
    hleCalls.push_back(call);

    mgr.CorrelateRuntimeExecutions(execAddresses, hleCalls);
    auto f2Updated = mgr.FindByRva(0x2000);
    assert(f2Updated != nullptr);
    assert(f2Updated->wasExecutedInRuntime);
    assert(f2Updated->runtimeExecutionCount >= 1);

    std::cout << "[Test] Function Intelligence Suite PASSED!\n";
    return 0;
}
