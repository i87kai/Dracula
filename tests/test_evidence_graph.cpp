#include "utr/evidence_graph.h"
#include <iostream>
#include <cassert>

using namespace Dracula::UTR;

int main() {
    std::cout << "[Test] Running Evidence Graph & Behavior Chain Suite...\n";

    EvidenceGraph graph;

    // 1. Add Observed Node
    EvidenceNode n1;
    n1.id = "EV_001";
    n1.category = "AntiAnalysis";
    n1.truthLevel = EvidenceTruthLevel::Observed;
    n1.title = "IsDebuggerPresent Call Executed";
    n1.description = "Direct call to kernel32!IsDebuggerPresent observed during CPU emulation";
    n1.provenance.engine = "UnicornAnalyzer";
    n1.provenance.address = 0x140001050;
    n1.tags = {"Evasion", "AntiDebug", "DirectCall"};
    graph.AddEvidence(n1);

    // 2. Add Inferred Node
    EvidenceNode n2;
    n2.id = "EV_002";
    n2.category = "CodeTransformation";
    n2.truthLevel = EvidenceTruthLevel::Inferred;
    n2.title = "Dynamic Payload Deobfuscation";
    n2.description = "Page 0x10000000 transitioned from RW to RX with entropy jump";
    n2.provenance.engine = "MemoryIntelligence";
    n2.provenance.address = 0x10000000;
    n2.tags = {"Memory", "SelfModifying", "Unpacking"};
    graph.AddEvidence(n2);

    assert(graph.GetNodes().size() == 2);

    // 3. Connect nodes with Behavior Chain
    BehaviorChain chain;
    chain.chainId = "CHAIN_001";
    chain.name = "Anti-Analysis Followed By Dynamic Unpacking";
    chain.evidenceNodeIds = { "EV_001", "EV_002" };
    chain.steps = { "1. Call IsDebuggerPresent", "2. Unpack payload" };
    chain.description = "The target binary first verifies debugger absence before decrypting its secondary payload.";
    graph.AddBehaviorChain(chain);

    assert(graph.GetChains().size() == 1);

    // 4. Test Serialization
    std::string json = graph.ToJson();
    assert(json.find("\"EV_001\"") != std::string::npos);
    assert(json.find("\"Observed\"") != std::string::npos);
    assert(json.find("\"CHAIN_001\"") != std::string::npos);

    std::string md = graph.ToMarkdown();
    assert(md.find("IsDebuggerPresent Call Executed") != std::string::npos);

    std::cout << "[Test] Evidence Graph Suite PASSED!\n";
    return 0;
}
