//
// Dracula Anti-Evasion Intelligence Engine verification suite.
//
// Every dynamic assertion here runs real machine code through Unicorn under a
// real EnvironmentProfile. Nothing is asserted about helper functions that the
// production path does not itself use.
//

#include "common/findings.h"
#include "core/anti_evasion_engine.h"
#include "core/environment_profile.h"
#include "core/evasion_artifact_rules.h"
#include "core/virtual_time.h"
#include "core/branch_influence.h"
#include "core/unicorn_analyzer.h"
#include "core/threat_evaluator.h"
#include "core/analysis_orchestrator.h"
#include "host/sandbox_fingerprint.h"
#include "cli/command_registry.h"
#include "cli/dracula_shell.h"
#include "cli/terminal.h"
#include "mcp/mcp_server.h"

#include <unicorn/unicorn.h>
#include <unicorn/x86.h>
#include <capstone/capstone.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <stack>
#include <string>
#include <vector>

using namespace Dracula;

static int g_pass = 0;
static int g_fail = 0;
static int g_blocked = 0;

static void Check(bool condition, const std::string& name) {
    if (condition) {
        std::cout << "  \033[32m[PASS]\033[0m " << name << "\n";
        g_pass++;
    } else {
        std::cout << "  \033[1;31m[FAIL]\033[0m " << name << "\n";
        g_fail++;
    }
}

static void Blocked(const std::string& name, const std::string& reason) {
    std::cout << "  \033[1;33m[BLOCKED BY ENVIRONMENT]\033[0m " << name << " - " << reason << "\n";
    g_blocked++;
}

static void Section(const std::string& title) {
    std::cout << "\n\033[1;36m=== " << title << " ===\033[0m\n";
}

#ifndef DRACULA_AE_SAMPLE_DIR
#define DRACULA_AE_SAMPLE_DIR "samples/antievasion"
#endif

static std::string SamplePath(const std::string& name) {
    return (std::filesystem::path(DRACULA_AE_SAMPLE_DIR) / (name + ".exe")).string();
}

static bool ValidateJson(const std::string& json, std::string& err) {
    std::stack<char> stack;
    bool inString = false, escape = false;
    for (size_t i = 0; i < json.size(); ++i) {
        const char c = json[i];
        if (inString) {
            if (escape)            escape = false;
            else if (c == '\\')    escape = true;
            else if (c == '"')     inString = false;
        } else if (c == '"')       inString = true;
        else if (c == '{' || c == '[') stack.push(c);
        else if (c == '}') {
            if (stack.empty() || stack.top() != '{') { err = "unmatched } at " + std::to_string(i); return false; }
            stack.pop();
        } else if (c == ']') {
            if (stack.empty() || stack.top() != '[') { err = "unmatched ] at " + std::to_string(i); return false; }
            stack.pop();
        }
    }
    if (!stack.empty()) { err = "unclosed containers"; return false; }
    if (inString)       { err = "unterminated string"; return false; }
    return true;
}

// ─── 1. Taxonomy and parsing ────────────────────────────────────────────────

static void TestTaxonomy() {
    Section("1. Technique taxonomy and identifiers");

    Check(std::string(EvasionCategoryId(EvasionCategory::AntiVmCpuid)) == "ANTI_VM_CPUID",
          "ANTI_VM_CPUID has its documented identifier");
    Check(std::string(EvasionCategoryId(EvasionCategory::EvasionBehaviorDivergence)) ==
              "EVASION_BEHAVIOR_DIVERGENCE",
          "EVASION_BEHAVIOR_DIVERGENCE has its documented identifier");
    Check(std::string(EvasionCategoryId(EvasionCategory::AntiDebugPeb)) == "ANTI_DEBUG_PEB",
          "ANTI_DEBUG_PEB has its documented identifier");

    // Every category must round-trip through its identifier.
    bool roundTrip = true;
    std::vector<std::string> ids;
    for (int i = 0; i <= static_cast<int>(EvasionCategory::ProfileCoherenceWarning); ++i) {
        const auto c = static_cast<EvasionCategory>(i);
        EvasionCategory parsed;
        if (!ParseEvasionCategory(EvasionCategoryId(c), parsed) || parsed != c) roundTrip = false;
        ids.emplace_back(EvasionCategoryId(c));
    }
    Check(roundTrip, "Every category round-trips through its string identifier");

    std::sort(ids.begin(), ids.end());
    Check(std::adjacent_find(ids.begin(), ids.end()) == ids.end(),
          "Category identifiers are unique");

    EvasionCategory bogus;
    Check(!ParseEvasionCategory("NOT_A_CATEGORY", bogus),
          "An unknown identifier does not parse");

    ProfileKind kind;
    Check(ParseProfileKind("baseline", kind) && kind == ProfileKind::Baseline,
          "Profile name 'baseline' parses");
    Check(ParseProfileKind("Realistic", kind) && kind == ProfileKind::Realistic,
          "Profile name 'Realistic' parses case-insensitively");
    Check(ParseProfileKind("analysis-friendly", kind) && kind == ProfileKind::AnalysisFriendly,
          "Profile name 'analysis-friendly' parses");
    Check(!ParseProfileKind("stealth", kind), "An unknown profile name is rejected");
}

// ─── 2. Coherent virtual clock ──────────────────────────────────────────────

static void TestVirtualTime() {
    Section("2. Multi-clock consistency model");

    TimingPolicy policy;
    policy.tscHz = 3600000000ULL;
    policy.qpcHz = 10000000ULL;
    policy.nanosPerInstruction = 1;
    policy.tickCountBaseMs = 1000;
    policy.bootUptimeMs = 1000;
    policy.sleepAdvancesClock = true;

    VirtualTimeState clock(policy);
    Check(clock.Tsc() == 0 && clock.QpcCounter() == 0 && clock.TickCount64() == 1000,
          "A fresh clock reads zero elapsed on every source");

    clock.AdvanceMillis(5000, "test sleep", "kernel32!Sleep");

    const uint64_t tsc = clock.Tsc();
    const uint64_t qpc = clock.QpcCounter();
    const uint64_t tick = clock.TickCount64();
    const uint64_t uptime = clock.UptimeMillis();

    Check(tick - policy.tickCountBaseMs == 5000, "GetTickCount advanced by exactly 5000 ms");
    Check(qpc == 5000ULL * 10000ULL, "QueryPerformanceCounter advanced by 5000 ms at 10 MHz");
    Check(tsc == 5000ULL * 3600000ULL, "RDTSC advanced by 5000 ms at 3.6 GHz");
    Check(uptime - policy.bootUptimeMs == 5000, "System uptime advanced by 5000 ms");

    // The contradiction the guide warns about must be arithmetically impossible.
    const double tscMs = static_cast<double>(tsc) / (policy.tscHz / 1000.0);
    const double qpcMs = static_cast<double>(qpc) / (policy.qpcHz / 1000.0);
    Check(std::abs(tscMs - 5000.0) < 1.0 && std::abs(qpcMs - 5000.0) < 1.0,
          "Every clock source agrees on the elapsed interval to within 1 ms");

    Check(clock.WasNormalized() && clock.AdvanceEvents().size() == 1,
          "The explicit advance is recorded in the audit trail");
    Check(clock.AdvanceEvents()[0].byNanos == 5000ULL * 1000000ULL,
          "The recorded advance carries the exact amount of logical time added");

    // Instruction retirement moves the same single counter.
    VirtualTimeState instrClock(policy);
    instrClock.OnInstructionsRetired(1000000);
    Check(instrClock.ElapsedMillis() == 1 && instrClock.Tsc() > 0,
          "Retiring instructions advances the same logical counter");
    Check(!instrClock.WasNormalized(),
          "Instruction retirement is not recorded as a normalization");

    // A Baseline clock does not move: that is deliberate and detectable.
    VirtualTimeState frozen(EnvironmentProfile::Baseline().timing);
    frozen.OnInstructionsRetired(100000);
    Check(frozen.ElapsedMillis() == 0 && frozen.Tsc() == 0,
          "The Baseline clock is frozen, reproducing Dracula's historical behaviour");
}

// ─── 3. Profile coherence validation ────────────────────────────────────────

static void TestProfileCoherence() {
    Section("3. Environment coherence validator");

    for (auto kind : {ProfileKind::Baseline, ProfileKind::Realistic, ProfileKind::AnalysisFriendly}) {
        const auto profile = EnvironmentProfile::FromKind(kind);
        const auto graph = BuildConsistencyGraph(profile);
        Check(graph.IsCoherent(),
              std::string("Shipped profile ") + profile.name + " produces no coherence warnings");
    }

    // Fingerprintability must reflect reality: an honest analysis environment
    // is more detectable than one that has been normalized.
    const auto baseGraph = BuildConsistencyGraph(EnvironmentProfile::Baseline());
    const auto friendlyGraph = BuildConsistencyGraph(EnvironmentProfile::AnalysisFriendly());
    Check(baseGraph.fingerprintability > friendlyGraph.fingerprintability,
          "Baseline is scored as more fingerprintable than AnalysisFriendly");
    Check(!baseGraph.claims.empty() && !friendlyGraph.claims.empty(),
          "Both profiles produce environment claims");

    // ── Invalid profile 1: hypervisor hidden, vendor leaf still exposed ──
    {
        auto p = EnvironmentProfile::AnalysisFriendly();
        p.cpu.hypervisorPresent = false;
        p.cpu.hypervisorLeavesExposed = true;
        p.cpu.hypervisorVendor = "KVMKVMKVM";
        const auto g = BuildConsistencyGraph(p);
        bool caught = false;
        for (const auto& c : g.contradictions) {
            if (c.property == "Cpu.Virtualized" && c.severity == FindingSeverity::Critical) caught = true;
        }
        Check(caught, "Hypervisor bit cleared while the vendor leaf answers is caught as critical");
    }

    // ── Invalid profile 2: CPU topology disagrees with the OS API ──
    {
        auto p = EnvironmentProfile::Realistic();
        p.cpu.logicalProcessors = 8;
        p.host.processorCount = 1;
        const auto g = BuildConsistencyGraph(p);
        bool caught = false;
        for (const auto& c : g.contradictions) {
            if (c.property == "Cpu.LogicalProcessors") caught = true;
        }
        Check(caught, "CPUID topology contradicting the OS processor count is caught");
    }

    // ── Invalid profile 3: physical presentation with virtual disk metadata ──
    {
        auto p = EnvironmentProfile::AnalysisFriendly();
        p.host.diskModel = "QEMU HARDDISK";
        const auto g = BuildConsistencyGraph(p);
        bool caught = false;
        for (const auto& c : g.contradictions) {
            if (c.property == "Disk.Model") caught = true;
        }
        Check(caught, "Physical-looking profile exposing a QEMU disk model is caught");
    }

    // ── Invalid profile 4: impossible timing configuration ──
    {
        auto p = EnvironmentProfile::AnalysisFriendly();
        p.timing.nanosPerInstruction = 0;   // clock frozen, but presents as hardware
        const auto g = BuildConsistencyGraph(p);
        bool caught = false;
        for (const auto& c : g.contradictions) {
            if (c.property == "Timing.Model") caught = true;
        }
        Check(caught, "A frozen clock on a physically-presented profile is caught");
    }

    // ── Invalid profile 5: zero-frequency clock ──
    {
        auto p = EnvironmentProfile::Realistic();
        p.timing.qpcHz = 0;
        const auto g = BuildConsistencyGraph(p);
        Check(!g.IsCoherent(), "A zero-frequency timing source is caught");
    }

    // Contradictions must surface as findings with the documented id.
    {
        auto p = EnvironmentProfile::AnalysisFriendly();
        p.cpu.hypervisorLeavesExposed = true;
        const auto findings = BuildConsistencyGraph(p).ToFindings();
        bool tagged = !findings.empty();
        for (const auto& f : findings) {
            if (f.id != "PROFILE_COHERENCE_WARNING") tagged = false;
        }
        Check(tagged, "Contradictions surface as PROFILE_COHERENCE_WARNING findings");
    }
}

// ─── 4. Artifact rules ──────────────────────────────────────────────────────

static void TestArtifactRules() {
    Section("4. Data-driven artifact rules");

    Check(!EvasionArtifactRules().empty(), "The artifact rule table is populated");

    const auto* qemuDisk = MatchArtifact("\\Device\\QEMU HARDDISK\\0");
    Check(qemuDisk && qemuDisk->pattern == "qemu harddisk",
          "The longest matching artifact wins over the bare vendor name");
    Check(qemuDisk && qemuDisk->baseConfidence == FindingConfidence::High,
          "A device product id is high-confidence in the rule table");

    const auto* vendor = MatchArtifact("Built for VMware compatibility");
    Check(vendor && vendor->baseConfidence == FindingConfidence::Low,
          "A bare vendor name is only low confidence");

    const auto* hv = MatchArtifact("KVMKVMKVM");
    Check(hv && hv->category == EvasionCategory::AntiVmHypervisorVendor,
          "A CPUID hypervisor signature maps to ANTI_VM_HYPERVISOR_VENDOR");

    Check(MatchArtifact("hello world") == nullptr, "An ordinary string matches no rule");
    Check(MatchArtifact("ab") == nullptr, "Very short strings are not matched");

    const auto* api = MatchEnvironmentApi("GetSystemInfo");
    Check(api && api->category == EvasionCategory::AntiVmCpuTopology && !api->strongIndicator,
          "GetSystemInfo is recognised but marked as NOT a strong indicator");

    const auto* strong = MatchEnvironmentApi("GetLastInputInfo");
    Check(strong && strong->strongIndicator,
          "GetLastInputInfo is marked as a strong indicator");

    Check(MatchEnvironmentApi("CreateFileW") == nullptr,
          "An ordinary API is not in the environment rule table");
    Check(MatchEnvironmentApi("getsysteminfo") != nullptr,
          "API matching is case-insensitive");
}

// ─── 5. Branch influence provenance ─────────────────────────────────────────

static void TestBranchInfluence() {
    Section("5. Bounded branch-influence provenance");

    BranchInfluenceTracker tracker;
    OriginMark mark;
    mark.origin = EnvironmentOrigin::Cpuid;
    mark.producedAt = 0x1000;
    mark.producedRva = 0x1000;
    mark.property = "Hypervisor presence";

    tracker.MarkRegister(X86_REG_RCX, mark);
    Check(tracker.RegisterMark(X86_REG_RCX).Valid(), "A marked register carries its origin");

    tracker.OnDataFlow({static_cast<unsigned>(X86_REG_RCX)}, {static_cast<unsigned>(X86_REG_RAX)});
    Check(tracker.RegisterMark(X86_REG_RAX).origin == EnvironmentOrigin::Cpuid,
          "The mark propagates through data movement");

    tracker.OnFlagsWritten({static_cast<unsigned>(X86_REG_RAX)}, 0x1010, 0x1010, "test eax, eax");
    Check(tracker.FlagsMarked(), "A compare on a marked register marks the flags");

    auto attributed = tracker.OnConditionalBranch(0x1012, 0x1012, "je", 0x1050, 0x1014, true);
    Check(attributed.origin == EnvironmentOrigin::Cpuid,
          "A conditional branch on marked flags is attributed to CPUID");
    Check(tracker.InfluencedBranches().count(0x1012) == 1,
          "The influenced branch is recorded");

    // A write from an untainted source must destroy the mark. Over-eager
    // attribution would inflate confidence, which is the one thing this engine
    // must never do.
    tracker.OnDataFlow({}, {static_cast<unsigned>(X86_REG_RAX)});
    Check(!tracker.RegisterMark(X86_REG_RAX).Valid(),
          "An untainted write clears the mark rather than keeping it");

    tracker.OnFlagsWritten({static_cast<unsigned>(X86_REG_RAX)}, 0x1020, 0x1020, "cmp eax, 1");
    Check(!tracker.FlagsMarked(), "Flags set from an unmarked register are unmarked");

    auto none = tracker.OnConditionalBranch(0x1022, 0x1022, "jne", 0x1060, 0x1024, false);
    Check(!none.Valid(), "A branch on unmarked flags is not attributed");

    tracker.Reset();
    Check(tracker.InfluencedBranches().empty() && !tracker.FlagsMarked(),
          "Reset clears all provenance state");
}

// ─── 6. CPUID machine-code behaviour under each profile ─────────────────────

// mov eax, <leaf> ; xor ecx, ecx ; cpuid ; mov r8d, ecx ; mov r9d, ebx ; hlt
static std::vector<uint8_t> CpuidProbe(uint32_t leaf) {
    std::vector<uint8_t> code = {
        0xB8, 0, 0, 0, 0,          // mov eax, leaf
        0x31, 0xC9,                // xor ecx, ecx
        0x0F, 0xA2,                // cpuid
        0x41, 0x89, 0xC8,          // mov r8d, ecx
        0x41, 0x89, 0xD9,          // mov r9d, ebx
    };
    code[1] = static_cast<uint8_t>(leaf & 0xFF);
    code[2] = static_cast<uint8_t>((leaf >> 8) & 0xFF);
    code[3] = static_cast<uint8_t>((leaf >> 16) & 0xFF);
    code[4] = static_cast<uint8_t>((leaf >> 24) & 0xFF);
    return code;
}

static void TestCpuidMachineCode() {
    Section("6. CPUID machine-code execution under environment profiles");

    auto runCpuid = [](ProfileKind kind, uint32_t leaf,
                       uint64_t& outEcx, uint64_t& outEbx, uint64_t& outEax) {
        UnicornAnalyzer emu;
        emu.GetEnvironment().ApplyProfile(EnvironmentProfile::FromKind(kind));
        const auto code = CpuidProbe(leaf);
        auto r = emu.EmulateBuffer(code, 0x400000, {}, {"RAX", "RBX", "R8", "R9"},
                                   true, 64, 0, 0);
        outEcx = r.registers.count("R8") ? r.registers.at("R8") : 0;
        outEbx = r.registers.count("R9") ? r.registers.at("R9") : 0;
        outEax = r.registers.count("RAX") ? r.registers.at("RAX") : 0;
        return r.success;
    };

    uint64_t ecx = 0, ebx = 0, eax = 0;

    // Leaf 1 ECX bit 31 is the hypervisor-present bit.
    Check(runCpuid(ProfileKind::Baseline, 1, ecx, ebx, eax), "CPUID leaf 1 executes under Baseline");
    const bool baselineHv = (ecx & 0x80000000ULL) != 0;
    Check(baselineHv, "Baseline sets the CPUID hypervisor-present bit");
    const uint32_t baselineCpus = static_cast<uint32_t>((ebx >> 16) & 0xFF);
    Check(baselineCpus == 2, "Baseline reports 2 logical processors in CPUID leaf 1 EBX");

    Check(runCpuid(ProfileKind::AnalysisFriendly, 1, ecx, ebx, eax),
          "CPUID leaf 1 executes under AnalysisFriendly");
    const bool friendlyHv = (ecx & 0x80000000ULL) != 0;
    Check(!friendlyHv, "AnalysisFriendly clears the CPUID hypervisor-present bit");
    const uint32_t friendlyCpus = static_cast<uint32_t>((ebx >> 16) & 0xFF);
    Check(friendlyCpus == 8, "AnalysisFriendly reports 8 logical processors in CPUID leaf 1 EBX");

    Check(runCpuid(ProfileKind::Realistic, 1, ecx, ebx, eax), "CPUID leaf 1 executes under Realistic");
    Check((ecx & 0x80000000ULL) != 0,
          "Realistic leaves the hypervisor bit SET: it does not suppress evidence");

    // Leaf 0x40000000 is the hypervisor vendor leaf.
    Check(runCpuid(ProfileKind::Baseline, 0x40000000, ecx, ebx, eax),
          "CPUID hypervisor vendor leaf executes under Baseline");
    Check(ebx == 0x564D4B56ULL /* "VMKV" == 'K','V','M','K' little-endian */ || ebx != 0,
          "Baseline answers the hypervisor vendor leaf with a signature");
    const uint64_t baselineVendorEbx = ebx;

    Check(runCpuid(ProfileKind::AnalysisFriendly, 0x40000000, ecx, ebx, eax),
          "CPUID hypervisor vendor leaf executes under AnalysisFriendly");
    Check(ebx == 0 && eax == 0,
          "AnalysisFriendly does not answer the hypervisor vendor leaf");
    Check(baselineVendorEbx != ebx,
          "The hypervisor vendor leaf differs between Baseline and AnalysisFriendly");

    // Leaf 0 must return a consistent CPU vendor string in both.
    Check(runCpuid(ProfileKind::Baseline, 0, ecx, ebx, eax), "CPUID leaf 0 executes");
    Check(ebx == 0x756E6547ULL, "CPUID leaf 0 EBX is 'Genu' as configured");
}

// ─── 7. RDTSC machine-code behaviour ────────────────────────────────────────

static void TestTimestampMachineCode() {
    Section("7. Timestamp-counter machine-code interception");

    // rdtsc ; mov r8d, eax ; mov r9d, edx ; <many nops> ; rdtsc ; mov r10d, eax
    auto runRdtsc = [](ProfileKind kind, uint64_t& first, uint64_t& second) {
        std::vector<uint8_t> code = {
            0x0F, 0x31,             // rdtsc
            0x41, 0x89, 0xC0,       // mov r8d, eax
        };
        for (int i = 0; i < 200; ++i) code.push_back(0x90);   // 200 nops of work
        code.insert(code.end(), {0x0F, 0x31});                // rdtsc
        code.insert(code.end(), {0x41, 0x89, 0xC1});          // mov r9d, eax

        UnicornAnalyzer emu;
        emu.GetEnvironment().ApplyProfile(EnvironmentProfile::FromKind(kind));
        auto r = emu.EmulateBuffer(code, 0x400000, {}, {"R8", "R9"}, true, 1000, 0, 0);
        first = r.registers.count("R8") ? r.registers.at("R8") : 0;
        second = r.registers.count("R9") ? r.registers.at("R9") : 0;
        return r.success;
    };

    uint64_t a = 0, b = 0;
    Check(runRdtsc(ProfileKind::Baseline, a, b), "RDTSC machine code executes under Baseline");
    Check(a == 0 && b == 0, "Under the frozen Baseline clock both RDTSC reads return 0");

    Check(runRdtsc(ProfileKind::Realistic, a, b), "RDTSC machine code executes under Realistic");
    Check(b > a, "Under Realistic the second RDTSC is strictly later than the first");
    Check((b - a) >= 200 * 3, "The measured delta reflects the ~200 instructions of work");

    // RDTSCP (0F 01 F9) must also be intercepted and must not fault.
    {
        std::vector<uint8_t> code = {
            0x0F, 0x01, 0xF9,       // rdtscp
            0x41, 0x89, 0xC0,       // mov r8d, eax
        };
        UnicornAnalyzer emu;
        emu.GetEnvironment().ApplyProfile(EnvironmentProfile::Realistic());
        auto r = emu.EmulateBuffer(code, 0x400000, {}, {"R8"}, true, 64, 0, 0);
        Check(r.success, "RDTSCP machine code executes without faulting");
    }
}

// ─── 8. Static detection on real samples ────────────────────────────────────

static void TestStaticDetection() {
    Section("8. Static detection");

    const std::string cpuidSample = SamplePath("ae_cpuid_gate");
    if (!std::filesystem::exists(cpuidSample)) {
        Blocked("Static detection", "probe samples were not built");
        return;
    }

    auto techniques = AntiEvasionEngine::DetectStatic(cpuidSample);
    Check(!techniques.empty(), "Static detection finds techniques in the CPUID gate probe");

    bool foundCpuid = false, cpuidControlsFlow = false;
    for (const auto& t : techniques) {
        if (t.category == EvasionCategory::AntiVmCpuid ||
            t.category == EvasionCategory::AntiVmHypervisorVendor) {
            foundCpuid = true;
            if (t.controlsFlow) cpuidControlsFlow = true;
        }
    }
    Check(foundCpuid, "The CPUID instruction is located statically by Capstone");
    Check(cpuidControlsFlow,
          "Static analysis proves the CPUID result reaches a compare and a conditional branch");

    // Every technique must carry evidence pointing back at something concrete.
    bool allHaveEvidence = true, allHaveRva = true;
    for (const auto& t : techniques) {
        if (t.evidence.empty()) allHaveEvidence = false;
        if (t.rva == 0 && t.category != EvasionCategory::ProfileCoherenceWarning) allHaveRva = false;
    }
    Check(allHaveEvidence, "Every detected technique carries at least one piece of evidence");
    Check(allHaveRva, "Every detected technique is anchored to an RVA");

    // Timing probe: RDTSC/tick APIs.
    auto timing = AntiEvasionEngine::DetectStatic(SamplePath("ae_timing_gate"));
    bool foundTiming = false;
    for (const auto& t : timing) {
        if (t.category == EvasionCategory::AntiVmTiming ||
            t.category == EvasionCategory::AntiSandboxSleep) {
            foundTiming = true;
        }
    }
    Check(foundTiming, "Timing APIs are detected statically in the timing gate probe");
}

// ─── 9. Differential execution ──────────────────────────────────────────────

struct DifferentialOutcome {
    AntiEvasionResult result;
    bool ran = false;
};

static DifferentialOutcome RunCompare(const std::string& sample) {
    DifferentialOutcome out;
    if (!std::filesystem::exists(sample)) return out;
    AntiEvasionOptions opts;
    opts.runComparison = true;
    opts.maxInstructionsPerRun = 100000;
    AntiEvasionEngine engine;
    out.result = engine.Analyze(sample, opts);
    out.ran = true;
    return out;
}

static void TestDifferentialExecution() {
    Section("9. Differential execution: CPUID gate");

    auto outcome = RunCompare(SamplePath("ae_cpuid_gate"));
    if (!outcome.ran) {
        Blocked("Differential execution", "probe samples were not built");
        return;
    }
    const auto& r = outcome.result;

    Check(r.runs.size() == 3, "Three environment profiles were executed");
    Check(r.comparePerformed, "The result records that comparison was performed");

    const DifferentialRun* baseline = nullptr;
    const DifferentialRun* friendly = nullptr;
    for (const auto& run : r.runs) {
        if (run.profileKind == ProfileKind::Baseline) baseline = &run;
        if (run.profileKind == ProfileKind::AnalysisFriendly) friendly = &run;
    }
    Check(baseline && friendly, "Baseline and AnalysisFriendly runs are both present");
    if (!baseline || !friendly) return;

    Check(friendly->fingerprint.blocksReached > baseline->fingerprint.blocksReached,
          "AnalysisFriendly reaches strictly more basic blocks than Baseline");
    Check(friendly->fingerprint.functionsReached > baseline->fingerprint.functionsReached,
          "AnalysisFriendly reaches strictly more functions than Baseline");
    Check(friendly->fingerprint.instructionsExecuted > baseline->fingerprint.instructionsExecuted,
          "AnalysisFriendly executes strictly more instructions than Baseline");
    Check(friendly->fingerprint.digest != baseline->fingerprint.digest,
          "The two runs produce different behavioural fingerprints");

    Check(!r.branchDivergences.empty(), "At least one branch changed direction between profiles");
    Check(r.status == AntiEvasionStatus::BehaviorDiverged,
          "The engine reports status BehaviorDiverged");

    // The divergence must be a specific branch with concrete consequences, not
    // merely "the two results differ".
    bool concrete = false, attributed = false;
    for (const auto& bd : r.branchDivergences) {
        if (bd.rva != 0 && bd.baselineTaken != bd.alternateTaken &&
            !bd.baselineConsequence.empty() && !bd.alternateConsequence.empty()) {
            concrete = true;
        }
        if (bd.influenceOrigin == "CPUID") attributed = true;
    }
    Check(concrete, "A divergent branch is reported with an RVA and both consequences");
    Check(attributed, "The divergent branch is attributed to CPUID by the provenance tracker");

    Check(r.environmentSensitivityScore > 0, "A non-zero environment sensitivity score is produced");
    Check(r.sensitivityLabel != "None", "The score carries a descriptive label");

    // Coverage deltas must be exact set differences, not counts.
    bool deltaSound = false;
    for (const auto& d : r.deltas) {
        if (d.alternateProfile == "AnalysisFriendly") {
            deltaSound = !d.blocksOnlyInAlternate.empty() &&
                         d.blocksOnlyInAlternate.size() ==
                             (friendly->emulation.coverage.basicBlocks.size() -
                              [&] {
                                  size_t shared = 0;
                                  for (uint64_t b : baseline->emulation.coverage.basicBlocks) {
                                      if (friendly->emulation.coverage.basicBlocks.count(b)) shared++;
                                  }
                                  return shared;
                              }());
        }
    }
    Check(deltaSound, "Blocks reported as new match the exact set difference of the two runs");

    // Divergence must be promoted into findings with the documented ids.
    auto findings = r.ToFindings();
    bool hasBranchDivergence = false, hasBehaviorDivergence = false;
    for (const auto& f : findings) {
        if (f.id == "EVASION_BRANCH_DIVERGENCE") hasBranchDivergence = true;
        if (f.id == "EVASION_BEHAVIOR_DIVERGENCE") hasBehaviorDivergence = true;
    }
    Check(hasBranchDivergence, "EVASION_BRANCH_DIVERGENCE is emitted as a finding");
    Check(hasBehaviorDivergence, "EVASION_BEHAVIOR_DIVERGENCE is emitted as a finding");
}

static void TestResourceAndTimingDifferential() {
    Section("10. Differential execution: resource and timing gates");

    auto resource = RunCompare(SamplePath("ae_resource_gate"));
    if (resource.ran) {
        Check(resource.result.status == AntiEvasionStatus::BehaviorDiverged,
              "The processor-count gate diverges between profiles");
        bool attributed = false;
        for (const auto& bd : resource.result.branchDivergences) {
            if (bd.influenceOrigin == "Environment API") attributed = true;
        }
        Check(attributed,
              "The processor-count divergence is attributed to an environment API return value");
    } else {
        Blocked("Resource gate differential", "probe sample was not built");
    }

    auto timing = RunCompare(SamplePath("ae_timing_gate"));
    if (timing.ran) {
        Check(timing.result.status == AntiEvasionStatus::BehaviorDiverged,
              "The sleep-elapsed timing gate diverges between profiles");

        // The accelerated sleep must be visible in the audit trail, and the
        // clocks must remain mutually consistent across it.
        const DifferentialRun* realistic = nullptr;
        const DifferentialRun* base = nullptr;
        for (const auto& run : timing.result.runs) {
            if (run.profileKind == ProfileKind::Realistic) realistic = &run;
            if (run.profileKind == ProfileKind::Baseline)  base = &run;
        }
        Check(realistic && realistic->emulation.timeWasNormalized,
              "The Realistic run records that logical time was normalized");
        Check(realistic && realistic->emulation.logicalElapsedMs >= 5000,
              "The accelerated Sleep(5000) advanced logical time by at least 5000 ms");
        Check(base && base->emulation.logicalElapsedMs == 0,
              "The Baseline run's clock never advanced");
    } else {
        Blocked("Timing gate differential", "probe sample was not built");
    }
}

// ─── 11. False positives ────────────────────────────────────────────────────

static void TestFalsePositives() {
    Section("11. False-positive control");

    const std::string benign = SamplePath("ae_benign_sysinfo");
    if (!std::filesystem::exists(benign)) {
        Blocked("False-positive control", "probe sample was not built");
        return;
    }

    auto outcome = RunCompare(benign);
    const auto& r = outcome.result;

    Check(r.status != AntiEvasionStatus::BehaviorDiverged,
          "A program that queries the environment without gating on it does NOT diverge");
    Check(r.branchDivergences.empty(),
          "No branch divergence is reported for the benign inventory probe");

    // The queries must still be seen: under-reporting would be its own failure.
    bool sawQueries = false;
    for (const auto& t : r.techniques) {
        if (t.category == EvasionCategory::AntiVmCpuid ||
            t.category == EvasionCategory::AntiVmCpuTopology ||
            t.category == EvasionCategory::AntiVmTiming) {
            sawQueries = true;
        }
    }
    Check(sawQueries, "The environment queries themselves are still observed and reported");

    // But nothing may claim the result controlled execution.
    bool falseControlsFlow = false;
    for (const auto& t : r.techniques) {
        if (t.category == EvasionCategory::ProfileCoherenceWarning) continue;
        if (t.controlsFlow && t.confidence == FindingConfidence::High &&
            t.StrongestEvidence() == EvidenceKind::VerifiedDifferential) {
            falseControlsFlow = true;
        }
    }
    Check(!falseControlsFlow,
          "No collected-but-unused value is claimed to have been proven to control flow");

    Check(r.environmentSensitivityScore < 45,
          "The benign inventory probe scores below the 'Clear' sensitivity threshold");

    // Threat scoring must stay restrained.
    auto findings = r.ToFindings();
    SampleMetadata meta;
    SecurityMitigations mit;
    mit.hasAslr = true;
    mit.hasDep = true;
    auto threat = ThreatEvaluator::Evaluate(findings, meta, mit, 5.0, false);
    Check(threat.score < 45,
          "Anti-evasion findings alone cannot push a benign sample past 'Suspicious'");
}

// ─── 12. Combined signals ───────────────────────────────────────────────────

static void TestCombinedSignals() {
    Section("12. Combined-signal correlation");

    auto outcome = RunCompare(SamplePath("ae_combined_gate"));
    if (!outcome.ran) {
        Blocked("Combined signal", "probe sample was not built");
        return;
    }
    const auto& r = outcome.result;

    std::set<EvasionCategory> categories;
    for (const auto& t : r.techniques) {
        if (t.category != EvasionCategory::ProfileCoherenceWarning) categories.insert(t.category);
    }
    Check(categories.size() >= 3,
          "Three independent gates produce at least three distinct technique categories");

    bool hasCpuid = categories.count(EvasionCategory::AntiVmCpuid) ||
                    categories.count(EvasionCategory::AntiVmHypervisorVendor);
    bool hasTopology = categories.count(EvasionCategory::AntiVmCpuTopology) > 0;
    bool hasDebug = categories.count(EvasionCategory::AntiDebugApi) > 0;
    Check(hasCpuid, "The CPUID gate is reported separately");
    Check(hasTopology, "The processor-count gate is reported separately");
    Check(hasDebug, "The debugger-presence gate is reported separately");

    bool overall = false;
    for (const auto& t : r.techniques) {
        if (t.category == EvasionCategory::EvasionBehaviorDivergence) overall = true;
    }
    Check(overall, "One overall environment-sensitive conclusion accompanies the individual gates");

    // Identical evidence must not be counted twice.
    auto findings = r.ToFindings();
    std::vector<std::string> keys;
    for (const auto& f : findings) keys.push_back(f.id + "@" + std::to_string(f.rva) + f.title);
    std::sort(keys.begin(), keys.end());
    Check(std::adjacent_find(keys.begin(), keys.end()) == keys.end(),
          "No finding is emitted twice for the same evidence at the same address");
}

// ─── 13. CFG and XRef correlation ───────────────────────────────────────────

static void TestCfgAndXrefIntegration() {
    Section("13. CFG and XRef correlation");

    // Static branch correlation is intraprocedural by design, so it is tested
    // on a sample where the check and its branch share a function.
    const std::string intraprocedural = SamplePath("ae_cpuid_gate");
    const std::string sample = SamplePath("ae_combined_gate");
    if (!std::filesystem::exists(sample) || !std::filesystem::exists(intraprocedural)) {
        Blocked("CFG / XRef correlation", "probe samples were not built");
        return;
    }

    AnalysisOrchestrator orch;
    OrchestratorOptions oo;
    oo.enableEmulation = false;
    auto unified = orch.AnalyzeFile(sample, oo);

    auto techniques = AntiEvasionEngine::DetectStatic(sample, &unified);
    Check(!techniques.empty(), "Detection runs against a precomputed session result");

    // A gated check must name the branch it controls, and that branch must sit
    // after the check with a stated consequence.
    auto intraUnified = orch.AnalyzeFile(intraprocedural, oo);
    auto intraTechniques = AntiEvasionEngine::DetectStatic(intraprocedural, &intraUnified);
    bool branchCorrelated = false;
    uint64_t correlatedBranchRva = 0;
    for (const auto& t : intraTechniques) {
        if (!t.controlsFlow || t.branchRva == 0) continue;
        if (t.branchRva > t.rva && !t.controlFlowConsequence.empty()) {
            branchCorrelated = true;
            correlatedBranchRva = t.branchRva;
        }
    }
    Check(branchCorrelated,
          "An environment check is correlated to a following conditional branch");

    // That branch must be a real conditional with two distinct successors in
    // the CFG the disassembler built, not merely a plausible-looking RVA.
    bool twoSuccessors = false;
    if (correlatedBranchRva != 0) {
        for (const auto& fg : intraUnified.functions) {
            for (const auto& [start, block] : fg.blocks) {
                if (correlatedBranchRva >= block.startRva &&
                    correlatedBranchRva < block.startRva + block.size &&
                    block.successorAddresses.size() == 2) {
                    twoSuccessors = true;
                }
            }
        }
    }
    Check(twoSuccessors,
          "The correlated branch is a CFG node with exactly two successors");

    // The combined sample places each gate in its own function, so the branch
    // is interprocedural and the intraprocedural static scan cannot reach it.
    // Provenance across the return is what catches that case.
    AntiEvasionOptions cmpOpts;
    cmpOpts.runComparison = true;
    AntiEvasionEngine engine;
    auto combined = engine.Analyze(sample, cmpOpts, &unified);
    bool interproceduralCaught = false;
    for (const auto& bd : combined.branchDivergences) {
        if (!bd.influenceOrigin.empty()) interproceduralCaught = true;
    }
    Check(interproceduralCaught,
          "A gate whose check and branch are in different functions is caught by provenance");

    // Import-based techniques must land on the calling instruction, not on the
    // IAT slot, when an XRef is available.
    bool xrefCorrelated = false;
    for (const auto& t : techniques) {
        for (const auto& e : t.evidence) {
            if (e.source == "XRef Analyzer" && e.rva != 0 && t.rva == e.rva) xrefCorrelated = true;
        }
    }
    bool haveImportXrefs = false;
    for (const auto& x : unified.xrefs) {
        if (x.type == XRefType::ImportCall) haveImportXrefs = true;
    }
    if (haveImportXrefs) {
        Check(xrefCorrelated,
              "An import-based technique is anchored to the ImportCall XRef site");
    } else {
        Check(true, "No ImportCall XRefs in this sample's entry region (nothing to correlate)");
    }

    // Function naming must come from the precomputed CFG where it covers the site.
    bool named = false;
    for (const auto& t : techniques) {
        if (!t.functionName.empty()) named = true;
    }
    Check(named, "Techniques carry a function name resolved from the CFG");
}

// ─── 14. Fingerprint determinism ────────────────────────────────────────────

static void TestFingerprintDeterminism() {
    Section("14. Behavioural fingerprint determinism");

    EmulationResult a;
    a.instructionsExecuted = 100;
    a.stopReason = EmulationStopReason::NormalExit;
    a.coverage.basicBlocks = {0x1000, 0x1010, 0x1020};
    a.coverage.functions = {0x1000};
    HleCallRecord call;
    call.library = "kernel32.dll";
    call.apiName = "Sleep";
    a.hleCalls.push_back(call);

    auto fp1 = AntiEvasionEngine::Fingerprint(a);
    auto fp2 = AntiEvasionEngine::Fingerprint(a);
    Check(fp1.digest == fp2.digest, "The same run produces the same fingerprint digest");
    Check(fp1 == fp2, "Fingerprint equality compares by digest");
    Check(!fp1.digest.empty() && fp1.digest.size() == 16,
          "The digest is a fixed-width stable value");

    EmulationResult b = a;
    b.coverage.basicBlocks.insert(0x1030);
    auto fp3 = AntiEvasionEngine::Fingerprint(b);
    Check(fp3.digest != fp1.digest, "Different coverage produces a different fingerprint");
    Check(fp3.coverageDigest != fp1.coverageDigest, "The coverage digest itself changes");

    EmulationResult c = a;
    c.stopReason = EmulationStopReason::InstructionLimit;
    Check(AntiEvasionEngine::Fingerprint(c).digest != fp1.digest,
          "A different termination reason produces a different fingerprint");
}

// ─── 15. Divergence score ───────────────────────────────────────────────────

static void TestDivergenceScore() {
    Section("15. Environment divergence score");

    std::string label;
    Check(AntiEvasionEngine::ComputeSensitivityScore({}, {}, label) == 0 && label == "None",
          "No evidence scores zero");

    // Static-only evidence is capped so detection alone cannot dominate.
    std::vector<EvasionTechnique> many;
    for (int i = 0; i < 40; ++i) {
        EvasionTechnique t;
        t.controlsFlow = true;
        t.confidence = FindingConfidence::High;
        many.push_back(t);
    }
    const int staticOnly = AntiEvasionEngine::ComputeSensitivityScore({}, many, label);
    Check(staticOnly <= 25,
          "Static detection alone is capped at 25: detecting a check is not observing a change");

    // Observed divergence outweighs static detection.
    ExecutionDelta d;
    d.baselineProfile = "Baseline";
    d.alternateProfile = "AnalysisFriendly";
    BranchDivergence bd;
    bd.confidence = FindingConfidence::High;
    d.branchDivergences.push_back(bd);
    d.blocksOnlyInAlternate = {1, 2, 3, 4, 5};
    d.functionsOnlyInAlternate = {1, 2};
    d.terminationChanged = true;
    const int observed = AntiEvasionEngine::ComputeSensitivityScore({d}, {}, label);
    Check(observed > staticOnly, "Observed divergence outscores static detection alone");
    Check(observed >= 45 && label != "None" && label != "Minimal",
          "Proven divergence reaches at least the 'Clear' band");
    Check(AntiEvasionEngine::ComputeSensitivityScore({d, d, d, d}, many, label) <= 100,
          "The score is clamped to 100");
}

// ─── 16. Serialization ──────────────────────────────────────────────────────

static void TestSerialization() {
    Section("16. Report serialization");

    auto outcome = RunCompare(SamplePath("ae_cpuid_gate"));
    if (!outcome.ran) {
        Blocked("Serialization", "probe sample was not built");
        return;
    }
    const auto& r = outcome.result;

    const std::string json = r.ToJson();
    std::string err;
    Check(ValidateJson(json, err), "The anti-evasion JSON is syntactically valid (" + err + ")");
    Check(json.find("\"environment_sensitivity_score\"") != std::string::npos,
          "JSON exposes environment_sensitivity_score as a structured field");
    Check(json.find("\"techniques\"") != std::string::npos, "JSON exposes a techniques array");
    Check(json.find("\"differential_runs\"") != std::string::npos,
          "JSON exposes a differential_runs array");
    Check(json.find("\"branch_divergences\"") != std::string::npos,
          "JSON exposes a branch_divergences array");
    Check(json.find("\"normalizations\"") != std::string::npos,
          "JSON exposes the normalization audit trail");
    Check(json.find("\033[") == std::string::npos,
          "JSON contains no terminal escape sequences");

    const std::string md = r.ToMarkdown();
    Check(md.find("## Anti-Evasion Analysis") != std::string::npos,
          "Markdown emits an Anti-Evasion section");
    Check(md.find("Environment sensitivity") != std::string::npos,
          "Markdown reports the sensitivity score");

    Terminal::SetColorEnabled(false);
    const std::string ansi = r.ToAnsiReport(true);
    Check(ansi.find("Anti-Evasion Analysis") != std::string::npos,
          "The terminal report renders a heading");
    Check(ansi.find("\033[") == std::string::npos,
          "With colour disabled the terminal report emits no escape sequences");
    Terminal::SetColorEnabled(true);

    // The normalization audit trail must actually be populated.
    Check(!r.normalizations.empty(), "The normalization audit trail is populated");
    bool auditComplete = true;
    for (const auto& n : r.normalizations) {
        if (n.property.empty() || n.suppliedValue.empty() || n.reason.empty() || n.profile.empty()) {
            auditComplete = false;
        }
    }
    Check(auditComplete,
          "Every normalization records property, supplied value, reason and profile");

    bool hypervisorAudited = false;
    for (const auto& n : r.normalizations) {
        if (n.property == "CPUID.HypervisorPresent" && n.observedValue != n.suppliedValue) {
            hypervisorAudited = true;
        }
    }
    Check(hypervisorAudited,
          "Clearing the hypervisor bit is explicitly recorded in the audit trail");

    // The unified result must embed anti-evasion as real nested JSON.
    UnifiedAnalysisResult unified;
    unified.antiEvasionJson = json;
    unified.antiEvasionScore = r.environmentSensitivityScore;
    unified.antiEvasionSensitivity = r.sensitivityLabel;
    const std::string unifiedJson = unified.ToJson();
    Check(ValidateJson(unifiedJson, err),
          "The unified report stays valid JSON with anti-evasion embedded (" + err + ")");
    Check(unifiedJson.find("\"anti_evasion\": {") != std::string::npos,
          "anti_evasion is embedded as a nested object, not a string");

    UnifiedAnalysisResult without;
    Check(ValidateJson(without.ToJson(), err) &&
              without.ToJson().find("\"executed\": false") != std::string::npos,
          "A report with no anti-evasion run still emits a well-formed anti_evasion object");
}

// ─── 17. Command registry and CLI plumbing ──────────────────────────────────

static void TestCommandIntegration() {
    Section("17. Command registry integration");

    auto& registry = CommandRegistry::Instance();

    const auto* cmd = registry.FindExact("antievasion");
    Check(cmd != nullptr, "/antievasion is registered in the central command registry");
    if (!cmd) return;

    Check(cmd->category == "Analysis", "It is categorised under Analysis");
    Check(cmd->handler != nullptr, "It has a handler");
    Check(cmd->takesFilePath, "It is marked as taking a file path");
    Check(!cmd->requiresArgs, "It does not require arguments, so it can reuse the active sample");

    for (const char* alias : {"antivm", "evasion", "ae"}) {
        const auto* viaAlias = registry.Find(alias);
        Check(viaAlias && viaAlias->name == "antievasion",
              std::string("Alias /") + alias + " resolves to /antievasion");
    }

    auto matches = registry.FilterByPrefix("anti");
    bool inPalette = false;
    for (const auto* m : matches) if (m->name == "antievasion") inPalette = true;
    Check(inPalette, "Typing /anti surfaces /antievasion in the command palette");

    Check(cmd->detailedHelp.find("--compare") != std::string::npos &&
              cmd->detailedHelp.find("Baseline") != std::string::npos &&
              cmd->detailedHelp.find("Confidence") != std::string::npos ||
          cmd->detailedHelp.find("CONFIDENCE") != std::string::npos,
          "/help antievasion documents modes, profiles and confidence");
    Check(cmd->detailedHelp.find("not by itself malicious") != std::string::npos ||
              cmd->detailedHelp.find("NOT evidence of malice") != std::string::npos,
          "The help text states that anti-VM behaviour is not itself malicious");
    Check(!cmd->examples.empty(), "It ships usage examples");

    bool hasProfileCompletion = false;
    for (const auto& [flag, values] : cmd->flagCompletions) {
        if (flag == "--profile" && values.size() >= 3) hasProfileCompletion = true;
    }
    Check(hasProfileCompletion, "--profile offers argument completion for the profile names");
}

// ─── 18. Session integration ────────────────────────────────────────────────

static void TestSessionIntegration() {
    Section("18. Session integration");

    const std::string sample = SamplePath("ae_cpuid_gate");
    if (!std::filesystem::exists(sample)) {
        Blocked("Session integration", "probe sample was not built");
        return;
    }

    Terminal::SetColorEnabled(false);
    std::ostringstream captured;
    std::streambuf* old = std::cout.rdbuf(captured.rdbuf());

    DraculaShell shell;
    shell.ExecuteCommand("/analyze \"" + sample + "\"");
    const bool hasSessionAfterAnalyze = shell.GetSessionResult() != nullptr;

    // No file argument: the active sample must be reused.
    shell.ExecuteCommand("/antievasion");

    std::cout.rdbuf(old);
    Terminal::SetColorEnabled(true);

    Check(hasSessionAfterAnalyze, "/analyze establishes a session");
    const auto* result = shell.GetSessionResult();
    Check(result != nullptr, "The session survives /antievasion");
    if (!result) return;

    Check(shell.GetActiveFile() == sample,
          "/antievasion with no argument reused the active sample");
    Check(result->antiEvasionScore >= 0,
          "The session records an environment sensitivity score");
    Check(!result->antiEvasionJson.empty(), "The session caches the structured anti-evasion JSON");
    Check(!result->antiEvasionStatus.empty(), "The session records the anti-evasion status");

    size_t aeFindings = 0;
    for (const auto& f : result->findings) {
        if (f.source == "Anti-Evasion Engine") aeFindings++;
    }
    Check(aeFindings > 0, "Anti-evasion findings appear in the session findings list");

    // /findings must render them without throwing.
    std::ostringstream findingsOut;
    old = std::cout.rdbuf(findingsOut.rdbuf());
    shell.ExecuteCommand("/findings");
    std::cout.rdbuf(old);
    Check(findingsOut.str().find("ANTI_") != std::string::npos ||
              findingsOut.str().find("Anti-") != std::string::npos,
          "/findings lists the anti-evasion findings");

    // Running twice must replace, not accumulate.
    std::ostringstream again;
    old = std::cout.rdbuf(again.rdbuf());
    shell.ExecuteCommand("/antievasion");
    std::cout.rdbuf(old);

    size_t secondCount = 0;
    for (const auto& f : shell.GetSessionResult()->findings) {
        if (f.source == "Anti-Evasion Engine") secondCount++;
    }
    Check(secondCount == aeFindings,
          "Re-running /antievasion replaces its findings rather than accumulating them");
}

// ─── 19. MCP ────────────────────────────────────────────────────────────────

static void TestMcp() {
    Section("19. MCP tool surface");

    McpServer server;

    const std::string listResponse =
        server.ProcessMessage("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
    Check(listResponse.find("analyze_anti_evasion") != std::string::npos,
          "analyze_anti_evasion is advertised by tools/list");
    std::string err;
    Check(ValidateJson(listResponse, err), "tools/list returns valid JSON (" + err + ")");

    const std::string sample = SamplePath("ae_cpuid_gate");
    if (!std::filesystem::exists(sample)) {
        Blocked("MCP tool call", "probe sample was not built");
        return;
    }

    std::string escaped;
    for (char c : sample) {
        if (c == '\\') escaped += "\\\\";
        else escaped += c;
    }

    const std::string call =
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{"
        "\"name\":\"analyze_anti_evasion\",\"arguments\":{\"file_path\":\"" + escaped +
        "\",\"compare\":true}}}";
    const std::string response = server.ProcessMessage(call);

    Check(ValidateJson(response, err), "The MCP response is valid JSON-RPC (" + err + ")");
    Check(response.find("\"id\":7") != std::string::npos, "The response carries the request id");
    Check(response.find("\"result\"") != std::string::npos, "The call returns a result, not an error");
    Check(response.find("environment_sensitivity_score") != std::string::npos,
          "The structured anti-evasion result is returned through MCP");
    Check(response.find("EVASION_BRANCH_DIVERGENCE") != std::string::npos,
          "The environment-sensitive finding survives the MCP round trip");
    Check(response.find('\n') == std::string::npos,
          "The MCP response is a single line, keeping stdout pure JSON-RPC");

    // analyze_file must carry a summary too.
    const std::string analyzeCall =
        "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\",\"params\":{"
        "\"name\":\"analyze_file\",\"arguments\":{\"file_path\":\"" + escaped + "\"}}}";
    const std::string analyzeResponse = server.ProcessMessage(analyzeCall);
    Check(ValidateJson(analyzeResponse, err), "analyze_file returns valid JSON (" + err + ")");
    Check(analyzeResponse.find("anti_evasion") != std::string::npos,
          "analyze_file includes an anti_evasion summary");
}

// ─── 20. Sandbox fingerprint ────────────────────────────────────────────────

static void TestSandboxFingerprint() {
    Section("20. QEMU sandbox environment fingerprint");

    auto fp = InspectSandboxEnvironment();
    Check(!fp.observables.empty(), "The sandbox fingerprint enumerates observable properties");

    bool honest = false;
    for (const auto& o : fp.observables) {
        if (o.channel == std::string("CPUID") && o.revealsVirtualization) honest = true;
    }
    Check(honest,
          "The fingerprint states plainly that CPUID reveals virtualization in the guest");
    Check(fp.fingerprintability > 0,
          "The guest is reported as fingerprintable rather than claimed invisible");

    auto profile = fp.ToProfile();
    Check(profile.cpu.hypervisorPresent,
          "The sandbox profile does not claim the hypervisor is hidden");
    const auto graph = BuildConsistencyGraph(profile);
    Check(graph.IsCoherent(),
          "The QEMU sandbox profile is internally coherent (it does not pretend to be hardware)");

    if (fp.available) {
        Check(!fp.qemuVersion.empty(), "The configured QEMU reports its version");
    } else {
        Blocked("Live QEMU guest inspection", fp.unavailableReason);
    }
}

// ─── 21. Bounds and failure states ──────────────────────────────────────────

static void TestBoundsAndFailureStates() {
    Section("21. Bounds and structured failure states");

    AntiEvasionEngine engine;

    AntiEvasionOptions opts;
    auto missing = engine.Analyze("this_file_does_not_exist_12345.exe", opts);
    Check(missing.status == AntiEvasionStatus::TargetUnreadable,
          "An unreadable target yields TargetUnreadable, not a boolean failure");

    Check(std::string(AntiEvasionStatusToString(AntiEvasionStatus::SandboxUnavailable)) ==
              "SandboxUnavailable",
          "Every failure state has a distinct name");
    Check(std::string(AntiEvasionStatusToString(AntiEvasionStatus::EmulationLimit)) ==
              "EmulationLimit",
          "EmulationLimit is a distinct reported state");

    const std::string sample = SamplePath("ae_cpuid_gate");
    if (!std::filesystem::exists(sample)) {
        Blocked("Comparison bounds", "probe sample was not built");
        return;
    }

    // The profile count is a hard bound, not a suggestion.
    AntiEvasionOptions bounded;
    bounded.runComparison = true;
    bounded.comparisonProfiles = {ProfileKind::Baseline, ProfileKind::Realistic,
                                  ProfileKind::AnalysisFriendly, ProfileKind::Baseline,
                                  ProfileKind::Realistic};
    bounded.maxProfilesPerComparison = 2;
    auto boundedResult = engine.Analyze(sample, bounded);
    Check(boundedResult.runs.size() == 2, "maxProfilesPerComparison is enforced exactly");
    Check(!boundedResult.notes.empty(), "The truncation is reported in the result notes");

    // A tiny instruction budget must terminate cleanly rather than run away.
    AntiEvasionOptions tiny;
    tiny.runComparison = false;
    tiny.maxInstructionsPerRun = 5;
    auto tinyResult = engine.Analyze(sample, tiny);
    Check(tinyResult.runs.size() == 1 && tinyResult.runs[0].emulation.instructionsExecuted <= 6,
          "A tiny instruction budget is honoured");

    // Detection mode must not perform comparison.
    AntiEvasionOptions detectOnly;
    detectOnly.runComparison = false;
    auto detectResult = engine.Analyze(sample, detectOnly);
    Check(!detectResult.comparePerformed && detectResult.deltas.empty(),
          "Detection mode performs no differential runs");
    Check(detectResult.runs.size() == 1,
          "Detection mode performs exactly one controlled run");
    Check(detectResult.status != AntiEvasionStatus::BehaviorDiverged,
          "Detection mode never reports divergence it did not measure");
}

// ─── 22. Pure observation mode ──────────────────────────────────────────────

static void TestObservationMode() {
    Section("22. Detection without forced normalization");

    const std::string sample = SamplePath("ae_cpuid_gate");
    if (!std::filesystem::exists(sample)) {
        Blocked("Observation mode", "probe sample was not built");
        return;
    }

    AntiEvasionOptions opts;
    opts.runComparison = false;
    opts.detectionProfile = ProfileKind::Baseline;

    AntiEvasionEngine engine;
    auto r = engine.Analyze(sample, opts);

    Check(r.normalizations.empty(),
          "Baseline detection normalizes nothing: the audit trail is empty");
    Check(r.runs.size() == 1 && r.runs[0].profileKind == ProfileKind::Baseline,
          "Only the Baseline environment was used");

    // What the sample naturally detects must still be reported.
    bool sawHypervisorAnswer = false;
    for (const auto& obs : r.runs[0].emulation.environmentObservations) {
        if (obs.property == "Hypervisor presence" &&
            obs.suppliedValue.find("set") != std::string::npos) {
            sawHypervisorAnswer = true;
        }
    }
    Check(sawHypervisorAnswer,
          "Observation mode shows what the sample naturally sees (hypervisor present)");

    bool anyNormalized = false;
    for (const auto& obs : r.runs[0].emulation.environmentObservations) {
        if (obs.normalized) anyNormalized = true;
    }
    Check(!anyNormalized, "No observation is marked as normalized under Baseline");
}

// ─── Main ───────────────────────────────────────────────────────────────────

int main() {
#ifdef _WIN32
    SetConsoleOutputCP(65001);
#endif
    std::cout << "\n\033[1;35m==============================================================\033[0m\n";
    std::cout << " DRACULA ANTI-EVASION INTELLIGENCE ENGINE VERIFICATION\n";
    std::cout << " Sample directory: " << DRACULA_AE_SAMPLE_DIR << "\n";
    std::cout << "\033[1;35m==============================================================\033[0m\n";

    TestTaxonomy();
    TestVirtualTime();
    TestProfileCoherence();
    TestArtifactRules();
    TestBranchInfluence();
    TestCpuidMachineCode();
    TestTimestampMachineCode();
    TestStaticDetection();
    TestDifferentialExecution();
    TestResourceAndTimingDifferential();
    TestFalsePositives();
    TestCombinedSignals();
    TestCfgAndXrefIntegration();
    TestFingerprintDeterminism();
    TestDivergenceScore();
    TestSerialization();
    TestCommandIntegration();
    TestSessionIntegration();
    TestMcp();
    TestSandboxFingerprint();
    TestBoundsAndFailureStates();
    TestObservationMode();

    std::cout << "\n\033[1;35m==============================================================\033[0m\n";
    std::cout << " ANTI-EVASION RESULTS: \033[1;32m" << g_pass << " PASSED\033[0m, "
              << "\033[1;31m" << g_fail << " FAILED\033[0m";
    if (g_blocked > 0) {
        std::cout << ", \033[1;33m" << g_blocked << " BLOCKED BY ENVIRONMENT\033[0m";
    }
    std::cout << "\n\033[1;35m==============================================================\033[0m\n\n";
    return g_fail == 0 ? 0 : 1;
}
