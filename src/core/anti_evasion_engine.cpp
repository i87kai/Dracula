#include "core/anti_evasion_engine.h"
#include "core/evasion_artifact_rules.h"
#include "core/pe_inspector.h"
#include "core/disassembler.h"
#include "core/cfg_analyzer.h"
#include "core/xref_analyzer.h"
#include "core/strings_analyzer.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <set>
#include <map>

namespace Dracula {

    // ─── Taxonomy ───────────────────────────────────────────────────────────

    namespace {
        struct CategoryInfo { const char* id; const char* label; };

        const CategoryInfo& Info(EvasionCategory c) {
            static const std::map<EvasionCategory, CategoryInfo> table = {
                {EvasionCategory::AntiVmCpuid,            {"ANTI_VM_CPUID", "Anti-VM CPUID"}},
                {EvasionCategory::AntiVmHypervisorVendor, {"ANTI_VM_HYPERVISOR_VENDOR", "Anti-VM hypervisor vendor"}},
                {EvasionCategory::AntiVmCpuTopology,      {"ANTI_VM_CPU_TOPOLOGY", "Anti-VM CPU topology"}},
                {EvasionCategory::AntiVmSmbios,           {"ANTI_VM_SMBIOS", "Anti-VM SMBIOS / firmware"}},
                {EvasionCategory::AntiVmAcpi,             {"ANTI_VM_ACPI", "Anti-VM ACPI"}},
                {EvasionCategory::AntiVmDevice,           {"ANTI_VM_DEVICE", "Anti-VM device"}},
                {EvasionCategory::AntiVmDriver,           {"ANTI_VM_DRIVER", "Anti-VM driver"}},
                {EvasionCategory::AntiVmService,          {"ANTI_VM_SERVICE", "Anti-VM service"}},
                {EvasionCategory::AntiVmProcess,          {"ANTI_VM_PROCESS", "Anti-VM process"}},
                {EvasionCategory::AntiVmRegistry,         {"ANTI_VM_REGISTRY", "Anti-VM registry"}},
                {EvasionCategory::AntiVmMacOui,           {"ANTI_VM_MAC_OUI", "Anti-VM MAC prefix"}},
                {EvasionCategory::AntiVmDisk,             {"ANTI_VM_DISK", "Anti-VM disk"}},
                {EvasionCategory::AntiVmMemory,           {"ANTI_VM_MEMORY", "Anti-VM memory size"}},
                {EvasionCategory::AntiVmTiming,           {"ANTI_VM_TIMING", "Anti-VM timing"}},
                {EvasionCategory::AntiVmUptime,           {"ANTI_VM_UPTIME", "Anti-VM uptime"}},
                {EvasionCategory::AntiVmScreen,           {"ANTI_VM_SCREEN", "Anti-VM screen"}},
                {EvasionCategory::AntiVmInputActivity,    {"ANTI_VM_INPUT_ACTIVITY", "Anti-VM input activity"}},
                {EvasionCategory::AntiVmDescriptorTable,  {"ANTI_VM_DESCRIPTOR_TABLE", "Anti-VM descriptor table"}},
                {EvasionCategory::AntiDebugPeb,           {"ANTI_DEBUG_PEB", "Anti-debug PEB"}},
                {EvasionCategory::AntiDebugApi,           {"ANTI_DEBUG_API", "Anti-debug API"}},
                {EvasionCategory::AntiDebugTiming,        {"ANTI_DEBUG_TIMING", "Anti-debug timing"}},
                {EvasionCategory::AntiDebugException,     {"ANTI_DEBUG_EXCEPTION", "Anti-debug exception"}},
                {EvasionCategory::AntiDebugHardwareBreakpoint, {"ANTI_DEBUG_HARDWARE_BREAKPOINT", "Anti-debug hardware breakpoint"}},
                {EvasionCategory::AntiDebugProcessCheck,  {"ANTI_DEBUG_PROCESS_CHECK", "Anti-debug process check"}},
                {EvasionCategory::AntiSandboxSleep,       {"ANTI_SANDBOX_SLEEP", "Anti-sandbox sleep"}},
                {EvasionCategory::AntiSandboxResourceCheck,{"ANTI_SANDBOX_RESOURCE_CHECK", "Anti-sandbox resource check"}},
                {EvasionCategory::AntiSandboxUserActivity,{"ANTI_SANDBOX_USER_ACTIVITY", "Anti-sandbox user activity"}},
                {EvasionCategory::AntiSandboxFileArtifact,{"ANTI_SANDBOX_FILE_ARTIFACT", "Anti-sandbox file artifact"}},
                {EvasionCategory::AntiSandboxEnvironment, {"ANTI_SANDBOX_ENVIRONMENT", "Anti-sandbox environment"}},
                {EvasionCategory::AntiEmulationUnsupportedBehavior, {"ANTI_EMULATION_UNSUPPORTED_BEHAVIOR", "Anti-emulation behaviour"}},
                {EvasionCategory::AntiInstrumentationCheck,{"ANTI_INSTRUMENTATION_CHECK", "Anti-instrumentation check"}},
                {EvasionCategory::EvasionBehaviorDivergence,{"EVASION_BEHAVIOR_DIVERGENCE", "Behaviour divergence"}},
                {EvasionCategory::EvasionBranchDivergence, {"EVASION_BRANCH_DIVERGENCE", "Branch divergence"}},
                {EvasionCategory::EvasionEnvironmentSensitive,{"EVASION_ENVIRONMENT_SENSITIVE", "Environment sensitive"}},
                {EvasionCategory::ProfileCoherenceWarning,{"PROFILE_COHERENCE_WARNING", "Profile coherence warning"}},
            };
            static const CategoryInfo unknown{"UNKNOWN", "Unknown"};
            auto it = table.find(c);
            return it != table.end() ? it->second : unknown;
        }
    } // namespace

    const char* EvasionCategoryId(EvasionCategory c)    { return Info(c).id; }
    const char* EvasionCategoryLabel(EvasionCategory c) { return Info(c).label; }

    bool ParseEvasionCategory(const std::string& id, EvasionCategory& out) {
        for (int i = 0; i <= static_cast<int>(EvasionCategory::ProfileCoherenceWarning); ++i) {
            const auto c = static_cast<EvasionCategory>(i);
            if (id == EvasionCategoryId(c)) { out = c; return true; }
        }
        return false;
    }

    const char* EvidenceKindToString(EvidenceKind kind) {
        switch (kind) {
            case EvidenceKind::DetectedStatically:   return "Detected statically";
            case EvidenceKind::ModelledInUnicorn:    return "Modelled in Unicorn";
            case EvidenceKind::ObservedInQemu:       return "Observed in QEMU";
            case EvidenceKind::VerifiedDifferential: return "Verified differentially";
            case EvidenceKind::Unsupported:          return "Unsupported";
        }
        return "Unknown";
    }

    const char* AntiEvasionStatusToString(AntiEvasionStatus s) {
        switch (s) {
            case AntiEvasionStatus::Completed:              return "Completed";
            case AntiEvasionStatus::NoEvasionDetected:      return "NoEvasionDetected";
            case AntiEvasionStatus::BehaviorDiverged:       return "BehaviorDiverged";
            case AntiEvasionStatus::EnvironmentUnsupported: return "EnvironmentUnsupported";
            case AntiEvasionStatus::ProfileInvalid:         return "ProfileInvalid";
            case AntiEvasionStatus::EmulationLimit:         return "EmulationLimit";
            case AntiEvasionStatus::UnsupportedInstruction: return "UnsupportedInstruction";
            case AntiEvasionStatus::SandboxUnavailable:     return "SandboxUnavailable";
            case AntiEvasionStatus::SandboxTimeout:         return "SandboxTimeout";
            case AntiEvasionStatus::TargetUnreadable:       return "TargetUnreadable";
        }
        return "Unknown";
    }

    EvidenceKind EvasionTechnique::StrongestEvidence() const {
        EvidenceKind best = EvidenceKind::Unsupported;
        auto rank = [](EvidenceKind k) {
            switch (k) {
                case EvidenceKind::Unsupported:          return 0;
                case EvidenceKind::DetectedStatically:   return 1;
                case EvidenceKind::ModelledInUnicorn:    return 2;
                case EvidenceKind::ObservedInQemu:       return 3;
                case EvidenceKind::VerifiedDifferential: return 4;
            }
            return 0;
        };
        for (const auto& e : evidence) {
            if (rank(e.kind) > rank(best)) best = e.kind;
        }
        return evidence.empty() ? EvidenceKind::DetectedStatically : best;
    }

    Finding EvasionTechnique::ToFinding() const {
        Finding f;
        f.id = id;
        f.category = "AntiAnalysis / Evasion";
        f.severity = severity;
        f.confidence = confidence;
        f.rva = rva;
        f.virtualAddress = virtualAddress;
        f.title = title;
        f.description = description;
        f.source = "Anti-Evasion Engine";

        std::ostringstream ev;
        if (!environmentProperty.empty()) ev << environmentProperty << ": ";
        bool first = true;
        for (const auto& e : evidence) {
            if (!first) ev << "; ";
            ev << e.detail;
            first = false;
        }
        if (controlsFlow) {
            std::ostringstream br;
            br << " (controls the branch at RVA 0x" << std::hex << branchRva << ")";
            ev << br.str();
        }
        f.evidence = ev.str();

        f.tags = tags;
        f.tags.push_back("AntiEvasion");
        f.tags.push_back(std::string(EvasionCategoryId(category)));
        return f;
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    namespace {

        std::string Hex(uint64_t v) {
            std::ostringstream ss;
            ss << "0x" << std::hex << std::uppercase << v;
            return ss.str();
        }

        std::string Lower(std::string s) {
            std::transform(s.begin(), s.end(), s.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return s;
        }

        // FNV-1a, so a fingerprint digest is stable across runs and machines.
        std::string Digest(const std::string& s) {
            uint64_t h = 1469598103934665603ULL;
            for (unsigned char c : s) {
                h ^= c;
                h *= 1099511628211ULL;
            }
            std::ostringstream ss;
            ss << std::hex << std::setw(16) << std::setfill('0') << h;
            return ss.str();
        }

        bool IsCompare(const std::string& mnemonic) {
            return mnemonic == "cmp" || mnemonic == "test" || mnemonic == "sub" ||
                   mnemonic == "and" || mnemonic == "or"  || mnemonic == "xor" ||
                   mnemonic == "bt"  || mnemonic == "shr" || mnemonic == "sar";
        }

        std::string FunctionNameFor(uint64_t rva, const std::vector<FunctionGraph>& functions) {
            for (const auto& fg : functions) {
                if (fg.entryRva == rva) return fg.name;
                for (const auto& [start, block] : fg.blocks) {
                    if (rva >= block.startRva && rva < block.startRva + block.size) {
                        return fg.name;
                    }
                }
            }
            std::ostringstream ss;
            ss << "sub_" << std::hex << rva;
            return ss.str();
        }

        uint64_t BlockStartFor(uint64_t rva, const std::vector<FunctionGraph>& functions) {
            for (const auto& fg : functions) {
                for (const auto& [start, block] : fg.blocks) {
                    if (rva >= block.startRva && rva < block.startRva + block.size) {
                        return block.startRva;
                    }
                }
            }
            return 0;
        }

    } // namespace

    // ─── Static detection ───────────────────────────────────────────────────

    std::vector<EvasionTechnique> AntiEvasionEngine::DetectStatic(
        const std::string& filePath, const UnifiedAnalysisResult* precomputed) {

        std::vector<EvasionTechnique> out;

        PeInspector inspector;
        std::string err;
        if (!inspector.LoadFromFile(filePath, err)) return out;

        const auto& meta = inspector.GetMetadata();
        const Architecture arch = meta.is64Bit ? Architecture::X86_64 : Architecture::X86_32;
        const std::vector<FunctionGraph> emptyFunctions;
        const auto& functions = precomputed ? precomputed->functions : emptyFunctions;

        // ── 1. Instruction-level environment probes ─────────────────────────
        //
        // A linear sweep of every executable section, not just the entry point:
        // an environment gate placed in a helper function must still be found.

        Disassembler disasm(arch);
        for (const auto& section : inspector.GetSections()) {
            if (!section.isExecutable) continue;
            const uint64_t offset = inspector.RvaToFileOffset(section.virtualAddress);
            if (offset >= inspector.GetBufferSize()) continue;

            size_t size = std::min<size_t>(section.rawSize, inspector.GetBufferSize() - offset);
            size = std::min<size_t>(size, 2 * 1024 * 1024);   // bounded sweep
            if (size == 0) continue;

            const uint64_t sectionVa = meta.imageBase + section.virtualAddress;
            auto instructions = disasm.Disassemble(inspector.GetBuffer() + offset, size,
                                                   sectionVa, section.virtualAddress);

            for (size_t i = 0; i < instructions.size(); ++i) {
                const auto& insn = instructions[i];
                const std::string m = Lower(insn.mnemonic);

                EvasionCategory category;
                std::string property;
                std::string what;

                if (m == "cpuid") {
                    category = EvasionCategory::AntiVmCpuid;
                    property = "CPU identification";
                    what = "CPUID";
                } else if (m == "rdtsc" || m == "rdtscp") {
                    category = EvasionCategory::AntiVmTiming;
                    property = "Timestamp counter";
                    what = Lower(insn.mnemonic);
                } else if (m == "sidt" || m == "sgdt" || m == "sldt" || m == "str" || m == "smsw") {
                    category = EvasionCategory::AntiVmDescriptorTable;
                    property = "Descriptor table / machine status register";
                    what = m;
                } else if (m == "in" && insn.operands.find("dx") != std::string::npos) {
                    // The VMware backdoor port. Reading port 0x5658 has no
                    // legitimate use in user-mode code.
                    category = EvasionCategory::AntiVmDevice;
                    property = "I/O port (hypervisor backdoor)";
                    what = "in";
                } else {
                    continue;
                }

                EvasionTechnique t;
                t.category = category;
                t.id = EvasionCategoryId(category);
                t.rva = insn.rva;
                t.virtualAddress = insn.address;
                t.environmentProperty = property;
                t.functionName = FunctionNameFor(insn.rva, functions);
                t.basicBlockStart = BlockStartFor(insn.rva, functions);
                t.corroboratingAnalyzers = { "Capstone" };

                EvasionEvidence e;
                e.kind = EvidenceKind::DetectedStatically;
                e.source = "Capstone";
                e.rva = insn.rva;
                e.virtualAddress = insn.address;
                e.instruction = insn.mnemonic + " " + insn.operands;
                e.detail = "instruction `" + e.instruction + "` at RVA " + Hex(insn.rva);
                t.evidence.push_back(e);

                // ── CPUID leaf recovery ─────────────────────────────────────
                // Look back a short window for the constant loaded into EAX.
                if (category == EvasionCategory::AntiVmCpuid) {
                    for (size_t back = 1; back <= 8 && back <= i; ++back) {
                        const auto& prev = instructions[i - back];
                        const std::string pm = Lower(prev.mnemonic);
                        if (pm != "mov" && pm != "xor") continue;
                        const std::string ops = Lower(prev.operands);
                        if (ops.rfind("eax,", 0) != 0) continue;

                        uint64_t leaf = 0;
                        if (pm == "xor" && ops == "eax, eax") {
                            leaf = 0;
                        } else {
                            const size_t comma = ops.find(',');
                            std::string imm = ops.substr(comma + 1);
                            imm.erase(0, imm.find_first_not_of(" \t"));
                            if (imm.rfind("0x", 0) != 0 && !isdigit(static_cast<unsigned char>(imm[0]))) break;
                            try { leaf = std::stoull(imm, nullptr, 0); } catch (...) { break; }
                        }

                        t.observedValue = "leaf " + Hex(leaf);
                        EvasionEvidence le;
                        le.kind = EvidenceKind::DetectedStatically;
                        le.source = "Capstone";
                        le.rva = prev.rva;
                        le.virtualAddress = prev.address;
                        le.instruction = prev.mnemonic + " " + prev.operands;
                        le.detail = "CPUID input leaf loaded by `" + le.instruction + "` at RVA " + Hex(prev.rva);
                        t.evidence.push_back(le);

                        if (leaf == 1) {
                            t.environmentProperty = "Hypervisor presence";
                        } else if (leaf >= 0x40000000 && leaf <= 0x400000FF) {
                            t.category = EvasionCategory::AntiVmHypervisorVendor;
                            t.id = EvasionCategoryId(t.category);
                            t.environmentProperty = "Hypervisor vendor signature";
                        } else if (leaf == 0) {
                            t.environmentProperty = "CPU vendor string";
                        } else if (leaf == 0xB || leaf == 0x1F || leaf == 4) {
                            t.category = EvasionCategory::AntiVmCpuTopology;
                            t.id = EvasionCategoryId(t.category);
                            t.environmentProperty = "CPU topology";
                        }
                        break;
                    }
                }

                // ── Does the result reach a conditional branch? ──────────────
                // Bounded forward scan for a compare followed by a conditional
                // jump. This is the difference between "queried" and "gated".
                uint64_t compareRva = 0;
                std::string compareText;
                for (size_t fwd = 1; fwd <= 24 && i + fwd < instructions.size(); ++fwd) {
                    const auto& next = instructions[i + fwd];
                    const std::string nm = Lower(next.mnemonic);

                    // A return ends the function, so anything past it belongs to
                    // other code. A call does not: `call IsDebuggerPresent; test
                    // al, al; je` is one of the most common gate shapes there is,
                    // and stopping at the call would miss all of them.
                    if (next.isReturn) break;
                    if (next.isCall) continue;

                    if (compareRva == 0 && IsCompare(nm)) {
                        compareRva = next.rva;
                        compareText = next.mnemonic + " " + next.operands;
                        continue;
                    }
                    if (next.isBranch && next.isConditional) {
                        t.controlsFlow = (compareRva != 0);
                        t.branchRva = next.rva;
                        if (t.controlsFlow) {
                            EvasionEvidence be;
                            be.kind = EvidenceKind::DetectedStatically;
                            be.source = "Capstone + CFG";
                            be.rva = next.rva;
                            be.virtualAddress = next.address;
                            be.instruction = next.mnemonic + " " + next.operands;
                            be.detail = "result reaches `" + compareText + "` at RVA " + Hex(compareRva) +
                                        " and then the conditional branch `" + be.instruction +
                                        "` at RVA " + Hex(next.rva);
                            t.evidence.push_back(be);
                            t.controlFlowConsequence =
                                "conditional branch at RVA " + Hex(next.rva) +
                                " selects between " + Hex(next.targetRva ? next.targetRva : next.targetAddress) +
                                " and fallthrough";
                            t.corroboratingAnalyzers.push_back("CFG");
                        }
                        break;
                    }
                }

                // ── Confidence ──────────────────────────────────────────────
                // An instruction that merely executes is a Medium-confidence
                // pattern. Only a value that demonstrably steers a branch earns
                // High from static evidence alone.
                if (t.controlsFlow) {
                    t.confidence = FindingConfidence::High;
                    t.severity = FindingSeverity::Low;
                } else {
                    t.confidence = FindingConfidence::Medium;
                    t.severity = FindingSeverity::Info;
                }

                t.title = std::string(EvasionCategoryLabel(t.category)) + " via " + what +
                          " at RVA " + Hex(insn.rva);
                t.description =
                    "The sample executes `" + what + "` to inspect " + Lower(t.environmentProperty) +
                    (t.controlsFlow
                         ? ". The result is compared and controls a conditional branch, so it "
                           "influences which code runs."
                         : ". No branch dependency on the result was found nearby, so the value "
                           "may simply be collected rather than acted on.");
                t.tags = { "MITRE:T1497" };
                out.push_back(std::move(t));
            }
        }

        // ── 2. Environment-discovery imports ────────────────────────────────
        //
        // Being on this list is not evidence of wrongdoing. Inventory tools,
        // installers and games call these APIs legitimately, so a plain import
        // is Low confidence and Info severity, and says so.

        const std::vector<XRefEntry> emptyXrefs;
        const auto& xrefs = precomputed ? precomputed->xrefs : emptyXrefs;

        for (const auto& imp : inspector.GetImports()) {
            const EnvironmentApiRule* rule = MatchEnvironmentApi(imp.functionName);
            if (!rule) continue;

            EvasionTechnique t;
            t.category = rule->category;
            t.id = EvasionCategoryId(t.category);
            t.rva = imp.iatRva;
            t.virtualAddress = meta.imageBase + imp.iatRva;
            t.environmentProperty = rule->property;
            t.confidence = rule->strongIndicator ? FindingConfidence::Medium : FindingConfidence::Low;
            t.severity = FindingSeverity::Info;
            t.corroboratingAnalyzers = { "PE Inspector (imports)" };
            t.title = std::string(EvasionCategoryLabel(t.category)) + " API imported: " + imp.functionName;
            t.description =
                "The import table references " + imp.dllName + "!" + imp.functionName +
                ", which reveals " + Lower(rule->property) + ". " +
                (rule->strongIndicator
                     ? "This API is rarely called except to fingerprint the environment."
                     : "This is an ordinary Windows API with many legitimate uses; on its own it "
                       "is not evidence of evasion.");

            EvasionEvidence e;
            e.kind = EvidenceKind::DetectedStatically;
            e.source = "PE Inspector";
            e.rva = imp.iatRva;
            e.detail = "import " + imp.dllName + "!" + imp.functionName +
                       " at IAT RVA " + Hex(imp.iatRva);
            t.evidence.push_back(e);

            // Correlate with the XRef that actually calls it, so the technique
            // points at code rather than at a table entry.
            for (const auto& x : xrefs) {
                if (x.type != XRefType::ImportCall) continue;
                if (Lower(x.targetName).find(Lower(imp.functionName)) == std::string::npos) continue;

                t.rva = x.fromRva;
                t.virtualAddress = x.fromAddress;
                t.functionName = FunctionNameFor(x.fromRva, functions);
                t.basicBlockStart = BlockStartFor(x.fromRva, functions);

                EvasionEvidence xe;
                xe.kind = EvidenceKind::DetectedStatically;
                xe.source = "XRef Analyzer";
                xe.rva = x.fromRva;
                xe.virtualAddress = x.fromAddress;
                xe.instruction = x.sourceInstruction;
                xe.detail = "called from RVA " + Hex(x.fromRva) + " (`" + x.sourceInstruction + "`)";
                t.evidence.push_back(xe);
                t.corroboratingAnalyzers.push_back("XRefs");
                break;
            }

            t.tags = { "MITRE:T1497" };
            out.push_back(std::move(t));
        }

        // ── 3. Artifact strings ─────────────────────────────────────────────
        //
        // Weakest evidence in the engine, and deliberately so: a program that
        // contains the word "VMware" has told us almost nothing.

        StringsAnalyzer sa;
        const std::vector<ExtractedString> ownStrings =
            precomputed ? std::vector<ExtractedString>()
                        : sa.ExtractStrings(inspector.GetBuffer(), inspector.GetBufferSize(), 4);
        const auto& strings = precomputed ? precomputed->strings : ownStrings;

        std::set<std::string> seenArtifacts;
        for (const auto& s : strings) {
            const ArtifactRule* rule = MatchArtifact(s.value);
            if (!rule) continue;
            if (!seenArtifacts.insert(rule->pattern).second) continue;   // one per artifact

            EvasionTechnique t;
            t.category = rule->category;
            t.id = EvasionCategoryId(t.category);
            t.rva = s.rva;
            t.virtualAddress = meta.imageBase + s.rva;
            t.environmentProperty = std::string(ArtifactTypeToString(rule->type)) +
                                    " artifact (" + rule->provider + ")";
            t.observedValue = s.value;

            // A bare string never rises above Low here. Anything stronger has
            // to come from correlation with execution.
            t.confidence = (rule->baseConfidence == FindingConfidence::High)
                               ? FindingConfidence::Medium : FindingConfidence::Low;
            t.severity = FindingSeverity::Info;
            t.corroboratingAnalyzers = { "Strings Analyzer" };
            t.title = std::string(rule->provider) + " " + ArtifactTypeToString(rule->type) +
                      " artifact referenced: " + s.value;
            t.description =
                "The binary contains the " + rule->provider + " " +
                ArtifactTypeToString(rule->type) + " artifact \"" + s.value + "\". " + rule->note +
                " A string on its own is weak evidence; it becomes meaningful when it is "
                "compared against live firmware, device or process data.";

            EvasionEvidence e;
            e.kind = EvidenceKind::DetectedStatically;
            e.source = "Strings Analyzer";
            e.rva = s.rva;
            e.detail = "string \"" + s.value + "\" at RVA " + Hex(s.rva) +
                       " matches the " + rule->provider + " artifact rule \"" + rule->pattern + "\"";
            t.evidence.push_back(e);
            t.tags = { "MITRE:T1497" };
            out.push_back(std::move(t));
        }

        return out;
    }

    // ─── Fingerprint ────────────────────────────────────────────────────────

    BehaviorFingerprint AntiEvasionEngine::Fingerprint(const EmulationResult& r) {
        BehaviorFingerprint fp;
        fp.blocksReached = r.coverage.BlockCount();
        fp.functionsReached = r.coverage.FunctionCount();
        fp.instructionsExecuted = r.instructionsExecuted;
        fp.hleCallCount = r.hleCalls.size();
        fp.terminationReason = StopReasonToString(r.stopReason);

        std::ostringstream apis;
        for (const auto& c : r.hleCalls) apis << c.library << "!" << c.apiName << ";";
        fp.apiSequenceDigest = Digest(apis.str());

        std::ostringstream blocks;
        for (uint64_t b : r.coverage.basicBlocks) blocks << std::hex << b << ",";
        fp.coverageDigest = Digest(blocks.str());

        std::ostringstream all;
        all << fp.blocksReached << "|" << fp.functionsReached << "|" << fp.instructionsExecuted
            << "|" << fp.hleCallCount << "|" << fp.terminationReason
            << "|" << fp.apiSequenceDigest << "|" << fp.coverageDigest;
        fp.digest = Digest(all.str());
        return fp;
    }

    // ─── Run comparison ─────────────────────────────────────────────────────

    ExecutionDelta AntiEvasionEngine::CompareRuns(const DifferentialRun& a,
                                                  const DifferentialRun& b) {
        ExecutionDelta d;
        d.baselineProfile = a.profileName;
        d.alternateProfile = b.profileName;
        d.baselineTermination = StopReasonToString(a.emulation.stopReason);
        d.alternateTermination = StopReasonToString(b.emulation.stopReason);
        d.terminationChanged = (d.baselineTermination != d.alternateTermination);
        d.instructionDelta = static_cast<int64_t>(b.emulation.instructionsExecuted) -
                             static_cast<int64_t>(a.emulation.instructionsExecuted);

        const auto& aBlocks = a.emulation.coverage.basicBlocks;
        const auto& bBlocks = b.emulation.coverage.basicBlocks;
        std::set_difference(aBlocks.begin(), aBlocks.end(), bBlocks.begin(), bBlocks.end(),
                            std::back_inserter(d.blocksOnlyInBaseline));
        std::set_difference(bBlocks.begin(), bBlocks.end(), aBlocks.begin(), aBlocks.end(),
                            std::back_inserter(d.blocksOnlyInAlternate));

        const auto& aFuncs = a.emulation.coverage.functions;
        const auto& bFuncs = b.emulation.coverage.functions;
        std::set_difference(aFuncs.begin(), aFuncs.end(), bFuncs.begin(), bFuncs.end(),
                            std::back_inserter(d.functionsOnlyInBaseline));
        std::set_difference(bFuncs.begin(), bFuncs.end(), aFuncs.begin(), aFuncs.end(),
                            std::back_inserter(d.functionsOnlyInAlternate));

        // API sets
        std::set<std::string> aApis, bApis;
        for (const auto& c : a.emulation.hleCalls) aApis.insert(c.library + "!" + c.apiName);
        for (const auto& c : b.emulation.hleCalls) bApis.insert(c.library + "!" + c.apiName);
        std::set_difference(aApis.begin(), aApis.end(), bApis.begin(), bApis.end(),
                            std::back_inserter(d.apisOnlyInBaseline));
        std::set_difference(bApis.begin(), bApis.end(), aApis.begin(), aApis.end(),
                            std::back_inserter(d.apisOnlyInAlternate));

        // ── Branches that went a different way ──────────────────────────────
        std::map<uint64_t, const BranchObservation*> aBranch;
        for (const auto& br : a.emulation.branches) aBranch[br.address] = &br;

        for (const auto& br : b.emulation.branches) {
            auto it = aBranch.find(br.address);
            if (it == aBranch.end()) continue;
            const BranchObservation& base = *it->second;

            const bool baseTaken = base.WasTaken();
            const bool altTaken  = br.WasTaken();
            if (baseTaken == altTaken) continue;

            BranchDivergence bd;
            bd.rva = br.rva;
            bd.virtualAddress = br.address;
            bd.mnemonic = br.mnemonic;
            bd.baselineProfile = a.profileName;
            bd.alternateProfile = b.profileName;
            bd.baselineTaken = baseTaken;
            bd.alternateTaken = altTaken;
            bd.baselineTarget = baseTaken ? base.takenTarget : base.fallthrough;
            bd.alternateTarget = altTaken ? br.takenTarget : br.fallthrough;

            if (br.environmentInfluenced) {
                bd.influenceOrigin = br.influenceOrigin;
                bd.influenceProperty = br.influenceProperty;
            } else if (base.environmentInfluenced) {
                bd.influenceOrigin = base.influenceOrigin;
                bd.influenceProperty = base.influenceProperty;
            }

            // Confidence: a branch that changed direction is already strong
            // evidence; a branch that changed direction AND was attributed to a
            // specific environment value is as strong as this engine gets.
            bd.confidence = bd.influenceOrigin.empty() ? FindingConfidence::Medium
                                                       : FindingConfidence::High;

            std::ostringstream baseCons, altCons;
            baseCons << (baseTaken ? "branch taken" : "fallthrough") << " -> " << Hex(bd.baselineTarget);
            altCons  << (altTaken ? "branch taken" : "fallthrough")  << " -> " << Hex(bd.alternateTarget);
            if (d.blocksOnlyInAlternate.size() > 0) {
                altCons << ", reaching " << d.blocksOnlyInAlternate.size()
                        << " block(s) the reference run never entered";
            }
            if (a.emulation.stopReason != b.emulation.stopReason) {
                baseCons << ", run ends " << d.baselineTermination;
                altCons  << ", run ends " << d.alternateTermination;
            }
            bd.baselineConsequence = baseCons.str();
            bd.alternateConsequence = altCons.str();

            d.branchDivergences.push_back(std::move(bd));
        }

        return d;
    }

    // ─── Divergence score ───────────────────────────────────────────────────
    //
    // Documented in DRACULA_GUIDE.md. This is an environment-sensitivity
    // measure, NOT a malware score: legitimate software can score highly.

    int AntiEvasionEngine::ComputeSensitivityScore(
        const std::vector<ExecutionDelta>& deltas,
        const std::vector<EvasionTechnique>& techniques,
        std::string& outLabel) {

        int score = 0;

        // Static signal contributes a small, capped floor. Detecting checks is
        // not the same as observing behaviour change, so it can never dominate.
        int staticFloor = 0;
        for (const auto& t : techniques) {
            if (t.controlsFlow && t.confidence == FindingConfidence::High) staticFloor += 6;
            else if (t.confidence == FindingConfidence::Medium)            staticFloor += 2;
        }
        score += std::min(staticFloor, 25);

        // Observed divergence is what the score is really about.
        for (const auto& d : deltas) {
            // A branch that changed direction is the clearest possible signal.
            for (const auto& bd : d.branchDivergences) {
                score += (bd.confidence == FindingConfidence::High) ? 20 : 12;
            }
            // Newly reachable code.
            if (!d.blocksOnlyInAlternate.empty()) {
                score += std::min<int>(static_cast<int>(d.blocksOnlyInAlternate.size()) * 2, 20);
            }
            if (!d.functionsOnlyInAlternate.empty()) {
                score += std::min<int>(static_cast<int>(d.functionsOnlyInAlternate.size()) * 4, 20);
            }
            // Ending the run differently.
            if (d.terminationChanged) score += 15;
            // Reaching APIs it otherwise never called.
            if (!d.apisOnlyInAlternate.empty()) {
                score += std::min<int>(static_cast<int>(d.apisOnlyInAlternate.size()) * 3, 12);
            }
        }

        score = std::clamp(score, 0, 100);
        if (score >= 75)      outLabel = "Strong";
        else if (score >= 45) outLabel = "Clear";
        else if (score >= 20) outLabel = "Weak";
        else if (score > 0)   outLabel = "Minimal";
        else                  outLabel = "None";
        return score;
    }

    // ─── Engine ─────────────────────────────────────────────────────────────

    AntiEvasionEngine::AntiEvasionEngine() = default;
    AntiEvasionEngine::~AntiEvasionEngine() = default;

    namespace {

        DifferentialRun ExecuteUnderProfile(const std::string& filePath,
                                            ProfileKind kind,
                                            const AntiEvasionOptions& opts) {
            DifferentialRun run;
            run.profileKind = kind;
            run.profile = EnvironmentProfile::FromKind(kind);
            run.profileName = run.profile.name;

            UnicornAnalyzer emu;
            EmulationOptions eo;
            eo.maxInstructions = opts.maxInstructionsPerRun;
            eo.timeoutMicros = opts.maxMicrosPerRun;
            eo.strictSandbox = false;
            eo.antiDebugPolicy = AntiDebugPolicy::Bypass;
            eo.environmentProfile = run.profile;
            eo.recordCoverage = true;
            eo.trackBranchInfluence = true;

            run.emulation = emu.EmulatePE(filePath, eo, &run.findings);
            run.fingerprint = AntiEvasionEngine::Fingerprint(run.emulation);
            run.completed = true;
            if (!run.emulation.errorMessage.empty()) {
                run.failureReason = run.emulation.errorMessage;
            }
            return run;
        }

        // Promote the raw observations of one run into techniques, deduplicated
        // by (category, address) so a CPUID inside a loop is one finding, not
        // thirty-seven.
        void PromoteRunObservations(const DifferentialRun& run,
                                    std::vector<EvasionTechnique>& techniques) {
            std::map<uint64_t, const BranchObservation*> influenced;
            for (const auto& b : run.emulation.branches) {
                if (b.environmentInfluenced) influenced[b.influenceProducedAt] = &b;
            }

            for (const auto& obs : run.emulation.environmentObservations) {
                // Find or create the technique for this site.
                EvasionTechnique* existing = nullptr;
                for (auto& t : techniques) {
                    if (t.virtualAddress == obs.address &&
                        Lower(t.environmentProperty) == Lower(obs.property)) {
                        existing = &t;
                        break;
                    }
                }

                EvasionTechnique fresh;
                EvasionTechnique& t = existing ? *existing : fresh;
                if (!existing) {
                    // Categorise by what was actually asked for.
                    EvasionCategory c = EvasionCategory::AntiSandboxEnvironment;
                    const std::string p = Lower(obs.property);
                    if (obs.source == "CPUID") {
                        c = p.find("hypervisor vendor") != std::string::npos
                                ? EvasionCategory::AntiVmHypervisorVendor
                            : p.find("hypervisor") != std::string::npos
                                ? EvasionCategory::AntiVmCpuid
                            : p.find("topology") != std::string::npos
                                ? EvasionCategory::AntiVmCpuTopology
                                : EvasionCategory::AntiVmCpuid;
                    } else if (obs.source == "RDTSC" || obs.source == "RDTSCP") {
                        c = EvasionCategory::AntiVmTiming;
                    } else if (obs.source == "SIDT" || obs.source == "SGDT" ||
                               obs.source == "SLDT" || obs.source == "STR" || obs.source == "SMSW") {
                        c = EvasionCategory::AntiVmDescriptorTable;
                    } else if (p.find("tick") != std::string::npos ||
                               p.find("performance counter") != std::string::npos) {
                        c = EvasionCategory::AntiVmTiming;
                    } else if (p.find("sleep") != std::string::npos) {
                        c = EvasionCategory::AntiSandboxSleep;
                    } else if (p.find("processor count") != std::string::npos) {
                        c = EvasionCategory::AntiVmCpuTopology;
                    } else if (p.find("memory") != std::string::npos) {
                        c = EvasionCategory::AntiVmMemory;
                    } else if (p.find("disk") != std::string::npos) {
                        c = EvasionCategory::AntiVmDisk;
                    } else if (p.find("screen") != std::string::npos) {
                        c = EvasionCategory::AntiVmScreen;
                    } else if (p.find("input activity") != std::string::npos) {
                        c = EvasionCategory::AntiVmInputActivity;
                    } else if (p.find("debugger") != std::string::npos) {
                        c = EvasionCategory::AntiDebugApi;
                    } else if (p.find("firmware") != std::string::npos) {
                        c = EvasionCategory::AntiVmSmbios;
                    } else if (p.find("registry") != std::string::npos) {
                        c = EvasionCategory::AntiVmRegistry;
                    }

                    t.category = c;
                    t.id = EvasionCategoryId(c);
                    t.rva = obs.rva;
                    t.virtualAddress = obs.address;
                    t.environmentProperty = obs.property;
                    t.confidence = FindingConfidence::Medium;
                    t.severity = FindingSeverity::Info;
                    t.title = std::string(EvasionCategoryLabel(c)) + " observed at RVA " + Hex(obs.rva);
                    t.description = "During controlled emulation the sample queried " +
                                    Lower(obs.property) + " via " + obs.source + ".";
                }

                t.profile = obs.profile;
                t.suppliedValue = obs.suppliedValue;
                t.observedValue = obs.suppliedValue;

                EvasionEvidence e;
                e.kind = EvidenceKind::ModelledInUnicorn;
                e.source = obs.source;
                e.rva = obs.rva;
                e.virtualAddress = obs.address;
                e.detail = obs.source + " answered " + Lower(obs.property) + " as \"" +
                           obs.suppliedValue + "\" under profile " + obs.profile +
                           (obs.occurrences > 1 ? " (" + std::to_string(obs.occurrences) + " times)" : "");
                t.evidence.push_back(e);
                if (std::find(t.corroboratingAnalyzers.begin(), t.corroboratingAnalyzers.end(),
                              "Unicorn") == t.corroboratingAnalyzers.end()) {
                    t.corroboratingAnalyzers.push_back("Unicorn");
                }

                // Provenance: did this specific value steer a branch?
                auto inf = influenced.find(obs.address);
                if (inf != influenced.end()) {
                    t.controlsFlow = true;
                    t.branchRva = inf->second->rva;
                    t.confidence = FindingConfidence::High;
                    t.severity = FindingSeverity::Low;
                    t.controlFlowConsequence =
                        "value flows into `" + inf->second->compareText + "` and decides the branch `" +
                        inf->second->mnemonic + "` at RVA " + Hex(inf->second->rva);

                    EvasionEvidence pe;
                    pe.kind = EvidenceKind::ModelledInUnicorn;
                    pe.source = "Branch influence tracker";
                    pe.rva = inf->second->rva;
                    pe.virtualAddress = inf->second->address;
                    pe.instruction = inf->second->mnemonic;
                    pe.detail = "the value produced here reaches `" + inf->second->compareText +
                                "` and controls the conditional branch at RVA " + Hex(inf->second->rva);
                    t.evidence.push_back(pe);
                    if (std::find(t.corroboratingAnalyzers.begin(), t.corroboratingAnalyzers.end(),
                                  "Provenance") == t.corroboratingAnalyzers.end()) {
                        t.corroboratingAnalyzers.push_back("Provenance");
                    }
                }

                if (!existing) techniques.push_back(std::move(fresh));
            }
        }

    } // namespace

    AntiEvasionResult AntiEvasionEngine::Analyze(const std::string& filePath,
                                                 const AntiEvasionOptions& options,
                                                 const UnifiedAnalysisResult* precomputed) {
        const auto start = std::chrono::steady_clock::now();
        AntiEvasionResult res;
        res.samplePath = filePath;
        res.comparePerformed = options.runComparison;
        try {
            res.sampleName = std::filesystem::path(filePath).filename().string();
        } catch (...) {
            res.sampleName = filePath;
        }

        if (!std::filesystem::exists(filePath)) {
            res.status = AntiEvasionStatus::TargetUnreadable;
            res.conclusion = "The target file could not be read.";
            return res;
        }

        // ── 1. Static detection ─────────────────────────────────────────────
        res.techniques = DetectStatic(filePath, precomputed);

        // ── 2. Validate every profile before it is used ─────────────────────
        std::vector<ProfileKind> profiles;
        if (options.runComparison) {
            profiles = options.comparisonProfiles;
            if (profiles.size() > options.maxProfilesPerComparison) {
                profiles.resize(options.maxProfilesPerComparison);
                res.notes.push_back("Comparison limited to " +
                                    std::to_string(options.maxProfilesPerComparison) + " profiles.");
            }
        } else if (options.useEmulation) {
            profiles = { options.detectionProfile };
        }

        for (ProfileKind kind : profiles) {
            const auto profile = EnvironmentProfile::FromKind(kind);
            auto graph = BuildConsistencyGraph(profile);
            res.profileCoherence.push_back(graph);

            auto norms = profile.NormalizationsAgainstBaseline();
            res.normalizations.insert(res.normalizations.end(), norms.begin(), norms.end());

            // A contradictory profile is reported, not silently used as if it
            // were sound.
            for (const auto& c : graph.contradictions) {
                EvasionTechnique t;
                t.category = EvasionCategory::ProfileCoherenceWarning;
                t.id = EvasionCategoryId(t.category);
                t.profile = profile.name;
                t.severity = c.severity;
                t.confidence = FindingConfidence::High;
                t.environmentProperty = c.property;
                t.title = "Profile " + profile.name + " contradicts itself on " + c.property;
                t.description = c.explanation;
                EvasionEvidence e;
                e.kind = EvidenceKind::DetectedStatically;
                e.source = "Environment Coherence Validator";
                e.detail = std::string(ClaimChannelToString(c.first.channel)) + " says \"" +
                           c.first.value + "\" but " + ClaimChannelToString(c.second.channel) +
                           " says \"" + c.second.value + "\"";
                t.evidence.push_back(e);
                t.corroboratingAnalyzers = { "Coherence validator" };
                res.techniques.push_back(std::move(t));
            }
        }

        // ── 3. Controlled execution ─────────────────────────────────────────
        if (!profiles.empty() && options.useEmulation) {
            for (ProfileKind kind : profiles) {
                auto run = ExecuteUnderProfile(filePath, kind, options);
                PromoteRunObservations(run, res.techniques);
                res.runs.push_back(std::move(run));
            }
        }

        // ── 4. Differential comparison ──────────────────────────────────────
        if (options.runComparison && res.runs.size() >= 2) {
            for (size_t i = 1; i < res.runs.size(); ++i) {
                auto delta = CompareRuns(res.runs[0], res.runs[i]);
                for (const auto& bd : delta.branchDivergences) {
                    if (res.branchDivergences.size() >= options.maxBranchDivergences) break;
                    res.branchDivergences.push_back(bd);
                }
                res.deltas.push_back(std::move(delta));
            }

            // Promote proven divergence into techniques. This is the only place
            // an anti-evasion finding is allowed to reach Medium severity: it
            // is the only place behaviour was actually observed to change.
            for (const auto& d : res.deltas) {
                if (!d.Diverged()) continue;

                for (const auto& bd : d.branchDivergences) {
                    EvasionTechnique t;
                    t.category = EvasionCategory::EvasionBranchDivergence;
                    t.id = EvasionCategoryId(t.category);
                    t.rva = bd.rva;
                    t.virtualAddress = bd.virtualAddress;
                    t.severity = FindingSeverity::Medium;
                    t.confidence = FindingConfidence::High;
                    t.controlsFlow = true;
                    t.branchRva = bd.rva;
                    t.profile = bd.alternateProfile;
                    t.environmentProperty = bd.influenceProperty.empty()
                                                ? "environment (origin not attributed)"
                                                : bd.influenceProperty;
                    t.title = "Environment-sensitive branch at RVA " + Hex(bd.rva);
                    t.description =
                        "The conditional branch at RVA " + Hex(bd.rva) + " went a different way "
                        "under " + bd.alternateProfile + " than under " + bd.baselineProfile +
                        ". Under " + bd.baselineProfile + ": " + bd.baselineConsequence +
                        ". Under " + bd.alternateProfile + ": " + bd.alternateConsequence + ".";
                    t.controlFlowConsequence = bd.alternateConsequence;

                    EvasionEvidence e;
                    e.kind = EvidenceKind::VerifiedDifferential;
                    e.source = "Differential execution";
                    e.rva = bd.rva;
                    e.virtualAddress = bd.virtualAddress;
                    e.instruction = bd.mnemonic;
                    e.detail = bd.baselineProfile + ": " + bd.baselineConsequence + " | " +
                               bd.alternateProfile + ": " + bd.alternateConsequence;
                    t.evidence.push_back(e);
                    if (!bd.influenceOrigin.empty()) {
                        EvasionEvidence oe;
                        oe.kind = EvidenceKind::ModelledInUnicorn;
                        oe.source = "Branch influence tracker";
                        oe.detail = "the branch condition was attributed to " + bd.influenceOrigin +
                                    " (" + bd.influenceProperty + ")";
                        t.evidence.push_back(oe);
                    }
                    t.corroboratingAnalyzers = { "Unicorn", "Differential" };
                    t.tags = { "MITRE:T1497" };
                    res.techniques.push_back(std::move(t));
                }

                if (!d.functionsOnlyInAlternate.empty() || d.terminationChanged) {
                    EvasionTechnique t;
                    t.category = EvasionCategory::EvasionBehaviorDivergence;
                    t.id = EvasionCategoryId(t.category);
                    t.severity = FindingSeverity::Medium;
                    t.confidence = FindingConfidence::High;
                    t.profile = d.alternateProfile;
                    t.environmentProperty = "overall behaviour";
                    t.title = "Behaviour diverges between " + d.baselineProfile +
                              " and " + d.alternateProfile;
                    std::ostringstream desc;
                    desc << "Running the same sample under " << d.alternateProfile
                         << " reached " << d.functionsOnlyInAlternate.size()
                         << " function(s) and " << d.blocksOnlyInAlternate.size()
                         << " basic block(s) that " << d.baselineProfile << " never entered";
                    if (d.terminationChanged) {
                        desc << ", and the run ended " << d.alternateTermination
                             << " instead of " << d.baselineTermination;
                    }
                    desc << ".";
                    t.description = desc.str();
                    t.controlFlowConsequence = desc.str();

                    EvasionEvidence e;
                    e.kind = EvidenceKind::VerifiedDifferential;
                    e.source = "Differential execution";
                    e.detail = "coverage " + std::to_string(d.blocksOnlyInBaseline.size()) +
                               " blocks only in " + d.baselineProfile + ", " +
                               std::to_string(d.blocksOnlyInAlternate.size()) + " only in " +
                               d.alternateProfile;
                    t.evidence.push_back(e);
                    t.corroboratingAnalyzers = { "Unicorn", "Differential" };
                    t.tags = { "MITRE:T1497" };
                    res.techniques.push_back(std::move(t));
                }
            }
        }

        // ── 5. Bounds, dedup, score, conclusion ─────────────────────────────
        if (res.techniques.size() > options.maxTechniques) {
            res.notes.push_back("Technique list truncated at " +
                                std::to_string(options.maxTechniques) + " entries.");
            res.techniques.resize(options.maxTechniques);
        }

        // Order by what an analyst should read first.
        std::stable_sort(res.techniques.begin(), res.techniques.end(),
                         [](const EvasionTechnique& a, const EvasionTechnique& b) {
                             if (a.severity != b.severity) return a.severity > b.severity;
                             if (a.confidence != b.confidence) return a.confidence > b.confidence;
                             return a.controlsFlow && !b.controlsFlow;
                         });

        res.environmentSensitivityScore =
            ComputeSensitivityScore(res.deltas, res.techniques, res.sensitivityLabel);

        bool diverged = false;
        for (const auto& d : res.deltas) if (d.Diverged()) diverged = true;

        bool profileInvalid = false;
        for (const auto& g : res.profileCoherence) if (!g.IsCoherent()) profileInvalid = true;

        bool hitLimit = false;
        for (const auto& r : res.runs) {
            if (r.emulation.stopReason == EmulationStopReason::InstructionLimit ||
                r.emulation.stopReason == EmulationStopReason::Timeout) {
                hitLimit = true;
            }
        }

        if (diverged)                       res.status = AntiEvasionStatus::BehaviorDiverged;
        else if (profileInvalid)            res.status = AntiEvasionStatus::ProfileInvalid;
        else if (!res.techniques.empty())   res.status = AntiEvasionStatus::Completed;
        else if (hitLimit)                  res.status = AntiEvasionStatus::EmulationLimit;
        else                                res.status = AntiEvasionStatus::NoEvasionDetected;

        // Overall confidence follows the strongest evidence anywhere.
        res.overallConfidence = FindingConfidence::Low;
        bool differentiallyVerified = false;
        for (const auto& t : res.techniques) {
            if (t.StrongestEvidence() == EvidenceKind::VerifiedDifferential) differentiallyVerified = true;
            if (t.confidence > res.overallConfidence) res.overallConfidence = t.confidence;
        }

        std::ostringstream conclusion;
        if (diverged) {
            conclusion << "Behaviour is environment-sensitive. Changing what the sample could "
                          "observe about its host changed which code it executed.";
        } else if (!res.runs.empty() && res.comparePerformed) {
            conclusion << "The sample inspected its environment but behaved identically under "
                          "every profile tried, so no environment gate was demonstrated.";
        } else if (!res.techniques.empty()) {
            conclusion << "Environment inspection was detected. Run with --compare to test "
                          "whether it actually changes behaviour.";
        } else {
            conclusion << "No environment inspection was detected in this sample.";
        }
        if (differentiallyVerified) {
            conclusion << " Confidence is very high: this was proven by re-execution, not inferred.";
        }
        conclusion << " Detecting a virtual environment is not by itself malicious; "
                      "development tools, games and licensing systems do it legitimately.";
        res.conclusion = conclusion.str();

        const auto end = std::chrono::steady_clock::now();
        res.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        return res;
    }

    std::vector<Finding> AntiEvasionResult::ToFindings() const {
        std::vector<Finding> out;
        std::set<std::string> seen;
        for (const auto& t : techniques) {
            Finding f = t.ToFinding();
            // Deduplicate identical evidence: the same technique at the same
            // address must not be counted twice by the threat evaluator.
            const std::string key = f.id + "@" + std::to_string(f.rva) + "|" + f.title;
            if (!seen.insert(key).second) continue;
            out.push_back(std::move(f));
        }
        return out;
    }

} // namespace Dracula
