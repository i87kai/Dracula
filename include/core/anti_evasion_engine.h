#pragma once

//
// Dracula Anti-Evasion Intelligence Engine.
//
// Detects, locates, explains and — when asked — experimentally verifies code
// that changes its behaviour because it believes it is being analysed.
//
//      static detection      Capstone instruction semantics, CFG, XRefs,
//                            imports, data-driven artifact rules
//              +
//      controlled execution  Unicorn under an explicit EnvironmentProfile,
//                            coherent virtual clock, Win32 HLE
//              +
//      differential runs     the same sample under several profiles
//              ↓
//      evidence correlation  every finding traced to the evidence that
//                            produced it, with an honest confidence
//
// Scope: this engine's environment control exists only inside Dracula's own
// Unicorn and QEMU analysis environments. It is an instrument for observing
// evasive behaviour under authorized analysis, not a host-stealth toolkit.
//
// It does not claim, and cannot deliver, an environment indistinguishable from
// physical hardware. Where it changes what a sample sees, it says so.
//

#include "common/findings.h"
#include "core/environment_profile.h"
#include "core/unicorn_analyzer.h"
#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace Dracula {

    // ─── Technique taxonomy ─────────────────────────────────────────────────

    enum class EvasionCategory {
        // Anti-VM
        AntiVmCpuid,
        AntiVmHypervisorVendor,
        AntiVmCpuTopology,
        AntiVmSmbios,
        AntiVmAcpi,
        AntiVmDevice,
        AntiVmDriver,
        AntiVmService,
        AntiVmProcess,
        AntiVmRegistry,
        AntiVmMacOui,
        AntiVmDisk,
        AntiVmMemory,
        AntiVmTiming,
        AntiVmUptime,
        AntiVmScreen,
        AntiVmInputActivity,
        AntiVmDescriptorTable,

        // Anti-debug
        AntiDebugPeb,
        AntiDebugApi,
        AntiDebugTiming,
        AntiDebugException,
        AntiDebugHardwareBreakpoint,
        AntiDebugProcessCheck,

        // Anti-sandbox
        AntiSandboxSleep,
        AntiSandboxResourceCheck,
        AntiSandboxUserActivity,
        AntiSandboxFileArtifact,
        AntiSandboxEnvironment,

        // Anti-emulation / instrumentation
        AntiEmulationUnsupportedBehavior,
        AntiInstrumentationCheck,

        // Differential conclusions
        EvasionBehaviorDivergence,
        EvasionBranchDivergence,
        EvasionEnvironmentSensitive,

        // Environment quality diagnostics
        ProfileCoherenceWarning
    };

    // Stable identifier used in findings, JSON and tests, e.g. "ANTI_VM_CPUID".
    const char* EvasionCategoryId(EvasionCategory category);
    // Human readable label, e.g. "Anti-VM CPUID".
    const char* EvasionCategoryLabel(EvasionCategory category);
    bool ParseEvasionCategory(const std::string& id, EvasionCategory& out);

    // How the technique was established. Kept explicit so a report never blurs
    // "we saw this happen" into "we inferred this from a string".
    enum class EvidenceKind {
        DetectedStatically,   // Capstone / imports / rules
        ModelledInUnicorn,    // observed during controlled emulation
        ObservedInQemu,       // observed in the hardware sandbox
        VerifiedDifferential, // proven by comparing runs
        Unsupported           // recognised but not modelled by this build
    };

    const char* EvidenceKindToString(EvidenceKind kind);

    // ─── A single piece of supporting evidence ──────────────────────────────

    struct EvasionEvidence {
        EvidenceKind kind = EvidenceKind::DetectedStatically;
        std::string  source;       // "Capstone", "Win32 HLE", "Differential"
        std::string  detail;
        uint64_t     rva = 0;
        uint64_t     virtualAddress = 0;
        std::string  instruction;  // disassembly text when applicable
    };

    // ─── A detected technique ───────────────────────────────────────────────

    struct EvasionTechnique {
        EvasionCategory   category = EvasionCategory::AntiVmCpuid;
        std::string       id;            // EvasionCategoryId(category)
        std::string       title;
        std::string       description;
        FindingSeverity   severity = FindingSeverity::Info;
        FindingConfidence confidence = FindingConfidence::Low;

        uint64_t          rva = 0;
        uint64_t          virtualAddress = 0;
        std::string       functionName;
        uint64_t          basicBlockStart = 0;

        std::string       environmentProperty;  // "Hypervisor presence"
        std::string       observedValue;        // what the sample saw
        std::string       suppliedValue;        // what Dracula supplied
        std::string       profile;

        // Whether the value demonstrably steered execution.
        bool              controlsFlow = false;
        uint64_t          branchRva = 0;
        std::string       controlFlowConsequence;

        std::vector<EvasionEvidence> evidence;
        std::vector<std::string>     corroboratingAnalyzers;
        std::vector<std::string>     tags;

        // Highest-authority evidence kind attached to this technique.
        EvidenceKind StrongestEvidence() const;
        Finding ToFinding() const;
    };

    // ─── Differential execution ─────────────────────────────────────────────

    // Deterministic summary of one run, suitable for comparison and for
    // regression tests.
    struct BehaviorFingerprint {
        size_t      blocksReached = 0;
        size_t      functionsReached = 0;
        uint64_t    instructionsExecuted = 0;
        size_t      hleCallCount = 0;
        std::string terminationReason;
        std::string apiSequenceDigest;   // stable digest of the HLE call order
        std::string coverageDigest;      // stable digest of reached blocks
        std::string digest;              // digest of the whole fingerprint

        bool operator==(const BehaviorFingerprint& o) const { return digest == o.digest; }
    };

    struct DifferentialRun {
        std::string          profileName;
        ProfileKind          profileKind = ProfileKind::Baseline;
        EnvironmentProfile   profile;
        EmulationResult      emulation;
        BehaviorFingerprint  fingerprint;
        std::vector<Finding> findings;
        bool                 completed = false;
        std::string          failureReason;
    };

    // One branch that behaved differently between two runs.
    struct BranchDivergence {
        uint64_t    rva = 0;
        uint64_t    virtualAddress = 0;
        std::string mnemonic;
        std::string baselineProfile;
        std::string alternateProfile;
        bool        baselineTaken = false;
        bool        alternateTaken = false;
        uint64_t    baselineTarget = 0;
        uint64_t    alternateTarget = 0;
        std::string baselineConsequence;   // "early exit"
        std::string alternateConsequence;  // "reaches 13 further functions"
        std::string influenceOrigin;
        std::string influenceProperty;
        FindingConfidence confidence = FindingConfidence::Medium;
    };

    // Full comparison of two runs.
    struct ExecutionDelta {
        std::string           baselineProfile;
        std::string           alternateProfile;
        std::vector<uint64_t> blocksOnlyInBaseline;
        std::vector<uint64_t> blocksOnlyInAlternate;
        std::vector<uint64_t> functionsOnlyInBaseline;
        std::vector<uint64_t> functionsOnlyInAlternate;
        std::vector<BranchDivergence> branchDivergences;
        std::vector<std::string> apisOnlyInBaseline;
        std::vector<std::string> apisOnlyInAlternate;
        std::string           baselineTermination;
        std::string           alternateTermination;
        int64_t               instructionDelta = 0;
        bool                  terminationChanged = false;

        bool Diverged() const {
            return !blocksOnlyInAlternate.empty() || !blocksOnlyInBaseline.empty() ||
                   !branchDivergences.empty() || terminationChanged;
        }
    };

    // ─── Result status ──────────────────────────────────────────────────────

    enum class AntiEvasionStatus {
        Completed,             // ran, techniques were found
        NoEvasionDetected,     // ran cleanly, nothing environment-sensitive
        BehaviorDiverged,      // differential execution proved divergence
        EnvironmentUnsupported,// the requested backend is not available here
        ProfileInvalid,        // the profile failed coherence validation
        EmulationLimit,        // hit an instruction / time bound
        UnsupportedInstruction,
        SandboxUnavailable,
        SandboxTimeout,
        TargetUnreadable
    };

    const char* AntiEvasionStatusToString(AntiEvasionStatus status);

    // ─── Engine result ──────────────────────────────────────────────────────

    struct AntiEvasionResult {
        AntiEvasionStatus status = AntiEvasionStatus::NoEvasionDetected;
        std::string       samplePath;
        std::string       sampleName;

        std::vector<EvasionTechnique>       techniques;
        std::vector<DifferentialRun>        runs;
        std::vector<ExecutionDelta>         deltas;
        std::vector<BranchDivergence>       branchDivergences;
        std::vector<NormalizationRecord>    normalizations;
        std::vector<EnvironmentConsistencyGraph> profileCoherence;

        // 0-100. How strongly behaviour changed when analysis-environment
        // variables changed. Deliberately NOT the malware threat score.
        int          environmentSensitivityScore = 0;
        std::string  sensitivityLabel = "None";
        FindingConfidence overallConfidence = FindingConfidence::Low;
        std::string  conclusion;

        bool         comparePerformed = false;
        int64_t      durationMs = 0;
        std::vector<std::string> notes;   // limitations, skipped work, bounds

        std::vector<Finding> ToFindings() const;
        std::string ToJson() const;
        std::string ToMarkdown() const;
        std::string ToAnsiReport(bool detailed = false) const;
    };

    // ─── Engine options ─────────────────────────────────────────────────────

    struct AntiEvasionOptions {
        bool     runDetection = true;      // static + single controlled run
        bool     runComparison = false;    // differential execution
        bool     detailed = false;
        bool     useEmulation = true;

        // Profiles used by comparison mode, in order. The first is the
        // reference run.
        std::vector<ProfileKind> comparisonProfiles = {
            ProfileKind::Baseline, ProfileKind::Realistic, ProfileKind::AnalysisFriendly
        };
        ProfileKind detectionProfile = ProfileKind::Baseline;

        // Hard bounds. There is no adaptive loop; these are never exceeded.
        size_t   maxProfilesPerComparison = 4;
        uint64_t maxInstructionsPerRun = 200000;
        uint64_t maxMicrosPerRun = 10000000;   // 10 s
        size_t   maxTechniques = 256;
        size_t   maxBranchDivergences = 64;

        std::string yaraRulesPath;
    };

    // ─── The engine ─────────────────────────────────────────────────────────

    class AntiEvasionEngine {
    public:
        AntiEvasionEngine();
        ~AntiEvasionEngine();

        // Full analysis of a file. When `precomputed` is supplied the engine
        // reuses that session's parsed PE, disassembly, CFG, XRefs and strings
        // instead of redoing them.
        AntiEvasionResult Analyze(const std::string& filePath,
                                  const AntiEvasionOptions& options = {},
                                  const UnifiedAnalysisResult* precomputed = nullptr);

        // Static-only pass. Cheap enough to run inside ordinary /analyze.
        static std::vector<EvasionTechnique> DetectStatic(
            const std::string& filePath,
            const UnifiedAnalysisResult* precomputed = nullptr);

        // Compare two completed runs.
        static ExecutionDelta CompareRuns(const DifferentialRun& baseline,
                                          const DifferentialRun& alternate);

        // Deterministic fingerprint of one run.
        static BehaviorFingerprint Fingerprint(const EmulationResult& result);

        // Divergence score from the deltas. Documented in DRACULA_GUIDE.md.
        static int ComputeSensitivityScore(const std::vector<ExecutionDelta>& deltas,
                                           const std::vector<EvasionTechnique>& techniques,
                                           std::string& outLabel);
    };

} // namespace Dracula
