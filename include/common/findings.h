#pragma once

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <chrono>
#include <sstream>

namespace Dracula {

    // ─── Finding Severity & Confidence ──────────────────────────────────────────
    enum class FindingSeverity {
        Info,
        Low,
        Medium,
        High,
        Critical
    };

    inline const char* SeverityToString(FindingSeverity sev) {
        switch (sev) {
            case FindingSeverity::Info:     return "INFO";
            case FindingSeverity::Low:      return "LOW";
            case FindingSeverity::Medium:   return "MEDIUM";
            case FindingSeverity::High:     return "HIGH";
            case FindingSeverity::Critical: return "CRITICAL";
            default:                        return "UNKNOWN";
        }
    }

    inline FindingSeverity StringToSeverity(const std::string& str) {
        if (str == "LOW") return FindingSeverity::Low;
        if (str == "MEDIUM") return FindingSeverity::Medium;
        if (str == "HIGH") return FindingSeverity::High;
        if (str == "CRITICAL") return FindingSeverity::Critical;
        return FindingSeverity::Info;
    }

    enum class FindingConfidence {
        Low,
        Medium,
        High
    };

    inline const char* ConfidenceToString(FindingConfidence conf) {
        switch (conf) {
            case FindingConfidence::Low:    return "LOW";
            case FindingConfidence::Medium: return "MEDIUM";
            case FindingConfidence::High:   return "HIGH";
            default:                        return "UNKNOWN";
        }
    }

    // ─── Individual Finding / Evidence ─────────────────────────────────────────
    struct Finding {
        std::string       id;            // e.g. "SEC_NO_ASLR", "EMU_ANTI_DEBUG"
        std::string       category;      // e.g. "Security", "AntiAnalysis", "Packing", "Injection"
        FindingSeverity   severity = FindingSeverity::Info;
        FindingConfidence confidence = FindingConfidence::Medium;

        uint64_t          virtualAddress = 0;
        uint64_t          rva = 0;

        std::string       title;
        std::string       description;
        std::string       evidence;
        std::string       source;        // e.g. "PE Inspector", "Unicorn HLE", "Disassembler"

        std::vector<std::string> tags;   // e.g. "MITRE:T1055", "ASLR"
    };

    // ─── Sample Metadata ───────────────────────────────────────────────────────
    struct SampleMetadata {
        std::string filePath;
        std::string fileName;
        uint64_t    fileSize = 0;
        std::string sha256;
        std::string md5;
        std::string magic;
        std::string architecture = "Unknown"; // "x86", "x64", etc.
        std::string subsystem = "Unknown";    // "Console", "GUI", "Native", etc.
        uint64_t    entryPointRva = 0;
        uint64_t    imageBase = 0;
        uint32_t    sectionCount = 0;
        bool        is64Bit = false;
        bool        isDll = false;
    };

    // ─── Security Mitigations ──────────────────────────────────────────────────
    struct SecurityMitigations {
        bool hasAslr = false;            // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        bool hasHighEntropyAslr = false; // IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        bool hasDep = false;             // IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        bool hasCfg = false;             // IMAGE_DLLCHARACTERISTICS_GUARD_CF
        bool hasSeh = true;              // !(IMAGE_DLLCHARACTERISTICS_NO_SEH)
        bool hasTls = false;
        bool hasAuthenticode = false;
        bool hasRwxSections = false;
        bool isDotNet = false;
        std::vector<std::string> details;
    };

    // ─── Section Details ───────────────────────────────────────────────────────
    struct SectionInfo {
        std::string name;
        uint64_t    virtualAddress = 0;
        uint32_t    virtualSize = 0;
        uint32_t    rawAddress = 0;
        uint32_t    rawSize = 0;
        uint32_t    characteristics = 0;
        double      entropy = 0.0;
        bool        isExecutable = false;
        bool        isWritable = false;
        bool        isReadable = false;
        bool        isHighEntropy = false;
    };

    // ─── Imports & Exports ────────────────────────────────────────────────────
    struct ImportEntry {
        std::string dllName;
        std::string functionName;
        uint32_t    ordinal = 0;
        uint64_t    iatRva = 0;
        bool        isDangerous = false;
        std::string riskDescription;
    };

    struct ExportEntry {
        std::string functionName;
        uint32_t    ordinal = 0;
        uint64_t    rva = 0;
        uint64_t    forwarderRva = 0;
        std::string forwarderName;
    };

    struct TlsCallbackEntry {
        uint64_t rva = 0;
        uint64_t va = 0;
    };

    // ─── Extracted String ─────────────────────────────────────────────────────
    enum class StringCategory {
        Generic,
        Url,
        IPv4,
        IPv6,
        FilePath,
        RegistryKey,
        DllName,
        CommandFragment,
        SuspiciousApi
    };

    inline const char* StringCategoryToString(StringCategory cat) {
        switch (cat) {
            case StringCategory::Url:             return "URL";
            case StringCategory::IPv4:            return "IPv4";
            case StringCategory::IPv6:            return "IPv6";
            case StringCategory::FilePath:        return "FILEPATH";
            case StringCategory::RegistryKey:     return "REGISTRY";
            case StringCategory::DllName:         return "DLL";
            case StringCategory::CommandFragment: return "COMMAND";
            case StringCategory::SuspiciousApi:   return "SUSPICIOUS_API";
            default:                              return "GENERIC";
        }
    }

    struct ExtractedString {
        std::string    value;
        uint64_t       fileOffset = 0;
        uint64_t       rva = 0;
        bool           isWide = false;
        StringCategory category = StringCategory::Generic;
    };

    // ─── Disassembly & Control Flow ───────────────────────────────────────────
    struct DisassembledInstruction {
        uint64_t    address = 0;
        uint64_t    rva = 0;
        std::string bytesHex;
        std::string mnemonic;
        std::string operands;
        uint32_t    size = 0;
        bool        isBranch = false;
        bool        isConditional = false;
        bool        isCall = false;
        bool        isReturn = false;
        bool        isInterrupt = false;
        uint64_t    targetAddress = 0;
        uint64_t    targetRva = 0;
        std::string comment;
    };

    struct BasicBlock {
        uint64_t startAddress = 0;
        uint64_t endAddress = 0;
        uint64_t startRva = 0;
        uint32_t size = 0;
        std::vector<DisassembledInstruction> instructions;
        std::vector<uint64_t> successorAddresses;
        std::vector<uint64_t> predecessorAddresses;
        std::string terminatorMnemonic;
    };

    struct FunctionGraph {
        std::string name;
        uint64_t    entryAddress = 0;
        uint64_t    entryRva = 0;
        uint32_t    totalInstructions = 0;
        std::map<uint64_t, BasicBlock> blocks;
        std::vector<uint64_t> directCallTargets;
    };

    // ─── Emulation Result & HLE ───────────────────────────────────────────────
    enum class EmulationStopReason {
        NormalExit,
        InstructionLimit,
        Timeout,
        InvalidMemory,
        UnsupportedApi,
        UnhandledException,
        ExplicitStop
    };

    inline const char* StopReasonToString(EmulationStopReason r) {
        switch (r) {
            case EmulationStopReason::NormalExit:         return "NormalExit";
            case EmulationStopReason::InstructionLimit:   return "InstructionLimit";
            case EmulationStopReason::Timeout:            return "Timeout";
            case EmulationStopReason::InvalidMemory:      return "InvalidMemory";
            case EmulationStopReason::UnsupportedApi:     return "UnsupportedApi";
            case EmulationStopReason::UnhandledException: return "UnhandledException";
            case EmulationStopReason::ExplicitStop:       return "ExplicitStop";
            default:                                      return "Unknown";
        }
    }

    struct HleCallRecord {
        std::string library;
        std::string apiName;
        uint64_t    callerAddress = 0;
        uint64_t    callerRva = 0;
        std::vector<uint64_t> arguments;
        uint64_t    returnValue = 0;
        bool        wasHandled = false;
        std::string details;
    };

    struct EmulationResult {
        bool                success = false;
        EmulationStopReason stopReason = EmulationStopReason::NormalExit;
        uint64_t            instructionsExecuted = 0;
        uint64_t            startAddress = 0;
        uint64_t            stopAddress = 0;
        std::map<std::string, uint64_t> registers;
        std::vector<HleCallRecord>      hleCalls;
        std::vector<DisassembledInstruction> trace;
        std::string         errorMessage;
    };

    // ─── Unified Analysis Result ──────────────────────────────────────────────
    struct UnifiedAnalysisResult {
        SampleMetadata                 sample;
        SecurityMitigations            mitigations;
        std::vector<SectionInfo>       sections;
        double                         overallEntropy = 0.0;
        bool                           isPacked = false;
        std::string                    detectedPacker;
        std::vector<ImportEntry>       imports;
        std::vector<ExportEntry>       exports;
        std::vector<TlsCallbackEntry>  tlsCallbacks;
        std::vector<ExtractedString>   strings;
        std::vector<std::string>       yaraMatches;
        std::vector<FunctionGraph>     functions;
        EmulationResult                emulation;
        std::vector<Finding>           findings;

        int                            threatScore = 0; // 0 to 100
        std::string                    threatLevel = "Clean"; // Clean, Low, Medium, High, Critical
        std::vector<std::string>       threatReasoning;
        std::vector<std::string>       mitreAttackTechniques;

        int64_t                        analysisDurationMs = 0;
        std::string                    timestampIso;

        // Serialization
        std::string ToJson() const;
        std::string ToMarkdown() const;
        std::string ToAnsiSummary() const;
    };

} // namespace Dracula
