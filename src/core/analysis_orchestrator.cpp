#include "core/analysis_orchestrator.h"
#include "core/dynamic_vm_analyzer.h"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <filesystem>

namespace Dracula {

    static std::string GetCurrentIsoTimestamp() {
        auto now = std::chrono::system_clock::now();
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf;
#ifdef _WIN32
        gmtime_s(&tm_buf, &now_c);
#else
        gmtime_r(&now_c, &tm_buf);
#endif
        char buf[64];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
        return std::string(buf);
    }

    AnalysisOrchestrator::AnalysisOrchestrator() = default;
    AnalysisOrchestrator::~AnalysisOrchestrator() = default;

    UnifiedAnalysisResult AnalysisOrchestrator::AnalyzeFile(const std::string& filePath, const OrchestratorOptions& options) {
        auto start = std::chrono::steady_clock::now();
        UnifiedAnalysisResult res;
        res.timestampIso = GetCurrentIsoTimestamp();

        // 1. Safe PE Parsing & Hashes
        PeInspector inspector;
        std::string peErr;
        if (!inspector.LoadFromFile(filePath, peErr)) {
            res.sample.filePath = filePath;
            res.sample.fileName = std::filesystem::path(filePath).filename().string();
            res.sample.fileSize = std::filesystem::exists(filePath) ? std::filesystem::file_size(filePath) : 0;

            Finding f;
            f.id = "PARSE_ERROR";
            f.category = "Error";
            f.severity = FindingSeverity::High;
            f.confidence = FindingConfidence::High;
            f.title = "PE Parser Error: " + peErr;
            f.description = "Failed to parse binary as standard PE format.";
            f.evidence = peErr;
            f.source = "PE Inspector";
            res.findings.push_back(f);

            auto end = std::chrono::steady_clock::now();
            res.analysisDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            auto threat = ThreatEvaluator::Evaluate(res.findings, res.sample, res.mitigations, res.overallEntropy, res.isPacked);
            res.threatScore = threat.score;
            res.threatLevel = threat.level;
            res.threatReasoning = threat.reasoning;
            return res;
        }

        res.sample = inspector.GetMetadata();
        res.mitigations = inspector.GetMitigations();
        res.sections = inspector.GetSections();
        res.imports = inspector.GetImports();
        res.exports = inspector.GetExports();
        res.tlsCallbacks = inspector.GetTlsCallbacks();

        // Add PE Inspector Findings
        auto peFindings = inspector.GenerateFindings();
        res.findings.insert(res.findings.end(), peFindings.begin(), peFindings.end());

        // 2. Entropy & Packing Analysis
        auto packingInfo = EntropyAnalyzer::AnalyzeBuffer(inspector.GetBuffer(), inspector.GetBufferSize());
        res.overallEntropy = packingInfo.overallEntropy;
        res.isPacked = packingInfo.isPacked;
        res.detectedPacker = packingInfo.detectedPacker;
        res.findings.insert(res.findings.end(), packingInfo.findings.begin(), packingInfo.findings.end());

        // 3. Strings Extraction & Classification
        StringsAnalyzer stringsAnalyzer;
        res.strings = stringsAnalyzer.ExtractStrings(inspector.GetBuffer(), inspector.GetBufferSize(), options.maxStringsLength);
        auto strFindings = stringsAnalyzer.GenerateFindings(res.strings);
        res.findings.insert(res.findings.end(), strFindings.begin(), strFindings.end());

        // 4. YARA Scanning
        if (!options.yaraRulesPath.empty() && std::filesystem::exists(options.yaraRulesPath)) {
            std::string yaraOut = EntropyAnalyzer::RunYaraScan(filePath, options.yaraRulesPath);
            if (!yaraOut.empty()) {
                std::istringstream yss(yaraOut);
                std::string line;
                while (std::getline(yss, line)) {
                    if (!line.empty()) {
                        res.yaraMatches.push_back(line);

                        Finding f;
                        f.id = "YARA_MATCH";
                        f.category = "Signatures";
                        f.severity = FindingSeverity::High;
                        f.confidence = FindingConfidence::High;
                        f.title = "YARA Rule Match: " + line;
                        f.description = "Matched signature rule from " + options.yaraRulesPath;
                        f.evidence = line;
                        f.source = "YARA 64";
                        f.tags = {"YARA", "Signature"};
                        res.findings.push_back(f);
                    }
                }
            }
        }

        // 5. Disassembly & Control Flow Graph around Entry Point
        if (res.sample.entryPointRva != 0) {
            uint64_t epOffset = inspector.RvaToFileOffset(res.sample.entryPointRva);
            if (epOffset < inspector.GetBufferSize()) {
                size_t epCodeSize = std::min<size_t>(0x2000, inspector.GetBufferSize() - epOffset);
                CfgAnalyzer cfgAnalyzer;
                Architecture arch = res.sample.is64Bit ? Architecture::X86_64 : Architecture::X86_32;
                uint64_t epVa = res.sample.imageBase + res.sample.entryPointRva;
                auto fg = cfgAnalyzer.BuildFunctionGraph(inspector.GetBuffer() + epOffset, epCodeSize, epVa, res.sample.entryPointRva, arch, 500);
                fg.name = "EntryPoint";
                res.functions.push_back(fg);
            }
        }

        // 6. Unicorn 2 CPU Emulation with Win32 HLE
        if (options.enableEmulation && res.sample.entryPointRva != 0) {
            UnicornAnalyzer emu;
            EmulationOptions emuOpts;
            emuOpts.maxInstructions = options.maxEmulationInstructions;
            emuOpts.strictSandbox = options.strictSandbox;
            emuOpts.antiDebugPolicy = options.antiDebugPolicy;

            std::vector<Finding> emuFindings;
            res.emulation = emu.EmulatePE(filePath, emuOpts, &emuFindings);
            res.findings.insert(res.findings.end(), emuFindings.begin(), emuFindings.end());
        }

        // 7. Evidence-Based Threat Scoring
        auto threat = ThreatEvaluator::Evaluate(res.findings, res.sample, res.mitigations, res.overallEntropy, res.isPacked);
        res.threatScore = threat.score;
        res.threatLevel = threat.level;
        res.threatReasoning = threat.reasoning;
        res.mitreAttackTechniques = threat.mitreTechniques;

        auto end = std::chrono::steady_clock::now();
        res.analysisDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        return res;
    }

    UnifiedAnalysisResult AnalysisOrchestrator::AnalyzeMemory(const uint8_t* data, size_t size, const std::string& sampleName, const OrchestratorOptions& options) {
        auto start = std::chrono::steady_clock::now();
        UnifiedAnalysisResult res;
        res.timestampIso = GetCurrentIsoTimestamp();

        PeInspector inspector;
        std::string peErr;
        if (!inspector.LoadFromMemory(data, size, peErr)) {
            res.sample.fileName = sampleName;
            res.sample.fileSize = size;

            Finding f;
            f.id = "PARSE_ERROR";
            f.category = "Error";
            f.severity = FindingSeverity::High;
            f.confidence = FindingConfidence::High;
            f.title = "PE Memory Parse Failed: " + peErr;
            f.evidence = peErr;
            f.source = "PE Inspector";
            res.findings.push_back(f);

            auto end = std::chrono::steady_clock::now();
            res.analysisDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            return res;
        }

        res.sample = inspector.GetMetadata();
        res.sample.fileName = sampleName;
        res.mitigations = inspector.GetMitigations();
        res.sections = inspector.GetSections();
        res.imports = inspector.GetImports();
        res.exports = inspector.GetExports();
        res.tlsCallbacks = inspector.GetTlsCallbacks();

        auto peFindings = inspector.GenerateFindings();
        res.findings.insert(res.findings.end(), peFindings.begin(), peFindings.end());

        auto packingInfo = EntropyAnalyzer::AnalyzeBuffer(data, size);
        res.overallEntropy = packingInfo.overallEntropy;
        res.isPacked = packingInfo.isPacked;
        res.detectedPacker = packingInfo.detectedPacker;
        res.findings.insert(res.findings.end(), packingInfo.findings.begin(), packingInfo.findings.end());

        StringsAnalyzer stringsAnalyzer;
        res.strings = stringsAnalyzer.ExtractStrings(data, size, options.maxStringsLength);
        auto strFindings = stringsAnalyzer.GenerateFindings(res.strings);
        res.findings.insert(res.findings.end(), strFindings.begin(), strFindings.end());

        auto threat = ThreatEvaluator::Evaluate(res.findings, res.sample, res.mitigations, res.overallEntropy, res.isPacked);
        res.threatScore = threat.score;
        res.threatLevel = threat.level;
        res.threatReasoning = threat.reasoning;
        res.mitreAttackTechniques = threat.mitreTechniques;

        auto end = std::chrono::steady_clock::now();
        res.analysisDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        return res;
    }

    UnifiedAnalysisResult AnalysisOrchestrator::RunDynamicSandbox(const std::string& filePath, uint32_t timeoutSeconds) {
        // Run static analysis first
        OrchestratorOptions opts;
        opts.enableEmulation = false; // Let QEMU do the execution
        auto res = AnalyzeFile(filePath, opts);

        // Orchestrate QEMU Dynamic VM Execution
        Sandbox::DynamicVMAnalyzer vmAnalyzer;
        Sandbox::VMConfig vmConfig;
        Sandbox::TraceOptions traceOpts;
        traceOpts.executionTimeoutSeconds = timeoutSeconds;

        if (vmAnalyzer.Initialize(vmConfig, traceOpts)) {
            vmAnalyzer.RunAnalysis(filePath);
            auto report = vmAnalyzer.GetReport();

            // Normalize dynamic events into findings
            auto dynamicFindings = ThreatEvaluator::NormalizeSandboxEvents(report.events);
            res.findings.insert(res.findings.end(), dynamicFindings.begin(), dynamicFindings.end());

            // Re-evaluate threat with dynamic evidence included!
            auto threat = ThreatEvaluator::Evaluate(res.findings, res.sample, res.mitigations, res.overallEntropy, res.isPacked);
            res.threatScore = threat.score;
            res.threatLevel = threat.level;
            res.threatReasoning = threat.reasoning;
            res.mitreAttackTechniques = threat.mitreTechniques;
        }

        return res;
    }

} // namespace Dracula
