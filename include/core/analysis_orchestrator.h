#pragma once

#include "common/findings.h"
#include "core/pe_inspector.h"
#include "core/entropy_analyzer.h"
#include "core/strings_analyzer.h"
#include "core/disassembler.h"
#include "core/cfg_analyzer.h"
#include "core/pattern_scanner.h"
#include "core/unicorn_analyzer.h"
#include "core/threat_evaluator.h"

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Dracula {

    struct OrchestratorOptions {
        bool enableEmulation = true;
        bool strictSandbox = false;
        AntiDebugPolicy antiDebugPolicy = AntiDebugPolicy::Bypass;
        size_t maxStringsLength = 4;
        uint64_t maxEmulationInstructions = 5000;
        std::string yaraRulesPath = "rules/packers.yar";
    };

    class AnalysisOrchestrator {
    public:
        AnalysisOrchestrator();
        ~AnalysisOrchestrator();

        // Run complete unified static + emulation analysis on a file
        UnifiedAnalysisResult AnalyzeFile(
            const std::string& filePath,
            const OrchestratorOptions& options = {}
        );

        // Run complete unified analysis on an in-memory buffer
        UnifiedAnalysisResult AnalyzeMemory(
            const uint8_t* data,
            size_t size,
            const std::string& sampleName = "memory_sample.bin",
            const OrchestratorOptions& options = {}
        );

        // Run dynamic QEMU VM sandbox analysis
        UnifiedAnalysisResult RunDynamicSandbox(
            const std::string& filePath,
            uint32_t timeoutSeconds = 60
        );
    };

} // namespace Dracula
