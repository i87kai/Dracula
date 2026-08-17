#pragma once

#include "common/findings.h"
#include "core/disassembler.h"
#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstdint>

namespace Dracula {

    class CfgAnalyzer {
    public:
        CfgAnalyzer();
        ~CfgAnalyzer();

        // Build a Control Flow Graph starting at an entry point
        FunctionGraph BuildFunctionGraph(
            const uint8_t* code,
            size_t codeSize,
            uint64_t funcAddress,
            uint64_t funcRva,
            Architecture arch = Architecture::X86_64,
            size_t maxInstructions = 1000
        );

        // Render function CFG graph as a formatted text block
        static std::string RenderGraph(const FunctionGraph& fg, bool colored = false);

    private:
        void TraverseBlock(
            const uint8_t* code,
            size_t codeSize,
            uint64_t blockAddress,
            uint64_t blockRva,
            Architecture arch,
            FunctionGraph& outGraph,
            std::set<uint64_t>& visited,
            size_t& instrCount,
            size_t maxInstructions
        );
    };

} // namespace Dracula
