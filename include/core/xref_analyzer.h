#pragma once

#include "common/findings.h"
#include "core/pe_inspector.h"
#include "core/strings_analyzer.h"
#include <vector>
#include <string>

namespace Dracula {

    class XrefAnalyzer {
    public:
        XrefAnalyzer() = default;
        ~XrefAnalyzer() = default;

        // Extract all cross-references from disassembled instructions
        static std::vector<XRefEntry> ExtractXrefs(
            const std::vector<DisassembledInstruction>& instructions,
            const PeInspector& inspector,
            const std::vector<ExtractedString>& strings
        );

        // Find all cross references pointing to a specific target address or RVA
        static std::vector<XRefEntry> FindXrefsTo(
            uint64_t targetVaOrRva,
            const std::vector<XRefEntry>& allXrefs
        );
    };

} // namespace Dracula
