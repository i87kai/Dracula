#include "core/xref_analyzer.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <unordered_map>

namespace Dracula {

    std::vector<XRefEntry> XrefAnalyzer::ExtractXrefs(
        const std::vector<DisassembledInstruction>& instructions,
        const PeInspector& inspector,
        const std::vector<ExtractedString>& strings
    ) {
        std::vector<XRefEntry> xrefs;
        const auto& meta = inspector.GetMetadata();
        uint64_t imageBase = meta.imageBase ? meta.imageBase : 0x140000000ULL;
        const auto& imports = inspector.GetImports();
        const auto& sections = inspector.GetSections();

        // Index imports by IAT VA and RVA
        std::unordered_map<uint64_t, std::string> importMap;
        for (const auto& imp : imports) {
            importMap[imp.iatRva] = imp.dllName + "!" + imp.functionName;
            importMap[imageBase + imp.iatRva] = imp.dllName + "!" + imp.functionName;
        }

        // Index strings by RVA (with tolerance for sub-string offsets)
        std::vector<std::pair<uint64_t, std::string>> stringList;
        for (const auto& s : strings) {
            if (s.rva != 0) {
                stringList.emplace_back(s.rva, s.value);
            }
        }

        for (const auto& inst : instructions) {
            if (inst.targetAddress == 0) continue;

            uint64_t targetVa = inst.targetAddress;
            uint64_t targetRva = (targetVa >= imageBase) ? (targetVa - imageBase) : targetVa;

            XRefEntry xr;
            xr.fromAddress = inst.address;
            xr.fromRva = inst.rva;
            xr.toAddress = targetVa;
            xr.toRva = targetRva;
            xr.sourceInstruction = inst.mnemonic + " " + inst.operands;

            // 1. Check if target matches an Import Table entry
            auto impIt = importMap.find(targetRva);
            if (impIt == importMap.end()) {
                impIt = importMap.find(targetVa);
            }
            if (impIt != importMap.end()) {
                xr.type = XRefType::ImportCall;
                xr.targetName = impIt->second;
                xrefs.push_back(xr);
                continue;
            }

            // 2. Check if target matches an Extracted String
            bool foundString = false;
            for (const auto& [strRva, strVal] : stringList) {
                if (targetRva >= strRva && targetRva < strRva + strVal.size() + 2) {
                    xr.type = XRefType::StringRef;
                    xr.targetName = "\"" + strVal + "\"";
                    xrefs.push_back(xr);
                    foundString = true;
                    break;
                }
            }
            if (foundString) continue;

            // 3. Check instruction type
            if (inst.isCall) {
                xr.type = XRefType::CodeCall;
                std::ostringstream ss;
                ss << "sub_" << std::hex << targetRva;
                xr.targetName = ss.str();
                xrefs.push_back(xr);
            } else if (inst.isBranch) {
                xr.type = XRefType::CodeJump;
                std::ostringstream ss;
                ss << "loc_" << std::hex << targetRva;
                xr.targetName = ss.str();
                xrefs.push_back(xr);
            } else {
                // 4. Check if target is inside a data section
                for (const auto& sec : sections) {
                    if (targetRva >= sec.virtualAddress && targetRva < sec.virtualAddress + sec.virtualSize) {
                        xr.type = XRefType::DataRef;
                        xr.targetName = sec.name + " + 0x" + std::to_string(targetRva - sec.virtualAddress);
                        xrefs.push_back(xr);
                        break;
                    }
                }
            }
        }

        return xrefs;
    }

    std::vector<XRefEntry> XrefAnalyzer::FindXrefsTo(
        uint64_t targetVaOrRva,
        const std::vector<XRefEntry>& allXrefs
    ) {
        std::vector<XRefEntry> matches;
        for (const auto& x : allXrefs) {
            if (x.toAddress == targetVaOrRva || x.toRva == targetVaOrRva) {
                matches.push_back(x);
            }
        }
        return matches;
    }

} // namespace Dracula
