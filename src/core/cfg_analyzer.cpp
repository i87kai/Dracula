#include "core/cfg_analyzer.h"
#include "common/format.h"
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <queue>

namespace Dracula {

    CfgAnalyzer::CfgAnalyzer() = default;
    CfgAnalyzer::~CfgAnalyzer() = default;

    FunctionGraph CfgAnalyzer::BuildFunctionGraph(
        const uint8_t* code,
        size_t codeSize,
        uint64_t funcAddress,
        uint64_t funcRva,
        Architecture arch,
        size_t maxInstructions
    ) {
        FunctionGraph graph;
        graph.name = Format::FunctionName(funcRva);
        graph.entryAddress = funcAddress;
        graph.entryRva = funcRva;

        if (!code || codeSize == 0) return graph;

        std::set<uint64_t> visited;
        size_t totalInstructions = 0;

        TraverseBlock(code, codeSize, funcAddress, funcRva, arch, graph, visited, totalInstructions, maxInstructions);

        graph.totalInstructions = static_cast<uint32_t>(totalInstructions);

        // Build predecessor addresses from successors
        for (const auto& [addr, block] : graph.blocks) {
            for (uint64_t succ : block.successorAddresses) {
                if (graph.blocks.find(succ) != graph.blocks.end()) {
                    graph.blocks[succ].predecessorAddresses.push_back(addr);
                }
            }
        }

        return graph;
    }

    void CfgAnalyzer::TraverseBlock(
        const uint8_t* code,
        size_t codeSize,
        uint64_t blockAddress,
        uint64_t blockRva,
        Architecture arch,
        FunctionGraph& outGraph,
        std::set<uint64_t>& visited,
        size_t& instrCount,
        size_t maxInstructions
    ) {
        if (visited.find(blockAddress) != visited.end()) return;
        if (blockAddress < outGraph.entryAddress || blockAddress >= outGraph.entryAddress + codeSize) return;
        if (instrCount >= maxInstructions) return;

        visited.insert(blockAddress);

        Disassembler disasm(arch);
        BasicBlock block;
        block.startAddress = blockAddress;
        block.startRva = blockRva;

        uint64_t currentAddress = blockAddress;
        size_t currentOffset = static_cast<size_t>(blockAddress - outGraph.entryAddress);

        while (currentOffset < codeSize && instrCount < maxInstructions) {
            DisassembledInstruction inst;
            if (!disasm.DisassembleOne(code + currentOffset, codeSize - currentOffset, currentAddress, inst)) {
                break;
            }

            inst.rva = blockRva + (currentAddress - blockAddress);
            block.instructions.push_back(inst);
            instrCount++;

            currentAddress += inst.size;
            currentOffset += inst.size;

            if (inst.isCall) {
                if (inst.targetAddress != 0) {
                    outGraph.directCallTargets.push_back(inst.targetAddress);
                }
                // Calls fall through to next instruction within same block
            }

            if (inst.isReturn || inst.isBranch || inst.isInterrupt) {
                block.terminatorMnemonic = inst.mnemonic;
                block.endAddress = currentAddress;
                block.size = static_cast<uint32_t>(block.endAddress - block.startAddress);

                if (inst.isConditional) {
                    // Two branch paths: target (True) and fallthrough (False)
                    if (inst.targetAddress != 0) {
                        block.successorAddresses.push_back(inst.targetAddress);
                    }
                    block.successorAddresses.push_back(currentAddress);

                    outGraph.blocks[block.startAddress] = block;

                    // Recurse into both branches
                    if (inst.targetAddress != 0) {
                        uint64_t targetRva = outGraph.entryRva + (inst.targetAddress - outGraph.entryAddress);
                        TraverseBlock(code, codeSize, inst.targetAddress, targetRva, arch, outGraph, visited, instrCount, maxInstructions);
                    }
                    uint64_t fallRva = outGraph.entryRva + (currentAddress - outGraph.entryAddress);
                    TraverseBlock(code, codeSize, currentAddress, fallRva, arch, outGraph, visited, instrCount, maxInstructions);
                    return;
                }
                else if (inst.isBranch && !inst.isConditional) {
                    // Unconditional jump: one target
                    if (inst.targetAddress != 0) {
                        block.successorAddresses.push_back(inst.targetAddress);
                    }
                    outGraph.blocks[block.startAddress] = block;

                    if (inst.targetAddress != 0) {
                        uint64_t targetRva = outGraph.entryRva + (inst.targetAddress - outGraph.entryAddress);
                        TraverseBlock(code, codeSize, inst.targetAddress, targetRva, arch, outGraph, visited, instrCount, maxInstructions);
                    }
                    return;
                }
                else if (inst.isReturn) {
                    // Leaf block: no successors
                    outGraph.blocks[block.startAddress] = block;
                    return;
                }
            }
        }

        block.endAddress = currentAddress;
        block.size = static_cast<uint32_t>(block.endAddress - block.startAddress);
        outGraph.blocks[block.startAddress] = block;
    }

    std::string CfgAnalyzer::RenderGraph(const FunctionGraph& fg, bool colored) {
        std::ostringstream ss;
        if (colored) ss << "\033[1;36m";
        ss << "======================================================================\n";
        ss << " FUNCTION CFG: " << fg.name << " @ 0x" << std::hex << fg.entryAddress
           << " (RVA 0x" << fg.entryRva << ") | Blocks: " << std::dec << fg.blocks.size()
           << " | Instructions: " << fg.totalInstructions << "\n";
        ss << "======================================================================\n";
        if (colored) ss << "\033[0m";

        for (const auto& [addr, block] : fg.blocks) {
            if (colored) ss << "\033[1;33m";
            ss << "\n[ BLOCK 0x" << std::hex << block.startAddress << " - 0x" << block.endAddress << " ]\n";
            if (colored) ss << "\033[0m";

            for (const auto& inst : block.instructions) {
                ss << "  " << Disassembler::FormatInstruction(inst, colored) << "\n";
            }

            if (!block.successorAddresses.empty()) {
                if (colored) ss << "\033[90m";
                ss << "  --> Successors: ";
                for (size_t i = 0; i < block.successorAddresses.size(); ++i) {
                    ss << "0x" << std::hex << block.successorAddresses[i]
                       << (i + 1 < block.successorAddresses.size() ? ", " : "");
                }
                ss << "\n";
                if (colored) ss << "\033[0m";
            }
        }

        return ss.str();
    }

} // namespace Dracula
