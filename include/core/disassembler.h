#pragma once

#include "common/findings.h"
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace Dracula {

    enum class Architecture {
        X86_32,
        X86_64
    };

    class Disassembler {
    public:
        explicit Disassembler(Architecture arch = Architecture::X86_64);
        ~Disassembler();

        // Disassemble a buffer of raw machine code
        std::vector<DisassembledInstruction> Disassemble(const uint8_t* code, size_t size, uint64_t baseAddress = 0, uint64_t baseRva = 0);

        // Disassemble a single instruction at code pointer
        bool DisassembleOne(const uint8_t* code, size_t size, uint64_t address, DisassembledInstruction& outInst);

        // Format instruction as colored/aligned string
        static std::string FormatInstruction(const DisassembledInstruction& inst, bool colored = false);

    private:
        Architecture m_arch;
    };

} // namespace Dracula
