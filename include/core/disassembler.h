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

        Disassembler(const Disassembler&) = delete;
        Disassembler& operator=(const Disassembler&) = delete;
        Disassembler(Disassembler&& other) noexcept;
        Disassembler& operator=(Disassembler&& other) noexcept;

        // Disassemble a buffer of raw machine code
        std::vector<DisassembledInstruction> Disassemble(const uint8_t* code, size_t size, uint64_t baseAddress = 0, uint64_t baseRva = 0);

        // Disassemble a single instruction at code pointer
        bool DisassembleOne(const uint8_t* code, size_t size, uint64_t address, DisassembledInstruction& outInst);

        // Format instruction as colored/aligned string
        static std::string FormatInstruction(const DisassembledInstruction& inst, bool colored = false);

        Architecture GetArchitecture() const { return m_arch; }
        bool IsValid() const { return m_handleValid; }

    private:
        Architecture m_arch;
        uint64_t m_handle = 0; // csh handle
        bool m_handleValid = false;

        void InitEngine();
        void CloseEngine();
    };

} // namespace Dracula
