#include "core/disassembler.h"
#include <iomanip>
#include <sstream>
#include <cstring>
#include <algorithm>

namespace Dracula {

    Disassembler::Disassembler(Architecture arch) : m_arch(arch) {}
    Disassembler::~Disassembler() = default;

    // Registers table for 32/64-bit ModR/M decoding
    static const char* kRegs64[] = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };
    static const char* kRegs32[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d" };
    static const char* kRegs16[] = { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di" };
    static const char* kRegs8[]  = { "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh" };

    static const char* kJccMnemonics[] = {
        "jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "ja",
        "js", "jns", "jpe", "jpo", "jl", "jge", "jle", "jg"
    };

    bool Disassembler::DisassembleOne(const uint8_t* code, size_t size, uint64_t address, DisassembledInstruction& outInst) {
        if (!code || size == 0) return false;

        outInst = {};
        outInst.address = address;

        size_t idx = 0;
        bool hasRex = false;
        uint8_t rex = 0;
        bool hasOpSize = false;
        bool hasAddrSize = false;
        bool is64 = (m_arch == Architecture::X86_64);

        // 1. Prefix decoding
        while (idx < size) {
            uint8_t b = code[idx];
            if (b == 0x66) { hasOpSize = true; idx++; }
            else if (b == 0x67) { hasAddrSize = true; idx++; }
            else if (b == 0xF0) { outInst.mnemonic = "lock "; idx++; }
            else if (b == 0xF2) { outInst.mnemonic = "repne "; idx++; }
            else if (b == 0xF3) { outInst.mnemonic = "repe "; idx++; }
            else if (b == 0x64 || b == 0x65 || b == 0x2E || b == 0x3E || b == 0x26 || b == 0x36) {
                // Segment prefix (e.g. gs: or fs:)
                if (b == 0x65) outInst.comment = "gs:";
                else if (b == 0x64) outInst.comment = "fs:";
                idx++;
            }
            else if (is64 && (b >= 0x40 && b <= 0x4F)) {
                hasRex = true;
                rex = b;
                idx++;
            }
            else {
                break;
            }
        }

        if (idx >= size) return false;

        uint8_t op = code[idx++];
        outInst.mnemonic += "unknown";
        outInst.isBranch = false;
        outInst.isCall = false;
        outInst.isReturn = false;
        outInst.isConditional = false;
        outInst.isInterrupt = false;

        // 2. Opcode decoding
        if (op == 0x90) {
            outInst.mnemonic = "nop";
        }
        else if (op == 0xCC) {
            outInst.mnemonic = "int3";
            outInst.isInterrupt = true;
        }
        else if (op == 0xCD && idx < size) {
            outInst.mnemonic = "int";
            outInst.operands = "0x" + std::to_string(code[idx++]);
            outInst.isInterrupt = true;
        }
        else if (op == 0xC3) {
            outInst.mnemonic = "ret";
            outInst.isReturn = true;
        }
        else if (op == 0xC2 && idx + 1 < size) {
            uint16_t imm = *reinterpret_cast<const uint16_t*>(code + idx);
            idx += 2;
            outInst.mnemonic = "ret";
            outInst.operands = "0x" + std::to_string(imm);
            outInst.isReturn = true;
        }
        else if (op == 0xE8 && idx + 3 < size) {
            int32_t disp = *reinterpret_cast<const int32_t*>(code + idx);
            idx += 4;
            outInst.mnemonic = "call";
            outInst.isCall = true;
            outInst.targetAddress = address + idx + disp;
            std::ostringstream ss;
            ss << "0x" << std::hex << outInst.targetAddress;
            outInst.operands = ss.str();
        }
        else if (op == 0xE9 && idx + 3 < size) {
            int32_t disp = *reinterpret_cast<const int32_t*>(code + idx);
            idx += 4;
            outInst.mnemonic = "jmp";
            outInst.isBranch = true;
            outInst.targetAddress = address + idx + disp;
            std::ostringstream ss;
            ss << "0x" << std::hex << outInst.targetAddress;
            outInst.operands = ss.str();
        }
        else if (op == 0xEB && idx < size) {
            int8_t disp = static_cast<int8_t>(code[idx++]);
            outInst.mnemonic = "jmp";
            outInst.isBranch = true;
            outInst.targetAddress = address + idx + disp;
            std::ostringstream ss;
            ss << "0x" << std::hex << outInst.targetAddress;
            outInst.operands = ss.str();
        }
        else if (op >= 0x70 && op <= 0x7F && idx < size) {
            int8_t disp = static_cast<int8_t>(code[idx++]);
            outInst.mnemonic = kJccMnemonics[op - 0x70];
            outInst.isBranch = true;
            outInst.isConditional = true;
            outInst.targetAddress = address + idx + disp;
            std::ostringstream ss;
            ss << "0x" << std::hex << outInst.targetAddress;
            outInst.operands = ss.str();
        }
        else if (op == 0x0F && idx < size) {
            uint8_t op2 = code[idx++];
            if (op2 >= 0x80 && op2 <= 0x8F && idx + 3 < size) {
                int32_t disp = *reinterpret_cast<const int32_t*>(code + idx);
                idx += 4;
                outInst.mnemonic = kJccMnemonics[op2 - 0x80];
                outInst.isBranch = true;
                outInst.isConditional = true;
                outInst.targetAddress = address + idx + disp;
                std::ostringstream ss;
                ss << "0x" << std::hex << outInst.targetAddress;
                outInst.operands = ss.str();
            }
            else if (op2 == 0x05) {
                outInst.mnemonic = "syscall";
                outInst.isInterrupt = true;
            }
            else if (op2 == 0x34) {
                outInst.mnemonic = "sysenter";
                outInst.isInterrupt = true;
            }
            else if (op2 == 0x1F && idx < size) {
                // Multi-byte NOP
                uint8_t modrm = code[idx++];
                if ((modrm & 0xC0) == 0x40 && idx < size) idx++;
                else if ((modrm & 0xC0) == 0x80 && idx + 3 < size) idx += 4;
                outInst.mnemonic = "nop";
            }
            else if (op2 == 0xB6 || op2 == 0xB7) { // MOVZX
                outInst.mnemonic = (op2 == 0xB6) ? "movzx" : "movzx";
                if (idx < size) {
                    uint8_t modrm = code[idx++];
                    int reg = (modrm >> 3) & 7;
                    int rm = modrm & 7;
                    outInst.operands = std::string(kRegs64[reg]) + ", " + std::string(kRegs8[rm]);
                }
            }
            else {
                outInst.mnemonic = "0f_" + std::to_string(op2);
            }
        }
        else if (op >= 0x50 && op <= 0x57) { // PUSH r64/r32
            int reg = (op - 0x50) + (hasRex && (rex & 1) ? 8 : 0);
            outInst.mnemonic = "push";
            outInst.operands = is64 ? kRegs64[reg] : kRegs32[reg];
        }
        else if (op >= 0x58 && op <= 0x5F) { // POP r64/r32
            int reg = (op - 0x58) + (hasRex && (rex & 1) ? 8 : 0);
            outInst.mnemonic = "pop";
            outInst.operands = is64 ? kRegs64[reg] : kRegs32[reg];
        }
        else if (op >= 0xB8 && op <= 0xBF) { // MOV r, imm
            int reg = (op - 0xB8) + (hasRex && (rex & 1) ? 8 : 0);
            outInst.mnemonic = "mov";
            if (is64 && hasRex && (rex & 8)) { // 64-bit imm
                if (idx + 7 < size) {
                    uint64_t imm = *reinterpret_cast<const uint64_t*>(code + idx);
                    idx += 8;
                    std::ostringstream ss;
                    ss << kRegs64[reg] << ", 0x" << std::hex << imm;
                    outInst.operands = ss.str();
                }
            } else {
                if (idx + 3 < size) {
                    uint32_t imm = *reinterpret_cast<const uint32_t*>(code + idx);
                    idx += 4;
                    std::ostringstream ss;
                    ss << (is64 ? kRegs64[reg] : kRegs32[reg]) << ", 0x" << std::hex << imm;
                    outInst.operands = ss.str();
                }
            }
        }
        else if (op == 0x89 || op == 0x8B) { // MOV r/m, r or MOV r, r/m
            outInst.mnemonic = "mov";
            if (idx < size) {
                uint8_t modrm = code[idx++];
                int reg = ((modrm >> 3) & 7) + (hasRex && (rex & 4) ? 8 : 0);
                int rm = (modrm & 7) + (hasRex && (rex & 1) ? 8 : 0);
                uint8_t mod = (modrm >> 6) & 3;

                if (mod == 3) {
                    const char* r1 = is64 ? kRegs64[reg] : kRegs32[reg];
                    const char* r2 = is64 ? kRegs64[rm] : kRegs32[rm];
                    outInst.operands = (op == 0x89) ? (std::string(r2) + ", " + r1) : (std::string(r1) + ", " + r2);
                } else if (mod == 0 && rm == 5 && is64) { // RIP-relative
                    if (idx + 3 < size) {
                        int32_t disp = *reinterpret_cast<const int32_t*>(code + idx);
                        idx += 4;
                        uint64_t target = address + idx + disp;
                        outInst.targetAddress = target;
                        std::ostringstream ss;
                        if (op == 0x89) ss << "[rip + 0x" << std::hex << disp << "], " << kRegs64[reg];
                        else ss << kRegs64[reg] << ", [rip + 0x" << std::hex << disp << "] ; 0x" << target;
                        outInst.operands = ss.str();
                    }
                } else {
                    if (mod == 1 && idx < size) idx++;
                    else if (mod == 2 && idx + 3 < size) idx += 4;
                    outInst.operands = std::string(kRegs64[reg]) + ", [memory]";
                }
            }
        }
        else if (op == 0x8D && idx < size) { // LEA
            outInst.mnemonic = "lea";
            uint8_t modrm = code[idx++];
            int reg = ((modrm >> 3) & 7) + (hasRex && (rex & 4) ? 8 : 0);
            int rm = (modrm & 7) + (hasRex && (rex & 1) ? 8 : 0);
            uint8_t mod = (modrm >> 6) & 3;

            if (mod == 0 && rm == 5 && is64 && idx + 3 < size) { // RIP-relative
                int32_t disp = *reinterpret_cast<const int32_t*>(code + idx);
                idx += 4;
                uint64_t target = address + idx + disp;
                outInst.targetAddress = target;
                std::ostringstream ss;
                ss << kRegs64[reg] << ", [rip + 0x" << std::hex << disp << "] ; 0x" << target;
                outInst.operands = ss.str();
            } else {
                if (mod == 1 && idx < size) idx++;
                else if (mod == 2 && idx + 3 < size) idx += 4;
                outInst.operands = std::string(kRegs64[reg]) + ", [memory]";
            }
        }
        else if (op == 0x31 || op == 0x33) { // XOR
            outInst.mnemonic = "xor";
            if (idx < size) {
                uint8_t modrm = code[idx++];
                int reg = ((modrm >> 3) & 7) + (hasRex && (rex & 4) ? 8 : 0);
                int rm = (modrm & 7) + (hasRex && (rex & 1) ? 8 : 0);
                const char* r = is64 ? kRegs64[reg] : kRegs32[reg];
                outInst.operands = std::string(r) + ", " + r;
            }
        }
        else if (op == 0x83 || op == 0x81) { // Arithmetic / Logic with imm
            if (idx < size) {
                uint8_t modrm = code[idx++];
                int opType = (modrm >> 3) & 7;
                int rm = (modrm & 7) + (hasRex && (rex & 1) ? 8 : 0);
                static const char* kAluOps[] = { "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp" };
                outInst.mnemonic = kAluOps[opType];
                if (op == 0x83 && idx < size) {
                    int8_t imm = static_cast<int8_t>(code[idx++]);
                    std::ostringstream ss;
                    ss << (is64 ? kRegs64[rm] : kRegs32[rm]) << ", 0x" << std::hex << (int)(uint8_t)imm;
                    outInst.operands = ss.str();
                } else if (op == 0x81 && idx + 3 < size) {
                    uint32_t imm = *reinterpret_cast<const uint32_t*>(code + idx);
                    idx += 4;
                    std::ostringstream ss;
                    ss << (is64 ? kRegs64[rm] : kRegs32[rm]) << ", 0x" << std::hex << imm;
                    outInst.operands = ss.str();
                }
            }
        }
        else if (op == 0xFF && idx < size) { // Group 5 (CALL r/m, JMP r/m, PUSH r/m, INC/DEC)
            uint8_t modrm = code[idx++];
            int opType = (modrm >> 3) & 7;
            int rm = (modrm & 7) + (hasRex && (rex & 1) ? 8 : 0);
            uint8_t mod = (modrm >> 6) & 3;

            if (opType == 2) { // CALL r/m
                outInst.mnemonic = "call";
                outInst.isCall = true;
                if (mod == 3) outInst.operands = is64 ? kRegs64[rm] : kRegs32[rm];
                else {
                    if (mod == 0 && rm == 5 && is64 && idx + 3 < size) {
                        int32_t disp = *reinterpret_cast<const int32_t*>(code + idx);
                        idx += 4;
                        outInst.targetAddress = address + idx + disp;
                        std::ostringstream ss;
                        ss << "qword ptr [rip + 0x" << std::hex << disp << "] ; 0x" << outInst.targetAddress;
                        outInst.operands = ss.str();
                    } else {
                        if (mod == 1 && idx < size) idx++;
                        else if (mod == 2 && idx + 3 < size) idx += 4;
                        outInst.operands = "[memory]";
                    }
                }
            } else if (opType == 4) { // JMP r/m
                outInst.mnemonic = "jmp";
                outInst.isBranch = true;
                if (mod == 3) outInst.operands = is64 ? kRegs64[rm] : kRegs32[rm];
                else outInst.operands = "[memory]";
            } else if (opType == 6) { // PUSH r/m
                outInst.mnemonic = "push";
                if (mod == 3) outInst.operands = is64 ? kRegs64[rm] : kRegs32[rm];
                else outInst.operands = "[memory]";
            } else {
                outInst.mnemonic = "ff_grp5";
            }
        }
        else {
            // Generic opcode fallback
            std::ostringstream ss;
            ss << "db 0x" << std::hex << std::setw(2) << std::setfill('0') << (int)op;
            outInst.mnemonic = ss.str();
        }

        outInst.size = static_cast<uint32_t>(idx);
        std::ostringstream hexStream;
        for (size_t b = 0; b < idx; ++b) {
            hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)code[b] << " ";
        }
        outInst.bytesHex = hexStream.str();

        return true;
    }

    std::vector<DisassembledInstruction> Disassembler::Disassemble(const uint8_t* code, size_t size, uint64_t baseAddress, uint64_t baseRva) {
        std::vector<DisassembledInstruction> instructions;
        if (!code || size == 0) return instructions;

        size_t offset = 0;
        while (offset < size) {
            DisassembledInstruction inst;
            if (!DisassembleOne(code + offset, size - offset, baseAddress + offset, inst)) {
                // If decoding fails, emit raw byte and advance 1 byte
                inst.address = baseAddress + offset;
                inst.rva = baseRva + offset;
                inst.size = 1;
                std::ostringstream ss;
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)code[offset];
                inst.bytesHex = ss.str();
                inst.mnemonic = "db 0x" + ss.str();
                instructions.push_back(inst);
                offset++;
            } else {
                inst.rva = baseRva + offset;
                instructions.push_back(inst);
                offset += inst.size;
            }
        }

        return instructions;
    }

    std::string Disassembler::FormatInstruction(const DisassembledInstruction& inst, bool colored) {
        std::ostringstream ss;
        if (colored) ss << "\033[90m";
        ss << "0x" << std::hex << std::setw(12) << std::setfill('0') << inst.address << "  ";
        if (colored) ss << "\033[36m";
        ss << std::left << std::setw(18) << std::setfill(' ') << inst.bytesHex;
        if (colored) {
            if (inst.isCall) ss << "\033[1;92m";
            else if (inst.isBranch) ss << "\033[1;93m";
            else if (inst.isReturn) ss << "\033[1;91m";
            else ss << "\033[1;37m";
        }
        ss << std::left << std::setw(8) << inst.mnemonic << " ";
        if (colored) ss << "\033[0m";
        ss << inst.operands;
        if (!inst.comment.empty()) {
            if (colored) ss << " \033[90m; " << inst.comment << "\033[0m";
            else ss << " ; " << inst.comment;
        }
        return ss.str();
    }

} // namespace Dracula
