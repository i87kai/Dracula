#include "core/disassembler.h"
#include <capstone/capstone.h>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace Dracula {

    Disassembler::Disassembler(Architecture arch)
        : m_arch(arch), m_handle(0), m_handleValid(false) {
        InitEngine();
    }

    Disassembler::~Disassembler() {
        CloseEngine();
    }

    Disassembler::Disassembler(Disassembler&& other) noexcept
        : m_arch(other.m_arch), m_handle(other.m_handle), m_handleValid(other.m_handleValid) {
        other.m_handle = 0;
        other.m_handleValid = false;
    }

    Disassembler& Disassembler::operator=(Disassembler&& other) noexcept {
        if (this != &other) {
            CloseEngine();
            m_arch = other.m_arch;
            m_handle = other.m_handle;
            m_handleValid = other.m_handleValid;
            other.m_handle = 0;
            other.m_handleValid = false;
        }
        return *this;
    }

    void Disassembler::InitEngine() {
        csh handle = 0;
        cs_mode mode = (m_arch == Architecture::X86_64) ? CS_MODE_64 : CS_MODE_32;
        if (cs_open(CS_ARCH_X86, mode, &handle) == CS_ERR_OK) {
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
            m_handle = static_cast<uint64_t>(handle);
            m_handleValid = true;
        }
    }

    void Disassembler::CloseEngine() {
        if (m_handleValid && m_handle != 0) {
            csh handle = static_cast<csh>(m_handle);
            cs_close(&handle);
            m_handle = 0;
            m_handleValid = false;
        }
    }

    std::vector<DisassembledInstruction> Disassembler::Disassemble(
        const uint8_t* code,
        size_t size,
        uint64_t baseAddress,
        uint64_t baseRva
    ) {
        std::vector<DisassembledInstruction> result;
        if (!m_handleValid || code == nullptr || size == 0) {
            return result;
        }

        csh handle = static_cast<csh>(m_handle);
        cs_insn* insn = nullptr;
        size_t count = cs_disasm(handle, code, size, baseAddress, 0, &insn);

        if (count > 0 && insn != nullptr) {
            result.reserve(count);
            for (size_t i = 0; i < count; ++i) {
                DisassembledInstruction d;
                d.address = insn[i].address;
                d.rva = baseRva + (insn[i].address - baseAddress);
                d.size = insn[i].size;
                d.bytes.assign(insn[i].bytes, insn[i].bytes + insn[i].size);

                std::ostringstream bh;
                for (size_t b = 0; b < insn[i].size; ++b) {
                    bh << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(insn[i].bytes[b]) << " ";
                }
                d.bytesHex = bh.str();
                if (!d.bytesHex.empty() && d.bytesHex.back() == ' ') d.bytesHex.pop_back();

                d.mnemonic = insn[i].mnemonic ? insn[i].mnemonic : "";
                d.operands = insn[i].op_str ? insn[i].op_str : "";

                cs_detail* detail = insn[i].detail;
                if (detail != nullptr) {
                    if (cs_insn_group(handle, &insn[i], CS_GRP_JUMP)) {
                        d.isBranch = true;
                        d.isConditional = (insn[i].id != X86_INS_JMP);
                    }
                    if (cs_insn_group(handle, &insn[i], CS_GRP_CALL)) {
                        d.isCall = true;
                    }
                    if (cs_insn_group(handle, &insn[i], CS_GRP_RET)) {
                        d.isReturn = true;
                    }

                    // Direct branch / call target resolution from immediate
                    if (detail->x86.op_count > 0 && detail->x86.operands[0].type == X86_OP_IMM) {
                        d.targetAddress = static_cast<uint64_t>(detail->x86.operands[0].imm);
                    }

                    // RIP-relative address resolution
                    for (int op = 0; op < detail->x86.op_count; ++op) {
                        if (detail->x86.operands[op].type == X86_OP_MEM &&
                            detail->x86.operands[op].mem.base == X86_REG_RIP) {
                            d.targetAddress = insn[i].address + insn[i].size + detail->x86.operands[op].mem.disp;
                            break;
                        }
                    }
                }

                result.push_back(std::move(d));
            }

            cs_free(insn, count);
        }

        return result;
    }

    bool Disassembler::DisassembleOne(
        const uint8_t* code,
        size_t size,
        uint64_t address,
        DisassembledInstruction& outInst
    ) {
        if (!m_handleValid || code == nullptr || size == 0) return false;

        csh handle = static_cast<csh>(m_handle);
        cs_insn* insn = nullptr;
        size_t count = cs_disasm(handle, code, size, address, 1, &insn);

        if (count > 0 && insn != nullptr) {
            outInst.address = insn[0].address;
            outInst.size = insn[0].size;
            outInst.bytes.assign(insn[0].bytes, insn[0].bytes + insn[0].size);

            std::ostringstream bh;
            for (size_t b = 0; b < insn[0].size; ++b) {
                bh << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(insn[0].bytes[b]) << " ";
            }
            outInst.bytesHex = bh.str();
            if (!outInst.bytesHex.empty() && outInst.bytesHex.back() == ' ') outInst.bytesHex.pop_back();

            outInst.mnemonic = insn[0].mnemonic ? insn[0].mnemonic : "";
            outInst.operands = insn[0].op_str ? insn[0].op_str : "";

            cs_detail* detail = insn[0].detail;
            if (detail != nullptr) {
                if (cs_insn_group(handle, &insn[0], CS_GRP_JUMP)) {
                    outInst.isBranch = true;
                    outInst.isConditional = (insn[0].id != X86_INS_JMP);
                }
                if (cs_insn_group(handle, &insn[0], CS_GRP_CALL)) {
                    outInst.isCall = true;
                }
                if (cs_insn_group(handle, &insn[0], CS_GRP_RET)) {
                    outInst.isReturn = true;
                }
                if (detail->x86.op_count > 0 && detail->x86.operands[0].type == X86_OP_IMM) {
                    outInst.targetAddress = static_cast<uint64_t>(detail->x86.operands[0].imm);
                }
                for (int op = 0; op < detail->x86.op_count; ++op) {
                    if (detail->x86.operands[op].type == X86_OP_MEM &&
                        detail->x86.operands[op].mem.base == X86_REG_RIP) {
                        outInst.targetAddress = insn[0].address + insn[0].size + detail->x86.operands[op].mem.disp;
                        break;
                    }
                }
            }

            cs_free(insn, count);
            return true;
        }

        return false;
    }

    std::string Disassembler::FormatInstruction(const DisassembledInstruction& inst, bool colored) {
        std::ostringstream ss;

        // Address
        if (colored) ss << "\033[90m";
        ss << "0x" << std::hex << std::setw(12) << std::setfill('0') << inst.address << "  ";
        if (colored) ss << "\033[0m";

        // Hex bytes (up to 7 bytes shown cleanly)
        std::string hexStr;
        for (size_t i = 0; i < std::min<size_t>(inst.bytes.size(), 7); ++i) {
            std::ostringstream bs;
            bs << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(inst.bytes[i]) << " ";
            hexStr += bs.str();
        }
        ss << std::left << std::setw(22) << std::setfill(' ') << hexStr;

        // Mnemonic
        if (colored) {
            if (inst.isCall) ss << "\033[1;32m";
            else if (inst.isBranch && inst.isConditional) ss << "\033[1;33m";
            else if (inst.isBranch) ss << "\033[1;36m";
            else if (inst.isReturn) ss << "\033[1;31m";
            else ss << "\033[1m";
        }
        ss << std::left << std::setw(8) << inst.mnemonic;
        if (colored) ss << "\033[0m";

        // Operands
        ss << " " << inst.operands;

        // Target comment if resolved
        if (inst.targetAddress != 0) {
            if (colored) ss << " \033[90m";
            ss << " ; target = 0x" << std::hex << inst.targetAddress << std::dec;
            if (colored) ss << "\033[0m";
        }

        return ss.str();
    }

} // namespace Dracula
