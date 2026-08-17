#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>

namespace Dracula {
namespace Format {

    // Format integer value as 0x-prefixed lowercase hexadecimal (e.g. 4191 -> "0x105f", 0 -> "0x0")
    inline std::string Hex(uint64_t val) {
        std::ostringstream ss;
        ss << "0x" << std::hex << val;
        return ss.str();
    }

    // Format integer value as 0x-prefixed zero-padded lowercase hexadecimal
    inline std::string HexWidth(uint64_t val, int width) {
        std::ostringstream ss;
        ss << "0x" << std::hex << std::setw(width) << std::setfill('0') << val;
        return ss.str();
    }

    // Format RVA as "0x..."
    inline std::string Rva(uint64_t rva) {
        return Hex(rva);
    }

    // Format Virtual Address as "0x..."
    inline std::string Va(uint64_t va) {
        return Hex(va);
    }

    // Format file offset as "0x..."
    inline std::string FileOffset(uint64_t off) {
        return Hex(off);
    }

    // Format function name from RVA as "sub_<hex>" (e.g. 4191 / 0x105f -> "sub_105f")
    inline std::string FunctionName(uint64_t rva) {
        std::ostringstream ss;
        ss << "sub_" << std::hex << rva;
        return ss.str();
    }

} // namespace Format
} // namespace Dracula
