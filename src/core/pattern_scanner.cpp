#include "core/pattern_scanner.h"
#include <sstream>
#include <fstream>
#include <cctype>
#include <algorithm>

namespace Dracula {

    PatternScanner::PatternScanner() = default;
    PatternScanner::~PatternScanner() = default;

    bool PatternScanner::ParsePattern(const std::string& patternStr, std::vector<PatternByte>& outPattern) {
        outPattern.clear();
        std::istringstream ss(patternStr);
        std::string token;

        while (ss >> token) {
            if (token == "?" || token == "??" || token == "*") {
                outPattern.push_back({ 0, true });
            } else {
                try {
                    uint8_t byteVal = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
                    outPattern.push_back({ byteVal, false });
                } catch (...) {
                    return false;
                }
            }
        }

        return !outPattern.empty();
    }

    std::vector<size_t> PatternScanner::Scan(const uint8_t* data, size_t size, const std::vector<PatternByte>& pattern) {
        std::vector<size_t> matches;
        if (!data || size == 0 || pattern.empty() || size < pattern.size()) return matches;

        size_t patLen = pattern.size();
        size_t maxScan = size - patLen;

        for (size_t i = 0; i <= maxScan; ++i) {
            bool matched = true;
            for (size_t j = 0; j < patLen; ++j) {
                if (!pattern[j].isWildcard && data[i + j] != pattern[j].value) {
                    matched = false;
                    break;
                }
            }
            if (matched) {
                matches.push_back(i);
            }
        }

        return matches;
    }

    std::vector<size_t> PatternScanner::Scan(const uint8_t* data, size_t size, const std::string& patternStr) {
        std::vector<PatternByte> pattern;
        if (!ParsePattern(patternStr, pattern)) return {};
        return Scan(data, size, pattern);
    }

    std::vector<size_t> PatternScanner::ScanFile(const std::string& filePath, const std::string& patternStr) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) return {};

        std::streamsize size = file.tellg();
        if (size <= 0) return {};

        file.seekg(0, std::ios::beg);
        std::vector<uint8_t> buffer(static_cast<size_t>(size));
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) return {};

        return Scan(buffer.data(), buffer.size(), patternStr);
    }

} // namespace Dracula
