#include "core/pattern_scanner.h"
#include "common/input_validator.h"
#include <sstream>
#include <fstream>
#include <cctype>
#include <algorithm>

namespace Dracula {

    PatternScanner::PatternScanner() = default;
    PatternScanner::~PatternScanner() = default;

    PatternParseResult PatternScanner::ParsePatternStrict(const std::string& patternStr) {
        PatternParseResult res;
        std::istringstream ss(patternStr);
        std::string token;
        size_t tokenIndex = 0;

        while (ss >> token) {
            tokenIndex++;

            if (token == "?" || token == "??" || token == "*") {
                res.pattern.push_back({ 0, true });
                continue;
            }

            // Hex byte tokens must be exactly 2 hex characters
            if (token.size() != 2) {
                res.status = PatternParseStatus::InvalidTokenLength;
                res.errorTokenIndex = tokenIndex;
                res.errorToken = token;
                res.errorMessage = "Invalid hex token '" + token + "' at pattern token " +
                                   std::to_string(tokenIndex) +
                                   ". Expected two hexadecimal digits or ?? wildcard.";
                res.pattern.clear();
                return res;
            }

            char c0 = token[0];
            char c1 = token[1];
            if (!std::isxdigit(static_cast<unsigned char>(c0)) ||
                !std::isxdigit(static_cast<unsigned char>(c1))) {
                res.status = PatternParseStatus::InvalidHexDigit;
                res.errorTokenIndex = tokenIndex;
                res.errorToken = token;
                res.errorMessage = "Invalid hex token '" + token + "' at pattern token " +
                                   std::to_string(tokenIndex) +
                                   ". Expected two hexadecimal digits or ?? wildcard.";
                res.pattern.clear();
                return res;
            }

            try {
                uint8_t byteVal = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
                res.pattern.push_back({ byteVal, false });
            } catch (...) {
                res.status = PatternParseStatus::InvalidToken;
                res.errorTokenIndex = tokenIndex;
                res.errorToken = token;
                res.errorMessage = "Invalid hex token '" + token + "' at pattern token " +
                                   std::to_string(tokenIndex) +
                                   ". Expected two hexadecimal digits or ?? wildcard.";
                res.pattern.clear();
                return res;
            }
        }

        if (res.pattern.empty()) {
            res.status = PatternParseStatus::EmptyPattern;
            res.errorMessage = "Pattern cannot be empty.";
            return res;
        }

        res.status = PatternParseStatus::Valid;
        res.errorMessage.clear();
        return res;
    }

    bool PatternScanner::ParsePattern(const std::string& patternStr, std::vector<PatternByte>& outPattern) {
        auto res = ParsePatternStrict(patternStr);
        if (!res.IsValid()) {
            outPattern.clear();
            return false;
        }
        outPattern = std::move(res.pattern);
        return true;
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

    std::vector<size_t> PatternScanner::Scan(const uint8_t* data, size_t size, const std::string& patternStr, std::string* outError) {
        auto parseRes = ParsePatternStrict(patternStr);
        if (!parseRes.IsValid()) {
            if (outError) *outError = parseRes.errorMessage;
            return {};
        }
        return Scan(data, size, parseRes.pattern);
    }

    std::vector<size_t> PatternScanner::ScanFile(const std::string& filePath, const std::vector<PatternByte>& pattern, std::string* outError) {
        auto val = InputValidator::ValidateFile(filePath);
        if (!val.IsValid()) {
            if (outError) *outError = val.errorMessage;
            return {};
        }

        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            if (outError) *outError = "Failed to open file: " + filePath;
            return {};
        }

        std::vector<uint8_t> buffer(static_cast<size_t>(val.fileSize));
        if (!file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(val.fileSize))) {
            if (outError) *outError = "Failed to read file contents: " + filePath;
            return {};
        }

        return Scan(buffer.data(), buffer.size(), pattern);
    }

    std::vector<size_t> PatternScanner::ScanFile(const std::string& filePath, const std::string& patternStr, std::string* outError) {
        auto parseRes = ParsePatternStrict(patternStr);
        if (!parseRes.IsValid()) {
            if (outError) *outError = parseRes.errorMessage;
            return {};
        }

        return ScanFile(filePath, parseRes.pattern, outError);
    }

} // namespace Dracula
