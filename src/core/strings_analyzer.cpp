#include "core/strings_analyzer.h"
#include <cctype>
#include <algorithm>
#include <regex>

namespace Dracula {

    StringsAnalyzer::StringsAnalyzer() = default;
    StringsAnalyzer::~StringsAnalyzer() = default;

    static bool IsPrintableAscii(uint8_t c) {
        return (c >= 0x20 && c <= 0x7E);
    }

    StringCategory StringsAnalyzer::ClassifyString(const std::string& str) {
        std::string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

        // URL
        if (lower.rfind("http://", 0) == 0 || lower.rfind("https://", 0) == 0 || lower.rfind("ftp://", 0) == 0) {
            return StringCategory::Url;
        }

        // Registry Key
        if (str.rfind("HKEY_", 0) == 0 || str.rfind("HKLM\\", 0) == 0 || str.rfind("HKCU\\", 0) == 0 ||
            lower.find("software\\microsoft\\windows\\currentversion\\run") != std::string::npos) {
            return StringCategory::RegistryKey;
        }

        // File Path
        if ((str.size() >= 3 && std::isalpha(static_cast<unsigned char>(str[0])) && str[1] == ':' && (str[2] == '\\' || str[2] == '/')) ||
            lower.find("\\system32\\") != std::string::npos || lower.find("\\temp\\") != std::string::npos || lower.find("\\appdata\\") != std::string::npos) {
            return StringCategory::FilePath;
        }

        // PowerShell / Command
        if (lower.find("powershell") != std::string::npos || lower.find("cmd.exe") != std::string::npos ||
            lower.find("-nop -exec bypass") != std::string::npos || lower.find("certutil -urlcache") != std::string::npos ||
            lower.find("bitsadmin /transfer") != std::string::npos) {
            return StringCategory::CommandFragment;
        }

        // DLL Name
        if (str.size() >= 4 && lower.rfind(".dll") == (str.size() - 4)) {
            return StringCategory::DllName;
        }

        // Suspicious API text
        if (str == "VirtualAlloc" || str == "WriteProcessMemory" || str == "CreateRemoteThread" ||
            str == "IsDebuggerPresent" || str == "NtUnmapViewOfSection" || str == "SetWindowsHookExA" ||
            str == "QueueUserAPC") {
            return StringCategory::SuspiciousApi;
        }

        // IPv4 regex check (only if 7 to 15 chars)
        if (str.size() >= 7 && str.size() <= 15) {
            static const std::regex ipRegex(R"(^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$)");
            if (std::regex_match(str, ipRegex)) {
                return StringCategory::IPv4;
            }
        }

        return StringCategory::Generic;
    }

    std::vector<ExtractedString> StringsAnalyzer::ExtractStrings(const uint8_t* data, size_t size, size_t minLength) {
        std::vector<ExtractedString> out;
        if (!data || size < minLength) return out;

        // 1. ASCII String Extraction
        std::string currentAscii;
        size_t startOffset = 0;

        for (size_t i = 0; i < size; ++i) {
            uint8_t c = data[i];
            if (IsPrintableAscii(c)) {
                if (currentAscii.empty()) startOffset = i;
                currentAscii.push_back(static_cast<char>(c));
            } else {
                if (currentAscii.size() >= minLength) {
                    ExtractedString es;
                    es.value = currentAscii;
                    es.fileOffset = startOffset;
                    es.isWide = false;
                    es.category = ClassifyString(currentAscii);
                    out.push_back(es);
                }
                currentAscii.clear();
            }
        }
        if (currentAscii.size() >= minLength) {
            ExtractedString es;
            es.value = currentAscii;
            es.fileOffset = startOffset;
            es.isWide = false;
            es.category = ClassifyString(currentAscii);
            out.push_back(es);
        }

        // 2. UTF-16LE Unicode String Extraction
        std::string currentWide;
        size_t wideStartOffset = 0;

        for (size_t i = 0; i + 1 < size; i += 2) {
            uint8_t charByte = data[i];
            uint8_t nullByte = data[i + 1];

            if (IsPrintableAscii(charByte) && nullByte == 0x00) {
                if (currentWide.empty()) wideStartOffset = i;
                currentWide.push_back(static_cast<char>(charByte));
            } else {
                if (currentWide.size() >= minLength) {
                    ExtractedString es;
                    es.value = currentWide;
                    es.fileOffset = wideStartOffset;
                    es.isWide = true;
                    es.category = ClassifyString(currentWide);
                    out.push_back(es);
                }
                currentWide.clear();
            }
        }
        if (currentWide.size() >= minLength) {
            ExtractedString es;
            es.value = currentWide;
            es.fileOffset = wideStartOffset;
            es.isWide = true;
            es.category = ClassifyString(currentWide);
            out.push_back(es);
        }

        return out;
    }

    std::vector<ExtractedString> StringsAnalyzer::ExtractStrings(const std::vector<uint8_t>& buffer, size_t minLength) {
        return ExtractStrings(buffer.data(), buffer.size(), minLength);
    }

    std::vector<Finding> StringsAnalyzer::GenerateFindings(const std::vector<ExtractedString>& strings) const {
        std::vector<Finding> out;

        for (const auto& s : strings) {
            if (s.category == StringCategory::Url) {
                Finding f;
                f.id = "STR_EMBEDDED_URL";
                f.category = "Network / C2";
                f.severity = FindingSeverity::Medium;
                f.confidence = FindingConfidence::High;
                f.title = "Embedded URL Detected: " + s.value;
                f.description = "Extracted hardcoded URL indicator from binary string tables.";
                f.evidence = s.value + " (offset: 0x" + std::to_string(s.fileOffset) + ")";
                f.source = "Strings Analyzer";
                f.tags = {"URL", "C2", "MITRE:T1071"};
                out.push_back(f);
            } else if (s.category == StringCategory::CommandFragment) {
                Finding f;
                f.id = "STR_COMMAND_EXECUTION";
                f.category = "Execution";
                f.severity = FindingSeverity::High;
                f.confidence = FindingConfidence::High;
                f.title = "Command-Line / PowerShell Execution String: " + s.value;
                f.description = "Extracted command execution fragment indicating script invocation or downloader behavior.";
                f.evidence = s.value;
                f.source = "Strings Analyzer";
                f.tags = {"Execution", "PowerShell", "MITRE:T1059"};
                out.push_back(f);
            } else if (s.category == StringCategory::RegistryKey && s.value.find("Run") != std::string::npos) {
                Finding f;
                f.id = "STR_PERSISTENCE_REGISTRY";
                f.category = "Persistence";
                f.severity = FindingSeverity::Medium;
                f.confidence = FindingConfidence::High;
                f.title = "Autorun Persistence Registry Key: " + s.value;
                f.description = "References Windows Run/Autorun registry location commonly used for persistence.";
                f.evidence = s.value;
                f.source = "Strings Analyzer";
                f.tags = {"Persistence", "Registry", "MITRE:T1547"};
                out.push_back(f);
            }
        }

        return out;
    }

} // namespace Dracula
