#include "core/entropy_analyzer.h"
#include "common/config.h"
#include <cmath>
#include <fstream>
#include <array>
#include <sstream>
#include <filesystem>
#include <iostream>
#include <cstring>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace Sandbox {

    double EntropyAnalyzer::CalculateShannonEntropy(const uint8_t* data, size_t length) {
        if (!data || length == 0) return 0.0;

        std::array<size_t, 256> byteCounts = {0};
        for (size_t i = 0; i < length; ++i) {
            byteCounts[data[i]]++;
        }

        double entropy = 0.0;
        double len = static_cast<double>(length);

        for (int i = 0; i < 256; ++i) {
            if (byteCounts[i] > 0) {
                double p = static_cast<double>(byteCounts[i]) / len;
                entropy -= p * std::log2(p);
            }
        }

        return entropy;
    }

    BinaryPackingAnalysis EntropyAnalyzer::AnalyzeBinary(const std::string& filePath) {
        BinaryPackingAnalysis analysis;
        analysis.overallEntropy = 0.0;
        analysis.isPacked = false;
        analysis.detectedPacker = "None (Native Binary)";

        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            analysis.indicators.push_back("Failed to open binary file for entropy analysis.");
            return analysis;
        }

        file.seekg(0, std::ios::end);
        size_t fileSize = static_cast<size_t>(file.tellg());
        file.seekg(0, std::ios::beg);

        if (fileSize < sizeof(IMAGE_DOS_HEADER)) {
            analysis.indicators.push_back("File too small to be a valid PE.");
            return analysis;
        }

        std::vector<uint8_t> buffer(fileSize);
        file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
        file.close();

        // 1. Overall Entropy Calculation
        analysis.overallEntropy = CalculateShannonEntropy(buffer.data(), fileSize);
        if (analysis.overallEntropy > 7.1) {
            analysis.isPacked = true;
            analysis.indicators.push_back("Overall file entropy is unusually high (> 7.1), indicating encryption/compression.");
        }

        // 2. Parse PE Headers (Supporting both 32-bit and 64-bit PEs)
        auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew <= 0 ||
            static_cast<size_t>(dosHeader->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > fileSize) {
            return analysis;
        }

        const uint8_t* pNt = buffer.data() + dosHeader->e_lfanew;
        auto ntSig = *reinterpret_cast<const DWORD*>(pNt);
        if (ntSig != IMAGE_NT_SIGNATURE) {
            return analysis;
        }

        auto fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(pNt + sizeof(DWORD));
        bool is64Bit = (fileHeader->Machine == IMAGE_FILE_MACHINE_AMD64);

        WORD numSections = fileHeader->NumberOfSections;
        const IMAGE_SECTION_HEADER* sectionHeader = nullptr;

        if (is64Bit) {
            if (static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > fileSize) return analysis;
            auto nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(pNt);
            sectionHeader = IMAGE_FIRST_SECTION(nt64);
        } else {
            if (static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > fileSize) return analysis;
            auto nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(pNt);
            sectionHeader = IMAGE_FIRST_SECTION(nt32);
        }

        for (WORD i = 0; i < numSections; ++i) {
            PESectionEntropy sec;
            char nameBuf[9] = {0};
            std::memcpy(nameBuf, sectionHeader[i].Name, 8);
            sec.name = nameBuf;
            sec.virtualAddress = sectionHeader[i].VirtualAddress;
            sec.virtualSize = sectionHeader[i].Misc.VirtualSize;
            sec.rawSize = sectionHeader[i].SizeOfRawData;
            sec.isExecutable = (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            sec.isWritable = (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

            // Compute section entropy if data is present
            if (sectionHeader[i].PointerToRawData + sectionHeader[i].SizeOfRawData <= fileSize && sectionHeader[i].SizeOfRawData > 0) {
                const uint8_t* secData = buffer.data() + sectionHeader[i].PointerToRawData;
                sec.entropy = CalculateShannonEntropy(secData, sectionHeader[i].SizeOfRawData);
            } else {
                sec.entropy = 0.0;
            }

            // Detect packed section indicators
            sec.isPacked = (sec.entropy > 7.0) || (sec.isExecutable && sec.isWritable);
            if (sec.isPacked) {
                analysis.isPacked = true;
                if (sec.isExecutable && sec.isWritable) {
                    analysis.indicators.push_back("Section [" + sec.name + "] has RWX (Read/Write/Execute) permissions (common in unpacker stubs).");
                }
                if (sec.entropy > 7.0) {
                    analysis.indicators.push_back("Section [" + sec.name + "] has high entropy: " + std::to_string(sec.entropy));
                }
            }

            // Check for known packer section names
            std::string sName = sec.name;
            if (sName.find("UPX") != std::string::npos) {
                analysis.detectedPacker = "UPX Packer";
                analysis.isPacked = true;
            } else if (sName.find(".vmp") != std::string::npos) {
                analysis.detectedPacker = "VMProtect";
                analysis.isPacked = true;
            } else if (sName.find("themida") != std::string::npos) {
                analysis.detectedPacker = "Themida / WinLicense";
                analysis.isPacked = true;
            } else if (sName.find(".aspack") != std::string::npos) {
                analysis.detectedPacker = "ASPack";
                analysis.isPacked = true;
            } else if (sName.find(".MPRESS") != std::string::npos) {
                analysis.detectedPacker = "MPRESS";
                analysis.isPacked = true;
            }

            analysis.sections.push_back(sec);
        }

        // 3. YARA rule scanning
        const auto& toolsCfg = ConfigManager::Instance().GetToolsConfig();
        std::string yaraResult = RunYaraScan(filePath, toolsCfg.yaraRulesPath);
        if (!yaraResult.empty()) {
            analysis.isPacked = true;
            analysis.detectedPacker = yaraResult;
            analysis.indicators.push_back("YARA Rule Match: " + yaraResult);
        }

        return analysis;
    }

    std::string EntropyAnalyzer::RunYaraScan(const std::string& binaryPath, const std::string& yaraRulePath) {
        const auto& toolsCfg = ConfigManager::Instance().GetToolsConfig();
        std::string yaraExe = toolsCfg.yaraExecutable;

        if (!std::filesystem::exists(yaraExe) || !std::filesystem::exists(yaraRulePath)) {
            return "";
        }

        std::string cmd = "\"" + yaraExe + "\" \"" + yaraRulePath + "\" \"" + binaryPath + "\" 2>nul";
        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) return "";

        char buffer[256];
        std::string result = "";
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        _pclose(pipe);

        std::istringstream iss(result);
        std::string matchedRule;
        if (iss >> matchedRule) {
            return matchedRule;
        }

        return "";
    }

} // namespace Sandbox
