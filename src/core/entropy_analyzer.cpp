#include "core/entropy_analyzer.h"
#include <fstream>
#include <cmath>
#include <vector>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <filesystem>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace Dracula {

    double EntropyAnalyzer::CalculateShannonEntropy(const uint8_t* data, size_t length) {
        if (!data || length == 0) return 0.0;

        uint64_t freq[256] = {0};
        for (size_t i = 0; i < length; ++i) {
            freq[data[i]]++;
        }

        double entropy = 0.0;
        double total = static_cast<double>(length);

        for (int i = 0; i < 256; ++i) {
            if (freq[i] > 0) {
                double p = static_cast<double>(freq[i]) / total;
                entropy -= p * (std::log(p) / std::log(2.0));
            }
        }

        return entropy;
    }

    double EntropyAnalyzer::CalculateFileEntropy(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) return 0.0;

        std::streamsize size = file.tellg();
        if (size <= 0) return 0.0;

        file.seekg(0, std::ios::beg);
        std::vector<uint8_t> buffer(static_cast<size_t>(size));
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) return 0.0;

        return CalculateShannonEntropy(buffer.data(), buffer.size());
    }

    BinaryPackingAnalysis EntropyAnalyzer::AnalyzeBuffer(const uint8_t* data, size_t size) {
        BinaryPackingAnalysis result;
        if (!data || size < sizeof(IMAGE_DOS_HEADER)) return result;

        result.overallEntropy = CalculateShannonEntropy(data, size);
        if (result.overallEntropy >= 7.2) {
            result.isPacked = true;
            result.indicators.push_back("Overall file entropy is high (> 7.20 / 8.00)");
        }

        const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return result;
        if (dos->e_lfanew < 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > size) return result;

        size_t ntOffset = static_cast<size_t>(dos->e_lfanew);
        const DWORD* ntSig = reinterpret_cast<const DWORD*>(data + ntOffset);
        if (*ntSig != IMAGE_NT_SIGNATURE) return result;

        const IMAGE_FILE_HEADER* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(data + ntOffset + sizeof(DWORD));
        size_t optHeaderOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        if (optHeaderOffset + sizeof(WORD) > size) return result;

        WORD optMagic = *reinterpret_cast<const WORD*>(data + optHeaderOffset);
        size_t sectionTableOffset = optHeaderOffset + fileHeader->SizeOfOptionalHeader;

        for (WORD i = 0; i < fileHeader->NumberOfSections; ++i) {
            size_t secOffset = sectionTableOffset + (i * sizeof(IMAGE_SECTION_HEADER));
            if (secOffset + sizeof(IMAGE_SECTION_HEADER) > size) break;

            const IMAGE_SECTION_HEADER* sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(data + secOffset);
            PESectionEntropy pse;
            char nameBuf[9] = {};
            std::memcpy(nameBuf, sec->Name, 8);
            pse.name = nameBuf;
            pse.virtualAddress = sec->VirtualAddress;
            pse.virtualSize = sec->Misc.VirtualSize;
            pse.rawSize = sec->SizeOfRawData;
            pse.isExecutable = (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            pse.isWritable = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

            if (sec->PointerToRawData < size && sec->SizeOfRawData > 0) {
                size_t actualSize = std::min<size_t>(sec->SizeOfRawData, size - sec->PointerToRawData);
                pse.entropy = CalculateShannonEntropy(data + sec->PointerToRawData, actualSize);
                pse.isPacked = (pse.entropy >= 7.2);
            }

            if (pse.isPacked) {
                result.isPacked = true;
                result.indicators.push_back("Section '" + pse.name + "' has high entropy: " + std::to_string(pse.entropy));

                Finding f;
                f.id = "ENTROPY_PACKED_SECTION_" + pse.name;
                f.category = "Packing";
                f.severity = FindingSeverity::Medium;
                f.confidence = FindingConfidence::Medium;
                f.rva = pse.virtualAddress;
                f.title = "High Entropy Section: " + pse.name;
                f.description = "Section exhibits entropy of " + std::to_string(pse.entropy) + " / 8.00 (likely packed or encrypted)";
                f.evidence = "Entropy = " + std::to_string(pse.entropy);
                f.source = "Entropy Analyzer";
                f.tags = {"Packing", "Entropy", "MITRE:T1027"};
                result.findings.push_back(f);
            }

            // Known packer section name detection
            std::string secUpper = pse.name;
            std::transform(secUpper.begin(), secUpper.end(), secUpper.begin(), ::toupper);
            if (secUpper.find("UPX") != std::string::npos) {
                result.isPacked = true;
                result.detectedPacker = "UPX Packer";
            } else if (secUpper.find(".MPRESS") != std::string::npos) {
                result.isPacked = true;
                result.detectedPacker = "MPRESS Packer";
            } else if (secUpper.find("ASPACK") != std::string::npos) {
                result.isPacked = true;
                result.detectedPacker = "ASPack Protector";
            } else if (secUpper.find(".THEMIDA") != std::string::npos || secUpper.find(".VMP") != std::string::npos) {
                result.isPacked = true;
                result.detectedPacker = "Themida / VMProtect Virtualizer";
            }

            result.sections.push_back(pse);
        }

        if (!result.detectedPacker.empty()) {
            Finding f;
            f.id = "PACKER_DETECTED";
            f.category = "Packing";
            f.severity = FindingSeverity::High;
            f.confidence = FindingConfidence::High;
            f.title = "Known Packer Signature Detected: " + result.detectedPacker;
            f.description = "Binary contains standard section names or signatures associated with " + result.detectedPacker;
            f.evidence = "Packer: " + result.detectedPacker;
            f.source = "Entropy Analyzer";
            f.tags = {"Packer", "AntiAnalysis", "MITRE:T1027.002"};
            result.findings.push_back(f);
        }

        return result;
    }

    BinaryPackingAnalysis EntropyAnalyzer::AnalyzeBinary(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) return {};

        std::streamsize size = file.tellg();
        if (size <= 0) return {};

        file.seekg(0, std::ios::beg);
        std::vector<uint8_t> buffer(static_cast<size_t>(size));
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) return {};

        return AnalyzeBuffer(buffer.data(), buffer.size());
    }

    std::string EntropyAnalyzer::RunYaraScan(const std::string& binaryPath, const std::string& yaraRulePath) {
        std::string yaraExe = "tools/yara64.exe";
        if (!std::filesystem::exists(yaraExe)) {
            yaraExe = "yara64.exe";
            if (!std::filesystem::exists(yaraExe)) return "";
        }

        if (!std::filesystem::exists(yaraRulePath) || !std::filesystem::exists(binaryPath)) return "";

        std::string cmd = "\"" + std::filesystem::absolute(yaraExe).string() + "\" \"" +
                          std::filesystem::absolute(yaraRulePath).string() + "\" \"" +
                          std::filesystem::absolute(binaryPath).string() + "\" 2>NUL";
        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) return "";

        char buffer[256];
        std::string result;
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        _pclose(pipe);
        return result;
    }

} // namespace Dracula
