#include "core/pe_inspector.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cmath>
#include <algorithm>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#endif

namespace Dracula {

    // Helper hashing function using WinCrypt (or native fallback)
    static std::string ComputeHash(const uint8_t* data, size_t size, ALG_ID algId) {
#ifdef _WIN32
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        std::string result;

        if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            if (CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
                if (CryptHashData(hHash, data, static_cast<DWORD>(size), 0)) {
                    DWORD hashLen = 0;
                    DWORD lenSize = sizeof(DWORD);
                    if (CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashLen), &lenSize, 0)) {
                        std::vector<BYTE> hashBuf(hashLen);
                        if (CryptGetHashParam(hHash, HP_HASHVAL, hashBuf.data(), &hashLen, 0)) {
                            std::ostringstream ss;
                            for (BYTE b : hashBuf) {
                                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
                            }
                            result = ss.str();
                        }
                    }
                }
                CryptDestroyHash(hHash);
            }
            CryptReleaseContext(hProv, 0);
        }
        if (!result.empty()) return result;
#endif
        return "N/A";
    }

    std::string PeInspector::ComputeSha256(const uint8_t* data, size_t size) {
        if (!data || size == 0) return "";
        return ComputeHash(data, size, CALG_SHA_256);
    }

    std::string PeInspector::ComputeMd5(const uint8_t* data, size_t size) {
        if (!data || size == 0) return "";
        return ComputeHash(data, size, CALG_MD5);
    }

    PeInspector::PeInspector() = default;
    PeInspector::~PeInspector() = default;

    bool PeInspector::SafeRead(size_t offset, void* dest, size_t count) const {
        if (offset + count > m_rawBuffer.size() || offset + count < offset) {
            return false;
        }
        std::memcpy(dest, m_rawBuffer.data() + offset, count);
        return true;
    }

    std::string PeInspector::SafeReadString(size_t offset, size_t maxLen) const {
        if (offset >= m_rawBuffer.size()) return "";
        std::string str;
        for (size_t i = 0; i < maxLen && (offset + i) < m_rawBuffer.size(); ++i) {
            char c = static_cast<char>(m_rawBuffer[offset + i]);
            if (c == '\0') break;
            str.push_back(c);
        }
        return str;
    }

    bool PeInspector::LoadFromFile(const std::string& filePath, std::string& outError) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            outError = "Failed to open file: " + filePath;
            return false;
        }

        std::streamsize size = file.tellg();
        if (size <= 0) {
            outError = "File is empty: " + filePath;
            return false;
        }

        file.seekg(0, std::ios::beg);
        m_rawBuffer.resize(static_cast<size_t>(size));
        if (!file.read(reinterpret_cast<char*>(m_rawBuffer.data()), size)) {
            outError = "Failed to read file contents: " + filePath;
            return false;
        }

        m_metadata.filePath = filePath;
        size_t lastSlash = filePath.find_last_of("/\\");
        m_metadata.fileName = (lastSlash != std::string::npos) ? filePath.substr(lastSlash + 1) : filePath;
        m_metadata.fileSize = static_cast<uint64_t>(size);

        return ParsePE(outError);
    }

    bool PeInspector::LoadFromMemory(const uint8_t* data, size_t size, std::string& outError) {
        if (!data || size == 0) {
            outError = "Invalid memory buffer passed to PeInspector";
            return false;
        }

        m_rawBuffer.assign(data, data + size);
        m_metadata.filePath = "<in-memory>";
        m_metadata.fileName = "memory_buffer.bin";
        m_metadata.fileSize = size;

        return ParsePE(outError);
    }

    void PeInspector::ComputeHashes() {
        if (m_rawBuffer.empty()) return;
        m_metadata.sha256 = ComputeHash(m_rawBuffer.data(), m_rawBuffer.size(), CALG_SHA_256);
        m_metadata.md5 = ComputeHash(m_rawBuffer.data(), m_rawBuffer.size(), CALG_MD5);
    }

    bool PeInspector::ParsePE(std::string& outError) {
        m_isValid = false;
        m_sections.clear();
        m_imports.clear();
        m_exports.clear();
        m_tlsCallbacks.clear();

        ComputeHashes();

        // 1. Verify DOS Header
        if (m_rawBuffer.size() < sizeof(IMAGE_DOS_HEADER)) {
            outError = "Buffer too small for DOS Header (minimum 64 bytes required)";
            return false;
        }

        IMAGE_DOS_HEADER dosHeader;
        SafeRead(0, &dosHeader, sizeof(dosHeader));
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            outError = "Invalid DOS Signature (Expected 'MZ' 0x5A4D)";
            return false;
        }

        m_metadata.magic = "MZ";

        // 2. Locate NT Headers (e_lfanew)
        if (dosHeader.e_lfanew < 0 || static_cast<size_t>(dosHeader.e_lfanew) + sizeof(DWORD) > m_rawBuffer.size()) {
            outError = "Corrupt e_lfanew offset in DOS header";
            return false;
        }

        size_t ntOffset = static_cast<size_t>(dosHeader.e_lfanew);
        DWORD ntSignature = 0;
        SafeRead(ntOffset, &ntSignature, sizeof(ntSignature));
        if (ntSignature != IMAGE_NT_SIGNATURE) {
            outError = "Invalid NT Signature (Expected 'PE\\0\\0' 0x00004550)";
            return false;
        }

        // 3. Parse File Header
        size_t fileHeaderOffset = ntOffset + sizeof(DWORD);
        IMAGE_FILE_HEADER fileHeader;
        if (!SafeRead(fileHeaderOffset, &fileHeader, sizeof(fileHeader))) {
            outError = "Failed to read IMAGE_FILE_HEADER";
            return false;
        }

        m_metadata.sectionCount = fileHeader.NumberOfSections;
        m_metadata.isDll = (fileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

        if (fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            m_metadata.architecture = "x64 (AMD64)";
            m_metadata.is64Bit = true;
        } else if (fileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
            m_metadata.architecture = "x86 (i386)";
            m_metadata.is64Bit = false;
        } else if (fileHeader.Machine == 0xAA64) { // IMAGE_FILE_MACHINE_ARM64
            m_metadata.architecture = "ARM64";
            m_metadata.is64Bit = true;
        } else {
            m_metadata.architecture = "Unknown (0x" + std::to_string(fileHeader.Machine) + ")";
        }

        // 4. Parse Optional Header (32 vs 64 bit)
        size_t optHeaderOffset = fileHeaderOffset + sizeof(IMAGE_FILE_HEADER);
        WORD optMagic = 0;
        if (!SafeRead(optHeaderOffset, &optMagic, sizeof(optMagic))) {
            outError = "Failed to read Optional Header Magic";
            return false;
        }

        size_t sectionTableOffset = 0;
        uint16_t dllCharacteristics = 0;
        size_t dataDirOffset = 0;
        uint32_t numDataDirs = 0;

        if (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            IMAGE_OPTIONAL_HEADER64 opt64;
            if (!SafeRead(optHeaderOffset, &opt64, sizeof(opt64))) {
                outError = "Truncated IMAGE_OPTIONAL_HEADER64";
                return false;
            }
            m_metadata.entryPointRva = opt64.AddressOfEntryPoint;
            m_metadata.imageBase = opt64.ImageBase;
            dllCharacteristics = opt64.DllCharacteristics;
            dataDirOffset = optHeaderOffset + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
            numDataDirs = opt64.NumberOfRvaAndSizes;
            sectionTableOffset = optHeaderOffset + fileHeader.SizeOfOptionalHeader;

            switch (opt64.Subsystem) {
                case IMAGE_SUBSYSTEM_WINDOWS_GUI: m_metadata.subsystem = "Windows GUI"; break;
                case IMAGE_SUBSYSTEM_WINDOWS_CUI: m_metadata.subsystem = "Windows Console"; break;
                case IMAGE_SUBSYSTEM_NATIVE:      m_metadata.subsystem = "Native (Driver)"; break;
                default:                          m_metadata.subsystem = "Other (" + std::to_string(opt64.Subsystem) + ")"; break;
            }
        } else if (optMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            IMAGE_OPTIONAL_HEADER32 opt32;
            if (!SafeRead(optHeaderOffset, &opt32, sizeof(opt32))) {
                outError = "Truncated IMAGE_OPTIONAL_HEADER32";
                return false;
            }
            m_metadata.entryPointRva = opt32.AddressOfEntryPoint;
            m_metadata.imageBase = opt32.ImageBase;
            dllCharacteristics = opt32.DllCharacteristics;
            dataDirOffset = optHeaderOffset + offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
            numDataDirs = opt32.NumberOfRvaAndSizes;
            sectionTableOffset = optHeaderOffset + fileHeader.SizeOfOptionalHeader;

            switch (opt32.Subsystem) {
                case IMAGE_SUBSYSTEM_WINDOWS_GUI: m_metadata.subsystem = "Windows GUI"; break;
                case IMAGE_SUBSYSTEM_WINDOWS_CUI: m_metadata.subsystem = "Windows Console"; break;
                case IMAGE_SUBSYSTEM_NATIVE:      m_metadata.subsystem = "Native (Driver)"; break;
                default:                          m_metadata.subsystem = "Other (" + std::to_string(opt32.Subsystem) + ")"; break;
            }
        } else {
            outError = "Unsupported Optional Header Magic: 0x" + std::to_string(optMagic);
            return false;
        }

        // 5. Parse Mitigations
        ParseSecurityMitigations(dllCharacteristics, fileHeader.Characteristics);

        // 6. Parse Sections
        ParseSections(fileHeader.NumberOfSections, sectionTableOffset);

        // 7. Parse Data Directories (Imports, Exports, TLS)
        ParseDataDirectories(dataDirOffset, numDataDirs);

        m_isValid = true;
        return true;
    }

    void PeInspector::ParseSecurityMitigations(uint16_t dllCharacteristics, uint16_t characteristics) {
        m_mitigations.hasAslr = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
        m_mitigations.hasHighEntropyAslr = (dllCharacteristics & 0x0020) != 0; // IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        m_mitigations.hasDep = (dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
        m_mitigations.hasCfg = (dllCharacteristics & 0x4000) != 0; // IMAGE_DLLCHARACTERISTICS_GUARD_CF
        m_mitigations.hasSeh = !(dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH);

        if (m_mitigations.hasAslr) m_mitigations.details.push_back("ASLR Enabled");
        else m_mitigations.details.push_back("ASLR Disabled (Predictable Base Address)");

        if (m_mitigations.hasDep) m_mitigations.details.push_back("DEP/NX Compatibility Enabled");
        else m_mitigations.details.push_back("DEP/NX Disabled (Executable Stack/Heap Vulnerable)");

        if (m_mitigations.hasCfg) m_mitigations.details.push_back("Control Flow Guard (CFG) Enabled");
    }

    void PeInspector::ParseSections(uint16_t numSections, size_t sectionTableOffset) {
        m_sections.clear();
        m_mitigations.hasRwxSections = false;

        for (uint16_t i = 0; i < numSections; ++i) {
            size_t secOffset = sectionTableOffset + (i * sizeof(IMAGE_SECTION_HEADER));
            IMAGE_SECTION_HEADER sec;
            if (!SafeRead(secOffset, &sec, sizeof(sec))) break;

            SectionInfo s;
            char nameBuf[9] = {};
            std::memcpy(nameBuf, sec.Name, 8);
            s.name = nameBuf;
            s.virtualAddress = sec.VirtualAddress;
            s.virtualSize = sec.Misc.VirtualSize;
            s.rawAddress = sec.PointerToRawData;
            s.rawSize = sec.SizeOfRawData;
            s.characteristics = sec.Characteristics;

            s.isExecutable = (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            s.isWritable = (sec.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            s.isReadable = (sec.Characteristics & IMAGE_SCN_MEM_READ) != 0;

            if (s.isExecutable && s.isWritable) {
                m_mitigations.hasRwxSections = true;
            }

            // Compute Shannon entropy for section raw data
            if (s.rawAddress < m_rawBuffer.size() && s.rawSize > 0) {
                size_t actualSize = std::min<size_t>(s.rawSize, m_rawBuffer.size() - s.rawAddress);
                uint64_t freq[256] = {0};
                for (size_t b = 0; b < actualSize; ++b) {
                    freq[m_rawBuffer[s.rawAddress + b]]++;
                }
                double entropy = 0.0;
                for (int b = 0; b < 256; ++b) {
                    if (freq[b] > 0) {
                        double p = static_cast<double>(freq[b]) / static_cast<double>(actualSize);
                        entropy -= p * (std::log2(p));
                    }
                }
                s.entropy = entropy;
                s.isHighEntropy = (entropy >= 7.2);
            }

            m_sections.push_back(s);
        }
    }

    void PeInspector::ParseDataDirectories(size_t dataDirOffset, uint32_t numDataDirs) {
        if (numDataDirs == 0) return;

        // Directory 0: Export
        if (numDataDirs > IMAGE_DIRECTORY_ENTRY_EXPORT) {
            IMAGE_DATA_DIRECTORY exportDir;
            if (SafeRead(dataDirOffset + (IMAGE_DIRECTORY_ENTRY_EXPORT * sizeof(IMAGE_DATA_DIRECTORY)), &exportDir, sizeof(exportDir))) {
                if (exportDir.VirtualAddress != 0 && exportDir.Size != 0) {
                    ParseExports(exportDir.VirtualAddress, exportDir.Size);
                }
            }
        }

        // Directory 1: Import
        if (numDataDirs > IMAGE_DIRECTORY_ENTRY_IMPORT) {
            IMAGE_DATA_DIRECTORY importDir;
            if (SafeRead(dataDirOffset + (IMAGE_DIRECTORY_ENTRY_IMPORT * sizeof(IMAGE_DATA_DIRECTORY)), &importDir, sizeof(importDir))) {
                if (importDir.VirtualAddress != 0 && importDir.Size != 0) {
                    ParseImports(importDir.VirtualAddress, importDir.Size);
                }
            }
        }

        // Directory 4: Security / Certificate
        if (numDataDirs > IMAGE_DIRECTORY_ENTRY_SECURITY) {
            IMAGE_DATA_DIRECTORY secDir;
            if (SafeRead(dataDirOffset + (IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof(IMAGE_DATA_DIRECTORY)), &secDir, sizeof(secDir))) {
                m_mitigations.hasAuthenticode = (secDir.VirtualAddress != 0 && secDir.Size != 0);
            }
        }

        // Directory 9: TLS
        if (numDataDirs > IMAGE_DIRECTORY_ENTRY_TLS) {
            IMAGE_DATA_DIRECTORY tlsDir;
            if (SafeRead(dataDirOffset + (IMAGE_DIRECTORY_ENTRY_TLS * sizeof(IMAGE_DATA_DIRECTORY)), &tlsDir, sizeof(tlsDir))) {
                if (tlsDir.VirtualAddress != 0 && tlsDir.Size != 0) {
                    m_mitigations.hasTls = true;
                    ParseTls(tlsDir.VirtualAddress, tlsDir.Size);
                }
            }
        }

        // Directory 14: CLR / .NET Header
        if (numDataDirs > 14) {
            IMAGE_DATA_DIRECTORY clrDir;
            if (SafeRead(dataDirOffset + (14 * sizeof(IMAGE_DATA_DIRECTORY)), &clrDir, sizeof(clrDir))) {
                m_mitigations.isDotNet = (clrDir.VirtualAddress != 0 && clrDir.Size != 0);
            }
        }
    }

    uint64_t PeInspector::RvaToFileOffset(uint64_t rva) const {
        for (const auto& s : m_sections) {
            if (rva >= s.virtualAddress && rva < s.virtualAddress + std::max(s.virtualSize, s.rawSize)) {
                return s.rawAddress + (rva - s.virtualAddress);
            }
        }
        return 0;
    }

    uint64_t PeInspector::FileOffsetToRva(uint64_t offset) const {
        for (const auto& s : m_sections) {
            if (offset >= s.rawAddress && offset < s.rawAddress + s.rawSize) {
                return s.virtualAddress + (offset - s.rawAddress);
            }
        }
        return 0;
    }

    const SectionInfo* PeInspector::GetSectionForRva(uint64_t rva) const {
        for (const auto& s : m_sections) {
            if (rva >= s.virtualAddress && rva < s.virtualAddress + std::max(s.virtualSize, s.rawSize)) {
                return &s;
            }
        }
        return nullptr;
    }

    void PeInspector::ParseImports(uint32_t importRva, uint32_t importSize) {
        uint64_t descOffset = RvaToFileOffset(importRva);
        if (descOffset == 0) return;

        // Dangerous APIs dictionary
        static const std::map<std::string, std::pair<std::string, std::string>> kDangerousApis = {
            {"VirtualAlloc", {"Memory Manipulation", "Allocates virtual memory with arbitrary permissions"}},
            {"VirtualAllocEx", {"Process Injection", "Allocates memory in remote target process"}},
            {"VirtualProtect", {"Memory Protection", "Modifies page protections (e.g. W+X / RWX)"}},
            {"WriteProcessMemory", {"Process Injection", "Writes shellcode or payload into foreign process"}},
            {"CreateRemoteThread", {"Process Injection", "Spawns execution thread inside foreign process"}},
            {"QueueUserAPC", {"Process Injection", "Queues asynchronous procedure call (Early Bird Injection)"}},
            {"SetThreadContext", {"Process Injection", "Modifies thread instruction pointer (Thread Hijacking)"}},
            {"NtQueueApcThread", {"Process Injection", "Native APC execution"}},
            {"IsDebuggerPresent", {"Anti-Analysis", "Detects active user-mode debugger"}},
            {"CheckRemoteDebuggerPresent", {"Anti-Analysis", "Queries ProcessDebugPort for remote debugger"}},
            {"NtQueryInformationProcess", {"Anti-Analysis", "Queries ProcessDebugPort / ProcessDebugFlags"}},
            {"WinExec", {"Execution", "Executes arbitrary command/process"}},
            {"ShellExecuteA", {"Execution", "Executes process via shell"}},
            {"ShellExecuteW", {"Execution", "Executes process via shell"}},
            {"URLDownloadToFileA", {"Downloader", "Downloads payload directly from URL to disk"}},
            {"URLDownloadToFileW", {"Downloader", "Downloads payload directly from URL to disk"}},
            {"InternetOpenA", {"Network C2", "Initializes network socket connection"}},
            {"HttpSendRequestA", {"Network C2", "Transmits HTTP POST/GET telemetry to C2 server"}},
            {"RegSetValueExA", {"Persistence", "Modifies Windows Registry keys"}},
            {"RegSetValueExW", {"Persistence", "Modifies Windows Registry keys"}}
        };

        while (true) {
            IMAGE_IMPORT_DESCRIPTOR desc;
            if (!SafeRead(descOffset, &desc, sizeof(desc))) break;
            if (desc.Characteristics == 0 && desc.Name == 0 && desc.FirstThunk == 0) break; // Null terminator

            uint64_t nameOffset = RvaToFileOffset(desc.Name);
            std::string dllName = SafeReadString(nameOffset, 64);
            if (dllName.empty()) dllName = "UNKNOWN.DLL";

            uint32_t thunkRva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
            uint64_t thunkOffset = RvaToFileOffset(thunkRva);
            uint64_t iatRva = desc.FirstThunk;

            if (thunkOffset != 0) {
                while (true) {
                    if (m_metadata.is64Bit) {
                        uint64_t thunkValue = 0;
                        if (!SafeRead(thunkOffset, &thunkValue, sizeof(thunkValue)) || thunkValue == 0) break;

                        ImportEntry imp;
                        imp.dllName = dllName;
                        imp.iatRva = iatRva;

                        if (thunkValue & IMAGE_ORDINAL_FLAG64) {
                            imp.ordinal = static_cast<uint32_t>(thunkValue & 0xFFFF);
                            imp.functionName = "Ordinal_" + std::to_string(imp.ordinal);
                        } else {
                            uint64_t ibnOffset = RvaToFileOffset(thunkValue);
                            WORD hint = 0;
                            SafeRead(ibnOffset, &hint, sizeof(hint));
                            imp.functionName = SafeReadString(ibnOffset + 2, 128);
                        }

                        auto it = kDangerousApis.find(imp.functionName);
                        if (it != kDangerousApis.end()) {
                            imp.isDangerous = true;
                            imp.riskDescription = it->second.first + ": " + it->second.second;
                        }

                        m_imports.push_back(imp);
                        thunkOffset += sizeof(uint64_t);
                        iatRva += sizeof(uint64_t);
                    } else {
                        uint32_t thunkValue = 0;
                        if (!SafeRead(thunkOffset, &thunkValue, sizeof(thunkValue)) || thunkValue == 0) break;

                        ImportEntry imp;
                        imp.dllName = dllName;
                        imp.iatRva = iatRva;

                        if (thunkValue & IMAGE_ORDINAL_FLAG32) {
                            imp.ordinal = thunkValue & 0xFFFF;
                            imp.functionName = "Ordinal_" + std::to_string(imp.ordinal);
                        } else {
                            uint64_t ibnOffset = RvaToFileOffset(thunkValue);
                            WORD hint = 0;
                            SafeRead(ibnOffset, &hint, sizeof(hint));
                            imp.functionName = SafeReadString(ibnOffset + 2, 128);
                        }

                        auto it = kDangerousApis.find(imp.functionName);
                        if (it != kDangerousApis.end()) {
                            imp.isDangerous = true;
                            imp.riskDescription = it->second.first + ": " + it->second.second;
                        }

                        m_imports.push_back(imp);
                        thunkOffset += sizeof(uint32_t);
                        iatRva += sizeof(uint32_t);
                    }
                }
            }

            descOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
    }

    void PeInspector::ParseExports(uint32_t exportRva, uint32_t exportSize) {
        uint64_t expOffset = RvaToFileOffset(exportRva);
        if (expOffset == 0) return;

        IMAGE_EXPORT_DIRECTORY exp;
        if (!SafeRead(expOffset, &exp, sizeof(exp))) return;

        uint64_t funcTableOffset = RvaToFileOffset(exp.AddressOfFunctions);
        uint64_t nameTableOffset = RvaToFileOffset(exp.AddressOfNames);
        uint64_t ordTableOffset = RvaToFileOffset(exp.AddressOfNameOrdinals);

        for (DWORD i = 0; i < exp.NumberOfNames; ++i) {
            uint32_t nameRva = 0;
            WORD ordIndex = 0;
            SafeRead(nameTableOffset + (i * sizeof(uint32_t)), &nameRva, sizeof(nameRva));
            SafeRead(ordTableOffset + (i * sizeof(WORD)), &ordIndex, sizeof(ordIndex));

            uint32_t funcRva = 0;
            SafeRead(funcTableOffset + (ordIndex * sizeof(uint32_t)), &funcRva, sizeof(funcRva));

            ExportEntry ee;
            ee.functionName = SafeReadString(RvaToFileOffset(nameRva), 128);
            ee.ordinal = exp.Base + ordIndex;
            ee.rva = funcRva;

            // Check if forwarded export (RVA inside export directory)
            if (funcRva >= exportRva && funcRva < exportRva + exportSize) {
                ee.forwarderName = SafeReadString(RvaToFileOffset(funcRva), 128);
            }

            m_exports.push_back(ee);
        }
    }

    void PeInspector::ParseTls(uint32_t tlsRva, uint32_t tlsSize) {
        uint64_t tlsOffset = RvaToFileOffset(tlsRva);
        if (tlsOffset == 0) return;

        if (m_metadata.is64Bit) {
            IMAGE_TLS_DIRECTORY64 tls64;
            if (SafeRead(tlsOffset, &tls64, sizeof(tls64))) {
                if (tls64.AddressOfCallBacks != 0 && m_metadata.imageBase != 0) {
                    uint64_t cbRva = tls64.AddressOfCallBacks - m_metadata.imageBase;
                    uint64_t cbFileOffset = RvaToFileOffset(cbRva);
                    if (cbFileOffset != 0) {
                        uint64_t cbVa = 0;
                        while (SafeRead(cbFileOffset, &cbVa, sizeof(cbVa)) && cbVa != 0) {
                            m_tlsCallbacks.push_back({ cbVa - m_metadata.imageBase, cbVa });
                            cbFileOffset += sizeof(uint64_t);
                        }
                    }
                }
            }
        } else {
            IMAGE_TLS_DIRECTORY32 tls32;
            if (SafeRead(tlsOffset, &tls32, sizeof(tls32))) {
                if (tls32.AddressOfCallBacks != 0 && m_metadata.imageBase != 0) {
                    uint64_t cbRva = tls32.AddressOfCallBacks - m_metadata.imageBase;
                    uint64_t cbFileOffset = RvaToFileOffset(cbRva);
                    if (cbFileOffset != 0) {
                        uint32_t cbVa = 0;
                        while (SafeRead(cbFileOffset, &cbVa, sizeof(cbVa)) && cbVa != 0) {
                            m_tlsCallbacks.push_back({ cbVa - m_metadata.imageBase, cbVa });
                            cbFileOffset += sizeof(uint32_t);
                        }
                    }
                }
            }
        }
    }

    std::vector<Finding> PeInspector::GenerateFindings() const {
        std::vector<Finding> out;
        if (!m_isValid) return out;

        // 1. ASLR Finding
        if (!m_mitigations.hasAslr) {
            Finding f;
            f.id = "SEC_NO_ASLR";
            f.category = "Security";
            f.severity = FindingSeverity::Low;
            f.confidence = FindingConfidence::High;
            f.title = "ASLR (Address Space Layout Randomization) Disabled";
            f.description = "Binary lacks DYNAMIC_BASE characteristic flag; loads at fixed image base 0x" + std::to_string(m_metadata.imageBase);
            f.evidence = "DllCharacteristics missing IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE";
            f.source = "PE Inspector";
            f.tags = {"ASLR", "ExploitMitigation"};
            out.push_back(f);
        }

        // 2. DEP Finding
        if (!m_mitigations.hasDep) {
            Finding f;
            f.id = "SEC_NO_DEP";
            f.category = "Security";
            f.severity = FindingSeverity::Medium;
            f.confidence = FindingConfidence::High;
            f.title = "Data Execution Prevention (DEP / NX) Disabled";
            f.description = "Binary lacks NX_COMPAT flag; stack/heap may allow executable code execution";
            f.evidence = "DllCharacteristics missing IMAGE_DLLCHARACTERISTICS_NX_COMPAT";
            f.source = "PE Inspector";
            f.tags = {"DEP", "ExploitMitigation"};
            out.push_back(f);
        }

        // 3. RWX Section Finding
        if (m_mitigations.hasRwxSections) {
            for (const auto& s : m_sections) {
                if (s.isExecutable && s.isWritable) {
                    Finding f;
                    f.id = "SEC_RWX_SECTION";
                    f.category = "Packing / Injection";
                    f.severity = FindingSeverity::High;
                    f.confidence = FindingConfidence::High;
                    f.rva = s.virtualAddress;
                    f.title = "Writable & Executable (RWX) Section Detected: " + s.name;
                    f.description = "Section '" + s.name + "' has both WRITE and EXECUTE permissions, commonly used by packers or self-modifying shellcode.";
                    f.evidence = "Characteristics: 0x" + std::to_string(s.characteristics);
                    f.source = "PE Inspector";
                    f.tags = {"RWX", "SelfModifyingCode", "MITRE:T1055"};
                    out.push_back(f);
                }
            }
        }

        // 4. High Entropy Sections
        for (const auto& s : m_sections) {
            if (s.isHighEntropy) {
                Finding f;
                f.id = "SEC_HIGH_ENTROPY_SECTION";
                f.category = "Packing";
                f.severity = FindingSeverity::Medium;
                f.confidence = FindingConfidence::Medium;
                f.rva = s.virtualAddress;
                f.title = "High Shannon Entropy in Section: " + s.name;
                std::ostringstream ss;
                ss << "Calculated entropy " << std::fixed << std::setprecision(2) << s.entropy << " / 8.00 indicates encryption or compression.";
                f.description = ss.str();
                f.evidence = "Section " + s.name + " entropy=" + std::to_string(s.entropy);
                f.source = "Entropy Analyzer";
                f.tags = {"Packing", "Entropy", "MITRE:T1027"};
                out.push_back(f);
            }
        }

        // 5. TLS Callbacks (Execution before Entry Point)
        if (!m_tlsCallbacks.empty()) {
            Finding f;
            f.id = "SEC_TLS_CALLBACKS";
            f.category = "AntiAnalysis";
            f.severity = FindingSeverity::Medium;
            f.confidence = FindingConfidence::High;
            f.title = "TLS Callbacks Present (" + std::to_string(m_tlsCallbacks.size()) + " callbacks)";
            f.description = "TLS callbacks execute before the main entry point; often leveraged for anti-debugging or payload decryption.";
            f.evidence = "TLS Table defines " + std::to_string(m_tlsCallbacks.size()) + " callback pointers";
            f.source = "PE Inspector";
            f.tags = {"TLS", "AntiDebug", "MITRE:T1055"};
            out.push_back(f);
        }

        // 6. Dangerous Imports Findings
        for (const auto& imp : m_imports) {
            if (imp.isDangerous) {
                Finding f;
                f.id = "IMPORT_SUSPICIOUS_API_" + imp.functionName;
                f.category = "SuspiciousImports";
                f.severity = FindingSeverity::Low;
                f.confidence = FindingConfidence::High;
                f.rva = imp.iatRva;
                f.title = "Imported Sensitive API: " + imp.functionName + " (" + imp.dllName + ")";
                f.description = imp.riskDescription;
                f.evidence = "Import Table: " + imp.dllName + "!" + imp.functionName + " @ IAT RVA 0x" + std::to_string(imp.iatRva);
                f.source = "PE Inspector";
                f.tags = {"Imports", "Capabilities"};
                out.push_back(f);
            }
        }

        return out;
    }

} // namespace Dracula
