#pragma once

#include "common/findings.h"
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace Dracula {

    class PeInspector {
    public:
        PeInspector();
        ~PeInspector();

        // Load binary from disk
        bool LoadFromFile(const std::string& filePath, std::string& outError);

        // Load binary from raw memory buffer
        bool LoadFromMemory(const uint8_t* data, size_t size, std::string& outError);

        // Accessors
        bool IsValid() const { return m_isValid; }
        const SampleMetadata& GetMetadata() const { return m_metadata; }
        const SecurityMitigations& GetMitigations() const { return m_mitigations; }
        const std::vector<SectionInfo>& GetSections() const { return m_sections; }
        const std::vector<ImportEntry>& GetImports() const { return m_imports; }
        const std::vector<ExportEntry>& GetExports() const { return m_exports; }
        const std::vector<TlsCallbackEntry>& GetTlsCallbacks() const { return m_tlsCallbacks; }
        const uint8_t* GetBuffer() const { return m_rawBuffer.data(); }
        size_t GetBufferSize() const { return m_rawBuffer.size(); }

        // Address resolution helpers
        uint64_t RvaToFileOffset(uint64_t rva) const;
        uint64_t FileOffsetToRva(uint64_t offset) const;
        const SectionInfo* GetSectionForRva(uint64_t rva) const;

        // Structured findings generation
        std::vector<Finding> GenerateFindings() const;

        // Static cryptographic hashing
        static std::string ComputeSha256(const uint8_t* data, size_t size);
        static std::string ComputeMd5(const uint8_t* data, size_t size);

    private:
        bool ParsePE(std::string& outError);
        void ComputeHashes();
        void ParseSecurityMitigations(uint16_t dllCharacteristics, uint16_t characteristics);
        void ParseSections(uint16_t numSections, size_t sectionTableOffset);
        void ParseDataDirectories(size_t dataDirOffset, uint32_t numDataDirs);
        void ParseImports(uint32_t importRva, uint32_t importSize);
        void ParseExports(uint32_t exportRva, uint32_t exportSize);
        void ParseTls(uint32_t tlsRva, uint32_t tlsSize);

        bool SafeRead(size_t offset, void* dest, size_t count) const;
        std::string SafeReadString(size_t offset, size_t maxLen = 256) const;

        std::vector<uint8_t>       m_rawBuffer;
        SampleMetadata             m_metadata;
        SecurityMitigations        m_mitigations;
        std::vector<SectionInfo>   m_sections;
        std::vector<ImportEntry>   m_imports;
        std::vector<ExportEntry>   m_exports;
        std::vector<TlsCallbackEntry> m_tlsCallbacks;
        bool                       m_isValid = false;
    };

} // namespace Dracula
