#pragma once

//
// Streaming SHA-256.
//
// PeInspector::ComputeSha256 hashes a buffer that is already fully in memory,
// which is fine for a sample but impossible for a 17 GB disk image. This
// wraps the same platform CryptoAPI provider in an incremental interface so a
// package can be hashed as it streams past.
//

#include <string>
#include <cstdint>
#include <cstddef>

namespace Dracula {
namespace App {

    class Sha256Stream {
    public:
        Sha256Stream();
        ~Sha256Stream();

        Sha256Stream(const Sha256Stream&) = delete;
        Sha256Stream& operator=(const Sha256Stream&) = delete;

        bool Valid() const { return m_valid; }

        void Update(const uint8_t* data, size_t size);

        // Finalizes and returns the lowercase hex digest. Further Update()
        // calls after this are ignored.
        std::string Hex();

        // Convenience: hash an entire file without loading it into memory.
        // Returns "" when the file cannot be read.
        static std::string OfFile(const std::string& path);

    private:
        void* m_provider = nullptr;   // HCRYPTPROV
        void* m_hash = nullptr;       // HCRYPTHASH
        bool  m_valid = false;
        bool  m_finalized = false;
        std::string m_digest;
    };

    // Fast, non-cryptographic checksum used for per-chunk corruption detection
    // inside a package. Cheap enough to run on every chunk of a large image.
    uint32_t Crc32(const uint8_t* data, size_t size, uint32_t seed = 0);

} // namespace App
} // namespace Dracula
