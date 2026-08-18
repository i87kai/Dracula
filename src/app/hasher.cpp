#include "app/hasher.h"

#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#endif

namespace Dracula {
namespace App {

    Sha256Stream::Sha256Stream() {
#ifdef _WIN32
        HCRYPTPROV provider = 0;
        // PROV_RSA_AES is the provider that offers SHA-256; the older
        // PROV_RSA_FULL tops out at SHA-1.
        if (CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES,
                                 CRYPT_VERIFYCONTEXT)) {
            HCRYPTHASH hash = 0;
            if (CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
                m_provider = reinterpret_cast<void*>(provider);
                m_hash = reinterpret_cast<void*>(hash);
                m_valid = true;
            } else {
                CryptReleaseContext(provider, 0);
            }
        }
#endif
    }

    Sha256Stream::~Sha256Stream() {
#ifdef _WIN32
        if (m_hash) CryptDestroyHash(reinterpret_cast<HCRYPTHASH>(m_hash));
        if (m_provider) CryptReleaseContext(reinterpret_cast<HCRYPTPROV>(m_provider), 0);
#endif
    }

    void Sha256Stream::Update(const uint8_t* data, size_t size) {
        if (!m_valid || m_finalized || !data || size == 0) return;
#ifdef _WIN32
        // CryptHashData takes a DWORD length, so a chunk larger than 4 GB has
        // to be fed in pieces. Chunks are far smaller than that in practice,
        // but the loop costs nothing and removes the failure mode.
        const size_t kMax = 0x40000000;  // 1 GB per call
        size_t offset = 0;
        while (offset < size) {
            const DWORD piece = static_cast<DWORD>(std::min(kMax, size - offset));
            if (!CryptHashData(reinterpret_cast<HCRYPTHASH>(m_hash),
                               data + offset, piece, 0)) {
                m_valid = false;
                return;
            }
            offset += piece;
        }
#else
        (void)data; (void)size;
#endif
    }

    std::string Sha256Stream::Hex() {
        if (m_finalized) return m_digest;
        m_finalized = true;
        if (!m_valid) return "";

#ifdef _WIN32
        BYTE digest[32] = {0};
        DWORD length = sizeof(digest);
        if (!CryptGetHashParam(reinterpret_cast<HCRYPTHASH>(m_hash), HP_HASHVAL,
                               digest, &length, 0)) {
            return "";
        }
        std::ostringstream oss;
        for (DWORD i = 0; i < length; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<unsigned>(digest[i]);
        }
        m_digest = oss.str();
#endif
        return m_digest;
    }

    std::string Sha256Stream::OfFile(const std::string& path) {
        std::ifstream in(path, std::ios::binary);
        if (!in.is_open()) return "";

        Sha256Stream hasher;
        if (!hasher.Valid()) return "";

        std::vector<uint8_t> buffer(1u << 20);  // 1 MB
        while (in) {
            in.read(reinterpret_cast<char*>(buffer.data()),
                    static_cast<std::streamsize>(buffer.size()));
            const std::streamsize got = in.gcount();
            if (got > 0) hasher.Update(buffer.data(), static_cast<size_t>(got));
        }
        return hasher.Hex();
    }

    // Standard CRC-32 (IEEE 802.3), table built once on first use.
    uint32_t Crc32(const uint8_t* data, size_t size, uint32_t seed) {
        static uint32_t table[256];
        static bool initialized = false;
        if (!initialized) {
            for (uint32_t i = 0; i < 256; ++i) {
                uint32_t c = i;
                for (int k = 0; k < 8; ++k) {
                    c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
                }
                table[i] = c;
            }
            initialized = true;
        }

        uint32_t crc = seed ^ 0xFFFFFFFFu;
        for (size_t i = 0; i < size; ++i) {
            crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
        }
        return crc ^ 0xFFFFFFFFu;
    }

} // namespace App
} // namespace Dracula
