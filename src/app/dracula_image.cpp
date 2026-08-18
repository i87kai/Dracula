#include "app/dracula_image.h"
#include "app/hasher.h"
#include "app/project.h"
#include "common/version.h"

#include <zstd.h>

#include <filesystem>
#include <fstream>
#include <vector>
#include <cstring>
#include <chrono>
#include <algorithm>

namespace fs = std::filesystem;

namespace Dracula {
namespace App {

    namespace {

        constexpr char     kMagic[8]      = {'D', 'R', 'A', 'C', 'I', 'M', 'G', '\0'};
        constexpr uint32_t kFormatVersion = 1;
        constexpr size_t   kHeaderSize    = 512;
        constexpr uint32_t kChunkMagic    = 0x4B484344;  // "DCHK"

        // A chunk whose compressed form is not smaller is stored verbatim, so
        // packaging can never inflate incompressible regions.
        constexpr uint32_t kFlagChunkRaw = 0x1;

#pragma pack(push, 1)
        struct ChunkRecord {
            uint32_t magic;
            uint32_t flags;
            uint32_t compressedSize;
            uint32_t uncompressedSize;
            uint32_t crc32;
            uint32_t reserved;
        };
#pragma pack(pop)

        static_assert(sizeof(ChunkRecord) == 24, "ChunkRecord must stay 24 bytes");

        // The header is a fixed 512-byte block written by hand rather than as a
        // packed struct, so field offsets are explicit and stable.
        struct Header {
            uint32_t    formatVersion = kFormatVersion;
            uint64_t    originalSize = 0;
            uint64_t    chunkSize = 0;
            uint64_t    chunkCount = 0;
            std::string sourceFormat;
            std::string sourceName;
            std::string originalSha256;
            std::string createdAt;
            std::string draculaVersion;
        };

        void PutU32(uint8_t* p, uint32_t v) { std::memcpy(p, &v, 4); }
        void PutU64(uint8_t* p, uint64_t v) { std::memcpy(p, &v, 8); }
        uint32_t GetU32(const uint8_t* p) { uint32_t v; std::memcpy(&v, p, 4); return v; }
        uint64_t GetU64(const uint8_t* p) { uint64_t v; std::memcpy(&v, p, 8); return v; }

        void PutStr(uint8_t* p, const std::string& s, size_t capacity) {
            std::memset(p, 0, capacity);
            std::memcpy(p, s.data(), std::min(s.size(), capacity - 1));
        }

        std::string GetStr(const uint8_t* p, size_t capacity) {
            size_t length = 0;
            while (length < capacity && p[length] != 0) ++length;
            return std::string(reinterpret_cast<const char*>(p), length);
        }

        // Header field offsets.
        constexpr size_t kOffMagic     = 0;    // 8
        constexpr size_t kOffVersion   = 8;    // 4
        constexpr size_t kOffOrigSize  = 16;   // 8
        constexpr size_t kOffChunkSize = 24;   // 8
        constexpr size_t kOffChunkCnt  = 32;   // 8
        constexpr size_t kOffFormat    = 40;   // 16
        constexpr size_t kOffSha       = 56;   // 65
        constexpr size_t kOffCreated   = 128;  // 32
        constexpr size_t kOffVersionStr= 160;  // 32
        constexpr size_t kOffName      = 192;  // 256

        std::vector<uint8_t> SerializeHeader(const Header& h) {
            std::vector<uint8_t> buffer(kHeaderSize, 0);
            std::memcpy(buffer.data() + kOffMagic, kMagic, sizeof(kMagic));
            PutU32(buffer.data() + kOffVersion, h.formatVersion);
            PutU64(buffer.data() + kOffOrigSize, h.originalSize);
            PutU64(buffer.data() + kOffChunkSize, h.chunkSize);
            PutU64(buffer.data() + kOffChunkCnt, h.chunkCount);
            PutStr(buffer.data() + kOffFormat, h.sourceFormat, 16);
            PutStr(buffer.data() + kOffSha, h.originalSha256, 65);
            PutStr(buffer.data() + kOffCreated, h.createdAt, 32);
            PutStr(buffer.data() + kOffVersionStr, h.draculaVersion, 32);
            PutStr(buffer.data() + kOffName, h.sourceName, 256);
            return buffer;
        }

        bool ParseHeader(const std::vector<uint8_t>& buffer, Header& out) {
            if (buffer.size() < kHeaderSize) return false;
            if (std::memcmp(buffer.data() + kOffMagic, kMagic, sizeof(kMagic)) != 0) return false;

            out.formatVersion  = GetU32(buffer.data() + kOffVersion);
            out.originalSize   = GetU64(buffer.data() + kOffOrigSize);
            out.chunkSize      = GetU64(buffer.data() + kOffChunkSize);
            out.chunkCount     = GetU64(buffer.data() + kOffChunkCnt);
            out.sourceFormat   = GetStr(buffer.data() + kOffFormat, 16);
            out.originalSha256 = GetStr(buffer.data() + kOffSha, 65);
            out.createdAt      = GetStr(buffer.data() + kOffCreated, 32);
            out.draculaVersion = GetStr(buffer.data() + kOffVersionStr, 32);
            out.sourceName     = GetStr(buffer.data() + kOffName, 256);
            return true;
        }

        std::string DetectSourceFormat(const std::string& path) {
            std::string ext = fs::path(path).extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (!ext.empty() && ext.front() == '.') ext.erase(ext.begin());
            return ext.empty() ? "raw" : ext;
        }

        uint64_t NowMs() {
            return static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
        }

    } // namespace

    bool DraculaImage::IsPackage(const std::string& path) {
        std::error_code ec;
        if (!fs::exists(path, ec)) return false;

        std::ifstream in(path, std::ios::binary);
        if (!in.is_open()) return false;

        char magic[8] = {0};
        in.read(magic, sizeof(magic));
        return in.gcount() == sizeof(magic) &&
               std::memcmp(magic, kMagic, sizeof(kMagic)) == 0;
    }

    DraculaImageResult DraculaImage::Package(const std::string& sourcePath,
                                             const std::string& packagePath,
                                             int compressionLevel,
                                             ImageProgressFn progress) {
        DraculaImageResult result;
        result.outputPath = packagePath;
        const uint64_t startMs = NowMs();

        std::error_code ec;
        if (!fs::exists(sourcePath, ec)) {
            result.error = "source image does not exist: " + sourcePath;
            return result;
        }
        if (!fs::is_regular_file(sourcePath, ec)) {
            result.error = "source is not a regular file: " + sourcePath;
            return result;
        }

        const uint64_t originalSize = static_cast<uint64_t>(fs::file_size(sourcePath, ec));
        if (ec) {
            result.error = "could not determine source size: " + ec.message();
            return result;
        }
        result.originalSize = originalSize;

        // Refuse rather than fill the destination disk (section 47). The
        // package should be far smaller, but a worst case of "no compression
        // at all" is the only safe assumption before reading the data.
        const fs::path destDir = fs::path(packagePath).parent_path();
        if (!destDir.empty()) {
            fs::create_directories(destDir, ec);
            auto space = fs::space(destDir, ec);
            if (!ec && space.available < originalSize / 2) {
                result.error = "insufficient free space at " + destDir.string() +
                               ": " + std::to_string(space.available / (1024 * 1024)) +
                               " MB available, at least " +
                               std::to_string((originalSize / 2) / (1024 * 1024)) +
                               " MB recommended";
                return result;
            }
        }

        std::ifstream in(sourcePath, std::ios::binary);
        if (!in.is_open()) {
            result.error = "could not open source image: " + sourcePath;
            return result;
        }

        const std::string tempPath = packagePath + ".partial";
        std::ofstream out(tempPath, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            result.error = "could not create package: " + tempPath;
            return result;
        }

        // Cleans up the partial package on any failure or cancellation, so a
        // failed packaging never leaves a multi-gigabyte carcass behind. The
        // stream is closed first: on Windows an open handle blocks the delete,
        // and members destruct in reverse declaration order, so the guard would
        // otherwise run while the file is still held open.
        struct PartialGuard {
            std::string path;
            std::ofstream& stream;
            bool commit = false;
            ~PartialGuard() {
                if (commit) return;
                if (stream.is_open()) stream.close();
                std::error_code ec;
                fs::remove(path, ec);
            }
        } guard{tempPath, out, false};

        const uint64_t chunkSize = kDefaultChunkSize;

        // The header is written twice: a placeholder now, and the real one once
        // the SHA-256 and chunk count are known.
        Header header;
        header.originalSize = originalSize;
        header.chunkSize = chunkSize;
        header.sourceFormat = DetectSourceFormat(sourcePath);
        header.sourceName = fs::path(sourcePath).filename().string();
        header.createdAt = NowIso8601();
        header.draculaVersion = DRACULA_VERSION_STRING;

        {
            auto placeholder = SerializeHeader(header);
            out.write(reinterpret_cast<const char*>(placeholder.data()),
                      static_cast<std::streamsize>(placeholder.size()));
        }

        std::vector<uint8_t> inputBuffer(static_cast<size_t>(chunkSize));
        std::vector<uint8_t> compressedBuffer(ZSTD_compressBound(static_cast<size_t>(chunkSize)));

        Sha256Stream originalHasher;
        uint64_t processed = 0;
        uint64_t chunkCount = 0;

        while (processed < originalSize) {
            in.read(reinterpret_cast<char*>(inputBuffer.data()),
                    static_cast<std::streamsize>(inputBuffer.size()));
            const std::streamsize got = in.gcount();
            if (got <= 0) break;

            const size_t chunkBytes = static_cast<size_t>(got);
            originalHasher.Update(inputBuffer.data(), chunkBytes);

            const size_t compressed = ZSTD_compress(compressedBuffer.data(),
                                                    compressedBuffer.size(),
                                                    inputBuffer.data(),
                                                    chunkBytes,
                                                    compressionLevel);

            ChunkRecord record{};
            record.magic = kChunkMagic;
            record.uncompressedSize = static_cast<uint32_t>(chunkBytes);
            record.crc32 = Crc32(inputBuffer.data(), chunkBytes);

            const bool useRaw = ZSTD_isError(compressed) || compressed >= chunkBytes;
            const uint8_t* payload = nullptr;
            size_t payloadSize = 0;

            if (useRaw) {
                record.flags = kFlagChunkRaw;
                record.compressedSize = static_cast<uint32_t>(chunkBytes);
                payload = inputBuffer.data();
                payloadSize = chunkBytes;
            } else {
                record.flags = 0;
                record.compressedSize = static_cast<uint32_t>(compressed);
                payload = compressedBuffer.data();
                payloadSize = compressed;
            }

            out.write(reinterpret_cast<const char*>(&record), sizeof(record));
            out.write(reinterpret_cast<const char*>(payload),
                      static_cast<std::streamsize>(payloadSize));
            if (!out.good()) {
                result.error = "write failed while packaging (disk full?)";
                return result;
            }

            processed += chunkBytes;
            ++chunkCount;

            if (progress && !progress(processed, originalSize, "packaging")) {
                result.error = "cancelled";
                return result;
            }
        }

        header.chunkCount = chunkCount;
        header.originalSha256 = originalHasher.Hex();

        // Rewrite the header now that it is complete.
        out.seekp(0, std::ios::beg);
        {
            auto finalHeader = SerializeHeader(header);
            out.write(reinterpret_cast<const char*>(finalHeader.data()),
                      static_cast<std::streamsize>(finalHeader.size()));
        }
        out.flush();
        if (!out.good()) {
            result.error = "could not finalize package header";
            return result;
        }
        out.close();

        fs::remove(packagePath, ec);
        fs::rename(tempPath, packagePath, ec);
        if (ec) {
            result.error = "could not commit package: " + ec.message();
            return result;
        }
        guard.commit = true;

        result.ok = true;
        result.packagedSize = static_cast<uint64_t>(fs::file_size(packagePath, ec));
        result.chunkCount = chunkCount;
        result.originalSha256 = header.originalSha256;
        result.packageSha256 = Sha256Stream::OfFile(packagePath);
        result.durationMs = NowMs() - startMs;
        return result;
    }

    DraculaImageInfo DraculaImage::Inspect(const std::string& packagePath) {
        DraculaImageInfo info;

        std::ifstream in(packagePath, std::ios::binary);
        if (!in.is_open()) return info;

        std::vector<uint8_t> buffer(kHeaderSize);
        in.read(reinterpret_cast<char*>(buffer.data()),
                static_cast<std::streamsize>(buffer.size()));
        if (in.gcount() != static_cast<std::streamsize>(kHeaderSize)) return info;

        Header header;
        if (!ParseHeader(buffer, header)) return info;

        std::error_code ec;
        info.valid = true;
        info.formatVersion = header.formatVersion;
        info.sourceFormat = header.sourceFormat;
        info.sourceName = header.sourceName;
        info.originalSize = header.originalSize;
        info.chunkSize = header.chunkSize;
        info.chunkCount = header.chunkCount;
        info.originalSha256 = header.originalSha256;
        info.createdAt = header.createdAt;
        info.draculaVersion = header.draculaVersion;
        info.packagedSize = static_cast<uint64_t>(fs::file_size(packagePath, ec));
        return info;
    }

    DraculaImageVerification DraculaImage::Verify(const std::string& packagePath,
                                                  bool deep,
                                                  ImageProgressFn progress) {
        DraculaImageVerification verification;

        verification.info = Inspect(packagePath);
        if (!verification.info.valid) {
            verification.error = "not a Dracula image package (bad or missing header)";
            return verification;
        }
        if (verification.info.formatVersion != kFormatVersion) {
            verification.error = "unsupported package format version " +
                                 std::to_string(verification.info.formatVersion);
            return verification;
        }
        verification.headerValid = true;
        verification.expectedSha256 = verification.info.originalSha256;

        std::ifstream in(packagePath, std::ios::binary);
        if (!in.is_open()) {
            verification.error = "could not open package";
            return verification;
        }
        in.seekg(static_cast<std::streamoff>(kHeaderSize), std::ios::beg);

        std::vector<uint8_t> compressedBuffer;
        std::vector<uint8_t> plainBuffer(static_cast<size_t>(verification.info.chunkSize));

        Sha256Stream hasher;
        uint64_t processed = 0;

        for (uint64_t index = 0; index < verification.info.chunkCount; ++index) {
            ChunkRecord record{};
            in.read(reinterpret_cast<char*>(&record), sizeof(record));
            if (in.gcount() != static_cast<std::streamsize>(sizeof(record))) {
                verification.error = "package truncated: chunk " + std::to_string(index) +
                                     " header is missing";
                verification.firstBadChunk = index;
                return verification;
            }
            if (record.magic != kChunkMagic) {
                verification.error = "corruption detected: chunk " + std::to_string(index) +
                                     " has a bad signature";
                verification.firstBadChunk = index;
                return verification;
            }
            if (record.uncompressedSize > verification.info.chunkSize) {
                verification.error = "corruption detected: chunk " + std::to_string(index) +
                                     " declares an impossible size";
                verification.firstBadChunk = index;
                return verification;
            }

            compressedBuffer.resize(record.compressedSize);
            in.read(reinterpret_cast<char*>(compressedBuffer.data()),
                    static_cast<std::streamsize>(record.compressedSize));
            if (in.gcount() != static_cast<std::streamsize>(record.compressedSize)) {
                verification.error = "package truncated inside chunk " + std::to_string(index);
                verification.firstBadChunk = index;
                return verification;
            }

            if (record.flags & kFlagChunkRaw) {
                std::memcpy(plainBuffer.data(), compressedBuffer.data(), record.uncompressedSize);
            } else {
                const size_t decompressed = ZSTD_decompress(plainBuffer.data(),
                                                            plainBuffer.size(),
                                                            compressedBuffer.data(),
                                                            compressedBuffer.size());
                if (ZSTD_isError(decompressed) || decompressed != record.uncompressedSize) {
                    verification.error = "corruption detected: chunk " + std::to_string(index) +
                                         " failed to decompress";
                    verification.firstBadChunk = index;
                    return verification;
                }
            }

            if (Crc32(plainBuffer.data(), record.uncompressedSize) != record.crc32) {
                verification.error = "corruption detected: chunk " + std::to_string(index) +
                                     " failed its checksum";
                verification.firstBadChunk = index;
                return verification;
            }

            if (deep) hasher.Update(plainBuffer.data(), record.uncompressedSize);

            processed += record.uncompressedSize;
            ++verification.chunksChecked;

            if (progress && !progress(processed, verification.info.originalSize, "verifying")) {
                verification.error = "cancelled";
                return verification;
            }
        }

        verification.chunksValid = true;

        if (processed != verification.info.originalSize) {
            verification.error = "size mismatch: package holds " + std::to_string(processed) +
                                 " bytes, header declares " +
                                 std::to_string(verification.info.originalSize);
            return verification;
        }

        if (deep) {
            verification.actualSha256 = hasher.Hex();
            if (verification.actualSha256 != verification.expectedSha256) {
                verification.error = "content hash mismatch: the packaged image does not match "
                                     "the recorded SHA-256";
                return verification;
            }
            verification.contentVerified = true;
        }

        verification.ok = true;
        return verification;
    }

    DraculaImageResult DraculaImage::Restore(const std::string& packagePath,
                                             const std::string& outputPath,
                                             bool overwrite,
                                             ImageProgressFn progress) {
        DraculaImageResult result;
        result.outputPath = outputPath;
        const uint64_t startMs = NowMs();

        DraculaImageInfo info = Inspect(packagePath);
        if (!info.valid) {
            result.error = "not a Dracula image package: " + packagePath;
            return result;
        }

        std::error_code ec;
        if (fs::exists(outputPath, ec) && !overwrite) {
            result.error = "refusing to overwrite an existing file: " + outputPath;
            return result;
        }

        // Restoring expands back to the full image, so the space check is
        // against the original size, not the package size.
        const fs::path destDir = fs::path(outputPath).parent_path();
        if (!destDir.empty()) {
            fs::create_directories(destDir, ec);
            auto space = fs::space(destDir, ec);
            if (!ec && space.available < info.originalSize) {
                result.error = "insufficient free space at " + destDir.string() + ": need " +
                               std::to_string(info.originalSize / (1024 * 1024)) +
                               " MB, have " + std::to_string(space.available / (1024 * 1024)) + " MB";
                return result;
            }
        }

        std::ifstream in(packagePath, std::ios::binary);
        if (!in.is_open()) {
            result.error = "could not open package";
            return result;
        }
        in.seekg(static_cast<std::streamoff>(kHeaderSize), std::ios::beg);

        const std::string tempPath = outputPath + ".partial";
        std::ofstream out(tempPath, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            result.error = "could not create " + tempPath;
            return result;
        }

        // Same ordering concern as in Package(): close before removing.
        struct PartialGuard {
            std::string path;
            std::ofstream& stream;
            bool commit = false;
            ~PartialGuard() {
                if (commit) return;
                if (stream.is_open()) stream.close();
                std::error_code ec;
                fs::remove(path, ec);
            }
        } guard{tempPath, out, false};

        std::vector<uint8_t> compressedBuffer;
        std::vector<uint8_t> plainBuffer(static_cast<size_t>(info.chunkSize));

        Sha256Stream hasher;
        uint64_t processed = 0;

        for (uint64_t index = 0; index < info.chunkCount; ++index) {
            ChunkRecord record{};
            in.read(reinterpret_cast<char*>(&record), sizeof(record));
            if (in.gcount() != static_cast<std::streamsize>(sizeof(record)) ||
                record.magic != kChunkMagic) {
                result.error = "package is corrupt at chunk " + std::to_string(index);
                return result;
            }
            if (record.uncompressedSize > info.chunkSize) {
                result.error = "package is corrupt: chunk " + std::to_string(index) +
                               " declares an impossible size";
                return result;
            }

            compressedBuffer.resize(record.compressedSize);
            in.read(reinterpret_cast<char*>(compressedBuffer.data()),
                    static_cast<std::streamsize>(record.compressedSize));
            if (in.gcount() != static_cast<std::streamsize>(record.compressedSize)) {
                result.error = "package truncated inside chunk " + std::to_string(index);
                return result;
            }

            if (record.flags & kFlagChunkRaw) {
                std::memcpy(plainBuffer.data(), compressedBuffer.data(), record.uncompressedSize);
            } else {
                const size_t decompressed = ZSTD_decompress(plainBuffer.data(),
                                                            plainBuffer.size(),
                                                            compressedBuffer.data(),
                                                            compressedBuffer.size());
                if (ZSTD_isError(decompressed) || decompressed != record.uncompressedSize) {
                    result.error = "chunk " + std::to_string(index) + " failed to decompress";
                    return result;
                }
            }

            if (Crc32(plainBuffer.data(), record.uncompressedSize) != record.crc32) {
                result.error = "chunk " + std::to_string(index) + " failed its checksum";
                return result;
            }

            hasher.Update(plainBuffer.data(), record.uncompressedSize);
            out.write(reinterpret_cast<const char*>(plainBuffer.data()),
                      static_cast<std::streamsize>(record.uncompressedSize));
            if (!out.good()) {
                result.error = "write failed while restoring (disk full?)";
                return result;
            }

            processed += record.uncompressedSize;

            if (progress && !progress(processed, info.originalSize, "restoring")) {
                result.error = "cancelled";
                return result;
            }
        }

        out.flush();
        out.close();

        // A restore is only successful if the result is provably the original.
        const std::string restoredSha = hasher.Hex();
        if (!info.originalSha256.empty() && restoredSha != info.originalSha256) {
            result.error = "restored image does not match the recorded SHA-256";
            return result;
        }

        fs::remove(outputPath, ec);
        fs::rename(tempPath, outputPath, ec);
        if (ec) {
            result.error = "could not commit restored image: " + ec.message();
            return result;
        }
        guard.commit = true;

        result.ok = true;
        result.originalSize = info.originalSize;
        result.packagedSize = info.packagedSize;
        result.chunkCount = info.chunkCount;
        result.originalSha256 = restoredSha;
        result.durationMs = NowMs() - startMs;
        return result;
    }

} // namespace App
} // namespace Dracula
