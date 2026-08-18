#pragma once

//
// .draculaimg -- Dracula's packaged analysis-VM container.
//
// The user owns a local Windows analysis VM (a .vdi, .qcow2 or raw image).
// Dracula packages THEIR image into an immutable, integrity-checked container
// that it can verify and restore from. The image itself is never redistributed
// and never enters the repository (section 29); only this format, its tooling
// and synthetic-fixture tests do.
//
// Layout on disk:
//
//   [ Header      512 bytes, fixed ]
//   [ Chunk 0     record + zstd payload ]
//   [ Chunk 1     record + zstd payload ]
//   ...
//   [ Chunk index appended after the payload ]
//
// Design notes:
//   * Streaming. A 17 GB image is read, compressed and written a chunk at a
//     time; nothing holds the whole image in memory.
//   * Chunked with per-chunk CRC-32, so corruption is localized and reported
//     with the chunk it occurred in rather than as a blanket failure.
//   * SHA-256 of the ORIGINAL image is stored in the header, so a restored
//     image can be proven byte-identical to what was packaged.
//   * Compression is Zstandard, which is already vendored -- no hand-written
//     compressor (section 28.6).
//   * An incompressible chunk is stored raw rather than inflated, so the
//     package can never be larger than the source plus its framing.
//

#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace Dracula {
namespace App {

    // What a package describes and how it was built.
    struct DraculaImageInfo {
        bool        valid = false;
        uint32_t    formatVersion = 0;
        std::string sourceFormat;      // "vdi", "qcow2", "raw", ...
        std::string sourceName;        // original filename, for display only
        uint64_t    originalSize = 0;
        uint64_t    packagedSize = 0;
        uint64_t    chunkSize = 0;
        uint64_t    chunkCount = 0;
        std::string originalSha256;
        std::string createdAt;
        std::string draculaVersion;

        double CompressionRatio() const {
            return originalSize > 0
                 ? static_cast<double>(packagedSize) / static_cast<double>(originalSize)
                 : 0.0;
        }
    };

    // Outcome of packaging or restoring.
    struct DraculaImageResult {
        bool        ok = false;
        std::string error;

        uint64_t    originalSize = 0;
        uint64_t    packagedSize = 0;
        uint64_t    chunkCount = 0;
        uint64_t    durationMs = 0;
        std::string originalSha256;
        std::string packageSha256;
        std::string outputPath;

        double CompressionRatio() const {
            return originalSize > 0
                 ? static_cast<double>(packagedSize) / static_cast<double>(originalSize)
                 : 0.0;
        }
    };

    // Outcome of verification. Corruption names the chunk that failed.
    struct DraculaImageVerification {
        bool        ok = false;
        std::string error;

        bool        headerValid = false;
        bool        chunksValid = false;
        bool        contentVerified = false;   // full SHA-256 recomputed and matched

        uint64_t    chunksChecked = 0;
        uint64_t    firstBadChunk = 0;
        std::string expectedSha256;
        std::string actualSha256;
        DraculaImageInfo info;
    };

    // Reports progress as bytes processed out of a total. Returning false
    // cancels the operation, which then cleans up its partial output.
    using ImageProgressFn = std::function<bool(uint64_t processed, uint64_t total,
                                               const std::string& stage)>;

    class DraculaImage {
    public:
        static constexpr const char* kExtension = ".draculaimg";

        // 16 MB strikes the balance: large enough that zstd sees real
        // redundancy, small enough that a corrupt chunk loses little and
        // progress stays responsive.
        static constexpr uint64_t kDefaultChunkSize = 16ull * 1024 * 1024;

        // Packages a local VM image. `sourcePath` is the user's own file and is
        // only ever read.
        static DraculaImageResult Package(const std::string& sourcePath,
                                          const std::string& packagePath,
                                          int compressionLevel = 9,
                                          ImageProgressFn progress = nullptr);

        // Reads the header without scanning the payload.
        static DraculaImageInfo Inspect(const std::string& packagePath);

        // Verifies structure and per-chunk checksums. With `deep`, also
        // decompresses everything and recomputes the original SHA-256.
        static DraculaImageVerification Verify(const std::string& packagePath,
                                               bool deep = true,
                                               ImageProgressFn progress = nullptr);

        // Restores the packaged image. Refuses to overwrite unless `overwrite`.
        static DraculaImageResult Restore(const std::string& packagePath,
                                          const std::string& outputPath,
                                          bool overwrite = false,
                                          ImageProgressFn progress = nullptr);

        // True when the path looks like a package (by extension and magic).
        static bool IsPackage(const std::string& path);
    };

} // namespace App
} // namespace Dracula
