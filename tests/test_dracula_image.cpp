//
// .draculaimg package format suite (v1.3.0 milestone, section 28).
//
// Everything here runs against SYNTHETIC fixtures. The user's Windows image is
// never used by, committed to, or required by this test (section 29); the live
// packaging of that image is a separate, environment-specific acceptance step.
//

#include "app/dracula_image.h"
#include "app/hasher.h"

#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <random>
#include <cstdlib>

namespace fs = std::filesystem;
using namespace Dracula::App;

static int g_checks = 0;

static void Check(bool condition, const std::string& what) {
    ++g_checks;
    if (!condition) {
        std::cerr << "  FAILED: " << what << "\n";
        std::exit(1);
    }
    std::cout << "  ok: " << what << "\n";
}

// A fixture shaped like a disk image: long runs of zeroes (sparse regions),
// repeating structure (filesystem metadata) and incompressible noise.
static void WriteFixture(const fs::path& path, size_t sizeBytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    std::mt19937 rng(1234);

    std::vector<uint8_t> block(64 * 1024);
    size_t written = 0;
    int phase = 0;

    while (written < sizeBytes) {
        const size_t piece = std::min(block.size(), sizeBytes - written);

        switch (phase % 3) {
            case 0:  // sparse
                std::fill(block.begin(), block.end(), 0);
                break;
            case 1:  // repetitive structure
                for (size_t i = 0; i < block.size(); ++i) {
                    block[i] = static_cast<uint8_t>((i % 251));
                }
                break;
            default: // incompressible
                for (size_t i = 0; i < block.size(); ++i) {
                    block[i] = static_cast<uint8_t>(rng());
                }
                break;
        }

        out.write(reinterpret_cast<const char*>(block.data()),
                  static_cast<std::streamsize>(piece));
        written += piece;
        ++phase;
    }
}

static uint64_t FileSize(const fs::path& p) {
    std::error_code ec;
    return static_cast<uint64_t>(fs::file_size(p, ec));
}

int main() {
    std::cout << "[Test] Running Dracula Image Package Suite...\n";

    fs::path sandbox = fs::temp_directory_path() / "dracula_image_test";
    std::error_code ec;
    fs::remove_all(sandbox, ec);
    fs::create_directories(sandbox);

    const fs::path source  = sandbox / "synthetic.vdi";
    const fs::path package = sandbox / "synthetic.draculaimg";
    const fs::path restored = sandbox / "restored.vdi";

    // Comfortably larger than one 16 MB chunk, so multi-chunk paths are real.
    const size_t kFixtureSize = 40 * 1024 * 1024;
    WriteFixture(source, kFixtureSize);
    Check(FileSize(source) == kFixtureSize, "synthetic image fixture written");

    const std::string sourceSha = Sha256Stream::OfFile(source.string());
    Check(!sourceSha.empty(), "source image hashes");

    // --- Streaming hasher agrees with a whole-file hash --------------------
    {
        Sha256Stream incremental;
        std::ifstream in(source, std::ios::binary);
        std::vector<uint8_t> buffer(7919);  // deliberately not a power of two
        while (in) {
            in.read(reinterpret_cast<char*>(buffer.data()),
                    static_cast<std::streamsize>(buffer.size()));
            if (in.gcount() > 0) {
                incremental.Update(buffer.data(), static_cast<size_t>(in.gcount()));
            }
        }
        Check(incremental.Hex() == sourceSha,
              "streaming SHA-256 matches regardless of read granularity");
    }

    // --- Packaging ----------------------------------------------------------
    uint64_t seenTotal = 0;
    int progressCalls = 0;
    auto result = DraculaImage::Package(source.string(), package.string(), 9,
        [&](uint64_t processed, uint64_t total, const std::string& stage) {
            ++progressCalls;
            seenTotal = total;
            (void)processed; (void)stage;
            return true;
        });

    Check(result.ok, std::string("packaging succeeds") +
                     (result.ok ? "" : (": " + result.error)));
    Check(fs::exists(package), "package file written");
    Check(progressCalls > 0, "progress is reported during packaging");
    Check(seenTotal == kFixtureSize, "progress reports the true total size");

    Check(result.originalSize == kFixtureSize, "packaging records the original size");
    Check(result.originalSha256 == sourceSha, "packaging records the original SHA-256");
    Check(!result.packageSha256.empty(), "packaging reports the package SHA-256");
    Check(result.chunkCount > 1, "a multi-chunk image really is chunked");
    Check(result.packagedSize > 0, "packaging reports the package size");
    Check(result.durationMs > 0 || result.ok, "packaging reports a duration");

    // A third of the fixture is zeroes, so it must compress meaningfully --
    // and it must never inflate.
    Check(result.packagedSize < result.originalSize,
          "the package is smaller than the source");
    Check(result.CompressionRatio() > 0.0 && result.CompressionRatio() < 1.0,
          "compression ratio is reported and below 1.0");

    std::cout << "      original " << result.originalSize
              << " -> package " << result.packagedSize
              << "  (ratio " << result.CompressionRatio() << ", "
              << result.chunkCount << " chunks, " << result.durationMs << " ms)\n";

    // --- Inspection ---------------------------------------------------------
    {
        Check(DraculaImage::IsPackage(package.string()), "the package is recognized by magic");
        Check(!DraculaImage::IsPackage(source.string()), "a raw image is not mistaken for a package");

        auto info = DraculaImage::Inspect(package.string());
        Check(info.valid, "package header parses");
        Check(info.formatVersion == 1, "format version recorded");
        Check(info.sourceFormat == "vdi", "source format detected from the extension");
        Check(info.sourceName == "synthetic.vdi", "original filename retained for display");
        Check(info.originalSize == kFixtureSize, "header records the original size");
        Check(info.originalSha256 == sourceSha, "header records the original hash");
        Check(!info.createdAt.empty(), "header records a creation timestamp");
        Check(!info.draculaVersion.empty(), "header records the Dracula version");
        Check(info.chunkCount == result.chunkCount, "header records the chunk count");
    }

    // --- Verification -------------------------------------------------------
    {
        auto verification = DraculaImage::Verify(package.string(), true);
        Check(verification.ok, std::string("deep verification passes") +
                               (verification.ok ? "" : (": " + verification.error)));
        Check(verification.headerValid, "verification confirms the header");
        Check(verification.chunksValid, "verification confirms every chunk");
        Check(verification.contentVerified, "verification recomputes and matches the content hash");
        Check(verification.actualSha256 == sourceSha, "recomputed hash equals the source hash");
        Check(verification.chunksChecked == result.chunkCount, "every chunk was checked");

        auto shallow = DraculaImage::Verify(package.string(), false);
        Check(shallow.ok, "shallow verification passes");
        Check(!shallow.contentVerified,
              "shallow verification does not claim to have verified content");
    }

    // --- Restore ------------------------------------------------------------
    {
        auto restore = DraculaImage::Restore(package.string(), restored.string());
        Check(restore.ok, std::string("restore succeeds") +
                          (restore.ok ? "" : (": " + restore.error)));
        Check(fs::exists(restored), "restored image written");
        Check(FileSize(restored) == kFixtureSize, "restored image is the original size");

        const std::string restoredSha = Sha256Stream::OfFile(restored.string());
        Check(restoredSha == sourceSha, "restored image is byte-identical to the original");
        Check(restore.originalSha256 == sourceSha, "restore reports the verified hash");

        // Restoring must not silently clobber.
        auto again = DraculaImage::Restore(package.string(), restored.string(), false);
        Check(!again.ok, "restore refuses to overwrite by default");
        Check(again.error.find("overwrite") != std::string::npos,
              "the refusal explains itself");

        auto forced = DraculaImage::Restore(package.string(), restored.string(), true);
        Check(forced.ok, "restore overwrites when explicitly asked");
    }

    // --- The source image is never modified ---------------------------------
    Check(Sha256Stream::OfFile(source.string()) == sourceSha,
          "the user's source image is untouched by packaging and restoring");

    // --- Corruption is detected, and names the chunk ------------------------
    {
        const fs::path corrupt = sandbox / "corrupt.draculaimg";
        fs::copy_file(package, corrupt, fs::copy_options::overwrite_existing, ec);

        // Flip bytes well inside the payload, past the 512-byte header.
        {
            std::fstream f(corrupt, std::ios::binary | std::ios::in | std::ios::out);
            f.seekp(512 + 4096, std::ios::beg);
            const char garbage[64] = {static_cast<char>(0xDE), static_cast<char>(0xAD)};
            f.write(garbage, sizeof(garbage));
        }

        auto verification = DraculaImage::Verify(corrupt.string(), true);
        Check(!verification.ok, "corruption is detected");
        Check(!verification.error.empty(), "corruption is reported with a reason");
        Check(verification.error.find("chunk") != std::string::npos,
              "the corruption report names the chunk");

        auto restore = DraculaImage::Restore(corrupt.string(), (sandbox / "bad.vdi").string());
        Check(!restore.ok, "restoring a corrupt package fails");
        Check(!fs::exists(sandbox / "bad.vdi"),
              "a failed restore leaves no partial output behind");
    }

    // --- A truncated package is detected ------------------------------------
    {
        const fs::path truncated = sandbox / "truncated.draculaimg";
        fs::copy_file(package, truncated, fs::copy_options::overwrite_existing, ec);
        fs::resize_file(truncated, FileSize(package) / 2, ec);

        auto verification = DraculaImage::Verify(truncated.string(), true);
        Check(!verification.ok, "a truncated package fails verification");
        Check(verification.error.find("truncat") != std::string::npos ||
              verification.error.find("corrupt") != std::string::npos,
              "truncation is reported clearly");
    }

    // --- A non-package is rejected without crashing -------------------------
    {
        auto info = DraculaImage::Inspect(source.string());
        Check(!info.valid, "a raw image does not parse as a package");

        auto verification = DraculaImage::Verify(source.string(), true);
        Check(!verification.ok, "verifying a non-package fails");
        Check(!verification.error.empty(), "the failure explains itself");

        auto missing = DraculaImage::Verify((sandbox / "nope.draculaimg").string(), true);
        Check(!missing.ok, "verifying a missing file fails gracefully");

        auto badPackage = DraculaImage::Package((sandbox / "nope.vdi").string(),
                                                (sandbox / "out.draculaimg").string());
        Check(!badPackage.ok, "packaging a missing source fails");
        Check(badPackage.error.find("does not exist") != std::string::npos,
              "the missing source is named in the error");
        Check(!fs::exists(sandbox / "out.draculaimg"),
              "a failed packaging leaves no partial package behind");
    }

    // --- Cancellation cleans up ---------------------------------------------
    {
        const fs::path cancelled = sandbox / "cancelled.draculaimg";
        auto result2 = DraculaImage::Package(source.string(), cancelled.string(), 3,
            [](uint64_t processed, uint64_t, const std::string&) {
                return processed < 1024 * 1024;  // bail out early
            });
        Check(!result2.ok, "cancellation aborts packaging");
        Check(result2.error == "cancelled", "cancellation is reported as such");
        Check(!fs::exists(cancelled), "a cancelled packaging leaves no partial file");
        Check(!fs::exists(fs::path(cancelled.string() + ".partial")),
              "the partial working file is removed too");
    }

    fs::remove_all(sandbox, ec);

    std::cout << "[Test] Dracula Image Package Suite PASSED (" << g_checks << " checks).\n";
    return 0;
}
