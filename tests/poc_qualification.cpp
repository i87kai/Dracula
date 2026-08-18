#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <cassert>

// Include SQLite
#include "sqlite3.h"

// Include Zstandard
#include "zstd.h"

int main() {
    std::cout << "[POC] Testing SQLite Amalgamation..." << std::endl;
    std::cout << "  SQLite Version: " << sqlite3_libversion() << std::endl;

    sqlite3* db = nullptr;
    int rc = sqlite3_open(":memory:", &db);
    assert(rc == SQLITE_OK && db != nullptr);

    char* errMsg = nullptr;
    rc = sqlite3_exec(db, "CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT);", nullptr, nullptr, &errMsg);
    assert(rc == SQLITE_OK);

    rc = sqlite3_exec(db, "INSERT INTO test (name) VALUES ('Dracula UTR Session 1');", nullptr, nullptr, &errMsg);
    assert(rc == SQLITE_OK);

    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, "SELECT id, name FROM test WHERE id = 1;", -1, &stmt, nullptr);
    assert(rc == SQLITE_OK);

    rc = sqlite3_step(stmt);
    assert(rc == SQLITE_ROW);
    int id = sqlite3_column_int(stmt, 0);
    const unsigned char* name = sqlite3_column_text(stmt, 1);
    assert(id == 1);
    assert(std::string(reinterpret_cast<const char*>(name)) == "Dracula UTR Session 1");
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    std::cout << "  SQLite POC: PASSED!" << std::endl;

    std::cout << "[POC] Testing Zstandard Compression..." << std::endl;
    std::cout << "  Zstd Version: " << ZSTD_versionString() << std::endl;

    std::string originalData = "Dracula Universal Target Runtime - Deterministic Memory Snapshot Verification String 0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (int i = 0; i < 20; ++i) {
        originalData += " Additional repetitive payload data for memory compression testing.";
    }

    size_t origSize = originalData.size();
    size_t maxCompressedSize = ZSTD_compressBound(origSize);
    std::vector<uint8_t> compressed(maxCompressedSize);

    size_t compressedSize = ZSTD_compress(compressed.data(), maxCompressedSize, originalData.data(), origSize, 3);
    assert(!ZSTD_isError(compressedSize));
    std::cout << "  Original size: " << origSize << " bytes, Compressed size: " << compressedSize << " bytes" << std::endl;
    assert(compressedSize < origSize);

    std::vector<uint8_t> decompressed(origSize);
    size_t decompressedSize = ZSTD_decompress(decompressed.data(), origSize, compressed.data(), compressedSize);
    assert(!ZSTD_isError(decompressedSize));
    assert(decompressedSize == origSize);
    assert(std::memcmp(decompressed.data(), originalData.data(), origSize) == 0);
    std::cout << "  Zstd POC: PASSED! (Byte-exact round-trip verified)" << std::endl;

    std::cout << "[POC] All Third-Party Qualification Tests Passed!" << std::endl;
    return 0;
}
