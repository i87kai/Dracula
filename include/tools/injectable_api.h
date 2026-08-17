#pragma once

// ============================================================================
//  injectable_api.h  --  Shared ABI between HostController.exe and the
//                         injectable analysis DLL (InjectableDLL.dll).
//
//  Communication channel: Named Pipe
//    Server: injectable DLL (inside target process)
//    Client: HostController.exe (reads results after injection)
//
//  All structs are POD / fixed-size so they cross the process boundary safely.
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>

// ------------------------------------------------------------------
// Named Pipe name (both sides must agree on this string)
// ------------------------------------------------------------------
#define INJECT_PIPE_NAME  L"\\\\.\\pipe\\SandboxInjectorPipe"
#define INJECT_PIPE_TIMEOUT_MS  10000   // 10 s wait for DLL to connect

// ------------------------------------------------------------------
// Maximum limits
// ------------------------------------------------------------------
#define INJECT_MAX_OFFSETS      256     // Max found offsets per scan
#define INJECT_MAX_MODULES       64     // Max reported loaded DLLs
#define INJECT_MAX_NAME_LEN      128    // String field length (chars)
#define INJECT_MAX_PATTERN_MATCHES 64   // Max AOB matches returned

// ------------------------------------------------------------------
// Packet / message type tags written to the pipe
// ------------------------------------------------------------------
enum class InjectMsgType : uint32_t {
    // DLL → Host
    StatusMessage   = 1,   // Human-readable progress text
    FoundOffset     = 2,   // A single named offset result
    RegisterValues  = 3,   // CPU register state snapshot
    ModuleList      = 4,   // Loaded module / DLL list
    UnicornResult   = 5,   // Unicorn emulation summary
    PatternMatch    = 6,   // AOB pattern hit
    MathResult      = 7,   // Arithmetic analysis result
    DoneMarker      = 99,  // DLL finished, no more packets
};

// ------------------------------------------------------------------
// Packet header (precedes every payload on the pipe)
// ------------------------------------------------------------------
#pragma pack(push, 1)
struct InjectPacketHeader {
    InjectMsgType type;    // Which payload follows
    uint32_t      payloadSize; // Bytes of the payload struct
};

// ------------------------------------------------------------------
// STATUS MESSAGE  (human-readable progress / log line)
// ------------------------------------------------------------------
struct InjectMsg_Status {
    char text[512];    // UTF-8 log line from inside the target process
};

// ------------------------------------------------------------------
// FOUND OFFSET  –  a single discovered pointer / offset with a
//                  descriptive name (e.g. "PlayerHealth", "LocalPlayer",
//                  "ViewMatrix", "EntityBase", "WeaponAmmo" …)
// ------------------------------------------------------------------
struct InjectMsg_FoundOffset {
    char     offsetName[INJECT_MAX_NAME_LEN];   // Human-readable label
    char     moduleName[INJECT_MAX_NAME_LEN];   // Owning module (e.g. "game.exe")
    uint64_t absoluteAddress;                   // Absolute VA inside target
    uint64_t rva;                               // RVA from module base
    uint64_t moduleBase;                        // Module image base
    uint8_t  patternBytes[32];                  // The bytes that matched
    uint32_t patternLen;                        // How many bytes matched
    char     patternHex[96];                    // "48 8B 05 ?? ?? ?? ??" text
    char     derefChain[256];                   // Optional pointer chain
    bool     isWritable;                        // Memory protection includes WRITE
    bool     isExecutable;                      // Memory protection includes EXEC
};

// ------------------------------------------------------------------
// REGISTER VALUES  –  CPU register snapshot from Unicorn emulation
// ------------------------------------------------------------------
struct InjectMsg_RegisterValues {
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rsp, rbp;
    uint64_t r8,  r9,  r10, r11;
    uint64_t r12, r13, r14, r15;
    uint64_t rip;
    uint64_t rflags;
    uint64_t instructionsExecuted;
    uint64_t emulationBaseAddr;
    char     terminationReason[64];  // uc_strerror text
};

// ------------------------------------------------------------------
// MODULE ENTRY  –  one loaded DLL / module inside the target
// ------------------------------------------------------------------
struct InjectMsg_ModuleEntry {
    char     moduleName[INJECT_MAX_NAME_LEN];
    char     modulePath[MAX_PATH];
    uint64_t baseAddress;
    uint64_t sizeOfImage;
    uint32_t entryPointRva;
    bool     isExecutable;
    bool     isMainModule;
};

// ------------------------------------------------------------------
// UNICORN RESULT SUMMARY
// ------------------------------------------------------------------
struct InjectMsg_UnicornResult {
    uint64_t emulatedAddress;        // VA of emulated code window
    uint64_t emulatedSize;           // Bytes emulated
    uint64_t instructionsExecuted;
    uint64_t stopRip;
    bool     success;
    bool     completedCleanly;
    char     terminationReason[64];
    uint32_t rawErrorCode;
    // Register snapshot at stop
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, rip;
};

// ------------------------------------------------------------------
// PATTERN (AOB) MATCH
// ------------------------------------------------------------------
struct InjectMsg_PatternMatch {
    char     patternDescription[128]; // Human label for the pattern
    uint64_t matchAddress;            // Absolute VA of match
    uint64_t rva;                     // RVA from module base
    char     moduleName[INJECT_MAX_NAME_LEN];
    uint64_t moduleBase;
    uint8_t  contextBytes[32];        // Bytes around the match
    uint32_t contextLen;
    char     hexDump[96];             // Hex of contextBytes
};

// ------------------------------------------------------------------
// MATH / ARITHMETIC RESULT  (derived values computed in-process)
// ------------------------------------------------------------------
struct InjectMsg_MathResult {
    char     label[INJECT_MAX_NAME_LEN];   // e.g. "EntityArrayStride"
    int64_t  valueInt;                     // Signed integer result
    double   valueFloat;                   // Floating-point result
    char     formula[256];                 // Human-readable formula used
    char     unit[32];                     // "bytes", "fps", "ms", etc.
};

#pragma pack(pop)

// ------------------------------------------------------------------
// Helper: write a typed packet to a pipe handle
// ------------------------------------------------------------------
#ifdef __cplusplus
#include <type_traits>
template<typename T>
inline bool InjectWritePacket(HANDLE pipe, InjectMsgType type, const T& payload) {
    static_assert(std::is_trivially_copyable_v<T>, "Payload must be trivially copyable");
    InjectPacketHeader hdr{ type, static_cast<uint32_t>(sizeof(T)) };
    DWORD written = 0;
    if (!WriteFile(pipe, &hdr, sizeof(hdr), &written, nullptr)) return false;
    if (!WriteFile(pipe, &payload, sizeof(T), &written, nullptr)) return false;
    return true;
}

inline bool InjectWriteStatus(HANDLE pipe, const char* text) {
    InjectMsg_Status msg{};
    strncpy_s(msg.text, text, _TRUNCATE);
    return InjectWritePacket(pipe, InjectMsgType::StatusMessage, msg);
}
#endif // __cplusplus
