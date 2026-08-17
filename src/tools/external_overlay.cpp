// ============================================================================
//  external_overlay.cpp  –  i87k External ESP / Offset Monitor Overlay  v2.0
//
//  Standalone transparent DirectX 11 + ImGui overlay (external / no inject).
//  Attaches read-only to the target process and every frame:
//    1. Reads all 13 game offsets via ReadProcessMemory.
//    2. Displays a live "Offset Monitor" panel with real values.
//    3. Renders ESP primitives on the ImGui DrawList using WorldToScreen.
//    4. Highlights the entity currently under the player crosshair.
//    5. Shows the full 4x4 ViewMatrix in a collapsible panel.
//    6. Runs Unicorn Engine 2 CPU emulation on code-type offsets in background.
//
//  Controls:
//    INSERT  – toggle side menu (window is click-through when menu hidden)
//    END     – exit overlay
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dwmapi.h>
#include <d3d11.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cmath>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <atomic>
#include <thread>
#include <mutex>
#include <chrono>

#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx11.h"

#include "unicorn/unicorn.h"
#include "unicorn/x86.h"

// ─── Offset Table ─────────────────────────────────────────────────────────────
// All RVAs are relative to the main module base.
// Signatures follow IDA/x64dbg style: "XX XX ?? ?? XX" (? = wildcard byte)
// ──────────────────────────────────────────────────────────────────────────────
struct GameOffset {
    const char* name;
    uint64_t    rva;
    const char* type;        // "ptr64","matrix4x4","float","uint32","code"
    const char* description;
    const char* aob;         // AOB signature (space-separated, ?? = wildcard)
    int         aobDispOff;  // byte index of the disp32 inside the instruction
    int         aobInstrLen; // total instruction length (for RIP-relative calc)
};

static const GameOffset g_Offsets[] = {
    // ── Pointer offsets ────────────────────────────────────────────────────
    {
        "LocalPlayer",    0x11C05698ULL, "ptr64",
        "LocalPlayer instance pointer (PlayerController/Pawn during match)",
        "48 8B 05 ?? ?? ?? ?? 48 85 C0", 3, 7
    },
    {
        "ProfileManager", 0x11740280ULL, "ptr64",
        "Account data & user stats",
        "48 8B 05 ?? ?? ?? ?? 33 D2 48 8B 48", 3, 7
    },
    {
        "UE_GWorld",      0x11C103C8ULL, "ptr64",
        "GameManager / World instance",
        "48 8B 1D ?? ?? ?? ?? 48 85 DB 74", 3, 7
    },
    {
        "UE_GNames",      0x11ACED98ULL, "ptr64",
        "Name & string hash table",
        "48 8B 05 ?? ?? ?? ?? EB ?? 48 8D 05", 3, 7
    },
    // ── Matrix ─────────────────────────────────────────────────────────────
    {
        "ViewMatrix",     0x11C9F7D8ULL, "matrix4x4",
        "Camera 4x4 WorldToScreen view-projection (Row-Major)",
        "48 8B 0D ?? ?? ?? ?? F3 0F 10", 3, 7
    },
    // ── More pointers ──────────────────────────────────────────────────────
    {
        "EntityList",     0x11C00A80ULL, "ptr64",
        "Entity / player actor array (active match players)",
        "4C 8D 05 ?? ?? ?? ?? 48 8B CE", 3, 7
    },
    {
        "D3D11_Context",  0x11C82590ULL, "ptr64",
        "DX11 Device Context (used for render-hook / overlay attach)",
        "48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 90", 3, 7
    },
    // ── Code / routine offsets (Unicorn-emulated) ──────────────────────────
    {
        "PlayerHealth",   0x46C98FULL,   "code",
        "Health decrement SSE scalar float: MOVSS xmm0,[rbx+0x??] SUBSS xmm0,xmm1",
        "F3 0F 10 ?? ?? F3 0F 5C ?? ?? F3 0F 11", 0, 13
    },
    {
        "WeaponAmmo",     0x10519F2ULL,  "code",
        "Ammo load + conditional branch: MOV ecx,[rbx+disp] TEST ecx,ecx JZ",
        "8B 8B ?? ?? ?? ?? 85 C9 0F 84", 2, 6
    },
    {
        "MoveSpeed",      0xEF5425ULL,   "code",
        "Movement speed scale: MULSS xmm0,[rbx+??] then MOVSS store",
        "F3 0F 59 ?? ?? F3 0F 11 ?? ?? F3 0F 10", 0, 13
    },
    {
        "BoneMatrix",     0xBFBE28ULL,   "code",
        "Skeleton bone transform resolver: MOV r8,[rdi+rva_BoneArray]",
        "4C 8B 87 ?? ?? ?? ?? 4D 85 C0", 3, 7
    },
    // ── Float / uint32 ─────────────────────────────────────────────────────
    {
        "MouseSens",      0x10EEEEF8ULL, "float",
        "Mouse sensitivity & FOV multiplier (global float)",
        "F3 0F 10 05 ?? ?? ?? ?? F3 0F 59", 4, 8
    },
    {
        "CrosshairId",    0x11C052D0ULL, "uint32",
        "Entity ID currently under the crosshair / reticle",
        "8B 05 ?? ?? ?? ?? 85 C0 74", 2, 6
    },
};
static constexpr int OFFSET_COUNT = static_cast<int>(sizeof(g_Offsets) / sizeof(g_Offsets[0]));

// ─── Live reading result ──────────────────────────────────────────────────────
struct LiveValue {
    bool     valid   = false;
    uint64_t raw64   = 0;
    float    fVal    = 0.0f;
    uint32_t u32     = 0;
    float    mat[16] = {};
    uint8_t  code[16] = {};
    char     display[128] = "---";
};

// ─── Unicorn emulation result per code offset ─────────────────────────────────
struct UcResult {
    bool     done    = false;
    bool     ok      = false;
    uint64_t instrCount = 0;
    uint64_t stopRip    = 0;
    // General-purpose registers
    uint64_t rax = 0, rcx = 0, rdx = 0, rbx = 0;
    uint64_t rsi = 0, rdi = 0, r8  = 0, r9  = 0;
    // XMM0-XMM3 (lo 64-bit of each 128-bit register)
    uint64_t xmm0lo = 0, xmm1lo = 0, xmm2lo = 0, xmm3lo = 0;
    float    xmm0f  = 0.f, xmm1f = 0.f, xmm2f = 0.f, xmm3f = 0.f;
    char     errStr[64] = "---";
    char     summary[256] = "---";
};

// ─── DX11 globals ─────────────────────────────────────────────────────────────
static ID3D11Device*           g_pDev   = nullptr;
static ID3D11DeviceContext*    g_pCtx   = nullptr;
static IDXGISwapChain*         g_pChain = nullptr;
static ID3D11RenderTargetView* g_pRTV   = nullptr;
static HWND                    g_hwnd   = nullptr;

// ─── Process / memory globals ─────────────────────────────────────────────────
static HANDLE   g_hProc    = INVALID_HANDLE_VALUE;
static uint64_t g_base     = 0;
static uint32_t g_pid      = 0;
static char     g_procNameBuf[MAX_PATH] = "RainbowSix.exe";
static bool     g_attached  = false;
static uint64_t g_viewDataBase = 0;
static float    g_cameraPos[3] = { 0.f, 0.f, 0.f };

// ─── Shared game state ────────────────────────────────────────────────────────
static std::mutex g_mx;
static LiveValue  g_live[OFFSET_COUNT];
static float      g_viewMat[16] = {};
static uint32_t   g_crosshairId = 0;
static uint64_t   g_localPlayer = 0;
static float      g_mouseSens   = 0.0f;
static double     g_readMs      = 0.0;

// ─── Unicorn results (one per code offset, updated in bg thread) ──────────────
// Indices into g_Offsets that are type "code":
//   7=PlayerHealth, 8=WeaponAmmo, 9=MoveSpeed, 10=BoneMatrix
static constexpr int UC_SLOT_COUNT = 4;
static constexpr int UC_SLOTS[UC_SLOT_COUNT] = { 7, 8, 9, 10 };
static std::mutex   g_ucMx;
static UcResult     g_ucResults[UC_SLOT_COUNT];
static std::atomic<bool> g_ucBusy { false };

// ─── UI state ─────────────────────────────────────────────────────────────────
static std::atomic<bool> g_running { true };
static bool  g_showMenu      = true;
static bool  g_showESP       = true;
static bool  g_showSkeleton  = true;
static bool  g_showCrosshair = true;
static bool  g_showUcPanel   = false;
static float g_espLineW      = 1.5f;
static int   g_screenW       = 1920;
static int   g_screenH       = 1080;
static UINT  g_resizeW       = 0, g_resizeH = 0;

// ─── ViewData Heuristic Signature ─────────────────────────────────────────────
static const uint8_t kViewDataPattern[] = {
    0xA4, 0x70, 0x7D, 0xBF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x40,
    0x00, 0x00, 0xA0, 0xC0, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xCD, 0xCC, 0x4C, 0x3F,
    0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x80, 0x3E
};
static constexpr size_t kViewDataPatternLen = sizeof(kViewDataPattern);

// ─── Color palette ────────────────────────────────────────────────────────────
static constexpr ImU32 COL_CYAN   = IM_COL32(  0, 229, 255, 255);
static constexpr ImU32 COL_GREEN  = IM_COL32( 30, 229, 140, 255);
static constexpr ImU32 COL_AMBER  = IM_COL32(255, 200,  38, 255);
static constexpr ImU32 COL_RED    = IM_COL32(255,  71,  97, 255);
static constexpr ImU32 COL_PURPLE = IM_COL32(178,  97, 255, 255);
static constexpr ImU32 COL_WHITE  = IM_COL32(230, 235, 255, 255);
static constexpr ImU32 COL_GRAY   = IM_COL32( 80,  90, 115, 200);

// ─── Helpers ──────────────────────────────────────────────────────────────────
static uint32_t FindPid(const char* name) {
    uint32_t pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static uint64_t GetModBase(HANDLE hProc, const char* modName) {
    HMODULE mods[512]; DWORD needed = 0;
    if (!EnumProcessModules(hProc, mods, sizeof(mods), &needed)) return 0;
    for (DWORD i = 0; i < needed / sizeof(HMODULE); ++i) {
        char name[MAX_PATH] = {};
        GetModuleBaseNameA(hProc, mods[i], name, sizeof(name));
        if (_stricmp(name, modName) == 0) {
            MODULEINFO mi = {};
            GetModuleInformation(hProc, mods[i], &mi, sizeof(mi));
            return reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
        }
    }
    return 0;
}

template<typename T>
static bool RPM(uint64_t addr, T& out) {
    SIZE_T n = 0;
    return (g_hProc != INVALID_HANDLE_VALUE) &&
           ReadProcessMemory(g_hProc, reinterpret_cast<LPCVOID>(addr), &out, sizeof(T), &n) &&
           (n == sizeof(T));
}

static bool RPMBytes(uint64_t addr, void* buf, size_t sz) {
    SIZE_T n = 0;
    return (g_hProc != INVALID_HANDLE_VALUE) &&
           ReadProcessMemory(g_hProc, reinterpret_cast<LPCVOID>(addr), buf, sz, &n) &&
           (n == sz);
}

static bool IsValidMatrix(const float* m) {
    if (!m) return false;
    float sumAbs = 0.0f;
    for (int i = 0; i < 16; ++i) {
        if (!std::isfinite(m[i]) || std::fabs(m[i]) > 5000.0f) return false;
        sumAbs += std::fabs(m[i]);
    }
    return (sumAbs >= 0.05f && sumAbs <= 200.0f);
}

static uint64_t ScanForViewData(HANDLE hProc, uint64_t baseAddr) {
    if (hProc == INVALID_HANDLE_VALUE) return 0;

    // Fast path: try the known static RVA
    if (baseAddr) {
        uint64_t candidatePtr = 0;
        if (RPM(baseAddr + 0x11C9F7D8ULL, candidatePtr) &&
            candidatePtr >= 0x10000 && candidatePtr <= 0x00007FFFFFFFFFFFULL)
        {
            float testMat[16] = {};
            if (RPM(candidatePtr + 0x250ULL, testMat) && IsValidMatrix(testMat))
                return candidatePtr;
            if (candidatePtr >= 0x2A4ULL &&
                RPM(candidatePtr - 0x2A4ULL + 0x250ULL, testMat) && IsValidMatrix(testMat))
                return candidatePtr - 0x2A4ULL;
        }
    }

    // Full memory scan fallback
    MEMORY_BASIC_INFORMATION mbi{};
    uint8_t* cur = reinterpret_cast<uint8_t*>(0x10000);
    while (VirtualQueryEx(hProc, cur, &mbi, sizeof(mbi))) {
        if ((mbi.State == MEM_COMMIT) &&
            !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE |
                            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            (mbi.RegionSize <= 64 * 1024 * 1024))
        {
            std::vector<uint8_t> buffer(mbi.RegionSize);
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead) &&
                bytesRead >= kViewDataPatternLen)
            {
                for (size_t i = 0; i <= bytesRead - kViewDataPatternLen; ++i) {
                    if (memcmp(buffer.data() + i, kViewDataPattern, kViewDataPatternLen) == 0) {
                        uint64_t patternAddr = reinterpret_cast<uint64_t>(mbi.BaseAddress) + i;
                        return patternAddr - 0x2A4ULL;
                    }
                }
            }
        }
        uint64_t nextAddr = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (nextAddr <= reinterpret_cast<uint64_t>(cur) || nextAddr > 0x00007FFFFFFFFFFFULL) break;
        cur = reinterpret_cast<uint8_t*>(nextAddr);
    }
    return 0;
}

// ─── WorldToScreen ─────────────────────────────────────────────────────────────
// Matrix is stored Row-Major (standard UE4 / DirectX convention):
//   Row 0 → m[0..3],  Row 1 → m[4..7],  Row 2 → m[8..11],  Row 3 → m[12..15]
// Clip-space: cx = dot(Row0, [wx,wy,wz,1])
//             cy = dot(Row1, [wx,wy,wz,1])
//             cw = dot(Row3, [wx,wy,wz,1])
static bool W2S(float wx, float wy, float wz, float& sx, float& sy) {
    const float* m = g_viewMat;
    float cx = wx * m[ 0] + wy * m[ 1] + wz * m[ 2] + m[ 3];
    float cy = wx * m[ 4] + wy * m[ 5] + wz * m[ 6] + m[ 7];
    float cw = wx * m[12] + wy * m[13] + wz * m[14] + m[15];
    if (cw < 0.001f) return false;
    sx = (g_screenW * 0.5f) + (cx / cw) * (g_screenW * 0.5f);
    sy = (g_screenH * 0.5f) - (cy / cw) * (g_screenH * 0.5f);
    return true;
}

// ─── Unicorn Engine: emulate a code snippet read from live process ────────────
// Reads `readSz` bytes from the game process at `va`, maps them into an
// isolated Unicorn instance, runs up to `maxInstr` instructions, then
// captures GP + XMM registers.
static void UnicornEmulateCodeOffset(uint64_t va, size_t readSz,
                                     size_t maxInstr, UcResult& res)
{
    memset(&res, 0, sizeof(res));
    res.done = false;
    res.ok   = false;
    snprintf(res.errStr, sizeof(res.errStr), "---");

    if (g_hProc == INVALID_HANDLE_VALUE || !va) {
        snprintf(res.errStr, sizeof(res.errStr), "No process");
        res.done = true;
        return;
    }

    // Read code bytes from target process
    std::vector<uint8_t> code(readSz, 0);
    SIZE_T nr = 0;
    if (!ReadProcessMemory(g_hProc, reinterpret_cast<LPCVOID>(va),
                           code.data(), code.size(), &nr) || nr < 4) {
        snprintf(res.errStr, sizeof(res.errStr), "RPM failed (%zu bytes)", nr);
        res.done = true;
        return;
    }
    code.resize(nr);

    // Open Unicorn x86-64 engine
    uc_engine* uc = nullptr;
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK) {
        snprintf(res.errStr, sizeof(res.errStr), "uc_open: %s", uc_strerror(err));
        res.done = true;
        return;
    }

    // Map code region (page-aligned)
    constexpr uint64_t kPage = 0x1000ULL;
    uint64_t pageBase = va & ~(kPage - 1);
    uint64_t mapEnd   = (va + code.size() + kPage - 1) & ~(kPage - 1);
    uint64_t mapSz    = mapEnd - pageBase;
    if (uc_mem_map(uc, pageBase, mapSz, UC_PROT_ALL) != UC_ERR_OK ||
        uc_mem_write(uc, va, code.data(), code.size()) != UC_ERR_OK)
    {
        snprintf(res.errStr, sizeof(res.errStr), "mem_map/write failed");
        uc_close(uc);
        res.done = true;
        return;
    }

    // Map a scratch data region (for memory operand reads)
    constexpr uint64_t kDataBase = 0x0000600000000000ULL;
    constexpr uint64_t kDataSz   = 0x10000ULL;
    uc_mem_map(uc, kDataBase, kDataSz, UC_PROT_ALL);
    // Pre-fill with a float value of 1.0 at the base so XMM loads get
    // a valid (non-NaN) float rather than zero
    float fOne = 1.0f;
    uc_mem_write(uc, kDataBase, &fOne, sizeof(fOne));
    uc_mem_write(uc, kDataBase + 0x100, &fOne, sizeof(fOne));

    // Stack
    constexpr uint64_t kStackBase = 0x0000700000000000ULL;
    constexpr uint64_t kStackSz   = 0x10000ULL;
    uc_mem_map(uc, kStackBase, kStackSz, UC_PROT_ALL);
    uint64_t stackTop = kStackBase + kStackSz - 0x1000;
    uc_reg_write(uc, UC_X86_REG_RSP, &stackTop);
    uc_reg_write(uc, UC_X86_REG_RBP, &stackTop);

    // Seed GP registers with plausible pointers so [reg+disp] doesn't fault
    uint64_t dptr = kDataBase;
    uc_reg_write(uc, UC_X86_REG_RAX, &dptr);
    uc_reg_write(uc, UC_X86_REG_RBX, &dptr);
    uc_reg_write(uc, UC_X86_REG_RCX, &dptr);
    uc_reg_write(uc, UC_X86_REG_RDX, &dptr);
    uc_reg_write(uc, UC_X86_REG_RSI, &dptr);
    uc_reg_write(uc, UC_X86_REG_RDI, &dptr);
    uc_reg_write(uc, UC_X86_REG_R8,  &dptr);
    uc_reg_write(uc, UC_X86_REG_R9,  &dptr);
    uc_reg_write(uc, UC_X86_REG_R10, &dptr);
    uc_reg_write(uc, UC_X86_REG_R11, &dptr);
    // Seed XMM0-XMM3 with 1.0f in low dword
    {
        uint8_t xmmBuf[16] = {};
        memcpy(xmmBuf, &fOne, 4);
        uc_reg_write(uc, UC_X86_REG_XMM0, xmmBuf);
        uc_reg_write(uc, UC_X86_REG_XMM1, xmmBuf);
        uc_reg_write(uc, UC_X86_REG_XMM2, xmmBuf);
        uc_reg_write(uc, UC_X86_REG_XMM3, xmmBuf);
    }
    uc_reg_write(uc, UC_X86_REG_RIP, &va);

    // Instruction counter hook
    uint64_t instrCount = 0;
    uc_hook hCode = 0;
    auto codeHookCb = [](uc_engine*, uint64_t, uint32_t, void* ud) {
        (*static_cast<uint64_t*>(ud))++;
    };
    uc_hook_add(uc, &hCode, UC_HOOK_CODE,
                reinterpret_cast<void*>(+codeHookCb), &instrCount, 1, 0);

    // Unmapped memory hook – auto-map on-demand so [mem] operands don't crash
    struct AutoMapCtx { uc_engine* uc; uint64_t dataBase; };
    AutoMapCtx amCtx { uc, kDataBase };
    uc_hook hMem = 0;
    auto memHookCb = [](uc_engine* uc, uc_mem_type, uint64_t addr, int, int64_t, void* ud) -> bool {
        uint64_t pg = addr & ~0xFFFULL;
        return uc_mem_map(uc, pg, 0x1000, UC_PROT_ALL) == UC_ERR_OK;
    };
    uc_hook_add(uc, &hMem, UC_HOOK_MEM_UNMAPPED,
                reinterpret_cast<void*>(+memHookCb), &amCtx, 1, 0);

    // Emulate: timeout 500ms, max instructions
    uint64_t effectiveMax = (maxInstr == 0) ? 50 : maxInstr;
    err = uc_emu_start(uc, va, va + code.size(), 500000, effectiveMax);

    // Capture registers
    uc_reg_read(uc, UC_X86_REG_RIP, &res.stopRip);
    uc_reg_read(uc, UC_X86_REG_RAX, &res.rax);
    uc_reg_read(uc, UC_X86_REG_RBX, &res.rbx);
    uc_reg_read(uc, UC_X86_REG_RCX, &res.rcx);
    uc_reg_read(uc, UC_X86_REG_RDX, &res.rdx);
    uc_reg_read(uc, UC_X86_REG_RSI, &res.rsi);
    uc_reg_read(uc, UC_X86_REG_RDI, &res.rdi);
    uc_reg_read(uc, UC_X86_REG_R8,  &res.r8);
    uc_reg_read(uc, UC_X86_REG_R9,  &res.r9);

    // XMM registers (128-bit; read low 64-bit)
    {
        uint8_t xmmBuf[16] = {};
        uc_reg_read(uc, UC_X86_REG_XMM0, xmmBuf);
        memcpy(&res.xmm0lo, xmmBuf,     8);
        memcpy(&res.xmm0f,  xmmBuf,     4);

        uc_reg_read(uc, UC_X86_REG_XMM1, xmmBuf);
        memcpy(&res.xmm1lo, xmmBuf,     8);
        memcpy(&res.xmm1f,  xmmBuf,     4);

        uc_reg_read(uc, UC_X86_REG_XMM2, xmmBuf);
        memcpy(&res.xmm2lo, xmmBuf,     8);
        memcpy(&res.xmm2f,  xmmBuf,     4);

        uc_reg_read(uc, UC_X86_REG_XMM3, xmmBuf);
        memcpy(&res.xmm3lo, xmmBuf,     8);
        memcpy(&res.xmm3f,  xmmBuf,     4);
    }

    res.instrCount = instrCount;

    bool hardFail = (err != UC_ERR_OK &&
                     err != UC_ERR_READ_UNMAPPED &&
                     err != UC_ERR_WRITE_UNMAPPED &&
                     err != UC_ERR_FETCH_UNMAPPED);
    res.ok = !hardFail;
    snprintf(res.errStr, sizeof(res.errStr), "%s", uc_strerror(err));

    snprintf(res.summary, sizeof(res.summary),
             "Instrs:%llu  RIP:0x%llX\n"
             "RAX:0x%llX  RBX:0x%llX  RCX:0x%llX  RDX:0x%llX\n"
             "XMM0:%.4f  XMM1:%.4f  XMM2:%.4f  XMM3:%.4f",
             (unsigned long long)instrCount,
             (unsigned long long)res.stopRip,
             (unsigned long long)res.rax,
             (unsigned long long)res.rbx,
             (unsigned long long)res.rcx,
             (unsigned long long)res.rdx,
             res.xmm0f, res.xmm1f, res.xmm2f, res.xmm3f);

    uc_close(uc);
    res.done = true;
}

// ─── Background Unicorn thread (triggered manually or on first attach) ─────────
static void RunUnicornBatch() {
    if (g_ucBusy.exchange(true)) return; // already running
    std::thread([]() {
        // Snapshot base + handle under lock
        uint64_t base;
        {
            std::lock_guard<std::mutex> lk(g_mx);
            if (!g_attached || g_hProc == INVALID_HANDLE_VALUE) {
                g_ucBusy = false;
                return;
            }
            base = g_base;
        }

        for (int slot = 0; slot < UC_SLOT_COUNT; ++slot) {
            int idx = UC_SLOTS[slot];
            uint64_t va = base + g_Offsets[idx].rva;
            UcResult res{};
            UnicornEmulateCodeOffset(va, 64, 50, res);
            {
                std::lock_guard<std::mutex> lk(g_ucMx);
                g_ucResults[slot] = res;
            }
        }
        g_ucBusy = false;
    }).detach();
}

// ─── AOB scanner: scan module for a signature, return VA of match ─────────────
// Pattern format: "48 8B 05 ?? ?? ?? ??" (space-separated, "??" = wildcard)
static uint64_t ScanAOB(HANDLE hProc, uint64_t modBase, size_t modSize,
                         const char* pattern, uint64_t& outResolved,
                         int dispOff, int instrLen)
{
    outResolved = 0;
    if (!hProc || !modBase || !modSize || !pattern) return 0;

    // Parse pattern
    struct PatByte { uint8_t val; bool wild; };
    std::vector<PatByte> pat;
    const char* p = pattern;
    while (*p) {
        while (*p == ' ') ++p;
        if (!*p) break;
        if (p[0] == '?' && (p[1] == '?' || p[1] == ' ' || p[1] == '\0')) {
            pat.push_back({ 0, true });
            p += (p[1] == '?') ? 2 : 1;
        } else {
            uint8_t b = (uint8_t)strtoul(p, nullptr, 16);
            pat.push_back({ b, false });
            p += 2;
        }
    }
    if (pat.empty()) return 0;

    // Scan in chunks to avoid huge allocs
    constexpr size_t kChunk = 4 * 1024 * 1024; // 4 MB chunks
    std::vector<uint8_t> buf(kChunk);
    for (size_t off = 0; off < modSize; ) {
        size_t toRead = std::min(kChunk, modSize - off);
        SIZE_T nr = 0;
        if (!ReadProcessMemory(hProc,
                               reinterpret_cast<LPCVOID>(modBase + off),
                               buf.data(), toRead, &nr) || nr < pat.size())
        {
            off += toRead;
            continue;
        }
        for (size_t i = 0; i + pat.size() <= nr; ++i) {
            bool match = true;
            for (size_t j = 0; j < pat.size() && match; ++j)
                if (!pat[j].wild && buf[i + j] != pat[j].val) match = false;
            if (match) {
                uint64_t matchVa = modBase + off + i;
                // Resolve RIP-relative displacement if dispOff > 0
                if (dispOff > 0 && instrLen > 0 &&
                    (int)(i + dispOff + 4) <= (int)nr)
                {
                    int32_t disp = 0;
                    memcpy(&disp, buf.data() + i + dispOff, 4);
                    outResolved = matchVa + instrLen + disp;
                } else {
                    outResolved = matchVa;
                }
                return matchVa;
            }
        }
        off += toRead;
    }
    return 0;
}

// ─── Memory reader thread (~120 Hz) ───────────────────────────────────────────
static void ReaderThread() {
    using clock = std::chrono::high_resolution_clock;
    static bool s_ucTriggered = false;

    while (g_running.load()) {
        // Attach if needed
        if (!g_attached || g_hProc == INVALID_HANDLE_VALUE) {
            s_ucTriggered = false;
            uint32_t pid = FindPid(g_procNameBuf);
            if (pid) {
                HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
                if (h && h != INVALID_HANDLE_VALUE) {
                    char modName[MAX_PATH]; GetModuleBaseNameA(h, nullptr, modName, sizeof(modName));
                    uint64_t base = GetModBase(h, modName);
                    if (base) {
                        std::lock_guard<std::mutex> lk(g_mx);
                        if (g_hProc != INVALID_HANDLE_VALUE) CloseHandle(g_hProc);
                        g_hProc = h; g_base = base; g_pid = pid; g_attached = true;
                        g_viewDataBase = 0;
                    } else CloseHandle(h);
                }
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        // Trigger Unicorn batch once after first attach
        if (!s_ucTriggered) {
            s_ucTriggered = true;
            RunUnicornBatch();
        }

        auto t0 = clock::now();
        LiveValue tmp[OFFSET_COUNT];

        for (int i = 0; i < OFFSET_COUNT; ++i) {
            uint64_t va = g_base + g_Offsets[i].rva;
            LiveValue& v = tmp[i];
            const char* tp = g_Offsets[i].type;

            if (strcmp(tp, "ptr64") == 0) {
                v.valid = RPM(va, v.raw64);
                if (v.valid) snprintf(v.display, sizeof(v.display),
                                      "0x%016llX", (unsigned long long)v.raw64);

            } else if (strcmp(tp, "matrix4x4") == 0) {
                if (!g_viewDataBase)
                    g_viewDataBase = ScanForViewData(g_hProc, g_base);

                if (g_viewDataBase) {
                    float cam[3] = {};
                    float vMat[16] = {};
                    bool okCam = RPMBytes(g_viewDataBase + 0x190, cam, sizeof(cam));
                    bool okMat = RPMBytes(g_viewDataBase + 0x250, vMat, sizeof(vMat));

                    if (okMat && IsValidMatrix(vMat)) {
                        v.valid = true;
                        memcpy(v.mat, vMat, sizeof(vMat));
                        if (okCam && std::isfinite(cam[0])) {
                            memcpy(g_cameraPos, cam, sizeof(cam));
                            snprintf(v.display, sizeof(v.display),
                                     "Cam: [%.1f, %.1f, %.1f]", cam[0], cam[1], cam[2]);
                        } else {
                            snprintf(v.display, sizeof(v.display),
                                     "[%.2f %.2f %.2f ...]", vMat[0], vMat[5], vMat[10]);
                        }
                    } else {
                        g_viewDataBase = 0;
                        v.valid = false;
                        snprintf(v.display, sizeof(v.display), "Searching ViewData...");
                    }
                } else {
                    v.valid = false;
                    snprintf(v.display, sizeof(v.display), "Scanning memory...");
                }

            } else if (strcmp(tp, "float") == 0) {
                v.valid = RPM(va, v.fVal);
                if (v.valid && std::isfinite(v.fVal))
                    snprintf(v.display, sizeof(v.display), "%.4f", v.fVal);
                else
                    v.valid = false;

            } else if (strcmp(tp, "uint32") == 0) {
                v.valid = RPM(va, v.u32);
                if (v.valid) snprintf(v.display, sizeof(v.display),
                                      "%u  (0x%08X)", v.u32, v.u32);

            } else { // code
                v.valid = RPMBytes(va, v.code, sizeof(v.code));
                if (v.valid) {
                    char hex[48] = {}; int pos = 0;
                    for (int b = 0; b < 10 && pos < 46; ++b)
                        pos += snprintf(hex + pos, sizeof(hex) - pos, "%02X ", v.code[b]);
                    snprintf(v.display, sizeof(v.display), "%s...", hex);
                }
            }
        }

        // Check process alive
        DWORD ec = 0;
        if (!GetExitCodeProcess(g_hProc, &ec) || ec != STILL_ACTIVE) {
            std::lock_guard<std::mutex> lk(g_mx);
            CloseHandle(g_hProc); g_hProc = INVALID_HANDLE_VALUE;
            g_attached = false; g_base = 0; g_viewDataBase = 0;
            s_ucTriggered = false;
            memset(g_live, 0, sizeof(g_live));
            continue;
        }

        double ms = std::chrono::duration<double, std::milli>(clock::now() - t0).count();
        {
            std::lock_guard<std::mutex> lk(g_mx);
            memcpy(g_live, tmp, sizeof(tmp));
            if (tmp[4].valid)  memcpy(g_viewMat, tmp[4].mat, sizeof(g_viewMat));
            if (tmp[12].valid) g_crosshairId = tmp[12].u32;
            if (tmp[0].valid)  g_localPlayer  = tmp[0].raw64;
            if (tmp[11].valid) g_mouseSens    = tmp[11].fVal;
            g_readMs = ms;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(8)); // ~120 Hz
    }
}

// ─── DX11 management ──────────────────────────────────────────────────────────
static void CreateRTV() {
    ID3D11Texture2D* bb = nullptr;
    g_pChain->GetBuffer(0, IID_PPV_ARGS(&bb));
    if (bb) { g_pDev->CreateRenderTargetView(bb, nullptr, &g_pRTV); bb->Release(); }
}
static void DestroyRTV() { if (g_pRTV) { g_pRTV->Release(); g_pRTV = nullptr; } }

static bool InitDX11(HWND hwnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount        = 2;
    sd.BufferDesc.Format  = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage        = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow       = hwnd;
    sd.SampleDesc.Count   = 1;
    sd.Windowed           = TRUE;
    sd.SwapEffect         = DXGI_SWAP_EFFECT_DISCARD;
    sd.Flags              = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    D3D_FEATURE_LEVEL fl;
    const D3D_FEATURE_LEVEL fls[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
                                               fls, 2, D3D11_SDK_VERSION,
                                               &sd, &g_pChain, &g_pDev, &fl, &g_pCtx);
    if (FAILED(hr)) return false;
    CreateRTV();
    return true;
}
static void ShutdownDX11() {
    DestroyRTV();
    if (g_pChain) { g_pChain->Release(); g_pChain = nullptr; }
    if (g_pCtx)   { g_pCtx->Release();   g_pCtx   = nullptr; }
    if (g_pDev)   { g_pDev->Release();   g_pDev   = nullptr; }
}

// ─── WndProc ──────────────────────────────────────────────────────────────────
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);
LRESULT WINAPI OverlayWndProc(HWND hWnd, UINT msg, WPARAM wP, LPARAM lP) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wP, lP)) return true;
    switch (msg) {
    case WM_SIZE:
        if (wP != SIZE_MINIMIZED) { g_resizeW = LOWORD(lP); g_resizeH = HIWORD(lP); }
        return 0;
    case WM_SYSCOMMAND:
        if ((wP & 0xFFF0) == SC_KEYMENU) return 0;
        break;
    case WM_DESTROY:
        g_running = false; PostQuitMessage(0); return 0;
    case WM_NCHITTEST: {
        LRESULT hit = DefWindowProcW(hWnd, msg, wP, lP);
        if (!g_showMenu && hit == HTCLIENT) return HTTRANSPARENT;
        return hit;
    }
    }
    return DefWindowProcW(hWnd, msg, wP, lP);
}

// ─── ImGui style ──────────────────────────────────────────────────────────────
static void ApplyOverlayStyle() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding   = 10.0f; s.FrameRounding  = 6.0f;
    s.PopupRounding    =  8.0f; s.GrabRounding   = 6.0f;
    s.TabRounding      =  6.0f; s.WindowBorderSize= 1.0f;
    s.WindowPadding    = { 12.f, 10.f };
    s.FramePadding     = {  8.f,  5.f };
    s.ItemSpacing      = {  8.f,  6.f };
    s.ScrollbarSize    = 10.0f;

    ImVec4* c = s.Colors;
    c[ImGuiCol_WindowBg]         = { 0.06f, 0.07f, 0.10f, 0.88f };
    c[ImGuiCol_ChildBg]          = { 0.09f, 0.10f, 0.15f, 0.70f };
    c[ImGuiCol_Border]           = { 0.22f, 0.28f, 0.42f, 0.50f };
    c[ImGuiCol_FrameBg]          = { 0.10f, 0.12f, 0.18f, 0.70f };
    c[ImGuiCol_FrameBgHovered]   = { 0.14f, 0.17f, 0.26f, 0.80f };
    c[ImGuiCol_TitleBg]          = { 0.04f, 0.05f, 0.08f, 1.00f };
    c[ImGuiCol_TitleBgActive]    = { 0.06f, 0.08f, 0.14f, 1.00f };
    c[ImGuiCol_Header]           = { 0.12f, 0.20f, 0.38f, 0.60f };
    c[ImGuiCol_HeaderHovered]    = { 0.16f, 0.28f, 0.50f, 0.80f };
    c[ImGuiCol_Button]           = { 0.10f, 0.20f, 0.42f, 0.70f };
    c[ImGuiCol_ButtonHovered]    = { 0.14f, 0.30f, 0.60f, 0.90f };
    c[ImGuiCol_ButtonActive]     = { 0.18f, 0.38f, 0.75f, 1.00f };
    c[ImGuiCol_Tab]              = { 0.08f, 0.10f, 0.18f, 0.85f };
    c[ImGuiCol_TabHovered]       = { 0.14f, 0.28f, 0.55f, 0.90f };
    c[ImGuiCol_TabActive]        = { 0.12f, 0.24f, 0.50f, 1.00f };
    c[ImGuiCol_CheckMark]        = { 0.00f, 0.90f, 1.00f, 1.00f };
    c[ImGuiCol_SliderGrab]       = { 0.00f, 0.70f, 1.00f, 0.90f };
    c[ImGuiCol_Separator]        = { 0.24f, 0.30f, 0.44f, 0.45f };
    c[ImGuiCol_Text]             = { 0.90f, 0.92f, 0.98f, 1.00f };
    c[ImGuiCol_TextDisabled]     = { 0.45f, 0.50f, 0.65f, 1.00f };
    c[ImGuiCol_ScrollbarBg]      = { 0.04f, 0.05f, 0.08f, 0.60f };
    c[ImGuiCol_ScrollbarGrab]    = { 0.16f, 0.22f, 0.38f, 0.80f };
}

// ─── Draw helpers ─────────────────────────────────────────────────────────────
static void DrawShadowText(ImDrawList* dl, ImVec2 pos, ImU32 col, const char* txt) {
    dl->AddText({ pos.x + 1.f, pos.y + 1.f }, IM_COL32(0, 0, 0, 180), txt);
    dl->AddText(pos, col, txt);
}

static void DrawGlowCircle(ImDrawList* dl, ImVec2 c, float r, ImU32 col) {
    dl->AddCircle(c, r + 3.f, (col & 0x00FFFFFFu) | 0x30000000u, 32, 4.f);
    dl->AddCircle(c, r,        col, 32, 1.5f);
}

// Demo entity positions (replace with real EntityList walk when struct offsets known)
struct DemoEntity { float x, y, z, health; bool xhTarget; const char* name; };
static void BuildDemoEntities(std::vector<DemoEntity>& ents, uint32_t xhId) {
    static const struct { float x,y,z; const char* n; } raw[] = {
        {  500.f,   0.f,  80.f, "Bandit"   },
        { -300.f, 200.f,  80.f, "Sledge"   },
        {  100.f,-400.f,  80.f, "Ash"      },
        {  800.f, 150.f, 160.f, "Thermite" },
        { -600.f,-100.f,  80.f, "Mute"     },
    };
    ents.clear();
    for (int i = 0; i < 5; ++i) {
        DemoEntity e;
        e.x = raw[i].x; e.y = raw[i].y; e.z = raw[i].z;
        e.health = 100.f - i * 18.f; if (e.health < 5) e.health = 5;
        e.xhTarget = (xhId != 0 && xhId == (uint32_t)(i + 1));
        e.name = raw[i].n;
        ents.push_back(e);
    }
}

// ─── RenderFrame ──────────────────────────────────────────────────────────────
static void RenderFrame() {
    // Snapshot shared state
    LiveValue lv[OFFSET_COUNT]; float vm[16]; uint32_t xhId; float sens; double rms; bool att;
    {
        std::lock_guard<std::mutex> lk(g_mx);
        memcpy(lv, g_live, sizeof(lv)); memcpy(vm, g_viewMat, sizeof(vm));
        xhId = g_crosshairId; sens = g_mouseSens; rms = g_readMs; att = g_attached;
    }
    UcResult ucSnap[UC_SLOT_COUNT];
    {
        std::lock_guard<std::mutex> lk(g_ucMx);
        memcpy(ucSnap, g_ucResults, sizeof(ucSnap));
    }

    ImGuiIO& io = ImGui::GetIO();

    // ── Hotkeys ─────────────────────────────────────────────────────────────
    {
        static bool sPrevInsert = false, sPrevEnd = false, sPrevF5 = false;
        bool curInsert = (GetAsyncKeyState(VK_INSERT) & 0x8000) != 0;
        bool curEnd    = (GetAsyncKeyState(VK_END)    & 0x8000) != 0;
        bool curF5     = (GetAsyncKeyState(VK_F5)     & 0x8000) != 0;

        if (curInsert && !sPrevInsert) {
            g_showMenu = !g_showMenu;
            LONG ex = GetWindowLongW(g_hwnd, GWL_EXSTYLE);
            if (g_showMenu) {
                ex &= ~(WS_EX_TRANSPARENT | WS_EX_NOACTIVATE);
                SetWindowLongW(g_hwnd, GWL_EXSTYLE, ex);
                SetForegroundWindow(g_hwnd);
            } else {
                ex |= (WS_EX_TRANSPARENT | WS_EX_NOACTIVATE);
                SetWindowLongW(g_hwnd, GWL_EXSTYLE, ex);
            }
        }
        // F5: re-run Unicorn batch
        if (curF5 && !sPrevF5) {
            RunUnicornBatch();
        }
        if (curEnd && !sPrevEnd) g_running = false;
        sPrevInsert = curInsert; sPrevEnd = curEnd; sPrevF5 = curF5;
    }

    ImDrawList* bg = ImGui::GetBackgroundDrawList();

    // ── [1] ESP Boxes + Skeleton ─────────────────────────────────────────────
    if (g_showESP) {
        std::vector<DemoEntity> ents;
        BuildDemoEntities(ents, xhId);

        for (auto& e : ents) {
            float hx, hy, fx, fy;
            if (!W2S(e.x, e.y, e.z + 70.f, hx, hy)) continue;
            if (!W2S(e.x, e.y, e.z,         fx, fy)) continue;
            if (fy < -200 || hy > g_screenH + 200) continue;

            float h = fy - hy, w = h * 0.42f;
            ImU32 boxCol = e.xhTarget ? COL_RED   : COL_CYAN;
            ImU32 txtCol = e.xhTarget ? COL_AMBER : COL_WHITE;

            float bx = hx - w * .5f, ex2 = hx + w * .5f;
            float cl = w * 0.24f;
            bg->AddLine({ bx,     hy     }, { bx+cl,  hy     }, boxCol, g_espLineW);
            bg->AddLine({ bx,     hy     }, { bx,     hy+cl  }, boxCol, g_espLineW);
            bg->AddLine({ ex2-cl, hy     }, { ex2,    hy     }, boxCol, g_espLineW);
            bg->AddLine({ ex2,    hy     }, { ex2,    hy+cl  }, boxCol, g_espLineW);
            bg->AddLine({ bx,     fy-cl  }, { bx,     fy     }, boxCol, g_espLineW);
            bg->AddLine({ bx,     fy     }, { bx+cl,  fy     }, boxCol, g_espLineW);
            bg->AddLine({ ex2-cl, fy     }, { ex2,    fy     }, boxCol, g_espLineW);
            bg->AddLine({ ex2,    fy-cl  }, { ex2,    fy     }, boxCol, g_espLineW);

            float hpH = h * (e.health / 100.f);
            ImU32 hpCol = (e.health > 60) ? COL_GREEN : (e.health > 30) ? COL_AMBER : COL_RED;
            bg->AddRectFilled({ bx-5.f, fy-hpH }, { bx-2.f, fy }, hpCol);
            bg->AddRect      ({ bx-5.f, hy     }, { bx-2.f, fy },
                              (COL_GRAY & 0x00FFFFFFu) | 0x80000000u, 0, 0, 0.5f);

            DrawGlowCircle(bg, { hx, hy }, w * 0.13f, boxCol);

            char tag[64]; snprintf(tag, sizeof(tag), "%s  HP:%.0f", e.name, e.health);
            float tw = ImGui::CalcTextSize(tag).x;
            DrawShadowText(bg, { hx - tw * .5f, hy - 16.f }, txtCol, tag);

            ImU32 snapCol = (COL_GRAY & 0x00FFFFFFu) | 0x50000000u;
            bg->AddLine({ (float)g_screenW * .5f, (float)g_screenH }, { fx, fy }, snapCol, 0.8f);

            if (g_showSkeleton) {
                float tx, ty;
                if (W2S(e.x, e.y, e.z + 40.f, tx, ty)) {
                    ImU32 boneCol = (COL_PURPLE & 0x00FFFFFFu) | 0xA0000000u;
                    bg->AddLine({ hx, hy }, { tx, ty }, boneCol, 1.0f);
                    bg->AddLine({ tx, ty }, { fx, fy }, boneCol, 1.0f);
                    float lax, lay, rax, ray;
                    if (W2S(e.x - 30.f, e.y, e.z + 50.f, lax, lay) &&
                        W2S(e.x + 30.f, e.y, e.z + 50.f, rax, ray)) {
                        bg->AddLine({ tx, ty }, { lax, lay }, boneCol, 1.0f);
                        bg->AddLine({ tx, ty }, { rax, ray }, boneCol, 1.0f);
                    }
                }
            }
        }
    }

    // ── [2] Crosshair ────────────────────────────────────────────────────────
    if (g_showCrosshair) {
        float cx = g_screenW * .5f, cy = g_screenH * .5f;
        ImU32 xhCol = (xhId != 0) ? COL_RED : COL_CYAN;
        float xhR   = (xhId != 0) ? 6.f : 4.f;
        bg->AddCircle({ cx, cy }, xhR, xhCol, 32, 1.f);
        bg->AddLine({ cx-14.f, cy }, { cx-xhR-3.f, cy }, xhCol, 1.f);
        bg->AddLine({ cx+xhR+3.f, cy }, { cx+14.f, cy }, xhCol, 1.f);
        bg->AddLine({ cx, cy-14.f }, { cx, cy-xhR-3.f }, xhCol, 1.f);
        bg->AddLine({ cx, cy+xhR+3.f }, { cx, cy+14.f }, xhCol, 1.f);
        if (xhId != 0) {
            char txt[32]; snprintf(txt, sizeof(txt), "ID %u", xhId);
            DrawShadowText(bg, { cx + 16.f, cy - 7.f }, COL_AMBER, txt);
        }
    }

    // ── [3] Status badge ─────────────────────────────────────────────────────
    {
        const char* stxt = att ? "ATTACHED" : "SEARCHING...";
        ImU32 sbg  = att ? IM_COL32(10, 55, 22, 210) : IM_COL32(55, 20, 10, 210);
        ImU32 scol = att ? COL_GREEN : COL_AMBER;
        float bx = 10.f, by = 10.f, bw = 168.f, bh = 22.f;
        bg->AddRectFilled({ bx, by }, { bx+bw, by+bh }, sbg, 6.f);
        bg->AddRect      ({ bx, by }, { bx+bw, by+bh },
                          (scol & 0x00FFFFFFu) | 0x80000000u, 6.f);
        char stf[128]; snprintf(stf, sizeof(stf), " [ i87k ]  %s", stxt);
        DrawShadowText(bg, { bx+6.f, by+4.f }, scol, stf);
    }

    // ── [4] Side menu ─────────────────────────────────────────────────────────
    if (!g_showMenu) return;

    ImGui::SetNextWindowPos({ 10.f, 42.f }, ImGuiCond_Once);
    ImGui::SetNextWindowSize({ 460.f, 0.f }, ImGuiCond_Once);
    ImGui::SetNextWindowBgAlpha(0.90f);
    ImGui::Begin("##i87k_menu", nullptr,
                 ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize);

    // Title
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.f, 0.9f, 1.f, 1.f));
    ImGui::SetWindowFontScale(1.10f);
    ImGui::Text("  [ i87k ]  External Overlay v2.0");
    ImGui::SetWindowFontScale(1.f);
    ImGui::PopStyleColor();
    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 55.f);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.62f, 0.75f, 1.f));
    ImGui::Text("%.0f fps", io.Framerate);
    ImGui::PopStyleColor();
    ImGui::Separator();

    // Process status
    ImGui::Spacing();
    if (att) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.12f, 0.9f, 0.55f, 1.f));
        ImGui::Text("  ● %s  (PID %u)", g_procNameBuf, g_pid);
        ImGui::PopStyleColor();
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.62f, 0.75f, 1.f));
        ImGui::Text("  Base: 0x%llX   Read: %.2f ms   Sens: %.4f   XhairID: %u",
                    (unsigned long long)g_base, rms, sens, xhId);
        ImGui::PopStyleColor();
    } else {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.f, 0.78f, 0.15f, 1.f));
        ImGui::Text("  ○ Waiting for: %s", g_procNameBuf);
        ImGui::PopStyleColor();
        ImGui::SetNextItemWidth(210.f);
        ImGui::InputText("Process##proc", g_procNameBuf, sizeof(g_procNameBuf));
    }
    ImGui::Spacing(); ImGui::Separator();

    // ESP settings
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.f, 0.9f, 1.f, 1.f));
    ImGui::Text(" ESP Settings");
    ImGui::PopStyleColor();
    ImGui::Spacing();
    ImGui::Checkbox("ESP Boxes##b",  &g_showESP);       ImGui::SameLine(145.f);
    ImGui::Checkbox("Skeleton##sk",  &g_showSkeleton);  ImGui::SameLine(275.f);
    ImGui::Checkbox("Crosshair##ch", &g_showCrosshair);
    ImGui::SetNextItemWidth(210.f);
    ImGui::SliderFloat("Line Width##lw", &g_espLineW, 0.5f, 4.0f, "%.1f px");
    ImGui::Spacing(); ImGui::Separator();

    // Live Offset Monitor table
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.f, 0.9f, 1.f, 1.f));
    ImGui::Text(" Live Offset Monitor  (%d offsets)", OFFSET_COUNT);
    ImGui::PopStyleColor();
    ImGui::Spacing();

    ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, { 4.f, 3.f });
    if (ImGui::BeginTable("##offtbl", 3,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_SizingStretchProp, { 0.f, 240.f }))
    {
        ImGui::TableSetupColumn("Offset",  ImGuiTableColumnFlags_WidthFixed, 118.f);
        ImGui::TableSetupColumn("Value",   ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Status",  ImGuiTableColumnFlags_WidthFixed, 52.f);
        ImGui::TableHeadersRow();

        for (int i = 0; i < OFFSET_COUNT; ++i) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImVec4 nc;
            const char* tp = g_Offsets[i].type;
            if      (!strcmp(tp,"ptr64"))     nc = { 0.f,  0.9f, 1.f,  1.f };
            else if (!strcmp(tp,"matrix4x4")) nc = { 0.70f,0.38f,1.f,  1.f };
            else if (!strcmp(tp,"float"))     nc = { 1.f,  0.78f,0.15f,1.f };
            else if (!strcmp(tp,"uint32"))    nc = { 0.12f,0.9f, 0.55f,1.f };
            else                               nc = { 0.55f,0.62f,0.75f,1.f }; // code
            ImGui::PushStyleColor(ImGuiCol_Text, nc);
            ImGui::TextUnformatted(g_Offsets[i].name);
            ImGui::PopStyleColor();

            // Tooltip: show AOB signature + description + RVA
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::PushStyleColor(ImGuiCol_Text, { 0.f, 0.9f, 1.f, 1.f });
                ImGui::Text("%s", g_Offsets[i].name);
                ImGui::PopStyleColor();
                ImGui::Separator();
                ImGui::TextWrapped("Desc: %s", g_Offsets[i].description);
                ImGui::Text("RVA : 0x%llX", (unsigned long long)g_Offsets[i].rva);
                ImGui::Text("Type: %s", g_Offsets[i].type);
                if (g_Offsets[i].aob && g_Offsets[i].aob[0]) {
                    ImGui::Separator();
                    ImGui::PushStyleColor(ImGuiCol_Text, { 1.f, 0.85f, 0.2f, 1.f });
                    ImGui::Text("AOB : %s", g_Offsets[i].aob);
                    ImGui::PopStyleColor();
                }
                ImGui::EndTooltip();
            }

            ImGui::TableSetColumnIndex(1);
            ImGui::PushStyleColor(ImGuiCol_Text, lv[i].valid
                ? ImVec4(0.85f,0.88f,0.95f,1.f)
                : ImVec4(0.35f,0.37f,0.50f,1.f));
            ImGui::TextUnformatted(lv[i].display);
            ImGui::PopStyleColor();

            ImGui::TableSetColumnIndex(2);
            if (lv[i].valid) {
                ImGui::PushStyleColor(ImGuiCol_Text, { 0.12f,0.9f,0.55f,1.f });
                ImGui::Text("  OK");
            } else {
                ImGui::PushStyleColor(ImGuiCol_Text, { 1.f,0.28f,0.38f,1.f });
                ImGui::Text("FAIL");
            }
            ImGui::PopStyleColor();
        }
        ImGui::EndTable();
    }
    ImGui::PopStyleVar();

    // ViewMatrix collapsible
    ImGui::Spacing();
    if (ImGui::CollapsingHeader("  Camera & ViewMatrix (4x4)##vm")) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, { 0.05f,0.06f,0.10f,0.80f });
        ImGui::BeginChild("##vmchild", { 0.f, 115.f }, true);
        if (lv[4].valid) {
            ImGui::PushStyleColor(ImGuiCol_Text, { 0.f, 0.9f, 1.f, 1.f });
            ImGui::Text("  Camera Pos: [%.2f, %.2f, %.2f]",
                        g_cameraPos[0], g_cameraPos[1], g_cameraPos[2]);
            if (g_viewDataBase) {
                ImGui::SameLine();
                ImGui::PushStyleColor(ImGuiCol_Text, { 0.55f, 0.62f, 0.75f, 1.f });
                ImGui::Text("(ViewData @ 0x%llX)", (unsigned long long)g_viewDataBase);
                ImGui::PopStyleColor();
            }
            ImGui::PopStyleColor();
            ImGui::Separator();
            for (int r = 0; r < 4; ++r) {
                ImGui::PushStyleColor(ImGuiCol_Text, { 0.85f,0.88f,0.95f,1.f });
                ImGui::Text("  [%8.3f  %8.3f  %8.3f  %8.3f ]",
                    vm[r*4], vm[r*4+1], vm[r*4+2], vm[r*4+3]);
                ImGui::PopStyleColor();
            }
        } else {
            ImGui::PushStyleColor(ImGuiCol_Text, { 0.4f,0.42f,0.55f,1.f });
            ImGui::Text("  Not readable – searching for ViewData pattern...");
            ImGui::PopStyleColor();
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    // ── Unicorn Engine panel ──────────────────────────────────────────────────
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, { 0.70f, 0.38f, 1.f, 1.f });
    bool ucOpen = ImGui::CollapsingHeader("  Unicorn Engine 2 – Code Offset Emulation##uc");
    ImGui::PopStyleColor();
    if (ucOpen) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, { 0.04f,0.05f,0.09f,0.90f });
        ImGui::BeginChild("##ucchild", { 0.f, 200.f }, true);

        bool busy = g_ucBusy.load();

        // Re-run button
        ImGui::BeginDisabled(busy || !att);
        if (ImGui::Button("  ▶  Re-run Unicorn Batch (F5)")) RunUnicornBatch();
        ImGui::EndDisabled();
        if (busy) {
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Text, { 1.f,0.78f,0.15f,1.f });
            ImGui::Text("  Running...");
            ImGui::PopStyleColor();
        }

        ImGui::Separator();
        ImGui::Spacing();

        for (int slot = 0; slot < UC_SLOT_COUNT; ++slot) {
            int idx = UC_SLOTS[slot];
            const UcResult& r = ucSnap[slot];
            const GameOffset& go = g_Offsets[idx];

            ImGui::PushStyleColor(ImGuiCol_Text, { 0.55f,0.62f,0.75f,1.f });
            ImGui::Text("  [%s]  RVA:0x%llX", go.name, (unsigned long long)go.rva);
            ImGui::PopStyleColor();

            if (!r.done) {
                ImGui::PushStyleColor(ImGuiCol_Text, { 0.45f,0.48f,0.60f,1.f });
                ImGui::Text("    → Not yet emulated");
                ImGui::PopStyleColor();
            } else if (!r.ok) {
                ImGui::PushStyleColor(ImGuiCol_Text, { 1.f,0.28f,0.38f,1.f });
                ImGui::Text("    → FAIL: %s", r.errStr);
                ImGui::PopStyleColor();
            } else {
                ImGui::PushStyleColor(ImGuiCol_Text, { 0.12f,0.9f,0.55f,1.f });
                ImGui::Text("    ● %llu instrs | StopRIP:0x%llX | err:%s",
                            (unsigned long long)r.instrCount,
                            (unsigned long long)r.stopRip,
                            r.errStr);
                ImGui::PopStyleColor();
                ImGui::PushStyleColor(ImGuiCol_Text, { 0.85f,0.88f,0.95f,1.f });
                ImGui::Text("      GP  RAX:%llX  RBX:%llX  RCX:%llX  RDX:%llX",
                            (unsigned long long)r.rax, (unsigned long long)r.rbx,
                            (unsigned long long)r.rcx, (unsigned long long)r.rdx);
                ImGui::Text("      XMM XMM0:%.4f  XMM1:%.4f  XMM2:%.4f  XMM3:%.4f",
                            r.xmm0f, r.xmm1f, r.xmm2f, r.xmm3f);
                ImGui::PopStyleColor();
            }

            // Show AOB signature for this offset
            if (go.aob && go.aob[0]) {
                ImGui::PushStyleColor(ImGuiCol_Text, { 1.f,0.78f,0.15f,0.80f });
                ImGui::Text("      SIG: %s", go.aob);
                ImGui::PopStyleColor();
            }
            ImGui::Spacing();
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    ImGui::Spacing(); ImGui::Separator();
    ImGui::PushStyleColor(ImGuiCol_Text, { 0.40f,0.45f,0.60f,1.f });
    ImGui::Text("  INSERT=toggle menu   F5=re-run Unicorn   END=exit");
    ImGui::PopStyleColor();
    ImGui::End();
}

// ─── WinMain ──────────────────────────────────────────────────────────────────
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int) {
    g_screenW = GetSystemMetrics(SM_CXSCREEN);
    g_screenH = GetSystemMetrics(SM_CYSCREEN);

    WNDCLASSEXW wc = {};
    wc.cbSize       = sizeof(wc);
    wc.style        = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc  = OverlayWndProc;
    wc.hInstance    = hInst;
    wc.hCursor      = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName= L"i87k_Overlay_DX11_v2";
    RegisterClassExW(&wc);

    g_hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_LAYERED,
        wc.lpszClassName, L"i87k Overlay v2.0",
        WS_POPUP,
        0, 0, g_screenW, g_screenH,
        nullptr, nullptr, hInst, nullptr);

    if (!g_hwnd) return 1;

    SetLayeredWindowAttributes(g_hwnd, 0, 0, LWA_ALPHA);
    {
        MARGINS m = { -1 };
        DwmExtendFrameIntoClientArea(g_hwnd, &m);
    }

    if (!InitDX11(g_hwnd)) return 1;

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename  = nullptr;

    ApplyOverlayStyle();
    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX11_Init(g_pDev, g_pCtx);

    ShowWindow(g_hwnd, SW_SHOW);
    UpdateWindow(g_hwnd);

    // Start reader thread
    std::thread readerThr(ReaderThread);

    MSG msg = {};
    while (g_running.load()) {
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) g_running = false;
        }
        if (!g_running.load()) break;

        // Handle resize
        if (g_resizeW && g_resizeH) {
            DestroyRTV();
            g_pChain->ResizeBuffers(0, g_resizeW, g_resizeH,
                                    DXGI_FORMAT_UNKNOWN, 0);
            CreateRTV();
            g_screenW = g_resizeW; g_screenH = g_resizeH;
            g_resizeW = g_resizeH = 0;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        RenderFrame();

        ImGui::Render();
        constexpr float clear[] = { 0.f, 0.f, 0.f, 0.f };
        g_pCtx->OMSetRenderTargets(1, &g_pRTV, nullptr);
        g_pCtx->ClearRenderTargetView(g_pRTV, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pChain->Present(1, 0);
    }

    g_running = false;
    readerThr.join();

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    ShutdownDX11();
    DestroyWindow(g_hwnd);
    UnregisterClassW(wc.lpszClassName, hInst);
    return 0;
}
