// ============================================================================
//  injectable_dll.cpp  –  InjectableDLL.dll (i87k Tool)
//
//  This DLL is injected into any live game or application process by HostController.exe.
//  On DllMain (DLL_PROCESS_ATTACH) it:
//
//   1. Spawns an On-Screen Display (OSD) overlay thread showing "[ i87k ]"
//      centered on the screen, smoothly fading in, staying for 2.5s, then fading out.
//   2. Connects to HostController via Named Pipe and streams real-time debug telemetry.
//   3. Safely iterates all committed executable/readable memory regions (via VirtualQuery).
//   4. Runs an optimized AOB pattern scan for 18 named game/app offsets (LocalPlayer,
//      ViewMatrix, EntityList, PlayerHealth, WeaponAmmo, UE_GWorld, BoneMatrix, etc.).
//   5. For matched sites, it routes the live instruction bytes into native Unicorn Engine 2
//      CPU emulation, traces instructions, and extracts output register states.
//   6. Writes all results to both the live Named Pipe stream and %TEMP%\i87k_injection_results.txt.
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <set>
#include <cmath>

#include "injectable/injectable_api.h"
#include "unicorn/unicorn.h"
#include "unicorn/x86.h"

// ---------------------------------------------------------------------------
// Well-known AOB signatures for games & applications
// ---------------------------------------------------------------------------
struct AobEntry {
    const char* name;
    const int16_t pattern[32];  // -1 = wildcard
    int len;
    int instrOffset;  // byte offset inside pattern where disp begins
    int dispSize;     // 0=none, 4=rel32, 8=ptr64
};

static const AobEntry g_CommonPatterns[] = {
    // --- LocalPlayer / Player Base (Targeted Signatures) ---
    { "LocalPlayer_Main",
      {0x48,0x8B,0x05,-1,-1,-1,-1, 0x48,0x85,0xC0, 0x74},
      11, 3, 4 },

    { "LocalPlayer_Profile",
      {0x48,0x8B,0x05,-1,-1,-1,-1, 0x33,0xD2, 0x48,0x8B,0x48},
      12, 3, 4 },

    { "LocalPlayer_Controller",
      {0x48,0x8B,0x0D,-1,-1,-1,-1, 0x48,0x85,0xC9, 0x74},
      11, 3, 4 },

    { "LocalPlayer_x64",
      {0x48,0x8B,0x05,-1,-1,-1,-1, 0x48,0x85,0xC0},
      10, 3, 4 },

    { "LocalPlayer_x86",
      {0xA1,-1,-1,-1,-1, 0x85,0xC0},
      7, 1, 4 },

    // --- ViewMatrix & ViewData (Camera & 4x4 ViewProjection Matrix) ---
    { "ViewData_Camera",
      {0xA4,0x70,0x7D,0xBF, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0xA0,0x40, 0x00,0x00,0xA0,0xC0, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0xCD,0xCC,0x4C,0x3F},
      32, 0, 0 },

    { "ViewMatrix_x64",
      {0x48,0x8B,0x0D,-1,-1,-1,-1, 0xF3,0x0F,0x10},
      10, 3, 4 },

    { "ViewMatrix_x64_v2",
      {0x4C,0x8B,0x05,-1,-1,-1,-1, 0x49,0x8B},
      9, 3, 4 },

    // --- EntityList / EntityArray ---
    { "EntityList_x64",
      {0x4C,0x8D,0x05,-1,-1,-1,-1, 0x48,0x8B,0xCE},
      10, 3, 4 },

    { "EntityList_x64_v2",
      {0x48,0x8B,0x15,-1,-1,-1,-1, 0x48,0x8B,0xCB},
      10, 3, 4 },

    // --- Health / Player Health ---
    { "PlayerHealth_offset",
      {0xF3,0x0F,0x10,-1,-1, 0xF3,0x0F,0x5C,-1,-1},
      10, 0, 0 },

    { "PlayerHealthPtr_x64",
      {0x48,0x8B,0x83,-1,-1,-1,-1, 0xF3,0x0F,0x10,0x40},
      11, 3, 4 },

    // --- Ammunition / Ammo ---
    { "WeaponAmmo_offset",
      {0x8B,0x8B,-1,-1,-1,-1, 0x85,0xC9, 0x0F,0x84},
      10, 2, 4 },

    // --- Name / String pointer ---
    { "EntityName_ptr",
      {0x48,0x8D,0x15,-1,-1,-1,-1, 0xE8,-1,-1,-1,-1},
      12, 3, 4 },

    // --- GWorld / UWorld (Unreal Engine) ---
    { "UE_GWorld",
      {0x48,0x8B,0x1D,-1,-1,-1,-1, 0x48,0x85,0xDB, 0x74},
      11, 3, 4 },

    // --- GNames (Unreal Engine) ---
    { "UE_GNames",
      {0x48,0x8B,0x05,-1,-1,-1,-1, 0xEB,-1, 0x48,0x8D,0x05},
      12, 3, 4 },

    // --- GameBase / D3D DeviceContext ---
    { "D3D11_DeviceContext",
      {0x48,0x8B,0x0D,-1,-1,-1,-1, 0x48,0x8B,0x01, 0xFF,0x90},
      12, 3, 4 },

    // --- Speed / Movement ---
    { "MoveSpeed_float",
      {0xF3,0x0F,0x59,-1,-1, 0xF3,0x0F,0x11,-1,-1},
      10, 0, 0 },

    // --- Bone Matrix ---
    { "BoneMatrix_ptr",
      {0x4C,0x8B,0x87,-1,-1,-1,-1, 0x4D,0x85,0xC0},
      10, 3, 4 },

    // --- Sensitivity / FovScale ---
    { "MouseSensitivity",
      {0xF3,0x0F,0x10,0x05,-1,-1,-1,-1, 0xF3,0x0F,0x59},
      11, 4, 4 },

    // --- Crosshair ID / Aim Pointer ---
    { "CrosshairEntityId",
      {0x8B,0x05,-1,-1,-1,-1, 0x85,0xC0, 0x74},
      9, 2, 4 },

    // --- Generic Function Prologue ---
    { "Subroutine_Prologue",
      {0x48,0x89,0x5C,0x24,-1, 0x48,0x89,0x74,0x24},
      9, 0, 0 }
};

static constexpr int g_PatternCount = static_cast<int>(sizeof(g_CommonPatterns) / sizeof(g_CommonPatterns[0]));

// ---------------------------------------------------------------------------
// File-based debug logger
// ---------------------------------------------------------------------------
static void LogDebug(const char* fmt, ...) {
    char tempDir[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, tempDir);
    std::string path = std::string(tempDir) + "i87k_injection_results.txt";
    FILE* f = fopen(path.c_str(), "a");
    if (!f) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);
    fprintf(f, "\n");
    fclose(f);
}

// ---------------------------------------------------------------------------
// ON-SCREEN DISPLAY (OSD) OVERLAY: "[ i87k ]" in the center of the screen
// ---------------------------------------------------------------------------
static LRESULT CALLBACK OSDWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);

        RECT rc;
        GetClientRect(hWnd, &rc);

        // Dark rounded background
        HBRUSH bgBrush = CreateSolidBrush(RGB(15, 18, 26));
        HPEN borderPen = CreatePen(PS_SOLID, 2, RGB(0, 220, 255)); // Bright Cyan Border
        HGDIOBJ oldBrush = SelectObject(hdc, bgBrush);
        HGDIOBJ oldPen = SelectObject(hdc, borderPen);

        RoundRect(hdc, rc.left + 2, rc.top + 2, rc.right - 2, rc.bottom - 2, 16, 16);

        // Title Font: "i87k"
        HFONT hTitleFont = CreateFontA(
            34, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Arial");

        HFONT hSubFont = CreateFontA(
            15, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");

        SetBkMode(hdc, TRANSPARENT);

        // Draw "[ i87k ]"
        SelectObject(hdc, hTitleFont);
        SetTextColor(hdc, RGB(0, 255, 200)); // Bright Green-Cyan
        RECT rcTitle = rc;
        rcTitle.top += 12;
        rcTitle.bottom = rcTitle.top + 40;
        DrawTextA(hdc, "[ i87k ]", -1, &rcTitle, DT_CENTER | DT_SINGLELINE);

        // Draw "Injected Successfully • Unicorn Active"
        SelectObject(hdc, hSubFont);
        SetTextColor(hdc, RGB(220, 225, 235)); // Soft White
        RECT rcSub = rc;
        rcSub.top += 55;
        DrawTextA(hdc, "Injected Successfully • Unicorn Analyzer Active", -1, &rcSub, DT_CENTER | DT_SINGLELINE);

        // Cleanup
        SelectObject(hdc, oldBrush);
        SelectObject(hdc, oldPen);
        DeleteObject(bgBrush);
        DeleteObject(borderPen);
        DeleteObject(hTitleFont);
        DeleteObject(hSubFont);

        EndPaint(hWnd, &ps);
        return 0;
    }
    return DefWindowProcA(hWnd, msg, wParam, lParam);
}

static DWORD WINAPI OSDThread(LPVOID /*param*/) {
    HINSTANCE hInst = GetModuleHandleA(nullptr);

    WNDCLASSEXA wc = {};
    wc.cbSize        = sizeof(WNDCLASSEXA);
    wc.lpfnWndProc   = OSDWndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = "i87k_OSD_Overlay_Class";
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassExA(&wc);

    int winW = 420;
    int winH = 95;
    int scrW = GetSystemMetrics(SM_CXSCREEN);
    int scrH = GetSystemMetrics(SM_CYSCREEN);
    int winX = (scrW - winW) / 2;
    int winY = (scrH - winH) / 2;

    HWND hWnd = CreateWindowExA(
        WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE,
        wc.lpszClassName,
        "i87k_Notification",
        WS_POPUP,
        winX, winY, winW, winH,
        nullptr, nullptr, hInst, nullptr);

    if (!hWnd) return 0;

    // Fade In (Alpha 0 -> 240)
    ShowWindow(hWnd, SW_SHOWNOACTIVATE);
    for (int alpha = 0; alpha <= 240; alpha += 20) {
        SetLayeredWindowAttributes(hWnd, 0, static_cast<BYTE>(alpha), LWA_ALPHA);
        UpdateWindow(hWnd);
        Sleep(15);
    }

    // Stay visible for 2.5 seconds
    Sleep(2500);

    // Fade Out (Alpha 240 -> 0)
    for (int alpha = 240; alpha >= 0; alpha -= 20) {
        SetLayeredWindowAttributes(hWnd, 0, static_cast<BYTE>(alpha), LWA_ALPHA);
        UpdateWindow(hWnd);
        Sleep(15);
    }

    DestroyWindow(hWnd);
    UnregisterClassA(wc.lpszClassName, hInst);
    return 0;
}

// ---------------------------------------------------------------------------
// Resolve RIP-relative displacement to an absolute address
// ---------------------------------------------------------------------------
static uint64_t ResolveRipRelative(uint64_t instrVa, int instrLen, int dispOffset, const uint8_t* bytes) {
    if (dispOffset + 4 > instrLen) return 0;
    int32_t disp = 0;
    memcpy(&disp, bytes + dispOffset, 4);
    return instrVa + instrLen + static_cast<int64_t>(disp);
}

// ---------------------------------------------------------------------------
// Unicorn: emulate code window captured from the target process
// ---------------------------------------------------------------------------
static bool EmulateCodeWindow(
    HANDLE pipe,
    const uint8_t* codeBytes,
    size_t codeLen,
    uint64_t baseVa,
    bool is64Bit)
{
    if (!codeBytes || codeLen == 0) return false;

    uc_engine* uc = nullptr;
    uc_err err = uc_open(UC_ARCH_X86, is64Bit ? UC_MODE_64 : UC_MODE_32, &uc);
    if (err != UC_ERR_OK) {
        char buf[256];
        snprintf(buf, sizeof(buf), "[Unicorn] uc_open failed: %s", uc_strerror(err));
        InjectWriteStatus(pipe, buf);
        return false;
    }

    // Page-align mapping
    const uint64_t kPage = 0x1000ULL;
    uint64_t pageBase = baseVa & ~(kPage - 1);
    uint64_t alignedEnd = (baseVa + codeLen + kPage - 1) & ~(kPage - 1);
    uint64_t mapSize = alignedEnd - pageBase;

    uc_mem_map(uc, pageBase, mapSize, UC_PROT_ALL);
    uc_mem_write(uc, baseVa, codeBytes, codeLen);

    // Setup minimal virtual stack
    uint64_t stackBase = is64Bit ? 0x0000700000000000ULL : 0x60000000ULL;
    uint64_t stackSize = 0x10000ULL;
    uc_mem_map(uc, stackBase, stackSize, UC_PROT_ALL);
    uint64_t stackTop = stackBase + stackSize - 0x1000;

    if (is64Bit) {
        uc_reg_write(uc, UC_X86_REG_RSP, &stackTop);
        uc_reg_write(uc, UC_X86_REG_RBP, &stackTop);
        uc_reg_write(uc, UC_X86_REG_RIP, &baseVa);
    } else {
        uint32_t esp = static_cast<uint32_t>(stackTop);
        uc_reg_write(uc, UC_X86_REG_ESP, &esp);
        uint32_t eip = static_cast<uint32_t>(baseVa);
        uc_reg_write(uc, UC_X86_REG_EIP, &eip);
    }

    // Instruction counter hook
    uint64_t instrCount = 0;
    uc_hook cntHook = 0;
    auto cntCb = [](uc_engine*, uint64_t, uint32_t, void* ud) {
        (*static_cast<uint64_t*>(ud))++;
    };
    uc_hook_add(uc, &cntHook, UC_HOOK_CODE,
                reinterpret_cast<void*>(+cntCb), &instrCount, 1, 0);

    // Dynamic unmapped memory hook: mirrors real target process memory into Unicorn
    struct DynamicMemContext {
        std::vector<uint64_t> mappedPages;
    } memCtx;

    auto memUnmappedCb = [](uc_engine* uc, uc_mem_type /*type*/, uint64_t address, int /*size*/, int64_t /*value*/, void* ud) -> bool {
        auto* ctx = static_cast<DynamicMemContext*>(ud);
        uint64_t pageBase = address & ~0xFFFULL;
        uint64_t pageSize = 0x1000ULL;

        if (uc_mem_map(uc, pageBase, pageSize, UC_PROT_ALL) == UC_ERR_OK) {
            if (ctx) ctx->mappedPages.push_back(pageBase);

            // Safely mirror real process memory into Unicorn context
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(pageBase), &mbi, sizeof(mbi))) {
                if ((mbi.State == MEM_COMMIT) && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
                    uint8_t pageBuf[0x1000] = {};
                    SIZE_T br = 0;
                    if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(pageBase), pageBuf, pageSize, &br) && br > 0) {
                        uc_mem_write(uc, pageBase, pageBuf, pageSize);
                    }
                }
            }
            return true; // Successfully mapped and seeded, resume instruction!
        }
        return false;
    };

    uc_hook unmappedHook = 0;
    uc_hook_add(uc, &unmappedHook, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
                reinterpret_cast<void*>(+memUnmappedCb), &memCtx, 1, 0);

    // Run bounded emulation (1000 instructions max, 2s timeout)
    uint64_t stopVa = baseVa + codeLen;
    err = uc_emu_start(uc, baseVa, stopVa, 2000000ULL, 1000ULL);

    // Collect registers
    InjectMsg_UnicornResult res{};
    res.emulatedAddress      = baseVa;
    res.emulatedSize         = static_cast<uint64_t>(codeLen);
    res.instructionsExecuted = instrCount;
    res.rawErrorCode         = static_cast<uint32_t>(err);
    strncpy_s(res.terminationReason, uc_strerror(err), _TRUNCATE);
    res.success        = (err == UC_ERR_OK || err == UC_ERR_READ_UNMAPPED ||
                          err == UC_ERR_WRITE_UNMAPPED || err == UC_ERR_FETCH_UNMAPPED);
    res.completedCleanly = (err == UC_ERR_OK);

    if (is64Bit) {
        uint64_t rip = 0;
        uc_reg_read(uc, UC_X86_REG_RIP, &rip);  res.stopRip = rip;
        uc_reg_read(uc, UC_X86_REG_RAX, &res.rax);
        uc_reg_read(uc, UC_X86_REG_RBX, &res.rbx);
        uc_reg_read(uc, UC_X86_REG_RCX, &res.rcx);
        uc_reg_read(uc, UC_X86_REG_RDX, &res.rdx);
        uc_reg_read(uc, UC_X86_REG_RSI, &res.rsi);
        uc_reg_read(uc, UC_X86_REG_RDI, &res.rdi);
        uc_reg_read(uc, UC_X86_REG_RSP, &res.rsp);
        uc_reg_read(uc, UC_X86_REG_RBP, &res.rbp);
        res.rip = rip;
    } else {
        uint32_t eax=0,ebx=0,ecx=0,edx=0,esi=0,edi=0,esp=0,ebp=0,eip=0;
        uc_reg_read(uc, UC_X86_REG_EAX, &eax); res.rax = eax;
        uc_reg_read(uc, UC_X86_REG_EBX, &ebx); res.rbx = ebx;
        uc_reg_read(uc, UC_X86_REG_ECX, &ecx); res.rcx = ecx;
        uc_reg_read(uc, UC_X86_REG_EDX, &edx); res.rdx = edx;
        uc_reg_read(uc, UC_X86_REG_ESI, &esi); res.rsi = esi;
        uc_reg_read(uc, UC_X86_REG_EDI, &edi); res.rdi = edi;
        uc_reg_read(uc, UC_X86_REG_ESP, &esp); res.rsp = esp;
        uc_reg_read(uc, UC_X86_REG_EBP, &ebp); res.rbp = ebp;
        uc_reg_read(uc, UC_X86_REG_EIP, &eip); res.rip = eip; res.stopRip = eip;
    }

    for (uint64_t page : memCtx.mappedPages) {
        uc_mem_unmap(uc, page, 0x1000ULL);
    }
    uc_mem_unmap(uc, pageBase, mapSize);
    uc_mem_unmap(uc, stackBase, stackSize);
    uc_close(uc);

    InjectWritePacket(pipe, InjectMsgType::UnicornResult, res);

    InjectMsg_RegisterValues regSnap{};
    regSnap.rax = res.rax; regSnap.rbx = res.rbx;
    regSnap.rcx = res.rcx; regSnap.rdx = res.rdx;
    regSnap.rsi = res.rsi; regSnap.rdi = res.rdi;
    regSnap.rsp = res.rsp; regSnap.rbp = res.rbp;
    regSnap.rip = res.rip;
    regSnap.instructionsExecuted = instrCount;
    regSnap.emulationBaseAddr    = baseVa;
    strncpy_s(regSnap.terminationReason, uc_strerror(err), _TRUNCATE);
    InjectWritePacket(pipe, InjectMsgType::RegisterValues, regSnap);

    return res.success;
}

// ---------------------------------------------------------------------------
// Main worker thread that runs inside the injected process
// ---------------------------------------------------------------------------
static DWORD WINAPI WorkerThread(LPVOID /*param*/) {
    LogDebug("[i87k] Injectable worker thread started in PID %lu", GetCurrentProcessId());

    // 1. Connect to Named Pipe
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int retry = 0; retry < 50; ++retry) {
        pipe = CreateFileW(
            INJECT_PIPE_NAME,
            GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING,
            FILE_FLAG_WRITE_THROUGH, nullptr);

        if (pipe != INVALID_HANDLE_VALUE) {
            LogDebug("[i87k] Connected to Named Pipe successfully on retry %d", retry + 1);
            break;
        }

        DWORD gle = GetLastError();
        if (gle == ERROR_PIPE_BUSY) {
            WaitNamedPipeW(INJECT_PIPE_NAME, 1000);
        } else {
            Sleep(100);
        }
    }

    if (pipe != INVALID_HANDLE_VALUE) {
        DWORD pipeMode = PIPE_READMODE_BYTE;
        SetNamedPipeHandleState(pipe, &pipeMode, nullptr, nullptr);
    }

    char banner[256];
    snprintf(banner, sizeof(banner), "[i87k] === INJECTION SUCCESSFUL (PID: %lu) ===", GetCurrentProcessId());
    InjectWriteStatus(pipe, banner);
    LogDebug("%s", banner);

    // -----------------------------------------------------------------------
    // STEP 1: Enumerate all loaded modules in THIS process
    // -----------------------------------------------------------------------
    InjectWriteStatus(pipe, "[i87k] [Step 1/4] Enumerating loaded modules in target address space...");
    HANDLE hProc = GetCurrentProcess();
    HMODULE mods[512]; DWORD needed = 0;
    int modCount = 0;

    if (EnumProcessModules(hProc, mods, sizeof(mods), &needed)) {
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < count; ++i) {
            InjectMsg_ModuleEntry me{};
            MODULEINFO mi{};
            GetModuleInformation(hProc, mods[i], &mi, sizeof(mi));
            GetModuleBaseNameA(hProc, mods[i], me.moduleName, sizeof(me.moduleName));
            GetModuleFileNameExA(hProc, mods[i], me.modulePath, sizeof(me.modulePath));
            me.baseAddress  = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
            me.sizeOfImage  = mi.SizeOfImage;
            me.isMainModule = (i == 0);
            me.isExecutable = true;

            auto pDos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mi.lpBaseOfDll);
            if (pDos && pDos->e_magic == IMAGE_DOS_SIGNATURE) {
                auto pNt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                    reinterpret_cast<const uint8_t*>(mi.lpBaseOfDll) + pDos->e_lfanew);
                if (pNt->Signature == IMAGE_NT_SIGNATURE) {
                    me.entryPointRva = pNt->OptionalHeader.AddressOfEntryPoint;
                }
            }
            InjectWritePacket(pipe, InjectMsgType::ModuleList, me);
            modCount++;
        }
    }

    char modSummary[128];
    snprintf(modSummary, sizeof(modSummary), "[i87k] Found %d loaded modules.", modCount);
    InjectWriteStatus(pipe, modSummary);

    // -----------------------------------------------------------------------
    // STEP 2: Main Module Information & Section Mapping
    // -----------------------------------------------------------------------
    HMODULE hMain = GetModuleHandleW(nullptr);
    auto* pDosMain = reinterpret_cast<const IMAGE_DOS_HEADER*>(hMain);
    bool is64Bit = true;
    uint64_t mainBase = reinterpret_cast<uint64_t>(hMain);
    uint64_t mainSize = 0;

    if (pDosMain && pDosMain->e_magic == IMAGE_DOS_SIGNATURE) {
        auto* pNtMain = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            reinterpret_cast<const uint8_t*>(hMain) + pDosMain->e_lfanew);
        if (pNtMain->Signature == IMAGE_NT_SIGNATURE) {
            is64Bit = (pNtMain->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
            mainSize = pNtMain->OptionalHeader.SizeOfImage;
        }
    }

    char mainModName[MAX_PATH] = "Target.exe";
    GetModuleBaseNameA(hProc, hMain, mainModName, sizeof(mainModName));

    char mainInfo[256];
    snprintf(mainInfo, sizeof(mainInfo),
             "[i87k] [Step 2/4] Main Module: '%s' | Base: 0x%llX | Size: 0x%llX | Arch: %s",
             mainModName, (unsigned long long)mainBase, (unsigned long long)mainSize, is64Bit ? "x64" : "x86");
    InjectWriteStatus(pipe, mainInfo);
    LogDebug("%s", mainInfo);

    // -----------------------------------------------------------------------
    // STEP 3: Safe Memory-Region Scanner (Iterates VirtualQuery Committed Pages)
    // -----------------------------------------------------------------------
    InjectWriteStatus(pipe, "[i87k] [Step 3/4] Scanning committed memory regions for game offsets...");

    int totalFoundOffsets = 0;
    int unicornRunCount = 0;
    std::set<std::pair<std::string, uint64_t>> seenOffsets;

    // Walk all committed pages belonging to the main module
    uint8_t* scanPtr = reinterpret_cast<uint8_t*>(mainBase);
    uint8_t* scanEnd = scanPtr + mainSize;

    while (scanPtr < scanEnd) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery(scanPtr, &mbi, sizeof(mbi))) {
            scanPtr += 0x1000;
            continue;
        }

        // Only scan readable committed pages
        bool isReadable = (mbi.State == MEM_COMMIT) &&
                          !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
                          (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE |
                                          PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));

        if (isReadable && mbi.RegionSize > 0) {
            size_t regLen = std::min(mbi.RegionSize, static_cast<size_t>(scanEnd - scanPtr));
            const uint8_t* regBytes = reinterpret_cast<const uint8_t*>(mbi.BaseAddress);
            uint64_t regBase = reinterpret_cast<uint64_t>(mbi.BaseAddress);

            for (int pi = 0; pi < g_PatternCount; ++pi) {
                const AobEntry& entry = g_CommonPatterns[pi];
                if (regLen < static_cast<size_t>(entry.len)) continue;

                for (size_t i = 0; i <= regLen - entry.len; ++i) {
                    bool match = true;
                    for (int j = 0; j < entry.len; ++j) {
                        if (entry.pattern[j] != -1 &&
                            static_cast<uint8_t>(entry.pattern[j]) != regBytes[i + j]) {
                            match = false;
                            break;
                        }
                    }

                    if (match) {
                        uint64_t hitVa = regBase + i;
                        const uint8_t* matchBytes = regBytes + i;

                        // Resolve pointer / structure address
                        uint64_t resolvedAddr = hitVa;
                        if (strcmp(entry.name, "ViewData_Camera") == 0) {
                            resolvedAddr = hitVa - 0x2A4ULL; // ViewData base = pattern - 0x2A4
                        } else if (entry.dispSize == 4 && entry.instrOffset > 0) {
                            resolvedAddr = ResolveRipRelative(
                                hitVa, entry.instrOffset + 4, entry.instrOffset, matchBytes);
                        }

                        // Deduplication: prevent emitting identical (Name, ResolvedAddress) pairs
                        auto offsetKey = std::make_pair(std::string(entry.name), resolvedAddr);
                        if (seenOffsets.count(offsetKey) > 0) {
                            continue;
                        }
                        seenOffsets.insert(offsetKey);

                        // Build pattern hex string
                        char hexStr[96] = {};
                        int hexPos = 0;
                        for (int b = 0; b < entry.len && hexPos < 90; ++b) {
                            if (entry.pattern[b] == -1) {
                                hexPos += snprintf(hexStr + hexPos, sizeof(hexStr) - hexPos, "?? ");
                            } else {
                                hexPos += snprintf(hexStr + hexPos, sizeof(hexStr) - hexPos,
                                                   "%02X ", static_cast<uint8_t>(entry.pattern[b]));
                            }
                        }

                        // Check memory protection of resolved address
                        MEMORY_BASIC_INFORMATION resMbi{};
                        bool isWritable   = false;
                        bool isExecutable = false;
                        if (resolvedAddr && VirtualQuery(reinterpret_cast<LPCVOID>(resolvedAddr), &resMbi, sizeof(resMbi))) {
                            isWritable   = (resMbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) != 0;
                            isExecutable = (resMbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
                        }

                        // Live Pointer Validation: test if pointer is allocated and active
                        uint64_t livePointer = 0;
                        bool isLiveValid = false;
                        float camPos[3] = {};
                        bool isCamValid = false;

                        if (strcmp(entry.name, "ViewData_Camera") == 0) {
                            SIZE_T br = 0;
                            if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(resolvedAddr + 0x190), camPos, sizeof(camPos), &br) && br == sizeof(camPos)) {
                                isCamValid = std::isfinite(camPos[0]) && std::isfinite(camPos[1]) && std::isfinite(camPos[2]);
                            }
                        } else if (resolvedAddr && (resMbi.State == MEM_COMMIT)) {
                            SIZE_T br = 0;
                            if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(resolvedAddr), &livePointer, sizeof(livePointer), &br) && br == sizeof(livePointer)) {
                                if (livePointer >= 0x10000 && livePointer <= 0x00007FFFFFFFFFFFULL) {
                                    MEMORY_BASIC_INFORMATION ptrMbi{};
                                    if (VirtualQuery(reinterpret_cast<LPCVOID>(livePointer), &ptrMbi, sizeof(ptrMbi))) {
                                        if ((ptrMbi.State == MEM_COMMIT) && !(ptrMbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
                                            isLiveValid = true;
                                        }
                                    }
                                }
                            }
                        }

                        // Emit Found Offset
                        InjectMsg_FoundOffset fo{};
                        strncpy_s(fo.offsetName, entry.name, _TRUNCATE);
                        strncpy_s(fo.moduleName, mainModName, _TRUNCATE);
                        fo.absoluteAddress = resolvedAddr;
                        fo.rva             = (resolvedAddr >= mainBase) ? resolvedAddr - mainBase : 0;
                        fo.moduleBase      = mainBase;
                        fo.patternLen      = static_cast<uint32_t>(std::min(static_cast<size_t>(entry.len), sizeof(fo.patternBytes)));
                        memcpy(fo.patternBytes, matchBytes, fo.patternLen);
                        strncpy_s(fo.patternHex, hexStr, _TRUNCATE);
                        fo.isWritable   = isWritable;
                        fo.isExecutable = isExecutable;

                        if (strcmp(entry.name, "ViewData_Camera") == 0) {
                            if (isCamValid) {
                                snprintf(fo.derefChain, sizeof(fo.derefChain),
                                         "ViewData @ 0x%llX  →  ★ Camera: [%.2f, %.2f, %.2f] | VP @ +0x250 ★",
                                         (unsigned long long)resolvedAddr, camPos[0], camPos[1], camPos[2]);
                            } else {
                                snprintf(fo.derefChain, sizeof(fo.derefChain),
                                         "ViewData @ 0x%llX (Pattern - 0x2A4)",
                                         (unsigned long long)resolvedAddr);
                            }
                        } else if (entry.dispSize == 4) {
                            if (isLiveValid) {
                                snprintf(fo.derefChain, sizeof(fo.derefChain),
                                         "[%s + 0x%llX]  →  0x%llX  →  ★ LIVE: 0x%llX ★",
                                         mainModName, (unsigned long long)(hitVa - mainBase), (unsigned long long)resolvedAddr, (unsigned long long)livePointer);
                            } else if (livePointer != 0) {
                                snprintf(fo.derefChain, sizeof(fo.derefChain),
                                         "[%s + 0x%llX]  →  0x%llX  →  0x%llX (Invalid)",
                                         mainModName, (unsigned long long)(hitVa - mainBase), (unsigned long long)resolvedAddr, (unsigned long long)livePointer);
                            } else {
                                snprintf(fo.derefChain, sizeof(fo.derefChain),
                                         "[%s + 0x%llX]  →  0x%llX  (Null/Unspawned)",
                                         mainModName, (unsigned long long)(hitVa - mainBase), (unsigned long long)resolvedAddr);
                            }
                        } else {
                            snprintf(fo.derefChain, sizeof(fo.derefChain),
                                     "Direct match at %s + 0x%llX",
                                     mainModName, (unsigned long long)(hitVa - mainBase));
                        }

                        InjectWritePacket(pipe, InjectMsgType::FoundOffset, fo);
                        totalFoundOffsets++;

                        char logLine[384];
                        snprintf(logLine, sizeof(logLine),
                                 "[i87k] FOUND UNIQUE OFFSET: '%s' @ 0x%llX (RVA: 0x%llX) Live: 0x%llX",
                                 entry.name, (unsigned long long)resolvedAddr, (unsigned long long)fo.rva, (unsigned long long)livePointer);
                        LogDebug("%s", logLine);

                        // ---------------------------------------------------
                        // STEP 4: Unicorn CPU Emulation on Match Window
                        // ---------------------------------------------------
                        if (unicornRunCount < 6) {
                            size_t winLen = 128;
                            if (i + winLen <= regLen) {
                                char emuMsg[256];
                                snprintf(emuMsg, sizeof(emuMsg),
                                         "[i87k] [Unicorn] Emulating 128 bytes @ 0x%llX for '%s'",
                                         (unsigned long long)hitVa, entry.name);
                                InjectWriteStatus(pipe, emuMsg);
                                LogDebug("%s", emuMsg);

                                EmulateCodeWindow(pipe, matchBytes, winLen, hitVa, is64Bit);
                                unicornRunCount++;
                            }
                        }

                        if (totalFoundOffsets >= 100) break;
                    }
                }
            }
        }

        scanPtr = reinterpret_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
        if (totalFoundOffsets >= 100) break;
    }

    // -----------------------------------------------------------------------
    // Done Summary
    // -----------------------------------------------------------------------
    char doneMsg[256];
    snprintf(doneMsg, sizeof(doneMsg),
             "[i87k] Analysis complete! Found %d offsets, executed %d Unicorn emulation sessions.",
             totalFoundOffsets, unicornRunCount);
    InjectWriteStatus(pipe, doneMsg);
    LogDebug("%s", doneMsg);

    // Send Done packet
    InjectMsg_Status doneMarker{};
    strncpy_s(doneMarker.text, "DONE", _TRUNCATE);
    InjectWritePacket(pipe, InjectMsgType::DoneMarker, doneMarker);

    if (pipe != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(pipe);
        CloseHandle(pipe);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// DllMain – Entry point called on injection
// ---------------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*reserved*/) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // 1. Launch On-Screen Notification "[ i87k ]" in target window
        HANDLE hOsd = CreateThread(nullptr, 0, OSDThread, nullptr, 0, nullptr);
        if (hOsd) CloseHandle(hOsd);

        // 2. Launch Main Analysis & Unicorn Worker Thread
        HANDLE hWorker = CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
        if (hWorker) CloseHandle(hWorker);
    }
    return TRUE;
}
