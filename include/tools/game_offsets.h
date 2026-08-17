#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Sandbox::Tools {

    // ========================================================================
    // Unified Game & Application Offset / Signature Definitions (Single Source of Truth)
    // ========================================================================
    struct GameOffsetDef {
        std::string name;
        std::string aobPattern;     // Hex pattern with ?? wildcards
        uint64_t    rva;            // Default verified RVA
        int         dispOffset;     // Byte index of displacement inside instruction
        int         instructionLen; // Total instruction length
        std::string type;           // "ptr64", "matrix4x4", "float", "uint32", "code"
        std::string description;
    };

    inline const std::vector<GameOffsetDef>& GetKnownOffsetDatabase() {
        static const std::vector<GameOffsetDef> s_db = {
            // --- Pointer Offsets ---
            {
                "LocalPlayer",
                "48 8B 05 ?? ?? ?? ?? 48 85 C0",
                0x11C05698ULL, 3, 7, "ptr64",
                "LocalPlayer instance pointer (PlayerController/Pawn active during match)"
            },
            {
                "LocalPlayer_Profile",
                "48 8B 05 ?? ?? ?? ?? 33 D2 48 8B 48",
                0x11740280ULL, 3, 7, "ptr64",
                "Profile / User Account Manager (stores user stats & inventory)"
            },
            {
                "UE_GWorld / GameManager",
                "48 8B 1D ?? ?? ?? ?? 48 85 DB 74",
                0x11C103C8ULL, 3, 7, "ptr64",
                "Global World / GameManager Instance (manages world entities & game state)"
            },
            {
                "UE_GNames / StringTable",
                "48 8B 05 ?? ?? ?? ?? EB ?? 48 8D 05",
                0x11ACED98ULL, 3, 7, "ptr64",
                "Global Name / String Hash Table"
            },
            {
                "EntityList",
                "4C 8D 05 ?? ?? ?? ?? 48 8B CE",
                0x11C00A80ULL, 3, 7, "ptr64",
                "Entity / Actor Array (contains active player objects)"
            },
            {
                "D3D11_Context",
                "48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 90",
                0x11C82590ULL, 3, 7, "ptr64",
                "DX11 Device Context (used for render-hook / overlay attach)"
            },

            // --- Matrix Offsets ---
            {
                "ViewMatrix",
                "48 8B 0D ?? ?? ?? ?? F3 0F 10",
                0x11C9F7D8ULL, 3, 7, "matrix4x4",
                "Camera 4x4 WorldToScreen view-projection matrix (Row-Major)"
            },

            // --- Code Routine Offsets (Unicorn-Emulated) ---
            {
                "PlayerHealth",
                "F3 0F 10 ?? ?? F3 0F 5C ?? ?? F3 0F 11",
                0x0046C98FULL, 0, 13, "code",
                "Health decrement SSE scalar float: MOVSS xmm0,[rbx+??] SUBSS xmm0,xmm1"
            },
            {
                "WeaponAmmo",
                "8B 8B ?? ?? ?? ?? 85 C9 0F 84",
                0x010519F2ULL, 2, 6, "code",
                "Ammo load + conditional branch: MOV ecx,[rbx+disp] TEST ecx,ecx JZ"
            },
            {
                "MoveSpeed",
                "F3 0F 59 ?? ?? F3 0F 11 ?? ?? F3 0F 10",
                0x00EF5425ULL, 0, 13, "code",
                "Movement speed scale: MULSS xmm0,[rbx+??] then MOVSS store"
            },
            {
                "BoneMatrix",
                "4C 8B 87 ?? ?? ?? ?? 4D 85 C0",
                0x00BFBE28ULL, 3, 7, "code",
                "Skeleton bone transform resolver: MOV r8,[rdi+rva_BoneArray]"
            },

            // --- Float & Integer Offsets ---
            {
                "MouseSensitivity",
                "F3 0F 10 05 ?? ?? ?? ?? F3 0F 59",
                0x10EEEEF8ULL, 4, 8, "float",
                "Mouse sensitivity & FOV multiplier (global float)"
            },
            {
                "CrosshairEntityId",
                "8B 05 ?? ?? ?? ?? 85 C0 74",
                0x11C052D0ULL, 2, 6, "uint32",
                "Entity ID currently under the crosshair / reticle"
            }
        };
        return s_db;
    }

} // namespace Sandbox::Tools
