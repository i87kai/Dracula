#pragma once

#include <cstdint>

// ============================================================================
//  game_offsets.h  –  Verified live RVAs and pointers from injection telemetry
// ============================================================================

namespace GameOffsets {

    // --- Core Entity & Player Pointers (Validated Live) ---
    inline constexpr uint64_t LocalPlayer_RVA    = 0x11C05698ULL; // Main verified LocalPlayer pointer
    inline constexpr uint64_t LocalPlayer_Alt1   = 0x11CD8EE8ULL; // Active player instance
    inline constexpr uint64_t LocalPlayer_Alt2   = 0x11CD05B0ULL; // Active player instance
    inline constexpr uint64_t ViewMatrix_RVA     = 0x11C9F7D8ULL; // 4x4 Camera ViewProjection Matrix
    inline constexpr uint64_t EntityList_RVA     = 0x11C00A80ULL; // Active Entity/Player Array
    inline constexpr uint64_t D3D11Context_RVA   = 0x11C82590ULL; // DirectX 11 Device Context

    // --- Engine Managers & Global Tables ---
    inline constexpr uint64_t GameManager_RVA    = 0x11C103C8ULL; // UE_GWorld / GameManager instance
    inline constexpr uint64_t StringTable_RVA    = 0x11ACED98ULL; // UE_GNames / String Table
    inline constexpr uint64_t MouseSens_RVA      = 0x10EEEEF8ULL; // Mouse sensitivity float
    inline constexpr uint64_t CrosshairId_RVA    = 0x11C052D0ULL; // Entity ID under crosshair

    // --- Executable Code Sites / Subroutine Offsets ---
    inline constexpr uint64_t PlayerHealth_Code  = 0x0046C98FULL; // Health decrement routine
    inline constexpr uint64_t WeaponAmmo_Code    = 0x010519F2ULL; // Ammo check routine
    inline constexpr uint64_t MoveSpeed_Code     = 0x00EF5425ULL; // Movement speed calculation
    inline constexpr uint64_t BoneMatrix_Code    = 0x00BFBE28ULL; // Skeleton bone matrix resolver

} // namespace GameOffsets
