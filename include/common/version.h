#pragma once

#define DRACULA_VERSION_MAJOR 1
#define DRACULA_VERSION_MINOR 0
#define DRACULA_VERSION_PATCH 0

#define DRACULA_VERSION_STRING "1.0.0"
#define DRACULA_PLATFORM_NAME "Dracula Unified Binary Intelligence Platform"
#define DRACULA_RELEASE_DATE "2026-08-17"
#define DRACULA_BUILD_TARGET "x86_64-w64-mingw32"

namespace Dracula {
    namespace Version {
        inline constexpr int Major = DRACULA_VERSION_MAJOR;
        inline constexpr int Minor = DRACULA_VERSION_MINOR;
        inline constexpr int Patch = DRACULA_VERSION_PATCH;
        inline constexpr const char* String = DRACULA_VERSION_STRING;
        inline constexpr const char* PlatformName = DRACULA_PLATFORM_NAME;
        inline constexpr const char* ReleaseDate = DRACULA_RELEASE_DATE;
        inline constexpr const char* BuildTarget = DRACULA_BUILD_TARGET;

        inline std::string GetFullVersionString() {
            return std::string("Dracula v") + String + " (" + BuildTarget + ")";
        }
    }
}
