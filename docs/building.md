# Building from Source

Dracula is a Windows C++20 project with pinned Capstone and Unicorn submodules,
vendored SQLite and Zstandard sources, and an out-of-process .NET 10 managed
host.

## Prerequisites

- Windows 10 or 11, x64
- Git for Windows
- CMake 3.20 or newer
- MinGW-w64 GCC 13+ or a current MSVC toolchain with C++20 support
- .NET 10 SDK for the managed-analysis host
- PowerShell 5.1 or newer for packaging and installer tests

Git for Windows supplies `sh.exe`, used only by Unicorn's MinGW configuration.
Dracula includes a narrow `pkg-config` compatibility shim because Unicorn's
compact build checks that the command exists but does not query a package.

## Clone

```powershell
git clone --recurse-submodules https://github.com/i87kxxz/Dracula.git
cd Dracula
```

If the repository was cloned without submodules:

```powershell
git submodule update --init --recursive
```

## MinGW release build

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 4
ctest --test-dir build --output-on-failure
```

The first build compiles Unicorn from source and takes longer than an
incremental Dracula build.

## Visual Studio build

From a Developer PowerShell:

```powershell
cmake -S . -B build-vs -G "Visual Studio 18 2026" -A x64
cmake --build build-vs --config Release --parallel 4
ctest --test-dir build-vs -C Release --output-on-failure
```

Use the generator installed on the machine; CMake lists available generators
with `cmake --help`.

## Build options

```text
BUILD_TESTS=ON          Build the CTest suite (default)
```

The CMake project limits Capstone and Unicorn to the x86 family required by the
Windows x64 product.

## Package

After a Release build:

```powershell
& .\packaging\package_release.ps1 -BuildDir .\build
```

The script derives the version from the top-level CMake project and refuses a
different `-Version`. It creates:

```text
dist\Dracula-v<version>-windows-x64.zip
dist\Dracula-v<version>-windows-x64.zip.sha256
```

Inspect the archive before publication. It must not contain source trees,
CMake caches, object files, projects, dumps, VM images, `.draculaimg` files, or
overlays.

## Test environment notes

Most tests use synthetic fixtures. Live process and installed-root tests need
normal Windows access to temporary and per-user locations. Real QEMU guest
acceptance additionally needs QEMU, a configured user-owned image, and
GuestAgent; its absence is an environment limitation, not simulated proof.
