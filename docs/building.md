# Building Dracula from Source

This guide covers setting up your build environment, compiling Dracula, and running the test suite on Windows x64.

---

## 1. Prerequisites

* **Windows 10 / 11 (64-bit)**
* **CMake 3.20 or newer**
* **MinGW-w64 (GCC 13+)** or **MSVC 2022** with C++20 standard support.
* **Git** and **PowerShell 5.1+**

---

## 2. Clone & Build Instructions

```powershell
# 1. Clone repository
git clone https://github.com/i87kxxz/Dracula.git
cd Dracula

# 2. Generate CMake build tree
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release

# 3. Compile project & test binaries
cmake --build build -j8
```

---

## 3. Running Test Suites

Dracula includes 19+ automated CTest suites verifying disassembler bindings, terminal UI geometry, UTR target adapters, evidence graph structures, and memory intelligence:

```powershell
ctest --test-dir build --output-on-failure
```

Expected output:
```text
100% tests passed, 0 tests failed out of 19
Total Test time (real) = ~4.5 sec
```

---

## 4. Packaging Release Binaries

To produce an official release zip and `.sha256` digest locally:

```powershell
powershell -ExecutionPolicy Bypass -File .\packaging\package_release.ps1 -Version "1.3.1"
```
The output archive is created in `dist/Dracula-v1.3.1-windows-x64.zip`.
