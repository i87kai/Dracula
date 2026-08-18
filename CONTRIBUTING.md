# Contributing to Dracula

Thank you for your interest in contributing to **Dracula — Unified Binary Intelligence Platform**!

Dracula is an open-source, reproducible reverse engineering platform designed around three immutable pillars:
1. **ONE PROJECT** — Durable workspace storage that persists samples, artifacts, and evidence graphs.
2. **ONE TARGET CONTEXT** — Unified inspection across static PE binaries, live processes, .NET assemblies, DLLs, and drivers.
3. **ONE EVIDENCE MODEL** — Every claim carries rigorous provenance (`CALCULATED`, `RESOLVED`, `LIVE-READ VERIFIED`).

---

## 🛠️ Development Setup

### Prerequisites
* **Windows 10 / 11 (x64)**
* **CMake 3.20+**
* **GCC / MinGW-w64** (or MSVC 2022) with C++20 support
* **PowerShell 5.1+**

### Building from Source
```powershell
# 1. Clone the repository
git clone https://github.com/i87kxxz/Dracula.git
cd Dracula

# 2. Configure build with CMake
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release

# 3. Build project and test suites
cmake --build build -j8

# 4. Run automated test suites
ctest --test-dir build --output-on-failure
```

---

## 🧪 Testing Guidelines

* Every bugfix or new feature **must** include corresponding automated unit/integration tests under `tests/`.
* The command registry is authoritative: all new commands or subcommands must be registered in `src/cli/command_registry.cpp` with handlers and tested in `tests/test_command_registry.cpp`.
* Run the full test suite before opening a Pull Request:
  ```powershell
  ctest --test-dir build --output-on-failure
  ```

---

## 📐 Architecture & Coding Standards

* **C++ Standard**: C++20.
* **Separation of Presentation & Logic**: Core analysis services (`App::*` and `UTR::*`) return structured DTOs and `CommandResult` without console escape codes or terminal formatting. Terminal layout is handled solely in `src/cli/`.
* **Zero Hardcoded Personal Paths**: All paths must resolve through `Paths::*` utilities or relative workspace roots.
* **Semantic Error Reporting**: Avoid bare error messages. Provide structured `ErrorDetail` (`code`, `message`, `reason`, `remediation`, `availableInstead`).

---

## 📦 Pull Request Process

1. Fork the repository and create a feature branch (`git checkout -b feature/amazing-feature`).
2. Ensure your changes compile with zero warnings and pass all 19+ automated test suites.
3. Commit with concise, descriptive commit messages.
4. Push to your branch and open a Pull Request using the PR template.
