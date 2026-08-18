#include "utr/dll_harness.h"

#include <chrono>
#include <iostream>
#include <filesystem>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace Dracula {
namespace UTR {

    DllExecutionHarness::~DllExecutionHarness() {
        Unload();
    }

    bool DllExecutionHarness::LoadSafe(const std::string& dllPath, std::string& outError) {
        Unload();
        std::string fullPath = dllPath;
        try {
            if (std::filesystem::exists(dllPath)) {
                fullPath = std::filesystem::absolute(dllPath).string();
            }
        } catch (...) {}
        m_dllPath = fullPath;

#ifdef _WIN32
        // Try safe data-file load first for inspection
        HMODULE hMod = LoadLibraryExA(fullPath.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE);
        if (!hMod) {
            hMod = LoadLibraryA(fullPath.c_str());
        }
        if (!hMod) {
            DWORD err = GetLastError();
            outError = "Failed to load DLL: Error 0x" + std::to_string(err);
            return false;
        }
        m_hModule = hMod;
        return true;
#else
        outError = "DLL Harness requires Windows host.";
        return false;
#endif
    }

    void DllExecutionHarness::Unload() {
#ifdef _WIN32
        if (m_hModule) {
            FreeLibrary(static_cast<HMODULE>(m_hModule));
            m_hModule = nullptr;
        }
#endif
        m_dllPath.clear();
    }

    std::vector<DllExportSymbol> DllExecutionHarness::EnumerateExports(std::string& outError) {
        std::vector<DllExportSymbol> exports;
#ifdef _WIN32
        if (!m_hModule) {
            outError = "No DLL loaded in harness.";
            return exports;
        }

        uint8_t* base = reinterpret_cast<uint8_t*>(reinterpret_cast<uintptr_t>(m_hModule) & ~3); // Strip data-file flags
        auto dosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
            outError = "Invalid DOS header in DLL.";
            return exports;
        }

        auto ntHdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dosHdr->e_lfanew);
        if (ntHdrs->Signature != IMAGE_NT_SIGNATURE) {
            outError = "Invalid NT header in DLL.";
            return exports;
        }

        auto& expDir = ntHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (expDir.VirtualAddress == 0 || expDir.Size == 0) {
            return exports; // No exports
        }

        auto exportsTable = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + expDir.VirtualAddress);
        DWORD* names = reinterpret_cast<DWORD*>(base + exportsTable->AddressOfNames);
        WORD* ordinals = reinterpret_cast<WORD*>(base + exportsTable->AddressOfNameOrdinals);
        DWORD* functions = reinterpret_cast<DWORD*>(base + exportsTable->AddressOfFunctions);

        for (DWORD i = 0; i < exportsTable->NumberOfNames; ++i) {
            DllExportSymbol sym;
            const char* namePtr = reinterpret_cast<const char*>(base + names[i]);
            sym.name = namePtr ? namePtr : "";
            WORD ordIndex = ordinals[i];
            sym.ordinal = exportsTable->Base + ordIndex;
            sym.rva = functions[ordIndex];
            sym.absoluteAddress = reinterpret_cast<uint64_t>(base + sym.rva);

            // Check forwarder
            if (sym.rva >= expDir.VirtualAddress && sym.rva < expDir.VirtualAddress + expDir.Size) {
                sym.isForwarder = true;
                const char* fwdPtr = reinterpret_cast<const char*>(base + sym.rva);
                sym.forwarderTarget = fwdPtr ? fwdPtr : "";
            }

            exports.push_back(sym);
        }
#else
        outError = "DLL Harness requires Windows host.";
#endif
        return exports;
    }

    DllInvocationResult DllExecutionHarness::InvokeTestExport(
        const std::string& exportName,
        const std::vector<uint64_t>& args)
    {
        DllInvocationResult res;
#ifdef _WIN32
        if (m_dllPath.empty()) {
            res.errorMessage = "No DLL path specified.";
            return res;
        }

        // Live execution requires a full active load
        HMODULE hLive = LoadLibraryA(m_dllPath.c_str());
        if (!hLive) {
            res.errorMessage = "Failed to load DLL for execution: Error 0x" + std::to_string(GetLastError());
            return res;
        }

        FARPROC proc = GetProcAddress(hLive, exportName.c_str());
        if (!proc) {
            res.errorMessage = "Export symbol '" + exportName + "' not found in DLL.";
            FreeLibrary(hLive);
            return res;
        }

        auto start = std::chrono::steady_clock::now();
        typedef uint64_t (*TestExportFn0)();
        typedef uint64_t (*TestExportFn1)(uint64_t);
        typedef uint64_t (*TestExportFn2)(uint64_t, uint64_t);

        try {
            if (args.empty()) {
                auto fn = reinterpret_cast<TestExportFn0>(proc);
                res.returnValue = fn();
            } else if (args.size() == 1) {
                auto fn = reinterpret_cast<TestExportFn1>(proc);
                res.returnValue = fn(args[0]);
            } else {
                auto fn = reinterpret_cast<TestExportFn2>(proc);
                res.returnValue = fn(args[0], args[1]);
            }
            res.success = true;
        } catch (...) {
            res.errorMessage = "Exception caught during DLL export execution.";
            res.success = false;
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
        res.executionTimeMs = elapsed;
        FreeLibrary(hLive);
#else
        res.errorMessage = "DLL Harness requires Windows host.";
#endif
        return res;
    }

} // namespace UTR
} // namespace Dracula
