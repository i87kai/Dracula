#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <functional>

#include "injectable/injectable_api.h"

namespace Sandbox {

    // A running process located via CreateToolhelp32Snapshot.
    struct ProcessMatch {
        uint32_t pid = 0;
        std::string exeName;
    };

    // Result of resolving a target process's main module.
    struct ModuleInfo {
        uint64_t baseAddress = 0;
        uint64_t sizeOfImage = 0;
        std::string modulePath;
    };

    // Exported function or symbol resolved from the PE Export Directory.
    struct ExportedSymbol {
        std::string name;
        uint32_t ordinal = 0;
        uint64_t rva = 0;
        uint64_t absoluteAddress = 0;
    };

    // Read-only live process inspection: locate a target by name/PID, resolve its
    // main module base, and pull instruction bytes out of its address space for
    // offline analysis (e.g. via UnicornAnalyzer::EmulateBuffer). No code is ever
    // written into, or executed inside, the inspected process.
    class ProcessInspector {
    public:
        // ---------------------------------------------------------------
        // Process enumeration & lookup
        // ---------------------------------------------------------------

        // Enumerate all accessible running processes with their PID and executable name.
        static std::vector<ProcessMatch> ListAllProcesses();

        // Enumerate running processes whose executable name matches (case-insensitive).
        static std::vector<ProcessMatch> FindProcessesByName(const std::string& exeName);

        // ---------------------------------------------------------------
        // Read-only handle operations
        // ---------------------------------------------------------------

        // Open a read-only handle: PROCESS_VM_READ | PROCESS_QUERY_INFORMATION.
        // Returns nullptr on failure (invalid PID, access denied, elevated target, etc.).
        static void* OpenReadOnly(uint32_t pid, std::string& outError);

        static void Close(void* handle);

        // Resolve the target's main (first) module base address and size.
        static std::optional<ModuleInfo> ResolveMainModule(void* handle, uint32_t pid, std::string& outError);

        // Resolve ALL loaded modules / DLLs in the target process address space.
        static std::vector<ModuleInfo> ResolveAllModules(void* handle, uint32_t pid, std::string& outError);

        // Read `length` bytes starting at absolute virtual address `address`.
        // Returns fewer bytes than requested (or empty) on a partial/failed read;
        // outBytesRead reports how much actually came back.
        static std::vector<uint8_t> ReadMemory(void* handle, uint64_t address, size_t length,
                                                 size_t& outBytesRead, std::string& outError);

        // Parse PE Export Directory from memory to resolve all exported functions and their offsets (RVAs).
        static std::vector<ExportedSymbol> ResolveExportedSymbols(void* handle, uint64_t baseAddress, std::string& outError);

        // Pattern / Signature Scanner (AOB scan): search for byte signatures with wildcards (e.g. "48 89 5C 24 ?? 48").
        static std::vector<uint64_t> FindPattern(void* handle, uint64_t startAddress, size_t scanLength,
                                                  const std::string& patternHexWithWildcards, std::string& outError);

        // ---------------------------------------------------------------
        // DLL Injection API  (requires PROCESS_ALL_ACCESS – run as Admin)
        // ---------------------------------------------------------------

        // Open a full-access handle suitable for DLL injection.
        static void* OpenForInjection(uint32_t pid, std::string& outError);

        // Extract the embedded InjectableDLL resource from this EXE to a temp file.
        static bool ExtractEmbeddedDLL(std::string& outDllPath, std::string& outError);

        // Inject dllPath via VirtualAllocEx + WriteProcessMemory + CreateRemoteThread.
        static bool InjectDLL(void* handle, const std::string& dllPath, std::string& outError);

        // ── Named Pipe – two-phase API (eliminates race condition) ──────────
        //
        // Phase 1 (call BEFORE injection):
        //   Creates the Named Pipe server and returns its HANDLE wrapped as void*.
        //   Returns nullptr on failure.
        static void* CreateInjectionPipe();

        // Phase 2 (call on a background thread AFTER CreateInjectionPipe,
        //          then call InjectDLL on the main thread):
        //   Waits for the injected DLL to connect, streams all typed packets to the
        //   provided callbacks, and blocks until DoneMarker or timeout.
        //
        //   pipeHandle  – the value returned by CreateInjectionPipe()
        //   timeoutMs   – max ms to wait for the initial connection
        //
        //   Callbacks:
        //     onStatus    – StatusMessage   (progress log from DLL)
        //     onOffset    – FoundOffset     (named offset with address & RVA)
        //     onRegisters – RegisterValues  (CPU snapshot from Unicorn)
        //     onModule    – ModuleList      (loaded DLL entry)
        //     onUnicorn   – UnicornResult   (emulation summary)
        //     onPattern   – PatternMatch    (AOB hit)
        //     onMath      – MathResult      (arithmetic result)
        static bool DrainInjectionPipe(
            void* pipeHandle,
            int   timeoutMs,
            std::function<void(const std::string&)>              onStatus,
            std::function<void(const InjectMsg_FoundOffset&)>    onOffset,
            std::function<void(const InjectMsg_RegisterValues&)> onRegisters,
            std::function<void(const InjectMsg_ModuleEntry&)>    onModule,
            std::function<void(const InjectMsg_UnicornResult&)>  onUnicorn,
            std::function<void(const InjectMsg_PatternMatch&)>   onPattern,
            std::function<void(const InjectMsg_MathResult&)>     onMath);
    };

} // namespace Sandbox
