#include "host/process_inspector.h"

#include <sstream>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#endif

namespace Sandbox {

#ifdef _WIN32

    std::vector<ProcessMatch> ProcessInspector::ListAllProcesses() {
        std::vector<ProcessMatch> list;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return list;
        }

        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &entry)) {
            do {
                if (entry.th32ProcessID != 0) {
                    list.push_back({ entry.th32ProcessID, entry.szExeFile });
                }
            } while (Process32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return list;
    }

    std::vector<ProcessMatch> ProcessInspector::FindProcessesByName(const std::string& exeName) {
        std::vector<ProcessMatch> matches;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return matches;
        }

        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &entry)) {
            do {
                std::string current = entry.szExeFile;
                if (_stricmp(current.c_str(), exeName.c_str()) == 0) {
                    matches.push_back({ entry.th32ProcessID, current });
                }
            } while (Process32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return matches;
    }

    static bool EnableDebugPrivilege() {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            return false;
        }
        LUID luid;
        if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
            CloseHandle(hToken);
            return false;
        }
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
        CloseHandle(hToken);
        return (ok && GetLastError() == ERROR_SUCCESS);
    }

    void* ProcessInspector::OpenReadOnly(uint32_t pid, std::string& outError) {
        EnableDebugPrivilege();
        HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (h == nullptr) {
            DWORD gle = GetLastError();
            std::ostringstream ss;
            ss << "OpenProcess failed for PID " << pid << " (GetLastError=" << gle << ")";
            if (gle == ERROR_ACCESS_DENIED) {
                ss << " - access denied (target may be running elevated or protected)";
            }
            outError = ss.str();
            return nullptr;
        }
        return static_cast<void*>(h);
    }

    void ProcessInspector::Close(void* handle) {
        if (handle) {
            CloseHandle(static_cast<HANDLE>(handle));
        }
    }

    std::optional<ModuleInfo> ProcessInspector::ResolveMainModule(void* handle, uint32_t pid, std::string& outError) {
        HANDLE h = static_cast<HANDLE>(handle);

        HMODULE modules[1];
        DWORD needed = 0;

        // A read-only PROCESS_VM_READ|PROCESS_QUERY_INFORMATION handle is sufficient
        // for EnumProcessModules; PROCESS_QUERY_LIMITED_INFORMATION targets (or
        // cross-bitness processes) can still fail here with ERROR_PARTIAL_COPY.
        if (!EnumProcessModules(h, modules, sizeof(modules), &needed)) {
            DWORD gle = GetLastError();
            std::ostringstream ss;
            ss << "EnumProcessModules failed for PID " << pid << " (GetLastError=" << gle << ")";
            if (gle == ERROR_PARTIAL_COPY) {
                ss << " - likely a 32/64-bit architecture mismatch between HostController and target";
            }
            outError = ss.str();
            return std::nullopt;
        }

        MODULEINFO mi{};
        if (!GetModuleInformation(h, modules[0], &mi, sizeof(mi))) {
            outError = "GetModuleInformation failed (GetLastError=" + std::to_string(GetLastError()) + ")";
            return std::nullopt;
        }

        char pathBuf[MAX_PATH] = {};
        GetModuleFileNameExA(h, modules[0], pathBuf, MAX_PATH);

        ModuleInfo info;
        info.baseAddress = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
        info.sizeOfImage = mi.SizeOfImage;
        info.modulePath = pathBuf;
        return info;
    }

    std::vector<ModuleInfo> ProcessInspector::ResolveAllModules(void* handle, uint32_t pid, std::string& outError) {
        std::vector<ModuleInfo> list;
        HANDLE h = static_cast<HANDLE>(handle);

        HMODULE modules[1024];
        DWORD needed = 0;

        if (!EnumProcessModules(h, modules, sizeof(modules), &needed)) {
            DWORD gle = GetLastError();
            std::ostringstream ss;
            ss << "EnumProcessModules failed for PID " << pid << " (GetLastError=" << gle << ")";
            outError = ss.str();
            return list;
        }

        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < count; ++i) {
            MODULEINFO mi{};
            if (GetModuleInformation(h, modules[i], &mi, sizeof(mi))) {
                char pathBuf[MAX_PATH] = {};
                GetModuleFileNameExA(h, modules[i], pathBuf, MAX_PATH);

                ModuleInfo info;
                info.baseAddress = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
                info.sizeOfImage = mi.SizeOfImage;
                info.modulePath = pathBuf;
                list.push_back(info);
            }
        }
        return list;
    }

    std::vector<uint8_t> ProcessInspector::ReadMemory(void* handle, uint64_t address, size_t length,
                                                        size_t& outBytesRead, std::string& outError) {
        std::vector<uint8_t> buffer(length);
        outBytesRead = 0;

        SIZE_T bytesRead = 0;
        BOOL ok = ReadProcessMemory(static_cast<HANDLE>(handle),
                                     reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(address)),
                                     buffer.data(), length, &bytesRead);

        outBytesRead = static_cast<size_t>(bytesRead);

        if (!ok && bytesRead == 0) {
            std::ostringstream ss;
            ss << "ReadProcessMemory failed at 0x" << std::hex << address
               << " (GetLastError=" << std::dec << GetLastError() << ")";
            outError = ss.str();
            buffer.clear();
            return buffer;
        }

        // Partial read (region spans an unmapped/guard page boundary): trim to what
        // was actually copied rather than returning zero-filled tail bytes.
        buffer.resize(outBytesRead);
        return buffer;
    }

    std::vector<ExportedSymbol> ProcessInspector::ResolveExportedSymbols(void* handle, uint64_t baseAddress, std::string& outError) {
        std::vector<ExportedSymbol> exports;
        if (!handle || baseAddress == 0) return exports;

        size_t read = 0;
        std::string err;
        auto dosBuf = ReadMemory(handle, baseAddress, sizeof(IMAGE_DOS_HEADER), read, err);
        if (dosBuf.size() < sizeof(IMAGE_DOS_HEADER)) {
            outError = "Failed to read DOS header: " + err;
            return exports;
        }

        auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(dosBuf.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            outError = "Invalid DOS header signature.";
            return exports;
        }

        uint64_t ntAddr = baseAddress + dosHeader->e_lfanew;
        auto ntBuf = ReadMemory(handle, ntAddr, sizeof(IMAGE_NT_HEADERS64), read, err);
        if (ntBuf.size() < sizeof(IMAGE_NT_HEADERS64)) {
            outError = "Failed to read NT headers: " + err;
            return exports;
        }

        auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(ntBuf.data());
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            outError = "Invalid NT signature.";
            return exports;
        }

        const auto& exportDirHeader = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDirHeader.VirtualAddress == 0 || exportDirHeader.Size == 0) {
            outError = "No Export Directory found in module.";
            return exports;
        }

        uint64_t exportDirAddr = baseAddress + exportDirHeader.VirtualAddress;
        auto expDirBuf = ReadMemory(handle, exportDirAddr, sizeof(IMAGE_EXPORT_DIRECTORY), read, err);
        if (expDirBuf.size() < sizeof(IMAGE_EXPORT_DIRECTORY)) {
            outError = "Failed to read IMAGE_EXPORT_DIRECTORY: " + err;
            return exports;
        }

        auto exportDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(expDirBuf.data());
        DWORD numNames = exportDir->NumberOfNames;
        DWORD numFunctions = exportDir->NumberOfFunctions;

        if (numNames == 0 || numFunctions == 0) {
            return exports;
        }

        // Read Name RVA array
        uint64_t namesAddr = baseAddress + exportDir->AddressOfNames;
        auto namesBuf = ReadMemory(handle, namesAddr, numNames * sizeof(DWORD), read, err);

        // Read Ordinal array
        uint64_t ordinalsAddr = baseAddress + exportDir->AddressOfNameOrdinals;
        auto ordinalsBuf = ReadMemory(handle, ordinalsAddr, numNames * sizeof(WORD), read, err);

        // Read Function RVA array
        uint64_t funcsAddr = baseAddress + exportDir->AddressOfFunctions;
        auto funcsBuf = ReadMemory(handle, funcsAddr, numFunctions * sizeof(DWORD), read, err);

        if (namesBuf.size() < numNames * sizeof(DWORD) ||
            ordinalsBuf.size() < numNames * sizeof(WORD) ||
            funcsBuf.size() < numFunctions * sizeof(DWORD)) {
            outError = "Failed to read export address/name tables.";
            return exports;
        }

        auto nameRVAs = reinterpret_cast<const DWORD*>(namesBuf.data());
        auto ordinals = reinterpret_cast<const WORD*>(ordinalsBuf.data());
        auto funcRVAs = reinterpret_cast<const DWORD*>(funcsBuf.data());

        for (DWORD i = 0; i < numNames && i < 1024; ++i) { // Limit to 1024 exports
            DWORD nameRVA = nameRVAs[i];
            WORD ordinal = ordinals[i];

            if (ordinal >= numFunctions) continue;
            DWORD funcRVA = funcRVAs[ordinal];

            // Read string name from memory
            auto strBuf = ReadMemory(handle, baseAddress + nameRVA, 128, read, err);
            std::string symName = "";
            for (uint8_t c : strBuf) {
                if (c == '\0') break;
                symName += static_cast<char>(c);
            }

            if (!symName.empty()) {
                ExportedSymbol sym;
                sym.name = symName;
                sym.ordinal = static_cast<uint32_t>(exportDir->Base + ordinal);
                sym.rva = funcRVA;
                sym.absoluteAddress = baseAddress + funcRVA;
                exports.push_back(sym);
            }
        }

        return exports;
    }

    std::vector<uint64_t> ProcessInspector::FindPattern(void* handle, uint64_t startAddress, size_t scanLength,
                                                         const std::string& patternHexWithWildcards, std::string& outError) {
        std::vector<uint64_t> matches;
        if (!handle || scanLength == 0 || patternHexWithWildcards.empty()) return matches;

        // Parse pattern tokens (e.g. "48 89 5C ?? 48")
        std::vector<int16_t> patternBytes;
        std::istringstream iss(patternHexWithWildcards);
        std::string token;
        while (iss >> token) {
            if (token == "?" || token == "??" || token == "*") {
                patternBytes.push_back(-1); // Wildcard
            } else {
                try {
                    int val = std::stoi(token, nullptr, 16);
                    patternBytes.push_back(static_cast<int16_t>(val & 0xFF));
                } catch (...) {
                    outError = "Invalid pattern token: " + token;
                    return matches;
                }
            }
        }

        if (patternBytes.empty()) return matches;

        const size_t chunkSize = 64 * 1024; // 64 KB chunk
        size_t offset = 0;

        while (offset < scanLength) {
            size_t toRead = std::min(chunkSize, scanLength - offset);
            size_t bytesRead = 0;
            std::string readErr;

            auto buf = ReadMemory(handle, startAddress + offset, toRead + patternBytes.size(), bytesRead, readErr);
            if (buf.empty() || bytesRead < patternBytes.size()) {
                offset += chunkSize;
                continue;
            }

            for (size_t i = 0; i + patternBytes.size() <= bytesRead; ++i) {
                bool match = true;
                for (size_t j = 0; j < patternBytes.size(); ++j) {
                    if (patternBytes[j] != -1 && static_cast<uint8_t>(patternBytes[j]) != buf[i + j]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    matches.push_back(startAddress + offset + i);
                    if (matches.size() >= 50) break; // Limit to first 50 matches
                }
            }

            if (matches.size() >= 50) break;
            offset += chunkSize;
        }

        return matches;
    }

    // =========================================================================
    //  DLL INJECTION  –  VirtualAllocEx / WriteProcessMemory / CreateRemoteThread
    // =========================================================================

    void* ProcessInspector::OpenForInjection(uint32_t pid, std::string& outError) {
        EnableDebugPrivilege();
        HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!h) {
            // Fallback to specific granular rights if full access is restricted
            DWORD flags = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
            h = OpenProcess(flags, FALSE, pid);
        }
        if (!h) {
            DWORD gle = GetLastError();
            std::ostringstream ss;
            ss << "OpenProcess failed for PID " << pid
               << " (GetLastError=" << gle << ")";
            if (gle == ERROR_ACCESS_DENIED) {
                ss << " - Access denied (run HostController.exe as Administrator or target is protected).";
            }
            outError = ss.str();
            return nullptr;
        }
        return static_cast<void*>(h);
    }

    bool ProcessInspector::ExtractEmbeddedDLL(std::string& outDllPath, std::string& outError) {
        // Resource ID 101 / type RCDATA – embedded by injectable_resource.rc
        const int IDR_INJECTABLE_DLL = 101;

        HMODULE hSelf = GetModuleHandleW(nullptr);
        HRSRC hRes = FindResourceW(hSelf, MAKEINTRESOURCEW(IDR_INJECTABLE_DLL), MAKEINTRESOURCEW(10)); // 10 = RT_RCDATA
        if (hRes) {
            HGLOBAL hLoad = LoadResource(hSelf, hRes);
            if (hLoad) {
                DWORD resSize = SizeofResource(hSelf, hRes);
                const void* pData = LockResource(hLoad);
                if (pData && resSize > 0) {
                    char tempDir[MAX_PATH] = {};
                    GetTempPathA(MAX_PATH, tempDir);

                    char outPath[MAX_PATH] = {};
                    snprintf(outPath, MAX_PATH, "%sSandboxInjectableDLL_%u.dll", tempDir, GetCurrentProcessId());

                    HANDLE hFile = CreateFileA(outPath, GENERIC_WRITE, 0, nullptr,
                                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        DWORD written = 0;
                        BOOL ok = WriteFile(hFile, pData, resSize, &written, nullptr);
                        CloseHandle(hFile);
                        if (ok && written == resSize) {
                            outDllPath = outPath;
                            return true;
                        }
                    }
                }
            }
        }

        // Fallback: check if InjectableDLL.dll exists on disk next to EXE or in current dir
        char exeDir[MAX_PATH] = {};
        GetModuleFileNameA(hSelf, exeDir, MAX_PATH);
        char* lastSlash = strrchr(exeDir, '\\');
        if (lastSlash) {
            *(lastSlash + 1) = '\0';
            std::string localDll = std::string(exeDir) + "InjectableDLL.dll";
            DWORD attr = GetFileAttributesA(localDll.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                outDllPath = localDll;
                return true;
            }
        }

        if (GetFileAttributesA("InjectableDLL.dll") != INVALID_FILE_ATTRIBUTES) {
            char fullPath[MAX_PATH] = {};
            GetFullPathNameA("InjectableDLL.dll", MAX_PATH, fullPath, nullptr);
            outDllPath = fullPath;
            return true;
        }

        outError = "Could not extract embedded DLL and InjectableDLL.dll was not found next to EXE.";
        return false;
    }

    bool ProcessInspector::InjectDLL(void* handle, const std::string& dllPath, std::string& outError) {
        HANDLE h = static_cast<HANDLE>(handle);

        // 1. Allocate memory in the target for the DLL path string
        SIZE_T pathLen = dllPath.size() + 1;
        LPVOID remotePathBuf = VirtualAllocEx(h, nullptr, pathLen,
                                               MEM_RESERVE | MEM_COMMIT,
                                               PAGE_READWRITE);
        if (!remotePathBuf) {
            outError = "VirtualAllocEx failed (GetLastError=" +
                       std::to_string(GetLastError()) + ")";
            return false;
        }

        // 2. Write the DLL path into the target
        SIZE_T bytesWritten = 0;
        if (!WriteProcessMemory(h, remotePathBuf, dllPath.c_str(), pathLen, &bytesWritten)
            || bytesWritten != pathLen) {
            outError = "WriteProcessMemory failed (GetLastError=" +
                       std::to_string(GetLastError()) + ")";
            VirtualFreeEx(h, remotePathBuf, 0, MEM_RELEASE);
            return false;
        }

        // 3. Locate LoadLibraryA in kernel32 (same VA in all x64 processes)
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (!hKernel32) {
            outError = "GetModuleHandle(kernel32.dll) failed.";
            VirtualFreeEx(h, remotePathBuf, 0, MEM_RELEASE);
            return false;
        }

        FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
        if (!pLoadLibraryA) {
            outError = "GetProcAddress(LoadLibraryA) failed.";
            VirtualFreeEx(h, remotePathBuf, 0, MEM_RELEASE);
            return false;
        }

        // 4. Create a remote thread that calls LoadLibraryA(dllPath)
        DWORD threadId = 0;
        HANDLE hThread = CreateRemoteThread(
            h, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibraryA),
            remotePathBuf, 0, &threadId);

        if (!hThread) {
            outError = "CreateRemoteThread failed (GetLastError=" +
                       std::to_string(GetLastError()) + ")";
            VirtualFreeEx(h, remotePathBuf, 0, MEM_RELEASE);
            return false;
        }

        // 5. Wait for the remote thread (LoadLibraryA) to finish loading
        WaitForSingleObject(hThread, 8000); // up to 8s

        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        CloseHandle(hThread);

        // Don't free remotePathBuf – the DLL might still reference it.
        // It will be released when the process terminates.

        if (exitCode == 0) {
            outError = "LoadLibraryA inside target returned NULL "
                       "(DLL not found, missing dependencies, or wrong architecture).";
            return false;
        }

        return true; // exitCode is the HMODULE of the loaded DLL (non-zero = success)
    }

    // =========================================================================
    //  Named Pipe – two-phase API
    //  Phase 1: CreateInjectionPipe  – called on MAIN thread BEFORE InjectDLL
    //  Phase 2: DrainInjectionPipe  – called on BACKGROUND thread after injection
    // =========================================================================

    void* ProcessInspector::CreateInjectionPipe() {
        // NULL DACL security descriptor allows all processes / integrity levels (low, medium, high) to connect
        SECURITY_DESCRIPTOR sd;
        InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);

        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = &sd;
        sa.bInheritHandle = FALSE;

        HANDLE pipe = CreateNamedPipeW(
            INJECT_PIPE_NAME,
            PIPE_ACCESS_INBOUND,                         // Host only reads from DLL
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,                    // Allow multiple instances/reconnects
            0, 65536,                                    // out buf=0, in buf=64KB
            30000,                                       // default timeout 30s
            &sa);

        if (pipe == INVALID_HANDLE_VALUE) {
            return nullptr;
        }
        return static_cast<void*>(pipe);
    }

    bool ProcessInspector::DrainInjectionPipe(
        void* pipeHandle,
        int   timeoutMs,
        std::function<void(const std::string&)>              onStatus,
        std::function<void(const InjectMsg_FoundOffset&)>    onOffset,
        std::function<void(const InjectMsg_RegisterValues&)> onRegisters,
        std::function<void(const InjectMsg_ModuleEntry&)>    onModule,
        std::function<void(const InjectMsg_UnicornResult&)>  onUnicorn,
        std::function<void(const InjectMsg_PatternMatch&)>   onPattern,
        std::function<void(const InjectMsg_MathResult&)>     onMath)
    {
        if (!pipeHandle) return false;
        HANDLE pipe = static_cast<HANDLE>(pipeHandle);

        // Set read timeout via COMMTIMEOUTS-style overlapped – simpler: use
        // a thread that will CloseHandle(pipe) after timeoutMs if still waiting.
        // We implement a simple approach: use SetNamedPipeHandleState with
        // a collection timeout. Since the pipe is BLOCKING, we rely on the
        // DLL's own retry loop (30 * 200ms = 6s) and the pipe's default timeout.

        // Wait for the DLL client to connect
        BOOL connected = ConnectNamedPipe(pipe, nullptr);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(pipe);
            return false;
        }

        // ── Packet dispatch loop ─────────────────────────────────────────
        bool done = false;
        while (!done) {
            InjectPacketHeader hdr{};
            DWORD bytesRead = 0;

            if (!ReadFile(pipe, &hdr, sizeof(hdr), &bytesRead, nullptr)
                || bytesRead != sizeof(hdr)) {
                break;
            }

            if (hdr.payloadSize == 0 || hdr.payloadSize > 65536) {
                break; // Corrupt packet guard
            }

            std::vector<uint8_t> payload(hdr.payloadSize);
            DWORD payRead = 0;
            if (!ReadFile(pipe, payload.data(), hdr.payloadSize, &payRead, nullptr)
                || payRead != hdr.payloadSize) {
                break;
            }

            switch (hdr.type) {
                case InjectMsgType::StatusMessage:
                    if (payRead >= sizeof(InjectMsg_Status) && onStatus)
                        onStatus(std::string(reinterpret_cast<const InjectMsg_Status*>(payload.data())->text));
                    break;

                case InjectMsgType::FoundOffset:
                    if (payRead >= sizeof(InjectMsg_FoundOffset) && onOffset)
                        onOffset(*reinterpret_cast<const InjectMsg_FoundOffset*>(payload.data()));
                    break;

                case InjectMsgType::RegisterValues:
                    if (payRead >= sizeof(InjectMsg_RegisterValues) && onRegisters)
                        onRegisters(*reinterpret_cast<const InjectMsg_RegisterValues*>(payload.data()));
                    break;

                case InjectMsgType::ModuleList:
                    if (payRead >= sizeof(InjectMsg_ModuleEntry) && onModule)
                        onModule(*reinterpret_cast<const InjectMsg_ModuleEntry*>(payload.data()));
                    break;

                case InjectMsgType::UnicornResult:
                    if (payRead >= sizeof(InjectMsg_UnicornResult) && onUnicorn)
                        onUnicorn(*reinterpret_cast<const InjectMsg_UnicornResult*>(payload.data()));
                    break;

                case InjectMsgType::PatternMatch:
                    if (payRead >= sizeof(InjectMsg_PatternMatch) && onPattern)
                        onPattern(*reinterpret_cast<const InjectMsg_PatternMatch*>(payload.data()));
                    break;

                case InjectMsgType::MathResult:
                    if (payRead >= sizeof(InjectMsg_MathResult) && onMath)
                        onMath(*reinterpret_cast<const InjectMsg_MathResult*>(payload.data()));
                    break;

                case InjectMsgType::DoneMarker:
                    done = true;
                    break;

                default:
                    break;
            }
        }

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return true;
    }

#else // !_WIN32

    std::vector<ProcessMatch> ProcessInspector::FindProcessesByName(const std::string&) {
        return {};
    }

    void* ProcessInspector::OpenReadOnly(uint32_t, std::string& outError) {
        outError = "Live process inspection is only supported on Windows.";
        return nullptr;
    }

    void ProcessInspector::Close(void*) {}

    std::optional<ModuleInfo> ProcessInspector::ResolveMainModule(void*, uint32_t, std::string& outError) {
        outError = "Live process inspection is only supported on Windows.";
        return std::nullopt;
    }

    std::vector<uint8_t> ProcessInspector::ReadMemory(void*, uint64_t, size_t, size_t& outBytesRead, std::string& outError) {
        outBytesRead = 0;
        outError = "Live process inspection is only supported on Windows.";
        return {};
    }

    std::vector<ExportedSymbol> ProcessInspector::ResolveExportedSymbols(void*, uint64_t, std::string& outError) {
        outError = "Live process inspection is only supported on Windows.";
        return {};
    }

    std::vector<uint64_t> ProcessInspector::FindPattern(void*, uint64_t, size_t, const std::string&, std::string& outError) {
        outError = "Live process inspection is only supported on Windows.";
        return {};
    }

    void* ProcessInspector::OpenForInjection(uint32_t, std::string& outError) {
        outError = "DLL injection is only supported on Windows.";
        return nullptr;
    }

    bool ProcessInspector::ExtractEmbeddedDLL(std::string&, std::string& outError) {
        outError = "DLL injection is only supported on Windows.";
        return false;
    }

    bool ProcessInspector::InjectDLL(void*, const std::string&, std::string& outError) {
        outError = "DLL injection is only supported on Windows.";
        return false;
    }

    void* ProcessInspector::CreateInjectionPipe() { return nullptr; }

    bool ProcessInspector::DrainInjectionPipe(void*, int,
        std::function<void(const std::string&)>,
        std::function<void(const InjectMsg_FoundOffset&)>,
        std::function<void(const InjectMsg_RegisterValues&)>,
        std::function<void(const InjectMsg_ModuleEntry&)>,
        std::function<void(const InjectMsg_UnicornResult&)>,
        std::function<void(const InjectMsg_PatternMatch&)>,
        std::function<void(const InjectMsg_MathResult&)>) {
        return false;
    }

#endif

} // namespace Sandbox
