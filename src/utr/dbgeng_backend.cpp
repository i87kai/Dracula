#include "utr/external_observer.h"

#include <iostream>
#include <sstream>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dbghelp.h>
#endif

namespace Dracula {
namespace UTR {

    DbgEngBackend::DbgEngBackend() = default;

    DbgEngBackend::~DbgEngBackend() {
        Detach();
    }

    bool DbgEngBackend::Initialize(std::string& outError) {
        if (m_initialized) return true;

#ifdef _WIN32
        m_hDbgHelpDll = LoadLibraryA("dbghelp.dll");
        if (!m_hDbgHelpDll) {
            outError = "Failed to load dbghelp.dll";
            return false;
        }

        m_initialized = true;
        return true;
#else
        outError = "DbgEng requires Windows host.";
        return false;
#endif
    }

    bool DbgEngBackend::AttachProcess(uint32_t pid, std::string& outError) {
        Detach();
        if (!Initialize(outError)) return false;

#ifdef _WIN32
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) {
            outError = "Failed to open process PID " + std::to_string(pid) + " (Error: " + std::to_string(GetLastError()) + ")";
            return false;
        }

        m_processHandle = hProcess;
        m_targetPid = pid;
        m_attached = true;

        // Initialize SymInitialize
        typedef BOOL (WINAPI *SymInitFn)(HANDLE, PCSTR, BOOL);
        auto symInit = reinterpret_cast<SymInitFn>(GetProcAddress(static_cast<HMODULE>(m_hDbgHelpDll), "SymInitialize"));
        if (symInit) {
            symInit(hProcess, nullptr, TRUE);
        }

        return true;
#else
        outError = "DbgEng requires Windows host.";
        return false;
#endif
    }

    void DbgEngBackend::Detach() {
#ifdef _WIN32
        if (m_processHandle) {
            if (m_hDbgHelpDll) {
                typedef BOOL (WINAPI *SymCleanupFn)(HANDLE);
                auto symCleanup = reinterpret_cast<SymCleanupFn>(GetProcAddress(static_cast<HMODULE>(m_hDbgHelpDll), "SymCleanup"));
                if (symCleanup) symCleanup(static_cast<HANDLE>(m_processHandle));
            }
            CloseHandle(static_cast<HANDLE>(m_processHandle));
            m_processHandle = nullptr;
        }
        if (m_hDbgHelpDll) {
            FreeLibrary(static_cast<HMODULE>(m_hDbgHelpDll));
            m_hDbgHelpDll = nullptr;
        }
#endif
        m_attached = false;
        m_initialized = false;
    }

    Result<std::vector<UtrModuleInfo>> DbgEngBackend::EnumerateModules() {
        std::vector<UtrModuleInfo> modules;
#ifdef _WIN32
        if (!m_attached || !m_processHandle) {
            return Result<std::vector<UtrModuleInfo>>::Fail("Debugger not attached to process.");
        }

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_targetPid);
        if (hSnap == INVALID_HANDLE_VALUE) {
            return Result<std::vector<UtrModuleInfo>>::Fail("Failed to create module snapshot for PID " + std::to_string(m_targetPid));
        }

        MODULEENTRY32W me;
        me.dwSize = sizeof(MODULEENTRY32W);
        if (Module32FirstW(hSnap, &me)) {
            bool isMain = true;
            do {
                UtrModuleInfo mod;
                mod.baseAddress = reinterpret_cast<uint64_t>(me.modBaseAddr);
                mod.size = me.modBaseSize;

                char nameBuf[MAX_PATH] = {0};
                WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, nameBuf, sizeof(nameBuf) - 1, nullptr, nullptr);
                mod.name = nameBuf;

                char pathBuf[MAX_PATH] = {0};
                WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, pathBuf, sizeof(pathBuf) - 1, nullptr, nullptr);
                mod.path = pathBuf;
                mod.isMainModule = isMain;
                isMain = false;

                modules.push_back(mod);
            } while (Module32NextW(hSnap, &me));
        }
        CloseHandle(hSnap);
        return Result<std::vector<UtrModuleInfo>>::Success(modules);
#else
        return Result<std::vector<UtrModuleInfo>>::Fail("DbgEng requires Windows host.");
#endif
    }

    Result<std::vector<UtrThreadInfo>> DbgEngBackend::EnumerateThreads() {
        std::vector<UtrThreadInfo> threads;
#ifdef _WIN32
        if (!m_attached) {
            return Result<std::vector<UtrThreadInfo>>::Fail("Debugger not attached.");
        }

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap == INVALID_HANDLE_VALUE) {
            return Result<std::vector<UtrThreadInfo>>::Fail("Failed to create thread snapshot.");
        }

        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(hSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == m_targetPid) {
                    UtrThreadInfo t;
                    t.tid = te.th32ThreadID;
                    t.priority = te.tpBasePri;
                    t.state = "Running";
                    threads.push_back(t);
                }
            } while (Thread32Next(hSnap, &te));
        }
        CloseHandle(hSnap);
        return Result<std::vector<UtrThreadInfo>>::Success(threads);
#else
        return Result<std::vector<UtrThreadInfo>>::Fail("DbgEng requires Windows host.");
#endif
    }

    Result<std::vector<uint8_t>> DbgEngBackend::ReadMemory(uint64_t address, size_t size) {
#ifdef _WIN32
        if (!m_attached || !m_processHandle) {
            return Result<std::vector<uint8_t>>::Fail("Debugger not attached.");
        }

        std::vector<uint8_t> buffer(size);
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(static_cast<HANDLE>(m_processHandle), reinterpret_cast<LPCVOID>(address), buffer.data(), size, &bytesRead)) {
            return Result<std::vector<uint8_t>>::Fail("ReadProcessMemory failed at 0x" + std::to_string(address));
        }
        buffer.resize(bytesRead);
        return Result<std::vector<uint8_t>>::Success(buffer);
#else
        return Result<std::vector<uint8_t>>::Fail("DbgEng requires Windows host.");
#endif
    }

    Result<std::string> DbgEngBackend::ResolveSymbol(uint64_t address) {
#ifdef _WIN32
        if (!m_attached || !m_processHandle || !m_hDbgHelpDll) {
            return Result<std::string>::Fail("Debugger not attached.");
        }

        typedef BOOL (WINAPI *SymFromAddrFn)(HANDLE, DWORD64, PDWORD64, PSYMBOL_INFO);
        auto symFromAddr = reinterpret_cast<SymFromAddrFn>(GetProcAddress(static_cast<HMODULE>(m_hDbgHelpDll), "SymFromAddr"));
        if (!symFromAddr) {
            return Result<std::string>::Fail("SymFromAddr not found in dbghelp.dll");
        }

        char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)] = {0};
        auto pSymbol = reinterpret_cast<PSYMBOL_INFO>(buffer);
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement = 0;
        if (symFromAddr(static_cast<HANDLE>(m_processHandle), address, &displacement, pSymbol)) {
            std::string name(pSymbol->Name);
            if (displacement > 0) {
                name += "+0x" + std::to_string(displacement);
            }
            return Result<std::string>::Success(name);
        }

        return Result<std::string>::Fail("Symbol not found");
#else
        return Result<std::string>::Fail("DbgEng requires Windows host.");
#endif
    }

} // namespace UTR
} // namespace Dracula
