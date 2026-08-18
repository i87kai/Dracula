#include "utr/managed_backend.h"
#include "common/paths.h"

#include <iostream>
#include <sstream>
#include <vector>
#include <regex>
#include <filesystem>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace Dracula {
namespace UTR {

    static std::string ExtractJsonField(const std::string& json, const std::string& field) {
        std::regex re("\"" + field + "\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch match;
        if (std::regex_search(json, match, re) && match.size() > 1) {
            return match[1].str();
        }
        return "";
    }

    static int ExtractJsonInt(const std::string& json, const std::string& field, int defaultVal = 0) {
        std::regex re("\"" + field + "\"\\s*:\\s*([0-9]+)");
        std::smatch match;
        if (std::regex_search(json, match, re) && match.size() > 1) {
            try {
                return std::stoi(match[1].str());
            } catch (...) {}
        }
        return defaultVal;
    }

    static std::string EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            if (c == '"') o << "\\\"";
            else if (c == '\\') o << "\\\\";
            else if (c == '\n') o << "\\n";
            else if (c == '\r') o << "\\r";
            else if (c == '\t') o << "\\t";
            else o << c;
        }
        return o.str();
    }

    ManagedHostClient& ManagedHostClient::Instance() {
        static ManagedHostClient instance;
        return instance;
    }

    ManagedHostClient::ManagedHostClient() {
        EnsureStarted();
    }

    ManagedHostClient::~ManagedHostClient() {
        Shutdown();
    }

    std::string ManagedHostClient::LocateManagedHostExe() const {
        std::vector<std::string> candidates = {
            (fs::path(Paths::ExecutableDir()) / "src" / "managed" / "Dracula.ManagedHost" / "bin" / "Release" / "net10.0" / "Dracula.ManagedHost.exe").string(),
            (fs::path(Paths::ResourceRoot()) / "src" / "managed" / "Dracula.ManagedHost" / "bin" / "Release" / "net10.0" / "Dracula.ManagedHost.exe").string(),
            (fs::path(Paths::CurrentWorkingDir()) / "src" / "managed" / "Dracula.ManagedHost" / "bin" / "Release" / "net10.0" / "Dracula.ManagedHost.exe").string(),
            (fs::path(Paths::ExecutableDir()) / "Dracula.ManagedHost.exe").string()
        };

        for (const auto& c : candidates) {
            if (fs::exists(c)) return c;
        }

        // Check DLL for dotnet invocation
        std::vector<std::string> dllCandidates = {
            (fs::path(Paths::ResourceRoot()) / "src" / "managed" / "Dracula.ManagedHost" / "bin" / "Release" / "net10.0" / "Dracula.ManagedHost.dll").string(),
            (fs::path(Paths::ExecutableDir()) / "src" / "managed" / "Dracula.ManagedHost" / "bin" / "Release" / "net10.0" / "Dracula.ManagedHost.dll").string(),
            (fs::path(Paths::CurrentWorkingDir()) / "src" / "managed" / "Dracula.ManagedHost" / "bin" / "Release" / "net10.0" / "Dracula.ManagedHost.dll").string()
        };

        for (const auto& d : dllCandidates) {
            if (fs::exists(d)) return d;
        }

        return "";
    }

    bool ManagedHostClient::EnsureStarted() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_available && m_hProcess != nullptr) {
#ifdef _WIN32
            DWORD exitCode = 0;
            if (GetExitCodeProcess(static_cast<HANDLE>(m_hProcess), &exitCode) && exitCode == STILL_ACTIVE) {
                return true;
            }
#endif
            Shutdown();
        }

        std::string hostTarget = LocateManagedHostExe();
        if (hostTarget.empty()) {
            m_available = false;
            return false;
        }

#ifdef _WIN32
        SECURITY_ATTRIBUTES saAttr;
        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle = TRUE;
        saAttr.lpSecurityDescriptor = nullptr;

        HANDLE hChildStdInRead = nullptr;
        HANDLE hChildStdInWrite = nullptr;
        HANDLE hChildStdOutRead = nullptr;
        HANDLE hChildStdOutWrite = nullptr;

        if (!CreatePipe(&hChildStdOutRead, &hChildStdOutWrite, &saAttr, 0)) return false;
        if (!SetHandleInformation(hChildStdOutRead, HANDLE_FLAG_INHERIT, 0)) return false;

        if (!CreatePipe(&hChildStdInRead, &hChildStdInWrite, &saAttr, 0)) {
            CloseHandle(hChildStdOutRead);
            CloseHandle(hChildStdOutWrite);
            return false;
        }
        if (!SetHandleInformation(hChildStdInWrite, HANDLE_FLAG_INHERIT, 0)) return false;

        PROCESS_INFORMATION piProcInfo;
        STARTUPINFOA siStartInfo;
        ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
        ZeroMemory(&siStartInfo, sizeof(STARTUPINFOA));
        siStartInfo.cb = sizeof(STARTUPINFOA);
        siStartInfo.hStdError = hChildStdOutWrite;
        siStartInfo.hStdOutput = hChildStdOutWrite;
        siStartInfo.hStdInput = hChildStdInRead;
        siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

        std::string cmdLine;
        if (hostTarget.ends_with(".dll")) {
            cmdLine = "dotnet \"" + hostTarget + "\"";
        } else {
            cmdLine = "\"" + hostTarget + "\"";
        }

        BOOL bSuccess = CreateProcessA(
            nullptr,
            cmdLine.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &siStartInfo,
            &piProcInfo
        );

        CloseHandle(hChildStdOutWrite);
        CloseHandle(hChildStdInRead);

        if (!bSuccess) {
            CloseHandle(hChildStdOutRead);
            CloseHandle(hChildStdInWrite);
            m_available = false;
            return false;
        }

        CloseHandle(piProcInfo.hThread);
        m_hProcess = piProcInfo.hProcess;
        m_hStdInWrite = hChildStdInWrite;
        m_hStdOutRead = hChildStdOutRead;
        m_available = true;
        return true;
#else
        return false;
#endif
    }

    void ManagedHostClient::Shutdown() {
#ifdef _WIN32
        if (m_hProcess) {
            TerminateProcess(static_cast<HANDLE>(m_hProcess), 0);
            CloseHandle(static_cast<HANDLE>(m_hProcess));
            m_hProcess = nullptr;
        }
        if (m_hStdInWrite) {
            CloseHandle(static_cast<HANDLE>(m_hStdInWrite));
            m_hStdInWrite = nullptr;
        }
        if (m_hStdOutRead) {
            CloseHandle(static_cast<HANDLE>(m_hStdOutRead));
            m_hStdOutRead = nullptr;
        }
#endif
        m_available = false;
    }

    Result<std::string> ManagedHostClient::SendRequest(const std::string& method, const std::string& paramsJson, uint32_t timeoutMs) {
        if (!EnsureStarted()) {
            return Result<std::string>::Fail("ManagedHost executable unavailable or failed to launch.");
        }

#ifdef _WIN32
        std::string id = std::to_string(++m_reqCounter);
        std::string req = "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"method\":\"" + method + "\",\"params\":" + paramsJson + "}\n";

        DWORD bytesWritten = 0;
        if (!WriteFile(static_cast<HANDLE>(m_hStdInWrite), req.data(), static_cast<DWORD>(req.size()), &bytesWritten, nullptr)) {
            Shutdown();
            return Result<std::string>::Fail("Failed to write request to ManagedHost stdin pipe.");
        }

        // Read response line with bounded timeout
        std::string response;
        auto startTime = std::chrono::steady_clock::now();

        while (true) {
            DWORD bytesAvail = 0;
            if (!PeekNamedPipe(static_cast<HANDLE>(m_hStdOutRead), nullptr, 0, nullptr, &bytesAvail, nullptr)) {
                Shutdown();
                return Result<std::string>::Fail("ManagedHost process terminated unexpectedly.");
            }

            if (bytesAvail > 0) {
                char ch = 0;
                DWORD bytesRead = 0;
                if (ReadFile(static_cast<HANDLE>(m_hStdOutRead), &ch, 1, &bytesRead, nullptr) && bytesRead > 0) {
                    if (ch == '\n') break;
                    if (ch != '\r') response += ch;
                }
            } else {
                Sleep(10);
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime).count();
                if (elapsed > timeoutMs) {
                    Shutdown();
                    return Result<std::string>::Fail("ManagedHost request timed out (" + std::to_string(timeoutMs) + "ms).");
                }
            }
        }

        if (response.find("\"error\"") != std::string::npos) {
            std::string errMessage = ExtractJsonField(response, "message");
            return Result<std::string>::Fail(errMessage.empty() ? "ManagedHost returned error" : errMessage);
        }

        return Result<std::string>::Success(response);
#else
        return Result<std::string>::Fail("ManagedHost not supported on POSIX host.");
#endif
    }

    Result<std::string> ManagedHostClient::Ping() {
        return SendRequest("ping", "{}");
    }

    Result<ManagedAssemblyInfo> ManagedHostClient::InspectAssembly(const std::string& filePath) {
        std::string params = "{\"path\":\"" + EscapeJson(filePath) + "\"}";
        auto res = SendRequest("inspect_assembly", params);
        if (!res.Ok()) return Result<ManagedAssemblyInfo>::Fail(res.Error());

        const std::string& json = res.Value();
        ManagedAssemblyInfo info;
        info.path = filePath;
        info.assemblyName = ExtractJsonField(json, "assembly_name");
        info.version = ExtractJsonField(json, "version");
        info.culture = ExtractJsonField(json, "culture");
        info.moduleName = ExtractJsonField(json, "module_name");
        info.typeCount = static_cast<uint32_t>(ExtractJsonInt(json, "type_count"));
        info.methodCount = static_cast<uint32_t>(ExtractJsonInt(json, "method_count"));
        info.entryPoint = ExtractJsonField(json, "entry_point");
        return Result<ManagedAssemblyInfo>::Success(info);
    }

    Result<std::vector<ManagedTypeInfo>> ManagedHostClient::ListTypes(const std::string& filePath) {
        std::string params = "{\"path\":\"" + EscapeJson(filePath) + "\"}";
        auto res = SendRequest("list_types", params);
        if (!res.Ok()) return Result<std::vector<ManagedTypeInfo>>::Fail(res.Error());

        std::vector<ManagedTypeInfo> types;
        // Parse types array
        std::regex typeRe("\\{\"full_name\":\"([^\"]+)\",\"namespace_name\":\"([^\"]*)\",\"name\":\"([^\"]+)\",\"base_type\":\"([^\"]*)\"");
        std::string json = res.Value();
        auto begin = std::sregex_iterator(json.begin(), json.end(), typeRe);
        auto end = std::sregex_iterator();

        for (auto it = begin; it != end; ++it) {
            std::smatch m = *it;
            ManagedTypeInfo t;
            t.fullName = m[1].str();
            t.namespaceName = m[2].str();
            t.name = m[3].str();
            t.baseType = m[4].str();
            types.push_back(t);
        }

        return Result<std::vector<ManagedTypeInfo>>::Success(types);
    }

    Result<ManagedMethodInfo> ManagedHostClient::InspectMethod(
        const std::string& filePath,
        const std::string& typeName,
        const std::string& methodName)
    {
        std::string params = "{\"path\":\"" + EscapeJson(filePath) + "\",\"type\":\"" + EscapeJson(typeName) + "\",\"method\":\"" + EscapeJson(methodName) + "\"}";
        auto res = SendRequest("inspect_method", params);
        if (!res.Ok()) return Result<ManagedMethodInfo>::Fail(res.Error());

        const std::string& json = res.Value();
        ManagedMethodInfo m;
        m.type = typeName;
        m.method = methodName;
        m.rva = ExtractJsonField(json, "rva");
        m.attributes = ExtractJsonField(json, "attributes");
        m.isPInvoke = (json.find("\"is_pinvoke\":true") != std::string::npos);
        m.pinvokeDll = ExtractJsonField(json, "pinvoke_dll");
        m.pinvokeEntryPoint = ExtractJsonField(json, "pinvoke_entrypoint");
        m.ilHex = ExtractJsonField(json, "il_hex");
        m.ilSize = static_cast<uint32_t>(ExtractJsonInt(json, "il_size"));
        return Result<ManagedMethodInfo>::Success(m);
    }

    Result<std::vector<std::string>> ManagedHostClient::ListStrings(const std::string& filePath) {
        std::string params = "{\"path\":\"" + EscapeJson(filePath) + "\"}";
        auto res = SendRequest("list_strings", params);
        if (!res.Ok()) return Result<std::vector<std::string>>::Fail(res.Error());

        std::vector<std::string> strings;
        std::regex strRe("\"([^\"]+)\"");
        std::string json = res.Value();
        size_t stringsPos = json.find("\"strings\":[");
        if (stringsPos != std::string::npos) {
            std::string sub = json.substr(stringsPos + 11);
            auto begin = std::sregex_iterator(sub.begin(), sub.end(), strRe);
            auto end = std::sregex_iterator();
            for (auto it = begin; it != end; ++it) {
                strings.push_back((*it)[1].str());
                if (strings.size() >= 500) break;
            }
        }
        return Result<std::vector<std::string>>::Success(strings);
    }

    Result<std::vector<ManagedMethodInfo>> ManagedHostClient::ListAllMethods(const std::string& filePath) {
        std::string params = "{\"path\":\"" + EscapeJson(filePath) + "\"}";
        auto res = SendRequest("list_all_methods", params);
        if (!res.Ok()) return Result<std::vector<ManagedMethodInfo>>::Fail(res.Error());

        std::vector<ManagedMethodInfo> methods;
        std::regex mRe("\\{\"type\":\"([^\"]+)\",\"method\":\"([^\"]+)\",\"rva\":\"([^\"]+)\",\"attributes\":\"([^\"]*)\",\"is_static\":(true|false),\"is_pinvoke\":(true|false),\"pinvoke_dll\":\"([^\"]*)\",\"pinvoke_entrypoint\":\"([^\"]*)\",\"il_size\":([0-9]+)");
        std::string json = res.Value();
        auto begin = std::sregex_iterator(json.begin(), json.end(), mRe);
        auto end = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            std::smatch m = *it;
            ManagedMethodInfo info;
            info.type = m[1].str();
            info.method = m[2].str();
            info.rva = m[3].str();
            info.attributes = m[4].str();
            info.isStatic = (m[5].str() == "true");
            info.isPInvoke = (m[6].str() == "true");
            info.pinvokeDll = m[7].str();
            info.pinvokeEntryPoint = m[8].str();
            try { info.ilSize = std::stoul(m[9].str()); } catch (...) {}
            methods.push_back(info);
        }
        return Result<std::vector<ManagedMethodInfo>>::Success(methods);
    }

    Result<std::vector<ManagedPInvokeInfo>> ManagedHostClient::ListPInvokes(const std::string& filePath) {
        std::string params = "{\"path\":\"" + EscapeJson(filePath) + "\"}";
        auto res = SendRequest("list_pinvokes", params);
        if (!res.Ok()) return Result<std::vector<ManagedPInvokeInfo>>::Fail(res.Error());

        std::vector<ManagedPInvokeInfo> pinvokes;
        std::regex pRe("\\{\"type\":\"([^\"]+)\",\"method\":\"([^\"]+)\",\"dll\":\"([^\"]+)\",\"entry_point\":\"([^\"]*)\"");
        std::string json = res.Value();
        auto begin = std::sregex_iterator(json.begin(), json.end(), pRe);
        auto end = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            std::smatch m = *it;
            ManagedPInvokeInfo p;
            p.type = m[1].str();
            p.method = m[2].str();
            p.dll = m[3].str();
            p.entryPoint = m[4].str();
            pinvokes.push_back(p);
        }
        return Result<std::vector<ManagedPInvokeInfo>>::Success(pinvokes);
    }

} // namespace UTR
} // namespace Dracula
