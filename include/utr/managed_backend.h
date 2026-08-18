#pragma once

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <cstdint>

#include "utr/types.h"

namespace Dracula {
namespace UTR {

    struct ManagedTypeInfo {
        std::string fullName;
        std::string namespaceName;
        std::string name;
        std::string baseType;
        std::string attributes;
        bool        isInterface = false;
        bool        isClass = true;
        uint32_t    methodCount = 0;
        uint32_t    fieldCount = 0;
    };

    struct ManagedMethodInfo {
        std::string type;
        std::string method;
        std::string rva;
        std::string attributes;
        bool        isStatic = false;
        bool        isPInvoke = false;
        std::string pinvokeDll;
        std::string pinvokeEntryPoint;
        uint32_t    ilSize = 0;
        std::string ilHex;
        std::vector<std::string> ilDisassembly;
    };

    struct ManagedPInvokeInfo {
        std::string type;
        std::string method;
        std::string dll;
        std::string entryPoint;
        std::string callingConvention;
    };

    struct ManagedAssemblyInfo {
        std::string path;
        std::string assemblyName;
        std::string version;
        std::string culture;
        std::string moduleName;
        uint32_t    typeCount = 0;
        uint32_t    methodCount = 0;
        std::string entryPoint;
        bool        isAssembly = true;
    };

    class ManagedHostClient {
    public:
        static ManagedHostClient& Instance();

        ManagedHostClient();
        ~ManagedHostClient();

        bool EnsureStarted();
        void Shutdown();

        Result<std::string> Ping();
        Result<ManagedAssemblyInfo> InspectAssembly(const std::string& filePath);
        Result<std::vector<ManagedTypeInfo>> ListTypes(const std::string& filePath);
        Result<ManagedMethodInfo> InspectMethod(const std::string& filePath, const std::string& typeName, const std::string& methodName);
        Result<std::vector<std::string>> ListStrings(const std::string& filePath);
        Result<std::vector<ManagedPInvokeInfo>> ListPInvokes(const std::string& filePath);

        bool IsAvailable() const { return m_available; }

    private:
        Result<std::string> SendRequest(const std::string& method, const std::string& paramsJson, uint32_t timeoutMs = 5000);
        std::string LocateManagedHostExe() const;

        void*       m_hProcess = nullptr;
        void*       m_hStdInWrite = nullptr;
        void*       m_hStdOutRead = nullptr;
        bool        m_available = false;
        uint32_t    m_reqCounter = 0;
        std::mutex  m_mutex;
    };

} // namespace UTR
} // namespace Dracula
