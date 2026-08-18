#include "utr/target.h"

#include <iostream>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#endif

namespace Dracula {
namespace UTR {

    std::shared_ptr<ITarget> CreateFileTarget(const TargetInfo& info);
    std::shared_ptr<ITarget> CreateProcessTarget(const TargetInfo& info);

    class ServiceTarget : public ITarget {
    public:
        ServiceTarget(const TargetInfo& info) : m_info(info) {
            ResolveService();
        }

        ~ServiceTarget() override = default;

        TargetInfo GetInfo() const override {
            return m_info;
        }

        TargetCapabilities GetCapabilities() const override {
            TargetCapabilities caps;
            caps.staticAnalysis = true;
            caps.modules = true;
            if (m_info.pid > 0) {
                caps.threads = true;
                caps.memoryRead = true;
                caps.memorySnapshots = true;
                caps.runtimeEvents = true;
            }
            caps.functions = true;
            caps.symbols = true;
            return caps;
        }

        Result<std::vector<UtrModuleInfo>> EnumerateModules() override {
            if (m_delegateTarget) return m_delegateTarget->EnumerateModules();
            return Result<std::vector<UtrModuleInfo>>::Success({});
        }

        Result<std::vector<UtrThreadInfo>> EnumerateThreads() override {
            if (m_delegateTarget) return m_delegateTarget->EnumerateThreads();
            return Result<std::vector<UtrThreadInfo>>::Success({});
        }

        Result<std::vector<MemoryRegion>> GetMemoryMap() override {
            if (m_delegateTarget) return m_delegateTarget->GetMemoryMap();
            return Result<std::vector<MemoryRegion>>::Success({});
        }

        Result<std::vector<uint8_t>> ReadMemory(uint64_t address, size_t size) override {
            if (m_delegateTarget) return m_delegateTarget->ReadMemory(address, size);
            return Result<std::vector<uint8_t>>::Fail("Service not running and no image available.");
        }

        Result<MemorySnapshot> TakeSnapshot(const std::string& label) override {
            if (m_delegateTarget) return m_delegateTarget->TakeSnapshot(label);
            return Result<MemorySnapshot>::Fail("Service snapshot requires running process or valid image.");
        }

        Result<std::vector<FunctionIntelligenceItem>> EnumerateFunctions() override {
            if (m_delegateTarget) return m_delegateTarget->EnumerateFunctions();
            return Result<std::vector<FunctionIntelligenceItem>>::Success({});
        }

    private:
        void ResolveService() {
#ifdef _WIN32
            SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
            if (!hSCM) return;

            SC_HANDLE hService = OpenServiceA(hSCM, m_info.serviceName.c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
            if (hService) {
                SERVICE_STATUS_PROCESS ssp;
                DWORD bytesNeeded = 0;
                if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded)) {
                    m_info.pid = (ssp.dwCurrentState == SERVICE_RUNNING) ? ssp.dwProcessId : 0;
                    m_info.serviceState = (ssp.dwCurrentState == SERVICE_RUNNING) ? "Running" : "Stopped";
                }

                BYTE configBuf[4096] = {0};
                auto pConfig = reinterpret_cast<LPQUERY_SERVICE_CONFIGA>(configBuf);
                if (QueryServiceConfigA(hService, pConfig, sizeof(configBuf), &bytesNeeded)) {
                    m_info.serviceDisplayName = pConfig->lpDisplayName ? pConfig->lpDisplayName : "";
                    m_info.path = pConfig->lpBinaryPathName ? pConfig->lpBinaryPathName : "";
                }
                CloseServiceHandle(hService);
            }
            CloseServiceHandle(hSCM);

            if (m_info.pid > 0) {
                m_info.kind = TargetKind::RunningProcess;
                m_delegateTarget = CreateProcessTarget(m_info);
            } else if (!m_info.path.empty()) {
                m_info.kind = TargetKind::NativeExe;
                m_delegateTarget = CreateFileTarget(m_info);
            }
#endif
        }

        TargetInfo               m_info;
        std::shared_ptr<ITarget> m_delegateTarget;
    };

    std::shared_ptr<ITarget> CreateServiceTarget(const TargetInfo& info) {
        return std::make_shared<ServiceTarget>(info);
    }

} // namespace UTR
} // namespace Dracula
