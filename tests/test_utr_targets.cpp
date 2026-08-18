#include "utr/target_manager.h"
#include "utr/target.h"
#include <iostream>
#include <cassert>

using namespace Dracula;
using namespace Dracula::UTR;

int main() {
    std::cout << "[Test] Running UTR Target Identification & Abstraction Suite...\n";

    TargetManager& mgr = TargetManager::Instance();

    // 1. Test Native EXE Fingerprinting
    TargetInfo exeInfo = mgr.Fingerprint("samples/utr/native_simple.exe");
    std::cout << "  EXE Kind: " << TargetKindToString(exeInfo.kind) << " (Expected: NativeExe)\n";
    assert(exeInfo.kind == TargetKind::NativeExe);
    assert(!exeInfo.isDotNet);

    // 2. Test Native DLL Fingerprinting
    TargetInfo dllInfo = mgr.Fingerprint("samples/utr/test_library.dll");
    std::cout << "  DLL Kind: " << TargetKindToString(dllInfo.kind) << " (Expected: NativeDll)\n";
    assert(dllInfo.kind == TargetKind::NativeDll);

    // 3. Test Driver (.sys) Fingerprinting
    TargetInfo sysInfo = mgr.Fingerprint("samples/utr/driver_static_fixture.sys");
    std::cout << "  SYS Kind: " << TargetKindToString(sysInfo.kind) << " (Expected: Driver)\n";
    assert(sysInfo.kind == TargetKind::Driver);

    // 4. Test Managed .NET Assembly Fingerprinting
    TargetInfo mgdInfo = mgr.Fingerprint("samples/utr/managed/bin/Release/net10.0/ManagedFixture.dll");
    std::cout << "  .NET Kind: " << TargetKindToString(mgdInfo.kind) << " (Expected: ManagedDll)\n";
    assert(mgdInfo.kind == TargetKind::ManagedDll || mgdInfo.isDotNet);

    // 5. Test PID Specifier Fingerprinting
    TargetInfo pidInfo = mgr.Fingerprint("--pid 1234");
    std::cout << "  PID Kind: " << TargetKindToString(pidInfo.kind) << " PID=" << pidInfo.pid << " (Expected: RunningProcess, 1234)\n";
    assert(pidInfo.kind == TargetKind::RunningProcess);
    assert(pidInfo.pid == 1234);

    // 6. Test Service Specifier Fingerprinting
    TargetInfo svcInfo = mgr.Fingerprint("--service Spooler");
    std::cout << "  SVC Kind: " << TargetKindToString(svcInfo.kind) << " Svc=" << svcInfo.serviceName << " (Expected: Service, Spooler)\n";
    assert(svcInfo.kind == TargetKind::Service);
    assert(svcInfo.serviceName == "Spooler");

    // 7. Test Target Opening & Capability Matrix
    auto openRes = mgr.OpenTarget("samples/utr/native_simple.exe");
    assert(openRes.Ok());
    auto target = openRes.Value();
    assert(target != nullptr);
    auto caps = target->GetCapabilities();
    assert(caps.staticAnalysis);
    assert(caps.functions);

    mgr.CloseActiveTarget();
    assert(mgr.GetActiveTarget() == nullptr);

    std::cout << "[Test] UTR Target Abstraction Suite PASSED!\n";
    return 0;
}
