#include "utr/managed_backend.h"
#include <iostream>
#include <cassert>

using namespace Dracula::UTR;

int main() {
    std::cout << "[Test] Running ManagedHost .NET 10 Out-of-Process Backend Suite...\n";

    ManagedHostClient& client = ManagedHostClient::Instance();
    if (!client.IsAvailable()) {
        std::cout << "  [Skip] ManagedHost executable not present on path or in build artifacts.\n";
        return 0;
    }

    auto pingRes = client.Ping();
    assert(pingRes.Ok());
    std::cout << "  Ping response: " << pingRes.Value() << "\n";

    std::string sampleDll = "samples/utr/managed/bin/Release/net10.0/ManagedFixture.dll";

    // 1. Inspect Assembly
    auto asmRes = client.InspectAssembly(sampleDll);
    assert(asmRes.Ok());
    std::cout << "  Assembly Name: " << asmRes.Value().assemblyName << " (Types: " << asmRes.Value().typeCount << ")\n";
    assert(asmRes.Value().assemblyName == "ManagedFixture");

    // 2. List Types
    auto typesRes = client.ListTypes(sampleDll);
    assert(typesRes.Ok());
    std::cout << "  Discovered " << typesRes.Value().size() << " types\n";
    bool foundSecurityManager = false;
    for (const auto& t : typesRes.Value()) {
        if (t.name == "SecurityManager") foundSecurityManager = true;
    }
    assert(foundSecurityManager);

    // 3. Inspect Method
    auto methRes = client.InspectMethod(sampleDll, "Dracula.ManagedFixture.SecurityManager", "CalculateHash");
    assert(methRes.Ok());
    std::cout << "  CalculateHash IL size: " << methRes.Value().ilSize << " bytes\n";
    assert(methRes.Value().ilSize > 0);

    // 4. List P/Invokes
    auto pinvokesRes = client.ListPInvokes(sampleDll);
    assert(pinvokesRes.Ok());
    std::cout << "  Discovered " << pinvokesRes.Value().size() << " P/Invokes\n";
    bool foundGetCurrentProcessId = false;
    for (const auto& p : pinvokesRes.Value()) {
        if (p.method == "GetCurrentProcessId" && p.dll == "kernel32.dll") {
            foundGetCurrentProcessId = true;
        }
    }
    assert(foundGetCurrentProcessId);

    // 5. List Strings
    auto strRes = client.ListStrings(sampleDll);
    assert(strRes.Ok());
    std::cout << "  Discovered " << strRes.Value().size() << " user strings\n";
    bool foundSecret = false;
    for (const auto& s : strRes.Value()) {
        if (s.find("DRACULA_CONFIDENTIAL_KEY") != std::string::npos) foundSecret = true;
    }
    assert(foundSecret);

    std::cout << "[Test] ManagedHost Backend Suite PASSED!\n";
    return 0;
}
