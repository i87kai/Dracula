#include <iostream>
#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

using PfnGetVersion = uint32_t (*)();
using PfnGetEngineName = const char* (*)();
using PfnInitialize = bool (*)(const char*);
using PfnSendEvent = bool (*)(const char*);
using PfnEnumModules = uint32_t (*)(char*, uint32_t);
using PfnRecordMemProtect = bool (*)(uint64_t, uint64_t, uint32_t);
using PfnShutdown = void (*)();

int main() {
    std::cout << "[Test] Running DraculaAgent64 Telemetry Test Suite...\n";

#ifdef _WIN32
    HMODULE hAgent = LoadLibraryA("DraculaAgent64.dll");
    if (!hAgent) {
        hAgent = LoadLibraryA("bin/DraculaAgent64.dll");
    }
    if (!hAgent) {
        hAgent = LoadLibraryA("build/libDraculaAgent64.dll");
    }
    if (!hAgent) {
        hAgent = LoadLibraryA("libDraculaAgent64.dll");
    }
    assert(hAgent != nullptr && "Failed to load DraculaAgent64.dll");

    auto pfnGetVersion = reinterpret_cast<PfnGetVersion>(GetProcAddress(hAgent, "DraculaAgentGetVersion"));
    auto pfnGetEngineName = reinterpret_cast<PfnGetEngineName>(GetProcAddress(hAgent, "DraculaAgentGetEngineName"));
    auto pfnInitialize = reinterpret_cast<PfnInitialize>(GetProcAddress(hAgent, "DraculaAgentInitialize"));
    auto pfnSendEvent = reinterpret_cast<PfnSendEvent>(GetProcAddress(hAgent, "DraculaAgentSendEvent"));
    auto pfnEnumModules = reinterpret_cast<PfnEnumModules>(GetProcAddress(hAgent, "DraculaAgentEnumerateModules"));
    auto pfnRecordMemProtect = reinterpret_cast<PfnRecordMemProtect>(GetProcAddress(hAgent, "DraculaAgentRecordMemoryProtection"));
    auto pfnShutdown = reinterpret_cast<PfnShutdown>(GetProcAddress(hAgent, "DraculaAgentShutdown"));

    assert(pfnGetVersion != nullptr);
    assert(pfnGetEngineName != nullptr);
    assert(pfnInitialize != nullptr);
    assert(pfnSendEvent != nullptr);
    assert(pfnEnumModules != nullptr);
    assert(pfnRecordMemProtect != nullptr);
    assert(pfnShutdown != nullptr);

    // 1. Version & Protocol Negotiation
    uint32_t ver = pfnGetVersion();
    assert(ver == 0x00010201);
    std::cout << "  [PASS] DraculaAgentGetVersion returned 0x" << std::hex << ver << std::dec << "\n";

    // 2. Engine Name
    const char* engine = pfnGetEngineName();
    assert(engine != nullptr);
    std::cout << "  [PASS] Agent Engine: " << engine << "\n";

    // 3. Initialize
    bool initOk = pfnInitialize("\\\\.\\pipe\\TestDraculaAgentPipe");
    assert(initOk);
    std::cout << "  [PASS] DraculaAgentInitialize succeeded\n";

    // 4. Module Enumeration
    char buffer[4096] = {0};
    uint32_t len = pfnEnumModules(buffer, sizeof(buffer));
    assert(len > 0);
    assert(std::string(buffer).find("Dracula") != std::string::npos ||
           std::string(buffer).find(".exe") != std::string::npos ||
           std::string(buffer).find(".dll") != std::string::npos);
    std::cout << "  [PASS] DraculaAgentEnumerateModules returned " << len << " bytes\n";

    // 5. Send Event & Memory Protect Telemetry
    bool evOk = pfnSendEvent("{\"event\":\"TEST_TELEMETRY\",\"val\":42}");
    assert(evOk);
    bool memOk = pfnRecordMemProtect(0x140001000, 4096, 0x20);
    assert(memOk);
    std::cout << "  [PASS] Memory protection telemetry logged successfully\n";

    // 6. Malformed & Null pointer safety
    bool nullEventOk = pfnSendEvent(nullptr);
    assert(!nullEventOk && "Handled null event safely");
    uint32_t nullBufLen = pfnEnumModules(nullptr, 0);
    assert(nullBufLen == 0 && "Handled null buffer safely");
    std::cout << "  [PASS] Malformed input & null pointer bounds handled safely\n";

    // 7. Clean Shutdown & Detach
    pfnShutdown();
    FreeLibrary(hAgent);
    std::cout << "  [PASS] Clean shutdown and DLL detach completed\n";

#else
    std::cout << "  [SKIP] DraculaAgent64 requires Windows host.\n";
#endif

    std::cout << "[Test] DraculaAgent64 Test Suite PASSED!\n";
    return 0;
}
