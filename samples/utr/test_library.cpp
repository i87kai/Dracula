#include <windows.h>

#define EXPORT __declspec(dllexport)

extern "C" {

    EXPORT int AddNumbers(int a, int b) {
        return a + b;
    }

    EXPORT int GetVersionNumber() {
        return 120; // v1.2.0
    }

    EXPORT int TriggerBenignEvent() {
        DWORD id = GetCurrentProcessId();
        return (int)id;
    }

} // extern "C"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL; (void)fdwReason; (void)lpvReserved;
    return TRUE;
}
