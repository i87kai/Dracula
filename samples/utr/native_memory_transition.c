#include <windows.h>
#include <stdio.h>

// Harmless deterministic x64/x86 stub: returns 42
// x64: B8 2A 00 00 00 C3 (mov eax, 42; ret)
// x86: B8 2A 00 00 00 C3 (mov eax, 42; ret)
static const unsigned char kStubCode[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };

int main() {
    printf("[Fixture] 1. Allocating PAGE_READWRITE memory...\n");
    void* pMem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pMem) {
        printf("VirtualAlloc failed\n");
        return 1;
    }

    printf("[Fixture] 2. Writing deterministic bytecode payload to allocated buffer...\n");
    memcpy(pMem, kStubCode, sizeof(kStubCode));

    printf("[Fixture] 3. Transitioning protection from PAGE_READWRITE to PAGE_EXECUTE_READ...\n");
    DWORD oldProtect = 0;
    if (!VirtualProtect(pMem, 4096, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("VirtualProtect failed\n");
        VirtualFree(pMem, 0, MEM_RELEASE);
        return 1;
    }

    printf("[Fixture] 4. Executing code in newly transitioned region...\n");
    typedef int (*StubFn)();
    StubFn fn = (StubFn)pMem;
    int val = fn();

    printf("[Fixture] 5. Result from dynamic code execution: %d (Expected: 42)\n", val);
    VirtualFree(pMem, 0, MEM_RELEASE);
    return (val == 42) ? 0 : 2;
}
