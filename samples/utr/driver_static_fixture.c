// Driver static test fixture
// Simulates PE headers, entry point, and kernel import structure for static analysis

#include <windows.h>

// Mock kernel driver entry point
int DriverEntry(void* DriverObject, void* RegistryPath) {
    (void)DriverObject; (void)RegistryPath;
    return 0; // STATUS_SUCCESS
}

int main() {
    return DriverEntry(NULL, NULL);
}
