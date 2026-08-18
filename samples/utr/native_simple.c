#include <windows.h>
#include <stdio.h>

int ComputeValue(int a, int b) {
    return (a * 3) + (b * 7) + 42;
}

int main() {
    DWORD pid = GetCurrentProcessId();
    DWORD ticks = GetTickCount();
    int result = ComputeValue((int)pid, (int)ticks);
    printf("Native Simple Fixture (PID=%lu, Ticks=%lu, Val=%d)\n", pid, ticks, result);
    return 0;
}
