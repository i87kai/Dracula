/*
 * Dracula environment probe.
 *
 * This is NOT malware. It has no payload, writes nothing, opens no network
 * connection and changes no system state. Its only job is to read a fixed list
 * of environment properties and print them in a stable, machine-parseable form:
 *
 *     KEY=VALUE
 *
 * That makes it usable as ground truth for Dracula's own sandbox. Run it in the
 * QEMU guest and the printed values are exactly what a real sample would have
 * seen; compare them against the configured EnvironmentProfile and the profile
 * is either proven real or proven to be documentation only.
 *
 * It is safe to run natively, which is the point: there is nothing here that a
 * benign inventory tool does not also do.
 */

#include <windows.h>
#include <stdio.h>
#include <intrin.h>

static void PrintCpuid(void) {
    int regs[4] = {0, 0, 0, 0};
    char vendor[13] = {0};

    __cpuid(regs, 0);
    *(int*)(vendor + 0) = regs[1];
    *(int*)(vendor + 4) = regs[3];
    *(int*)(vendor + 8) = regs[2];
    printf("CPUID_MAX_LEAF=0x%X\n", (unsigned)regs[0]);
    printf("CPU_VENDOR=%s\n", vendor);

    __cpuid(regs, 1);
    printf("CPUID_1_EAX=0x%08X\n", (unsigned)regs[0]);
    printf("CPUID_1_EBX=0x%08X\n", (unsigned)regs[1]);
    printf("CPUID_LOGICAL_PROCESSORS=%u\n", ((unsigned)regs[1] >> 16) & 0xFF);
    printf("HYPERVISOR_BIT=%d\n", ((unsigned)regs[2] & 0x80000000u) ? 1 : 0);

    __cpuid(regs, 0x40000000);
    {
        char hv[13] = {0};
        *(int*)(hv + 0) = regs[1];
        *(int*)(hv + 4) = regs[2];
        *(int*)(hv + 8) = regs[3];
        printf("HYPERVISOR_VENDOR=%s\n", hv[0] ? hv : "(none)");
        printf("HYPERVISOR_MAX_LEAF=0x%08X\n", (unsigned)regs[0]);
    }

    {
        char brand[49] = {0};
        __cpuid((int*)(brand + 0),  0x80000002);
        __cpuid((int*)(brand + 16), 0x80000003);
        __cpuid((int*)(brand + 32), 0x80000004);
        printf("CPU_BRAND=%s\n", brand);
    }
}

static void PrintTopologyAndMemory(void) {
    SYSTEM_INFO si;
    MEMORYSTATUSEX ms;
    ULONGLONG installedKb = 0;

    GetSystemInfo(&si);
    printf("API_PROCESSOR_COUNT=%u\n", (unsigned)si.dwNumberOfProcessors);
    printf("API_PAGE_SIZE=%u\n", (unsigned)si.dwPageSize);

    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        printf("API_TOTAL_PHYS_MB=%llu\n",
               (unsigned long long)(ms.ullTotalPhys / (1024ULL * 1024ULL)));
    }
    if (GetPhysicallyInstalledSystemMemory(&installedKb)) {
        printf("API_INSTALLED_PHYS_MB=%llu\n",
               (unsigned long long)(installedKb / 1024ULL));
    }
}

static void PrintDisk(void) {
    ULARGE_INTEGER freeToCaller, total, freeTotal;
    if (GetDiskFreeSpaceExA("C:\\", &freeToCaller, &total, &freeTotal)) {
        printf("DISK_TOTAL_GB=%llu\n",
               (unsigned long long)(total.QuadPart / (1024ULL * 1024ULL * 1024ULL)));
    }
}

/* 'RSMB' as a four-character code, spelled out so the compiler does not have to
 * interpret a multi-character constant. */
#define DRACULA_FIRMWARE_RSMB 0x52534D42u

static void PrintFirmware(void) {
    /* 'RSMB' = raw SMBIOS table. Reading it is exactly what an inventory tool
     * does; the interesting part is the manufacturer string it contains. */
    DWORD size = GetSystemFirmwareTable(DRACULA_FIRMWARE_RSMB, 0, NULL, 0);
    printf("FIRMWARE_TABLE_BYTES=%u\n", (unsigned)size);
    if (size > 0 && size < (1u << 20)) {
        BYTE* buffer = (BYTE*)malloc(size);
        if (buffer) {
            DWORD got = GetSystemFirmwareTable(DRACULA_FIRMWARE_RSMB, 0, buffer, size);
            DWORD i;
            int found = 0;
            /* Report whether any well-known virtualization vendor string is
             * present in the firmware tables, without dumping the whole blob. */
            static const char* markers[] = {
                "QEMU", "VMware", "VirtualBox", "innotek", "Xen", "Parallels",
                "Microsoft Corporation", "Bochs"
            };
            for (i = 0; i < sizeof(markers) / sizeof(markers[0]); ++i) {
                DWORD j;
                size_t len = strlen(markers[i]);
                for (j = 0; got > len && j < got - len; ++j) {
                    if (memcmp(buffer + j, markers[i], len) == 0) {
                        printf("FIRMWARE_MARKER=%s\n", markers[i]);
                        found = 1;
                        break;
                    }
                }
            }
            if (!found) printf("FIRMWARE_MARKER=(none)\n");
            free(buffer);
        }
    }
}

static void PrintDisplayAndInput(void) {
    LASTINPUTINFO lii;
    printf("SCREEN_WIDTH=%d\n", GetSystemMetrics(SM_CXSCREEN));
    printf("SCREEN_HEIGHT=%d\n", GetSystemMetrics(SM_CYSCREEN));

    lii.cbSize = sizeof(lii);
    if (GetLastInputInfo(&lii)) {
        DWORD now = GetTickCount();
        printf("LAST_INPUT_IDLE_MS=%u\n", (unsigned)(now - lii.dwTime));
    }
}

static void PrintTiming(void) {
    LARGE_INTEGER freq, before, after;
    ULONGLONG tickBefore, tickAfter;
    unsigned __int64 tscBefore, tscAfter;

    QueryPerformanceFrequency(&freq);
    printf("QPC_FREQUENCY=%lld\n", (long long)freq.QuadPart);
    printf("UPTIME_MS=%llu\n", (unsigned long long)GetTickCount64());

    /* Measure one deliberate 500 ms sleep with three independent clocks. On
     * real hardware all three agree. An analysis environment that accelerates
     * sleeps without keeping its clocks consistent shows up right here. */
    QueryPerformanceCounter(&before);
    tickBefore = GetTickCount64();
    tscBefore = __rdtsc();

    Sleep(500);

    tscAfter = __rdtsc();
    tickAfter = GetTickCount64();
    QueryPerformanceCounter(&after);

    printf("SLEEP_REQUESTED_MS=500\n");
    printf("SLEEP_TICKCOUNT_MS=%llu\n", (unsigned long long)(tickAfter - tickBefore));
    printf("SLEEP_QPC_MS=%lld\n",
           freq.QuadPart ? (long long)(((after.QuadPart - before.QuadPart) * 1000) / freq.QuadPart) : -1);
    printf("SLEEP_TSC_DELTA=%llu\n", (unsigned long long)(tscAfter - tscBefore));
}

static void PrintDebuggerState(void) {
    printf("IS_DEBUGGER_PRESENT=%d\n", IsDebuggerPresent() ? 1 : 0);
#if defined(_M_X64) || defined(__x86_64__)
    {
        /* PEB.BeingDebugged, read directly rather than through the API. */
        BYTE* peb = (BYTE*)__readgsqword(0x60);
        printf("PEB_BEING_DEBUGGED=%d\n", peb ? (int)peb[2] : -1);
    }
#endif
}

static void PrintIdentity(void) {
    char name[256];
    DWORD size = sizeof(name);
    if (GetComputerNameA(name, &size)) printf("COMPUTER_NAME=%s\n", name);
    size = sizeof(name);
    if (GetUserNameA(name, &size)) printf("USER_NAME=%s\n", name);
}

int main(void) {
    printf("DRACULA_ENVIRONMENT_PROBE=1\n");
    PrintCpuid();
    PrintTopologyAndMemory();
    PrintDisk();
    PrintFirmware();
    PrintDisplayAndInput();
    PrintTiming();
    PrintDebuggerState();
    PrintIdentity();
    printf("PROBE_COMPLETE=1\n");
    fflush(stdout);
    return 0;
}
