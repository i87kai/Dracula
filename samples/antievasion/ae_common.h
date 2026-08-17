/*
 * Shared scaffolding for Dracula's benign anti-evasion probes.
 *
 * These programs are NOT malware and contain no payload. Each one inspects a
 * single environment property and then takes one of two harmless code paths
 * that differ only in which functions they call and which exit code they
 * return. That makes the difference between the paths observable to Dracula
 * without anything being executed that could affect the host.
 *
 * They are built freestanding (-nostdlib) so that the entry point is the first
 * thing that runs and every call they make is a Win32 import Dracula's HLE
 * layer models. No C runtime startup, no hidden initialisation.
 */

#ifndef AE_COMMON_H
#define AE_COMMON_H

#define WIN32_IMPORT __declspec(dllimport)
#define AE_NOINLINE  __attribute__((noinline))

typedef unsigned int   ae_u32;
typedef unsigned long long ae_u64;

WIN32_IMPORT __attribute__((stdcall)) void  ExitProcess(ae_u32 code);
WIN32_IMPORT __attribute__((stdcall)) void  Sleep(ae_u32 ms);
WIN32_IMPORT __attribute__((stdcall)) ae_u32 GetTickCount(void);
WIN32_IMPORT __attribute__((stdcall)) int   IsDebuggerPresent(void);
WIN32_IMPORT __attribute__((stdcall)) void  GetSystemInfo(void* info);
WIN32_IMPORT __attribute__((stdcall)) int   QueryPerformanceCounter(ae_u64* count);

/* Only the field these probes read; the rest of SYSTEM_INFO is padding. */
typedef struct {
    unsigned char pad[0x20];
    ae_u32        numberOfProcessors;
    unsigned char tail[0x0C];
} ae_system_info;

static inline void ae_cpuid(ae_u32 leaf, ae_u32* a, ae_u32* b, ae_u32* c, ae_u32* d) {
    __asm__ volatile("cpuid"
                     : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                     : "a"(leaf), "c"(0));
}

static inline ae_u64 ae_rdtsc(void) {
    ae_u32 lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((ae_u64)hi << 32) | lo;
}

/* A deliberately branchy, side-effect-free work chain. Reaching it adds
 * distinctly more basic blocks and functions to the coverage of a run, which is
 * exactly what Dracula's differential comparison measures. */
AE_NOINLINE static ae_u32 ae_stage_one(ae_u32 seed)   { return (seed * 1103515245u) + 12345u; }
AE_NOINLINE static ae_u32 ae_stage_two(ae_u32 seed)   { return ae_stage_one(seed) ^ 0xA5A5A5A5u; }
AE_NOINLINE static ae_u32 ae_stage_three(ae_u32 seed) { return ae_stage_two(seed) + (seed >> 3); }
AE_NOINLINE static ae_u32 ae_stage_four(ae_u32 seed)  { return ae_stage_three(seed) * 2654435761u; }

AE_NOINLINE static ae_u32 ae_full_path(ae_u32 seed) {
    ae_u32 acc = seed;
    acc = ae_stage_four(acc);
    if (acc & 1u)  acc = ae_stage_three(acc);
    if (acc & 2u)  acc = ae_stage_two(acc);
    if (acc & 4u)  acc = ae_stage_one(acc);
    if (acc & 8u)  acc ^= 0x5A5A5A5Au;
    return acc;
}

/* The "environment looks like analysis" path: leave immediately, doing nothing.
 * Exit code 1 marks it. */
AE_NOINLINE static void ae_exit_detected(void) {
    ExitProcess(1);
}

/* The "environment looks ordinary" path: run the work chain, then leave with
 * exit code 0. */
AE_NOINLINE static void ae_exit_clear(ae_u32 seed) {
    ae_u32 result = ae_full_path(seed);
    ExitProcess(result == 0xFFFFFFFFu ? 2 : 0);
}

#endif /* AE_COMMON_H */
