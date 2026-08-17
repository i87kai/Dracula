/*
 * Benign probe: three independent environment gates in sequence.
 *
 *   1. CPUID hypervisor-present bit
 *   2. processor count
 *   3. debugger presence
 *
 * Every gate exits early on its own, so the work chain is only reached when all
 * three say the environment looks ordinary. Used to verify that Dracula reports
 * three separate underlying techniques plus one overall environment-sensitive
 * conclusion, without double-counting the same evidence.
 */

#include "ae_common.h"

AE_NOINLINE static int ae_gate_hypervisor(void) {
    ae_u32 a = 0, b = 0, c = 0, d = 0;
    ae_cpuid(1, &a, &b, &c, &d);
    return (c & 0x80000000u) ? 1 : 0;
}

AE_NOINLINE static int ae_gate_processors(void) {
    ae_system_info info;
    ae_u32 i;
    for (i = 0; i < sizeof(info); ++i) {
        ((volatile unsigned char*)&info)[i] = 0;
    }
    GetSystemInfo(&info);
    return (info.numberOfProcessors < 4u) ? 1 : 0;
}

AE_NOINLINE static int ae_gate_debugger(void) {
    return IsDebuggerPresent() ? 1 : 0;
}

void entry(void) {
    if (ae_gate_hypervisor()) {
        ae_exit_detected();
    }
    if (ae_gate_processors()) {
        ae_exit_detected();
    }
    if (ae_gate_debugger()) {
        ae_exit_detected();
    }
    ae_exit_clear(0x1234u);
}
