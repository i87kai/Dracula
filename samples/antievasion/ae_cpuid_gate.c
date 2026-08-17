/*
 * Benign probe: gates on the CPUID hypervisor-present bit.
 *
 * CPUID leaf 1, ECX bit 31 is set by every mainstream hypervisor. This program
 * reads it and takes one of two harmless paths. Nothing else happens.
 *
 *   hypervisor bit set    -> exit(1) immediately          (Baseline)
 *   hypervisor bit clear  -> run the work chain, exit(0)  (AnalysisFriendly)
 */

#include "ae_common.h"

void entry(void) {
    ae_u32 a = 0, b = 0, c = 0, d = 0;
    ae_cpuid(1, &a, &b, &c, &d);

    if (c & 0x80000000u) {
        ae_exit_detected();
    }
    ae_exit_clear(a ^ b);
}
