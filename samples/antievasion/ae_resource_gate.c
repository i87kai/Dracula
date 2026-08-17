/*
 * Benign probe: gates on the reported processor count.
 *
 * Sandboxes are routinely given one or two cores, so "fewer than four
 * processors means I am being analysed" is a widespread heuristic. This program
 * applies it and takes one of two harmless paths.
 *
 *   fewer than 4 processors -> exit(1) immediately          (Baseline: 2)
 *   4 or more processors    -> run the work chain, exit(0)  (Realistic: 8)
 */

#include "ae_common.h"

#define AE_MIN_PROCESSORS 4u

void entry(void) {
    ae_system_info info;
    ae_u32 i;
    for (i = 0; i < sizeof(info); ++i) {
        ((volatile unsigned char*)&info)[i] = 0;
    }

    GetSystemInfo(&info);

    if (info.numberOfProcessors < AE_MIN_PROCESSORS) {
        ae_exit_detected();
    }
    ae_exit_clear(info.numberOfProcessors);
}
