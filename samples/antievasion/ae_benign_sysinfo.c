/*
 * Benign probe: the false-positive control.
 *
 * This program queries exactly the same environment properties as the gate
 * probes -- CPUID, processor count, the performance counter, the tick count --
 * and then does nothing with the answers except fold them into an arithmetic
 * result. No comparison, no branch, no early exit: the values are collected,
 * never acted on.
 *
 * This is what an ordinary inventory tool, installer or benchmark looks like.
 * Dracula must NOT report high-confidence anti-VM behaviour here, and must NOT
 * report any behavioural divergence between profiles, because there is none.
 */

#include "ae_common.h"

void entry(void) {
    ae_u32 a = 0, b = 0, c = 0, d = 0;
    ae_u64 counter = 0;
    ae_system_info info;
    ae_u32 i;
    ae_u32 accumulator = 0;

    for (i = 0; i < sizeof(info); ++i) {
        ((volatile unsigned char*)&info)[i] = 0;
    }

    ae_cpuid(0, &a, &b, &c, &d);
    accumulator += a + b + c + d;

    ae_cpuid(1, &a, &b, &c, &d);
    accumulator += a + b + c + d;

    GetSystemInfo(&info);
    accumulator += info.numberOfProcessors;

    QueryPerformanceCounter(&counter);
    accumulator += (ae_u32)counter;

    accumulator += GetTickCount();
    accumulator += (ae_u32)ae_rdtsc();

    /* Fold the collected values into a result. Nothing branches on them. */
    accumulator = ae_full_path(accumulator);

    ExitProcess(accumulator & 0u);
}
