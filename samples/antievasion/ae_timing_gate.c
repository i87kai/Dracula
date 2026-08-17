/*
 * Benign probe: gates on whether a sleep actually elapsed.
 *
 * A sandbox that fast-forwards or ignores Sleep() leaves the tick count
 * unchanged, which is a classic and very cheap analysis test. This program
 * measures the gap and takes one of two harmless paths.
 *
 *   sleep did not elapse  -> exit(1) immediately          (Baseline: frozen clock)
 *   sleep elapsed         -> run the work chain, exit(0)  (Realistic / AnalysisFriendly)
 */

#include "ae_common.h"

#define AE_SLEEP_MS 5000u
#define AE_MIN_ELAPSED_MS 4000u

void entry(void) {
    ae_u32 before = GetTickCount();
    Sleep(AE_SLEEP_MS);
    ae_u32 after = GetTickCount();
    ae_u32 elapsed = after - before;

    if (elapsed < AE_MIN_ELAPSED_MS) {
        ae_exit_detected();
    }
    ae_exit_clear(elapsed);
}
