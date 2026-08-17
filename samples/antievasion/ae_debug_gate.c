/*
 * Benign probe: gates on debugger presence.
 *
 * Reads BOTH IsDebuggerPresent and the PEB BeingDebugged byte it is a wrapper
 * for, so Dracula's correlation can show two independent observations of one
 * environment property rather than double-counting them as two techniques.
 *
 *   debugger reported     -> exit(1) immediately
 *   no debugger reported  -> run the work chain, exit(0)
 *
 * Under Dracula's default Bypass anti-debug policy both answers say "no
 * debugger", so this probe is expected to be DETECTED but not to diverge. That
 * is the correct outcome and the sample exists partly to prove the engine does
 * not invent divergence where there is none.
 */

#include "ae_common.h"

AE_NOINLINE static unsigned char ae_peb_being_debugged(void) {
#if defined(__x86_64__)
    unsigned char flag;
    __asm__ volatile(
        "movq %%gs:0x60, %%rax\n\t"
        "movb 0x02(%%rax), %0\n\t"
        : "=r"(flag)
        :
        : "rax");
    return flag;
#else
    return 0;
#endif
}

void entry(void) {
    int viaApi = IsDebuggerPresent();
    unsigned char viaPeb = ae_peb_being_debugged();

    if (viaApi != 0) {
        ae_exit_detected();
    }
    if (viaPeb != 0) {
        ae_exit_detected();
    }
    ae_exit_clear((ae_u32)viaApi + viaPeb);
}
