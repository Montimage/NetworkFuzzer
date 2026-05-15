/*
 * gcov_ctrl.c — LD_PRELOAD helper: reset/dump gcov counters via signals.
 *
 * SIGUSR1 → __gcov_reset()  (zero in-memory edge counters)
 * SIGUSR2 → __gcov_dump()   (flush counters to .gcda files)
 *
 * Build (done by open5gs.sh setup --gcov):
 *   gcc -shared -fPIC -o gcov_ctrl.so gcov_ctrl.c -lgcov
 *
 * Use (done automatically by open5gs.sh start --gcov):
 *   LD_PRELOAD=/path/to/gcov_ctrl.so ./open5gs-nrfd -c nrf.yaml
 *
 * Python side (NfMonitor.gcov_reset / gcov_dump):
 *   os.kill(nf_pid, signal.SIGUSR1)   # reset before request
 *   os.kill(nf_pid, signal.SIGUSR2)   # dump after request, then read .gcda
 */

#define _GNU_SOURCE
#include <signal.h>

/* GCC-internal gcov runtime functions; available when linked with -lgcov */
extern void __gcov_reset(void);
extern void __gcov_dump(void);

static void _handle_reset(int sig __attribute__((unused))) { __gcov_reset(); }
static void _handle_dump (int sig __attribute__((unused))) { __gcov_dump();  }

__attribute__((constructor))
static void _gcov_ctrl_init(void) {
    struct sigaction sa_reset = { .sa_handler = _handle_reset, .sa_flags = SA_RESTART };
    struct sigaction sa_dump  = { .sa_handler = _handle_dump,  .sa_flags = SA_RESTART };
    sigemptyset(&sa_reset.sa_mask);
    sigemptyset(&sa_dump.sa_mask);
    sigaction(SIGUSR1, &sa_reset, NULL);
    sigaction(SIGUSR2, &sa_dump,  NULL);
}
