/*
 * gcov_ctrl.c — LD_PRELOAD helper: reset/dump gcov counters via signals,
 *               and flush coverage on crash so a dying NF does not lose its
 *               counters (the "gcov-on-crash undercount").
 *
 * SIGUSR1 → __gcov_reset()  (zero in-memory edge counters)
 * SIGUSR2 → __gcov_dump()   (flush counters to .gcda files)
 *
 * Crash flush:
 *   gcc only writes .gcda on normal exit (atexit __gcov_dump). A process that
 *   dies on SIGSEGV/SIGABRT/etc. never runs atexit, so every edge executed
 *   since the last graceful dump is lost. open5gs additionally consumes
 *   SIGUSR1/SIGUSR2 in its own signal thread, so the signal-driven dump above
 *   often never fires either. To make crash coverage reliable we install a
 *   fatal-signal handler that calls __gcov_dump() and then chains to whatever
 *   handler open5gs installed (preserving its backtrace + core dump). Because
 *   open5gs registers its handlers in main() — after this constructor — we also
 *   interpose sigaction() so that when the app installs a fatal-signal handler
 *   we transparently wrap it instead of letting it overwrite ours.
 *
 * Build (done by open5gs.sh setup --gcov):
 *   gcc -shared -fPIC -o gcov_ctrl.so gcov_ctrl.c -ldl -lgcov
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
#include <dlfcn.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

/* GCC-internal gcov runtime functions; available when linked with -lgcov */
extern void __gcov_reset(void);
extern void __gcov_dump(void);

static void _handle_reset(int sig __attribute__((unused))) { __gcov_reset(); }
static void _handle_dump (int sig __attribute__((unused))) { __gcov_dump();  }

/* ── crash-flush ──────────────────────────────────────────────────────────
 * Fatal signals after which the process will die. On each we flush coverage,
 * then chain to the handler the app had installed (or the default action) so
 * the crash still behaves exactly as it would without this preload.
 */
static const int _fatal_sigs[] = { SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGTRAP };
#define N_FATAL ((int)(sizeof(_fatal_sigs) / sizeof(_fatal_sigs[0])))

/* The app's previously-installed disposition for each fatal signal. */
static struct sigaction _prev_fatal[N_FATAL];

/* Real libc sigaction, resolved lazily so our interposer can delegate to it. */
static int (*_real_sigaction)(int, const struct sigaction *, struct sigaction *) = NULL;

static int _fatal_idx(int sig) {
    for (int i = 0; i < N_FATAL; i++)
        if (_fatal_sigs[i] == sig) return i;
    return -1;
}

static void _resolve_real_sigaction(void) {
    if (!_real_sigaction)
        _real_sigaction = (int (*)(int, const struct sigaction *, struct sigaction *))
            dlsym(RTLD_NEXT, "sigaction");
}

/* Re-entrancy guard: if our own flush path faults again, don't loop. */
static volatile sig_atomic_t _in_fatal = 0;

/* Chain to whatever the app installed (or the default action), preserving the
 * crash's normal behaviour — backtrace + core dump. Used when crash-flush is
 * disabled, and as the fallback when we re-enter. */
static void _chain_to_prev(int sig, siginfo_t *info, void *ctx) {
    int idx = _fatal_idx(sig);
    struct sigaction *prev = (idx >= 0) ? &_prev_fatal[idx] : NULL;
    if (prev) {
        if ((prev->sa_flags & SA_SIGINFO) && prev->sa_sigaction) {
            prev->sa_sigaction(sig, info, ctx);
            return;
        }
        if (prev->sa_handler == SIG_IGN) return;
        if (prev->sa_handler && prev->sa_handler != SIG_DFL) {
            prev->sa_handler(sig);
            return;
        }
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

/* Last-resort watchdog: if the gcov dump / exit() path wedges (e.g. the crash
 * happened while holding an allocator lock that the dump then needs), SIGALRM
 * forces immediate termination so the process still disappears and the harness
 * detects the crash and restarts. */
static void _force_exit(int sig __attribute__((unused))) { _exit(99); }

static void _handle_fatal(int sig, siginfo_t *info, void *ctx) {
    if (_in_fatal) {            /* faulted again inside the flush — bail hard */
        signal(sig, SIG_DFL);
        raise(sig);
        return;
    }
    _in_fatal = 1;

    /* GCOV_CRASH_FLUSH=0 disables coverage flushing on crash (preserves the
     * core dump + app backtrace for triage runs). Default: flush. */
    const char *off = getenv("GCOV_CRASH_FLUSH");
    if (off && off[0] == '0') {
        _chain_to_prev(sig, info, ctx);
        return;
    }

    /* The instrumented binary keeps its own static libgcov runtime and does NOT
     * export __gcov_dump, so we cannot call its dump directly (our preload's
     * __gcov_dump sees an empty runtime). exit() runs the binary's own gcov
     * destructor/atexit, which dumps+merges its .gcda. Arm a watchdog first so a
     * wedged dump can't hang the process. */
    signal(SIGALRM, _force_exit);
    alarm(5);
    exit(128 + sig);
}

/* Install our fatal handler for one signal, remembering the prior disposition. */
static void _install_fatal(int sig) {
    int idx = _fatal_idx(sig);
    if (idx < 0) return;
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sa.sa_sigaction = _handle_fatal;
    _resolve_real_sigaction();
    if (_real_sigaction)
        _real_sigaction(sig, &sa, &_prev_fatal[idx]);
}

/* Interpose sigaction(): when the app (open5gs) installs a fatal-signal
 * handler, record it as the chain target and keep ours frontmost instead. */
int sigaction(int sig, const struct sigaction *act, struct sigaction *oldact) {
    _resolve_real_sigaction();
    int idx = _fatal_idx(sig);
    if (idx >= 0 && act) {
        /* Hand the caller back what *they* think is installed (their own prior),
         * but actually keep _handle_fatal frontmost and record their new handler
         * as the chain target. */
        struct sigaction prev = _prev_fatal[idx];
        _prev_fatal[idx] = *act;
        struct sigaction ours = *act;
        ours.sa_flags |= SA_SIGINFO;
        ours.sa_sigaction = _handle_fatal;
        int rc = _real_sigaction ? _real_sigaction(sig, &ours, NULL) : -1;
        if (oldact) *oldact = prev;
        return rc;
    }
    return _real_sigaction ? _real_sigaction(sig, act, oldact) : -1;
}

__attribute__((constructor))
static void _gcov_ctrl_init(void) {
    struct sigaction sa_reset = { .sa_handler = _handle_reset, .sa_flags = SA_RESTART };
    struct sigaction sa_dump  = { .sa_handler = _handle_dump,  .sa_flags = SA_RESTART };
    sigemptyset(&sa_reset.sa_mask);
    sigemptyset(&sa_dump.sa_mask);
    _resolve_real_sigaction();
    if (_real_sigaction) {
        _real_sigaction(SIGUSR1, &sa_reset, NULL);
        _real_sigaction(SIGUSR2, &sa_dump,  NULL);
    }

    /* Seed prior dispositions to SIG_DFL, then install our crash-flush handlers.
     * If open5gs later installs its own, our interposed sigaction() wraps them. */
    for (int i = 0; i < N_FATAL; i++) {
        _prev_fatal[i].sa_handler = SIG_DFL;
        _prev_fatal[i].sa_flags = 0;
        sigemptyset(&_prev_fatal[i].sa_mask);
    }
    for (int i = 0; i < N_FATAL; i++)
        _install_fatal(_fatal_sigs[i]);
}
