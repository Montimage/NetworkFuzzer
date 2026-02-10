/*
 * coverage_handler.c — LD_PRELOAD helper for gcov coverage flush via SIGUSR1.
 *
 * This solves the ASAN + gcov conflict: GDB cannot call __gcov_dump() in an
 * ASAN-instrumented process, but a signal handler can.
 *
 * Build (on the remote server where DCMTK is compiled with --coverage):
 *   gcc -shared -fPIC -o coverage_handler.so coverage_handler.c
 *
 * Usage:
 *   LD_PRELOAD=./coverage_handler.so ./storescp 4242
 *   # Then from fuzzer: kill -SIGUSR1 $(pidof storescp)
 *   # .gcda files are written + counters reset for next interval
 *
 * DCMTK must be compiled with --coverage:
 *   cmake .. -DCMAKE_C_FLAGS="--coverage -fsanitize=address -fno-omit-frame-pointer -g -O1" \
 *            -DCMAKE_CXX_FLAGS="--coverage -fsanitize=address -fno-omit-frame-pointer -g -O1" \
 *            -DCMAKE_EXE_LINKER_FLAGS="--coverage -fsanitize=address" \
 *            -DBUILD_SHARED_LIBS=OFF
 */
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

/* GCC 11+: __gcov_dump() + __gcov_reset()
 * GCC < 11: __gcov_flush() (dump + reset combined, deprecated)
 * These symbols are provided by the gcov runtime when compiled with --coverage.
 */
extern void __gcov_dump(void) __attribute__((weak));
extern void __gcov_reset(void) __attribute__((weak));
extern void __gcov_flush(void) __attribute__((weak));

static volatile sig_atomic_t dump_requested = 0;

static void sigusr1_handler(int sig) {
    (void)sig;
    dump_requested = 1;
}

/* Periodic check from a safe context (not signal handler).
 * For simplicity, we call directly from the signal handler since
 * storescp is mostly idle when receiving SIGUSR1 between requests.
 * In practice this works reliably for single-threaded/low-contention servers.
 */
static void do_coverage_dump(int sig) {
    (void)sig;
    if (__gcov_dump) {
        __gcov_dump();
        if (__gcov_reset) {
            __gcov_reset();
        }
        /* Write a marker so the fuzzer knows the dump completed */
        FILE *f = fopen("/tmp/.gcov_dumped", "w");
        if (f) {
            fprintf(f, "1\n");
            fclose(f);
        }
    } else if (__gcov_flush) {
        /* Fallback for older GCC */
        __gcov_flush();
        FILE *f = fopen("/tmp/.gcov_dumped", "w");
        if (f) {
            fprintf(f, "1\n");
            fclose(f);
        }
    }
}

__attribute__((constructor))
static void install_coverage_handler(void) {
    struct sigaction sa;
    sa.sa_handler = do_coverage_dump;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;  /* Don't interrupt blocking syscalls */
    sigaction(SIGUSR1, &sa, NULL);

    if (__gcov_dump || __gcov_flush) {
        fprintf(stderr, "[coverage_handler] SIGUSR1 handler installed "
                "(gcov_dump=%s, gcov_flush=%s)\n",
                __gcov_dump ? "yes" : "no",
                __gcov_flush ? "yes" : "no");
    } else {
        fprintf(stderr, "[coverage_handler] WARNING: no gcov symbols found. "
                "Was the target compiled with --coverage?\n");
    }
}
