/* ---------------------------------------------------------------------------
 * tests/integration/asan_coverage_probe.c -- PROVE the ASan error classes this
 * project claims to cover are actually being watched.
 *
 * WHY THIS FILE EXISTS, and it is the SAME argument as lsan_probe.c's, one level up.
 * lsan_probe.c proves LeakSanitizer is live: it leaks on purpose and fails unless
 * LSan says so. This file proves the ADDRESS sanitizer's error classes are live,
 * because `scripts/gate-linux-cell.sh` reports a count of AddressSanitizer findings
 * and a count of zero is only a statement about what was being watched. It was not
 * watching one of them.
 *
 * THE MEASUREMENT THAT PROMPTED IT, taken on the machine this was written on and
 * reproduced in the project's own container, over the four classes below. "silent"
 * means the child printed no ASan report at all and exited 0 -- the defect went
 * completely unremarked, which is worse than a false positive:
 *
 *   toolchain                                   default    with the option
 *   ----------------------------------------   --------   ----------------
 *   debian bookworm gcc 12.2.0 (the container)  false      REPORTED
 *   gcc 16.2.1 linux (cachyos-x8664)            true       REPORTED
 *   clang 22.1.8 linux (cachyos-x8664)          true       REPORTED
 *   gcc 16.2.0 macos (this machine)             false      REPORTED
 *   Apple clang 21.0.0 macos (this machine)     false      -
 *
 *   class                       gcc 12.2.0 container, ASAN_OPTIONS=detect_leaks=1
 *   -------------------------   ---------------------------------------------
 *   heap-use-after-free         REPORTED
 *   stack-use-after-scope       REPORTED
 *   heap-buffer-overflow        REPORTED
 *   stack-use-after-return      SILENT -- read back 7 and exited 0
 *
 * `stack-use-after-return` is the class that found this project's real
 * `nf_free()` registry defect, and it is a RUNTIME option whose default differs
 * between four of the five toolchains above. A cell whose coverage is a function
 * of its toolchain's default is not asserting its coverage; it is reporting
 * whatever the default happened to be. So the cell passes the option explicitly
 * (scripts/gate-linux-cell.sh) and this file is what proves the option took.
 *
 * WHY THE PROBE INHERITS ASAN_OPTIONS INSTEAD OF SETTING IT. That is the whole
 * design and it is what gives the file its teeth. A probe that supplied
 * `detect_stack_use_after_return=1` itself would be green in a cell that had
 * dropped it, which is a decorative check wearing a probe's clothes. So the child
 * runs under the CALLER's options, verbatim, plus two REPORTING controls this file
 * owns and no detection control at all:
 *
 *   exitcode=23      so a reported finding can be distinguished from a report that
 *                    was printed and did not fail the run -- a check that cannot
 *                    fail is not a check;
 *   abort_on_error=0 so the child EXITS with that code instead of raising SIGABRT.
 *                    ASan's abort_on_error default is platform-dependent (measured:
 *                    1 on both macOS compilers, 0 on linux), and without this the
 *                    exit-code half of the assertion would only work on one of them.
 *
 * The only options this file appends are therefore ones that change how a finding
 * is REPORTED, never whether it is FOUND. If a class is not watched, this probe is
 * red and says which class and which option is missing.
 *
 * ONE PROCESS PER CLASS, because ASan dies on the first error it reports. A single
 * process could provoke one and then say nothing about the other three, so each case
 * is a re-exec of this binary told apart by an environment variable -- the same
 * parent/child arrangement as lsan_probe.c, for the same reason: the report arrives
 * at process exit, so the assertion has to happen in a different process from the
 * one that provokes it.
 *
 * IT IS OPT-IN AND OFF BY DEFAULT, built only under -DIRC_LSAN_PROBE=ON, exactly
 * like lsan_probe. It is NOT registered as a CTest test, and that asymmetry with
 * lsan_probe.c is deliberate: ctest cannot tell "this toolchain is not watching
 * stack-use-after-return" from "the suite found a real memory error", and a red
 * suite line that means the second thing when it means the first is the misleading
 * report this project keeps finding. So `scripts/gate-linux-cell.sh` runs this
 * binary DIRECTLY, with the same ASAN_OPTIONS it gives ctest, and prints one
 * COVER line per class. The exit status is still non-zero when any class is
 * unproved, so the cell fails; it just fails with a sentence that says why.
 *
 * THE COST, which is real and is paid only when the option is on: one extra
 * executable, and four short-lived child processes per run. Each child provokes
 * exactly one deliberate error and is killed by the sanitizer while doing it. The
 * heap-buffer-overflow case allocates 8 bytes and never frees them -- which is
 * sound only because ASan aborts on the overflow before main() returns, so there is
 * no path on which LSan's atexit handler sees them.
 * --------------------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* The child is told which class to provoke by this variable, not by argv, so the
 * parent's own argv[0] stays the only thing it has to know about its own path. */
#define PROBE_ENV "IRC_ASAN_COVERAGE_CASE"

/* The exit code the parent requires. 23 rather than ASan's default 1 so that a
 * child which dies for an unrelated reason -- a crash, a bad exec -- is
 * distinguishable from one the sanitizer stopped. Same number lsan_probe.c uses,
 * and the same reason: these two probes answer different questions about one
 * runtime and a shared magic number would make their reports ambiguous together. */
#define PROBE_EXIT 23

/* 8 KiB of child stderr. An ASan report for a one-line case is a few hundred
 * bytes plus a shared-library trace; the cap only exists so a pathological child
 * cannot run the parent out of stack. */
#define PROBE_OUT_CAP 8192

/* ---------------------------------------------------------------------------
 * THE FOUR CASES. Each provokes exactly one ASan error class and nothing else,
 * because a case that provoked two would satisfy an assertion about the first by
 * way of the second.
 * --------------------------------------------------------------------------- */

/* heap-use-after-free. The pointer is read back through a FILE-SCOPE global and the
 * free happens inside a noinline helper, both because that is the shape the
 * compiler cannot fold away and both because of a MEASUREMENT: written as
 *
 *     char *p = malloc(8); free(p); fprintf(stderr, "%d", p[0]);
 *
 * it does not even build in this tree. gcc 12 reports -Wuse-after-free, and this
 * tree builds with -Werror, so the obvious spelling of the simplest class in the
 * file is a compile error here. Routing the free through a helper is what puts the
 * access and the free out of each other's reach, for the compiler and for us. */
static char *g_freed_block;

__attribute__((noinline))
static void release_block(void *p)
{
    free(p);
}

/* stack-use-after-scope. The address of a local leaves its scope, and the read
 * happens after it. `keep()` is noinline so the block's lifetime cannot be extended
 * back over the read: with it inlined, the compiler is free to conclude the two are
 * the same moment and there is nothing to report. */
__attribute__((noinline))
static int *keep_address(int *p)
{
    return p;
}

/* stack-use-after-return. The address of a local is stored by a function that then
 * RETURNS, so the frame is gone before the read. This is a different assertion from
 * the scope case above and it is the one that matters: it is the class whose ASan
 * runtime option is off by default in three of the five toolchains measured in this
 * file's header, and the class that found this project's real nf_free() defect.
 *
 * It is an out-parameter and a file-scope global rather than `return &local`,
 * because -Wreturn-local-addr fires on the direct form and gcc 12 then compiles the
 * return value to a LITERAL NULL at -O2 -- measured, not assumed. The probe then
 * provoked a SEGV on the zero page instead of the class it exists to prove, and a
 * probe that reports the wrong class is worse than no probe, because it is green. */
static int *g_returned_block;

__attribute__((noinline))
static void stash_address(void)
{
    int local = 7;

    g_returned_block = &local;
}

/* ---------------------------------------------------------------------------
 * The class table. `expect` is the string AddressSanitizer prints for the class
 * (`ERROR: AddressSanitizer: <expect>`); `needs` names the runtime option the class
 * depends on, and is printed ONLY when that class is unproved -- so the failure
 * sentence tells the reader what to set rather than only that something is wrong.
 * --------------------------------------------------------------------------- */
struct asan_class {
    const char *expect;
    const char *needs;
    void (*run)(void);
};

static void provoke_heap_use_after_free(void)
{
    char *block = (char *)malloc(8);

    if (block == NULL) {
        fprintf(stderr, "asan_coverage_probe: malloc(8) failed\n");
        return;
    }
    g_freed_block = block;
    release_block(block);
    /* The read. If this line does not execute, nothing below runs either. */
    fprintf(stderr, "asan_coverage_probe: uaf read %d\n", g_freed_block[0]);
}

static void provoke_stack_use_after_scope(void)
{
    int *escaped;

    {
        int local = 7;

        escaped = keep_address(&local);
    }
    fprintf(stderr, "asan_coverage_probe: sas read %d\n", *escaped);
}

static void provoke_stack_use_after_return(void)
{
    stash_address();
    fprintf(stderr, "asan_coverage_probe: uar read %d\n", *g_returned_block);
}

static void provoke_heap_buffer_overflow(void)
{
    /* `volatile` on the size, so the compiler cannot prove the bound and turn this
     * into a -Wstringop-overflow error -- which it does, measured, without it, and
     * this tree builds with -Werror. The cost is one byte at runtime and one
     * obscured store in the report's source line; both are cheaper than the probe
     * not existing. */
    volatile size_t size = 8;
    char *block = (char *)malloc(size);

    if (block == NULL) {
        fprintf(stderr, "asan_coverage_probe: malloc(8) failed\n");
        return;
    }
    /* One byte past the end. ASan reports the WRITE, which is where the redzone is
     * entered, and exits before main() returns -- so `block` is never freed and
     * never reaches a leak check. */
    block[size] = 1;
    fprintf(stderr, "asan_coverage_probe: hbo read %d\n", block[size]);
}

static const struct asan_class CLASSES[] = {
    { "heap-use-after-free", "none beyond -fsanitize=address", &provoke_heap_use_after_free },
    { "stack-use-after-scope", "none beyond -fsanitize-address-use-after-scope",
      &provoke_stack_use_after_scope },
    { "heap-buffer-overflow", "none beyond -fsanitize=address", &provoke_heap_buffer_overflow },
    { "stack-use-after-return", "ASAN_OPTIONS=detect_stack_use_after_return=1",
      &provoke_stack_use_after_return },
};

#define N_CLASSES ((int)(sizeof CLASSES / sizeof CLASSES[0]))

/* ---------------------------------------------------------------------------
 * Run one class in a child and answer two questions: did the sanitizer name the
 * class, and did it fail the run.
 *
 * The fork-then-dup2 order is load-bearing and is the same one lsan_probe.c's
 * comment explains at length: redirecting the PARENT's fd 2 into the pipe before
 * forking leaves the parent holding the write end, so the read below never sees EOF
 * and blocks until ctest's timeout kills it. The redirection belongs in the child,
 * between fork and exec, where the child never returns.
 * --------------------------------------------------------------------------- */
static int run_case(const char *exe, char **argv, const char *casename,
                    char *out, size_t outcap)
{
    int errpipe[2];
    pid_t pid;
    int status = 0;
    size_t used = 0u;

    out[0] = '\0';
    if (pipe(errpipe) != 0) {
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        (void)close(errpipe[0]);
        (void)close(errpipe[1]);
        return -1;
    }
    if (pid == 0) {
        /* The child. ASAN_OPTIONS is INHERITED -- see the header for why this file
         * does not set the detection option itself -- with the two reporting
         * controls appended. */
        const char *inherited = getenv("ASAN_OPTIONS");
        char opts[1024];

        if (dup2(errpipe[1], STDERR_FILENO) < 0) {
            _exit(127);
        }
        (void)close(errpipe[0]);
        (void)close(errpipe[1]);
        if (inherited != NULL && inherited[0] != '\0') {
            (void)snprintf(opts, sizeof opts, "%s:exitcode=%d:abort_on_error=0",
                           inherited, PROBE_EXIT);
        } else {
            (void)snprintf(opts, sizeof opts, "exitcode=%d:abort_on_error=0",
                           PROBE_EXIT);
        }
        (void)setenv("ASAN_OPTIONS", opts, 1);
        (void)setenv(PROBE_ENV, casename, 1);
        (void)execv(exe, argv);
        fprintf(stderr, "asan_coverage_probe: execv(%s) failed\n", exe);
        _exit(127);
    }

    (void)close(errpipe[1]);
    (void)waitpid(pid, &status, 0);
    for (;;) {
        ssize_t n = read(errpipe[0], out + used, outcap - 1u - used);

        if (n > 0) {
            used += (size_t)n;
            if (used >= outcap - 1u) {
                used = outcap - 2u;
                break;
            }
            continue;
        }
        break;
    }
    out[used] = '\0';
    (void)close(errpipe[0]);

    if (!WIFEXITED(status)) {
        return -1;
    }
    return WEXITSTATUS(status);
}

int main(int argc, char **argv)
{
    char out[PROBE_OUT_CAP];
    char exe[4096];
    const char *wanted = getenv(PROBE_ENV);
    int proved = 0;
    int i;

    (void)argc;

    if (wanted != NULL) {
        for (i = 0; i < N_CLASSES; i++) {
            if (strcmp(wanted, CLASSES[i].expect) == 0) {
                CLASSES[i].run();
                return 0;
            }
        }
        fprintf(stderr, "asan_coverage_probe: unknown case '%s'\n", wanted);
        return 2;
    }

    (void)snprintf(exe, sizeof exe, "%s", argv[0]);

    printf("asan_coverage_probe: caller ASAN_OPTIONS=%s\n",
           getenv("ASAN_OPTIONS") ? getenv("ASAN_OPTIONS") : "(unset)");
    printf("asan_coverage_probe: %d ASan error classes, one deliberate finding each\n",
           N_CLASSES);

    for (i = 0; i < N_CLASSES; i++) {
        const char *want = CLASSES[i].expect;
        char needle[128];
        int rc;

        fflush(stdout);
        rc = run_case(exe, argv, want, out, sizeof out);
        (void)snprintf(needle, sizeof needle, "ERROR: AddressSanitizer: %s", want);

        if (rc < 0) {
            /* The child died without a normal exit, so there is no report to read.
             * Printed in full because this is the sentence a person debugging an
             * unproved class will be reading. */
            printf("COVER %s NOT-COVERED (the child did not exit normally; "
                   "its output follows)\n", want);
            printf("    --- child output ---\n%s    --- end ---\n", out);
            continue;
        }
        if (strstr(out, needle) == NULL) {
            /* WHICH of the two failures this is, because the remedies are different
             * and a message that cannot tell them apart sends the reader to the wrong
             * one. The child prints its own marker line just before the offending
             * access, so its presence proves the case executed and the RUNTIME chose
             * to say nothing -- which is a coverage gap and is reported with the
             * option that closes it. Its absence means the child died before it got
             * there, which is not a coverage statement at all. */
            if (strstr(out, "asan_coverage_probe:") != NULL) {
                printf("COVER %s NOT-COVERED (the case ran and AddressSanitizer "
                       "reported nothing for it: this class is not being watched "
                       "under these options, and it needs %s)\n", want,
                       CLASSES[i].needs);
            } else {
                printf("COVER %s NOT-COVERED (the child produced no output at all, "
                       "so there is nothing to judge: it did not run, or it was "
                       "killed before reaching the deliberate access)\n", want);
            }
            printf("    --- child output ---\n%s    --- end ---\n", out);
            continue;
        }
        if (rc != PROBE_EXIT) {
            printf("COVER %s NOT-COVERED (the class WAS reported but the child "
                   "exited %d, not %d: a report that does not fail the run is not "
                   "a check)\n", want, rc, PROBE_EXIT);
            printf("    --- child output ---\n%s    --- end ---\n", out);
            continue;
        }
        proved++;
        printf("COVER %s PROVED\n", want);
    }

    printf("asan_coverage_probe: %d of %d ASan error classes proved live under this "
           "toolchain and these options\n", proved, N_CLASSES);
    if (proved == 0) {
        /* The one case where the answer is about the BINARY rather than about a
         * class, and it is worth saying outright: no class at all is a build that
         * was not instrumented, and that is a different problem from a missing
         * runtime option. */
        printf("asan_coverage_probe: FAILED -- not one class was reported, which "
               "says this binary carries no working AddressSanitizer at all "
               "(-DIRC_SANITIZE=ON builds it, and ASan must be linked into every "
               "executable that uses it).\n");
        return 1;
    }
    if (proved != N_CLASSES) {
        printf("asan_coverage_probe: FAILED -- a count of 0 findings from a cell "
               "that was not watching %d of these classes is not a result.\n",
               N_CLASSES - proved);
        return 1;
    }
    return 0;
}
