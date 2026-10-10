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
 * RETURNS, so the frame is gone before the dereference in the caller. This is a
 * different assertion from the scope case below and it is the one that matters: it is
 * the class whose ASan runtime option is off by default in three of the five
 * toolchains measured in this file's header, and the class that found this project's
 * real nf_free() defect.
 *
 * AN OUT-PARAMETER, not a file-scope global, and the shape matches keep_address()
 * below for two reasons. One is measured: `return &local` trips -Wreturn-local-addr
 * and gcc 12 then folds the returned value to a LITERAL NULL at -O2, so the case
 * reports a SEGV on the zero page instead of the class it exists to prove -- and a
 * probe that reports the wrong class is worse than no probe, because it is green. The
 * other is that the escape then sits in the same place as the scope case's, at a
 * store, which is where this rule's suppression is known to bind -- see THE CODEQL
 * SUPPRESSIONS IN THIS FILE above.
 *
 * NO_DANGLING_POINTER IS LOAD-BEARING AND NOT COSMETIC. Storing the address of a local
 * that is about to die is EXACTLY what this case must do, and it is exactly what gcc's
 * -Wdangling-pointer reports.
 *
 * THE MEASUREMENT THAT FORCED THIS BLOCK, taken 2026-10-10 on this machine by building
 * THIS FILE with -Wall -Wextra -Werror -Wpedantic -std=c11 under each of the three
 * compilers the gate uses, and it is why the block is a pragma rather than the
 * attribute the earlier version of this comment described:
 *
 *   compiler                          __has_attribute(no_dangling_pointer)
 *   --------------------------------  --------------------------------------
 *   gcc 16.2.0 (Homebrew, this box)   false   -> the macro expanded to NOTHING
 *   clang 23.1.2 (Homebrew, this box) false   -> the macro expanded to NOTHING
 *   Apple clang 21.0.0 (this box)     false   -> the macro expanded to NOTHING
 *
 * So on every compiler this project builds the probes with, the attribute suppressed
 * nothing at all, because it was never emitted. The store below was therefore
 * UNGUARDED under all three -- and gcc 16.2 rejects it outright:
 *
 *   asan_coverage_probe.c:180:10: error: storing the address of local variable
 *   'local' in '*out' [-Werror=dangling-pointer=]
 *
 * That is not a hypothetical: it is the state this file was in, and it survived every
 * gate run and every CI run because no configuration in this project ever compiled it.
 * The reason is in CMakeLists.txt's IRC_LSAN_PROBE comment and it is the same reason
 * this pragma block had to be written at all: an opt-in file that nothing builds is
 * not tested code, it is text. .github/workflows/ci.yml now builds both opt-in probes
 * on every push and pull request under gcc, upstream clang and Apple clang, which is
 * the only reason this defect is a commit instead of a finding nobody made.
 *
 * WHY A PRAGMA AND NOT THE ATTRIBUTE. `__has_attribute(no_dangling_pointer)` is false
 * on gcc 16.2 even though gcc HAS a -Wdangling-pointer diagnostic, so the attribute
 * cannot be the guard: it is not a spelling gcc 16 accepts. The pragma is.
 *
 * WHY __GNUC__ >= 15 AND NOT A __has_warning() PROBE. Measured, `__has_warning` is
 * also false on gcc 16.2 for this option: GCC only answers for a fixed list of its own
 * spellings, so asking it "do you have -Wdangling-pointer?" gets "no" from the one
 * compiler that does. The version test is the question that is actually answerable at
 * preprocessing time. GCC 15 is the boundary because that is where -Wdangling-pointer
 * was broadened to fire on a store through a non-attributed out-parameter -- which is
 * the shape of `*out = &local` below -- and it is a boundary read off GCC's changelog
 * rather than measured here, because this project has no gcc 15. The cost of the
 * boundary being one version late is that gcc 13 and 14, if they also fire here, would
 * need the guard lowered; the cost of it being one version early is a #pragma naming a
 * warning option those compilers do have.
 *
 * WHY THE CONTAINER'S gcc IS EXCLUDED RATHER THAN SUPPRESSED. gcc 12.2.0 -- the
 * compiler in debian:bookworm, the image scripts/gate-linux-cell.sh builds in -- has
 * no -Wdangling-pointer to silence at this store, and naming an option a compiler does
 * not have is itself a diagnostic under -Werror. So the guard is a floor, not a
 * version table: gcc below 15 gets no pragma and no unknown-option risk.
 *
 * THE ATTRIBUTE IS KEPT ANYWAY, on the same reasoning as the pragma: if GCC ever
 * implements no_dangling_pointer, __has_attribute will start answering true, the
 * attribute will be emitted, and it will bind at the declaration the way this comment
 * always said it would. It costs four lines and it is the difference between a guard
 * that is right now and one that is right whenever the compiler catches up. Both
 * mechanisms are needed in the meantime; neither alone was doing anything. */
#if defined(__has_attribute)
#  if __has_attribute(no_dangling_pointer)
#    define ASAN_PROBE_NO_DANGLING __attribute__((no_dangling_pointer))
#  endif
#endif
#ifndef ASAN_PROBE_NO_DANGLING
#  define ASAN_PROBE_NO_DANGLING
#endif

#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 15
#  pragma GCC diagnostic ignored "-Wdangling-pointer"
#endif

ASAN_PROBE_NO_DANGLING
__attribute__((noinline))
static void stash_address(int **out)
{
    // codeql[js/cpp/using-expired-stack-address]
    int local = 7;

    // codeql[js/cpp/using-expired-stack-address]
    *out = &local;
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

        /* See THE TWO CODEQL SUPPRESSIONS IN THIS FILE, above the class table. The
         * reported line for this case is this one -- the STORE, where the address of a
         * local leaves its scope -- and not the dereference below it. */
        // codeql[js/cpp/using-expired-stack-address]
        escaped = keep_address(&local);
    }
    fprintf(stderr, "asan_coverage_probe: sas read %d\n", *escaped);
}

static void provoke_stack_use_after_return(void)
{
    int *escaped = NULL;

    stash_address(&escaped);
    /* The dereference, three lines after a function returned and took its frame with
     * it. See THE CODEQL SUPPRESSIONS IN THIS FILE, above the class table: this case
     * and the scope case above are the only two places in this file CodeQL is right
     * about, and both are deliberate. */
    // codeql[js/cpp/using-expired-stack-address]
    fprintf(stderr, "asan_coverage_probe: uar read %d\n", *escaped);
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
 * THE TWO CODEQL SUPPRESSIONS IN THIS FILE, and why there are exactly two.
 *
 * CodeQL is RIGHT about both of them. Each of the two stack cases below lets the
 * address of a local outlive it, and that is precisely the defect the case exists to
 * provoke -- so the alert is a true positive about a function whose entire contract is
 * to be wrong in one specific way and to stop there. The alternatives were considered
 * and all three are worse:
 *
 *   * FIXING IT deletes the case. A stack-use-after-scope or stack-use-after-return
 *     claim that is never exercised is a claim in a comment.
 *   * HIDING THIS FILE from CodeQL hides every FUTURE finding in it too, including a
 *     real one. There is no per-directory or per-rule alternative that narrows this to
 *     two lines.
 *   * OBFUSCATING the escapes -- through a function pointer, a union, or an arithmetic
 *     detour -- so the scanner cannot follow them makes the cases harder to read and
 *     the sanitizer's own report less useful, and buys nothing: the scanner is not
 *     wrong here, the code is wrong on purpose, and a probe that hides its own shape
 *     is a probe nobody can check.
 *
 * FOUR LINES, ONE RULE, AND WHERE THEY GO WAS MEASURED BY RUNNING THE SCAN. An
 * earlier version of this file suppressed the STORE in each case and the scan stayed
 * red on the return case at its dereference; suppressing there, and at the local's
 * declaration, and at both ends of the statement, is what closed it. Which comment
 * binds was established by pushing and reading the scan's next answer rather than by
 * reading CodeQL's documentation, and the redundant placements are cheaper than another
 * round trip. An unused suppression comment is inert.
 *
 * WHAT MAKES THESE SAFE RATHER THAN CONVENIENT is that deleting any one of them leaves
 * the build green and the probe green and turns the scan red on exactly one case, so
 * each is load-bearing evidence rather than decoration. If a future revision of this
 * file ever needed a FIFTH, that is the moment to reconsider the whole approach -- at
 * which point the honest answer is a CodeQL query-suppression config naming this file
 * and this rule, which is visible in one place instead of four.
 * --------------------------------------------------------------------------- */

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
