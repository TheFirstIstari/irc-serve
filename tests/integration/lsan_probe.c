/* ---------------------------------------------------------------------------
 * tests/integration/lsan_probe.c -- PROVE LeakSanitizer is live, on purpose.
 *
 * WHY THIS FILE EXISTS. The project claims "0 leaks" from LeakSanitizer. That claim
 * has been carried by a CI job for four passes, and every pass has repeated it. It is
 * a CLAIM ABOUT A TOOL THAT WAS NEVER SEEN WORKING. A suppressed check cannot report a
 * leak that is not there, so "no leaks" is exactly what a LeakSanitizer build with
 * leak detection switched off, running on a platform without it, or wired to nothing
 * at all, also reports. This file is the missing tooth: it makes a child leak on
 * PURPOSE and requires that LSan say so.
 *
 * IT IS OPT-IN AND IT MUST STAY OPT-IN. The probe is built and registered as a CTest
 * test only when -DIRC_LSAN_PROBE=ON, and nothing in scripts/gate.sh and nothing in CI
 * passes that by default. A test that deliberately leaks and is in the normal gate
 * would make the normal gate red, and "the gate is red on purpose" is indistinguishable
 * from "the gate is red" once anyone is bisecting at 2am. The opt-in is what makes
 * this safe to ship: the executable is only built when asked, the CTest entry only
 * exists when asked, and the gate's own cell count is unchanged.
 *
 * HOW IT WORKS, and the reason it is a parent AND a child rather than one process:
 * LSan reports at PROCESS EXIT, from an atexit handler, and it reports on whatever the
 * process still holds. A single process cannot both leak and then assert that LSan
 * noticed, because the assertion has to happen after the report. So this is two runs
 * of one binary, told apart by an environment variable:
 *
 *   IRC_LSAN_PROBE_CHILD set   -> the child: allocate, do not free, return from main.
 *   IRC_LSAN_PROBE_CHILD unset -> the parent: re-exec ourselves as that child under
 *                                 ASAN_OPTIONS=detect_leaks=1, and assert on what it
 *                                 printed AND on what it exited with.
 *
 * WHAT IT ASSERTS, and all three halves matter:
 *   1. the child's output names LeakSanitizer. Without this, a platform with no LSan
 *      produces neither the string nor a non-zero exit, and the probe would pass on a
 *      build that cannot see leaks at all -- which is the failure this file exists to
 *      rule out;
 *   2. the report names 65536 bytes, which is the block THIS test leaked. Without
 *      this, any report that happened to contain the word LeakSanitizer would satisfy
 *      the probe, including a build that detected some other leak while this probe's
 *      own block was somehow not reported;
 *   3. the child exited 23, which is the exitcode this test configured. LSan reporting
 *      without failing the run is the shape of "a check that runs and cannot fail", and
 *      only the exit code distinguishes that from a real finding.
 *
 * WHY 64 KiB AND NOT ONE BYTE. It is the size PR #140's leak was, so the needle is a
 * number this project has already had to read once. A 1-byte leak is equally invisible
 * but is not findable by eye in a 200-line ctest log, which is where a person looks
 * when this test fails. Deliberately not a power of two, so the number in the report
 * is evidence of this allocation rather than of an allocator rounding a small one up.
 *
 * THE COST, WHICH IS REAL: this test spawns a process and that process leaks 64 KiB on
 * purpose. Under LSan the leak is reported and this test asserts on the report; with
 * LSan absent the parent FAILS, which is correct and is the design. The 64 KiB is
 * released when the child's address space goes away, so a run of this test accumulates
 * nothing across a suite run.
 * --------------------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* The child hands its own argv[0] back to the parent rather than the parent guessing a
 * path: under ctest argv[0] is the instrumented binary ctest started, and hardcoding a
 * build path would make this test fail in every build directory except one. */
#define PROBE_ENV "IRC_LSAN_PROBE_CHILD"

/* 64 KiB, named because two halves of this file talk about it: the child allocates it
 * and the parent looks for this many bytes in the report. */
#define PROBE_LEAK_BYTES 65536

/* The only pointer the child ever holds to the block it leaks, and it is set to NULL
 * before main() returns -- see run_as_child() for why that line is load-bearing and
 * what the probe measured when it was missing. */
static void *g_probe_block;

/* ---------------------------------------------------------------------------
 * The child. Deliberately minimal: if this allocated anything else, or freed
 * anything, the report would name a different block and the parent's byte-count
 * assertion would stop being evidence about this file.
 * --------------------------------------------------------------------------- */
static int run_as_child(void)
{
    g_probe_block = malloc(PROBE_LEAK_BYTES);
    if (g_probe_block == NULL) {
        fprintf(stderr, "lsan_probe: malloc(%d) failed, so there is nothing to leak\n",
                PROBE_LEAK_BYTES);
        return 1;
    }
    /* Touch every page, so the allocation is real memory and not a lazy mapping an
     * allocator could decline to back. LSan tracks the malloc either way, but a report
     * about an untouched page is a weaker claim than one about 64 KiB actually used. */
    memset(g_probe_block, 0xA5, PROBE_LEAK_BYTES);
    /* AND THEN DROP THE ONLY POINTER TO IT, WHICH IS WHAT MAKES IT A LEAK.
     *
     * This line is here because the first version of this file left `g_probe_block`
     * pointing at the block, and the probe went RED on the build where it had been
     * green: LSan reported nothing and the child exited 0. The reason is that LSan
     * checks REACHABILITY, not allocation -- it reports blocks no live pointer can
     * reach, and a global pointer in .bss is about as reachable as a pointer gets. So
     * `static void *g_probe_block` held at exit is not a leak; it is a global, and the
     * program is entitled to keep it.
     *
     * The failure was silent and expensive in the worst way: the probe FAILED, which
     * looked like LSan being broken rather than the probe being wrong, and the obvious
     * response -- trust the red -- would have meant deleting a working check. Which is
     * the argument for reading what a red test says before believing it, and for a
     * probe having more than one assertion: half 1 was the only one that fired, and it
     * fired correctly, saying "no report". It was the PROBE that was wrong.
     *
     * It is kept as a global rather than being a local because the compiler would be
     * free to reuse the stack slot, and a stack slot that has been reused is not
     * evidence about anything. A global, cleared, is unambiguous. */
    g_probe_block = NULL;
    fprintf(stderr, "lsan_probe: child leaked %d bytes on purpose\n",
            PROBE_LEAK_BYTES);
    /* Return from main() normally, so LSan's atexit handler runs. This is the whole
     * reason the child is a separate process rather than a branch in this one. */
    return 0;
}

/* Run the child, collect its stderr and its exit status, and answer both questions.
 *
 * TWO ORDERING FACTS, both of which were got wrong in a first draft and both of which
 * are load-bearing:
 *
 *   * THE PIPE IS INSTALLED BEFORE THE FORK, by redirecting the PARENT's own fd 2 and
 *     then forking. Doing it in the child -- opening a pipe, dup2'ing, running -- would
 *     capture nothing, because the report the parent wants to read is written by a
 *     grandchild this process never sees.
 *   * THE REAP HAPPENS BEFORE THE READ. A pipe's capacity is 64 KiB and an LSan report
 *     is smaller, so reading first would not deadlock today; but a report that grew
 *     past the pipe buffer would, and the wait-then-read order cannot deadlock at any
 *     report size.
 *
 * `out` is filled with the child's stderr (NUL-terminated, possibly truncated) and the
 * child's exit status is returned as -1 when it did not exit normally. */
static int run_child(const char *exe, char **argv, char *out, size_t outcap)
{
    int errpipe[2];
    pid_t pid;
    int status = 0;
    size_t used = 0u;

    out[0] = '\0';
    if (pipe(errpipe) != 0) {
        return -1;
    }

    /* THE FORK COMES BEFORE ANY dup2, AND MOVING IT AFTER ONE HANGS THE PARENT.
     *
     * The first version of this redirected the PARENT's own fd 2 into the pipe before
     * forking, so that the child inherited it. That makes the parent hold the pipe's
     * WRITE END for the rest of its life, and a read() on the other end therefore never
     * sees EOF -- it waits for a writer that is itself -- so the test blocked on
     * read() until ctest's TIMEOUT killed it, on the plain build AND under LSan. The
     * symptom was a 60-second timeout with no diagnostic, on a run whose whole purpose
     * is to produce a diagnostic.
     *
     * The parent's stderr is left exactly as it was and the redirection happens in the
     * CHILD, between fork and exec, which is where a redirection belongs: the child
     * never returns to this function, so it cannot keep the write end open.
     *
     * THE COST: the parent no longer sees the child's report on its own stderr while the
     * test runs, so on failure the report appears inside this test's own failure
     * message rather than in the ctest log directly. That is not a loss -- the failure
     * path prints `out` in full -- and it is the only arrangement that terminates. */
    pid = fork();
    if (pid < 0) {
        (void)close(errpipe[0]);
        (void)close(errpipe[1]);
        return -1;
    }
    if (pid == 0) {
        /* The child: take the pipe as stderr, drop both of the parent's ends, then
         * setenv and execv so the options that turn leak detection ON and the variable
         * that selects this file's child path travel through exec rather than through
         * inherited state. The child is a fresh, fully instrumented process image,
         * which is the process LSan reports on. */
        if (dup2(errpipe[1], STDERR_FILENO) < 0) {
            _exit(127);
        }
        (void)close(errpipe[0]);
        (void)close(errpipe[1]);
        (void)setenv("ASAN_OPTIONS", "detect_leaks=1", 1);
        (void)setenv("LSAN_OPTIONS", "exitcode=23", 1);
        (void)setenv(PROBE_ENV, "1", 1);
        (void)execv(exe, argv);
        /* Only reached if execv failed, which means there is no instrumented process
         * to report anything. Say so in the child's own words, because this message is
         * the whole output the parent is about to assert on. */
        fprintf(stderr, "lsan_probe: execv(%s) failed\n", exe);
        _exit(127);
    }

    /* Close the write end in the PARENT before waiting on the child. This is the same
     * thing the comment above the fork is about, from the other side: the parent's
     * copy of the write end is the only one left alive once the child has exec'd, and
     * holding it is what makes read() below block forever. */
    (void)close(errpipe[1]);

    (void)waitpid(pid, &status, 0);
    for (;;) {
        ssize_t n = read(errpipe[0], out + used, outcap - 1u - used);

        if (n > 0) {
            used += (size_t)n;
            if (used >= outcap - 1u) {
                used = outcap - 2u; /* leave room for the terminator */
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
    /* 8 KiB: enough for an LSan report, small enough to be a stack buffer. This is a
     * test asserting on a report it caused, not a log collector. */
    char out[8192];
    char bytes_text[32];
    char exe[4096];
    int rc;

    (void)argc;

    if (getenv(PROBE_ENV) != NULL) {
        return run_as_child();
    }

    printf("ok: this test passes ONLY if LeakSanitizer reports a deliberate leak\n");
    printf("note: a build without leak detection cannot pass it, and that is the point\n");

    /* argv[0], not a hardcoded path: under ctest this IS the instrumented binary. */
    (void)snprintf(exe, sizeof exe, "%s", argv[0]);
    (void)snprintf(bytes_text, sizeof bytes_text, "%d", PROBE_LEAK_BYTES);

    fflush(stdout);
    rc = run_child(exe, argv, out, sizeof out);
    if (rc < 0) {
        fprintf(stderr, "lsan_probe: FAILED -- the child did not run to a normal "
                "exit, so there is no report to assert on.\n");
        return 1;
    }

    /* Half 1: LSan ran and said the word. A build with no leak detection produces
     * neither this string nor a non-zero exit, and this is the assertion that makes
     * the probe RED on such a build rather than green. */
    if (strstr(out, "LeakSanitizer") == NULL) {
        fprintf(stderr, "lsan_probe: FAILED -- the child's output does not mention "
                "LeakSanitizer, so the deliberate leak was NOT detected. This test is "
                "red on any platform where LSan is absent or disabled, and that is "
                "correct: on such a platform the project's \"0 leaks\" claim has no "
                "oracle behind it.\n--- child output follows ---\n%s", out);
        return 1;
    }
    printf("ok: the child printed a LeakSanitizer report\n");

    /* Half 2: the report is about OUR block, not some other leak. */
    if (strstr(out, bytes_text) == NULL) {
        fprintf(stderr, "lsan_probe: FAILED -- a LeakSanitizer report was printed but "
                "it does not name %s bytes, so it is not about the block this test "
                "leaked on purpose.\n--- child output follows ---\n%s", bytes_text,
                out);
        return 1;
    }
    printf("ok: the report names the %s bytes this test leaked on purpose\n",
           bytes_text);

    /* Half 3: the exit code. Configured above as exitcode=23, so a child whose leak
     * was detected exits 23. A child that leaked and exited 0 would mean LSan printed
     * a finding without failing the run -- the shape of a check that cannot fail. */
    if (rc != 23) {
        fprintf(stderr, "lsan_probe: FAILED -- the child exited %d, not 23. A leak "
                "report that does not fail the run is a check that cannot fail.\n"
                "--- child output follows ---\n%s", rc, out);
        return 1;
    }
    printf("ok: the child exited 23, which is the exitcode this test configured\n");

    printf("ok: LeakSanitizerProbe\n");
    return 0;
}