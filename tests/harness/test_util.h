/* test_util.h -- the assertion and cleanup helpers the integration tests share.
 *
 * Why this exists instead of plain assert():
 *
 * These tests fork a child that runs a server. A failing assert() calls abort(),
 * which does NOT run atexit handlers -- so the child would be orphaned, still
 * holding a port and still writing to a pipe nobody reads, and every later test
 * in the run would be affected by a failure in an earlier one. The macros below
 * report the failed expression, kill any node this process spawned, and exit 1.
 *
 * The exit() lives in the macro rather than in a helper function on purpose. A
 * helper that never returns is a candidate for a noreturn attribute, and under
 * -Weverything that attribute is itself a portability problem (-Wpre-c11-compat
 * objects to the C11 _Noreturn when the warning set pretends C89 is possible).
 * Keeping the exit where the failure happens avoids the question entirely and
 * reads better: the macro is the whole failure path.
 *
 * It is deliberately NOT compiled out by NDEBUG. The rest of the suite relies
 * on -UNDEBUG in tests/CMakeLists.txt to keep assert() alive in Release, and
 * this has the same requirement with none of the cleanup problem: a Release
 * build must not silently stop checking.
 *
 * The failure report prints every registered node's output, because "assertion
 * failed" without the child saying why is close to useless when the thing under
 * test is a forked process.
 */
#ifndef TEST_HARNESS_TEST_UTIL_H
#define TEST_HARNESS_TEST_UTIL_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"

/* Nodes registered here are killed and their output dumped if a check fails.
 * nf_spawn_*() registers automatically. */
void tf_register(nf_node_t *n);
void tf_unregister(nf_node_t *n);

/* Print the failure and every registered node's output, then kill the nodes. It
 * RETURNS: the macro that called it decides to exit, which is why this is a
 * plain void function rather than a terminating one. */
void tf_report(const char *expr, const char *file, int line);

#define TF_CHECK(cond)                                                       \
    do {                                                                     \
        if (!(cond)) {                                                       \
            tf_report(#cond, __FILE__, __LINE__);                            \
            exit(1);                                                         \
        }                                                                    \
    } while (0)

/* As TF_CHECK, but with a message printed first, for the cases where the
 * expression alone does not say which value was wrong. */
#define TF_CHECK_MSG(cond, ...)                                              \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "note: ");                                       \
            fprintf(stderr, __VA_ARGS__);                                    \
            fprintf(stderr, "\n");                                           \
            tf_report(#cond, __FILE__, __LINE__);                            \
            exit(1);                                                         \
        }                                                                    \
    } while (0)

/* A final "the test got to the end" line, so a passing CTest run is visibly
 * different from one that exited early by accident. */
void tf_done(const char *name);

/* ---------------------------------------------------------------------------
 * Counting, for the "nothing else was said" assertions
 * ---------------------------------------------------------------------------
 * A protocol test has to be able to assert that a command produced NO output,
 * and the obvious way to do that is to wait and see -- which is a sleep, and 6.3
 * forbids it. This, plus tc_expect(), is how it is done without one.
 *
 * The technique: send the command under test followed by a command whose reply
 * is known, wait for the known reply, and then count occurrences of the
 * unknown one. If the node had answered the first command, the count would be
 * higher; because the known reply arrived, the wait is not a guess about
 * timing. So "PONG is accepted silently" becomes "exactly one PONG arrived,
 * and it is the one for the token I sent afterwards" -- a fact about the bytes,
 * with no sleeping anywhere in it.
 */

/* Non-overlapping occurrences of `needle` in `hay`, or 0 if either is NULL or
 * `needle` is empty. */
size_t tf_count(const char *hay, const char *needle);

/* ---------------------------------------------------------------------------
 * Source inspection
 * ---------------------------------------------------------------------------
 * A few properties here are properties of the code's SHAPE -- "nothing outside
 * the reaper closes a descriptor", "the one function that emits numerics is the
 * one that refuses to write to a peer" -- and no runtime test can check them,
 * because the failure mode is a stray call that happens to leave every runtime
 * invariant intact. Looking is the only way to check those, and these two are
 * how. Both were in test_close_sites.c; they live here so the second source
 * test does not carry a second copy of a C comment stripper.
 */

/* Read `rel` (a path under IRCSERVE_SRC_DIR) with comments and string/character
 * literals REMOVED, so a search sees code rather than prose. Returns a
 * NUL-terminated heap buffer and sets *len_out, or NULL if the file could not be
 * read or allocated. The caller frees it. */
char *tf_read_code(const char *rel, size_t *len_out);

/* THE SAME READ INTO A CALLER'S BUFFER, and this is the form a NEW call site
 * should use. #134's test read `src/core/connection.h` through `tf_read_code()`
 * behind a one-line `read_src()` wrapper, and `check_fields_are_arrays()` forgot the
 * `free()` that the wrapper's contract obliged it to write. Linux's LeakSanitizer
 * found it as "Direct leak of 65536 byte(s) in 1 object(s)" -- the wrapper, not the
 * harness, is what hid it, because the `malloc` is in `tf_read_code()` and the
 * obligation is in the caller's frame three frames away.
 *
 * `tf_read_code_into(dst, cap, rel, &len)` returns the number of bytes written, or
 * -1 if the file cannot be read OR **if it does not fit** -- it REFUSES rather than
 * truncating, because a source check that silently examines half a file reports
 * clean for a reason nobody can see, and that is the same failure as a leak check
 * that silently examines none of it. There is nothing to free and nothing to
 * forget, which is the whole reason it exists.
 *
 * COST: the caller provides `cap` bytes of stack. TF_SRC_MAX is the width that is
 * comfortable for a source file in this tree -- the largest is src/core/msg_verbs.c
 * at 84 KiB -- and a caller that wants more has to say so. `tf_read_code()` remains
 * for the 19 existing call sites that pair their free correctly, and removing it
 * would be a change to every one of them for no gain. */
#define TF_SRC_MAX (256u * 1024u)
long tf_read_code_into(char *dst, size_t cap, const char *rel, size_t *len_out);

/* Is `name` called in `code`? The character before it must not be an identifier
 * character, so a search for `close` does not match conn_close( or
 * server_close_conn(. */
int tf_calls(const char *code, const char *name);

#endif /* TEST_HARNESS_TEST_UTIL_H */
