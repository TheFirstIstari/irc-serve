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

#include <stdio.h>
#include <stdlib.h>

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

#endif /* TEST_HARNESS_TEST_UTIL_H */
