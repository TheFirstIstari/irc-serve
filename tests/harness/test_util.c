/* test_util.c -- see test_util.h. */
#include "harness/test_util.h"

#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef IRCSERVE_SRC_DIR
#error "IRCSERVE_SRC_DIR must name the source tree for the source-inspection helpers"
#endif

/* A handful of nodes, which is more than any test here spawns at once. Fixed
 * size on purpose: this runs on a failing path, and an allocation there could
 * fail for the same reason the test did. */
#define TF_MAX_NODES 4

static nf_node_t *g_nodes[TF_MAX_NODES];
static int g_nnodes = 0;

void tf_register(nf_node_t *n)
{
    if (g_nnodes < TF_MAX_NODES) {
        g_nodes[g_nnodes++] = n;
    }
}

void tf_unregister(nf_node_t *n)
{
    int i;

    for (i = 0; i < g_nnodes; i++) {
        if (g_nodes[i] == n) {
            g_nodes[i] = g_nodes[--g_nnodes];
            return;
        }
    }
}

/* The pipe capacity quoted below. It is a CONSTANT rather than a query because
 * the point of printing the queued count is the comparison against the ceiling:
 * "0 of 65536" says the child has nothing to say, and "65330 of 65536" says the
 * child is stopped inside write() and every wait that was waiting on it was
 * waiting for a node that had stopped running. 65536 is the capacity of a
 * pipe(2) buffer on both Linux and macOS, which is why it can be named here
 * instead of measured -- the measurement that matters is the queued half, and
 * that one is read from the kernel every time. */
#define TF_PIPE_CAPACITY 65536

/* Dump what every live node said, and -- the part this exists for -- how much
 * each of them still has UNREAD in its stdout pipe.
 *
 * WHY THE SECOND NUMBER. `n->out` is only what the parent happened to pump, so
 * on a failure it cannot distinguish the two states a reader actually has to
 * separate: a node that had nothing to say, and a node that said a great deal
 * and then stopped being able to say any more because its 64 KiB pipe filled
 * and it is now blocked inside write(), in the middle of its own event loop.
 * Both print the same buffer, and on a loaded runner guessing between them from
 * a truncated dump is how a real defect gets diagnosed as a scheduler.
 *
 * So the number is read from the kernel (ioctl FIONREAD on the pipe's read end)
 * and printed beside the buffer it explains. A large value is a node that is
 * WEDGED, and it says so here rather than leaving it to be inferred. */
void tf_report(const char *expr, const char *file, int line)
{
    int i;

    fprintf(stderr, "\nFAILED: %s\n  at %s:%d\n", expr, file, line);
    for (i = 0; i < g_nnodes; i++) {
        int queued = 0;

        if (nf_pending_bytes(g_nodes[i], &queued) != 0) {
            fprintf(stderr,
                    "--- node %d (pid %ld, port %d): stdout pipe is closed or "
                    "unreadable, so its queued-byte count is unknown ---\n",
                    i, (long)g_nodes[i]->pid, g_nodes[i]->port);
        } else if (queued > 0) {
            fprintf(stderr,
                    "--- node %d (pid %ld, port %d): %d of %d bytes still QUEUED "
                    "in its stdout pipe. A child fills that pipe and stops running "
                    "until somebody reads, so this node may have stopped inside "
                    "write() rather than having nothing to say: ---\n",
                    i, (long)g_nodes[i]->pid, g_nodes[i]->port, queued,
                    TF_PIPE_CAPACITY);
        } else {
            fprintf(stderr,
                    "--- node %d (pid %ld, port %d): 0 of %d bytes queued in its "
                    "stdout pipe, so this node has said everything it had to say ---\n",
                    i, (long)g_nodes[i]->pid, g_nodes[i]->port, TF_PIPE_CAPACITY);
        }
        fprintf(stderr, "%s\n",
                (g_nodes[i]->out != NULL) ? g_nodes[i]->out : "(nothing)");
    }
    /* Kill rather than stop: this path is already a failure, and there is no
     * point waiting politely for a loop that just misbehaved. Iterating by
     * index because nf_kill() does not touch the registry. */
    for (i = 0; i < g_nnodes; i++) {
        nf_kill(g_nodes[i]);
    }
    fflush(stderr);
    fflush(stdout);
}

/* ---------------------------------------------------------------------------
 * tf_done: the exit path EVERY test takes, and until now a registry edit
 * ---------------------------------------------------------------------------
 * WHAT THIS WAS. A loop over the node registry calling `tf_unregister()`, which
 * removes a node from the array and frees NOTHING -- no `nf_kill()`, no `nf_free()`,
 * no `close()`. It read like a teardown and discharged no debt, which is how the
 * two leaks PR #140's Linux LeakSanitizer run found got as far as the edge of this
 * file: every test in the tree reaches this function, and every one of them reached
 * a helper that freed nothing.
 *
 * WHY IT SURVIVED, and this is the part worth writing down rather than fixing.
 * A leak in a helper SHARED BY EVERY TEST is invisible to every test that uses it,
 * for the same reason a defect in a shared teardown helper is invisible to the suite
 * in any language: the assertion would have to be about the process's memory, and
 * this suite asserts on wire bytes. There is no `ctest` assertion that distinguishes
 * "exited cleanly" from "exited cleanly having leaked", which is why the only oracle
 * is LeakSanitizer, which runs on Linux CI and nowhere else. A test asserting
 * anything about this locally would be a test asserting nothing.
 *
 * WHAT IT DOES NOW, in the order the order matters:
 *
 *   nf_kill() FIRST, then nf_free(). The other order would free the buffer and then
 *   try to kill through a node whose pid field had been zeroed -- and nf_kill() is
 *   idempotent for a node a test already stopped (it returns early on `pid <= 0`),
 *   so calling it on a node whose nf_free() has already run is a no-op rather than a
 *   double free. Killing first is what leaves that property available; freeing first
 *   is what spends it.
 *
 *   SO A TEST THAT ALREADY TEARD DOWN ITS NODES IS UNAFFECTED. Every test in this
 *   tree does -- the harness documents "Does NOT kill; call nf_kill() or nf_stop()
 *   first" on nf_free() precisely because nf_free() is the wrong half -- so for a
 *   clean run this loop does no work at all, and for a test that forgot, it does the
 *   work the test's author meant by calling it.
 *
 * COST: one `kill(2)` and one `waitpid(2)` per node a test did not already reap, and
 * one `free()` per node whose buffer is still allocated. On a clean run, nothing.
 * NOT a fixed `sleep()` and NOT a fixed timeout: nf_kill() waits on the child's pid
 * with `wait`, bounded by its own budget, which is the harness's existing mechanism.
 *
 * WHAT IT STILL DOES NOT DO, because honesty about the limit is the point: it cannot
 * free a `test_client_t`, a `tf_tls_t` or a raw socket, because none of those is
 * registered anywhere and a registry that had them would have had to be added when
 * they were created. That is why `tc_init` without `tc_close` was a real LSan finding
 * in its own right: those helpers are the test author's to pair. Adding a second
 * registry for them is a change to every fixture in the tree and is not this
 * function's decision to make; see scripts/audit-teardown.py, which is the sweep
 * that found this one and says what it cannot decide.
 */
void tf_done(const char *name)
{
    int i;

    /* Iterate by index FROM THE END, because the loop's own body now unregisters:
     * nf_free() calls tf_unregister(), which does `g_nodes[i] = g_nodes[--g_nnodes]`
     * -- it compacts the array by moving the LAST element into the hole. Walking
     * forward would SKIP an element every time: with three nodes [A,B,C],
     * unregistering index 0 moves C into it, and the loop then reads index 1 (now C)
     * and index 2 (past the end), leaving B never released.
     *
     * THIS COMMENT USED TO DESCRIBE THAT WALK WITHOUT BEING TRUE OF THE CODE, which
     * is worth saying rather than quietly fixing. It claimed the loop unregistered
     * as it went when neither nf_kill() nor nf_free() unregistered at all -- which is
     * how a node freed inside a helper function stayed in this registry as a pointer
     * into a RETURNED stack frame, and how tf_done()'s own nf_kill() call became an
     * ASan stack-use-after-return on Linux. A comment describing a fix that was never
     * applied is worse than no comment: it reads as the reason the code is correct.
     * The walk direction was right for a reason that did not hold; it is right now,
     * and the reason it is right is in this paragraph.
     *
     * `g_nnodes = 0` after the loop is belt and braces: the loop empties the registry
     * by construction now, and this makes that a property of the exit rather than an
     * inference about the loop. */
    for (i = g_nnodes - 1; i >= 0; i--) {
        nf_kill(g_nodes[i]);
        nf_free(g_nodes[i]);
    }
    g_nnodes = 0;
    printf("ok: %s\n", name);
    fflush(stdout);
}

size_t tf_count(const char *hay, const char *needle)
{
    size_t n = 0;
    size_t nlen;

    if (hay == NULL || needle == NULL) {
        return 0;
    }
    nlen = strlen(needle);
    if (nlen == 0) {
        return 0; /* an empty needle matches everywhere; refuse to pretend */
    }
    while (strstr(hay, needle) != NULL) {
        hay = strstr(hay, needle) + nlen;
        n++;
    }
    return n;
}

/* THE STRIPPER, AND WHY IT IS NOW A FUNCTION RATHER THAN A LOOP.
 *
 * It was a loop inside `tf_read_code()` until #134's leak, and the reason it had to
 * become one is worth stating because it is the whole of that defect: the loop was
 * fine, but it was only reachable through a function that RETURNED ITS BUFFER, so
 * every caller acquired an obligation and every caller had to remember it. Two of
 * #134's five call sites forgot -- and one of them could not have been caught by
 * reading the harness, because the obligation had left the harness.
 *
 * So the stripper writes into a CALLER'S buffer and owns nothing. Both entry points
 * are thin wrappers over it, which is also why the two cannot disagree about what
 * "stripped" means -- a second copy of a C comment stripper is what
 * `test_close_sites.c`'s header says this one was moved here to avoid. */
static long strip_into(char *out, size_t cap, FILE *f, size_t *len_out)
{
    size_t len = 0;
    int in_block = 0;
    int in_line = 0;
    int quote = 0;
    int prev = 0;
    int ch;

    if (out == NULL || cap == 0u || f == NULL) {
        return -1;
    }
    while ((ch = fgetc(f)) != EOF) {
        /* REFUSE RATHER THAN TRUNCATE, and the growth the heap form does is what
         * makes that difference visible: here `cap` is the caller's, so a file that
         * does not fit has to say so. A source check that silently examines half a
         * file reports clean for a reason nobody can see, and that is the same
         * failure as a leak check that silently examines none of it. */
        if (len + 2u >= cap) {
            out[0] = '\0';
            return -1;
        }
        /* A comment opener is two characters, so the CLOSING pair is detected
         * on its second character and the previous one has to be remembered.
         * Getting that backwards silently reduces the stripped output to almost
         * nothing, and the symptom is an assertion about a function that
         * "cannot be found" in a file that plainly contains it. */
        if (in_block) {
            if (ch == '/' && prev == '*') {
                in_block = 0;
            }
            prev = ch;
            continue;
        }
        if (in_line) {
            if (ch == '\n') {
                in_line = 0;
                out[len++] = (char)ch;
            }
            prev = 0;
            continue;
        }
        if (quote != 0) {
            if (ch == '\\') {
                (void)fgetc(f); /* skip the escaped character */
                prev = 0;
                continue;
            }
            if (ch == quote) {
                quote = 0;
            }
            prev = 0;
            continue;
        }
        if (prev == '/' && ch == '/') {
            in_line = 1;
            prev = 0;
            continue;
        }
        if (prev == '/' && ch == '*') {
            in_block = 1;
            prev = 0;
            continue;
        }
        if (ch == '"' || ch == '\'') {
            quote = ch;
            prev = 0;
            continue;
        }
        out[len++] = (char)ch;
        prev = ch;
    }
    out[len] = '\0';
    if (len_out != NULL) {
        *len_out = len;
    }
    return (long)len;
}

char *tf_read_code(const char *rel, size_t *len_out)
{
    char path[1024];
    FILE *f;
    char *out;
    size_t cap = 65536;
    size_t len = 0;

    (void)snprintf(path, sizeof path, "%s/%s", IRCSERVE_SRC_DIR, rel);
    f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    /* ONE PASS PER CAPACITY, growing until it fits, which is what the loop used to
     * do in one pass and what keeps this wrapper from needing the stripper's state.
     * The stripper REFUSES a file that does not fit `cap`, so growing is a loop
     * here rather than a branch in there -- and the loop cannot leak the partial
     * result, because every exit path frees before it returns. */
    for (;;) {
        out = (char *)malloc(cap);
        if (out == NULL) {
            fclose(f);
            return NULL;
        }
        if (strip_into(out, cap, f, &len) >= 0) {
            if (len_out != NULL) {
                *len_out = len;
            }
            return out;
        }
        free(out);
        if (len + 2u >= cap && cap < (size_t)TF_SRC_MAX * 4u) {
            cap *= 2u;
            continue;
        }
        /* Not a size problem -- `strip_into` only fails on size or a bad
         * argument, and the arguments were checked above -- so this is a file the
         * harness will not read rather than one it ran out of room for. Refusing is
         * the old behaviour for an unreadable file and stays it. */
        fclose(f);
        return NULL;
    }
}

long tf_read_code_into(char *dst, size_t cap, const char *rel, size_t *len_out)
{
    char path[1024];
    FILE *f;
    long n;

    (void)snprintf(path, sizeof path, "%s/%s", IRCSERVE_SRC_DIR, rel);
    f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }
    n = strip_into(dst, cap, f, len_out);
    fclose(f);
    return n;
}

int tf_calls(const char *code, const char *name)
{
    size_t nlen;
    const char *at;

    if (code == NULL || name == NULL) {
        return 0;
    }
    nlen = strlen(name);
    at = code;
    while ((at = strstr(at, name)) != NULL) {
        int before_ok = (at == code) ||
                        !(isalnum((unsigned char)at[-1]) || at[-1] == '_');

        if (before_ok && at[nlen] == '(') {
            return 1;
        }
        at += nlen;
    }
    return 0;
}
