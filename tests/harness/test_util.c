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

void tf_done(const char *name)
{
    int i;

    for (i = 0; i < g_nnodes; i++) {
        tf_unregister(g_nodes[i]);
    }
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

char *tf_read_code(const char *rel, size_t *len_out)
{
    char path[1024];
    FILE *f;
    char *out;
    size_t cap = 65536;
    size_t len = 0;
    int in_block = 0;
    int in_line = 0;
    int quote = 0;
    int prev = 0;
    int ch;

    (void)snprintf(path, sizeof path, "%s/%s", IRCSERVE_SRC_DIR, rel);
    f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    out = (char *)malloc(cap);
    if (out == NULL) {
        fclose(f);
        return NULL;
    }
    while ((ch = fgetc(f)) != EOF) {
        if (len + 2u >= cap) {
            char *grown = (char *)realloc(out, cap * 2u);

            if (grown == NULL) {
                free(out);
                fclose(f);
                return NULL;
            }
            out = grown;
            cap *= 2u;
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
    fclose(f);
    out[len] = '\0';
    if (len_out != NULL) {
        *len_out = len;
    }
    return out;
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
