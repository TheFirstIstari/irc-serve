/* test_util.c -- see test_util.h. */
#include "harness/test_util.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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

void tf_report(const char *expr, const char *file, int line)
{
    int i;

    fprintf(stderr, "\nFAILED: %s\n  at %s:%d\n", expr, file, line);
    for (i = 0; i < g_nnodes; i++) {
        fprintf(stderr, "--- node %d (pid %ld, port %d) output ---\n%s\n",
                i, (long)g_nodes[i]->pid, g_nodes[i]->port,
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
