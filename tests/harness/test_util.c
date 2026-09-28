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
