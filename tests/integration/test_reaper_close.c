/* test_reaper_close.c -- the reaper is the only thing that closes a connection,
 * and a closed slot leaves nothing behind.
 *
 * docs/SERVER_DESIGN.md 3.4: "The send path never closes a connection. It
 * marks CLOSING; a reaper runs at a fixed point in the loop." The registry side
 * of the same requirement is the fd-indexed table, whose slots must be cleared
 * and whose conn_t must be torn down, so a descriptor the OS hands out again
 * starts clean.
 *
 * This file is the RUNTIME half of that. test_close_sites.c is the structural
 * half -- it proves by inspection that nothing else calls close() on a
 * connection -- and the two are complementary because each catches what the
 * other cannot. Asserted here, from inside the child, where the loop and the
 * registry are both visible:
 *
 *   1. NO CLOSING CONNECTION SURVIVES AN ITERATION. The tick runs at the end of
 *      the iteration, after the reap, so anything still marked CLOSING at that
 *      point means the reap is not a fixed point but a later pass -- the
 *      failure mode 3.4 is written against.
 *   2. EVERY CONNECTION IS CLOSED EXACTLY ONCE: closed == accepted, and closed
 *      never exceeds accepted.
 *   3. A REUSED DESCRIPTOR STARTS CLEAN. The first connection is deliberately
 *      left DIRTY -- it holds a nick, has bytes queued in its write queue, and
 *      is CLOSING -- before being reaped. The second connection is then almost
 *      certainly handed the same descriptor, because the kernel issues the
 *      lowest free number and that is exactly the one just released. If
 *      anything survived the close, the new connection inherits it, and the
 *      audit says so and fails.
 *   4. THE SLOT INDEX AND THE DESCRIPTOR AGREE, and the live count matches the
 *      registry's own counter -- an off-by-one in the fd-indexed table would
 *      hand back the wrong connection, which is worse than a leak.
 *
 * What is NOT claimed: a second close() syscall on an already-closed descriptor
 * is not detectable from inside the process without a sanitizer, because the
 * kernel's EBADF is swallowed by any error path that looks correct. That is
 * exactly why (3) is here: a spurious second close would land on a descriptor
 * the OS had since reissued, and the connection on that descriptor would not be
 * clean. test_close_sites.c closes the remaining gap by construction.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/connection.h"
#include "core/message.h"
#include "core/poll_loop.h"
#include "core/server.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000
#define NF_MAX_SEEN 64

/* Descriptors this child has already seen a connection on, so a reuse can be
 * recognised rather than assumed. */
static int g_seen[NF_MAX_SEEN];
static int g_nseen = 0;

/* Which audit lines have already been printed for a descriptor. The audit runs
 * every tick, so without this the node would write a line per 50 ms for as long
 * as the connection is open -- and a parent that is not reading at that instant
 * would fill the pipe and deadlock against a child waiting to write. */
static unsigned char g_reported[FD_SETSIZE];

static int seen_before(int fd)
{
    int i;

    for (i = 0; i < g_nseen; i++) {
        if (g_seen[i] == fd) {
            return 1;
        }
    }
    if (g_nseen < NF_MAX_SEEN) {
        g_seen[g_nseen++] = fd;
    }
    return 0;
}

/* Report an invariant violation and end the child. The exit is in the macro,
 * for the same reason it is in test_util.h: a helper that never returns is a
 * candidate for a noreturn attribute, and -Weverything makes that a portability
 * problem rather than a fix. Exit code 3 is distinct from the test's own 1 so a
 * child that dies on an audit failure is obvious in the log. */
static void bug_report(const char *what, const conn_t *c)
{
    printf("[fixture] BUG %s fd=%d state=%d woff=%zu wlen=%zu rlen=%zu "
           "kind=%d nick=%s\n",
           what, c->fd, c->state, c->woff, c->wlen, c->rlen, c->kind, c->nick);
    fflush(stdout);
}

#define BUG(what, c)                                                         \
    do {                                                                     \
        bug_report((what), (c));                                             \
        exit(3);                                                             \
    } while (0)

/* The tick hook. It runs inside the child, at the end of every iteration and
 * therefore after the reap -- which is the only reason it can assert anything
 * about the reap at all. */
static void audit_tick(server_t *s, uint64_t now_ms)
{
    uint64_t live = 0;
    int i;

    (void)now_ms;

    for (i = 0; i < FD_SETSIZE; i++) {
        const conn_t *c = s->by_fd[i];

        if (c == NULL) {
            continue;
        }
        live++;
        if (c->state == CONN_CLOSING) {
            BUG("closing_survived_reap", c);
        }
        if (c->fd != i) {
            /* The table is indexed BY descriptor; a mismatch means a lookup
             * would hand back somebody else's connection. */
            BUG("fd_index_mismatch", c);
        }
        if (seen_before(c->fd)) {
            /* (3) A reissued descriptor must come back pristine. The report
             * carries every field a stale struct would corrupt, so the test can
             * assert the values rather than take "it looked fine" on trust. */
            if ((g_reported[c->fd] & 2u) == 0u) {
                g_reported[c->fd] |= 2u;
                printf("[fixture] reuse fd=%d rstate=%d roff=%zu rlen=%zu "
                       "rkind=%d rnick=%s\n",
                       c->fd, c->state, c->woff, c->rlen, c->kind, c->nick);
                fflush(stdout);
            }
            if (c->state != CONN_REG_PASS || c->woff != 0u || c->wlen != 0u ||
                c->rlen != 0u || c->kind != CONN_CLIENT || c->nick[0] != '\0') {
                BUG("reuse_dirty", c);
            }
        } else if ((g_reported[c->fd] & 1u) == 0u) {
            g_reported[c->fd] |= 1u;
            printf("[fixture] first_conn fd=%d state=%d\n", c->fd, c->state);
            fflush(stdout);
        }
    }

    if (live != (uint64_t)s->nconns) {
        printf("[fixture] BUG nconns_mismatch live=%llu counted=%llu\n",
               (unsigned long long)live, (unsigned long long)s->nconns);
        fflush(stdout);
        exit(3);
    }
    /* (2) More closes than accepts means something closed a descriptor the
     * registry had already released. */
    if (s->n_closed > s->n_accepted) {
        printf("[fixture] BUG closed_gt_accepted closed=%llu accepted=%llu\n",
               (unsigned long long)s->n_closed,
               (unsigned long long)s->n_accepted);
        fflush(stdout);
        exit(3);
    }
}

/* Leave the connection DIRTY, then drop it through the documented path: mark
 * CLOSING and let the reaper close it. Nothing here closes a descriptor. */
static void dirty_and_drop(server_t *s, conn_t *c, const message_t *m)
{
    char payload[128];

    (void)m;
    (void)s;
    memset(c->nick, 0, sizeof c->nick);
    memcpy(c->nick, "stale", 5u);
    memset(payload, 'Z', sizeof payload);
    /* Queued but never pumped: wlen is non-zero at the moment of the close, so
     * a descriptor handed back out still carrying it would be visible. */
    TF_CHECK_MSG(conn_queue(c, payload, sizeof payload) == 0,
                 "could not queue the dirty payload");
    conn_mark_closing(c);
    printf("[fixture] mark_closing fd=%d wlen=%zu state=%d\n", c->fd,
           conn_write_pending(c), c->state);
    fflush(stdout);
}

static void setup(server_t *s)
{
    s->dispatch = dirty_and_drop;
    s->on_tick = audit_tick;
}

int main(void)
{
    nf_node_t node;
    test_client_t a;
    test_client_t b;

    TF_CHECK(nf_spawn_inline(&node, setup) == 0);

    /* Connection 1: a line makes the node dirty it and mark it CLOSING; the
     * reaper closes it at the end of that same iteration. */
    tc_init(&a);
    TF_CHECK_MSG(tc_connect(&a, node.port) == 0, "connect a failed");
    /* dispatch is only reached through the message path, so the line is what
     * makes the node dirty the connection and drop it. */
    TF_CHECK_MSG(tc_send(&a, "GO") == 0, "send on connection 1 failed");
    TF_CHECK_MSG(nf_expect(&node, "[fixture] mark_closing", T_IO_MS) == 0,
                 "the node never saw a line on connection 1");
    TF_CHECK_MSG(nf_expect(&node, "[fixture] first_conn", T_IO_MS) == 0,
                 "the audit never saw connection 1");
    {
        int rc = tc_expect_eof(&a, T_IO_MS);

        TF_CHECK_MSG(rc == 0, "connection 1 was not closed after being marked "
                     "CLOSING: rc=%d", rc);
    }
    TF_CHECK_MSG(nf_expect_u64(&node, "closed=", 1, T_IO_MS) == 0,
                 "closed should be 1 after one dropped connection: the reaper "
                 "closes at the fixed point in the iteration, not later");

    /* Connection 2. The kernel reissues the lowest free descriptor, which is
     * the one just released, so this is where "a reused fd cannot inherit stale
     * state" is observed rather than assumed. */
    tc_init(&b);
    TF_CHECK_MSG(tc_connect(&b, node.port) == 0, "connect b failed");
    TF_CHECK_MSG(nf_expect(&node, "[fixture] reuse fd=", T_IO_MS) == 0,
                 "the second connection did not land on the released "
                 "descriptor, so the registry's zero-on-close behaviour was "
                 "not exercised");
    TF_CHECK_MSG(nf_expect(&node, "rstate=0 roff=0 rlen=0 rkind=0 rnick=",
                           T_IO_MS) == 0,
                 "a reissued descriptor carried state from the closed "
                 "connection");

    /* (2) after the stop: every connection closed exactly once, none left. */
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", 2, T_IO_MS) == 0,
                 "accepted should be 2");
    TF_CHECK_MSG(nf_expect_u64(&node, "closed=", 2, T_IO_MS) == 0,
                 "closed should be 2: every connection must be closed exactly "
                 "once");
    TF_CHECK_MSG(nf_expect_u64(&node, "nconns=", 0, T_IO_MS) == 0,
                 "nconns should be 0 after shutdown");
    /* No [fixture] BUG line appears anywhere in the child's output. The audit
     * exits the child on any violation, so a clean exit already implies that --
     * but the negative is asserted explicitly, because a future audit change
     * that only warns would otherwise go unnoticed. */
    TF_CHECK_MSG(strstr(node.out, "[fixture] BUG") == NULL,
                 "the audit reported a violation: %s", node.out);

    tc_close(&a);
    tc_close(&b);
    nf_free(&node);
    tf_done("reaper_close");
    return 0;
}
