/* test_dedup_error.c -- the dedup store's -1 error arm (#174).
 *
 * fed_dedup_seen() is TRI-STATE: 0 for a new key (recorded), 1 for a duplicate,
 * -1 when the store itself failed -- the table could not be allocated, or is
 * full past eviction. The -1 is not a duplicate: federation/verbs.c's G7 drops
 * it under n_fed_dedup_error / [observable] fed_dedup_error, and a climbing dup
 * counter under memory pressure is the misdiagnosis this file exists to prevent.
 *
 * Three cases, all in-process against server_t (no sleeps, no wall clock):
 *
 *   1. FILL TO IRC_DEDUP_MAX. Distinct keys up to capacity, one past it (the
 *      LRU victim goes, the insert still reports new), then the evicted key
 *      reads new again while a live one still reads duplicate. Capacity
 *      eviction is not an error: it forgets, it does not fail.
 *   2. CALLOC FAILURE, fault-injected with RLIMIT_AS on Linux. The
 *      address-space ceiling is set to the current size (read from
 *      /proc/self/statm) plus 64 KiB -- room for the probe's stack and
 *      registers, not for the ~416 KiB table -- on a server whose table is not
 *      yet allocated, so the table's calloc is the allocation that fails. The
 *      call must answer -1, record nothing, and the store must work again once
 *      the ceiling is restored. The ceiling is restored BEFORE any assertion
 *      runs, so a failure reports rather than starving the reporter.
 *   3. THE G7 COUNTER SPLIT. A tagged relay line through fed_dispatch() with
 *      the ceiling in place lands on n_fed_dedup_error (and the guard's
 *      n_fed_dup_drop, which counts every guard drop) and NOT on
 *      n_fed_dedup_dup. Without the ceiling the same line sent twice lands on
 *      the dup counter and leaves the error counter at zero.
 *
 * WHY RLIMIT_AS AND NOT A WRAPPER. A --wrap=calloc probe needs linker support
 * the macOS build does not have, and an LD_PRELOAD/DYLD shim is a second
 * binary the suite would have to build and clean. An address-space ceiling
 * fails exactly the large mmap the table needs, needs no new build product,
 * and has precedent (RLIMIT_NOFILE in tests/harness/node_fixture.c, then
 * test_fdsize_reject.c).
 *
 * WHERE THE CEILING RUNS. Linux only, non-ASan builds. Two measured reasons,
 * one per exclusion:
 *   - macOS accounts the shared cache and other reservations in the address
 *     space, so the measured size is ~2^63 and every finite ceiling is EINVAL
 *     (verified: 32 MiB through 32 GiB all refuse). There is no settable value
 *     that fails a 416 KiB mmap and keeps the process alive.
 *   - AddressSanitizer serves allocations from a pool it maps at startup, so a
 *     ceiling set after init does not fail the table's calloc -- and forcing
 *     exhaustion would abort rather than return NULL.
 * Everywhere else cases 2 and the error half of 3 are replaced by the
 * no-ceiling double dispatch, which still proves the counter split from the
 * duplicate side: a real duplicate never touches n_fed_dedup_error. The
 * replacement is selected at COMPILE time and printed as mode=ceiling or
 * mode=fallback on stdout, so a log shows which half ran; no CTest skip is
 * involved and tests/known_skips.txt stays empty. The Linux CI job is the one
 * that covers the -1 arm.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/resource.h>
#endif

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"
#include "federation/dedup.h"
#include "federation/link.h"
#include "federation/verbs.h"
#include "federation_handshake.h"
#include "harness/test_util.h"

#define NODE_NAME "irc.test"
#define PEER_NAME "irc.b"

/* 64 KiB of headroom above the current address space: the probe path between
 * the ceiling and its restore allocates nothing (the one calloc is the failure
 * under test), so this only has to cover stack and registers. It is far below
 * IRC_DEDUP_TABLE_BYTES (~416 KiB), which is the point. */
#define OOM_HEADROOM ((unsigned long long)(64u * 1024u))

#if defined(__SANITIZE_ADDRESS__)
#define DEDUP_ERR_NO_OOM 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define DEDUP_ERR_NO_OOM 1
#endif
#endif

/* The ceiling probe runs only where it can work: Linux, without ASan. */
#if defined(__linux__) && !defined(DEDUP_ERR_NO_OOM)
#define DEDUP_ERR_CEILING 1
#endif

static void tag_of(irc_serve_tags_t *t, const char *origin, uint64_t epoch,
                   uint64_t id, uint32_t hops)
{
    memset(t, 0, sizeof *t);
    memcpy(t->origin, origin, strlen(origin) + 1u);
    t->epoch = epoch;
    t->id = id;
    t->hops = hops;
}

#if defined(DEDUP_ERR_CEILING)
static unsigned long long proc_vsize(void)
{
    FILE *f = fopen("/proc/self/statm", "r");
    unsigned long long pages = 0;
    long page = sysconf(_SC_PAGESIZE);

    if (f == NULL || page <= 0) {
        if (f != NULL) {
            (void)fclose(f);
        }
        return 0;
    }
    if (fscanf(f, "%llu", &pages) != 1) {
        (void)fclose(f);
        return 0;
    }
    (void)fclose(f);
    return pages * (unsigned long long)page;
}
#endif

/* A server with an ESTABLISHED link to PEER_NAME and an unregistered
 * CONN_SERVER conn naming it -- the least fed_dispatch() needs to reach G7.
 * No sockets: nothing here pumps, and the conn is freed by hand (it is never
 * registered, and server_add_conn() refuses fd < 0). */
static void link_rig(server_t *s, conn_t **pc_out)
{
    server_link_t *l;
    conn_t *pc;

    s->links = (server_link_t *)calloc(IRC_FED_MAX_PEERS, sizeof *s->links);
    TF_CHECK_MSG(s->links != NULL, "could not allocate the link vector");
    s->links_cap = (size_t)IRC_FED_MAX_PEERS;
    s->nlinks = 1;
    l = &s->links[0];
    memcpy(l->name, PEER_NAME, strlen(PEER_NAME) + 1u);
    l->fd = -1;
    handshake_init(&l->hs);
    l->hs.state = ESTABLISHED;
    l->state = (int)l->hs.state;

    pc = conn_new(-1, CONN_SERVER);
    TF_CHECK_MSG(pc != NULL, "conn_new() failed for the peer connection");
    pc->peer_name = (char *)malloc(strlen(PEER_NAME) + 1u);
    TF_CHECK_MSG(pc->peer_name != NULL, "could not set the peer's name");
    memcpy(pc->peer_name, PEER_NAME, strlen(PEER_NAME) + 1u);
    *pc_out = pc;
}

int main(void)
{
    server_t s;
    irc_serve_tags_t t;
    uint64_t base = 1000000ULL;
    uint64_t i;

    TF_CHECK_MSG(server_init(&s, NODE_NAME) == 0, "server_init failed");

    /* =======================================================================
     * 1. FILL TO IRC_DEDUP_MAX: eviction forgets, it does not fail
     * ==================================================================== */
    for (i = 1; i <= (uint64_t)IRC_DEDUP_MAX; i++) {
        tag_of(&t, PEER_NAME, 1700000003ULL, i, 0u);
        TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 0,
                     "insert %llu of %d was not reported as new",
                     (unsigned long long)i, IRC_DEDUP_MAX);
    }
    TF_CHECK_MSG(fed_dedup_size(&s) == (size_t)IRC_DEDUP_MAX,
                 "a full store holds %zu entries, not IRC_DEDUP_MAX",
                 fed_dedup_size(&s));
    /* One past capacity: still new (the LRU victim pays for it), still full. */
    tag_of(&t, PEER_NAME, 1700000003ULL, (uint64_t)IRC_DEDUP_MAX + 1u, 0u);
    TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 0,
                 "the insert past capacity was not reported as new: eviction "
                 "broke, and a full store would rather fail than forget");
    TF_CHECK_MSG(fed_dedup_size(&s) == (size_t)IRC_DEDUP_MAX,
                 "the insert past capacity left %zu entries", fed_dedup_size(&s));
    /* The victim (id 1, least recently seen) reads new again; the newest still
     * reads duplicate. */
    tag_of(&t, PEER_NAME, 1700000003ULL, 1u, 0u);
    TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 0,
                 "the evicted key still reads as seen: eviction did not free it");
    tag_of(&t, PEER_NAME, 1700000003ULL, (uint64_t)IRC_DEDUP_MAX + 1u, 0u);
    TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 1,
                 "a live key reads as new: the insert past capacity recorded "
                 "nothing");
    fed_dedup_reset(&s);

    /* =======================================================================
     * 2 + 3. THE ERROR ARM, with and without the ceiling
     *
     * On a server of its own: the -1 needs a table that is not yet allocated
     * (table_alloc runs only when dedup_tab is NULL), and case 1's server
     * already holds one.
     * ==================================================================== */
    {
        server_t e;
        conn_t *pc = NULL;
        message_t msg;
        char line[256];

        TF_CHECK_MSG(server_init(&e, NODE_NAME) == 0, "server_init failed");
        link_rig(&e, &pc);
        /* A tagged relay that clears every guard above G7: another origin, a
         * fresh id, hops below the ceiling. Parsed BEFORE any ceiling goes up
         * (the parser allocates) and freed after it comes down. */
        (void)snprintf(line, sizeof line,
                       "@irc-serve-origin=irc.z;irc-serve-epoch=1700000003;"
                       "irc-serve-id=4242;irc-serve-hops=1 "
                       ":mallory!u@example.org SPRIVMSG #T :errprobe");
        TF_CHECK_MSG(message_parse(line, &msg) == 0,
                     "the test's own relay line does not parse");
        /* Warm up stdout: the error arm logs, and the buffer it logs into
         * must not be the allocation that meets the ceiling. The mode line
         * doubles as the log record of which half ran (see the header). */
#if defined(DEDUP_ERR_CEILING)
        (void)printf("dedup_error: mode=ceiling\n");
#else
        (void)printf("dedup_error: mode=fallback\n");
#endif
        (void)fflush(stdout);

#if defined(DEDUP_ERR_CEILING)
        {
            struct rlimit old_rl;
            struct rlimit new_rl;
            unsigned long long vs = proc_vsize();

            TF_CHECK_MSG(vs != 0,
                         "no address-space measurement on this platform, so no "
                         "ceiling can be set");
            TF_CHECK_MSG(getrlimit(RLIMIT_AS, &old_rl) == 0,
                         "getrlimit(RLIMIT_AS) failed");
            new_rl.rlim_cur = (rlim_t)(vs + OOM_HEADROOM);
            new_rl.rlim_max = old_rl.rlim_max;
            TF_CHECK_MSG(setrlimit(RLIMIT_AS, &new_rl) == 0,
                         "setrlimit(RLIMIT_AS) failed");
            /* The store level first: a valid fresh key under a ceiling that
             * admits no table. */
            tag_of(&t, PEER_NAME, 1700000003ULL, 8u, 0u);
            {
                int r = fed_dedup_seen(&e, &t, base);

                fed_dispatch(&e, pc, &msg);
                /* Restored BEFORE any assertion: the reporters below
                 * allocate. */
                TF_CHECK_MSG(setrlimit(RLIMIT_AS, &old_rl) == 0,
                             "restoring RLIMIT_AS failed; the process ceiling "
                             "is still %llu",
                             vs + OOM_HEADROOM);
                TF_CHECK_MSG(r == -1,
                             "a store that could not allocate answered %d, not "
                             "-1: the failure is still masquerading",
                             r);
            }
            TF_CHECK_MSG(e.n_fed_dedup_error == 1u,
                         "a store failure under G7 left n_fed_dedup_error at "
                         "%llu, expected 1",
                         (unsigned long long)e.n_fed_dedup_error);
            TF_CHECK_MSG(e.n_fed_dedup_dup == 0u,
                         "a store failure was counted as a DUPLICATE: "
                         "n_fed_dedup_dup is %llu",
                         (unsigned long long)e.n_fed_dedup_dup);
            TF_CHECK_MSG(e.n_fed_dup_drop == 1u,
                         "a store failure was not counted as a guard drop: "
                         "n_fed_dup_drop is %llu",
                         (unsigned long long)e.n_fed_dup_drop);
            TF_CHECK_MSG(fed_dedup_size(&e) == 0u,
                         "a failed store recorded %zu entries",
                         fed_dedup_size(&e));
            /* And the store works once the ceiling is gone: the failure left
             * no half-state behind. */
            tag_of(&t, PEER_NAME, 1700000003ULL, 7u, 0u);
            TF_CHECK_MSG(fed_dedup_seen(&e, &t, base) == 0,
                         "the store did not recover after the ceiling was "
                         "lifted");
        }
#else
        /* No ceiling on this build (see the file header). The double dispatch
         * still proves the split from the duplicate side. */
        fed_dispatch(&e, pc, &msg);
        fed_dispatch(&e, pc, &msg);
        TF_CHECK_MSG(e.n_fed_dedup_dup == 1u,
                     "the redelivered line left n_fed_dedup_dup at %llu",
                     (unsigned long long)e.n_fed_dedup_dup);
        TF_CHECK_MSG(e.n_fed_dedup_error == 0u,
                     "a real duplicate touched n_fed_dedup_error: %llu",
                     (unsigned long long)e.n_fed_dedup_error);
#endif
        message_free(&msg);
        conn_free(pc);
        server_shutdown(&e);
    }

    /* server_shutdown() releases the link vector and the dedup table; see
     * test_fed_dedup.c's teardown for the ownership argument. */
    server_shutdown(&s);
    tf_done("dedup_error");
    return 0;
}
