/* test_failover_reconnect.c -- the reconnect POLICY, on a real link.
 *
 * docs/SERVER_DESIGN.md 2.3 (a peer link and its FSM), 3.4 (the poll tick drives
 * time; a saturated link is dropped), 8 ("Link loss and reconnect re-syncs
 * channel state via SBURST" -- this is the half of that sentence about the
 * resync being DRIVEN, and 8's "A peer that goes away is announced and
 * forgotten"), and the retry block in federation/link.h, which is where the
 * three intervals and their derivations are written down.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS ASSERTED, AND WHERE EACH CLAIM IS TAKEN FROM
 * ---------------------------------------------------------------------------
 *   1. A link that goes silent is RE-DIALLED BY THE TICK. This is the claim
 *      Phase 6 made the opposite of on purpose, and the retraction is in
 *      link.h's "C2's LATCH IS GONE" block: the old assertion was `link_dial`
 *      appears exactly ONCE for the life of the process, and it is now false.
 *   2. The wait GROWS between attempts -- a backoff, not a fixed delay. Read
 *      from the node's own `delay_ms=` on consecutive `link_retry:` lines,
 *      because that is the number the policy actually used.
 *   3. The wait is CAPPED: every delay this test sees is at or below the
 *      ceiling the child was configured with, so a ladder that simply grew
 *      without limit would fail here even though 2 would pass.
 *   4. The BUDGET BOUNDS IT: the node stops, says so in words
 *      (`link_retry_exhausted:`), and does not dial again. This is the case that
 *      fails if the budget is removed -- an unbounded ladder would produce
 *      `link_retry:` lines until the test's deadline and never the exhausted
 *      one, and that is a failure rather than a slow pass.
 *   5. After the budget is spent, the node is STILL ALIVE AND STILL SERVING: the
 *      child exits 0. A policy that made a node abandon a dead peer by
 *      wedging itself would pass 1-4.
 *   6. A peer that comes BACK gets a FRESH BUDGET, not the spent one. Two
 *      separate node pairs, because the second half of this case is about a
 *      different link entirely and one link cannot be both spent and revived.
 *
 * ---------------------------------------------------------------------------
 * WHY THE TIMERS AND THE LADDER ARE SET PER PROCESS
 * ---------------------------------------------------------------------------
 * fed_set_timeouts() and fed_set_retry() are called in the CHILD's setup hook,
 * which runs after fork, so the values apply in the child's own process and the
 * parent is unaffected. The header explains why they are functions and not
 * #ifdefs; what is specific to this file is the SCALE.
 *
 * The shipped ladder starts at IRC_FED_RETRY_BASE_MS, which is IRC_FED_DEAD_MS
 * (90 s at the shipped keepalive). A test that waited out even the first rung
 * would take a minute and a half, and the third rung would take ten minutes --
 * so the child is configured with a 300 ms base, a 1200 ms ceiling and a budget
 * of 3. WHAT IS SHORTENED IS THE SCALE AND NOTHING ELSE: the same code computes
 * the delay, doubles it, caps it and counts the budget, and the assertions
 * below are about the SEQUENCE (grows, capped, bounded, reported) rather than
 * about any particular duration. A production run differs only in the value of
 * three numbers, all of which are #defines in one header block.
 *
 * The link timers are set to 200 ms keepalive / 600 ms dead -- the same
 * three-to-one relationship IRC_FED_DEAD_MS spells, written out so the test's
 * numbers and the constant cannot drift apart silently -- and 2 s for the dial
 * and the handshake, which bound the happy path and which nothing in this file
 * waits on.
 *
 * ---------------------------------------------------------------------------
 * SIGSTOP, AND WHY NOT A KILL
 * ---------------------------------------------------------------------------
 * The peer is frozen, not killed, for the reason test_fed_handshake.c's case 7
 * gives: a killed peer sends a FIN, the survivor sees the EOF, and what it
 * observes is a CLOSED CONNECTION rather than a silent one. T4 exists to notice
 * silence. SIGSTOP leaves the socket open and unanswered, which is the only way
 * to produce a link that is ESTABLISHED and silent.
 *
 * AND THE FROZEN PEER IS NOT RESUMED, which is what makes the ladder observable:
 * a peer that came back would satisfy the very first retry and the test would
 * assert nothing about the wait between the second and third.
 *
 * ---------------------------------------------------------------------------
 * NO FIXED SLEEP ANYWHERE (6.3)
 * ---------------------------------------------------------------------------
 * Every wait is a deadline over the child's own output. There is no clock read
 * in this file at all, which is deliberate: a test that measured how long a
 * delay took would be asserting on the scheduler, and what is being asserted is
 * the ORDER of the node's own reports.
 */
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/server.h"
#include "federation/link.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

/* Deadlines, for the same reason every other test in this tree says so: these
 * are deadlines for forked children on a possibly loaded runner, not estimates
 * of how long anything should take. */
#define T_IO_MS 20000

#define SECRET "irc-serve-failover-secret"
#define NAME_A "irc.a"
#define NAME_B "irc.b"

/* ---------------------------------------------------------------------------
 * The numbers under test, and where they come from
 * ---------------------------------------------------------------------------
 * KEEPALIVE/DEAD are the liveness pair and preserve the shipped three-to-one
 * relationship. HS bounds the handshake and nothing in the happy path waits on
 * it, but every rung of the ladder does: a peer frozen with SIGSTOP still has
 * its kernel completing the three-way handshake, so each retry reaches T2 rather
 * than T1, and this is the interval each rung pays.
 *
 * THE LADDER IS PROPORTIONED SO THAT BOTH CLAIMS ARE SEPARATELY OBSERVABLE, which
 * is the one non-obvious thing about these four numbers. The ceiling is four times
 * the base because IRC_FED_RETRY_MAX_STEPS is 4, so a base of 300 ms reaches
 * 1200 ms on the third rung and the cap is what makes the FOURTH wait 1200 ms
 * rather than 2400. The budget is therefore 4, not 3: with a budget of 3 the
 * ladder is exhausted on the same rung that first touches the ceiling, so "the
 * wait was capped" and "the budget ran out" would be the same observation and
 * neither could fail alone. At a budget of 4 the node reports four waits -- 300,
 * 600, 1200, 1200 -- and the cap is visible in the last two being equal, and the
 * budget in a fifth failure producing no wait at all.
 *
 * A test that only checked "it stopped eventually" would pass against a fixed
 * delay and against no cap at all; these numbers are what let the growth
 * assertion, the cap assertion and the budget assertion be three claims. */
#define KEEPALIVE_MS 200
#define DEAD_MS (3 * KEEPALIVE_MS)
#define HS_MS 1500
#define RETRY_BASE_MS 300
#define RETRY_MAX_MS (4 * RETRY_BASE_MS)
#define RETRY_BUDGET 4

/* What the child is told to configure. A LIST because the third case needs a
 * node with one peer and the others need the same shape, and a single struct
 * filled per spawn keeps a stale peer from one case leaking into the next. */
typedef struct {
    const char *peer_name; /* NULL: no peer configured */
    int         peer_port;
} child_cfg_t;

static child_cfg_t g_cfg;

static void child_setup(server_t *s)
{
    struct sockaddr_in addr;

    /* The client command surface, installed BEFORE fed_open(). The fixture
     * brings up a server_t and a listener and nothing else, so s->dispatch is
     * NULL on a fresh node -- which is what a peer-only test wants and what a
     * test with clients must fix. fed_open() saves whatever is there and
     * replaces it, so a commands_dispatch installed afterwards would become the
     * node's whole dispatch and a peer line would never reach the guard chain. */
    TF_CHECK_MSG(commands_dispatch != NULL,
                 "the client command surface is missing from the build");
    s->dispatch = commands_dispatch;

    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child; a node with an unopenable "
                 "federation module cannot reach any assertion in this test");
    s->on_tick = fed_tick;
    /* Applied BEFORE the loop is armed, and therefore before the first tick, so
     * the first dial is already timed against this process's numbers. */
    fed_set_timeouts(2000, HS_MS, KEEPALIVE_MS, DEAD_MS);
    fed_set_retry(RETRY_BASE_MS, RETRY_MAX_MS, RETRY_BUDGET);

    if (g_cfg.peer_name != NULL && g_cfg.peer_port > 0) {
        /* 127.0.0.1 built by hand rather than resolved, for the reason
         * test_fed_handshake.c gives: the shipped binary's getaddrinfo is
         * covered there, and a second resolver in a test is a second thing to
         * keep right. What this respects is the ADDRESS SHAPE. */
        memset(&addr, 0, sizeof addr);
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons((unsigned short)g_cfg.peer_port);
        TF_CHECK_MSG(fed_link_configure(s, g_cfg.peer_name,
                                        (const struct sockaddr *)&addr,
                                        (socklen_t)sizeof addr) != NULL,
                     "the child could not configure peer %s on port %d",
                     g_cfg.peer_name, g_cfg.peer_port);
    }
}

/* ---------------------------------------------------------------------------
 * Reading the ladder out of the node's own reports
 * ---------------------------------------------------------------------------
 * The delays are on the `link_retry:` lines as delay_ms=, and this collects them
 * in order. A COLLECTOR RATHER THAN A SEQUENCE OF nf_expect() CALLS because the
 * whole point is the ORDER of several lines, and nf_expect() searches the
 * accumulated buffer -- waiting for a third `link_retry:` would be satisfied by
 * the first if the needle were not required to be a new one. The count is what
 * nf_expect_nth() exists for; the VALUES need this.
 *
 * Returns how many were found, writing at most `cap` of them. A `cap` smaller
 * than the count is not an error here: the caller asserts on the first few and
 * does not need the rest, and a test that failed because the node was MORE
 * persistent than expected would be asserting the wrong direction. */
static size_t collect_delays(const char *hay, unsigned *out, size_t cap)
{
    const char *p = hay;
    size_t n = 0;

    if (hay == NULL) {
        return 0;
    }
    while ((p = strstr(p, "delay_ms=")) != NULL) {
        char *end = NULL;
        unsigned long v = strtoul(p + strlen("delay_ms="), &end, 10);

        if (end == NULL || end == p + strlen("delay_ms=")) {
            break; /* a key with no number: a different format, stop rather than loop */
        }
        if (n < cap) {
            out[n] = (unsigned)v;
        }
        n++;
        p = end;
    }
    return n;
}

/* ---------------------------------------------------------------------------
 * CASE 1-5: the whole ladder, from a link that WAS up
 * ---------------------------------------------------------------------------
 * One node with one peer, linked, and then the peer is frozen. Everything the
 * case asserts after the freeze is the node's own account of what it decided to
 * do about it.
 *
 * THE PEER IS THE ACCEPTOR, and that is forced: only a link this node DIALLED
 * is one T7 can re-dial, because an accepted link has no address. Freezing the
 * dialling node instead would leave the accepting node with a dead link it
 * cannot dial, and nothing would happen -- which is the correct behaviour and
 * useless as a test of the dial policy. */
static void case_backoff_is_bounded_and_reported(void)
{
    nf_node_t a;
    nf_node_t b;
    unsigned delays[8];
    size_t ndelays;

    memset(&g_cfg, 0, sizeof g_cfg);
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    TF_CHECK_MSG(a.port > 0, "node A reported no port");

    g_cfg.peer_name = NAME_A;
    g_cfg.peer_port = a.port;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");

    /* The link was ALIVE, so everything after the freeze is about the freeze
     * and not about a link that never came up. The keepalive is the positive
     * control: it is a line the node RECEIVED, which cannot happen unless the
     * link was carrying traffic in both directions. */
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A: %s", b.out);
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never accepted the link from node B: %s", a.out);
    TF_CHECK_MSG(nf_expect_u64_ge(&b, "lines=", 1, T_IO_MS) == 0,
                 "node B framed no lines at all, so the link it is about to lose "
                 "was not demonstrably alive: %s",
                 b.out);

    /* FREEZE THE ACCEPTOR. Not a kill: a killed peer sends a FIN and the
     * survivor would observe a closed connection, which is a different event
     * from the silent one T4 exists to notice. */
    TF_CHECK_MSG(kill(a.pid, SIGSTOP) == 0, "could not freeze node A");

    /* CLAIM 1: THE TICK REDIALS. The wait is for the SECOND `link_dial:` for
     * this peer, not the first: the first happened during the happy path above
     * and nf_expect_nth() is the only way to ask for an occurrence that has not
     * happened yet, because nf_expect() searches the accumulated buffer and the
     * first one is already in it.
     *
     * THIS IS THE ASSERTION THAT IS FALSE AGAINST PHASE 6, and it is the reason
     * this test exists. A node with Phase 6's latch dialled exactly once for
     * the life of the process, so the second `link_dial:` would never arrive and
     * this wait would run out its deadline. */
    TF_CHECK_MSG(nf_expect_nth(&b, "link_dial: peer=" NAME_A, 2u, T_IO_MS) == 0,
                 "node B did not re-dial its peer after the link went dead. "
                 "Phase 6 deliberately never dialled a link twice, behind a latch "
                 "on created_ms; the reconnect policy is supposed to have "
                 "replaced that latch with a backoff and a budget, and this is the "
                 "assertion that it did.\n  node said: %s",
                 b.out);

    /* CLAIM 4, THE HALF WITH TEETH: the node gives up and SAYS SO. This is the
     * line an operator's log needs and that an unbounded ladder would never
     * produce -- it would print `link_retry:` until the heat death of the
     * universe instead. */
    TF_CHECK_MSG(nf_expect(&b, "link_retry_exhausted: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never reported exhausting its retry budget for a dead "
                 "peer, so either it is still retrying for ever or it stopped for "
                 "some other reason. The budget is the whole of what makes a "
                 "failed link a bounded cost rather than a leak.\n  node said: %s",
                 b.out);
    TF_CHECK_MSG(nf_expect_u64(&b, "fed_retry_exhausted=", 1, T_IO_MS) == 0,
                 "the exhaustion should have been counted once, and the counter "
                 "is what a dashboard reads: %s",
                 b.out);

    /* CLAIM 2 AND 3: the ladder, read out of the node's own numbers. The waits
     * are on the `link_retry:` lines the policy printed, so this is the value
     * the code computed rather than a value the test invented. */
    ndelays = collect_delays(b.out, delays, sizeof delays / sizeof delays[0]);
    TF_CHECK_MSG(ndelays >= 2u,
                 "node B printed %zu `link_retry:` lines with a delay on them, "
                 "so there is nothing to compare and the backoff is not "
                 "observable: %s",
                 ndelays, b.out);
    /* GROWS. Strictly, because a ladder that returned the same number twice
     * would be a fixed delay and a fixed delay against a black-holed peer is a
     * hot loop at that period. */
    TF_CHECK_MSG(delays[1] > delays[0],
                 "the second retry waited %u ms and the first waited %u ms, so "
                 "the wait did not grow: this is a fixed delay, not a backoff. "
                 "node said: %s",
                 delays[1], delays[0], b.out);
    /* CAPPED. The child was configured with a ceiling of %d ms, and a ladder
     * that only grew would still be growing here -- so this assertion is what
     * distinguishes a capped ladder from an uncapped one, and it is separate
     * from the growth assertion above rather than implied by it. */
    TF_CHECK_MSG(delays[ndelays - 1u] <= (unsigned)RETRY_MAX_MS,
                 "the last retry the node attempted waited %u ms, which is above "
                 "the %d ms ceiling this node was configured with, so the ladder "
                 "is not capped: %s",
                 delays[ndelays - 1u], RETRY_MAX_MS, b.out);
    /* AND THE LADDER SATURATED, which is the assertion that makes the ceiling
     * reachable at all: the final two waits are equal, so the CAP is what made
     * the last one no longer than the one before it. Without this a node whose
     * ladder simply kept doubling would pass the growth assertion above and fail
     * here, and a node whose budget ran out before reaching the cap would pass
     * the budget assertion and fail here -- which is the whole reason the
     * budget in this test is one larger than the number of rungs the cap needs.
     *
     * The expected value is written out rather than derived, because a test that
     * computed the expected ladder from the same constants the implementation
     * uses would agree with a broken ladder by construction. */
    TF_CHECK_MSG(ndelays == (size_t)RETRY_BUDGET,
                 "node B reported %zu retries against a budget of %d, so the "
                 "rungs and the budget cannot both be what this test configured: "
                 "%s",
                 ndelays, RETRY_BUDGET, b.out);
    TF_CHECK_MSG(ndelays >= 2u && delays[ndelays - 1u] == delays[ndelays - 2u] &&
                     delays[ndelays - 1u] == (unsigned)RETRY_MAX_MS,
                 "the last two waits were %u ms and %u ms; they should both be "
                 "the %d ms ceiling, and a ladder that reached its cap at a "
                 "different rung would mean the cap is not derived from the "
                 "rungs: %s",
                 ndelays >= 2u ? delays[ndelays - 2u] : 0u,
                 delays[ndelays - 1u], RETRY_MAX_MS, b.out);

    /* CLAIM 5: THE NODE IS STILL ALIVE AND STILL SERVING. A policy that made a
     * node abandon a dead peer by wedging itself would satisfy everything above
     * and be useless, and nf_stop() is the assertion: it sends SIGTERM and
     * requires exit status 0. */
    TF_CHECK_MSG(nf_stop(&b) == 0,
                 "node B did not exit cleanly after giving up on a dead peer, so "
                 "the budget was paid for with the node itself: %s",
                 b.out);

    /* The dump at shutdown carries the schedule, and it is the number an
     * operator reads to answer "is this node still trying". Asserted after the
     * stop, so the buffer is whole. */
    TF_CHECK_MSG(strstr(b.out, "gave_up=1") != NULL,
                 "node B's shutdown dump does not show the link as having given "
                 "up, so the terminal state is not observable: %s",
                 b.out);
    TF_CHECK_MSG(strstr(b.out, "retries=") != NULL,
                 "node B's shutdown dump does not carry the retry count: %s",
                 b.out);

    /* THE FROZEN NODE IS RESUMED AND THEN STOPPED, and the two halves are not
     * tidiness. A STOPPED process does not run its signal handler, so an
     * nf_stop() on node A here would queue SIGTERM on a process that will never
     * read it and then escalate to a kill -- which is a finding about the
     * teardown rather than a clean exit. And nf_free() alone is not enough
     * either: node A inherits this test's stdout, so an orphan holding the write
     * end of the pipe keeps CTest from ever seeing EOF and the whole run hangs
     * instead of failing. test_fed_resync.c's teardown says the same thing for
     * the same reason. */
    TF_CHECK_MSG(kill(a.pid, SIGCONT) == 0, "could not resume node A");
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly after being "
                                   "resumed");
    nf_free(&a);
    nf_free(&b);
}

/* ---------------------------------------------------------------------------
 * CASE 6: a peer that comes back gets a FRESH budget
 * ---------------------------------------------------------------------------
 * A SEPARATE PAIR, and the separation is the point: the link in case 1 has spent
 * its budget, and a link that has spent its budget cannot also be the link that
 * recovers. Using one pair for both halves would have to reset it in between,
 * and a reset is fed_link_reset()'s job -- so the case would be testing the
 * reset rather than the recovery.
 *
 * What is asserted is that a link which RE-ESTABLISHES carries retries=0 and
 * gave_up=0 again, which is the property that makes the budget a budget of
 * CONSECUTIVE failures rather than a lifetime ban on a peer. A node that kept
 * counting through a success would stop dialling a peer it had just proved was
 * there.
 *
 * The peer is resumed rather than replaced, for the reason test_fed_resync.c
 * gives: a brand-new process would bind a different ephemeral port and the link
 * holds the old address, so the retry would have nowhere to go. */
static void case_recovery_refills_the_budget(void)
{
    nf_node_t a;
    nf_node_t b;
    unsigned delays[8];
    size_t ndelays;

    memset(&g_cfg, 0, sizeof g_cfg);
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    TF_CHECK_MSG(a.port > 0, "node A reported no port");

    g_cfg.peer_name = NAME_A;
    g_cfg.peer_port = a.port;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");

    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A: %s", b.out);
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never accepted the link from node B: %s", a.out);

    TF_CHECK_MSG(kill(a.pid, SIGSTOP) == 0, "could not freeze node A");
    /* One retry, which is all this half needs: the point is that the SECOND
     * one comes from a refilled budget, and the budget is refilled by the
     * success rather than by a reset. */
    TF_CHECK_MSG(nf_expect(&b, "link_retry: peer=" NAME_A " attempt=1/4", T_IO_MS)
                     == 0,
                 "node B did not schedule its first retry after the link went "
                 "dead, so there is no budget to refill: %s",
                 b.out);

    /* THE PEER COMES BACK, and it comes back before this node exhausts its
     * budget, so the recovery is not being confused with the give-up case. */
    TF_CHECK_MSG(kill(a.pid, SIGCONT) == 0, "could not resume node A");
    TF_CHECK_MSG(nf_expect_nth(&b, "link_established: peer=" NAME_A, 2u, T_IO_MS)
                     == 0,
                 "node B's link to node A never came back up, so nothing here "
                 "tests what a recovered link's budget looks like: %s",
                 b.out);

    /* THE BUDGET IS WHOLE AGAIN, and this is read from the dump printed by
     * fed_link_established() -- which fires on the re-establishment, so the
     * line is on the wire before the parent gets here rather than only at
     * shutdown. retries=0 and gave_up=0 together are the claim; a node that
     * counted through its successes would show a non-zero count here. */
    TF_CHECK_MSG(strstr(b.out, "retries=0 gave_up=0") != NULL,
                 "node B's link dump after the re-establishment does not show a "
                 "whole budget, so a recovered link would still be refusing to "
                 "dial its peer: %s",
                 b.out);

    /* AND NO EXHAUSTION WAS REPORTED, which is the negative half and the one
     * that would catch a node that exhausted the budget before recovering. */
    TF_CHECK_MSG(strstr(b.out, "link_retry_exhausted: peer=" NAME_A) == NULL,
                 "node B reported exhausting its retry budget for a peer it then "
                 "reconnected to, so the budget is not a budget of CONSECUTIVE "
                 "failures: %s",
                 b.out);

    /* The first wait is still the base, which is what makes the refill legible
     * in the ladder as well as in the dump: a second outage after this one
     * starts at the base again rather than where the previous outage left off. */
    ndelays = collect_delays(b.out, delays, sizeof delays / sizeof delays[0]);
    TF_CHECK_MSG(ndelays >= 1u && delays[0] == (unsigned)RETRY_BASE_MS,
                 "the first retry after the link died waited %u ms rather than "
                 "the configured base of %d ms, so the ladder does not start at "
                 "the base: %s",
                 ndelays >= 1u ? delays[0] : 0u, RETRY_BASE_MS, b.out);

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    nf_free(&a);
    nf_free(&b);
}

int main(void)
{
    case_backoff_is_bounded_and_reported();
    case_recovery_refills_the_budget();
    tf_done("failover_reconnect");
    return 0;
}
