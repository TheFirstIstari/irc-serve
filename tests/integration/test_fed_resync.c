/* test_fed_resync.c -- what a node does when a peer goes away, and what it does
 * when one comes back.
 *
 * docs/SERVER_DESIGN.md 2.2 (origin is immutable; owner death is FAIL CLOSED --
 * a locally orphaned channel refuses origin-requiring actions with 437 and
 * re-linking a server of the same name resurrects it), 4.3 (`SQUIT` is in the
 * verb list; a burst is a replacement, never a merge), 2.3 (name uniqueness is
 * enforced at the handshake) and 9 (re-election is NOT started, and must not be
 * without re-opening 2.4 first).
 *
 * ---------------------------------------------------------------------------
 * WHAT IS ASSERTED, AND WHERE EACH CLAIM IS TAKEN FROM
 * ---------------------------------------------------------------------------
 *   1. A client on a node that does not own a channel gets 437 NAMING THE
 *      ORIGIN, once the link to that origin is down.  On the wire, from the
 *      client.  This is 2.2's fail-closed rule with the number in it.
 *   2. NAMES still answers after the drop, and the local members still see each
 *      other.  On the wire, from a client.  A node that emptied the channel on
 *      link-down would fail it; so would one that dropped the remote roster.
 *   3. A link that went down is NOT re-dialled.  From the node's own counters.
 *      This is the latch, and it is why the resurrection below is a test at all
 *      rather than a wait.
 *   4. Re-linking a server of the same name makes the channel work again: the
 *      same command, from the same client, on the same node, stops being
 *      refused -- and the forward it now takes is OBSERVED ON THE FAR SIDE, so
 *      "not refused" is not the same claim as "delivered".
 *   5. A link going down makes this node tell its other peers, and the peer
 *      purges what it learned THROUGH the departed node.  Observed on both
 *      nodes and on a client's 353.
 *   6. A purge is PER ORIGIN: a roster belonging to an unrelated origin
 *      survives a SQUIT for a different one.  This is the assertion that fails
 *      against the obvious implementation.
 *   7. A peer that says THIS NODE is gone is refused, counted, and does not cost
 *      this node its link.  Observed on a socket this test owns.
 *
 * ---------------------------------------------------------------------------
 * WHY THE FIXTURE HAS FOUR NODES, WHICH IS MORE THAN EVERY OTHER TEST HERE
 * ---------------------------------------------------------------------------
 * Claims 5 and 6 are about a node that has SOMEONE ELSE TO TELL, and that is the
 * whole of the difficulty. A link going down announces this node's departure to
 * the peers that are still up -- so a two-node mesh, where the link that died was
 * the only link, has nobody to tell and the announcement cannot exist. One extra
 * peer is the minimum, and that extra peer needs a peer of its own to make claim
 * 6 testable, so the smallest topology that reaches every claim here is:
 *
 *      irc.a ──── irc.b          a and b: a DIALS b.  b is FROZEN (see below).
 *        │
 *        └──────── irc.c ──── irc.d    a DIALS c, d DIALS c
 *
 *   - irc.a is the node whose link dies. It has two ESTABLISHED links (to b and
 *     to c), so it has exactly one peer left to tell, and that peer's name is
 *     deterministic rather than a race between two links going down at once.
 *   - irc.c is the node that receives the announcement and purges.
 *   - irc.d exists only to give irc.c a second origin. See the note on claim 6
 *     below for why an unrelated origin has to arrive over a DIFFERENT link.
 *
 * EACH PAIR IS CONFIGURED IN ONE DIRECTION, which federation/link.h names as this
 * phase's limitation: a node that configures both ends of a pair both dials and
 * neither accepts, and the pair ends up with no link at all. Here that falls out
 * naturally -- a, c and d all DIAL, and b accepts.
 *
 * ---------------------------------------------------------------------------
 * HOW A LINK IS MADE TO DIE WITHOUT KILLING A PROCESS
 * ---------------------------------------------------------------------------
 * SIGSTOP, not SIGKILL, and for the reason test_fed_handshake.c's case 7 gives:
 * a killed peer sends a FIN, the survivor sees the EOF, and the event it
 * observes is a closed connection rather than a silent one. SIGSTOP leaves the
 * socket open and unanswered, and an open-and-silent socket is the only way to
 * produce a link that is ESTABLISHED and silent, which is the condition T4
 * exists to notice.
 *
 * IT IS RESUMED AGAIN in the resurrection case rather than replaced by a fresh
 * process, and that is what makes the case deterministic. A brand-new irc.a would
 * bind a DIFFERENT ephemeral port (6.1), and the link that has to be re-dialled
 * still holds the old address -- there is no resolver in the event loop (3.4) and
 * no way to re-point one from outside. So: resume the frozen node, wait for IT
 * to notice its own side is dead (an observable on the other node), and only then
 * let the dialling node retry. Both waits are on observable output, so the
 * ordering is a fact rather than a hope about scheduling.
 *
 * ---------------------------------------------------------------------------
 * THE RETRY IS THE TEST'S, AND IT IS fed_link_reset() -- THE PHASE 9 SEAM
 * ---------------------------------------------------------------------------
 * C2 deliberately never dials a link twice: T7's condition is
 * server_link_t::created_ms, which is stamped at the dial and never cleared, and
 * the one function that clears it is fed_link_reset(). 7/Phase 9 owns the POLICY
 * -- when a failed link is worth another attempt, with what backoff, and whether
 * a peer that was ever established is dialled more eagerly than one that never
 * was. This test stands in for that policy with the seam itself: the parent
 * signals the child, and the child's tick calls fed_link_reset() on a link that
 * is down. So claim 3 ("no auto-redial") and claim 4 ("re-linking resurrects")
 * are asserted about the SAME node minutes apart, and the only difference between
 * them is whether the policy ran.
 *
 * THE SIGNAL IS SIGUSR1, whose handler sets a volatile sig_atomic_t and does
 * nothing else -- the only async-signal-safe thing a handler may do. The tick
 * reads and clears it. A shared-memory flag would need mmap, and a pipe would
 * need the tick to poll a descriptor, and both are more machinery for the same
 * answer. poll() returns EINTR and the loop retries, which is 3.4's documented
 * behaviour and is not new.
 *
 * NO FIXED sleep() ANYWHERE (6.3). Every wait is a deadline: nf_expect(),
 * tc_expect(), or a select() loop in the one case that owns a raw socket.
 */
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/server.h"
#include "federation/link.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define SECRET "irc-serve-federation-secret-a"
#define NAME_A "irc.a"
#define NAME_B "irc.b"
#define NAME_C "irc.c"
#define NAME_D "irc.d"
#define CHAN_A "#OWNEDA"  /* owned by irc.a: the origin that is squitted */
#define CHAN_D "#OWNEDD"  /* owned by irc.d: the origin that is not         */
#define NICK_A "alice"
#define NICK_B "bob"
#define NICK_C "carol"
#define NICK_D "dave"
#define NICK_E "erin"
/* The fresh observer a case attaches AFTER the event under test, so that a "this
 * name is NOT in the roster" assertion cannot be satisfied by a 366 this same
 * connection received earlier. See ask_names(). */
#define NICK_O "dana"
/* The rest of the fresh observers. irc.c has no local member of either channel in
 * this case -- it is purely the node that holds two other nodes' rosters -- so
 * these nicks are free, and being free is what makes each connection's first
 * 366 unambiguous. */
#define NICK_P "gail"
#define NICK_Q "hank"
#define NICK_R "iris"
/* The name the raw socket in the last case claims. A legal 2.4 tag value, and
 * not the node's own name: a claim of the node's own name is SELF_NAME, and that
 * case is about the guards that come after the handshake. */
#define PEER   "irc.x"

/* ---------------------------------------------------------------------------
 * THE TWO TIMERS, AND WHY THEY CANNOT BE THE SHIPPED ONES
 * ---------------------------------------------------------------------------
 * dead_ms is three keepalives (link.h: IRC_FED_DEAD_MS is 3 *
 * IRC_FED_KEEPALIVE_MS, and the multiplier is written as the expression so that
 * retuning one moves the other). Both are set here far below the shipped 30 s /
 * 90 s, and the shipped RELATIONSHIP is kept rather than a different one.
 *
 * BOTH HAVE TO MOVE, and that is the part worth stating: a received line is the
 * liveness signal, so on a mesh that exchanges nothing but handshake a 30 s
 * keepalive and a 750 ms dead threshold mean every link is declared dead three
 * quarters of a second after it comes up. An earlier version of this file did
 * exactly that, and the symptom was a fixture that looked like a routing bug:
 * the node under test noticed its own link to the announcer go silent in the
 * same 50 ms tick in which the announcement arrived, and never saw the SQUIT.
 *
 * The cost is a PING on every link every 250 ms, which is noise in a log and
 * lines on a node's `lines=` counter. Nothing here asserts on `lines=` (which
 * is why the counter is a lower bound for a test that does, per link.h's
 * "WHAT T3 COSTS A TEST"), and a case that wanted a PING it did not ask for
 * would be testing the timer rather than the behaviour. */
/* TEST_KEEPALIVE_MS and TEST_DEAD_MS are the pair this test EXISTS to exercise --
 * 250ms keepalive so a 750ms dead-link expiry is observable inside the test's own
 * deadline. They must stay small.
 *
 * TEST_DIAL_MS and TEST_HS_MS are the opposite: they bound the happy path and
 * nothing in this file waits on them. They were 1000 and 2000, which on a loaded
 * runner is 20 and 40 poll ticks -- not enough when a tick slips behind 30
 * competing suites. The product then does the right thing (times out, retries the
 * dial) and the test's deadline expires first, which reads as a federation bug.
 * The shipped defaults are IRC_FED_DIAL_TIMEOUT_MS (10s) and
 * IRC_FED_HS_TIMEOUT_MS (5s); these now match the handshake one and nothing in the
 * happy path waits either way. */
/* This file's dial and handshake budgets are 12000, not the 5000 the two-node
 * federation tests use, and the reason is the node count.
 *
 * The four-node case runs four poll loops plus four parent pumps plus CTest on a
 * GitHub runner that has TWO cores. A dial and a FEDERATE exchange that settle in
 * two ticks on an idle box can miss even a 5s budget there, and the failure reads
 * as "federation does not work", which is the most expensive kind of wrong.
 *
 * Node A also dials TWO peers in one tick here, which is the only place the
 * multi-dial path is exercised at all; the other three federation tests are one
 * dial per node. T7 latches created_ms before calling server_dial(), and although
 * the dial table reallocs, neither touches s->links, so the iteration the tick
 * holds is safe. The budget is the exposure, not a defect.
 *
 * WHY 12000 AND NOT 6000. Phase 6 deliberately does NOT auto-redial -- that is
 * Phase 9's policy -- so a node gets exactly ONE attempt at a peer. If that attempt
 * times out, the link sits at INIT for the rest of the test doing nothing and the
 * assertion deadline expires on a link that never got a second chance. The budget
 * therefore has to leave room for the whole of T_IO_MS (15000) to be spent on ONE
 * attempt, rather than for several, because there is only one.
 *
 * Getting this wrong twice is not hypothetical. The first attempt set the budget
 * EQUAL to the deadline, which is worse than no fix: a timeout then consumed the
 * entire window and the link could not establish however healthy it was. The second
 * set it to 6000 -- inside the deadline, but leaving half of it unused, so a
 * slow-but-successful dial was killed at 6s with nowhere left to succeed. Both
 * failed on CI with the same "link_established: peer=irc.a" timeout, on node C's
 * link to A and then node A's link to B. A moving target like that is the
 * signature of a budget, not of a defect.
 *
 * The margin is 3s, so a genuinely dead link still fails the assertion rather than
 * running to the harness deadline. */
#define TEST_KEEPALIVE_MS 250
#define TEST_DEAD_MS (3 * TEST_KEEPALIVE_MS)
#define TEST_DIAL_MS 12000
#define TEST_HS_MS 12000

/* ---------------------------------------------------------------------------
 * PRE-FORK STATE
 * ---------------------------------------------------------------------------
 * A forked child inherits the parent's memory as of fork(), and 6.2's harness is
 * two child processes with the parent configuring the second one from what the
 * first one reported. So the parent fills these between the spawns and the child
 * that comes next reads them. The list is a LIST because the four-node case
 * needs a node with two peers, and a second global for "the other peer" would be
 * a shape that only the last case needs. */
typedef struct {
    const char *name;
    int         port;
} peer_cfg_t;

static peer_cfg_t g_peers[2];
static size_t     g_npeers;
static int        g_trace;

/* Set by SIGUSR1 in the child, read and cleared by the tick. See the header. */
static volatile sig_atomic_t g_retry_link;

/* SIGUSR1's handler does one assignment and nothing else, which is the whole of
 * what a handler may do: it runs in the middle of the event loop, and anything
 * but a store to a sig_atomic_t could find the loop's own state half-updated. */
static void on_retry_signal(int signo)
{
    (void)signo;
    g_retry_link = 1;
}

static void child_tick(server_t *s, uint64_t now_ms)
{
    fed_tick(s, now_ms);
    if (g_retry_link == 0) {
        return;
    }
    g_retry_link = 0;
    /* PHASE 9'S POLICY, STOOD IN FOR. The tick is this test's own, so adding a
     * retry here does not put one into the node: fed_tick() below is unchanged
     * and still refuses to dial a link whose latch is set, which is what claim 3
     * asserts minutes before this branch runs.
     *
     * A link qualifies when this node was the one that dialled it (so it holds
     * the address a retry needs), it is in INIT (the state a link is left in by
     * a death, and the only state T7 will act on), and its latch is SET (so it
     * has been dialled and is not a link that is merely waiting for its first
     * attempt). The last condition is what stops this from dialling a link that
     * has never been tried. */
    for (size_t i = 0; i < server_link_count(s); i++) {
        server_link_t *link = server_link_at(s, i);

        if (link != NULL && link->initiator != 0 && link->state == (int)INIT &&
            link->created_ms != 0u) {
            fed_link_reset(s, link);
        }
    }
}

static void child_setup(server_t *s)
{
    struct sigaction sa;

    /* THE CLIENT COMMAND SURFACE, INSTALLED BEFORE fed_open(). The fixture
     * brings up a server_t and a listener and nothing else, so s->dispatch is
     * NULL on a fresh node -- which is what a peer-only test wants and what a
     * test with clients must fix. fed_open() saves whatever is there and replaces
     * it, so a commands_dispatch installed afterwards would become the node's
     * whole dispatch and a peer line would never reach the guard chain. */
    TF_CHECK_MSG(commands_dispatch != NULL,
                 "the client command surface is missing from the build");
    s->dispatch = commands_dispatch;

    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child; a node with an unopenable "
                 "federation module cannot reach any assertion in this test");
    s->trace = g_trace;
    s->on_tick = child_tick;
    fed_set_timeouts(TEST_DIAL_MS, TEST_HS_MS, TEST_KEEPALIVE_MS, TEST_DEAD_MS);

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_retry_signal;
    sigemptyset(&sa.sa_mask);
    /* SA_RESTART IS DELIBERATELY ABSENT, so the signal interrupts poll() and
     * the loop comes back through its own EINTR path (3.4) rather than being
     * resumed inside the syscall. The retry itself waits for the next tick
     * either way, so this is about not hiding the signal from the loop. */
    TF_CHECK_MSG(sigaction(SIGUSR1, &sa, NULL) == 0,
                 "the child could not install its SIGUSR1 handler, so it cannot "
                 "be told to retry a link and the resurrection case is "
                 "unreachable");

    for (size_t i = 0; i < g_npeers; i++) {
        struct sockaddr_in addr;

        /* 127.0.0.1 built by hand rather than resolved, which is the honest
         * thing for a fixture to do: node_main.c's getaddrinfo is exercised by
         * test_fed_handshake.c's shipped-binary case and a second resolver in a
         * test is a second thing to keep right. What this respects is the
         * ADDRESS SHAPE -- a struct sockaddr for fed_link_configure() -- and not
         * the lookup. */
        memset(&addr, 0, sizeof addr);
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons((unsigned short)g_peers[i].port);
        TF_CHECK_MSG(fed_link_configure(s, g_peers[i].name,
                                        (const struct sockaddr *)&addr,
                                        (socklen_t)sizeof addr) != NULL,
                     "the child could not configure peer %s on port %d",
                     g_peers[i].name, g_peers[i].port);
    }
}

/* Configure a node's peer list from scratch, for the parent to call between
 * spawns. Named rather than assigned inline because the two-element array is
 * the shape every call site wants and an inline initialiser at four call sites
 * is four chances to leave a stale entry in the slot the node does not use. */
static void set_peers(const peer_cfg_t *peers, size_t n)
{
    memset(g_peers, 0, sizeof g_peers);
    g_npeers = n;
    for (size_t i = 0; i < n && i < sizeof g_peers / sizeof g_peers[0]; i++) {
        g_peers[i] = peers[i];
    }
}

/* ---------------------------------------------------------------------------
 * Client helpers
 * ---------------------------------------------------------------------------
 * register_client() drains with a UNIQUE token rather than with "PONG",
 * because tc_expect() searches the ACCUMULATED buffer: a needle of "PONG" is
 * satisfied by the previous drain's answer and returns instantly, so every
 * later wait on that connection is a wait against bytes that were already read.
 * A token per call makes each drain its own event. */
static void register_client(test_client_t *c, int port, const char *nick,
                            const char *token)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "NICK send failed for %s", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "USER send failed for %s", nick);
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered", nick);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s's drain PING send failed", nick);
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "%s got no PONG carrying its drain token, so the lines before "
                 "it have not been read yet and nothing this test asserts about "
                 "this client would be about the node",
                 nick);
}

/* Everything this client has received SINCE `mark`, as a string. The buffer
 * only ever grows and is NUL-terminated at its end, so an offset into it is a
 * valid C string -- and it is how a "this name is no longer in the roster"
 * assertion avoids matching the name in a roster the same client asked for
 * before the event under test. */
static const char *since(const test_client_t *c, size_t mark)
{
    const char *buf = tc_buffer(c);

    return (tc_received(c) > mark) ? buf + mark : "";
}

/* Send a PING carrying `token` and wait for it to come back. A PONG is ordered
 * behind everything the node had already queued on this connection, so once the
 * token is in the buffer the node has finished processing the lines before it --
 * which is what makes "this reply is not in the buffer" a statement about the
 * node rather than about the parent's read schedule.
 *
 * THE TOKEN IS NOT "PONG", and that is not a style choice: tc_expect() searches
 * the ACCUMULATED buffer, so a needle of "PONG" is satisfied by the first drain
 * and every later drain returns instantly without reading a byte. */
static void drain(test_client_t *c, const char *token)
{
    char line[128];

    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "the drain PING for %s failed to send",
                 token);
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG carrying the drain token %s, so the lines before it "
                 "have not been read yet and nothing asserted about this client "
                 "would be about the node",
                 token);
}

/* A BRAND-NEW client, registered, that then asks for one channel's roster, and
 * the offset at which that roster begins in its buffer.
 *
 * A NEW CLIENT EVERY TIME, and that is the load-bearing part rather than tidiness.
 * tc_expect() searches the whole accumulated buffer, so a 366 this client
 * received two commands ago satisfies a wait for the next one and the wait
 * returns without reading a byte -- which turns every "this name is NOT in the
 * roster" assertion into a statement about the parent's read schedule. A
 * connection that has never asked anything cannot be satisfied by an earlier
 * answer, so the 366 below is always this roster's, and the bytes from `mark`
 * onwards are exactly the response.
 *
 * `mark` is taken after the registration drain, so it points at the first byte
 * of the NAMES answer and not at the MOTD behind it. */
static size_t ask_names(test_client_t *c, int port, const char *nick,
                        const char *chan, const char *token)
{
    char line[128];
    size_t mark;

    register_client(c, port, nick, token);
    mark = tc_received(c);
    (void)snprintf(line, sizeof line, "NAMES %s", chan);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s's NAMES send failed", nick);
    TF_CHECK_MSG(tc_expect(c, " 366 ", T_IO_MS) == 0,
                 "%s's NAMES of %s was never terminated, so the roster is a "
                 "truncated list and a name missing from it proves nothing: %s",
                 nick, chan, tc_buffer(c));
    return mark;
}

/* ---------------------------------------------------------------------------
 * CASE 1: the link drops, and the channel is locally orphaned
 * ---------------------------------------------------------------------------
 * Two nodes, which is the smallest mesh that can produce this at all: A owns #T
 * and B does not, so every origin-requiring action B takes for #T is B asking
 * the owner. Freezing A makes the owner unreachable and 2.2's rule fire.
 *
 * ALICE JOINS FIRST, and the order is load-bearing for the reason
 * test_fed_roster.c's header spells out: a JOIN on a node that has never heard
 * of a channel creates it there with that node as its origin, so whoever joins
 * first owns it. Alice first means A owns #T and B is a forwarding participant,
 * which is the only arrangement in which B has an origin it cannot reach. */
static void case_link_down_fails_closed(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;
    test_client_t bob;
    test_client_t carol;
    test_client_t observer;
    peer_cfg_t dial[] = { { NAME_A, 0 } };
    size_t mark;

    set_peers(NULL, 0);
    g_trace = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    TF_CHECK_MSG(a.port > 0, "node A reported no port");

    dial[0].port = a.port;
    set_peers(dial, 1);
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");

    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A");

    register_client(&alice, a.port, NICK_A, "reg-alice");
    register_client(&bob, b.port, NICK_B, "reg-bob");
    register_client(&carol, b.port, NICK_C, "reg-carol");

    TF_CHECK_MSG(tc_send(&alice, "JOIN #T") == 0, "alice's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed on the node that owns the channel");
    /* B LEARNED THE CHANNEL FROM A, and the wait is on B's own account of it:
     * until this line exists, B has no #T at all and the rest of the case would
     * be testing a node with no channel. */
    TF_CHECK_MSG(nf_expect(&b, "fed_sjoin: channel=#T member=" NICK_A, T_IO_MS) == 0,
                 "node B never learned about #T from node A, so B has no channel "
                 "to be orphaned from: %s",
                 b.out);
    /* And the ownership is B's to be wrong about: B records the channel with A
     * as its origin, which is what makes every action below an origin-requiring
     * one rather than a local write. */
    TF_CHECK_MSG(nf_expect(&b, "origin=" NAME_A " owned=0", T_IO_MS) == 0,
                 "node B does not believe %s owns #T, so nothing this case does "
                 "afterwards is a non-owner action at all: %s",
                 NAME_A, b.out);

    TF_CHECK_MSG(tc_send(&bob, "JOIN #T") == 0, "bob's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob's JOIN never completed on the node that does not own the "
                 "channel");
    TF_CHECK_MSG(tc_send(&carol, "JOIN #T") == 0, "carol's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&carol, " 366 ", T_IO_MS) == 0,
                 "carol's JOIN never completed");

    /* While the link is UP the same action is accepted and forwarded. This is
     * the control, and without it the 437 below would be satisfied by a node
     * that refuses the action for any reason at all -- including a bug that
     * refuses it always. The client is answered with the topic it already has
     * (331 when there is none, 332 when there is), which is 2.2's stated
     * behaviour for a FORWARD: the client is not told its request was rejected,
     * because the origin is going to carry it out. So the wire assertion is the
     * ABSENCE of 437, and the node's own line is the positive one. */
    mark = tc_received(&bob);
    TF_CHECK_MSG(tc_send(&bob, "TOPIC #T :before") == 0, "bob's TOPIC send failed");
    drain(&bob, "drain-before-drop");
    TF_CHECK_MSG(strstr(since(&bob, mark), " 437 ") == NULL,
                 "a TOPIC on a channel this node does not own was refused with 437 "
                 "while the owner was REACHABLE. authority_ok() is supposed to "
                 "FORWARD rather than refuse, and a node that refused here would "
                 "make the 437 after the drop mean nothing at all.\n  client saw: "
                 "%s",
                 since(&bob, mark));
    TF_CHECK_MSG(nf_expect(&b, "chan_state_forward: channel=#T verb=TOPIC origin="
                                NAME_A,
                           T_IO_MS) == 0,
                 "node B did not report forwarding the topic, so the control "
                 "above proved nothing about the forward path: %s",
                 b.out);

    /* FREEZE THE OWNER. Not a kill: a killed peer sends a FIN and the survivor
     * would observe a closed connection, which is a different event from a
     * silent one. What T4 exists to notice is an ESTABLISHED link that has
     * stopped talking, and SIGSTOP is the only way to produce one. */
    TF_CHECK_MSG(kill(a.pid, SIGSTOP) == 0, "could not freeze node A");

    TF_CHECK_MSG(nf_expect(&b, "link_dead: peer=" NAME_A " silent_ms=", T_IO_MS) == 0,
                 "node B did not notice that its owner had gone silent, so the "
                 "rest of this case would run against a link that is still up");
    /* The link is back in INIT with the address attached -- the state a Phase 9
     * reconnect starts from, and the state that would attract an auto-redial. */
    TF_CHECK_MSG(nf_expect(&b, "peer=" NAME_A " state=INIT fd=-1 initiator=1",
                           T_IO_MS) == 0,
                 "the dead link is not back in INIT with no descriptor and its "
                 "initiator flag kept: %s",
                 b.out);

    /* CLAIM 1: 437, NAMING THE ORIGIN, ON THE WIRE. Not a node log line: the
     * claim is about what a CLIENT is told, and 2.2's whole point is that the
     * refusal reaches the person who asked. The numeric, the channel, and the
     * origin name are three separate substrings because the first is the
     * protocol and the third is the part a reader would otherwise have to take
     * on trust. */
    mark = tc_received(&bob);
    TF_CHECK_MSG(tc_send(&bob, "TOPIC #T :after") == 0,
                 "bob's second TOPIC send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 437 ", T_IO_MS) == 0,
                 "a client on a node that cannot reach the origin of a channel it "
                 "is on was NOT refused with 437 after the link to that origin "
                 "went down. 2.2 is fail-closed: origin-requiring actions are "
                 "refused while the channel is locally orphaned.\n  client saw: %s",
                 tc_buffer(&bob));
    TF_CHECK_MSG(strstr(since(&bob, mark), "(" NAME_A ")") != NULL,
                 "the 437 did not NAME the origin (%s), so a client cannot tell "
                 "a refused action from a bad channel and an operator cannot tell "
                 "which link to repair. The numeric's text is the only place that "
                 "name is available.\n  client saw: %s",
                 NAME_A, since(&bob, mark));
    /* And the node said so in its own words, which is the half a test cannot get
     * from the wire: ORPHANED is a different diagnosis from a malformed request,
     * and only the node can distinguish them. */
    TF_CHECK_MSG(nf_expect(&b, "chan_state_refused: channel=#T verb=TOPIC origin="
                                NAME_A " state=ORPHANED numeric=437",
                           T_IO_MS) == 0,
                 "node B did not report the refusal as ORPHANED, so the 437 above "
                 "cannot be told apart from any other refusal: %s",
                 b.out);
    /* NOTHING WAS APPLIED. A node that logged the refusal and changed the topic
     * anyway would be the permanent divergence 2.2's single-writer rule exists
     * to prevent, and `chan_topic:` is the line the local write prints. */
    TF_CHECK_MSG(strstr(since(&bob, mark), "TOPIC #T :after") == NULL,
                 "the refused topic was applied locally and echoed to the "
                 "requester, so the refusal was cosmetic: %s",
                 since(&bob, mark));

    /* CLAIM 2: NAMES STILL ANSWERS, AND THE LOCAL MEMBERS STILL SEE EACH OTHER.
     * 2.2's locally-orphaned wording is precise: local members still see each
     * other, and only origin-REQUIRING actions are refused. A NAMES is a query,
     * and chan_verbs.h's decision 2 says an orphaned channel is listed and
     * named normally -- hiding it would be a worse answer than showing it. */
    mark = ask_names(&observer, b.port, NICK_O, "#T", "observer-names");
    /* A 353 AT ALL, so that the two name searches below are about a roster and
     * not about a 366 with an empty list. */
    TF_CHECK_MSG(strstr(since(&observer, mark), " 353 " NICK_O " = #T ") != NULL,
                 "the 353 for #T is not there at all, so this is a 366 with an "
                 "empty list rather than a roster: %s",
                 since(&observer, mark));
    /* The two LOCAL members are both named, which is the literal claim: local
     * members still see each other. Both nicks are searched as whole words with
     * a leading space, so neither can be satisfied by the other. */
    TF_CHECK_MSG(strstr(since(&observer, mark), NICK_B) != NULL,
                 "bob, a local member of #T on node B, is missing from B's own "
                 "roster after the drop: %s",
                 since(&observer, mark));
    /* AND THE REMOTE MEMBER IS STILL NAMED, which is a different property and the
     * one a link-down purge would break. A dead LINK is not a departed SERVER:
     * nothing about this fixture says irc.a is gone, so its member is still in
     * the roster and the roster is still served. See the note on servers[] in the
     * handoff: keeping the name is what stops chan_dispose_if_empty() from
     * freeing a channel whose origin may come back. */
    TF_CHECK_MSG(strstr(since(&observer, mark), NICK_A) != NULL,
                 "alice, who is on the node that went silent, is missing from "
                 "node B's roster. A link that went down is not a server that "
                 "departed: no SQUIT was received and nothing here is evidence "
                 "that %s is gone.\n  client saw: %s",
                 NAME_A, since(&observer, mark));

    /* CLAIM 3: NO AUTO-REDIAL, AND COUNTED HERE RATHER THAN IMMEDIATELY ABOVE.
     *
     * The placement is the lesson this assertion was taught, and it is worth
     * recording because the first version of it sat right after the link_dead
     * wait, where it passed against a node that re-dials on every tick: the tick
     * that would re-dial had not run yet, so the count was still 1 and the
     * assertion was a statement about the scheduler rather than about the node.
     *
     * IT IS HERE, after every client interaction the case performs, because each
     * of those is a round trip the node had to answer, and POLL_TICK_MS is 50 --
     * so a node that re-dials on its own has had many ticks in which to do it.
     * The latch is server_link_t::created_ms and fed_link_reset() is the only
     * thing that clears it, so the whole life of this node is ONE dial.
     *
     * The frozen peer is what makes the wait honest: it never answers, so
     * nothing this node sends can come back as a reply that would satisfy an
     * earlier wait, and a `link_dial` here can only have come from the tick. */
    TF_CHECK_MSG(tf_count(b.out, "link_dial: peer=" NAME_A) == 1,
                 "the dialling node dialled its peer %lu times; this phase dials "
                 "a link exactly once and the reconnect POLICY is Phase 9's, "
                 "behind fed_link_reset(). This is checked after every client "
                 "interaction above on purpose -- checked the moment the link "
                 "died it would pass against a node that re-dials every tick, "
                 "because that tick has not run yet.",
                 (unsigned long)tf_count(b.out, "link_dial: peer=" NAME_A));

    /* A is resumed before the teardown rather than killed: a STOPPED process
     * does not run its signal handler, so SIGTERM would sit queued on it and
     * nf_stop() would have to escalate to a kill -- which is a finding about the
     * teardown rather than a clean exit. */
    TF_CHECK_MSG(kill(a.pid, SIGCONT) == 0, "could not resume node A");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    tc_close(&alice);
    tc_close(&bob);
    tc_close(&carol);
    tc_close(&observer);
    nf_free(&a);
    nf_free(&b);
}

/* ---------------------------------------------------------------------------
 * CASE 2: the same channel, re-linked
 * ---------------------------------------------------------------------------
 * Same pair, same channel, same client, and the same command as case 1 -- with
 * the link up this time. That symmetry IS the assertion: 2.2 says a
 * locally-orphaned channel is resurrected by re-linking a server of the SAME
 * NAME, so anything that would also work with a different name, or with no link
 * at all, is not the property.
 *
 * "THE CHANNEL WORKS AGAIN" IS ASSERTED AS A ROUND TRIP rather than as an
 * absence of 437, because an absence is weak: a node that silently dropped every
 * origin-requiring action would pass it. So the client JOINs, the node forwards,
 * and the assertion that the forward was DELIVERED is on the FAR node's own
 * output. The far node applies an SJOIN, which is one of the two verbs
 * federation/verbs.c applies on a link that is not the channel's origin -- a
 * topic and a mode are deliberately not, because their handlers only take a
 * report from a link bearing the origin's name. That is a pre-existing property
 * of those two handlers and this case does not depend on it or change it.
 */
static void case_relink_resurrects(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;
    test_client_t bob;
    test_client_t erin;
    test_client_t observer;
    peer_cfg_t dial[] = { { NAME_A, 0 } };
    size_t mark;

    set_peers(NULL, 0);
    g_trace = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    dial[0].port = a.port;
    set_peers(dial, 1);
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");

    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A");
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");

    register_client(&alice, a.port, NICK_A, "reg-alice");
    register_client(&bob, b.port, NICK_B, "reg-bob");

    TF_CHECK_MSG(tc_send(&alice, "JOIN #T") == 0, "alice's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed on the node that owns the channel");
    TF_CHECK_MSG(nf_expect(&b, "fed_sjoin: channel=#T member=" NICK_A, T_IO_MS) == 0,
                 "node B never learned about #T, so it has nothing to resurrect: "
                 "%s",
                 b.out);
    TF_CHECK_MSG(tc_send(&bob, "JOIN #T") == 0, "bob's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob's JOIN never completed on the non-owning node");

    /* DROP IT. */
    TF_CHECK_MSG(kill(a.pid, SIGSTOP) == 0, "could not freeze node A");
    TF_CHECK_MSG(nf_expect(&b, "link_dead: peer=" NAME_A " silent_ms=", T_IO_MS) == 0,
                 "node B did not notice that its owner had gone silent");
    TF_CHECK_MSG(kill(a.pid, SIGCONT) == 0, "could not resume node A");

    /* A NEW CLIENT, because the claim is about a channel this node cannot route
     * to, and a client that was already on it is not the same state: JOIN is a
     * local membership fact and the authority check is asked before the
     * membership is touched, so a JOIN is refused for an unreachable origin even
     * though it would otherwise have applied locally. */
    register_client(&erin, b.port, NICK_E, "reg-erin");

    mark = tc_received(&erin);
    TF_CHECK_MSG(tc_send(&erin, "JOIN #T") == 0, "erin's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&erin, " 437 ", T_IO_MS) == 0,
                 "a JOIN of a channel whose origin is unreachable was accepted, "
                 "so this case has no orphaned state to come back from.\n  client "
                 "saw: %s",
                 since(&erin, mark));

    /* NOW WAIT FOR A TO NOTICE ITS OWN SIDE, BEFORE the retry. This is the step
     * that makes the case deterministic rather than a race: A's link to B is
     * still ESTABLISHED on A's side, and an inbound FEDERATE for a name that is
     * already ESTABLISHED is refused as DUPLICATE_LINK (fed_claim_accepted).
     * So a re-dial that arrives before A has noticed its link is dead would be
     * rejected, and a test that did not wait for A's own line would fail
     * intermittently on a loaded machine. */
    TF_CHECK_MSG(nf_expect(&a, "link_dead: peer=" NAME_B " silent_ms=", T_IO_MS) == 0,
                 "node A never noticed that its own side of the link was dead, so "
                 "the retry below would arrive at a node that still believes the "
                 "name is established and would be refused as a duplicate: %s",
                 a.out);

    /* THE RETRY, and nothing else changes: the policy is fed_link_reset(), which
     * clears the latch the previous half of this case proved was still set. */
    TF_CHECK_MSG(kill(b.pid, SIGUSR1) == 0, "could not signal node B to retry");
    /* The re-dial ARRIVES at A, and the parent waits for that on A rather than on
     * B. It is the only wait on A after the drop, so it is what gets A's output
     * read: a failure below can then say what A did with the re-dialled
     * connection instead of only that B saw a socket close. A prints one
     * client_connect per accept -- the peer, then alice, then the re-dial. */
    TF_CHECK_MSG(nf_expect_nth(&a, "client_connect: ", 3u, T_IO_MS) == 0,
                 "node A never accepted a re-dialled connection from the same "
                 "name, so the retry did not reach the node it was aimed at: %s",
                 a.out);
    /* AND A ACTED ON IT, waited on A rather than on B for the reason above: a
     * link dump is printed on every link event, so the third one for this peer
     * is A's own account of having done something -- accepted, or refused with
     * a reason -- and waiting for it is what pulls A's verdict into the parent's
     * buffer so that a failure below can report it. */
    TF_CHECK_MSG(nf_expect_nth(&a, "link: peer=" NAME_B, 3u, T_IO_MS) == 0,
                 "node A never acted on the re-dialled connection at all: %s",
                 a.out);
    /* THE SECOND ONE, counted. nf_expect() searches the accumulated buffer, so
     * a plain wait for `link_established: peer=irc.a` would be satisfied by the
     * one that already happened minutes ago and would return having read
     * nothing -- which is the shape of a test that passes without reaching the
     * state it is about. */
    TF_CHECK_MSG(nf_expect_nth(&b, "link_established: peer=" NAME_A, 2, T_IO_MS) == 0,
                 "the link to a server of the SAME NAME never came back up, so 2.2's "
                 "resurrection is not reachable: %s",
                 b.out);
    TF_CHECK_MSG(tf_count(b.out, "link_dial: peer=" NAME_A) == 2,
                 "node B dialled its peer %lu times; the second one is the retry "
                 "this case asked for and no more, and a third would be the "
                 "auto-redial Phase 9 owns",
                 (unsigned long)tf_count(b.out, "link_dial: peer=" NAME_A));

    /* CLAIM 4, PART ONE: the same command from the same client is no longer
     * refused. The 437 from the orphaned half is on erin's buffer already, so
     * the search is over the bytes since. */
    mark = tc_received(&erin);
    TF_CHECK_MSG(tc_send(&erin, "JOIN #T") == 0, "erin's second JOIN send failed");
    TF_CHECK_MSG(tc_expect(&erin, " 366 ", T_IO_MS) == 0,
                 "after the link to a server of the same name came back up, the "
                 "JOIN of that channel was still refused. 2.2 says re-linking the "
                 "same name resurrects the channel.\n  client saw: %s",
                 since(&erin, mark));
    TF_CHECK_MSG(strstr(since(&erin, mark), " 437 ") == NULL,
                 "the JOIN was both accepted and refused: %s", since(&erin, mark));

    /* CLAIM 4, PART TWO, and it is the half with teeth: the forward was
     * DELIVERED. A node that dropped the action instead of forwarding it would
     * have answered 366 all the same. */
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=#T member=" NICK_E " server="
                                NAME_B,
                           T_IO_MS) == 0,
                 "the origin never received erin's join, so the channel did not "
                 "come back -- the node simply stopped refusing and then threw "
                 "the request away, which is a different failure with the same "
                 "client-visible symptom.\n  node said: %s",
                 a.out);
    /* And the local half happened too, because a JOIN on a node that does not
     * own the channel is the documented exception to "an origin-requiring state
     * change applies nothing here": the membership is a local fact and the
     * origin decides what it means. */
    mark = ask_names(&observer, b.port, NICK_O, "#T", "observer-names-2");
    TF_CHECK_MSG(strstr(since(&observer, mark), NICK_E) != NULL,
                 "erin joined on node B and is not in node B's own roster, so the "
                 "membership did not happen locally either: %s",
                 since(&observer, mark));

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    tc_close(&alice);
    tc_close(&bob);
    tc_close(&erin);
    tc_close(&observer);
    nf_free(&a);
    nf_free(&b);
}

/* ---------------------------------------------------------------------------
 * CASE 3: a link dies, the node says so, and the purge is PER ORIGIN
 * ---------------------------------------------------------------------------
 * Four nodes, for the reason the header gives. irc.a has two peers, so when its
 * link to the frozen irc.b dies it has exactly one peer left to tell -- irc.c --
 * and the SQUIT it sends is observed there.
 *
 * WHAT IS ASSERTED, IN THE ORDER THE EVENTS HAPPEN:
 *   - irc.c holds a member of #OWNEDA reported by irc.a, and a member of #OWNEDD
 *     reported by irc.d. Both are REMOTE on c and both are real reports over a
 *     real link.
 *   - irc.a announces its departure to irc.c, and says how many peers it told.
 *   - irc.c applies it, and reports how many roster entries went and how many
 *     channels lost the name.
 *   - the departed origin's member is gone from irc.c's roster, on the wire.
 *   - the UNRELATED origin's roster is untouched, on the wire. This is the
 *     assertion with teeth: the obvious implementation of "a server is gone,
 *     drop what we learned through it" is a loop with no key, and it takes both
 *     rosters in the same pass.
 *
 * WHY THE UNRELATED ORIGIN HAS TO ARRIVE OVER A DIFFERENT LINK, which is why
 * irc.d exists. A roster entry is keyed by the server that REPORTED it (that is
 * what 4.3.1's "keyed by the burst origin, not by the member's own server"
 * freezes, and it is what SBURSTM's <server> field is *for* rather than *keyed*
 * by), so every entry irc.c holds about a channel reaches it over one of its two
 * links. A purge that removed "the whole channel" and a purge that removed "this
 * origin's share of it" are therefore indistinguishable for any single channel --
 * the only way to tell them apart is a second channel whose entries arrived over
 * the other link, and that is the whole of irc.d.
 *
 * WHAT THIS CASE DOES NOT COVER, because the honest limit belongs here rather
 * than in the report: it does NOT put two origins' entries in ONE channel, which
 * would be the strongest form. That state is not producible on a mesh without a
 * creation-race divergence -- only a node that believes it owns a channel sends
 * an SJOIN for it (3.1's non-owned row forwards to the owner and nowhere else),
 * so two origins reporting one channel means two owners, which is the gap
 * fed_in_channel() documents. So the guarantee proven here is per-origin across
 * channels, and a same-channel wipe is not excluded by these assertions.
 */
static void case_squit_is_observed_and_per_origin(void)
{
    nf_node_t a;
    nf_node_t b;
    nf_node_t c;
    nf_node_t d;
    test_client_t alice;
    test_client_t dave;
    test_client_t before;
    test_client_t after;
    test_client_t other;
    test_client_t last;
    peer_cfg_t a_peers[2] = { { NAME_B, 0 }, { NAME_C, 0 } };
    peer_cfg_t d_peers[1] = { { NAME_C, 0 } };
    size_t mark;

    /* b FIRST and configured with nothing: it is the node that is going to be
     * frozen, and it has to be listening before anything dials it. */
    set_peers(NULL, 0);
    g_trace = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");
    TF_CHECK_MSG(b.port > 0, "node B reported no port");

    /* c next, and still configured with nothing: it ACCEPTS both of its links
     * (from a and from d), so the parent can fill its peer list afterwards. A
     * node that configured both ends of a pair both dials and neither accepts,
     * and the pair ends up with no link at all -- federation/link.h names that
     * limitation and Phase 9 owns removing it. */
    set_peers(NULL, 0);
    TF_CHECK_MSG(nf_spawn_inline_named(&c, NAME_C, child_setup) == 0,
                 "could not spawn node C");
    TF_CHECK_MSG(c.port > 0, "node C reported no port");

    /* a, which dials BOTH b and c: this is the node with TWO peers, and the one
     * whose link to b is about to die. The two entries go in together because
     * the parent fills the whole list between the spawns, and a child only ever
     * reads the list as it stood when it was forked. */
    a_peers[0].port = b.port;
    a_peers[1].port = c.port;
    set_peers(a_peers, 2);
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    /* d, which dials c over the other of c's two links. That second link is the
     * whole reason d exists: it is how an origin the announcement will NOT name
     * gets an entry into c's state, and therefore how "the purge is per origin"
     * becomes an assertion instead of a hope. */
    d_peers[0].port = c.port;
    set_peers(d_peers, 1);
    TF_CHECK_MSG(nf_spawn_inline_named(&d, NAME_D, child_setup) == 0,
                 "could not spawn node D");

    /* THE ORDER OF THESE FIVE IS NOT COSMETIC. Every wait pumps ONE child's
     * output, and a child whose pipe nobody reads stops being read by the kernel
     * and then stops running -- node_fixture.c says so where it throttles the
     * stats line. So a wait on A that comes before any wait on C means that if C
     * is the one that is stuck, nothing has read C and the failure report for it
     * is "[fixture] ready" and nothing else. Interleaved: every node is pumped
     * before any single node's second wait, and a failure can be diagnosed from
     * the log the test prints.
     *
     * A and C are each other's pair, and D and C likewise, so the interleave
     * follows the links rather than the spawn order. */
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B: %s", a.out);
    TF_CHECK_MSG(nf_expect(&c, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node C never established its link to node A: %s", c.out);
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_C, T_IO_MS) == 0,
                 "node A never established its link to node C: %s", a.out);
    TF_CHECK_MSG(nf_expect(&d, "link_established: peer=" NAME_C, T_IO_MS) == 0,
                 "node D never established its link to node C: %s", d.out);
    TF_CHECK_MSG(nf_expect(&c, "link_established: peer=" NAME_D, T_IO_MS) == 0,
                 "node C never established its link to node D: %s", c.out);

    register_client(&alice, a.port, NICK_A, "reg-alice");
    register_client(&dave, d.port, NICK_D, "reg-dave");

    /* irc.a JOINS FIRST in #OWNEDA, so irc.a owns it and every SJOIN for it
     * leaves from irc.a -- which is what puts an irc.a-keyed entry in irc.c's
     * roster. irc.d does the same for #OWNEDD, over its own link to irc.c, so
     * the second entry in irc.c's state is keyed by a server the announcement
     * will not name. */
    TF_CHECK_MSG(tc_send(&alice, "JOIN " CHAN_A) == 0, "alice's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed on the node that owns %s", CHAN_A);
    TF_CHECK_MSG(tc_send(&dave, "JOIN " CHAN_D) == 0, "dave's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&dave, " 366 ", T_IO_MS) == 0,
                 "dave's JOIN never completed on the node that owns %s", CHAN_D);

    /* THE PRECONDITION, from irc.c's own account and for BOTH origins. Nothing
     * after this is about the purge if this is not true, and a case that
     * measured a purge over an empty roster would pass against a node that
     * purges nothing at all. */
    TF_CHECK_MSG(nf_expect(&c, "fed_sjoin: channel=" CHAN_A " member=" NICK_A
                               " server=" NAME_A,
                           T_IO_MS) == 0,
                 "node C never recorded %s's member, so there is nothing for the "
                 "announcement below to purge: %s",
                 CHAN_A, c.out);
    TF_CHECK_MSG(nf_expect(&c, "fed_sjoin: channel=" CHAN_D " member=" NICK_D
                               " server=" NAME_D,
                           T_IO_MS) == 0,
                 "node C never recorded %s's member, so the assertion that an "
                 "UNRELATED origin survives the purge has nothing to survive "
                 "with: %s",
                 CHAN_D, c.out);

    /* AND ON THE WIRE, before anything happens: the roster is served and alice is
     * in it. */
    mark = ask_names(&before, c.port, NICK_O, CHAN_A, "before-squit-names");
    TF_CHECK_MSG(strstr(since(&before, mark), NICK_A) != NULL,
                 "alice is not in node C's roster for %s before anything is "
                 "purged, so the purge below proves nothing: %s",
                 CHAN_A, since(&before, mark));

    /* FREEZE b, which is the peer whose link is about to die. */
    TF_CHECK_MSG(kill(b.pid, SIGSTOP) == 0, "could not freeze node B");

    /* THE ANNOUNCEMENT, read on irc.a, which is the node that has to make it.
     * `peers=1` is in the needle on purpose: irc.a has two links and one of them
     * is the one that died, so telling the dead one would be a line nobody
     * reads. */
    TF_CHECK_MSG(nf_expect(&a, "fed_squit_sent: self=" NAME_A " peers=1", T_IO_MS)
                     == 0,
                 "node A did not announce its departure to its remaining peer "
                 "when a link went down. Without it every other node keeps a "
                 "roster for a server it can no longer reach, until something "
                 "resyncs it, and driving resyncs is Phase 9's.\n  node said: %s",
                 a.out);
    /* And the link really is the one that died, so the announcement is a
     * consequence of the drop and not of something else in the tick. */
    TF_CHECK_MSG(nf_expect(&a, "link_dead: peer=" NAME_B " silent_ms=", T_IO_MS)
                     == 0,
                 "node A never reported the link to node B as dead, so whatever "
                 "sent that announcement is not the link lifecycle: %s",
                 a.out);

    /* AND IT IS APPLIED, on the node that received it, with the counts the purge
     * is supposed to produce: one roster entry gone and one channel that lost
     * the name from servers[]. */
    TF_CHECK_MSG(nf_expect(&c, "fed_squit: server=" NAME_A " chans=1 purged=1",
                           T_IO_MS) == 0,
                 "node C did not apply the departure announcement: %s", c.out);
    /* Exactly one, because a SQUIT is a state-destroying line and the guard chain
     * deduplicates it like anything else. Two would mean the forward and the
     * local handling were both applied. */
    TF_CHECK_MSG(tf_count(c.out, "fed_squit: server=" NAME_A) == 1,
                 "node C applied the announcement %lu times; it is one line and "
                 "the guard chain is supposed to see it once",
                 (unsigned long)tf_count(c.out, "fed_squit: server=" NAME_A));
    /* It was NOT a malformed line and NOT a deferred verb, which is what makes
     * "a peer is running a build that does not implement 4.3" the wrong
     * diagnosis for an operator reading these counters. */
    TF_CHECK_MSG(nf_expect_u64(&c, "fed_malformed=", 0, T_IO_MS) == 0,
                 "node C counted the announcement as malformed, so its counters "
                 "would point an operator at a version mismatch instead of at a "
                 "server that left: %s",
                 c.out);
    TF_CHECK_MSG(nf_expect_u64(&c, "fed_verb_deferred=", 0, T_IO_MS) == 0,
                 "node C counted the announcement as a verb it does not speak, "
                 "which is the answer for a peer running a NEWER build and not "
                 "for one running this one: %s",
                 c.out);

    /* THE DEPARTED ORIGIN'S MEMBER IS GONE, on the wire, from a connection that
     * never asked anything else. */
    mark = ask_names(&after, c.port, NICK_P, CHAN_A, "after-squit-names");
    TF_CHECK_MSG(strstr(since(&after, mark), NICK_A) == NULL,
                 "alice is still in node C's roster for %s after node C was told "
                 "that %s is gone. The purge is the whole point of the "
                 "announcement.\n  client saw: %s",
                 CHAN_A, NAME_A, since(&after, mark));

    /* CLAIM 6: THE UNRELATED ORIGIN'S ROSTER IS INTACT. Same node, same moment,
     * one command after the previous observation -- so nothing about the node's
     * state differs between the two assertions except which origin the entry is
     * keyed by. This is the assertion that fails against a purge with no key,
     * which would take this name out in the same pass as the other one. */
    mark = ask_names(&other, c.port, NICK_Q, CHAN_D, "unrelated-names");
    TF_CHECK_MSG(strstr(since(&other, mark), NICK_D) != NULL,
                 "dave -- a member of %s, reported by %s, a server nobody "
                 "announced -- is missing from node C's roster. A purge is PER "
                 "ORIGIN: it removes what this node learned THROUGH the departed "
                 "server and nothing else, and a node that dropped every remote "
                 "roster it held would pass everything above.\n  client saw: %s",
                 CHAN_D, NAME_D, since(&other, mark));

    /* AND THE ANNOUNCEMENT TRAVELLED ONWARD, which is 3.1's rule for a state
     * change and the reason a mesh larger than a star converges. It is read on
     * the node that was NOT the sender, so it cannot be satisfied by irc.c
     * having simply printed its own purge. */
    TF_CHECK_MSG(nf_expect(&d, "fed_squit: server=" NAME_A, T_IO_MS) == 0,
                 "the announcement did not reach the far side of irc.c. A SQUIT "
                 "is a state change, so 3.1 applies it locally and forwards it, "
                 "and a node two hops from the departure is the case that proves "
                 "the forward arm runs.\n  node said: %s",
                 d.out);
    /* irc.d owns the channel it was told about the departure in, and its own
     * roster is what the wrong implementation would have emptied. */
    TF_CHECK_MSG(nf_expect(&d, "chans=0 purged=0", T_IO_MS) == 0,
                 "the departure of %s changed something on a node that had never "
                 "heard of it beyond the announcement itself: %s",
                 NAME_A, d.out);

    /* NOTHING ON irc.c WAS LEFT BROKEN BY THE PURGE: it still answers, and the
     * channel the purge did not name is still served. A purge that freed the
     * channels irc.c was IN, or that took irc.c's own link down, shows up here.
     * A fresh connection again, because a 366 this case's earlier clients
     * already received is in irc.c's output as far as any search of it is
     * concerned. */
    mark = ask_names(&last, c.port, NICK_R, CHAN_D, "after-everything-names");
    TF_CHECK_MSG(strstr(since(&last, mark), " 353 " NICK_R " = " CHAN_D " ") != NULL,
                 "node C is no longer serving %s, the channel the purge did not "
                 "name, so the purge took more than the origin it was about -- or "
                 "freed a channel this node still had members in.\n  client saw: "
                 "%s",
                 CHAN_D, since(&last, mark));

    TF_CHECK_MSG(kill(b.pid, SIGCONT) == 0, "could not resume node B");
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&c) == 0, "node C did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&d) == 0, "node D did not exit cleanly");
    tc_close(&alice);
    tc_close(&dave);
    tc_close(&before);
    tc_close(&after);
    tc_close(&other);
    tc_close(&last);
    nf_free(&a);
    nf_free(&b);
    nf_free(&c);
    nf_free(&d);
}

/* ---------------------------------------------------------------------------
 * CASE 4: a peer says this node is gone
 * ---------------------------------------------------------------------------
 * The one line a peer can send that, taken literally, would have a listening
 * node delete itself from the mesh. A second node built from this code will not
 * send it -- 2.2 says origin is immutable and 2.3 makes a duplicate name
 * catastrophic -- so this test owns ONE END of the link, exactly as
 * test_fed_guards.c does: it listens, the node dials it, it answers with a real
 * FEDERATE, and from then on the test can put any line on that socket.
 *
 * THE HANDSHAKE IS REAL. The answer is a genuine FEDERATE with the right name,
 * the right secret and the right version word, and the node's link goes through
 * the real FSM. What is not real is the node on the far side, and the test says
 * so rather than pretending otherwise.
 *
 * THE ASSERTION IS ABOUT THE LINK SURVIVING, and the order is the point: the
 * wire assertion comes BEFORE the counter, so a node that refused the line and
 * then dropped the link anyway fails on the wire first. A counter assertion
 * placed first would pass against that fault, because a node that counted the
 * refusal and hung up on the peer would still have printed the number.
 */
static uint64_t now_ms_local(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000L);
}

static int peer_listen(int *port_out)
{
    struct sockaddr_in sa;
    socklen_t len = sizeof sa;
    int one = 1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        return -1;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0 ||
        listen(fd, 8) != 0 ||
        getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
        close(fd);
        return -1;
    }
    *port_out = (int)ntohs(sa.sin_port);
    return fd;
}

static int peer_accept(int listen_fd, int timeout_ms)
{
    uint64_t deadline = now_ms_local() + (uint64_t)timeout_ms;

    for (;;) {
        struct timeval tv;
        uint64_t left;
        fd_set rfds;
        int rc;

        if (deadline > now_ms_local()) {
            left = deadline - now_ms_local();
        } else {
            left = 0;
        }
        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);
        tv.tv_sec = (time_t)(left / 1000u);
        tv.tv_usec = (suseconds_t)((left % 1000u) * 1000u);
        rc = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            continue; /* EINTR from the harness's own signals */
        }
        if (rc == 0) {
            return -1;
        }
        return accept(listen_fd, NULL, NULL);
    }
}

/* Read until every needle has appeared in what has arrived, or the deadline
 * passes. All the needles in ONE call, because the buffer is local: a second
 * call starts from nothing and can never see what the first consumed. */
static int read_until(int fd, const char *const *needles, size_t nneedles,
                      int timeout_ms)
{
    char buf[4096];
    char seen[8192];
    size_t used = 0;
    size_t got_all = 0;
    uint64_t deadline = now_ms_local() + (uint64_t)timeout_ms;

    for (;;) {
        struct timeval tv;
        uint64_t left;
        fd_set rfds;
        ssize_t got;
        int rc;

        if (got_all == nneedles || used >= sizeof seen - 1u) {
            break;
        }
        if (deadline > now_ms_local()) {
            left = deadline - now_ms_local();
        } else {
            left = 0;
        }
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        tv.tv_sec = (time_t)(left / 1000u);
        tv.tv_usec = (suseconds_t)((left % 1000u) * 1000u);
        rc = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (rc <= 0) {
            break;
        }
        got = read(fd, buf, sizeof buf);
        if (got <= 0) {
            break;
        }
        if ((size_t)got >= sizeof seen - 1u - used) {
            got = (ssize_t)(sizeof seen - 1u - used);
        }
        memcpy(seen + used, buf, (size_t)got);
        used += (size_t)got;
        seen[used] = '\0';
        got_all = 0;
        for (size_t i = 0; i < nneedles; i++) {
            if (strstr(seen, needles[i]) != NULL) {
                got_all++;
            }
        }
    }
    return (got_all == nneedles) ? 0 : -1;
}

static int send_line(int fd, const char *line)
{
    size_t n = strlen(line);
    size_t off = 0;

    while (off < n) {
        ssize_t got = write(fd, line + off, n - off);

        if (got <= 0) {
            return -1;
        }
        off += (size_t)got;
    }
    return 0;
}

static void case_self_squit_refused(void)
{
    /* The node is irc.b; the socket below claims to be irc.x. */
    const char *const claim_needles[] = { ":irc.b FEDERATE irc.b ",
                                          " " SECRET " " IRC_SERVE_VERSION "\r\n" };
    peer_cfg_t dial[] = { { PEER, 0 } };
    const char *const post_needles[] = { ":irc.b PING " PEER " irc.b\r\n" };
    nf_node_t node;
    char line[512];
    char block[128];
    int listen_fd;
    int peer_fd;
    int port = 0;

    listen_fd = peer_listen(&port);
    TF_CHECK_MSG(listen_fd >= 0, "the test could not open a listening socket");
    dial[0].port = port;
    set_peers(dial, 1);
    g_trace = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&node, "irc.b", child_setup) == 0,
                 "could not spawn the node under test");

    peer_fd = peer_accept(listen_fd, T_IO_MS);
    /* The listener is the test's own and there is only ever one peer, so it is
     * closed here rather than at the end: leaving it open would let a second
     * dial be accepted by accident. */
    close(listen_fd);
    TF_CHECK_MSG(peer_fd >= 0, "the node never dialled the socket this test owns");

    /* Read its claim first, for the reason test_fed_handshake.c gives: without
     * it, "the link came up" would be satisfied by a node that never sent a
     * handshake. */
    TF_CHECK_MSG(read_until(peer_fd, claim_needles, 2, T_IO_MS) == 0,
                 "the node never sent a FEDERATE naming itself with the "
                 "configured secret, so nothing after this could mean anything");
    (void)snprintf(line, sizeof line,
                   ":irc.x FEDERATE irc.x 1700000000 %s %s\r\n", SECRET,
                   IRC_SERVE_VERSION);
    TF_CHECK_MSG(send_line(peer_fd, line) == 0,
                 "the test could not answer with a FEDERATE");
    TF_CHECK_MSG(nf_expect(&node, "link_established: peer=" PEER, T_IO_MS) == 0,
                 "the node never established its link, so the case below is "
                 "unreachable: %s",
                 node.out);

    /* CLAIM 7, PART ONE: the claim is refused and named as what it is. The
     * stamp is a real one -- the verb is deduplicated by the chain, and a case
     * that sent an UNTAGGED line would be exercising case A (the peer ORIGINATED
     * it, so the identity is minted) rather than the handler. */
    (void)snprintf(block, sizeof block,
                   "@irc-serve-origin=%s;irc-serve-epoch=%lu;irc-serve-id=%lu"
                   ";irc-serve-hops=%lu ",
                   PEER, 1700000000UL, 4242UL, 0UL);
    (void)snprintf(line, sizeof line, "%s:irc.x SQUIT irc.b :so long\r\n", block);
    TF_CHECK_MSG(send_line(peer_fd, line) == 0,
                 "the test could not send the SQUIT naming this node");
    TF_CHECK_MSG(nf_expect(&node, "fed_squit_refused: ", T_IO_MS) == 0,
                 "a peer that said this node is gone was not refused. 2.3 calls "
                 "two nodes with one name catastrophic and undetectable later, "
                 "and this is the announcement a re-joining node acts on.\n  node "
                 "said: %s",
                 node.out);
    TF_CHECK_MSG(nf_expect(&node, "reason=SELF_NOT_GONE", T_IO_MS) == 0,
                 "the refusal did not name its reason, so an operator cannot "
                 "tell it from any other refusal: %s",
                 node.out);
    /* AND IT WAS NOT A MALFORMED LINE, which is the difference between "a peer
     * running a build that does not implement 4.3" and "a peer running this
     * build and claiming this node is gone". The second is a finding. */
    TF_CHECK_MSG(nf_expect_u64(&node, "fed_malformed=", 0, T_IO_MS) == 0,
                 "the refusal was counted as a malformed line, so the node's own "
                 "counters would point an operator at a version mismatch: %s",
                 node.out);
    TF_CHECK_MSG(nf_expect_u64(&node, "fed_squit_self=", 1, T_IO_MS) == 0,
                 "the refusal was not counted on its own counter, so a node whose "
                 "peers keep disagreeing about whether it exists looks identical "
                 "to a node whose peers speak a different version: %s",
                 node.out);

    /* CLAIM 7, PART TWO, AND IT IS THE ONE WITH TEETH: THE LINK IS STILL UP.
     * Read on the socket, because "the link survived" is a claim about the wire
     * and a dump line would be a claim about the node's own opinion of itself.
     *
     * There is no PONG to wait for: an inbound PING on a peer link is not in
     * 4.3's vocabulary and the guard chain counts it as an unknown verb, which
     * is what the assertion below checks. So the node's OWN T3 keepalive is the
     * liveness evidence, at this fixture's 250 ms interval. The node queues a
     * probe every interval on an ESTABLISHED link and on no other, so a probe
     * arriving AFTER the refusal is the link, on the wire, still carrying
     * traffic in the outbound direction -- and the read begins after the refusal
     * has been observed, so a probe queued before it cannot satisfy the wait. */
    (void)snprintf(line, sizeof line, ":irc.x PING irc.b :are-you-there\r\n");
    TF_CHECK_MSG(send_line(peer_fd, line) == 0, "the test could not send a PING");
    TF_CHECK_MSG(read_until(peer_fd, post_needles, 1, T_IO_MS) == 0,
                 "the node sent no keepalive over the link it was just told it no "
                 "longer exists on. A peer that says this node is gone is either "
                 "broken or hostile, and neither of those is a reason to hang up "
                 "on the only route to half the network.");
    /* The same evidence in the inbound direction: the node read the line the
     * test sent afterwards and accounted for it, rather than having stopped
     * reading the socket. */
    TF_CHECK_MSG(nf_expect_u64(&node, "fed_unknown_verb=", 1, T_IO_MS) == 0,
                 "the node did not process the PING sent after the refused "
                 "SQUIT, so the link is not carrying traffic inbound either: %s",
                 node.out);

    /* And the node never reported the link as gone, on either of the two things
     * it would report. */
    TF_CHECK_MSG(strstr(node.out, "why=link_down") == NULL,
                 "the node took a link down after a peer announced its departure, "
                 "which is the failure 2.2 and 2.3 are both about: %s",
                 node.out);
    TF_CHECK_MSG(nf_expect_u64(&node, "fed_dead=", 0, T_IO_MS) == 0,
                 "the node declared the link dead after a refused SQUIT: %s",
                 node.out);

    /* THE REFUSAL WAS A REFUSAL AND NOT A NO-OP. The purge it refused would have
     * removed this node's own name from every channel's servers[], so the
     * observable for "nothing was purged" is that a channel it still holds is
     * still served. */
    {
        test_client_t client;

        register_client(&client, node.port, "frank", "reg-frank");
        TF_CHECK_MSG(tc_send(&client, "JOIN #Z") == 0, "frank's JOIN send failed");
        TF_CHECK_MSG(tc_expect(&client, " 366 ", T_IO_MS) == 0,
                     "a client could not join a channel on the node after a "
                     "refused SQUIT, so the refusal was not a no-op");
        TF_CHECK_MSG(strstr(node.out, "chan_state_refused") == NULL,
                     "the node refused a local JOIN, which means the refused "
                     "SQUIT did something to a channel this node owns: %s",
                     node.out);
        tc_close(&client);
    }

    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    if (peer_fd >= 0) {
        close(peer_fd);
    }
    nf_free(&node);
}

int main(void)
{
    case_link_down_fails_closed();
    case_relink_resurrects();
    case_squit_is_observed_and_per_origin();
    case_self_squit_refused();
    tf_done("fed_resync");
    return 0;
}
