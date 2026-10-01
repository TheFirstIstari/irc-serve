/* test_sync_state.c -- the §4.3 SBURST resync being DRIVEN by a reconnect.
 *
 * docs/SERVER_DESIGN.md 4.3 ("On every link establishment the initiator sends
 * full state"), 4.3.1 (the five verbs, the BEGIN/COMMIT transaction, and
 * "a resync REPLACES state for that origin; it never merges"), 8 ("Link loss and
 * reconnect re-syncs channel state via SBURST"), and 2.2 (the per-channel remote
 * roster the resync installs into).
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS IS NOT, AND WHY IT IS STILL THE TEST FOR §8's SENTENCE
 * ---------------------------------------------------------------------------
 * Phase 6 proved BOTH HALVES either side of this gap and explicitly did not
 * claim the middle:
 *
 *   - fed_burst_sent()/fed_burst_applied() on a link that was just established,
 *     which is "a resync happens".
 *   - fed_link_reset() re-establishing a link and re-bursting, which is "a
 *     RECONNECT re-bursts" -- but driven by a test's own signal to a child that
 *     had no policy at all.
 *
 * What was missing is the seam: nothing in the NODE decided to reconnect, so the
 * two halves above were a node doing what it was told and never a node recovering
 * on its own. §8's sentence is a claim about the node's behaviour, and this test
 * asserts the node's behaviour: the link dies, nothing tells node B to do
 * anything, and B re-establishes and re-bursts by itself.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS ASSERTED, AND WHERE EACH CLAIM IS TAKEN FROM
 * ---------------------------------------------------------------------------
 *   1. The link comes back UP without being told to. This is the claim that is
 *      false against Phase 6, whose latch meant one dial for the life of the
 *      process, and it is why the file exists.
 *   2. The reconnect is followed by a SECOND burst on the far side, counted as a
 *      second `fed_burst_applied:` -- "resync on reconnect", not merely "a resync
 *      happened at some point". Phase 6's establishment-time burst is the FIRST
 *      one, so the count is what makes this the reconnect's burst and not the
 *      link's original.
 *   3. AND the resync is a REPLACEMENT, not a merge, which is the property that
 *      makes it a resync: a member who LEFT while the link was down is gone from
 *      the far side's roster after the reconnect, and a member who JOINED while
 *      the link was down is on it. Both are the things a merge cannot do, and
 *      both are asserted on the WIRE through a 353.
 *   4. The channel's ORIGIN and the member's holder are both still right after
 *      the replacement, because a resync that re-installed the roster under the
 *      wrong origin would pass 3 and leave the mesh unforwardable.
 *
 * ---------------------------------------------------------------------------
 * WHY THE STATE IS CHANGED *WHILE THE LINK IS DOWN*
 * ---------------------------------------------------------------------------
 * Claims 3 and 4 are what stop this from being a test of the retry policy alone.
 * A link that comes back and re-bursts an UNCHANGED state proves the burst ran;
 * it does not prove the burst was applied to anything, and a resync whose records
 * were all discarded would look identical from the sending side. So the case
 * makes the far side's world genuinely different while the link is down, and then
 * requires the resync to have carried the difference.
 *
 * The changes are made by REAL CLIENTS on node A, sending ordinary commands,
 * because that is the only way to produce state this node did not already have:
 * there is no back door in the protocol, and a test that synthesised a channel
 * record directly would be asserting on a struct rather than on the wire.
 *
 * ---------------------------------------------------------------------------
 * WHY THE LADDER IS SCALED DOWN
 * ---------------------------------------------------------------------------
 * The shipped retry base is IRC_FED_RETRY_BASE_MS = IRC_FED_DEAD_MS, which is
 * 90 s at the shipped keepalive. A test that waited that out would take a minute
 * and a half on a successful run and five minutes on a slow runner, which is a
 * slow test rather than a test. The child therefore calls fed_set_retry() with a
 * 300 ms base, exactly as test_failover_reconnect.c does.
 *
 * WHAT IS SHORTENED IS THE SCALE AND NOTHING ELSE. The code that is under test
 * here -- "the link died, the tick dialled again, the re-established link
 * re-bursts" -- contains no constant this test changes; the three numbers are
 * the WAIT, and the test is about what happens after the wait. The sibling test
 * is the one that asserts the ladder's shape (grows, capped, bounded), so between
 * them the policy is checked and its scale is not mistaken for it.
 *
 * ---------------------------------------------------------------------------
 * SIGSTOP, AND WHY THE PEER IS NOT KILLED
 * ---------------------------------------------------------------------------
 * For the reason test_fed_handshake.c's case 7 gives: a killed peer sends a FIN,
 * the survivor sees the EOF, and what it observes is a closed connection rather
 * than silence. T4 exists to notice silence. SIGSTOP leaves the socket open and
 * unanswered.
 *
 * The peer is RESUMED rather than replaced, for the reason test_fed_resync.c
 * gives: a new process binds a different ephemeral port and the link holds the
 * old address, so the retry would have nowhere to go.
 *
 * ---------------------------------------------------------------------------
 * NO FIXED SLEEP ANYWHERE (6.3)
 * ---------------------------------------------------------------------------
 * Every wait is a deadline over a child's output or over a socket. The one thing
 * that is NOT a wait is the window in which the link is down, and it is bounded
 * by an assertion rather than slept through: the case waits for the node to
 * REPORT the link dead, does its client work, and then waits for the link to come
 * back. Nothing assumes how long any of that takes.
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
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 20000

#define SECRET "irc-serve-sync-state-secret"
#define NAME_A "irc.a"
#define NAME_B "irc.b"

/* The liveness pair, the shipped three-to-one relationship written out so the
 * test's numbers and IRC_FED_DEAD_MS cannot drift apart silently. */
#define KEEPALIVE_MS 200
#define DEAD_MS (3 * KEEPALIVE_MS)

/* The retry SCALE, and the only thing this test shortens. See the header. The
 * ceiling is not interesting here (only one retry is needed) and the budget is
 * generous on purpose: a node that gave up during this case would leave the
 * second half with nothing to observe, and the give-up is test_failover_reconnect's
 * claim rather than this file's. */
#define RETRY_BASE_MS 300
#define RETRY_MAX_MS 1200
#define RETRY_BUDGET 8

/* The channel, and the two members whose membership changes while the link is
 * down. LEAVE is the one that proves REPLACE rather than MERGE: a merge would
 * keep them. */
#define CHAN "#SYNC"
#define NICK_EARLY "early"  /* joined BEFORE the link went down */
#define NICK_LATE "late"    /* joined WHILE it was down */
#define NICK_GONE "gone"    /* joined before, parted while it was down */

/* The nicks the case's own observers use. They are on node B, and they are never
 * on the channel, so their presence in a 353 would be a bug rather than a
 * coincidence. */
#define NICK_W1 "watch1"
#define NICK_W2 "watch2"

typedef struct {
    const char *peer_name; /* NULL: no peer configured */
    int         peer_port;
} child_cfg_t;

static child_cfg_t g_cfg;

static void child_setup(server_t *s)
{
    struct sockaddr_in addr;

    TF_CHECK_MSG(commands_dispatch != NULL,
                 "the client command surface is missing from the build");
    s->dispatch = commands_dispatch;
    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child; a node with an unopenable "
                 "federation module cannot reach any assertion in this test");
    s->on_tick = fed_tick;
    fed_set_timeouts(2000, 2000, KEEPALIVE_MS, DEAD_MS);
    fed_set_retry(RETRY_BASE_MS, RETRY_MAX_MS, RETRY_BUDGET);

    if (g_cfg.peer_name != NULL && g_cfg.peer_port > 0) {
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
 * A client, registered, with its own drain
 * ---------------------------------------------------------------------------
 * register_client() drains with a UNIQUE token rather than with "PONG", because
 * tc_expect() searches the ACCUMULATED buffer: a needle of "PONG" is satisfied by
 * the previous drain's answer, so every later wait on that connection would be a
 * wait against bytes already read. A token per call makes each drain its own
 * event. */
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
                 "%s got no PONG carrying its drain token, so the lines before it "
                 "have not been read yet",
                 nick);
}

/* Connect and send NICK and USER, asserting NOTHING about a reply.
 *
 * FOR A FROZEN NODE, and the reason it is a separate function rather than a
 * register_client() with the waits removed is that the difference is load-bearing:
 * on a RUNNING node, "the client registered" is a fact this test can establish
 * and should (a 001 that never arrives is a bug), and on a frozen one it is a fact
 * the node cannot yet report, so waiting for it would be waiting for a clock
 * rather than for behaviour. The assertions that the registration took effect are
 * made after the resume, by drain() and by the roster.
 *
 * The name is still validated by the node when it is resumed, so a %s that this
 * node would refuse is a case failure at the drain rather than a silent one. */
static void connect_for_later(test_client_t *c, int port, const char *nick)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "NICK send failed for %s", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "USER send failed for %s", nick);
}

/* Send a PING carrying `token` and wait for it back, which is how a case knows the
 * node has processed everything queued ahead of it on that connection.
 *
 * IT IS USED ONCE, at the point where node A has been RESUMED and its clients'
 * commands are being answered again -- the first assertion in the file that reads
 * a client on the far side of a freeze, and therefore the first place where "the
 * node has caught up" is a question this case has to ask. */
static void drain(test_client_t *c, const char *token)
{
    char line[128];

    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "the drain PING for %s failed to send",
                  token);
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG carrying the drain token %s, so anything asserted about "
                 "this client would be about the parent's read schedule",
                 token);
}

/* Everything this client has received SINCE `mark`. The buffer only grows and is
 * NUL-terminated, so an offset into it is a valid C string -- and it is how a
 * "this name is no longer in the roster" assertion avoids matching a roster this
 * same client asked for earlier. */
static const char *since(const test_client_t *c, size_t mark)
{
    const char *buf = tc_buffer(c);

    return (tc_received(c) > mark) ? buf + mark : "";
}

/* A BRAND-NEW client that asks for one channel's roster, and the offset at which
 * that roster begins.
 *
 * A NEW CLIENT EVERY TIME, and that is the load-bearing part rather than tidiness:
 * tc_expect() searches the whole accumulated buffer, so a 366 this client received
 * two commands ago satisfies a wait for the next one -- which would turn every
 * "this name is NOT in the roster" assertion into a statement about the parent's
 * read schedule. A connection that has never asked anything cannot be satisfied by
 * an earlier answer. `mark` is taken after the registration drain, so it points at
 * the first byte of the NAMES answer and not at the MOTD behind it. */
static size_t ask_names(test_client_t *c, int port, const char *nick,
                        const char *token)
{
    char line[128];
    size_t mark;

    register_client(c, port, nick, token);
    mark = tc_received(c);
    (void)snprintf(line, sizeof line, "NAMES " CHAN);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s's NAMES send failed", nick);
    TF_CHECK_MSG(tc_expect(c, " 366 ", T_IO_MS) == 0,
                 "%s's NAMES of " CHAN " was never terminated, so the roster is a "
                 "truncated list and a name missing from it proves nothing: %s",
                 nick, tc_buffer(c));
    return mark;
}

/* ---------------------------------------------------------------------------
 * THE CASE
 * ---------------------------------------------------------------------------
 * Two nodes, irc.b DIALS irc.a, and only the dialling node can reconnect -- an
 * accepted link has no address, so a node whose peer accepted its link has
 * nothing to retry and the case would prove nothing about the policy. The four
 * beats are, in order:
 *
 *   1. LINKED, and three members on the channel. This is the state a resync
 *      would carry, and it is what makes the later assertions about a CHANGE
 *      rather than about a first observation.
 *   2. THE LINK GOES, and while it is down one member parts and another joins.
 *   3. THE LINK COMES BACK, unprompted, and the far side re-bursts.
 *   4. The far side's roster is the NEW one, checked on the wire.
 */
static void case_reconnect_drives_a_resync(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t early;
    test_client_t gone;
    test_client_t late;
    test_client_t watch_before;
    test_client_t watch_after;
    size_t mark;

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

    /* --- beat 1: three members, and the far side holds all of them --------- */
    register_client(&early, a.port, NICK_EARLY, "reg-early");
    register_client(&gone, a.port, NICK_GONE, "reg-gone");
    TF_CHECK_MSG(tc_send(&early, "JOIN " CHAN) == 0, "the first JOIN failed");
    TF_CHECK_MSG(tc_expect(&early, " 366 ", T_IO_MS) == 0,
                 "the first JOIN never completed on the node that owns " CHAN);
    TF_CHECK_MSG(tc_send(&gone, "JOIN " CHAN) == 0, "the second JOIN failed");
    TF_CHECK_MSG(tc_expect(&gone, " 366 ", T_IO_MS) == 0,
                 "the second JOIN never completed");
    /* B LEARNED OF THEM over the link, and the wait is on B's own account: until
     * these lines exist B has no roster for the channel and everything after this
     * would be a test of a node with no state. */
    TF_CHECK_MSG(nf_expect(&b, "fed_sjoin: channel=" CHAN " member=" NICK_EARLY,
                           T_IO_MS) == 0,
                 "node B never learned that %s joined " CHAN ": %s",
                 NICK_EARLY, b.out);
    TF_CHECK_MSG(nf_expect(&b, "fed_sjoin: channel=" CHAN " member=" NICK_GONE,
                           T_IO_MS) == 0,
                 "node B never learned that %s joined " CHAN ": %s",
                 NICK_GONE, b.out);

    /* AND THE PRECONDITION, ON THE WIRE, FROM A FRESH CONNECTION. Every
     * negative assertion later is about a name that WAS in this roster, so a case
     * that measured a roster which never had it would pass by construction. */
    mark = ask_names(&watch_before, b.port, NICK_W1, "before");
    TF_CHECK_MSG(strstr(since(&watch_before, mark), NICK_EARLY) != NULL,
                 "%s is not in node B's roster for " CHAN " before anything "
                 "happens, so the rest of this case is measuring nothing: %s",
                 NICK_EARLY, since(&watch_before, mark));
    TF_CHECK_MSG(strstr(since(&watch_before, mark), NICK_GONE) != NULL,
                 "%s is not in node B's roster for " CHAN " before anything "
                 "happens: %s",
                 NICK_GONE, since(&watch_before, mark));
    tc_close(&watch_before);

    /* --- beat 2: the link goes, and the world changes without it ------------ */
    TF_CHECK_MSG(kill(a.pid, SIGSTOP) == 0, "could not freeze node A");
    TF_CHECK_MSG(nf_expect(&b, "link_dead: peer=" NAME_A " silent_ms=", T_IO_MS)
                     == 0,
                 "node B did not notice that node A had gone silent, so the rest "
                 "of this case would run against a link that is still up: %s",
                 b.out);

    /* THE CHANGES, made by real clients on the frozen node's own listener -- which
     * is still accepting, because SIGSTOP stops the process and not the kernel.
     * That is what lets this case produce state the mesh cannot have seen.
     *
     * A is frozen, so nothing reaches it, and every command below is answered by
     * nobody until it is resumed. tc_expect() therefore CANNOT be used here: it
     * would wait for numerics the frozen node will not send for the whole case.
     * The commands are sent and their effects are checked later, on the resumed
     * node, which is the honest way to assert on a node that was not running. */
    TF_CHECK_MSG(tc_send(&gone, "PART " CHAN) == 0,
                 "%s's PART could not be sent while node A was frozen", NICK_GONE);
    /* %s is registered WITHOUT waiting for 001, and that is forced by the
     * situation rather than chosen: the node is frozen, so no numeric will arrive
     * until the case resumes it, and a register_client() here would sit in
     * tc_expect() for the whole outage and time out. connect_for_later() therefore
     * asserts only that the CONNECTION was made -- which is a fact about this
     * process -- and leaves the registration unacknowledged, for the same reason
     * the PART above is unacknowledged.
     *
     * What makes this a real membership change rather than a pending command is
     * the drain() after the resume: a PONG on that connection is behind NICK, USER
     * and JOIN in node A's own queue, so the node has processed all three. */
    connect_for_later(&late, a.port, NICK_LATE);
    TF_CHECK_MSG(tc_send(&late, "JOIN " CHAN) == 0,
                 "%s's JOIN could not be sent while node A was frozen", NICK_LATE);

    /* --- beat 3: the link comes back, unprompted --------------------------- */
    /* CLAIM 1, and it is the claim Phase 6's latch made false: nothing signals
     * this node, and the link comes back anyway. The SECOND occurrence is asked
     * for with nf_expect_nth() because nf_expect() searches the accumulated
     * buffer and the first establishment is minutes old and already in it. */
    TF_CHECK_MSG(kill(a.pid, SIGCONT) == 0, "could not resume node A");
    TF_CHECK_MSG(nf_expect_nth(&b, "link_established: peer=" NAME_A, 2u, T_IO_MS)
                     == 0,
                 "node B's link to node A never came back up. A node with Phase "
                 "6's latch dials a link exactly once for the life of the "
                 "process, so nothing this test does after the freeze could "
                 "produce a second establishment.\n  node said: %s",
                 b.out);

    /* CLAIM 2: A SECOND BURST, on the RECEIVING side, which is the one that
     * matters -- a burst the sender composed is a burst the receiver may have
     * discarded, and the assertion that distinguishes them is the receiver's own
     * `fed_burst_applied:` line, which is printed only after the commit's counts
     * were asserted against what arrived. */
    TF_CHECK_MSG(nf_expect_nth(&b, "fed_burst_applied: peer=" NAME_A, 2u, T_IO_MS)
                     == 0,
                 "node B applied the resync from the reconnected link only %lu "
                 "time(s). A reconnect that re-establishes without re-bursting "
                 "leaves the mesh's view of the far side frozen at whatever it "
                 "was when the link dropped, and every client that had joined in "
                 "the meantime is invisible until something else resyncs it.\n"
                 "  node said: %s",
                 (unsigned long)tf_count(b.out, "fed_burst_applied: peer=" NAME_A),
                 b.out);

    /* NODE A HAS CAUGHT UP, which is the first moment in this case at which a
     * client on the far side of the freeze can be read at all. Without it the
     * roster assertions below would race node A's own processing of the PART and
     * the JOIN that were queued while it was stopped: the resync may legitimately
     * have carried the state as of some point in A's backlog, and a 353 answering
     * it would then be a statement about when the parent looked rather than about
     * what the resync did. A PONG behind both commands is A's own word that it has
     * processed them, and it is why this file has no fixed sleep where a sleep
     * would otherwise be the obvious substitute. */
    drain(&late, "drain-after-resume");

    /* CLAIM 3: THE RESYNC REPLACED THE STATE. Both directions, because a merge
     * fails each of them differently: a merge ADDS, so it would keep %s; a
     * resync that simply did not apply would keep both, and a resync that applied
     * only the new members would drop %s. */
    mark = ask_names(&watch_after, b.port, NICK_W2, "after");
    /* The member who joined DURING the outage is there, and it can only have got
     * there through the resync: no SJOIN could have crossed the link, because the
     * link was down for the whole of their session on this node. */
    TF_CHECK_MSG(strstr(since(&watch_after, mark), NICK_LATE) != NULL,
                 "%s joined " CHAN " while the link to node A was down and is not "
                 "in node B's roster after it came back. The only thing that could "
                 "have carried that state is the resync the reconnect drove.\n"
                 "  client saw: %s",
                 NICK_LATE, since(&watch_after, mark));
    /* The member who PARTED during the outage is gone. This is the assertion with
     * teeth: the roster is keyed by (origin, member) and an implementation that
     * installs the new records without the per-origin purge would pass the check
     * above and fail this one, and a user who left a channel would be visible in
     * it on every other node for ever. */
    TF_CHECK_MSG(strstr(since(&watch_after, mark), NICK_GONE) == NULL,
                 "%s parted " CHAN " while the link to node A was down and is STILL "
                 "in node B's roster after it came back. 4.3's resync REPLACES state "
                 "for an origin rather than merging it, and this is the assertion "
                 "that says so -- a merge keeps departed members for ever, because "
                 "a SPART is a per-member line and only a resync can say 'none of "
                 "them are here any more'.\n  client saw: %s",
                 NICK_GONE, since(&watch_after, mark));
    /* And the member who was there the whole time is still there, so the previous
     * assertion is about a REPLACEMENT and not about an emptied channel. A
     * resync that cleared the roster and failed to refill it would satisfy the
     * check above. */
    TF_CHECK_MSG(strstr(since(&watch_after, mark), NICK_EARLY) != NULL,
                 "%s never left " CHAN " and is not in node B's roster after the "
                 "resync, so the resync dropped the channel rather than replacing "
                 "its membership: %s",
                 NICK_EARLY, since(&watch_after, mark));

    /* CLAIM 4: THE ORIGIN SURVIVED THE REPLACEMENT, read from the node's own
     * account of the resync. 2.2 says the origin is what makes a channel
     * forwardable, and a resync that re-installed the roster under the wrong
     * origin would satisfy every wire assertion above and leave the channel
     * unroutable from every node but this one -- a divergence that no 353 can
     * show. It is not a 353 assertion because the origin is NOT on the wire in a
     * 353 (RFC 2812 3.3.5 renders bare nicknames), and this project stores the
     * attribution rather than displaying it; see channel.h's chan_remote_t. */
    TF_CHECK_MSG(strstr(b.out, "fed_burst_applied: peer=" NAME_A) != NULL &&
                     tf_count(b.out, "fed_burst_applied: peer=" NAME_A) == 2u,
                 "node B applied %lu resyncs from node A rather than the two this "
                 "case expects, so the assertions above were about an unknown "
                 "number of transactions: %s",
                 (unsigned long)tf_count(b.out, "fed_burst_applied: peer=" NAME_A),
                 b.out);
    TF_CHECK_MSG(nf_expect(&b, "chans=1", T_IO_MS) == 0,
                 "node B's second resync did not report the channel it installed, "
                 "so nothing was replaced and the roster assertions above were "
                 "about a resync that carried no channels: %s",
                 b.out);
    /* A channel is only forwarded if this node believes somebody else can reach
     * its origin, and after a link-down-and-up the node that OWNS the channel is
     * the one holding the route. The dump's `established=` count is the direct
     * observable for "the route came back". */
    TF_CHECK_MSG(nf_expect(&b, "link_dump: why=established name=" NAME_B " peers=1 "
                               "established=1",
                           T_IO_MS) == 0,
                 "node B's dump after the reconnect does not show an ESTABLISHED "
                 "link, so the route the resync installed into is not there and "
                 "the roster is stale by construction: %s",
                 b.out);

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    tc_close(&early);
    tc_close(&gone);
    tc_close(&late);
    tc_close(&watch_after);
    nf_free(&a);
    nf_free(&b);
}

int main(void)
{
    case_reconnect_drives_a_resync();
    tf_done("sync_state");
    return 0;
}
