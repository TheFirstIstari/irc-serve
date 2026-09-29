/* test_fed_loop.c -- a message from A reaches B once, and then the node goes
 * quiet.
 *
 * docs/SERVER_DESIGN.md 7/Phase 6, acceptance criterion 4: "a PRIVMSG from A
 * reaches B exactly once" and "a two-node ping-pong does not loop", plus 2.4's
 * three rules, which are the whole of what stops the second of those.
 *
 * ---------------------------------------------------------------------------
 * WHY "EXACTLY ONCE" AND "SETTLES" ARE SEPARATE ASSERTIONS
 * ---------------------------------------------------------------------------
 * They are different failures and a test that checked only the first would pass
 * against a mesh that loops:
 *
 *   exactly once   a client-visible count. A node that delivered a message twice
 *                  and then delivered it four more times while the test was not
 *                  looking satisfies "the text arrived" and satisfies "the text
 *                  arrived once" as well.
 *   settles        a node-visible count, read TWICE with a client-visible line
 *                  between the two reads. A loop is a message that keeps
 *                  circulating after the original has been delivered, and the
 *                  only way to see it without a timer is to read a counter, let
 *                  a line the client is watching go past -- which forces at least
 *                  one more loop iteration on any node that is looping -- and
 *                  read the counter again. Equal the second time means nothing
 *                  moved in between.
 *
 * WHY THE READS ARE `>=` AND NEVER `==`. federation/link.h says it and the
 * consequence is mechanical: T3 puts a keepalive PING on the link every 30 s and
 * every line a node RECEIVES is framed and counted in n_lines, so on a linked
 * node that number climbs with no client involved. An equality assertion is a
 * race against a timer. The counter this test READS TWICE is a federation one
 * that only a relay moves, which is why it is a settle check rather than a
 * `lines=` check.
 *
 * ---------------------------------------------------------------------------
 * THE SHAPE, AND WHY BOB JOINS FIRST
 * ---------------------------------------------------------------------------
 * bob JOINs on B first, which makes B the channel's origin (2.2: first server to
 * see a channel owns it). A therefore does NOT own it, and 3.1's non-owned
 * `message` row is the one that applies: write to local members AND forward to
 * the owner. That is the row that has to be exercised for criterion 4 to mean
 * anything -- with A as the origin the message would leave A over 3.1's
 * OWNED/`message` row instead, which is a different target set and a different
 * test.
 *
 * THE MESSAGE NOW BOUNCES, ONCE, AND THAT IS THE POINT OF THE AMENDED 3.1.
 * 3.1's owned/`message` row used to be "write to each local member; no forward
 * -- the origin already holds every member", and the reason was false: in a mesh
 * the origin holds those members in a roster, and a roster entry is not a
 * delivery path. The row is amended, so B -- the owner, holding the only member --
 * now forwards alice's message on to `servers[]` UNION the ESTABLISHED links,
 * which is A. A receives a message whose irc-serve-origin is A, and 2.4's
 * never-forward-own-origin rule drops it there.
 *
 * So the loop below is TWO experiments sharing one mesh, and the counters are
 * what separate them:
 *
 *   the SJOIN bounce  A relays alice's SJOIN to B; B relays the state change it
 *                     received onward to servers[] UNION the links, which is A;
 *                     A drops its own. This is the baseline, read before the
 *                     message, and it is already non-zero when the case starts.
 *   the MESSAGE bounce B forwards the PRIVMSG it was relayed back to A, and A
 *                     drops that too. It is EXPECTED, it is EXACTLY ONE, and
 *                     asserting it is a stronger claim than the old row allowed:
 *                     "the owner relays back once and 2.4 stops it there" is a
 *                     statement about the guard, where "the owner does not relay
 *                     back" was only a statement about the routing table.
 *
 * A node that delivered the message twice would pass the first count below and
 * is caught by the second and by the settle check, which is why the client count
 * is read again at the very end.
 *
 * ---------------------------------------------------------------------------
 * THE TWO-NODE FIXTURE
 * ---------------------------------------------------------------------------
 * nf_spawn_inline_named() forks a child that binds port 0 and reports the port,
 * so A's port only exists in the parent after A has already been forked. A
 * forked child inherits the parent's memory as of fork(), so the parent fills a
 * file-static global BETWEEN the two spawns: spawn A, set g_peer_port = A.port,
 * spawn B, whose setup() reads the already-populated global.
 *
 * ONE DIRECTION ONLY, because a node that configures BOTH ends of a pair both
 * dials, neither accepts, and the pair ends up with no link at all --
 * federation/link.h names that limitation and Phase 9 owns fixing it. A is
 * configured with no peer and the inbound FEDERATE's claim configures its link;
 * B is configured with the name AND A's address. Both directions of the
 * resulting link work, because a peer link is ONE socket used both ways.
 *
 * NO FIXED sleep() ANYWHERE (6.3): every wait is a deadline over nf_expect() or
 * tc_expect().
 */
#include <netinet/in.h>
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

#define T_IO_MS 15000

#define SECRET     "irc-serve-federation-secret-a"
#define NAME_A     "irc.a"
#define NAME_B     "irc.b"
#define CHAN       "#T"
#define NICK_A     "alice"
#define NICK_B     "bob"

/* The channel both nodes learn about. Deliberately NOT derived from a channel
 * name, because the topic is the one piece of shared state the two nodes cannot
 * have without an SJOIN carrying it, and 7/Phase 6's criterion here is the
 * roster. */
/* PRE-FORK STATE. The parent sets g_peer_port from A's reported port and spawns
 * B; B's setup() reads it. See the header for why this is the only ordering that
 * works. Zero means "configure no peer at all", which is how node A is set up. */
static int    g_peer_port;
static int    g_trace;

/* Keep the 30-second shipped keepalive out of the way of nothing in particular:
 * it is left at the shipped value deliberately, so the `lines=` lower bounds
 * below are the honest ones (a shorter interval would make them trivially true)
 * and a test that waited on one would take 30 s. Nothing here waits on a
 * keepalive. */
/* The node's own time seam, chained rather than replaced. 3.4 says the poll tick
 * drives time and node_main.c installs the federation tick HERE, visibly, rather
 * than delegating to fed_open(); a test that did not install it would have a
 * link that never dials and never dies, and would read that as a federation
 * failure. */
static void child_tick(server_t *s, uint64_t now_ms)
{
    fed_tick(s, now_ms);
}

static void child_setup(server_t *s)
{
    struct sockaddr_in sa;

    /* THE CLIENT COMMAND SURFACE, INSTALLED BEFORE fed_open().
     *
     * The fixture brings up a server_t and a listener and nothing else -- s->dispatch
     * is NULL on a fresh node, which is the honest Phase 2 state and is what every
     * peer-only test in this directory wants. A test with CLIENTS has to install the
     * surface itself, and it has to install it FIRST: fed_open() saves whatever
     * dispatch is there and replaces it with its own, so a commands_dispatch
     * installed after fed_open() would be the node's whole dispatch and the peer
     * path would never be reached.
     *
     * This is also the arrangement that makes 3's "one dispatch" claim testable
     * rather than asserted: the node's dispatch is fed_dispatch_hook, its inner is
     * commands_dispatch, and a peer line reaches the guard chain THROUGH the client
     * dispatch on the strength of src->kind. If that were two dispatch functions,
     * nothing in this file would notice -- which is why the claim is made where
     * both live rather than in a comment. */
    TF_CHECK_MSG(commands_dispatch != NULL,
                 "the client command surface is missing from the build");
    s->dispatch = commands_dispatch;

    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child; a node with an unopenable "
                 "federation module cannot reach any assertion in this test");
    s->trace = g_trace;
    s->on_tick = child_tick;
    fed_set_timeouts(1000, 2000, 30000, 90000);

    if (g_peer_port <= 0) {
        /* The accepting side. No peer is configured, and that IS the
         * configuration: the link is created when the inbound FEDERATE's claim
         * names it. See the header. */
        return;
    }
    {
        /* 127.0.0.1 built by hand rather than resolved, which is the honest
         * thing for a fixture to do: node_main.c's getaddrinfo is exercised by
         * test_fed_handshake.c's shipped-binary case, and a second resolver in a
         * test is a second thing to keep right. What this respects is the
         * ADDRESS SHAPE -- a struct sockaddr handed to fed_link_configure() --
         * and not the lookup. */
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = htons((unsigned short)g_peer_port);
        TF_CHECK_MSG(fed_link_configure(s, NAME_A, (const struct sockaddr *)&sa,
                                        (socklen_t)sizeof sa) != NULL,
                     "the child could not configure peer %s on port %d", NAME_A,
                     g_peer_port);
    }
}

/* Register a client and wait for the welcome, with a PING as the drain token so
 * every line the registration produced has been read before the case makes a
 * claim about what is or is not on the wire. */
static void register_client(test_client_t *c, int port, const char *nick)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "NICK send failed for %s", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "USER send failed for %s", nick);
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered", nick);
    TF_CHECK_MSG(tc_send(c, "PING :registered") == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(c, "PONG", T_IO_MS) == 0,
                 "%s got no PONG after registration, so the lines after it have "
                 "not been read yet",
                 nick);
}

/* The text, and a token in it. The token is what the exactly-once count looks
 * for, and it is a single word with no spaces, so a count of it in a client's
 * buffer is a count of DELIVERIES and not of words. */
#define TEXT  "the quick brown fox"
#define TOKEN "fox"

/* How many times `needle` appears in everything the client has received. */
static size_t times_seen(const test_client_t *c, const char *needle)
{
    const char *p = tc_buffer(c);
    size_t n = 0;
    size_t len = strlen(needle);

    while ((p = strstr(p, needle)) != NULL) {
        n++;
        p += len;
    }
    return n;
}

/* Read one node's federation counters into a small set of out-parameters, and
 * WAIT for the node to have published them at all.
 *
 * nf_find_u64() parses the LAST value the node has published, and a node
 * republishes only when a counter MOVES (that is the fixture's change-driven
 * rule, and it exists so a test can read a mid-run state). So a read of a
 * counter the node has never printed is -1, not 0, and a test that treated -1 as
 * a value would settle on a number that was never there. Hence the wait first.
 *
 * THE WAIT IS FOR THE KEY, NOT FOR A VALUE, and that is deliberate: this
 * function is used for the settle check as well as for the baseline, and a wait
 * for a value would be a wait for MOVEMENT -- which is exactly what the settle
 * check is asserting does not happen. A caller that needs to wait for a value
 * asks for it itself, with nf_expect_u64_ge(). */
typedef struct {
    uint64_t own_origin;
    uint64_t dup_drop;
    uint64_t hop_drop;
} relay_counters_t;

static void read_relay_counters(nf_node_t *n, const char *who,
                                relay_counters_t *out)
{
    TF_CHECK_MSG(nf_expect(n, "fed_own_origin=", T_IO_MS) == 0,
                 "%s never published its own-origin counter, so the settle check "
                 "below would be comparing numbers this node has not reported",
                 who);
    TF_CHECK_MSG(nf_find_u64(n, "fed_own_origin=", &out->own_origin) == 0,
                 "%s published fed_own_origin but it does not parse", who);
    TF_CHECK_MSG(nf_find_u64(n, "fed_dup_drop=", &out->dup_drop) == 0,
                 "%s published fed_dup_drop but it does not parse", who);
    TF_CHECK_MSG(nf_find_u64(n, "fed_hop_drop=", &out->hop_drop) == 0,
                 "%s published fed_hop_drop but it does not parse", who);
}

/* ---------------------------------------------------------------------------
 * THE CASE
 * ---------------------------------------------------------------------------
 */
static void case_message_arrives_once_and_settles(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;
    test_client_t bob;
    size_t bob_mark;
    relay_counters_t a_first;
    relay_counters_t b_first;
    relay_counters_t a_second;
    relay_counters_t b_second;
    uint64_t a_bounce;
    size_t b_deliveries;

    g_peer_port = 0;
    g_trace = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    TF_CHECK_MSG(a.port > 0, "node A reported no port");
    g_peer_port = a.port;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");

    /* The precondition, asserted before the case is worth anything: without a
     * link every assertion below would be satisfied by two nodes that never
     * spoke. B is the initiator, so B is where the dial is visible. */
    TF_CHECK_MSG(nf_expect(&b, "link_dial: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never dialled its configured peer");
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A");

    register_client(&alice, a.port, NICK_A);
    register_client(&bob, b.port, NICK_B);

    /* bob first, so B owns the channel and A is a forwarding participant. */
    TF_CHECK_MSG(tc_send(&bob, "JOIN " CHAN) == 0, "bob's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob's JOIN never completed on the node that owns the channel");
    TF_CHECK_MSG(tc_send(&alice, "JOIN " CHAN) == 0, "alice's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed on the node that does not own the "
                 "channel");

    /* Both nodes must have finished the JOIN exchange before the message, or the
     * counters this case settles on would still be moving for an unrelated
     * reason. A NAMES on each side is the drain: it cannot be answered until the
     * node has processed everything ahead of it. */
    TF_CHECK_MSG(tc_send(&alice, "NAMES " CHAN) == 0, "alice's NAMES send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's NAMES was never answered");
    TF_CHECK_MSG(tc_send(&bob, "NAMES " CHAN) == 0, "bob's NAMES send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob's NAMES was never answered");

    /* WAIT FOR THE JOIN EXCHANGE TO CONVERGE BEFORE READING ANYTHING, and the
     * waiting is done on the nodes' OWN lines rather than on the counters. A
     * counter read is a race for a second reason on top of the half-drained
     * buffer: the fixture republishes its stats line when a counter MOVES, so a
     * line carrying `fed_own_origin=0` exists from the first tick onwards and a
     * read of it succeeds long before the SJOINs have been exchanged. The two
     * lines below are printed only when the exchange has happened -- one when B
     * has alice in its roster, one when A has dropped its own SJOIN -- so
     * waiting for them makes the counter read a read of a settled node.
     *
     * THE JOIN ALREADY MADE THE PING-PONG, and this is the baseline the settle
     * check is measured from. A relayed alice's SJOIN onward; B, which owns the
     * channel, relayed a state change it received to servers[] UNION the
     * ESTABLISHED links -- which includes A; A received its own SJOIN back and
     * 2.4's never-forward-own-origin rule dropped it. So the counter is already
     * non-zero and already stopped, and the message below is a test of a node
     * that is NOT looping rather than a test that happens to produce one count.
     *
     * A second count here would be a defect and is asserted not to happen: the
     * only line that can move fed_own_origin is a relayed state change, and the
     * only ones in flight are the two SJOINs, so more than one means a duplicate
     * forward that the dedup store is standing in for. */
    TF_CHECK_MSG(nf_expect(&b, "fed_sjoin: channel=" CHAN " member=" NICK_A, T_IO_MS) ==
                     0,
                 "node B never put alice in its roster, so the cross-node exchange "
                 "this case rests on did not happen: %s",
                 b.out);
    TF_CHECK_MSG(nf_expect(&a, "fed_own_origin_drop: ", T_IO_MS) == 0,
                 "node A never dropped a message of its own origin, so the "
                 "two-node ping-pong never happened: %s",
                 a.out);
    /* And the VALUE, waited for as a floor rather than read: the drop line above
     * is printed by the guard, while the stats line carrying `fed_own_origin=1`
     * is published on the NEXT tick, so a read taken between the two would see
     * zero. A floor is also the honest wait -- "at least one message of this
     * node's own origin was dropped" is the property, and an exact value would
     * be an assertion about how many SJOINs the mesh exchanged. */
    TF_CHECK_MSG(nf_expect_u64_ge(&a, "fed_own_origin=", 1, T_IO_MS) == 0,
                 "node A never published fed_own_origin=1, so the value this case "
                 "settles on was read before the node had republished it: %s",
                 a.out);
    read_relay_counters(&a, "node A", &a_first);
    read_relay_counters(&b, "node B", &b_first);
    /* THE EXPECTED OWN-ORIGIN COUNT AFTER THE MESSAGE, and it is derived from
     * the measured baseline rather than written as a literal: the baseline is
     * however many bounces the SJOIN exchange produced on this mesh, and the
     * message adds exactly one more. Two places that both know the number is two
     * places to be wrong. */
    a_bounce = a_first.own_origin + 1u;
    TF_CHECK_MSG(a_first.own_origin >= 1,
                 "node A dropped no message of its own origin, so the two-node "
                 "ping-pong this case is about never happened: nothing was "
                 "relayed back to be dropped, and the message below would prove "
                 "nothing about 2.4's second rule");
    TF_CHECK_MSG(a_first.dup_drop == 0 && b_first.dup_drop == 0,
                 "the join exchange produced a duplicate drop (A=%llu B=%llu), so "
                 "the two SJOINs reached a node twice and the fan-out is "
                 "double-sending",
                 (unsigned long long)a_first.dup_drop,
                 (unsigned long long)b_first.dup_drop);

    /* THE MESSAGE. A -> B, from a user on A, into a channel A does not own, so
     * 3.1's non-owned `message` row applies: alice sees it locally and it is
     * forwarded to the owner. */
    bob_mark = tc_received(&bob);
    TF_CHECK_MSG(tc_send(&alice, "PRIVMSG " CHAN " :" TEXT) == 0,
                 "alice's PRIVMSG send failed");

    /* B's client sees the text, and this is the "exactly once" assertion: the
     * needle is the WHOLE message with its trailing CRLF, so it matches a
     * delivery and not a prefix of a longer one, and the count that follows is
     * over everything bob has received since the mark above -- which is the
     * moment before the message was sent.
     *
     * A count, not a presence. tc_expect() returning 0 would be satisfied by a
     * node that delivered the message twice and a third time while the test was
     * not looking, which is exactly what a loop looks like from inside the
     * window. */
    {
        char want[256];

        (void)snprintf(want, sizeof want, " :" TEXT "\r\n");
        TF_CHECK_MSG(tc_expect(&bob, want, T_IO_MS) == 0,
                     "the PRIVMSG from A never reached B's client.\n"
                     "  client saw: %s",
                     tc_buffer(&bob));
    }
    /* The author, from the prefix, which is what the C3 prefix parameter is for:
     * a peer that is handed a server name instead of a hostmask cannot tell a
     * client who wrote the message. */
    TF_CHECK_MSG(strstr(tc_buffer(&bob) + bob_mark, "!") != NULL,
                 "the relayed PRIVMSG carried no hostmask, so a client on B "
                 "cannot tell who wrote it: %s",
                 tc_buffer(&bob) + bob_mark);
    TF_CHECK_MSG(times_seen(&bob, TOKEN) == 1,
                 "B's client saw the text %lu times; 7/Phase 6's criterion is "
                 "EXACTLY once and a node that delivers it twice has a fan-out "
                 "or a dedup defect that a presence check would not catch",
                 (unsigned long)times_seen(&bob, TOKEN));

    /* THE NODE-SIDE DELIVERY LINE, waited for on the NODE rather than on the
     * client. It is the marker that says B has processed the relayed message,
     * which is what makes the reads below reads of a node that has finished with
     * it -- and it is a COUNTABLE line, so the settle check has a second, finer
     * instrument than the relay counters: a node that delivered the message once
     * and then again prints this again, and a CLIENT byte count would not
     * necessarily have caught the second before this point.
     *
     * There is no `msg:` line for a relayed message -- that one is the client
     * path's, printed by msg_verbs.c for a message a CLIENT sent, and a relayed
     * one arrives on a peer link and is fanned out from federation/verbs.c
     * instead. That is why the observable is `fed_message:` and why it exists. */
    TF_CHECK_MSG(nf_expect(&b, "fed_message: channel=" CHAN, T_IO_MS) == 0,
                 "node B never reported delivering the relayed PRIVMSG, so the "
                 "delivery the client saw is not the one this case is about: %s",
                 b.out);
    b_deliveries = tf_count(b.out, "fed_message: channel=" CHAN);

    /* WAIT FOR THE MESSAGE BOUNCE, so the settle check below is a read of a mesh
     * that has finished bouncing rather than a read that happened to land
     * before the bounce did. The bounce is B (the owner) forwarding the PRIVMSG
     * it was relayed back to A over servers[] UNION the ESTABLISHED links, and A
     * dropping it on 2.4's never-forward-own-origin rule -- and the counter is
     * waited for as a FLOOR above the baseline rather than as a value, because
     * the baseline itself is an assertion about how many SJOINs the mesh
     * exchanged and pinning it here would be a second place to be wrong.
     *
     * Without this the old assertion at the end of this function ("the message
     * did not have to be stopped by any of 2.4's rules") would pass RACIALLY:
     * A drops the bounce and publishes the counter on the NEXT tick, and a read
     * taken between the two sees the pre-bounce number, so a test asserting "no
     * bounce" passes against a mesh that bounced. Which is what it did. */
    TF_CHECK_MSG(nf_expect_u64_ge(&a, "fed_own_origin=", a_bounce, T_IO_MS) == 0,
                 "node A never published an own-origin drop above its baseline of "
                 "%llu, so B did not relay the PRIVMSG back to A at all. Under the "
                 "amended 3.1 an owner forwards a `message` to servers[] UNION the "
                 "ESTABLISHED links, so this case is no longer measuring the loop "
                 "guard: %s",
                 (unsigned long long)a_first.own_origin, a.out);

    /* THE SETTLE CHECK, and it is a read-and-compare rather than a timer.
     *
     * A client-visible line goes past in between: bob is sent a NAMES, whose 366
     * can only be produced after his node has processed every queued line, and
     * which is itself proof that the node is still turning its loop over. If
     * anything were circulating, the counters would move while that happened.
     *
     * EQUALITY BETWEEN THE TWO READS, on both the relay counters and the
     * delivery count. The counters are federation ones rather than `lines=`,
     * because `lines=` climbs on its own (see this file's header);
     * fed_own_origin, fed_dup_drop and fed_hop_drop are the three a circulating
     * message would move, and they are the three 2.4's rules guard with, so a
     * mesh that is not settling cannot leave them still. */
    TF_CHECK_MSG(tc_send(&bob, "NAMES " CHAN) == 0, "bob's second NAMES failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob's second NAMES was never answered, so the settle check has "
                 "no client-visible line to put between its two reads");
    read_relay_counters(&a, "node A", &a_second);
    read_relay_counters(&b, "node B", &b_second);
    TF_CHECK_MSG(tf_count(b.out, "fed_message: channel=" CHAN) == b_deliveries,
                 "node B delivered the relayed PRIVMSG %lu times and then again "
                 "while a client-visible line went past: the mesh is still "
                 "circulating it, and no hop ceiling has stopped it yet",
                 (unsigned long)b_deliveries);
    TF_CHECK_MSG(a_second.own_origin == a_bounce &&
                     a_second.dup_drop == a_first.dup_drop &&
                     a_second.hop_drop == a_first.hop_drop,
                 "node A's loop counters moved after the message settled: "
                 "own_origin %llu -> %llu (expected %llu), dup_drop %llu -> %llu, "
                 "hop_drop %llu -> %llu. A client-visible line went past in "
                 "between, so something is still circulating.",
                 (unsigned long long)a_first.own_origin,
                 (unsigned long long)a_second.own_origin,
                 (unsigned long long)a_bounce,
                 (unsigned long long)a_first.dup_drop,
                 (unsigned long long)a_second.dup_drop,
                 (unsigned long long)a_first.hop_drop,
                 (unsigned long long)a_second.hop_drop);
    TF_CHECK_MSG(b_second.own_origin == b_first.own_origin &&
                     b_second.dup_drop == b_first.dup_drop &&
                     b_second.hop_drop == b_first.hop_drop,
                 "node B's loop counters moved after the message settled: "
                 "own_origin %llu -> %llu, dup_drop %llu -> %llu, hop_drop "
                 "%llu -> %llu. A client-visible line went past in between, so "
                 "something is still circulating.",
                 (unsigned long long)b_first.own_origin,
                 (unsigned long long)b_second.own_origin,
                 (unsigned long long)b_first.dup_drop,
                 (unsigned long long)b_second.dup_drop,
                 (unsigned long long)b_first.hop_drop,
                 (unsigned long long)b_second.hop_drop);

    /* The client still sees it exactly once AFTER all of that, which is the
     * assertion the first count could not make: a delivery that happens late
     * would be past the first count and inside this one. */
    TF_CHECK_MSG(times_seen(&bob, TOKEN) == 1,
                 "B's client saw the text %lu times after the settle check, so a "
                 "delivery arrived late: a loop delivers on every pass and the "
                 "first count would not have seen the later ones",
                 (unsigned long)times_seen(&bob, TOKEN));

    /* AND THE BOUNCE IS EXACTLY ONE, which is the claim the amended 3.1 makes
     * and the old row could not: the owner relays the message back to where it
     * came from, 2.4's never-forward-own-origin rule stops it there, and the
     * settle check above says it did not start again. A hop drop would mean the
     * bounce was not stopped at all and only the ceiling ended it, which is a
     * different and worse defect -- a loop that happened to terminate -- so the
     * two are told apart rather than merged. */
    TF_CHECK_MSG(a_second.own_origin == a_bounce,
                 "node A dropped the PRIVMSG as its own origin %llu times, expected "
                 "%llu: the owner relayed the message back and the loop guard should "
                 "have stopped exactly that one bounce. More than one means a "
                 "forward that skipped the guard; the hop-drop count in the settle "
                 "check above is the other thing that could have ended it.",
                 (unsigned long long)a_second.own_origin,
                 (unsigned long long)a_bounce);

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    tc_close(&alice);
    tc_close(&bob);
    nf_free(&a);
    nf_free(&b);
}

int main(void)
{
    case_message_arrives_once_and_settles();
    tf_done("fed_loop");
    return 0;
}
