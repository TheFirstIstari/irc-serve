/* test_fed_relay.c -- a node with ZERO local members still relays.
 *
 * docs/SERVER_DESIGN.md 7/Phase 6, acceptance criterion 5: "a node with zero
 * local members in the channel still relays that channel's SPRIVMSG to the
 * owner".
 *
 * ---------------------------------------------------------------------------
 * WHY THE WORDING IS NOW THE WORDING, AND WHY IT WAS NOT BEFORE
 * ---------------------------------------------------------------------------
 * C3 wrote this test against a client NOTICE and left a long note saying the
 * criterion's literal SPRIVMSG was unreachable. That note records a 3.1 row
 * that was WRONG, so it is replaced rather than deleted -- a reader who finds
 * the amendment and not the reasoning is exactly the reader who re-derives the
 * old rule.
 *
 * 3.1's `message` row for an OWNED channel used to read "write to each local
 * member; no forward -- the origin already holds every member". The reason was
 * false. In a mesh of three or more nodes the origin does not hold those members
 * as LOCAL members; it holds them in a remote roster, and a roster entry is not
 * a delivery path. An owner therefore forwarded nothing, the only path a
 * `message` took across a link was leaf -> owner, and a node that was neither
 * origin nor leaf NEVER RECEIVED a `message` to relay. 7/Phase 6's criterion 5
 * -- "a node with zero local members in the channel still relays that
 * channel's SPRIVMSG to the owner" -- was unreachable from the code as
 * specified: its subject is a relay, and there were no relays.
 *
 * The row is amended: an owned channel with a `message` writes to each local
 * member AND forwards to every peer in servers[ch] UNION the ESTABLISHED links,
 * which is the state-change row. A relay node in a mesh exists to carry a
 * message onward to servers the origin does not hold members on directly, and
 * with the old row there was no such thing for it to do.
 *
 * SO THE TEST IS NOW THE LITERAL CRITERION, with no workaround: the message is
 * a client's SPRIVMSG, the S-verb on the wire is SPRIVMSG, and the node that
 * cannot deliver it to anybody is the node that has to carry it.
 *
 * The `NOTICE` fallback C3 used is no longer needed and is not used. Its reason
 * was 2.2's arithmetic rather than taste -- PRIVMSG to a channel the sender is
 * not on is 404, so a client with no local membership could not ORIGINATE a
 * PRIVMSG into it, and a client that could was by definition a local member,
 * which is the thing the case is trying to be without. Under the amendment
 * neither half binds: the message originates on the OWNING node, where the
 * sender is a member, and the node under test RECEIVES it over the peer link,
 * where membership is not consulted at all.
 *
 * The non-owned client-originated `message` row -- a message from a client on a
 * node that does not own the channel -- is still routed, and test_fed_loop.c
 * covers it with a PRIVMSG from a member on a non-owning node. What is gone is
 * the excuse for a test that asserted something other than the criterion.
 *
 * ---------------------------------------------------------------------------
 * THE SHAPE, AND WHY IT IS TWO NODES
 * ---------------------------------------------------------------------------
 * A relay hop needs a node that is neither the origin nor a leaf, and a
 * three-node chain does not produce one for THIS criterion: the origin is the
 * node the criterion names as the forward's destination, so a third leaf would
 * forward straight past a middle node. The shape below puts the ORIGINATOR on
 * the owner and the relay underneath it, which is both the smallest arrangement
 * that produces a relay hop and the one the criterion describes:
 *
 *   A  the origin, and the only node with a member. It OWNS #T.
 *   B  knows the channel, holds a remote member and NO local member of it, and
 *      has nothing else to deliver to. This is the node under test.
 *
 * B receives the owner's SPRIVMSG over the link, delivers it to nobody, and
 * forwards it onward to the owner -- where 2.4's never-forward-own-origin rule
 * stops it, because the message's origin IS the owner. The bounce is the guard
 * working, and the case asserts it: a relay that forwards nothing and a relay
 * that is not a relay at all are the same observation from the client side.
 *
 * ---------------------------------------------------------------------------
 * HOW B GETS A CHANNEL WITH NO MEMBERS
 * ---------------------------------------------------------------------------
 * B never hears about #T from a local JOIN, because it has no local JOIN in it.
 * It hears about it from A's SJOIN, which arrives because A is the origin and
 * 3.1's owned `state-change` row forwards to servers[] UNION every ESTABLISHED
 * link -- and B is a linked peer. B's SJOIN handler creates the channel with the
 * SENDER as its origin (2.2: first server to see a channel owns it, and the
 * sender has a member) and records the member. So the state the case needs --
 * a known channel, a remote member, and zero LOCAL members -- is produced by the
 * federation path rather than arranged by hand, which is what makes it a test of
 * the path rather than of a field write.
 *
 * ---------------------------------------------------------------------------
 * THE FIXTURE
 * ---------------------------------------------------------------------------
 * nf_spawn_inline_named() forks a child that binds port 0 and reports the port,
 * so B's port only exists in the parent after B has been forked, and A has to
 * be told it. A forked child inherits the parent's memory as of fork(), so the
 * parent writes a file-static global between the spawns and the child that comes
 * next reads it.
 *
 * ONE DIRECTION PER PAIR, because a node that configures BOTH ends of a pair both
 * dials, neither accepts, and the pair ends up with no link at all --
 * federation/link.h names that limitation and Phase 9 owns fixing it. B is
 * configured with no peer (the inbound FEDERATE's claim configures its link) and
 * A with the name AND B's address. Both directions of the resulting link work,
 * because a peer link is ONE socket used both ways.
 *
 * A CLIENT ON B, WITH NO MEMBERSHIP, and that is deliberate: the case is about
 * what a node does with a message it has nobody to deliver to, and a node with
 * no client at all would let a bug that only manifests when a client is attached
 * hide. That client connects, registers and joins nothing.
 *
 * NO FIXED sleep() ANYWHERE (6.3): every wait is a deadline.
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

/* The log-injection set's two named members, octal so the C grammar cannot extend
 * the escape into the following `[` -- `\x1b[` would be one hex escape reading as
 * U+1B3 and the case would send something else entirely. */
#define ESC "\033"
#define BEL "\007"

/* The payload from #121's audit, and what it becomes once only the escapes go.
 * Written out as two literals rather than one with a filter applied in the test,
 * because a "stripped" expectation assembled by the same arithmetic that builds
 * the payload would agree with a wrong implementation. */
#define PAYLOAD       ESC "[2J" ESC "[31mbrb back in 5"
#define PAYLOAD_STRIPPED "[2J[31mbrb back in 5"

#define SECRET     "irc-serve-federation-secret-a"
#define NAME_A     "irc.a"
#define NAME_B     "irc.b"
#define CHAN       "#T"
#define NICK_A     "alice"
#define NICK_B     "bob"
#define NICK_C     "carol"

/* The channel both nodes learn about. Deliberately NOT derived from a channel
 * name, because the topic is the one piece of shared state the two nodes cannot
 * have without an SJOIN carrying it, and 7/Phase 6's criterion here is the
 * roster. */
/* PRE-FORK STATE. The parent sets g_peer_name/g_peer_port from B's reported name
 * and port and then spawns A; A's setup() reads both. See the header for why this
 * is the only ordering that works. A port of zero means "configure no peer at
 * all", which is how node B is set up -- B is spawned first and accepts.
 *
 * THE PEER'S NAME IS PRE-FORK STATE TOO, and not a constant, because which node
 * is the origin and which is the relay under test is the whole shape of the case
 * (see the header) and the two roles are not symmetric in the fixture. A
 * hardcoded name here would silently configure a link to a server nobody is
 * listening for, and the case would fail on a link that never forms rather than
 * on the routing it is about. */
static const char *g_peer_name;
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
    /* The SHIPPED defaults are IRC_FED_DIAL_TIMEOUT_MS (10s) and
     * IRC_FED_HS_TIMEOUT_MS (5s) in federation/link.h, and fed_set_timeouts() is a
     * per-process seam used only by tests -- so raising these here does not change
     * the product.
     *
     * They were 1000 and 2000. On a loaded runner -- a 2-core CI box, or 30+ copies
     * of this suite on one machine -- a poll tick slips far enough that a FEDERATE
     * exchange which completes in two ticks on an idle box misses its budget. The
     * product then does the correct thing (times out, and retries the dial) while
     * the test's 15s deadline expires first, and the failure reads as 'federation
     * is broken' rather than 'the fixture was too impatient'.
     *
     * 5000 is 100 poll ticks of POLL_TICK_MS, which is the shipped handshake
     * default. The happy path still completes in two ticks, so nothing waits
     * longer -- these budgets only bound the failure case. */
    fed_set_timeouts(5000, 5000, 30000, 90000);

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
        TF_CHECK_MSG(fed_link_configure(s, g_peer_name, (const struct sockaddr *)&sa,
                                        (socklen_t)sizeof sa) != NULL,
                     "the child could not configure peer %s on port %d", g_peer_name,
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

/* The text, and a token in it. The token is what the delivery count looks for,
 * and it is a single word with no spaces, so a count of it in a client's buffer
 * is a count of DELIVERIES and not of words. */
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
/* ---------------------------------------------------------------------------
 * THE CASE
 * ---------------------------------------------------------------------------
 *
 * THE ORDER IS THE POINT. Every precondition is asserted BEFORE the message is
 * sent, because each one is a statement about the state the case is about, and a
 * case that sends first and checks afterwards has already produced the outcome it
 * is trying to measure. In particular the zero-local-member fact is checked from
 * B's own log AND from a client attached to B, so it cannot be a fixture that
 * forgot a JOIN and quietly measured something else.
 */
static void case_zero_member_node_relays(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t carol;
    test_client_t bob;
    char want[256];
    size_t b_relays;

    /* B first, and it configures no peer: B is the node under test. */
    g_peer_name = NAME_A;
    g_peer_port = 0;
    g_trace = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");
    TF_CHECK_MSG(b.port > 0, "node B reported no port");
    /* Then A, which dials B and owns the channel. The parent writes the port
     * between the two forks. */
    g_peer_name = NAME_B;
    g_peer_port = b.port;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");

    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A");

    register_client(&carol, b.port, NICK_C);
    register_client(&bob, a.port, NICK_B);

    /* bob JOINs on A, which therefore OWNS the channel -- and 3.1's owned
     * `message` row is the AMENDED one, so A forwards the message below to B
     * even though A holds a local member of its own. B learns about the channel
     * from the SJOIN alone: carol joins nothing, ever. */
    TF_CHECK_MSG(tc_send(&bob, "JOIN " CHAN) == 0, "bob's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob's JOIN never completed on the node that owns the channel");

    /* THE PRECONDITION, and it is the whole case: B holds the channel, B has a
     * remote member, and B has NO LOCAL MEMBERS. The `local=0` is B's own
     * account of its local membership count at the moment it recorded bob, which
     * is the number 3.1's forward arm must NOT be gated on. */
    TF_CHECK_MSG(nf_expect(&b, "fed_sjoin: channel=" CHAN " member=" NICK_B
                                  " server=" NAME_A " flags=1 local=0 remote=1 "
                                  "origin=" NAME_A " owned=0",
                           T_IO_MS) == 0,
                 "node B did not record #T with a remote member from %s and NO "
                 "local members, which is the state this case is about: %s",
                 NAME_A, b.out);
    /* And the same fact from a client attached to B rather than from B's log:
     * carol asks for the roster and B answers with bob and not with carol. If B
     * had a local member in the channel, the local write would be the reason the
     * message travelled and the case would be measuring nothing. */
    TF_CHECK_MSG(tc_send(&carol, "NAMES " CHAN) == 0, "carol's NAMES send failed");
    TF_CHECK_MSG(tc_expect(&carol, " 366 ", T_IO_MS) == 0,
                 "carol's NAMES was never answered");
    TF_CHECK_MSG(strstr(tc_buffer(&carol), " 353 " NICK_C " = " CHAN " " NICK_C) ==
                     NULL,
                 "carol is a member of #T on node B, so the node under test has a "
                 "local member and this case is not measuring what it claims to");

    /* THE MESSAGE. A client's SPRIVMSG, from the OWNING node, into a channel the
     * node under test knows and holds nobody in. This is the literal criterion
     * and the literal verb; under the pre-amendment 3.1 it never crossed the
     * link at all, because an owner forwarded nothing. */
    (void)snprintf(want, sizeof want, "PRIVMSG " CHAN " :" TEXT);
    TF_CHECK_MSG(tc_send(&bob, want) == 0, "bob's PRIVMSG send failed");

    /* The owner sees his own message exactly once: PRIVMSG excludes nobody, so
     * the sender is in the audience (RFC 2812 3.3.1), and this is the count a
     * second copy would break -- whether it came from the relay bouncing it back
     * or from a double forward. */
    (void)snprintf(want, sizeof want, " :" TEXT "\r\n");
    TF_CHECK_MSG(tc_expect(&bob, want, T_IO_MS) == 0,
                 "the PRIVMSG never reached the sender on the owning node, so the "
                 "local half of the amended 3.1 row did not happen.\n"
                 "  client saw: %s",
                 tc_buffer(&bob));
    TF_CHECK_MSG(times_seen(&bob, TOKEN) == 1,
                 "the owner's client saw the text %lu times; a message is "
                 "delivered once or not at all, and the owner writing it and a "
                 "peer echoing it back are two different deliveries",
                 (unsigned long)times_seen(&bob, TOKEN));

    /* IT CROSSED THE LINK. B is the node under test and this is its own account
     * of receiving it, with a count that says it received it ONCE: the amended
     * row is what put the line on the wire, and a message that arrived twice is
     * the fan-out double-sending rather than a relay doing its job. */
    TF_CHECK_MSG(nf_expect(&b, "fed_message: channel=" CHAN " from=" NICK_B "!",
                           T_IO_MS) == 0,
                 "node B never received a relayed message for #T, so the owner did "
                 "not forward it: 3.1's owned `message` row is the whole of this "
                 "criterion and it is the thing under test.\n  node said: %s",
                 b.out);
    TF_CHECK_MSG(tf_count(b.out, "fed_message: channel=" CHAN) == 1,
                 "node B received the SPRIVMSG %lu times; a relay that receives "
                 "one message twice has a fan-out or a dedup defect",
                 (unsigned long)tf_count(b.out, "fed_message: channel=" CHAN));

    /* AND DELIVERED IT TO NOBODY, which is the whole of what B was asked to do
     * with it. The tail of B's own line carries the count; the front of it is
     * separated from the tail by the hostmask, which is a fixture detail
     * (127.0.0.1) and not a protocol fact, so the two halves are asserted as two
     * substrings rather than glued into one needle that would break on a
     * different loopback address. hops=0 is the first hop, so this is the owner's
     * own emission and not something B relayed onward a second time. */
    TF_CHECK_MSG(nf_expect(&b, "delivered=0 origin=" NAME_A " hops=0", T_IO_MS) == 0,
                 "node B did not report zero local deliveries for a channel it "
                 "holds no member of, so the state this case is about was not "
                 "reached: %s",
                 b.out);

    /* AND RELAYED IT TO THE OWNER, which is the criterion's own verb and the
     * assertion with the most teeth in the file. It is read on A rather than on
     * B, because the forward is B's and the only observable for it is what the
     * line does when it lands: A is the owner, so 2.4's never-forward-own-origin
     * rule drops it there. Gating B's forward on the local write's result removes
     * that line and this assertion fails -- which is the point, because that gate
     * is exactly the bug the criterion exists to forbid.
     *
     * hops=1 is the relay's own increment, so this is B's single forward and not
     * a later pass. */
    TF_CHECK_MSG(nf_expect(&a, "fed_own_origin_drop: ", T_IO_MS) == 0,
                 "node A never dropped a message of its own origin, so nothing "
                 "came back: %s",
                 a.out);
    TF_CHECK_MSG(nf_expect(&a, "peer=" NAME_B " command=SPRIVMSG origin=" NAME_A
                           " self=" NAME_A " hops=1",
                           T_IO_MS) == 0,
                 "node A never dropped B's SPRIVMSG as its own origin, so the "
                 "zero-member node did NOT relay it to the owner and 7/Phase 6's "
                 "criterion 5 is not met. Under the amended 3.1 B holds no local "
                 "member and forwards anyway.\n  node said: %s",
                 a.out);
    b_relays = tf_count(a.out, "command=SPRIVMSG origin=" NAME_A);
    TF_CHECK_MSG(b_relays == 1,
                 "node A dropped %lu copies of the relayed SPRIVMSG, expected 1: "
                 "the relay forwarded it more than once, or the loop guard did not "
                 "stop it on the first pass",
                 (unsigned long)b_relays);

    /* The negative that makes the positive mean something: nothing was written
     * to B's own client, because B has no member of the channel. A node with
     * nobody to deliver to must not invent a recipient, and the count is over
     * the whole conversation so a delivery B DID make would be caught. */
    TF_CHECK_MSG(times_seen(&carol, TOKEN) == 0,
                 "carol saw the text %lu times on the node that has no members of "
                 "the channel",
                 (unsigned long)times_seen(&carol, TOKEN));

    /* And it SETTLED: the owner still sees the message exactly once after the
     * bounce went out and came back, which is the count a loop breaks. */
    TF_CHECK_MSG(times_seen(&bob, TOKEN) == 1,
                 "the owner's client saw the text %lu times after the relay "
                 "bounced, so the bounce was delivered as well as dropped and the "
                 "mesh is delivering twice",
                 (unsigned long)times_seen(&bob, TOKEN));

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    tc_close(&carol);
    tc_close(&bob);
    nf_free(&a);
    nf_free(&b);
}

/* ---------------------------------------------------------------------------
 * THE SAME ROW, ON THE OTHER SIDE: AN OWNER WITH NO LOCAL MEMBERS
 * ---------------------------------------------------------------------------
 * The case above is the amended 3.1 row's NON-OWNED arm. The OWNED arm carries an
 * obligation the design states in the same amendment and that C3 did not test, and
 * the reason it was not tested is worth recording rather than leaving: a fault
 * injected at the spot -- "only forward if the local write reached somebody" --
 * produced no failure, because in every message test the owner had a local member
 * to write to. A node that owns a channel it holds NOBODY in is a state the wire
 * reaches only by a member leaving, and that is what this case does.
 *
 * HOW THE STATE IS REACHED, with no fixture poking at all:
 *
 *   A owns #T and bob is its only local member. carol, on B, joins -- so A records
 *   a member-server for irc.b, and A's #T has nservers == 1.
 *   bob PARTs on A. 2.2 removes the member, the SPART is forwarded, and A is left
 *   with nmembers == 0 and nservers == 1 -- which is precisely the state
 *   chan_dispose_if_empty() exists to KEEP, and a part is the only ordinary way a
 *   node reaches it.
 *   A therefore still OWNS a channel it is in nobody in, and origin is immutable
 *   for a channel's lifetime (2.2), so A takes the OWNED row for that channel's
 *   next `message`.
 *
 * THE ASSERTION IS THE OWNED ARM'S OWN CONSEQUENCE, which is the only observable
 * for it: A cannot deliver the message to anybody, so if the forward were gated on
 * the local write nothing would leave A, and B would never see the message come
 * back. B dropping it as its own origin (2.4) is therefore the proof, and it is
 * the same observable the case above uses -- which is not a duplication, because
 * the two cases put the zero-membership node on OPPOSITE sides of the table and a
 * single forward arm serves both.
 */
static void case_owner_with_no_local_members_relays(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t bob;
    test_client_t carol;
    char want[256];
    size_t a_drops;

    /* A first this time, and it configures no peer; B dials it and B's client is
     * the one on the far side of the forward. Same one-direction rule as the case
     * above and for the same reason (federation/link.h names the limitation). */
    g_peer_name = NAME_B;
    g_peer_port = 0;
    g_trace = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");
    TF_CHECK_MSG(b.port > 0, "node B reported no port");
    g_peer_port = b.port;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");

    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A");

    register_client(&bob, a.port, NICK_B);
    register_client(&carol, b.port, NICK_C);

    /* bob JOINs on A, so A OWNS #T and has a local member of it. */
    TF_CHECK_MSG(tc_send(&bob, "JOIN " CHAN) == 0, "bob's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob's JOIN never completed on the node that owns the channel");
    /* carol JOINs on B, which does not own it, so the SJOIN reaches A and A's #T
     * gains a member-server. This is the step that makes the later PART leave a
     * channel behind instead of disposing of it. */
    TF_CHECK_MSG(tc_send(&carol, "JOIN " CHAN) == 0, "carol's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&carol, " 366 ", T_IO_MS) == 0,
                 "carol's JOIN never completed on the node that does not own the "
                 "channel");
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=" CHAN " member=" NICK_C, T_IO_MS)
                     == 0,
                 "node A never learned about carol, so its #T has no member-server "
                 "and the state this case is about is not reachable: %s",
                 a.out);

    /* bob PARTs, and A is left owning a channel it is in nobody in. The
     * `members=0 servers=1` in A's own line is the precondition stated as a
     * single observation: the second half is why the channel still exists, and the
     * first half is what the case is about. */
    TF_CHECK_MSG(tc_send(&bob, "PART " CHAN) == 0, "bob's PART send failed");
    TF_CHECK_MSG(nf_expect(&a, "chan_part: channel=" CHAN " nick=" NICK_B
                               " members=0 servers=1",
                           T_IO_MS) == 0,
                 "node A did not end up owning a channel it holds NO local member "
                 "of, which is the state 3.1's amended owned/`message` row has to "
                 "carry: %s",
                 a.out);

    /* THE MESSAGE, from the one member A knows about, over the link. */
    (void)snprintf(want, sizeof want, "PRIVMSG " CHAN " :" TEXT);
    TF_CHECK_MSG(tc_send(&carol, want) == 0, "carol's PRIVMSG send failed");

    /* IT CROSSED TO A, AND A DELIVERED IT TO NOBODY. The `origin=` is irc.b and
     * the sender is a real hostmask, so this is A receiving a relayed message
     * rather than one of its own. */
    TF_CHECK_MSG(nf_expect(&a, "fed_message: channel=" CHAN " from=" NICK_C "!",
                           T_IO_MS) == 0,
                 "node A never received the message for the channel it owns and "
                 "holds nobody in: %s",
                 a.out);
    TF_CHECK_MSG(nf_expect(&a, "delivered=0 origin=" NAME_B " hops=0", T_IO_MS) == 0,
                 "node A reported a local delivery for a channel it holds no member "
                 "of, so the state this case is about was not reached: %s",
                 a.out);
    TF_CHECK_MSG(tf_count(a.out, "fed_message: channel=" CHAN) == 1,
                 "node A received the message %lu times; an owner that forwards "
                 "twice is a fan-out defect rather than a routing one",
                 (unsigned long)tf_count(a.out, "fed_message: channel=" CHAN));

    /* AND A FORWARDED IT ANYWAY, which is the whole of the obligation. It is read
     * on B, because the only observable for A's forward is what the line does when
     * it lands: the message's origin IS B, so 2.4's never-forward-own-origin rule
     * drops it there. Gating A's forward on the local write's result removes that
     * line and this assertion fails -- which is the point, because that gate is
     * exactly the bug the amended row exists to forbid. */
    TF_CHECK_MSG(nf_expect(&b, "peer=" NAME_A " command=SPRIVMSG origin=" NAME_B
                           " self=" NAME_B " hops=1",
                           T_IO_MS) == 0,
                 "node B never dropped A's SPRIVMSG as its own origin, so nothing "
                 "came back and the owner that holds NO local member did NOT relay "
                 "it. 3.1's amended owned/`message` row applies to an owner with "
                 "zero members just as much as to a non-owner.\n  node said: %s",
                 b.out);
    a_drops = tf_count(b.out, "command=SPRIVMSG origin=" NAME_B);
    TF_CHECK_MSG(a_drops == 1,
                 "node B dropped %lu copies of the relayed SPRIVMSG, expected 1",
                 (unsigned long)a_drops);

    /* AND CAROL SAW IT EXACTLY ONCE. B delivered it locally -- she is a member
     * there -- and the bounce was DROPPED, not delivered, so a second copy here
     * would be a loop rather than a relay.
     *
     * THE PING IS A DRAIN AND NOT A POLITENESS. times_seen() counts what the
     * PARENT has read off the socket, and nothing above forced a read of carol's,
     * so without this the count is a statement about the parent's read schedule
     * rather than about the node. The PONG is ordered behind the message on the
     * same connection, so once it is in the buffer the whole answer is. */
    TF_CHECK_MSG(tc_send(&carol, "PING :relay") == 0, "carol's drain PING failed");
    /* The TOKEN, not "PONG": register_client() already drained this client with a
     * PING, so a needle of "PONG" is satisfied by that earlier answer and returns
     * before this connection has read a byte of the message. */
    TF_CHECK_MSG(tc_expect(&carol, "relay", T_IO_MS) == 0,
                 "carol got no PONG, so her buffer is not yet drained and the count "
                 "below is a statement about the read schedule");
    TF_CHECK_MSG(times_seen(&carol, TOKEN) == 1,
                 "carol saw the text %lu times, expected 1: she is the sender's "
                 "peer on the non-owning node, so the local delivery is the one "
                 "legitimate copy and the bounce must not add another",
                 (unsigned long)times_seen(&carol, TOKEN));

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    tc_close(&bob);
    tc_close(&carol);
    nf_free(&a);
    nf_free(&b);
}

/* ---------------------------------------------------------------------------
 * THE `TOPIC` FORWARD ARM, AND WHAT IT ACTUALLY REACHES (#121)
 * ---------------------------------------------------------------------------
 * `handle_topic()` has two arms. The owned one stores through `chan_set_topic()`
 * and broadcasts `ch->topic`; the `CHAN_VERDICT_FORWARD` one stores nothing --
 * 2.2 forbids writing a cache field on a client's say-so -- and put the client's
 * own `m->params[1]` straight into the emission. So the one path this file exists
 * to exercise was the one path a control byte still travelled on, and the fix is a
 * strip there rather than "broadcast the stored field", because there is nothing
 * stored to broadcast.
 *
 * ---------------------------------------------------------------------------
 * WHAT THE FIX COULD NOT BE, MEASURED RATHER THAN ASSUMED
 * ---------------------------------------------------------------------------
 * The obvious test for this arm is "the other local member of the cache receives
 * the stripped line". That test cannot exist, and the reason is 3.1's table rather
 * than anything about this bug: a non-owned channel's `state-change` emission is
 *
 *     FORWARD ONLY -- never a local write
 *
 * (`fanout.c`'s row for FANOUT_REMOTE_CHANNEL, and it is a local write that is
 * FORBIDDEN there, not one that is merely insufficient). So `deliver_state_change()`
 * on the non-owning node never reaches that node's own members at all, and the
 * exposure this arm had was never a local member's terminal -- it was the LINK.
 *
 * The second thing measured rather than assumed: the ORIGIN DISCARDS a forwarded
 * topic. `fed_stopic()` applies a topic only when the link's name is the channel's
 * origin's, and a non-owner's link never bears it, so the origin logs
 * `fed_topic_ignored:`. Which means the bytes that crossed are not observable at the
 * far end either -- the origin records the SENDER's name and nothing else. There is
 * no fixture here that reads the wire between two real nodes.
 *
 * SO THE CLAIM IS ABOUT B'S OWN RECORD, and it is a real claim: the strip happens
 * before the emission, `forwarded=1` is printed only by the branch that put the
 * STRIPPED value into the parameter list, and both counts are on that line. A revert
 * of the strip makes `kept_len` equal `in_len`, which is what the second assertion
 * below is for -- and which is why the record is inside each branch rather than
 * summarised after both of them.
 *
 * AND THE LOCAL-MEMBER FACT IS ASSERTED AS A NEGATIVE, because it is the reason the
 * arm needed no local test and it is worth pinning: if 3.1's FORWARD ONLY row were
 * ever relaxed, this case would start failing, which is the moment someone would
 * need to know that the arm's local exposure came back with it.
 *
 * dave JOINs as the second local member of B's cache specifically so that the
 * negative below is about a member rather than about a node with nobody in it.
 */
static void case_topic_forward_strips(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t bob;
    test_client_t carol;
    test_client_t dave;
    size_t mark_d;

    g_peer_name = NAME_B;
    g_peer_port = 0;
    g_trace = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");
    TF_CHECK_MSG(b.port > 0, "node B reported no port");
    g_peer_port = b.port;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");

    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A");

    /* A OWNS #T, so carol's TOPIC on B is forwarded rather than applied. */
    register_client(&bob, a.port, NICK_B);
    TF_CHECK_MSG(tc_send(&bob, "JOIN " CHAN) == 0, "bob's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob's JOIN never completed on the node that owns the channel");

    /* Two local members of B's CACHE. A JOIN on a non-owned channel does add a local
     * member -- membership is a local fact while the channel's state is the origin's
     * -- so carol may set the topic on B at all, and dave is a member rather than an
     * empty channel. */
    register_client(&carol, b.port, NICK_C);
    register_client(&dave, b.port, "dave");
    TF_CHECK_MSG(tc_send(&carol, "JOIN " CHAN) == 0, "carol's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&carol, " 366 ", T_IO_MS) == 0,
                 "carol's JOIN never completed on the node that does not own it");
    TF_CHECK_MSG(tc_send(&dave, "JOIN " CHAN) == 0, "dave's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&dave, " 366 ", T_IO_MS) == 0, "dave's JOIN never completed");

    /* THE PRECONDITION, before the message: B has not forwarded a TOPIC yet, so the
     * line asserted below is about this case and not about something earlier. */
    TF_CHECK_MSG(nf_expect(&b, "chan_state_forward: channel=" CHAN " verb=TOPIC",
                           200) == -1,
                 "node B already logged a TOPIC forward before the case sent one, so "
                 "the assertions below would be about something else.\n  node said: %s",
                 b.out);

    mark_d = tc_received(&dave);
    TF_CHECK_MSG(tc_send(&carol, "TOPIC " CHAN " :" PAYLOAD) == 0,
                 "carol's TOPIC send failed");

    /* 1. B TOOK THE FORWARD ARM. Asserted before the strip, because every claim
     * below is a claim about that arm. */
    TF_CHECK_MSG(nf_expect(&b, "chan_state_forward: channel=" CHAN " verb=TOPIC "
                           "origin=" NAME_A, T_IO_MS) == 0,
                 "node B did not forward carol's TOPIC, so nothing below is about "
                 "the forward arm at all.\n  node said: %s", b.out);

    /* 2. THE STRIP, WITH BOTH LENGTHS, ON THE BRANCH THAT FORWARDED. The lengths
     * come from strlen() of the two literals rather than from numbers typed in, so
     * the assertion cannot be made permanently wrong by an arithmetic slip -- which
     * is the same failure as an assertion that cannot fail. The point of the
     * comparison is that kept_len is STRICTLY LESS than in_len: a strip that had
     * been reverted would print them equal. */
    {
        char needle[192];
        const size_t raw = strlen(PAYLOAD);
        const size_t kept = strlen(PAYLOAD_STRIPPED);
        size_t hits;

        (void)snprintf(needle, sizeof needle,
                       "chan_topic_forward: channel=" CHAN " nick=" NICK_C
                       " in_len=%zu kept_len=%zu forwarded=1", raw, kept);
        TF_CHECK_MSG(nf_expect(&b, needle, T_IO_MS) == 0,
                     "node B did not record the topic strip on the forward arm; "
                     "expected \"%s\". The payload carries two ESCs, so kept_len must "
                     "be strictly less than in_len -- equal is what a reverted strip "
                     "prints.\n  node said: %s", needle, b.out);
        /* AND EXACTLY ONCE, because a second occurrence would mean the record is
         * printed outside the branch that forwarded, which is the property that
         * makes it evidence. */
        hits = tf_count(b.out, "chan_topic_forward: channel=" CHAN);
        TF_CHECK_MSG(hits == 1u,
                     "node B recorded %lu TOPIC forwards and this case sent one "
                     "TOPIC. A record printed outside the forwarding branch would be "
                     "counted here, and it is the branch that makes `forwarded=1` "
                     "mean the STRIPPED value went on the wire.\n  node said: %s",
                     (unsigned long)hits, b.out);
    }

    /* 3. THE FORWARD REALLY CROSSED, and the origin discarded it -- which is 2.2's
     * single-writer rule, not a failure of the mesh. Asserted because it is what
     * makes claim 2 about the wire rather than about a branch nobody took: if B had
     * not sent, A would not have ignored anything. */
    TF_CHECK_MSG(nf_expect(&a, "fed_topic_ignored: channel=" CHAN " from=" NAME_B,
                           T_IO_MS) == 0,
                 "the origin never recorded discarding the forwarded topic, so the "
                 "forward did not cross and claim 2 is about a branch that was not "
                 "taken.\n  node said: %s", a.out);

    /* 4. NO CONTROL BYTE ON EITHER NODE. B emitted it into the forward and A
     * received it; neither may have let one into its own output. */
    {
        size_t i;

        for (i = 0; i < b.out_len; i++) {
            const unsigned char ch = (unsigned char)b.out[i];

            if (ch == '\r' || ch == '\n') {
                continue;
            }
            TF_CHECK_MSG(ch > 0x1fu && ch != 0x7fu,
                         "a byte from the log-injection set (0x%02x) reached node "
                         "B's own output on the TOPIC forward arm (0x%02x).\n"
                         "  node said: %s", ch, ch, b.out);
        }
        for (i = 0; i < a.out_len; i++) {
            const unsigned char ch = (unsigned char)a.out[i];

            if (ch == '\r' || ch == '\n') {
                continue;
            }
            TF_CHECK_MSG(ch > 0x1fu && ch != 0x7fu,
                         "a byte from the log-injection set (0x%02x) reached node "
                         "A's own output, having crossed the link.\n  node said: %s",
                         ch, a.out);
        }
    }

    /* 5. AND NO LOCAL DELIVERY, which is the fact that makes 1-4 the whole of the
     * arm's exposure. dave is a member of B's cache and got nothing, because a
     * non-owned channel's state-change emission is FORWARD ONLY. */
    TF_CHECK_MSG(tc_send(&dave, "PING :post-topic") == 0, "dave's PING send failed");
    TF_CHECK_MSG(tc_expect(&dave, "PONG", T_IO_MS) == 0,
                 "dave got no PONG, so the absence below is about the read schedule "
                 "rather than about what he was sent");
    TF_CHECK_MSG(strstr(tc_buffer(&dave) + mark_d, "TOPIC " CHAN) == NULL,
                 "a local member of the non-owning node's cache received the TOPIC. "
                 "3.1's row for a non-owned channel is `state-change`: FORWARD ONLY, "
                 "never a local write -- so this is not a bug in the forward arm, it "
                 "is the reason the arm has no LOCAL exposure to fix, and it is pinned "
                 "here because relaxing that row would bring the local exposure back "
                 "with nothing else noticing.\n  dave saw: %s", tc_buffer(&dave) + mark_d);

    /* dave is still a usable connection and his cache is still coherent. */
    TF_CHECK_MSG(strstr(tc_buffer(&dave), " 366 ") != NULL,
                 "dave's own JOIN numerics never arrived, so the negative above was "
                 "measured against a client that had not arrived on the channel");

    tc_close(&bob);
    tc_close(&carol);
    tc_close(&dave);
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    nf_free(&a);
    nf_free(&b);
}


int main(void)
{
    case_zero_member_node_relays();
    case_owner_with_no_local_members_relays();
    case_topic_forward_strips();
    tf_done("fed_relay");
    return 0;
}
