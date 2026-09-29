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


int main(void)
{
    case_zero_member_node_relays();
    tf_done("fed_relay");
    return 0;
}
