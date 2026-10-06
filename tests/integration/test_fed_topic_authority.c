/* test_fed_topic_authority.c -- #132: who is allowed to set a channel's topic.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS EXISTS FOR, AND WHY test_fed_relay.c COULD NOT CARRY IT
 * ---------------------------------------------------------------------------
 * `fed_in_stopic()` decided whether a received `STOPIC` was authoritative by
 * comparing `link->name` against `ch->origin`. `link->name` is the server THIS
 * NODE IS SPEAKING TO. On the one topology where the origin and the peer are the
 * same server those two strings agree, so the rule looked right; on every other
 * topology it is false, and the consequences are not subtle:
 *
 *   - A topic set by a client attached to a node the origin does not hold
 *     directly is FORWARDED to the origin (chan_verbs.c's authority_ok() answers
 *     CHAN_VERDICT_FORWARD for a channel this node does not own) and then refused
 *     there, because the arrival is on a link named the non-owner while
 *     `ch->origin` is the receiving node. So the topic never exists.
 *   - Beyond two nodes the same false negative also suppresses the onward
 *     forward, so the divergence is permanent for everything behind the node that
 *     first dropped it.
 *
 * THE OLD TEST PINNED THE DEFECT. test_fed_relay.c's control-bytes case waited
 * for `fed_topic_ignored: channel=#T from=irc.b` ON THE ORIGIN and called it
 * 2.2's single-writer rule working. A rule that makes a topic set by most of the
 * network unreachable is not a rule, so that assertion is inverted in that file
 * and this one covers the rest: the positive arms and the arm that must still be
 * REFUSED.
 *
 * ---------------------------------------------------------------------------
 * THE THREE CASES
 * ---------------------------------------------------------------------------
 *   1. ORIGIN ACCEPTS FROM A MEMBER-SERVER. Two of the three nodes are enough
 *      for the shape: A owns #T, bob is on B, bob's TOPIC is a forward, and A
 *      must cache it. This is the case the defect broke and the case the old
 *      assertion contradicted.
 *
 *   2. THE ORIGIN'S OWN TOPIC SURVIVES ONE RELAY HOP. Three nodes in a chain.
 *      alice sets the topic on A; A stamps `irc-serve-origin: irc.a`; B caches
 *      it and forwards it to C; C caches it too. On C the arrival is on the link
 *      named `irc.b`, so the old check refused it and -- being above the forward
 *      -- did not pass it on either. This case needs the third node: with only A
 *      and B every arrival is on the origin's own link and the check is
 *      accidentally right, which is the shape the old test's header names as the
 *      reason the defect survived a suite that already had two-node federation.
 *
 *   3. A THIRD SERVER'S CLAIM IS STILL REFUSED. Same verb, same link, same
 *      channel: the only thing that differs between the applied line and the
 *      refused one is the subject, and the refused subject is a server the node
 *      has no record of for this channel. A fix that had only widened the test
 *      would have deleted this arm, and "accepts anything a peer says" is not a
 *      fix.
 *
 * ---------------------------------------------------------------------------
 * THE KNOWN LIMIT, STATED HERE BECAUSE A TEST THAT DOES NOT MENTION IT READS
 * LIKE ONE THAT DOES NOT HAVE IT
 * ---------------------------------------------------------------------------
 * Case 1's topic does NOT reach C. The origin applies it and forwards it, but the
 * onward emission carries the REQUESTING server's stamp -- `fanout_stamp()` treats
 * a forward of a received line as a relay and relays the identity rather than
 * re-minting one, because a new id would give the far side's dedup store a key it
 * has never seen -- so on C the subject is `irc.b` while the channel's origin is
 * `irc.a`. `STOPIC` carries no field naming the evaluating server the way
 * `SMODES`' first parameter does, so a node that is neither the origin nor a peer
 * the requesting server has a member with has no evidence that the origin
 * approved the value and cannot tell an approved topic from a forged one.
 *
 * That is a bounded staleness rather than a wrong record: the ORIGIN holds the
 * correct value, and 4.3's SBURST replaces the topic from the origin, so a resync
 * converges it. It is NOT pinned as expected behaviour here, because pinning a
 * limitation as though it were a design is how the original defect survived --
 * the old assertion did exactly that. See the two arms at the check in
 * src/federation/verbs.c and the issue comment.
 *
 * ---------------------------------------------------------------------------
 * THE FIXTURES
 * ---------------------------------------------------------------------------
 * `nf_spawn_inline_named()` forks a child that binds port 0 and reports its port,
 * so a node only exists in the parent after the spawn, and the next spawn's setup
 * has to be told about it through a file-static global the child inherits at
 * fork(). The peer list is therefore an array the parent fills between spawns.
 *
 * ONE DIRECTIONAL CONFIGURED LINK PER PAIR, because a node that configures BOTH
 * ends of a pair both dials and neither accepts and the pair ends up with no link
 * at all -- federation/link.h names that limitation. A dials B and C; B dials C;
 * so the established mesh is A--B, A--C and B--C with every pair formed by exactly
 * one dial. `fed_link_configure()` takes one peer per call, which is why the array
 * exists rather than a single global.
 *
 * ONE MESH PER CASE, and that is not tidiness. Cases 1 and 2 both assert an
 * ABSENCE on a node's output, and an absence is only attributable to one case if
 * the buffer belongs to one case: sharing three nodes means case 1's refusals are
 * still in case 2's buffer and an absence assertion over somebody else's lines is
 * a claim about nothing. Three spawns is cheap next to that.
 *
 * NO FIXED sleep() ANYWHERE (6.3): every wait is a deadline, and every wait is
 * for an OBSERVABLE LINE or a WIRE BYTE rather than for a silence. Where a case
 * asserts that something did NOT happen it drains with a PING/PONG first, so "no
 * reply" is a fact about the bytes read after a known reply rather than a guess
 * about timing.
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
#include "harness/peer_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define SECRET     "irc-serve-federation-secret-b"
#define NAME_A     "irc.a"
#define NAME_B     "irc.b"
#define NAME_C     "irc.c"
#define CHAN       "#T"
#define NICK_OWNER "alice"
#define NICK_FAR   "bob"
#define NICK_RELAY "carol"

/* ---------------------------------------------------------------------------
 * PRE-FORK STATE
 * ---------------------------------------------------------------------------
 * The peer table is what the child reads: `name`/`port` pairs to dial. A zero
 * port means "dial nobody", which is the accepting side. The parent rewrites the
 * table between spawns and the next child inherits it at fork(). */
typedef struct {
    const char *name;
    int         port;
} peer_spec_t;

static peer_spec_t g_peers[2];

/* Why every node here installs this: 3.4 says the poll tick drives time and
 * node_main.c installs the federation tick visibly rather than delegating to
 * fed_open(), so a test that did not install it would have a link that never
 * dials and never dies and would read that as a federation failure. */
static void child_tick(server_t *s, uint64_t now_ms)
{
    fed_tick(s, now_ms);
}

static void child_setup(server_t *s)
{
    struct sockaddr_in sa;

    /* The client surface BEFORE fed_open(): fed_open() saves whatever dispatch
     * is there and replaces it with its own, so a commands_dispatch installed
     * after it would be the node's whole dispatch and the peer path would never
     * be reached. Every case in this file has clients. */
    TF_CHECK_MSG(commands_dispatch != NULL,
                 "the client command surface is missing from the build");
    s->dispatch = commands_dispatch;

    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child; a node with an unopenable "
                 "federation module cannot reach any assertion in this test");
    s->on_tick = child_tick;
    /* The shipped defaults are 10s/5s for the handshake and 30s/90s for the
     * keepalive, left where they are. They are only bounds on the failure path, so
     * nothing waits longer; raising them would be the thing that hides a genuine
     * handshake failure behind a longer deadline rather than naming it. */
    fed_set_timeouts(5000, 5000, 30000, 90000);

    for (size_t i = 0; i < sizeof g_peers / sizeof g_peers[0]; i++) {
        if (g_peers[i].port <= 0) {
            continue;
        }
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = htons((unsigned short)g_peers[i].port);
        TF_CHECK_MSG(fed_link_configure(s, g_peers[i].name,
                                        (const struct sockaddr *)&sa,
                                        (socklen_t)sizeof sa) != NULL,
                     "the child could not configure peer %s on port %d",
                     g_peers[i].name, g_peers[i].port);
    }
}

/* Register a client and wait for the welcome, then drain with a PING so every
 * line registration produced has been read before a case claims anything about
 * the wire. */
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
                 "not been read yet", nick);
}

/* One client, joined to CHAN, with the completion numerics drained. */
static void join_chan(test_client_t *c, int port, const char *nick)
{
    char line[128];

    register_client(c, port, nick);
    (void)snprintf(line, sizeof line, "JOIN %s", CHAN);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s's JOIN send failed", nick);
    TF_CHECK_MSG(tc_expect(c, " 366 ", T_IO_MS) == 0, "%s's JOIN never completed", nick);
}

/* The mesh, torn down. `nf_stop()` before `nf_free()` is the documented order:
 * nf_free() does not kill, so a free without a stop would leave a child holding
 * a port. */
static void mesh_stop(nf_node_t *a, nf_node_t *b, nf_node_t *c)
{
    TF_CHECK_MSG(nf_stop(a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(b) == 0, "node B did not exit cleanly");
    TF_CHECK_MSG(nf_stop(c) == 0, "node C did not exit cleanly");
    nf_free(a);
    nf_free(b);
    nf_free(c);
}

/* A OWNS #T. Asserted POSITIVELY, and immediately after the local JOIN that makes
 * it true rather than at the top of the case, because the first client to JOIN a
 * channel a node has never heard of becomes that node's origin -- an assertion
 * made before the JOIN would be waiting for a line nothing has caused yet. B and C
 * must also have LEARNED that the channel is A's before any client joins it on
 * them, or the first such client would make THEM the origin. That ordering is not
 * a formality: without it this case has a race, and that race is what made the
 * sibling case in test_fed_relay.c red on Linux and green on macOS. */
static void assert_owner_is_a(nf_node_t *a, nf_node_t *b, nf_node_t *c)
{
    TF_CHECK_MSG(nf_expect(a, "chan_create: channel=" CHAN " origin=" NAME_A, T_IO_MS) == 0,
                 "node A never claimed " CHAN ", so the cases below would be about a "
                 "mesh where every claim is inverted");
    TF_CHECK_MSG(nf_expect(b, "fed_sjoin: channel=" CHAN " member=" NICK_OWNER
                           " server=" NAME_A, T_IO_MS) == 0,
                 "node B never learned that " CHAN " belongs to " NAME_A ", so a topic "
                 "set on B would take the local-write arm instead of the forward arm "
                 "these cases are about.\n  node said: %s", b->out);
    TF_CHECK_MSG(nf_expect(c, "fed_sjoin: channel=" CHAN " member=" NICK_OWNER
                           " server=" NAME_A, T_IO_MS) == 0,
                 "node C never learned that " CHAN " belongs to " NAME_A ".\n"
                 "  node said: %s", c->out);
}

/* ---------------------------------------------------------------------------
 * THE MESH: A owns #T, and every pair has a link formed by exactly one dial.
 *
 * A dials B and C, B dials C, and nothing dials A -- so the three links are A--B,
 * A--C and B--C, and `irc.a` is the accepting side of both of its links while
 * `irc.b` accepts C's dial. Spawn order is A, B, C precisely so that each port
 * exists in the parent before the node that has to dial it is forked.
 */
static void spawn_mesh(nf_node_t *a, nf_node_t *b, nf_node_t *c)
{
    memset(g_peers, 0, sizeof g_peers);
    TF_CHECK_MSG(nf_spawn_inline_named(a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    TF_CHECK_MSG(a->port > 0, "node A reported no port");

    g_peers[0].name = NAME_A;
    g_peers[0].port = a->port;
    TF_CHECK_MSG(nf_spawn_inline_named(b, NAME_B, child_setup) == 0,
                 "could not spawn node B");
    TF_CHECK_MSG(b->port > 0, "node B reported no port");

    g_peers[1].name = NAME_B;
    g_peers[1].port = b->port;
    TF_CHECK_MSG(nf_spawn_inline_named(c, NAME_C, child_setup) == 0,
                 "could not spawn node C");
    TF_CHECK_MSG(c->port > 0, "node C reported no port");

    TF_CHECK_MSG(nf_expect(a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(a, "link_established: peer=" NAME_C, T_IO_MS) == 0,
                 "node A never established its link to node C");
    TF_CHECK_MSG(nf_expect(b, "link_established: peer=" NAME_C, T_IO_MS) == 0,
                 "node B never established its link to node C");
    TF_CHECK_MSG(nf_expect(c, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node C never established its link to node B");
}

/* ---------------------------------------------------------------------------
 * CASE 1: THE ORIGIN ACCEPTS A TOPIC FORWARDED BY A MEMBER-SERVER
 * ---------------------------------------------------------------------------
 * The exact shape the defect broke. alice is on A, which owns #T. bob is on B,
 * which does not, so bob's TOPIC is a FORWARD: 2.2 makes the topic cache on a
 * non-owner, so nothing is written on B and the line goes to A on the link named
 * `irc.b`. The old check compared that name against A's own name and refused. */
static void case_origin_accepts_forwarded_topic(void)
{
    nf_node_t a;
    nf_node_t b;
    nf_node_t c;
    test_client_t alice;
    test_client_t bob;

    spawn_mesh(&a, &b, &c);

    join_chan(&alice, a.port, NICK_OWNER);
    assert_owner_is_a(&a, &b, &c);
    join_chan(&bob, b.port, NICK_FAR);

    /* B TOOK THE FORWARD ARM. Asserted first: every claim below is a claim about
     * a line that only exists on that arm. If B had taken the local-write arm it
     * would have written a cache field 2.2 forbids writing, and A would have
     * nothing to accept. */
    TF_CHECK_MSG(nf_expect(&b, "chan_state_forward: channel=" CHAN " verb=JOIN "
                           "origin=" NAME_A, T_IO_MS) == 0,
                 "bob's JOIN on the non-owning node did not take the forward arm, so "
                 "node B owns " CHAN " and this case is about the wrong topology.\n"
                 "  node said: %s", b.out);

    TF_CHECK_MSG(tc_send(&bob, "TOPIC " CHAN " :set from the far side") == 0,
                 "bob's TOPIC send failed");
    TF_CHECK_MSG(nf_expect(&b, "chan_state_forward: channel=" CHAN " verb=TOPIC "
                           "origin=" NAME_A, T_IO_MS) == 0,
                 "node B did not forward bob's TOPIC, so nothing below is about the "
                 "forward arm at all.\n  node said: %s", b.out);

    /* A APPLIED IT. The line names the member and the length, so the assertion is
     * about the origin's own cache rather than about a branch it happened to run.
     * This is the assertion test_fed_relay.c used to make the opposite of. */
    TF_CHECK_MSG(nf_expect(&a, "fed_topic: channel=" CHAN " member=" NICK_FAR,
                           T_IO_MS) == 0,
                 "the origin never recorded applying the topic bob set on the node it "
                 "does not hold directly. Under the rule this replaced, every client "
                 "attached to every node except the origin's own had its TOPIC dropped "
                 "at the origin -- so a mesh could not set a topic at all.\n"
                 "  node said: %s", a.out);

    /* AND THE VALUE, ON THE WIRE, to a client on the origin. 332 is the only
     * place a cached topic is rendered to a client, so this is the observable
     * that the CACHE holds the value and not merely that a branch ran. */
    TF_CHECK_MSG(tc_send(&alice, "TOPIC " CHAN) == 0, "alice's TOPIC query failed");
    TF_CHECK_MSG(tc_expect(&alice, " 332 " NICK_OWNER " " CHAN " :set from the far side", T_IO_MS) == 0,
                 "the origin's cached topic is not the value bob set on the other "
                 "node, so the topic was recorded somewhere other than the field a "
                 "client is shown.\n  alice saw: %s", tc_buffer(&alice));

    /* B DID NOT WRITE IT LOCALLY. 2.2's single-writer rule is a real constraint
     * and the fix widens the AUTHORITY test, not the set of nodes that may write
     * a cache field. B holds alice's channel as a cache and must still hold the
     * origin's value. */
    {
        size_t at = tc_received(&bob);

        TF_CHECK_MSG(tc_send(&bob, "PING :post-topic") == 0, "bob's PING send failed");
        TF_CHECK_MSG(tc_expect(&bob, "PONG", T_IO_MS) == 0,
                     "bob got no PONG, so the absence below is about the read schedule");
        TF_CHECK_MSG(strstr(tc_buffer(&bob) + at, "TOPIC " CHAN) == NULL,
                     "a local member of the non-owning node's cache received the TOPIC. "
                     "3.1's row for a non-owned channel is FORWARD ONLY, so this pins "
                     "the half of 2.2 the fix must not have moved.\n  bob saw: %s",
                     tc_buffer(&bob) + at);
    }

    tc_close(&alice);
    tc_close(&bob);
    mesh_stop(&a, &b, &c);
}

/* ---------------------------------------------------------------------------
 * CASE 2: THE ORIGIN'S OWN TOPIC SURVIVES ONE RELAY HOP
 * ---------------------------------------------------------------------------
 * alice is on A, which owns #T. alice sets the topic on A; A stamps
 * `irc-serve-origin: irc.a` because the emission is its own; B caches it and
 * forwards it to C; C caches it too. On C the arrival is on the link named
 * `irc.b` and the subject is `irc.a`, which is what makes this the case the old
 * rule could not pass: `link->name` and `ch->origin` are different servers in
 * EVERY three-node topology, which is every real one. */
static void case_relay_carries_origin_topic(void)
{
    nf_node_t a;
    nf_node_t b;
    nf_node_t c;
    test_client_t alice;
    test_client_t remote;

    spawn_mesh(&a, &b, &c);
    join_chan(&alice, a.port, NICK_OWNER);
    assert_owner_is_a(&a, &b, &c);
    /* C holds a member of #T too, so it is a relay with somewhere to send the
     * line rather than a node that would drop it for want of a target -- and a
     * client there to be shown the value at the end. */
    join_chan(&remote, c.port, NICK_RELAY);

    TF_CHECK_MSG(tc_send(&alice, "TOPIC " CHAN " :set on the origin") == 0,
                 "alice's TOPIC send failed");

    /* B, ONE HOP. */
    TF_CHECK_MSG(nf_expect(&b, "fed_topic: channel=" CHAN " member=" NICK_OWNER,
                           T_IO_MS) == 0,
                 "the directly-linked relay never cached the origin's topic.\n"
                 "  node said: %s", b.out);

    /* C, TWO HOPS. The arrival is on the link named `irc.b` and the subject is
     * `irc.a`, which is what makes this the case the old rule could not pass. And
     * because the old refusal sat ABOVE the forward, everything behind this node
     * would have kept the stale topic for ever. */
    TF_CHECK_MSG(nf_expect(&c, "fed_topic: channel=" CHAN " member=" NICK_OWNER,
                           T_IO_MS) == 0,
                 "the second-hop relay never cached the origin's topic. The arrival is "
                 "on the link named " NAME_B " while the channel's origin is " NAME_A
                 ", so this is the arrangement the origin-identity-by-link rule got "
                 "wrong.\n  node said: %s", c.out);

    /* AND NEITHER RELAY REFUSED IT, because a node that reached the refusal arm
     * and then applied the topic anyway would satisfy both assertions above. This
     * is an absence over a buffer that belongs to THIS case alone -- see the
     * fixture note on why the meshes are not shared. */
    TF_CHECK_MSG(strstr(b.out, "fed_topic_ignored: channel=" CHAN) == NULL,
                 "node B both applied the origin's topic and logged a refusal for the "
                 "channel, so the two arms are not exclusive.\n  node said: %s", b.out);
    TF_CHECK_MSG(strstr(c.out, "fed_topic_ignored: channel=" CHAN) == NULL,
                 "node C both applied the origin's topic and logged a refusal for the "
                 "channel, so the two arms are not exclusive.\n  node said: %s", c.out);

    /* C's own client sees the value, so the cache assertions above are about
     * fields and not about log lines. */
    TF_CHECK_MSG(tc_send(&remote, "TOPIC " CHAN) == 0, "carol's TOPIC query failed");
    TF_CHECK_MSG(tc_expect(&remote, " 332 " NICK_RELAY " " CHAN " :set on the origin", T_IO_MS) == 0,
                 "a client on the second-hop relay was shown a cached topic that is not "
                 "the origin's.\n  carol saw: %s", tc_buffer(&remote));

    tc_close(&alice);
    tc_close(&remote);
    mesh_stop(&a, &b, &c);
}

/* ---------------------------------------------------------------------------
 * CASE 3: A THIRD SERVER'S CLAIM IS STILL REFUSED, AND THE ORIGIN'S OWN IS NOT
 * ---------------------------------------------------------------------------
 * A fix that had only ever widened the authority test would have made a node
 * cache any `STOPIC` any peer sent about any channel it holds, which is the
 * failure 2.2 exists to prevent. So the refusal arm is asserted, from the peer
 * side, on a channel whose origin is the PEER rather than this node -- which
 * puts the line on the `subject == ch->origin` arm, the one a widening fix would
 * have deleted.
 *
 * THE PEER IS A RAW SOCKET AND NOT A SECOND NODE, for the reason
 * test_fed_guards.c gives: no node built from this code will emit a `STOPIC`
 * whose subject is a server nobody has ever heard of, so a two-node fixture can
 * only prove the guard is not reached. This test owns one end of a link -- it
 * listens, node A dials it, it answers A's FEDERATE with a correct claim -- and
 * from that moment A believes it is talking to `irc.b` and the test can put any
 * line on that socket, tagged however it likes. The handshake is real: the answer
 * is a genuine FEDERATE with the right name, secret and version word, and A's
 * link goes through the real FSM. What is not real is the node on the far side,
 * and this says so rather than pretending otherwise.
 *
 * TWO CLAIMS FROM ONE FIXTURE, because they are the two sides of one term: a
 * subject that IS the channel's origin is applied, and a subject that is a third
 * server is refused. Asserting only the refusal would pass against a node that
 * refuses every topic from every peer, which is not a property anything wants.
 */
#define PEER "irc.b"
/* A server name no line in this fixture has ever mentioned, and the subject of
 * the refused claim. It is a legal 2.4 tag value, so the refusal is about
 * authority and not about the grammar. */
#define THIRD "irc.z"
/* The client on the raw-peer node. Named here because the 332 below is asserted on
 * the wire and the wire spells the requesting client's own nick in that field. */
#define NICK_RAW "dave"

typedef struct {
    int fd;
    int port;
} raw_peer_t;

/* The node under test, dialling THIS test's listener. Spawned after the listener
 * so the address exists before the child reads it at fork(). */
static int g_raw_peer_port;

static void raw_child_setup(server_t *s)
{
    struct sockaddr_in sa;

    s->dispatch = commands_dispatch;
    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child; a node with an unopenable "
                 "federation module cannot reach any assertion in this test");
    s->on_tick = child_tick;
    fed_set_timeouts(1000, 5000, 30000, 90000);

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)g_raw_peer_port);
    TF_CHECK_MSG(fed_link_configure(s, PEER, (const struct sockaddr *)&sa,
                                    (socklen_t)sizeof sa) != NULL,
                 "the child could not configure peer %s on port %d", PEER,
                 g_raw_peer_port);
}

/* The 2.4 stamp, rendered by the test rather than read from the node, because
 * the point of the case is what the node does with a stamp the node did not mint.
 * `epoch` is this test's own number and is never compared against anything; `id`
 * is given a distinct value per line so two lines in this case are two distinct
 * messages to the dedup store rather than one being dropped as a duplicate. */
static void stamp(char *out, size_t cap, const char *origin, unsigned long id)
{
    (void)snprintf(out, cap,
                   "@irc-serve-origin=%s;irc-serve-epoch=1700000000;"
                   "irc-serve-id=%lu;irc-serve-hops=1 ",
                   origin, id);
}

static void case_third_server_claim_refused(void)
{
    nf_node_t node;
    raw_peer_t peer;
    test_client_t client;
    char line[512];
    char block[256];
    const char *needles[2];
    int listen_fd;
    size_t mark;

    peer.fd = -1;
    peer.port = 0;

    listen_fd = pf_listen_loopback(&peer.port);
    TF_CHECK_MSG(listen_fd >= 0, "the test could not open a listening socket");
    g_raw_peer_port = peer.port;
    TF_CHECK_MSG(nf_spawn_inline_named(&node, NAME_A, raw_child_setup) == 0,
                 "could not spawn node A");

    peer.fd = pf_accept_deadline(listen_fd, T_IO_MS);
    /* The listener is the test's own and there is only ever one peer on it, so it
     * is closed here rather than at the end: leaving it open would mean a second
     * dial could be accepted by accident. */
    close(listen_fd);
    TF_CHECK_MSG(peer.fd >= 0, "node A never dialled the socket this test owns");

    needles[0] = ":" NAME_A " FEDERATE " NAME_A " ";
    needles[1] = " " SECRET " " IRC_SERVE_VERSION "\r\n";
    TF_CHECK_MSG(pf_read_until(peer.fd, needles, 2, T_IO_MS) == 0,
                 "node A never sent a FEDERATE naming itself with the configured "
                 "secret, so nothing after this could mean anything.\n  node said: %s",
                 node.out);
    (void)snprintf(line, sizeof line, ":" PEER " FEDERATE " PEER " 1700000000 %s %s\r\n",
                   SECRET, IRC_SERVE_VERSION);
    TF_CHECK_MSG(pf_send_line(peer.fd, line) == 0,
                 "the test could not answer with a FEDERATE");
    TF_CHECK_MSG(nf_expect(&node, "link_established: peer=" PEER, T_IO_MS) == 0,
                 "node A never established its link, so every refusal below would be "
                 "a pre-auth drop wearing the wrong name.\n  node said: %s", node.out);

    /* A client on the node, in the channel. A refusal has to be a statement about
     * bytes a client did not receive, which needs somebody to deliver to. */
    TF_CHECK_MSG(tc_connect(&client, node.port) == 0, "the client could not connect");
    TF_CHECK_MSG(tc_send(&client, "NICK " NICK_RAW) == 0, "NICK send failed");
    TF_CHECK_MSG(tc_send(&client, "USER " NICK_RAW " 0 *spoofed :Real " NICK_RAW) == 0,
                 "USER send failed");
    TF_CHECK_MSG(tc_expect(&client, " 001 ", T_IO_MS) == 0,
                 "the client never registered");
    TF_CHECK_MSG(tc_send(&client, "JOIN " CHAN) == 0, "JOIN send failed");
    TF_CHECK_MSG(tc_expect(&client, " 366 ", T_IO_MS) == 0,
                 "the client's JOIN never completed, so it is not a member and a "
                 "refused delivery to it would prove nothing");

    /* SJOIN, so this node knows the channel AND that the peer holds a member of
     * it. Without the second half the `chan_server_has()` term is false for every
     * name, the positive claim below is vacuous, and the file would pass against a
     * node that refuses every topic from every peer. */
    /* AND THE ORDER MATTERS: the SJOIN is sent BEFORE the client's JOIN. A client
     * that joins a channel the node has never heard of becomes its origin, and the
     * channel's origin would then be this node -- which G6 would make unnameable
     * on the wire, since a stamp naming this node is dropped as own-origin before
     * any handler runs. Sending the SJOIN first is what puts the origin on the
     * PEER's side of the wire. */
    stamp(block, sizeof block, PEER, 900UL);
    (void)snprintf(line, sizeof line, "%s:" PEER " SJOIN " CHAN " carol - *\r\n", block);
    TF_CHECK_MSG(pf_send_line(peer.fd, line) == 0, "the SJOIN send failed");
    TF_CHECK_MSG(nf_expect(&node, "fed_sjoin: channel=" CHAN " member=carol",
                           T_IO_MS) == 0,
                 "node A never installed the peer's member, so the channel's origin is "
                 "not " PEER " and the claims below would not be about the arm they "
                 "are about.\n  node said: %s", node.out);

    /* THE POSITIVE CLAIM. The subject is a server the channel's roster records as
     * holding a member -- the peer, which the SJOIN just installed -- so the line
     * is applied and the value is cached.
     *
     * BOTH TERMS OF THE DISJUNCTION ADMIT IT and this file does not pretend to
     * separate them: on a well-formed mesh the channel's origin always has a
     * member of the channel somewhere, so `subject == ch->origin` implies
     * `chan_server_has(ch, subject)` too. What is separated here, and what the rule
     * exists for, is ACCEPT from REFUSE. The term that a three-node relay needs --
     * `subject == ch->origin` on a node the origin has no member on -- is exercised
     * by case 2's second hop, where C's subject is `irc.a` and C's origin is
     * `irc.a`.
     *
     * Asserted on the client's 332 as well as on the log line, because this is a
     * claim about a cache field and a log line is a claim about a branch. */
    stamp(block, sizeof block, PEER, 901UL);
    (void)snprintf(line, sizeof line,
                   "%s:" PEER "!u@h STOPIC carol " CHAN " :the origin's topic\r\n",
                   block);
    TF_CHECK_MSG(pf_send_line(peer.fd, line) == 0, "the STOPIC send failed");
    TF_CHECK_MSG(nf_expect(&node, "fed_topic: channel=" CHAN " member=carol",
                           T_IO_MS) == 0,
                 "a STOPIC whose subject is the channel's origin was not applied, so "
                 "the refusal below would be vacuous: a node that refuses every topic "
                 "from every peer passes it.\n  node said: %s", node.out);
    TF_CHECK_MSG(tc_send(&client, "TOPIC " CHAN) == 0,
                 "the client's TOPIC query failed");
    TF_CHECK_MSG(tc_expect(&client, " 332 " NICK_RAW " " CHAN " :the origin's topic", T_IO_MS) == 0,
                 "the origin's own subject was reported as applied but the cached field "
                 "does not hold it.\n  client saw: %s", tc_buffer(&client));

    /* THE REFUSED CLAIM. Same verb, same link, same channel: only the subject
     * differs, and it is a server this node has no record of for this channel.
     * That is the arm a widening fix would have deleted, so it is a separate
     * assertion and not a consequence of the one above. */
    mark = tc_received(&client);
    stamp(block, sizeof block, THIRD, 902UL);
    (void)snprintf(line, sizeof line,
                   "%s:" THIRD "!u@h STOPIC carol " CHAN " :a third server's topic\r\n",
                   block);
    TF_CHECK_MSG(pf_send_line(peer.fd, line) == 0, "the second STOPIC send failed");
    TF_CHECK_MSG(nf_expect(&node, "fed_topic_ignored: channel=" CHAN " from=" PEER
                           " subject=" THIRD " origin=" NAME_A
                           " reason=NOT_THE_ORIGIN_OR_A_MEMBER_SERVER", T_IO_MS) == 0,
                 "a STOPIC whose subject is a third server was not refused. The node has "
                 "no record of " THIRD " for this channel, so the only way to accept it "
                 "would be to accept any claim from any peer about any channel, which "
                 "is the divergence 2.2 exists to prevent.\n  node said: %s",
                 node.out);

    /* AND THE VALUE DID NOT MOVE, which is the half with teeth: a node that
     * reported the refusal and then cached the topic anyway would pass the
     * assertion above. Read after a PING/PONG, so the 332 is known to precede the
     * drain and not to have arrived later. */
    TF_CHECK_MSG(tc_send(&client, "PING :post-refusal") == 0, "PING send failed");
    TF_CHECK_MSG(tc_expect(&client, "PONG", T_IO_MS) == 0,
                 "the client got no PONG, so the absence below is about the read "
                 "schedule rather than about what it was sent");
    TF_CHECK_MSG(strstr(tc_buffer(&client) + mark, "a third server's topic") == NULL,
                 "the topic a third server claimed was cached. The node reported the "
                 "refusal and did the thing anyway, which is worse than either alone.\n"
                 "  client saw: %s", tc_buffer(&client) + mark);

    /* AND THE ORIGINAL SURVIVED, so the refusal is a refusal rather than a
     * clearing. A field that went empty would also satisfy the absence above, and
     * "the topic is gone" is not what a refused claim should mean. */
    TF_CHECK_MSG(tc_send(&client, "TOPIC " CHAN) == 0,
                 "the second TOPIC query failed");
    TF_CHECK_MSG(tc_expect(&client, " 332 " NICK_RAW " " CHAN " :the origin's topic", T_IO_MS) == 0,
                 "the refused claim did not leave the previous topic in place, so the "
                 "node replaced the field rather than ignoring the line.\n"
                 "  client saw: %s", tc_buffer(&client));

    TF_CHECK_MSG(nf_stop(&node) == 0, "node A did not exit cleanly");
    tc_close(&client);
    nf_free(&node);
    if (peer.fd >= 0) {
        close(peer.fd);
    }
}

int main(void)
{
    case_origin_accepts_forwarded_topic();
    case_relay_carries_origin_topic();
    case_third_server_claim_refused();

    tf_done("test_fed_topic_authority");
    return 0;
}
