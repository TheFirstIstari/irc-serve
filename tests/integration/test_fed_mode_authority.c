/* test_fed_mode_authority.c -- #141: who is allowed to evaluate a channel mode.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS IS, AND WHY IT IS A SIBLING OF test_fed_topic_authority.c
 * ---------------------------------------------------------------------------
 * `fed_in_smodes()` decided whether a received `SMODES` was authoritative with
 * `chan_same_name(params[0], ch->origin)` alone -- "the evaluating server is the
 * origin" -- and `MODE #chan +b mask` is one of the three fields 2.2 reserves to the
 * origin. So a ban set by an operator on a node that does NOT own the channel never
 * took effect anywhere.
 *
 * It is #132's defect in the opposite half. There, a field that does not carry the
 * authority (`link->name`, the socket) was read as if it did. Here, the field that
 * DOES carry the authority (`params[0]`, 4.3's `<server>`) was read as the whole of
 * it. Both made a documented 2.2 field unreachable from half the network, and both
 * were invisible to a two-node fixture because on a two-node mesh the origin and the
 * peer are the same name -- which is the reason that class survived a suite that
 * already had two-node federation.
 *
 * ---------------------------------------------------------------------------
 * WHERE THE INPUT COMES FROM, AND IT IS NOT WHERE THE ISSUE SAYS
 * ---------------------------------------------------------------------------
 * The issue's verification note says "a client-originated `MODE +b` on a non-owning
 * node reaching the origin" is uncovered, and this file set out to cover it with two
 * of this node's own nodes. THAT TOPOLOGY CANNOT PRODUCE THE INPUT, and finding that
 * out is half of what this file is for.
 *
 * `handle_mode()` answers 482 to a client who is not a channel operator, and it does
 * so BEFORE the authority verdict is used. Op status comes only from
 * `chan_set_member_flags()`, which has exactly ONE caller in the tree -- `handle_mode()`'s
 * own `+o`/`+v` arm, which requires the client to already be op. So on a channel this
 * node does not own, no client can ever become op, and no client can ever issue a MODE
 * at all. The FORWARD arm `handle_mode()` now has is therefore UNREACHABLE TODAY, and
 * the old `MODE_NEEDS_ORIGIN` line it replaced was unreachable for the same reason:
 * nothing tested it because nothing could produce it.
 *
 * That is a real constraint on what this pass could verify and it is stated here
 * rather than worked around. It also means the defect was only ever observable from
 * the PEER side -- which is exactly where #141 found it, and exactly why the
 * entitlement test in `fed_in_smodes()` is the load-bearing half of the fix. The
 * client-side change is still made, because a node that answers 437 forever is a node
 * where the feature does not exist the moment op propagation lands, and 437 is not a
 * policy anyone chose; but it is not what the required test asserts, and pretending
 * otherwise would be a test that passes for the wrong reason.
 *
 * ---------------------------------------------------------------------------
 * THE THREE CASES, AND WHY THREE
 * ---------------------------------------------------------------------------
 *   1. A MEMBER-SERVER'S `+b` IS APPLIED, AND THE ORIGIN'S BAN LIST CHANGES. One
 *      node owning #T and one raw peer holding a member of it, which is what a
 *      non-owner's forward looks like by the time it arrives: `SMODES irc.b #T +b
 *      mask`, subject `irc.b`, on a link named something else. Asserted ON THE WIRE
 *      to a client on the ORIGIN through 367 -- not on the log line, because a log
 *      line is a claim about a branch and a ban list is a field.
 *
 *   2. A THIRD SERVER'S CLAIM IS STILL REFUSED. Same verb, same link, same channel;
 *      the only thing that differs is the subject, and the refused subject is a server
 *      the node has no record of for this channel. A fix that had only widened the
 *      test would have deleted this arm, and "accepts anything a peer says" is not a
 *      fix. Asserted POSITIVELY on the refusal line and then on the ABSENCE of any
 *      change to the list, because a node that logs the refusal and applies it anyway
 *      passes the first assertion.
 *
 *   3. THE ORIGIN'S OWN `SMODES` SURVIVES ONE RELAY HOP. The onward-forward audit.
 *      Two nodes: A owns #T and evaluates a `+b` on behalf of the peer, and A
 *      forwards it to C, which caches it. On C the arrival is on the link named
 *      something else and the `<server>` field still names the origin, so this is the
 *      case that decides whether the fix makes the mesh converge or merely stops the
 *      origin from refusing. It needs the second node: with only A every arrival is on
 *      the origin's own link and the check is accidentally true.
 *
 * AND THE REACHABILITY FACT ITSELF IS PINNED, by the assertion in case 1 that a
 * plain member of a cache is refused 482 for a MODE. Without it, the absence of a
 * client-originated case in this file would read as an oversight rather than as a
 * measured property.
 *
 * ---------------------------------------------------------------------------
 * THE KNOWN LIMIT, STATED HERE RATHER THAN DISCOVERED LATER
 * ---------------------------------------------------------------------------
 * Case 3's onward forward carries the ORIGINAL evaluating server, not the origin's
 * name, because `fed_in_smodes()` forwards `params` unchanged and re-stamping the
 * `<server>` field would assert an evaluation that did not happen at that hop. So at
 * the second hop the subject is `irc.a` -- the origin -- and it converges by term (a).
 * For a forward whose subject is a MEMBER-SERVER (`bob` on B), the onward emission
 * carries `irc.b` and the next hop needs term (b), i.e. that the next node's roster
 * records `irc.b` as holding a member of #T. In a real mesh it does, because B
 * forwards its SJOINs onward; on a node whose roster has not learned that yet, the
 * second hop refuses and 4.3's SBURST replaces the list from the origin on the next
 * resync. That is bounded staleness rather than a wrong record -- the ORIGIN holds
 * the correct list -- and it is pinned as a limit rather than as a design, because
 * pinning a limitation as though it were a design is how the original defect survived
 * (#132's old assertion did exactly that).
 *
 * ---------------------------------------------------------------------------
 * THE FIXTURES
 * ---------------------------------------------------------------------------
 * Cases 1 and 4 use two of this node's own nodes, which is what they are about: a
 * client's MODE on a non-owner takes the forward arm and the origin applies it. That
 * cannot be produced any other way, because a second node's client path would be the
 * same code and a raw socket could not produce a client's own `MODE`.
 *
 * Cases 2 and 3 need one node and a RAW PEER SOCKET, for the reason
 * test_fed_topic_authority.c's case 3 gives: no node built from this code will emit
 * an `SMODES` naming a server nobody has ever heard of, or carry `<server>` =
 * something other than its own name, so a two-node fixture can only prove the guard
 * is not reached. The handshake is REAL -- a genuine FEDERATE with the right name,
 * secret and version word, and the node's link goes through the real FSM. What is
 * not real is the node on the far side, and this says so rather than pretending.
 *
 * ONE MESH PER CASE. Cases 2 and 3 both assert an ABSENCE, and an absence is only
 * attributable to one case if the buffer belongs to one case: sharing nodes means
 * case 2's refusals are still in case 3's buffer and an absence assertion over
 * somebody else's lines is a claim about nothing.
 *
 * NO FIXED sleep() ANYWHERE (6.3): every wait is a deadline, and every wait is for an
 * OBSERVABLE LINE or a WIRE BYTE. Where a case asserts that something did NOT happen
 * it drains with a PING/PONG first, so "no reply" is a fact about the bytes read after
 * a known reply rather than a guess about timing.
 */
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/channel.h"
#include "core/commands.h"
#include "core/server.h"
#include "federation/link.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/peer_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define SECRET     "irc-serve-federation-secret-d"
#define NAME_A     "irc.a"
#define NAME_B     "irc.b"
#define NAME_C     "irc.c"
#define PEER       "irc.b"
/* A server no line in this file has ever mentioned, and the subject of the refused
 * claim. It is a legal 2.4 server name, so the refusal is about authority and not
 * about the grammar. */
#define THIRD      "irc.z"
#define CHAN       "#T"
#define NICK_OWNER "alice"
#define NICK_FAR   "bob"
#define NICK_RELAY "carol"
#define MASK       "*!*@example.org"

/* ---------------------------------------------------------------------------
 * PRE-FORK STATE AND THE CHILD
 * ---------------------------------------------------------------------------
 * `nf_spawn_inline_named()` forks a child that binds port 0 and reports its port, so
 * a node only exists in the parent after the spawn and the next spawn's peer list has
 * to be told about it through a file-static the child inherits at fork(). The list is
 * therefore an array the parent fills between spawns.
 *
 * ONE DIRECTIONAL CONFIGURED LINK PER PAIR: a node that configures BOTH ends of a
 * pair both dials and neither accepts, and the pair ends up with no link at all
 * (federation/link.h names that limitation). A dials B and C, B dials C, so the
 * established mesh is A--B, A--C and B--C with every pair formed by exactly one dial.
 */
typedef struct {
    const char *name;
    int         port;
} peer_spec_t;

static peer_spec_t g_peers[2];

static void child_tick(server_t *s, uint64_t now_ms)
{
    fed_tick(s, now_ms);
}

static void child_setup(server_t *s)
{
    struct sockaddr_in sa;

    /* The client command surface BEFORE fed_open(): fed_open() saves whatever dispatch
     * is there and replaces it with its own, so a commands_dispatch installed
     * afterwards becomes the node's whole dispatch and the peer path is never
     * reached. Cases 1 and 4 have clients; cases 2 and 3 have one each. */
    s->dispatch = commands_dispatch;
    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child; a node with an unopenable "
                 "federation module cannot reach any assertion in this test");
    s->on_tick = child_tick;
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

/* ---------------------------------------------------------------------------
 * THE RAW-PEER FIXTURE, for the cases a pair of this node's nodes cannot produce
 * ---------------------------------------------------------------------------
 * One end of a link, owned by this test: it listens, the node dials it, it answers
 * the FEDERATE with a genuine claim, and from that moment the node believes it is
 * talking to `irc.b` and the test can put any line on that socket.
 */
typedef struct {
    int fd;
    int port;
} raw_peer_t;

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

    /* AND ANY NODE THE PARER NAMED BEFORE THE FORK, for the onward-forward case. The
     * list is the file-static the child inherits rather than a parameter, because a
     * child cannot see a change the parent makes afterwards -- and a peer configured
     * after the fork is a peer this node never dialled, which reads as a
     * federation failure and is not one. Zero ports mean "dial nobody", which is how
     * cases 1 and 2 leave this list empty. */
    for (size_t i = 0; i < sizeof g_peers / sizeof g_peers[0]; i++) {
        if (g_peers[i].port <= 0) {
            continue;
        }
        sa.sin_port = htons((unsigned short)g_peers[i].port);
        TF_CHECK_MSG(fed_link_configure(s, g_peers[i].name,
                                        (const struct sockaddr *)&sa,
                                        (socklen_t)sizeof sa) != NULL,
                     "the child could not configure peer %s on port %d",
                     g_peers[i].name, g_peers[i].port);
    }
}

/* Open the link and answer the handshake. Returns the listening-socket-owning struct
 * with a live `fd`. Every refusal below would be a pre-auth drop wearing the wrong
 * name if this were skipped, so it is one function rather than four copies. */
static void raw_peer_open(raw_peer_t *peer, nf_node_t *node)
{
    char line[512];
    const char *needles[2];
    int listen_fd;

    peer->fd = -1;
    peer->port = 0;
    listen_fd = pf_listen_loopback(&peer->port);
    TF_CHECK_MSG(listen_fd >= 0, "the test could not open a listening socket");
    g_raw_peer_port = peer->port;
    TF_CHECK_MSG(nf_spawn_inline_named(node, NAME_A, raw_child_setup) == 0,
                 "could not spawn node A");

    peer->fd = pf_accept_deadline(listen_fd, T_IO_MS);
    /* Closed as soon as it has served its purpose: leaving a second listener open
     * would let a second dial be accepted by accident, and every "there is one link"
     * claim in this file rests on there being exactly one. */
    close(listen_fd);
    TF_CHECK_MSG(peer->fd >= 0, "node A never dialled the socket this test owns");

    needles[0] = ":" NAME_A " FEDERATE " NAME_A " ";
    needles[1] = " " SECRET " " IRC_SERVE_VERSION "\r\n";
    TF_CHECK_MSG(pf_read_until(peer->fd, needles, 2, T_IO_MS) == 0,
                 "node A never sent a FEDERATE naming itself with the configured "
                 "secret, so nothing after this could mean anything.\n  node said: %s",
                 node->out);
    (void)snprintf(line, sizeof line, ":" PEER " FEDERATE " PEER " 1700000000 %s %s\r\n",
                   SECRET, IRC_SERVE_VERSION);
    TF_CHECK_MSG(pf_send_line(peer->fd, line) == 0,
                 "the test could not answer with a FEDERATE");
    TF_CHECK_MSG(nf_expect(node, "link_established: peer=" PEER, T_IO_MS) == 0,
                 "node A never established its link, so every assertion below would "
                 "be a pre-auth drop wearing the wrong name.\n  node said: %s",
                 node->out);
}

/* The 2.4 stamp, rendered by the test rather than read from the node, because the
 * point of these cases is what the node does with a stamp it did not mint. `epoch` is
 * this test's own number and is compared against nothing; `id` differs per line so
 * two lines are two messages to the dedup store rather than one being dropped as a
 * duplicate. */
static void stamp(char *out, size_t cap, unsigned long id)
{
    (void)snprintf(out, cap,
                   "@irc-serve-origin=%s;irc-serve-epoch=1700000000;"
                   "irc-serve-id=%lu;irc-serve-hops=1 ", PEER, id);
}

/* THE ORIGIN-SIDED FIXTURE: alice creates #T, and the peer then installs a member.
 *
 * THE ORDER IS THE WHOLE OF IT, and both halves are forced.
 *
 * ALICE JOINS FIRST, so the channel's origin is this node AND alice is its operator.
 * `chan_join()` makes the first member of a new channel its operator, which is what
 * test_banlist.c relies on when it says "alice JOINS, so she creates #banme and is
 * its operator". She has to be op because every read of `ch->bans[]` from a client --
 * 367, 368, and the `MODE #T +b` query -- goes through `handle_mode()`'s 482 check
 * first, and a plain member is refused before the query form is even reached.
 *
 * THE PEER'S SJOIN COMES SECOND, so `chan_server_has(ch, "irc.b")` is true. Without
 * it the entitlement test's second term is false for every name, the positive claims
 * in case 1 are vacuous, and this file would pass against a node that refuses every
 * mode change from every peer.
 *
 * AND NEITHER ORDER MAY BE SWAPPED: the SJOIN first would make the PEER the origin,
 * which is case 3's topology, and alice's JOIN second would leave alice a plain
 * member who cannot read anything back. */
static void origin_client_op(raw_peer_t *peer, nf_node_t *node,
                             test_client_t *client)
{
    char block[256];
    char line[512];

    TF_CHECK_MSG(tc_connect(client, node->port) == 0, "alice could not connect");
    TF_CHECK_MSG(tc_send(client, "NICK " NICK_OWNER) == 0, "NICK send failed");
    TF_CHECK_MSG(tc_send(client, "USER " NICK_OWNER " 0 *spoofed :Real " NICK_OWNER) == 0,
                 "USER send failed");
    TF_CHECK_MSG(tc_expect(client, " 001 ", T_IO_MS) == 0, "alice never registered");
    TF_CHECK_MSG(tc_send(client, "JOIN " CHAN) == 0, "alice's JOIN send failed");
    TF_CHECK_MSG(tc_expect(client, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed, so she is not a member and a refused "
                 "delivery to her would prove nothing");

    stamp(block, sizeof block, 900UL);
    (void)snprintf(line, sizeof line, "%s:" PEER " SJOIN " CHAN " carol - *\r\n", block);
    TF_CHECK_MSG(pf_send_line(peer->fd, line) == 0, "the SJOIN send failed");
    TF_CHECK_MSG(nf_expect(node, "fed_sjoin: channel=" CHAN " member=carol",
                           T_IO_MS) == 0,
                 "node A never installed the peer's member, so the entitlement test's "
                 "member-server term is false for every name and the acceptance "
                 "assertions below would be vacuous.\n  node said: %s", node->out);
}

/* A PLAIN MEMBER, which is what the reachability assertion below needs: `MODE` from
 * someone who is not op is refused 482, and that refusal is the whole reason the
 * client-side forward arm cannot be reached from two of this node's nodes. */
static void plain_member_join(nf_node_t *node, test_client_t *client,
                              const char *nick)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(client, node->port) == 0, "%s could not connect", nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(client, line) == 0, "%s NICK send failed", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(client, line) == 0, "%s USER send failed", nick);
    TF_CHECK_MSG(tc_expect(client, " 001 ", T_IO_MS) == 0, "%s never registered", nick);
    TF_CHECK_MSG(tc_send(client, "JOIN " CHAN) == 0, "%s's JOIN send failed", nick);
    TF_CHECK_MSG(tc_expect(client, " 366 ", T_IO_MS) == 0,
                 "%s's JOIN never completed", nick);
}

/* ---------------------------------------------------------------------------
 * CASE 1: A MEMBER-SERVER'S +b IS APPLIED, AND THE BAN LIST CHANGES
 * ---------------------------------------------------------------------------
 * The shape the defect broke, as it arrives: the origin owns #T, a peer holds a member
 * of it, and the peer's `SMODES irc.b #T +b mask` arrives on a link named something
 * else. Under the old test the origin compared `params[0]` against its own name,
 * found a peer, and refused -- so no ban set on any node but the origin's took effect
 * anywhere on the mesh.
 *
 * WHY 367 AND NOT THE LOG. `fed_modes:` is a claim about a branch; `ch->bans[]` is a
 * field, and a field is what a ban is. 367 (RPL_BANLIST) is the only place a ban list
 * is rendered to a client, so a 367 naming the mask is the difference between "the
 * entitlement test returned true" and "the ban exists".
 *
 * AND THE REACHABILITY FACT, asserted rather than asserted-in-a-comment: a plain
 * member of a cache cannot issue a MODE at all, because op status has exactly one
 * writer and it is `handle_mode()`'s own `+o` arm. So the CLIENT-side forward arm is
 * unreachable today, and this is what says so -- see the header. */
static void case_member_server_ban_applied(void)
{
    nf_node_t node;
    raw_peer_t peer;
    test_client_t alice;
    test_client_t bob;
    char line[512];
    char block[256];
    char want[256];
    size_t mark;

    raw_peer_open(&peer, &node);
    origin_client_op(&peer, &node, &alice);
    plain_member_join(&node, &bob, NICK_FAR);

    /* THE REACHABILITY FACT. This is the assertion that says "no client-originated
     * MODE is tested here" is a measured property rather than an omission. If it ever
     * FAILS -- because a cache started granting local op -- then this file has a whole
     * missing case, and this failure is where a reader learns it. */
    mark = tc_received(&bob);
    TF_CHECK_MSG(tc_send(&bob, "MODE " CHAN " +b " MASK) == 0,
                 "bob's MODE send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 482 ", T_IO_MS) == 0,
                 "a plain member of a channel was NOT refused 482 for a MODE, so the "
                 "reachability fact this file is built around no longer holds: a cache "
                 "that grants local op can issue MODE, and the client-originated case "
                 "this file does not have becomes a real gap.\n"
                 "  bob saw: %s", tc_buffer(&bob) + mark);
    TF_CHECK_MSG(strstr(tc_buffer(&bob) + mark, " 367 ") == NULL,
                 "the refused MODE still produced a ban list, so it was not refused.\n"
                 "  bob saw: %s", tc_buffer(&bob) + mark);

    /* THE MEMBER-SERVER'S CLAIM, which is what a non-owner's forward is on the wire:
     * `SMODES <evaluating server> <channel> <modes> [<arg>]`, with the evaluating
     * server naming a node that is not the origin. */
    stamp(block, sizeof block, 910UL);
    (void)snprintf(line, sizeof line,
                   "%s:" PEER " SMODES " PEER " " CHAN " +b " MASK "\r\n", block);
    TF_CHECK_MSG(pf_send_line(peer.fd, line) == 0, "the SMODES send failed");
    TF_CHECK_MSG(nf_expect(&node, "fed_modes: channel=" CHAN " by=" PEER, T_IO_MS) == 0,
                 "the origin never recorded applying the member-server's MODE +b. "
                 "Under the rule this replaced it compared `params[0]` -- which "
                 "`fed_sverb_params()` stamps with the forwarding node's own name -- "
                 "against its own name and refused, so a ban set on any node but the "
                 "origin's took effect nowhere on the mesh.\n  node said: %s",
                 node.out);
    TF_CHECK_MSG(strstr(node.out, "fed_modes_ignored: channel=" CHAN) == NULL,
                 "the origin both applied the member-server's MODE and logged a refusal "
                 "for it, so the two arms are not exclusive.\n  node said: %s",
                 node.out);
    TF_CHECK_MSG(strstr(node.out, "fed_modes_ban_cached: channel=" CHAN) == NULL,
                 "the origin recorded caching the ban rather than applying it, so it "
                 "does not believe it owns this channel -- and it does: alice's JOIN "
                 "created it. A node that treats its own channel as a cache is applying "
                 "2.2's rule to the wrong side.\n  node said: %s", node.out);

    /* AND THE LIST ACTUALLY CHANGED, on the wire, to a client ON THE ORIGIN. This is
     * the assertion the defect made impossible: with only the mode letter applied, the
     * origin's `ch->bans[]` would be empty and 367 would say so. */
    TF_CHECK_MSG(tc_send(&alice, "MODE " CHAN " +b") == 0,
                 "the ban-list query failed");
    TF_CHECK_MSG(tc_expect(&alice, " 367 ", T_IO_MS) == 0,
                 "the origin's own client was shown no ban list at all, so the mask "
                 "the member-server set is not in the field a client reads and "
                 "`fed_modes:` was reporting a letter rather than a ban.\n"
                 "  alice saw: %s", tc_buffer(&alice));
    (void)snprintf(want, sizeof want, " 367 " NICK_OWNER " " CHAN " " MASK);
    TF_CHECK_MSG(strstr(tc_buffer(&alice), want) != NULL,
                 "the origin's ban list does not carry the mask: 367 named a list but "
                 "not this one.\n  alice saw: %s", tc_buffer(&alice));

    /* AND THE LETTER SURVIVED, so the fix did not buy the list by losing the mode.
     * 324 is the only place `ch->modes[]` is rendered, and the two halves of `MODE +b`
     * disagreeing with each other would be a new defect rather than a fix. */
    TF_CHECK_MSG(tc_send(&alice, "MODE " CHAN) == 0, "the MODE query failed");
    TF_CHECK_MSG(tc_expect(&alice, " 324 ", T_IO_MS) == 0,
                 "the origin did not answer a MODE query, so the mode letter cannot be "
                 "read back.\n  alice saw: %s", tc_buffer(&alice));
    TF_CHECK_MSG(strstr(tc_buffer(&alice), "+b") != NULL,
                 "the origin applied the ban list but not the mode letter, so the two "
                 "halves of `MODE +b` now disagree with each other.\n"
                 "  alice saw: %s", tc_buffer(&alice));

    /* AND IT CAN BE REMOVED, which is the other half of a mask mode and the one a
     * forward-only implementation of the list would fail: `-b mask` has to take the
     * mask OFF, not merely decline to add it. */
    mark = tc_received(&alice);
    stamp(block, sizeof block, 911UL);
    (void)snprintf(line, sizeof line,
                   "%s:" PEER " SMODES " PEER " " CHAN " -b " MASK "\r\n", block);
    TF_CHECK_MSG(pf_send_line(peer.fd, line) == 0, "the second SMODES send failed");
    TF_CHECK_MSG(tc_send(&alice, "PING :post-unban") == 0, "PING send failed");
    TF_CHECK_MSG(tc_expect(&alice, "PONG", T_IO_MS) == 0,
                 "alice got no PONG, so the query below is about the read schedule");
    TF_CHECK_MSG(tc_send(&alice, "MODE " CHAN " +b") == 0,
                 "the second ban-list query failed");
    TF_CHECK_MSG(tc_expect(&alice, " 368 ", T_IO_MS) == 0,
                 "the origin still answers a ban-list query with 367 after the mask was "
                 "removed, so `-b` set the letter and left the list alone.\n"
                 "  alice saw: %s", tc_buffer(&alice) + mark);
    TF_CHECK_MSG(strstr(tc_buffer(&alice) + mark, MASK) == NULL,
                 "the removed mask is still in the origin's ban list.\n"
                 "  alice saw: %s", tc_buffer(&alice) + mark);

    TF_CHECK_MSG(nf_stop(&node) == 0, "node A did not exit cleanly");
    tc_close(&alice);
    tc_close(&bob);
    nf_free(&node);
    if (peer.fd >= 0) {
        close(peer.fd);
    }
}

/* ---------------------------------------------------------------------------
 * CASE 2: A THIRD SERVER'S CLAIM IS STILL REFUSED
 * ---------------------------------------------------------------------------
 * A fix that had only ever widened the authority test would have made a node apply any
 * `SMODES` any peer sent about any channel it holds, which is the divergence 2.2
 * exists to prevent. The refused subject is a server this node has no record of for
 * this channel, which is the arm a widening fix would have deleted. */
static void case_third_server_claim_refused(void)
{
    nf_node_t node;
    raw_peer_t peer;
    test_client_t client;
    char line[512];
    char block[256];
    char want[256];
    size_t mark;

    raw_peer_open(&peer, &node);
    origin_client_op(&peer, &node, &client);

    /* THE POSITIVE CLAIM FIRST, so the refusal below cannot be vacuous: a node that
     * refuses every SMODES from every peer passes a refusal test on its own.
     *
     * BOTH TERMS OF THE DISJUNCTION ADMIT IT, and this file does not pretend to
     * separate them: on a well-formed mesh the channel's origin always has a member
     * somewhere, so `subject == ch->origin` implies `chan_server_has(ch, subject)`
     * too. What is separated is ACCEPT from REFUSE. The term a relay hop needs --
     * `subject == ch->origin` where the node has no member on that server -- is case
     * 3's job. */
    stamp(block, sizeof block, 901UL);
    (void)snprintf(line, sizeof line,
                   "%s:" PEER " SMODES " PEER " " CHAN " +b " MASK "\r\n", block);
    TF_CHECK_MSG(pf_send_line(peer.fd, line) == 0, "the first SMODES send failed");
    TF_CHECK_MSG(nf_expect(&node, "fed_modes: channel=" CHAN " by=" PEER, T_IO_MS) == 0,
                 "an SMODES whose subject is the channel's origin was not applied, so "
                 "the refusal below would be vacuous: a node that refuses every mode "
                 "from every peer passes it.\n  node said: %s", node.out);

    /* AND THE LIST TOOK IT, so the positive arm is about a field rather than a
     * branch -- the same reason case 1 reads 367. */
    TF_CHECK_MSG(tc_send(&client, "MODE " CHAN " +b") == 0,
                 "the ban-list query failed");
    TF_CHECK_MSG(tc_expect(&client, " 367 " NICK_OWNER " " CHAN " " MASK, T_IO_MS) == 0,
                 "the origin applied the peer's MODE but its ban list does not carry "
                 "the mask. `+b` is a MASK mode: the letter in `ch->modes[]` is not the "
                 "ban, and 367 is the only place the ban is rendered to a client.\n"
                 "  client saw: %s", tc_buffer(&client));

    /* THE REFUSED CLAIM. Same verb, same link, same channel; only the subject differs,
     * and it is a server this node has no record of for this channel. A separate
     * assertion rather than a consequence of the one above. */
    mark = tc_received(&client);
    stamp(block, sizeof block, 902UL);
    (void)snprintf(line, sizeof line,
                   "%s:" THIRD " SMODES " THIRD " " CHAN " +b bad!*@elsewhere.example\r\n",
                   block);
    TF_CHECK_MSG(pf_send_line(peer.fd, line) == 0, "the second SMODES send failed");
    /* Two needles rather than one long one: the refusal line carries the subject's
     * length and bad-byte count between `subject=` and `origin=`, which is
     * connection.h's Rule 1 and which a needle that skipped them would be asserting
     * is not there. */
    TF_CHECK_MSG(nf_expect(&node, "fed_modes_ignored: channel=" CHAN " from=" PEER
                           " subject=" THIRD " ", T_IO_MS) == 0,
                 "an SMODES whose subject is a third server was not refused. The node "
                 "has no record of " THIRD " for this channel, so the only way to "
                 "accept it would be to accept any claim from any peer about any "
                 "channel, which is the divergence 2.2 exists to prevent.\n"
                 "  node said: %s", node.out);
    TF_CHECK_MSG(nf_expect(&node, "origin=" NAME_A
                           " reason=NOT_THE_ORIGIN_OR_A_MEMBER_SERVER", T_IO_MS) == 0,
                 "the refusal did not name the channel's origin and the reason it was "
                 "refused. `subject=` alone does not say which of the two names the "
                 "node believed, and a reader guessing between them is the ambiguity "
                 "#132's line was changed to remove.\n  node said: %s", node.out);

    /* AND THE LIST DID NOT MOVE. Read after a PING/PONG so the absence is about the
     * bytes read after a known reply rather than a guess about timing, and asserted
     * as an ABSENCE OF THE NEW MASK rather than of 367, because the previous mask is
     * still there and a 367 must be. */
    TF_CHECK_MSG(tc_send(&client, "PING :post-refusal") == 0, "PING send failed");
    TF_CHECK_MSG(tc_expect(&client, "PONG", T_IO_MS) == 0,
                 "the client got no PONG, so the absence below is about the read "
                 "schedule");
    TF_CHECK_MSG(strstr(tc_buffer(&client) + mark, "elsewhere.example") == NULL,
                 "the mask a third server claimed reached the ban list. The node "
                 "reported the refusal and did the thing anyway, which is worse than "
                 "either alone.\n  client saw: %s", tc_buffer(&client) + mark);

    /* AND THE ACCEPTED ONE SURVIVED, so the refusal is a refusal rather than a
     * clearing: a list that went empty would also satisfy the absence above. */
    (void)snprintf(want, sizeof want, " 367 " NICK_OWNER " " CHAN " " MASK);
    TF_CHECK_MSG(strstr(tc_buffer(&client), want) != NULL,
                 "the refused claim did not leave the accepted mask in place, so the "
                 "node replaced the list rather than ignoring the line.\n"
                 "  client saw: %s", tc_buffer(&client));

    TF_CHECK_MSG(nf_stop(&node) == 0, "node A did not exit cleanly");
    tc_close(&client);
    nf_free(&node);
    if (peer.fd >= 0) {
        close(peer.fd);
    }
}

/* ---------------------------------------------------------------------------
 * CASE 3: THE ORIGIN'S OWN MODE CHANGE REACHES A SECOND NODE
 * ---------------------------------------------------------------------------
 * THE ONWARD-FORWARD AUDIT, and it is the property #132's fix had to be audited for
 * too. `fed_in_stopic()` and `fed_in_smodes()` are the same shape: the refusal is a
 * `return` ABOVE the `fanout_forward_channel_sverb()` call, so a false negative does
 * not merely fail to apply the change -- it also SUPPRESSES the onward forward, and
 * everything behind that node stays stale until a 4.3 resync. So the claim needs a
 * SECOND node, or it is accidentally true on a one-node mesh.
 *
 * WHY THE PEER IS A RAW SOCKET AND WHY THE STAMP IS ABSENT. The line has to reach A
 * with `<server>` naming A, and G6 drops any line whose 2.4 stamp names the receiving
 * node -- so a stamped `SMODES irc.a ...` is an own-origin drop before any handler
 * runs. An UNTAGGED line whose prefix is the link's own name takes G4's CASE A
 * instead, which MINTS the identity rather than reading it, and the subject in
 * `params[0]` is then free to be A. That is also the only way to put a chosen
 * `<server>` on the wire: `fed_sverb_params()` stamps `self`, so a second node's own
 * forward always names itself.
 *
 * WHAT C ACTUALLY SEES, because the shape is not the obvious one and a reader will
 * get it wrong: A owns the channel, so fanout.c's OWNED row sends to `ch->servers[]`
 * UNION every ESTABLISHED link, and C is an established link. The onward emission is
 * therefore DIRECT from A to C. It is not relayed through a third node -- and
 * `test_fed_topic_authority.c`'s case 2 header describes its own case as "B caches it
 * and forwards it to C", which is not what the code does either. The property under
 * test is unaffected: C's arrival is on a link that is NOT its channel's origin, and
 * the `<server>` field names the origin, which is the arrangement the old test got
 * wrong. */
static void case_origin_modes_reach_second_node(void)
{
    nf_node_t node;
    nf_node_t c;
    raw_peer_t peer;
    test_client_t alice;
    char line[512];
    char block[256];

    /* C first, with NO peers: it is reached by A's onward emission and by nothing
     * else, so every claim about it is about what arrived over the link A dials.
     * Spawned first so its port exists in the parent before A is told about it. */
    memset(g_peers, 0, sizeof g_peers);
    TF_CHECK_MSG(nf_spawn_inline_named(&c, NAME_C, child_setup) == 0,
                 "could not spawn node C");
    TF_CHECK_MSG(c.port > 0, "node C reported no port");

    /* A dials BOTH the raw peer and C. The peer list was filled above, before the
     * fork, because a child cannot see a change the parent makes afterwards and a
     * peer configured after the fork is a peer this node never dialled. */
    memset(g_peers, 0, sizeof g_peers);
    g_peers[0].name = NAME_C;
    g_peers[0].port = c.port;
    raw_peer_open(&peer, &node);

    /* alice creates #T on A, so A OWNS it and its owned forward row reaches C. She is
     * its operator as well, which is what `chan_join()` does for a new channel's first
     * member and what test_banlist.c relies on. */
    TF_CHECK_MSG(tc_connect(&alice, node.port) == 0, "alice could not connect");
    TF_CHECK_MSG(tc_send(&alice, "NICK " NICK_OWNER) == 0, "NICK send failed");
    TF_CHECK_MSG(tc_send(&alice, "USER " NICK_OWNER " 0 *spoofed :Real " NICK_OWNER) == 0,
                 "USER send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 001 ", T_IO_MS) == 0, "alice never registered");
    TF_CHECK_MSG(tc_send(&alice, "JOIN " CHAN) == 0, "alice's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed");
    TF_CHECK_MSG(nf_expect(&node, "chan_create: channel=" CHAN " origin=" NAME_A,
                           T_IO_MS) == 0,
                 "node A did not create " CHAN ", so it does not own it and its "
                 "onward forward row is not the one that runs.\n  node said: %s",
                 node.out);

    /* A's link TO C MUST BE UP BEFORE THE SJOIN GOES OUT: the owned forward row walks
     * ESTABLISHED links, so an SJOIN that arrives before that link exists has nowhere
     * to go and C never hears about the channel at all. A wait, not a sleep, and the
     * absence it rules out is on the far side of a node this test cannot see into. */
    TF_CHECK_MSG(nf_expect(&node, "link_established: peer=" NAME_C, T_IO_MS) == 0,
                 "node A never established its link to node C, so nothing it applies "
                 "here can be forwarded onward and every claim below would be about a "
                 "one-node mesh.\n  node said: %s", node.out);

    /* The peer's member, which puts "irc.b" in the channel's `servers[]` and makes the
     * member-server term of the entitlement test true. */
    stamp(block, sizeof block, 950UL);
    (void)snprintf(line, sizeof line, "%s:" PEER " SJOIN " CHAN " carol - *\r\n", block);
    TF_CHECK_MSG(pf_send_line(peer.fd, line) == 0, "the SJOIN send failed");
    TF_CHECK_MSG(nf_expect(&node, "fed_sjoin: channel=" CHAN " member=carol",
                           T_IO_MS) == 0,
                 "node A never installed the peer's member, so the channel's roster "
                 "records no other server and the member-server term is false for "
                 "every name.\n  node said: %s", node.out);

    /* C MUST HOLD #T BEFORE THE MODE CHANGE ARRIVES, or it cannot resolve the target
     * and `fed_malformed:` is all that reaches it. */
    TF_CHECK_MSG(nf_expect(&c, "fed_sjoin: channel=" CHAN " member=carol", T_IO_MS) == 0,
                 "node C never learned that " CHAN " exists. The origin's owned forward "
                 "row sends to `servers[]` UNION every established link, so C is "
                 "reached directly rather than through a third node -- which is worth "
                 "knowing, because it means this case does NOT test relay-hop "
                 "behaviour and must not be read as if it did.\n  node said: %s",
                 c.out);

    /* THE CLAIM: UNTAGGED, prefix the link's own name, `<server>` naming the origin.
     * G4 CASE A mints the identity from the link rather than reading one, which is what
     * gets a line past G6 with a subject this node's own name. */
    (void)snprintf(line, sizeof line,
                   ":" PEER " SMODES " NAME_A " " CHAN " +b " MASK "\r\n");
    TF_CHECK_MSG(pf_send_line(peer.fd, line) == 0, "the SMODES send failed");
    TF_CHECK_MSG(nf_expect(&node, "fed_modes: channel=" CHAN " by=" NAME_A, T_IO_MS) == 0,
                 "the origin did not apply the mode change naming itself, so the onward "
                 "emission below has nothing to carry.\n  node said: %s", node.out);
    TF_CHECK_MSG(strstr(node.out, "fed_modes_ban_cached: channel=" CHAN) == NULL,
                 "the origin recorded caching the ban rather than applying it, so it "
                 "does not believe it owns this channel -- and it does: alice's JOIN "
                 "created it.\n  node said: %s", node.out);

    /* AND C CACHED IT. Asserted POSITIVELY on C's own log, because C is the node the
     * onward-forward property is about: a refusal above the forward would leave
     * everything behind it permanently stale. The arrival on C is on the link named
     * " NAME_A " and the subject in the `<server>` field also names " NAME_A ", which
     * is what makes this the arrangement the old test could not pass: on a two-node
     * mesh every arrival is on the origin's own link and the check is accidentally
     * true. */
    TF_CHECK_MSG(nf_expect(&c, "fed_modes: channel=" CHAN " by=" NAME_A, T_IO_MS) == 0,
                 "the second node never cached the origin's mode change. Under the rule "
                 "this replaced it compared the <server> field against its own channel "
                 "origin, refused, and -- because the refusal sits ABOVE the forward -- "
                 "did not pass it on either.\n  node said: %s", c.out);

    /* AND NEITHER REFUSED IT, because a node that reached the refusal arm and then
     * applied the change anyway would satisfy both assertions above. These are
     * absences over buffers that belong to THIS case alone. */
    TF_CHECK_MSG(strstr(node.out, "fed_modes_ignored: channel=" CHAN) == NULL,
                 "the origin both applied the mode change and logged a refusal for it, "
                 "so the two arms are not exclusive.\n  node said: %s", node.out);
    TF_CHECK_MSG(strstr(c.out, "fed_modes_ignored: channel=" CHAN) == NULL,
                 "the second node both cached the mode change and logged a refusal for "
                 "it, so the two arms are not exclusive.\n  node said: %s", c.out);

    /* AND C DID NOT ENFORCE IT. This is 2.2's single-writer rule from the other side,
     * and it is the constraint the fix must not have moved: a cache records the LETTER
     * and nothing else, so C's `modes[]` holds `b` and C's ban list does not. The
     * observable exists because the correct behaviour here produces NO output
     * otherwise -- a cache that declines to enforce a ban is indistinguishable from a
     * cache that never heard of one. */
    TF_CHECK_MSG(nf_expect(&c, "fed_modes_ban_cached: channel=" CHAN " subject=" NAME_A,
                           T_IO_MS) == 0,
                 "the second node did not record that it cached the ban rather than "
                 "applying it. It holds the mode letter and nothing else, and the only "
                 "evidence of that is this line -- without it, a cache that enforced the "
                 "ban would be indistinguishable from one that never heard of it.\n"
                 "  node said: %s", c.out);

    TF_CHECK_MSG(nf_stop(&node) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&c) == 0, "node C did not exit cleanly");
    tc_close(&alice);
    nf_free(&node);
    nf_free(&c);
    if (peer.fd >= 0) {
        close(peer.fd);
    }
}

int main(void)
{
    case_member_server_ban_applied();
    case_third_server_claim_refused();
    case_origin_modes_reach_second_node();

    tf_done("test_fed_mode_authority");
    return 0;
}
