/* test_fed_roster.c -- cross-server channel membership, asserted on BOTH nodes.
 *
 * docs/SERVER_DESIGN.md 7/Phase 6, acceptance criterion 1 and the join half of
 * criterion 2: "a user on node A JOINs a channel and a user on node B JOINs the
 * same channel; the FULL 353 CONTENTS on each node, in the Phase 4 order -- a
 * truncated roster does not pass".
 *
 * ---------------------------------------------------------------------------
 * WHY TWO CHILDREN AND NOT ONE NODE WITH TWO CLIENTS
 * ---------------------------------------------------------------------------
 * The thing under test is a fact that exists on two machines and nowhere else:
 * what each node's 353 says after each has been told about the other's member.
 * A single node with two clients already knows both names from its own
 * registrations, so it would exercise the render and not the federation, and
 * the acceptance criterion would pass on a node with no peer link at all. 6.2
 * wants two child processes over real TCP and this is 6.2's fixture.
 *
 * ---------------------------------------------------------------------------
 * THE FIXTURE MECHANICS, AND WHY THE PARENT FILLS A GLOBAL BETWEEN TWO SPAWNS
 * ---------------------------------------------------------------------------
 * nf_spawn_inline_named() forks a child that binds port 0 and REPORTS the port
 * over its own stdout, so node A's port only exists in the parent AFTER the
 * first fork has already happened and the child is running. Node B, which has to
 * be told A's address, therefore cannot be configured before A exists.
 *
 * The fix is that a forked child inherits the parent's memory AS OF fork(), so
 * the parent fills a file-static global BETWEEN the two spawns: spawn A (which
 * reports A.port), set g_peer_port = A.port, then spawn B, whose setup() reads
 * the already-populated global. The value B reads is the one the parent wrote
 * before the fork, which is the only ordering that works and is why the global
 * is documented as pre-fork state rather than as a convenience.
 *
 * ONE DIRECTION ONLY, and the reason is a limitation C2 documented rather than
 * hid (federation/link.h, "THE LIMITATION C2 LEAVES, NAMED"): a node that
 * configures BOTH ends of a pair both dials, neither accepts, and the pair ends
 * up with no link at all. So node A is configured with NO peer at all and node B
 * with the name AND A's address.
 *
 * "No peer at all" rather than "the name with no address", because
 * fed_link_configure() cannot express the latter: it REFUSES a NULL address and
 * it always creates the link with initiator set, so there is no way to declare a
 * peer this node will recognise but never dial. That is not a gap -- 2.3 says a
 * peer is "rejected before ESTABLISHED" and makes the HANDSHAKE, not the
 * configuration, the place a peer is identified -- so the accepting side is
 * expressed the way the design expresses it: the inbound FEDERATE's claim
 * configures the link, through fed_claim_accepted(). A test that wanted a
 * pre-declared accepting peer would need fed_link_configure() to grow a
 * no-address mode, and nothing in this phase needs one.
 *
 * Both directions of the resulting link work, because a peer link is ONE socket
 * used both ways (2.3), so this is not a half-link and not asymmetric cheating;
 * it is a mesh where the dialling side is picked once.
 *
 * `nf_expect_u64_ge()` FOR ANY lines= ASSERTION, and never equality: T3 puts a
 * keepalive on every ESTABLISHED link every 30 s and every line a node RECEIVES
 * is framed and counted in n_lines, so on a linked node that number climbs with
 * no client involved. An equality assertion is a race against a timer, and this
 * suite has been bitten by exactly that race (see the header of
 * test_fed_handshake.c).
 *
 * NO FIXED sleep() ANYWHERE (6.3). Every wait is a deadline: nf_expect() over a
 * child's stdout, tc_expect() over a socket.
 */
#include <errno.h>
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
#define TOPIC "a topic only the origin set"

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

/* ---------------------------------------------------------------------------
 * The assertion
 * ---------------------------------------------------------------------------
 * `groups` are the 353 LINES the roster must contain, IN ORDER, one entry per
 * line: 7/Phase 4's fixed order is "nicks, then ops, then voiced", and this node
 * renders one 353 per group rather than one per roster, so the order that must be
 * asserted is the order of the LINES and not the order of the names within a
 * line.
 *
 * THAT IS WHY THE ORDER IS THE ASSERTION AND NOT A SET. A roster that carried
 * both names under each other would be a roster this node produced by a rule
 * nobody wrote down, and a test built from per-name substring checks passes
 * against it. So each line is searched for FROM THE END OF THE PREVIOUS ONE: a
 * line that appears out of order is not found, and a roster with the two lines
 * swapped fails.
 *
 * A TRUNCATED ROSTER DOES NOT PASS, and that is the other half of the criterion.
 * Checking for one name at a time would pass a 353 carrying only alice, which is
 * the failure mode a cross-server roster has: the local member is always there
 * and the REMOTE one is the thing that has to arrive.
 *
 * The 366 is asserted last and separately, because 7/Phase 4 requires the
 * terminator to be LAST: a 366 that arrived before the names would be a truncated
 * list that happens to contain them.
 *
 * `who_nick` is the ASKING client, which is 353's <client> parameter. The shape
 * is `:server 353 <client> = <channel> <names>` -- RFC 2812 3.3.5's
 * `:server 353 <client> <channel> :<names>` with this node's `=` symbol as the
 * first middle parameter. Note there is NO colon before the names: reply.c
 * renders a trailing value without the marker when it needs none, and a needle
 * written with one can never match.
 */
static void expect_roster(test_client_t *client, const char *who,
                          const char *who_nick, const char *const *groups,
                          size_t ngroups)
{
    const char *p = tc_buffer(client);
    char want[256];

    for (size_t i = 0; i < ngroups; i++) {
        const char *at;

        (void)snprintf(want, sizeof want, " 353 %s = " CHAN " %s\r\n", who_nick,
                       groups[i]);
        if (i == 0) {
            /* THE FIRST LINE IS WAITED FOR AND THE REST ARE SEARCHED, and the
             * split is not tidiness. `tc_buffer()` is whatever the PARENT has
             * happened to read off the socket, and a strstr() against it is a
             * race: the cross-node 353 arrives some milliseconds after the JOIN
             * that caused it, so a test that searched instead of waiting would
             * pass on a machine where the bytes arrived in one read() and fail
             * on one where the read stopped between them. test_fed_handshake.c's
             * header records this suite being bitten by exactly that race, on
             * Apple clang while passing on GCC.
             *
             * The remaining lines are searched FROM THE END OF THE PREVIOUS ONE,
             * which is what makes the order the assertion: a line that appears
             * earlier is not found, and the search never restarts. */
            TF_CHECK_MSG(tc_expect(client, want, T_IO_MS) == 0,
                         "%s: 353 line %zu of %zu (\"%s\") never arrived. The "
                         "roster is what 7/Phase 6's acceptance criterion is "
                         "about and a truncated one does not pass.\n"
                         "  client saw: %s",
                         who, i + 1u, ngroups, groups[i], tc_buffer(client));
            if (tc_expect(client, want, 0) != 0) {
                return;
            }
        }
        at = strstr(p, want);
        TF_CHECK_MSG(at != NULL,
                     "%s: 353 line %zu of %zu (\"%s\") is out of order. "
                     "7/Phase 4 fixes the order as nicks, then ops, then voiced, "
                     "and this node renders one line per group.\n"
                     "  client saw: %s",
                     who, i + 1u, ngroups, groups[i], tc_buffer(client));
        if (at == NULL) {
            return;
        }
        p = at + strlen(want);
    }
    TF_CHECK_MSG(tc_expect(client, " 366 ", T_IO_MS) == 0,
                 "%s got no 366 after its roster, so the list is not terminated "
                 "and the node cannot say which names were the whole list: %s",
                 who, tc_buffer(client));
}

/* ---------------------------------------------------------------------------
 * THE CASE
 * ---------------------------------------------------------------------------
 * bob JOINs on B FIRST, and the order is load-bearing rather than incidental.
 *
 * A JOIN on a node that has never heard of a channel CREATES it there, with that
 * node as its origin (2.2: first server to see a channel owns it). So whichever
 * node joins first owns the channel, and the other node's first SJOIN is what
 * teaches it the channel exists -- fed_in_channel() creates it from the SJOIN
 * with the SENDER as origin, which is the same rule arriving over the wire.
 *
 * With bob first, node B owns #T and node A does not, and that is what makes A a
 * FORWARDING participant rather than a second origin: alice's JOIN on A is a
 * local membership fact (chan_verbs.c's documented JOIN exception) whose SJOIN
 * goes to B, and a message alice sends afterwards is a `message` on a non-owned
 * channel, which 3.1 routes to the owner. With alice first, A would own the
 * channel and 3.1's owned/`message` row forwards nothing at all, so the
 * cross-server message path would never be exercised and both nodes would claim
 * ownership of the same channel -- a split 2.2's tie-break exists to prevent and
 * one that cannot be resolved from an SJOIN, because the epoch of the FIRST
 * creator only arrives in 4.3's SBURST vocabulary.
 *
 * ---------------------------------------------------------------------------
 * AND A SECOND ORDERING, BETWEEN THE TWO NODES RATHER THAN BETWEEN THE TWO JOINs
 * ---------------------------------------------------------------------------
 * The section above settles WHICH node creates the channel. It does not settle
 * WHEN node A hears about it, and that is a separate race in a separate process:
 * B forwards bob's SJOIN from its own poll tick, A applies it on one of its own,
 * and everything this test does between the two JOINs happens on B's socket, so
 * it gives A no reason to be further along.
 *
 * If A is still behind when alice's JOIN lands then A has never seen #T, creates
 * it (2.2 again), and makes alice its creator and therefore its operator -- so
 * alice's roster comes back ops-only and the ` 353 alice = #T alice` line this
 * case asserts is never sent by anyone, ever. Nothing is broken at that point;
 * the case asked a node about the world before the world had arrived, and then
 * waited out its whole deadline against a line that was not coming. This is what
 * the Phase 6 CI failures in this case were: a 15 s timeout with the node's
 * counters entirely consistent with a node that had done nothing wrong.
 *
 * So A's `fed_sjoin:` line is waited for BEFORE alice's JOIN, where it is a
 * precondition on the assertion, and the same line is still asserted at the end
 * of the case for what it says rather than for when it arrived.
 */
static void case_cross_node_roster(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;
    test_client_t bob;

    /* Node A first: it reports its port, and the parent cannot configure B until
     * it has. */
    g_peer_port = 0;
    g_trace = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    TF_CHECK_MSG(a.port > 0, "node A reported no port");

    /* THE STEP THE WHOLE FIXTURE TURNS ON. A's port is only known here, in the
     * parent, after A's fork; writing it into a global now means the child that
     * becomes B inherits it, and B's setup() reads it. */
    g_peer_port = a.port;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");

    /* The precondition, asserted before the case is worth anything: without a
     * link, every assertion below would be satisfied by two nodes that never
     * spoke. B is the initiator, so B is where the dial is visible. */
    TF_CHECK_MSG(nf_expect(&b, "link_dial: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never dialled its configured peer");
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A");

    /* A PING as a drain token on B, so B has finished processing the handshake
     * before a client is attached to it and the ordering of the rest is about
     * JOINs rather than about the handshake. */
    register_client(&alice, a.port, NICK_A);
    register_client(&bob, b.port, NICK_B);

    /* bob joins FIRST, on B, which is therefore the origin. */
    TF_CHECK_MSG(tc_send(&bob, "JOIN " CHAN) == 0, "bob's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob's JOIN never completed on the node that owns the channel");
    /* The origin's own roster, before any federation has happened: bob alone.
     * This is the CONTROL for the cross-node case. It is asserted as the EXACT
     * one-name line, so that a cross-node assertion below which passed with only
     * one name could not be passing on the local member -- which is the failure
     * mode a cross-server roster has, because the local member is always there
     * and the remote one is the thing that has to arrive. */
    /* `@bob` and not `bob`: bob CREATED the channel, and RFC 1459 2.3.1 makes
     * the creator an operator. So the origin's own roster is also the first
     * proof that the Phase 4 grouping is in force -- an op is rendered with its
     * prefix and in the op group, and this node puts the op group in a second
     * 353. The control is therefore TWO lines, in this order, and the
     * cross-node assertion below has the same shape. */
    {
        const char *const own[] = { "@" NICK_B };

        expect_roster(&bob, "bob before alice joined", NICK_B, own, 1u);
    }

    /* THE PRECONDITION ALICE'S ROSTER DEPENDS ON, AND IT IS WAITED FOR HERE
     * BECAUSE IT IS A PRECONDITION, NOT BELOW WHERE IT USED TO BE.
     *
     * alice's JOIN makes A render a roster, and what that roster can contain is
     * fixed by what A already knows about #T at that instant. If A has already
     * applied bob's SJOIN then A knows #T came from %s, does NOT own it, and
     * renders `alice` in the plain group and `@bob` in the ops group -- the two
     * lines this case asserts. If A has NOT applied it yet then #T does not
     * exist on A at all, alice's JOIN CREATES it there (2.2: first server to see
     * a channel owns it), alice becomes the creator and therefore an operator
     * (RFC 1459 2.3.1), and the roster comes back ops-only: `@alice`. The needle
     * ` 353 alice = #T alice` then cannot match anything this node will ever
     * send, and the case waits out its whole deadline against a line that is not
     * coming. That is the failure, and it is a failure of the WAIT rather than of
     * the roster: the node rendered correctly for the state it was in.
     *
     * THE ORDERING IS THE WHOLE POINT, and it is a real ordering rather than a
     * stylistic one. B's forward of bob's SJOIN and A's processing of it are
     * events in two different processes, separated by two poll ticks at worst,
     * and between them this test does a client round trip on B. Nothing in the
     * round trip makes A wait. So the question "does A know bob yet?" is a race,
     * and on a loaded runner A can lose it -- and then the test reports a
     * federation defect that is not there.
     *
     * `chan_remote_add()` runs BEFORE the `fed_sjoin:` line is printed
     * (federation/verbs.c, fed_in_sjoin), so this line is not merely "B tried to
     * send it": it is A having applied it. That is what makes it a usable
     * precondition rather than just another observable.
     *
     * The assertion at the end of this case checks the same line and is KEPT.
     * It is the one that carries the origin/owned/remote detail, and this wait is
     * about ordering rather than about what the line says. */
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=" CHAN " member=" NICK_B,
                           T_IO_MS) == 0,
                 "node A never applied bob's SJOIN, so alice's JOIN would reach a "
                 "node that has never heard of %s and would create it there with "
                 "alice as its operator. The roster this case asserts would be a "
                 "different roster, so the case cannot proceed: %s",
                 CHAN, a.out);

    /* alice joins on A. A does not own the channel, so this is the JOIN
     * exception: the local membership happens and the SJOIN is forwarded. */
    TF_CHECK_MSG(tc_send(&alice, "JOIN " CHAN) == 0, "alice's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed on the node that does not own the "
                 "channel");

    /* BOTH nodes, both names, in order. This is the acceptance criterion, and
     * the two assertions are independent: A's is about the SJOIN's member
     * arriving, and B's is about A's membership being reported to the origin. */
    /* `alice` then `@bob`, on BOTH nodes, and that is the Phase 4 order doing
     * its job: alice is a plain member and bob is an op, so the plain name is in
     * the first 353 and the op in the second -- on the origin's own node and on
     * the non-owning one alike. A node that appended remote members after the
     * local ones regardless of their flags would render one line containing
     * `@bob alice`, or two lines in the other order, and this test fails on
     * either. */
    {
        const char *const both[] = { NICK_A, "@" NICK_B };

        /* A's roster, out of the JOIN itself: alice joined AFTER bob's SJOIN
         * arrived, so the 353 her JOIN produced already names both of them. That
         * is the non-owning node's half of the criterion and it costs no extra
         * command. */
        expect_roster(&alice, "alice on the non-owning node", NICK_A, both, 2u);

        /* B's roster has to be ASKED FOR, and that is a real property of the
         * protocol rather than a shortcut in the test: a node does not
         * spontaneously repaint a client's roster when a peer reports a new
         * member. C3 delivers the member into the ROSTER and not as a channel
         * echo (federation/verbs.c says why: an inbound SJOIN carries a server
         * prefix and a client cannot be shown a JOIN from one), so the origin's
         * own member learns about alice the next time it asks. */
        TF_CHECK_MSG(tc_send(&bob, "NAMES " CHAN) == 0, "bob's NAMES send failed");
        expect_roster(&bob, "bob on the owning node", NICK_B, both, 2u);
    }

    /* The node counters that make the two assertions mean something. On A, the
     * SJOIN from B is the thing that created the channel and the thing that put
     * bob in the roster; on B, alice's SJOIN is the thing that put alice in it.
     * Both are observable lines rather than struct reads, because a test that
     * inspects chan_t proves nothing about the wire and breaks on a
     * restructuring. */
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=" CHAN " member=" NICK_B,
                           T_IO_MS) == 0,
                 "node A never reported accepting an SJOIN for bob, so alice's "
                 "roster cannot have got bob's name from a peer: %s",
                 a.out);
    TF_CHECK_MSG(nf_expect(&b, "fed_sjoin: channel=" CHAN " member=" NICK_A,
                           T_IO_MS) == 0,
                 "node B never reported accepting an SJOIN for alice, so bob's "
                 "roster cannot have got alice's name from a peer: %s",
                 b.out);
    /* The channel each node believes it is: A must NOT think it owns the channel
     * it learned about, or every state change on it would be applied twice. */
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=" CHAN " member=" NICK_B
                           " server=" NAME_B " flags=1 local=0 remote=1 origin="
                           NAME_B " owned=0",
                           T_IO_MS) == 0,
                 "node A did not record #T as a channel it does not own with one "
                 "remote member from %s, which is what an SJOIN from the origin "
                 "has to produce: %s",
                 NAME_B, a.out);

    /* And the convergence is not a coincidence of the roster: the SJOINs
     * themselves are counted, one each. Two would mean the fan-out is
     * double-sending, and the dedup store is what would have to catch it. */
    TF_CHECK_MSG(tf_count(a.out, "fed_sjoin: channel=" CHAN) == 1,
                 "node A reported %lu SJOINs for the channel; the fan-out target "
                 "set is servers[] UNION the ESTABLISHED links, and the peer must "
                 "appear in it once",
                 (unsigned long)tf_count(a.out, "fed_sjoin: channel=" CHAN));

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    /* A last check on the whole story, after both nodes have published their
     * final counters: neither dropped the line as a duplicate, so the
     * convergence came from the forward and not from one side swallowing it. */
    TF_CHECK_MSG(nf_expect_u64(&a, "fed_dup_drop=", 0, 1000) == 0,
                 "node A dropped an SJOIN as a duplicate, so its roster only "
                 "converged by luck: %s",
                 a.out);
    TF_CHECK_MSG(nf_expect_u64(&b, "fed_dup_drop=", 0, 1000) == 0,
                 "node B dropped an SJOIN as a duplicate, so its roster only "
                 "converged by luck: %s",
                 b.out);

    tc_close(&alice);
    tc_close(&bob);
    nf_free(&a);
    nf_free(&b);
}

int main(void)
{
    case_cross_node_roster();
    tf_done("fed_roster");
    return 0;
}
