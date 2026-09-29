/* test_fed_burst.c -- 4.3's SBURST, and the two properties it exists for.
 *
 * docs/SERVER_DESIGN.md 4.3 ("A resync REPLACES state for that origin; it never
 * merges. There is no partial burst and no delta") and 7/Phase 6, acceptance
 * criterion 2: "the FULL 353 CONTENTS on each node, in the Phase 4 order -- a
 * truncated roster does not pass".
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS FILE PROVES
 * ---------------------------------------------------------------------------
 * That a resync moves a ROSTER, and that it replaces rather than merges.
 *
 * The roster half is acceptance criterion 2 asserted on BOTH nodes after the two
 * nodes have exchanged a burst: not "NAMES answers something" but the full 353
 * contents, in Phase 4's order (nicks, then ops, then voiced), terminated by a
 * 366, with BOTH names in it -- because the local member is always there and the
 * REMOTE one is the thing that has to arrive.
 *
 * The replace half is three resyncs over one already-established link, each of
 * which must leave the receiver's picture of the SENDER's state exactly as the
 * sender last reported it and not one record more. Three, because "replaces,
 * never merges" is three different claims and a burst that merges fails all
 * three in different ways:
 *
 *   #1  the roster is already right -- a resync must not damage it. A merge
 *       passes this one, and it is here because a resync that damages a correct
 *       roster is a worse defect than one that fails to refresh a stale one.
 *   #2  the origin has DE-PRIVILEGED a member -- the receiver must show the new
 *       flags. NO POUNGLY POKE IS INVOLVED: the de-op is an ordinary MODE from an
 *       ordinary client, and a merge leaves the old +o entry standing because the
 *       new record is recognised as already-known and skipped. The client is then
 *       shown a privilege the origin has taken away.
 *   #3  the origin has LOST a member -- the receiver must forget the name. See
 *       the honesty note below: this one cannot be produced by client commands,
 *       and the fixture says so in its own log.
 *
 * ---------------------------------------------------------------------------
 * WHY #3 NEEDS THE TICK HOOK, AND WHAT THAT POKE IS NOT
 * ---------------------------------------------------------------------------
 * On a two-node mesh, a member the ORIGIN no longer has is always removed from
 * the RECEIVER by an SPART first, and there is no other route: the only way node
 * A stops reporting a member of a channel is for A to stop having them, and A
 * having them is a local membership that 2.2 removes by a PART -- which A
 * forwards. So the SPART removes them on B, the burst never had to, and a merge
 * and a replace agree. This is a property of the topology rather than of this
 * implementation, and it is why the fixture has to put A's state wrong behind the
 * wire's back.
 *
 * SO THE FIXTURE REMOVES THE MEMBERSHIP SILENTLY, from the CHILD's own tick hook,
 * through chan_remove_member() -- the function channel.h documents as "used where
 * the caller has already broadcast the departure". The fixture deliberately does
 * NOT broadcast it: that is the poke, it is the point, and chan_remove_member()
 * exists separately from chan_member_leave() precisely because it emits nothing.
 * The shape is the one tests/integration/test_channels.c uses to drive
 * chan_rekey from a tick, and the parent never touches the child's server_t --
 * every assertion below is on the WIRE, on a client's socket or on a node's own
 * `[observable]` output.
 *
 * IT IS NOT VACUOUS, and the thing that makes it not vacuous is that resync #2 --
 * which involves no poke at all -- has to have moved the same member's flags on
 * the same channel first. A run in which the poke silently did nothing is a run in
 * which #2's assertion is also measuring nothing, and the case would be reporting
 * on a fixture that forgot to poke rather than on a merge.
 *
 * ---------------------------------------------------------------------------
 * WHERE #U COMES FROM, AND WHY A IS NOT IGNORANT OF IT
 * ---------------------------------------------------------------------------
 * The obvious design for the per-origin check is a second channel created "on B
 * only", meaning a channel A has never heard of. THAT IS NOT REACHABLE ON A
 * TWO-NODE MESH, and the reason is 3.1's amended owned/`state-change` arm: it
 * forwards to `servers[ch] UNION every ESTABLISHED link`, and B is an established
 * link, so B's SJOIN for a channel B created reaches A and A holds a copy. That is
 * the amendment working as designed -- it is what lets a new channel reach a relay
 * -- and the consequence is that #U is in A's burst.
 *
 * WHICH MAKES THE CHECK STRONGER, not weaker. A's burst NAMES #U, the receiver
 * visits it in its channel loop, and the only reason dave is still in the roster is
 * that the replacement is keyed by the ORIGIN: the record's origin is irc.b and the
 * purge is for irc.a. An implementation that purged every channel the burst
 * mentioned -- an "erase and refill" rather than a per-origin replace -- empties
 * #U, and this is the case that catches it.
 *
 * "NAMES #U -> 366 and no 353" is not an observation this node can make, and
 * saying so is better than writing a needle that can never match: a channel that
 * EXISTS always answers NAMES with at least one 353, because a channel with no
 * member in any group is answered with one explicitly empty 353 rather than with
 * silence (send_names_list in chan_verbs.c). So the assertion is the roster's
 * exact contents PLUS the 366 terminator, and the 366 is what proves the channel
 * survived rather than having been disposed and answered with 403.
 *
 * ---------------------------------------------------------------------------
 * THE FIXTURE
 * ---------------------------------------------------------------------------
 * nf_spawn_inline_named() forks a child that binds port 0 and reports the port, so
 * node A's port only exists in the parent after A's fork. The parent writes it
 * into a file-static global between the two spawns and the child that comes next
 * inherits it -- the only ordering that works, and the reason the global is
 * documented as pre-fork state rather than as a convenience.
 *
 * ONE DIRECTION PER PAIR, because a node that configures BOTH ends of a pair both
 * dials, neither accepts, and the pair ends up with no link at all --
 * federation/link.h names that limitation and Phase 9 owns fixing it. A is
 * configured with no peer (the inbound FEDERATE's claim configures its link) and B
 * with the name AND A's address. Both directions of the resulting link work,
 * because a peer link is ONE socket used both ways.
 *
 * THE RESYNCS ARE DRIVEN FROM THE CHILD'S OWN TICK HOOK, chained after fed_tick,
 * for the reason tests/integration/test_channels.c chains its chan_rekey driver
 * there rather than replacing the hook: node_main.c installs the federation tick
 * VISIBLY, and a child that replaced it would have a link that never dials and
 * never dies, which it would read as a federation failure.
 *
 * AND THEIR GATES ARE STATES THE PARENT CREATES, which is the whole of how the
 * sequence avoids being a race. A forked child cannot see anything the parent
 * writes after the fork, so a resync cannot be triggered by a later global; it has
 * to be triggered by something the parent does ON THE WIRE, which the child can
 * observe through its own registries:
 *
 *   resync #1   A holds two registered nicks      (after the parent registers ann)
 *   resync #2   A's local member of #T is not an op (after the parent's de-op)
 *   resync #3   A holds three registered nicks      (after the parent registers eve)
 *
 * Registering a client is a deliberate choice of trigger for #1 and #3: it changes
 * the node's nick count, it is something the parent controls exactly, and -- unlike
 * a tick counter or a wall clock -- it cannot happen by accident before the
 * assertions that must precede it. The assertions in step 5 below are only
 * race-free BECAUSE resync #1 is gated on a second registration.
 *
 * THE THREE RESYNCs HAVE DISTINCT NUMBERS in the `fed_burst_applied` line, which
 * is not a stylistic choice. nf_expect() searches everything a node has printed, so
 * a needle that matched the first resync would satisfy a wait for the third; the
 * cases are told apart by the counts in the line, and each of the three needles
 * below names a (nicks, chans, members, installed, purged) tuple that only that
 * resync can produce.
 *
 * nf_expect_u64_ge() FOR ANY lines= ASSERTION, and never equality: T3 puts a
 * keepalive on every ESTABLISHED link every 30 s and every line a node RECEIVES is
 * framed and counted in n_lines, so on a linked node that number climbs with no
 * client involved.
 *
 * AND ON CEILING WHAT A CASE CAN PROVE ABOUT THE WIRE. SBURSTM now carries the
 * member's own <server> (4.3.1), and on a two-node mesh that field is always the
 * burst origin -- which is exactly the mesh this file builds. So the assertions
 * here CANNOT tell a receiver that stored the wire's <server> from one that fell
 * back to the origin, and this file does not pretend otherwise: the four
 * parameters' shape is asserted (a three-parameter SBURSTM is a malformed line,
 * and fed_malformed= at the end of the truncation case is what says so), the
 * field is exercised, and what it is WORTH is not measurable until there is a
 * third node. docs/SERVER_DESIGN.md 4.3.1 records the same limit in the design
 * rather than in a test, and the honest statement of it is here.
 *
 * NO FIXED sleep() ANYWHERE (6.3). Every wait is a deadline: nf_expect() over a
 * child's stdout, tc_expect() over a socket.
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
#include "federation/burst.h"
#include "federation/link.h"
#include "federation/verbs.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define SECRET "irc-serve-federation-secret-a"
#define NAME_A "irc.a"
#define NAME_B "irc.b"
#define CHAN_T "#T"
#define CHAN_U "#U"
#define NICK_A "alice" /* on A, and the CREATOR of #T there */
#define NICK_B "bob"   /* on B */
#define NICK_C "carol" /* on B */
#define NICK_D "dave"  /* on B, and the CREATOR of #U there */
#define NICK_E "ann"   /* on A, never joins: the gate for resync #1 */
#define NICK_F "eve"   /* on A, never joins: the gate for resync #3 */

/* The staging budget case_burst_refused() shrinks node A's QUEUE to.
 *
 * IT SITS BETWEEN TWO MEASURED THINGS, and choosing it by measurement rather than
 * by taste is the whole of the case: an EMPTY transaction -- the SBURST/SBURSTE
 * pair and nothing between them, which is what node A sends on establishment
 * because it has no clients yet -- renders 227 bytes at this node's widths, and
 * the same transaction carrying two nicks renders 483. 320 is above the first by
 * 93 and below the second by 163, so the case refuses a burst that has CONTENT in
 * it and not one that has none, and the control -- the establishment burst going
 * out under the very same budget -- is a fact rather than a hope. Both margins are
 * orders of magnitude larger than the one byte per line that the message-id
 * counter can add, so the case cannot sit on the boundary. */
#define BURST_TEST_SEND_BUDGET ((size_t)320u)

/* The shadow budget case_over_budget_changes_nothing() shrinks node B's to.
 *
 * A DIFFERENT NUMBER FOR A DIFFERENT ACCOUNTING, and that is the whole reason
 * there are two constants. A charge is not a rendered line: it is
 * IRC_MAX_TAG_OVERHEAD (the frozen 179-byte worst case) plus the prefix, the verb
 * and the parameters, so an empty transaction CHARGES about 420 where it RENDERS
 * 227. The charge is deliberately pessimistic and a peer cannot shrink it by
 * having a short server name.
 *
 * 1400 IS CHOSEN TO TRIP INSIDE THE MEMBER RECORDS, and that is the number's
 * whole job rather than a round figure. The transaction this case sends is a BEGIN,
 * two nick records, one channel record, three member records and a COMMIT; measured
 * on this node it charges 1298 by the end of the FIRST member line and 1508 in
 * full. 1400 is above 1298 by 102 and below 1508 by 108, so the transaction is
 * refused part way through its MEMBERS -- which is the only place a leak is
 * observable on this node, because a member record the node already holds is
 * idempotent and only a CHANGED one shows. A budget that tripped on the channel
 * header would prove the same arithmetic and nothing about a member.
 *
 * BOTH NUMBERS ARE MEASURED AND BOTH MOVE WHEN A FIELD WIDTH DOES: SBURSTM's
 * <server> field added 6 bytes per member line in Phase 6 C5 (strlen("irc.a") + a
 * separator, on the two records the transaction trips over), and the full figure
 * was 1766 in the comment before that change while actually being 1508 -- which is
 * why this says "measured" rather than giving a derivation nobody re-ran. A test
 * asserting either number would be testing the constants rather than the
 * behaviour, so neither is asserted; they are stated so the next person who
 * changes a width knows to re-measure.
 *
 * Both margins are two orders of magnitude larger than the one byte per line the
 * message-id counter can add, so the case cannot sit on the boundary. */
#define BURST_TEST_RECV_BUDGET ((size_t)1400u)

/* PRE-FORK STATE. The parent sets g_peer_port from A's reported port and spawns B;
 * B's setup() reads it. Zero means "configure no peer at all", which is how node A
 * is set up. */
static int g_peer_port;
static int g_trace;

/* WHICH NODE THE CHILD IS. A global rather than a second setup function, because a
 * forked child cannot see anything the parent writes after the fork, so the tick
 * hook has to know from the moment it is installed. */
static int g_is_b;

/* The resyncs node A has already driven, which the tick hook walks. */
static int g_stage;

/* SHRINK THE BOUND, IN ONE DIRECTION OR THE OTHER, for the two refusal cases.
 * Pre-fork state, like every other global here. Two globals and not one because
 * the bound is SYMMETRIC in the code and the two halves are different mechanisms:
 * the sender's is a staging buffer measured in bytes of wire, and the receiver's
 * is a shadow measured in charged records. A case that shrank both at once would
 * be unable to say which half refused, and the two cases below are about one each.
 * See case_burst_refused() and case_over_budget_changes_nothing() for why the
 * shipped bound is not what a test would want to provoke. */
static int g_tiny_send;
static int g_tiny_recv;

/* SEND A DELIBERATELY TRUNCATED TRANSACTION INSTEAD OF A RESYNC, for
 * case_truncated_burst_changes_nothing(). Pre-fork state, like the rest. */
static int g_truncate;

/* SEND A BEGIN AND NOTHING ELSE INSTEAD OF A RESYNC, for
 * case_open_transaction_released_at_shutdown(). Pre-fork state, like the rest --
 * the tick hook cannot see anything the parent sets after the fork. */
static int g_open_burst;

/* Defined below, with the wire format written out. Forward-declared rather than
 * moved so the RESYNC DRIVER -- the thing every case in this file is about -- reads
 * first and the one case that bypasses it reads as the exception it is. */
static void send_truncated_burst(server_t *s, server_link_t *link);
static void send_open_burst(server_t *s, server_link_t *link);

/* ---------------------------------------------------------------------------
 * THE RESYNC DRIVER
 * ---------------------------------------------------------------------------
 * This is a FIXTURE, and the line with the most weight in it is the comment on the
 * poke. Everything else it does is what the production code does on a link
 * establishment -- federation/link.c calls the same function -- and the difference
 * is WHEN, plus the one thing only a fixture may do.
 */
static void offer_resync(server_t *s)
{
    chan_t *ch;

    if (g_is_b != 0) {
        /* NODE B DRIVES EXACTLY ONE, AND THAT IS A DIFFERENT CLAIM FROM A's THREE.
         * A's three are about what a burst does to the RECEIVER's roster. This one
         * is about the RECEIVING side of a node that owns channels of its own and
         * holds somebody else's member of a channel it does not own: A applying B's
         * burst purges irc.b out of a channel where irc.b is two of the three
         * members, and puts them back, and does the same for a channel A does not
         * own at all. Neither of those happens on B in A's resyncs -- B is the
         * non-owner on #T throughout -- so without this the code that installs a
         * member onto a node that holds the member LOCALLY would never run, and
         * that is the branch `member_known()` exists for.
         *
         * The gate is B's own #T holding two local members, which happens when
         * carol joins, and it is a stronger gate than a tick count for the reason
         * the others are: the parent controls it from the wire, so it cannot have
         * happened before the assertions that must precede it. */
        server_link_t *link = server_find_link(s, NAME_A);

        if (g_stage >= 1 || link == NULL) {
            return;
        }
        ch = server_chan_get(s, CHAN_T);
        if (ch == NULL || ch->nmembers < 2u || server_chan_get(s, CHAN_U) == NULL) {
            return;
        }
        g_stage = 1;
        if (federation_resync(s, link) == 0) {
            printf("[fixture] resync_offered: side=b stage=1\n");
        } else {
            printf("[fixture] resync_refused: side=b stage=1\n");
        }
        fflush(stdout);
        return;
    }
    if (g_stage >= 3) {
        return; /* node A drives three, and no more */
    }
    ch = server_chan_get(s, CHAN_T);
    if (ch == NULL || ch->nmembers == 0u) {
        return; /* not yet: alice has not JOINed */
    }
    if (g_stage == 0) {
        if (g_open_burst != 0) {
            /* Straight to 3, for the reason the truncated case below gives: this
             * case sends one hand-built transaction ONCE, and the stage-1 branch
             * would send a second one on the next tick, so the node under test
             * would be holding a shadow the case cannot account for. */
            g_stage = 3;
            send_open_burst(s, server_find_link(s, NAME_B));
            return;
        }
        if (g_truncate != 0) {
            /* THIS CASE SENDS A HAND-BUILT TRANSACTION INSTEAD OF A RESYNC, and it
             * waits for the de-op first so that the one member record the
             * transaction does carry is a CHANGE -- which is the only thing that
             * makes believing the terminator visible on the wire. The gate is
             * therefore the de-op and not the second registration, and it is the
             * same predicate the resync stage below uses, read at the point where
             * the two arrangements part company. */
            if (chan_has_flag(ch, ch->members[0].c, CHAN_MEMBER_OP) != 0) {
                return;
            }
            /* Straight to 3 rather than to 1: this case does one thing ONCE, and
             * the stage-1 branch below would send a second transaction on the next
             * tick -- which is how a fixture ends up with a receiver that discarded
             * two transactions and a counter that no longer identifies either. */
            g_stage = 3;
            send_truncated_burst(s, server_find_link(s, NAME_B));
            return;
        }
        if (server_nick_count(s) < 2u) {
            return; /* ann has not registered */
        }
        g_stage = 1;
        if (g_tiny_send != 0) {
            /* THE REFUSED ATTEMPT, and then IMMEDIATELY A GOOD ONE, both in this
             * one tick and both driven through the same product function. The
             * recovery is the point: a refusal that took the link down, or that
             * left the next resync unable to run, would be a different defect and
             * this case would pass on it. Restoring the budget before the second
             * attempt is what makes "the node resyncs again" an assertion rather
             * than an assumption. */
            (void)federation_resync(s, server_find_link(s, NAME_B));
            printf("[fixture] resync_refused_tiny: stage=1\n");
            fflush(stdout);
            fed_burst_set_max_bytes(IRC_BURST_MAX_BYTES);
        }
    } else if (g_stage == 1) {
        if (chan_has_flag(ch, ch->members[0].c, CHAN_MEMBER_OP) != 0) {
            return; /* the de-op has not happened yet */
        }
        g_stage = 2;
        if (g_truncate != 0) {
            send_truncated_burst(s, server_find_link(s, NAME_B));
            return;
        }
    } else {
        if (server_nick_count(s) < 3u) {
            return; /* eve has not registered */
        }
        /* THE POKE, and the only line in this file that reaches inside the node it
         * is testing. See the header: on a two-node mesh the case this makes is
         * otherwise unreachable, because a member the origin loses is always
         * removed on the far side by an SPART before any burst is involved.
         *
         * chan_remove_member() and NOT chan_member_leave(): the first emits
         * nothing, which is the entire point. The second broadcasts a PART and
         * forwards an SPART, and the far side would then drop the member for the
         * ordinary reason -- after which the assertion that follows would pass
         * against a merge as well, and the case would measure nothing.
         *
         * THE CHANNEL SURVIVES IT, and that matters: A's #T still records irc.b
         * in servers[] because bob and carol are remote members of it there, so
         * chan_dispose_if_empty() keeps it and A's third burst still names #T.
         * Had the channel been disposed, the burst would have had nothing to say
         * about it and the case would be measuring the channel-disposal branch
         * rather than the roster one. */
        (void)chan_remove_member(ch, ch->members[0].c);
        g_stage = 3;
    }
    /* THE PRODUCT FUNCTION, called the way federation/link.c calls it -- not
     * fed_burst_send() directly. Factoring the resync out of the establishment
     * path exists so a second caller can drive it, and a test that reached past
     * that seam would not be exercising the one Phase 9 will use. */
    if (federation_resync(s, server_find_link(s, NAME_B)) == 0) {
        printf("[fixture] resync_offered: stage=%d\n", g_stage);
    } else {
        printf("[fixture] resync_refused: stage=%d\n", g_stage);
    }
    fflush(stdout);
}

/* 2.4's stamp for a line this node originates, from core/fanout.h's statement of
 * the outbound half. A local so its address is valid for the call: fed_queue_line()
 * takes a const pointer and does not keep it, but a compound literal would be a
 * second thing to get right in a fixture. */
static const irc_serve_tags_t *burst_fixture_stamp(server_t *s)
{
    static irc_serve_tags_t tags;

    memset(&tags, 0, sizeof tags);
    (void)snprintf(tags.origin, sizeof tags.origin, "%s", s->name);
    tags.epoch = s->epoch;
    tags.id = server_next_msg_id(s);
    tags.hops = 0u;
    return &tags;
}

/* An unsigned decimal in the grammar 2.4's tags use, for a field the fixture has
 * to fill. It is two lines and it is here rather than borrowed from
 * federation/burst.c because that function is static, and borrowing it would mean
 * the fixture's idea of the grammar and the node's could not drift apart -- which is
 * the reason the copy is this small. */
static void burst_render_u64(char *out, size_t cap, uint64_t v)
{
    (void)snprintf(out, cap, "%llu", (unsigned long long)v);
}

/* A TRANSACTION WITH ITS LAST RECORD LEFT OFF, built by hand on the tick.
 *
 * THIS IS THE ONE PLACE IN THE TREE WHERE A TEST WRITES THE WIRE FORMAT, and the
 * reason is that the thing under test is a transaction that ENDS WRONGLY and there
 * is no other way to produce one. Every other path into a burst ends correctly by
 * construction: the sender renders the whole thing into a staging buffer and
 * refuses it if it does not fit, and a link that saturates mid-flush is a
 * saturation this node does not get to choose. So the shapes below are written out
 * as literals rather than derived from the encoder -- which is the same reasoning
 * test_fed_wire.c gives for its per-verb table, and for the same reason: an
 * expectation derived from the encoder passes whatever the encoder says.
 *
 * THE ONLY THING BORROWED FROM THE IMPLEMENTATION IS THE STAMP, and the stamp is
 * borrowed rather than invented because it is not the format: 2.4's four tags are
 * frozen in core/message.h and the outbound half is stated once in core/fanout.h.
 * A burst with no legal identity never reaches the guard chain, so a fixture that
 * sent an untagged transaction would be testing case E and not the count.
 *
 * WHAT IS LEFT OFF IS ONE MEMBER RECORD, and the terminator still claims it: the
 * transaction announces two members and carries one. Everything before the
 * terminator is well formed, so the ONLY thing that can catch it is the assertion
 * that the terminator's counts match what arrived -- and the member record it
 * claims and does not send is one whose FLAGS DIFFER from what the far side already
 * holds, so a receiver that believed the terminator would visibly rewrite a
 * roster it had no right to touch.
 */
static void send_truncated_burst(server_t *s, server_link_t *link)
{
    conn_t *peer = server_link_conn(s, link);
    char signon[24];
    const char *n0[2];
    const char *n1[6];
    const char *c1[6];
    const char *m1[4];
    const char *e1[4];
    char epoch[24];
    int ok = 0;

    if (peer == NULL) {
        return;
    }
    burst_render_u64(epoch, sizeof epoch, s->epoch);
    burst_render_u64(signon, sizeof signon, 0u); /* any legal 2.4 decimal */

    n0[0] = epoch;
    n0[1] = "1"; /* one nick follows */
    n1[0] = NICK_A;
    n1[1] = NICK_A;
    n1[2] = "127.0.0.1";
    n1[3] = "-"; /* no user modes: this build evaluates none */
    n1[4] = signon;
    n1[5] = ""; /* no away */
    c1[0] = CHAN_T;
    c1[1] = NAME_A;
    c1[2] = "-"; /* no topic setter */
    c1[3] = "0"; /* topic_when: any legal 2.4 decimal */
    c1[4] = "-"; /* no channel modes */
    c1[5] = ""; /* no topic */
    /* alice, PLAIN. The origin has de-opped her, so this is a change -- and a
     * receiver that applied a transaction it should have thrown away would show it
     * as a 353 with no op group at all. The <server> field says irc.a, because
     * that is where alice is, which on this two-node mesh is also the burst
     * origin -- so the field is correct WITHOUT being load-bearing here, and the
     * test that would catch a wrong one is the three-node one, which does not
     * exist yet. What this case does prove is that the four-parameter shape is
     * what the receiver accepts: a three-parameter SBURSTM is a malformed line,
     * and the assertion on fed_malformed= at the end of the case is what says so. */
    m1[0] = CHAN_T;
    m1[1] = NAME_A;
    m1[2] = NICK_A;
    m1[3] = "-";
    e1[0] = epoch;
    e1[1] = "1"; /* nicks: correct */
    e1[2] = "1"; /* chans: correct */
    e1[3] = "2"; /* members: TWO, and one was not sent */

    /* One line at a time through the shared render-and-queue step, so the stamp is
     * minted exactly the way the real sender mints it -- once per line, which is
     * also what keeps the dedup store from dropping the records after the first. */
    if (fed_queue_line(s, peer, burst_fixture_stamp(s), s->name, "SBURST", n0, 2,
                       NULL) == 0 &&
        fed_queue_line(s, peer, burst_fixture_stamp(s), s->name, "SBURSTN", n1, 6,
                       NULL) == 0 &&
        fed_queue_line(s, peer, burst_fixture_stamp(s), s->name, "SBURSTC", c1, 6,
                       NULL) == 0 &&
        fed_queue_line(s, peer, burst_fixture_stamp(s), s->name, "SBURSTM", m1, 4,
                       NULL) == 0 &&
        fed_queue_line(s, peer, burst_fixture_stamp(s), s->name, "SBURSTE", e1, 4,
                       NULL) == 0) {
        ok = 1;
    }
    printf("[fixture] truncated_sent: ok=%d\n", ok);
    fflush(stdout);
}

/* ---------------------------------------------------------------------------
 * AN OPEN TRANSACTION: a BEGIN AND NOTHING ELSE
 * ---------------------------------------------------------------------------
 * This is the second place in the tree where a test writes the wire format, for
 * the same reason send_truncated_burst() is the first: a transaction that never
 * ENDS is the one thing a correctly behaving sender cannot produce and a
 * fixture has to build by hand.
 *
 * ONE LINE IS ENOUGH, and that is worth saying so a reader does not go looking
 * for the records: the transaction is open the moment a BEGIN arrives, and
 * nothing in this node's memory budget depends on there being any. The BEGIN
 * also charges a few hundred bytes against the shadow, so the shape being closed
 * at teardown is one that ALLOCATED -- a shadow that was open and empty would
 * make the teardown arm look exercised by accident.
 */
static void send_open_burst(server_t *s, server_link_t *link)
{
    conn_t *peer = server_link_conn(s, link);
    const char *n0[2];
    char epoch[24];
    int ok = 0;

    if (peer == NULL) {
        return;
    }
    burst_render_u64(epoch, sizeof epoch, s->epoch);
    n0[0] = epoch;
    n0[1] = "0"; /* zero nicks follow, and none do */
    if (fed_queue_line(s, peer, burst_fixture_stamp(s), s->name, "SBURST", n0, 2,
                       NULL) == 0) {
        ok = 1;
    }
    printf("[fixture] open_sent: ok=%d\n", ok);
    fflush(stdout);
}

static void child_tick(server_t *s, uint64_t now_ms)
{
    fed_tick(s, now_ms);
    offer_resync(s);
}

/* Runs in the CHILD, before anything may connect. */
static void child_setup(server_t *s)
{
    struct sockaddr_in sa;

    /* The client command surface, installed BEFORE fed_open(): fed_open() saves
     * whatever dispatch is there and replaces it with its own, so a
     * commands_dispatch installed after it would become the node's whole dispatch
     * and the peer path would never be reached. It is also what makes 3's "one
     * dispatch" claim testable: the node's dispatch is fed_dispatch_hook, its inner
     * is commands_dispatch, and a peer line reaches the guard chain THROUGH the
     * client dispatch on the strength of src->kind. */
    TF_CHECK_MSG(commands_dispatch != NULL,
                 "the client command surface is missing from the build");
    s->dispatch = commands_dispatch;

    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child; a node with an unopenable "
                 "federation module cannot reach any assertion in this test");
    s->trace = g_trace;
    s->on_tick = child_tick;
    fed_set_timeouts(1000, 2000, 30000, 90000);
    if (g_tiny_send != 0 && g_is_b == 0) {
        /* NODE A ONLY, and the distinction is the case's whole point. The bound is
         * symmetric in the code -- the receiver charges every record against the
         * same IRC_BURST_MAX_BYTES, so a peer that ignored the sender-side check
         * could not make this node's shadow grow without bound -- but the two
         * halves are different MECHANISMS and this case is about one of them.
         * Shrinking B's budget as well would make the RECOVERY burst (about 730
         * bytes, against a 320-byte bound) a second refusal, on the far side, for
         * a reason that has nothing to do with node A declining to send it -- and
         * the case would then be asserting that A's refusal was invisible while
         * the far side threw the next transaction away. The figure moves by a
         * byte or two with the per-line message id, which is why the word is
         * "about"; the margin against the bound is two orders of magnitude.
         *
         * The per-process override is also the ONLY reason this case exists in a
         * reasonable time. IRC_BURST_MAX_BYTES is the shipped bound and a
         * deployment is what it says; provoking it for real takes a burst of
         * roughly 170 records, which is a few hundred client connections and
         * channels, on every run of the suite, for ever, to exercise one branch.
         * This is the same per-process override the four link timers have, for the
         * same reason -- a build default serves a deployment, a per-process
         * override serves a case that must not make every later case slow. */
        fed_burst_set_max_bytes(BURST_TEST_SEND_BUDGET);
    }
    if (g_tiny_recv != 0 && g_is_b != 0) {
        /* THE RECEIVER'S HALF, and it is the same bound reached from the other
         * side: the shadow charges every record against IRC_BURST_MAX_BYTES, so a
         * peer that ignored the sender-side check could not make this node's
         * memory grow without bound. The number is different from the sender's
         * because the accounting is different -- a charge is the FROZEN 179-byte
         * tag block plus the prefix, the verb and the parameters, not the bytes
         * actually rendered -- and the case below states both numbers. */
        fed_burst_set_max_bytes(BURST_TEST_RECV_BUDGET);
    }

    if (g_peer_port <= 0) {
        return; /* the accepting side; the inbound claim configures its link */
    }
    /* 127.0.0.1 built by hand rather than resolved, as every two-node fixture in
     * this directory does. What this respects is the ADDRESS SHAPE -- a struct
     * sockaddr handed to fed_link_configure() -- and not the lookup. */
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)g_peer_port);
    TF_CHECK_MSG(fed_link_configure(s, NAME_A, (const struct sockaddr *)&sa,
                                    (socklen_t)sizeof sa) != NULL,
                 "the child could not configure peer %s on port %d", NAME_A,
                 g_peer_port);
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
 * THE ROSTER ASSERTION
 * ---------------------------------------------------------------------------
 * `lines` are the 353 LINES the roster must contain, IN ORDER, one entry per line.
 * 7/Phase 4's fixed order is "nicks, then ops, then voiced" and this node renders
 * one 353 per group rather than one per roster, so the order that has to be
 * asserted is the order of the LINES and not the order of the names within a line.
 *
 * THAT IS WHY THE ORDER IS THE ASSERTION AND NOT A SET. A roster carrying both
 * names under each other would be a roster this node produced by a rule nobody
 * wrote down, and a test built from per-name substring checks passes against it.
 * So each line is searched for from the end of the previous one, starting at a
 * MARK taken before the command was sent -- a client asks NAMES several times in
 * this case, and a search that restarted at the beginning of the connection would
 * be satisfied by an earlier answer.
 *
 * THREE SEPARATE CLAIMS, and all three are needed:
 *
 *   the exact lines, in order     the roster is this
 *   the LINE COUNT is this many   a roster that is a SUPERSET fails, which is the
 *                                 merge: the extra group, or the extra name
 *   `absent` appears nowhere      the specific record that must be gone IS gone,
 *                                 named rather than left to the count
 *
 * The count is the one that catches a merge whose names happen to land in the
 * expected groups, and the absence is the one that names the defect in the failure
 * message instead of leaving an operator to diff two 353 lines.
 *
 * A TRUNCATED ROSTER DOES NOT PASS. `nlines` is the whole list, and a 353 that
 * arrives with fewer lines than that leaves the later searches looking for a line
 * that is not there.
 *
 * AND THE WIRE IS ASSERTED BEFORE THE COUNTERS, everywhere in this file. The
 * `[observable]` shapes -- installed=, purged= -- are excellent diagnosis and they
 * are asserted too, but they are assertions about what the node SAID it did, and a
 * defect in the doing changes the saying. A merge or an install-on-arrival changes
 * both, and if the counter assertion runs first then the failing message names the
 * node's own account of the transaction rather than the client-visible consequence
 * the reader came here to see.
 *
 * The 366 is asserted, and it is asserted on THIS answer: 7/Phase 4 requires the
 * terminator to be LAST, so a 366 that arrived before the names would be a
 * truncated list that happens to contain them.
 *
 * `who_nick` is the ASKING client, which is 353's <client> parameter. The shape is
 * `:server 353 <client> = <channel> <names>` -- RFC 2812 3.3.5's form with this
 * node's `=` symbol as the first middle parameter. There is NO colon before the
 * names: reply.c renders a trailing value without the marker when it needs none,
 * and a needle written with one can never match.
 */
/* Does this node render 353's <names> with a ':' marker in front of it? 3.2's
 * rule, and it is a rule about the VALUE rather than about the numeric: a value
 * that is empty, that already starts with a colon, or that contains a separator
 * loses information without the marker and gets one. One name in a group needs no
 * marker, so the Phase-4 test's literals have none; a group of three does, and a
 * needle written without it can never match. The test carries the rule rather than
 * a per-call guess, because a per-call guess is a guess. */
static int names_need_colon(const char *v)
{
    if (v == NULL || v[0] == '\0' || v[0] == ':') {
        return 1;
    }
    return (strpbrk(v, " \t") != NULL) ? 1 : 0;
}

/* How many 353 lines for one channel appear in `buf` from byte `from` on. */
static size_t roster_lines_from(const char *buf, size_t from, const char *who_nick,
                                const char *chan)
{
    char want[128];
    const char *p = buf + from;
    size_t n = 0u;

    (void)snprintf(want, sizeof want, " 353 %s = %s ", who_nick, chan);
    while ((p = strstr(p, want)) != NULL) {
        n++;
        p += strlen(want);
    }
    return n;
}

static void expect_names(test_client_t *c, const char *who, const char *who_nick,
                         const char *chan, const char *const *lines, size_t nlines,
                         const char *absent)
{
    char want[256];
    char cmd[192];
    char ping[80];
    char token[32];
    const char *p;
    /* THE MARK IS EVERYTHING RECEIVED SO FAR, not the last 353 line. A client asks
     * NAMES several times in this case and the two are different by exactly the
     * amount that matters here: an earlier answer's 353 lines and its 366 are both
     * AFTER its last 353 header, so a mark taken there counts them as part of this
     * answer and the line count -- the assertion that catches a merge -- is off by
     * one before the case has measured anything. */
    size_t mark = strlen(tc_buffer(c));
    /* A PER-CALL TOKEN, and the reason is that this file drains with a PING. A
     * client that has already been drained once still has the previous PONG in its
     * buffer, so a needle of "PONG" is satisfied by an answer to an earlier
     * question and every search after it runs against bytes that were already
     * there. The token makes the drain token itself unique, and it is ZERO-PADDED
     * so that "roster7" cannot be satisfied by a line carrying "roster70". */
    static int drain = 0;

    drain++;
    (void)snprintf(token, sizeof token, "roster%03d", drain);
    (void)snprintf(ping, sizeof ping, "PING :%s", token);
    (void)snprintf(cmd, sizeof cmd, "NAMES %s", chan);
    TF_CHECK_MSG(tc_send(c, cmd) == 0, "%s: NAMES %s send failed", who, chan);
    /* THE PING IS THE DRAIN, AND IT IS LOAD-BEARING RATHER THAN TIDY. Waiting for
     * the answer's own 366 would be a race in the worst direction: a client that
     * asked NAMES before already has a 366 in its buffer, so tc_expect() returns
     * instantly against the PREVIOUS answer and the search that follows runs
     * before this one has arrived. That is not a hypothetical -- it is what the
     * first two runs of this case did, each reporting a line that was merely
     * unread. A PING on the same connection is ordered behind the NAMES by the
     * single-threaded loop, so once the PONG is in the buffer the whole answer is,
     * and every strstr() below is against static bytes.
     *
     * The needle is the BARE token, with no colon: the node renders a PONG whose
     * final parameter carries no ':' marker unless the value needs one, and this
     * token does not (send_pong in reply.c, and 3.2's rule about the marker).
     * A needle written with the colon can never match. */
    TF_CHECK_MSG(tc_send(c, ping) == 0, "%s: drain PING send failed", who);
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "%s: NAMES %s was never answered, so this node does not hold the "
                 "channel at all: %s",
                 who, chan, tc_buffer(c));
    p = tc_buffer(c) + mark;
    for (size_t i = 0; i < nlines; i++) {
        const char *at;

        (void)snprintf(want, sizeof want, " 353 %s = %s %s%s\r\n", who_nick, chan,
                       (names_need_colon(lines[i]) != 0) ? ":" : "", lines[i]);
        at = strstr(p, want);
        TF_CHECK_MSG(at != NULL,
                     "%s: 353 line %zu of %zu (\"%s\") is missing or out of order "
                     "for %s. 7/Phase 4 fixes the order as nicks, then ops, then "
                     "voiced, and this node renders one line per group.\n"
                     "  client saw: %s",
                     who, i + 1u, nlines, lines[i], chan, tc_buffer(c));
        if (at == NULL) {
            return;
        }
        p = at + strlen(want);
    }
    TF_CHECK_MSG(roster_lines_from(tc_buffer(c), mark, who_nick, chan) == nlines,
                 "%s: the answer to NAMES %s carried a different NUMBER of 353 "
                 "lines than the %zu this case requires. A resync REPLACES state "
                 "for its origin and never merges, so a roster with a record in it "
                 "that the origin no longer reports is a merge -- and the extra "
                 "line is where the merge shows.\n  client saw: %s",
                 who, chan, nlines, tc_buffer(c));
    if (absent != NULL) {
        TF_CHECK_MSG(strstr(p, absent) == NULL,
                     "%s: the answer to NAMES %s still names \"%s\". 4.3 says a "
                     "resync replaces state for that origin and never merges, so a "
                     "record the origin no longer reports has to be gone -- and the "
                     "membership this node is showing is the old roster merged with "
                     "the new one.\n  client saw: %s",
                     who, chan, absent, tc_buffer(c));
    }
    /* THE 366 IS ASSERTED, and it is asserted on THIS answer rather than by
     * counting numerics anywhere: 7/Phase 4 requires the terminator to be LAST, so
     * a 366 that arrived before the names would be a truncated list that happens to
     * contain them. It is searched for after the last matched 353 rather than
     * anywhere, because an earlier answer's 366 is still in the buffer. */
    TF_CHECK_MSG(strstr(p, " 366 ") != NULL,
                 "%s: the answer to NAMES %s has no 366 after its 353 lines, so the "
                 "list is not terminated and the node cannot say which names were "
                 "the whole list.\n  client saw: %s",
                 who, chan, tc_buffer(c));
}

/* ---------------------------------------------------------------------------
 * THE CASE
 * ---------------------------------------------------------------------------
 * alice joins on A, so A OWNS #T. That is load-bearing rather than incidental:
 * with bob joining first, A would be the forwarding node and the de-op that
 * resync #2 needs could not be issued at all -- 2.2 says only the origin evaluates
 * +o/+v, and chan_verbs.c refuses a forwarded MODE with 437 rather than inventing
 * a line to forward. The de-op has to come from the origin, on the origin, from a
 * client that holds the privilege.
 *
 * So the shapes are: A owns #T with alice as its operator; B's client bob and then
 * carol join it; B owns #U with dave as its operator. A's #T is therefore half
 * local and half remote, which is the only shape in which the receiver's
 * already-known rule and the per-origin purge both have anything to do.
 */
static void case_resync_replaces(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;
    test_client_t bob;
    test_client_t carol;
    test_client_t dave;
    test_client_t ann;
    test_client_t eve;
    /* THE THREE ANSWERS #T MUST GIVE, and each one is a different state of the
     * world. They are written out rather than built so that a reader can see what
     * a merge would render instead: on every one of them, a merge shows
     * "@alice" in a second group, or shows the name the origin dropped. */
    const char *const t_two[] = { NICK_B, "@" NICK_A };
    const char *const t_deop[] = { NICK_B " " NICK_C " " NICK_A };
    const char *const t_gone[] = { NICK_B " " NICK_C };
    const char *const u_dave[] = { "@" NICK_D };
    /* THE ANSWER FOR A CHANNEL WITH NO MEMBERS AT ALL: one 353 line whose trailing
     * value is empty, and the 366. It is not silence and not a 403 -- a node that
     * holds a channel it has nobody in says so, rather than pretending the channel
     * does not exist (see send_names_list in chan_verbs.c), and the empty marker is
     * 3.2's representation of an empty trailing value. */
    const char *const empty[] = { "" };
    const char *const a_two[] = { NICK_B, "@" NICK_A };
    const char *const a_deop[] = { NICK_A " " NICK_B " " NICK_C };

    /* Node A first: it reports its port, and the parent cannot configure B until
     * it has. */
    g_peer_port = 0;
    g_trace = 0;
    g_is_b = 0;
    g_stage = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    TF_CHECK_MSG(a.port > 0, "node A reported no port");

    /* THE STEP THE WHOLE FIXTURE TURNS ON. A's port is only known here, in the
     * parent, after A's fork. */
    g_peer_port = a.port;
    g_is_b = 1;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");

    /* The precondition, asserted before the case is worth anything: without a link
     * every assertion below would be satisfied by two nodes that never spoke. B is
     * the initiator, so B is where the dial is visible. */
    TF_CHECK_MSG(nf_expect(&b, "link_dial: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never dialled its configured peer");
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A");

    /* AND BOTH SIDES BURST ON ESTABLISHMENT, which is a deliberate superset of
     * 4.3's "the initiator sends full state" and is asserted because it is
     * load-bearing rather than decorative. A node only forwards to peers that
     * already hold the chan_t, so if only the initiator burst, the RESPONDER's
     * channels would never reach the initiator and this whole case would be
     * asserting a roster on one node only. A is the responder here, so this
     * assertion is the one that would fail first if the responder's resync were
     * dropped. */
    TF_CHECK_MSG(nf_expect(&a, "fed_burst_sent: peer=" NAME_B, T_IO_MS) == 0,
                 "node A -- the RESPONDER -- never burst on establishment, so a "
                 "responder's state can never reach the initiator: %s",
                 a.out);
    TF_CHECK_MSG(nf_expect(&b, "fed_burst_sent: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never burst on establishment: %s", b.out);
    /* AND BOTH SIDES APPLY one, which is the half that says the guard chain
     * reaches the transaction at all. A burst that is sent and not applied is a
     * node with a working encoder and a missing decoder, and the first symptom
     * would be a 353 that never changes. */
    TF_CHECK_MSG(nf_expect(&a, "fed_burst_applied: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never applied a burst from node B, so the inbound guard "
                 "chain is not reaching the resync: %s",
                 a.out);
    TF_CHECK_MSG(nf_expect(&b, "fed_burst_applied: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never applied a burst from node A: %s", b.out);

    register_client(&bob, b.port, NICK_B);
    register_client(&alice, a.port, NICK_A);

    /* alice JOINs on A and therefore CREATES #T there, so she is its operator
     * (RFC 1459 2.3.1) and A is its origin. bob JOINs on B, which does not own
     * it: the membership happens locally and the SJOIN is forwarded to the owner,
     * which is the JOIN exception chan_verbs.c documents. */
    TF_CHECK_MSG(tc_send(&alice, "JOIN " CHAN_T) == 0, "alice's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed on the node that owns the channel");
    TF_CHECK_MSG(tc_send(&bob, "JOIN " CHAN_T) == 0, "bob's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob's JOIN never completed on the node that does not own the "
                 "channel");
    /* BOB'S 366 IS NOT A'S KNOWLEDGE OF HIM, and asserting the pre-state without
     * waiting for it is a race: B answers bob from its own loop the moment it has
     * applied the local membership, and A learns of bob from the SJOIN on a
     * different socket a moment later. A 353 asked in between renders the local
     * member and nothing else, which is a correct answer to a question asked too
     * early. Both directions are therefore waited for, and each is the node's own
     * record of the arrival rather than the far side's opinion of it. */
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=" CHAN_T " member=" NICK_B, T_IO_MS)
                     == 0,
                 "node A never learned about bob, so its pre-state roster cannot "
                 "have the remote name the criterion is about: %s",
                 a.out);
    TF_CHECK_MSG(nf_expect(&b, "fed_sjoin: channel=" CHAN_T " member=" NICK_A, T_IO_MS)
                     == 0,
                 "node B never learned about alice, so its pre-state roster cannot "
                 "have the remote name the criterion is about: %s",
                 b.out);

    /* dave CREATES #U on B, so B owns it and dave is its operator. The channel
     * exists to be the per-origin control: it is in A's burst with B as its
     * origin, and it must come through the receiver's channel loop untouched. */
    register_client(&dave, b.port, NICK_D);
    TF_CHECK_MSG(tc_send(&dave, "JOIN " CHAN_U) == 0, "dave's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&dave, " 366 ", T_IO_MS) == 0,
                 "dave's JOIN never completed on the node that owns the channel");
    /* Wait for A to have LEARNED about it, or the control below would be about a
     * burst that does not mention #U at all and would pass for the wrong reason. */
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=" CHAN_U " member=" NICK_D, T_IO_MS)
                     == 0,
                 "node A never learned about %s, so A's burst does not mention it "
                 "and the per-origin check below is not being exercised: %s",
                 CHAN_U, a.out);

    /* --- the pre-state, asserted BEFORE any resync ------------------------- */
    /* RACE-FREE ONLY BECAUSE resync #1 IS GATED ON A SECOND REGISTRATION, and A
     * has one nick here. That is the whole reason the gate is a registration and
     * not a tick count: without it, A's next poll iteration would fire a resync
     * in the middle of these assertions and the "before" would be measured after
     * an unknown number of resyncs.
     *
     * AND IT IS A REAL CONTROL, not a formality. The remote name on each node is
     * the thing that has to have travelled, and the LOCAL name is the thing that
     * is always there whatever the federation does -- so a cross-node assertion
     * that passed with one name would be passing on the local member. Both names
     * are required, in Phase 4's order, and the op group is the second 353. */
    expect_names(&alice, "alice on the origin", NICK_A, CHAN_T, a_two, 2u, NULL);
    expect_names(&bob, "bob on the non-owner", NICK_B, CHAN_T, t_two, 2u, NULL);
    expect_names(&dave, "dave on the other origin", NICK_D, CHAN_U, u_dave, 1u, NULL);

    /* --- resync #1: a correct roster must SURVIVE a resync ----------------- */
    /* Registering ann is the trigger. A's tick hook fires the resync the moment it
     * sees the second name, and the `[fixture] resync_offered` line is what makes
     * the case non-vacuous: it says the resync was OFFERED, so a later failure is
     * about what it did rather than about one that never ran. */
    register_client(&ann, a.port, NICK_E);
    TF_CHECK_MSG(nf_expect(&a, "resync_offered: stage=1", T_IO_MS) == 0,
                 "node A never drove the first resync: %s", a.out);
    /* A's state at this point: one client of #T (alice, an op), one remote member
     * of it (bob, from irc.b), one remote member of #U (dave, from irc.b), and
     * #U has no local member anywhere. So nicks=2, chans=2, members=3. */
    TF_CHECK_MSG(nf_expect(&a, "nicks=2 chans=2 members=3 bytes=", T_IO_MS) == 0,
                 "node A's first resync did not carry the two clients and two "
                 "channels its own state has, so the sender's counts and its content "
                 "disagree: %s",
                 a.out);
    /* #U CAME THROUGH THE SAME LOOP AND WAS NOT TOUCHED. dave is a member B hosts
     * itself, so he would survive even a purge that ignored the origin -- so the
     * line count is the load-bearing half here: an erase-and-refill implementation
     * empties #U's remote side and adds nothing back, and this is the only place
     * in the case where that shows. */
    expect_names(&dave, "dave after resync 1", NICK_D, CHAN_U, u_dave, 1u, NULL);
    /* AND THE MAIN ACCEPTANCE CRITERION, after a resync rather than before one:
     * the FULL 353 contents on BOTH nodes, in Phase 4's order, terminated by a
     * 366, with both names. A truncated roster does not pass, and neither does one
     * carrying a name the origin no longer reports. */
    expect_names(&alice, "alice after resync 1", NICK_A, CHAN_T, a_two, 2u, NULL);
    expect_names(&bob, "bob after resync 1", NICK_B, CHAN_T, t_two, 2u, NULL);
    /* AND WHAT THE RECEIVER DID WITH IT. installed=1 is alice arriving as a
     * REMOTE member of #T on B; purged=1 is the irc.a entry she had there being
     * removed first, which is what makes the install a replacement rather than a
     * second copy; dropped=0 says nothing was refused, so a later assertion about
     * the roster cannot be explained by a burst that failed to apply. bob and dave
     * are NOT installed: they are members B hosts itself, and installing them
     * again is what would put the same nickname in 353 twice. */
    TF_CHECK_MSG(nf_expect(&b, "nicks=2 chans=2 members=3 installed=1 purged=1 "
                                  "dropped=0 bytes=",
                           T_IO_MS) == 0,
                 "node B did not apply A's first resync with the expected shape: one "
                 "remote member installed, the irc.a entry it replaces purged, "
                 "nothing dropped.\n  node said: %s",
                 b.out);


    /* --- the origin DE-PRIVILEGES a member --------------------------------- */
    /* carol joins from B first, so the next burst has a record count no earlier
     * one can produce: A's #T now has a local member (alice) and TWO remote ones
     * (bob and carol), so the resync that follows carries members=4. That is how
     * the three resyncs are told apart in the assertions below -- nf_expect()
     * searches everything a node has printed, so a needle that matched the first
     * resync would satisfy a wait for the second. */
    register_client(&carol, b.port, NICK_C);
    TF_CHECK_MSG(tc_send(&carol, "JOIN " CHAN_T) == 0, "carol's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&carol, " 366 ", T_IO_MS) == 0,
                 "carol's JOIN never completed on the node that does not own the "
                 "channel");
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=" CHAN_T " member=" NICK_C, T_IO_MS)
                     == 0,
                 "node A never learned about carol, so the resync that follows "
                 "would not carry her: %s",
                 a.out);

    /* AND B DRIVES ONE RESYNC OF ITS OWN, which is a claim the three above cannot
     * make: it puts a CONTENT burst on the wire from the node that does NOT own
     * the channel, so what A does with it exercises the installing half of the
     * replace. On A the purge is for irc.b and removes bob and carol from a channel
     * A holds one local member of, plus dave from a channel A does not own at all;
     * all three go back in, and alice -- a local member of A -- is recognised and
     * skipped. A receiver-side-only implementation, or one that installed a
     * member this node already has, would show a different count here. */
    TF_CHECK_MSG(nf_expect(&b, "resync_offered: side=b stage=1", T_IO_MS) == 0,
                 "node B never drove its own resync, so the non-owner-to-origin "
                 "direction of the transaction is not covered: %s",
                 b.out);
    TF_CHECK_MSG(nf_expect(&a, "nicks=3 chans=2 members=4 installed=3 purged=3 "
                                  "dropped=0 bytes=",
                           T_IO_MS) == 0,
                 "node A did not apply B's resync with the shape that says the "
                 "per-origin purge runs against a node holding the members "
                 "locally: three installed after three purged, nothing dropped.\n"
                 "  node said: %s",
                 a.out);

    /* The de-op, from the origin, by a client that holds the privilege. 2.2 says
     * only the origin evaluates +o/+v, and chan_verbs.c refuses a MODE that would
     * have to be forwarded with 437 rather than inventing a line for it -- so a
     * de-op requested on the non-owner would never reach the origin at all, and
     * this is the only route to a changed flag on the origin's own roster. */
    TF_CHECK_MSG(tc_send(&alice, "MODE " CHAN_T " -o " NICK_A) == 0,
                 "alice's MODE -o send failed");
    TF_CHECK_MSG(nf_expect(&a, "chan_member_mode: channel=" CHAN_T " by=" NICK_A
                               " nick=" NICK_A " mode=o set=0",
                           T_IO_MS) == 0,
                 "node A never applied alice's own de-op, so its ROSTER is "
                 "unchanged and there is nothing for a resync to correct: %s",
                 a.out);
    /* Drain the MODE echo, or it would be sitting in alice's buffer and the next
     * NAMES would search from a mark that had already moved. */
    TF_CHECK_MSG(tc_expect(&alice, "MODE " CHAN_T " -o " NICK_A "\r\n", T_IO_MS) == 0,
                 "alice never saw the echo of her own de-op, so the fan-out of the "
                 "mode change is not what the assertions below assume: %s",
                 tc_buffer(&alice));
    TF_CHECK_MSG(tc_send(&alice, "PING :deop") == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(&alice, "PONG", T_IO_MS) == 0, "alice got no PONG");

    /* --- resync #2: a CHANGED flag must not survive as the old one --------- */
    /* A's tick hook fires this the moment A's local member of #T is no longer an
     * operator, which is now. No poke is involved anywhere in this step. */
    TF_CHECK_MSG(nf_expect(&a, "resync_offered: stage=2", T_IO_MS) == 0,
                 "node A never drove the second resync: %s", a.out);
    TF_CHECK_MSG(nf_expect(&a, "nicks=2 chans=2 members=4 bytes=", T_IO_MS) == 0,
                 "node A's second resync did not carry the four member records its "
                 "own state has (alice and bob and carol on %s, dave on %s): %s",
                 CHAN_T, CHAN_U, a.out);
    /* THE TEETH, and this is the one that needs no poke at all. A MERGE leaves
     * B's (irc.a, alice) entry standing with +o on it, recognises the new record
     * as a name this node already knows, and skips it -- so the client is shown
     * "@alice" in a second 353 group for a privilege the origin has taken away.
     * The LINE COUNT is what catches it: the correct answer is ONE line and a
     * merge renders two, and the `absent` check names the record that is wrong
     * rather than leaving an operator to diff the two answers. */
    expect_names(&bob, "bob after the de-op", NICK_B, CHAN_T, t_deop, 1u,
                 "@" NICK_A);
    /* AND A's own view, as a control: A's roster moved when the de-op happened, so
     * it is one plain line naming all three, and it was one line naming bob and an
     * op before. If A's own 353 were wrong, B's being right would prove nothing. */
    expect_names(&alice, "alice after the de-op", NICK_A, CHAN_T, a_deop, 1u, NULL);
    TF_CHECK_MSG(nf_expect(&b, "nicks=2 chans=2 members=4 installed=1 purged=1 "
                                  "dropped=0 bytes=",
                           T_IO_MS) == 0,
                 "node B did not apply A's second resync with the expected shape: "
                 "alice reinstalled once, her irc.a entry purged once, nothing "
                 "dropped.\n  node said: %s",
                 b.out);

    /* --- resync #3: a member the origin LOST must be forgotten ------------- */
    /* Registering eve is the trigger. The tick hook removes alice from A's #T
     * silently first -- see the poke at offer_resync() and the header for why this
     * case is not reachable any other way on a two-node mesh -- and then bursts.
     * A's #T now has NO local member and two remote ones, so the burst carries
     * members=3 and installed=0: alice is purged and NOT reported, and bob and
     * carol are members B hosts itself. */
    register_client(&eve, a.port, NICK_F);
    TF_CHECK_MSG(nf_expect(&a, "resync_offered: stage=3", T_IO_MS) == 0,
                 "node A never drove the third resync: %s", a.out);
    TF_CHECK_MSG(nf_expect(&a, "nicks=3 chans=2 members=3 bytes=", T_IO_MS) == 0,
                 "node A's third resync did not carry three clients and three member "
                 "records, so the fixture's silent removal did not happen: %s",
                 a.out);
    /* THE SECOND SET OF TEETH, and this is the one the pass's "a departed member
     * must appear in 353" describes. A MERGE keeps B's (irc.a, alice) entry, so
     * the answer is two names on the first line plus alice; a replace is the two
     * names B hosts and nothing else. */
    expect_names(&bob, "bob after alice was dropped at the origin", NICK_B, CHAN_T,
                 t_gone, 1u, NICK_A);
    TF_CHECK_MSG(nf_expect(&b, "nicks=3 chans=2 members=3 installed=0 purged=1 "
                                  "dropped=0 bytes=",
                           T_IO_MS) == 0,
                 "node B did not apply A's third resync with the expected shape: "
                 "one irc.a entry purged and nothing installed, because the origin "
                 "no longer reports that member.\n  node said: %s",
                 b.out);
    /* AND #U, one last time, after a burst that named it. dave is still there, and
     * the 366 is there: the channel survived and its roster was not disturbed by a
     * resync about a different origin. */
    expect_names(&dave, "dave after resync 3", NICK_D, CHAN_U, u_dave, 1u, NULL);

    /* --- and the ONE thing a burst contributes that an SJOIN never does ----- */
    /* dave is B's only member of #U, and B OWNS #U, so nothing about B's own
     * membership ever puts a name in its servers[] -- 2.2 says this node's own name
     * is implicit in nmembers and must not be in there, because 3.1's forward arm
     * would then forward to this node. The only thing that put irc.a in B's #U
     * servers[] is the SBURSTC record in A's burst, and dave is about to leave.
     *
     * SO THE CHANNEL HAS TO SURVIVE HIM, and that is the whole of
     * chan_server_add() at the burst's channel record. A node holding a channel it
     * has no members of is a RELAY for it rather than a corpse: it still has to
     * route that channel's messages, and a freed channel cannot be routed for. The
     * observable is the pair -- B's NAMES #U is ANSWERED, and B never printed a
     * `chan_destroy` for it -- because the two failure directions are different: a
     * channel that is still there with nobody in it is a relay, and one that is
     * gone is a node that has forgotten a channel the mesh still has. */
    TF_CHECK_MSG(tc_send(&dave, "PART " CHAN_U) == 0, "dave's PART send failed");
    TF_CHECK_MSG(nf_expect(&b, "chan_part: channel=" CHAN_U " nick=" NICK_D
                           " members=0 servers=1",
                           T_IO_MS) == 0,
                 "node B's %s did not survive dave leaving it with no local member, "
                 "so a burst's channel record is not recording the origin in the "
                 "member-server set and a channel with no members here is being "
                 "freed rather than relayed: %s",
                 CHAN_U, b.out);
    expect_names(&dave, "dave after leaving the only member", NICK_D, CHAN_U, empty,
                 1u, NULL);
    TF_CHECK_MSG(strstr(b.out, "chan_destroy: channel=" CHAN_U) == NULL,
                 "node B destroyed %s, so the member-server entry a burst's channel "
                 "record should have left behind did not keep it alive: %s", CHAN_U,
                 b.out);

    /* NOTHING WAS THROWN AWAY along the way, and that is a claim rather than a
     * footnote: a resync that DISCARDED its own transaction would leave every
     * roster assertion above either unsatisfied or satisfied by the live SJOIN
     * path rather than by the burst. The counts are the only way to tell those
     * apart from the outside. */
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&a, "burst_abandoned=", 0, 1000) == 0,
                 "node A abandoned a burst transaction, so a roster that reads "
                 "right may be right because nothing was ever applied to it: %s",
                 a.out);
    TF_CHECK_MSG(nf_expect_u64(&b, "burst_abandoned=", 0, 1000) == 0,
                 "node B abandoned a burst transaction: %s", b.out);
    TF_CHECK_MSG(nf_expect_u64(&a, "burst_refused=", 0, 1000) == 0,
                 "node A refused a burst, so one of the three resyncs never left: "
                 "%s",
                 a.out);
    TF_CHECK_MSG(nf_expect_u64(&b, "burst_refused=", 0, 1000) == 0,
                 "node B refused a burst, so one of the three resyncs never "
                 "arrived: %s",
                 b.out);
    /* AND NOTHING WAS DROPPED OR MANGLED ON THE WAY IN, for the same reason: a
     * line the guard chain refused would leave a gap the terminator's counts
     * cannot see, because the counts assert what was ACCEPTED. A dedup drop is
     * the same argument from the other side -- it is how a replayed burst is
     * answered, and a burst dropped wholesale as a duplicate would mean the ids
     * are not per line. */
    TF_CHECK_MSG(nf_expect_u64(&a, "fed_dup_drop=", 0, 1000) == 0,
                 "node A dropped a burst line as a duplicate, so the resyncs arrived "
                 "by some other route: %s",
                 a.out);
    TF_CHECK_MSG(nf_expect_u64(&b, "fed_dup_drop=", 0, 1000) == 0,
                 "node B dropped a burst line as a duplicate, so the resyncs arrived "
                 "by some other route: %s",
                 b.out);
    TF_CHECK_MSG(nf_expect_u64(&b, "fed_malformed=", 0, 1000) == 0,
                 "node B refused a burst line as malformed, so a record was lost and "
                 "the transaction was discarded rather than applied: %s",
                 b.out);
    TF_CHECK_MSG(nf_expect_u64(&b, "fed_verb_deferred=", 0, 1000) == 0,
                 "node B still reports a 4.3 verb it does not speak, and SBURST is "
                 "supposed to have left that table: %s",
                 b.out);

    tc_close(&alice);
    tc_close(&bob);
    tc_close(&carol);
    tc_close(&dave);
    tc_close(&ann);
    tc_close(&eve);
    nf_free(&a);
    nf_free(&b);
}

/* ---------------------------------------------------------------------------
 * THE REFUSAL
 * ---------------------------------------------------------------------------
 * 3.4 says a saturated peer link is DROPPED, not buffered, and IRC_BURST_MAX_BYTES
 * is what stops a burst from getting there: a resync is O(nicks + members), so a
 * large node's burst can be megabytes, and queueing all of it would starve every
 * live message behind it. So a burst that does not fit is REFUSED IN FULL -- one
 * n_burst_refused, nothing queued, the link untouched, the node's own state
 * exactly as it was -- rather than truncated in the middle of a transaction, which
 * the peer would discard anyway and which would leave it holding a half-built
 * shadow for as long as the link stayed up.
 *
 * THE OBSERVABLE IS A PAIR, and neither half is the interesting one alone:
 *
 *   A refused, and said so          the budget is enforced, and the node says which
 *   B abandoned NOTHING             the refusal is total. A partially flushed burst
 *                                   would leave B's shadow open, and the next BEGIN
 *                                   would discard it as SUPERSEDED -- which is
 *                                   exactly what n_burst_abandoned counts. So
 *                                   burst_refused=1 on one node and
 *                                   burst_abandoned=0 on the other is "refused in
 *                                   full" stated as a fact about two machines.
 *   A resynced again immediately    the refusal did not cost the link, which is
 *                                   the difference between a bound and a fault
 *
 * AND THE CONTROL, which is the assertion that stops the case being a tautology:
 * node A's ESTABLISHMENT burst went out under the very same shrunken budget, and
 * the case asserts it did. Without that, a node whose federation path was simply
 * broken would also report a refusal, and the refusal count would be right for the
 * wrong reason. 227 bytes against a 320-byte budget is the difference the case
 * turns on, and the empty transaction is under it.
 */
static void case_burst_refused(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;
    test_client_t ann;
    const char *const both[] = { "@" NICK_A };
    /* alice is the CREATOR of #T on A, so she is its operator and the group she is
     * in is the second one. B's copy of her comes over the SJOIN with the flag
     * attached, so both nodes render the same two groups. */
    const char *const both_b[] = { NICK_B, "@" NICK_A };

    g_peer_port = 0;
    g_trace = 0;
    g_is_b = 0;
    g_stage = 0;
    g_tiny_send = 1;
    g_tiny_recv = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    g_peer_port = a.port;
    g_is_b = 1;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");

    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A");

    /* THE CONTROL. Node A has no clients and no channels yet, so its
     * establishment burst is the empty transaction -- and it must GO OUT under the
     * 320-byte budget, because it is 227 bytes. This is what makes the refusal
     * below a statement about volume rather than about a node whose peer path is
     * broken. */
    TF_CHECK_MSG(nf_expect(&a, "fed_burst_sent: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never sent a burst at all under the shrunken budget, so the "
                 "refusal below would be satisfied by a resync path that does not "
                 "work: %s",
                 a.out);
    /* And it is the ESTABLISHMENT burst, which is the empty transaction and the
     * only thing that can have been sent at this point -- the case has provoked
     * nothing yet. A counter at zero says the 227-byte transaction was not
     * refused, which is the half of the control that the existence of a
     * `fed_burst_sent` line does not on its own. */
    TF_CHECK_MSG(nf_expect_u64(&a, "burst_refused=", 0, 1000) == 0,
                 "node A already refused a burst before the case provoked one, so the "
                 "refusal below is not the one under test: %s",
                 a.out);

    register_client(&alice, a.port, NICK_A);
    register_client(&ann, a.port, NICK_E);
    TF_CHECK_MSG(tc_send(&alice, "JOIN " CHAN_T) == 0, "alice's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed on the node that owns the channel");

    /* THE REFUSAL. The tick hook resyncs with the budget still shrunken, and the
     * transaction now carries two nicks and a channel -- about 480 bytes against a
     * 320-byte budget -- so it is refused. */
    TF_CHECK_MSG(nf_expect(&a, "fed_burst_refused: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never refused a burst that did not fit, so the staging "
                 "bound is not enforced: %s",
                 a.out);
    TF_CHECK_MSG(nf_expect(&a, "resync_refused_tiny: stage=1", T_IO_MS) == 0,
                 "node A never reported the refusal through the product function "
                 "the case is exercising: %s",
                 a.out);
    TF_CHECK_MSG(nf_expect(&a, "reason=TOO_LARGE", T_IO_MS) == 0,
                 "node A refused a burst for a reason other than its size, so the "
                 "case is measuring something else: %s",
                 a.out);
    TF_CHECK_MSG(nf_expect_u64(&a, "burst_refused=", 1, 2000) == 0,
                 "node A's refusal counter is not 1, so the refusal above and this "
                 "count are not the same event: %s",
                 a.out);

    /* AND THE IMMEDIATE RECOVERY, in the same tick, through the same function with
     * the budget restored. This is the half that says the bound is a bound and not
     * a fault. */
    TF_CHECK_MSG(nf_expect(&a, "resync_offered: stage=1", T_IO_MS) == 0,
                 "node A never resynced again after refusing one, so refusing cost "
                 "it the link: %s",
                 a.out);
    /* purged=1, not 0, and that is worth stating because the two are different
     * stories: alice's SJOIN has already given B a remote copy of her, so the
     * burst is REPLACING a record rather than creating the first one. A node that
     * had not heard of #T at all would report purged=0 here, and the assertion
     * would be measuring a different arrangement. */
    TF_CHECK_MSG(nf_expect(&b, "nicks=2 chans=1 members=1 installed=1 purged=1 "
                                  "dropped=0 bytes=",
                           T_IO_MS) == 0,
                 "node B never applied the burst node A sent after the refusal, so "
                 "the link really did carry a second transaction: %s",
                 b.out);

    /* AND THE PAIR, which is the claim the case exists for. A refused something
     * and B threw nothing away. */
    TF_CHECK_MSG(nf_expect_u64(&b, "burst_abandoned=", 0, 1000) == 0,
                 "node B abandoned a transaction, so node A's refusal was not total: "
                 "part of a burst reached the wire and the rest did not, and B "
                 "discarded the half it was holding.\n  node said: %s",
                 b.out);
    TF_CHECK_MSG(nf_expect_u64(&b, "burst_refused=", 0, 1000) == 0,
                 "node B refused a burst, so the node under refusal is not the only "
                 "one that declined: %s",
                 b.out);
    /* AND THE ROSTER IS RIGHT, which is what the pair is protecting: a refusal
     * that had reached the wire at all would have left B holding a partial view of
     * node A, and this is the client-visible form of that. */
    expect_names(&alice, "alice after the refusal", NICK_A, CHAN_T, both, 1u, NULL);
    (void)both_b;

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&a, "burst_abandoned=", 0, 1000) == 0,
                 "node A abandoned a transaction of its own: %s", a.out);
    TF_CHECK_MSG(nf_expect_u64(&b, "fed_malformed=", 0, 1000) == 0,
                 "node B refused a burst line as malformed, so a record was lost: %s",
                 b.out);

    tc_close(&alice);
    tc_close(&ann);
    nf_free(&a);
    nf_free(&b);
    g_tiny_send = 0;
}

/* ---------------------------------------------------------------------------
 * THE RECEIVER'S HALF OF THE BOUND, AND WHY IT IS ALSO A CLAIM ABOUT THE SHADOW
 * ---------------------------------------------------------------------------
 * The sender-side bound is the interesting one for 3.4, and case_burst_refused()
 * covers it. The other half is the one that keeps a node's MEMORY bounded, and it
 * is a different mechanism: the shadow is a per-record heap allocation made out of
 * what a peer SAID, so a peer that ignored the sender-side check could describe an
 * unbounded roster and this node would believe it. Every record is charged against
 * IRC_BURST_MAX_BYTES, and a transaction that exceeds it is discarded in full.
 *
 * WHICH IS WHERE IT STOPS BEING A BUDGET AND BECOMES A TRANSACTION PROPERTY. A
 * resync is a BEGIN, an unbounded number of records and a terminator, and the
 * terminator is the only thing that says the records were the whole truth. So a
 * transaction this node throws away half way through has to leave NOTHING behind:
 * a member it installed on the way in, a channel it created on the way in, a
 * servers[] entry it added on the way in -- all of it invisible, because 4.3 says
 * "there is no partial burst" and a node that shows one has broken the sentence
 * from the receiver's side rather than the sender's.
 *
 * THE SETUP IS ARRANGED SO THAT LEAKING IS VISIBLE, which is the part that makes
 * this a test rather than a restatement. The member the transaction carries and
 * node B must NOT end up knowing is `ann`, who exists only on node A: if the
 * install happened as each member line arrived, ann would be in B's roster and in
 * its 353, and the roster assertion below fails. `alice` could not have caught
 * it -- B already knows her from the SJOIN, and chan_remote_add() is idempotent
 * on (server, nick), so installing her twice changes nothing that is visible.
 */
static void case_over_budget_changes_nothing(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;
    test_client_t ann;
    test_client_t bob;
    /* B's roster after the SJOINs and BEFORE the refused resync, and it is also
     * what it must be AFTER -- including the two-LINE shape, which is the part
     * that carries the weight: the origin de-privileges alice in the transaction it
     * is about to have discarded, so a node that applied the record on the way in
     * would render one 353 line instead of two. */
    const char *const unchanged[] = { NICK_B " " NICK_E, "@" NICK_A };

    g_peer_port = 0;
    g_trace = 0;
    g_is_b = 0;
    g_stage = 0;
    g_tiny_send = 0;
    g_tiny_recv = 1;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    g_peer_port = a.port;
    g_is_b = 1;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");

    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A");
    /* THE CONTROL, again, and for the same reason: node B's own empty transaction
     * charges about 420 against a 900-byte shadow budget, so it must have been
     * APPLIED rather than discarded. A node that discarded everything would reach
     * every assertion below without doing anything. */
    TF_CHECK_MSG(nf_expect(&b, "fed_burst_applied: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never applied the empty establishment transaction, so the "
                 "refusal this case is about is not being measured against a "
                 "working apply path: %s",
                 b.out);
    TF_CHECK_MSG(nf_expect_u64(&b, "burst_abandoned=", 0, 1000) == 0,
                 "node B abandoned a transaction before the case provoked one: %s",
                 b.out);

    register_client(&alice, a.port, NICK_A);
    register_client(&ann, a.port, NICK_E);
    register_client(&bob, b.port, NICK_B);
    TF_CHECK_MSG(tc_send(&alice, "JOIN " CHAN_T) == 0, "alice's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed on the node that owns the channel");
    /* ann joins on A as well, so the transaction has more than one member line --
     * which is what makes the budget trip INSIDE the member records rather than in
     * the header, and therefore what makes the case a claim about a member record
     * having been applied rather than about a channel header having been read. */
    TF_CHECK_MSG(tc_send(&ann, "JOIN " CHAN_T) == 0, "ann's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&ann, " 366 ", T_IO_MS) == 0,
                 "ann's JOIN never completed on the node that owns the channel");
    TF_CHECK_MSG(tc_send(&bob, "JOIN " CHAN_T) == 0, "bob's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob's JOIN never completed on the node that does not own the "
     "channel");
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=" CHAN_T " member=" NICK_B, T_IO_MS)
                     == 0,
                 "node A never learned about bob: %s", a.out);
    /* THE PRE-STATE, asserted so that "unchanged" below has a baseline on the wire
     * and not only in the reader's head. bob is a local member and therefore plain,
     * ann is a remote member with no flags, and alice is a remote member the origin
     * granted +o to -- so the answer is two 353 lines and the second one is the op
     * group. */
    expect_names(&bob, "bob before the over-budget resync", NICK_B, CHAN_T, unchanged,
                 2u, NULL);

    /* AND THE ORIGIN DE-PRIVILEGES alice, which is what the leaked member record
     * would carry. A resync that installed each member line as it arrived would set
     * her flags to 0 HERE, before the transaction was thrown away, and B's answer
     * would collapse from two 353 lines to one. A member the node already knows by
     * name could not show this -- chan_remote_add() is idempotent on (server, nick)
     * and simply overwrites the flags, so a leak of a record whose flags had NOT
     * changed is invisible on the wire. The de-op is what makes the leak
     * observable, and it is the same mechanism resync #2 above relies on. */
    TF_CHECK_MSG(tc_send(&alice, "MODE " CHAN_T " -o " NICK_A) == 0,
                 "alice's MODE -o send failed");
    TF_CHECK_MSG(nf_expect(&a, "chan_member_mode: channel=" CHAN_T " by=" NICK_A
                               " nick=" NICK_A " mode=o set=0",
                           T_IO_MS) == 0,
                 "node A never applied alice's own de-op, so the transaction the "
                 "node under test is about would carry no changed record: %s",
                 a.out);
    TF_CHECK_MSG(tc_expect(&alice, "MODE " CHAN_T " -o " NICK_A "\r\n", T_IO_MS) == 0,
                 "alice never saw the echo of her own de-op: %s",
                 tc_buffer(&alice));
    TF_CHECK_MSG(tc_send(&alice, "PING :over") == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(&alice, "over", T_IO_MS) == 0, "alice got no PONG");
    /* The resync has to be provoked AFTER the de-op, and the tick hook's stage-1
     * gate is exactly that: it fires the moment A's local member of #T is no longer
     * an operator. So this is the first resync A drives in this case. */
    TF_CHECK_MSG(nf_expect(&a, "resync_offered: stage=1", T_IO_MS) == 0,
                 "node A never drove the resync this case is about: %s", a.out);
    TF_CHECK_MSG(nf_expect(&b, "fed_burst_abandon: origin=" NAME_A, T_IO_MS) == 0,
                 "node B never discarded an over-budget transaction, so the "
                 "receiver's half of the bound is not enforced: %s",
                 b.out);
    /* reason=TOO_LARGE is the volume charge and nothing else, and members=2 is the
     * load-bearing half: the transaction got as far as accepting ONE member record
     * and was refused on the second, which is the position the budget above was
     * chosen for. A case that tripped earlier would not be measuring a member
     * record at all. The byte count is deliberately NOT asserted: it moves whenever
     * a field width does, and a test that failed on that would be testing the
     * constants rather than the behaviour. */
    TF_CHECK_MSG(nf_expect(&b, "reason=TOO_LARGE nicks=2 chans=1 members=2 bytes=",
                           T_IO_MS) == 0,
                 "node B did not discard the transaction where the case expects -- "
                 "inside its member records -- or discarded it for another reason: "
                 "%s",
                 b.out);
    TF_CHECK_MSG(nf_expect_u64(&b, "burst_abandoned=", 1, 2000) == 0,
                 "node B's discard counter is not 1, so the abandonment above and "
                 "this count are not the same event: %s",
                 b.out);
    /* AND IT WAS NOT APPLIED. The applied line is printed by the same code that
     * installs the members, so an over-budget transaction that also printed one
     * would be a transaction that did both. */
    TF_CHECK_MSG(tf_count(b.out, "fed_burst_applied: peer=" NAME_A " nicks=2") == 0,
                 "node B applied a transaction it also discarded, so the discard is "
                 "not total: %s",
                 b.out);

    /* AND NOTHING LEAKED. This is the assertion the whole case is for: ann was on
     * the wire, in a member line the node read and charged, and the transaction
     * that carried her was thrown away -- so she must not be in B's roster, in
     * B's 353, or in the channel's member-server set. The absence check is scoped
     * to THIS answer, and the line count is asserted too, so a leak that landed
     * `ann` in the same 353 group as the others would be caught by the name and a
     * leak that added a group of her own by the count. */
    expect_names(&bob, "bob after the over-budget resync", NICK_B, CHAN_T, unchanged,
                 2u, NULL);
    /* AND THE LINK IS STILL GOOD, which is the other half of "discarded in full":
     * a peer is not punished for a transaction this node chose to refuse, because
     * the sender did nothing wrong -- it applied its own bound and never sent
     * anything over the cap. */
    TF_CHECK_MSG(nf_expect(&b, "link: peer=" NAME_A " state=ESTABLISHED", T_IO_MS) == 0,
                 "node B's link to node A is not ESTABLISHED, so refusing a "
                 "transaction cost it the link: %s",
                 b.out);
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");

    tc_close(&alice);
    tc_close(&ann);
    tc_close(&bob);
    nf_free(&a);
    nf_free(&b);
    g_tiny_send = 0;
    g_tiny_recv = 0;
}

/* ---------------------------------------------------------------------------
 * A TRUNCATED TRANSACTION
 * ---------------------------------------------------------------------------
 * 4.3 says "There is no partial burst and no delta", and a receiver cannot know a
 * burst has ended unless it is told -- so what it is told is ASSERTED against what
 * arrived rather than believed. That assertion is the only thing standing between a
 * lossy link and a node quietly holding half of somebody else's state, and this
 * case is the only way to reach it: a correctly behaving sender cannot produce a
 * transaction whose terminator disagrees with its records (it renders all-or-
 * nothing, and case_burst_refused() covers the half of that which is a refusal),
 * and a link that saturates mid-flush is not something a fixture can ask for.
 *
 * SO THE FIXTURE SENDS ONE, described in full at send_truncated_burst(): well
 * formed all the way through, one member record short, and a terminator that claims
 * the member it did not send.
 *
 * WHAT IT IS ASSERTED TO CHANGE, and it is the same wire property the over-budget
 * case asserts and for the same reason -- a discarded transaction must leave
 * nothing behind. The member record the transaction DOES carry claims alice is
 * plain, and the origin has de-opped her, so a receiver that believed the
 * terminator would rewrite a roster it had no right to touch: her op group would
 * disappear and B's answer would collapse from two 353 lines to one. The roster
 * assertion is therefore the teeth, and the counters are the diagnosis.
 */
static void case_truncated_burst_changes_nothing(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;
    test_client_t ann;
    test_client_t bob;
    const char *const unchanged[] = { NICK_B " " NICK_E, "@" NICK_A };

    g_peer_port = 0;
    g_trace = 0;
    g_is_b = 0;
    g_stage = 0;
    g_tiny_send = 0;
    g_tiny_recv = 0;
    g_truncate = 1;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    g_peer_port = a.port;
    g_is_b = 1;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");

    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A");
    TF_CHECK_MSG(nf_expect(&b, "fed_burst_applied: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never applied the empty establishment transaction, so the "
                 "apply path this case contrasts against is not working: %s",
                 b.out);
    TF_CHECK_MSG(nf_expect_u64(&b, "burst_abandoned=", 0, 1000) == 0,
                 "node B abandoned a transaction before the case provoked one: %s",
                 b.out);

    register_client(&alice, a.port, NICK_A);
    register_client(&ann, a.port, NICK_E);
    register_client(&bob, b.port, NICK_B);
    TF_CHECK_MSG(tc_send(&alice, "JOIN " CHAN_T) == 0, "alice's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed on the node that owns the channel");
    TF_CHECK_MSG(tc_send(&ann, "JOIN " CHAN_T) == 0, "ann's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&ann, " 366 ", T_IO_MS) == 0,
                 "ann's JOIN never completed on the node that owns the channel");
    TF_CHECK_MSG(tc_send(&bob, "JOIN " CHAN_T) == 0, "bob's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 366 ", T_IO_MS) == 0,
                 "bob's JOIN never completed on the node that does not own the "
                 "channel");
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=" CHAN_T " member=" NICK_B, T_IO_MS)
                     == 0,
                 "node A never learned about bob: %s", a.out);
    expect_names(&bob, "bob before the truncated transaction", NICK_B, CHAN_T,
                 unchanged, 2u, NULL);

    /* The de-op, so the transaction's one surviving member record is a CHANGE. */
    TF_CHECK_MSG(tc_send(&alice, "MODE " CHAN_T " -o " NICK_A) == 0,
                 "alice's MODE -o send failed");
    TF_CHECK_MSG(nf_expect(&a, "chan_member_mode: channel=" CHAN_T " by=" NICK_A
                               " nick=" NICK_A " mode=o set=0",
                           T_IO_MS) == 0,
                 "node A never applied alice's own de-op, so the truncated "
                 "transaction would carry no changed record and could not be told "
                 "apart from one that agreed: %s",
                 a.out);
    TF_CHECK_MSG(tc_expect(&alice, "MODE " CHAN_T " -o " NICK_A "\r\n", T_IO_MS) == 0,
                 "alice never saw the echo of her own de-op: %s",
                 tc_buffer(&alice));
    TF_CHECK_MSG(tc_send(&alice, "PING :trunc") == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(&alice, "trunc", T_IO_MS) == 0, "alice got no PONG");

    /* THE TRUNCATED TRANSACTION, and the count assertion catching it. The
     * members=2/1 is the load-bearing part of the needle: the terminator claimed
     * two members and one arrived. */
    TF_CHECK_MSG(nf_expect(&a, "truncated_sent: ok=1", T_IO_MS) == 0,
                 "node A never sent the truncated transaction: %s", a.out);
    TF_CHECK_MSG(nf_expect(&b, "fed_burst_truncated: peer=" NAME_A, T_IO_MS) == 0,
                 "node B did not detect a truncated transaction, so the terminator's "
                 "counts are not being asserted against what arrived: %s",
                 b.out);
    TF_CHECK_MSG(nf_expect(&b, "nicks=1/1 chans=1/1 members=2/1", T_IO_MS) == 0,
                 "node B detected the truncation somewhere other than the member "
                 "count, so this case is not measuring the count assertion: %s",
                 b.out);
    /* THE COUNTER THAT NAMES THE DIAGNOSIS, asserted BEFORE the general discard
     * count on purpose. burst_abandoned=1 below is also true of an over-budget
     * discard and of a malformed record, so a test that asserted it first and
     * failed would leave the reader guessing which of the three happened; this
     * one is only ever incremented on the branch that printed
     * `fed_burst_truncated` above, so asserting it first means the failure names
     * the truncation rather than the discard it caused. That ordering is the
     * whole point of the counter existing: before it, this case had exactly one
     * number for three different faults.
     *
     * AND IT IS NOT A SUBSTITUTE FOR THE WIRE ASSERTIONS ABOVE, which are what
     * says the node behaved correctly; this says it said so in a countable way. */
    TF_CHECK_MSG(nf_expect_u64(&b, "burst_truncated=", 1, 2000) == 0,
                 "node B's truncation counter is not 1, so the truncation above and "
                 "this count are not the same event -- the discard is real but the "
                 "node cannot say which rule threw the transaction away: %s",
                 b.out);
    TF_CHECK_MSG(nf_expect_u64(&b, "burst_abandoned=", 1, 2000) == 0,
                 "node B's discard counter is not 1, so the truncation above and this "
                 "count are not the same event: %s",
                 b.out);
    TF_CHECK_MSG(tf_count(b.out, "fed_burst_applied: peer=" NAME_A " nicks=1") == 0,
                 "node B applied a transaction it also discarded, so the count "
                 "assertion is not preventing the apply: %s",
                 b.out);

    /* AND NOTHING CHANGED, which is the claim. alice is still an operator on B,
     * because the transaction that would have de-privileged her was thrown away
     * before anything in it was installed. */
    expect_names(&bob, "bob after the truncated transaction", NICK_B, CHAN_T, unchanged,
                 2u, NULL);
    TF_CHECK_MSG(nf_expect(&b, "link: peer=" NAME_A " state=ESTABLISHED", T_IO_MS) == 0,
                 "node B's link to node A is not ESTABLISHED, so a truncated "
                 "transaction cost it the link: %s",
                 b.out);
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&b, "fed_malformed=", 0, 1000) == 0,
                 "node B refused a burst line as malformed, so this case is "
                 "measuring a field validation rather than the count assertion: %s",
                 b.out);

    tc_close(&alice);
    tc_close(&ann);
    tc_close(&bob);
    nf_free(&a);
    nf_free(&b);
    g_truncate = 0;
}

/* ---------------------------------------------------------------------------
 * A TRANSACTION OPEN AT SHUTDOWN
 * ---------------------------------------------------------------------------
 * 4.3's shadow is the one allocation on a node whose owner is a module global
 * rather than a field on server_t, so it is the one teardown arm server_shutdown()
 * has to CALL rather than free. C4 declined to add that arm because it could not
 * be verified locally -- LeakSanitizer does not run on Darwin -- which is the
 * reasoning this case exists to contradict: an arm that is unverifiable locally
 * is exactly the one worth adding when LSan DOES run on the CachyOS Linux CI
 * runner, and the arm is made verifiable HERE instead, by printing whether a
 * shadow was open at teardown.
 *
 * SO WHAT IS ASSERTED is that the arm RAN while a shadow was open, not that it
 * freed anything -- this platform cannot observe the free, and saying so in the
 * assertion rather than implying otherwise is the honest form. Linux CI reads the
 * same line next to its leak check.
 *
 * THE ORDER IS LOAD-BEARING AND IS THE OTHER HALF OF THE CLAIM. Node B is
 * stopped while node A is still ALIVE, so B's link never goes down and
 * fed_burst_abandon() -- the link-down discard -- is never reached. If A were
 * stopped first, the shadow would be released by the ordinary link-down path, the
 * teardown arm would report NONE, and the case would be measuring the wrong arm.
 * burst_abandoned=0 at the end is what proves that is what happened rather than a
 * shutdown that found nothing.
 */
static void case_open_transaction_released_at_shutdown(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;

    g_peer_port = 0;
    g_trace = 0;
    g_is_b = 0;
    g_stage = 0;
    g_tiny_send = 0;
    g_tiny_recv = 0;
    g_truncate = 0;
    g_open_burst = 1;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");
    g_peer_port = a.port;
    g_is_b = 1;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");

    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(&b, "fed_burst_applied: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never applied the empty establishment transaction, so the "
                 "begin/record machinery this case leaves open is not the one under "
                 "test: %s",
                 b.out);
    /* A client so the node is a node with real state rather than an empty one, and
     * so the establishment transaction above is not the only thing that has ever
     * been true of it. Nothing in the case depends on this -- it is here because a
     * shadow left open on a node that has never had a client is an arrangement no
     * deployment produces. */
    register_client(&alice, a.port, NICK_A);
    TF_CHECK_MSG(tc_send(&alice, "JOIN " CHAN_T) == 0, "alice's JOIN send failed");
    TF_CHECK_MSG(tc_expect(&alice, " 366 ", T_IO_MS) == 0,
                 "alice's JOIN never completed on the node that owns the channel");

    /* THE OPEN TRANSACTION. The tick hook fires it the moment alice has JOINed,
     * which is the same gate the truncated case uses, and the `[fixture] open_sent`
     * line is what makes the rest of the case non-vacuous: it says the line was
     * queued, so a later failure is about what the receiver did with it. */
    TF_CHECK_MSG(nf_expect(&a, "open_sent: ok=1", T_IO_MS) == 0,
                 "node A never sent the open transaction: %s", a.out);
    /* AND NOTHING HAPPENED YET, which is the point of leaving one open: a BEGIN
     * with no terminator installs nothing, and the two assertions below are the
     * pair -- the link is still up AND node B has discarded nothing -- that says
     * the shadow is sitting there rather than having been thrown away on the way
     * in. A receiver that discarded an unterminated transaction immediately would
     * have burst_abandoned=1 here and the case would be measuring a different
     * design. */
    TF_CHECK_MSG(nf_expect(&b, "link: peer=" NAME_A " state=ESTABLISHED", T_IO_MS) == 0,
                 "node B's link to node A is not ESTABLISHED, so an open "
                 "transaction cost it the link: %s",
                 b.out);
    TF_CHECK_MSG(nf_expect_u64(&b, "burst_abandoned=", 0, 1000) == 0,
                 "node B discarded something while the transaction was open, so the "
                 "teardown arm below would be finding nothing and this case would "
                 "be measuring a transaction that was never open: %s",
                 b.out);

    /* B FIRST, A SECOND. See the header: this is what keeps fed_burst_abandon()
     * out of the picture. */
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    TF_CHECK_MSG(nf_expect(&b, "fed_burst_close: shadow=OPEN", T_IO_MS) == 0,
                 "node B's shutdown did not report an open shadow, so "
                 "server_shutdown()'s arm either did not run or found nothing -- and "
                 "a node that stops mid-burst is the case the arm exists for: %s",
                 b.out);
    /* THE NEGATIVE HALF, because a line that always says OPEN would satisfy the
     * assertion above as easily as a real teardown would. Every other case in this
     * file ends with its node's shadow closed, so this is the one place in the
     * suite that can see the NONE reading. */
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_expect(&a, "fed_burst_close: shadow=NONE", T_IO_MS) == 0,
                 "node A reported an open shadow at shutdown, and node A never had "
                 "one -- so the OPEN reading above is a constant rather than a "
                 "measurement: %s",
                 a.out);
    TF_CHECK_MSG(nf_expect_u64(&a, "burst_abandoned=", 0, 1000) == 0,
                 "node A abandoned a transaction of its own, so the NONE reading "
                 "above may be a shadow that had already been thrown away rather "
                 "than one that never existed: %s",
                 a.out);

    tc_close(&alice);
    nf_free(&a);
    nf_free(&b);
    g_open_burst = 0;
}

int main(void)
{
    case_resync_replaces();
    case_burst_refused();
    case_over_budget_changes_nothing();
    case_truncated_burst_changes_nothing();
    case_open_transaction_released_at_shutdown();
    tf_done("fed_burst");
    return 0;
}
