/* test_invite_notify.c -- IRCv3 `invite-notify`.
 *
 * ---------------------------------------------------------------------------
 * THE AUDIENCE IS THE CHANNEL, AND THAT IS THE FIRST THING THIS FILE ESTABLISHES
 * ---------------------------------------------------------------------------
 * The specification says the capability "allows a client to specify that it would like
 * to be notified when users are invited to channels", and the message is
 *
 *     :<inviter> INVITE <target> <channel>
 *
 * -- the SOURCE is the inviter, the TARGET is a third party, and the CHANNEL is where
 * the recipient has to be. **It is easy to misread this as being about the invitee's own
 * other connections**, and that reading is wrong twice over: the message is about
 * somebody else doing something, and RFC 2812 3.3.6's own rule is "Other channel members
 * SHOULD NOT be notified", which is exactly the rule this capability lets a client opt
 * out of.
 *
 * THE OTHER-CONNECTIONS QUESTION IS ANSWERED BECAUSE IT WAS ASKED, and the answer is
 * that on this node the set is EMPTY BY CONSTRUCTION: exactly one connection may hold a
 * nickname, because the nick registry refuses a second with `433`. So a reading of the
 * brief that made this specification about an invitee's other connections would have been
 * vacuously satisfied on this node -- and it is the wrong reading anyway. The cases below
 * are about the channel, and `case_one_connection_per_nick` asserts the one-connection
 * invariant that makes the other reading vacuous, so that the vacuity is on the record
 * rather than in the prose.
 *
 * ---------------------------------------------------------------------------
 * WHY THE COUNTS ARE COUNTS
 * ---------------------------------------------------------------------------
 * The line this feature adds is an `INVITE`, and `test_invite.c` already asserts that an
 * `INVITE` reaches the INVITEE. So a substring search for "INVITE" on the invitee's socket
 * is satisfied by the delivery whether or not the notification fired, and a search on a
 * member's socket is satisfied by that member being the invitee. Every claim below is a
 * count over a marked window instead.
 *
 * NO FIXED sleep() ANYWHERE (6.3): every wait is tc_expect()'s deadline loop and every
 * window is closed by a PING whose PONG is the drain token, numbered per call because
 * tc_expect() searches the ACCUMULATED buffer and a reused token would be satisfied by
 * an earlier PONG with no read at all.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/cap.h"
#include "core/connection.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define SRV "irc.test"
#define OBSERVED_HOST "127.0.0.1"
#define CHAN "#I"
#define OTHER "#J"

static unsigned g_drain_seq;

static void drain(test_client_t *c)
{
    char token[64];
    char line[128];

    (void)snprintf(token, sizeof token, "in%u", g_drain_seq++);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING failed");
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG for drain token %s, so the buffer is not yet drained and "
                 "every count below would be about the read schedule", token);
}

static size_t lines_since(const test_client_t *c, size_t from)
{
    const char *at = tc_buffer(c) + from;
    size_t n = 0;

    for (; *at != '\0'; at++) {
        if (at[0] == '\r' && at[1] == '\n') {
            n++;
        }
    }
    return n;
}

static void expect_only_replies(test_client_t *c, size_t mark, const char *what,
                                size_t n_replies)
{
    drain(c);
    TF_CHECK_MSG(lines_since(c, mark) == n_replies + 1u,
                 "%s: the window holds %zu lines and it must hold exactly %zu -- the "
                 "%zu expected replies and the drain PONG. Anything else fails this, "
                 "which is why it is a COUNT and not a list of verbs somebody thought "
                 "of.\n  client saw: %s",
                 what, lines_since(c, mark), n_replies + 1u, n_replies,
                 tc_buffer(c) + mark);
}

static size_t count_since(const test_client_t *c, size_t mark, const char *needle)
{
    return tf_count(tc_buffer(c) + mark, needle);
}

static void register_caps(test_client_t *c, int port, const char *nick,
                          const char *caps)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    if (caps != NULL) {
        (void)snprintf(line, sizeof line, "CAP REQ :%s", caps);
        TF_CHECK_MSG(tc_send(c, line) == 0, "%s CAP REQ send failed", nick);
        (void)snprintf(line, sizeof line, " ACK :%s\r\n", caps);
        TF_CHECK_MSG(tc_expect(c, line, T_IO_MS) == 0,
                     "%s was not ACKed \"%s\", so the node does not have the "
                     "capability and the cases below would be asserting the wrong "
                     "thing about it", nick, caps);
    }
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s NICK send failed", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s USER send failed", nick);
    if (caps != NULL) {
        TF_CHECK_MSG(tc_send(c, "CAP END") == 0, "%s CAP END send failed", nick);
    }
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered", nick);
    drain(c);
}

static void join(test_client_t *c, const char *chan)
{
    char line[128];

    (void)snprintf(line, sizeof line, "JOIN %s", chan);
    TF_CHECK_MSG(tc_send(c, line) == 0, "JOIN %s send failed", chan);
    (void)snprintf(line, sizeof line, " JOIN %s\r\n", chan);
    TF_CHECK_MSG(tc_expect(c, line, T_IO_MS) == 0,
                 "the JOIN %s echo never arrived, so the roster is not the one under "
                 "test", chan);
    drain(c);
}

/* ---------------------------------------------------------------------------
 * 1. ADVERTISED, AND THE NOTIFICATION IS THE SPECIFICATION'S LINE
 * ---------------------------------------------------------------------------
 * Four connections, because the specification's audience needs four different
 * relationships to the event:
 *
 *   op       the inviter. Negotiated, and on the channel. Gets `341` and NOTHING else.
 *   watcher  a plain member. Negotiated. Gets the notification.
 *   blunt    a plain member. NOT negotiated. Gets nothing.
 *   guest    the invitee. NOT on the channel, and NOT negotiated -- and this is the
 *            connection the OTHER reading of the specification would have been about.
 *
 * The line is asserted byte for byte, because its shape IS the specification's claim:
 * the source is the inviter's own hostmask, and the two parameters are the target's
 * nickname and the channel.
 */
static void case_advertised_and_the_line(void)
{
    nf_node_t node;
    test_client_t op;
    test_client_t watcher;
    test_client_t blunt;
    test_client_t guest;
    size_t mark_op;
    size_t mark_w;
    size_t mark_b;
    size_t mark_g;
    char want[160];

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&op);
    register_caps(&op, node.port, "in_op", CAP_INVITE_NOTIFY);
    tc_init(&watcher);
    register_caps(&watcher, node.port, "in_w", CAP_INVITE_NOTIFY);
    tc_init(&blunt);
    register_caps(&blunt, node.port, "in_b", NULL);
    tc_init(&guest);
    register_caps(&guest, node.port, "in_g", NULL);

    /* The inviter becomes op so the INVITE is not refused with 482, and the members
     * have to be on the channel before the invite or the notification has no audience. */
    join(&op, CHAN);
    join(&watcher, CHAN);
    join(&blunt, CHAN);
    TF_CHECK_MSG(tc_send(&op, "MODE " CHAN " +o in_op") == 0, "MODE +o send failed");
    drain(&op);
    drain(&watcher);
    drain(&blunt);

    mark_op = tc_received(&op);
    mark_w = tc_received(&watcher);
    mark_b = tc_received(&blunt);
    mark_g = tc_received(&guest);
    TF_CHECK_MSG(tc_send(&op, "INVITE in_g " CHAN) == 0, "the INVITE failed to send");

    /* THE INVITEE'S OWN COPY IS UNCHANGED, and that is `test_invite.c`'s claim rather
     * than this feature's: the invitee gets `:op!op@… INVITE in_g #I` because they were
     * invited, not because they negotiated anything. The two are the SAME line on the
     * wire and they go to different connections for different reasons. */
    TF_CHECK_MSG(tc_expect(&guest, ":in_op!in_op@" OBSERVED_HOST " INVITE in_g " CHAN,
                           T_IO_MS) == 0,
                 "the invitee did not get the INVITE. This feature is not what delivers "
                 "it -- RFC 2812 3.3.6 requires it and test_invite.c owns that claim -- "
                 "so a failure here is a failure of the invitation, not of the "
                 "notification.\n  guest saw: %s", tc_buffer(&guest));

    /* THE MEMBER WHO ASKED IS TOLD, and the line is the specification's. */
    (void)snprintf(want, sizeof want,
                   ":in_op!in_op@" OBSERVED_HOST " INVITE in_g " CHAN "\r\n");
    TF_CHECK_MSG(tc_expect(&watcher, want, T_IO_MS) == 0,
                 "a member of the channel who negotiated invite-notify was not told, or "
                 "was told a different line. The specification's format is\n"
                 "  :<inviter> INVITE <target> <channel>\n"
                 "and the source is the INVITER's own hostmask, not the server's.\n"
                 "  watcher saw: %s", tc_buffer(&watcher));
    expect_only_replies(&watcher, mark_w, "the negotiated member", 1u);
    TF_CHECK_MSG(count_since(&watcher, mark_w, " INVITE ") == 1u,
                 "%zu INVITE lines reached the member and exactly 1 must.\n  watcher "
                 "saw: %s", count_since(&watcher, mark_w, " INVITE "),
                 tc_buffer(&watcher) + mark_w);

    /* THE MEMBER WHO DID NOT ASK IS TOLD NOTHING. RFC 2812 3.3.6's "SHOULD NOT be
     * notified" still stands for a client that did not opt in, and this is the case that
     * keeps the capability from being an unsolicited announcement. */
    expect_only_replies(&blunt, mark_b, "the non-negotiating member", 0u);
    TF_CHECK_MSG(count_since(&blunt, mark_b, "INVITE") == 0u,
                 "%zu INVITE lines reached a member who did not negotiate "
                 "invite-notify. The notification is an unsolicited ASSERTION about a "
                 "third party, so it goes to the clients that asked for it and to nobody "
                 "else.\n  blunt saw: %s", count_since(&blunt, mark_b, "INVITE"),
                 tc_buffer(&blunt) + mark_b);

    /* THE INVITER GETS ITS `341` AND NOTHING ELSE, and that is the exclusion rather than
     * the gate: the inviter DID negotiate, so the gate would have let it through. The
     * `341` is the inviter's answer and the specification's own phrase is "when ANOTHER
     * client does an /INVITE". */
    TF_CHECK_MSG(tc_expect(&op, " 341 in_op " CHAN " in_g ", T_IO_MS) == 0,
                 "the inviter was not answered 341.\n  op saw: %s", tc_buffer(&op));
    expect_only_replies(&op, mark_op, "the inviter", 1u);
    TF_CHECK_MSG(count_since(&op, mark_op, " INVITE ") == 0u,
                 "%zu INVITE lines reached the inviter, which negotiated the "
                 "capability. The exclusion is `exclude`, not the gate, and this is the "
                 "case that proves the two are different questions.\n  op saw: %s",
                 count_since(&op, mark_op, " INVITE "), tc_buffer(&op) + mark_op);

    /* AND THE INVITEE'S WINDOW IS EXACTLY ONE LINE, because the notification is not a
     * second copy of what they were already sent. */
    expect_only_replies(&guest, mark_g, "the invitee", 1u);

    tc_close(&op);
    tc_close(&watcher);
    tc_close(&blunt);
    tc_close(&guest);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 2. THE AUDIENCE IS THE CHANNEL, NOT THE NODE AND NOT THE INVITEE
 * ---------------------------------------------------------------------------
 * `test_away_notify.c` has a case_two_channels() for exactly this shape and the argument
 * is the same one here: a notification that names a channel must reach that channel's
 * members and nobody else. Two channels and three connections, so each is wrong in a
 * different direction:
 *
 *   op       the inviter, op on BOTH channels.
 *   near     a member of `CHAN` only, negotiated.
 *   far      a member of `OTHER` only, negotiated -- must hear nothing about `CHAN`, and
 *            must hear about `OTHER`.
 */
static void case_audience_is_the_channel(void)
{
    nf_node_t node;
    test_client_t op;
    test_client_t near_m;
    test_client_t far_m;
    char line[128];
    size_t mark_near;
    size_t mark_far;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&op);
    register_caps(&op, node.port, "in_op", CAP_INVITE_NOTIFY);
    tc_init(&near_m);
    register_caps(&near_m, node.port, "in_n", CAP_INVITE_NOTIFY);
    tc_init(&far_m);
    register_caps(&far_m, node.port, "in_f", CAP_INVITE_NOTIFY);

    join(&op, CHAN);
    join(&near_m, CHAN);
    join(&op, OTHER);
    join(&far_m, OTHER);
    (void)snprintf(line, sizeof line, "MODE " CHAN " +o in_op");
    TF_CHECK_MSG(tc_send(&op, line) == 0, "MODE +o on " CHAN " failed");
    drain(&op);
    (void)snprintf(line, sizeof line, "MODE " OTHER " +o in_op");
    TF_CHECK_MSG(tc_send(&op, line) == 0, "MODE +o on " OTHER " failed");
    drain(&op);
    drain(&near_m);
    drain(&far_m);

    /* THE INVITE ON THE FIRST CHANNEL. */
    mark_near = tc_received(&near_m);
    mark_far = tc_received(&far_m);
    TF_CHECK_MSG(tc_send(&op, "INVITE in_f " CHAN) == 0,
                 "the INVITE on " CHAN " failed to send");
    TF_CHECK_MSG(tc_expect(&near_m, ":in_op!in_op@" OBSERVED_HOST " INVITE in_f " CHAN,
                           T_IO_MS) == 0,
                 "the member of " CHAN " was not told.\n  near saw: %s",
                 tc_buffer(&near_m));
    expect_only_replies(&near_m, mark_near, "the member of the invited-to channel", 1u);

    /* AND NOTHING AT ALL WENT TO THE MEMBER OF THE OTHER CHANNEL, which is the half a
     * node-wide walk would fail.
     *
     * **THE COUNT IS ONE, NOT ZERO, AND THAT IS THE INTERESTING PART.** `far` is the
     * INVITEE, so its socket legitimately holds `:in_op!in_op@… INVITE in_f #I` -- and
     * that line is BYTE-IDENTICAL to the notification the member of `CHAN` receives. The
     * two reach the same bytes by different rules (RFC 2812 3.3.6 delivers the
     * invitation; `invite-notify` announces it), so the ONLY way to tell them apart on a
     * socket that has both is to count. A node that also announced the invitation to the
     * invitee would put two identical lines there, and a substring search would see
     * nothing wrong.
     *
     * The invitee also did NOT negotiate, so even if the announcement did reach it the
     * gate would have stopped it -- which makes this case a weaker discriminator than it
     * looks, and `case_refused_invite_notifies_nobody` plus case 1's `blunt` are where
     * the gate is actually proved. What this case proves is the AUDIENCE: the notification
     * is addressed to one channel, and a member of another channel heard nothing. */
    expect_only_replies(&far_m, mark_far, "the invitee on the other channel", 1u);
    TF_CHECK_MSG(count_since(&far_m, mark_far, " INVITE in_f " CHAN) == 1u,
                 "%zu copies of the invitation reached a member of %s, and exactly 1 "
                 "must. The notification addresses ONE channel and the audience is that "
                 "channel's members -- the one line here is the invitee's own, which is "
                 "byte-identical to what a member of %s receives.\n  far saw: %s",
                 count_since(&far_m, mark_far, " INVITE in_f " CHAN), OTHER, CHAN,
                 tc_buffer(&far_m) + mark_far);

    /* AND THE INVITE ON THE SECOND CHANNEL REACHES THE SECOND CHANNEL, so the case is
     * about the audience rather than about `far` being silent in general. */
    mark_near = tc_received(&near_m);
    mark_far = tc_received(&far_m);
    TF_CHECK_MSG(tc_send(&op, "INVITE in_n " OTHER) == 0,
                 "the INVITE on " OTHER " failed to send");
    TF_CHECK_MSG(tc_expect(&far_m, ":in_op!in_op@" OBSERVED_HOST " INVITE in_n " OTHER,
                           T_IO_MS) == 0,
                 "the member of %s was not told about an invitation to %s.\n  far "
                 "saw: %s", OTHER, OTHER, tc_buffer(&far_m));
    expect_only_replies(&far_m, mark_far, "the member of the invited-to channel", 1u);
    /* ONE line and not zero: `near` is the INVITEE of this one, so it holds its own
     * INVITE. What it must not ALSO hold is a notification -- and because the two lines
     * are byte-identical, only the count can tell them apart. */
    expect_only_replies(&near_m, mark_near, "the member of the other channel", 1u);
    TF_CHECK_MSG(count_since(&near_m, mark_near, " INVITE ") == 1u,
                 "%zu INVITE lines reached a member of %s who is on no such channel as a "
                 "member -- they are the invitee, so exactly 1 is right and 2 would mean "
                 "the notification reached them as well.\n  near saw: %s",
                 count_since(&near_m, mark_near, " INVITE "), CHAN,
                 tc_buffer(&near_m) + mark_near);

    tc_close(&op);
    tc_close(&near_m);
    tc_close(&far_m);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 3. A REFUSED INVITE NOTIFIES NOBODY
 * ---------------------------------------------------------------------------
 * The notification is emitted AFTER every refusal in `handle_invite()` has returned, so a
 * client that saw `482` (not an operator), `403` (no such channel), `401` (no such nick)
 * or `442` (not on the channel) has produced no invitation and therefore has nothing to
 * announce.
 *
 * `482` is the interesting one, because it is the refusal a client can provoke on purpose
 * and because it is the only one whose absence would be a real disclosure: a node that
 * emitted the notification before the authority check would tell a channel "X has
 * invited Y" about an invitation that never happened.
 */
static void case_refused_invite_notifies_nobody(void)
{
    nf_node_t node;
    test_client_t op;
    test_client_t watcher;
    test_client_t plain;
    size_t mark_w;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&op);
    register_caps(&op, node.port, "in_op", CAP_INVITE_NOTIFY);
    tc_init(&watcher);
    register_caps(&watcher, node.port, "in_w", CAP_INVITE_NOTIFY);
    tc_init(&plain);
    register_caps(&plain, node.port, "in_p", CAP_INVITE_NOTIFY);

    join(&op, CHAN);
    join(&watcher, CHAN);
    join(&plain, CHAN);
    /* `plain` is deliberately NOT op, so its INVITE is 482. */
    drain(&op);
    drain(&watcher);
    drain(&plain);

    mark_w = tc_received(&watcher);
    TF_CHECK_MSG(tc_send(&plain, "INVITE in_w " CHAN) == 0, "the INVITE failed");
    TF_CHECK_MSG(tc_expect(&plain, " 482 in_p " CHAN " :You're not a channel operator",
                           T_IO_MS) == 0,
                 "a non-operator's INVITE was not refused with 482, so the refusal cases "
                 "below would not be about a refusal.\n  plain saw: %s",
                 tc_buffer(&plain));
    drain(&plain);
    expect_only_replies(&watcher, mark_w, "the channel after a refused INVITE", 0u);
    TF_CHECK_MSG(count_since(&watcher, mark_w, "INVITE") == 0u,
                 "%zu INVITE lines reached the channel after an INVITE that was refused "
                 "with 482. A notification about an invitation that did not happen is a "
                 "false statement about a third party.\n  watcher saw: %s",
                 count_since(&watcher, mark_w, "INVITE"), tc_buffer(&watcher) + mark_w);

    tc_close(&op);
    tc_close(&watcher);
    tc_close(&plain);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 4. ONE CONNECTION PER NICK, WHICH IS WHY THE OTHER READING IS VACUOUS HERE
 * ---------------------------------------------------------------------------
 * The brief for this pass described `invite-notify` as "INVITE reaching a client's other
 * connections", which is a BOUNCER-shaped reading and not what the specification says --
 * but it is worth putting the fact on the record that on this node the set of a user's
 * other connections is EMPTY, so that reading would have been vacuously satisfied and the
 * vacuity is a property of the node rather than an accident of the test.
 *
 * It is one assertion on `433`, and the reason it is here rather than in a comment is that
 * a future phase adding multi-connection support would silently make a second reading of
 * this specification meaningful without touching a line of this file -- and this line is
 * what would notice.
 */
static void case_one_connection_per_nick(void)
{
    nf_node_t node;
    test_client_t a;
    test_client_t b;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&a);
    register_caps(&a, node.port, "in_same", CAP_INVITE_NOTIFY);
    tc_init(&b);
    TF_CHECK_MSG(tc_connect(&b, node.port) == 0, "the second connect failed");
    TF_CHECK_MSG(tc_send(&b, "NICK in_same") == 0, "the second NICK failed");
    TF_CHECK_MSG(tc_expect(&b, " 433 ", T_IO_MS) == 0,
                 "a second connection took a nickname that is already held. Exactly one "
                 "connection may hold a nickname on this node, which is why a reading of "
                 "invite-notify as being about a user's OTHER connections has an EMPTY "
                 "audience here -- vacuously satisfied, and not what the specification "
                 "says.\n  second saw: %s", tc_buffer(&b));

    tc_close(&a);
    tc_close(&b);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * TEETH, AND WHERE THEY WERE INJECTED
 * ---------------------------------------------------------------------------
 * Each was watched go red with the behaviour broken, and the BUILD was checked before the
 * run was believed -- an uncompilable fault leaves the previous binary in place and
 * reports a pass, which has happened in this repo ten times.
 *
 *   THE CAPABILITY ADVERTISED WITH NOTHING BEHIND IT -- cap.c: the
 *       `{ CAP_INVITE_NOTIFY, CAPBIT_INVITE_NOTIFY }` row added with a fresh bit.
 *       Fails case 1's watcher assertion and every count. It is the fault with teeth: a
 *       client that negotiated it would sit in a channel waiting for an `INVITE` that no
 *       event on this node produces.
 *
 *   THE GATE IGNORED -- cap.c: `cap_gate_invite_notify()` made to return 1
 *       unconditionally. Fails case 1's `blunt` count and case 2's two cross-channel
 *       counts. This is the fault that turns an opt-in notification into an unsolicited
 *       line for everybody in the channel, which is RFC 2812 3.3.6's rule that the whole
 *       capability exists to relax.
 *
 *   THE INVITER NOT EXCLUDED -- chan_verbs.c: `c` replaced by NULL in
 *       `notify_invite()`'s `fanout_deliver_local_gated()` call. Fails case 1's `op`
 *       count and ONLY that: the inviter negotiated the capability, so the GATE would
 *       have let it through and the exclusion is the only thing keeping it out. It is the
 *       fault that proves `exclude` and the gate are different questions.
 *
 *   THE NOTIFICATION BEFORE THE REFUSALS -- chan_verbs.c: `notify_invite()` moved above
 *       `authority_ok()`. Fails case 3's `watcher` count, which is the only assertion in
 *       the suite that a notification cannot be about an invitation that did not happen.
 */
int main(void)
{
    case_advertised_and_the_line();
    case_audience_is_the_channel();
    case_refused_invite_notifies_nobody();
    case_one_connection_per_nick();

    tf_done("invite-notify");
    return 0;
}