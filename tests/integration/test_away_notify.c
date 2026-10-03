/* test_away_notify.c -- `away-notify`: the `AWAY` notification, on both edges.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS BEING CLAIMED, AND WHY THE CLEARED CASE IS HALF THE FILE
 * ---------------------------------------------------------------------------
 * The specification says: "When this capability is enabled, clients will be sent an
 * AWAY message when a user **sharing a channel with them** sets, changes or removes
 * their away state", and the format is
 *
 *     :nick!user@host AWAY [:message]
 *
 * where the message being present means GOING away and absent means REMOVING the
 * away state. Three properties, and the second is the one implementations miss:
 *
 *   1. the AUDIENCE is the users sharing a channel, per destination, on their own
 *      negotiation, and NEVER the user themselves -- "Clients SHOULD NOT be sent
 *      AWAY messages to notify them of their own away status (as they can rely on
 *      `RPL_NOWAYAY` and `RPL_UNAWAY`)", and `305`/`306` are those two.
 *   2. the CLEARED case notifies too. Without it a member's client believes the
 *      user is still away for ever, because the parameterless `AWAY` is the ONLY
 *      thing that carries the fact and nothing else would ever say it.
 *   3. it is NOT forwarded, and it does not need to be: away STATE federates
 *      through 4.3's SBURST, and a notification is not state. There is no peer on
 *      this node, so "does not forward" is asserted structurally -- through the
 *      local-only fan-out entry point -- and the argument is at the emitter.
 *
 * ---------------------------------------------------------------------------
 * WHY EVERY CASE COUNTS LINES RATHER THAN SEARCHING FOR A NEEDLE
 * ---------------------------------------------------------------------------
 * Most of the claims here are ABSENCES: the setter gets nothing, the client that did
 * not negotiate gets nothing, the member of another channel gets nothing. A list of
 * absent verbs would satisfy a fault that notified somebody nobody thought of, so
 * each window is counted: the drain `PONG` and nothing else. test_setname.c records
 * the reason that matters -- a `482` fault passed the first version of an assertion
 * that listed "417, 421, 451 are absent".
 *
 * NO FIXED sleep() ANYWHERE (6.3): every wait is tc_expect()'s deadline loop and
 * every window is closed by a PING whose PONG is the drain token, numbered per call
 * because tc_expect() searches the ACCUMULATED buffer and a reused token would be
 * satisfied by an earlier PONG with no read at all.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/cap.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define SRV "irc.test"
#define OBSERVED_HOST "127.0.0.1"
#define CHAN "#T"
#define OTHER "#U"

static unsigned g_drain_seq;

static void drain(test_client_t *c)
{
    char token[64];
    char line[128];

    (void)snprintf(token, sizeof token, "an%u", g_drain_seq++);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING failed");
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG for drain token %s, so the buffer is not yet drained and "
                 "every claim below would be about the read schedule", token);
}

/* Register `c` as `nick`, negotiating `caps` first (NULL for no CAP exchange).
 * The REQ is ACKed whole, so a capability this node does not have fails the wait
 * rather than being quietly NAKed -- which means no case below can pass because the
 * gate was never reached. */
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
                     "capability and every case below would be asserting the wrong "
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
    {
        char want[64];

        (void)snprintf(want, sizeof want, " JOIN %s\r\n", chan);
        TF_CHECK_MSG(tc_expect(c, want, T_IO_MS) == 0, "the JOIN %s echo never "
                     "arrived, so the roster below is not the one under test", chan);
    }
    /* The numerics that follow a JOIN (331/332/333/353/366/329) are drained here so
     * that a window opened below contains the notification and nothing else. */
    drain(c);
}

/* How many complete CRLF-terminated lines the region `from`..end of `c` holds. */
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

/* Assert that `c` received EXACTLY `n_replies` lines after `mark`, the drain PONG
 * included. Every absence claim in this file is one of these with `n_replies` 0. */
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

/* Assert that `want` -- a complete line -- arrived since `mark`, and that it sits at
 * the start of a line rather than being the tail of a longer one. */
static void expect_line_since(test_client_t *c, size_t mark, const char *what,
                              const char *want)
{
    const char *at;

    TF_CHECK_MSG(tc_expect(c, want, T_IO_MS) == 0,
                 "%s: expected the exact line \"%s\".\n  client saw: %s", what, want,
                 tc_buffer(c) + mark);
    at = strstr(tc_buffer(c), want);
    TF_CHECK_MSG(at != NULL, "%s: the line vanished from the buffer", what);
    TF_CHECK_MSG(at == tc_buffer(c) || at[-1] == '\n',
                 "%s: \"%s\" is not at the start of a line: it is the tail of a longer "
                 "one", what, want);
    TF_CHECK_MSG((size_t)(at - tc_buffer(c)) >= mark,
                 "%s: the line is from BEFORE this command", what);
}

/* ---------------------------------------------------------------------------
 * THE CASES
 * ---------------------------------------------------------------------------
 */

/* ADVERTISED. `cap.h`'s rule is that every name in `CAP LS` is an implementation
 * behind it, and this one has one: `handle_away()` notifies on both edges. The
 * capability's availability check is nothing, because `conn_t::away` exists on every
 * connection -- a node that advertised it and then sent nothing would be a client
 * waiting for a message that never comes. */
static void case_advertised(void)
{
    nf_node_t node;
    test_client_t c;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");
    TF_CHECK_MSG(tc_send(&c, "CAP LS") == 0, "CAP LS send failed");
    TF_CHECK_MSG(tc_expect(&c, " CAP * LS :", T_IO_MS) == 0, "CAP LS was not answered");
    TF_CHECK_MSG(strstr(tc_buffer(&c), CAP_AWAY_NOTIFY) != NULL,
                 "CAP LS does not advertise %s. `conn_t::away` exists on every "
                 "connection and AWAYLEN is advertised from CONN_MAX_AWAY, so there is "
                 "no configuration in which this node cannot honour the capability.",
                 CAP_AWAY_NOTIFY);
    tc_close(&c);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* SET, CLEARED, AND EVERYBODY ELSE.
 *
 * THE ROSTER, AND WHY EACH MEMBER IS THERE:
 *
 *   setter   negotiated `away-notify`, in #T      -> gets 306, and NOTHING else
 *   watcher  negotiated `away-notify`, in #T      -> gets the AWAY, both edges
 *   blunt    NO CAP exchange, in #T               -> gets nothing, both edges
 *   stranger negotiated `away-notify`, in #U only -> gets nothing, both edges
 *
 * `blunt` and `stranger` are the two negatives that are easy to conflate. `blunt`
 * is in the channel and did not ask, so it is refused by the GATE. `stranger` asked
 * and is not in the channel, so the fan-out never reaches it at all. A node with
 * one of the two defects -- gate ignored, or audience widened to the whole node --
 * passes the other half of this file and fails here. */
static void case_set_and_cleared(void)
{
    nf_node_t node;
    test_client_t setter;
    test_client_t watcher;
    test_client_t blunt;
    test_client_t stranger;
    char setline[256];
    char clearline[256];
    size_t m_setter;
    size_t m_watcher;
    size_t m_blunt;
    size_t m_stranger;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&setter);
    register_caps(&setter, node.port, "setter", CAP_AWAY_NOTIFY);
    join(&setter, CHAN);

    tc_init(&watcher);
    register_caps(&watcher, node.port, "watcher", CAP_AWAY_NOTIFY);
    join(&watcher, CHAN);

    tc_init(&blunt);
    register_caps(&blunt, node.port, "blunt", NULL);
    join(&blunt, CHAN);

    /* `stranger` JOINS #U first, so it is the CHANNEL CREATOR there and gets +o --
     * which is what makes the next JOIN succeed, since `setter` is not on #U and
     * would otherwise be refused 437 as a JOIN on a channel nobody owns. */
    tc_init(&stranger);
    register_caps(&stranger, node.port, "stranger", CAP_AWAY_NOTIFY);
    join(&stranger, OTHER);

    /* THE MESSAGE HOLDS A SPACE, so 3.2 REQUIRES the colon and the wire has one --
     * and the cleared line below is the other shape, with NO trailing parameter at
     * all, which is the whole of how the two edges are told apart. Both are
     * accounted for on purpose: a node that always coloned would still be legal and
     * a node that never did would not. */
    (void)snprintf(setline, sizeof setline,
                   ":setter!setter@" OBSERVED_HOST " AWAY " CHAN " :going to lunch\r\n");
    (void)snprintf(clearline, sizeof clearline,
                   ":setter!setter@" OBSERVED_HOST " AWAY " CHAN "\r\n");

    /* EVERY CONNECTION IS DRAINED BEFORE ANY WINDOW IS OPENED, and that is not
     * tidiness. The four clients registered and joined one after another, so each
     * one has the LATER clients' JOIN echoes in its buffer, and a window opened
     * without settling first counts a JOIN as a notification. Settling here means
     * every `lines_since()` below counts lines the AWAY produced -- which is the
     * only thing the count can be a statement about. */
    drain(&setter);
    drain(&watcher);
    drain(&blunt);
    drain(&stranger);

    /* ---- THE FIRST AWAY EDGE: SET ---- */
    m_setter = tc_received(&setter);
    m_watcher = tc_received(&watcher);
    m_blunt = tc_received(&blunt);
    m_stranger = tc_received(&stranger);

    TF_CHECK_MSG(tc_send(&setter, "AWAY :going to lunch") == 0, "the AWAY send failed");
    TF_CHECK_MSG(tc_expect(&setter, " 306 setter :You have been marked as being away\r\n",
                           T_IO_MS) == 0,
                 "the setter's own 306 did not arrive.\n  setter saw: %s",
                 tc_buffer(&setter));

    /* The one member that asked and shares the channel. */
    expect_line_since(&watcher, m_watcher, "the AWAY set notification", setline);

    /* THE SETTER GETS NOTHING BEYOND ITS 306 -- and this is a distinct claim from
     * "the notification is gated", because the setter negotiated the capability. The
     * specification is explicit ("Clients SHOULD NOT be sent AWAY messages to notify
     * them of their own away status") and the two numerics it points at, 305 and 306,
     * are exactly what the setter has already been sent. */
    expect_only_replies(&setter, m_setter, "the setter", 1u);

    /* THE CLIENT THAT DID NOT ASK, IN THE CHANNEL. */
    expect_only_replies(&blunt, m_blunt, "a member that did not negotiate", 0u);
    /* THE CLIENT THAT ASKED, IN ANOTHER CHANNEL. */
    expect_only_replies(&stranger, m_stranger, "a member of another channel", 0u);

    /* ---- AND THE NODE'S OWN VIEW AGREES: `301 RPL_AWAY` carries the text, and it
     * is here while the user IS away. A notification about a state the node does
     * not hold would satisfy the assertions above and this would not.
     *
     * THE COLON BEFORE THE TEXT IS THERE because the value holds a space, which is
     * 3.2's rule for a trailing parameter; it is the same rule as the `AWAY` line's
     * own message two lines earlier, and asserting it in both places is what says
     * one formatter is rendering both. ---- */
    m_watcher = tc_received(&watcher);
    TF_CHECK_MSG(tc_send(&watcher, "WHOIS setter") == 0, "the WHOIS send failed");
    {
        char want[256];

        (void)snprintf(want, sizeof want,
                       ":" SRV " 301 watcher setter :going to lunch\r\n");
        expect_line_since(&watcher, m_watcher, "WHOIS of an away user", want);
    }
    /* 311, 312, 317, 318 plus the 301 is five lines, and counting them closes the
     * next window cleanly rather than leaving a stray 301 in it. */
    expect_only_replies(&watcher, m_watcher, "watcher's WHOIS of an away user", 5u);

    /* ---- THE SECOND AWAY EDGE: CLEARED ---- */
    m_setter = tc_received(&setter);
    m_watcher = tc_received(&watcher);
    m_blunt = tc_received(&blunt);
    m_stranger = tc_received(&stranger);

    TF_CHECK_MSG(tc_send(&setter, "AWAY") == 0, "the clearing AWAY send failed");
    TF_CHECK_MSG(tc_expect(&setter, " 305 setter :You are no longer marked as being away\r\n",
                           T_IO_MS) == 0,
                 "the setter's own 305 did not arrive.\n  setter saw: %s",
                 tc_buffer(&setter));

    /* THE HALF THAT IS USUALLY MISSED, and the assertion is a COUNT and not a
     * search: the parameterless line has to arrive, and exactly one line has to
     * arrive. A node that notified only on the way out would leave `watcher`
     * believing its friend is still at lunch for ever. */
    expect_line_since(&watcher, m_watcher, "the AWAY cleared notification", clearline);
    expect_only_replies(&watcher, m_watcher, "the watcher after clearing", 1u);

    expect_only_replies(&setter, m_setter, "the setter after clearing", 1u);
    expect_only_replies(&blunt, m_blunt, "a non-negotiating member after clearing", 0u);
    expect_only_replies(&stranger, m_stranger, "another channel's member after clearing",
                        0u);

    /* ---- AND THE STATE REALLY IS EMPTY NOW. `301`'s ABSENCE is what says the field
     * was cleared, and a WHOIS with no 301 in it is FOUR lines rather than five --
     * so this is the same probe as above with the count one lower, which is what
     * makes it a claim about the node rather than about the substring. ---- */
    m_watcher = tc_received(&watcher);
    TF_CHECK_MSG(tc_send(&watcher, "WHOIS setter") == 0, "the second WHOIS send failed");
    expect_only_replies(&watcher, m_watcher, "watcher's WHOIS after the clear", 4u);
    TF_CHECK_MSG(strstr(tc_buffer(&watcher) + m_watcher, " 301 ") == NULL,
                 "a 301 RPL_AWAY is still being reported for a user who is no longer "
                 "away. `handle_away()` clears `conn_t::away` before it notifies, so "
                 "the node's own view and the notification below are about the same "
                 "state -- and if this fires, one of them is lying.\n"
                 "  watcher saw: %s", tc_buffer(&watcher) + m_watcher);

    tc_close(&setter);
    tc_close(&watcher);
    tc_close(&blunt);
    tc_close(&stranger);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* NO SHARED CHANNEL, NO NOTIFICATION.
 *
 * A user who is in no channel has no audience, and the two numerics they get are
 * the whole answer. This is the case where the walk over `c->chans` has nothing to
 * iterate, and it is here because a notification to *everybody on the node* would
 * satisfy every case in the file above and fail only this one. */
static void case_no_channel_no_notification(void)
{
    nf_node_t node;
    test_client_t solo;
    test_client_t watcher;
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&solo);
    register_caps(&solo, node.port, "solo", CAP_AWAY_NOTIFY);
    tc_init(&watcher);
    register_caps(&watcher, node.port, "watcher", CAP_AWAY_NOTIFY);
    join(&watcher, CHAN);

    mark = tc_received(&watcher);
    TF_CHECK_MSG(tc_send(&solo, "AWAY :going to lunch") == 0, "the AWAY send failed");
    TF_CHECK_MSG(tc_expect(&solo, " 306 solo :You have been marked as being away\r\n",
                           T_IO_MS) == 0,
                 "the solo user's 306 did not arrive.\n  solo saw: %s",
                 tc_buffer(&solo));
    /* `watcher` negotiated the capability and shares NOTHING with `solo`, so the
     * only thing this can be is an audience computed somewhere other than the
     * channel roster. */
    expect_only_replies(&watcher, mark, "a user in no shared channel", 0u);

    /* AND THE NODE SAYS WHY, so an operator reading the log can tell "nobody to tell"
     * from "told nobody". */
    TF_CHECK_MSG(strstr(node.out, "away_notify: nick=solo recipients=0 "
                     "reason=NO_SHARED_CHANNEL") != NULL,
                 "the node did not report that the away notification had no "
                 "audience. `notify_away()` prints that line for the nchans == 0 "
                 "case, and an operator debugging a silent notification needs it.\n"
                 "  node output:\n%s", node.out);

    tc_close(&solo);
    tc_close(&watcher);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* TWO CHANNELS, AND THE MEMBER OF THE OTHER ONE.
 *
 * A user in two channels has an audience in each, and a member of only one of them
 * hears about the change once -- not once per channel they are not in, and not
 * zero times because the walk found a channel they were not a member of. */
static void case_two_channels(void)
{
    nf_node_t node;
    test_client_t setter;
    test_client_t watcher;
    char line[256];
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&watcher);
    register_caps(&watcher, node.port, "watcher", CAP_AWAY_NOTIFY);
    join(&watcher, CHAN);

    tc_init(&setter);
    register_caps(&setter, node.port, "setter", CAP_AWAY_NOTIFY);
    join(&setter, CHAN);
    /* A second channel, created by `watcher` so the JOIN below is not 437. */
    {
        test_client_t maker;

        tc_init(&maker);
        register_caps(&maker, node.port, "maker", NULL);
        join(&maker, OTHER);
        tc_close(&maker);
    }
    join(&setter, OTHER);

    /* Settled for the same reason as the first case: `setter`'s JOIN of %s reaches
     * `watcher`, and a window opened without settling would count it. */
    drain(&setter);
    drain(&watcher);

    mark = tc_received(&watcher);
    TF_CHECK_MSG(tc_send(&setter, "AWAY :back soon") == 0, "the AWAY send failed");
    TF_CHECK_MSG(tc_expect(&setter, " 306 setter :You have been marked as being away\r\n",
                           T_IO_MS) == 0,
                 "the setter's 306 did not arrive.\n  setter saw: %s",
                 tc_buffer(&setter));
    (void)snprintf(line, sizeof line,
                   ":setter!setter@" OBSERVED_HOST " AWAY " CHAN " :back soon\r\n");
    expect_line_since(&watcher, mark, "the notification in the shared channel", line);
    /* EXACTLY ONE, and it names #T. `watcher` is not on #U, so a node that walked
     * every channel the SETTER is in and wrote to all of its members would produce
     * a second line naming #U -- and a node that notified per node rather than per
     * channel would produce this one twice. */
    expect_only_replies(&watcher, mark, "the watcher in one of two channels", 1u);
    TF_CHECK_MSG(strstr(tc_buffer(&watcher) + mark, OTHER) == NULL,
                 "a notification naming %s reached a client that is not on it. The "
                 "fan-out writes to the ROSTER of the channel being notified, so a "
                 "member of another channel cannot be reached.\n  watcher saw: %s",
                 OTHER, tc_buffer(&watcher) + mark);

    tc_close(&setter);
    tc_close(&watcher);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* AN OVER-LONG AWAY CHANGES NOTHING AND NOTIFIES NOBODY.
 *
 * The refusal has to come BEFORE the field is written and before the notification,
 * or a member is told about a state change that did not happen -- and the
 * notification is the half that is new. `fanout_line_fits()` is not involved (that
 * is PRIVMSG's own cap) and this is the bound 005 advertises as `AWAYLEN`. */
static void case_refused_notifies_nobody(void)
{
    nf_node_t node;
    test_client_t setter;
    test_client_t watcher;
    char over[300];
    char line[512];
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    memset(over, 'a', sizeof over - 1u);
    over[sizeof over - 1u] = '\0';

    tc_init(&setter);
    register_caps(&setter, node.port, "setter", CAP_AWAY_NOTIFY);
    join(&setter, CHAN);
    tc_init(&watcher);
    register_caps(&watcher, node.port, "watcher", CAP_AWAY_NOTIFY);
    join(&watcher, CHAN);

    mark = tc_received(&watcher);
    (void)snprintf(line, sizeof line, "AWAY :%s", over);
    TF_CHECK_MSG(tc_send(&setter, line) == 0, "the over-long AWAY failed to send");
    TF_CHECK_MSG(tc_expect(&setter, " 417 setter :Away message is too long\r\n",
                           T_IO_MS) == 0,
                 "an over-long away message was not refused with 417.\n"
                 "  setter saw: %s", tc_buffer(&setter));
    /* AND NOBODY WAS TOLD, which is the claim this capability adds: a refusal that
     * notified first and answered second would have told every member the user is
     * away with a message nobody accepted. */
    expect_only_replies(&watcher, mark, "a refused AWAY", 0u);

    tc_close(&setter);
    tc_close(&watcher);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * TEETH, AND WHERE THEY WERE INJECTED
 * ---------------------------------------------------------------------------
 * Each was watched go red with the behaviour broken, and the BUILD was checked
 * before the run was believed -- an uncompilable fault leaves the previous binary in
 * place and reports a pass, which has happened in this repo seven times.
 *
 *   away CLEARED NOT NOTIFYING -- msg_verbs.c, handle_away(): the
 *       `notify_away(s, c, NULL)` call removed from the bare-AWAY branch, leaving
 *       the set edge alone. Fails case_set_and_cleared() on the cleared
 *       notification and NOTHING ELSE -- which is the whole argument for the second
 *       edge being in the same case as the first. A test file with only the SET
 *       case would have gone green on it, and a node would have left every member
 *       believing their friend was still at lunch for ever.
 *
 *   the GATE IGNORED -- cap.c: `cap_gate_away_notify()` made to return 1
 *       unconditionally. Fails the `blunt` line counts on BOTH edges and nothing
 *       else, because `blunt` differs from `watcher` in nothing but the
 *       negotiation. This is the fault that turns an unsolicited notification into
 *       an unsolicited line for everybody.
 *
 *   the SETTER NOT EXCLUDED -- msg_verbs.c, notify_away(): `c` replaced by NULL in
 *       the `fanout_deliver_local_gated()` call. Fails the setter's line count, and
 *       only that: the setter negotiated the capability, so the GATE would have let
 *       it through and the only thing keeping it out is `exclude`. It is the fault
 *       that proves the two are different questions -- "did this destination ask?"
 *       and "is this the author?" -- rather than one gate doing both.
 *
 *   the AUDIENCE WIDENED -- msg_verbs.c, notify_away(): `c->chans[i]` replaced by
 *       every channel the node holds. Fails case_two_channels() (a line naming %U
 *       reaches a client not on it, and the shared channel's notification arrives
 *       twice) and case_no_channel_no_notification() (a user in no channel notifies
 *       the whole node). It is invisible in case_set_and_cleared(), which is why
 *       that case is not the only one.
 */
int main(void)
{
    case_advertised();
    case_set_and_cleared();
    case_no_channel_no_notification();
    case_two_channels();
    case_refused_notifies_nobody();

    tf_done("away-notify");
    return 0;
}
