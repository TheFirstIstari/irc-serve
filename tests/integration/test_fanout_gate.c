/* test_fanout_gate.c -- the THIRD outcome: a destination that is sent NOTHING.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS BEING CLAIMED, AND WHY IT IS ASSERTED AGAINST THE API
 * ---------------------------------------------------------------------------
 * `fanout.c`'s per-destination decision had two answers and this pass gave it a
 * third. For one emission to one resolved channel, a destination may receive:
 *
 *   1. the PLAIN shape            -- what every caller has always meant
 *   2. the ALTERNATE shape        -- what `extended-join` asks for, decided by
 *                                    `fanout_form_for()` on the recipient's own
 *                                    negotiation
 *   3. NOTHING                    -- the new outcome, decided by the caller's
 *                                    `gate` predicate
 *
 * All three must be decidable for the SAME emission, which is the property the
 * third outcome exists to provide: `setname`, `chghost` and `away-notify` all
 * publish to a SUBSET of a channel's members, and all three also publish one
 * line. A contract that could only say "one shape for all" or "the other shape
 * for some" would make each of them reimplement the member walk.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE DRIVES fanout_deliver_local_gated() DIRECTLY
 * ---------------------------------------------------------------------------
 * Nothing on the wire produces a gated emission until `away-notify` (Phase 10.8b)
 * lands, and that is not a reason to leave the contract untested until a later
 * pass does: this is the argument test_nick_index.c makes -- "nothing on the wire
 * produces that state" is a fact about the CALLERS, not a reason the API goes
 * untested. (Phase 10.8b then adds the wire-level case, so this file is not the
 * last word on it; it is the first.)
 *
 * WHAT IS STILL ASSERTED IS WIRE. `conn_write_pending()` is the count of bytes
 * this node has queued for that descriptor, which is the same buffer the loop
 * pumps, and every assertion below is the exact CRLF-terminated line a client on
 * that socket would read. No fixed sleep, no scheduling assumption, no dependence
 * on another test, and independent under `ctest -j`.
 *
 * ---------------------------------------------------------------------------
 * WHY ONE in-process SERVER AND NOT THREE SOCKETS
 * ---------------------------------------------------------------------------
 * The point of the third outcome is that THREE different negotiations coexist in
 * ONE channel at the SAME time, so the test has to hold them still long enough to
 * compare. Over real TCP that is a read-scheduling problem and half the assertions
 * would be about when a line arrived. Here the three members are three
 * socketpair-backed conn_t's in one process and the whole emission is one call,
 * so "the member who receives nothing" is `0 bytes queued` rather than "nothing
 * arrived within a deadline" -- which is the difference between a claim about the
 * node and a claim about a test runner.
 *
 * THE THREE MEMBERS DIFFER ONLY IN NEGOTIATION:
 *
 *   blunt    no CAP exchange at all                            -> PLAIN shape
 *   fancy    CAP REQ :extended-join                            -> ALTERNATE shape
 *   muted    CAP REQ :extended-join, and the gate refuses it   -> NOTHING
 *
 * `muted` negotiates the SAME capability as `fancy`, and that is the half that
 * makes the test able to fail: a gate keyed on anything but the gate -- a channel
 * position, a member index, "the third one" -- could tell `muted` from `fancy`,
 * and this file has to be able to say that a node which distinguished them by
 * anything except the predicate is wrong.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/cap.h"
#include "core/channel.h"
#include "core/commands.h"
#include "core/connection.h"
#include "core/fanout.h"
#include "core/message.h"
#include "core/server.h"
#include "harness/test_util.h"

/* ---------------------------------------------------------------------------
 * The rig
 * ---------------------------------------------------------------------------
 */

/* One member: the conn, and the two ends of its socketpair.
 *
 * `pair[0]` is the conn's descriptor and `pair[1]` is the peer end that nothing
 * ever reads -- the bytes under test stay in the conn's write queue, which is what
 * server_queue() fills and what a poll iteration would drain. The peer end is
 * still closed explicitly: a socketpair with one end closed is a descriptor this
 * process still owns, and the teardown arm below has to close it for the same
 * reason it closes the rest. */
typedef struct {
    conn_t *c;
    int     pair[2];
} member_t;

static server_t g_server;

static void member_open(member_t *m, const char *nick, const char *caps)
{
    char line[128];
    message_t msg;

    TF_CHECK_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, m->pair) == 0,
                 "socketpair failed for %s", nick);
    /* Nonblocking, because the loop guarantees every registered descriptor is and
     * conn_pump() is written on that promise. Nothing here pumps, but the rig
     * matches the invariant rather than relying on nothing noticing. */
    for (int i = 0; i < 2; i++) {
        int flags = fcntl(m->pair[i], F_GETFL, 0);

        TF_CHECK(flags >= 0);
        TF_CHECK_MSG(fcntl(m->pair[i], F_SETFL, flags | O_NONBLOCK) == 0,
                     "could not make %s's descriptor nonblocking", nick);
    }
    m->c = conn_new(m->pair[0], CONN_CLIENT);
    TF_CHECK(m->c != NULL);
    if (m->c == NULL) {
        return;
    }
    /* Registered, so that server_shutdown() owns it: the teardown arm at the foot
     * of each case closes every descriptor and frees every conn_t through the
     * node's own exit path, which is the only claim about leaks this file makes
     * and the only one LeakSanitizer would be able to check on Linux. */
    TF_CHECK_MSG(server_add_conn(&g_server, m->c) == 0,
                 "could not register %s, so nothing below would be owned by the "
                 "node's teardown", nick);
    TF_CHECK_MSG(server_nick_claim(&g_server, nick, m->c) == 0,
                 "could not claim the nickname %s", nick);
    /* A hostmask has to RENDER for the prefix below, and accept() is what fills
     * these on a real connection. Written here so the expected lines are the ones
     * a client would actually be shown. */
    memcpy(m->c->nick, nick, strlen(nick) + 1u);
    memcpy(m->c->user, nick, strlen(nick) + 1u);
    memcpy(m->c->host, "10.0.0.9", sizeof "10.0.0.9");

    /* NEGOTIATION THROUGH THE REAL PATH. `CAP REQ` is dispatched through
     * commands_dispatch() rather than by writing `c->caps` directly, because a
     * test that sets the bit itself asserts nothing about whether the capability
     * is the one the gate reads: a renamed constant and a hand-set bit disagree
     * silently, which is the drift cap.c's table exists to prevent.
     *
     * `CAP` is `pre_reg`, so this works on a connection that has not registered,
     * which is also what makes the dispatch reach cap_handle() at all --
     * commands_dispatch() answers 451 for anything else first. */
    if (caps == NULL) {
        return;
    }
    (void)snprintf(line, sizeof line, "CAP REQ :%s", caps);
    TF_CHECK_MSG(message_parse(line, &msg) == 0,
                 "%s: the CAP REQ this test writes does not parse", nick);
    commands_dispatch(&g_server, m->c, &msg);
    message_free(&msg);
    TF_CHECK_MSG(cap_enabled(m->c, caps) != 0,
                 "%s was not granted %s, so every case below would be asserting "
                 "the wrong shape for it", nick, caps);
    /* The CAP REQ and its ACK are themselves queued bytes. Draining them here
     * means the marks below start at zero and a failure prints only the emission
     * under test rather than a negotiation that is already known good. */
    TF_CHECK_MSG(conn_pump(m->c) == 0,
                 "could not drain %s's negotiation bytes", nick);
    TF_CHECK_MSG(conn_write_pending(m->c) == 0u,
                 "%s still has %zu queued bytes after its negotiation drained",
                 nick, conn_write_pending(m->c));
}

/* The peer ends, closed after server_shutdown() has closed and freed the
 * registered ones. The order is not a detail: server_shutdown() frees the
 * conn_t, so `m->c` is dangling afterwards and nothing may touch it. */
static void member_close_peer(member_t *m)
{
    if (m->pair[1] >= 0) {
        (void)close(m->pair[1]);
        m->pair[1] = -1;
    }
}

/* The queued bytes for `m` from `from` onwards, as a NUL-terminated copy.
 *
 * COPIED rather than pointed at because the assertions compare whole lines and
 * the buffer is NUL-terminated at its very end, so a pointer into it would let a
 * needle match across two lines and turn "the right line" into "the right bytes
 * somewhere". */
static void queued(const member_t *m, size_t from, char *out, size_t cap)
{
    const size_t have = conn_write_pending(m->c);
    size_t n = 0;

    TF_CHECK_MSG(out != NULL && cap > 0u, "queued() called with nowhere to write");
    if (out == NULL || cap == 0u) {
        return;
    }
    out[0] = '\0';
    for (size_t i = from; i < have && n + 1u < cap; i++) {
        out[n++] = m->c->wbuf[m->c->woff + i];
    }
    out[n] = '\0';
}

/* Assert that `m` received EXACTLY `want` (CRLF included) after `from`, and that
 * `from` was where the emission started. Comparing the whole queue rather than
 * searching for a needle is what makes "received nothing" and "received exactly
 * this" the same kind of assertion. */
static void expect_exactly(const member_t *m, size_t from, const char *what,
                           const char *want)
{
    char buf[1024];

    queued(m, from, buf, sizeof buf);
    TF_CHECK_MSG(strcmp(buf, want) == 0,
                 "%s did not get exactly the line it should have.\n"
                 "  expected: %s\n  got:      %s", what, want, buf);
}

/* Create `#T` owned by this node, with `n` members, through the two calls
 * handle_join() uses to create a channel: chan_new() with this node's name and
 * epoch, then server_chan_attach(). server_chan_add() alone is not enough -- it
 * registers a key with a NULL value, which is Phase 2's probe shape, so
 * server_chan_get() would hand back NULL and fanout_resolve() would answer 403. */
static chan_t *make_channel(server_t *s, const char *name)
{
    chan_t *ch = chan_new(name, s->name, s->epoch);

    TF_CHECK_MSG(ch != NULL, "chan_new(%s) failed", name);
    if (ch == NULL) {
        return NULL;
    }
    TF_CHECK_MSG(server_chan_attach(s, ch) == 0, "could not attach %s", name);
    return ch;
}

/* ---------------------------------------------------------------------------
 * The gate, and what it is allowed to see
 * ---------------------------------------------------------------------------
 */

/* What the gate is asked about, and how often. The counts are the point of this
 * struct: a gate asked twice for one destination, or asked about a destination
 * the caller had already excluded, is not the gate fanout.c documents -- and
 * neither shows up in the bytes. */
typedef struct {
    const conn_t *refuse;  /* the ONE destination that gets nothing */
    unsigned      asked;
    unsigned      refused;
    int           ctx_seen;
} gate_ctx_t;

static int gate(const conn_t *dst, void *ctx)
{
    gate_ctx_t *g = (gate_ctx_t *)ctx;

    TF_CHECK_MSG(g != NULL, "the gate was asked with a NULL context");
    if (g == NULL) {
        return 1;
    }
    g->asked++;
    g->ctx_seen = (g == ctx) ? 1 : 0;
    if (g->refuse != NULL && dst == g->refuse) {
        g->refused++;
        return 0;
    }
    return 1;
}

/* ---------------------------------------------------------------------------
 * THE CASES
 * ---------------------------------------------------------------------------
 */

/* One emission, three destinations, three outcomes, and the count that says how
 * many deliveries happened. */
static void case_three_outcomes(void)
{
    member_t blunt;
    member_t fancy;
    member_t muted;
    chan_t *ch;
    fanout_target_t t;
    fanout_form_t plain;
    fanout_form_t ext;
    const char *ext_params[2];
    gate_ctx_t g;
    const char *prefix = "muted!muted@10.0.0.9";
    char line[160];
    int delivered;

    TF_CHECK_MSG(server_init(&g_server, "irc.test") == 0, "server_init failed");

    member_open(&blunt, "blunt", NULL);
    member_open(&fancy, "fancy", CAP_EXTENDED_JOIN);
    member_open(&muted, "muted", CAP_EXTENDED_JOIN);

    ch = make_channel(&g_server, "#T");
    TF_CHECK_MSG(ch != NULL, "#T could not be created");
    if (ch == NULL) {
        return;
    }
    TF_CHECK_MSG(chan_add_member(ch, blunt.c, 0u) == 0, "blunt did not join");
    TF_CHECK_MSG(chan_add_member(ch, fancy.c, 0u) == 0, "fancy did not join");
    TF_CHECK_MSG(chan_add_member(ch, muted.c, 0u) == 0, "muted did not join");
    /* Resolved through the ONLY function that answers "is this a channel or a
     * nick", and through the canonicalising path (`#t`, lower case) so that the
     * target under test is the resolved one rather than a literal. A gate that
     * could not see a member walking `members[]` would be a gate tested against
     * an array the production path never walks. */
    TF_CHECK_MSG(fanout_resolve(&g_server, blunt.c, "#t", FANOUT_STATE_CHANGE, &t) != 0,
                 "resolving #t failed, so nothing below is about the gate");
    TF_CHECK_MSG(t.kind == FANOUT_LOCAL_CHANNEL,
                 "#t resolved to kind %d rather than a local channel", (int)t.kind);

    /* THE TWO SHAPES. The plain one carries no parameters at all -- the extended
     * JOIN is the emission whose two shapes this file rides on, and the extended
     * list is the account token and the realname, which is exactly what
     * `extended-join` puts on a JOIN. */
    ext_params[0] = "*";
    ext_params[1] = "Real Name";
    plain.params = NULL;
    plain.nparams = 0;
    ext.params = ext_params;
    ext.nparams = 2;

    memset(&g, 0, sizeof g);
    g.refuse = muted.c;

    /* Every queue is empty here, because member_open() drained the negotiation.
     * The marks are therefore all zero, and "received nothing" is readable as a
     * length rather than as a difference -- which is the assertion that survives
     * a fault that appends a line this test did not predict. */
    TF_CHECK_MSG(conn_write_pending(blunt.c) == 0u &&
                 conn_write_pending(fancy.c) == 0u &&
                 conn_write_pending(muted.c) == 0u,
                 "a member had %zu/%zu/%zu queued bytes before the emission",
                 conn_write_pending(blunt.c), conn_write_pending(fancy.c),
                 conn_write_pending(muted.c));

    delivered = fanout_deliver_local_gated(&g_server, &t, prefix, "JOIN", &plain, &ext,
                                           gate, &g, NULL);

    /* ---- THE COUNT ---- */
    /* Two deliveries, not three. The gate makes `muted` not a destination, so a
     * count of three is the symptom of a gate that was not consulted, and this
     * assertion is independent of the byte assertions because a node that
     * delivered to all three and counted two would be a different bug again. */
    TF_CHECK_MSG(delivered == 2,
                 "the gated emission reported %d deliveries, expected 2: `muted` was "
                 "refused by the gate and must not be counted",
                 delivered);

    /* ---- 1. THE PLAIN SHAPE ---- */
    (void)snprintf(line, sizeof line, ":%s JOIN #T\r\n", prefix);
    expect_exactly(&blunt, 0u, "the member that negotiated nothing",
                   line);

    /* ---- 2. THE ALTERNATE SHAPE ---- */
    /* Two shapes for ONE emission is the whole claim, and a member that got the
     * plain one would be a node that negotiated the extension and then declined
     * it. */
    (void)snprintf(line, sizeof line, ":%s JOIN #T * :Real Name\r\n", prefix);
    expect_exactly(&fancy, 0u, "the member that negotiated extended-join", line);

    /* ---- 3. NOTHING, PROVABLY ---- */
    /* `0 bytes queued` and not "the line is absent from the buffer": the second
     * is satisfied by a line that arrived somewhere else in the stream. This is
     * the assertion that fails if the gate is ignored, and it is the reason the
     * rig reads a length rather than searching for a needle -- an unsolicited
     * notification is an ASSERTION about a user's away state or realname, so a
     * member that did not ask must receive no line at all, not a line that means
     * nothing. */
    TF_CHECK_MSG(conn_write_pending(muted.c) == 0u,
                 "the member the gate refused received %zu bytes",
                 conn_write_pending(muted.c));

    /* ---- THE GATE WAS ASKED, ONCE PER DESTINATION, WITH ITS CONTEXT ---- */
    TF_CHECK_MSG(g.asked == 3u,
                 "the gate was asked %u times for 3 live, non-excluded members; it "
                 "is asked once per destination and no more", g.asked);
    TF_CHECK_MSG(g.refused == 1u,
                 "the gate refused %u times; it refuses exactly the one destination "
                 "it was pointed at", g.refused);
    TF_CHECK_MSG(g.ctx_seen != 0,
                 "the gate did not receive its context, so a caller that had to "
                 "pass something about the emission could not have done it");

    /* ---- THE TEARDOWN ARM ---- */
    /* One close per registered descriptor and the peer ends by hand, so a
     * sanitized run has nothing to report and the claim "every conn this case
     * made was freed by the node's own exit path" is checkable here rather than
     * assumed. */
    server_shutdown(&g_server);
    TF_CHECK_MSG(g_server.nconns == 0u,
                 "the node still holds %zu connections after shutdown", g_server.nconns);
    TF_CHECK_MSG(g_server.by_fd == NULL, "the descriptor registry survived shutdown");
    member_close_peer(&blunt);
    member_close_peer(&fancy);
    member_close_peer(&muted);
}

/* THE GATE IS NOT A NEW MECHANISM FOR "ONE SHAPE FOR EVERYBODY".
 *
 * fanout_deliver_local_forms() is the NULL-gate case and must be exactly what it
 * was: the two shapes, decided per destination, with everybody addressed. If the
 * gate's introduction had changed that, every existing emission -- the rename
 * echo, the extended JOIN -- would have silently changed audience, and no wire
 * test would notice because the audience is the same size. */
static void case_null_gate_is_the_old_behaviour(void)
{
    member_t blunt;
    member_t fancy;
    member_t muted;
    chan_t *ch;
    fanout_target_t t;
    fanout_form_t plain;
    fanout_form_t ext;
    const char *ext_params[2];
    const char *prefix = "blunt!blunt@10.0.0.9";
    char line[160];
    int delivered;

    TF_CHECK_MSG(server_init(&g_server, "irc.test") == 0, "server_init failed");

    member_open(&blunt, "blunt", NULL);
    member_open(&fancy, "fancy", CAP_EXTENDED_JOIN);
    member_open(&muted, "muted", CAP_EXTENDED_JOIN);

    ch = make_channel(&g_server, "#T");
    TF_CHECK_MSG(ch != NULL, "#T could not be created");
    if (ch == NULL) {
        return;
    }
    TF_CHECK_MSG(chan_add_member(ch, blunt.c, 0u) == 0, "blunt did not join");
    TF_CHECK_MSG(chan_add_member(ch, fancy.c, 0u) == 0, "fancy did not join");
    TF_CHECK_MSG(chan_add_member(ch, muted.c, 0u) == 0, "muted did not join");
    TF_CHECK_MSG(fanout_resolve(&g_server, blunt.c, "#t", FANOUT_STATE_CHANGE, &t) != 0,
                 "resolving #t failed");

    ext_params[0] = "*";
    ext_params[1] = "Real Name";
    plain.params = NULL;
    plain.nparams = 0;
    ext.params = ext_params;
    ext.nparams = 2;

    /* THE NO-GATE ENTRY POINT, not the gated one with a NULL predicate: both are
     * supposed to be the same thing, and this asserts the wrapper is the thin
     * thing it claims to be by using it. */
    delivered = fanout_deliver_local_forms(&g_server, &t, prefix, "JOIN", &plain, &ext,
                                           NULL);

    TF_CHECK_MSG(delivered == 3,
                 "without a gate every live member is a destination, so this "
                 "reported %d deliveries for 3 members", delivered);

    (void)snprintf(line, sizeof line, ":%s JOIN #T\r\n", prefix);
    expect_exactly(&blunt, 0u, "the plain member, without a gate", line);

    /* `muted` negotiated extended-join, so it is owed the extended shape and
     * nothing may have decided otherwise. A gate that DEFAULTED to refusing would
     * pass the previous case and fail here, which is why this one exists. */
    (void)snprintf(line, sizeof line, ":%s JOIN #T * :Real Name\r\n", prefix);
    expect_exactly(&muted, 0u, "an extended-join member, without a gate", line);

    server_shutdown(&g_server);
    member_close_peer(&blunt);
    member_close_peer(&fancy);
    member_close_peer(&muted);
}

/* THE GATE IS ABOUT DESTINATIONS, AND BOTH KINDS ARE COVERED.
 *
 * The `FANOUT_LOCAL_USER` row writes to one connection, and a gate honoured only
 * by the channel walk would leave a direct delivery ungated -- which for a
 * notification is the difference between "unsolicited, to the clients that asked"
 * and "unsolicited, to everyone". The row needs its own assertions because
 * nothing else in this file reaches it. */
static void case_user_target(void)
{
    member_t blunt;
    member_t fancy;
    fanout_target_t t;
    fanout_form_t plain;
    const char *text[1];
    gate_ctx_t g;
    const char *prefix = "blunt!blunt@10.0.0.9";
    char line[160];
    int delivered;

    TF_CHECK_MSG(server_init(&g_server, "irc.test") == 0, "server_init failed");

    member_open(&blunt, "blunt", NULL);
    member_open(&fancy, "fancy", NULL);

    /* A USER TARGET, resolved through the only function that answers "is this a
     * channel or a nick" -- the point being that the gate does not care which it
     * is, so the test should not have to arrange a special case to prove it.
     *
     * The target is `blunt`, who is also the SENDER, because that is the only
     * case in which `exclude` has anything to do: addressing yourself is RFC 2812
     * 3.3.2's no-echo case, and the two refusals below are about the gate and
     * about `exclude` respectively, so they need two different destinations. */
    TF_CHECK_MSG(fanout_resolve(&g_server, blunt.c, "blunt", FANOUT_MESSAGE, &t) != 0,
                 "resolving `blunt` as a user target failed");
    TF_CHECK_MSG(t.kind == FANOUT_LOCAL_USER,
                 "`blunt` resolved to kind %d rather than a local user", (int)t.kind);

    text[0] = "hello";
    plain.params = text;
    plain.nparams = 1;

    memset(&g, 0, sizeof g);
    g.refuse = blunt.c;

    /* FIRST: `exclude` alone, with the gate pointed at the SAME destination. Zero
     * deliveries, and the gate must not even be consulted: addressing the excluded
     * sender is RFC 2812 3.3.2's no-echo rule, and a gate asked about a
     * destination the caller had already removed is the expensive one -- the
     * questions are not the same and the cheaper one runs first. */
    delivered = fanout_deliver_local_gated(&g_server, &t, prefix, "PRIVMSG", &plain,
                                           NULL, gate, &g, blunt.c);
    TF_CHECK_MSG(delivered == 0,
                 "addressing the excluded sender itself reported %d deliveries",
                 delivered);
    TF_CHECK_MSG(g.asked == 0u,
                 "the gate was asked %u times for a destination `exclude` had "
                 "already removed", g.asked);

    /* THEN: the gate as the only thing in the way, which is the case the row
     * needs. */
    delivered = fanout_deliver_local_gated(&g_server, &t, prefix, "PRIVMSG", &plain,
                                           NULL, gate, &g, NULL);
    TF_CHECK_MSG(delivered == 0,
                 "a direct delivery to a user target the gate refused reported %d "
                 "deliveries", delivered);
    TF_CHECK_MSG(g.asked == 1u,
                 "the gate was asked %u times for one user destination", g.asked);
    TF_CHECK_MSG(conn_write_pending(blunt.c) == 0u,
                 "the user the gate refused received %zu bytes",
                 conn_write_pending(blunt.c));

    /* AND with a gate that permits, the same call delivers -- so the two
     * assertions above are about the gate and not about the row refusing to write
     * to a user at all. Without this the case would also pass if the row dropped
     * every direct delivery. */
    g.refuse = NULL;
    g.asked = 0u;
    delivered = fanout_deliver_local_gated(&g_server, &t, prefix, "PRIVMSG", &plain,
                                           NULL, gate, &g, NULL);
    TF_CHECK_MSG(delivered == 1,
                 "a direct delivery with a gate that permits reported %d deliveries",
                 delivered);
    /* NO LEADING COLON BEFORE `hello`, and that is not a slip in the expectation
     * -- it is the other half of a property worth asserting. 3.2 colons a
     * trailing parameter only when the value needs it, so a one-word text with no
     * separator and no leading colon renders bare. A node that coloned
     * unconditionally would still be legal; a node that never did would not. The
     * point is that this file's two expectations have DIFFERENT shapes and both
     * are right, which is the same observation test_setname.c makes about its own
     * 255-byte case. */
    (void)snprintf(line, sizeof line, ":%s PRIVMSG blunt hello\r\n", prefix);
    expect_exactly(&blunt, 0u, "the permitted user target", line);

    /* AND the other connection was never a destination, in any of the three
     * calls: a direct delivery writes to exactly one connection, and a row that
     * walked the roster instead would have written to `fancy` too. */
    TF_CHECK_MSG(conn_write_pending(fancy.c) == 0u,
                 "a direct delivery to `blunt` wrote %zu bytes to `fancy`, which is "
                 "not a destination of one",
                 conn_write_pending(fancy.c));

    server_shutdown(&g_server);
    member_close_peer(&blunt);
    member_close_peer(&fancy);
}

/* `exclude` AND THE GATE ARE TWO DIFFERENT QUESTIONS, AND THE CHEAPER ONE RUNS
 * FIRST.
 *
 * Both remove a destination and both leave the bytes of the others untouched, so
 * a test that only checked the lines could not tell them apart -- and a node that
 * asked the gate about a member it had already excluded would be doing a
 * capability question about an emission that member was never going to receive.
 * The only observable is HOW MANY TIMES the gate was asked, which is why this case
 * exists and why it is here rather than folded into the three-outcome one. */
static void case_exclude_is_not_the_gate(void)
{
    member_t gone;
    member_t kept;
    chan_t *ch;
    fanout_target_t t;
    fanout_form_t plain;
    gate_ctx_t g;
    const char *prefix = "kept!kept@10.0.0.9";
    char line[160];
    int delivered;

    TF_CHECK_MSG(server_init(&g_server, "irc.test") == 0, "server_init failed");

    member_open(&gone, "gone", CAP_EXTENDED_JOIN);
    member_open(&kept, "kept", CAP_EXTENDED_JOIN);

    ch = make_channel(&g_server, "#T");
    TF_CHECK_MSG(ch != NULL, "#T could not be created");
    if (ch == NULL) {
        return;
    }
    TF_CHECK_MSG(chan_add_member(ch, gone.c, 0u) == 0, "gone did not join");
    TF_CHECK_MSG(chan_add_member(ch, kept.c, 0u) == 0, "kept did not join");
    TF_CHECK_MSG(fanout_resolve(&g_server, kept.c, "#t", FANOUT_STATE_CHANGE, &t) != 0,
                 "resolving #t failed");

    /* NO PARAMETERS AT ALL, so both members would receive byte-identical lines and
     * the only thing distinguishing the two destinations is which question
     * removed each of them. */
    plain.params = NULL;
    plain.nparams = 0;

    memset(&g, 0, sizeof g);
    g.refuse = kept.c;

    /* `gone` is excluded AND would have been refused; `kept` is only refused. */
    delivered = fanout_deliver_local_gated(&g_server, &t, prefix, "PART", &plain, NULL,
                                           gate, &g, gone.c);
    TF_CHECK_MSG(delivered == 0,
                 "both destinations were removed, yet %d deliveries were reported",
                 delivered);
    TF_CHECK_MSG(g.asked == 1u,
                 "the gate was asked %u times for ONE member that was not excluded. "
                 "The liveness, `exclude` and gate tests are three different "
                 "questions and they run cheapest-first; asking the gate about a "
                 "member the caller had already excluded is work about an emission "
                 "that member was never going to receive.", g.asked);
    TF_CHECK_MSG(g.refused == 1u,
                 "the gate refused %u times; it refuses `kept` and nothing else",
                 g.refused);
    TF_CHECK_MSG(conn_write_pending(gone.c) == 0u &&
                 conn_write_pending(kept.c) == 0u,
                 "a member received bytes: gone=%zu kept=%zu",
                 conn_write_pending(gone.c), conn_write_pending(kept.c));

    /* AND `kept` WAS ADDRESSABLE: with no gate and no exclusion it receives the
     * line. Without this the case would also pass if `kept` had been removed for
     * some other reason, and "the gate was asked once" would be satisfied by a
     * walk that asked it about nobody and then stopped. */
    memset(&g, 0, sizeof g);
    delivered = fanout_deliver_local_forms(&g_server, &t, prefix, "PART", &plain, NULL,
                                           gone.c);
    TF_CHECK_MSG(delivered == 1,
                 "excluding `gone` and gating nothing delivered %d lines to one "
                 "remaining member", delivered);
    (void)snprintf(line, sizeof line, ":%s PART #T\r\n", prefix);
    expect_exactly(&kept, 0u, "the one member neither excluded nor refused", line);

    server_shutdown(&g_server);
    member_close_peer(&gone);
    member_close_peer(&kept);
}

/* ---------------------------------------------------------------------------
 * TEETH, AND WHERE THEY WERE INJECTED
 * ---------------------------------------------------------------------------
 * Each was watched go red with the behaviour broken, and the BUILD was checked
 * before the run was believed -- an uncompilable fault leaves the previous binary
 * in place and reports a pass, which has happened in this repo seven times. (The
 * first version of the first fault below was exactly that: deleting the gate test
 * outright leaves `gate` and `gate_ctx` unused, which -Weverything turns into a
 * hard error, so the fault was written with the `(void)` casts that keep it
 * compiling and still never consult the predicate.)
 *
 *   the gate's predicate NEVER CONSULTED -- fanout.c, write_to_members(): the
 *       test replaced by `(void)gate; (void)gate_ctx;`. Red on the delivery
 *       COUNT first (3 rather than 2), because that is the assertion ordered
 *       before the bytes. It also makes `muted`'s zero-bytes assertion and the
 *       asked/refused counts unreachable, so this single fault is what those
 *       three are for.
 *
 *   the gate's predicate INVERTED -- fanout.c, write_to_members(): `== 0`
 *       becomes `!= 0`. Then everybody but `muted` is refused and `muted` is
 *       addressed, so the count is 1 and `muted`'s zero-bytes assertion is
 *       UNREACHABLE. That is the argument for asserting all three outcomes
 *       separately rather than only "the refused member got nothing": a test
 *       with just that assertion would have gone green on this.
 *
 *   the gate asked for an EXCLUDED destination -- fanout.c,
 *       write_to_members(): the gate test MOVED above the `exclude` test. The
 *       bytes are byte-identical, so this is invisible on the wire and the ONLY
 *       thing that can see it is an asked-count -- and case_three_outcomes()'
 *       cannot, because nothing there is excluded. That case went green the
 *       first time this fault was injected, which is why
 *       case_exclude_is_not_the_gate() exists.
 *
 *   the gate NOT asked for a user target -- fanout.c,
 *       fanout_deliver_local_gated()'s FANOUT_LOCAL_USER arm: the test removed.
 *       Fails only case_user_target(), which is the case that exists for it.
 */
int main(void)
{
    case_three_outcomes();
    case_null_gate_is_the_old_behaviour();
    case_exclude_is_not_the_gate();
    case_user_target();

    tf_done("fanout gate");
    return 0;
}
