/* test_messaging.c -- PRIVMSG and NOTICE on the wire, against the real binary.
 *
 * docs/SERVER_DESIGN.md 7/Phase 5, acceptance:
 *   "two clients exchange a PRIVMSG; NOTICE not echoed to sender."
 *
 * Those two sentences are the milestone -- this is the phase the server becomes
 * usable -- and this file is where they are checked. Everything else here exists
 * to stop the two from passing for the wrong reasons.
 *
 * ---------------------------------------------------------------------------
 * WHAT MAKES THESE TWO ASSERTIONS MEAN SOMETHING
 * ---------------------------------------------------------------------------
 * "B received the message" passes against a node that delivered it with no
 * source prefix, to a third party as well, and to the sender when it should not
 * have. Each of those is a broken server, so each has its own section below:
 *
 *   - THE SOURCE PREFIX, asserted byte for byte, and asserted to carry the
 *     OBSERVED host rather than the one the client CLAIMED. This is the direct
 *     test of the Phase 3 decision documented at commands.c's handle_user():
 *     every client here sends `USER <nick> 0 *spoofed.example :...`, putting a
 *     hostname in the slot RFC 2812 3.1 names <unused>, and every prefix in
 *     this file is then REQUIRED to carry 127.0.0.1 and FORBIDDEN from
 *     carrying "spoofed.example". A node that had regressed to the client's
 *     claim fails the first message assertion and nothing else in this file.
 *   - THE ROSTER IS COMPLETE. Three members of #t, and all three are asserted
 *     individually. "At least two arrived" would pass against a fan-out that
 *     skipped the last member of the list.
 *   - NO LEAK. A fourth client, in a different channel and holding a nick that
 *     appears in no target, must receive nothing. A node that fanned out to
 *     "every connection" passes every delivery assertion here and is not an
 *     IRC server.
 *   - NOTICE IS NOT ECHOED, asserted as a NEGATIVE, and the positive control
 *     beside it is the same sender, same channel, same member set, one word
 *     different, delivered as a PRIVMSG. Without that control a fan-out that
 *     delivered NEITHER verb to that member would satisfy the negative
 *     perfectly.
 *
 * ---------------------------------------------------------------------------
 * THE ONE PRIMITIVE: A CLOSED WINDOW PER COMMAND
 * ---------------------------------------------------------------------------
 * Every assertion in this file runs against a WINDOW [from, end), where:
 *
 *   from  the offset of a PING's PONG, sent before the command under test
 *   end   the offset of a second PING's PONG, sent after it
 *
 * Because a connection's answers are written in order, the closing PONG's
 * arrival proves every earlier answer is already in the buffer. So the window
 * is closed by a FACT about the node rather than by a wait, which is how this
 * file gets "nothing arrived" without the fixed sleep 6.3 forbids -- and 6.3's
 * reason (a sleep is short on a loaded runner and long on a fast one) is
 * precisely the reason a window is better than a wait.
 *
 * The scoping is not decoration. tc_expect() searches the whole accumulated
 * buffer, so a second ` 461 alice :Not enough parameters` would match the FIRST
 * one and return instantly, and the wait covering the command under test would
 * never happen. That is a test that passes against a node which stopped
 * answering after the first case. Here the search is always over the span the
 * command could have answered in, and the drain token is unique per call.
 *
 * NO sleep() ANYWHERE. No socket buffer is pinned either: a test that reads back
 * a SO_RCVBUF figure is macOS-only by construction, because Linux doubles it.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_READY_MS 15000
#define T_IO_MS 15000

/* The shipped binary's node name. Numerics and echoes are prefixed with it, so
 * an assertion that hard-codes a different one asserts against a line this node
 * never sends. */
#define BIN_NAME "irc.test"

/* The host every client here connects FROM, and the hostname every client here
 * CLAIMS in USER. assert_no_claim_echoed() forbids the second in every window
 * and every prefix check requires the first, so the two can only both be
 * satisfied by a node that used what accept() observed. */
#define OBSERVED_HOST "127.0.0.1"
#define CLAIMED_HOST "spoofed.example"

static size_t g_opened;
static unsigned g_drain_seq;

typedef struct {
    test_client_t c;
    char          nick[72];
} client_t;

/* ---------------------------------------------------------------------------
 * The window primitives
 * ---------------------------------------------------------------------------
 */

/* Send a PING, wait for its PONG, and return the offset where the PONG's line
 * begins. The token is unique per call, because a repeated one would match its
 * own earlier PONG and the "wait" would return instantly -- which is the same
 * stale-needle trap expect_line_between() exists to avoid, one level down. */
static size_t drain(client_t *cl)
{
    char line[64];
    char needle[96];
    const char *at;

    g_drain_seq++;
    (void)snprintf(line, sizeof line, "PING :dr%u", g_drain_seq);
    (void)snprintf(needle, sizeof needle, "PONG %s dr%u\r\n", BIN_NAME,
                   g_drain_seq);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0, "no PONG for %s", line);
    at = strstr(tc_buffer(&cl->c), needle);
    TF_CHECK_MSG(at != NULL, "the drain PONG vanished from the buffer");
    return (at != NULL) ? (size_t)(at - tc_buffer(&cl->c)) : 0u;
}

/* Open a window on `cl` and return its start offset. The caller closes it with
 * another drain() once the command under test has been sent. */
static size_t open_window(client_t *cl)
{
    return drain(cl);
}

/* `want` must appear in cl's window, terminated, at a line boundary.
 *
 * The CRLF is part of the needle so this proves the line is terminated on the
 * wire rather than being a prefix of a longer one, and the boundary is checked
 * explicitly so a match that is the SUFFIX of some other line cannot pass. Both
 * matter here: these needles are whole messages, and a needle that matched the
 * tail of an unrelated line would pass a node that never sent it. */
static void expect_in_window(client_t *cl, size_t from, size_t end,
                             const char *what, const char *want)
{
    const char *base = tc_buffer(&cl->c);
    const char *at;

    TF_CHECK_MSG(end > from, "%s: the window was never closed (from=%zu end=%zu)",
                 what, from, end);
    at = strstr(base + from, want);
    TF_CHECK_MSG(at != NULL, "%s: expected the exact line \"%s\"", what, want);
    if (at == NULL) {
        return;
    }
    TF_CHECK_MSG(at < base + end,
                 "%s: \"%s\" appears only AFTER the window closed, so it was not "
                 "an answer to the command under test",
                 what, want);
    TF_CHECK_MSG(at == base + from || at[-1] == '\n',
                 "%s: \"%s\" is not at the start of a line: it is the tail of a "
                 "longer one",
                 what, want);
}

/* `needle` must NOT appear anywhere in the window. */
static void expect_absent_in_window(client_t *cl, size_t from, size_t end,
                                    const char *what, const char *needle)
{
    const char *base = tc_buffer(&cl->c);
    size_t count = 0;

    TF_CHECK_MSG(end > from,
                 "%s: the window was never closed (from=%zu end=%zu), so \"did "
                 "not appear\" would prove nothing",
                 what, from, end);
    /* Counted only inside the window, not over the whole buffer, so a needle
     * from an earlier exchange cannot be mistaken for this one. */
    for (const char *p = base + from; p < base + end;) {
        const char *hit = strstr(p, needle);

        if (hit == NULL || hit >= base + end) {
            break;
        }
        count++;
        p = hit + strlen(needle);
    }
    TF_CHECK_MSG(count == 0,
                 "%s: \"%s\" appeared %zu time(s) in the window and must not "
                 "have appeared at all",
                 what, needle, count);
}

/* The workhorse: `cl` sends `line`, and the answer is checked inside a window
 * opened before and closed after it. Nearly every assertion in this file is
 * one line of this. */
static void send_expect(client_t *cl, const char *line, const char *want)
{
    size_t from = open_window(cl);
    size_t end;

    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "tc_send(%s) failed", line);
    end = drain(cl);
    expect_in_window(cl, from, end, line, want);
}


/* ---------------------------------------------------------------------------
 * Clients
 * ---------------------------------------------------------------------------
 */

/* One registration path, so no scenario below can accidentally assert a
 * messaging verb against an unregistered connection and get a 451 for a reason
 * that has nothing to do with messaging. */
static void client_open(client_t *cl, nf_node_t *node, const char *nick)
{
    char line[512];

    tc_init(&cl->c);
    (void)snprintf(cl->nick, sizeof cl->nick, "%s", nick);
    g_opened++;
    TF_CHECK_MSG(tc_connect(&cl->c, node->port) == 0, "tc_connect(%s) failed",
                 nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "NICK send failed");
    /* RFC 2812 3.1: USER <user> <mode> <unused> :<realname>. The third
     * parameter is the one older clients fill with a hostname, which is exactly
     * why it is the one worth lying in: a node that stored it would put a value
     * the client chose into every prefix it emits to every other client. */
    (void)snprintf(line, sizeof line, "USER %s 0 *%s :Real %s", nick,
                   CLAIMED_HOST, nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "USER send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, " 001 ", T_IO_MS) == 0, "%s did not register",
                 nick);
    TF_CHECK_MSG(tc_send(&cl->c, "PING :reg-drain") == 0, "PING send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, "PONG ", T_IO_MS) == 0,
                 "%s: no PONG after registration", nick);
}

static void client_join(client_t *cl, const char *channel)
{
    char line[128];
    char needle[160];
    size_t from = open_window(cl);
    size_t end;

    (void)snprintf(line, sizeof line, "JOIN %s", channel);
    (void)snprintf(needle, sizeof needle, ":%s 366 %s ", BIN_NAME, cl->nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "tc_send(%s) failed", line);
    /* 366 terminates a names list, so waiting for it means the JOIN is complete
     * and a later fan-out cannot race the roster.
     *
     * The needle is the full line PREFIX rather than a bare " 366 ": a bare
     * three-digit numeric appears as a SUBSTRING of 329's creation timestamp
     * (":irc.test 329 alice #T 1790643005 :Channel creation time") on almost
     * every JOIN, so a loose needle matches the tail of a longer number and the
     * line-boundary check then fails on a match that was never a 366 at all. */
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0, "%s: no 366 after JOIN %s",
                 cl->nick, channel);
    end = drain(cl);
    expect_in_window(cl, from, end, line, needle);
}

/* The line this node MUST have sent for `from_nick` addressing `target`. The
 * prefix is ASSEMBLED from the observed host rather than hard-coded as a
 * constant string, because a hard-coded ":alice!alice@127.0.0.1 " would still
 * pass against a node that computed the same bytes from a claim -- the point of
 * the prefix checks is that the value came from accept(), and the only way a
 * test can insist on that is by requiring the two possible sources to differ. */
static void expect_delivered(client_t *to, size_t from, size_t end,
                             const char *what, const char *from_nick,
                             const char *verb, const char *target,
                             const char *text)
{
    char want[512];

    (void)snprintf(want, sizeof want, ":%s!%s@%s %s %s :%s\r\n", from_nick,
                   from_nick, OBSERVED_HOST, verb, target, text);
    expect_in_window(to, from, end, what, want);
}

/* The negative that makes the source prefix honest. Checked in the windows that
 * carry a delivered message, because a node that only SOMETIMES trusts the
 * claim is the harder bug to see. */
static void expect_no_claim_echoed(client_t *cl, size_t from, size_t end,
                                   const char *what)
{
    expect_absent_in_window(cl, from, end, what, CLAIMED_HOST);
}

int main(void)
{
    nf_node_t node;
    client_t alice, bob, carol, dave;
    char want[256];

    if (nf_spawn_binary(&node) != 0) {
        fprintf(stderr, "could not spawn the irc-serve binary\n");
        return 1;
    }
    TF_CHECK_MSG(nf_expect(&node, "loop_running:", T_READY_MS) == 0,
                 "the node never reported its loop armed");

    client_open(&alice, &node, "alice");
    client_open(&bob, &node, "bob");
    client_open(&carol, &node, "carol");
    client_open(&dave, &node, "dave");
    client_join(&alice, "#t");
    client_join(&bob, "#t");
    client_join(&carol, "#t");
    /* dave is connected and registered but in NO channel named in this file's
     * target list. He is the control for "no leak to a non-member". */
    client_join(&dave, "#elsewhere");

    /* =======================================================================
     * 1. THE ACCEPTANCE CRITERION: two clients exchange a PRIVMSG
     * ==================================================================== */
    /* One window per client, opened before the single command under test and
     * closed after, so each assertion is about an answer to THAT command and
     * nothing else. */
    {
        size_t s1 = open_window(&alice);
        size_t f2 = open_window(&bob);
        size_t f3 = open_window(&carol);
        size_t f4 = open_window(&dave);
        size_t s2, e2, e3, e4;

        TF_CHECK_MSG(tc_send(&alice.c, "PRIVMSG #T :hello channel") == 0,
                     "tc_send failed");
        /* The SENDER is drained first, and that ordering is what makes the
         * observers' windows sound.
         *
         * Every window here is opened before the send, so each covers the whole
         * exchange. What is NOT guaranteed is the order in which the node
         * services four separate sockets: it may well answer bob's PING, write
         * "PONG" into his buffer, and only afterwards read alice's PRIVMSG and
         * deliver the message into that same buffer. Bob's window would then
         * close before the message landed -- the positive assertion would fail
         * spuriously, and (worse) the "dave did not get it" NEGATIVE would pass
         * for the wrong reason.
         *
         * Draining alice FIRST removes that. Her PING was sent after her PRIVMSG
         * on the SAME socket, and the loop processes one input line per dispatch,
         * with the whole fan-out happening inside the dispatch that carries the
         * PRIVMSG. So her PONG cannot be written until every recipient's copy is
         * already queued. Once it is in hand, draining bob and carol closes
         * their windows strictly after the delivery.
         *
         * Opening the observers' windows only after alice's drain would be
         * WRONG in the other direction: the message is already in their buffers
         * by then, so the window would start after the very bytes it is meant to
         * contain. */
        s2 = drain(&alice);
        e2 = drain(&bob);
        e3 = drain(&carol);
        e4 = drain(&dave);
        expect_delivered(&alice, s1, s2, "alice's own echo of her PRIVMSG",
                         "alice", "PRIVMSG", "#T", "hello channel");
        expect_delivered(&bob, f2, e2, "bob's copy of alice's PRIVMSG", "alice",
                         "PRIVMSG", "#T", "hello channel");
        /* carol is the THIRD member. Two of three would pass against a fan-out
         * that stopped early, which is the likeliest way a member walk goes
         * wrong. */
        expect_delivered(&carol, f3, e3, "carol's copy of alice's PRIVMSG",
                         "alice", "PRIVMSG", "#T", "hello channel");
        /* dave is the control, and he is in a DIFFERENT channel rather than in
         * none: a fan-out that walked "every connection" or "every connection
         * that has joined something" delivers to him, and passes every positive
         * assertion above. */
        expect_absent_in_window(&dave, f4, e4, "dave, in another channel",
                                "hello channel");
        expect_no_claim_echoed(&bob, f2, e2, "bob's first window");
        expect_no_claim_echoed(&carol, f3, e3, "carol's first window");
    }

    /* =======================================================================
     * 2. A TWO-MEMBER ROSTER, BOTH MEMBERS ASSERTED
     * ==================================================================== */
    /* A second channel with exactly two members. A one-member channel cannot
     * distinguish "fanned out to the member list" from "fanned out to one
     * conn_t", which is the distinction 3.1's first two rows are about. */
    client_join(&alice, "#pair");
    client_join(&bob, "#pair");
    {
        size_t s1 = open_window(&alice);
        size_t f2 = open_window(&bob);
        size_t f3 = open_window(&carol);
        size_t f4 = open_window(&dave);
        size_t s2, e2, e3, e4;

        TF_CHECK_MSG(tc_send(&alice.c, "PRIVMSG #pair :two members") == 0,
                     "tc_send failed");
        /* Sender drained first -- see section 1 for why, and for why the
         * observers' windows are opened BEFORE the send rather than after. */
        s2 = drain(&alice);
        e2 = drain(&bob);
        e3 = drain(&carol);
        e4 = drain(&dave);
        expect_delivered(&alice, s1, s2, "alice in the two-member channel",
                         "alice", "PRIVMSG", "#PAIR", "two members");
        expect_delivered(&bob, f2, e2, "bob, the second member of #pair", "alice",
                         "PRIVMSG", "#PAIR", "two members");
        expect_absent_in_window(&carol, f3, e3, "carol, on a different channel",
                                "two members");
        expect_absent_in_window(&dave, f4, e4, "dave, on a different channel",
                                "two members");
        expect_no_claim_echoed(&bob, f2, e2, "bob's #pair window");
    }

    /* =======================================================================
     * 3. NOTICE IS NOT ECHOED TO THE SENDER -- and the control beside it
     * ==================================================================== */
    /* bob is a member of #t, so under PRIVMSG he receives his own message --
     * which is asserted immediately afterwards, as the control. Without it this
     * negative would be satisfied by a fan-out that delivered nothing to bob at
     * all, and that is a much more likely bug than a deliberate echo. */
    {
        size_t s1 = open_window(&bob);
        size_t f2 = open_window(&alice);
        size_t f3 = open_window(&carol);
        size_t s2, e2, e3;

        TF_CHECK_MSG(tc_send(&bob.c, "NOTICE #T :notice from bob") == 0,
                     "tc_send failed");
        /* Sender first -- see section 1. This ordering is what makes the
         * assertion below sound in BOTH directions: bob's PONG proves the whole
         * fan-out has been decided, so an absent copy in his buffer means the
         * node did not write to him, rather than that the write had not happened
         * yet. Opening alice's and carol's windows up front instead would let
         * the loop answer one of their PINGs, and the test would be reading a
         * buffer the node had not finished with. */
        /* Sender drained first -- see section 1. This ordering is what makes the
         * assertion below sound in BOTH directions: bob's PONG proves the whole
         * fan-out has been decided, so an absent copy in his buffer means the
         * node did not write to him, rather than that the write had not happened
         * yet. Opening alice's and carol's windows up front instead would let
         * the loop answer one of their PINGs first, and the test would be
         * reading a buffer the node had not finished with. */
        s2 = drain(&bob);
        e2 = drain(&alice);
        e3 = drain(&carol);
        /* The assertion. */
        expect_absent_in_window(&bob, s1, s2, "the sender of a NOTICE",
                                "notice from bob");
        /* The other members DO get it, so the absence above is the rule rather
         * than a fan-out that reached nobody. */
        expect_delivered(&alice, f2, e2, "alice's copy of bob's NOTICE", "bob",
                         "NOTICE", "#T", "notice from bob");
        expect_delivered(&carol, f3, e3, "carol's copy of bob's NOTICE", "bob",
                         "NOTICE", "#T", "notice from bob");
    }

    /* The POSITIVE control: same sender, same channel, same members, one word
     * different, delivered as a PRIVMSG. bob sees it. This is the assertion that
     * makes the NOTICE negative above mean anything -- a fan-out that skipped
     * bob entirely would satisfy "bob did not receive the notice" perfectly. */
    send_expect(&bob, "PRIVMSG #T :privmsg from bob",
                ":bob!bob@127.0.0.1 PRIVMSG #T :privmsg from bob\r\n");

    /* =======================================================================
     * 4. THE SOURCE PREFIX, against a CLAIMED hostname
     * ==================================================================== */
    /* Every client sent `USER <nick> 0 *spoofed.example`, so the claimed host is
     * on the wire from all four of them and every window below must be free of
     * it. This is the direct test of the Phase 3 decision, and it is worth being
     * precise about what it is NOT: it is not a test of 001 (Phase 3 asserts
     * that) and not a test that USER's <unused> slot is ignored in isolation. It
     * is a test that the OBSERVED address is what reaches a THIRD PARTY, which
     * is the only place the decision has an effect a user could notice. */
    {
        size_t s1 = open_window(&alice);
        size_t f1 = open_window(&bob);
        size_t s2, e1;

        TF_CHECK_MSG(tc_send(&alice.c, "PRIVMSG #T :prefix under test") == 0,
                     "tc_send failed");
        s2 = drain(&alice); /* sender first -- see section 1 */
        e1 = drain(&bob);
        expect_no_claim_echoed(&alice, s1, s2, "alice's prefix window");
        expect_delivered(&bob, f1, e1, "bob's copy; the prefix must be observed",
                         "alice", "PRIVMSG", "#T", "prefix under test");
        expect_no_claim_echoed(&bob, f1, e1, "bob's prefix window");
    }

    /* A direct message carries the same prefix, and a body containing a space
     * AND a semicolon proves the trailing parameter is colonned: a body that
     * lost its colon would re-parse as two parameters, and 3.2's formatter is
     * where that is decided. The semicolon is here because it is the IRCv3 tag
     * separator -- a node that mishandled tags would strip or re-split on it.
     *
     * Sent by alice and checked on BOB, because a direct message is the case
     * where the recipient is one named connection rather than a member list, and
     * 3.1's first row is the one being exercised. */
    {
        size_t s1 = open_window(&alice);
        size_t f1 = open_window(&bob);
        size_t s2, e1;

        TF_CHECK_MSG(tc_send(&alice.c, "PRIVMSG bob :two words and a ; semicolon") ==
                         0,
                     "tc_send failed");
        s2 = drain(&alice); /* sender first -- see section 1 */
        e1 = drain(&bob);
        /* And the sender does NOT get a direct message back. This is 3.1's first
         * row rather than its channel rows: a direct message is written to the
         * one conn_t named as the target, and the target is not the sender. A
         * node that treated a nick target like a channel target -- or that
         * echoed every send -- would deliver this to alice as well, and a
         * client would see every private message twice. */
        expect_absent_in_window(&alice, s1, s2, "the sender of a direct message",
                                "two words");
        expect_in_window(&bob, f1, e1, "bob's direct message from alice",
                         ":alice!alice@127.0.0.1 PRIVMSG bob :two words and a ; "
                         "semicolon\r\n");
        expect_no_claim_echoed(&bob, f1, e1, "bob's direct-message window");
    }

    /* =======================================================================
     * 5. A SELF-RESOLVED TARGET
     * ==================================================================== */
    /* 3.1's first row is "local user | either | write to conn_t", and a client
     * that PRIVMSGs itself is the case where the target and the sender are the
     * same connection. The echo is REQUIRED here: it is what a client uses to
     * confirm delivery without a second command, and it is the positive
     * counterpart of section 3. */
    send_expect(&alice, "PRIVMSG alice :talking to myself",
                ":alice!alice@127.0.0.1 PRIVMSG alice :talking to myself\r\n");

    /* =======================================================================
     * 6. THE SAME SCENARIOS AGAINST BOTH VERBS
     * ==================================================================== */
    /* RFC 2812 3.3.2 defines NOTICE as PRIVMSG with a non-reply guarantee, so
     * the two differ in exactly two places: the echo (section 3) and the
     * membership rule (section 8). Every other outcome is driven through this
     * loop against BOTH verbs, so "they differ only where the RFC says they
     * must" is checked here rather than claimed.
     *
     * Each case is chosen so the VERB is what decides the answer, not leftover
     * state from an earlier one:
     *   401  a nick nobody holds -- nothing to echo, nothing to deliver
     *   403  a channel name the node does not hold -- a complaint about the
     *        NAME, so it is the same for both verbs
     *   461  a parameter count, decided before the target is looked at
     */
    for (int pass = 0; pass < 2; pass++) {
        const char *verb = (pass == 0) ? "PRIVMSG" : "NOTICE";
        char line[160];
        char probe[160];

        (void)snprintf(line, sizeof line, "%s nobody-here :hi", verb);
        (void)snprintf(want, sizeof want, ":%s 401 alice nobody-here ", BIN_NAME);
        send_expect(&alice, line, want);

        (void)snprintf(line, sizeof line, "%s #nosuchchannel :hi", verb);
        (void)snprintf(want, sizeof want, ":%s 403 alice #NOSUCHCHANNEL ",
                       BIN_NAME);
        send_expect(&alice, line, want);

        /* Arity, in BOTH directions. A node that only checked the low side
         * passes a one-case test.
         *
         * Note the THREE-parameter form has no colon. `PRIVMSG #t :a b` is two
         * parameters -- the trailing marker swallows the rest of the line, which
         * is 3.2's rule and is why it is worth a case of its own below. A
         * three-parameter PRIVMSG is written `PRIVMSG #t a b`, and it is
         * refused rather than guessed at: the node cannot know whether the
         * client meant "a" or "b" as the body, and delivering one of them would
         * be delivering a message the client did not write. */
        (void)snprintf(want, sizeof want, ":%s 461 alice :Not enough parameters",
                       BIN_NAME);
        (void)snprintf(line, sizeof line, "%s", verb);
        send_expect(&alice, line, want);
        (void)snprintf(line, sizeof line, "%s #t", verb);
        send_expect(&alice, line, want);
        (void)snprintf(line, sizeof line, "%s #t a b", verb);
        send_expect(&alice, line, want);

        /* ...and the colon form is TWO parameters, accepted and delivered whole.
         * 3.2's trailing-parameter rule is what makes a body containing spaces
         * expressible at all, and a node that split on the space would deliver
         * "a" and drop "b".
         *
         * Checked on BOB for both verbs, because bob is a member of #t and is
         * not the sender: the sender is exactly who section 3's echo rule
         * applies to, so asserting delivery there would be testing two things
         * at once. */
        {
            size_t f1 = open_window(&bob);
            size_t e1;
            char colon[160];
            char echoed[256];

            (void)snprintf(colon, sizeof colon, "%s #t :a b", verb);
            (void)snprintf(echoed, sizeof echoed,
                           ":alice!alice@127.0.0.1 %s #T :a b\r\n", verb);
            TF_CHECK_MSG(tc_send(&alice.c, colon) == 0, "tc_send failed");
            (void)drain(&alice); /* sender first -- see section 1 */
            e1 = drain(&bob);
            expect_in_window(&bob, f1, e1, "a colon body is one parameter",
                             echoed);
        }

        /* THE PARTIAL-SEND CHECK. A refused arity is the case where a half-
         * parsed command could reach somebody: a node that split `PRIVMSG #t a b`
         * on the space would find a target, find a body, and deliver "a" to
         * every member of #t BEFORE noticing the extra parameter. Nothing in the
         * positive checks above would catch that -- each of them is a different
         * command -- so the body is a unique marker and every member is checked
         * for its ABSENCE.
         *
         * alice sends it because she is a member, and bob is checked because he
         * is too: the leak this is looking for lands on members, not on
         * non-members. */
        /* NO colon: `%s #t leaked%d` is a TWO-parameter command that this node
         * correctly DELIVERS, and the whole point of this case is the
         * three-parameter form the arity check above refuses. With a colon it
         * would deliver "leaked0" to every member and the absence checks below
         * would be asserting the opposite of what they claim. */
        (void)snprintf(probe, sizeof probe, "%s #t leaked%d extra", verb, pass);
        {
            size_t s1 = open_window(&alice);
            size_t f1 = open_window(&bob);
            size_t f2 = open_window(&carol);
            size_t s2, e1, e2;

            TF_CHECK_MSG(tc_send(&alice.c, probe) == 0, "tc_send failed");
            /* Drain the SENDER first, then open the observers' windows. See the
             * "CROSS-CONNECTION WINDOWS" note at the top of this file: alice's
             * PING cannot be answered until the dispatch carrying her command has
             * finished, so her PONG proves the fan-out is already queued on every
             * recipient. Opening bob's window before draining alice would let the
             * loop answer bob's PING FIRST, close his window, and only then
             * deliver the message into it -- a false pass, and a timing-dependent
             * one, which is exactly how it showed up on Linux and not macOS. */
            s2 = drain(&alice);
            e1 = drain(&bob);
            e2 = drain(&carol);
            expect_in_window(&alice, s1, s2, "the refusal itself",
                             ":" BIN_NAME " 461 alice :Not enough parameters\r\n");
            expect_absent_in_window(&bob, f1, e1, "a member, for a refused body",
                                    "leaked");
            expect_absent_in_window(&carol, f2, e2, "a member, for a refused body",
                                    "leaked");
            /* ...and the marker must be one this file has never used, or the
             * absence is a statement about an earlier exchange. */
            TF_CHECK_MSG(strstr(probe, "leaked") != NULL &&
                             strstr(probe, "extra") != NULL,
                         "the partial-send probe is not the three-parameter form");
        }
        /* And the command is not silently dropped: a well-formed one right
         * afterwards is delivered whole, to bob, who is a member of #t and not
         * the sender. Without this the checks above would also pass against a
         * node that refused EVERYTHING after the first case. */
        (void)snprintf(line, sizeof line, "%s #t :delivered %d", verb, pass);
        (void)snprintf(want, sizeof want, ":alice!alice@127.0.0.1 %s #T :delivered "
                                      "%d\r\n",
                       verb, pass);
        {
            size_t f1 = open_window(&bob);
            size_t e1;

            TF_CHECK_MSG(tc_send(&alice.c, line) == 0, "tc_send failed");
            (void)drain(&alice); /* sender drained first -- see section 1 */
            e1 = drain(&bob);
            expect_in_window(&bob, f1, e1, "a well-formed message after refusals",
                             want);
        }
    }

    /* =======================================================================
     * 7. 404: a channel that EXISTS, addressed by a non-member
     * ==================================================================== */
    /* The numeric 4.4 lists 404 for, and the case it exists for. #priv exists
     * (bob made it) and alice is not on it, so 403 is demonstrably the wrong
     * answer here -- and the check below catches a node that gave it. Asserted
     * for PRIVMSG only, because the NOTICE case is the documented divergence
     * and is asserted immediately afterwards rather than being folded in. */
    client_join(&bob, "#priv");
    (void)snprintf(want, sizeof want, ":%s 404 alice #PRIV :Cannot send to "
                                      "channel\r\n",
                   BIN_NAME);
    send_expect(&alice, "PRIVMSG #priv :am I allowed", want);
    /* dave is a SECOND non-member. A 404 that came from "this client" rather
     * than from "this membership" passes the check above and fails this one. */
    (void)snprintf(want, sizeof want, ":%s 404 dave #PRIV :Cannot send to "
                                      "channel\r\n",
                   BIN_NAME);
    send_expect(&dave, "PRIVMSG #priv :nor I", want);
    /* And nobody received either refused message. bob is a member of #priv, so
     * he is where a partial delivery would land -- and the 404 itself goes to
     * ALICE, the sender, not to the channel, which is checked by asserting bob
     * never sees it. A node that answered 404 to the channel instead of to the
     * sender would satisfy a naive "no leak" check and still be wrong: every
     * other member of a channel you cannot write to would learn of your failed
     * attempts. */
    (void)snprintf(want, sizeof want, ":%s 404 alice #PRIV :Cannot send to "
                                      "channel\r\n",
                   BIN_NAME);
    {
        size_t s1 = open_window(&alice);
        size_t f1 = open_window(&bob);
        size_t s2, e1;

        TF_CHECK_MSG(tc_send(&alice.c, "PRIVMSG #priv :am I allowed") == 0,
                     "tc_send failed");
        /* Sender drained FIRST, for the reason in the note at the top: alice and
         * bob are different sockets and nothing orders a PING on one against a
         * PRIVMSG on the other. */
        s2 = drain(&alice);
        e1 = drain(&bob);
        expect_in_window(&alice, s1, s2, "the 404 goes to the sender", want);
        expect_absent_in_window(&bob, f1, e1, "a member of the refused channel",
                                "am I allowed");
        expect_absent_in_window(&bob, f1, e1,
                                "a member of the refused channel, for the 404 "
                                "itself",
                                "404");
    }

    /* =======================================================================
     * 8. THE ONE PLACE NOTICE IS DELIBERATELY DIFFERENT
     * ==================================================================== */
    /* RFC 1459 2.4.2: a NOTICE is sent to a channel "whether or not the sender
     * is on the channel". alice is still NOT a member of #priv, so the message
     * is DELIVERED to the members and NOTHING is sent back to her. Both halves
     * are asserted together on purpose: a node that delivered it to nobody would
     * satisfy the negative alone, and a node that answered 404 would fail the
     * delivery. */
    {
        size_t s1 = open_window(&alice);
        size_t f1 = open_window(&bob);
        size_t s2, e1;

        TF_CHECK_MSG(tc_send(&alice.c, "NOTICE #priv :from outside") == 0,
                     "tc_send failed");
        s2 = drain(&alice); /* sender first -- see section 1 */
        e1 = drain(&bob);
        expect_absent_in_window(&alice, s1, s2,
                                "the non-member sender of a NOTICE", "from outside");
        expect_delivered(&bob, f1, e1,
                         "the member of #priv, from a NON-member's NOTICE", "alice",
                         "NOTICE", "#PRIV", "from outside");
    }
    /* carol is on #t, #pair and #elsewhere but NOT #priv: the leak control for
     * this specific path, which took a different branch than the PRIVMSG one. */
    /* Sender drained first: alice's PONG is the proof that the delivery above has
     * already been queued on every member, so carol's window opened after it
     * cannot close before the message would have arrived. */
    {
        size_t s2 = drain(&alice);
        size_t f2;
        size_t e2;

        (void)s2;
        f2 = open_window(&carol);
        e2 = drain(&carol);
        expect_absent_in_window(&carol, f2, e2, "carol, not on #priv",
                                "from outside");
    }

    /* =======================================================================
     * 9. NO LEAK to a non-member, with the member as the control
     * ==================================================================== */
    {
        size_t s1 = open_window(&bob);
        size_t f2 = open_window(&carol);
        size_t f3 = open_window(&dave);
        size_t s2, e2, e3;

        TF_CHECK_MSG(tc_send(&bob.c, "PRIVMSG #priv :members only") == 0,
                     "tc_send failed");
        s2 = drain(&bob); /* sender first -- see section 1 */
        e2 = drain(&carol);
        e3 = drain(&dave);
        expect_in_window(&bob, s1, s2, "bob, the member of #priv",
                         ":bob!bob@127.0.0.1 PRIVMSG #PRIV :members only\r\n");
        expect_absent_in_window(&carol, f2, e2, "carol, not on #priv",
                                "members only");
        expect_absent_in_window(&dave, f3, e3, "dave, on another channel",
                                "members only");
    }

    /* =======================================================================
     * 10. AN EMPTY BODY IS DELIVERED, not dropped
     * ==================================================================== */
    /* `PRIVMSG #t :` parses to a message with an EMPTY trailing parameter, which
     * 3.2's formatter represents by coloning it. A node that treated the empty
     * body as "nothing to send" would drop it silently, and a client that pokes
     * a channel with an empty body would get no answer at all. */
    /* ...and is echoed to the sender, because the sender is a member of #t and
     * 3.1's channel row writes to the member list without exempting anybody.
     * Both halves are asserted because either alone is weak: a node that dropped
     * the trailing parameter as "nothing to send" would pass the absence, and a
     * node that dropped it everywhere would pass the presence on a channel
     * where it happened to reach carol by accident. */
    {
        size_t s1 = open_window(&bob);
        size_t f1 = open_window(&carol);
        size_t s2, e1;

        TF_CHECK_MSG(tc_send(&bob.c, "PRIVMSG #t :") == 0, "tc_send failed");
        s2 = drain(&bob); /* sender first -- see section 1 */
        e1 = drain(&carol);
        expect_in_window(&bob, s1, s2, "an empty body is echoed to its sender",
                         ":bob!bob@127.0.0.1 PRIVMSG #T :\r\n");
        expect_in_window(&carol, f1, e1, "an empty body reaches another member",
                         ":bob!bob@127.0.0.1 PRIVMSG #T :\r\n");
    }

    /* =======================================================================
     * The node's own accounting
     * ==================================================================== */
    /* n_reply_refused is documented in reply.c as a BUG REPORT rather than a
     * metric. A non-zero value is what an over-long message, an unrepresentable
     * parameter or a teardown race would produce without any wire assertion
     * above failing, which is exactly why it is asserted.
     *
     * It is read AFTER nf_stop(), because the node publishes its counters at
     * shutdown and not before: server_shutdown() runs first so the numbers
     * describe the node as it actually finished rather than a mid-teardown
     * snapshot. Waiting for the key before stopping would time out against a
     * node that had done nothing wrong. */
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0: a render or a destination rule was "
                 "refused somewhere in this test");
    TF_CHECK_MSG(nf_expect_u64_ge(&node, "accepted=", g_opened, T_IO_MS) == 0,
                 "the node accepted fewer connections than the test opened (%zu)",
                 g_opened);

    tc_close(&alice.c);
    tc_close(&bob.c);
    tc_close(&carol.c);
    tc_close(&dave.c);
    nf_free(&node);
    tf_done("messaging");
    return 0;
}
