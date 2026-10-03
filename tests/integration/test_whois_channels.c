/* test_whois_channels.c -- 319 RPL_WHOISCHANNELS on the wire, against the real
 * binary.
 *
 * docs/RFC2812_CONFORMANCE.md, section "319 RPL_WHOISCHANNELS": Phase 11 added
 * this numeric and this file is the proof that it is on the wire in the shape
 * RFC 2812 5.1 specifies.
 *
 * ---------------------------------------------------------------------------
 * WHY IT MATTERS, AND WHY IT WAS THE ONE REAL GAP IN `handle_whois()`
 * ---------------------------------------------------------------------------
 * Until this phase a WHOIS emitted 311, 312, 317, 318, plus 301 for an away user
 * and 330 for an identified one. Every one of those answers a question about a
 * PERSON: who they are, which node holds them, whether they are away, when they
 * signed on. None of them says where they are. A client that learned a friend
 * had gone away through `away-notify` had no way to learn which channels to look
 * in, and a client that had not negotiated the capability had no way at all.
 *
 * It is also what makes `away-notify`'s own documented promise true. The
 * specification's reason for not telling the setter about their own away state is
 * that "they can rely on RPL_NOWAWAY and RPL_UNAWAY" -- and 305/306 tell the
 * SETTER. They tell nobody else where that person is, which is the question a
 * third party has after seeing the notification.
 *
 * ---------------------------------------------------------------------------
 * THE PROPERTIES THAT MAKE THESE ASSERTIONS MEAN SOMETHING
 * ---------------------------------------------------------------------------
 *   - EVERY assertion is inside a window delimited by two PONGs. A bare
 *     tc_expect() searches the WHOLE accumulated buffer and ` 319 ` is a string
 *     that appears in every later WHOIS, so an unscoped search would be satisfied
 *     by a WHOIS issued seconds after the one under test.
 *   - 319's FIELD ORDER is asserted as one whole line: `:irc.test 319 <target>
 *     <nick> :<run>`. RFC 2812 5.1 writes "<nick> :*( ( "@" / "+" ) <channel>
 *     " " )", so the nick is a MIDDLE parameter and the run is the trailing one.
 *     A node that put the nick in the trailing text, or the run in the middle
 *     parameters, fails this needle while satisfying any "a 319 arrived" check.
 *   - ALL THREE SIGIL STATES ARE IN ONE LINE -- '@', nothing, and '+' -- plus
 *     three absences, because a node that wrote '@' for a voice or '+' for an
 *     operator would pass every count here and get exactly those wrong.
 *   - 319's ABSENCE is asserted for a user in no channel. A node that emitted it
 *     unconditionally would satisfy every positive check in this file.
 *   - 319 CHUNKING is exercised with real channels, not asserted in prose. Eight
 *     channels with 63-byte names cannot fit on one 319; send_whois_channels()
 *     exists precisely so they do not produce a trailing value reply() REFUSES,
 *     and a refusal is counted on `n_reply_refused`, the counter reply.c holds at
 *     zero because a non-zero value is a bug report.
 *
 * NO sleep() ANYWHERE (6.3): every wait is the select()-driven deadline inside
 * tc_expect(), and every negative assertion is closed by a PING drain rather than
 * by a wait.
 *
 * The window helpers below are duplicated across the integration tests rather than
 * shared. That is test_queries.c's and test_away_notify.c's arrangement too, and
 * the reason it holds is that each file's helper set is shaped by what that file
 * asserts -- this one has no use for the reply-counting helper its neighbours
 * carry.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_READY_MS 15000
#define T_IO_MS 15000

#define BIN_NAME "irc.test"

/* CHAN_MAX_NAME, written as the literal rather than included from channel.h for
 * the reason test_queries.c gives for AWAY_MAX: a test that reads a bound from
 * the header cannot FAIL if the header is wrong, and the WIDTH of these channel
 * names is the only reason the chunking case reaches a second line at all. 3.2
 * makes the same point about IRC_MAX_TAG_OVERHEAD -- "raising a value bound above
 * without re-deriving fails the suite instead of the network". */
#define CHAN_NAME_MAX 63

/* How many maximally-long channels the chunking case joins, and how many of them
 * fit on one 319. Derived rather than chosen: an entry costs CHAN_NAME_MAX bytes
 * plus a joining space, and send_whois_channels() breaks a line at 400, so six fit
 * and eight cannot. The check in the test body is what keeps the two numbers tied
 * together if either is ever raised. */
#define LONG_CHANS 8
#define FIRST_LINE_ENTRIES 6
#define WHIS_CHANNEL_BREAK 400

typedef struct {
    test_client_t c;
    char          nick[72];
} client_t;

static void client_open(client_t *cl, nf_node_t *node, const char *nick)
{
    char line[512];

    tc_init(&cl->c);
    (void)snprintf(cl->nick, sizeof cl->nick, "%s", nick);
    TF_CHECK_MSG(tc_connect(&cl->c, node->port) == 0, "tc_connect(%s) failed", nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "NICK send failed");
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "USER send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, " 001 ", T_IO_MS) == 0, "%s did not register", nick);
    TF_CHECK_MSG(tc_send(&cl->c, "PING :reg-drain") == 0, "PING send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, "PONG ", T_IO_MS) == 0,
                 "%s: no PONG after registration", nick);
}

/* ---------------------------------------------------------------------------
 * THE WINDOW PRIMITIVE -- identical in purpose to test_queries.c's, and for the
 * same reason. A window is [from, end): `from` is a PING's PONG sent before the
 * command under test, `end` a second PING's PONG sent after it. Because a
 * connection's answers are written in order, the closing PONG proves every
 * earlier answer is already in the buffer, so "nothing arrived" is a fact about
 * the node rather than a guess about its speed.
 * ------------------------------------------------------------------------ */
static unsigned g_drain_seq;

static size_t drain(client_t *cl)
{
    char line[64];
    char needle[96];
    const char *at;

    g_drain_seq++;
    (void)snprintf(line, sizeof line, "PING :w%u", g_drain_seq);
    (void)snprintf(needle, sizeof needle, "PONG %s w%u\r\n", BIN_NAME, g_drain_seq);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0, "no PONG for %s", line);
    at = strstr(tc_buffer(&cl->c), needle);
    TF_CHECK_MSG(at != NULL, "the drain PONG vanished from the buffer");
    return (at != NULL) ? (size_t)(at - tc_buffer(&cl->c)) : 0u;
}

/* `want` must appear in the window, terminated, at a line boundary. */
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
                 "%s: \"%s\" appears only AFTER the window closed, so it was not an "
                 "answer to the command under test",
                 what, want);
    TF_CHECK_MSG(at == base + from || at[-1] == '\n',
                 "%s: \"%s\" is not at the start of a line: it is the tail of a "
                 "longer one",
                 what, want);
}

/* `needle` must NOT appear anywhere in the window, and the window must have been
 * closed -- an unclosed window would make "did not appear" a statement about a
 * buffer the node may not have finished writing to. */
static void expect_absent_in_window(client_t *cl, size_t from, size_t end,
                                    const char *what, const char *needle)
{
    const char *base = tc_buffer(&cl->c);
    size_t count = 0;

    TF_CHECK_MSG(end > from,
                 "%s: the window was never closed (from=%zu end=%zu), so \"did not "
                 "appear\" would prove nothing",
                 what, from, end);
    for (const char *p = base + from; p < base + end;) {
        const char *hit = strstr(p, needle);

        if (hit == NULL || hit >= base + end) {
            break;
        }
        count++;
        p = hit + strlen(needle);
    }
    TF_CHECK_MSG(count == 0,
                 "%s: \"%s\" appeared %zu time(s) in the window and must not have "
                 "appeared at all",
                 what, needle, count);
}

/* `needle` must appear SOMEWHERE in the window, with no line-boundary check.
 *
 * This is a separate function rather than a flag because the boundary check is
 * wrong for this one case and wrong in a way no flag should paper over: a 319's
 * channel run is a space-separated LIST inside a single trailing parameter, so
 * every element except the last on its line is preceded by a space rather than
 * by a newline. Requiring a line boundary here would assert something false about
 * the protocol. The needle is still scoped to a closed window and still has to
 * occur, so "did not appear" remains a fact about the node. */
static void expect_in_window_list(client_t *cl, size_t from, size_t end,
                                  const char *what, const char *needle)
{
    const char *base = tc_buffer(&cl->c);
    const char *at;

    TF_CHECK_MSG(end > from, "%s: the window was never closed (from=%zu end=%zu)",
                 what, from, end);
    at = strstr(base + from, needle);
    TF_CHECK_MSG(at != NULL, "%s: expected \"%s\" somewhere in the window", what,
                 needle);
    TF_CHECK_MSG(at != NULL && at < base + end,
                 "%s: \"%s\" appears only AFTER the window closed", what, needle);
}

/* How many times `needle` occurs in the window. Scoped for the same reason the
 * helpers above are: a count over the whole buffer would include every earlier
 * reply of the same shape. */
static size_t count_in_window(const client_t *cl, size_t from, size_t end,
                              const char *needle)
{
    const char *base = tc_buffer(&cl->c);
    size_t n = 0;

    for (const char *p = base + from; p < base + end;) {
        const char *hit = strstr(p, needle);

        if (hit == NULL || hit >= base + end) {
            break;
        }
        n++;
        p = hit + strlen(needle);
    }
    return n;
}

static void client_join(client_t *cl, const char *channel)
{
    char line[CHAN_NAME_MAX + 8];
    char needle[CHAN_NAME_MAX + 48];

    (void)snprintf(line, sizeof line, "JOIN %s", channel);
    (void)snprintf(needle, sizeof needle, ":%s 366 %s ", BIN_NAME, cl->nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "tc_send(%s) failed", line);
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0, "no 366 after %s", line);
    (void)drain(cl);
}

/* A channel name of EXACTLY CHAN_NAME_MAX bytes, distinct per `idx`.
 *
 * The width is the point: send_whois_channels() breaks a 319 at 400 bytes of
 * channel run, so an entry costs CHAN_NAME_MAX + 1 and six entries are the most
 * that fit on one line. Eight of them cannot fit on one line, which is what makes
 * the chunking case real rather than asserted.
 *
 * The last two bytes carry the index so the eight names differ, and the body is
 * filler from the alphabet. '#' is CHAN_TYPE1 and chan_name_valid() refuses only
 * space, ',', ':', '@' and the control characters, so alphanumerics are legal
 * anywhere in the name.
 *
 * UPPERCASE, and that is not a style choice. Every channel this node holds is
 * canonicalised through chan_name_upper() -- 2.1's case folding, and the reason
 * `#alpha` and `#ALPHA` are one channel -- so a 319 names channels in upper case
 * whatever spelling the client used to create them. A test that JOINed lower-case
 * names and then searched the WHOIS for those lower-case names would be asserting
 * a canonicalisation this node deliberately does not do. */
static void long_chan_name(char *out, size_t cap, int idx)
{
    size_t n = 0;

    TF_CHECK_MSG(cap > (size_t)CHAN_NAME_MAX,
                 "the channel-name buffer holds %zu bytes and the test needs %d",
                 cap, CHAN_NAME_MAX + 1);
    out[n++] = '#';
    while (n < (size_t)CHAN_NAME_MAX) {
        /* `n` is READ into the arithmetic and WRITTEN by the increment, so the
         * two are sequenced explicitly rather than left to the order of evaluation
         * of the assignment's operands -- which is undefined, and which
         * -Weverything (-Wunsequenced) rejects on this toolchain. */
        size_t k = n;

        out[n++] = (char)('A' + ((k + (size_t)idx * 7u) % 26u));
    }
    out[CHAN_NAME_MAX - 2] = (char)('0' + (idx / 10) % 10);
    out[CHAN_NAME_MAX - 1] = (char)('0' + idx % 10);
    out[CHAN_NAME_MAX] = '\0';
}

int main(void)
{
    nf_node_t node;
    client_t alice, bob, gina, dave, erin;
    size_t from, end;
    char want[512];
    char name[CHAN_NAME_MAX + 1];
    int i;

    if (nf_spawn_binary(&node) != 0) {
        fprintf(stderr, "could not spawn the irc-serve binary\n");
        return 1;
    }
    TF_CHECK_MSG(nf_expect(&node, "loop_running:", T_READY_MS) == 0,
                 "the node never reported its loop armed");

    client_open(&alice, &node, "alice");
    client_open(&bob, &node, "bob");
    /* gina exists to be the OPERATOR of the channel alice is voiced in: 442 is
     * answered to a MODE by a non-member before the mode is even looked at, so
     * the voice has to be granted by somebody who is on the channel. */
    client_open(&gina, &node, "gina");
    /* dave registers and NEVER joins anything. He exists to make 319's absence
     * checkable, and a test cannot have a user in no channel if every user it
     * creates is in one. */
    client_open(&dave, &node, "dave");
    client_open(&erin, &node, "erin");

    /* =======================================================================
     * 1. THE FIELD LIST, THE SIGILS, AND THE ABSENCE
     * ==================================================================== */
    /* alice CREATES #alpha, so she is its operator and 319 must say so with '@'
     * -- RFC 2812 5.1's grammar is "( "@" / "+" ) <channel>", so the sigil
     * precedes the name with no space between them.
     *
     * #beta IS BOB'S, and that is not an incidental choice: whoever JOINs a
     * channel creates it and is therefore its operator, so a channel alice joined
     * herself would have given her a second '@' and the line under test would
     * carry two identical sigils and no plain state. bob creating #beta and alice
     * joining it is how the "member with no sigil" case is produced, and a node
     * that defaulted to a sigil on every entry would fail this line.
     *
     * alice is then voiced in #gamma, where gina created the channel, and the
     * VOICE has to come from that channel's operator rather than from anybody in
     * the test: handle_mode() answers 442 to a MODE by a non-member before it
     * looks at the mode at all, so `MODE #gamma +v` sent by alice -- who is not
     * on #gamma -- would be refused and the '+' state would never exist. */
    client_join(&alice, "#alpha");
    client_join(&bob, "#alpha");
    client_join(&bob, "#beta");
    client_join(&alice, "#beta");
    client_join(&gina, "#gamma");
    client_join(&alice, "#gamma");
    from = drain(&gina);
    TF_CHECK_MSG(tc_send(&gina.c, "MODE #gamma +v alice") == 0, "MODE +v failed");
    end = drain(&gina);
    expect_in_window(&gina, from, end, "the +v echo",
                     ":gina!gina@127.0.0.1 MODE #GAMMA +v alice\r\n");

    /* THE WHOLE LINE, which is the assertion that pins the FIELD ORDER. RFC 2812
     * 5.1 writes 319 as "<nick> :*( ( "@" / "+" ) <channel> " " )": the nick is a
     * MIDDLE parameter and the channel run is the trailing one. A node that put
     * the nick in the trailing text, or the run in the middle parameters, would
     * fail this needle while satisfying any "a 319 arrived" check.
     *
     * All THREE SIGIL STATES ARE IN THIS ONE LINE -- '@#ALPHA' (operator),
     * '#BETA' (plain member, no sigil) and '+#GAMMA' (voiced, not an operator) --
     * in join order, because the walk is over `conn_t::chans`. */
    from = drain(&bob);
    TF_CHECK_MSG(tc_send(&bob.c, "WHOIS alice") == 0, "WHOIS send failed");
    end = drain(&bob);
    (void)snprintf(want, sizeof want, ":%s 319 bob alice :@#ALPHA #BETA +#GAMMA\r\n",
                   BIN_NAME);
    expect_in_window(&bob, from, end, "319 for an operator in three channels", want);
    TF_CHECK_MSG(count_in_window(&bob, from, end, ":" BIN_NAME " 319 ") == 1u,
                 "WHOIS of a user in three channels produced %zu 319 lines, expected "
                 "exactly 1 (three channels fit on one line)",
                 count_in_window(&bob, from, end, ":" BIN_NAME " 319 "));

    /* THE '@' AND THE '+' ARE NOT INTERCHANGEABLE, asserted as three absences. A
     * node that wrote '@' for a voice or '+' for an operator would pass every
     * count in the block above and get these wrong -- and a client reading 319 to
     * decide whether somebody may moderate is reading exactly that distinction. */
    expect_absent_in_window(&bob, from, end, "the three-sigil 319", "@#BETA");
    expect_absent_in_window(&bob, from, end, "the three-sigil 319", "+#ALPHA");
    expect_absent_in_window(&bob, from, end, "the three-sigil 319", "@#GAMMA");

    /* 318 still terminates, and AFTER the 319. Checked as a POSITION rather than
     * a presence, because a 318 anywhere in the window satisfies a bare presence
     * check -- including one that arrived before the channel run. */
    {
        const char *base = tc_buffer(&bob.c);
        const char *last319 = NULL;
        const char *at318;

        from = drain(&bob);
        TF_CHECK_MSG(tc_send(&bob.c, "WHOIS alice") == 0, "WHOIS send failed");
        end = drain(&bob);
        for (const char *p = base + from; p < base + end; p++) {
            if (strncmp(p, " 319 ", 5) == 0) {
                last319 = p;
            }
        }
        at318 = strstr(base + from, ":" BIN_NAME " 318 bob alice :End of /WHOIS "
                                         "list\r\n");
        TF_CHECK_MSG(at318 != NULL, "the WHOIS of a channel member did not "
                                    "terminate with 318");
        TF_CHECK_MSG(at318 != NULL && last319 != NULL && at318 > last319,
                     "318 came before the last 319, so a client that stops reading "
                     "at the terminator would lose the channel list");
    }

    /* AND THE ABSENCE, which is the half that makes the presence meaningful. dave
     * is registered and in no channel, so RFC 2812's reply set for him carries no
     * channel run at all. A 319 with an empty run would be a line whose only
     * content is a nickname, and every client that renders "is in:" for a WHOIS
     * would print a dangling label for every user who has not joined anything --
     * which on this node is every client until it joins one. */
    from = drain(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "WHOIS dave") == 0, "WHOIS send failed");
    end = drain(&alice);
    expect_absent_in_window(&alice, from, end, "the WHOIS of a user in no channel",
                            " 319 ");
    expect_in_window(&alice, from, end, "318 still terminates for dave",
                     ":" BIN_NAME " 318 alice dave :End of /WHOIS list\r\n");

    /* =======================================================================
     * 2. 319 CHUNKED, because the alternative is a REFUSAL
     * ==================================================================== */
    /* RFC 2812 3.3.4 permits this in the sentence that defines the numeric: "For
     * each reply set, only RPL_WHOISCHANNELS may appear more than once (for long
     * lists of channel names)." send_whois_channels() breaks at 400 bytes; the
     * names below are CHAN_NAME_MAX each, so six fit on one line and eight cannot
     * fit on one. Without the break the trailing value would exceed reply()'s
     * REPLY_TEXT_MAX, which reply() REFUSES rather than truncates -- a refusal on
     * `n_reply_refused`, the counter reply.c holds at zero. */
    TF_CHECK_MSG((size_t)FIRST_LINE_ENTRIES * ((size_t)CHAN_NAME_MAX + 1u) <=
                     (size_t)WHIS_CHANNEL_BREAK
                     && (size_t)(FIRST_LINE_ENTRIES + 1) *
                            ((size_t)CHAN_NAME_MAX + 1u) > (size_t)WHIS_CHANNEL_BREAK,
                 "the chunking arithmetic no longer holds: %d entries of %d bytes "
                 "must fit on one 319 and %d must not",
                 FIRST_LINE_ENTRIES, CHAN_NAME_MAX + 1, FIRST_LINE_ENTRIES + 1);
    for (i = 0; i < LONG_CHANS; i++) {
        long_chan_name(name, sizeof name, i);
        client_join(&erin, name);
    }
    from = drain(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "WHOIS erin") == 0, "WHOIS send failed");
    end = drain(&alice);
    TF_CHECK_MSG(count_in_window(&alice, from, end, ":" BIN_NAME " 319 ") >= 2u,
                 "WHOIS of a user in %d maximally-named channels produced %zu 319 "
                 "lines, expected at least 2: the overflow was dropped rather than "
                 "chunked",
                 LONG_CHANS, count_in_window(&alice, from, end, ":" BIN_NAME " 319 "));
    /* EVERY channel is named somewhere in the window, which is what makes the
     * count above mean "chunked" rather than "truncated". A dropped second line
     * satisfies the count check if it emitted two empty ones.
     *
     * The needle is the bare 63-byte name, with no leading space: the FIRST entry
     * of each 319 has nothing in front of it, because the run is the trailing
     * parameter after the colon. Every name is unique and 63 bytes of distinct
     * filler, and the window opens after the JOINs that also carried them, so a
     * match here can only be a 319 naming it. */
    for (i = 0; i < LONG_CHANS; i++) {
        long_chan_name(name, sizeof name, i);
        expect_in_window_list(&alice, from, end, "every chunked channel is named",
                              name);
    }
    /* And 318 still terminates AFTER the last chunk. */
    expect_in_window(&alice, from, end, "318 terminates after the 319 chunks",
                     ":" BIN_NAME " 318 alice erin :End of /WHOIS list\r\n");

    /* =======================================================================
     * The node's own accounting
     * ==================================================================== */
    /* Read AFTER nf_stop(): the node publishes its counters at shutdown and not
     * before. `reply_refused` is the one that matters for THIS file in
     * particular -- every 319 above is a value reply() would REFUSE rather than
     * reshape if it did not fit, so a missing chunk shows up as a non-zero on
     * this counter before it shows up as a wrong line. */
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0");

    tc_close(&alice.c);
    tc_close(&bob.c);
    tc_close(&gina.c);
    tc_close(&dave.c);
    tc_close(&erin.c);
    nf_free(&node);
    tf_done("whois_channels");
    return 0;
}
