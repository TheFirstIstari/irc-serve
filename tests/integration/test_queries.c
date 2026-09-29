/* test_queries.c -- WHO, WHOIS, ISON and AWAY on the wire, against the real
 * binary.
 *
 * docs/SERVER_DESIGN.md 7/Phase 5: "WHO/WHOIS/ISON, AWAY", acceptance "AWAY set
 * and cleared, and WHO/WHOIS reflect it".
 *
 * ---------------------------------------------------------------------------
 * WHY AWAY IS IN THE SAME FILE AS WHO AND WHOIS
 * ---------------------------------------------------------------------------
 * Because 352's <flags> and 301's trailing text are the ONLY places an away
 * message reaches a client, and 4.4's numeric list does not contain either of
 * them. Both are gaps in the list rather than in the protocol, and both are
 * flagged where they are emitted (msg_verbs.c). A test that set AWAY and then
 * asserted on nothing would pass against a node that stored the field and never
 * reported it, which is the failure mode that matters here: an away state no
 * client can see is not an away state.
 *
 * ---------------------------------------------------------------------------
 * THE PROPERTIES THAT MAKE "AWAY IS REFLECTED" MEAN SOMETHING
 * ---------------------------------------------------------------------------
 *   - The absence of 301 is asserted, not just the presence. A node that sent
 *     301 unconditionally would satisfy every positive check here.
 *   - The FLAG in 352 changes and changes back: H when here, G when away, H
 *     again after a bare AWAY. Only the round trip shows the state is stored
 *     rather than latched.
 *   - A NEAR-MISS BOUNDARY on the away message: CONN_MAX_AWAY is 255, so 255
 *     bytes must be accepted and 256 refused, and the refusal must leave the
 *     PREVIOUS message intact. A bound of "some number" passes a test that only
 *     checks a long message is refused; a boundary checks it is the number the
 *     header says.
 *   - The refused AWAY does not change the away state, which is the same
 *     "a refusal leaves everything exactly as it was" property Phase 4 asserted
 *     for a 437. It is checked by reporting 301 again and reading the OLD
 *     message off the wire.
 *
 * NO sleep() ANYWHERE (6.3): every wait is a select()-driven deadline inside
 * tc_expect(), and every negative assertion is closed by a PING drain rather
 * than by a wait -- see test_messaging.c's client_drain(), which is the same
 * technique for the same reason.
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

#define BIN_NAME "irc.test"
#define OBSERVED_HOST "127.0.0.1"
#define CLAIMED_HOST "spoofed.example"

/* conn_t::away is bounded at 255 (connection.h, CONN_MAX_AWAY). Written here
 * as the literal rather than included from connection.h, deliberately: a test
 * that reads the bound from the header cannot FAIL if the header is wrong, and
 * this file's whole job at the boundary is to notice that. 3.2 makes the same
 * point about IRC_MAX_TAG_OVERHEAD -- "raising a value bound above without
 * re-deriving fails the suite instead of the network" -- and the only way that
 * works is if the expected value is written down independently. */
#define AWAY_MAX 255

static size_t g_opened;

typedef struct {
    test_client_t c;
    char          nick[72];
} client_t;

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
    (void)snprintf(line, sizeof line, "USER %s 0 *%s :Real %s", nick, CLAIMED_HOST,
                   nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "USER send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, " 001 ", T_IO_MS) == 0, "%s did not register",
                 nick);
    TF_CHECK_MSG(tc_send(&cl->c, "PING :reg-drain") == 0, "PING send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, "PONG ", T_IO_MS) == 0,
                 "%s: no PONG after registration", nick);
}

/* ---------------------------------------------------------------------------
 * THE WINDOW PRIMITIVE
 * ---------------------------------------------------------------------------
 * Identical in purpose to test_messaging.c's, and for the same reason: a bare
 * tc_expect() searches the WHOLE accumulated buffer, so a second ` 306 bob :...`
 * matches the first and returns instantly, and the wait that was supposed to
 * cover the command under test never happens. Here almost every assertion is
 * about a numeric this node has already sent at least once, so the scoping is
 * load-bearing rather than defensive.
 *
 * A window is [from, end): `from` is a PING's PONG sent before the command
 * under test, `end` a second PING's PONG sent after it. Because a connection's
 * answers are written in order, the closing PONG proves every earlier answer is
 * already in the buffer -- so "nothing arrived" is a fact about the node rather
 * than a guess about its speed, and no fixed sleep is involved (6.3). */
static unsigned g_drain_seq;

static size_t drain(client_t *cl)
{
    char line[64];
    char needle[96];
    const char *at;

    g_drain_seq++;
    (void)snprintf(line, sizeof line, "PING :q%u", g_drain_seq);
    (void)snprintf(needle, sizeof needle, "PONG %s q%u\r\n", BIN_NAME,
                   g_drain_seq);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0, "no PONG for %s (client %s)", line, cl->nick);
    at = strstr(tc_buffer(&cl->c), needle);
    TF_CHECK_MSG(at != NULL, "the drain PONG vanished from the buffer");
    return (at != NULL) ? (size_t)(at - tc_buffer(&cl->c)) : 0u;
}

static size_t open_window(client_t *cl)
{
    return drain(cl);
}

/* `want` must appear in the window, terminated, at a line boundary.
 *
 * Both halves of the CRLF matter. Including it proves the line is terminated on
 * the wire rather than being a prefix of a longer one; checking the boundary
 * stops a match that is the SUFFIX of some other line from passing. The latter
 * is not hypothetical here: this node prints a 329 with a ten-digit creation
 * timestamp on every JOIN, and a bare " 366 " needle matches inside it. */
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

/* `needle` must NOT appear anywhere in the window, and the window must have
 * been closed -- an unclosed window would make "did not appear" a statement
 * about a buffer the node may not have finished writing to, which is the race
 * that lets "assert nothing arrived" tests silently pass. */
static void expect_absent_in_window(client_t *cl, size_t from, size_t end,
                                    const char *what, const char *needle)
{
    const char *base = tc_buffer(&cl->c);
    size_t count = 0;

    TF_CHECK_MSG(end > from,
                 "%s: the window was never closed (from=%zu end=%zu), so \"did "
                 "not appear\" would prove nothing",
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
                 "%s: \"%s\" appeared %zu time(s) in the window and must not "
                 "have appeared at all",
                 what, needle, count);
}

static void client_join(client_t *cl, const char *channel)
{
    char line[128];
    char needle[160];
    size_t from = open_window(cl);
    size_t end;

    (void)snprintf(line, sizeof line, "JOIN %s", channel);
    /* Full line PREFIX, not a bare " 366 ": this node prints a 329 with a
     * ten-digit creation timestamp on every JOIN, so a bare three-digit needle
     * matches inside that number and the wait would be satisfied before the JOIN
     * had produced a 366 at all. */
    (void)snprintf(needle, sizeof needle, ":%s 366 %s ", BIN_NAME, cl->nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "tc_send(%s) failed", line);
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0,
                 "%s: no 366 after JOIN %s", cl->nick, channel);
    /* And the roster really arrived inside that window, so a later assertion
     * about the same channel cannot be reading a stale one. */
    end = drain(cl);
    expect_in_window(cl, from, end, line, needle);
}

/* How many times `needle` occurs in the window. Scoped for the same reason the
 * two helpers above are: a count over the whole buffer would include every
 * earlier WHO, and "WHO #Q produced 3 lines" would then be true of a node that
 * produced none. */
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

/* The workhorse: `cl` sends `line`, and the answer is checked in a window
 * opened before and closed after it. */
static void send_expect(client_t *cl, const char *line, const char *want)
{
    size_t from = open_window(cl);
    size_t end;

    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "tc_send(%s) failed", line);
    end = drain(cl);
    expect_in_window(cl, from, end, line, want);
}

/* 352 RPL_WHOREPLY for one nick, matched on its WHOLE parameter run.
 *
 *   :<server> 352 <client> <channel> <user> <host> <server> <nick> <flags> :0 ...
 *
 * so the needle reaches from the line prefix to the colon before <hopcount>,
 * which is where the flags live. Matching the whole run rather than a bare
 * " 352 " is deliberate: this node emits a 329 with a ten-digit creation
 * timestamp on every JOIN, and a bare three-digit needle matches inside it, so
 * a count or a search over " 352 " is a statement about the buffer rather than
 * about WHO.
 *
 * `channel` is '*' for the non-channel form, which is the RFC's placeholder and
 * the only way a client can tell a bare WHO from a channel one. */
static void expect_who_entry(client_t *cl, size_t from, size_t end,
                             const char *who, const char *channel,
                             const char *flags, const char *what)
{
    char want[512];

    (void)snprintf(want, sizeof want, ":%s 352 %s %s %s %s %s %s %s :0 ", BIN_NAME,
                   cl->nick, channel, who, OBSERVED_HOST, BIN_NAME, who, flags);
    expect_in_window(cl, from, end, what, want);
}

int main(void)
{
    nf_node_t node;
    client_t alice, bob, carol;
    size_t from, end;
    /* The away body is AWAY_MAX bytes, and it is composed into command and
     * expectation strings from there. The buffers are sized from the bound
     * rather than picked, because picking them is what Phase 2's portability
     * lesson is about: a hand-picked size is right on the machine that wrote it
     * and a -Wformat-truncation error on the machine that did not. glibc's
     * _FORTIFY_SOURCE analyses snprintf against the SOURCE buffer's maximum
     * size, not its current length, so `want` has to be able to hold the worst
     * case the compiler can see or the build fails on Linux and passes on
     * macOS. These are the two worst cases and nothing else:
     *
     *   "AWAY :" + AWAY_MAX + 1  and  ":<server> 301 alice bob :" + AWAY_MAX
     *
     * with the server name and the trailing CRLF bounded by the node's own
     * constant. */
    char line[AWAY_MAX + 1];
    char want[AWAY_MAX + 64];
    size_t i;

    if (nf_spawn_binary(&node) != 0) {
        fprintf(stderr, "could not spawn the irc-serve binary\n");
        return 1;
    }
    TF_CHECK_MSG(nf_expect(&node, "loop_running:", T_READY_MS) == 0,
                 "the node never reported its loop armed");

    client_open(&alice, &node, "alice");
    client_open(&bob, &node, "bob");
    client_open(&carol, &node, "carol");
    client_join(&alice, "#q");
    client_join(&bob, "#q");
    client_join(&carol, "#q");

    /* =======================================================================
     * 1. WHO #chan -> one 352 per member, terminated by 315
     * ==================================================================== */
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "WHO #Q") == 0, "tc_send failed");
    end = drain(&alice);

    /* The COUNT is as load-bearing as the content: a fan-out that emitted one
     * entry per CHANNEL rather than per member would satisfy any single-entry
     * assertion, and a client that stops reading at 315 would silently lose the
     * rest of a roster. */
    TF_CHECK_MSG(count_in_window(&alice, from, end, ":" BIN_NAME " 352 ") == 3,
                 "WHO #Q produced %zu 352 lines, expected exactly 3 (one per "
                 "member)",
                 count_in_window(&alice, from, end, ":" BIN_NAME " 352 "));
    /* All three members named individually, and in the fixed order a client
     * reads a roster in: the channel's own member list order. */
    expect_in_window(&alice, from, end, "352 for alice", ":" BIN_NAME " 352 alice #Q alice ");
    expect_in_window(&alice, from, end, "352 for bob", ":" BIN_NAME " 352 alice #Q bob ");
    expect_in_window(&alice, from, end, "352 for carol", ":" BIN_NAME " 352 alice #Q carol ");
    /* alice CREATED #q, so she is its operator and 352 must say so. 4.4 makes
     * PREFIX=(ov)@+ mandatory in 005, and a 352 that never showed an operator
     * would make that advertisement a lie. */
    expect_who_entry(&alice, from, end, "alice", "#Q", "H@",
                     "alice is here and an operator");
    expect_who_entry(&alice, from, end, "bob", "#Q", "H",
                     "bob is here and a plain member");
    expect_who_entry(&alice, from, end, "carol", "#Q", "H",
                     "carol is here and a plain member");

    /* 315 terminates, and it terminates AFTER every 352. Checked as a position
     * rather than a presence, because a 315 anywhere in the window satisfies a
     * bare presence check -- including one that arrived before the roster. */
    {
        const char *base = tc_buffer(&alice.c);
        const char *last352 = NULL;
        const char *at315;

        for (const char *p = base + from; p < base + end; p++) {
            if (strncmp(p, " 352 ", 5) == 0) {
                last352 = p;
            }
        }
        at315 = strstr(base + from, ":" BIN_NAME " 315 alice #Q :End of WHO list\r\n");
        TF_CHECK_MSG(at315 != NULL, "WHO #Q was not terminated by 315");
        TF_CHECK_MSG(at315 != NULL && last352 != NULL && at315 > last352,
                     "WHO #Q: 315 came before the last 352, so a client that "
                     "stops at the terminator would lose part of the roster");
    }

    /* The host in 352 is the OBSERVED one, for the reason the message prefix is:
     * a client does not choose the address it connected from. Every client here
     * CLAIMED one in USER. */
    expect_absent_in_window(&alice, from, end, "the WHO window", CLAIMED_HOST);
    expect_in_window(&alice, from, end, "the observed host in 352",
                     ":" BIN_NAME " 352 alice #Q alice " OBSERVED_HOST " ");

    /* A channel that does not exist: 403 and 315, and NOT a 352. Either alone
     * is wrong -- 315 without 403 cannot distinguish "no such channel" from "an
     * empty channel", and 403 without 315 leaves a client waiting for a
     * terminator that never comes. */
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "WHO #nosuch") == 0, "tc_send failed");
    end = drain(&alice);
    expect_in_window(&alice, from, end, "403 for a missing channel",
                     ":" BIN_NAME " 403 alice #NOSUCH :No such channel\r\n");
    expect_in_window(&alice, from, end, "315 for a missing channel",
                     ":" BIN_NAME " 315 alice #NOSUCH :End of WHO list\r\n");
    TF_CHECK_MSG(count_in_window(&alice, from, end, ":" BIN_NAME " 352 ") == 0,
                 "WHO on a missing channel produced %zu 352 lines, expected none",
                 count_in_window(&alice, from, end, ":" BIN_NAME " 352 "));

    /* A nickname mask. RFC 2812 3.3.4's WHO takes a <mask>, and a node that
     * answered "no such nick" for a mask matching a connected user would be
     * lying rather than limited. bob matches, alice and carol do not. */
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "WHO bo*") == 0, "tc_send failed");
    end = drain(&alice);
    TF_CHECK_MSG(count_in_window(&alice, from, end, ":" BIN_NAME " 352 ") == 1,
                 "WHO bo* produced %zu 352 lines, expected 1 (bob only)",
                 count_in_window(&alice, from, end, ":" BIN_NAME " 352 "));
    expect_in_window(&alice, from, end, "the masked entry", ":" BIN_NAME " 352 alice * bob ");

    /* Bare WHO: what irssi and weechat send on connect, and the reason the nick
     * registry has to be enumerable at all. The <channel> field is '*' -- the
     * RFC's placeholder for "this was not a channel query" -- and a node that
     * put an empty string or a leftover channel name there would be reporting
     * something false about a query that had no channel. */
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "WHO") == 0, "tc_send failed");
    end = drain(&alice);
    TF_CHECK_MSG(count_in_window(&alice, from, end, ":" BIN_NAME " 352 ") == 3,
                 "bare WHO produced %zu 352 lines, expected 3 (every nick)",
                 count_in_window(&alice, from, end, ":" BIN_NAME " 352 "));
    expect_in_window(&alice, from, end, "the '*' channel placeholder",
                     ":" BIN_NAME " 352 alice * alice ");
    expect_in_window(&alice, from, end, "bare WHO terminates",
                     ":" BIN_NAME " 315 alice * :End of WHO list\r\n");

    /* =======================================================================
     * 2. WHOIS <nick> -> 311, 312, 317, 318
     * ==================================================================== */
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "WHOIS bob") == 0, "tc_send failed");
    end = drain(&alice);
    /* 311's <host> is the observed address, and the RFC's '*' placeholder is a
     * MIDDLE parameter rather than part of the realname -- so the line has to
     * carry "* :Real bob" and not "* Real bob". A node that put the '*' in the
     * trailing text would render a realname of "* Real bob". */
    expect_in_window(&alice, from, end, "311",
                     ":" BIN_NAME " 311 alice bob bob " OBSERVED_HOST " * :Real bob\r\n");
    /* 312 names the node holding the nick. 2.1 makes the nick table per-server,
     * so naming the server IS the honest answer and not a placeholder -- and it
     * is what lets a client decide whether a nick@server target is local. */
    expect_in_window(&alice, from, end, "312",
                     ":" BIN_NAME " 312 alice bob " BIN_NAME " ");
    expect_in_window(&alice, from, end, "318 terminates",
                     ":" BIN_NAME " 318 alice bob :End of /WHOIS list\r\n");
    expect_absent_in_window(&alice, from, end, "the WHOIS window", CLAIMED_HOST);
    /* NOT 301. bob is not away yet, and a node that emitted 301 unconditionally
     * would satisfy every positive check in section 3. */
    expect_absent_in_window(&alice, from, end, "a here user's WHOIS", " 301 ");

    /* 317's two middle parameters are numbers whose values depend on the clock,
     * so only their SHAPE is checked -- and it is checked, because a 317 with no
     * numbers where it must carry two is a numeric that says nothing at all.
     *
     * The whole line is COPIED OUT of the window and matched against the RFC
     * 2812 3.3.4 shape, which is what makes the assertion mean something: it
     * fails if a parameter is missing, if one is not a number, or if the
     * trailing text is anything but the RFC's "seconds idle". A loose substring
     * search for " 317 " would pass a node that sent only the code.
     *
     * Note there is no %s for the server name in the scanf: %s WRITES to its
     * argument, and a string literal is not a destination. The line prefix is
     * located with strstr and stepped over instead. */
    {
        const char *base = tc_buffer(&alice.c);
        const char *at = strstr(base + from, ":" BIN_NAME " 317 alice bob ");
        char wire[256];   /* not `line`: that is the away-body buffer in main() */
        char trailing[64];
        unsigned long long idle = 0;
        unsigned long long signon = 0;
        const char *line_end;
        const char *body;
        size_t n;

        TF_CHECK_MSG(at != NULL, "the 317 line vanished from the window");
        if (at == NULL || at >= base + end) {
            TF_CHECK_MSG(at == NULL, "the 317 line is outside the window");
        } else {
            line_end = strstr(at, "\r\n");
            TF_CHECK_MSG(line_end != NULL && line_end < base + end,
                         "the 317 line is not terminated inside the window");
            n = (line_end != NULL) ? (size_t)(line_end - at) : strlen(at);
            if (n >= sizeof wire) {
                n = sizeof wire - 1u;
            }
            memcpy(wire, at, n);
            wire[n] = '\0';

            body = strstr(wire, " 317 alice bob ");
            TF_CHECK_MSG(body != NULL,
                         "the 317 line does not name bob after the client");
            if (body != NULL) {
                body += strlen(" 317 alice bob ");
            }
            TF_CHECK_MSG(body != NULL &&
                             sscanf(body, "%llu %llu :%63[^\r\n]", &idle, &signon,
                                    trailing) == 3,
                         "317's parameters are not <idle> <signon> "
                         ":seconds idle; the line was \"%s\"",
                         wire);
            /* The trailing parameter is read with a scanset rather than %s,
             * because the RFC's text is TWO WORDS: a plain %s stops at the
             * space and would compare "seconds" against "seconds idle" and
             * report a difference that is not one. */
            TF_CHECK_MSG(strcmp(trailing, "seconds idle") == 0,
                         "317's trailing text is \"%s\", not \"seconds idle\"",
                         trailing);
            /* A signon time of 0 is a field that was never written, and one in
             * the future is a clock read wrongly. Both are checked because
             * conn_t stores them at accept and connection.c stamps them on every
             * read -- a node that left signon_at at 0 passes every shape check
             * above. */
            TF_CHECK_MSG(signon > 1000000000ull,
                         "317's <signon> is %llu, which is not a plausible Unix "
                         "timestamp: conn_t::signon_at was never set",
                         signon);
            TF_CHECK_MSG(signon <= (unsigned long long)time(NULL),
                         "317's <signon> is in the future");
        }
    }

    /* An unknown nick: 401 and then 318. The 318 is not optional -- a client
     * that asked about a nick and received only 401 cannot tell "no such user"
     * from "the server is still working on it". */
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "WHOIS nosuchnick") == 0, "tc_send failed");
    end = drain(&alice);
    expect_in_window(&alice, from, end, "401",
                     ":" BIN_NAME " 401 alice nosuchnick :No such "
                     "nick/channel\r\n");
    expect_in_window(&alice, from, end, "318 after a 401",
                     ":" BIN_NAME " 318 alice nosuchnick :End of /WHOIS list\r\n");

    /* Case folding. 2.1 says nicknames are case-insensitive (RFC 2812 2.3.1),
     * and a WHOIS that 401'd a differently-cased spelling of a connected nick
     * would be refusing a user who is demonstrably there. */
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "WHOIS BOB") == 0, "tc_send failed");
    end = drain(&alice);
    expect_in_window(&alice, from, end, "WHOIS in a different case",
                     ":" BIN_NAME " 311 alice bob bob " OBSERVED_HOST " * :Real bob\r\n");

    /* =======================================================================
     * 3. AWAY: set, reflected by WHO and WHOIS, cleared, reflected again
     * ==================================================================== */
    /* 306 acknowledges the set. Neither 305 nor 306 is in 4.4's list, and they
     * are used anyway because a state-changing command that answers nothing
     * leaves a client unable to tell success from a dropped line. */
    from = open_window(&bob);
    TF_CHECK_MSG(tc_send(&bob.c, "AWAY :at lunch") == 0, "tc_send failed");
    end = drain(&bob);
    expect_in_window(&bob, from, end, "306 after AWAY",
                     ":" BIN_NAME " 306 bob :You have been marked as being "
                     "away\r\n");

    /* 301 carries the message, and 4.4 does not list it. It is the only numeric
     * that can report an away message at all, which is what makes "WHOIS
     * reflects AWAY" implementable rather than aspirational. */
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "WHOIS bob") == 0, "tc_send failed");
    end = drain(&alice);
    expect_in_window(&alice, from, end, "301 carrying the away message",
                     ":" BIN_NAME " 301 alice bob :at lunch\r\n");
    expect_in_window(&alice, from, end, "318 still terminates",
                     ":" BIN_NAME " 318 alice bob :End of /WHOIS list\r\n");

    /* 352's flag flips from H to G. ONE LETTER, and that letter is the whole
     * difference between "here" and "gone" on this numeric -- a node that
     * implemented away in 301 but not here would pass the check above and fail
     * this one, which is the point of making WHO report it at all. */
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "WHO #q") == 0, "tc_send failed");
    end = drain(&alice);
    expect_who_entry(&alice, from, end, "bob", "#Q", "G",
                     "bob is away, so the flag is G");
    expect_who_entry(&alice, from, end, "alice", "#Q", "H@",
                     "alice is still here");
    expect_who_entry(&alice, from, end, "carol", "#Q", "H",
                     "carol is still here");

    /* =======================================================================
     * 4. THE AWAY BOUNDARY: 255 accepted, 256 refused, and the refusal leaves
     *    the previous message exactly as it was
     * ==================================================================== */
    /* A body of exactly AWAY_MAX bytes, and it CONTAINS A SPACE on purpose.
     *
     * The space is not decoration: 3.2's formatter colons a trailing parameter
     * only when the value needs it (empty, leading ':', or holding a separator),
     * so a single-word away message renders UNCOLONNED and a needle written
     * ":irc.test 301 alice bob :xxx" would never match. One space near the front
     * makes the body need the colon -- which is also the form every real client
     * sees for a human-written away message -- while the LENGTH is still pinned
     * to the bound, which is what this test is for. */
    for (i = 0; i < (size_t)AWAY_MAX; i++) {
        line[i] = 'x';
    }
    line[0] = ' ';
    line[AWAY_MAX] = '\0';

    /* An accepted message is reported back BYTE FOR BYTE at the boundary. A
     * node that truncated at some other length passes a test that only checks
     * "a long message is refused"; this checks that 255 is the number the
     * header says it is. */
    (void)snprintf(want, sizeof want, "AWAY :%s", line);
    send_expect(&bob, want, ":" BIN_NAME " 306 bob :You have been marked as being "
                                   "away\r\n");
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "WHOIS bob") == 0, "tc_send failed");
    end = drain(&alice);
    (void)snprintf(want, sizeof want, ":" BIN_NAME " 301 alice bob :%s\r\n", line);
    expect_in_window(&alice, from, end, "301 for a maximum-length away message",
                     want);

    /* One byte more is REFUSED, not truncated. 3.2 forbids delivering a silently
     * shortened parameter, and an away message is a user's own sentence: storing
     * a prefix and reporting that prefix in 301 as if it were the whole of what
     * they wrote is exactly the failure the rule exists to prevent. */
    {
        char over[AWAY_MAX + 16];

        (void)snprintf(over, sizeof over, "AWAY :%s", line);
        (void)strcat(over, "x"); /* AWAY_MAX + 1 bytes of body */
        send_expect(&bob, over, ":" BIN_NAME " 417 bob :Away message is too "
                                          "long\r\n");
    }
    /* AND the previous message survived byte for byte. A refusal that also
     * cleared the state would be a second bug caught here, and a node that had
     * stored the truncated prefix fails the equality below rather than merely
     * looking shorter. */
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "WHOIS bob") == 0, "tc_send failed");
    end = drain(&alice);
    (void)snprintf(want, sizeof want, ":" BIN_NAME " 301 alice bob :%s\r\n", line);
    expect_in_window(&alice, from, end, "the away message after a refused AWAY",
                     want);
    /* And the converse: a 256-byte run must be ABSENT. The check above pins the
     * accepted value; this one catches a node that stored the refused one. */
    {
        char run[AWAY_MAX + 2];

        for (i = 0; i < (size_t)AWAY_MAX + 1u; i++) {
            run[i] = 'x';
        }
        run[AWAY_MAX + 1u] = '\0';
        expect_absent_in_window(&alice, from, end,
                                "the away message after a refused AWAY", run);
    }

    /* =======================================================================
     * 5. Clearing, and the round trip back to H
     * ==================================================================== */
    /* A short, recognisable message first, so the clear is checking the REMOVAL
     * of a known value rather than the absence of a 256-byte one. */
    from = open_window(&bob);
    TF_CHECK_MSG(tc_send(&bob.c, "AWAY :back soon") == 0, "tc_send failed");
    end = drain(&bob);
    expect_in_window(&bob, from, end, "306 for a second away message",
                     ":" BIN_NAME " 306 bob :You have been marked as being "
                     "away\r\n");

    from = open_window(&bob);
    TF_CHECK_MSG(tc_send(&bob.c, "AWAY") == 0, "tc_send failed");
    end = drain(&bob);
    expect_in_window(&bob, from, end, "305 after a bare AWAY",
                     ":" BIN_NAME " 305 bob :You are no longer marked as being "
                     "away\r\n");

    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "WHOIS bob") == 0, "tc_send failed");
    end = drain(&alice);
    /* 301 is GONE. This is the assertion the "AWAY set" check cannot make on
     * its own: a node that only ever ADDED the numeric would pass it. */
    expect_absent_in_window(&alice, from, end, "a cleared AWAY", " 301 ");
    expect_in_window(&alice, from, end, "318 still terminates after clearing",
                     ":" BIN_NAME " 318 alice bob :End of /WHOIS list\r\n");

    /* And 352 is back to H. The round trip is what shows the state is STORED
     * and not latched -- a node that set a flag and never cleared it passes
     * every "set" check above. */
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "WHO #q") == 0, "tc_send failed");
    end = drain(&alice);
    expect_who_entry(&alice, from, end, "bob", "#Q", "H",
                     "bob is back, so the flag is H");

    /* `AWAY :` -- one empty parameter -- means the same as no parameter. It
     * parses to a message with an empty trailing parameter, so a node that
     * checked "did I get a parameter" rather than "is it non-empty" would store
     * an empty away message and then report a 301 with nothing in it. */
    from = open_window(&bob);
    TF_CHECK_MSG(tc_send(&bob.c, "AWAY :short") == 0, "tc_send failed");
    end = drain(&bob);
    expect_in_window(&bob, from, end, "306",
                     ":" BIN_NAME " 306 bob :You have been marked as being "
                     "away\r\n");
    from = open_window(&bob);
    TF_CHECK_MSG(tc_send(&bob.c, "AWAY :") == 0, "tc_send failed");
    end = drain(&bob);
    expect_in_window(&bob, from, end, "305 after an empty AWAY",
                     ":" BIN_NAME " 305 bob :You are no longer marked as being "
                     "away\r\n");
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "WHOIS bob") == 0, "tc_send failed");
    end = drain(&alice);
    expect_absent_in_window(&alice, from, end, "an empty AWAY", " 301 ");

    /* =======================================================================
     * 6. ISON: present nicks are named, absent ones are simply missing
     * ==================================================================== */
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "ISON bob") == 0, "tc_send failed");
    end = drain(&alice);
    expect_in_window(&alice, from, end, "303 for one online nick",
                     ":" BIN_NAME " 303 alice bob :are online\r\n");

    /* Mixed: two present and two absent. The absent ones produce NO numeric and
     * no text -- their absence IS the answer, and the wire has no numeric for
     * "that user is not online". The exact line below is the whole assertion:
     * if either ghost had been named, this line would not match. */
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "ISON bob carol ghost1 ghost2") == 0,
                 "tc_send failed");
    end = drain(&alice);
    expect_in_window(&alice, from, end, "303 naming only the online nicks",
                     ":" BIN_NAME " 303 alice bob carol :are online\r\n");
    TF_CHECK_MSG(count_in_window(&alice, from, end, " 303 ") == 1,
                 "ISON produced %zu 303 lines where one reply was expected",
                 count_in_window(&alice, from, end, " 303 "));
    expect_absent_in_window(&alice, from, end, "the mixed ISON", "ghost1");
    expect_absent_in_window(&alice, from, end, "the mixed ISON", "ghost2");
    /* And nothing else was said about them: no 401, because a set query that
     * answers "no such nick" per entry is four lines of noise for one ISON. */
    expect_absent_in_window(&alice, from, end, "the mixed ISON", " 401 ");

    /* No online nicks at all still gets a 303, with an empty list. RFC 1459
     * 2.4.3 is explicit that an empty 303 is the answer, and silence would be
     * indistinguishable from a dropped command. */
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "ISON ghost1 ghost2") == 0, "tc_send failed");
    end = drain(&alice);
    expect_in_window(&alice, from, end, "303 with no names",
                     ":" BIN_NAME " 303 alice :are online\r\n");

    /* Case folding, for the same reason WHOIS has it. */
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "ISON BOB") == 0, "tc_send failed");
    end = drain(&alice);
    expect_in_window(&alice, from, end, "303 for a differently-cased nick",
                     ":" BIN_NAME " 303 alice bob :are online\r\n");

    /* An AWAY user is still ONLINE. ISON asks whether a nickname is connected,
     * not whether it is idle, and answering "no" for an away user would be the
     * single most damaging thing this handler could do: a monitoring client
     * would report a busy user as gone. */
    from = open_window(&bob);
    TF_CHECK_MSG(tc_send(&bob.c, "AWAY :brb") == 0, "tc_send failed");
    end = drain(&bob);
    expect_in_window(&bob, from, end, "306",
                     ":" BIN_NAME " 306 bob :You have been marked as being "
                     "away\r\n");
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "ISON bob") == 0, "tc_send failed");
    end = drain(&alice);
    expect_in_window(&alice, from, end, "303 for an AWAY user",
                     ":" BIN_NAME " 303 alice bob :are online\r\n");

    /* More names than fit in one reply. RFC 1459 2.4.3 allows a client to ask
     * about more nicknames than a single 303 can carry, and reply() refuses a
     * 303 with more than REPLY_MAX_MID of them -- so the node must CHUNK rather
     * than drop the overflow. The list below is longer than one reply can hold.
     *
     * "At least two lines" is the property, not an exact count: RFC 1459 leaves
     * the split point to the server, so pinning it would pin an internal
     * constant the RFC does not fix. A node that dropped the overflow would
     * emit exactly one, which is what this catches. */
    {
        char many[512];
        size_t n;
        size_t chunks;

        n = (size_t)snprintf(many, sizeof many, "ISON");
        for (i = 0; i < 7u; i++) {
            n += (size_t)snprintf(many + n, sizeof many - n, " carol");
        }
        for (i = 0; i < 7u; i++) {
            n += (size_t)snprintf(many + n, sizeof many - n, " bob");
        }
        from = open_window(&alice);
        TF_CHECK_MSG(tc_send(&alice.c, many) == 0, "tc_send failed");
        end = drain(&alice);
        chunks = count_in_window(&alice, from, end, " 303 ");
        TF_CHECK_MSG(chunks >= 2u,
                     "a 14-nick ISON produced %zu 303 lines, expected at least 2: "
                     "the overflow was dropped rather than chunked",
                     chunks);
        /* Every nick asked about is in the LAST chunk, which is what proves the
         * overflow was delivered rather than merely not refused. bob is the
         * seventh of the second batch, so he is past any plausible split point. */
        {
            const char *base = tc_buffer(&alice.c);
            const char *last = NULL;

            for (const char *p = base + from; p < base + end; p++) {
                if (strncmp(p, " 303 ", 5) == 0) {
                    last = p;
                }
            }
            TF_CHECK_MSG(last != NULL, "no 303 line was found in the window");
            if (last != NULL) {
                TF_CHECK_MSG(strstr(last, " bob") != NULL &&
                                 strstr(last, " bob") < base + end,
                             "the final 303 chunk is missing bob, so the "
                             "overflow was truncated rather than delivered");
            }
        }
    }

    /* =======================================================================
     * The node's own accounting
     * ==================================================================== */
    /* Read AFTER nf_stop(): the node publishes its counters at shutdown and not
     * before, and server_shutdown() runs first so the numbers describe the node
     * as it actually finished. Waiting for the key before stopping would time
     * out against a node that had done nothing wrong. */
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0");
    TF_CHECK_MSG(nf_expect_u64_ge(&node, "accepted=", g_opened, T_IO_MS) == 0,
                 "the node accepted fewer connections than the test opened (%zu)",
                 g_opened);

    tc_close(&alice.c);
    tc_close(&bob.c);
    tc_close(&carol.c);
    nf_free(&node);
    tf_done("queries");
    return 0;
}
