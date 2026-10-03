/* test_query_surface.c -- the rest of the server-query surface Phase 11 swept:
 * 254 RPL_LUSERCHANNELS, 433 recovery, and PING/PONG token echoing.
 *
 * docs/RFC2812_CONFORMANCE.md, the LUSERS and query sections.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS A FIX HERE AND WHAT IS ONLY EVIDENCE
 * ---------------------------------------------------------------------------
 *   254    a FIX. Phase 11 added it; RFC 2812 3.4.2 requires it whenever the
 *          channel count is non-zero and this node's count is non-zero from the
 *          first JOIN onward.
 *   433    EVIDENCE. The sweep checked whether a client can RECOVER from a
 *          nickname collision -- which is the point of the numeric -- and found
 *          that it can: the connection stays registered, keeps the name it had,
 *          and can immediately take a different one. Having that on the wire
 *          rather than only in the phase report is worth one section.
 *   PING   EVIDENCE. The sweep checked the token echo, because a server that
 *   PONG    answered with its own name would leave every client liveness check
 *          failing while looking healthy.
 *
 * ---------------------------------------------------------------------------
 * 254, AND WHY THE ZERO CASE IS THE FIRST CASE
 * ---------------------------------------------------------------------------
 * RFC 2812 3.4.2 draws the line: "When replying, a server MUST send back
 * RPL_LUSERCLIENT and RPL_LUSERME. The other replies are only sent back if a
 * non-zero count is found for them." So the test is not "is this server's feature
 * set rich" -- it is "is the count zero".
 *
 *   252 RPL_LUSEROP      operators online. This node has none: 258 says so on the
 *                        wire and CHOPER is unconditionally refused.
 *   253 RPL_LUSERUNKNOWN  unknown connections. This node has none: every accepted
 *                        connection is a registered client or a peer link.
 *   254 RPL_LUSERCHANNELS channels formed. NOT zero once anybody has joined, which
 *                        is why this is the one of the three that was missing.
 *
 * So the file asks LUSERS once BEFORE any channel exists -- where a 254 would be a
 * wrong answer, not a superset -- and once after four channels exist, where its
 * absence is a non-conformance a client can see, because it is the line /LUSERS
 * output renders as "channels formed".
 *
 * test_serverinfo.c asserts the zero case too, and it does not have to be changed:
 * that file's LUSERS runs before any channel exists, so both assertions are true of
 * the same behaviour.
 *
 * ---------------------------------------------------------------------------
 * THE PROPERTIES THAT MAKE THESE ASSERTIONS MEAN SOMETHING
 * ---------------------------------------------------------------------------
 *   - EVERY assertion is inside a window delimited by two PONGs; see the header of
 *     test_whois_channels.c for why.
 *   - 254's NUMBER is cross-checked against the number of 322 lines a LIST
 *     produces rather than compared to a literal. Both read server_chan_count(), so
 *     agreeing is a fact about the node and disagreeing is a defect in one of them.
 *     A literal would have to be re-derived every time this file creates a channel,
 *     and getting that wrong produces an assertion that hides bugs.
 *   - 433's RECOVERY is asserted positively: the second NICK is accepted and the
 *     new name is whoisable, and the old holder still holds the old name. A node
 *     that answered 433 by dropping the connection fails at the drain; one that
 *     answered it by silently taking the name fails the last assertion.
 *   - 433's FIELD LIST is asserted whole, including the observation that the IDENT
 *     is unchanged -- NICK sets the nickname and USER set the ident, and RFC 2812
 *     2.3.1 makes them separate fields.
 *   - PONG IS ANSWERED WITH NOTHING, asserted as the ABSENCE of the token the
 *     client sent rather than of the string "PONG": the window necessarily contains
 *     the closing drain's own PONG, so "no PONG here" is not a statement the window
 *     can make.
 *
 * NO sleep() ANYWHERE (6.3): every wait is the select()-driven deadline inside
 * tc_expect(), and every negative assertion is closed by a PING drain.
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

/* RFC 2812 5.1's own sentence for 254, written down rather than read out of the
 * handler: the test is asserting the specification's field list, and reading the
 * expectation out of the implementation would make it agree with whatever the
 * implementation does. */
#define LUSER_CHANNELS_TEXT "channels formed"

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
 * THE WINDOW PRIMITIVE -- identical to test_whois_channels.c's and for the same
 * reason: a bare tc_expect() searches the WHOLE accumulated buffer, so a needle
 * this node has already emitted satisfies the wait before the command under test
 * has been sent.
 * ------------------------------------------------------------------------ */
static unsigned g_drain_seq;

static size_t drain(client_t *cl)
{
    char line[64];
    char needle[96];
    const char *at;

    g_drain_seq++;
    (void)snprintf(line, sizeof line, "PING :q%u", g_drain_seq);
    (void)snprintf(needle, sizeof needle, "PONG %s q%u\r\n", BIN_NAME, g_drain_seq);
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
    char line[128];
    char needle[160];

    (void)snprintf(line, sizeof line, "JOIN %s", channel);
    (void)snprintf(needle, sizeof needle, ":%s 366 %s ", BIN_NAME, cl->nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "tc_send(%s) failed", line);
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0, "no 366 after %s", line);
    (void)drain(cl);
}

int main(void)
{
    nf_node_t node;
    client_t alice, bob;
    size_t from, end;

    if (nf_spawn_binary(&node) != 0) {
        fprintf(stderr, "could not spawn the irc-serve binary\n");
        return 1;
    }
    TF_CHECK_MSG(nf_expect(&node, "loop_running:", T_READY_MS) == 0,
                 "the node never reported its loop armed");

    client_open(&alice, &node, "alice");
    client_open(&bob, &node, "bob");

    /* =======================================================================
     * 1. 254 RPL_LUSERCHANNELS: ABSENT while the count is zero
     * ==================================================================== */
    from = drain(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "LUSERS") == 0, "LUSERS send failed");
    end = drain(&alice);
    /* 255 first, so the reader can see this is a whole LUSERS answer and not an
     * absence in an otherwise empty one. Two clients are on the node at this
     * point and no channels exist. */
    expect_in_window(&alice, from, end, "255 with no channels",
                     ":" BIN_NAME " 255 alice :I have 2 clients and 0 servers\r\n");
    expect_absent_in_window(&alice, from, end, "LUSERS before any channel", " 254 ");

    /* =======================================================================
     * 2. FOUR CHANNELS, AND 254 IS NO LONGER OPTIONAL
     * ==================================================================== */
    client_join(&alice, "#alpha");
    client_join(&bob, "#alpha");
    client_join(&alice, "#beta");
    client_join(&alice, "#gamma");
    client_join(&bob, "#delta");
    {
        size_t from_list;
        size_t end_list;
        size_t listed;
        unsigned long long formed = 0;
        const char *at254;

        from_list = drain(&alice);
        TF_CHECK_MSG(tc_send(&alice.c, "LIST") == 0, "LIST send failed");
        end_list = drain(&alice);
        listed = count_in_window(&alice, from_list, end_list, ":" BIN_NAME " 322 ");
        TF_CHECK_MSG(listed == 4u,
                     "LIST reported %zu channels where 4 were just joined, so the 254 "
                     "cross-check below would compare against the wrong number",
                     listed);

        from = drain(&alice);
        TF_CHECK_MSG(tc_send(&alice.c, "LUSERS") == 0, "LUSERS send failed");
        end = drain(&alice);
        at254 = strstr(tc_buffer(&alice.c) + from, ":" BIN_NAME " 254 alice ");
        TF_CHECK_MSG(at254 != NULL,
                     "LUSERS did not report 254 RPL_LUSERCHANNELS while %zu channels "
                     "exist. RFC 2812 3.4.2 requires it whenever the count is "
                     "non-zero, and the zero case is asserted in section 1.",
                     listed);
        if (at254 != NULL) {
            /* The <integer> is a MIDDLE parameter and the sentence is the trailing
             * one, so it is read positionally rather than as the first token of a
             * sscanf %s. The scanset stops at CR so it cannot run past the end of
             * the line, and it is compared as a STRING because the sentence is two
             * words and a plain %s would stop at the first and report a difference
             * that is not one.
             *
             * sscanf is in its own statement rather than inside the TF_CHECK_MSG
             * condition, so the diagnostic that names the offending line names the
             * scan and not the assertion. */
            char trailing[64];
            int fields;

            trailing[0] = '\0';
            fields = sscanf(at254, " %*s %*s %*s %llu :%63[^\r\n]", &formed,
                            trailing);
            TF_CHECK_MSG(fields == 2,
                         "254 is not <integer> :%s; the scan took %d field(s) from "
                         "\"%.80s\"",
                         LUSER_CHANNELS_TEXT, fields, at254);
            TF_CHECK_MSG(formed == (unsigned long long)listed,
                         "254 says %llu channels formed and LIST listed %zu: on this "
                         "node both read server_chan_count(), so they cannot differ",
                         formed, listed);
            TF_CHECK_MSG(strcmp(trailing, LUSER_CHANNELS_TEXT) == 0,
                         "254's trailing text is \"%s\", not \"%s\"", trailing,
                         LUSER_CHANNELS_TEXT);
        }
    }

    /* =======================================================================
     * 3. 433 ON A COLLISION, AND WHETHER A CLIENT CAN RECOVER
     * ==================================================================== */
    /* RFC 2812 3.1.2 makes 433 the answer to a nick already in use. The recovery
     * is the point: the sender keeps the name it HAD, is still registered, and can
     * immediately take a different one. A node that answered 433 by dropping the
     * connection would leave every client library with a reconnect loop; one that
     * answered it by silently taking the name would be two users with one
     * nickname. */
    from = drain(&bob);
    TF_CHECK_MSG(tc_send(&bob.c, "NICK alice") == 0, "the colliding NICK failed");
    end = drain(&bob);
    expect_in_window(&bob, from, end, "433 for a nickname in use",
                     ":" BIN_NAME " 433 bob alice :Nickname is already in use\r\n");
    /* STILL REGISTERED. The drain below succeeding IS the evidence that 433 did not
     * close the connection; if it had, the wait would time out against a socket the
     * node had already dropped rather than report a protocol failure. */
    TF_CHECK_MSG(tc_send(&bob.c, "NICK bobby") == 0, "the second NICK failed");
    (void)drain(&bob);
    from = drain(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "WHOIS bobby") == 0, "WHOIS send failed");
    end = drain(&alice);
    /* THE IDENT IS STILL `bob`, and that is RFC 2812 2.3.1 rather than an
     * oversight: NICK changes the nickname and USER set the ident, and the two are
     * separate fields a client may set to different values. The realname is
     * `Real bob` for the same reason. Asserted rather than assumed, because a node
     * that let a NICK rewrite the ident would be showing a client an identity it
     * never chose. */
    expect_in_window(&alice, from, end, "311 after the recovery NICK",
                     ":" BIN_NAME " 311 alice bobby bob 127.0.0.1 * :Real bob\r\n");
    /* AND THE LOSER DID NOT TAKE THE NAME, which is what makes 433 a refusal
     * rather than a pre-emption. The <target> is the asking connection's CURRENT
     * nick, which is bobby by now: 433's second parameter is the name that was
     * REFUSED, and the target field is whoever was refused. */
    from = drain(&bob);
    TF_CHECK_MSG(tc_send(&bob.c, "WHOIS alice") == 0, "WHOIS send failed");
    end = drain(&bob);
    expect_in_window(&bob, from, end, "311 for the incumbent nick",
                     ":" BIN_NAME " 311 bobby alice alice 127.0.0.1 * :Real alice\r\n");

    /* =======================================================================
     * 4. PING/PONG TOKEN ECHOING
     * ==================================================================== */
    /* The token is echoed verbatim, which is what a client's own liveness check
     * compares against, so a node answering with the server name would leave every
     * such check failing while looking healthy. A token that cannot be mistaken for
     * the server name. */
    from = drain(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "PING :unique-token-4711") == 0, "PING failed");
    end = drain(&alice);
    expect_in_window(&alice, from, end, "PONG echoes the token",
                     ":" BIN_NAME " PONG " BIN_NAME " unique-token-4711\r\n");
    /* A PING with NO argument is answered with the server name (RFC 1459 2.4),
     * which is the one case where the server name IS the right answer -- and it is
     * asserted separately so that the token case cannot be satisfied by a node that
     * always answers with the name. */
    from = drain(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "PING") == 0, "bare PING failed");
    end = drain(&alice);
    expect_in_window(&alice, from, end, "PONG for a bare PING",
                     ":" BIN_NAME " PONG " BIN_NAME " " BIN_NAME "\r\n");
    /* A PONG is answered with NOTHING. Answering a PONG with a PONG is how a naive
     * implementation starts a storm. The needle is the TOKEN rather than the string
     * "PONG" because this window necessarily contains the closing drain's own PONG
     * -- that is what closes it -- so "no PONG here" is not a statement the window
     * can make. */
    from = drain(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "PONG :server-token") == 0, "PONG failed");
    end = drain(&alice);
    expect_absent_in_window(&alice, from, end, "a client PONG", "server-token");

    /* =======================================================================
     * The node's own accounting
     * ==================================================================== */
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0");

    tc_close(&alice.c);
    tc_close(&bob.c);
    nf_free(&node);
    tf_done("query_surface");
    return 0;
}
