/* test_userhost.c -- USERHOST on the wire, against the real binary.
 *
 * docs/SERVER_DESIGN.md 4.2 (USERHOST, Phase 7) and RFC 2812 3.3.4. 4.4's
 * numeric list has a hole where 302 belongs; see msg_verbs.c's handle_userhost()
 * for why the RFC numeric is used anyway, which is the same argument Phase 5 made
 * for 301, 303 and 417.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS WORTH ASSERTING ABOUT A COMMAND THAT REPEATS A NAME AND A FLAG
 * ---------------------------------------------------------------------------
 * A 302 is `<nick>+<user>@<host>` for somebody here and `<nick>*` for somebody
 * who is not, so the format has four things that can each be wrong independently
 * and a test that only looks for a substring passes a node that got three of the
 * four right:
 *
 *   - the FLAG. '+' and '*' are the entire difference between "online" and
 *     "not", and a node that always emitted '+' would satisfy every presence
 *     check in this file. The offline case is asserted on its own exact line.
 *   - the HOST, which must be the OBSERVED one. Every client in this file
 *     ASSERTS a hostname in USER, so a node that stored the assertion would
 *     report a host the connection never came from. That is asserted by absence
 *     as well as by presence, exactly as test_queries.c does for 352 and 311.
 *   - the USER field, which is c->user -- the first USER parameter -- and is a
 *     different field from the nickname, so a node that swapped them would
 *     produce a plausible-looking line.
 *   - the fact that the offline answer is a `<nick>*` line rather than SILENCE.
 *     There is no 401 in USERHOST's reply set, so a node that reported nothing
 *     for an unknown nickname would leave a client unable to tell "not here"
 *     from "command dropped", which is the failure mode 4.4's numerics exist to
 *     prevent.
 *
 * ---------------------------------------------------------------------------
 * THE `*` PREFIX IS ASSERTED AS *NOT* MATCHING, AND THAT IS THE POINT
 * ---------------------------------------------------------------------------
 * RFC 2812 3.3.4: a parameter beginning with '*' matches only users who have set
 * a user mode to be invisible. This node has no user modes, so no user is
 * invisible, so `USERHOST *bob` must NOT come back with the '+' form. A node
 * that stripped the '*' and did an ordinary lookup would answer '+' and be
 * claiming a user is invisible -- a fact it has no way of knowing and must never
 * invent. See msg_verbs.c for the argument that this is the RFC's own '*'
 * marker rather than a special case.
 *
 * NO sleep() ANYWHERE (6.3): every wait is a select()-driven deadline inside
 * tc_expect(), and every negative assertion is scoped to a window closed by a
 * PING drain -- the window primitive below, and the reason for it is that a bare
 * tc_expect() searches the whole accumulated buffer, so a second ` 302 alice `
 * would match the first and return instantly.
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

static unsigned g_drain_seq;

static size_t mark(client_t *cl)
{
    char line[64];
    char needle[96];
    const char *at;

    g_drain_seq++;
    (void)snprintf(line, sizeof line, "PING :m%u", g_drain_seq);
    (void)snprintf(needle, sizeof needle, "PONG %s m%u\r\n", BIN_NAME,
                   g_drain_seq);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "mark PING send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0, "no PONG for %s", line);
    at = strstr(tc_buffer(&cl->c), needle);
    TF_CHECK_MSG(at != NULL, "the mark PONG vanished from the buffer");
    return (at != NULL) ? (size_t)(at - tc_buffer(&cl->c)) : 0u;
}

static void expect_in_window(client_t *cl, size_t from, size_t end,
                             const char *what, const char *want)
{
    const char *base = tc_buffer(&cl->c);
    const char *at;

    TF_CHECK_MSG(end > from,
                 "%s: the window was never closed (from=%zu end=%zu)", what, from,
                 end);
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
                 "%s: \"%s\" appeared %zu time(s) in the window and must not have "
                 "appeared at all",
                 what, needle, count);
}

/* How many times `needle` occurs in the window. Scoped for the same reason the
 * two helpers above are: a count over the whole buffer would include every
 * earlier USERHOST, so "three names produced three 302s" would then be true of a
 * node that produced none. */
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

int main(void)
{
    nf_node_t node;
    client_t alice, bob;
    size_t from, end;
    char want[256];

    if (nf_spawn_binary(&node) != 0) {
        fprintf(stderr, "could not spawn the irc-serve binary\n");
        return 1;
    }
    TF_CHECK_MSG(nf_expect(&node, "loop_running:", T_READY_MS) == 0,
                 "the node never reported its loop armed");

    client_open(&alice, &node, "alice");
    client_open(&bob, &node, "bob");

    /* =======================================================================
     * 1. A connected user: <nick>+<user>@<observed host>, and the value
     *    repeated in both of 302's positions
     * ==================================================================== */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "USERHOST bob") == 0, "tc_send failed");
    end = mark(&alice);

    /* 302's wire form carries the value TWICE -- once as a middle parameter and
     * once as the last parameter. The RFC's notation writes the second as
     * `:<reply>`, and this line has NO colon in front of it, which is not a
     * typo in the test: 3.2's formatter colons a trailing value only when it has
     * to (empty, leading ':', or holding a separator) and a
     * `<nick>+<user>@<host>` needs none of those. The last parameter is the
     * trailing one whether or not it was colonned (RFC 1459 2.3.1), so both
     * parameters are the answer, and a client reading it by position -- which is
     * every client -- sees the right thing. A 302 carrying the value ONCE would
     * parse as a client and a text where the text is the answer, and would
     * render the requesting nickname instead of it. See msg_verbs.c's
     * handle_userhost() for the same point at the source. */
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 302 alice bob+bob@" OBSERVED_HOST " bob+bob@"
                   OBSERVED_HOST "\r\n");
    expect_in_window(&alice, from, end, "302 for a connected user", want);
    /* EXACTLY ONE 302, for one parameter. A node that answered a single-name
     * query with a 302 per registry entry would satisfy the line above. */
    TF_CHECK_MSG(count_in_window(&alice, from, end, " 302 ") == 1,
                 "USERHOST bob produced %zu 302 lines, expected exactly 1",
                 count_in_window(&alice, from, end, " 302 "));
    /* The host is the OBSERVED one. Every client here CLAIMED one in USER, so the
     * claimed name must appear nowhere in the window -- not in this answer and
     * not in any other, which is the assertion test_queries.c makes for 352 and
     * 311. */
    expect_absent_in_window(&alice, from, end, "the USERHOST window",
                            CLAIMED_HOST);

    /* =======================================================================
     * 2. A nickname nobody holds: <nick>*, and STILL a 302
     * ==================================================================== */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "USERHOST ghost") == 0, "tc_send failed");
    end = mark(&alice);
    /* The '*' marker, and the name repeated so the client can match the answer
     * to the question. Silence would be indistinguishable from a dropped
     * command, which is the failure 4.4's numerics exist to prevent. The value
     * is uncolonned for the reason section 1 gives -- "ghost*" needs no colon. */
    (void)snprintf(want, sizeof want, ":" BIN_NAME " 302 alice ghost* ghost*\r\n");
    expect_in_window(&alice, from, end, "302 for an absent nickname", want);
    /* No 401. There is no numeric for "that user is not connected" in this
     * reply set, for the same reason 303 omits an offline nickname rather than
     * erroring on it: a set query answered with an error per entry is noise. */
    expect_absent_in_window(&alice, from, end, "the absent-nickname USERHOST",
                            " 401 ");

    /* =======================================================================
     * 3. Several names in one command: one 302 per name, in order
     * ==================================================================== */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "USERHOST bob ghost1 alice ghost2") == 0,
                 "tc_send failed");
    end = mark(&alice);
    /* The COUNT is the load-bearing part of this one. A node that answered a
     * multi-name query with a single 302 carrying everybody would satisfy every
     * individual line assertion below, and a client that reads one 302 per
     * parameter would silently lose the rest. */
    TF_CHECK_MSG(count_in_window(&alice, from, end, " 302 ") == 4,
                 "a four-name USERHOST produced %zu 302 lines, expected exactly "
                 "4 (one per name)",
                 count_in_window(&alice, from, end, " 302 "));
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 302 alice bob+bob@" OBSERVED_HOST " bob+bob@"
                   OBSERVED_HOST "\r\n");
    expect_in_window(&alice, from, end, "302 for bob in the mixed query", want);
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 302 alice ghost1* ghost1*\r\n");
    expect_in_window(&alice, from, end, "302 for ghost1 in the mixed query", want);
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 302 alice alice+alice@" OBSERVED_HOST
                   " alice+alice@" OBSERVED_HOST "\r\n");
    expect_in_window(&alice, from, end, "302 for alice in the mixed query", want);
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 302 alice ghost2* ghost2*\r\n");
    expect_in_window(&alice, from, end, "302 for ghost2 in the mixed query", want);
    expect_absent_in_window(&alice, from, end, "the mixed USERHOST", " 401 ");

    /* Case folding. 2.1 makes nicknames case-insensitive (RFC 2812 2.3.1) and
     * the fold is the registry's, so a USERHOST that 404'd -- or starred -- a
     * differently-cased spelling of a connected user would be refusing somebody
     * who is demonstrably there. The DISPLAYED case is the user's own, so the
     * answer carries `bob` and not `BOB`. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "USERHOST BOB") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "302 for a differently-cased nickname",
                     ":" BIN_NAME " 302 alice bob+bob@" OBSERVED_HOST
                     " bob+bob@" OBSERVED_HOST "\r\n");

    /* An AWAY user is still HERE. USERHOST reports presence, and answering '*'
     * for an away user would tell a monitoring client that a connected user is
     * gone -- the same defect test_queries.c asserts against for ISON. */
    from = mark(&bob);
    TF_CHECK_MSG(tc_send(&bob.c, "AWAY :brb") == 0, "tc_send failed");
    end = mark(&bob);
    TF_CHECK_MSG(strstr(tc_buffer(&bob.c) + from, " 306 bob ") != NULL,
                 "bob's AWAY was not acknowledged, so the next assertion would "
                 "be about nothing");
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "USERHOST bob") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "302 for an AWAY user",
                     ":" BIN_NAME " 302 alice bob+bob@" OBSERVED_HOST
                     " bob+bob@" OBSERVED_HOST "\r\n");

    /* =======================================================================
     * 4. The `*` invisibility prefix does NOT match a visible user
     * ==================================================================== */
    /* This node has no user modes -- 004 advertises "i" and MODE evaluates none
     * of it -- so no user is invisible and `*bob` must come back with the '*'
     * marker. A node that treated the '*' as decoration and did an ordinary
     * lookup would answer '+' here, and would be claiming a fact it cannot know.
     */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "USERHOST *bob") == 0, "tc_send failed");
    end = mark(&alice);
    (void)snprintf(want, sizeof want, ":" BIN_NAME " 302 alice bob* bob*\r\n");
    expect_in_window(&alice, from, end, "302 for `USERHOST *bob`", want);
    /* The converse, stated as an absence so a node that emitted BOTH forms is
     * caught: the '+' answer for bob must appear nowhere in this window. */
    expect_absent_in_window(&alice, from, end, "`USERHOST *bob`",
                            "bob+bob@" OBSERVED_HOST);

    /* =======================================================================
     * 5. Arity
     * ==================================================================== */
    /* Bare USERHOST is 461 rather than an empty answer. There is no default
     * name set: RFC 2812 3.3.4's <nickname> is mandatory, and answering an
     * omitted argument with "nobody" would be inventing a question the client
     * did not ask.
     *
     * `USERHOST` is 5.2's `<command>` field, asserted so that "461 arrived" and
     * "461 named the verb" are the same check: a needle of `461 alice :Not
     * enough` would pass against a node that dropped the field. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "USERHOST") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "461 for a bare USERHOST",
                     ":" BIN_NAME " 461 alice USERHOST :Not enough "
                     "parameters\r\n");
    TF_CHECK_MSG(count_in_window(&alice, from, end, " 302 ") == 0,
                 "a bare USERHOST produced %zu 302 lines, expected none",
                 count_in_window(&alice, from, end, " 302 "));

    /* An empty trailing parameter -- `USERHOST :` -- parses to one empty
     * parameter, which is a question about a nickname called "". It is answered
     * with the bare '*' marker rather than refused, and the reason is in the
     * handler: the answer is never empty, because an empty middle parameter is
     * a value 3.2's formatter REFUSES rather than reshapes, and a 302 whose
     * answer could not be rendered would be a refusal counted on
     * n_reply_refused -- the counter reply.c calls a bug report. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "USERHOST :") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "302 for an empty nickname",
                     ":" BIN_NAME " 302 alice * *\r\n");

    /* =======================================================================
     * The node's own accounting
     * ==================================================================== */
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    /* reply_refused must be 0, and this is the test that would notice: the empty
     * parameter above is the one line whose 302 could not be rendered if the
     * handler passed an empty middle parameter through. */
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0");
    TF_CHECK_MSG(nf_expect_u64_ge(&node, "accepted=", g_opened, T_IO_MS) == 0,
                 "the node accepted fewer connections than the test opened (%zu)",
                 g_opened);

    tc_close(&alice.c);
    tc_close(&bob.c);
    nf_free(&node);
    tf_done("userhost");
    return 0;
}
