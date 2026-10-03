/* test_invite.c -- INVITE on the wire, against the real binary.
 *
 * docs/SERVER_DESIGN.md 4.2 (INVITE, Phase 7), RFC 2812 3.3.6, 4.4 (341, 442,
 * 482, 401, 403) and 3 (numerics go to one client and are never relayed).
 *
 * ---------------------------------------------------------------------------
 * WHAT INVITE IS ACTUALLY TESTING, since it looks like a one-numeric command
 * ---------------------------------------------------------------------------
 * An INVITE produces a 341 to the inviter and a *different line* to the invitee,
 * addressed to one user and prefixed with the inviter's hostmask. That shape is
 * what makes the test worth writing, and each half has a failure mode the other
 * does not catch:
 *
 *   - A 341 sent to the INVITEE instead of the inviter is a server that tells
 *     the wrong client it did something. Asserted by checking carol, who is
 *     connected and watching, saw NOTHING -- a presence-only check on alice's
 *     socket would pass a node that also told carol.
 *   - An INVITE sent to every channel member is a server that broadcast a
 *     private message, which is the single worst thing an INVITE can do. The
 *     invitee in this file is deliberately NOT on the channel, and the members
 *     who ARE on it (alice herself, carol after she joins) are checked for
 *     absence.
 *   - The two clients' sockets are checked SEPARATELY, because the one-line
 *     mistake is putting both replies on one of them.
 *
 * ---------------------------------------------------------------------------
 * WHY BOTH PARAMETER ORDERS ARE EXERCISED
 * ---------------------------------------------------------------------------
 * RFC 1459 2.4.7 gave INVITE `<channel> <nick>` and RFC 2812 3.3.6 gives it
 * `<nick> <channel>`. Both are in the field. A node that implements only one
 * 401s half the clients that use it, so both are accepted, and the case that
 * tells the two readings apart -- `INVITE #i bob` against `INVITE bob #i` -- is
 * the assertion. See chan_verbs.c's handler for why the name rather than the
 * position decides.
 *
 * ---------------------------------------------------------------------------
 * NO sleep() ANYWHERE (6.3)
 * ---------------------------------------------------------------------------
 * Every wait is a select()-driven deadline inside tc_expect(), and every
 * "nothing was said" assertion is scoped to a window closed by a PING drain
 * rather than by a wait. A bare tc_expect() searches the WHOLE accumulated
 * buffer, so a second ` 341 bob ` would match the first and return instantly and
 * the wait that was supposed to cover the command under test would never
 * happen; the window primitive below is the fix, and it is the same one
 * test_queries.c and test_messaging.c use for the same reason.
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

/* The channel the invitee is NOT on, and the one everybody else is. Two
 * channels rather than one so that "the INVITE named the right channel" is
 * distinguishable from "the INVITE named a channel". */
#define CHAN "#INVITE"
#define OTHER "#OTHER"

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
    (void)snprintf(line, sizeof line, "USER %s 0 * :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "USER send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, " 001 ", T_IO_MS) == 0, "%s did not register",
                 nick);
    /* Drain the welcome burst so a later window does not start inside the MOTD
     * and inherit bytes the command under test did not produce. */
    TF_CHECK_MSG(tc_send(&cl->c, "PING :reg-drain") == 0, "PING send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, "PONG ", T_IO_MS) == 0,
                 "%s: no PONG after registration", nick);
}

static void client_join(client_t *cl, const char *channel)
{
    char line[128];
    char needle[160];

    (void)snprintf(line, sizeof line, "JOIN %s", channel);
    (void)snprintf(needle, sizeof needle, ":%s 366 %s ", BIN_NAME, cl->nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "tc_send(%s) failed", line);
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0,
                 "%s: no 366 after JOIN %s", cl->nick, channel);
}

/* ---------------------------------------------------------------------------
 * The window primitive: a [from, end) range of the accumulated buffer, opened
 * by a PING before the command under test and closed by another after it. A
 * connection's answers are written in order, so the closing PONG proves every
 * earlier answer is already in the buffer -- which is what makes "nothing
 * arrived" a fact about the node rather than a guess about its speed.
 * ------------------------------------------------------------------------- */
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

/* `want` must appear in the window, terminated, at a line boundary. The CRLF
 * proves the line is terminated on the wire rather than being a prefix of a
 * longer one; the boundary check stops a match that is the SUFFIX of some other
 * line from passing, which is not hypothetical here -- this node prints a 329
 * with a ten-digit creation timestamp on every JOIN, so a bare " 366 " needle
 * matches inside it. */
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

/* `needle` must NOT appear anywhere in the window, and the window must have
 * been closed -- an unclosed window makes "did not appear" a statement about a
 * buffer the node may not have finished writing to, which is the race that lets
 * "assert nothing arrived" tests silently pass. */
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

int main(void)
{
    nf_node_t node;
    client_t alice, bob, carol;
    size_t from, end;
    char want[512];

    if (nf_spawn_binary(&node) != 0) {
        fprintf(stderr, "could not spawn the irc-serve binary\n");
        return 1;
    }
    TF_CHECK_MSG(nf_expect(&node, "loop_running:", T_READY_MS) == 0,
                 "the node never reported its loop armed");

    client_open(&alice, &node, "alice");
    client_open(&bob, &node, "bob");
    client_open(&carol, &node, "carol");
    /* alice CREATES the channel, so she holds +o on it -- which is the only
     * reason 482 is reachable below at all, and 7/Phase 4's own argument for
     * the creator's privilege applies unchanged. */
    client_join(&alice, CHAN);
    client_join(&carol, OTHER);

    /* =======================================================================
     * 1. The happy path, RFC 2812 order: 341 to the inviter, INVITE to the
     *    invitee, and NOTHING to anybody else
     * ==================================================================== */
    /* The two OBSERVER windows are opened BEFORE the command, and that order
     * is load-bearing rather than tidiness. A window is a range of one client's
     * buffer, so a mark taken after the command would start past the reply the
     * test is looking for and every assertion about it would be a statement
     * about a range the reply was never in. bob's and carol's marks are taken
     * first, so both ranges begin before the INVITE exists at all. */
    size_t bob_from = mark(&bob);
    size_t carol_from = mark(&carol);
    size_t alice_from = mark(&alice);

    TF_CHECK_MSG(tc_send(&alice.c, "INVITE bob " CHAN) == 0, "tc_send failed");
    from = mark(&alice);
    end = from;

    /* 341's shape is RFC 2812 3.3.6's: <channel> and <nick> are MIDDLE
     * parameters and the sentence is the trailing one, so a client reading by
     * position can tell the channel from the nickname. Both bytes are asserted,
     * because a 341 that carried the nickname in the trailing text would still
     * read as English. */
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 341 alice #INVITE bob :alice has invited you to "
                   "channel #INVITE\r\n");
    expect_in_window(&alice, alice_from, from, "341 for the inviter", want);

    /* The invitee gets an INVITE, prefixed with the INVITER's hostmask (RFC 2812
     * 3.3.3), and named by the invitee's own chosen spelling. bob was never on
     * the channel, so this proves the verb addresses a person rather than
     * requiring membership of the target. */
    {
        size_t bob_end = mark(&bob);

        (void)snprintf(want, sizeof want,
                       ":alice!alice@" OBSERVED_HOST " INVITE bob #INVITE\r\n");
        expect_in_window(&bob, bob_from, bob_end, "INVITE for the invitee", want);
        /* And it is a command, not a numeric: bob was told nothing else. */
        expect_absent_in_window(&bob, bob_from, bob_end, "the invitee's window",
                                " 341 ");
    }

    /* carol is connected, is on a different channel, and saw nothing. This is
     * the assertion a presence-check on alice's socket cannot make: a node that
     * broadcast the 341 or the INVITE to everyone would pass every check above. */
    {
        size_t carol_end = mark(&carol);

        expect_absent_in_window(&carol, carol_from, carol_end,
                                "the uninvolved client's window", "INVITE");
        expect_absent_in_window(&carol, carol_from, carol_end,
                                "the uninvolved client's window", " 341 ");
    }

    /* =======================================================================
     * 2. RFC 1459's <channel> <nick> order is accepted too
     * ==================================================================== */
    carol_from = mark(&carol);
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "INVITE " CHAN " carol") == 0, "tc_send failed");
    end = mark(&alice);
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 341 alice #INVITE carol :alice has invited you "
                   "to channel #INVITE\r\n");
    expect_in_window(&alice, from, end, "341 in RFC 1459 parameter order", want);
    {
        size_t carol_end = mark(&carol);

        (void)snprintf(want, sizeof want,
                       ":alice!alice@" OBSERVED_HOST " INVITE carol #INVITE\r\n");
        expect_in_window(&carol, carol_from, carol_end,
                         "INVITE in RFC 1459 parameter order", want);
    }

    /* =======================================================================
     * 3. Arity, and a nickname that is not connected
     * ==================================================================== */
    /* Arity in both directions, and 461 rather than 462: 461 is what every other
     * handler in this node answers for a wrong-arity line, and 4.4 lists it.
     *
     * `INVITE` before the text is 5.2's `<command>` field, which 461's RFC field
     * list names and which reply_refused() renders from the command word the
     * handler already holds. It is asserted because a client attributing the
     * refusal to a verb needs it, and because a node that dropped it would pass
     * a needle that stopped at `461 alice`. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "INVITE bob") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "461 for one parameter",
                     ":" BIN_NAME " 461 alice INVITE :Not enough parameters\r\n");

    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "INVITE bob " CHAN " extra") == 0,
                 "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "461 for three parameters",
                     ":" BIN_NAME " 461 alice INVITE :Not enough parameters\r\n");

    /* A nickname this node has never heard of is 401, and NO 341 follows. The
     * absence is the half with teeth: a node that answered every INVITE with a
     * 341 regardless of the target would pass the 401 check. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "INVITE ghost " CHAN) == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "401 for an unknown nickname",
                     ":" BIN_NAME " 401 alice ghost :No such nick/channel\r\n");
    expect_absent_in_window(&alice, from, end, "the unknown-nickname INVITE",
                            " 341 ");

    /* A CHANNEL name in the nickname position is 401 too. An invite names a
     * person, and a node that treated a channel as an invitee would resolve the
     * name and then have no conn_t to send an INVITE to -- the check is what
     * stops that path existing. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "INVITE " CHAN " " CHAN) == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "401 for a channel in the nickname slot",
                     ":" BIN_NAME " 401 alice #INVITE :No such nick/channel\r\n");

    /* A channel this node does not hold is 442, and the numeral is worth a
     * paragraph because the intuitive answer is 403. INVITE resolves its channel
     * through the same resolve_joined() every other channel verb uses, and that
     * function answers 442 for a channel the node has never heard of --
     * deliberately, for the reason its own comment gives: "No such channel"
     * would send a client looking for a channel that may well exist somewhere
     * it cannot see, while "you're not on that channel" is the actionable
     * answer. One resolution primitive for the whole channel surface is worth
     * more than one verb having a marginally more precise numeral, and the
     * consistent answer is the one a client can parse without a special case.
     * 403 is still what a malformed channel NAME gets, and the check below
     * covers that half. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "INVITE bob #nosuch") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "442 for a channel that does not exist",
                     ":" BIN_NAME " 442 alice #NOSUCH :You're not on that "
                     "channel\r\n");
    expect_absent_in_window(&alice, from, end, "the missing-channel INVITE", " 341 ");

    /* A name that is not a channel name at all is 403, from the same primitive.
     * The channel position is the second parameter here, so the malformed name
     * has to go there or this would be testing the 461 above. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "INVITE bob not#a#channel") == 0,
                 "tc_send failed");
    end = mark(&alice);
    TF_CHECK_MSG(strstr(tc_buffer(&alice.c) + from, " 403 alice ") != NULL,
                 "a malformed channel name was not refused with 403");
    expect_absent_in_window(&alice, from, end, "the malformed-channel INVITE",
                            " 341 ");

    /* =======================================================================
     * 4. 442 and 482 -- the two refusals, and they are different complaints
     * ==================================================================== */
    /* carol is on #OTHER and not on the channel the invite names, so this is
     * 442: "you are not on that channel". It is checked BEFORE 482, and that
     * order is load-bearing -- a client that is neither on the channel nor an
     * operator of it must be told which of the two is wrong, and a node that
     * checked privilege first would answer 482 about a channel the client has
     * no standing in at all. */
    from = mark(&carol);
    TF_CHECK_MSG(tc_send(&carol.c, "INVITE bob " CHAN) == 0, "tc_send failed");
    end = mark(&carol);
    expect_in_window(&carol, from, end, "442 for an inviter off the channel",
                     ":" BIN_NAME " 442 carol #INVITE :You're not on that "
                     "channel\r\n");
    expect_absent_in_window(&carol, from, end, "the 442 window", " 482 ");

    /* Now carol IS on the channel and still holds no +o, so the same line is
     * 482. RFC 2812 3.3.6: "Only channel operators may invite new users to a
     * channel." 4.4 lists 482 and it is the same numeric KICK and MODE use, so
     * one phrase means one thing across the channel surface. bob's window is
     * opened FIRST, for the reason section 1 gives: a mark taken after the
     * command would begin past a reply that had already arrived, and "bob saw
     * nothing" would then be a statement about the wrong range. */
    client_join(&carol, CHAN);
    bob_from = mark(&bob);
    from = mark(&carol);
    TF_CHECK_MSG(tc_send(&carol.c, "INVITE bob " CHAN) == 0, "tc_send failed");
    end = mark(&carol);
    expect_in_window(&carol, from, end, "482 for a non-operator",
                     ":" BIN_NAME " 482 carol #INVITE :You're not a channel "
                     "operator\r\n");
    expect_absent_in_window(&carol, from, end, "the 482 window", " 441 ");
    /* bob was not told anything, because the refusal happened before the
     * target was resolved. An INVITE emitted on a refusal is the one thing that
     * would make this verb a broadcast. */
    {
        size_t bob_end = mark(&bob);

        expect_absent_in_window(&bob, bob_from, bob_end,
                                "bob after a refused INVITE", "INVITE");
        expect_absent_in_window(&bob, bob_from, bob_end,
                                "bob after a refused INVITE", " 341 ");
    }

    /* =======================================================================
     * 5. An invite into a channel the inviter is on but the target already
     *    belongs to is still an invite, and is not refused
     * ==================================================================== */
    /* alice invites carol, who is already on the channel. RFC 2812 3.3.6 does
     * not describe suppressing the invitation for somebody already there, and a
     * conditional here would be a behaviour a client could depend on and this
     * node could not point at. The channel IS still sent, so the invitee is
     * never left guessing which channel it is about. */
    carol_from = mark(&carol);
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "INVITE carol " CHAN) == 0, "tc_send failed");
    end = mark(&alice);
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 341 alice #INVITE carol :alice has invited you "
                   "to channel #INVITE\r\n");
    expect_in_window(&alice, from, end, "341 for an existing member", want);
    {
        size_t carol_end = mark(&carol);

        (void)snprintf(want, sizeof want,
                       ":alice!alice@" OBSERVED_HOST " INVITE carol #INVITE\r\n");
        expect_in_window(&carol, carol_from, carol_end,
                         "INVITE to an existing member", want);
    }

    /* =======================================================================
     * The node's own accounting
     * ==================================================================== */
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
    tf_done("invite");
    return 0;
}
