/* test_banlist.c -- `MODE <channel> +b` as a QUERY, and a full list refused.
 *
 * docs/RFC2812_CONFORMANCE.md, the ban-list section: Phase 11 added 367
 * RPL_BANLIST / 368 RPL_ENDOFBANLIST, corrected the ban-list-full refusal from 696
 * to RFC 2812's 478, and made the CHAN_MAX_BANS bound in channel.h real. This file
 * is the proof of all three on the wire.
 *
 * ---------------------------------------------------------------------------
 * THE DEFECT, AND WHY IT IS NOT COSMETIC
 * ---------------------------------------------------------------------------
 * RFC 2812 3.3.2 defines the ban list as a query: "If the <modestring> parameter
 * is given with a list of mode arguments, then a list of mode arguments is
 * returned for channel modes b, e and I." So
 *
 *     MODE #chan +b           -> one 367 per mask, then 368
 *
 * with no mask, and the absent mask IS the signal. This node answered that form
 * with 461 ERR_NEEDMOREPARAMS -- a refusal that told the client its own question
 * was malformed.
 *
 * irssi, weechat and hexchat all send `MODE <channel> b` when a window opens,
 * precisely so the client's ban list is populated before the user touches it. A
 * node that answers 461 leaves the client showing an error in a status window and
 * an EMPTY ban list on a channel where this node is enforcing bans perfectly
 * well. The ban feature worked and was unreadable, which is the same failure
 * Phase 5 named for 301: an away state no client can see is not an away state.
 *
 * ---------------------------------------------------------------------------
 * THE TWO NUMERICS' FIELD LISTS, ASSERTED AS WRITTEN DOWN
 * ---------------------------------------------------------------------------
 *   367 RPL_BANLIST       "<channel> <banmask>"
 *   368 RPL_ENDOFBANLIST  "<channel> :End of channel ban list"
 *   478 ERR_BANLISTFULL   "<channel> <char> :Channel list is full"
 *
 * So 367 has NO trailing field, 478 names the mode LETTER as well as the channel,
 * and 368 has one middle parameter and a sentence. Each is asserted as a whole
 * line rather than as a code plus a substring, because a node that got the arity
 * wrong would satisfy any search for the code.
 *
 * ---------------------------------------------------------------------------
 * THE PROPERTIES THAT MAKE THESE ASSERTIONS MEAN SOMETHING
 * ---------------------------------------------------------------------------
 *   - EVERY assertion is inside a window delimited by two PONGs; see the header of
 *     test_whois_channels.c for why, which is the same reason and the same
 *     primitive.
 *   - 367's COUNT is asserted, not just its presence. A loop that emitted one mask
 *     regardless of how many exist satisfies every presence check and shows a
 *     client one ban on a channel with two.
 *   - 368 comes AFTER every 367, checked as a position rather than a presence,
 *     because a client that stops reading at 368 loses the tail of the list.
 *   - THE LIST IS ROUND-TRIPPED: a mask is added, the list is read, one mask is
 *     removed, the list is read again, and the removed mask must be gone from the
 *     wire and the surviving one still present. A handler that reconstructed the
 *     list from the command rather than from `ch->bans` would fail this.
 *   - 478 is reached by filling the list to CHAN_MAX_BANS and asking for one more,
 *     so the assertion is on the bound the header names rather than on "a long
 *     list is refused" -- and the list is verified to be AT the cap first, so a
 *     node that refused early would be caught there rather than passing the 478
 *     check for the wrong reason.
 *   - THE REFUSAL DID NOT ADD THE MASK, which is the "a refusal leaves everything
 *     exactly as it was" property Phase 4 asserted for a 437 and that a capacity
 *     limit is the obvious place to get wrong.
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
#define BAN_CHAN "#banme"
#define EMPTY_CHAN "#empties"
#define FULL_CHAN "#full"

/* CHAN_MAX_BANS, written as the literal rather than included from channel.h for
 * the reason test_queries.c gives for AWAY_MAX: a test that reads a bound from the
 * header cannot FAIL if the header is wrong, and this file's whole last section is
 * about whether that bound is real. 64 masks plus one refusal is the ban-list-full
 * case; a smaller number would make the test prove the bound is "some number". */
#define BAN_LIST_MAX 64

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
 * reason. A window is [from, end): `from` is a PING's PONG sent before the command
 * under test, `end` a second PING's PONG sent after it, and because a connection's
 * answers are written in order the closing PONG proves every earlier answer is
 * already in the buffer.
 * ------------------------------------------------------------------------ */
static unsigned g_drain_seq;

static size_t drain(client_t *cl)
{
    char line[64];
    char needle[96];
    const char *at;

    g_drain_seq++;
    (void)snprintf(line, sizeof line, "PING :b%u", g_drain_seq);
    (void)snprintf(needle, sizeof needle, "PONG %s b%u\r\n", BIN_NAME, g_drain_seq);
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
    client_t alice;
    size_t from, end;
    int i;

    if (nf_spawn_binary(&node) != 0) {
        fprintf(stderr, "could not spawn the irc-serve binary\n");
        return 1;
    }
    TF_CHECK_MSG(nf_expect(&node, "loop_running:", T_READY_MS) == 0,
                 "the node never reported its loop armed");
    client_open(&alice, &node, "alice");

    /* =======================================================================
     * 1. TWO MASKS SET, THEN READ BACK
     * ==================================================================== */
    /* alice JOINS, so she creates #banme and is its operator: handle_mode()
     * answers 482 to a mode change by a non-operator before it evaluates the mode,
     * and the whole file would be asserting refusals rather than lists. */
    client_join(&alice, BAN_CHAN);
    for (i = 1; i <= 2; i++) {
        char line[96];
        char echo[160];

        (void)snprintf(line, sizeof line, "MODE " BAN_CHAN " +b *!*@10.9.9.%d", i);
        (void)snprintf(echo, sizeof echo,
                       ":alice!alice@127.0.0.1 MODE #BANME +b *!*@10.9.9.%d\r\n", i);
        from = drain(&alice);
        TF_CHECK_MSG(tc_send(&alice.c, line) == 0, "tc_send(%s) failed", line);
        end = drain(&alice);
        expect_in_window(&alice, from, end, "the +b echo", echo);
    }

    /* =======================================================================
     * 2. `MODE #chan +b` WITH NO MASK IS THE QUERY
     * ==================================================================== */
    from = drain(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "MODE " BAN_CHAN " +b") == 0, "MODE +b query failed");
    end = drain(&alice);
    /* THE COUNT is as load-bearing as the content: a loop that emitted one 367
     * regardless of how many masks exist satisfies every presence check here and
     * shows a client one ban on a channel with two. */
    TF_CHECK_MSG(count_in_window(&alice, from, end, ":" BIN_NAME " 367 ") == 2u,
                 "`MODE " BAN_CHAN " +b` produced %zu 367 lines, expected exactly 2 "
                 "(one per mask)",
                 count_in_window(&alice, from, end, ":" BIN_NAME " 367 "));
    /* 367's RFC 2812 5.1 field list is "<channel> <banmask>" -- two middle
     * parameters and no trailing field -- so the whole run up to the CRLF is
     * asserted, and the terminating ':' that message_format() writes for an empty
     * trailing parameter is asserted too. That ':' is not decoration: it is how a
     * reader knows the RFC's absent trailing field is genuinely absent rather than
     * truncated. */
    expect_in_window(&alice, from, end, "367 for the first mask",
                     ":" BIN_NAME " 367 alice #BANME *!*@10.9.9.1 :\r\n");
    expect_in_window(&alice, from, end, "367 for the second mask",
                     ":" BIN_NAME " 367 alice #BANME *!*@10.9.9.2 :\r\n");
    /* 368's own field list is "<channel> :End of channel ban list". */
    expect_in_window(&alice, from, end, "368 terminates the ban list",
                     ":" BIN_NAME " 368 alice #BANME :End of channel ban list\r\n");
    /* AND IT COMES LAST. A position, not a presence: a client that stops reading at
     * 368 would otherwise lose masks from the tail, and a bare presence check is
     * satisfied by a 368 that arrived before the list. */
    {
        const char *base = tc_buffer(&alice.c);
        const char *last367 = NULL;
        const char *at368;

        for (const char *p = base + from; p < base + end; p++) {
            if (strncmp(p, " 367 ", 5) == 0) {
                last367 = p;
            }
        }
        at368 = strstr(base + from, ":" BIN_NAME " 368 alice #BANME ");
        TF_CHECK_MSG(at368 != NULL, "the ban list was not terminated by 368");
        TF_CHECK_MSG(at368 != NULL && last367 != NULL && at368 > last367,
                     "368 came before the last 367, so a client that stops at the "
                     "terminator would lose part of the list");
    }

    /* `-b` WITH NO MASK IS THE SAME QUERY. RFC 2812 3.3.2 does not distinguish the
     * sign for the list form, and this node answered 461 to this spelling too. */
    from = drain(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "MODE " BAN_CHAN " -b") == 0, "MODE -b query failed");
    end = drain(&alice);
    TF_CHECK_MSG(count_in_window(&alice, from, end, ":" BIN_NAME " 367 ") == 2u,
                 "`MODE " BAN_CHAN " -b` produced %zu 367 lines, expected 2",
                 count_in_window(&alice, from, end, ":" BIN_NAME " 367 "));
    expect_in_window(&alice, from, end, "368 after the -b query",
                     ":" BIN_NAME " 368 alice #BANME :End of channel ban list\r\n");

    /* =======================================================================
     * 3. THE LIST IS READ FROM THE NODE'S STATE, NOT REBUILT FROM THE COMMAND
     * ==================================================================== */
    from = drain(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "MODE " BAN_CHAN " -b *!*@10.9.9.1") == 0,
                 "MODE -b <mask> failed");
    (void)drain(&alice);
    from = drain(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "MODE " BAN_CHAN " +b") == 0, "MODE +b query failed");
    end = drain(&alice);
    TF_CHECK_MSG(count_in_window(&alice, from, end, ":" BIN_NAME " 367 ") == 1u,
                 "after removing one mask the list is %zu entries, expected 1",
                 count_in_window(&alice, from, end, ":" BIN_NAME " 367 "));
    expect_absent_in_window(&alice, from, end, "the list after a removal",
                            "*!*@10.9.9.1");
    expect_in_window(&alice, from, end, "the mask that is still set",
                     ":" BIN_NAME " 367 alice #BANME *!*@10.9.9.2 :\r\n");

    /* =======================================================================
     * 4. AN EMPTY LIST STILL GETS ITS TERMINATOR
     * ==================================================================== */
    /* RFC 2812 3.3.4: "a server is required to send the list back using the
     * RPL_BANLIST and RPL_ENDOFBANLIST messages ... After the banmasks have been
     * listed (or if none present) a RPL_ENDOFBANLIST MUST be sent." A client that
     * asked and got nothing cannot tell "no bans" from a dropped command, which is
     * the whole reason the terminator exists. */
    client_join(&alice, EMPTY_CHAN);
    from = drain(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "MODE " EMPTY_CHAN " +b") == 0, "MODE +b failed");
    end = drain(&alice);
    TF_CHECK_MSG(count_in_window(&alice, from, end, ":" BIN_NAME " 367 ") == 0u,
                 "an empty ban list produced %zu 367 lines",
                 count_in_window(&alice, from, end, ":" BIN_NAME " 367 "));
    expect_in_window(&alice, from, end, "368 for an empty ban list",
                     ":" BIN_NAME " 368 alice #EMPTIES :End of channel ban list\r\n");

    /* =======================================================================
     * 5. 478 ERR_BANLISTFULL, AT THE BOUND channel.h PROMISES
     * ==================================================================== */
    /* A FRESH CHANNEL, because the cap is per channel and #banme already holds a
     * mask. */
    client_join(&alice, FULL_CHAN);
    for (i = 0; i < BAN_LIST_MAX; i++) {
        char line[96];

        (void)snprintf(line, sizeof line, "MODE " FULL_CHAN " +b *!*@172.%d.%d.%d",
                       i / 65536, (i / 256) % 256, i % 256);
        TF_CHECK_MSG(tc_send(&alice.c, line) == 0, "tc_send(%s) failed", line);
    }
    (void)drain(&alice);
    /* The list really is AT the cap before the next one is asked for, so a node
     * that refused early would be caught here rather than passing the 478 check for
     * the wrong reason. It is also the direct evidence that channel.h's
     * CHAN_MAX_BANS claim is true: until Phase 11 the cap was not enforced at all
     * and every one of these masks was accepted. */
    from = drain(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "MODE " FULL_CHAN " +b") == 0, "MODE +b query failed");
    end = drain(&alice);
    TF_CHECK_MSG(count_in_window(&alice, from, end, ":" BIN_NAME " 367 ") ==
                     (size_t)BAN_LIST_MAX,
                 "a channel filled to the cap listed %zu masks, expected %d",
                 count_in_window(&alice, from, end, ":" BIN_NAME " 367 "),
                 BAN_LIST_MAX);

    /* RFC 2812 5.1: 478 is "<channel> <char> :Channel list is full" -- the channel
     * AND the mode letter are middle parameters. This node used to answer 696 with
     * the channel alone, so the <char> was absent AND the numeric was not this
     * condition at all: RFC 2812 has no 696, and 696 is RPL_ENDOFMODES from the
     * historical MODE draft, which a client holding it renders as "End of MODE
     * list" and a client not holding it shows nothing for. Either way the refusal
     * for a full ban list was invisible or actively misleading. */
    from = drain(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "MODE " FULL_CHAN " +b *!*@172.255.255.255") == 0,
                 "the over-the-cap MODE send failed");
    end = drain(&alice);
    expect_in_window(&alice, from, end, "478 for a full ban list",
                     ":" BIN_NAME " 478 alice #FULL b :Channel list is full\r\n");
    expect_absent_in_window(&alice, from, end, "a full ban list", " 696 ");
    expect_absent_in_window(&alice, from, end, "the over-the-cap request", " 461 ");

    /* AND THE REFUSAL DID NOT ADD THE MASK. */
    from = drain(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "MODE " FULL_CHAN " +b") == 0, "MODE +b query failed");
    end = drain(&alice);
    TF_CHECK_MSG(count_in_window(&alice, from, end, ":" BIN_NAME " 367 ") ==
                     (size_t)BAN_LIST_MAX,
                 "the refused mask was added anyway: the list is now %zu entries, "
                 "expected %d",
                 count_in_window(&alice, from, end, ":" BIN_NAME " 367 "),
                 BAN_LIST_MAX);
    expect_absent_in_window(&alice, from, end, "the list after a refused +b",
                            "*!*@172.255.255.255");

    /* =======================================================================
     * The node's own accounting
     * ==================================================================== */
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0");

    tc_close(&alice.c);
    nf_free(&node);
    tf_done("banlist");
    return 0;
}
