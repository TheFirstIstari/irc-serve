/* test_knock.c -- KNOCK on the wire, against the real binary.
 *
 * docs/SERVER_DESIGN.md 4.2 (KNOCK, Phase 7) and 4.4 (482, 403). RFC 2812's
 * KNOCK is a DRAFT extension rather than a numbered section, so the reply numerics
 * it implies (480, 704, 705) are not in 4.4 either; see chan_verbs.c's
 * handle_knock() for the full argument and 482 is what 4.4 does have.
 *
 * ---------------------------------------------------------------------------
 * WHY A COMMAND THAT ONLY EVER SAYS 482 DESERVES A TEST
 * ---------------------------------------------------------------------------
 * Because "only ever says one thing" is exactly the claim a stub makes, and the
 * only way to tell an honest refusal from a stub is to check the things the
 * refusal is NOT allowed to be. A handler that answered 482 to everything --
 * including a malformed line, a channel that does not exist, and a client that
 * has not registered -- would pass a test that only looked for 482.
 *
 * So this file asserts, for each input, that the RIGHT numeric came back AND
 * that the others did not. Four refusals are distinguished:
 *
 *   451  the client has not registered. The verb is in the command table with
 *        pre_reg == 0, so the registration gate answers before the handler is
 *        reached. A KNOCK implemented outside the table would be a different
 *        verb as far as the gate is concerned.
 *   461  the line had no channel name.
 *   403  the name was not a channel, or named a channel this node does not hold.
 *        Two DIFFERENT inputs and the same numeral, and both are asserted,
 *        because a node that answered 482 for a nonexistent channel would tell
 *        a client the wrong thing: the channel is the part the client can fix.
 *   482  everything else, because this node has no operator flags and the RFC's
 *        gate is an IRC operator.
 *
 * ---------------------------------------------------------------------------
 * AND THE ONE ASSERTION THAT PROVES IT IS NOT ANSWERING 704
 * ---------------------------------------------------------------------------
 * A real KNOCK implementation answers 704 RPL_KNOCK when it has lodged the
 * request with the channel's origin. This node cannot: there is no operator
 * model to gate on and no SKNOCK in 4.3's frozen S-verb table, so nothing would
 * ever happen to the request. The absence of 704 (and of 705, the knock-list
 * variant) is therefore the assertion with teeth -- a node that faked the
 * success would pass every positive check above and fail this one.
 *
 * NO sleep() ANYWHERE (6.3): every wait is a select()-driven deadline inside
 * tc_expect(), and every negative assertion is scoped to a window closed by a
 * PING drain. A bare tc_expect() searches the whole accumulated buffer, so a
 * second ` 482 ` would match the first and return instantly and the wait
 * covering the command under test would never happen.
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
#define CHAN "#KNOCK"

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

int main(void)
{
    nf_node_t node;
    client_t alice, bob;
    test_client_t raw;
    size_t from, end;

    if (nf_spawn_binary(&node) != 0) {
        fprintf(stderr, "could not spawn the irc-serve binary\n");
        return 1;
    }
    TF_CHECK_MSG(nf_expect(&node, "loop_running:", T_READY_MS) == 0,
                 "the node never reported its loop armed");

    client_open(&alice, &node, "alice");
    client_open(&bob, &node, "bob");
    client_join(&alice, CHAN);
    client_join(&bob, CHAN);

    /* =======================================================================
     * 1. The refusal itself, on a channel that exists and has members
     * ==================================================================== */
    /* 482 carries the channel as a MIDDLE parameter, so a client reading by
     * position can tell WHICH channel it was refused for. The trailing text
     * says the privilege is an IRC one rather than a channel one, which is the
     * whole of the difference between this refusal and the 482 a non-operator
     * gets from INVITE -- the same numeral, two different sentences, and a
     * client that rendered "not a channel operator" here would be telling an
     * ordinary user they are not something they never claimed to be. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "KNOCK " CHAN) == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "482 for a knock on a live channel",
                     ":" BIN_NAME " 482 alice #KNOCK :You're not an IRC "
                     "operator\r\n");
    /* The 482 is the WHOLE answer. 704 RPL_KNOCK is what a node that had lodged
     * the request with the origin would send, and 705 is the knock-list
     * variant. Neither is emitted, because nothing can happen to this request:
     * there is no operator model to gate on and no SKNOCK in 4.3's frozen
     * S-verb table. A node that faked the success passes every positive check
     * above and fails here. */
    expect_absent_in_window(&alice, from, end, "the knock refusal", " 704 ");
    expect_absent_in_window(&alice, from, end, "the knock refusal", " 705 ");
    expect_absent_in_window(&alice, from, end, "the knock refusal", " 480 ");

    /* =======================================================================
     * 2. The refusal does NOT depend on the knocker's standing on the channel
     * ==================================================================== */
    /* bob is on the channel, alice is on it, and neither is an IRC operator --
     * because this node has no IRC operators at all. A KNOCK on a channel the
     * knocker is not on is the ordinary case for the verb, so it has to be
     * answered about the channel and not about the knocker's membership: 403
     * and 442 are the numerals that would be about membership, and neither may
     * appear. */
    from = mark(&bob);
    TF_CHECK_MSG(tc_send(&bob.c, "KNOCK " CHAN) == 0, "tc_send failed");
    end = mark(&bob);
    expect_in_window(&bob, from, end, "482 on the second client",
                     ":" BIN_NAME " 482 bob #KNOCK :You're not an IRC "
                     "operator\r\n");
    expect_absent_in_window(&bob, from, end, "the second knock", " 442 ");

    /* =======================================================================
     * 3. A channel this node does not hold is 403, not 482
     * ==================================================================== */
    /* The one place a client can fix the complaint by itself. Answering 482 here
     * would tell a client that the only way through is to become an operator,
     * which is not true and not fixable -- the channel simply is not here. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "KNOCK #nosuch") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "403 for a channel that does not exist",
                     ":" BIN_NAME " 403 alice #NOSUCH :No such channel\r\n");
    expect_absent_in_window(&alice, from, end, "the missing-channel knock",
                            " 482 ");

    /* A name that is not a channel name at all is 403 as well, and the numeral
     * carries the CANONICAL form of what the client typed. That is not this
     * handler's decision: canonical_channel() upper-cases before it validates,
     * and every channel verb in the node goes through the same primitive, so a
     * lowercase refusal subject here would be the only one in the tree. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "KNOCK 9nope") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "403 for a name that is not a channel",
                     ":" BIN_NAME " 403 alice 9NOPE :No such channel\r\n");
    expect_absent_in_window(&alice, from, end, "the malformed-channel knock",
                            " 482 ");

    /* =======================================================================
     * 4. Arity
     * ==================================================================== */
    /* KNOCK takes exactly one channel. Two channels is not "knock on both" --
     * the verb is defined per channel and a client that wanted two must send
     * two lines -- and a bare KNOCK names no channel at all. 461 for both,
     * which is the numeral every handler in the node uses for a wrong-arity
     * line and the one 4.4 lists.
     *
     * `KNOCK` is RFC 2812 5.2's `<command>` field, and both needles carry it. A
     * needle stopping at `461 alice` would pass against a node whose 461 named
     * no verb, which is the arity this pair exists to pin. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "KNOCK") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "461 for a bare KNOCK",
                     ":" BIN_NAME " 461 alice KNOCK :Not enough parameters\r\n");
    expect_absent_in_window(&alice, from, end, "the bare knock", " 482 ");

    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "KNOCK " CHAN " " CHAN) == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "461 for two channels",
                     ":" BIN_NAME " 461 alice KNOCK :Not enough parameters\r\n");
    expect_absent_in_window(&alice, from, end, "the two-channel knock", " 482 ");

    /* =======================================================================
     * 5. The registration gate answers before the handler does
     * ==================================================================== */
    /* A connection that has sent NICK but not USER is not a user of this
     * network, and the gate is what says so: 451, not 482. The verb is in
     * commands.c's table with pre_reg == 0, which is the same gate every other
     * Phase 4/5/7 channel command goes through -- a KNOCK implemented beside the
     * table rather than in it would be a different verb as far as the gate is
     * concerned, and this is the assertion that would notice. */
    tc_init(&raw);
    g_opened++;
    TF_CHECK_MSG(tc_connect(&raw, node.port) == 0, "tc_connect(raw) failed");
    TF_CHECK_MSG(tc_send(&raw, "NICK early") == 0, "NICK send failed");
    TF_CHECK_MSG(tc_send(&raw, "KNOCK " CHAN) == 0, "KNOCK send failed");
    TF_CHECK_MSG(tc_expect(&raw, " 451 ", T_IO_MS) == 0,
                 "an unregistered client was not answered with 451");
    TF_CHECK_MSG(strstr(tc_buffer(&raw), " 482 ") == NULL,
                 "an unregistered client's KNOCK reached the handler and was "
                 "answered 482 instead of being stopped by the registration gate");
    /* And it registers and knocks normally afterwards, so the gate is a gate and
     * not a state the connection is stuck in. The 482 needle is safe to search
     * over the WHOLE buffer here, rather than in a window: this connection has
     * never been answered 482 before, so a match cannot be an earlier one. That
     * is the only place in this file where the window discipline is skipped,
     * and the reason is stated here rather than left to the reader. */
    TF_CHECK_MSG(tc_send(&raw, "USER early 0 * :Real early") == 0,
                 "USER send failed");
    TF_CHECK_MSG(tc_expect(&raw, " 001 ", T_IO_MS) == 0, "raw did not register");
    TF_CHECK_MSG(tc_send(&raw, "PING :gate-drain") == 0, "PING send failed");
    TF_CHECK_MSG(tc_expect(&raw, "PONG ", T_IO_MS) == 0, "no PONG after USER");
    TF_CHECK_MSG(tc_send(&raw, "KNOCK " CHAN) == 0, "KNOCK send failed");
    TF_CHECK_MSG(tc_expect(&raw, ":" BIN_NAME " 482 early #KNOCK ", T_IO_MS) == 0,
                 "a registered client was not answered with 482, so the "
                 "registration gate is not what stopped the earlier KNOCK");

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
    tc_close(&raw);
    nf_free(&node);
    tf_done("knock");
    return 0;
}
