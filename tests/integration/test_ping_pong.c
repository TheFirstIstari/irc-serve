/* test_ping_pong.c -- PING is answered, PONG is accepted in silence, and the
 * reply format is the one a client's own liveness check can rely on.
 *
 * docs/SERVER_DESIGN.md 4.1 lists PING and PONG among the client commands, and
 * 3 puts the invariant that outbound messages are built in exactly one place
 * (see src/core/reply.h). This is the test for the PONG half of that module,
 * which is a COMMAND rather than a numeric and therefore easy to forget: a PONG
 * that reaches a peer link is exactly as wrong as a 433 reaching one, and it
 * would be reached by a different function if send_pong() did not share
 * emit_to_client() with reply().
 *
 * ---------------------------------------------------------------------------
 * THE FORMAT, AND WHY IT IS ASSERTED EXACTLY
 * ---------------------------------------------------------------------------
 * RFC 1459 2.4 defines the reply as
 *
 *     :<server> PONG <server> :<token>
 *
 * and a client compares the token it gets back against the one it sent. So the
 * token is echoed verbatim and the exact bytes are checked, including the cases
 * where the wire forces a colon and the case where it does not:
 *
 *   PING :token          -> ":irc.test PONG irc.test token"     (no colon: the
 *                                                                  value has no
 *                                                                  separator in
 *                                                                  it, so a colon
 *                                                                  would be noise)
 *   PING :two words here -> ":irc.test PONG irc.test :two words here"
 *   PING                 -> ":irc.test PONG irc.test irc.test"  (no argument: the
 *                                                                  server name, per
 *                                                                  2.4)
 *
 * The distinction between the second and third lines is the one that breaks
 * clients: a reply that drops a space without adding the colon re-parses as two
 * parameters, and the client's own comparison then fails against a node that is
 * perfectly alive.
 *
 * ---------------------------------------------------------------------------
 * "PONG IS ACCEPTED SILENTLY" WITHOUT A SLEEP
 * ---------------------------------------------------------------------------
 * Silence is the one thing a protocol test cannot observe by waiting, because
 * waiting is how you prove absence only with a timeout -- and a timeout is
 * indistinguishable from being too impatient. 6.3 forbids the fixed sleep that
 * would otherwise be the only way.
 *
 * So the absence is proved the other way round: PONG and the following PING go
 * out in ONE segment, and the PONG's arrival is the wait. By the time the reply
 * to the PING is in hand the node has already read both lines, so a reply to
 * the PONG -- had there been one -- would already be in the buffer. Exactly one
 * PONG line, carrying the PING's token, is therefore a fact about the bytes
 * rather than a guess about timing. That is also why a naive "answer every
 * message" implementation fails this test rather than passing it slowly: it
 * answers the PONG too, and the count is 2.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_READY_MS 15000
#define T_IO_MS 15000

/* Assert that `want` arrives on `c`, byte for byte, as a complete line.
 *
 * `want` INCLUDES the trailing CRLF, so matching it proves the line is
 * terminated on the wire rather than being a prefix of something longer -- which
 * is the difference between checking a numeric's format and checking that the
 * string "433" turns up somewhere. The leading boundary is then checked
 * explicitly, so a numeric that is a SUFFIX of a longer line cannot pass.
 *
 * The leading CRLF is deliberately NOT part of the needle: the first line on a
 * connection has nothing before it, so a needle anchored that way can never
 * match the first reply a client receives. */
static void expect_line(test_client_t *c, const char *what, const char *want)
{
    const char *at;

    TF_CHECK_MSG(tc_expect(c, want, T_IO_MS) == 0, "%s: expected the exact "
                 "line \"%s\"", what, want);
    at = strstr(tc_buffer(c), want);
    TF_CHECK_MSG(at != NULL, "%s: the line vanished from the buffer", what);
    TF_CHECK_MSG(at == tc_buffer(c) || at[-1] == '\n',
                 "%s: \"%s\" is not at the start of a line: it is the tail of "
                 "a longer one", what, want);
}

/* The count of PONG lines, which is how "answered in silence" is checked.
 *
 * The needle is the whole line's start, not the bare word: the MOTD this node
 * serves names PING and PONG in its text, and a bare "PONG " would match that
 * prose -- so the count would start at one and a reader could not tell a real
 * reply from a mention of one. */
static size_t pongs(const test_client_t *c)
{
    return tf_count(tc_buffer(c), ":irc.test PONG ");
}

int main(void)
{
    nf_node_t node;
    test_client_t c;
    size_t before;

    tc_init(&c);
    TF_CHECK(nf_spawn_binary(&node) == 0);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");

    /* ---------------------------------------------------------------------
     * Before registration: a client stuck mid-handshake still needs to know
     * the node is alive.
     * --------------------------------------------------------------------- */
    TF_CHECK_MSG(tc_send(&c, "PING :one") == 0, "tc_send failed");
    expect_line(&c, "PING with a token",
                ":irc.test PONG irc.test one\r\n");

    /* A token containing spaces. The trailing-parameter marker is REQUIRED
     * here, and getting that wrong is the classic PONG bug: without the colon
     * the line re-parses as two parameters and the client's comparison against
     * "two words here" fails. */
    TF_CHECK_MSG(tc_send(&c, "PING :two words here") == 0, "tc_send failed");
    expect_line(&c, "PING with a multi-word token",
                ":irc.test PONG irc.test :two words here\r\n");

    /* No argument at all. RFC 1459 2.4: answered with the server name. */
    TF_CHECK_MSG(tc_send(&c, "PING") == 0, "tc_send failed");
    expect_line(&c, "PING with no argument",
                ":irc.test PONG irc.test irc.test\r\n");

    /* An empty token is the same request as no argument, and must not render
     * as a bare trailing colon -- that would re-parse as an empty parameter,
     * which is a different answer from the one 2.4 specifies.
     *
     * The answer is byte-identical to the no-argument case above, so it cannot
     * be waited for by its own text: tc_expect would match the copy already in
     * the buffer and return before the second one had arrived. The PING behind
     * it carries a unique token and is the drain, and the count of PONG lines
     * is what proves BOTH were answered -- a node that dropped the empty PING,
     * or merged it with the next one, would leave the count one short. */
    before = pongs(&c);
    TF_CHECK_MSG(tc_send_raw(&c, "PING :\r\nPING :after-empty-token\r\n",
                             sizeof("PING :\r\nPING :after-empty-token\r\n") - 1u)
                     == 0, "tc_send_raw failed");
    expect_line(&c, "PING after an empty token",
                ":irc.test PONG irc.test after-empty-token\r\n");
    TF_CHECK_MSG(pongs(&c) == before + 2,
                 "PING with an empty token and the PING behind it should have "
                 "produced %zu PONG lines, saw %zu: an empty token must be "
                 "answered as the server name, not dropped and not merged",
                 before + 2, pongs(&c));

    /* ---------------------------------------------------------------------
     * PONG, accepted in silence.
     * --------------------------------------------------------------------- */
    before = pongs(&c);
    TF_CHECK_MSG(tc_send(&c, "PONG :one") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&c, "PING :after-pong") == 0, "tc_send failed");
    expect_line(&c, "PING after a PONG",
                ":irc.test PONG irc.test after-pong\r\n");
    TF_CHECK_MSG(pongs(&c) == before + 1,
                 "a PONG was answered with another PONG: %zu PONG lines, "
                 "expected %zu. Answering a PONG is how a naive implementation "
                 "starts a storm.", pongs(&c), before + 1);
    TF_CHECK_MSG(nf_expect(&node, "pong: fd=", T_IO_MS) == 0,
                 "the node did not record the PONG it accepted");

    /* The same after registration, where the gate would otherwise apply. */
    TF_CHECK_MSG(tc_send(&c, "NICK alice") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&c, "USER alice 0 * :Alice Example") == 0,
                 "tc_send failed");
    TF_CHECK_MSG(tc_expect(&c, " 001 alice :Welcome", T_IO_MS) == 0,
                 "registration did not complete");

    before = pongs(&c);
    TF_CHECK_MSG(tc_send(&c, "PONG :ignored") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&c, "PING :registered-ping") == 0, "tc_send failed");
    expect_line(&c, "PING after registration",
                ":irc.test PONG irc.test registered-ping\r\n");
    TF_CHECK_MSG(pongs(&c) == before + 1,
                 "an authenticated PONG was answered (%zu PONG lines, "
                 "expected %zu)", pongs(&c), before + 1);

    /* A token the client can recognise coming back: this is the whole point of
     * a PONG, and it is why the token is echoed rather than replaced. */
    TF_CHECK_MSG(tc_send(&c, "PING :9d8f7a6b-unique") == 0, "tc_send failed");
    expect_line(&c, "PING echoing its token",
                ":irc.test PONG irc.test 9d8f7a6b-unique\r\n");

    /* MOTD does not answer a PING and vice versa: one of these tests would
     * pass against a node that answered every line with everything. */
    TF_CHECK_MSG(tf_count(tc_buffer(&c), " 372 ") == 3,
                 "the MOTD was re-sent: 372 count is %zu, expected 3",
                 tf_count(tc_buffer(&c), " 372 "));

    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0: a PONG was dropped rather than sent");
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", 1, T_IO_MS) == 0,
                 "accepted should be 1");
    TF_CHECK_MSG(nf_expect_u64(&node, "closed=", 1, T_IO_MS) == 0,
                 "closed should be 1");

    tc_close(&c);
    nf_free(&node);
    tf_done("ping_pong");
    return 0;
}
