/* test_nick_rule.c -- valid_nick() enforced at runtime, on the wire.
 *
 * docs/SERVER_DESIGN.md 5 and 2.1: the nick charset rule is "MISSING" and must
 * be added, because 2.1 splits a qualified `nick@server` at the LAST '@' and
 * that is only unambiguous if '@' cannot appear inside a nickname. Phase 1
 * shipped the predicate and a unit test for it. Until this phase, NOTHING IN
 * src/ CALLED IT: the rule was specified and tested but not enforced at runtime,
 * so a nickname could in principle have been any bytes at all. Registration is
 * where a nickname is chosen, so it is the only place the call belongs, and
 * this test is what makes the predicate load-bearing.
 *
 * The assertions are on the RESPONSE, never on the fact that a function was
 * called. A test that asserted "valid_nick was invoked here" would pass against
 * a node that invoked it and then ignored the answer.
 *
 * ---------------------------------------------------------------------------
 * WHAT THE WIRE CAN AND CANNOT EXPRESS
 * ---------------------------------------------------------------------------
 * Three of the illegal shapes the nick rule names cannot be sent at all, and
 * the honest thing is to say so rather than to write a test that quietly does
 * not cover them:
 *
 *   a space        IRC parameters are space-separated, so a nickname
 *                  containing a space is not expressible as one parameter.
 *                  `NICK a b` is two parameters and the node answers 461 --
 *                  which IS the answer a client gets for trying, and it is
 *                  asserted.
 *
 *   a leading ':'  `:` at the START of a parameter is the trailing-parameter
 *                  marker, and the parser strips it. `NICK :bob` therefore
 *                  arrives as the nickname "bob" -- a different, legal request.
 *                  A nickname beginning with ':' is not expressible, so it is
 *                  not tested; what IS tested is that a ':' INSIDE a nickname
 *                  is refused, which is expressible and is the half that
 *                  actually matters for the nick@server split.
 *
 *   over-long      64 bytes is one parameter, one longer than the 63 that
 *                  conn_t::nick holds, and is refused with 432.
 *
 * The rest of the illegal set (@ # & + ! : ;) and the leading-digit rule are
 * refused with 432. After all of them, a legal nickname must still work: a
 * state machine that refused everything and then answered nothing would pass a
 * test that only checked the refusals.
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

/* One illegal nickname, and the exact line the node must answer with. The
 * expected line is BUILT here rather than passed in, so every case in the
 * caller is the same shape and the expected text cannot drift away from the
 * numeric it is checking -- which is exactly the kind of drift an exact-byte
 * test exists to prevent. */
static void expect_refused(test_client_t *c, const char *nick)
{
    char cmd[256];
    char want[512];
    int n;

    n = snprintf(cmd, sizeof cmd, "NICK %s", nick);
    TF_CHECK_MSG(n > 0 && (size_t)n < sizeof cmd, "nick too long to send");
    n = snprintf(want, sizeof want,
                 ":irc.test 432 * :Erroneous nickname: %s\r\n", nick);
    TF_CHECK_MSG(n > 0 && (size_t)n < sizeof want, "expected line too big");
    TF_CHECK_MSG(tc_send(c, cmd) == 0, "tc_send(NICK %s) failed", nick);
    expect_line(c, "refused nick", want);
}

int main(void)
{
    nf_node_t node;
    test_client_t carol;
    test_client_t dave;
    char long_nick[128];

    tc_init(&carol);
    tc_init(&dave);

    TF_CHECK(nf_spawn_binary(&node) == 0);
    TF_CHECK_MSG(tc_connect(&carol, node.port) == 0, "tc_connect failed");

    /* ---------------------------------------------------------------------
     * 432: a nickname that is not a legal nickname.
     * --------------------------------------------------------------------- */
    expect_refused(&carol, "1bob");
    expect_refused(&carol, "a:b");
    expect_refused(&carol, "a#b");
    expect_refused(&carol, "a&b");
    expect_refused(&carol, "a+b");
    expect_refused(&carol, "a!b");
    expect_refused(&carol, "a;b");
    /* '@' is the one that makes the whole identity scheme unsound: 2.1 splits
     * at the LAST '@', so a nickname holding one is ambiguous. */
    expect_refused(&carol, "a@evil");
    /* NOT tested: a nickname STARTING with ':'. `NICK :bob` is parsed as the
     * nickname "bob", because ':' at the start of a parameter is the
     * trailing-parameter marker and the parser strips it. The shape is not
     * expressible on the wire, so the case above -- a ':' inside the
     * nickname, which is what the nick@server split actually turns on -- is
     * the half that is testable. */

    /* Over-long. conn_t::nick is char[64], so 63 bytes is the bound, and 64 is
     * one too many. The same helper checks it, which is the point of building
     * the expected line from the input rather than restating it. */
    memset(long_nick, 'n', sizeof long_nick);
    long_nick[0] = 'l';
    long_nick[64] = '\0';
    expect_refused(&carol, long_nick);

    /* ---------------------------------------------------------------------
     * 431: no nickname at all. Zero parameters, and one EMPTY parameter --
     * `NICK :` parses to a single empty parameter, which is the same request.
     * --------------------------------------------------------------------- */
    TF_CHECK_MSG(tc_send(&carol, "NICK") == 0, "tc_send(NICK) failed");
    expect_line(&carol, "NICK with no parameter",
                ":irc.test 431 * :No nickname given\r\n");
    TF_CHECK_MSG(tc_send(&carol, "NICK :") == 0, "tc_send(NICK :) failed");
    expect_line(&carol, "NICK with an empty parameter",
                ":irc.test 431 * :No nickname given\r\n");

    /* ---------------------------------------------------------------------
     * 461: a nickname containing a space, which the wire expresses as two
     * parameters. See the header: the rule cannot be violated by a
     * well-formed line, and this is the answer a client gets for trying.
     * --------------------------------------------------------------------- */
    TF_CHECK_MSG(tc_send(&carol, "NICK a b") == 0, "tc_send(NICK a b) failed");
    expect_line(&carol, "NICK with two parameters",
                ":irc.test 461 * :Not enough parameters\r\n");

    /* ---------------------------------------------------------------------
     * None of the refusals may have wedged the state machine: a legal
     * nickname still works, and the client still registers.
     * --------------------------------------------------------------------- */
    TF_CHECK_MSG(tc_send(&carol, "NICK carol") == 0, "tc_send(NICK) failed");
    TF_CHECK_MSG(tc_send(&carol, "USER carol 0 * :Carol Example") == 0,
                 "tc_send(USER) failed");
    TF_CHECK_MSG(tc_expect(&carol, " 001 carol :Welcome", T_IO_MS) == 0,
                 "a legal nickname was refused after nine illegal ones, or the "
                 "registration did not complete: the state machine is not "
                 "recovering from a rejection");

    /* ---------------------------------------------------------------------
     * A nickname CHANGE after registration.
     * ---------------------------------------------------------------------
     * NICK is also a rename once the client is registered (RFC 2812 3.2), and
     * the change must not re-fire the welcome burst: 001 is what a client uses
     * to decide it has connected, and a second one pushes it back into its
     * connect path.
     *
     * "The change was accepted" is not visible as a line on the wire -- a
     * successful rename is silent -- so it is asserted through the node's own
     * observable output, and the silence is asserted by COUNTING: the PING in
     * the same segment produces the PONG that ends the wait, so by the time the
     * PONG is in hand the node has already answered or refused everything in
     * front of it, and no 432/433/001 in between would have been missed.
     */
    {
        size_t r432;
        size_t r433;
        size_t r001;

        TF_CHECK_MSG(tc_send(&carol, "NICK carol2") == 0, "tc_send failed");
        TF_CHECK_MSG(nf_expect(&node, "to=carol2", T_IO_MS) == 0,
                     "the node did not accept a nickname change to a free name");
        TF_CHECK_MSG(strstr(node.out, "from=carol to=carol2") != NULL,
                     "the nickname change did not record the old name, so the "
                     "old one cannot be shown to have been released");

        /* Re-asserting the nickname you already hold is not an error and not a
         * change: it must be silent, and must not be counted a second time.
         *
         * The counts are DELTAS, not absolutes: this client's buffer already
         * holds nine 432 lines from the illegal nicknames above, so an absolute
         * count of zero would be a statement about the whole session rather
         * than about the re-assertion. */
        r432 = tf_count(tc_buffer(&carol), " 432 ");
        r433 = tf_count(tc_buffer(&carol), " 433 ");
        r001 = tf_count(tc_buffer(&carol), " 001 ");
        TF_CHECK_MSG(tc_send(&carol, "NICK carol2") == 0, "tc_send failed");
        TF_CHECK_MSG(tc_send(&carol, "PING :after-reassert") == 0,
                     "tc_send failed");
        TF_CHECK_MSG(tc_expect(&carol, "PONG irc.test after-reassert",
                               T_IO_MS) == 0,
                     "no PONG after re-asserting the current nickname");
        TF_CHECK_MSG(tf_count(tc_buffer(&carol), " 432 ") == r432,
                     "re-asserting your own nickname answered 432");
        TF_CHECK_MSG(tf_count(tc_buffer(&carol), " 433 ") == r433,
                     "re-asserting your own nickname answered 433");
        TF_CHECK_MSG(tf_count(tc_buffer(&carol), " 001 ") == r001,
                     "the welcome burst was re-sent on a nickname change: 001 "
                     "went from %zu to %zu, and a client treats 001 as 'I am "
                     "connected'", r001,
                     tf_count(tc_buffer(&carol), " 001 "));
    }

    /* ---------------------------------------------------------------------
     * 433 mid-session: taking a name somebody else holds.
     * ---------------------------------------------------------------------
     * The target is the caller's CURRENT nickname, and the colliding name is
     * the middle parameter -- which is only safely renderable because it got
     * this far by passing valid_nick(), so it is non-empty and cannot start
     * with ':'. If this line ever arrives as `:irc.test 433 carol2` with no
     * name in it, the reply was refused rather than rendered.
     * --------------------------------------------------------------------- */
    TF_CHECK_MSG(tc_connect(&dave, node.port) == 0, "tc_connect failed");
    TF_CHECK_MSG(tc_send(&dave, "NICK dave") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&dave, "USER dave 0 * :Dave Example") == 0,
                 "tc_send failed");
    TF_CHECK_MSG(tc_expect(&dave, " 001 dave :Welcome", T_IO_MS) == 0,
                 "the second client did not register");

    TF_CHECK_MSG(tc_send(&carol, "NICK dave") == 0, "tc_send failed");
    expect_line(&carol, "mid-session collision",
                ":irc.test 433 carol2 dave :Nickname is already in use\r\n");

    /* And the incumbent keeps it: dave can still re-assert his own name
     * silently, which is only possible if carol's attempt did not take it. */
    TF_CHECK_MSG(tc_send(&dave, "NICK dave") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&dave, "PING :still-mine") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_expect(&dave, "PONG irc.test still-mine", T_IO_MS) == 0,
                 "the incumbent could not re-assert his own nickname");
    TF_CHECK_MSG(tf_count(tc_buffer(&dave), " 433 ") == 0,
                 "the incumbent got 433 for his own nickname (%zu seen): the "
                 "loser of a collision displaced the holder",
                 tf_count(tc_buffer(&dave), " 433 "));
    /* carol still holds carol2: if the failed claim had evicted it, the
     * registry would now say otherwise and this would not be silent. */
    TF_CHECK_MSG(tc_send(&carol, "NICK carol2") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&carol, "PING :unchanged") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_expect(&carol, "PONG irc.test unchanged", T_IO_MS) == 0,
                 "carol lost her own nickname to a failed claim");

    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0: a reply the node could not render "
                 "was dropped instead of sent");
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", 2, T_IO_MS) == 0,
                 "accepted should be 2");
    TF_CHECK_MSG(nf_expect_u64(&node, "closed=", 2, T_IO_MS) == 0,
                 "closed should be 2");

    tc_close(&carol);
    tc_close(&dave);
    nf_free(&node);
    tf_done("nick_rule");
    return 0;
}
