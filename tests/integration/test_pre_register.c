/* test_pre_register.c -- the registration gate, and what happens to a command
 * the node does not have.
 *
 * docs/SERVER_DESIGN.md 4.4 names 421 ERR_UNKNOWNCOMMAND and 451
 * ERR_NEEDMOREPARAMS among the numerics, and 4.1 lists the command surface. A
 * node that IGNORES a command it does not recognise is the quiet failure mode
 * this project exists to eliminate ("every test skipped or faked is what let a
 * green suite coexist with a non-functional server"), so the rule here is that
 * nothing falls through in silence: an unrecognised verb is 421, and a verb the
 * client is not yet entitled to send is 451.
 *
 * Three distinct cases, which are easy to conflate and are not the same code:
 *
 *   451  the client is not registered and this verb is not part of
 *        registration. The answer is about the CLIENT, and it is actionable:
 *        the client knows to send NICK and USER.
 *   421  the client IS registered and sent a verb this build has never heard
 *        of (`NICKX`).
 *   421  the client IS registered and sent a verb 4.1 lists but a later phase
 *        implements (`JOIN`). A slight lie about the reason -- the wire has no
 *        numeric for "not yet" -- but the alternative is silence, and the node
 *        records which of the two it was so a log reader is not misled.
 *
 * The ORDER matters and is asserted: from an unregistered connection an
 * unrecognised verb is 451, not 421, because "you have not registered" is both
 * true and actionable while "unknown command" would be neither. RFC 2812 3.1
 * puts the registration check first and so does this.
 *
 * PING and PONG are exempt from the gate, and that is asserted here rather than
 * assumed: a client stuck mid-registration must be able to tell the node is
 * alive, and one that has sent NICK and USER in a single segment and then
 * PINGs must get its answer.
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

int main(void)
{
    nf_node_t node;
    test_client_t c;
    size_t before_451;

    tc_init(&c);
    TF_CHECK(nf_spawn_binary(&node) == 0);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");

    /* ---------------------------------------------------------------------
     * PING works before registration. Asserted FIRST, so that everything after
     * it is known to have been read by a node that was already answering.
     * --------------------------------------------------------------------- */
    TF_CHECK_MSG(tc_send(&c, "PING :early") == 0, "tc_send failed");
    expect_line(&c, "PING before registration", ":irc.test PONG irc.test early\r\n");

    /* ---------------------------------------------------------------------
     * 451: a non-registration verb before registration.
     * --------------------------------------------------------------------- */
    before_451 = tf_count(tc_buffer(&c), " 451 ");
    TF_CHECK_MSG(tc_send(&c, "JOIN #somewhere") == 0, "tc_send failed");
    expect_line(&c, "JOIN before registration",
                ":irc.test 451 * :You have not registered\r\n");
    TF_CHECK_MSG(tf_count(tc_buffer(&c), " 451 ") == before_451 + 1,
                 "expected exactly one 451 for one JOIN");

    /* A misspelling of a real verb is 451 before registration, not 421: the
     * client has not registered, and that is the fact it needs. */
    TF_CHECK_MSG(tc_send(&c, "NICKX") == 0, "tc_send failed");
    expect_line(&c, "an unknown verb before registration",
                ":irc.test 451 * :You have not registered\r\n");

    /* 432/433 are answerable before registration -- they are about the
     * nickname, which is what registration is FOR -- so a client that renames
     * before registering is not gated. */
    TF_CHECK_MSG(tc_send(&c, "NICK 9bad") == 0, "tc_send failed");
    expect_line(&c, "an illegal nick before registration",
                ":irc.test 432 * :Erroneous nickname: 9bad\r\n");

    /* ---------------------------------------------------------------------
     * Register.
     * --------------------------------------------------------------------- */
    TF_CHECK_MSG(tc_send(&c, "NICK alice") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&c, "USER alice 0 * :Alice Example") == 0,
                 "tc_send failed");
    TF_CHECK_MSG(tc_expect(&c, " 001 alice :Welcome", T_IO_MS) == 0,
                 "registration did not complete");

    /* ---------------------------------------------------------------------
     * The gate is now open, which is the other half of the property: the same
     * verb that answered 451 a moment ago must no longer be answered 451.
     * --------------------------------------------------------------------- */
    TF_CHECK_MSG(tc_send(&c, "JOIN #somewhere") == 0, "tc_send failed");
    expect_line(&c, "JOIN after registration",
                ":irc.test 421 alice JOIN :Unknown command\r\n");
    TF_CHECK_MSG(tf_count(tc_buffer(&c), " 451 ") == before_451 + 2,
                 "a 451 was sent to a registered client");

    /* ---------------------------------------------------------------------
     * 421 for a verb this build has never heard of. `NICKX` specifically: it is
     * one character away from NICK, which is the case where a fallback to a
     * prefix match or a silent drop would do the most damage.
     * --------------------------------------------------------------------- */
    TF_CHECK_MSG(tc_send(&c, "NICKX") == 0, "tc_send failed");
    expect_line(&c, "an unknown verb after registration",
                ":irc.test 421 alice NICKX :Unknown command\r\n");
    TF_CHECK_MSG(tf_count(tc_buffer(&c), " 421 ") == 2,
                 "expected exactly two 421 lines, saw %zu",
                 tf_count(tc_buffer(&c), " 421 "));

    /* Lower case is the same command: 3.2 uppercases the command word, so a
     * client that sends "join" is not suddenly sending an unknown verb. */
    TF_CHECK_MSG(tc_send(&c, "join #somewhere") == 0, "tc_send failed");
    expect_line(&c, "a lower-case verb after registration",
                ":irc.test 421 alice JOIN :Unknown command\r\n");

    /* The node distinguishes "never heard of it" from "arrives in a later
     * phase" in its own output, so a log reader is not told a planned verb is
     * unknown. */
    TF_CHECK_MSG(nf_expect(&node, "cmd_unimplemented: fd=", T_IO_MS) == 0,
                 "the node did not record JOIN as a planned-but-unimplemented "
                 "verb");
    TF_CHECK_MSG(nf_expect(&node, "cmd_unknown: fd=", T_IO_MS) == 0,
                 "the node did not record NICKX as an unknown verb");

    /* ---------------------------------------------------------------------
     * Every 4.1 verb that a later phase owns is ANSWERED, not dropped. A verb
     * that fell through to silence would be invisible in this test and
     * invisible in production, so each one is sent and each 421 is counted.
     * --------------------------------------------------------------------- */
    {
        static const char *const later[] = {
            "PART #x", "PRIVMSG #x :hi", "NOTICE #x :hi", "TOPIC #x :t",
            "NAMES #x", "MODE #x", "KICK #x bob", "KILL bob"
        };
        size_t expect_421 = 3; /* JOIN, join, NICKX so far */

        for (size_t i = 0; i < sizeof later / sizeof later[0]; i++) {
            expect_421++;
            TF_CHECK_MSG(tc_send(&c, later[i]) == 0, "tc_send(%s) failed",
                         later[i]);
        }
        /* A PONG is the drain: the node reports it last, so by the time it is
         * in hand every verb above has been read and answered (or not). */
        TF_CHECK_MSG(tc_send(&c, "PING :drain") == 0, "tc_send failed");
        TF_CHECK_MSG(tc_expect(&c, "PONG irc.test drain", T_IO_MS) == 0,
                     "no PONG after the unimplemented-verb sweep");
        TF_CHECK_MSG(tf_count(tc_buffer(&c), " 421 ") == expect_421,
                     "expected %zu 421 lines and saw %zu: a planned verb "
                     "answered something other than 421, or was dropped "
                     "silently", expect_421, tf_count(tc_buffer(&c), " 421 "));
    }

    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0");
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", 1, T_IO_MS) == 0,
                 "accepted should be 1");
    TF_CHECK_MSG(nf_expect_u64(&node, "closed=", 1, T_IO_MS) == 0,
                 "closed should be 1");

    tc_close(&c);
    nf_free(&node);
    tf_done("pre_register");
    return 0;
}
