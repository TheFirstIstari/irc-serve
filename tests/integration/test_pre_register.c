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
 *   421  the client IS registered and sent a verb 4.1 lists that a LATER phase
 *        still owns (`PRIVMSG`, `NOTICE`, `KILL`). A slight lie about the
 *        reason -- the wire has no numeric for "not yet" -- but the alternative
 *        is silence, and the node records which of the two it was so a log
 *        reader is not misled.
 *
 * WHAT CHANGED IN PHASE 4, AND WHY IT IS A STRENGTHENING
 * ---------------------------------------------------
 * This test originally used `JOIN` as its example of the third case, because in
 * Phase 3 JOIN was a 4.1 verb nobody had implemented. Phase 4 implements it, so
 * JOIN is no longer in that category and the assertion had to move. The property
 * being tested did not move with it: it is still "every 4.1 verb is ANSWERED,
 * never dropped", and it is now asserted in BOTH directions, which is a stronger
 * statement than the original:
 *
 *   - a verb a later phase still owns produces exactly one 421 and nothing else;
 *   - a verb Phase 4 owns produces its real numerics and NO 421, which is the
 *     half the original could not check (a Phase 3 JOIN answering 421 and a
 *     Phase 4 JOIN answering 421 were indistinguishable on the wire).
 *
 * Nothing was removed and nothing was loosened. The 451 gate is still probed
 * with JOIN -- it is a registered-client gate, and a verb this node implements is
 * a BETTER probe for it than one it does not, because the gate has to hold for
 * the verbs the node is most likely to be asked about.
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
     *
     * It must not be answered 421 either. Phase 4 owns JOIN, so the assertion
     * here is the real JOIN sequence -- byte for byte, CRLF included, so this
     * checks the format of the numerics rather than the fact that the digits
     * "353" turn up somewhere. #somewhere is new and alice is its only member,
     * so the 353 lists exactly one name.
     *
     * That name is rendered WITH A PREFIX: alice is the channel's CREATOR, and
     * RFC 1459 2.3.1 makes the creator a channel operator. The test was first
     * written expecting a bare "alice" and timed out for 15 s waiting for it --
     * which is the correct behaviour of tc_expect() and the reason this
     * assertion was worth getting exactly right. The +o is not decoration:
     * every MODE +o and every KICK this node accepts requires an operator, so
     * a creator rendered without one is a channel nobody can manage.
     * --------------------------------------------------------------------- */
    TF_CHECK_MSG(tc_send(&c, "JOIN #somewhere") == 0, "tc_send failed");
    /* The channel name is stored uppercase-normalised (2.2), so it is UPPERCASE
     * on the wire. That is not cosmetic: a lookup that did not fold case the
     * same way the store did would make "#Somewhere" and "#somewhere" two
     * channels, and the second JOIN below would create one rather than finding
     * the first. */
    expect_line(&c, "the JOIN echo",
                ":alice!alice@127.0.0.1 JOIN #SOMEWHERE\r\n");
    expect_line(&c, "331 for a channel with no topic",
                ":irc.test 331 alice #SOMEWHERE :No topic is set\r\n");
    /* A single name contains no separator, so the formatter renders it
     * uncoloned -- message_format() colons the trailing parameter only when it
     * would otherwise not survive a re-parse, and that rule is Phase 1's and is
     * tested there. The two forms are the same message to a client. Asserted as
     * the bytes actually are, not as a convention. */
    expect_line(&c, "353 for a channel this client is alone in",
                ":irc.test 353 alice = #SOMEWHERE @alice\r\n");
    expect_line(&c, "366 terminating the names list",
                ":irc.test 366 alice #SOMEWHERE :End of /NAMES list\r\n");
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
    TF_CHECK_MSG(tf_count(tc_buffer(&c), " 421 ") == 1,
                 "expected exactly one 421 line, saw %zu",
                 tf_count(tc_buffer(&c), " 421 "));

    /* Lower case is the same command: 3.2 uppercases the command word, so a
     * client that sends "join" is not suddenly sending an unknown verb. Since
     * Phase 4 owns JOIN, that is now visible as a SECOND 366 for the same
     * channel rather than a 421 -- the verb is recognised AND the channel is
     * found case-insensitively, because a name lookup that folded case
     * differently from the stored name would make "#Somewhere" a second
     * channel. */
    TF_CHECK_MSG(tc_send(&c, "join #somewhere") == 0, "tc_send failed");
    expect_line(&c, "a lower-case verb after registration",
                ":irc.test 353 alice = #SOMEWHERE @alice\r\n");
    /* Drain with a PING before counting. A 366 could still be in flight when the
     * 353 above matched, and a count taken mid-stream is a race that passes or
     * fails on the scheduler -- which is what 6.3's no-sleeps rule is for, not
     * for. The PONG cannot overtake the 366 because the node writes them in
     * order, so seeing the PONG means the 366 is already in the buffer. */
    TF_CHECK_MSG(tc_send(&c, "PING :casefold-drain") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_expect(&c, "PONG irc.test casefold-drain", T_IO_MS) == 0,
                 "no PONG after the lower-case JOIN");
    TF_CHECK_MSG(tf_count(tc_buffer(&c), " 366 ") == 2,
                 "a repeat JOIN in a different case produced %zu 366 lines, "
                 "expected 2: the channel was either not found or created twice",
                 tf_count(tc_buffer(&c), " 366 "));
    TF_CHECK_MSG(tf_count(tc_buffer(&c), " 421 ") == 1,
                 "a verb this build implements was answered 421");

    /* The node distinguishes "never heard of it" from "arrives in a later
     * phase" in its own output, so a log reader is not told a planned verb is
     * unknown -- and the Phase 4 verbs are no longer in that category. The
     * cmd_unimplemented check is made further down, after the sweep has sent a
     * verb that really is one, because that is the only point at which the node
     * has had a chance to record one. */
    TF_CHECK_MSG(nf_expect(&node, "cmd_unknown: fd=", T_IO_MS) == 0,
                 "the node did not record NICKX as an unknown verb");
    TF_CHECK_MSG(nf_expect(&node, "chan_join: channel=#SOMEWHERE", T_IO_MS) == 0,
                 "the node did not record JOIN as an implemented verb: it is "
                 "still being answered through the unimplemented path");

    /* ---------------------------------------------------------------------
     * Every 4.1 verb is ANSWERED, not dropped, and the two categories now have
     * opposite answers on the wire. A verb that fell through to silence would be
     * invisible in this test and invisible in production, so each is sent, the
     * whole batch is drained with a PING whose answer cannot overtake them, and
     * the counts are checked.
     * --------------------------------------------------------------------- */
    {
        /* Still a later phase's: one 421 each, and nothing else. */
        static const char *const later[] = {
            "PRIVMSG #x :hi", "NOTICE #x :hi", "KILL bob"
        };
        /* One so far (NICKX), plus one for each verb in `later`. */
        size_t expect_421 = 1 + sizeof later / sizeof later[0];
        /* Where the "before" window ends. The casefold-drain PONG above is the
         * last thing the node had written at this point, so everything after it
         * is an answer to the sweep. Counting from a remembered offset is what
         * makes "no 421 arrived" a statement about those verbs rather than about
         * the whole session. */
        const char *const at = strstr(tc_buffer(&c), "PONG irc.test casefold-drain");
        size_t drain;

        TF_CHECK_MSG(at != NULL,
                     "expected the casefold-drain PONG in the buffer");
        drain = (at != NULL) ? (size_t)(at - tc_buffer(&c)) : 0u;

        /* Batch 1: a later phase's verbs. Each must be 421, and only 421. */
        for (size_t i = 0; i < sizeof later / sizeof later[0]; i++) {
            TF_CHECK_MSG(tc_send(&c, later[i]) == 0, "tc_send(%s) failed",
                         later[i]);
        }
        TF_CHECK_MSG(tc_send(&c, "PING :drain-later") == 0, "tc_send failed");
        TF_CHECK_MSG(tc_expect(&c, "PONG irc.test drain-later", T_IO_MS) == 0,
                     "no PONG after the unimplemented-verb sweep");
        TF_CHECK_MSG(tf_count(tc_buffer(&c) + drain, " 421 ") ==
                         sizeof later / sizeof later[0],
                     "expected %zu 421 lines for the unimplemented verbs and "
                     "saw %zu: a planned verb answered something other than 421, "
                     "or was dropped silently",
                     sizeof later / sizeof later[0],
                     tf_count(tc_buffer(&c) + drain, " 421 "));

        /* Batch 2: Phase 4's verbs, against a FRESH window. Reusing batch 1's
         * offset would conflate the two categories, which is the whole
         * distinction -- batch 1 must be 421 and batch 2 must not be, and a
         * shared window cannot show that. */
        {
            static const char *const now[] = {
                "PART #x", "TOPIC #x :t", "NAMES #x", "MODE #x", "KICK #x bob"
            };
            const char *const at2 =
                strstr(tc_buffer(&c), "PONG irc.test drain-later");
            size_t drain2 = (at2 != NULL) ? (size_t)(at2 - tc_buffer(&c)) : 0u;

            TF_CHECK_MSG(at2 != NULL, "expected the drain-later PONG");
            for (size_t i = 0; i < sizeof now / sizeof now[0]; i++) {
                TF_CHECK_MSG(tc_send(&c, now[i]) == 0, "tc_send(%s) failed",
                             now[i]);
            }
            TF_CHECK_MSG(tc_send(&c, "PING :drain-now") == 0, "tc_send failed");
            TF_CHECK_MSG(tc_expect(&c, "PONG irc.test drain-now", T_IO_MS) == 0,
                         "no PONG after the implemented-verb sweep");
            TF_CHECK_MSG(tf_count(tc_buffer(&c) + drain2, " 421 ") == 0,
                         "a verb Phase 4 implements was answered 421: %zu "
                         "421 lines arrived in the implemented-verb window",
                         tf_count(tc_buffer(&c) + drain2, " 421 "));
            /* And they were ANSWERED, not dropped: each produced output. A verb
             * that produced nothing would satisfy a 421 count of zero, which is
             * the silent failure this test exists to prevent. */
            TF_CHECK_MSG(tf_count(tc_buffer(&c) + drain2, "\r\n") >=
                             sizeof now / sizeof now[0],
                         "only %zu lines arrived for %zu implemented verbs: at "
                         "least one was dropped silently",
                         tf_count(tc_buffer(&c) + drain2, "\r\n"),
                         sizeof now / sizeof now[0]);
        }
        TF_CHECK_MSG(tf_count(tc_buffer(&c), " 421 ") == expect_421,
                     "expected %zu 421 lines and saw %zu overall", expect_421,
                     tf_count(tc_buffer(&c), " 421 "));
    }

    /* The "planned but not yet implemented" record, now that the sweep above has
     * actually sent one. Checked here rather than earlier because this is the
     * first point at which the node has had a chance to emit it -- a check made
     * before the sweep would pass against a node that never records the
     * distinction at all. */
    TF_CHECK_MSG(nf_expect(&node, "cmd_unimplemented: fd=", T_IO_MS) == 0,
                 "the node did not record an unimplemented-but-planned verb "
                 "(PRIVMSG, NOTICE and KILL are all still Phase 5+ verbs)");

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
