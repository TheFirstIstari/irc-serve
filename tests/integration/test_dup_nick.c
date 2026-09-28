/* test_dup_nick.c -- Phase 3's second acceptance criterion, taken to the point
 * where it actually says something.
 *
 * docs/SERVER_DESIGN.md 7/Phase 3: "Accept: integration test registers and
 * receives 001 and 005; duplicate nick -> 433." 2.1: nick uniqueness is
 * enforced PER SERVER, which is why a single node has a registry to consult at
 * all.
 *
 * "A second client taking a live nick receives 433 and the incumbent keeps it"
 * has two halves, and the second is the one that is easy to fake. Checking that
 * the second client got 433 is trivial. Checking that the INCUMBENT kept the
 * name is not, because a registry that handed the name to the loser anyway
 * would still have sent the 433 -- the loser is refused, then the name moves
 * behind its back, and the only symptom is two users both called `alice` on a
 * node whose whole identity scheme is nick@server.
 *
 * So the incumbent's ownership is proved by taking the name AWAY from it and
 * handing it to somebody else, then watching it fail to come back:
 *
 *   alice holds "shared"
 *   bob is refused "shared"            -> 433
 *   alice renames to "alice2"         -> the name is released
 *   carol takes "shared" and registers-> so the release happened
 *   alice renames back to "shared"    -> 433, because carol holds it now
 *
 * Every step is an assertion about a registry fact, and the last one is only
 * possible if the registry follows the holder rather than the requester. The
 * wire is real TCP to the shipped binary throughout; there is no in-process
 * shortcut to the strtab.
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

static void connect_and(test_client_t *c, int port, const char *nick)
{
    char line[128];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "tc_connect to port %d failed",
                 port);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "tc_send(NICK %s) failed", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 * :%s Example", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "tc_send(USER) failed");
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0,
                 "no 001 after registering as %s", nick);
}

int main(void)
{
    nf_node_t node;
    test_client_t alice;
    test_client_t bob;
    test_client_t carol;

    tc_init(&alice);
    tc_init(&bob);
    tc_init(&carol);

    TF_CHECK(nf_spawn_binary(&node) == 0);
    TF_CHECK_MSG(node.port > 0, "node reported no usable port");

    /* 1. alice registers and holds "shared". */
    connect_and(&alice, node.port, "shared");

    /* 2. A second client asking for a live name is refused, with "*" as the
     * target because it has no nickname yet -- which is what RFC 2812 3.3
     * requires and what makes the line parseable for a client that is still
     * mid-registration. The colliding name is the middle parameter. */
    TF_CHECK_MSG(tc_connect(&bob, node.port) == 0, "tc_connect failed");
    TF_CHECK_MSG(tc_send(&bob, "NICK shared") == 0, "tc_send failed");
    expect_line(&bob, "duplicate nick",
                ":irc.test 433 * shared :Nickname is already in use\r\n");

    /* 3. The loser is not stuck: it takes a free name and registers normally. */
    TF_CHECK_MSG(tc_send(&bob, "NICK bob") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&bob, "USER bob 0 * :Bob Example") == 0,
                 "tc_send failed");
    TF_CHECK_MSG(tc_expect(&bob, " 001 bob :Welcome", T_IO_MS) == 0,
                 "the refused client could not register under a free name: a "
                 "433 must not wedge the state machine");

    /* 4. alice hands the name back by renaming away from it. */
    TF_CHECK_MSG(tc_send(&alice, "NICK alice2") == 0, "tc_send failed");
    TF_CHECK_MSG(nf_expect(&node, "from=shared to=alice2", T_IO_MS) == 0,
                 "alice's rename away from \"shared\" did not happen, so the "
                 "next step proves nothing");

    /* 5. carol takes the vacated name and registers. This is the proof that
     * alice's rename RELEASED it rather than just moving alice off it while
     * leaving the registry entry pointing at a dead nick. */
    connect_and(&carol, node.port, "shared");

    /* 6. And now alice cannot have it back, because carol holds it. If the
     * registry followed the LAST REQUESTER instead of the holder, this would
     * succeed and the node would be running two users called "shared". */
    TF_CHECK_MSG(tc_send(&alice, "NICK shared") == 0, "tc_send failed");
    expect_line(&alice, "renaming onto a live name",
                ":irc.test 433 alice2 shared :Nickname is already in use\r\n");

    /* 7. alice kept what she had: the failed claim changed nothing. */
    TF_CHECK_MSG(tc_send(&alice, "NICK alice2") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&alice, "PING :still-alice2") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_expect(&alice, "PONG irc.test still-alice2", T_IO_MS) == 0,
                 "alice lost her own nickname to a failed claim");
    TF_CHECK_MSG(tf_count(tc_buffer(&alice), " 001 ") == 1,
                 "a nickname change re-sent the welcome burst: 001 count is "
                 "%zu, expected 1", tf_count(tc_buffer(&alice), " 001 "));

    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");

    /* Two claims were refused in this test -- bob's and alice's -- and exactly
     * two. Counting the refusals is how "the incumbent keeps it" is confirmed
     * from the node's side as well as the wire's: a fourth claim, or a second
     * refusal for a claim that succeeded, would both move this number.
     *
     * After nf_stop(), which drains the child's output. The node's stdout is a
     * pipe that is only read when something asks for it, so counting before
     * the child has exited would count whatever had happened to be pumped
     * already -- which is a number that depends on scheduling, and is exactly
     * the read-once race the harness warns about. */
    TF_CHECK_MSG(tf_count(node.out, "reason=in_use") == 2,
                 "the node refused %zu nickname claims, expected 2",
                 tf_count(node.out, "reason=in_use"));
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0: a 433 the node could not render was "
                 "dropped instead of sent, which would leave a client waiting "
                 "for an answer that never comes");
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", 3, T_IO_MS) == 0,
                 "accepted should be 3");
    TF_CHECK_MSG(nf_expect_u64(&node, "closed=", 3, T_IO_MS) == 0,
                 "closed should be 3: every connection closed exactly once");

    tc_close(&alice);
    tc_close(&bob);
    tc_close(&carol);
    nf_free(&node);
    tf_done("dup_nick");
    return 0;
}
