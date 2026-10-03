/* test_choper.c -- CHOPER on the wire, against the real binary.
 *
 * docs/SERVER_DESIGN.md 4.2 (CHOPER, Phase 7), 4.4 (401, 464) and RFC 2812
 * 3.4.1. See commands.c's handle_choper() for the argument that 464 is the right
 * refusal and that 381 is never emitted.
 *
 * ---------------------------------------------------------------------------
 * A COMMAND WHOSE WHOLE BEHAVIOUR IS A REFUSAL, AND WHY THAT STILL NEEDS A TEST
 * ---------------------------------------------------------------------------
 * Three things distinguish an honest refusal from a stub, and each is a separate
 * assertion:
 *
 *   1. THE TARGET IS LOOKED UP. `CHOPER ghost <password>` is 401 and
 *      `CHOPER alice <password>` is 464. A handler that answered 464 to every
 *      line would be refusing a request about a user who is demonstrably
 *      connected, and 464's text would then be about the wrong thing. Neither
 *      numeral is optional; both are asserted for their own input.
 *   2. 381 RPL_YOUREOPER IS ABSENT. This is the assertion with teeth. A node
 *      that faked the grant passes the 464 check and fails this one, and the
 *      faking is exactly what a stub does.
 *   3. THE PASSWORD IS NOT ECHOED ANYWHERE. Not on the wire -- which is a
 *      property of the node's own output and is asserted by reading the
 *      observable log rather than a socket. A node that printed a secret to its
 *      stdout leaks it into every log collector downstream, and no amount of
 *      correct wire behaviour makes up for that. PASS has the same discipline
 *      (commands.c's handle_pass) and CHOPER inherits it.
 *
 * ---------------------------------------------------------------------------
 * WHY 464 AND NOT 482
 * ---------------------------------------------------------------------------
 * Asserted here as a whole exact line, text included, because the TEXT is the
 * claim. 482 is what KICK and MODE use and it is right there -- a client with no
 * +o really is under-privileged. Here it would be the false claim: the caller is
 * not under-privileged, the SERVER has no operator privilege to grant, and the
 * same caller would get the same answer with every password. 464 is also what
 * RFC 2812 3.4.1 names for a CHOPER that did not take effect.
 *
 * NO sleep() ANYWHERE (6.3): every wait is a select()-driven deadline inside
 * tc_expect(), and every negative assertion is scoped to a window closed by a
 * PING drain. A bare tc_expect() searches the whole accumulated buffer, so a
 * second ` 464 ` would match the first and return instantly.
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

/* A password distinctive enough that finding it anywhere in the node's output is
 * unambiguous, and distinctive enough that a "the test's own needle appeared in
 * the log" confusion is not possible. It is not a real credential; it exists to
 * be looked for. */
#define SECRET "choper-secret-0xC0FFEE"

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
    size_t from, end;
    char line[256];

    if (nf_spawn_binary(&node) != 0) {
        fprintf(stderr, "could not spawn the irc-serve binary\n");
        return 1;
    }
    TF_CHECK_MSG(nf_expect(&node, "loop_running:", T_READY_MS) == 0,
                 "the node never reported its loop armed");

    client_open(&alice, &node, "alice");
    client_open(&bob, &node, "bob");

    /* =======================================================================
     * 1. A target this node holds: 464, naming the target, and no 381
     * ==================================================================== */
    /* alice is granted nothing, and the trailing text is the whole claim: the
     * SERVER has no operator flags and no credentials. A client that rendered
     * this as "your password was wrong" would be reporting a fault in a place
     * where there is none, so the sentence is asserted byte for byte rather than
     * by its numeric. */
    (void)snprintf(line, sizeof line, "CHOPER alice %s", SECRET);
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, line) == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "464 for a held target",
                     ":" BIN_NAME " 464 alice :alice cannot become an operator: "
                     "this server holds no operator flags and no operator "
                     "credentials\r\n");
    /* 381 RPL_YOUREOPER is the success answer and must never be emitted. This is
     * the assertion with teeth for the whole file: a node that faked the grant
     * satisfies the 464 check above and fails here. */
    expect_absent_in_window(&alice, from, end, "the CHOPER refusal", " 381 ");
    /* Nor is the target told anything. CHOPER's 464 goes to the REQUESTER, and
     * the target is a bystander who was named -- the same rule as INVITE's 341,
     * where the numeric goes to the actor and the other party gets a different
     * line or nothing. A node that sent the refusal to the target as well would
     * be telling a user that somebody tried to make them an operator. */
    from = mark(&bob);
    end = mark(&bob);
    expect_absent_in_window(&bob, from, end, "the named target's window",
                            " 464 ");
    expect_absent_in_window(&bob, from, end, "the named target's window",
                            " 381 ");

    /* A client cannot CHOPER ITSELF either. Same answer, because the gate is the
     * server's and not the caller's: a self-CHOPER is the one case where "you are
     * under-privileged" would be a plausible-sounding lie, and it is here because
     * nobody on this node is an operator at all. */
    (void)snprintf(line, sizeof line, "CHOPER bob %s", SECRET);
    from = mark(&bob);
    TF_CHECK_MSG(tc_send(&bob.c, line) == 0, "tc_send failed");
    end = mark(&bob);
    expect_in_window(&bob, from, end, "464 for a self-CHOPER",
                     ":" BIN_NAME " 464 bob :bob cannot become an operator: this "
                     "server holds no operator flags and no operator "
                     "credentials\r\n");

    /* A DIFFERENT password changes nothing, and that is the property which shows
     * the refusal is not a comparison. Two passwords, two answers, byte for byte
     * identical: a node that actually compared them would have to differ
     * somewhere, and a node with no store to compare against cannot. */
    (void)snprintf(line, sizeof line, "CHOPER alice another-password");
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, line) == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "464 for a different password",
                     ":" BIN_NAME " 464 alice :alice cannot become an operator: "
                     "this server holds no operator flags and no operator "
                     "credentials\r\n");

    /* =======================================================================
     * 2. A target this node does not hold: 401, and NOT 464
     * ==================================================================== */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "CHOPER ghost whatever") == 0,
                 "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "401 for an unknown target",
                     ":" BIN_NAME " 401 alice ghost :No such nick/channel\r\n");
    /* 464 must not also come back. Both would be true statements, and a client
     * reading two numerics for one line cannot tell which is the answer -- and
     * 464's text would then be about a server rather than about a user who does
     * not exist. */
    expect_absent_in_window(&alice, from, end, "the unknown-target CHOPER",
                            " 464 ");

    /* Case folding, because 2.1 makes nicknames case-insensitive and the fold is
     * the registry's. A CHOPER that 401'd a differently-cased spelling of a
     * connected user would be refusing somebody who is demonstrably there. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "CHOPER BOB whatever") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "464 for a differently-cased target",
                     ":" BIN_NAME " 464 alice :bob cannot become an operator: "
                     "this server holds no operator flags and no operator "
                     "credentials\r\n");
    /* And the DISPLAYED case is the target's own, so the 464 names BOB as `bob`.
     * The absence is the assertion: a node that folded the stored name would
     * render `BOB` here and every display assertion in the tree would be
     * ambiguous about which spelling is real. */
    expect_absent_in_window(&alice, from, end, "the folded CHOPER", "BOB cannot");

    /* =======================================================================
     * 3. Arity
     * ==================================================================== */
    /* CHOPER takes exactly two parameters (RFC 2812 3.4.1). One is 461 rather
     * than 462: 461 is the numeral every handler in this node uses and the one
     * 4.4 lists, and a client that saw 462 from one handler and 461 from another
     * would have to special-case it. Three is also 461, for the reason
     * msg_verbs.c's send_message() gives: the grammar has already absorbed
     * everything after a ':', so a third parameter is not text the client meant
     * to send.
     *
     * The `CHOPER` between alice and the text is RFC 2812 5.2's `<command>` field,
     * which 461's field list names. It is asserted in all four needles because
     * these four cases share one arity check and one answer, and a needle that
     * stopped at `461 alice` would pass against a 461 that named no verb. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "CHOPER alice") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "461 for one parameter",
                     ":" BIN_NAME " 461 alice CHOPER :Not enough parameters\r\n");
    expect_absent_in_window(&alice, from, end, "the one-parameter CHOPER",
                            " 464 ");

    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "CHOPER") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "461 for no parameters",
                     ":" BIN_NAME " 461 alice CHOPER :Not enough parameters\r\n");

    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "CHOPER alice " SECRET " extra") == 0,
                 "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "461 for three parameters",
                     ":" BIN_NAME " 461 alice CHOPER :Not enough parameters\r\n");
    expect_absent_in_window(&alice, from, end, "the three-parameter CHOPER",
                            " 464 ");

    /* A client that forgot the target and typed the password as a TRAILING
     * parameter -- `CHOPER :<password>` -- gets 461, not 464. This is worth a
     * case of its own because it is the mistake a real client makes, and because
     * the ':' absorbs the rest of the line into ONE parameter: the message has
     * one parameter, not two, so the arity check is what catches it. It is also
     * why this node CANNOT be asked to look up an empty nickname: 3.2 has no way
     * to express an empty middle parameter (4.3.1 says the same about a wire
     * format), so a name that reaches fanout_find_nick() from here is
     * non-empty by construction. The guard is defence in depth for a caller that
     * does not share that grammar, and there is deliberately no test for a
     * state the wire cannot produce. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "CHOPER :" SECRET) == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "461 for a trailing password",
                     ":" BIN_NAME " 461 alice CHOPER :Not enough parameters\r\n");
    expect_absent_in_window(&alice, from, end, "the trailing-password CHOPER",
                            " 464 ");
    expect_absent_in_window(&alice, from, end, "the trailing-password CHOPER",
                            " 401 ");

    /* =======================================================================
     * 4. The password is nowhere in the node's own output
     * ==================================================================== */
    /* Not on the wire is a property of reply(), which is already covered by
     * test_reply_guard.c and test_fed_wire.c. The leak that is NOT covered
     * anywhere is the LOG: a node that printed a secret to stdout would put it
     * into every collector downstream, and no wire assertion can see that. The
     * search is over the child's own stdout, which the fixture has already
     * captured -- the same bytes the `[observable]` lines arrive on, and the
     * observable output of the node by design. It is read here rather than
     * searched with nf_expect(), which can only assert that a needle IS
     * present; a negative is what this needs and the harness has no helper for
     * it.
     *
     * The node has by now answered five CHOPERs carrying SECRET or a different
     * password, plus the registration of two clients, so anything the node
     * printed about a CHOPER would be in this buffer. */
    TF_CHECK_MSG(node.out != NULL && node.out_len > 0u,
                 "the fixture captured none of the node's output, so asserting "
                 "the absence of the password would prove nothing");
    TF_CHECK_MSG(node.out != NULL && strstr(node.out, SECRET) == NULL,
                 "the password \"%s\" appears in the node's own output: a CHOPER "
                 "secret was written to the log",
                 SECRET);
    /* And the refusal WAS logged, so the absence above is not the absence of any
     * CHOPER output at all. A node that logged nothing would satisfy the check
     * above for the wrong reason, and this is what tells the two apart. */
    TF_CHECK_MSG(node.out != NULL && strstr(node.out, "choper_refused") != NULL,
                 "the node logged no choper_refused line, so the check that the "
                 "password is absent is passing because nothing was written");
    /* The target IS in the log. The discipline is about the SECRET, not about
     * suppressing the whole event, and asserting the name is present is what
     * makes the password's absence mean something. */
    TF_CHECK_MSG(node.out != NULL && strstr(node.out, "target=alice") != NULL,
                 "the refusal did not name the target, so the CHOPER was not "
                 "actually logged and the password check is vacuous");

    /* =======================================================================
     * The node's own accounting
     * ==================================================================== */
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0");
    /* n_pass_seen is untouched: CHOPER is not PASS. A node that routed a
     * CHOPER's password through the PASS counter would be recording a secret it
     * was given for a different purpose, and the count is read after nf_stop()
     * because that is when the node publishes it. */
    TF_CHECK_MSG(nf_expect_u64(&node, "pass_seen=", 0, T_IO_MS) == 0,
                 "pass_seen is not 0, so a CHOPER password was recorded as a PASS");
    TF_CHECK_MSG(nf_expect_u64_ge(&node, "accepted=", g_opened, T_IO_MS) == 0,
                 "the node accepted fewer connections than the test opened (%zu)",
                 g_opened);

    tc_close(&alice.c);
    tc_close(&bob.c);
    nf_free(&node);
    tf_done("choper");
    return 0;
}
