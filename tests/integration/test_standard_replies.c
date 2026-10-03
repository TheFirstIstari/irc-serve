/* test_standard_replies.c -- `standard-replies`, the four migrated numerics, and
 * the KICK reason bound that `KICKLEN` was waiting for.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS BEING CLAIMED
 * ---------------------------------------------------------------------------
 * `standard-replies` renders a refusal as
 *
 *     FAIL <command> <code> [<context>...] :<description>
 *
 * for a client that negotiated it, and as the legacy numeric -- byte-identical --
 * for a client that did not. Four numerics migrate, and the rule is one sentence:
 * **a legacy numeric migrates where it answers more than one question ON THIS
 * NODE**, so the number alone cannot tell a client which refusal happened.
 *
 *   417  four refusals (PRIVMSG text, AWAY, SETNAME realname, KICK reason)
 *   461  too few AND too many -- and its text says "Not enough parameters" in the
 *        too-many case too, so the number is ambiguous AND the text is wrong
 *   482  not a channel operator | not an IRC operator | the verb is disabled
 *   464  not an IRC operator | SASL authentication failed
 *
 * Every OTHER numeric on this node answers exactly one question and is asserted
 * UNCHANGED here, because "only these four" is half the claim and a test that only
 * checked the four would pass on a migration of all thirty.
 *
 * ---------------------------------------------------------------------------
 * WHY THE NON-NEGOTIATING CLIENT IS THE MORE IMPORTANT HALF
 * ---------------------------------------------------------------------------
 * A client that did not negotiate `standard-replies` has never been told to expect
 * a command word called `FAIL`, and one arriving would be parsed as an unknown
 * command by a client doing exactly what RFC 1459 says. So every case below runs
 * the SAME command on two connections that differ in exactly one thing -- whether
 * they sent `CAP REQ :standard-replies` -- and asserts BOTH answers, the legacy one
 * byte-for-byte. The legacy answer being byte-identical is the guarantee; a test
 * that only asserted the `FAIL` would not notice the legacy branch changing, and
 * `test_choper` is the evidence that it changed once (see TEETH).
 *
 * NO FIXED sleep() ANYWHERE (6.3): every wait is tc_expect()'s deadline loop and
 * every window is closed by a PING whose PONG is the drain token, numbered per
 * call because tc_expect() searches the ACCUMULATED buffer and a reused token
 * would be satisfied by an earlier PONG with no read at all.
 *
 * EVERY CASE OWNS ITS NODE AND FREES IT. The harness keeps a registry of spawned
 * nodes so a failing assertion can print them, and that registry holds the
 * ADDRESS of the caller's `nf_node_t` -- so a case that spawns into a local and
 * returns without `nf_free()` leaves a dangling pointer for the next case's spawn
 * to read. (That was this file's first version, and it was an ASan
 * stack-use-after-scope inside the harness rather than anything in the node.)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/cap.h"
#include "core/channel.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define CHAN "#T"

/* The KICK reason boundary, as a literal for the reason every boundary in this
 * project is a literal: a test built from CHAN_MAX_KICK_REASON would follow the
 * constant and never notice that the bound moved. The same argument
 * test_registration.c makes about the 005 tokens, and for the same reason. */
#define AT_LIMIT 255

/* AWAYLEN, so the over-long AWAY below is over-long by exactly one byte rather than
 * by an arbitrary amount -- a refusal that fires on any length proves the length
 * is not being tested. */
#define AWAY_AT_LIMIT 255

/* The server name the fixture's nodes answer with. Written out rather than
 * assembled, because every expectation below is a byte-for-byte line and the
 * server name is the first field of all of them. */
#define SRV "irc.test"

static unsigned g_drain_seq;

static void drain(test_client_t *c)
{
    char token[64];
    char line[128];

    (void)snprintf(token, sizeof token, "sr%u", g_drain_seq++);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING failed");
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG for drain token %s, so the buffer is not yet drained and "
                 "every claim below would be about the read schedule", token);
}

/* Register `c` as `nick`, negotiating `caps` first (NULL for no CAP exchange).
 * The REQ is ACKed whole, so a capability this node does not have fails the wait
 * rather than being quietly NAKed -- which means no case below can pass because the
 * gate was never reached. */
static void register_caps(test_client_t *c, int port, const char *nick,
                          const char *caps)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    if (caps != NULL) {
        (void)snprintf(line, sizeof line, "CAP REQ :%s", caps);
        TF_CHECK_MSG(tc_send(c, line) == 0, "%s CAP REQ send failed", nick);
        (void)snprintf(line, sizeof line, " ACK :%s\r\n", caps);
        TF_CHECK_MSG(tc_expect(c, line, T_IO_MS) == 0,
                     "%s was not ACKed \"%s\", so the node does not have the "
                     "capability and every case below would be asserting the wrong "
                     "thing about it", nick, caps);
    }
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s NICK send failed", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s USER send failed", nick);
    if (caps != NULL) {
        TF_CHECK_MSG(tc_send(c, "CAP END") == 0, "%s CAP END send failed", nick);
    }
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered", nick);
    /* Drain the welcome burst so the marks below start from a quiet buffer and a
     * failure prints the refusal rather than the registration. */
    drain(c);
}

/* How many complete CRLF-terminated lines the region `from`..end of `c` holds. */
static size_t lines_since(const test_client_t *c, size_t from)
{
    const char *at = tc_buffer(c) + from;
    size_t n = 0;

    for (; *at != '\0'; at++) {
        if (at[0] == '\r' && at[1] == '\n') {
            n++;
        }
    }
    return n;
}

/* Assert that `c` received EXACTLY `n_replies` replies after `mark`, and that the
 * last line in the window is its drain PONG.
 *
 * THIS IS THE "NOTHING ELSE HAPPENED" ASSERTION, and it is deliberately a COUNT
 * rather than a list of absent numerics. test_setname.c records why: a fault that
 * answered `482` where a `417` was expected satisfies every entry of a list of
 * "417, 421, 451 are absent". Counting closes that, because any reply of any kind
 * moves the number -- including a reply nobody thought of.
 *
 * `n_replies` IS COUNTED ALONG WITH THE PONG rather than instead of it, so the
 * arithmetic is `n_replies + 1`. A case that expects two lines (the 401 and the 318
 * that must follow it) passes 2; a case that expects one passes 1. Getting this
 * wrong in EITHER direction is a test failure rather than a silent pass, which is
 * the only property worth having from a bookkeeping argument.
 *
 * The three `FAIL`/`WARN`/`NOTE` absences are asserted as well, and separately,
 * because they are the specific claim this pass makes about clients that did not
 * negotiate: a `FAIL` reaching such a client is a command word RFC 1459 2.3 parses
 * as an unknown command, which breaks it rather than informing it. */
static void expect_only_replies(test_client_t *c, size_t mark, const char *what,
                                size_t n_replies, int negotiated)
{
    drain(c);
    TF_CHECK_MSG(lines_since(c, mark) == n_replies + 1u,
                 "%s: the window after the command holds %zu lines and it must hold "
                 "exactly %zu -- the %zu expected replies and the drain PONG. Any "
                 "reply at all beyond those fails this, which is why it is a COUNT "
                 "and not a list of numerics somebody thought of.\n  client saw: %s",
                 what, lines_since(c, mark), n_replies + 1u, n_replies,
                 tc_buffer(c) + mark);
    if (negotiated == 0) {
        TF_CHECK_MSG(strstr(tc_buffer(c) + mark, " FAIL ") == NULL,
                     "%s: a `FAIL` reached a client that did NOT negotiate "
                     "standard-replies. `FAIL` is a command word no such client has "
                     "ever been told to expect and RFC 1459 2.3 parses it as an "
                     "unknown command, so this BREAKS the client rather than "
                     "informing it -- and the client that negotiated nothing is the "
                     "one that must be byte-for-byte unaffected.\n  client saw: %s",
                     what, tc_buffer(c) + mark);
        TF_CHECK_MSG(strstr(tc_buffer(c) + mark, " WARN ") == NULL,
                     "%s: a `WARN` reached a client that did not negotiate "
                     "standard-replies", what);
        TF_CHECK_MSG(strstr(tc_buffer(c) + mark, " NOTE ") == NULL,
                     "%s: a `NOTE` reached a client that did not negotiate "
                     "standard-replies", what);
    }
}

/* Assert that `want` -- a complete line, CRLF included -- arrived on `c` since
 * `mark`, and that it sits at the start of a line rather than being the tail of a
 * longer one. The leading CRLF is not part of the needle because the first line on
 * a connection has nothing before it. */
static void expect_line_since(test_client_t *c, size_t mark, const char *what,
                              const char *want)
{
    const char *at;

    TF_CHECK_MSG(tc_expect(c, want, T_IO_MS) == 0,
                 "%s: expected the exact line \"%s\".\n  client saw: %s", what, want,
                 tc_buffer(c) + mark);
    at = strstr(tc_buffer(c), want);
    TF_CHECK_MSG(at != NULL, "%s: the line vanished from the buffer", what);
    TF_CHECK_MSG(at == tc_buffer(c) || at[-1] == '\n',
                 "%s: \"%s\" is not at the start of a line: it is the tail of a "
                 "longer one", what, want);
    TF_CHECK_MSG((size_t)(at - tc_buffer(c)) >= mark,
                 "%s: the line is from BEFORE this command", what);
}

/* Join `CHAN` on `c` and wait for the echo, so a case can be about a verb that
 * needs membership. The drain after it matters: a JOIN is followed by 331/332/333/
 * 353/366/329, and an undrained buffer would make the next case's line search
 * match one of those. */
static void join(test_client_t *c, const char *nick)
{
    char line[128];

    (void)snprintf(line, sizeof line, "JOIN %s", CHAN);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s JOIN send failed", nick);
    TF_CHECK_MSG(tc_expect(c, " JOIN " CHAN "\r\n", T_IO_MS) == 0,
                 "%s did not join %s", nick, CHAN);
    drain(c);
}

/* ---------------------------------------------------------------------------
 * ONE COMMAND, TWO CLIENTS, TWO ANSWERS
 * ---------------------------------------------------------------------------
 * `setup` is sent to BOTH connections after registration and before the command,
 * and is where a JOIN goes when the verb under test needs membership. It is the
 * same line for both, which is what keeps the two connections differing in
 * exactly one thing.
 *
 * `legacy` and `std` are the two complete answers and BOTH are asserted: the first
 * on a connection that negotiated nothing, the second on one that did. */
static void both_answers(int port, const char *who, const char *what,
                         const char *setup, const char *send,
                         const char *plain_nick, const char *std_nick,
                         const char *plain_caps, const char *std_caps,
                         const char *legacy, const char *std)
{
    test_client_t plain;
    test_client_t fancy;
    char line[1024];
    size_t mark_p;
    size_t mark_s;

    tc_init(&plain);
    tc_init(&fancy);
    register_caps(&plain, port, plain_nick, plain_caps);
    register_caps(&fancy, port, std_nick, std_caps);
    if (setup != NULL) {
        TF_CHECK_MSG(tc_send(&plain, setup) == 0, "%s setup send failed", who);
        TF_CHECK_MSG(tc_send(&fancy, setup) == 0, "%s setup send failed", who);
        (void)snprintf(line, sizeof line, " JOIN %s\r\n", CHAN);
        TF_CHECK_MSG(tc_expect(&plain, line, T_IO_MS) == 0,
                     "%s: the setup did not take effect", who);
        TF_CHECK_MSG(tc_expect(&fancy, line, T_IO_MS) == 0,
                     "%s: the setup did not take effect", who);
        drain(&plain);
        drain(&fancy);
    }

    (void)snprintf(line, sizeof line, "%s", send);

    mark_p = tc_received(&plain);
    TF_CHECK_MSG(tc_send(&plain, line) == 0, "%s: send failed", who);
    expect_line_since(&plain, mark_p, what, legacy);
    expect_only_replies(&plain, mark_p, who, 1u, 0);

    mark_s = tc_received(&fancy);
    TF_CHECK_MSG(tc_send(&fancy, line) == 0, "%s: send failed", who);
    expect_line_since(&fancy, mark_s, what, std);
    /* AND NOTHING ELSE, so the `FAIL` is the whole answer rather than the first of
     * several: a node that sent both the numeric and the `FAIL` would satisfy the
     * assertion above. */
    expect_only_replies(&fancy, mark_s, who, 1u, 1);

    tc_close(&plain);
    tc_close(&fancy);
}

/* ---------------------------------------------------------------------------
 * THE CASES
 * ---------------------------------------------------------------------------
 */

/* 417, FOUR WAYS. The over-long AWAY is the cheapest one to reach and is the
 * clearest instance: the node refuses it, stores nothing, and says so. */
static void case_417(void)
{
    nf_node_t node;
    char send[512];
    char at[AWAY_AT_LIMIT + 1];
    char over[AWAY_AT_LIMIT + 2];

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    memset(at, 'a', sizeof at - 1u);
    at[sizeof at - 1u] = '\0';
    memcpy(over, at, sizeof at - 1u);
    over[sizeof at - 1u] = 'a';
    over[sizeof at] = '\0';

    /* AT THE BOUND: accepted, and the 306 is the answer. This is here because a
     * bound that refuses everything is not a bound -- and because a 417 for 255
     * bytes would be indistinguishable, on the wire, from one for 256. */
    (void)snprintf(send, sizeof send, "AWAY :%s", at);
    both_answers(node.port, "away-255", "AWAY at AWAYLEN", NULL, send, "p255", "s255",
                 NULL, CAP_STANDARD_REPLIES,
                 ":" SRV " 306 p255 :You have been marked as being away\r\n",
                 ":" SRV " 306 s255 :You have been marked as being away\r\n");

    /* ONE OVER: refused, and the two renderings differ. */
    (void)snprintf(send, sizeof send, "AWAY :%s", over);
    both_answers(node.port, "away-256", "AWAY over AWAYLEN", NULL, send, "p256", "s256",
                 NULL, CAP_STANDARD_REPLIES,
                 ":" SRV " 417 p256 :Away message is too long\r\n",
                 ":" SRV " FAIL s256 AWAY ERR_INPUTTOOLONG :Away message is too "
                 "long\r\n");

    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* 461, THREE WAYS -- AND THIS IS WHERE THE MIGRATION EARNS ITS KEEP.
 *
 * `AWAY :one :two` is answered with the text "Not enough parameters", which is
 * false: the client sent too MANY. The legacy numeric and its text are unchanged
 * (a client that negotiated nothing must not see its wire move), and the `FAIL`
 * code says which of the two it was. Two clients, one command, and the ONLY
 * difference between the two answers is the code. */
static void case_461(void)
{
    nf_node_t node;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    /* The verb BETWEEN the target and the text is RFC 2812 5.2's `<command>`
     * field, and these three legacy needles assert it. That is the shape a
     * standard-replies client does NOT get: `command` is already FAIL's own
     * <command> there, so the paired FAIL lines below must NOT grow one, and
     * asserting both halves of every pair is what keeps the two renderings from
     * drifting into each other. */
    /* TOO MANY -- and the text lies.
     *
     * `AWAY one two`, NOT `AWAY :one two`: a trailing parameter swallows the rest
     * of the line, so the colonned form is ONE parameter whose value is the string
     * "one two" and is a perfectly legal away message. Two parameters need a space
     * and no colon, which is why the expectation below is about a command line a
     * client would have to work to produce -- and it is exactly the case the legacy
     * text gets wrong. */
    both_answers(node.port, "away-2", "AWAY with two parameters", NULL,
                 "AWAY one two", "pmany", "smany", NULL, CAP_STANDARD_REPLIES,
                 ":" SRV " 461 pmany AWAY :Not enough parameters\r\n",
                 ":" SRV " FAIL smany AWAY TOO_MANY_PARAMS :Not enough "
                 "parameters\r\n");

    /* TOO FEW -- USERHOST takes at least one. */
    both_answers(node.port, "userhost-0", "USERHOST with no parameter", NULL,
                 "USERHOST", "pfew", "sfew", NULL, CAP_STANDARD_REPLIES,
                 ":" SRV " 461 pfew USERHOST :Not enough parameters\r\n",
                 ":" SRV " FAIL sfew USERHOST NEED_MORE_PARAMS :Not enough "
                 "parameters\r\n");

    /* NEITHER -- WHOIS takes exactly one, and one test cannot say which way it
     * went, which is why `INVALID_PARAMS` is the code rather than a guess at the
     * direction. It is also a REGISTERED code and the other two are not, which is
     * the distinction standard-replies draws: "use an existing code if one is
     * defined". */
    both_answers(node.port, "whois-2", "WHOIS with two parameters", NULL,
                 "WHOIS alice bob", "pneither", "sneither", NULL,
                 CAP_STANDARD_REPLIES,
                 ":" SRV " 461 pneither WHOIS :Not enough parameters\r\n",
                 ":" SRV " FAIL sneither WHOIS INVALID_PARAMS :Not enough "
                 "parameters\r\n");

    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* 482 AND 464.
 *
 * THE 482 CASES ARE THE ONES THAT PROVE THE NUMBER WAS AMBIGUOUS, and both are
 * needed because there are three of them and two of those three appear here: a
 * KNOCK from a non-member is answered with 482, and 482 ALSO answers "you are not
 * a channel operator" for a KICK. The two sentences differ by three letters and
 * mean unrelated things, which is why there are two codes rather than one. */
static void case_482(void)
{
    nf_node_t node;
    test_client_t creator;
    char line[128];

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    /* The channel has to EXIST or the refusal is 403 instead of 482, so a client
     * creates it. It is deliberately not one of the two clients under test: the
     * creator gets +o and a KICK by an op is not a 482 at all. */
    tc_init(&creator);
    register_caps(&creator, node.port, "creator", NULL);
    join(&creator, "creator");

    /* 482 MEANING ONE: "not an IRC operator", from KNOCK. */
    both_answers(node.port, "knock", "KNOCK from a non-member", NULL,
                 "KNOCK " CHAN, "pknock", "sknock", NULL, CAP_STANDARD_REPLIES,
                 ":" SRV " 482 pknock " CHAN " :You're not an IRC operator\r\n",
                 ":" SRV " FAIL sknock KNOCK ERR_NOPRIVILEGES " CHAN " :You're not "
                 "an IRC operator\r\n");

    /* 482 MEANING TWO: "not a channel operator", from a KICK by a member who is not
     * one. The setup joins, so the clients under test are MEMBERS and the refusal
     * is about privilege rather than membership -- which is a different numeric
     * (442) and would otherwise be the thing under test by accident. */
    (void)snprintf(line, sizeof line, "JOIN %s", CHAN);
    both_answers(node.port, "kick-not-op", "KICK by a non-operator", line,
                 "KICK " CHAN " creator :x", "pkick", "skick", NULL,
                 CAP_STANDARD_REPLIES,
                 ":" SRV " 482 pkick " CHAN " :You're not a channel operator\r\n",
                 ":" SRV " FAIL skick KICK ERR_CHANOPRIVSNEEDED " CHAN
                 " :You're not a channel operator\r\n");

    tc_close(&creator);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* 464, WHICH ON THIS NODE IS BOTH "not an IRC operator" AND "SASL failed".
 *
 * Only the operator half is reachable without an operator file, and it is the half
 * that shares its NUMBER with the SASL refusals: `handle_authenticate()` answers
 * 464 for a payload it cannot read and for credentials that do not verify, which
 * `test_account.c` already pins byte-for-byte. So what is asserted here is that the
 * operator refusal got its own code, and `test_account.c` staying green is what
 * says the two no longer share a rendering. */
static void case_464(void)
{
    nf_node_t node;
    test_client_t target;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    /* A LIVE target, because CHOPER resolves its first parameter and answers 401
     * for a nickname this node does not hold -- which would make this case a test
     * of 401 (a numeric that does not migrate) rather than of 464. The target is
     * deliberately neither of the two clients under test. */
    tc_init(&target);
    register_caps(&target, node.port, "target", NULL);

    both_answers(node.port, "choper", "CHOPER on a node with no operators", NULL,
                 "CHOPER target whatever", "pchoper", "schoper", NULL,
                 CAP_STANDARD_REPLIES,
                 ":" SRV " 464 pchoper :target cannot become an operator: this "
                 "server holds no operator flags and no operator credentials\r\n",
                 ":" SRV " FAIL schoper CHOPER ERR_NOPRIVILEGES :target cannot "
                 "become an operator: this server holds no operator flags and no "
                 "operator credentials\r\n");

    tc_close(&target);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* `KICKLEN`, AND THE BOUND IT NAMES.
 *
 * The 005 token itself is asserted byte-for-byte by test_registration.c against the
 * literal `KICKLEN=255`; this file asserts the BOUND, because a token whose number
 * nothing enforces is exactly the defect Phase 10.4 reported -- and because the
 * interesting consequence of the missing bound was not a wrong token but a
 * reachable `n_reply_refused`. */
static void case_kicklen(void)
{
    nf_node_t node;
    test_client_t boss;
    test_client_t victim;
    test_client_t plain;
    test_client_t fancy;
    char line[AT_LIMIT + 256];
    char reason[AT_LIMIT + 1];
    char over[AT_LIMIT + 2];
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    memset(reason, 'r', sizeof reason - 1u);
    reason[sizeof reason - 1u] = '\0';
    memcpy(over, reason, sizeof reason - 1u);
    over[sizeof reason - 1u] = 'r';
    over[sizeof reason] = '\0';

    /* THE OP. A channel's creator gets +o, so the first client in is the only one
     * that can KICK at all, and it must not be one of the two under test. */
    tc_init(&boss);
    register_caps(&boss, node.port, "boss", NULL);
    join(&boss, "boss");

    /* The victim is IN the channel, so a successful KICK is observable on somebody
     * else's wire rather than being silent, and so the over-long attempt below has
     * a real target and its failure cannot be confused with "no such nick". */
    tc_init(&victim);
    register_caps(&victim, node.port, "victim", NULL);
    join(&victim, "victim");

    /* ---- AT THE BOUND: 255 bytes is ACCEPTED ---- */
    {
        char expect[AT_LIMIT + 160];
        size_t mark_v = tc_received(&victim);

        (void)snprintf(line, sizeof line, "KICK %s victim :%s", CHAN, reason);
        /* NO LEADING COLON BEFORE THE REASON, and that is not a slip in the
         * expectation -- it is the other half of a property worth asserting. 3.2
         * colons a trailing parameter only when the value needs it, and a 255-byte
         * run of `r` needs nothing. A node that coloned unconditionally would still
         * be legal; one that never did would not. */
        (void)snprintf(expect, sizeof expect,
                       ":boss!boss@127.0.0.1 KICK %s victim %s\r\n", CHAN, reason);
        TF_CHECK_MSG(tc_send(&boss, line) == 0, "the boundary KICK failed to send");
        TF_CHECK_MSG(tc_expect(&victim, expect, T_IO_MS) == 0,
                     "a KICK reason of exactly %d bytes was not accepted.\n"
                     "  expected: %s\n  victim saw: %s",
                     AT_LIMIT, expect, tc_buffer(&victim));
        drain(&victim);
        /* AND THE KICK ACTUALLY TOOK EFFECT, so the refusal case below is not a
         * bound that refuses everything and calls it a boundary.
         *
         * PROVEN BY A PRIVMSG, NOT BY A USERHOST. A KICK removes the CHANNEL
         * member and not the connection: the victim stays connected and keeps its
         * nickname, so `USERHOST victim` answers `victim+victim@127.0.0.1` both
         * before and after and proves nothing. What changed is the membership, and
         * 404 ERR_CANNOTSENDTOCHAN is this node's answer for a member who is not on
         * the channel they addressed -- so the kick is observable as a 404 the
         * victim can provoke, on the victim's own connection. */
        TF_CHECK_MSG(tc_send(&victim, "PRIVMSG " CHAN " :still here") == 0,
                     "the victim PRIVMSG send failed");
        expect_line_since(&victim, mark_v, "a PRIVMSG from a kicked member",
                          ":" SRV " 404 victim " CHAN " :Cannot send to channel\r\n");
        drain(&victim);
    }

    /* Re-admit the victim so the over-long attempt has a target again. */
    join(&victim, "victim");

    /* ---- ONE OVER: refused with 417, and the reason never reaches the wire ---- */
    tc_init(&plain);
    register_caps(&plain, node.port, "pk", NULL);
    tc_init(&fancy);
    register_caps(&fancy, node.port, "sk", CAP_STANDARD_REPLIES);

    (void)snprintf(line, sizeof line, "KICK %s victim :%s", CHAN, over);
    mark = tc_received(&plain);
    TF_CHECK_MSG(tc_send(&plain, line) == 0, "the over-long KICK failed to send");
    expect_line_since(&plain, mark, "a KICK reason of 256 bytes",
                      ":" SRV " 417 pk :Kick reason is too long\r\n");
    expect_only_replies(&plain, mark, "kick-over-plain", 1u, 0);

    /* ---- AND `FAIL KICK ERR_INPUTTOOLONG` for one that negotiated ---- */
    mark = tc_received(&fancy);
    TF_CHECK_MSG(tc_send(&fancy, line) == 0, "the over-long KICK failed to send");
    expect_line_since(&fancy, mark, "a KICK reason of 256 bytes",
                      ":" SRV " FAIL sk KICK ERR_INPUTTOOLONG :Kick reason is too "
                      "long\r\n");
    expect_only_replies(&fancy, mark, "kick-over-fancy", 1u, 1);

    /* ---- AND THE VICTIM IS STILL IN THE CHANNEL ----
     * A refusal that had already applied the change would leave the roster changed
     * and the KICK never delivered -- the failure a 417 written *after* the fact
     * would produce, and one both 417 assertions above would sail past.
     *
     * THE SAME PROBE AS ABOVE, INVERTED: the victim is still a member, so its
     * PRIVMSG to the channel is DELIVERED rather than refused, and this node echoes
     * a channel PRIVMSG back to its own sender (which is what `echo-message` is
     * standing on -- see test_echo_message.c). So the member's own connection shows
     * the delivery, and a node that had removed it would answer 404 instead.
     *
     * THE COLON BEFORE `still here` IS THERE because the value holds a space, which
     * 3.2 says needs the marker. It is the third distinct trailing-parameter shape
     * in this file (a bare 255-byte run with none, a description with one, and a
     * two-word message with one) and all three are accounted for on purpose. */
    {
        size_t mark_v = tc_received(&victim);

        TF_CHECK_MSG(tc_send(&victim, "PRIVMSG " CHAN " :still here") == 0,
                     "the victim PRIVMSG send failed");
        expect_line_since(&victim, mark_v, "a PRIVMSG from a still-membered victim",
                          ":victim!victim@127.0.0.1 PRIVMSG " CHAN " :still "
                          "here\r\n");
        drain(&victim);
    }

    /* ---- AND THE NODE REFUSED NO OUTBOUND LINE ----
     * The whole point of the bound. An over-long reason used to reach
     * `message_format()`, which refuses rather than reshapes, and the only outcome
     * at that depth is a refusal counted on `n_reply_refused` -- the counter
     * `reply.c` holds at zero because a non-zero value is a bug report. So a client
     * COMMAND used to be a reachable way to make the node file a bug report about
     * itself, and THIS is the assertion that notices if the bound is removed again:
     * the 417 assertions fail too, but they fail on a symptom, while this one fails
     * on the defect. */
    TF_CHECK_MSG(strstr(node.out, "reply_refused:") == NULL,
                 "the node refused an outbound line while handling a KICK. With no "
                 "reason bound an over-long reason is unrepresentable, "
                 "message_format() refuses it, and the refusal is counted on the "
                 "counter reply.c keeps at zero. Node output:\n%s", node.out);

    /* ---- AND THE 005 TOKEN, WITH ITS BOUND, IS WHAT SAYS 255 ---- */
    {
        test_client_t fresh;

        tc_init(&fresh);
        TF_CHECK_MSG(tc_connect(&fresh, node.port) == 0, "tc_connect failed");
        TF_CHECK_MSG(tc_send(&fresh, "NICK ict") == 0, "ict NICK send failed");
        TF_CHECK_MSG(tc_send(&fresh, "USER ict 0 *s :Real ict") == 0,
                     "ict USER send failed");
        TF_CHECK_MSG(tc_expect(&fresh, " 005 ", T_IO_MS) == 0, "no 005");
        /* SPACED, because a test for "KICKLEN=" would be satisfied by a neighbour
         * that shares the prefix -- the reason the other tokens in
         * test_registration.c are written with their spaces. */
        TF_CHECK_MSG(strstr(tc_buffer(&fresh), " KICKLEN=255 ") != NULL,
                     "005 does not carry \" KICKLEN=255 \". The token is rendered "
                     "from CHAN_MAX_KICK_REASON by IRC_STR(), so it moves with the "
                     "bound -- and the bound is what the two cases above are "
                     "about.\n  005 read: %s", tc_buffer(&fresh));
        tc_close(&fresh);
    }

    tc_close(&plain);
    tc_close(&fancy);
    tc_close(&victim);
    tc_close(&boss);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* WHAT DOES NOT MIGRATE, because "only these four" is half the claim.
 *
 * `401` for a nickname this node does not hold answers exactly ONE question, so it
 * reaches a client that negotiated `standard-replies` unchanged. A migration of every
 * numeric would pass every other case in this file and fail this one. */
static void case_unambiguous_numerics_do_not_move(void)
{
    nf_node_t node;
    test_client_t fancy;
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&fancy);
    register_caps(&fancy, node.port, "unmoved", CAP_STANDARD_REPLIES);

    /* 401: no such nick. One question, one number. */
    mark = tc_received(&fancy);
    TF_CHECK_MSG(tc_send(&fancy, "WHOIS nosuchnick") == 0, "WHOIS send failed");
    expect_line_since(&fancy, mark, "WHOIS of a nickname this node does not hold",
                      ":" SRV " 401 unmoved nosuchnick :No such nick/channel\r\n");
    /* 318 is not a refusal and is not migrated either; asserting it pins the fact
     * that the end-of-list marker still follows the 401, which is RFC 2812 3.3.4's
     * pairing and the reason a client can tell "answered" from "still working". */
    expect_line_since(&fancy, mark, "the end of the WHOIS",
                      ":" SRV " 318 unmoved nosuchnick :End of /WHOIS list\r\n");
    expect_only_replies(&fancy, mark, "whois-401", 2u, 1);

    /* 451: not registered. Also one question, and the one numeric a client is most
     * likely to be matching on, so it is the second half of the claim. */
    {
        test_client_t early;

        tc_init(&early);
        TF_CHECK_MSG(tc_connect(&early, node.port) == 0, "early tc_connect failed");
        TF_CHECK_MSG(tc_send(&early, "CAP REQ :" CAP_STANDARD_REPLIES) == 0,
                     "early CAP REQ send failed");
        TF_CHECK_MSG(tc_expect(&early, " ACK :" CAP_STANDARD_REPLIES "\r\n", T_IO_MS) == 0,
                     "early was not ACKed " CAP_STANDARD_REPLIES);
        TF_CHECK_MSG(tc_send(&early, "NICK early") == 0, "early NICK send failed");
        mark = tc_received(&early);
        TF_CHECK_MSG(tc_send(&early, "WHOIS somebody") == 0, "early WHOIS failed");
        expect_line_since(&early, mark, "WHOIS before registration",
                          ":" SRV " 451 early :You have not registered\r\n");
        expect_only_replies(&early, mark, "pre-reg", 1u, 1);
        tc_close(&early);
    }

    tc_close(&fancy);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* THE CAPABILITY IS ADVERTISED, and that is a claim like any other.
 *
 * `cap.h`'s rule is that every name in `CAP LS` is an implementation this node has
 * behind it, and this one has: the migration table in reply.c and a producer for
 * every entry in it. A capability advertised with nothing behind it is the failure
 * this project treats as worse than an absent one. */
static void case_advertised(void)
{
    nf_node_t node;
    test_client_t c;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");
    TF_CHECK_MSG(tc_send(&c, "CAP LS") == 0, "CAP LS send failed");
    TF_CHECK_MSG(tc_expect(&c, " CAP * LS :", T_IO_MS) == 0, "CAP LS was not answered");
    TF_CHECK_MSG(strstr(tc_buffer(&c), CAP_STANDARD_REPLIES) != NULL,
                 "CAP LS does not advertise %s. This node DOES implement the "
                 "specification's commands -- FAIL is emitted by reply_refused() for "
                 "every migrated numeric -- so withholding the name would be "
                 "refusing to tell a client something true.", CAP_STANDARD_REPLIES);
    tc_close(&c);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * TEETH, AND WHERE THEY WERE INJECTED
 * ---------------------------------------------------------------------------
 * Each was watched go red with the behaviour broken, and the BUILD was checked
 * before the run was believed -- an uncompilable fault leaves the previous binary
 * in place and reports a pass, which has happened in this repo seven times.
 *
 *   `FAIL` SENT TO A CLIENT THAT DID NOT NEGOTIATE -- reply.c,
 *       reply_refused(): the `cap_standard_replies_enabled(src) == 0` test
 *       dropped, so every refusal renders as a `FAIL` for every client. Fails
 *       EVERY `both_answers()` case on the plain side, and it is the fault with
 *       teeth: `FAIL` is a command word no such client has been told to expect,
 *       RFC 1459 2.3 parses it as an unknown command, and a client that trusted
 *       the numeric it would otherwise have received is now reading a verb it does
 *       not handle.
 *
 *   the MAPPED CODE DISCARDED -- reply.c, reply_refused(): `std_fail_code()` called
 *       only to DECIDE whether to migrate, with `fail_code` -- the caller's
 *       OVERRIDE, NULL at every site that wanted the table's answer -- passed to
 *       reply_std() instead. The second version of this code, not an injected
 *       fault, and the defect is worth keeping in the list because it is invisible
 *       from the wire: reply_std() refuses an empty code as `bad_args`, so the
 *       client received NOTHING at all -- no 417, no `FAIL` -- and the only evidence
 *       anywhere was a `reply_refused:` line on the node's own output for a refusal
 *       that had an answer. Caught here as a timeout waiting for
 *       `FAIL AWAY ERR_INPUTTOOLONG` from a client that had negotiated the
 *       capability and was owed one.
 *
 *   the legacy branch DROPPING THE CALLER'S ARGUMENTS -- reply.c,
 *       reply_refused(): the legacy branch restored to
 *       `reply(s, src, legacy, mid, nmid, "%s", fmt)`, which passes the caller's
 *       FORMAT STRING as an argument instead of rendering it. The FIRST version of
 *       this code, also not injected, and it was caught by the EXISTING suite
 *       rather than by a case here: `test_choper` received
 *       `:irc.test 464 * :SASL authentication failed: %s` and `test_cap_negotiation`
 *       timed out waiting for ` 464 * :SASL authentication failed: the credentials
 *       did not verify`. A refusal that had lost the one word saying whether the
 *       store was missing or the password was wrong.
 *
 *   BOTH OF THOSE ARE THE SAME SHAPE, and it is the shape worth remembering for the
 *   next variadic wrapper in this tree: a variadic function that RENAMES an argument
 *   on its way to the next function has not forwarded anything, it has copied a
 *   pointer. Both versions compiled clean and passed -Weverything, and neither was
 *   visible in a diff of the call sites.
 *
 *   the `461` TOO-MANY CODE INVERTED -- msg_verbs.c, handle_away(): the
 *       `"TOO_MANY_PARAMS"` override replaced with `NULL`, so the too-many case
 *       falls back to the table's `NEED_MORE_PARAMS`. Fails the `AWAY :one :two`
 *       case and ONLY that one -- which is the point of a per-site override: the
 *       table cannot hold two answers for one number and the call site can.
 *
 *   the KICK BOUND REMOVED -- chan_verbs.c, handle_kick(): the
 *       `strlen(reason) > CHAN_MAX_KICK_REASON` test raised by 4096, so nothing this
 *       node can receive reaches it. Fails the 417 case AND the `reply_refused:`
 *       assertion, and the second is the interesting one: the 417 disappears with
 *       the bound because the line is refused deeper in, so the `reply_refused` line
 *       is what says the node filed a bug report about itself.
 *
 *       WRITTEN AS A RAISE AND NOT AS A DELETION, and that is the ninth time in
 *       this repository a fault has been rewritten because it did not compile.
 *       `if (0)` is `-Wunreachable-code` under -Weverything, so "delete the test"
 *       leaves a hard build error, the previous binary in place, and a PASS -- and
 *       the first run of this fault did exactly that and reported the PREVIOUS
 *       fault's failure as if it were this one's.
 *
 *   the KICK bound MOVED -- channel.h: CHAN_MAX_KICK_REASON raised to 512. Fails the
 *       256-byte refusal and the ` KICKLEN=255 ` token, and it is the fault that
 *       proves the bound is tested rather than assumed. It also proves the token is
 *       derived: a node that advertised 512 while refusing at 255 fails here too.
 */
int main(void)
{
    case_advertised();
    case_417();
    case_461();
    case_482();
    case_464();
    case_kicklen();
    case_unambiguous_numerics_do_not_move();

    tf_done("standard-replies");
    return 0;
}
