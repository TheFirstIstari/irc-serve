/* test_multi_prefix.c -- the IRCv3 `multi-prefix` capability, on the wire.
 *
 * The CTest name is unchanged (`MultiPrefix`) because the test existed as an
 * honest `return 77` before this and the ratchet in scripts/check-skips.sh is
 * keyed on names. What changed is that there is nothing left to skip: the
 * capability is implemented, advertised, and the bytes below say so.
 *
 * ---------------------------------------------------------------------------
 * WHY IT WAS A SKIP AND WHAT THE SKIP WAS HONEST ABOUT
 * ---------------------------------------------------------------------------
 * The file used to read "multi-prefix IRCv3 capability is NOT implemented by this
 * codebase" and return 77. That sentence was TRUE and it was also a decision
 * deferred: `chan_verbs.c`'s send_names_list() drew one sigil per member out of
 * the ORDER group rather than out of the member's flags, and IRCv3's
 * `multi-prefix` says a `353` may draw the member's whole prefix set. Either
 * implement it or assert the absence.
 *
 * Asserting the absence was legitimate -- "this node does not offer
 * multi-prefix" is a checkable statement about a server -- but it is the weaker of
 * the two, and the arithmetic says so. The change is two draws in two functions:
 * `chan_verbs.c`'s names_signs() derives the sigils from `flags` instead of from
 * the order group, and `msg_verbs.c`'s who_flags() stops being an `else if` chain.
 * Both are already gated on `cap_multiprefix_enabled()`, which has existed since
 * CAP landed with its bit reserved and no name behind it. Shipping a capability
 * table with a reserved bit, a gate, and no implementation behind the gate is the
 * "documented but absent" pattern this project has been retracting all phase.
 *
 * ---------------------------------------------------------------------------
 * WHAT THE TEST HOLDS THE NODE TO
 * ---------------------------------------------------------------------------
 * Four things, and each is a thing a CLIENT can observe:
 *
 *   1. `CAP LS` advertises `multi-prefix`, because the capability is implemented.
 *      The absence half matters too: a node that advertised it and drew one sigil
 *      would be worse than a node that never offered it.
 *   2. WITHOUT the capability, a member who is BOTH op and voiced is drawn `@nick`
 *      -- exactly one sigil. This is the negative that keeps the feature honest:
 *      a change that drew `@+nick` unconditionally would satisfy case 3 and break
 *      every client that did not ask for it.
 *   3. WITH it, the same member is drawn `@+nick`, in 005's PREFIX order.
 *   4. `352` RPL_WHOREPLY obeys the same gate, because IRCv3's multi-prefix names
 *      both numerics and 353 alone would be half the capability.
 *
 * The member that is both op and voiced is the whole of the case. A node that
 * handles `@+` for an op and `+` for a voice and gets an op+voice member wrong is
 * drawing a nickname no client can resolve, and that is the failure mode worth
 * having a test for.
 *
 * ---------------------------------------------------------------------------
 * TWO CLIENTS, TWO SETTINGS, ONE ROSTER
 * ---------------------------------------------------------------------------
 * Cases 2, 3 and 4 run as three connections to ONE node holding ONE channel, and
 * the two roster renderings are read off two different sockets. That is the point
 * of the capability being per-connection: the roster is shared state and the
 * rendering is not, so a node that decided once per channel (or once per node)
 * would pass a test with one client and fail with two. The negative and the
 * positive are therefore read from two connections to the same channel rather
 * than from two channels on two nodes, which is the smallest fixture that can
 * tell "this connection negotiated it" from "the channel is like that".
 *
 * NO FIXED sleep() ANYWHERE (6.3): every wait is tc_expect()'s deadline loop, and
 * every case closes its window with a PING whose PONG is the drain token.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/cap.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define CHAN "#T"

/* The member the whole file is about. He creates the channel, so RFC 2812 3.3.1
 * made him an operator, and the case gives him +v as well -- so he holds BOTH
 * prefix modes and is the one entry in a 353 whose rendering can be wrong. */
#define OP_AND_VOICE "oliver"

/* A second member who holds NEITHER mode, so the case can tell "the capability
 * changed how a flagged member is drawn" from "the capability changed the line".
 * Plain members are drawn with no sigil under both settings and must stay that
 * way; a `@+` run appearing in front of an unflagged nickname is a different
 * defect and would be caught here rather than in a client. */
#define PLAIN       "peggy"

/* THE DRAIN TOKEN IS PER CALL AND NOT A CONSTANT, and that is not fussiness.
 * tc_expect() searches the ACCUMULATED buffer, so a token this file has already
 * used is satisfied by the PONG that answered it before -- with no read at all,
 * and every "the buffer now holds X" claim in this file is then a claim about the
 * moment the buffer happened to be last pumped. The first version used one fixed
 * token and reported an empty "client saw" for a 353 the node had drawn, because
 * nothing had been read since the previous drain.
 *
 * So the token is numbered per call and a monotonic counter is the only thing that
 * can promise uniqueness. It is a file-static because the drain is a helper and
 * the alternative -- threading a counter through every caller -- is more
 * machinery than the thing deserves. */
static unsigned g_drain_seq;

/* ---------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------ */

/* Register `nick`, negotiating `caps` first (NULL for no CAP exchange at all).
 * The REQ is ACKed whole, so a capability this node does not have fails the wait
 * rather than being quietly NAKed -- which means a case below can never pass
 * because the gate was never reached. */
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
                     "capability and the case below would be asserting a negative "
                     "for the wrong reason", nick, caps);
    }
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s NICK send failed", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s USER send failed", nick);
    if (caps != NULL) {
        TF_CHECK_MSG(tc_send(c, "CAP END") == 0, "%s CAP END send failed", nick);
    }
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered", nick);
}

static void drain(test_client_t *c)
{
    char token[64];
    char line[128];

    (void)snprintf(token, sizeof token, "mpdrain%u", g_drain_seq++);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING failed");
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG for drain token %s, so the buffer is not yet drained and "
                 "every claim below would be about the read schedule", token);
}

/* Read a fresh `353` for CHAN and require the rendered form of `nick` to be
 * exactly `want`.
 *
 * The comparison is on the rendered TOKEN rather than on the whole line, because a
 * 353 may be split across lines (RFC 2812 3.3.5 allows it) and because the rest of
 * the roster is not what this file is about. The token is bounded by the
 * surrounding whitespace on the wire: the drawn form of a member is one or two
 * sigils and the nickname, and nothing else, so what is looked for is
 * `<space><want><space|CRLF>`.
 *
 * WHY NOT strstr(): "@@oliver" and "@+oliver" and "oliver" all contain "oliver",
 * so a substring test cannot tell a member drawn with one sigil from one drawn
 * with two, which is the only thing the case is about. The sigils are what have to
 * be pinned, so they are part of the token. */
static void expect_names_token(test_client_t *c, const char *nick,
                               const char *want)
{
    char needle[128];
    char neg[128];
    char line[256];
    /* THE BUFFER IS MARKED BEFORE THE COMMAND, and both searches below are
     * against the region after it. This connection is asked for NAMES more than
     * once -- the point of the case is that ONE roster is rendered two ways for
     * two clients, so the same socket sees both -- and a search over everything
     * read so far finds the PREVIOUS answer. The first version of this helper did
     * that and reported "the 353 also drew oliver as @oliver" about the line it had
     * itself just been sent and accepted. */
    const size_t mark = tc_received(c);

    (void)snprintf(line, sizeof line, "NAMES " CHAN);
    TF_CHECK_MSG(tc_send(c, line) == 0, "the NAMES send failed");
    TF_CHECK_MSG(tc_expect(c, " 366 ", T_IO_MS) == 0, "NAMES was never answered");
    drain(c);

    /* A 353 is a SPACE-separated list and RFC 2812 3.3.5 allows it to be split
     * across lines, so a member's drawn form is bounded by whitespace on both
     * sides -- a space when it is followed by another member, a CR when it is the
     * last one on the line. Both are accepted for the positive and both are
     * excluded for the negative, which is what makes the test independent of where
     * the roster happened to wrap. The first version of this helper demanded a
     * CRLF and so only ever matched the LAST member drawn. */
    /* `tc_buffer(c) + mark` IS EVALUATED AT EVERY USE, and not once into a local
     * pointer. tc_buffer() returns c->buf, which the client's own reader REALLOCS
     * as the connection fills; a pointer into the old buffer is a pointer into
     * freed memory, and the version of this helper that cached it reported an
     * empty "client saw" for a roster the node had plainly drawn. The LENGTH is
     * what is stable across a realloc -- it is an offset, not an address. */
    (void)snprintf(needle, sizeof needle, " %s ", want);
    (void)snprintf(neg, sizeof neg, " %s\r", want);
    TF_CHECK_MSG(strstr(tc_buffer(c) + mark, needle) != NULL ||
                     strstr(tc_buffer(c) + mark, neg) != NULL,
                 "the 353 did not draw %s as \"%s\".\n  client saw: %s", nick, want,
                 tc_buffer(c) + mark);

    /* And the NEGATIVE, beside it. Without this the positive is satisfied by a
     * node that draws BOTH forms on one line, or that draws the right form for
     * the wrong member. Only two things can be drawn in front of this nickname,
     * so naming the other one is exhaustive rather than a sample. */
    {
        const char *other = (strcmp(want, "@" OP_AND_VOICE) == 0)
                                ? ("@+" OP_AND_VOICE)
                                : ("@" OP_AND_VOICE);
        char o_space[128];
        char o_last[128];

        (void)snprintf(o_space, sizeof o_space, " %s ", other);
        (void)snprintf(o_last, sizeof o_last, " %s\r", other);
        TF_CHECK_MSG(strstr(tc_buffer(c) + mark, o_space) == NULL &&
                         strstr(tc_buffer(c) + mark, o_last) == NULL,
                     "this 353 also drew %s as \"%s\"; exactly one of the two forms "
                     "belongs on the wire for this member.\n  client saw: %s", nick,
                     other, tc_buffer(c) + mark);
    }
}

/* The <flags> field of the ONE `352` naming `nick`, into `out`. Returns 0 if
 * there is no such line.
 *
 * THE POSITION IN THE RFC'S OWN SHAPE, not an index into anything. 352 is
 * `:server 352 <client> <channel> <user> <host> <server> <nick> <flags> :<hops>
 * <realname>` (RFC 2812 3.3.4), so <flags> is the SIXTH middle parameter of the
 * line and the nick is the fifth: find the line whose fifth parameter is `nick`,
 * then take the sixth. Every 352 on the connection is walked rather than the first
 * one being assumed, because WHO lists members in JOIN order and a test that
 * depended on that order would be testing the fixture's timing.
 *
 * The <flags> token is delimited by spaces, which is what makes "@+" one token:
 * it is a space-separated field, not two, and a helper that looked for a fixed
 * offset would be reading the shape of a nickname rather than the shape of the
 * field. */
static int who_flags_for(const test_client_t *c, const char *nick, char *out,
                         size_t cap)
{
    static const char mark[] = " 352 ";
    const char *at = tc_buffer(c);
    const size_t nicklen = strlen(nick);

    while ((at = strstr(at, mark)) != NULL) {
        const char *eol;
        const char *tok;
        int i;

        at += sizeof mark - 1u;
        eol = strchr(at, '\r');
        if (eol == NULL) {
            return 0;
        }
        /* Seven middle parameters here: <client> <channel> <user> <host>
         * <server> <nick> <flags>. The sixth is the nickname and the seventh is
         * what is wanted -- and the SECOND `<...>` is not the nick either, because
         * <user> is the account name and <server> sits between them, which is
         * exactly the kind of off-by-one a positional reader gets wrong. `at` is
         * walked with explicit bounds so a truncated line -- a short read, or a
         * numeric this node never wrote in full -- reads as "no such 352" rather
         * than walking off the buffer. */
        for (i = 0; i < 7; i++) {
            while (at < eol && *at == ' ') {
                at++;
            }
            if (at >= eol) {
                return 0;
            }
            tok = at;
            while (at < eol && *at != ' ') {
                at++;
            }
            if (i == 5) {
                if ((size_t)(at - tok) != nicklen || strncmp(tok, nick, nicklen) != 0) {
                    break; /* a 352 about somebody else; keep looking */
                }
            }
            if (i == 6) {
                const size_t n = (size_t)(at - tok);

                if (n >= cap) {
                    return 0;
                }
                memcpy(out, tok, n);
                out[n] = '\0';
                return 1;
            }
        }
        at = eol;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * THE CASE
 * ------------------------------------------------------------------------ */
static void case_multi_prefix(void)
{
    nf_node_t node;
    test_client_t plain;   /* no CAP exchange: one sigil */
    test_client_t fancy;   /* CAP REQ :multi-prefix: the whole set */
    test_client_t fitter;  /* no CAP: reads WHO */
    char line[256];
    char flags[16];

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    /* ---- ADVERTISED, because it is implemented ---- */
    {
        test_client_t c;

        tc_init(&c);
        TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");
        TF_CHECK_MSG(tc_send(&c, "CAP LS") == 0, "CAP LS send failed");
        TF_CHECK_MSG(tc_expect(&c, " CAP * LS :", T_IO_MS) == 0,
                     "CAP LS was not answered");
        TF_CHECK_MSG(strstr(tc_buffer(&c), CAP_MULTIPREFIX) != NULL,
                     "CAP LS does not advertise %s, which this node now "
                     "implements in 353 and in 352", CAP_MULTIPREFIX);
        tc_close(&c);
    }

    tc_init(&plain);
    tc_init(&fancy);
    tc_init(&fitter);
    register_caps(&plain, node.port, OP_AND_VOICE, NULL);
    register_caps(&fancy, node.port, PLAIN, CAP_MULTIPREFIX);
    register_caps(&fitter, node.port, "fiona", NULL);

    /* ---- 005's PREFIX= IS WHAT THE DRAWN RUN IS ORDERED BY ---- */
    /* Checked before anything is drawn, because it is the thing the drawing
     * indexes into: a run in an order 005 does not name gives a client a status
     * the node does not hold, and asserting the run without asserting the table
     * would let a node that draws `+@nick` pass every case below. */
    TF_CHECK_MSG(strstr(tc_buffer(&plain), " PREFIX=(ov)@+ ") != NULL,
                 "005 does not advertise PREFIX=(ov)@+, so there is no table for a "
                 "multi-prefix run to be drawn in the order of.\n  client saw: %s",
                 tc_buffer(&plain));

    /* ---- THE ROSTER, AND THE MEMBER THAT HOLDS BOTH MODES ---- */
    (void)snprintf(line, sizeof line, "JOIN " CHAN);
    TF_CHECK_MSG(tc_send(&plain, line) == 0, "%s's JOIN send failed", OP_AND_VOICE);
    TF_CHECK_MSG(tc_expect(&plain, " 366 ", T_IO_MS) == 0,
                 "%s never completed its JOIN", OP_AND_VOICE);
    (void)snprintf(line, sizeof line, "JOIN " CHAN);
    TF_CHECK_MSG(tc_send(&fancy, line) == 0, "%s's JOIN send failed", PLAIN);
    TF_CHECK_MSG(tc_expect(&fancy, " 366 ", T_IO_MS) == 0,
                 "%s never completed its JOIN", PLAIN);

    /* RFC 2812 3.3.1: the channel creator is an operator. The node makes him one
     * itself -- this is a fact the JOIN above produced, not a fixture that
     * arranged it -- and the case then adds +v, so he holds BOTH. */
    (void)snprintf(line, sizeof line, "MODE " CHAN " +v " OP_AND_VOICE);
    TF_CHECK_MSG(tc_send(&plain, line) == 0, "the MODE +v send failed");
    /* The ECHO, not a 324. A mode SET is answered by the RFC 1459 3.3.2 echo
     * `:nick!user@host MODE #chan +v nick` and a 324 is the answer to the QUERY
     * form, so waiting for a 324 here would be waiting for a numeric this node
     * does not send in response to a set. */
    (void)snprintf(line, sizeof line, "MODE " CHAN " +v " OP_AND_VOICE "\r\n");
    TF_CHECK_MSG(tc_expect(&plain, line, T_IO_MS) == 0,
                 "the MODE +v was neither echoed nor refused, so no member of this "
                 "channel is known to hold both prefix modes and the rest of this "
                 "case would be about an op alone.\n  client saw: %s",
                 tc_buffer(&plain));
    drain(&plain);
    /* The state the whole file is about, stated as an observation rather than as
     * a hope: the node's own account of the MODE it just applied. */
    TF_CHECK_MSG(nf_expect(&node, "chan_member_mode: channel=" CHAN " by=" OP_AND_VOICE
                                  " nick=" OP_AND_VOICE " mode=v set=1",
                           T_IO_MS) == 0,
                 "the node did not apply +v to %s, so no member of this channel "
                 "holds both prefix modes and the multi-prefix case is not being "
                 "exercised at all.\n  node said: %s", OP_AND_VOICE, node.out);

    /* ---- WITHOUT the capability: EXACTLY ONE sigil ---- */
    expect_names_token(&plain, OP_AND_VOICE, "@" OP_AND_VOICE);

    /* ---- WITH it: THE WHOLE SET, in 005's order ---- */
    expect_names_token(&fancy, OP_AND_VOICE, "@+" OP_AND_VOICE);

    /* ---- AND THE PLAIN MEMBER IS UNCHANGED BY EITHER SETTING ----
     * A member holding no prefix mode is drawn with no sigil under both
     * settings. This is the control for the pair above: without it, a node that
     * drew `@+` in front of EVERY name would satisfy both. */
    expect_names_token(&fancy, PLAIN, PLAIN);

    /* ---- 352 OBeys THE SAME GATE ---- */
    /* RFC 2812 3.3.4's <flags> begins with H (here) or G (away). */
    (void)snprintf(line, sizeof line, "WHO " CHAN);
    TF_CHECK_MSG(tc_send(&fitter, line) == 0, "fiona's WHO send failed");
    TF_CHECK_MSG(tc_expect(&fitter, " 315 ", T_IO_MS) == 0, "the WHO was never ended");
    drain(&fitter);
    TF_CHECK_MSG(who_flags_for(&fitter, OP_AND_VOICE, flags, sizeof flags) == 1,
                 "no 352 naming %s came back from WHO.\n  client saw: %s",
                 OP_AND_VOICE, tc_buffer(&fitter));
    TF_CHECK_MSG(strcmp(flags, "H@") == 0,
                 "a client that did NOT negotiate %s was told the flags \"%s\" for "
                 "an op+voice member; it must be told one sigil, because that is "
                 "what it knows how to read", CAP_MULTIPREFIX, flags);

    (void)snprintf(line, sizeof line, "WHO " CHAN);
    TF_CHECK_MSG(tc_send(&fancy, line) == 0, "%s's WHO send failed", PLAIN);
    TF_CHECK_MSG(tc_expect(&fancy, " 315 ", T_IO_MS) == 0, "the WHO was never ended");
    drain(&fancy);
    TF_CHECK_MSG(who_flags_for(&fancy, OP_AND_VOICE, flags, sizeof flags) == 1,
                 "no 352 naming %s came back from WHO.\n  client saw: %s",
                 OP_AND_VOICE, tc_buffer(&fancy));
    TF_CHECK_MSG(strcmp(flags, "H@+") == 0,
                 "a client that DID negotiate %s was told the flags \"%s\" for an "
                 "op+voice member. IRCv3's multi-prefix names 352 as well as 353, so "
                 "answering it in the names list alone is half the capability, and a "
                 "client that trusts its WHO over its NAMES is told two different "
                 "statuses for one member", CAP_MULTIPREFIX, flags);

    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
    tc_close(&plain);
    tc_close(&fancy);
    tc_close(&fitter);
}

/* ---------------------------------------------------------------------------
 * TEETH, AND WHERE THEY WERE INJECTED
 * ---------------------------------------------------------------------------
 * Each was watched go red with the behaviour broken, and the build was checked
 * before the run was believed -- an uncompilable fault leaves the previous binary
 * in place and reports a pass, which has happened in this repo seven times.
 *
 *   multi-prefix drawn unconditionally
 *       chan_verbs.c, names_signs(): the `multiprefix == 0` branch removed, so
 *       every member holding both modes is drawn `@+`. Fails the WITHOUT case and
 *       not the WITH one, which is what makes the negative load-bearing.
 *
 *   multi-prefix ignored
 *       chan_verbs.c, send_names_list(): `cap_multiprefix_enabled(dst)` replaced
 *       with 0. Fails the WITH case and not the WITHOUT one.
 *
 *   the order flipped
 *       chan_verbs.c, names_signs(): the two tests swapped, so an op+voice member
 *       is drawn `+@`. Fails the WITH case on the token alone -- which is the
 *       assertion 005's PREFIX=(ov)@+ justifies, and the reason the token
 *       comparison includes the sigils rather than the nickname.
 *
 *   352 not covered
 *       msg_verbs.c, who_flags(): the multiprefix argument ignored. Fails the
 *       second 352 assertion and no other, so the "both numerics" claim is
 *       checked rather than assumed from the 353 half.
 *
 *   advertised but not implemented
 *       cap.c, k_caps[]: CAP_MULTIPREFIX removed while the rendering stayed. Fails
 *       the CAP LS assertion, so "advertised" and "implemented" are asserted
 *       together.
 */
int main(void)
{
    case_multi_prefix();
    tf_done("multi_prefix");
    return 0;
}
