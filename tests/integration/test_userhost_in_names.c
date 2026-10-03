/* test_userhost_in_names.c -- the IRCv3 `userhost-in-names` capability, on the wire.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS BEING CLAIMED, AND WHY THE CLAIM IS A PRIVACY ONE
 * ---------------------------------------------------------------------------
 * A `353` roster normally carries a nickname and nothing else. With this capability
 * it carries `nick!user@host` for every member listed. That is not a rendering
 * preference: **it discloses every member's ident and observed host address to
 * every other member of the channel**, including clients that member has never
 * spoken to and clients who joined after them. There is no per-member consent
 * anywhere in it. One client asking puts the whole roster's hostmasks on the wire
 * to that client.
 *
 * So the test is not only "does the long form appear". It is: **the same channel,
 * the same member, drawn two different ways, for two different clients** -- and a
 * client that did not negotiate gets the bare nickname. A node that decided once
 * per channel, or once per node, would pass a single-client test and fail this one,
 * and that is the failure with consequences.
 *
 * ---------------------------------------------------------------------------
 * THREE CONNECTIONS, ONE CHANNEL, ONE MEMBER
 * ---------------------------------------------------------------------------
 * `fancy` and `plain` are on the same channel as the member being drawn, and they
 * disagree. `plain` did no CAP exchange at all; `fancy` negotiated. A third client
 * is the control that makes the positive mean something: it negotiates the SAME
 * capability as `fancy` and is asserted to get the SAME long form, so a node that
 * drew a hostmask for everyone would satisfy `fancy` alone.
 *
 * The subject is a member who is NOT the channel creator and holds no prefix mode,
 * so the drawn token has no sigil in front of it and the assertion is about the
 * name's shape alone. That is deliberate: with a sigil, `strstr` for `nick` would
 * be satisfied by a roster that drew `@nick!user@host` in the wrong order or drew
 * two sigils, and the case is about the hostmask.
 *
 * NO FIXED sleep() ANYWHERE (6.3): every wait is tc_expect()'s deadline loop, and
 * every window is closed by a PING whose PONG is the drain token -- numbered per
 * call, because tc_expect() searches the ACCUMULATED buffer and a reused token
 * would be satisfied by an earlier PONG with no read at all.
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

/* The member the whole file is about. He joins, so this node OWNS the channel and
 * the roster under test is a real one rather than a cache. He is a plain member:
 * RFC 2812 3.3.1 makes the CREATOR an operator, and an op's drawn token carries a
 * `@` that this case would have to exclude from its comparisons. */
#define SUBJECT "harriet"

/* THE OBSERVED HOST. Every client in this file connects from 127.0.0.1, and
 * commands.c's handle_user() stores what accept() saw rather than what USER
 * claimed, so this is the `<host>` half of the hostmask -- and a node that stored
 * the assertion would draw `spoofed.example` here instead. The assertions spell the
 * whole `nick!ident@host` token, so this half is checked too. */
#define OBSERVED_HOST "127.0.0.1"

/* The ident USER supplies, which is the same string as the nickname for every
 * client here -- spelled out so a future edit that changes USER's line cannot
 * silently change what the test is asking for. */
#define SUBJECT_IDENT "harriet"

static unsigned g_drain_seq;

static void drain(test_client_t *c)
{
    char token[64];
    char line[128];

    (void)snprintf(token, sizeof token, "uhn%u", g_drain_seq++);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING failed");
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG for drain token %s, so the buffer is not yet drained and "
                 "every claim below would be about the read schedule", token);
}

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
                     "capability and the cases below would be asserting a negative "
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

/* Read a fresh `353` for CHAN and require the drawn form of SUBJECT to be exactly
 * `want` -- and to be exactly `want` and nothing else.
 *
 * THE MARK BEFORE THE COMMAND. This connection is asked for NAMES more than once
 * in some cases, and tc_expect() searches the ACCUMULATED buffer, so a search over
 * everything read so far finds the PREVIOUS answer and reports it about the line
 * that has just been sent.
 *
 * `tc_buffer(c) + mark` IS EVALUATED AT EVERY USE rather than cached into a local
 * pointer: tc_buffer() returns c->buf, which the client's own reader REALLOCS as
 * the connection fills, so a cached pointer is a pointer into freed memory. The
 * LENGTH is the stable thing across a realloc -- it is an offset, not an address.
 *
 * A 353 is a SPACE-separated list and RFC 2812 3.3.5 allows it to be split across
 * lines, so a member's drawn form is bounded on the RIGHT by a space when another
 * member follows it and by a CR when it is last on the line -- and on the LEFT by
 * a space, unless it is the FIRST member drawn, in which case the byte before it is
 * the `:` that opens the trailing parameter. All four left-hand forms and both
 * right-hand forms are accepted, which is exhaustive for a 353 and therefore not
 * a sample of the ways one can appear.
 *
 * THE LEFT BOUND IS WHY THIS IS NOT A PLAIN strstr(want), and getting it wrong is
 * silent in the direction that matters. A hostmask contains no space, so
 * `strstr("... harriet!harriet@127.0.0.1 fancy!...")` succeeds on a substring that
 * a client would NOT read as one entry; and a node that drew `user@host!nick`
 * would satisfy it too. The bounds are what make the assertion about a rendered
 * ENTRY rather than about a run of characters.
 */
static int names_token_present(const char *hay, size_t from, const char *want)
{
    /* THE TRAILING '\0' IS NOT OPTIONAL IN EITHER ARRAY. strchr() needs a
     * terminated string, and `{ ' ', ':', '\r' }` is three bytes with no NUL --
     * which Apple clang and upstream clang both accept silently and gcc-16 rejects
     * as -Wstringop-overread. It is not a diagnostic about style: the call reads
     * past the end of the array until it happens to find a zero, so it is a
     * genuine out-of-bounds read that two of the three compilers declined to see. */
    static const char left[] = { ' ', ':', '\r', '\0' };
    static const char right[] = { ' ', '\r', '\0' };
    const size_t wlen = strlen(want);

    if (hay == NULL || want == NULL || wlen == 0u) {
        return 0;
    }
    for (const char *at = hay + from; (at = strstr(at, want)) != NULL; at++) {
        /* `at` CANNOT be the start of the haystack's own region in practice --
         * `from` is the mark, and the region begins with a complete line -- but the
         * check is written out rather than assumed, because an out-of-bounds read
         * one byte before the buffer is the failure mode a bounds check exists to
         * remove. */
        const int left_ok = ((size_t)(at - hay) > from)
                                ? (strchr(left, at[-1]) != NULL)
                                : 1;
        const int right_ok = (strchr(right, at[wlen]) != NULL);

        if (left_ok != 0 && right_ok != 0) {
            return 1;
        }
    }
    return 0;
}

static void expect_names_token(test_client_t *c, const char *who,
                               const char *want)
{
    const size_t mark = tc_received(c);

    TF_CHECK_MSG(tc_send(c, "NAMES " CHAN) == 0, "%s: NAMES send failed", who);
    TF_CHECK_MSG(tc_expect(c, " 366 ", T_IO_MS) == 0,
                 "%s: NAMES was never answered", who);
    drain(c);

    TF_CHECK_MSG(names_token_present(tc_buffer(c), mark, want) != 0,
                 "%s: the 353 did not draw %s as \"%s\".\n  client saw: %s", who,
                 SUBJECT, want, tc_buffer(c) + mark);
}

/* The one case, and the three shapes it asserts on one roster. */
static void case_userhost_in_names(void)
{
    nf_node_t node;
    test_client_t plain;   /* no CAP exchange: the bare nickname */
    test_client_t fancy;   /* CAP REQ :userhost-in-names */
    test_client_t other;   /* the SAME capability, so `fancy` alone proves nothing */
    test_client_t boss;    /* created the channel; holds no stake in the assertions */
    test_client_t subj;    /* the member being drawn */

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    /* ---- ADVERTISED, because it is implemented ---- */
    {
        test_client_t c;

        tc_init(&c);
        TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");
        TF_CHECK_MSG(tc_send(&c, "CAP LS") == 0, "CAP LS send failed");
        TF_CHECK_MSG(tc_expect(&c, " CAP * LS :", T_IO_MS) == 0,
                     "CAP LS was not answered");
        TF_CHECK_MSG(strstr(tc_buffer(&c), CAP_USERHOST_IN_NAMES) != NULL,
                     "CAP LS does not advertise %s, which this node now honours in "
                     "every 353 it draws", CAP_USERHOST_IN_NAMES);
        tc_close(&c);
    }

    tc_init(&plain);
    tc_init(&fancy);
    tc_init(&other);
    register_caps(&plain, node.port, "plain", NULL);
    register_caps(&fancy, node.port, "fancy", CAP_USERHOST_IN_NAMES);
    register_caps(&other, node.port, "other", CAP_USERHOST_IN_NAMES);

    /* The channel is created by SOMEBODY ELSE, and that is not incidental.
     * RFC 2812 3.3.1 makes a JOIN's creator an operator, and an op's drawn token
     * carries a `@` from `names_signs()` in front of the name -- which would mean
     * every assertion below had to know whether the subject held a prefix mode, and
     * the case is about the NAME's shape. So `boss` creates the channel and the
     * subject joins an existing one, and holds no mode. It also means the roster
     * under test has more than one member, so "drawn as a bare nick" cannot be
     * satisfied by an empty or single-entry list. */
    {
        tc_init(&boss);
        register_caps(&boss, node.port, "boss", NULL);
        TF_CHECK_MSG(tc_send(&boss, "JOIN " CHAN) == 0, "boss: JOIN failed");
        TF_CHECK_MSG(tc_expect(&boss, " 366 ", T_IO_MS) == 0,
                     "boss never completed the JOIN that creates the channel");
        drain(&boss);

        tc_init(&subj);
        register_caps(&subj, node.port, SUBJECT, NULL);
        TF_CHECK_MSG(tc_send(&subj, "JOIN " CHAN) == 0,
                     "%s: JOIN send failed", SUBJECT);
        TF_CHECK_MSG(tc_expect(&subj, " 366 ", T_IO_MS) == 0,
                     "%s never completed its JOIN", SUBJECT);
        drain(&subj);
        /* The subject's OWN roster is the BARE shape, and that is asserted rather
         * than assumed: he negotiated nothing, so this is the negative case on a
         * socket that has seen nothing else. If the node drew hostmasks
         * unconditionally, every case below would be checking a roster shape that
         * this connection contradicts -- and this connection is the subject of
         * every one of them. */
        expect_names_token(&subj, SUBJECT, SUBJECT);
        /* The two observers are IN the channel now, so the NAMES they ask for is
         * answered from the same roster the subject just saw. */
        TF_CHECK_MSG(tc_send(&fancy, "JOIN " CHAN) == 0, "fancy: JOIN failed");
        TF_CHECK_MSG(tc_expect(&fancy, " 366 ", T_IO_MS) == 0,
                     "fancy never completed its JOIN");
        drain(&fancy);
        TF_CHECK_MSG(tc_send(&plain, "JOIN " CHAN) == 0, "plain: JOIN failed");
        TF_CHECK_MSG(tc_expect(&plain, " 366 ", T_IO_MS) == 0,
                     "plain never completed its JOIN");
        drain(&plain);
        /* NEITHER `boss` NOR `subj` IS CLOSED HERE, and that is load-bearing rather
         * than tidiness: closing either removes it from the roster, and the cases
         * below are about how a member that is PRESENT is drawn. A closed subject
         * would have made the whole file pass against a roster that did not contain
         * the name at all -- which is the shape of a green test that proves nothing.
         * Both are closed at the end, with the rest. */
    }

    /* ---- WITH the capability: the full hostmask ---- */
    /* The OBSERVED host, not the `*spoofed` string USER asserted. A node that
     * stored the assertion would draw `harriet!harriet@spoofed` and fail here, and
     * that is the point: this case is about the shape, and the shape is only
     * trustworthy if the two halves of it come from where §2.1 says they do. */
    expect_names_token(&fancy, "fancy",
                       SUBJECT "!" SUBJECT_IDENT "@" OBSERVED_HOST);

    /* ---- WITHOUT it: the bare nickname, ON THE SAME CHANNEL ---- */
    expect_names_token(&plain, "plain", SUBJECT);

    /* ---- AND THE SECOND NEGOTIATING CLIENT GETS THE SAME ANSWER ----
     * This is the control for the pair above. Without it, a node that drew a
     * hostmask for `fancy` and nothing else -- or for the first client that asked
     * and not the second -- would satisfy every assertion so far. The roster is
     * shared state and the rendering is per connection; a second connection is the
     * only thing that can tell those apart. */
    expect_names_token(&other, "other",
                       SUBJECT "!" SUBJECT_IDENT "@" OBSERVED_HOST);

    /* ---- AND THE ORDER IS NOT FLIPPED ----
     * A node that rendered `user@host!nick` would still contain
     * `harriet!harriet@127.0.0.1`... it would not: the reversed form has the ident
     * and the host on the other side of the `!`, so the positive token is absent
     * rather than merely present. But the REVERSED form satisfies every assertion
     * above that searched for a nickname substring, so it is asserted absent
     * explicitly rather than left to be inferred. */
    {
        const size_t mark = tc_received(&other);

        TF_CHECK_MSG(tc_send(&other, "NAMES " CHAN) == 0, "other: NAMES failed");
        TF_CHECK_MSG(tc_expect(&other, " 366 ", T_IO_MS) == 0,
                     "other: NAMES was never answered");
        drain(&other);
        TF_CHECK_MSG(names_token_present(tc_buffer(&other), mark,
                                         SUBJECT_IDENT "@" OBSERVED_HOST "!"
                                             SUBJECT) == 0,
                     "the 353 drew the hostmask in the order ident@host!nick.\n  "
                     "client saw: %s", tc_buffer(&other) + mark);
    }

    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
    tc_close(&plain);
    tc_close(&fancy);
    tc_close(&other);
    tc_close(&boss);
    tc_close(&subj);
}

/* ---------------------------------------------------------------------------
 * TEETH, AND WHERE THEY WERE INJECTED
 * ---------------------------------------------------------------------------
 * Each was watched go red with the behaviour broken, and the build was checked
 * before the run was believed -- an uncompilable fault leaves the previous binary
 * in place and reports a pass, which has happened in this repo seven times.
 *
 *   userhost-in-names applied to EVERY destination
 *       cap.c, cap_userhost_in_names_enabled(): the gate replaced with 1, so every
 *       destination gets the long form whether it negotiated or not. Fails the
 *       `plain` case and the subject's own roster, and NOT the `fancy` one -- which
 *       is what makes the negative load-bearing.
 *
 *       (The same edit in chan_verbs.c does NOT compile: `dst` becomes an unused
 *       parameter under -Weverything. That is why the fault lives in cap.c, and it
 *       is worth recording that the build check caught this one before the run --
 *       a run against the previous binary would have reported a pass.)
 *
 *   userhost-in-names IGNORED
 *       cap.c, cap_userhost_in_names_enabled(): the gate replaced with 0. Fails the
 *       `fancy` and `other` cases and not `plain`'s.
 *
 *   the ident left out of the hostmask
 *       chan_verbs.c, names_entry(): `nick!ident@host` rendered `nick@host`. Fails
 *       the positives -- and it is the positives rather than a substring match that
 *       catches it, because a hostmask contains no space and a plain `strstr` for
 *       the nickname would still have succeeded.
 *
 *   the hostmask order flipped
 *       chan_verbs.c, names_entry(): `ident@host!nick`. Also fails the positives,
 *       because names_token_present() pins the whole ENTRY rather than a prefix of
 *       it. The explicit reversed-form assertion at the end of the case is the belt:
 *       it names the wrong shape directly, so the failure says which order was
 *       rendered rather than only which token was missing.
 *
 *   advertised but not implemented
 *       cap.c, k_caps[]: CAP_USERHOST_IN_NAMES removed while the rendering stayed.
 *       Fails the CAP LS assertion AND register_caps()'s ACK wait, so the two halves
 *       are asserted together rather than one being assumed from the other.
 */
int main(void)
{
    case_userhost_in_names();
    tf_done("userhost_in_names");
    return 0;
}
