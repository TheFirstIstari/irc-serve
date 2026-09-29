/* test_channels.c -- the channel surface on the wire, against the real binary,
 * and the two federation invariants of 2.2 that are single-node testable.
 *
 * docs/SERVER_DESIGN.md 7/Phase 4, acceptance:
 *   "two clients join #t, each sees both in 353 in the fixed order; 332/333 on
 *    TOPIC; non-op KICK -> 482; the creation race is broken by
 *    (creation_epoch, server_name) with the loser re-keying."
 *
 * Plus the properties that make those four mean something:
 *
 *   - 353's order is asserted EXACTLY, including a channel holding a mix of
 *     plain, op and voiced members. "Both names appear" would pass against a
 *     roster in any order at all.
 *   - 353 is terminated by 366 and 366 is LAST. A 353 with no terminator leaves
 *     a client waiting for the rest of the list forever.
 *   - +o GATES KICK, in BOTH directions. A 482 that every KICK draws passes the
 *     acceptance criterion and is broken, and so does a KICK that always works.
 *   - THE SINGLE-WRITER RULE, with the part that matters: the state change is
 *     refused with 437 AND the channel is provably unchanged afterwards. A
 *     refusal that still mutated state would be worse than no rule at all,
 *     because the node would then hold a local copy nobody can reconcile.
 *   - The creation tie-break in BOTH halves of its lexicographic order, in both
 *     directions, each observed on the wire.
 *   - servers[] is POPULATED and load-bearing, not declared.
 *
 * EVERY ASSERTION IS ON WIRE BYTES, per 6.1. Nothing here reads a chan_t. The
 * one place the test builds channel state is a FIXTURE callback running in the
 * child (see PART B), and even there the consequences are asserted through the
 * socket: a test that read members[] or modes[] would break on any
 * restructuring of them while proving nothing about the protocol.
 *
 * ---------------------------------------------------------------------------
 * TWO FIXTURES, AND WHY
 * ---------------------------------------------------------------------------
 * PART A runs the SHIPPED BINARY, on port 0, and asserts 6.1's wire output.
 * A channel bug that only appears in the real binary's loop is exactly the bug
 * this test exists to find, so this is not a bespoke in-process node.
 *
 * PART B runs an INLINE child (the same core loop, with a setup hook) because
 * 2.2's single-writer rule needs a channel this node does NOT own, and Phase 6
 * -- the only thing that can produce one legitimately -- is out of scope. The
 * fixture produces one through 2.2's OWN creation-race path: it pre-creates a
 * channel owned by itself, and chan_rekey() moves that ownership to another
 * server the moment the channel acquires a member. Nothing is stubbed and no
 * forbidden path is taken -- the re-key is the same call the creation race
 * makes, and chan_origin_wins() below it is the same pure function the design
 * names. "Build a channel and fake its origin" would have been easier and
 * would have tested nothing the design actually specifies.
 *
 * NO sleep() ANYWHERE (6.3). Every wait is a select()-driven deadline in
 * tc_expect()/nf_expect(): generous in seconds, and failing fast on a
 * condition that can never arrive.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/channel.h"
#include "core/commands.h"
#include "core/server.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_READY_MS 15000
#define T_IO_MS 15000

/* The shipped binary's node name, and the inline fixture's. They differ, and
 * the difference is load-bearing: numerics and echoes are prefixed with the
 * node's own name, so an assertion that hard-codes the wrong one is asserting
 * against a line this node never sends. */
#define BIN_NAME "irc.test"
#define FIX_NAME "irc.fixture"

/* How many clients this test has opened. Counted rather than written down, so
 * the "the node accepted exactly what we connected" assertion cannot drift out
 * of step with the tests above it the moment one is added. */
static size_t g_opened;

/* ---------------------------------------------------------------------------
 * Client helpers
 * ------------------------------------------------------------------------- */

/* One registered client. Registration is here rather than in each test so that
 * no test can accidentally assert a channel verb against an unregistered
 * connection and get a 451 for a reason that has nothing to do with channels. */
typedef struct {
    test_client_t c;
    char          nick[72];
} client_t;

static void client_open(client_t *cl, nf_node_t *node, const char *nick)
{
    char line[256];

    tc_init(&cl->c);
    (void)snprintf(cl->nick, sizeof cl->nick, "%s", nick);
    g_opened++;
    TF_CHECK_MSG(tc_connect(&cl->c, node->port) == 0, "tc_connect(%s) failed",
                 nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "NICK send failed");
    (void)snprintf(line, sizeof line, "USER %s 0 * :%s Example", nick, nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "USER send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, " 001 ", T_IO_MS) == 0,
                 "%s did not register", nick);
    /* Drain the rest of the welcome burst, so a later count of "lines received"
     * is about what the test sent rather than about the MOTD. */
    TF_CHECK_MSG(tc_send(&cl->c, "PING :reg-drain") == 0, "PING send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, "PONG ", T_IO_MS) == 0,
                 "%s: no PONG after registration", nick);
}

static void client_send(client_t *cl, const char *line)
{
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "tc_send(%s) failed", line);
}

/* Assert the EXACT line, CRLF included, and that it starts a line. The CRLF is
 * part of the needle so this proves the line is terminated on the wire rather
 * than being a prefix of a longer one, and the leading boundary is checked
 * explicitly so a numeric that is a SUFFIX of a longer line cannot pass. */
static void expect_line(test_client_t *c, const char *what, const char *want)
{
    const char *at;

    TF_CHECK_MSG(tc_expect(c, want, T_IO_MS) == 0, "%s: expected the exact line "
                 "\"%s\"", what, want);
    at = strstr(tc_buffer(c), want);
    TF_CHECK_MSG(at != NULL, "%s: the line vanished from the buffer", what);
    TF_CHECK_MSG(at == tc_buffer(c) || at[-1] == '\n',
                 "%s: \"%s\" is not at the start of a line: it is the tail of a "
                 "longer one", what, want);
}

/* Assert a PREFIX of a line whose tail is not known in advance -- a numeric
 * carrying a timestamp, say. Same boundary check, without demanding bytes the
 * test cannot legitimately predict. */
static void expect_line_prefix(test_client_t *c, const char *what,
                               const char *want)
{
    const char *at;

    TF_CHECK_MSG(tc_expect(c, want, T_IO_MS) == 0, "%s: expected a line "
                 "beginning \"%s\"", what, want);
    at = strstr(tc_buffer(c), want);
    TF_CHECK_MSG(at != NULL, "%s: the line vanished from the buffer", what);
    TF_CHECK_MSG(at == tc_buffer(c) || at[-1] == '\n',
                 "%s: \"%s\" is not at the start of a line: it is the tail of a "
                 "longer one", what, want);
}

static void expect_absent(test_client_t *c, const char *what, const char *needle)
{
    TF_CHECK_MSG(strstr(tc_buffer(c), needle) == NULL,
                 "%s: \"%s\" appeared and must not have", what, needle);
}

/* Assert that `needles` appear in this window, IN THIS ORDER.
 *
 * This exists because a set of expect_line() calls does not assert an order, and
 * an order is the whole of 7/Phase 4's "353 ordering fixed". Every one of the
 * expected lines is present under a REVERSED 353 order -- strstr() finds each of
 * them wherever it landed -- so a test built only from expect_line() passes
 * against a node with the order exactly backwards. That was demonstrated: the
 * order was broken on purpose and the suite stayed green until this helper
 * existed.
 *
 * `from` is a byte offset into the buffer, and it is where the search starts
 * rather than the whole buffer, so a needle that appeared in an earlier exchange
 * cannot satisfy the first entry. The search then advances past each match, so
 * two identical needles cannot satisfy two entries either. */
static void expect_order(test_client_t *c, size_t from, const char *what,
                         const char *const *needles, size_t n)
{
    const char *p = tc_buffer(c) + from;
    size_t prev = from;

    for (size_t i = 0; i < n; i++) {
        const char *at = strstr(p, needles[i]);

        TF_CHECK_MSG(at != NULL,
                     "%s: line %zu of %zu (\"%s\") is not in the answer at all",
                     what, i + 1u, n, needles[i]);
        if (at == NULL) {
            return;
        }
        TF_CHECK_MSG((size_t)(at - tc_buffer(c)) >= prev,
                     "%s: line %zu (\"%s\") appears before the line that should "
                     "precede it -- the order is wrong", what, i + 1u, needles[i]);
        prev = (size_t)(at - tc_buffer(c));
        p = at + strlen(needles[i]);
    }
}

/* The same, over a WINDOW of the buffer rather than all of it. Used wherever an
 * earlier part of the test has legitimately mentioned the thing being asserted
 * absent -- a whole-buffer absence check in that situation is not a strong
 * assertion, it is a coin toss. `from` is a byte offset into the buffer. */
static void expect_absent_from(const char *buf, size_t from, const char *what,
                               const char *needle)
{
    TF_CHECK_MSG(strstr(buf + from, needle) == NULL,
                 "%s: \"%s\" appeared and must not have", what, needle);
}

/* Send `line` and wait for a PONG, so every answer to `line` is in the buffer
 * when this returns. This is the no-sleep drain from 6.3: the node answers in
 * order, so the PONG cannot overtake an earlier reply, and nothing here assumes
 * how long the node takes.
 *
 * The offset of that PONG is returned, because it is the boundary of the window
 * everything the test sends next belongs to. Counting from a remembered offset
 * is what makes "no 421 arrived" a statement about those verbs rather than
 * about the whole session. */
static size_t send_and_drain(client_t *cl, const char *tag)
{
    char line[64];
    char want[80];
    const char *at;

    (void)snprintf(line, sizeof line, "PING :%s", tag);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "PING send failed");
    (void)snprintf(want, sizeof want, "PONG %s %s", BIN_NAME, tag);
    TF_CHECK_MSG(tc_expect(&cl->c, want, T_IO_MS) == 0,
                 "%s: no PONG(%s), so replies may not all have arrived", cl->nick,
                 tag);
    at = strstr(tc_buffer(&cl->c), tag);
    TF_CHECK_MSG(at != NULL, "%s: the drain tag %s is not in the buffer", cl->nick,
                 tag);
    return (size_t)(at - tc_buffer(&cl->c));
}

/* As send_and_drain(), for the inline fixture. Its name is FIX_NAME, not
 * BIN_NAME, so matching the whole PONG line would be an assertion about a
 * different node. The token alone is matched and the offset is taken from it,
 * so the two node names never appear in one helper and neither can drift. */
static size_t send_and_drain_fix(client_t *cl, const char *tag)
{
    char line[64];
    const char *at;

    (void)snprintf(line, sizeof line, "PING :%s", tag);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "PING send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, tag, T_IO_MS) == 0,
                 "%s: no PONG(%s), so replies may not all have arrived", cl->nick,
                 tag);
    at = strstr(tc_buffer(&cl->c), tag);
    TF_CHECK_MSG(at != NULL, "%s: the drain tag %s is not in the buffer", cl->nick,
                 tag);
    return (size_t)(at - tc_buffer(&cl->c));
}

/* Build a nick of exactly `len` characters, unique for `i`, legal under 2.1's
 * charset rule and inside IRC_MAX_NICK. Used to make a roster long without
 * opening forty connections: what 353 has to split is measured in BYTES, not in
 * members. */
static void long_nick(char *out, size_t cap, int i, size_t len)
{
    size_t k;

    TF_CHECK_MSG(len < cap, "long_nick: %zu does not fit in %zu", len, cap);
    (void)snprintf(out, cap, "n%02d", i);
    for (k = strlen(out); k < len; k++) {
        out[k] = 'z';
    }
    out[len] = '\0';
}

/* ===========================================================================
 * PART A -- the shipped binary
 * ======================================================================== */

/* 7/Phase 4: "each sees both in 353 in the fixed order". Two clients, one op
 * (the creator) and one plain, and BOTH must see both names -- in the order the
 * design fixes. The order is asserted as the exact 353 line, not as "alice then
 * bob appear somewhere", because a roster in an arbitrary order satisfies the
 * weak reading and defeats the purpose. */
static void test_roster_and_order(nf_node_t *node)
{
    client_t a;
    client_t b;
    size_t drain;

    client_open(&a, node, "roa");
    client_open(&b, node, "rob");

    client_send(&a, "JOIN #ro");
    expect_line(&a.c, "the creator's JOIN echo",
                ":roa!roa@127.0.0.1 JOIN #RO\r\n");
    /* The creator holds +o, so the roster shows it with '@'. RFC 1459 2.3.1
     * grants the creator operator status, and without it no channel on this node
     * would have an operator at all -- every MODE +o needs one. */
    expect_line(&a.c, "353 for a channel the creator is alone in",
                ":irc.test 353 roa = #RO @roa\r\n");
    expect_line(&a.c, "366 closing the creator's names list",
                ":irc.test 366 roa #RO :End of /NAMES list\r\n");

    client_send(&b, "JOIN #ro");
    (void)send_and_drain(&b, "b-joined");

    /* Both clients, both orders. The plain member's 353 comes FIRST and the
     * op's SECOND, which is the reverse of join order -- that inversion is the
     * fixed order doing its job, and a test asserting join order would pass
     * against a node with no ordering rule at all.
     *
     * ONE 353 PER GROUP, not one line holding all three. The order is a
     * property of the SEQUENCE of lines as much as of their contents, and
     * RFC 2812 3.3.5 explicitly allows a 353 to be split across lines, so the
     * groups arrive in the fixed order as three lines. Asserting a single line
     * here would be asserting a formatting choice the design does not make, and
     * would break the moment a roster needed splitting -- which is exactly what
     * test_long_roster_chunks() is for. */
    expect_line(&b.c, "353 for the plain group, first",
                ":irc.test 353 rob = #RO rob\r\n");
    expect_line(&b.c, "353 for the op group, second",
                ":irc.test 353 rob = #RO @roa\r\n");
    expect_line(&b.c, "366 after rob's roster",
                ":irc.test 366 rob #RO :End of /NAMES list\r\n");
    expect_line(&a.c, "the JOIN echo roa sees when rob joins",
                ":rob!rob@127.0.0.1 JOIN #RO\r\n");

    /* The window starts BEFORE the command, not at the drain tag. The drain tag
     * is in the PONG, and the node answers the NAMES before the PONG, so a
     * window anchored on the tag would be the empty span after the very lines
     * it is supposed to inspect. */
    drain = tc_received(&a.c);
    client_send(&a, "NAMES #ro");
    (void)send_and_drain(&a, "a-names");
    expect_line(&a.c, "353 from NAMES, plain group first",
                ":irc.test 353 roa = #RO rob\r\n");
    expect_line(&a.c, "353 from NAMES, op group second",
                ":irc.test 353 roa = #RO @roa\r\n");
    expect_line(&a.c, "366 after NAMES",
                ":irc.test 366 roa #RO :End of /NAMES list\r\n");
    {
        static const char *const seq[] = {
            ":irc.test 353 roa = #RO rob\r\n",
            ":irc.test 353 roa = #RO @roa\r\n",
            ":irc.test 366 roa #RO :End of /NAMES list\r\n"
        };

        expect_order(&a.c, drain, "the NAMES answer order", seq,
                     sizeof seq / sizeof seq[0]);
    }

    /* 366 is LAST, and asserted over a WINDOW rather than the whole buffer: the
     * earlier JOIN also produced a 366, so "the last 366 in everything I have
     * ever received" would be answered by the first JOIN and prove nothing.
     * Within the NAMES answer the only lines are 353(s) and then 366, so "the
     * final line of the window is the 366" is the real claim: a node that
     * emitted anything after the terminator fails here. */
    {
        const char *win = tc_buffer(&a.c) + drain;
        const char *first = strstr(win, " 353 ");
        const char *second = (first != NULL) ? strstr(first + 1, " 353 ") : NULL;
        const char *end366 = (second != NULL) ? strstr(second, " 366 ") : NULL;

        TF_CHECK_MSG(first != NULL && second != NULL && end366 != NULL,
                     "the NAMES answer did not carry two 353 lines and a 366");
        if (first != NULL && second != NULL && end366 != NULL) {
            /* 366 TERMINATES THE LIST, so it comes after every 353. Asserting
             * the relative order is the property; asserting only that all three
             * arrived would pass against a node that emitted 366 first. */
            TF_CHECK_MSG(first < second && second < end366,
                         "the names list is not terminated last: the 366 does "
                         "not follow both 353 lines");
            TF_CHECK_MSG(tf_count(win, " 353 ") == 2,
                         "the NAMES answer carried %zu 353 lines for a "
                         "two-member channel, expected one per non-empty group",
                         tf_count(win, " 353 "));
            TF_CHECK_MSG(tf_count(win, " 366 ") == 1,
                         "the NAMES answer carried %zu 366 lines, expected "
                         "exactly one terminator", tf_count(win, " 366 "));
            /* And NOTHING follows the 366 but the line's own CRLF. The next
             * thing in the buffer is the PONG this test sent to drain, so the
             * span between them must be exactly the terminator's text. A node
             * that emitted anything after the 366 -- a stray numeric, a second
             * names list -- fails here. */
            {
                const char *eol = strchr(end366, '\n');

                TF_CHECK_MSG(eol != NULL, "the 366 terminator line is "
                             "unterminated");
                /* Nothing numeric follows the terminator. Combined with the
                 * counts above -- exactly two 353 and exactly one 366 in the
                 * whole answer -- this is what "366 is LAST" means here: a node
                 * that emitted a stray numeric, or a second names list, after
                 * the terminator fails. The window's own last line is the PONG
                 * this test sent to drain, which is why the check is a count
                 * rather than "the last line is the 366". */
                if (eol != NULL) {
                    const char *after = eol + 1;

                    TF_CHECK_MSG(tf_count(after, " 353 ") == 0,
                                 "%zu 353 lines follow the 366 terminator",
                                 tf_count(after, " 353 "));
                    TF_CHECK_MSG(tf_count(after, " 366 ") == 0,
                                 "%zu 366 lines follow the 366 terminator",
                                 tf_count(after, " 366 "));
                }
            }
        }
    }

    tc_close(&a.c);
    tc_close(&b.c);
}

/* The three-group order, with a member in each. This is the assertion that 353
 * is a fixed ORDER rather than a set: three names, three groups, and the wire
 * shows which group each fell into and in what sequence. */
static void test_names_group_order(nf_node_t *node)
{
    client_t op;
    client_t plain;
    client_t second_plain;
    client_t voiced;

    client_open(&op, node, "gro");
    client_open(&plain, node, "gr1");
    client_open(&second_plain, node, "gr2");
    client_open(&voiced, node, "grv");

    /* gro creates, so it holds +o. The joins are deliberately scrambled
     * relative to the expected output: gr1, grv, gr2. */
    /* A drain per connection, in the join order, and the order MATTERS here
     * rather than merely being tidy: the expected roster orders the plain group
     * by JOIN order, so a join whose processing had not been confirmed could
     * render the two plain members the other way round -- which is the very
     * distinction the "#h" case below exists to draw. See test_topic. */
    client_send(&op, "JOIN #g");
    (void)send_and_drain(&op, "g-join-1");
    client_send(&plain, "JOIN #g");
    (void)send_and_drain(&plain, "g-join-2");
    client_send(&voiced, "JOIN #g");
    (void)send_and_drain(&voiced, "g-join-3");
    client_send(&second_plain, "JOIN #g");
    (void)send_and_drain(&second_plain, "g-join-4");

    client_send(&op, "MODE #g +v grv");
    (void)send_and_drain(&op, "g-voiced");
    expect_line(&op.c, "the +v echo",
                ":gro!gro@127.0.0.1 MODE #G +v grv\r\n");

    {
        size_t before = tc_received(&op.c);
        /* The order assertion, stated separately from the three content
         * assertions below. Those prove the lines are present; this proves they
         * arrive plain-then-op-then-voiced. A node that emitted them in the
         * reverse order satisfies all three content checks and fails this. */
        static const char *const seq[] = {
            ":irc.test 353 gro = #G :gr1 gr2\r\n",
            ":irc.test 353 gro = #G @gro\r\n",
            ":irc.test 353 gro = #G +grv\r\n",
            ":irc.test 366 gro #G :End of /NAMES list\r\n"
        };

        client_send(&op, "NAMES #g");
        (void)send_and_drain(&op, "g-names");
        expect_order(&op.c, before, "the 353 group order", seq,
                     sizeof seq / sizeof seq[0]);
    }

    /* nicks, then ops, then voiced. Each group in join order:
     *   plain: gr1, gr2   (gr1 joined before gr2)
     *   op:    gro
     *   voiced: grv
     * Note grv is NOT rendered as a plain nick as well: a member holding a
     * prefix renders in its group and nowhere else, so a roster that tested the
     * groups independently would list grv twice. */
    /* A 353 naming MORE THAN ONE member has a space in its trailing
     * parameter, so the formatter colons it -- which is exactly what every
     * other IRC server does, and what a client parsing by position requires.
     * A single-name 353 needs no colon, so the same channel produces both
     * forms and both are asserted below. Asserting the uncoloned form of a
     * multi-name line would be asserting a line this node does not send. */
    expect_line(&op.c, "353 with plain members first, in join order",
                ":irc.test 353 gro = #G :gr1 gr2\r\n");
    expect_line(&op.c, "353 then the ops",
                ":irc.test 353 gro = #G @gro\r\n");
    expect_line(&op.c, "353 then the voiced",
                ":irc.test 353 gro = #G +grv\r\n");
    expect_line(&op.c, "366 closing the roster",
                ":irc.test 366 gro #G :End of /NAMES list\r\n");

    /* Join order inside a group, and NOT alphabetical order inside a group.
     * grz creates #h, so grz is the op; then grm and then gra join, in that order.
     * Join order renders "grm gra" and alphabetical order would render "gra grm",
     * so the two rules are distinguishable and this picks one.
     *
     * A separate channel, so the two orderings cannot contaminate each other. */
    {
        client_t first;
        client_t second;

        client_open(&first, node, "grz");
        client_open(&second, node, "grm");
        client_send(&first, "JOIN #h");
        (void)send_and_drain(&first, "h-join-1");
        client_send(&second, "JOIN #h");
        (void)send_and_drain(&second, "h-join-2");
        {
            client_t third;

            client_open(&third, node, "gra");
            client_send(&third, "JOIN #h");
            (void)send_and_drain(&third, "h-join-3");
            client_send(&first, "NAMES #h");
            (void)send_and_drain(&first, "h-names");
            expect_line(&first.c, "join order inside the plain group, not "
                        "alphabetical",
                        ":irc.test 353 grz = #H :grm gra\r\n");
            expect_line(&first.c, "the op group after the plain one on #h",
                        ":irc.test 353 grz = #H @grz\r\n");
            tc_close(&third.c);
        }
        tc_close(&first.c);
        tc_close(&second.c);
    }

    tc_close(&op.c);
    tc_close(&plain.c);
    tc_close(&second_plain.c);
    tc_close(&voiced.c);
}

/* 332/333 on TOPIC, set and query. 333 must carry the setter AND the time: a 333
 * without a time is not a 333, and a time of 0 would be a lie about a topic that
 * was just set. */
static void test_topic(nf_node_t *node)
{
    client_t a;
    client_t b;

    client_open(&a, node, "tpa");
    client_open(&b, node, "tpb");
    /* Each JOIN is drained on ITS OWN connection. A drain on one client proves
     * only that client's command was processed; two clients joining the same
     * channel and then draining on the first leaves the second's JOIN racing
     * everything after it -- the TOPIC broadcast below would sometimes be sent
     * before tpb was a member, and the assertion on tpb's socket would fail on
     * a perfectly correct node. Draining per connection is what turns "these
     * commands happened" into "these commands have been processed", and it is a
     * select()-driven deadline rather than a sleep. */
    client_send(&a, "JOIN #tp");
    (void)send_and_drain(&a, "t-join-a");
    client_send(&b, "JOIN #tp");
    (void)send_and_drain(&b, "t-join-b");

    /* With no topic, 331 and no 332. */
    client_send(&a, "TOPIC #tp");
    (void)send_and_drain(&a, "t-query0");
    expect_line(&a.c, "331 for an unset topic",
                ":irc.test 331 tpa #TP :No topic is set\r\n");
    expect_absent(&a.c, "the unset-topic query", " 332 ");
    expect_absent(&a.c, "the unset-topic query", " 333 ");

    /* Set it. A topic containing a SPACE, which is the case that would break if
     * the topic were put in a middle parameter rather than the trailing one.
     *
     * The echo carries the ACTING user's hostmask, so tpa's, for BOTH
     * recipients -- RFC 2812 3.3.1 makes the broadcast a message FROM the user
     * who set the topic, not from the server and not from the recipient. A test
     * expecting tpb's own mask here would be expecting a line this node does
     * not send, and would pass against a node that attributed every channel
     * action to its own name.
     *
     * AND IT CARRIES THE TOPIC, as the trailing parameter of the same RFC
     * command. The bare `:setter TOPIC #TP` this node used to send is not a
     * TOPIC the RFC describes: a member that received it had to re-read 332 to
     * learn what the line it was just handed was about. (The setter is told the
     * topic again as 332/333 below, which is a different requirement -- the
     * canonical form and this node's clock -- and does not make the channel
     * echo's silence correct.) */
    client_send(&a, "TOPIC #tp :the phase four topic");
    (void)send_and_drain(&a, "t-set");
    expect_line(&a.c, "the TOPIC echo tpa sees",
                ":tpa!tpa@127.0.0.1 TOPIC #TP :the phase four topic\r\n");
    expect_line(&b.c, "the TOPIC echo tpb sees",
                ":tpa!tpa@127.0.0.1 TOPIC #TP :the phase four topic\r\n");
    expect_line(&a.c, "332 carrying the topic",
                ":irc.test 332 tpa #TP :the phase four topic\r\n");

    /* 333: :<server> 333 <nick> <channel> <setter> <time> :<topic>. The setter
     * and the time are MIDDLE parameters and the topic is the trailing one, so
     * the line is checked for all three separately -- a 333 with the right topic
     * and a missing time would pass a substring check on the topic alone. */
    {
        const char *at = strstr(tc_buffer(&a.c), " 333 ");
        const char *nl;

        TF_CHECK_MSG(at != NULL, "no 333 in tpa's buffer");
        nl = (at != NULL) ? strchr(at, '\n') : NULL;
        TF_CHECK_MSG(nl != NULL, "the 333 line is unterminated");
        if (at != NULL && nl != NULL) {
            const char *line = at;
            const char *chan_at = strstr(line, "#TP");
            const char *setter_at = strstr(line, " tpa 1");
            const char *topic_at = strstr(line, ":the phase four topic");
            const char *colon_time;

            TF_CHECK_MSG(chan_at != NULL && chan_at < nl,
                         "the 333 does not carry the channel as a middle "
                         "parameter: %.*s", (int)(nl - line), line);
            TF_CHECK_MSG(setter_at != NULL && setter_at < nl,
                         "the 333 does not carry the topic setter: %.*s",
                         (int)(nl - line), line);
            colon_time = strstr(line, " 1");
            TF_CHECK_MSG(colon_time != NULL, "the 333 carries no Unix time: %.*s",
                         (int)(nl - line), line);
            if (colon_time != NULL) {
                /* The time is the field just before the trailing topic and it
                 * must be a plausible Unix timestamp: 10 digits, and after
                 * 2020. A 0 or a monotonic millisecond count would both fail
                 * this, and both are the specific mistakes available (3.4's
                 * clock is milliseconds since an arbitrary epoch, not a date). */
                char stamp[24];
                const char *digits = colon_time + 1;
                size_t n = 0;
                long long value;

                while (digits[n] >= '0' && digits[n] <= '9' &&
                       n < sizeof stamp - 1u) {
                    stamp[n] = digits[n];
                    n++;
                }
                stamp[n] = '\0';
                TF_CHECK_MSG(n == 10,
                             "the 333 time is \"%s\", expected 10 digits of Unix "
                             "time: %.*s", stamp, (int)(nl - line), line);
                value = atoll(stamp);
                TF_CHECK_MSG(value > 1577836800LL,
                             "the 333 time %lld is before 2020, so it is not a "
                             "wall-clock stamp", value);
            }
            TF_CHECK_MSG(topic_at != NULL && topic_at < nl,
                         "the 333 does not repeat the topic as its trailing "
                         "parameter: %.*s", (int)(nl - line), line);
        }
    }

    /* The query, from the OTHER client, gets the same 332/333. */
    client_send(&b, "TOPIC #tp");
    (void)send_and_drain(&b, "t-query1");
    expect_line(&b.c, "332 on a query from another member",
                ":irc.test 332 tpb #TP :the phase four topic\r\n");
    expect_line_prefix(&b.c, "333 on a query from another member carries the "
                       "setter", ":irc.test 333 tpb #TP tpa 1");

    /* Clearing the topic: an empty trailing parameter. 331 comes back and the
     * topic is gone, so a 332 must not. The window starts BEFORE the command --
     * tpa's buffer legitimately contains the topic she just set. */
    {
        size_t before = tc_received(&a.c);

        client_send(&a, "TOPIC #tp :");
        (void)send_and_drain(&a, "t-clear");
        expect_line(&a.c, "331 after clearing the topic",
                    ":irc.test 331 tpa #TP :No topic is set\r\n");
        expect_absent_from(tc_buffer(&a.c), before, "the cleared topic",
                           "the phase four topic");
        expect_absent_from(tc_buffer(&a.c), before, "the cleared topic", " 332 ");
        expect_absent_from(tc_buffer(&a.c), before, "the cleared topic", " 333 ");
    }

    /* A query for a channel the client is not in is 442, and 442 is the whole
     * answer: no 331, no 332. */
    {
        client_t c;
        size_t before;

        client_open(&c, node, "tpc");
        before = tc_received(&c.c);
        client_send(&c, "TOPIC #tp");
        (void)send_and_drain(&c, "t-442");
        expect_line(&c.c, "442 for TOPIC on a channel tpc has not joined",
                    ":irc.test 442 tpc #TP :You're not on that channel\r\n");
        expect_absent_from(tc_buffer(&c.c), before, "the 442 reply", " 332 ");
        tc_close(&c.c);
    }

    tc_close(&a.c);
    tc_close(&b.c);
}

/* +o GATES KICK. Both halves, and both are needed: a 482 that every KICK draws
 * passes the acceptance criterion and is broken, and a KICK that always succeeds
 * passes it too. */
static void test_kick_authority(nf_node_t *node)
{
    client_t op;
    client_t victim;
    client_t stranger;
    size_t refused_from;

    client_open(&op, node, "kio");
    client_open(&victim, node, "kiv");
    client_open(&stranger, node, "kis");

    /* Per-connection drains; see test_topic. The roster assertions below read a
     * member COUNT, so they need both JOINs already processed. */
    client_send(&op, "JOIN #ki");
    (void)send_and_drain(&op, "k-join-op");
    client_send(&victim, "JOIN #ki");
    (void)send_and_drain(&victim, "k-join-vic");

    /* A non-op cannot kick. kiv holds no prefix at all. */
    client_send(&victim, "KICK #ki kio");
    (void)send_and_drain(&victim, "k-refused");
    expect_line(&victim.c, "482 for a non-op KICK",
                ":irc.test 482 kiv #KI :You're not a channel operator\r\n");

    /* And the kick did NOT happen: kio is still a member, which the roster
     * proves. Without this the test would pass against a node that sent 482 and
     * removed them anyway -- the refusal-without-effect check, which is the
     * property that matters most in this phase. */
    refused_from = tc_received(&op.c);
    client_send(&op, "NAMES #ki");
    (void)send_and_drain(&op, "k-after-refusal");
    expect_line(&op.c, "353 plain group after the refused KICK",
                ":irc.test 353 kio = #KI kiv\r\n");
    expect_line(&op.c, "353 op group after the refused KICK",
                ":irc.test 353 kio = #KI @kio\r\n");
    expect_absent(&op.c, "the roster after the refused KICK", " KICK ");
    {
        static const char *const seq[] = {
            ":irc.test 353 kio = #KI kiv\r\n",
            ":irc.test 353 kio = #KI @kio\r\n"
        };

        expect_order(&op.c, refused_from, "the roster order after the refused "
                     "KICK", seq, sizeof seq / sizeof seq[0]);
    }

    /* A non-member cannot kick either, and gets 442 rather than 482: kis is not
     * on the channel, so "you are not there" is the actionable answer. Checking
     * it before privilege is what stops a non-member being told something about
     * a channel's privilege list they have no standing to ask about. */
    client_send(&stranger, "KICK #ki kiv");
    (void)send_and_drain(&stranger, "k-nonmember");
    expect_line(&stranger.c, "442 for a KICK by a non-member",
                ":irc.test 442 kis #KI :You're not on that channel\r\n");

    /* An op CAN kick. The reason contains a space, so the formatter colons it:
     * asserting the uncoloned form would be asserting a line this node does not
     * send, and it is exactly the rule 3.2's formatter owns. */
    client_send(&op, "KICK #ki kiv :not today");
    {
        size_t before = send_and_drain(&op, "k-ok");

        expect_line_prefix(&op.c, "the KICK echo",
                           ":kio!kio@127.0.0.1 KICK #KI kiv :not today\r\n");
        /* The kicked user sees the same line: the prefix is the KICKER's, not
         * the recipient's and not the server's. Asserting kiv's own mask here
         * would be expecting a line this node does not send. */
        expect_line_prefix(&victim.c, "the kicked client sees its own KICK",
                           ":kio!kio@127.0.0.1 KICK #KI kiv :not today\r\n");
        client_send(&op, "NAMES #ki");
        (void)send_and_drain(&op, "k-after-ok");
        expect_line(&op.c, "the roster after the successful KICK",
                    ":irc.test 353 kio = #KI @kio\r\n");
        /* The window check, not a whole-buffer one: kiv is in this buffer many
         * times already, from their own JOIN, their 482 and their 442. Only the
         * span since the successful KICK can answer "were they removed". */
        expect_absent_from(tc_buffer(&op.c), before,
                           "the roster after the KICK", " kiv");
    }

    /* Kicking a nickname that is not on the channel is 441, distinct from 401
     * for a nickname this node has never heard of. The two are different facts
     * and 441 requires the kicker to BE a member of the channel -- 442 is
     * checked first, so this also pins the order. */
    client_send(&op, "KICK #ki nosuchnick");
    (void)send_and_drain(&op, "k-401");
    expect_line(&op.c, "401 for a nickname the node does not have",
                ":irc.test 401 kio nosuchnick :No such nick/channel\r\n");
    {
        client_t elsewhere;

        /* kie is on #ki3 and op is on #ki2, so `kie` is a real, registered nick
         * that is NOT on this channel -- which is the difference between 441
         * and 401. op must be a member of #ki2 too, or the KICK would be
         * answered 442 about a channel op is not on. */
        client_open(&elsewhere, node, "kie");
        client_send(&elsewhere, "JOIN #ki3");
        (void)send_and_drain(&op, "v-kie");
        client_send(&op, "JOIN #ki2");
        (void)send_and_drain(&op, "u-op");
        client_send(&op, "KICK #ki2 kie");
        (void)send_and_drain(&op, "k-441");
        /* RFC 2812 3.3.2 carries BOTH the nickname and the channel as middle
         * parameters of a 441, and the test asserts both: a 441 that named
         * only the nick would leave a client unable to tell which of several
         * channels the user is missing from. */
        expect_line(&op.c, "441 for a nickname that is not on THIS channel",
                    ":irc.test 441 kio kie #KI2 :They're not on that channel\r\n");
        tc_close(&elsewhere.c);
    }

    tc_close(&op.c);
    tc_close(&victim.c);
    tc_close(&stranger.c);
}

/* PART, and the 442 that a client not on the channel gets. Three different
 * situations, which must not collapse into one:
 *
 *   a channel that does not exist            442
 *   a channel that exists, client not on it  442   <- the case that matters
 *   a channel the client is on               the PART, echoed to everyone left
 */
static void test_part(nf_node_t *node)
{
    client_t a;
    client_t b;

    client_open(&a, node, "paa");
    client_open(&b, node, "pab");
    /* Per-connection drains; see test_topic for why a shared drain is a race. */
    client_send(&a, "JOIN #pa");
    (void)send_and_drain(&a, "p-join-a");
    client_send(&b, "JOIN #pa");
    (void)send_and_drain(&b, "p-join-b");

    /* PART of a channel that does not exist: 442, and no PART echo. */
    client_send(&b, "PART #nosuch");
    (void)send_and_drain(&b, "p-nosuch");
    expect_line(&b.c, "442 for PART of a channel that does not exist",
                ":irc.test 442 pab #NOSUCH :You're not on that channel\r\n");
    expect_absent(&b.c, "the refused PART", "PART #");

    /* PART of a channel that EXISTS but pab is not on. This is the one the
     * design's "you're not on that channel" is actually about, and it is
     * distinct from 403: 403 would send the client looking for a channel that
     * may well exist. paa creates #pa2 and pab stays out of it. */
    client_send(&a, "JOIN #pa2");
    (void)send_and_drain(&a, "p-u-created");
    client_send(&b, "PART #pa2");
    (void)send_and_drain(&b, "p-not-in");
    expect_line(&b.c, "442 for PART of a channel pab has not joined",
                ":irc.test 442 pab #PA2 :You're not on that channel\r\n");
    expect_absent(&b.c, "the refused PART of an existing channel", "PART #PA2");

    /* A real PART, with a reason containing a space, and both members see it.
     * The parting client sees its own departure (RFC 1459 2.3.1) and so does the
     * one left behind. */
    client_send(&a, "PART #pa :so long");
    (void)send_and_drain(&a, "p-real");
    expect_line(&a.c, "the parting client sees its own PART",
                ":paa!paa@127.0.0.1 PART #PA :so long\r\n");
    expect_line(&b.c, "the remaining member sees the PART",
                ":paa!paa@127.0.0.1 PART #PA :so long\r\n");

    /* The channel is GONE once its last local member has left, because there is
     * nothing left for it to be authoritative about. LIST proves it rather than
     * a 322 with a zero count, which a still-existing empty channel would also
     * produce. */
    client_send(&b, "PART #pa");
    (void)send_and_drain(&b, "p-last");
    {
        size_t before = tc_received(&b.c);

        client_send(&b, "LIST");
        (void)send_and_drain(&b, "p-list");
        expect_line(&b.c, "321 opening the LIST",
                    ":irc.test 321 pab Channel :Users  Name\r\n");
        /* A WINDOW, not the whole buffer: pab's buffer legitimately mentions
         * #PA in the 442s and the PART above. What matters is that the LIST --
         * this node's answer to "what channels exist" -- does not. */
        expect_absent_from(tc_buffer(&b.c), before,
                           "the LIST after the last member left", " #PA ");
        expect_line(&b.c, "323 closing the LIST",
                    ":irc.test 323 pab :End of LIST\r\n");
    }

    tc_close(&a.c);
    tc_close(&b.c);
}

/* NAMES and LIST, on a channel and on one that does not exist, and the decision
 * that LIST enumerates channels the requester has not joined. */
static void test_names_and_list(nf_node_t *node)
{
    client_t a;
    client_t b;
    client_t lurker;

    client_open(&a, node, "nla");
    client_open(&b, node, "nlb");
    client_open(&lurker, node, "nll");

    /* Per-connection drains; see test_topic. The 322 below reports a member
     * COUNT of 2, which is only true once b's JOIN has been processed. */
    client_send(&a, "JOIN #nl");
    (void)send_and_drain(&a, "nl-join-a");
    client_send(&a, "TOPIC #nl :a topic");
    (void)send_and_drain(&a, "nl-topic");
    client_send(&b, "JOIN #nl");
    (void)send_and_drain(&b, "nl-join-b");

    /* LIST enumerates EVERY channel on the node, including this one, which
     * lurker has NOT joined. A list restricted to joined channels would answer
     * nothing here, and answering nothing is the failure mode. */
    client_send(&lurker, "LIST");
    (void)send_and_drain(&lurker, "nl-list");
    expect_line(&lurker.c, "321 opening LIST for a non-member",
                ":irc.test 321 nll Channel :Users  Name\r\n");
    expect_line(&lurker.c, "322 for a channel nll has not joined",
                ":irc.test 322 nll #NL 2 :a topic\r\n");
    expect_line(&lurker.c, "323 closing LIST",
                ":irc.test 323 nll :End of LIST\r\n");

    /* LIST on a named channel the node has. */
    client_send(&lurker, "LIST #nl");
    (void)send_and_drain(&lurker, "nl-list1");
    expect_line(&lurker.c, "322 for LIST of a specific channel",
                ":irc.test 322 nll #NL 2 :a topic\r\n");
    expect_line(&lurker.c, "323 closing a single-channel LIST",
                ":irc.test 323 nll :End of LIST\r\n");

    /* LIST of a channel that does not exist is 403. Unlike NAMES, LIST names a
     * SPECIFIC channel whose absence is an error -- RFC 2812 3.3.5. */
    client_send(&lurker, "LIST #nosuch");
    (void)send_and_drain(&lurker, "nl-403");
    expect_line(&lurker.c, "403 for LIST of a nonexistent channel",
                ":irc.test 403 nll #NOSUCH :No such channel\r\n");

    /* NAMES of a channel that does not exist is 366 with no 353. NAMES is a
     * DISCOVERY command: a client calls it to find out whether something is
     * there, and "nobody" is a legitimate answer to exactly that question. */
    client_send(&lurker, "NAMES #nosuch");
    (void)send_and_drain(&lurker, "nl-366");
    expect_line(&lurker.c, "366 for NAMES of a nonexistent channel",
                ":irc.test 366 nll #NOSUCH :End of /NAMES list\r\n");
    expect_absent(&lurker.c, "the 366 reply", " 353 ");

    /* NAMES with no argument lists every channel. */
    client_send(&lurker, "NAMES");
    (void)send_and_drain(&lurker, "nl-names");
    expect_line(&lurker.c, "353 from a bare NAMES, plain group first",
                ":irc.test 353 nll = #NL nlb\r\n");
    expect_line(&lurker.c, "353 from a bare NAMES, op group second",
                ":irc.test 353 nll = #NL @nla\r\n");
    expect_line(&lurker.c, "366 after a bare NAMES",
                ":irc.test 366 nll #NL :End of /NAMES list\r\n");

    tc_close(&a.c);
    tc_close(&b.c);
    tc_close(&lurker.c);
}

/* 324 and 329, and the two 472s: a mode letter this node does not evaluate, and
 * a mode string with no sign. */
static void test_mode(nf_node_t *node)
{
    client_t a;
    client_t b;

    client_open(&a, node, "moa");
    client_open(&b, node, "mob");
    /* Per-connection drains; see test_topic. */
    client_send(&a, "JOIN #mo");
    (void)send_and_drain(&a, "m-join-a");
    client_send(&b, "JOIN #mo");
    (void)send_and_drain(&b, "m-join-b");

    /* The query, before any mode is set: the modestring is "-", which is the
     * honest answer for a channel with no modes rather than an empty string. */
    client_send(&a, "MODE #mo");
    (void)send_and_drain(&a, "m-query0");
    expect_line(&a.c, "324 for a channel with no modes",
                ":irc.test 324 moa #MO - :Channel modes\r\n");
    /* 329 carries a Unix timestamp, so it is asserted as a prefix: the value is
     * a wall-clock read and the test must not pretend to know it. */
    expect_line_prefix(&a.c, "329 carrying the channel creation time",
                       ":irc.test 329 moa #MO 1");

    /* +b is origin-only, and this node is the origin, so the creator may set
     * it. The 'b' letter then appears in 324. */
    client_send(&a, "MODE #mo +b *!*@10.9.9.9");
    (void)send_and_drain(&a, "m-ban0");
    expect_line(&a.c, "the +b echo",
                ":moa!moa@127.0.0.1 MODE #MO +b *!*@10.9.9.9\r\n");
    client_send(&a, "MODE #mo");
    (void)send_and_drain(&a, "m-query1");
    expect_line(&a.c, "324 now carries b",
                ":irc.test 324 moa #MO +b :Channel modes\r\n");

    /* A mode this node does not evaluate is 472 by name, not silence and not
     * 421. 004 advertises b,k,l,imnpst and this node acts on b alone; a node
     * that accepted 'k' would have a 324 that disagrees with its behaviour. */
    client_send(&a, "MODE #mo +k secret");
    (void)send_and_drain(&a, "m-472");
    expect_line(&a.c, "472 for a mode this node does not evaluate",
                ":irc.test 472 moa #MO :Unknown mode character\r\n");

    /* A mode string with no sign is 472 too. */
    client_send(&a, "MODE #mo k");
    (void)send_and_drain(&a, "m-472b");
    expect_line(&a.c, "472 for a mode string with no sign",
                ":irc.test 472 moa #MO :Unknown mode character\r\n");

    /* A non-op cannot set a mode. */
    client_send(&b, "MODE #mo +o mob");
    (void)send_and_drain(&b, "m-482");
    expect_line(&b.c, "482 for a MODE by a non-op",
                ":irc.test 482 mob #MO :You're not a channel operator\r\n");

    /* And the ban now refuses the masked host, which is the half of +b that
     * gives the mode AUTHORITY meaning: the origin can enforce, and the
     * single-writer test in PART B is what shows a non-origin cannot. */
    client_send(&a, "MODE #mo +b *!*@127.0.0.1");
    (void)send_and_drain(&a, "m-ban1");
    {
        client_t c;

        client_open(&c, node, "moban");
        client_send(&c, "JOIN #mo");
        (void)send_and_drain(&c, "m-474");
        expect_line(&c.c, "474 for a JOIN refused by the origin's ban list",
                    ":irc.test 474 moban #MO :Cannot join channel (banned)\r\n");
        /* And the refusal did not add them: a 353 for this channel must not
         * mention them. This is the second refusal-without-effect check in the
         * file, and the more likely one to get wrong, because a JOIN that bans
         * and then adds anyway is a plausible order of operations. */
        client_send(&a, "NAMES #mo");
        (void)send_and_drain(&a, "m-after-474");
        expect_line(&a.c, "353 plain group: the moban client is not on the "
                    "roster", ":irc.test 353 moa = #MO mob\r\n");
        expect_line(&a.c, "353 op group: the moban client is not on the "
                    "roster", ":irc.test 353 moa = #MO @moa\r\n");
        tc_close(&c.c);
    }

    /* -b removes the mask and, with no masks left, clears the 'b' letter. */
    client_send(&a, "MODE #mo -b *!*@127.0.0.1");
    (void)send_and_drain(&a, "m-unban1");
    client_send(&a, "MODE #mo");
    (void)send_and_drain(&a, "m-query2");
    expect_line(&a.c, "324 still carries b for the remaining mask",
                ":irc.test 324 moa #MO +b :Channel modes\r\n");
    client_send(&a, "MODE #mo -b *!*@10.9.9.9");
    (void)send_and_drain(&a, "m-unban2");
    client_send(&a, "MODE #mo");
    (void)send_and_drain(&a, "m-query3");
    expect_line(&a.c, "324 shows no modes once the last ban is lifted",
                ":irc.test 324 moa #MO - :Channel modes\r\n");

    tc_close(&a.c);
    tc_close(&b.c);
}

/* A roster too long for one 353 line must be CHUNKED, not truncated and not
 * refused. RFC 2812 3.3.5 allows a 353 to span several lines; 3.2 forbids
 * delivering a shortened value; and reply() REFUSES a trailing text that does not
 * fit REPLY_TEXT_MAX rather than truncating it, so a roster that was not chunked
 * would produce no names at all.
 *
 * Long NICKS rather than many members: what 353 has to split is measured in
 * bytes, and sixty connections would be sixty registrations to prove the same
 * thing. The first version of this test looped one client through sixty repeat
 * JOINs, which produces ONE member and therefore proved nothing at all -- a
 * repeat JOIN is answered with the roster of a one-member channel. */
static void test_long_roster_chunks(nf_node_t *node)
{
    client_t op;
    static const int kPlain = 7;
    static const size_t kNickLen = 60; /* seven of them overflow CHAN_NAMES_LINE */
    client_t plain[7];
    size_t drain;

    client_open(&op, node, "bio");
    client_send(&op, "JOIN #big");
    (void)send_and_drain(&op, "big-created");

    for (int i = 0; i < kPlain; i++) {
        char nick[72];

        long_nick(nick, sizeof nick, i, kNickLen);
        client_open(&plain[i], node, nick);
        (void)snprintf(plain[i].nick, sizeof plain[i].nick, "%s", nick);
        client_send(&plain[i], "JOIN #big");
        /* Drained per connection. The roster assertions below are about all
         * seven members, and a single drain on the op would prove only that the
         * op's own commands were processed. */
        (void)send_and_drain(&plain[i], "big-join");
    }

    /* The op asks for the roster once and everything counted below is inside
     * that one answer. Seven 60-character names plus separators is 427 bytes
     * against a 400-byte line budget, so the plain group cannot fit on one
     * line: a node that did not chunk would have to either drop names or let
     * reply() refuse the whole thing, and the counts below tell those apart.
     *
     * The window starts BEFORE the command. The drain tag lives in the PONG and
     * the node answers the NAMES first, so a window anchored on the tag would
     * be the empty span after the very lines it is inspecting. */
    drain = tc_received(&op.c);
    client_send(&op, "NAMES #big");
    (void)send_and_drain(&op, "big-names");
    {
        const char *win = tc_buffer(&op.c) + drain;

        TF_CHECK_MSG(tf_count(win, " 353 ") == 3,
                     "the long roster produced %zu 353 lines, expected 3: two "
                     "for the seven plain members and one for the op. A count of "
                     "1 means it was not chunked, a count of 0 means reply() "
                     "refused the line.", tf_count(win, " 353 "));
        TF_CHECK_MSG(tf_count(win, " 366 ") == 1,
                     "the long roster produced %zu terminators, expected 1",
                     tf_count(win, " 366 "));
        /* Every name is present as a STANDALONE TOKEN: preceded by a space or
         * by the colon that opens a names list, and followed by a space or by
         * the line's CR. That is what separates "chunked" from "truncated at a
         * byte boundary" -- a truncating node loses the tail of the roster and
         * this loop finds it, and a node that emitted a PREFIX of a nickname
         * does not pass.
         *
         * Both boundaries are needed. The nick also appears inside the
         * HOSTMASK of each client's own JOIN echo (":<nick>!<user>@<host>"),
         * so a search that only checked what followed the match would accept
         * the truncated first half of a hostmask. The nicks are unique, so
         * scanning for the first occurrence that satisfies both boundaries is
         * unambiguous. */
        for (int i = 0; i < kPlain; i++) {
            const size_t nlen = strlen(plain[i].nick);
            const char *at = win;
            int found = 0;

            while ((at = strstr(at, plain[i].nick)) != NULL) {
                const char prev = (at == win) ? '\n' : at[-1];
                const char next = at[nlen];

                if ((prev == ' ' || prev == ':') &&
                    (next == ' ' || next == '\r')) {
                    found = 1;
                    break;
                }
                at += nlen;
            }
            TF_CHECK_MSG(found,
                         "%s is not in the roster as a whole name: the roster "
                         "was truncated rather than chunked", plain[i].nick);
        }
        TF_CHECK_MSG(strstr(win, " @bio\r\n") != NULL,
                     "the long roster is missing the operator group");
    }

    /* reply() must never have refused. That is asserted once, over the whole
     * run, against the node's own counter at exit -- see main(). It cannot be
     * asserted here: the shipped binary publishes loop_stats when it exits and
     * not per tick, so a mid-run read of the counter would be a read of
     * nothing. Asserting the absence of a line instead would be the weaker
     * claim, since a refusal and a well-formed answer are both "no 353 here". */

    for (int i = 0; i < kPlain; i++) {
        tc_close(&plain[i].c);
    }
    tc_close(&op.c);
}

/* THE REAPER INVARIANT, at the channel layer: a connection that goes away takes
 * ITSELF out of every channel and leaves every other member, and every other
 * channel, alone. 3.4's reaper is the single close site, and a chan_t's member
 * list holds conn_t pointers -- so a conn freed while still a member leaves
 * every remaining member of that channel with a dangling pointer, and nothing
 * dereferences it until the next fan-out. The structural half of this
 * (no other file closes a descriptor) is test_close_sites; this is the runtime
 * half at the channel layer, and it is the only place a test can see it. */
static void test_reaper_leaves_channel(nf_node_t *node)
{
    client_t rea;
    client_t reb;

    client_open(&rea, node, "rea");
    client_open(&reb, node, "reb");
    /* Per-connection drains; see test_topic. The roster below names both
     * members, so reb's JOIN has to have been processed first. */
    client_send(&rea, "JOIN #re");
    (void)send_and_drain(&rea, "r-join-a");
    client_send(&reb, "JOIN #re");
    (void)send_and_drain(&reb, "r-join-b");
    /* A query, not the JOIN's own roster: the roster a JOIN prints is the one
     * the JOINER saw, and this is about what `rea` can see. */
    client_send(&rea, "NAMES #re");
    (void)send_and_drain(&rea, "r-names0");
    expect_line(&rea.c, "both members present before either leaves, plain group",
                ":irc.test 353 rea = #RE reb\r\n");
    expect_line(&rea.c, "both members present before either leaves, op group",
                ":irc.test 353 rea = #RE @rea\r\n");

    /* reb vanishes with no QUIT, so there is no reason to report: a hangup has
     * none and inventing one would put a word on the wire the client never
     * wrote. */
    tc_close(&reb.c);
    {
        size_t before = tc_received(&rea.c);

        /* Stay alive and talking, so the reaper is definitely reached. */
        client_send(&rea, "PING :r-after");
        (void)send_and_drain(&rea, "r-reaped");
        expect_line_prefix(&rea.c, "the survivors are told about the departure",
                           ":reb!reb@127.0.0.1 PART #RE");
        /* The channel is NOT freed out from under the member who is still in it.
         * If it were, NAMES would answer 366 with no roster at all, and a
         * channel whose remaining member had been silently dropped is exactly
         * the failure this test exists to catch. */
        client_send(&rea, "NAMES #re");
        (void)send_and_drain(&rea, "r-names");
        expect_line(&rea.c, "the survivor is still on the channel",
                    ":irc.test 353 rea = #RE @rea\r\n");
        expect_absent_from(tc_buffer(&rea.c), before,
                           "the survivor's roster", " reb");
    }

    /* And the nick is released, so the departed name is reusable. That is the
     * registry half of the same reaper path, and it is what makes "a client
     * reconnects with the same nick" work. */
    {
        client_t back;

        client_open(&back, node, "reb");
        client_send(&back, "JOIN #re");
        (void)send_and_drain(&back, "r-back");
        expect_line(&back.c, "the reconnected client is on the channel again, "
                    "plain group", ":irc.test 353 reb = #RE reb\r\n");
        expect_line(&back.c, "the reconnected client is on the channel again, "
                    "op group", ":irc.test 353 reb = #RE @rea\r\n");
        tc_close(&back.c);
    }

    tc_close(&rea.c);
}

/* ===========================================================================
 * PART B -- the inline fixture: 2.2's two single-node-testable invariants
 * ======================================================================== */

/* One creation-race case.
 *
 * The fixture creates the channel owned by ITSELF and, the moment the channel
 * has `min_members` local members, offers it to a rival server through
 * chan_rekey() -- 2.2's own "the loser re-keys to the winner's origin". chan_rekey
 * consults chan_origin_wins() and applies the result only if the candidate
 * WINS, so the four cases below are the four outcomes of the tie-break, and each
 * one's winner or loser is decided by the real rule rather than by a fixture
 * deciding what to pretend.
 *
 *   name    the rival's server name. Both "aaa.other" and "zzz.other" are legal
 *           under 2.4's tag grammar, and they straddle the fixture's own name
 *           "irc.fixture" so that the NAME comparison goes the way each case
 *           needs it to.
 *   delta   added to the fixture's own per-boot epoch (2.4), so the EPOCH
 *           comparison is exercised against a real value rather than a constant.
 *   expect  1 when the candidate must win, 0 when it must lose.
 */
struct rekey_case {
    const char *channel;
    const char *name;
    int         delta;
    size_t      min_members;
    int         expect;
};

/* THE SINGLE-WRITER TEST'S CHANNEL. Separate from the tie-break table below
 * because the tick hook offers each channel exactly once: sharing #tie would
 * mean the single-writer test consumed the offer and the tie-break test then
 * asserted on a channel that had already been re-keyed -- which passes for the
 * wrong reason. Its own channel makes each test the only thing that ever
 * happened to the channel it is asserting about.
 *
 * A higher epoch with a LOWER name, so the winner half of the rule is in force
 * here too: a rule that compared the name first would leave this channel owned
 * by the fixture and the 437s below would never be answered. */
static const struct rekey_case g_sw = { "#tie", "aaa.other", 1, 2u, 1 };

/* The four outcomes of a LEXICOGRAPHIC comparison, and the only two that matter
 * for correctness of the rule as 2.2 states it:
 *
 *   #re1  higher epoch, LOWER name  -> wins on epoch.  A rule that compared the
 *        name first would lose here, so this case is what distinguishes
 *        "lexicographic over (epoch, name)" from "name wins, epoch breaks ties".
 *   #re2  equal epoch, higher name  -> wins on name.  This is the ONLY case in
 *        which the name half of the tuple is ever decisive, and without it the
 *        name would be untested.
 *   #re3  equal epoch, LOWER name   -> loses on name.  The negative control for
 *        #re2; a rule that always accepted the candidate would pass #re2 and
 *        fail this.
 *   #re4  LOWER epoch, higher name  -> loses on epoch.  The negative control for
 *        #re1; this is the case that fails a "higher name always wins" rule.
 *
 * Testing only one ordering of a two-part comparison proves nothing, so both
 * halves are tested in both directions -- two winning cases and two losing ones,
 * and the two losers are losers for OPPOSITE reasons, so neither a
 * name-always-wins rule nor an epoch-always-wins rule can pass all four. */
static const struct rekey_case g_cases[] = {
    { "#re1", "aaa.other",  1, 1u, 1 },
    { "#re2", "zzz.other",  0, 1u, 1 },
    { "#re3", "aaa.other",  0, 1u, 0 },
    { "#re4", "zzz.other", -1, 1u, 0 }
};

#define NCASES (sizeof g_cases / sizeof g_cases[0])

/* Written only in the child, between the setup and the tests. */
static int g_case_done[NCASES];
static int g_sw_done;

/* 2.2's remote cache is a SET of server names, and this is the name put in it.
 * It is a legal server name under 2.4's grammar even though no peer bearing it
 * has ever existed -- which is the point: the cache records what a peer has
 * REPORTED, and the reporting is Phase 6's, while the storage and the
 * consequences of a non-empty cache are Phase 4's and are testable now. */
#define FAKE_PEER "peer.test"

#define CACHE_CH "#cached"
#define PLAIN_CH "#plainc"

/* The re-key. Runs in the child, from the tick hook, and only acts on a channel
 * that has acquired its required membership -- which is what makes it
 * deterministic. A hook that fired on a tick COUNT would race the client's JOIN;
 * one that fires on the STATE it is waiting for cannot, because the JOIN is a
 * single dispatch that runs to completion between two ticks. */
/* One offer, attempted at most once per channel. `slot` is the "already done"
 * flag for this channel; `done` is set as soon as the channel is eligible, so a
 * second tick cannot offer a second time. */
static void offer_rekey(server_t *s, const struct rekey_case *rc, int *done)
{
    chan_t *ch;
    uint64_t epoch;
    int won;

    if (*done != 0) {
        return;
    }
    ch = server_chan_get(s, rc->channel);
    if (ch == NULL || ch->nmembers < rc->min_members) {
        return;
    }
    *done = 1;
    /* The fixture created this channel, so the fixture is its creator -- and RFC
     * 1459 2.3.1 makes the creator a channel operator. Nobody joining it
     * afterwards gets that privilege, and without it here the fixture's own
     * channels would have NO operator at all: every MODE +o and every KICK
     * requires one, so the privileges Phase 4 exists to land would be
     * unreachable in every channel this test builds. Granting it to the first
     * member is the fixture standing in for a creator it cannot be.
     *
     * It also makes the MODE +v refusal checkable: a second member stays a
     * PLAIN member, so a refused `MODE +v <them>` has a visible effect if it
     * were wrongly applied -- they would move out of the plain group. */
    TF_CHECK_MSG(chan_set_member_flags(ch, ch->members[0].c, 1, CHAN_MEMBER_OP)
                     == 1,
                 "the fixture could not make %s's first member an operator",
                 ch->name);
    epoch = (rc->delta < 0)
                ? s->epoch - (uint64_t)(-rc->delta)
                : s->epoch + (uint64_t)rc->delta;
    won = chan_rekey(ch, rc->name, epoch);
    /* The fixture's own line, so the test can tell "the candidate was offered and
     * the rule refused it" from "the hook had not run yet". WITHOUT this line
     * the losing cases would be vacuous: a state change that succeeds because
     * nothing ever happened is indistinguishable from one that succeeds because
     * the candidate lost. The wire assertion is the load-bearing one; this line
     * is what makes it non-vacuous. */
    printf("[fixture] rekey_offered: channel=%s candidate=%s rc=%d\n", ch->name,
           rc->name, won);
    fflush(stdout);
}

static void fixture_tick(server_t *s, uint64_t now_ms)
{
    (void)now_ms;
    offer_rekey(s, &g_sw, &g_sw_done);
    for (size_t i = 0; i < NCASES; i++) {
        offer_rekey(s, &g_cases[i], &g_case_done[i]);
    }
}

/* Runs in the child, before anything may connect. */
static void fixture_setup(server_t *s)
{
    /* The command surface, installed exactly as node_main.c installs it for the
     * shipped binary. nf_setup_fn exists for this: "a test installs its
     * dispatch, its tick hook, or fills the descriptor table". Without it the
     * loop accepts, frames and parses and answers nothing -- which is the honest
     * Phase 2 state poll_loop.c documents ("NULL dispatch is the honest Phase 2
     * state") and the reason the other inline tests assert on the node's LOG
     * rather than on a client's socket.
     *
     * Same function, same command table, same numerics: PART B's node differs
     * from the shipped one only in which channels already exist and who owns
     * them. */
    s->dispatch = commands_dispatch;

    for (size_t i = 0; i < 1u + NCASES; i++) {
        const struct rekey_case *rc = (i == 0u) ? &g_sw : &g_cases[i - 1u];
        chan_t *ch = chan_new(rc->channel, s->name, s->epoch);

        TF_CHECK_MSG(ch != NULL, "the fixture could not create %s", rc->channel);
        TF_CHECK_MSG(server_chan_attach(s, ch) == 0,
                     "the fixture could not register %s", rc->channel);
        /* A topic set while the fixture still owns the channel, so the
         * single-writer test can prove the topic is UNCHANGED after a refused
         * TOPIC: it has a known-good value to be unchanged from. */
        TF_CHECK_MSG(chan_set_topic(ch, "kept topic", "founder") == 0,
                     "the fixture could not set a topic on %s", ch->name);
    }

    /* The two halves of the servers[] property, differing in exactly one thing.
     * Cached has one remote member-server recorded; Plainc has none. Both are
     * created here and both are owned by the fixture, so a client may join and
     * part them normally -- the ONLY difference between them is the entry below,
     * which is what makes the survival assertion non-vacuous. */
    {
        chan_t *cached = chan_new(CACHE_CH, s->name, s->epoch);
        chan_t *plainc = chan_new(PLAIN_CH, s->name, s->epoch);

        TF_CHECK_MSG(cached != NULL && plainc != NULL,
                     "the fixture could not create the cache pair");
        TF_CHECK_MSG(server_chan_attach(s, cached) == 0,
                     "the fixture could not register %s", CACHE_CH);
        TF_CHECK_MSG(server_chan_attach(s, plainc) == 0,
                     "the fixture could not register %s", PLAIN_CH);
        TF_CHECK_MSG(chan_set_topic(cached, "cached topic", "founder") == 0,
                     "the fixture could not set a topic on %s", CACHE_CH);
        TF_CHECK_MSG(chan_set_topic(plainc, "plain topic", "founder") == 0,
                     "the fixture could not set a topic on %s", PLAIN_CH);
        /* 2.2: "a refcounted servers[] set recording which servers hold at least
         * one member". Populating it here is the assertion that the field is
         * load-bearing rather than declared -- see the test below for the
         * observable consequence. */
        TF_CHECK_MSG(chan_server_add(cached, FAKE_PEER) == 0,
                     "the fixture could not record a remote member-server on "
                     "%s", CACHE_CH);
    }

    s->on_tick = fixture_tick;
}

/* Uppercase a channel name the way 2.2 stores it, into `out`. The wire carries
 * the stored form, so every PART/NAMES/LIST argument in the assertions below is
 * uppercased and this is where that comes from -- written out rather than
 * folded into the literals so a reader can see which half of the mismatch (if
 * any) a failure is about. */
static const char *upper(const char *in, char *out, size_t cap)
{
    size_t i;

    for (i = 0; in[i] != '\0' && i + 1u < cap; i++) {
        out[i] = (char)((in[i] >= 'a' && in[i] <= 'z')
                            ? (in[i] - ('a' - 'A'))
                            : in[i]);
    }
    out[i] = '\0';
    return out;
}

/* THE SINGLE-WRITER RULE, with the part that matters.
 *
 * 2.2: "A node never applies a channel state change it cannot route to the
 * channel's origin; it refuses the action (437). It does not queue and apply
 * later."
 *
 * The channel starts owned by the fixture, both clients join it as ordinary
 * members, and the fixture then offers it to "aaa.other" with a HIGHER epoch --
 * which wins, so the channel is re-keyed and the fixture is no longer its
 * origin. From that moment every origin-requiring action must be refused.
 *
 * The second half is the one that matters and it is the half a naive
 * implementation gets wrong: after each refusal the channel is read back, and
 * the topic, the member's +v flag, the membership and the member count must all
 * be EXACTLY what they were. A refusal that still mutated state is worse than no
 * rule at all, because the node would then hold a local copy that nothing can
 * reconcile with the origin's.
 *
 * Every assertion below is on the wire. The four "unchanged" readings are 322's
 * count and topic, 332/333's topic, and 353's prefixes and membership -- which
 * together cover the four pieces of state a state change could touch. */
static void test_single_writer_rule(nf_node_t *node)
{
    client_t op;
    client_t plain;
    client_t late;
    char ch[CHAN_MAX_NAME + 1];
    size_t window;

    upper("#tie", ch, sizeof ch);

    client_open(&op, node, "opa");
    client_open(&plain, node, "plb");
    client_send(&op, "JOIN #tie");
    (void)send_and_drain_fix(&op, "sw-1");
    client_send(&plain, "JOIN #tie");
    (void)send_and_drain_fix(&op, "sw-2");

    /* Both members are on, the topic is set while the fixture still owns the
     * channel, and the fixture has not been offered anything yet: #tie needs
     * two members before the re-key is attempted. */
    client_send(&op, "TOPIC #tie :kept topic");
    (void)send_and_drain_fix(&op, "sw-topic");
    expect_line_prefix(&op.c, "the topic is set while the node still owns the "
                       "channel", ":irc.fixture 332 opa #TIE :kept topic\r\n");
    TF_CHECK_MSG(nf_expect(node, "[fixture] rekey_offered: channel=#TIE ", T_IO_MS)
                     == 0,
                 "the fixture never offered #TIE to a rival server, so nothing "
                 "below was tested");
    /* chan_rekey() prints its own line on success, so its presence is the node's
     * own account of having taken the new origin rather than the fixture's. */
    TF_CHECK_MSG(nf_expect(node, "chan_rekey: channel=#TIE origin=aaa.other",
                           T_IO_MS) == 0,
                 "the channel was never re-keyed: the single-writer refusal "
                 "below would have been unreachable");

    /* ---- every origin-requiring state change is now refused ---- */

    /* Every window below starts BEFORE its command. The drain tag is in the
     * PONG and the node answers the command first, so a window anchored on the
     * tag would cover nothing at all and every "absent" check in this group
     * would be vacuous -- the exact failure this file is here to prevent. */
    client_open(&late, node, "plc");
    window = tc_received(&late.c);
    client_send(&late, "JOIN #tie");
    (void)send_and_drain_fix(&late, "sw-437-join");
    expect_line_prefix(&late.c, "437 for a JOIN on a channel this node does not "
                       "own", ":irc.fixture 437 plc #TIE");
    /* No 353 and no 366: a refused JOIN answers the refusal and nothing else,
     * so a client is never left waiting for a roster it was never given. */
    expect_absent_from(tc_buffer(&late.c), window, "the refused JOIN", " 353 ");
    expect_absent_from(tc_buffer(&late.c), window, "the refused JOIN", " 366 ");

    window = tc_received(&op.c);
    client_send(&op, "TOPIC #tie :hijacked");
    (void)send_and_drain_fix(&op, "sw-437-topic");
    expect_line_prefix(&op.c, "437 for a TOPIC on a channel this node does not "
                       "own", ":irc.fixture 437 opa #TIE");
    expect_absent_from(tc_buffer(&op.c), window, "the refused TOPIC", " 332 ");
    expect_absent_from(tc_buffer(&op.c), window, "the refused TOPIC", " TOPIC #");

    window = tc_received(&op.c);
    client_send(&op, "MODE #tie +v plb");
    (void)send_and_drain_fix(&op, "sw-437-mode");
    expect_line_prefix(&op.c, "437 for a MODE on a channel this node does not "
                       "own", ":irc.fixture 437 opa #TIE");
    expect_absent_from(tc_buffer(&op.c), window, "the refused MODE", " MODE ");

    window = tc_received(&op.c);
    client_send(&op, "KICK #tie plb");
    (void)send_and_drain_fix(&op, "sw-437-kick");
    expect_line_prefix(&op.c, "437 for a KICK on a channel this node does not "
                       "own", ":irc.fixture 437 opa #TIE");
    expect_absent_from(tc_buffer(&op.c), window, "the refused KICK", " KICK ");

    window = tc_received(&plain.c);
    client_send(&plain, "PART #tie");
    (void)send_and_drain_fix(&plain, "sw-437-part");
    expect_line_prefix(&plain.c, "437 for a PART on a channel this node does "
                        "not own", ":irc.fixture 437 plb #TIE");
    expect_absent_from(tc_buffer(&plain.c), window, "the refused PART", "PART #");

    /* 482, not 437, would be wrong here for a different reason: authority is
     * asked BEFORE privilege, so a node that answered 437 to everybody -- the
     * "a node that answered 482 to everybody would pass the test" failure mode,
     * in its other direction -- would be caught by the positive half below,
     * where a state change on a channel the node DOES own still succeeds. */

    /* ---- and the channel is UNCHANGED ---- */

    /* The count and the topic, in one line. Two members, and the topic the
     * fixture set rather than the one that was refused. */
    client_send(&op, "LIST #tie");
    (void)send_and_drain_fix(&op, "sw-list");
    expect_line_prefix(&op.c, "322: the refused actions left the member count "
                       "and the topic alone",
                       ":irc.fixture 322 opa #TIE 2 :kept topic\r\n");

    /* The topic, read back through the query rather than through LIST, so two
     * independent numerics agree that it did not change. */
    client_send(&op, "TOPIC #tie");
    (void)send_and_drain_fix(&op, "sw-reread");
    expect_line_prefix(&op.c, "332: the refused TOPIC left the topic alone",
                       ":irc.fixture 332 opa #TIE :kept topic\r\n");
    expect_line_prefix(&op.c, "333 still names the original setter",
                       ":irc.fixture 333 opa #TIE founder 1");

    /* The roster. plb holds no prefix, so a refused MODE +v leaves it rendered
     * bare: had the flag been applied it would read "+plb". Both members are
     * still there, which is what proves the refused PART and the refused KICK
     * removed nobody. This single line is the load-bearing assertion of the
     * whole test. */
    window = tc_received(&op.c);
    client_send(&op, "NAMES #tie");
    (void)send_and_drain_fix(&op, "sw-names");
    expect_line_prefix(&op.c, "353: the refused actions left membership and the "
                       "prefixes alone, plain group",
                       ":irc.fixture 353 opa = #TIE plb\r\n");
    expect_line_prefix(&op.c, "353: the refused actions left membership and the "
                       "prefixes alone, op group",
                       ":irc.fixture 353 opa = #TIE @opa\r\n");
    /* plb is rendered in the PLAIN group. A refused MODE +v that had been
     * applied anyway would have moved plb to the voiced group, and this is the
     * check that says it did not. Asserted over the window this NAMES answer
     * occupies, so it is a statement about the roster and not about the whole
     * session -- op's buffer legitimately contains " +v plb " from the MODE that
     * was refused. */
    {
        const size_t win = window;

        expect_absent_from(tc_buffer(&op.c), win,
                           "the roster after the refused MODE +v", " +");
        /* The positive form of "the refused PART and KICK removed nobody" is
         * the 353 line above, which still names plb. A " plb" absence check
         * would be its own negation. */
    }

    /* A QUERY against the orphan still answers, and says so in the log. 2.2's
     * fail-closed rule refuses origin-requiring ACTIONS; it does not make the
     * node pretend the channel does not exist, and a stale roster is transient
     * divergence that a later SJOIN corrects -- which is the self-healing
     * divergence 2.2 says the rule converts permanent divergence into. */
    TF_CHECK_MSG(nf_expect(node, "chan_query: channel=#TIE", T_IO_MS) == 0,
                 "a query against a locally orphaned channel was refused rather "
                 "than answered from the cache");

    tc_close(&late.c);
    tc_close(&plain.c);
    tc_close(&op.c);
}

/* THE CREATION RACE, all four outcomes of the tie-break, each observed on the
 * wire.
 *
 * The observable is deliberately a STATE CHANGE rather than the re-key's return
 * value: after the offer, the channel either belongs to another server -- and
 * every state change is refused with 437 -- or it does not, and the same state
 * change succeeds. So the assertion is "the node's behaviour on this channel is
 * 437" for a candidate that must win and "the node's behaviour is a successful
 * 332" for one that must lose, and the four cases together pin the whole
 * lexicographic rule in both directions.
 *
 * The fixture's own rekey_offered line is waited for in every case, so a
 * "losing" case can never pass because the offer never happened. */
static void test_creation_tiebreak(nf_node_t *node)
{
    static const char *const nicks[NCASES] = { "tc0", "tc1", "tc2", "tc3" };
    static const char *const tags[NCASES] = { "tb0", "tb1", "tb2", "tb3" };

    for (size_t i = 0; i < NCASES; i++) {
        const struct rekey_case *rc = &g_cases[i];
        client_t c;
        char offered[128];
        char rekeyed[128];
        char canon[CHAN_MAX_NAME + 1];

        (void)upper(rc->channel, canon, sizeof canon);

        client_open(&c, node, nicks[i]);
        {
            char line[64];

            (void)snprintf(line, sizeof line, "JOIN %s", rc->channel);
            client_send(&c, line);
        }
        (void)send_and_drain_fix(&c, "tb-joined");

        /* The node's own lines carry the CANONICAL name, because 2.2 stores it
         * uppercased and the fixture prints ch->name. Matching on the raw name
         * would wait fifteen seconds for a line that can never arrive. */
        (void)snprintf(offered, sizeof offered,
                       "[fixture] rekey_offered: channel=%s ", canon);
        (void)snprintf(rekeyed, sizeof rekeyed, "chan_rekey: channel=%s", canon);
        TF_CHECK_MSG(nf_expect(node, offered, T_IO_MS) == 0,
                     "the fixture never offered %s to %s (epoch %+d): the case "
                     "was not exercised", rc->channel, rc->name, rc->delta);

        /* The offer is always waited for. Only now is "the state change
         * succeeded" a statement about the tie-break rather than about the hook
         * not having run. */
        {
            char line[128];

            (void)snprintf(line, sizeof line, "TOPIC %s :after the race",
                           rc->channel);
            client_send(&c, line);
        }
        (void)send_and_drain_fix(&c, tags[i]);

        if (rc->expect != 0) {
            char want[128];

            (void)snprintf(want, sizeof want, ":irc.fixture 437 %s ", nicks[i]);
            expect_line_prefix(&c.c, "437 after a candidate that must WIN "
                               "(creation race)", want);
            TF_CHECK_MSG(nf_expect(node, rekeyed, T_IO_MS) == 0,
                         "%s: the winner did not re-key, so the 437 above is not "
                         "evidence that it won", rc->channel);
        } else {
            char want[128];

            (void)snprintf(want, sizeof want,
                           ":irc.fixture 332 %s ", nicks[i]);
            expect_line_prefix(&c.c, "332 after a candidate that must LOSE "
                               "(creation race)", want);
            /* The node must NOT have re-keyed. Without this the "432" case would
             * also pass against a node that re-keyed and then let the change
             * through anyway, which is the other half of the rule. */
            TF_CHECK_MSG(strstr(node->out, rekeyed) == NULL,
                         "%s: the losing candidate re-keyed anyway: origin=%s "
                         "epoch%+d was accepted over the incumbent",
                         rc->channel, rc->name, rc->delta);
        }
        tc_close(&c.c);
    }
}

/* servers[] IS A FIELD, NOT A DECLARATION.
 *
 * 2.2 exists partly for this: "Without servers[] the 3.1 row 'forward to peers
 * holding members' cannot be evaluated, and 353 cannot be answered for a
 * channel that is mostly remote." Its first observable consequence is
 * lifetime -- a channel this node has no local members of, but which a peer has
 * reported members for, has to SURVIVE, because 3.1 still has to route that
 * channel's messages to the owner.
 *
 * The assertion is a matched pair, and the pair is the whole point: two
 * channels created identically, joined and parted by the same client in the same
 * way, differing in nothing but whether servers[] holds an entry. The one with
 * the entry is still there afterwards; the one without is gone. A node that
 * ignored servers[] would fail the first, and a node that freed everything would
 * fail the second, so neither can pass this pair by accident. */
static void test_remote_server_cache(nf_node_t *node)
{
    client_t c;
    char cached[64];
    char plainc[64];
    char destroyed[128];

    upper(CACHE_CH, cached, sizeof cached);
    upper(PLAIN_CH, plainc, sizeof plainc);
    (void)snprintf(destroyed, sizeof destroyed, "chan_destroy: channel=%s",
                   plainc);

    client_open(&c, node, "cache1");

    /* The channel WITH a recorded member-server. Join and part it, leaving no
     * local members -- and the channel must remain, still enumerable by LIST. */
    client_send(&c, "JOIN #cached");
    (void)send_and_drain_fix(&c, "cc-1");
    client_send(&c, "PART #cached");
    (void)send_and_drain_fix(&c, "cc-2");
    client_send(&c, "LIST #cached");
    (void)send_and_drain_fix(&c, "cc-3");
    expect_line_prefix(&c.c, "a channel with a recorded remote member-server "
                       "survives its last local member",
                       ":irc.fixture 322 cache1 #CACHED 0 :cached topic\r\n");
    TF_CHECK_MSG(strstr(node->out, "chan_destroy: channel=#CACHED") == NULL,
                 "#CACHED was destroyed even though servers[] records a remote "
                 "member-server: the remote cache is not load-bearing");

    /* The control. Same client, same flow, no servers[] entry -- so there is
     * nothing left for the node to be authoritative about and the channel is
     * disposed. */
    client_send(&c, "JOIN #plainc");
    (void)send_and_drain_fix(&c, "pc-1");
    client_send(&c, "PART #plainc");
    (void)send_and_drain_fix(&c, "pc-2");
    client_send(&c, "LIST #plainc");
    (void)send_and_drain_fix(&c, "pc-3");
    expect_line_prefix(&c.c, "a channel with no members anywhere is disposed",
                       ":irc.fixture 403 cache1 #PLAINC");
    TF_CHECK_MSG(nf_expect(node, destroyed, T_IO_MS) == 0,
                 "the control channel was never destroyed, so the survival "
                 "assertion above proves nothing");

    /* And 353 answers for a channel with no LOCAL members at all, which is the
     * second thing 2.2 says servers[] exists for: one empty 353 plus the 366
     * terminator, rather than pretending the channel does not exist. The client
     * here is not a member, so NAMES -- not a lookup that needs membership --
     * is how the roster is asked for. */
    client_send(&c, "NAMES #cached");
    (void)send_and_drain_fix(&c, "cc-4");
    expect_line_prefix(&c.c, "353 for a channel with only remote members",
                       ":irc.fixture 353 cache1 = #CACHED :\r\n");
    expect_line_prefix(&c.c, "366 terminating it",
                       ":irc.fixture 366 cache1 #CACHED :End of /NAMES list\r\n");

    tc_close(&c.c);
}

int main(void)
{
    nf_node_t node;

    /* ------------------------------------------------------------------ */
    /* PART A -- the shipped binary.                                      */
    /* ------------------------------------------------------------------ */
    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the irc-serve "
                 "binary");
    TF_CHECK_MSG(nf_expect(&node, "loop_running:", T_READY_MS) == 0,
                 "the node never reported that its loop was armed");

    test_roster_and_order(&node);
    test_names_group_order(&node);
    test_topic(&node);
    test_kick_authority(&node);
    test_part(&node);
    test_names_and_list(&node);
    test_mode(&node);
    test_long_roster_chunks(&node);
    test_reaper_leaves_channel(&node);

    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    /* The whole-run invariant, read off the node's own counter at exit. The
     * shipped binary publishes loop_stats when it shuts down rather than on
     * every tick, so this is the only point at which the counter is readable --
     * and reading it once at the end is also the stronger claim, because it
     * covers every line every test above produced rather than one test's span. */
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0 over the whole run: some line was not "
                 "representable or was aimed somewhere it may not go");
    /* The counters are compared against the number of clients this test
     * actually opened rather than against a written-down constant, so this stays
     * true when a test above gains or loses a client. Both directions matter:
     * accepted != closed is a leaked descriptor, and accepted != opened is a
     * count nobody believes. */
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", (uint64_t)g_opened, T_IO_MS)
                     == 0,
                 "the node accepted %llu connections but this test opened %zu",
                 (unsigned long long)g_opened, g_opened);
    TF_CHECK_MSG(nf_expect_u64(&node, "closed=", (uint64_t)g_opened, T_IO_MS) == 0,
                 "closed does not match the %zu connections this test opened: a "
                 "connection was leaked", g_opened);
    nf_free(&node);

    /* ------------------------------------------------------------------ */
    /* PART B -- the inline fixture, for 2.2's two single-node-testable     */
    /* invariants.                                                        */
    /* ------------------------------------------------------------------ */
    g_opened = 0;
    TF_CHECK_MSG(nf_spawn_inline(&node, fixture_setup) == 0,
                 "could not spawn the inline channel fixture");
    TF_CHECK_MSG(nf_expect(&node, "[fixture] ready", T_READY_MS) == 0,
                 "the inline fixture never reported readiness");

    test_single_writer_rule(&node);
    test_creation_tiebreak(&node);
    test_remote_server_cache(&node);

    TF_CHECK_MSG(nf_stop(&node) == 0, "the inline fixture did not exit cleanly");
    /* Zero refusals, read off the node's own report. The counter itself is NOT
     * readable here: the shipped binary's loop_stats line carries
     * reply_refused= and the fixture's stats line does not, so
     * nf_expect_u64() would be waiting fifteen seconds for a key this node
     * never prints. The absence of the line is the equivalent statement rather
     * than a weaker one -- reply.c's refuse() increments the counter and prints
     * unconditionally, deliberately ungated on the trace flag, so "no such line
     * was printed" and "the counter is zero" are the same claim. */
    TF_CHECK_MSG(strstr(node.out, "reply_refused:") == NULL,
                 "the fixture refused an outbound line. Every 437 in PART B is "
                 "the single-writer rule answering a client, which is a "
                 "reply() SUCCESS, not a refusal -- a refusal here means some "
                 "line was unrenderable or was aimed at the wrong destination");
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", (uint64_t)g_opened, T_IO_MS)
                     == 0,
                 "the fixture accepted %llu connections but this test opened %zu",
                 (unsigned long long)g_opened, g_opened);
    TF_CHECK_MSG(nf_expect_u64(&node, "closed=", (uint64_t)g_opened, T_IO_MS) == 0,
                 "closed does not match the %zu connections this test opened: a "
                 "connection was leaked", g_opened);
    nf_free(&node);

    tf_done("channels");
    return 0;
}
