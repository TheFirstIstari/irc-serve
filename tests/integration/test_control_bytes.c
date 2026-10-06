/* test_control_bytes.c -- the log-injection set, and the three policies built on
 * it (#121).
 *
 * ---------------------------------------------------------------------------
 * WHAT IS BEING CLAIMED, AND WHY IT IS THREE CLAIMS IN ONE FILE
 * ---------------------------------------------------------------------------
 * `docs/SERVER_DESIGN.md` §9 already named this class -- "`0x07` rings the
 * recipient's bell and ESC `[` is a CSI sequence a terminal executes" -- and closed
 * it for exactly one field. `conn_realname_check()` refused every C0 control and
 * DEL, and it was applied to the realname. Two sibling free-text fields were not,
 * and the audit behind #121 confirmed it on the shipped binary: raw ESC and raw
 * BEL survived into this node's own output.
 *
 * The fix is ONE byte test (connection.h's `conn_byte_is_bad()`, behind
 * `conn_text_bad_count()` and `conn_text_strip()`) and THREE policies, because the
 * three fields have three different CONSUMERS. That is the whole content of the
 * issue's "one predicate applied at each field, with the policy for each decided
 * separately":
 *
 *   | FIELD                     | CONSUMER                      | POLICY  |
 *   |---------------------------|-------------------------------|---------|
 *   | USER's <servername>       | nobody -- the host is OBSERVED| summary |
 *   | AWAY's text               | other members' terminals     | strip   |
 *   | channel TOPIC             | other members' terminals     | strip   |
 *   | realname                  | every member of every channel| refuse  |
 *
 * A reader who wants to know whether this is one predicate with three answers, or
 * three predicates, needs only to read the one function and then this file's four
 * cases.
 *
 * ---------------------------------------------------------------------------
 * WHY EACH CASE IS CLAIMED DIFFERENTLY
 * ---------------------------------------------------------------------------
 * The three fields fail differently, so the cases assert different things:
 *
 *   1. SERVERNAME. The claim is an ABSENCE with a measurement attached. There is
 *      no wire line to assert -- the value was never on the wire and is no longer
 *      in the log -- so the case asserts (a) registration still completes, because
 *      refusing `USER` over a field nothing reads would strand a working client;
 *      (b) the node's output contains NO byte in the set, which is the security
 *      property and is asserted over the WHOLE buffer rather than over one line;
 *      and (c) the measurement is there and is correct, so the log still says
 *      something about the claim.
 *
 *   2-3. AWAY and TOPIC. The claim is about BYTES ON ANOTHER CLIENT'S SOCKET, so
 *      each case asserts the exact line a member receives, and each also asserts
 *      that the operator log records the strip -- silent mutation is its own
 *      defect, and a strip that is not announced is a strip nobody can debug.
 *
 *   4. THE POSITIVE CONTROL. Two cases send text with NO bad bytes in it -- spaces,
 *      punctuation, and UTF-8 whose bytes are all >= 0x80 -- and assert the
 *      recipient receives it byte for byte. Without these a strip that removed
 *      every byte >= 0x80, or every space, would pass cases 2 and 3 while silently
 *      destroying every non-ASCII user's topic, and a mangled multi-byte sequence
 *      is WORSE than the bug this closes because the user cannot see it happen.
 *
 * ---------------------------------------------------------------------------
 * NO FIXED sleep() ANYWHERE (6.3): every wait is tc_expect()'s or nf_expect()'s
 * deadline loop, and every window is closed by a PING whose PONG is the drain
 * token, numbered per call because tc_expect() searches the ACCUMULATED buffer.
 * ---------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/cap.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define SRV "irc.test"
#define OBSERVED_HOST "127.0.0.1"
#define CHAN "#T"

/* The bytes the set refuses. OCTAL and not \x: `"\x07bye"` is ONE hex escape --
 * the C grammar takes as many hex digits as it can, so `\x07b` is U+007B and the
 * next character of the sentence would silently become `{`. Every escape in this
 * file is three octal digits, which the grammar cannot extend.
 *
 * `ESC` is the first byte of every CSI sequence; `BEL` rings a terminal's bell.
 * Together they are the two bytes §9 names, and between them they cover both
 * halves of the hazard: something an operator SEES happen, and something that
 * makes noise on every channel member's terminal at once. */
#define ESC "\033"
#define BEL "\007"
/* A CSI sequence: erase-display, then a red foreground, then a sentence. The first
 * two sequences are the payload from the issue unchanged, because a fix that only
 * handles the bell is not a fix -- the escape is the sequence with the more
 * consequences.
 *
 * THE SENTENCE HAS A SPACE IN IT, and that is load-bearing for the assertions
 * rather than decorative. 3.2 colons a trailing parameter only when it has to, and
 * it has to when the value is empty, begins with ':', or holds a separator. A
 * payload with no space in it therefore renders UNCOLONNED -- `AWAY #T abc` -- which
 * is conformant (the last parameter is the trailing one whether or not it was
 * colonned) but means the byte-exact assertions below would be pinning the
 * formatter's whitespace rule rather than the strip. With a space, the line is the
 * conventional `:nick!user@host AWAY #chan :<text>` and every expected string here
 * is about the bytes that were removed. */
#define DEL "\177"
#define CSI ESC "[2J" ESC "[31mbrb back in 5" DEL
/* What CSI becomes once the two escapes are gone. This is a SEPARATE literal rather
 * than CSI with the ESCs deleted by the test, because a "stripped" expectation
 * assembled by the same arithmetic that builds the payload would agree with a wrong
 * implementation: writing both out is what makes the pair a claim. */
#define CSI_STRIPPED "[2J[31mbrb back in 5"

static unsigned g_drain_seq;

static void drain(test_client_t *c)
{
    char token[64];
    char line[128];

    (void)snprintf(token, sizeof token, "an%u", g_drain_seq++);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING failed");
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG for drain token %s, so the buffer is not yet drained and "
                 "every claim below would be about the read schedule", token);
}

/* Register `c` as `nick`. `servername` is `USER`'s third parameter, spelled out as
 * an argument rather than fixed to "*spoofed" because case 1 needs to put control
 * bytes in exactly that field. `caps` may be NULL for no CAP exchange. */
static void register_as(test_client_t *c, int port, const char *nick,
                        const char *servername, const char *caps)
{
    char line[512];

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
    (void)snprintf(line, sizeof line, "USER %s 0 %s :Real %s", nick, servername, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s USER send failed", nick);
    if (caps != NULL) {
        TF_CHECK_MSG(tc_send(c, "CAP END") == 0, "%s CAP END send failed", nick);
    }
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered", nick);
    drain(c);
}

static void join(test_client_t *c, const char *chan)
{
    char line[128];
    char want[64];

    (void)snprintf(line, sizeof line, "JOIN %s", chan);
    TF_CHECK_MSG(tc_send(c, line) == 0, "JOIN %s send failed", chan);
    (void)snprintf(want, sizeof want, " JOIN %s\r\n", chan);
    TF_CHECK_MSG(tc_expect(c, want, T_IO_MS) == 0,
                 "the JOIN %s echo never arrived, so the roster below is not the "
                 "one under test", chan);
    /* The numerics a JOIN produces (331/332/333/353/366/329) are drained here so a
     * window opened below holds only what its own claim put there. */
    drain(c);
}

/* ---------------------------------------------------------------------------
 * THE NEGATIVE HELPER, and why it scans rather than searching for two needles
 * ---------------------------------------------------------------------------
 * `tf_count(hay, ESC)` would answer "is there an escape" and `tf_count(hay, BEL)`
 * would answer "is there a bell", and a strip that removed ESC but passed BEL
 * through would pass the pair. The set has 30 members (0x00-0x1f plus 0x7f) and
 * this scans all of them, so the assertion is about the SET rather than about the
 * two bytes one person happened to think of.
 *
 * CR and LF are excluded because they are the wire's own line terminators and
 * every window legitimately contains them. `message_parse_n()` refuses them in a
 * parameter, so no client-supplied byte in a window can be either.
 *
 * WHY `mark` AND NOT THE WHOLE BUFFER: the buffer holds the 001 welcome burst,
 * 005's ISUPPORT and everything else the node said, and asserting an absence over
 * that would be asserting about text this file did not put there. `mark` is taken
 * after registration, so the window is exactly what the command under test caused.
 */
static void assert_no_controls(test_client_t *c, size_t mark, const char *what)
{
    const char *win = tc_buffer(c) + mark;
    size_t win_len = tc_received(c) - mark;
    size_t i;

    for (i = 0; i < win_len; i++) {
        const unsigned char ch = (unsigned char)win[i];

        if (ch == '\r' || ch == '\n') {
            continue;
        }
        TF_CHECK_MSG(ch > 0x1fu && ch != 0x7fu,
                     "%s: a byte from the log-injection set (0x%02x) reached the "
                     "client's socket. This node's output is the only place a "
                     "control byte can come from, and 0x07 rings a terminal's bell "
                     "while ESC followed by `[` is a CSI sequence any terminal "
                     "executes -- so this is one user rewriting another user's "
                     "screen, or ringing it.\n  window: %s", what, ch, win);
    }
}

/* The same scan over the child's own stdout, for the field whose only consumer was
 * the log. */
static void assert_no_controls_in_log(const nf_node_t *node, size_t mark,
                                      const char *what)
{
    size_t i;

    for (i = mark; i < node->out_len; i++) {
        const unsigned char ch = (unsigned char)node->out[i];

        if (ch == '\r' || ch == '\n') {
            continue;
        }
        TF_CHECK_MSG(ch > 0x1fu && ch != 0x7fu,
                     "%s: a byte from the log-injection set (0x%02x) reached the "
                     "node's own stdout, which is where an operator's terminal and "
                     "every other tool that reads this log is looking. ESC followed "
                     "by `[` is a CSI sequence, so a single pre-registration command "
                     "can rewrite an operator's screen.\n  log from the mark: %s",
                     what, ch, node->out + mark);
    }
}

/* ---------------------------------------------------------------------------
 * CASE 1 -- `USER`'s <servername>: MEASURED, NOT PRINTED
 * ---------------------------------------------------------------------------
 * The hazard this case exists for needs no credential, no channel and no second
 * client: one line on a socket, before registration completes, and an ESC and a
 * BEL in an operator's terminal. `host_source=observed` is on the same line --
 * the node uses the observed peer address and IGNORES this parameter, so printing
 * it bought no diagnostic and created the entire hazard.
 *
 * The claim, in the order it is asserted:
 *
 *   1. REGISTRATION STILL COMPLETES. A real client always sends a servername
 *      (usually an FQDN), so refusing `USER` with 417 over a field nothing reads
 *      would break working clients for a purely cosmetic hazard. `001` arriving is
 *      what proves the fix did not solve the hazard by breaking the command.
 *   2. NO BYTE IN THE SET REACHED THE LOG. Asserted over the whole buffer since a
 *      mark, which is the security property rather than a fact about one line.
 *   3. THE MEASUREMENT IS THERE AND CORRECT. `asserted_host_len` is the length the
 *      client sent, `asserted_host_wellformed` is 0 for a value carrying control
 *      bytes (this node's server-name grammar is alnum, '-' and '.'), and
 *      `asserted_host_bad_bytes` counts what was dropped. Three facts, no bytes.
 *
 * THE POSITIVE ARM IS HERE TOO, in the same case, because a `wellformed=0` that
 * this test produces and nothing else checks is a column that could be hardcoded.
 * The second registration sends `spoofed.example` and must report `wellformed=1`
 * with `bad_bytes=0` -- so the column is a verdict and not a constant.
 */
static void case_servername_is_summarised(void)
{
    nf_node_t node;
    test_client_t hostile;
    test_client_t clean;
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    /* 1. The hostile registration. `*` is not used here: `USER <user> <mode>
     * <servername> :<realname>`, and this is the field under test. */
    tc_init(&hostile);
    register_as(&hostile, node.port, "vic", ESC "[2J" BEL, NULL);

    /* 2 and 3, over everything the node said from the moment this client arrived. */
    TF_CHECK_MSG(nf_expect(&node, "asserted_host_len=5 asserted_host_wellformed=0 "
                           "asserted_host_bad_bytes=2", T_IO_MS) == 0,
                 "the node did not report the measurement #121 replaced the raw "
                 "value with. `USER`'s third parameter was 5 bytes carrying an ESC "
                 "and a BEL, so the measurement must say 5, not-well-formed, and 2 "
                 "bad bytes.\n  node said: %s", node.out);
    /* The dedicated line, which is what makes the drop visible as an EVENT rather
     * than as a column somebody has to notice has gone unusual. */
    TF_CHECK_MSG(nf_expect(&node, "asserted_host: fd=", T_IO_MS) == 0,
                 "the node dropped the bad bytes without saying so.\n  node said: %s",
                 node.out);

    mark = 0;
    assert_no_controls_in_log(&node, mark, "USER's <servername>");

    /* The positive arm: a well-formed servername reports wellformed=1, so the
     * column above is a verdict and not a constant. */
    tc_init(&clean);
    register_as(&clean, node.port, "clean", "spoofed.example", NULL);
    TF_CHECK_MSG(nf_expect(&node, "asserted_host_len=15 asserted_host_wellformed=1 "
                           "asserted_host_bad_bytes=0", T_IO_MS) == 0,
                 "a well-formed <servername> was not reported as well-formed. "
                 "`spoofed.example` is alnum, '-' and '.', which is exactly the "
                 "grammar irc_serve_server_name_valid() applies to this node's own "
                 "server name, so wellformed must be 1 -- a column that reports 0 "
                 "for a name this node would itself have accepted is not measuring "
                 "anything.\n  node said: %s", node.out);

    /* The hostile connection is still fully usable after a value this node dropped:
     * nothing about it was refused, because nothing about it was consumed. */
    TF_CHECK_MSG(tc_send(&hostile, "WHOIS clean") == 0, "hostile WHOIS send failed");
    TF_CHECK_MSG(tc_expect(&hostile, " 311 ", T_IO_MS) == 0,
                 "the connection that sent a control-bearing <servername> stopped "
                 "working. The policy for this field is \"print less\", not \"refuse "
                 "-- a real client always sends a servername, so a refusal here "
                 "would strand a half-registered client over a value the node never "
                 "reads.");

    tc_close(&hostile);
    tc_close(&clean);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * CASE 2 -- AWAY: STRIPPED FOR THE RECIPIENT, ANNOUNCED IN THE LOG
 * ---------------------------------------------------------------------------
 * Two members on one channel, both having negotiated `away-notify`, because the
 * hazard is one member's bytes reaching ANOTHER member's terminal. The setter
 * sends the payload from the issue verbatim.
 *
 * Four claims:
 *
 *   1. THE SENDER STILL GETS 306. A hard refusal would also keep the ESC off every
 *      other terminal, so this assertion is what distinguishes "stripped" from
 *      "refused" -- and refused is the answer this case exists to rule out, because
 *      an away message is a sentence a real client sends.
 *   2. THE MEMBER RECEIVES THE EXACT STRIPPED LINE. Not "does not contain ESC": the
 *      expected line is written out byte for byte, so a strip that dropped the
 *      WRONG bytes fails this. `[2J[31mbrb` is what `ESC [2J ESC [31mbrb` becomes
 *      when only the escapes go.
 *   3. NO BYTE IN THE SET IS ANYWHERE IN THE MEMBER'S WINDOW. The security property,
 *      scanned over the whole window rather than searched for two needles.
 *   4. THE LOG RECORDS THE STRIP, with the count. Silent mutation is its own
 *      defect: a member and the setter would otherwise disagree about what was
 *      said with no record of why.
 *
 * The 306 above is on the SENDER's socket and the announcement is on the MEMBER's,
 * so the two claims cannot be satisfied by one line.
 */
static void case_away_stripped_for_member(void)
{
    nf_node_t node;
    test_client_t setter;
    test_client_t member;
    char want[128];
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");
    tc_init(&setter);
    register_as(&setter, node.port, "vic", "*spoofed", CAP_AWAY_NOTIFY);
    tc_init(&member);
    register_as(&member, node.port, "bob", "*spoofed", CAP_AWAY_NOTIFY);
    join(&setter, CHAN);
    join(&member, CHAN);

    mark = tc_received(&member);
    TF_CHECK_MSG(tc_send(&setter, "AWAY :" CSI) == 0, "AWAY send failed");

    /* 1. The set edge, on the setter's own socket. */
    TF_CHECK_MSG(tc_expect(&setter, " 306 ", T_IO_MS) == 0,
                 "the setter was refused instead of stripped. An away message is "
                 "free text real clients send, so the answer for a control byte in "
                 "one is to remove the byte and keep the command -- a 417 here would "
                 "break a working feature and the user would see \"message too "
                 "long\" for a short sentence.");

    /* 2. The exact line the member receives, at the start of a line rather than as
     * the tail of a longer one. */
    (void)snprintf(want, sizeof want,
                   ":vic!vic@" OBSERVED_HOST " AWAY " CHAN " :" CSI_STRIPPED "\r\n");
    TF_CHECK_MSG(tc_expect(&member, want, T_IO_MS) == 0,
                 "the member did not receive the exact stripped line \"%s\". The "
                 "expected line is written out in full rather than searched for as a "
                 "substring, so a strip that removed the wrong bytes fails here "
                 "instead of passing.\n  member saw: %s",
                 want, tc_buffer(&member) + mark);

    /* 3. The whole window. */
    assert_no_controls(&member, mark, "the away-notify announcement");

    /* 4. The log, with the count, so the mutation is a record and not a surprise. */
    {
        char log_want[160];

        /* The counts come from strlen() of the two literals above rather than from
         * numbers typed in, because a hand-arithmetic byte count that is wrong by
         * one turns a real assertion into a permanently red test -- which is the
         * same failure as an assertion that cannot fail. `removed=3` IS written
         * out: it is the number of bytes in the payload that the set contains --
         * two ESCs and a DEL -- and it is what says the count is a measurement
         * rather than a constant. */
        (void)snprintf(log_want, sizeof log_want,
                       "away_stripped: nick=vic removed=3 in_len=%zu kept_len=%zu "
                       "reason=CONTROL_BYTES", strlen(CSI), strlen(CSI_STRIPPED));
        TF_CHECK_MSG(nf_expect(&node, log_want, T_IO_MS) == 0,
                     "the operator log did not record the strip, or recorded the "
                     "wrong counts; expected \"%s\". The payload carries two ESCs and "
                     "a DEL, so it must be announced as 3 removed, %zu in, %zu kept -- "
                     "silent "
                     "mutation is its own defect, and without this line a member and "
                     "the setter simply disagree about what was said with no record "
                     "of why.\n  node said: %s", log_want, strlen(CSI),
                     strlen(CSI_STRIPPED), node.out);
    }

    /* And the announcement reached EXACTLY ONE member, so the strip is not the
     * reason a second copy could appear -- the count is here to catch a fault that
     * delivers twice, which a substring assertion would pass. */
    drain(&member);
    TF_CHECK_MSG(tf_count(tc_buffer(&member) + mark, " AWAY " CHAN " ") == 1u,
                 "the away announcement did not reach the member exactly once.\n"
                 "  member saw: %s", tc_buffer(&member) + mark);

    /* ------------------------------------------------------------------------
     * A MESSAGE THAT WAS NOTHING BUT A REFUSED BYTE IS NOT AN AWAY MESSAGE
     * ------------------------------------------------------------------------
     * This is the one place where the strip changed what the command MEANS rather
     * than what it said, so it is asserted separately rather than folded into the
     * case above.
     *
     * `AWAY :<DEL>` is non-empty on the wire, so it passes the empty-parameter test
     * at the top of handle_away(), and it strips to nothing. Storing that would mark
     * the user away with an empty message -- and an empty trailing parameter IS the
     * parameterless `AWAY` line, which means "no longer away". So the user would be
     * away and every member who negotiated `away-notify` would be told they were
     * not. That is the mirror of the defect test_away_notify.c spends a case on.
     *
     * Three claims, and the third is the one that distinguishes the fix from a
     * numeric that merely keeps the byte off the wire:
     *
     *   1. The setter gets `305`, NOT `306`. `306` plus an empty message is the lie;
     *      `417` would tell a client its three-byte message was 258 characters.
     *   2. The member gets the PARAMETERLESS line, which is what actually happened.
     *      Asserted as an exact line, so the assertion fails both if nothing is sent
     *      and if a trailing `:` appears.
     *   3. The log says `kept_len=0 reason=ALL_BYTES_REFUSED state=NOT_SET`, so the
     *      `305` is distinguishable from a client that genuinely came back.
     */
    mark = tc_received(&member);
    (void)tc_send(&setter, "AWAY :away");   /* away first, so the clear edge has work */
    TF_CHECK_MSG(tc_expect(&setter, " 306 ", T_IO_MS) == 0, "could not set an away state");
    drain(&member);
    mark = tc_received(&member);
    TF_CHECK_MSG(tc_send(&setter, "AWAY :" DEL) == 0, "AWAY :<DEL> send failed");
    TF_CHECK_MSG(tc_expect(&setter, " 305 ", T_IO_MS) == 0,
                 "an away message made only of a refused byte was answered 306, which "
                 "asserts the user is away while the notification the same command "
                 "produces asserts they are not. A message this node cannot carry is "
                 "not an away message.");
    (void)snprintf(want, sizeof want,
                   ":vic!vic@" OBSERVED_HOST " AWAY " CHAN "\r\n");
    TF_CHECK_MSG(tc_expect(&member, want, T_IO_MS) == 0,
                 "the member was not told the user is back. Expected the "
                 "PARAMETERLESS line \"%s\" -- written out exactly, so it fails both "
                 "when nothing arrives and when a trailing colon does.\n  member saw: %s",
                 want, tc_buffer(&member) + mark);
    TF_CHECK_MSG(nf_expect(&node, "away_stripped: nick=vic removed=1 in_len=1 "
                           "kept_len=0 reason=ALL_BYTES_REFUSED state=NOT_SET",
                           T_IO_MS) == 0,
                 "the log did not record the all-refused away message distinctly. "
                 "Without `reason=ALL_BYTES_REFUSED state=NOT_SET` the 305 above is "
                 "indistinguishable in the log from a client that genuinely came "
                 "back.\n  node said: %s", node.out);
    assert_no_controls(&member, mark, "the clear-edge notification");

    tc_close(&setter);
    tc_close(&member);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * CASE 3 -- TOPIC: STRIPPED FOR THE MEMBERS, AND NOT STORED STRIPPED-ONLY
 * ---------------------------------------------------------------------------
 * The same policy as AWAY and the same consumer -- other members' terminals -- and
 * a WORSE exposure, which is the reason the strip is at `chan_set_topic()` rather
 * than in the handler: a topic is stored. One hostile write puts an ESC in
 * `chan_t::topic`, and from there `send_topic()` hands it to every member on 332
 * and 333, INCLUDING every member who joins afterwards, for as long as the channel
 * lives. One command, one stored byte, and an injection that replays itself.
 *
 * FOUR claims, and the third is the one that distinguishes this from a fix in the
 * handler alone:
 *
 *   1. THE SETTER SEES THE STRIPPED TOPIC BACK on 332, which is how it learns the
 *      canonical form the node stored.
 *   2. THE MEMBER SEES THE EXACT STRIPPED `TOPIC` line, and no byte in the set
 *      reaches its window.
 *   3. A CLIENT THAT JOINS LATER GETS A CLEAN 332. This is the claim that a strip
 *      in `handle_topic()` alone cannot satisfy: such a strip would clean the
 *      stored copy (if it stripped before storing) or the broadcast (if after) and
 *      leave the other one raw, and the joiner is the member who would find it.
 *   4. THE LOG RECORDS THE STRIP, with both lengths.
 *
 * Case 3 needs the topic SETTER to be a channel member, which is every member of a
 * locally-owned channel on a single node -- `authority_ok()` grants TOPIC to any
 * member, so no +o is needed and the case does not depend on operator setup.
 */
static void case_topic_stripped_for_members(void)
{
    nf_node_t node;
    test_client_t setter;
    test_client_t member;
    test_client_t joiner;      /* joins AFTER, and is the claim that bites */
    char want[160];
    size_t mark_setter;
    size_t mark_member;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");
    tc_init(&setter);
    register_as(&setter, node.port, "vic", "*spoofed", NULL);
    tc_init(&member);
    register_as(&member, node.port, "bob", "*spoofed", NULL);
    join(&setter, CHAN);
    join(&member, CHAN);

    mark_setter = tc_received(&setter);
    mark_member = tc_received(&member);
    TF_CHECK_MSG(tc_send(&setter, "TOPIC " CHAN " :" CSI) == 0, "TOPIC send failed");

    /* 1. The setter is told what was stored. */
    (void)snprintf(want, sizeof want, ":%s 332 vic " CHAN " :" CSI_STRIPPED "\r\n",
                   SRV);
    TF_CHECK_MSG(tc_expect(&setter, want, T_IO_MS) == 0,
                 "the setter was not told the stripped topic \"%s\". It is sent "
                 "332/333 back precisely so it learns the canonical form the node "
                 "stored, so a strip that did not reach the stored value is visible "
                 "here.\n  setter saw: %s", want, tc_buffer(&setter) + mark_setter);

    /* 2. The member sees the exact stripped line, and no control byte anywhere. */
    (void)snprintf(want, sizeof want,
                   ":vic!vic@" OBSERVED_HOST " TOPIC " CHAN " :" CSI_STRIPPED "\r\n");
    TF_CHECK_MSG(tc_expect(&member, want, T_IO_MS) == 0,
                 "the member did not receive the exact stripped TOPIC line \"%s\". "
                 "Written out in full rather than searched for, so a strip that "
                 "removed the wrong bytes fails here.\n  member saw: %s",
                 want, tc_buffer(&member) + mark_member);
    assert_no_controls(&member, mark_member, "the TOPIC broadcast");

    /* 3. THE JOINER. This is the claim a handler-local strip fails: the stored copy
     * is what 332 renders, so if the broadcast were cleaned and the store were not,
     * the member would be clean and every later joiner would not be. */
    {
        size_t mark_joiner;

        tc_init(&joiner);
        register_as(&joiner, node.port, "zaphod", "*spoofed", NULL);
        mark_joiner = tc_received(&joiner);
        join(&joiner, CHAN);
        (void)snprintf(want, sizeof want,
                       ":%s 332 zaphod " CHAN " :" CSI_STRIPPED "\r\n", SRV);
        TF_CHECK_MSG(tc_expect(&joiner, want, T_IO_MS) == 0,
                     "a client that joined AFTER the topic was set did not receive "
                     "the stripped topic \"%s\" on 332. The stored value is what a "
                     "later joiner is shown, so a strip applied only to the "
                     "broadcast would leave every future member of this channel with "
                     "the raw bytes on their screen.\n  joiner saw: %s", want,
                     tc_buffer(&joiner) + mark_joiner);
        assert_no_controls(&joiner, mark_joiner, "332 for a later joiner");
        tc_close(&joiner);
    }

    /* 4. The log, with both lengths, so the mutation is a record. */
    {
        char log_want[160];

        (void)snprintf(log_want, sizeof log_want,
                       "chan_topic_stripped: channel=" CHAN
                       " nick=vic in_len=%zu kept_len=%zu reason=CONTROL_BYTES",
                       strlen(CSI), strlen(CSI_STRIPPED));
        TF_CHECK_MSG(nf_expect(&node, log_want, T_IO_MS) == 0,
                     "the operator log did not record the topic strip; expected "
                     "\"%s\". Without it a member and the setter disagree about what "
                     "the topic says with no record of why, and the stored length on "
                     "the `chan_topic:` line cannot be compared with what the client "
                     "sent.\n  node said: %s", log_want, node.out);
    }

    tc_close(&setter);
    tc_close(&member);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * CASES 4 AND 5 -- WHAT THE STRIP MUST NOT EAT
 * ---------------------------------------------------------------------------
 * A strip that removes the wrong bytes is a silent corruption, and silent
 * corruption is a worse failure than the injection: a mangled topic is
 * indistinguishable from a topic somebody wrote badly, so the user cannot report
 * it. These two cases are therefore the ones that constrain the SET rather than the
 * policies, and they are what a fault that widened the byte test to `>= 0x80`, or
 * that added space, would fail.
 *
 * WHAT SURVIVES, and why each is a different constraint:
 *
 *   - SPACE (0x20). The commonest byte in every field this touches. A set that
 *     included it would turn "back in 5" into "backin5" on every channel.
 *   - BYTES >= 0x80. Every continuation byte of every UTF-8 multi-byte sequence is
 *     >= 0x80, so a set that reached them would destroy non-ASCII text while
 *     leaving the ASCII part intact -- the exact failure mode above.
 *   - A MULTI-BYTE SEQUENCE SPLIT ACROSS READS. The strip runs on an assembled
 *     NUL-terminated parameter, so it cannot see a read boundary at all; what these
 *     cases assert is that the ARRANGEMENT does not matter. `split_utf8_away()`
 *     deliberately cuts the wire in the middle of a character.
 *
 * ON THE SPLIT, stated honestly rather than overclaimed: a test cannot make the
 * kernel deliver two reads. `split_utf8_away()` sends the two halves as separate
 * writes back to back, and the node MAY read them in one recv(). So this does not
 * prove the reassembly works under every read schedule -- it proves the assertion
 * holds either way, and it does prove the thing that actually matters here, which
 * is that the result is the intact sequence and not a filtered one. A strip
 * implemented as "drop bytes >= 0x80" fails this case regardless of how the reads
 * were scheduled.
 */
#define UTF8_TEXT "caf" "\303\251" " na" "\303\257ve " "\346\227\245\346\234\254"

/* The three RELAYED fields' payloads, as a raw/stripped PAIR each rather than as a
 * raw string plus an arithmetic strip. The stripped form is its own literal, which
 * is the point: an expectation computed from the same expression that builds the
 * payload agrees with a wrong implementation, and a hand-arithmetic byte count that
 * is off by one turns a real assertion into a permanently red test. Every length in
 * the three cases below is strlen() of one of these six literals. */
#define KICK_RAW   ESC "[2J" ESC "[31mout you go " UTF8_TEXT
#define KICK_CLEAN "[2J[31mout you go " UTF8_TEXT
#define PART_RAW   ESC "adi" UTF8_TEXT
#define PART_CLEAN "adi" UTF8_TEXT
#define MASK_RAW   ESC "*!*@127.0.0.1"
#define MASK_CLEAN "*!*@127.0.0.1"

/* Build the whole line `AWAY :<esc><utf8>` into `out` and return the offset of the
 * byte to cut at, which is the MIDDLE of the first two-byte character of the UTF-8
 * text: "AWAY :" and the escape are complete, "caf" is complete, and the split falls
 * between the lead byte 0xC3 and its continuation 0xA9.
 *
 * The text is copied through a `char` array rather than indexed off the literal
 * directly, because `"literal" + 4u` is not pointer arithmetic to a compiler that
 * thinks in strings -- -Wstring-plus-int objects to it, and rightly: this returns an
 * offset into a buffer, not a pointer into a string constant. */
static size_t build_split_away(char *out, size_t cap, const char *esc,
                               size_t *total_out)
{
    /* A named array rather than the literal: `UTF8_TEXT + 4` is arithmetic on a
     * string constant, and a compiler that models string constants as objects
     * rejects it (-Wstring-plus-int). Copying it once is also what makes the two
     * memcpy() calls below obviously the same bytes. */
    char text[64];
    size_t text_len;
    size_t esc_len = strlen(esc);
    size_t n;

    (void)snprintf(text, sizeof text, "%s", UTF8_TEXT);
    text_len = strlen(text);
    if (cap < strlen("AWAY :") + esc_len + text_len + 3u) {
        TF_CHECK_MSG(0, "the buffer handed to build_split_away() is too small for "
                     "the line plus its CRLF");
    }
    (void)snprintf(out, cap, "AWAY :%s", esc);
    n = strlen(out);
    (void)memcpy(out + n, text, 4u);
    n += 4u;
    if (total_out != NULL) {
        *total_out = n + (text_len - 4u) + 2u; /* the rest of the text, then CRLF */
    }
    (void)memcpy(out + n, text + 4, text_len - 4u);
    n += text_len - 4u;
    out[n] = '\r';
    n++;
    out[n] = '\n';
    n++;
    out[n] = '\0';
    /* The cut: everything before it is a whole number of characters. */
    return strlen("AWAY :") + esc_len + 4u;
}

/* AWAY: the text a member receives when the strip kept everything it should. */
static void case_away_strip_keeps_good_bytes(void)
{
    nf_node_t node;
    test_client_t setter;
    test_client_t member;
    char line[512];
    char want[512];
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");
    tc_init(&setter);
    register_as(&setter, node.port, "vic", "*spoofed", CAP_AWAY_NOTIFY);
    tc_init(&member);
    register_as(&member, node.port, "bob", "*spoofed", CAP_AWAY_NOTIFY);
    join(&setter, CHAN);
    join(&member, CHAN);

    /* 4a. Spaces and UTF-8, in one line, with a control byte in front of them so
     * the strip is exercised on the same input that has bytes to keep. */
    (void)snprintf(line, sizeof line, "AWAY :" ESC UTF8_TEXT);
    mark = tc_received(&member);
    TF_CHECK_MSG(tc_send(&setter, line) == 0, "AWAY send failed");
    TF_CHECK_MSG(tc_expect(&setter, " 306 ", T_IO_MS) == 0,
                 "the AWAY with spaces and UTF-8 was refused");
    (void)snprintf(want, sizeof want,
                   ":vic!vic@" OBSERVED_HOST " AWAY " CHAN " :" UTF8_TEXT "\r\n");
    TF_CHECK_MSG(tc_expect(&member, want, T_IO_MS) == 0,
                 "the member did not receive \"%s\" byte for byte. Every byte of it "
                 "is either a space, printable ASCII, or part of a UTF-8 sequence "
                 "whose bytes are all >= 0x80, and none of those is in the "
                 "log-injection set -- a strip that removed any of them would "
                 "corrupt every non-ASCII user's away message SILENTLY, which is a "
                 "worse failure than the injection it prevents.\n  member saw: %s",
                 want, tc_buffer(&member) + mark);
    assert_no_controls(&member, mark, "an away message with spaces and UTF-8");

    /* And nothing was announced as stripped beyond the one ESC: 4b below counts
     * lines, and the log's kept_len is the arithmetic. */
    TF_CHECK_MSG(nf_expect(&node, "away_stripped: nick=vic removed=1", T_IO_MS) == 0,
                 "the log did not report removing exactly the one ESC.\n  node "
                 "said: %s", node.out);

    /* 4b. THE SPLIT CHARACTER. Same text, cut in the middle of a two-byte
     * character and sent in two writes. */
    {
        char buf[512];
        size_t total = 0;
        size_t cut = build_split_away(buf, sizeof buf, ESC, &total);

        mark = tc_received(&member);
        TF_CHECK_MSG(tc_send_raw(&setter, buf, cut) == 0, "first half send failed");
        TF_CHECK_MSG(tc_send_raw(&setter, buf + cut, total - cut) == 0,
                     "second half send failed");
        (void)snprintf(want, sizeof want,
                       ":vic!vic@" OBSERVED_HOST " AWAY " CHAN " :" UTF8_TEXT "\r\n");
        TF_CHECK_MSG(tc_expect(&member, want, T_IO_MS) == 0,
                     "the member did not receive the full text when the wire was "
                     "cut in the MIDDLE of a two-byte UTF-8 character (\"%s\" was "
                     "split after its lead byte). The strip runs on an assembled "
                     "parameter and cannot see a read boundary, so this cannot "
                     "depend on how the reads were scheduled -- and a strip that "
                     "removed bytes >= 0x80 fails here no matter what the schedule "
                     "was.\n  member saw: %s", UTF8_TEXT, tc_buffer(&member) + mark);
        assert_no_controls(&member, mark, "an away message split mid-character");
    }

    tc_close(&setter);
    tc_close(&member);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* TOPIC: the same constraint, on the field whose exposure is larger. */
static void case_topic_strip_keeps_good_bytes(void)
{
    nf_node_t node;
    test_client_t setter;
    test_client_t member;
    char want[512];
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");
    tc_init(&setter);
    register_as(&setter, node.port, "vic", "*spoofed", NULL);
    tc_init(&member);
    register_as(&member, node.port, "bob", "*spoofed", NULL);
    join(&setter, CHAN);
    join(&member, CHAN);

    mark = tc_received(&member);
    TF_CHECK_MSG(tc_send(&setter, "TOPIC " CHAN " :" ESC UTF8_TEXT) == 0,
                 "TOPIC send failed");
    (void)snprintf(want, sizeof want,
                   ":vic!vic@" OBSERVED_HOST " TOPIC " CHAN " :" UTF8_TEXT "\r\n");
    TF_CHECK_MSG(tc_expect(&member, want, T_IO_MS) == 0,
                 "the member did not receive the topic \"%s\" byte for byte with "
                 "only its leading ESC removed. A topic is stored and replayed to "
                 "every future joiner, so a strip that ate a space or a UTF-8 "
                 "continuation byte would corrupt it for the channel's whole life "
                 "rather than for one message.\n  member saw: %s", want,
                 tc_buffer(&member) + mark);
    assert_no_controls(&member, mark, "a topic with spaces and UTF-8");

    /* A LATER JOINER gets the same bytes, because the stored value is the one that
     * matters and this is the only path that reads it back. */
    {
        test_client_t joiner;
        size_t mark_joiner;

        tc_init(&joiner);
        register_as(&joiner, node.port, "zaphod", "*spoofed", NULL);
        mark_joiner = tc_received(&joiner);
        join(&joiner, CHAN);
        (void)snprintf(want, sizeof want,
                       ":%s 332 zaphod " CHAN " :" UTF8_TEXT "\r\n", SRV);
        TF_CHECK_MSG(tc_expect(&joiner, want, T_IO_MS) == 0,
                     "a later joiner did not receive the stored topic byte for "
                     "byte.\n  joiner saw: %s", tc_buffer(&joiner) + mark_joiner);
        tc_close(&joiner);
    }

    /* An ordinary topic changes nothing about the log: the strip line fires only
     * when a strip happened, so a needle for it means something. */
    TF_CHECK_MSG(tc_send(&setter, "TOPIC " CHAN " :plain ascii topic") == 0,
                 "plain TOPIC send failed");
    TF_CHECK_MSG(tc_expect(&setter, " 332 ", T_IO_MS) == 0,
                 "a plain ASCII topic was not accepted");
    {
        char log_want[160];

        (void)snprintf(log_want, sizeof log_want,
                       "chan_topic_stripped: channel=" CHAN
                       " nick=vic in_len=%zu kept_len=%zu",
                       strlen(ESC UTF8_TEXT), strlen(UTF8_TEXT));
        TF_CHECK_MSG(nf_expect(&node, log_want, T_IO_MS) == 0,
                     "the log did not report the UTF-8 topic's strip as %zu in / %zu "
                     "kept. Both lengths have to be right: a `kept_len` equal to the "
                     "input would mean the strip removed nothing, and a `kept_len` "
                     "shorter than the text would mean it removed something it should "
                     "have kept -- which is the failure these two cases exist to "
                     "catch.\n  node said: %s", strlen(ESC UTF8_TEXT),
                     strlen(UTF8_TEXT), node.out);
    }

    tc_close(&setter);
    tc_close(&member);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * CASE 7 -- THE RELAYED PARAMETERS: KICK REASON, PART REASON, BAN MASK
 * ---------------------------------------------------------------------------
 * The three remaining places a `m->params[]` value reached another client's socket
 * verbatim, and all three were found by asking the question the first pass should
 * have asked at the start: "where else does a client parameter go out on the wire
 * instead of the field the node stored?"
 *
 *   - `handle_kick()` put the client's own `<reason>` into the KICK it broadcasts
 *     to every member. Length-bounded by CHAN_MAX_KICK_REASON and not byte-bounded.
 *   - `chan_member_leave()` put a PART's `<reason>` on the wire to every member, and
 *     `handle_part()`'s forward arm put the same string on the link. RFC 2812 3.3.2
 *     gives a PART reason no limit and this node imposes none.
 *   - `handle_mode()` put a ban MASK into the MODE echo, and `chan_ban_add()`
 *     validated the mask's length and not its bytes -- so the mask that was STORED
 *     and the mask that was ANNOUNCED were both the client's bytes.
 *
 * All three are the same class as the away message and the topic: legitimate client
 * content, relayed to other people, so STRIPPED and ANNOUNCED. The ban mask is the
 * one with a second copy, and it is why the case asserts the stored and the
 * broadcast agree rather than only that the broadcast is clean: a strip applied to
 * one of the two would leave the other raw, which is exactly the defect the topic's
 * owned arm had.
 *
 * WHAT MUST SURVIVE, and it is asserted for each field rather than once: the space,
 * the punctuation and the UTF-8. A KICK reason is a sentence a person wrote and a
 * PART reason is usually a farewell, so "do not come back <ESC>" and "adiós" both
 * have to arrive intact. `assert_no_controls()` is the security half;
 * `expect_line_since()` on the EXACT line is the other half, and a strip that ate a
 * space fails it while passing every control-byte assertion in this file.
 */
static void case_relayed_parameters_are_stripped(void)
{
    nf_node_t node;
    test_client_t op;          /* does all three writes */
    test_client_t witness;     /* stays; sees all three */
    test_client_t target;      /* kicked; sees the KICK */
    test_client_t victim;      /* proves the stored ban mask by being refused */
    char want[256];
    char reason[128];
    size_t mark_w;
    size_t mark_t;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");
    tc_init(&op);
    register_as(&op, node.port, "vic", "*spoofed", NULL);
    tc_init(&witness);
    register_as(&witness, node.port, "bob", "*spoofed", NULL);
    tc_init(&target);
    register_as(&target, node.port, "zaphod", "*spoofed", NULL);
    tc_init(&victim);
    register_as(&victim, node.port, "mallory", "*spoofed", NULL);
    join(&op, CHAN);
    join(&witness, CHAN);
    join(&target, CHAN);
    join(&victim, CHAN);

    /* vic needs +o for both KICK and MODE +b. It creates the channel on its JOIN, so
     * it is the creator and holds +o already; asserting that is what stops the three
     * cases below being 482s about privilege. */
    TF_CHECK_MSG(tc_send(&op, "MODE " CHAN " +o bob") == 0, "the +o send failed");
    drain(&op);
    drain(&witness);
    drain(&target);

    /* --- 1. THE BAN MASK, WHOSE STORED AND ANNOUNCED COPIES MUST AGREE --- */
    mark_w = tc_received(&witness);
    TF_CHECK_MSG(tc_send(&op, "MODE " CHAN " +b " MASK_RAW) == 0,
                 "the ban mask send failed");
    (void)snprintf(want, sizeof want,
                   ":vic!vic@" OBSERVED_HOST " MODE " CHAN " +b " MASK_CLEAN "\r\n");
    TF_CHECK_MSG(tc_expect(&witness, want, T_IO_MS) == 0,
                 "the member did not receive the stripped ban mask \"%s\". The mask is "
                 "the one field here that is BOTH stored and announced, so this is the "
                 "half of the assertion a strip on only one copy would fail.\n"
                 "  witness saw: %s", want, tc_buffer(&witness) + mark_w);
    assert_no_controls(&witness, mark_w, "the MODE +b echo");
    /* THE BAN IS REAL, which is the other half and the half that cannot be faked.
     * A mask the node printed as stripped and stored as something else would look
     * perfect on the wire; the divergence is only visible in what the ban REFUSES.
     *
     * So a fourth client leaves the channel and asks to come back, and this
     * project's answer to that is 474. The ban is per-channel -- `ch->bans` belongs
     * to one channel -- so the client has to leave and re-join THE SAME one, which
     * is why this is a PART followed by a JOIN and not a JOIN into a fresh channel.
     * An earlier version of this case set the ban on #T and tested a JOIN to #B,
     * which of course was not banned and which taught the case nothing. */
    TF_CHECK_MSG(tc_send(&victim, "PART " CHAN) == 0,
                 "the ban victim's PART send failed");
    drain(&victim);
    {
        size_t mark_v = tc_received(&victim);

        TF_CHECK_MSG(tc_send(&victim, "JOIN " CHAN) == 0,
                     "the ban victim's re-JOIN send failed");
        drain(&victim);
        TF_CHECK_MSG(strstr(tc_buffer(&victim) + mark_v, " 474 ") != NULL,
                     "the ban was not enforced -- 474 is this node's answer for a JOIN "
                     "a ban mask refuses -- so the STORED mask is not the one that was "
                     "announced and the two copies have diverged. A strip applied to "
                     "the broadcast alone would print the clean mask on the wire and "
                     "store the raw one, and this is the assertion that catches it.\n"
                     "  victim saw: %s", tc_buffer(&victim) + mark_v);
        assert_no_controls(&victim, mark_v, "the 474 a ban mask produced");
    }
    (void)snprintf(want, sizeof want, "chan_ban_mask_stripped: channel=" CHAN
                   " by=vic in_len=%zu kept_len=%zu", strlen(MASK_RAW),
                   strlen(MASK_CLEAN));
    TF_CHECK_MSG(nf_expect(&node, want, T_IO_MS) == 0,
                 "the operator log did not record the ban mask strip; expected "
                 "\"%s\".\n  node said: %s", want, node.out);

    /* --- 2. THE KICK REASON, which reaches every remaining member --- */
    mark_w = tc_received(&witness);
    mark_t = tc_received(&target);
    (void)snprintf(reason, sizeof reason, "%s", KICK_RAW);
    {
        char line[512];

        (void)snprintf(line, sizeof line, "KICK " CHAN " zaphod :%s", reason);
        TF_CHECK_MSG(tc_send(&op, line) == 0, "the KICK send failed");
    }
    (void)snprintf(want, sizeof want, ":vic!vic@" OBSERVED_HOST " KICK " CHAN
                   " zaphod :" KICK_CLEAN "\r\n");
    TF_CHECK_MSG(tc_expect(&witness, want, T_IO_MS) == 0,
                 "the remaining member did not receive the stripped KICK reason "
                 "\"%s\". Written out in full, so a strip that ate a space or a UTF-8 "
                 "continuation byte fails here while passing every control-byte "
                 "assertion in this file.\n  witness saw: %s", want,
                 tc_buffer(&witness) + mark_w);
    assert_no_controls(&witness, mark_w, "the KICK broadcast");
    /* And the kicked user sees the same stripped text: the KICK names the reason to
     * its target, which is the only part of it most clients ever show. */
    (void)snprintf(want, sizeof want, ":vic!vic@" OBSERVED_HOST " KICK " CHAN
                   " zaphod :" KICK_CLEAN "\r\n");
    TF_CHECK_MSG(tc_expect(&target, want, T_IO_MS) == 0,
                 "the KICKED user did not receive the stripped reason \"%s\".\n"
                 "  target saw: %s", want, tc_buffer(&target) + mark_t);
    assert_no_controls(&target, mark_t, "the KICK as the target saw it");
    (void)snprintf(want, sizeof want, "chan_kick_stripped: channel=" CHAN
                   " nick=vic in_len=%zu kept_len=%zu", strlen(KICK_RAW),
                   strlen(KICK_CLEAN));
    TF_CHECK_MSG(nf_expect(&node, want, T_IO_MS) == 0,
                 "the operator log did not record the KICK reason strip; expected "
                 "\"%s\".\n  node said: %s", want, node.out);

    /* --- 3. THE PART REASON, which is the one with no length bound at all --- */
    mark_w = tc_received(&witness);
    (void)snprintf(reason, sizeof reason, "%s", PART_RAW);
    {
        char line[512];

        (void)snprintf(line, sizeof line, "PART " CHAN " :%s", reason);
        TF_CHECK_MSG(tc_send(&op, line) == 0, "the PART send failed");
    }
    (void)snprintf(want, sizeof want, ":vic!vic@" OBSERVED_HOST " PART " CHAN
                   " :" PART_CLEAN "\r\n");
    TF_CHECK_MSG(tc_expect(&witness, want, T_IO_MS) == 0,
                 "the remaining member did not receive the stripped PART reason "
                 "\"%s\". A PART reason is the one of these three with no length bound "
                 "in the RFC or here, so it is the case that would fail if the strip's "
                 "buffer were sized off a field bound instead of the line cap.\n"
                 "  witness saw: %s", want, tc_buffer(&witness) + mark_w);
    assert_no_controls(&witness, mark_w, "the PART broadcast");
    (void)snprintf(want, sizeof want, "chan_part_stripped: channel=" CHAN
                   " nick=vic in_len=%zu kept_len=%zu", strlen(PART_RAW),
                   strlen(PART_CLEAN));
    TF_CHECK_MSG(nf_expect(&node, want, T_IO_MS) == 0,
                 "the operator log did not record the PART reason strip; expected "
                 "\"%s\".\n  node said: %s", want, node.out);

    tc_close(&op);
    tc_close(&witness);
    tc_close(&target);
    tc_close(&victim);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * CASE 6 -- THE REALNAME IS STILL REFUSED (Rule 3's regression guard)
 * ---------------------------------------------------------------------------
 * `conn_realname_check()` now asks `conn_text_bad_count()` instead of running its
 * own loop, so the one predicate is a refactor as well as an addition and a fault
 * in it would break the field that was ALREADY closed. This case is the guard: the
 * realname must still come out EMPTY, must still be announced, and must still not
 * put its bytes in the log.
 *
 * WHY EMPTY AND NOT REFUSED is not re-argued here -- handle_user() argues it at
 * length and the asymmetry with SETNAME is deliberate. What this asserts is only
 * that the behaviour is unchanged.
 */
static void case_realname_still_refused(void)
{
    nf_node_t node;
    test_client_t c;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");
    tc_init(&c);
    /* The realname is `USER`'s FOURTH parameter, and this is the one field whose
     * policy is REFUSE -- a realname is reported to every member of every channel
     * as though they wrote it, so it is not the same decision as an away message's.
     * The servername here is ordinary, so nothing else in this command is unusual. */
    register_as(&c, node.port, "vic", "*spoofed", NULL);

    /* Re-sending USER is 462, so the hostile realname goes on a fresh connection
     * rather than by trying to change a registered one. */
    tc_close(&c);

    {
        test_client_t hostile;
        char line[256];
        size_t mark;

        tc_init(&hostile);
        TF_CHECK_MSG(tc_connect(&hostile, node.port) == 0, "could not connect");
        (void)snprintf(line, sizeof line, "NICK mallory");
        TF_CHECK_MSG(tc_send(&hostile, line) == 0, "NICK send failed");
        (void)snprintf(line, sizeof line, "USER mallory 0 *spoofed :" ESC "[2J" BEL);
        TF_CHECK_MSG(tc_send(&hostile, line) == 0, "USER send failed");
        /* Registration still COMPLETES, with an empty realname. A 417 here would
         * strand a half-registered client, which is the argument at handle_user()
         * and the reason USER empties rather than refusing. */
        TF_CHECK_MSG(tc_expect(&hostile, " 001 ", T_IO_MS) == 0,
                     "a USER carrying a control-bearing realname did not register. "
                     "The policy for the realname is \"empty it and say so\", not "
                     "\"refuse\", because refusing leaves the client half-registered "
                     "with no way back but a reconnect.");
        TF_CHECK_MSG(nf_expect(&node, "realname_refused: fd=", T_IO_MS) == 0,
                     "the node did not announce that it dropped the realname. The "
                     "only observable difference between \"the client sent none\" and "
                     "\"the client sent one this node threw away\" is this line.\n"
                     "  node said: %s", node.out);
        mark = 0;
        assert_no_controls_in_log(&node, mark, "the refused realname");
        drain(&hostile);
        tc_close(&hostile);
    }

    /* AND THE SAME FOR DEL ALONE. A separate connection because `USER` is 462 on a
     * registered one, which is the other half of what handle_user() refuses. */
    {
        test_client_t del_only;
        char line[256];

        tc_init(&del_only);
        TF_CHECK_MSG(tc_connect(&del_only, node.port) == 0, "could not connect");
        TF_CHECK_MSG(tc_send(&del_only, "NICK ford") == 0, "NICK send failed");
        (void)snprintf(line, sizeof line, "USER ford 0 *spoofed :" DEL DEL);
        TF_CHECK_MSG(tc_send(&del_only, line) == 0, "USER send failed");
        TF_CHECK_MSG(tc_expect(&del_only, " 001 ", T_IO_MS) == 0,
                     "a USER carrying a DEL-only realname did not register");
        /* nf_expect_nth(), NOT nf_expect(). The needle is the same one the C0
         * case above already put in the buffer, and nf_expect() searches what has
         * been accumulated -- so a plain nf_expect() here would be satisfied by
         * the ESC case's line and would pass against a node that had not refused
         * anything at all. This is the same trap as the reused drain token, and
         * counting the occurrence is what closes it. */
        TF_CHECK_MSG(nf_expect_nth(&node, "realname_refused: fd=", 2u, T_IO_MS) == 0,
                     "the node announced only ONE refused realname, so it accepted "
                     "the DEL-only one. DEL is in the set because it is invisible in a "
                     "log rather than because it rings a bell, and it is the half of "
                     "the test a C0-only case cannot reach -- dropping the "
                     "`|| ch == 0x7f` half passes every other assertion in this "
                     "file.\n  node said: %s", node.out);
        assert_no_controls_in_log(&node, 0, "the refused DEL-only realname");
        drain(&del_only);
        tc_close(&del_only);
    }

    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * CASE 7 -- `MODE`'s 472: A PLACEHOLDER ON THE WIRE AND A MEASUREMENT IN THE LOG
 * ---------------------------------------------------------------------------
 * This case exists because of a bypass, and the bypass is the reason the case is
 * shaped the way it is rather than one more "no control byte anywhere" assertion.
 *
 * WHAT THE BUG WAS. `chan_verbs.c` refused an unknown mode character twice: once as
 * the numeric's `<char>` parameter and once in the observable line's `reason=`
 * field, and both were the client's byte. `MODE #T <ESC>` put an ESC on the
 * operator's terminal AND in a `472` on the socket. The ONLY gate in front of it is
 * `chan_has_flag(ch, c, CHAN_MEMBER_OP)`, and `chan_verbs.c` OPERATES THE CHANNEL
 * CREATOR on the creator's own JOIN -- so the gate is self-issued, one line after the
 * JOIN, and an anonymous client reaches it.
 *
 * WHY THE CLAIM IS ABOUT THE PLACEHOLDER AND NOT ONLY ABOUT THE ABSENCE. The
 * RFC 2812 5.2 field list is `<client> <char> :is unknown mode char to me for
 * <channel>`, so a client that parses 472 BY POSITION reads exactly one character
 * out of that field. An absence-only assertion would pass an implementation that
 * answered `472 <client>` with the field simply missing, and that breaks every
 * positional parser on the network. So the case pins the whole line, byte for byte,
 * for BOTH routes into the branch -- the mode argument with no sign, and one byte of
 * a signed mode string -- because those are two separate sites that answer the same
 * numeric.
 *
 * AND IT PINS THE POSITIVE ARM, which is the other half: a PRINTABLE mode this node
 * does not evaluate must still come back as itself. A placeholder that swallowed
 * every unknown character would pass every assertion above while breaking the one
 * thing 472 exists to tell a user, which is WHICH character was wrong.
 *
 * The whole-buffer scans are here too, so this case is also a plain
 * no-control-byte-reached-anything assertion for this path.
 */
static void case_mode_472_refusal_is_measured(void)
{
    nf_node_t node;
    test_client_t c;
    char line[256];
    char want[256];
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");
    /* The CREATOR of #T, deliberately: an operator is the only client this node lets
     * reach the mode-string argument at all, and the creator is the only operator a
     * lone client can be. */
    register_as(&c, node.port, "vic", "*spoofed", NULL);
    join(&c, CHAN);

    mark = tc_received(&c);

    /* ROUTE 1: the mode ARGUMENT has no sign. `MODE #T <ESC>` -- the argument IS the
     * refused character, which is the branch at the top of the handler. */
    (void)snprintf(line, sizeof line, "MODE %s " ESC, CHAN);
    TF_CHECK_MSG(tc_send(&c, line) == 0, "the unsigned-mode 472 send failed");
    (void)snprintf(want, sizeof want, " 472 vic ? :is unknown mode char to me for "
                 "channel %s\r\n", CHAN);
    TF_CHECK_MSG(tc_expect(&c, want, T_IO_MS) == 0,
                 "the client did not receive a 472 whose <char> parameter is the "
                 "one-byte placeholder `?`. The field has to stay ONE byte -- a "
                 "positional parser reads exactly one character out of it -- and it "
                 "has to be printable.\n  window: %s", tc_buffer(&c) + mark);
    drain(&c);

    /* ROUTE 2: one byte INSIDE a signed mode string, which is a different site with
     * the same field list and therefore the same placeholder. Without this arm a fix "
     "that only guarded the argument would pass. */
    mark = tc_received(&c);
    (void)snprintf(line, sizeof line, "MODE %s +" ESC, CHAN);
    TF_CHECK_MSG(tc_send(&c, line) == 0, "the signed-mode 472 send failed");
    (void)snprintf(want, sizeof want, " 472 vic ? :is unknown mode char to me for "
                 "channel %s\r\n", CHAN);
    TF_CHECK_MSG(tc_expect(&c, want, T_IO_MS) == 0,
                 "the signed-mode route did not produce the same 472, so the two "
                 "sites have drifted apart.\n  window: %s", tc_buffer(&c) + mark);
    drain(&c);

    /* THE POSITIVE ARM: `q` is not a mode this node evaluates, so it is refused --
     * and it is a PRINTABLE character, so it must be echoed as itself rather than as
     * the placeholder. This is the assertion that fails if the fix were "answer 472
     * with `?` for everything". */
    mark = tc_received(&c);
    (void)snprintf(line, sizeof line, "MODE %s q", CHAN);
    TF_CHECK_MSG(tc_send(&c, line) == 0, "the printable-mode 472 send failed");
    (void)snprintf(want, sizeof want, " 472 vic q :is unknown mode char to me for "
                 "channel %s\r\n", CHAN);
    TF_CHECK_MSG(tc_expect(&c, want, T_IO_MS) == 0,
                 "a PRINTABLE unknown mode character must be echoed as itself: 472 "
                 "exists to tell a user which character was wrong, and answering `?` "
                 "to everything would throw that away.\n  window: %s",
                 tc_buffer(&c) + mark);
    drain(&c);

    assert_no_controls(&c, 0, "the MODE 472 refusals, the whole session");

    /* THE OPERATOR'S HALF. Rule 1: the value has no consumer beyond the line, so it
     * is WITHHELD rather than filtered -- `reason=-` -- and the measurement beside it
     * says how long it was, WHICH byte it was, and that it was unsafe. `reason_byte=`
     * is the field that makes the withholding diagnosable, and it is the reason an
     * operator can still act on this line. */
    TF_CHECK_MSG(nf_expect(&node, "chan_mode_refused: channel=" CHAN " nick=vic "
                           "reason=- reason_len=1 reason_byte=0x1b "
                           "reason_bad_bytes=1", T_IO_MS) == 0,
                 "the node did not report the measurement the 472's log line is "
                 "supposed to carry: the withheld value with its length, its byte in "
                 "hex, and its bad-byte count. `reason=-` alone would be "
                 "indistinguishable from an absent value.\n  node said: %s", node.out);
    assert_no_controls_in_log(&node, 0, "the MODE 472 refusals, the whole log");

    /* THE CLIENT'S BUFFER IS RELEASED, and it is worth saying why that line is here
     * rather than left out: `register_as()` calls `tc_init()`, which allocates the
     * receive buffer, and a `test_client_t` that is initialised and never closed
     * leaks it. LeakSanitizer found exactly this -- 8192 bytes, the buffer grown to
     * IRC_MAX_LINE -- and ONLY on Linux, because macOS's AddressSanitizer has no
     * LeakSanitizer and this tree's local gate therefore cannot see a leak at all.
     * A cleanup line that no local run requires is exactly the kind of line that goes
     * missing, so it is here with the reason. */
    tc_close(&c);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    tf_unregister(&node);
}

int main(void)
{
    case_servername_is_summarised();
    case_away_stripped_for_member();
    case_topic_stripped_for_members();
    case_away_strip_keeps_good_bytes();
    case_topic_strip_keeps_good_bytes();
    case_relayed_parameters_are_stripped();
    case_realname_still_refused();
    case_mode_472_refusal_is_measured();

    tf_done("control-bytes");
    return 0;
}
