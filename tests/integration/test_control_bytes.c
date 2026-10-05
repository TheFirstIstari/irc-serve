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
 * THIS STAGE (#121, commit 1 of 4) ASSERTS ONE CASE, and it is a GUARD rather than the
 * fix: `conn_realname_check()` now asks the shared predicate instead of running its
 * own loop, so the predicate is a refactor as well as an addition, and a fault in it
 * would break the one field that was already closed. The three fields the predicate
 * exists for arrive in the commits that follow.
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

/* Build the whole line `AWAY :<esc><utf8>` into `out` and return the offset of the
 * byte to cut at, which is the MIDDLE of the first two-byte character of the UTF-8
 * text: "AWAY :" and the escape are complete, "caf" is complete, and the split falls
 * between the lead byte 0xC3 and its continuation 0xA9.
 *
 * The text is copied through a `char` array rather than indexed off the literal
 * directly, because `"literal" + 4u` is not pointer arithmetic to a compiler that
 * thinks in strings -- -Wstring-plus-int objects to it, and rightly: this returns an
 * offset into a buffer, not a pointer into a string constant. */
/* AWAY: the text a member receives when the strip kept everything it should. */
/* TOPIC: the same constraint, on the field whose exposure is larger. */
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

int main(void)
{
    case_realname_still_refused();

    tf_done("control-bytes");
    return 0;
}
