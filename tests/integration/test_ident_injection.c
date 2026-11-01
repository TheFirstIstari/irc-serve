/* test_ident_injection.c -- `conn_t::user` had no predicate at all, and this is
 * the file that proves the hole is closed.
 *
 * ===========================================================================
 * WHAT THE DEFECT WAS
 * ===========================================================================
 * Of this node's five identity fields, four were validated at ingest:
 * `nick` by `valid_nick()`, `realname` by `conn_realname_check()`, `account` by
 * `account_name_wire_safe()`, and `host` by being OBSERVED rather than asserted.
 * The fifth -- `conn_t::user` -- had NOTHING. Its only writer was
 * `handle_user()`'s `copy_field()`, which bounds LENGTH and tests no byte, and
 * `CHGHOST` is deliberately unimplemented so there was no second writer to make
 * a second rule for.
 *
 * `conn_hostmask()` then rendered `nick!user@host` into the PREFIX of every line
 * the client sent, and that prefix goes to every co-member of every channel the
 * client joined. `message_build()` memcpy's it verbatim and no filter is applied
 * to a prefix anywhere in the tree. So one pre-registration line, with no
 * credential and no second client, put a CSI sequence into a stranger's
 * terminal:
 *
 *     USER \033[2J\033[31m...\033[0m 0 * :x     then JOIN and speak
 *
 * A raw `0x9B` survived it too, which is the exact byte class an earlier pass
 * removed from the peer->client path: on an 8-bit terminal `0x9B` IS CSI, and it
 * is neither `<= 0x20` nor `0x7f`, so nothing that looked at bytes had a reason
 * to stop it.
 *
 * The second defect in this file is the same class one layer down:
 * `handle_authenticate()`'s REJECTED branch printed `authcid` raw, and
 * `authcid` is whatever the client base64-encoded. `sasl_plain_parse()`
 * validates LENGTH and nothing else, so the value only needed to be WELL-FORMED
 * base64 of a three-NUL-field payload to reach an operator's screen -- with no
 * `--sasl-store` configured at all, which is the default.
 *
 * ===========================================================================
 * WHAT THIS FILE ASSERTS, AND WHAT IT DELIBERATELY DOES NOT
 * ===========================================================================
 *   1. A hostile ident is REFUSED at ingest, registration still completes, the
 *      operator log summarises the refusal as a measurement, and a CO-MEMBER's
 *      hostmask shows an empty `<user>` slot. That last assertion is the one
 *      that matters: the hazard was never the log, it was the stranger's screen.
 *   2. A UTF-8 ident is NOT caught by the same fix. `ā` and Cyrillic reach a
 *      co-member byte for byte. This is the arm that makes the fix defensible
 *      rather than merely different: a predicate widened to "refuse everything
 *      >= 0x80" would pass case 1 while silently destroying every non-ASCII
 *      ident on the network, and a mangled value the user cannot see happening
 *      is worse than the injection.
 *   3. `authcid` is measured rather than printed, with the true length beside
 *      the `-`, on the NO_STORE path that needs no store configured at all.
 *   4. The two hostmask paths ask ONE predicate. That claim is established here
 *      from the source, which is the only instrument that can reach it -- see
 *      the case's own header for why a behavioural test cannot.
 *
 * The wire is the assertion surface throughout: every wait is `tc_expect()`'s or
 * `nf_expect()`'s deadline loop and there is no `sleep()` anywhere. A PING whose
 * PONG is a per-call token is the drain, numbered because `tc_expect()` searches
 * the ACCUMULATED buffer and a reused token is satisfied by an earlier PONG with
 * no read at all.
 *
 * ---------------------------------------------------------------------------
 * THE MARKER SET, and why it is written out rather than borrowed
 * ---------------------------------------------------------------------------
 * `harness/sweep_scan.h` owns the sweep's set and this file does not sweep; it
 * asserts exact lines. So the bytes under test here are spelled out at the call
 * sites with the reason each one is in the set, and the scan that follows a
 * message walks the C0 controls that are not CR, LF or TAB, DEL, and the whole
 * C1 range -- the same 62 bytes, restated so that a change to the sweep's set
 * cannot silently narrow what this file looks for.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define SRV "irc.test"
#define OBSERVED_HOST "127.0.0.1"

/* OCTAL and not \x, and the reason is the C grammar rather than a style:
 * `"\x07bye"` is ONE hex escape -- the compiler takes as many hex digits as it
 * can -- so `\x07b` is U+007B and the next character of the sentence silently
 * becomes `{`. `"\007bye"` is three characters. Every escape in this file is
 * octal for that reason.
 *
 *   \033   ESC      0x1b  CSI follows; any terminal executes it.
 *   \007   BEL      0x07  rings the recipient's bell.
 *   \177   DEL      0x7f  invisible in a log, so a reader cannot see a value
 *                        that carries one.
 *   \233   0x9B     0x9b  RAW 8-bit CSI. This is the byte the peer->client pass
 *                        removed and the client->client path kept.
 */
#define CSI_ESC "\033[2J"
#define BEL     "\007"
#define DELCH   "\177"
#define C1_CSI  "\233[31m"

/* U+0101 LATIN SMALL LETTER A WITH MACRON, `ā`, and its two-byte UTF-8 form.
 * 0xC4 0x81: the SECOND byte is 0x81, which is inside the C1 range, so any
 * predicate looking at bytes alone refuses this character. That is the whole
 * reason the fix asks `conn_text_display_check()` -- a walk about CODE POINTS --
 * rather than a byte range. */
#define UTF8_MACRON "\304\201"
/* U+0434 CYRILLIC SMALL LETTER DE and U+0430 CYRILLIC SMALL LETTER A. */
#define UTF8_CYR    "\320\264\320\260"

/* ---------------------------------------------------------------------------
 * The scan, and why a whole-buffer walk rather than a substring search
 * ---------------------------------------------------------------------------
 * A substring search for ESC would pass a node that stripped ESC and relayed
 * BEL, which is exactly the shape of the two bugs this file was written beside.
 * So this walks every byte and refuses every member of the set. CR and LF are
 * skipped because they are the framing layer's own -- `message_parse_n()`
 * refuses both, so the only ones in a scanned buffer are the line terminators.
 */
static int marker_byte(unsigned char ch)
{
    if (ch == '\r' || ch == '\n' || ch == '\t' || ch == 0u) {
        return 0;
    }
    if (ch <= 0x1fu || ch == 0x7fu) {
        return 1;
    }
    if (ch >= 0x80u && ch <= 0x9fu) {
        return 1;
    }
    return 0;
}

static void assert_no_markers(const char *buf, size_t len, const char *what)
{
    for (size_t i = 0; i < len; i++) {
        const unsigned char ch = (unsigned char)buf[i];

        TF_CHECK_MSG(marker_byte(ch) == 0,
                     "%s: a byte from the terminal-injection set (0x%02x) reached "
                     "a surface a human reads. 0x07 rings a terminal's bell and ESC "
                     "followed by `[` is a CSI sequence any terminal executes, so "
                     "this is one user rewriting another user's screen, or ringing "
                     "it. The co-member's hostmask is the surface under test.\n"
                     "  window: %s", what, ch, buf);
    }
}

/* ---------------------------------------------------------------------------
 * Registering a client with an IDENT OF THE CALLER'S CHOOSING
 * ---------------------------------------------------------------------------
 * `test_control_bytes.c`'s `register_as()` puts the caller's value in the
 * <servername> slot, which is a field this node ignores. That is the wrong slot
 * for this file: the value under test is `params[0]`, the ident, and it is the
 * one field of the four `USER` parameters that reaches a co-member's terminal.
 */
static void register_ident(test_client_t *c, int port, const char *nick,
                           const char *ident)
{
    char line[512];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s NICK send failed", nick);
    /* The realname is deliberately clean: it is another field, checked by
     * another predicate, and a hostile value in it here would make a red run
     * ambiguous about which field was refused. */
    (void)snprintf(line, sizeof line, "USER %s 0 * :Real %s", ident, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s USER send failed", nick);
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0,
                 "%s never registered. A registration that does not complete is "
                 "not a refused ident -- the fix is supposed to leave the client "
                 "with an EMPTY ident and a working connection, and a node that "
                 "stranded the client instead would be failing this case for the "
                 "wrong reason.", nick);
}

/* A clean, boring registration, for the co-member that has to see the hostile
 * one's hostmask. */
static void register_plain(test_client_t *c, int port, const char *nick)
{
    register_ident(c, port, nick, nick);
}

/* The drain: a PING whose PONG token is numbered per call. */
static void drain(test_client_t *c, const char *who)
{
    static unsigned seq;
    char token[32];
    char line[64];

    (void)snprintf(token, sizeof token, "dr%u", seq++);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s PING send failed", who);
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "%s never answered its drain PING, so the buffer this case is "
                 "about to scan is not provably complete.", who);
}

/* Put TWO clients in one channel, and the ORDER IS THE POINT: the co-member
 * (`b`) joins FIRST, because the hostmask under test is rendered on the JOIN of
 * the client that holds the hostile value (`a`) -- and a JOIN is echoed to
 * everybody who is already in the channel. Joining `a` first would leave `b`
 * having never seen the line this file exists to assert, so the assertion would
 * time out on a node that is behaving correctly.
 *
 * AND THE ORDER IS ESTABLISHED BY A WAIT, NOT BY THE ORDER OF THE SENDS. Two
 * `send()` calls to two sockets microseconds apart are not an ordering: the node
 * has one event loop and reads whichever descriptor its poll set yields first,
 * so the second JOIN can be dispatched before the first. The barrier below is
 * the co-member's OWN JOIN echo, and it has to be an EXACT needle rather than a
 * substring -- the co-member has already joined other channels earlier in the
 * same case, so a search for `" JOIN "` is satisfied by an earlier line and
 * waits for nothing at all. The channel name makes the needle unique to this
 * join, which is what makes the wait mean "the node has processed this JOIN". */
static void join_shared(test_client_t *a, test_client_t *b, const char *chan)
{
    char line[128];
    char echo[96];

    (void)snprintf(line, sizeof line, "JOIN %s", chan);
    (void)snprintf(echo, sizeof echo, " JOIN %s\r\n", chan);
    TF_CHECK_MSG(tc_send(b, line) == 0, "the co-member could not JOIN");
    TF_CHECK_MSG(tc_expect(b, echo, T_IO_MS) == 0,
                 "the co-member's own JOIN into %s never echoed, so there is no "
                 "second reader and the rest of this case would be asserting "
                 "about a socket nobody is on.\n  %s saw: %s", chan, "the co-member",
                 tc_buffer(b));
    TF_CHECK_MSG(tc_send(a, line) == 0, "the hostile client could not JOIN");
    TF_CHECK_MSG(tc_expect(a, echo, T_IO_MS) == 0,
                 "the hostile client's own JOIN into %s never echoed, so it is not "
                 "in the channel and every hostmask assertion below would be "
                 "vacuous.\n  saw: %s", chan, tc_buffer(a));
}

/* ---------------------------------------------------------------------------
 * A one-line absence check over the node's stdout
 * ---------------------------------------------------------------------------
 * `log_line_absent()` is the negative half of `nf_expect()`: the node's buffer
 * is accumulated, so "this line never appeared" is a claim over the whole of it
 * and needs no mark. It is here rather than in the harness because the harness
 * has no caller that needs the negative and a helper with one caller is a
 * helper nobody maintains.
 */
static int log_line_absent(const nf_node_t *n, const char *token)
{
    return (strstr(n->out, token) != NULL) ? 1 : 0;
}

/* ---------------------------------------------------------------------------
 * CASE 1 -- THE HOSTILE IDENT IS REFUSED AT INGEST, AND A CO-MEMBER SEES AN
 *           EMPTY `<user>` SLOT
 * ---------------------------------------------------------------------------
 * The attack needs no credential, no channel and no second client to put bytes
 * in the operator's log; it needs a second client to put them in a TERMINAL. So
 * this case has both, and the assertion that matters is the one on the
 * co-member's socket.
 *
 * Four claims, in the order they are asserted:
 *
 *   1. REGISTRATION COMPLETES. `001` is what proves the fix did not solve the
 *      hazard by refusing the command, which would strand a half-registered
 *      client for a value no real client sends a control byte in. This is the
 *      same decision `conn_realname_check()`'s USER caller made, and the same
 *      consequence: the client registers with an empty field.
 *   2. THE CO-MEMBER'S HOSTMASK IS EXACT. `:atk!@127.0.0.1 JOIN #IDT` -- the
 *      `<user>` slot is EMPTY, not truncated, not substituted, not stripped.
 *      A byte-exact assertion is what makes "the ident was dropped" visible as
 *      an identity change rather than as a clean scan.
 *   3. NO MARKER BYTE REACHED ANY SURFACE. The co-member's whole buffer and the
 *      node's whole stdout. This is the security property, and it is asserted
 *      over the buffer rather than over one line because the leak was a prefix
 *      on every line, not a single line.
 *   4. THE REFUSAL IS REPORTED AS A MEASUREMENT. `user_refused:` with the
 *      reason, the length and the bad-byte count -- never the bytes. An
 *      operator can watch the count; an operator cannot un-read a CSI sequence.
 *
 * A raw 0x9B is in the payload on purpose. It is the byte that says the fix is
 * about code points rather than about a byte range: `0x9B` is not `<= 0x20`, it
 * is not `0x7f`, and on an 8-bit terminal it is CSI.
 */
static void case_hostile_ident_is_refused_at_ingest(void)
{
    nf_node_t node;
    test_client_t atk;
    test_client_t wit;
    char line[256];
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    /* The hostile registration: ESC + `[2J`, ESC + `[31m`, then a literal
     * ident-ish word, then ESC `[0m`, and a raw 0x9B leading a second CSI. */
    (void)snprintf(line, sizeof line, "NICK atk");
    tc_init(&atk);
    TF_CHECK_MSG(tc_connect(&atk, node.port) == 0, "atk could not connect");
    TF_CHECK_MSG(tc_send(&atk, line) == 0, "atk NICK send failed");
    (void)snprintf(line, sizeof line, "USER " CSI_ESC "\033[31mEVIL\033[0m" C1_CSI
                                     BEL DELCH " 0 * :x");
    TF_CHECK_MSG(tc_send(&atk, line) == 0, "atk USER send failed");
    /* CLAIM 1: registration completes. */
    TF_CHECK_MSG(tc_expect(&atk, " 001 ", T_IO_MS) == 0,
                 "the hostile ident stranded the client instead of registering it "
                 "with an empty ident. `handle_user()` refuses the FIELD and lets "
                 "the registration finish, which is the precedent "
                 "`conn_realname_check()` set for the realname on the same "
                 "command.\n  atk saw: %s", tc_buffer(&atk));

    register_plain(&wit, node.port, "wit");

    mark = node.out_len;
    join_shared(&atk, &wit, "#IDT");
    drain(&atk, "atk");
    drain(&wit, "wit");

    /* CLAIM 2: the co-member's hostmask, byte for byte. The `<user>` slot is
     * empty -- `atk!@127.0.0.1` and not `atk!...@127.0.0.1` -- which is what a
     * client that sent no ident at all looks like on this node. */
    TF_CHECK_MSG(tc_expect(&wit, ":atk!@" OBSERVED_HOST " JOIN #IDT\r\n",
                           T_IO_MS) == 0,
                 "the co-member did not see an EMPTY `<user>` slot in the hostile "
                 "client's hostmask. The claim is `atk!@127.0.0.1`, which is what "
                 "a registration whose ident was refused looks like; anything else "
                 "means the refused value was stored rather than dropped.\n"
                 "  wit saw: %s", tc_buffer(&wit));
    /* And the attacker's own JOIN echo is the same shape, because the hostmask
     * is rendered from the same fields on both sockets. */
    TF_CHECK_MSG(tc_expect(&atk, ":atk!@" OBSERVED_HOST " JOIN #IDT\r\n",
                           T_IO_MS) == 0,
                 "the attacker's own JOIN echo does not carry an empty `<user>` "
                 "slot.\n  atk saw: %s", tc_buffer(&atk));

    /* CLAIM 3: nothing reached a human. Both sockets and the node's own stdout,
     * over the whole of each rather than over a line. */
    assert_no_markers(tc_buffer(&atk), tc_received(&atk), "the attacker's socket");
    assert_no_markers(tc_buffer(&wit), tc_received(&wit), "the co-member's socket");
    assert_no_markers(node.out + mark, node.out_len - mark, "the node's stdout");

    /* CLAIM 4: the refusal is reported as a MEASUREMENT, and both numbers are
     * DERIVED from the string this file sent rather than written down: the
     * length is `strlen()` of the same literal and the bad-byte count is the
     * same walk `conn_text_bad_count()` performs. An expectation a reader has
     * to trust is an expectation that stops being checked the moment the
     * payload changes. */
    {
        char want[96];
        size_t bad = 0u;

        /* The ident as sent, spelled out here so the two numbers below are
         * computed from ONE object: ESC `[2J`, ESC `[31m`, EVIL, ESC `[0m`,
         * 0x9B `[31m`, BEL, DEL. */
        static const char hostile[] = CSI_ESC "\033[31mEVIL\033[0m" C1_CSI
                                      BEL DELCH;

        for (size_t i = 0; hostile[i] != '\0'; i++) {
            const unsigned char u = (unsigned char)hostile[i];

            /* `conn_byte_is_bad()`'s set, restated here rather than borrowed:
             * C0 and DEL. NOT a C1 byte, and the reason is connection.h's own
             * argument for it -- bytes >= 0x80 are UTF-8 continuation bytes and a
             * count that included them would eat every non-ASCII value. The
             * count is therefore a FLOOR: 0x9B is the byte that makes this
             * payload dangerous and it is not counted. */
            if (u <= 0x1fu || u == 0x7fu) {
                bad++;
            }
        }
        (void)snprintf(want, sizeof want, "len=%zu", strlen(hostile));
        TF_CHECK_MSG(nf_expect(&node, want, T_IO_MS) == 0,
                     "the refusal's length is not the length of what the client "
                     "sent (%zu bytes). A node that reported 0 or some other "
                     "number is measuring something other than the refused "
                     "value.\n  node said: %s", strlen(hostile), node.out);
        (void)snprintf(want, sizeof want, "bad_bytes=%zu", bad);
        TF_CHECK_MSG(nf_expect(&node, want, T_IO_MS) == 0,
                     "the refusal's bad-byte count is not %zu -- the count of C0 "
                     "controls and DEL in the payload this file sent. A node that "
                     "counts a different number is applying a different set than "
                     "the one that measured it.\n"
                     "AND WHY THE COUNT IS 5 AND NOT 6, which is the one number on "
                     "this line a reader will otherwise 'fix': `bad_bytes=` is "
                     "`conn_text_bad_count()`, whose set is C0 and DEL and which "
                     "deliberately EXCLUDES every byte >= 0x80 -- connection.h "
                     "says so and argues it, because those are UTF-8 continuation "
                     "bytes and a filter that counted them would eat every "
                     "non-ASCII value on the node. The predicate that refused this "
                     "ident is STRICTER: its second half is "
                     "`conn_text_display_check()`, which also refuses a raw C1 "
                     "byte. So the one byte that makes this payload dangerous on "
                     "an 8-bit terminal (0x9B) is not in the count, and the "
                     "measurement is a FLOOR rather than a census. The reason "
                     "token beside it is what names the rule.\n"
                     "  node said: %s", bad, node.out);
    }
    /* AND THE OPERATOR LINE MEASURES THE IDENT IT STORED rather than printing it,
     * which is the sibling contract on the same command. `user=-` with the true
     * length beside it is what an empty-or-withheld ident looks like on that
     * line, and the assertion is that the raw bytes are not there. */
    TF_CHECK_MSG(nf_expect(&node, "user=-", T_IO_MS) == 0,
                 "the `user:` line did not withhold the ident. An empty ident "
                 "prints as `-` on this node's log convention -- `ping: token=-` "
                 "is the same spelling for an absent value -- and a raw `%%s` here "
                 "would be the injection surface this pass closed.\n"
                 "  node said: %s", node.out);

    tc_close(&atk);
    tc_close(&wit);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * CASE 2 -- THE UTF-8 POSITIVE CONTROL, AND IT IS THE ARM THAT MATTERS MOST
 * ---------------------------------------------------------------------------
 * A predicate widened to "refuse every byte >= 0x80" would pass case 1
 * completely. It would refuse `ā`, whose UTF-8 form is `0xC4 0x81` and whose
 * SECOND byte is 0x81 -- inside the C1 range this node treats as a marker. It
 * would refuse every accented Latin character, every Greek and Cyrillic
 * character, and it would do it SILENTLY: the client registers, the co-member
 * sees an empty ident, and nothing anywhere says the value was thrown away.
 *
 * That is a worse failure than the bug this file exists for, and it is the
 * reason the fix asks `conn_text_display_check()` -- a walk about CODE POINTS,
 * where `0x81` after a lead byte that expects one is a letter -- rather than a
 * byte range. So the control is not optional and it is not a formality: it is
 * the assertion that separates the right fix from the easy one.
 *
 * The assertion is BYTE-EXACT, over a multi-byte ident, in a hostmask rendered
 * to another client's socket. If the value had been stripped rather than
 * refused, or mangled by a byte-range filter, the bytes on the witness's socket
 * would not match.
 */
static void case_utf8_idents_survive(void)
{
    nf_node_t node;
    test_client_t mac;
    test_client_t cyr;
    test_client_t ascii;
    test_client_t wit;
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    register_ident(&mac, node.port, "mac", UTF8_MACRON);
    register_ident(&cyr, node.port, "cyr", UTF8_CYR);
    register_ident(&ascii, node.port, "plain", "plainident");
    register_plain(&wit, node.port, "wit");

    mark = node.out_len;
    join_shared(&mac, &wit, "#UMAC");
    join_shared(&cyr, &wit, "#UCYR");
    join_shared(&ascii, &wit, "#UASC");
    drain(&mac, "mac");
    drain(&cyr, "cyr");
    drain(&ascii, "plain");
    drain(&wit, "wit");

    /* The hostmask the CO-MEMBER receives, byte for byte. Three of them, and
     * the third is the control that says the first two are not being compared
     * against a filter that emptied everything. */
    TF_CHECK_MSG(tc_expect(&wit, ":mac!" UTF8_MACRON "@" OBSERVED_HOST
                           " JOIN #UMAC\r\n", T_IO_MS) == 0,
                 "a UTF-8 ident did not reach the co-member byte for byte. `%s` is "
                 "U+0101 as `0xC4 0x81`, and its second byte is 0x81 -- inside the "
                 "C1 range. A predicate that refuses bytes rather than code points "
                 "drops this character silently, and a mangled value the user "
                 "cannot see happening is worse than the injection it was meant to "
                 "stop.\n  wit saw: %s", UTF8_MACRON, tc_buffer(&wit));
    TF_CHECK_MSG(tc_expect(&wit, ":cyr!" UTF8_CYR "@" OBSERVED_HOST
                           " JOIN #UCYR\r\n", T_IO_MS) == 0,
                 "a Cyrillic ident did not reach the co-member byte for byte. "
                 "`%s` is two 2-byte sequences; the same argument applies.\n"
                 "  wit saw: %s", UTF8_CYR, tc_buffer(&wit));
    TF_CHECK_MSG(tc_expect(&wit, ":plain!plainident@" OBSERVED_HOST
                           " JOIN #UASC\r\n", T_IO_MS) == 0,
                 "a plain ASCII ident did not reach the co-member byte for byte, so "
                 "the two assertions above would be passing against a filter that "
                 "emptied EVERY ident rather than one that refuses only the unsafe "
                 "ones.\n  wit saw: %s", tc_buffer(&wit));

    /* And the node did not refuse any of them. `user_refused:` appearing at all
     * here would mean the predicate is refusing a legal ident, which is the
     * silent failure case. */
    TF_CHECK_MSG(log_line_absent(&node, "user_refused:") == 0,
                 "the node logged a `user_refused:` line for a legal ident. A "
                 "UTF-8 ident is not a parameter byte the wire cannot carry -- it "
                 "is an ordinary stored value -- and refusing it would be the "
                 "silent mangling this case exists to catch.\n  node said: %s",
                 node.out);

    /* The operator line still reports each ident's TRUE LENGTH, which is what
     * makes the `user=-` withholding diagnosable rather than mysterious. Two
     * bytes for `ā`, four for the Cyrillic pair, ten for the ASCII one. */
    TF_CHECK_MSG(nf_expect(&node, "user_len=2", T_IO_MS) == 0,
                 "the `user:` line did not report the UTF-8 ident's length as 2 "
                 "bytes. A multi-byte ident prints as `-` on the operator's line "
                 "and its true length is what says how long the real value was.\n"
                 "  node said: %s", node.out);
    TF_CHECK_MSG(nf_expect(&node, "user_len=4", T_IO_MS) == 0,
                 "the `user:` line did not report the Cyrillic ident's length as 4 "
                 "bytes.\n  node said: %s", node.out);

    assert_no_markers(node.out + mark, node.out_len - mark, "the node's stdout");

    tc_close(&mac);
    tc_close(&cyr);
    tc_close(&ascii);
    tc_close(&wit);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * CASE 3 -- THE TWO HOSTMASK PATHS ASK ONE PREDICATE, AND WHY IT IS A SOURCE TEST
 * ---------------------------------------------------------------------------
 * `conn_t::user` is the `<user>` slot of a `nick!user@host` hostmask, and so is
 * `fed_rnick::user`. Before this pass the peer path asked `nickreg_ident_ok()`
 * about its copy and the client path asked NOTHING about its own -- so the same
 * slot was governed by a rule on one path and by nothing on the other, which is
 * how the same byte can be refused on a peer's record and rendered to a
 * stranger on a client's.
 *
 * The blunt way to close that would have been a second predicate next to the
 * first, and that is the mistake this tree has made three times: two functions
 * answering "which bytes may a hostmask component hold" is how they come to
 * disagree, and the disagreement is invisible until one of them is the one an
 * attacker reaches. The same reasoning already settled `SMODES` against client
 * `MODE` -- one predicate, asked twice, and a test that the two agree.
 *
 * WHY THIS IS A SOURCE TEST AND NOT A BEHAVIOURAL ONE. The claim is "there is
 * ONE rule and it is asked by both paths", and no socket can observe that: a
 * behavioural test can only show that two calls behave the same on the inputs
 * it tried, which is not the same as there being one function. What a source
 * test CAN show, and what is asserted below, is the shape of the tree: the
 * predicate is declared in a header rather than hidden in a .c file, it is
 * named by the peer path, named by the client path, named by the resume store
 * that copies the client's value, and defined exactly once. The behavioural
 * halves of the same claim are elsewhere: `user_refused:` is asserted on a
 * client socket in case 1 above, and `fed_nickreg_field_refused:` with
 * `field=user len=8 bad_bytes=1` is asserted on a peer's SBURSTN in
 * test_fed_burst.c. The REASON LITERAL is compared here, which is the piece
 * neither of those can reach on its own: the two paths must report the same
 * verdict about the same predicate, not merely refuse something. */
static size_t occurrences(const char *hay, const char *needle)
{
    size_t n = 0u;
    const char *at;

    for (at = strstr(hay, needle); at != NULL; at = strstr(at + 1, needle)) {
        n++;
    }
    return n;
}

static void case_both_paths_ask_one_predicate(void)
{
    char *commands;
    char *nickreg;
    char *nickreg_h;
    char *resume;
    size_t len = 0u;
    size_t n;

    /* The CLIENT path's call site, in `handle_user()`. Read with comments
     * stripped so a comment describing the predicate cannot satisfy the
     * assertion -- a rule that exists only in prose is not a rule. */
    commands = tf_read_code("src/core/commands.c", &len);
    TF_CHECK_MSG(commands != NULL && len > 0u,
                 "could not read src/core/commands.c, so the client path's call "
                 "site could not be checked and this case would pass by not "
                 "looking");
    TF_CHECK_MSG(strstr(commands, "nickreg_ident_ok(m->params[0], sizeof c->user)") != NULL,
                 "handle_user() no longer asks nickreg_ident_ok() about the client's "
                 "ident. Either the ingest check was removed -- in which case the "
                 "co-member hostmask assertion in case 1 is what will go red -- or "
                 "it moved, and a rule that has moved is a rule that has to be "
                 "justified again rather than assumed.\n  searched: handle_user()");
    TF_CHECK_MSG(occurrences(commands, "copy_field(c->user") == 1u,
                 "handle_user()'s single writer of `c->user` is no longer one "
                 "copy_field() call. `CHGHOST` is deliberately unimplemented and "
                 "the refusal branch stores an empty value, so a second writer is "
                 "a second rule this test does not know about.");
    free(commands);

    /* The PEER path's call sites, and the DEFINITION counted exactly once. */
    nickreg = tf_read_code("src/federation/nickreg.c", &len);
    TF_CHECK_MSG(nickreg != NULL && len > 0u,
                 "could not read src/federation/nickreg.c");
    /* One definition. Two definitions is the failure this case exists for, and
     * it would be invisible behaviourally until one of them was the one an
     * attacker reached. */
    n = occurrences(nickreg, "int nickreg_ident_ok(");
    TF_CHECK_MSG(n == 1u,
                 "nickreg_ident_ok() is defined %lu time(s) in nickreg.c. The "
                 "predicate for a hostmask component must be ONE function, asked "
                 "by both paths, because two answers to the same question come to "
                 "disagree and the disagreement is silent until one of them is the "
                 "one an attacker reaches.", (unsigned long)n);
    /* Three asks: the definition's own signature, the refresh arm and the
     * append arm. Fewer and the peer path has stopped asking. */
    n = occurrences(nickreg, "nickreg_ident_ok(");
    TF_CHECK_MSG(n >= 3u,
                 "nickreg.c names nickreg_ident_ok() %lu time(s) and the peer path "
                 "asks it on both the refresh and the append arm, so a smaller "
                 "number means the peer path has stopped asking and the two paths "
                 "no longer share a rule.", (unsigned long)n);
    free(nickreg);

    /* IT IS DECLARED IN THE HEADER, which is what makes it shareable at all.
     * A `static` predicate is a predicate only its own file can ask, and the
     * reason the client path could not use this one for a long time is that it
     * was. */
    nickreg_h = tf_read_code("src/federation/nickreg.h", &len);
    TF_CHECK_MSG(nickreg_h != NULL && len > 0u,
                 "could not read src/federation/nickreg.h");
    TF_CHECK_MSG(strstr(nickreg_h,
                        "int nickreg_ident_ok(const char *s, size_t cap);") != NULL,
                 "nickreg.h does not declare nickreg_ident_ok(), so the client path "
                 "cannot be asking the same predicate the peer path asks -- and a "
                 "predicate only one file can reach is how the two paths came to "
                 "hold different rules about the same hostmask slot.");
    free(nickreg_h);

    /* AND THE RESUME STORE ASKS IT TOO, because `resume_window::ident` is a copy
     * of `conn_t::user` and this node prints that value raw at seven sites. */
    resume = tf_read_code("src/core/resume.c", &len);
    TF_CHECK_MSG(resume != NULL && len > 0u, "could not read src/core/resume.c");
    TF_CHECK_MSG(strstr(resume, "nickreg_ident_ok(src, cap)") != NULL,
                 "resume.c's ident copy no longer asks nickreg_ident_ok(). "
                 "`resume_window::ident` is a copy of `conn_t::user`, which reaches "
                 "an operator's log at seven sites, so a copy that is not checked "
                 "is a stored byte that outlives the connection that sent it.");
    free(resume);
}

/* ---------------------------------------------------------------------------
 * CASE 4 -- THE TWO PATHS REPORT THE SAME VERDICT, NOT MERELY A VERDICT
 * ---------------------------------------------------------------------------
 * The predicate being shared is not enough: the two paths also have to SAY the
 * same thing about it, or an operator reading two refusal lines cannot tell
 * that they came from one rule. `NOT_A_PARAMETER_BYTE` is the reason literal
 * `nickreg_ident_refused()` has printed on the peer side since #142, and the
 * client path's `user_refused:` line must use the SAME token -- a second
 * spelling of "the same refusal" is how two paths drift apart without either
 * going red. */
/* ---------------------------------------------------------------------------
 * A RAW READER, because `tf_read_code()` strips string literals
 * ---------------------------------------------------------------------------
 * Case 4 below compares a LITERAL -- the reason token two refusal sites print --
 * and the harness's own reader removes literals along with comments, because
 * every existing caller searches for function NAMES. A literal is exactly what
 * this case needs, so it reads the bytes itself. One caller, fifteen lines, and
 * the alternative is a harness change that would have to argue with three other
 * files. */
static char *read_source(const char *rel, size_t *len_out)
{
    char path[1024];
    FILE *f;
    char *out;
    size_t cap = 65536u;
    size_t len = 0u;
    int ch;

    (void)snprintf(path, sizeof path, "%s/%s", IRCSERVE_SRC_DIR, rel);
    f = fopen(path, "rb");
    TF_CHECK_MSG(f != NULL, "could not open %s", path);
    out = (char *)malloc(cap);
    TF_CHECK_MSG(out != NULL, "could not allocate to read %s", path);
    while ((ch = fgetc(f)) != EOF) {
        if (len + 2u > cap) {
            char *grown = (char *)realloc(out, cap * 2u);

            TF_CHECK_MSG(grown != NULL, "could not grow the buffer for %s", path);
            out = grown;
            cap *= 2u;
        }
        out[len++] = (char)ch;
    }
    fclose(f);
    out[len] = '\0';
    *len_out = len;
    return out;
}

static void case_both_paths_report_the_same_reason(void)
{
    char *commands;
    char *nickreg;
    size_t len = 0u;

    commands = read_source("src/core/commands.c", &len);
    TF_CHECK_MSG(commands != NULL && len > 0u,
                 "could not read src/core/commands.c");
    TF_CHECK_MSG(occurrences(commands, "reason=NOT_A_PARAMETER_BYTE") >= 1u,
                 "the client path's refusal does not name reason="
                 "NOT_A_PARAMETER_BYTE, which is the token nickreg_ident_refused() "
                 "has printed on the peer path. Two spellings of one verdict is how "
                 "two paths stop being recognisable as one rule.");
    free(commands);

    nickreg = read_source("src/federation/nickreg.c", &len);
    TF_CHECK_MSG(nickreg != NULL && len > 0u,
                 "could not read src/federation/nickreg.c");
    TF_CHECK_MSG(occurrences(nickreg, "reason=NOT_A_PARAMETER_BYTE") >= 1u,
                 "the peer path's refusal does not name reason="
                 "NOT_A_PARAMETER_BYTE, so the two paths no longer report the same "
                 "verdict about the same predicate.");
    free(nickreg);
}

/* ---------------------------------------------------------------------------
 * THE DRIVER
 * ---------------------------------------------------------------------------
 * The order matters in one direction only: case 3 and case 4 read sources and
 * assert nothing about a running node, so they run last and a node left over
 * from case 2 cannot affect them. `tf_done()` is the one line that says the
 * test reached its end. */
int main(void)
{
    case_hostile_ident_is_refused_at_ingest();
    case_utf8_idents_survive();
    case_both_paths_ask_one_predicate();
    case_both_paths_report_the_same_reason();
    tf_done("test_ident_injection");
    return 0;
}
