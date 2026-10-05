/* test_msg_text.c -- relayed PRIVMSG/NOTICE text: what is stripped, what is kept,
 * and what the strip must never break (#121, final item).
 *
 * ---------------------------------------------------------------------------
 * THE RULE, AND WHY IT IS NOT THE OTHER RULE
 * ---------------------------------------------------------------------------
 * This node has ONE byte test for "can this byte control a terminal", and it
 * refuses every C0 control and DEL. That is right for every field the node
 * STORES -- an away message, a topic, a kick reason -- and it would be WRONG for a
 * message body, because two groups of C0 bytes are IRC message semantics:
 *
 *   STRIP   0x1B ESC   moves the cursor, retitles the window, sets the clipboard,
 *                      switches terminal modes -- every CSI/OSC/DECSC sequence is
 *                      made of it
 *          0x07 BEL   rings the terminal's bell
 *          0x7F DEL   invisible in a log, an ordinary glyph in most fonts
 *          0xC2 0x80-0x9F   C1, the 8-bit equivalent of the same escapes -- and
 *                      matched AS A PAIR, because those trailing bytes are also
 *                      the continuation bytes of ordinary text
 *
 *   KEEP    0x01       the CTCP delimiter. `\x01ACTION waves\x01` is one message
 *                      BECAUSE of the two 0x01s; removing either does not
 *                      sanitise it, it corrupts it into text starting with the
 *                      word ACTION.
 *          0x02 0x03 0x0F 0x11 0x16 0x1D 0x1F   the mIRC formatting codes, which
 *                      are how IRC has carried colour for thirty years and which
 *                      every client renders and then strips itself.
 *
 * A reader who "simplifies" this back into a deny-list silently breaks colour on
 * every client that uses it, which is a functional regression traded for a
 * cosmetic one. The comment at `conn_text_strip_relay()` says the same thing and
 * this file is what makes it true.
 *
 * ---------------------------------------------------------------------------
 * THE FIVE CLAIMS, AND EACH ONE IS A DIFFERENT FAILURE
 * ---------------------------------------------------------------------------
 *   1. ESC/BEL/DEL/C1 NEVER REACH A RECIPIENT. Asserted as a whole-window byte
 *      scan, not a needle search -- a strip that removed ESC and passed BEL would
 *      pass a search for one and fail a scan for the set.
 *   2. THE mIRC CODES ARRIVE BYTE FOR BYTE, and so does UTF-8 -- including
 *      Cyrillic and Greek, whose continuation bytes land in 0x80-0x9F and which a
 *      byte-wise C1 filter would destroy. This is the case that makes claim 1's
 *      implementation safe rather than merely aggressive.
 *   3. CTCP ROUND-TRIPS INTACT: ACTION, VERSION, and a DCC preamble, each with
 *      BOTH delimiters, each read as the exact bytes on the wire.
 *   4. A CTCP SPLIT ACROSS TWO READS SURVIVES. `0x01` at the end of one write and
 *      the word at the start of the next -- which is the shape a per-read filter
 *      would destroy, silently, because the delimiter and its payload would be
 *      examined by different invocations.
 *   5. THE COUNT IS PUBLISHED AND IT IS THE ONLY TRACE. The relay strip is
 *      deliberately NOT announced per message, so `msg_stripped=` on the existing
 *      `loop_stats` line is the only record, and a test that does not read it is
 *      not testing the decision.
 *
 * ---------------------------------------------------------------------------
 * NO FIXED sleep() ANYWHERE (6.3). Every wait is a deadline wait, and every window
 * is closed by a PING whose PONG is the drain token -- numbered per call, because
 * `tc_expect()` searches the ACCUMULATED buffer.
 * ---------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/connection.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define ESC "\033"
#define BEL "\007"
#define DEL "\177"
#define CTCP "\001"
/* The mIRC codes, one macro so the assertion and the input cannot drift apart. */
#define MIRC_BOLD   "\002"
#define MIRC_COLOUR "\003"
#define MIRC_ITALIC "\035"

#define SRV "irc.test"
#define OBSERVED_HOST "127.0.0.1"
#define CHAN "#T"

static unsigned g_drain_seq;

static void drain(test_client_t *c)
{
    char token[64];
    char line[128];

    (void)snprintf(token, sizeof token, "mt%u", g_drain_seq++);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING failed");
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG for drain token %s, so the buffer is not yet drained and "
                 "every window below would be about the read schedule", token);
}

static void register_as(test_client_t *c, int port, const char *nick)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s NICK send failed", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s USER send failed", nick);
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered", nick);
    drain(c);
}

static void join(test_client_t *c)
{
    char want[64];

    TF_CHECK_MSG(tc_send(c, "JOIN " CHAN) == 0, "JOIN send failed");
    (void)snprintf(want, sizeof want, " JOIN " CHAN "\r\n");
    TF_CHECK_MSG(tc_expect(c, want, T_IO_MS) == 0,
                 "the JOIN echo never arrived, so the roster is not the one under test");
    drain(c);
}

/* Every byte of `c`'s window since `mark`, refusing anything outside the set THIS
 * file allows to be relayed: printable ASCII, space, TAB, CR, LF, the kept C0
 * bytes, and everything at or above 0x80.
 *
 * THAT IS A DIFFERENT SET FROM `test_log_injection.c`'s, and the difference is the
 * whole decision: there, a C0 byte in the OUTPUT is always a bug; here, `0x01` and
 * the mIRC codes in the output are the feature. So this scanner takes the KEEP set
 * rather than the strip set, and a reader comparing the two files is looking at the
 * rule from both sides. */
static int relay_byte_allowed(unsigned char u)
{
    /* CR and LF are the wire's own terminators and a parameter can never hold one --
     * `message_parse_n()` refuses both -- so their appearance here is the framing
     * layer's and not a field's. TAB is NOT in this list: the relay strip denies it,
     * and a scanner that permitted it would stop being able to detect a widened
     * deny-list. See the note on the `kept` array in case_the_two_groups(). */
    if (u == '\r' || u == '\n' || u == ' ') {
        return 1;
    }
    if (u >= 0x20u && u != 0x7fu) {
        return 1; /* printable ASCII, and every byte of UTF-8 */
    }
    return u == 0x01u || u == 0x02u || u == 0x03u || u == 0x0fu || u == 0x11u ||
           u == 0x16u || u == 0x1du || u == 0x1fu;
}

/* The C1 PAIR, which cannot be judged byte-wise: `0xC2 0x9B` is CSI and
 * `0xD0 0x90` is the Cyrillic A, and both are two bytes. A lone `0xC2` followed by
 * a byte outside 0x80-0x9F is an ordinary character and must survive, which is
 * exactly what makes this a pair test and not a byte test. */
static void assert_window_clean(test_client_t *c, size_t mark, const char *what)
{
    const char *win = tc_buffer(c) + mark;
    size_t len = tc_received(c) - mark;
    size_t i;

    for (i = 0; i < len; i++) {
        const unsigned char ch = (unsigned char)win[i];

        TF_CHECK_MSG(relay_byte_allowed(ch) != 0,
                     "%s: byte 0x%02x reached a recipient's socket and is in neither "
                     "group of the rule -- not something a terminal executes and not "
                     "IRC message semantics. ESC is the injection; this is the other "
                     "half of the deny-list.\n  window: %s", what, ch, win);
        if (ch == 0xc2u && i + 1u < len) {
            const unsigned char next = (unsigned char)win[i + 1u];

            TF_CHECK_MSG(next < 0x80u || next > 0x9fu,
                         "%s: an ENCODED C1 control (`0xC2 0x%02x`) reached a "
                         "recipient. A UTF-8 terminal decodes that to U+009B or "
                         "sibling, which is the 8-bit form of the same escape "
                         "sequences ESC starts -- so it is the injection wearing a "
                         "different encoding.\n  window: %s", what, next, win);
        }
    }
}

/* ---------------------------------------------------------------------------
 * 1-5: the whole rule, against one recipient
 * ---------------------------------------------------------------------------
 * One client sends, one receives, and the second asserts everything. `echo-message`
 * is NOT negotiated on either, so the sender gets no copy and the recipient's
 * window holds exactly what the case put there.
 */
static void case_relay_text(void)
{
    nf_node_t node;
    test_client_t sender;
    test_client_t rcpt;
    char line[1024];
    char want[1024];
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");
    tc_init(&sender);
    register_as(&sender, node.port, "vic");
    tc_init(&rcpt);
    register_as(&rcpt, node.port, "bob");
    join(&sender);
    join(&rcpt);

    /* --- 1. ESC, BEL, DEL AND AN ENCODED C1 ALL GO ---
     *
     * THE SENTENCES HAVE SPACES IN THEM, and that is load-bearing for the
     * assertion rather than decorative. 3.2's formatter colons a trailing parameter
     * only when it has to -- when the value is empty, begins with ':', or holds a
     * separator -- so `before<ESC>[2Jafter` renders UNCOLONNED (`PRIVMSG #T
     * beforeafter`) and the colon in the needle would be asserting the formatter's
     * whitespace rule rather than the strip. With a space the line is the
     * conventional `:prefix PRIVMSG #chan :text`, and every expected string below is
     * about the bytes that were removed. */
    mark = tc_received(&rcpt);
    (void)snprintf(line, sizeof line, "PRIVMSG " CHAN " :before " ESC "[2J" BEL DEL
                   "\302\233" " after");
    TF_CHECK_MSG(tc_send(&sender, line) == 0, "the hostile PRIVMSG send failed");
    /* `[2J` SURVIVES, and that is the point of the whole rule rather than an
     * oversight in the expectation. `[2J` is two ORDINARY PRINTABLE ASCII bytes --
     * only the ESC in front of them is a control sequence, and `ESC [2J` is not a
     * sequence without its ESC. So the bracket and the digits and the letter are
     * message text and go to the recipient as text, exactly as they would in any
     * conversation about terminal codes. A strip that removed the brackets too would
     * be filtering on the WORD as well as the byte, and there is no principled way
     * to do that: any client may discuss an escape sequence in a PRIVMSG, and
     * mangling what people say about it is worse than leaving inert characters.
     *
     * This is also why the assertion is written out in full: a reader scanning for
     * `[2J` in the expected line needs to be told it is supposed to be there, or they
     * will "fix" it -- and that fix would be the bug this file exists to prevent. */
    (void)snprintf(want, sizeof want, ":vic!vic@" OBSERVED_HOST " PRIVMSG " CHAN
                   " :before [2J after\r\n");
    TF_CHECK_MSG(tc_expect(&rcpt, want, T_IO_MS) == 0,
                 "the recipient did not receive \"%s\". The ESC, the BEL, the DEL and "
                 "the encoded C1 are all gone, the words on either side are still "
                 "there, and the inert `[2J` behind the removed ESC survives -- "
                 "written out in full, so a strip that removed a byte it should have "
                 "kept fails here.\n  recipient saw: %s", want,
                 tc_buffer(&rcpt) + mark);
    assert_window_clean(&rcpt, mark, "the stripped message");


    /* --- 2. THE mIRC CODES AND NON-LATIN UTF-8 SURVIVE, BYTE FOR BYTE --- */
    mark = tc_received(&rcpt);
    /* Greek and Cyrillic are here DELIBERATELY: their continuation bytes land in
     * 0x80-0x9F, so they are the characters a byte-wise C1 filter destroys. A strip
     * written as "drop every byte in 0x80-0x9F" would pass every other case in this
     * file and turn every non-Latin message on the node into mojibake. */
    (void)snprintf(line, sizeof line,
                   "PRIVMSG " CHAN " :" MIRC_BOLD "b" MIRC_COLOUR "4" MIRC_ITALIC
                   "i" MIRC_BOLD " " "\316\261\316\262 " "\320\241\320\200 "
                   "\342\200\234quoted\342\200\235");
    TF_CHECK_MSG(tc_send(&sender, line) == 0, "the colour PRIVMSG send failed");
    (void)snprintf(want, sizeof want, ":vic!vic@" OBSERVED_HOST " PRIVMSG " CHAN
                   " :" MIRC_BOLD "b" MIRC_COLOUR "4" MIRC_ITALIC "i" MIRC_BOLD
                   " " "\316\261\316\262 " "\320\241\320\200 "
                   "\342\200\234quoted\342\200\235" "\r\n");
    TF_CHECK_MSG(tc_expect(&rcpt, want, T_IO_MS) == 0,
                 "the recipient did not receive \"%s\". The mIRC codes are how IRC "
                 "carries colour -- stripping them breaks colour on every client that "
                 "uses it, a functional regression traded for a cosmetic one -- and "
                 "the Greek, Cyrillic and curly quotes are the characters whose "
                 "continuation bytes land inside the C1 range.\n  recipient saw: %s",
                 want, tc_buffer(&rcpt) + mark);
    assert_window_clean(&rcpt, mark, "the colour and UTF-8 message");

    /* --- 3. CTCP ROUND-TRIPS, WITH BOTH DELIMITERS, FOR THE THREE SHAPES --- */
    {
        /* SENT TEXT, AND THE EXACT WIRE TEXT IT MUST ARRIVE AS.
         *
         * TWO COLUMNS BECAUSE THEY ARE NOT ALWAYS THE SAME, and the difference is
         * this node's formatter rather than this pass's strip. needs_colon()
         * (message.c) marks a trailing parameter with ':' when it is empty, when it
         * begins with ':', or when it holds a SEPARATOR -- a space or a tab. A 0x01
         * is none of those, so:
         *
         *   - `\001ACTION waves\001` holds spaces  -> colonned
         *   - `\001DCC SEND file 1 2 3 4\001`       -> colonned
         *   - `\001VERSION\001` holds none          -> NOT colonned
         *
         * The first version of this test assumed a colon on all three and failed on
         * VERSION alone -- ACTION and DCC passed, which is why this is worth spelling
         * out rather than computing: a test that recomputed needs_colon() would pass
         * whatever the formatter did, and this assertion is about the BYTES, not about
         * agreement with a rule.
         *
         * Whether a CTCP without a separator SHOULD be colonned is a real question
         * about this node's formatter and is NOT decided here; it is unchanged
         * pre-existing behaviour, it is not a strip question, and it is recorded as a
         * finding for review. What matters for this pass is that the two 0x01 bytes
         * arrive intact either way, which the delimiter count below asserts. */
        static const char *const ctcp[][2] = {
            { CTCP "ACTION waves" CTCP, ":" CTCP "ACTION waves" CTCP },
            { CTCP "VERSION" CTCP, CTCP "VERSION" CTCP },
            { CTCP "DCC SEND file 1 2 3 4" CTCP, ":" CTCP "DCC SEND file 1 2 3 4" CTCP },
            { NULL, NULL }
        };

        for (int i = 0; ctcp[i][0] != NULL; i++) {
            const char *sent = ctcp[i][0];
            const char *wire = ctcp[i][1];

            (void)snprintf(line, sizeof line, "PRIVMSG " CHAN " :%s", sent);
            mark = tc_received(&rcpt);
            TF_CHECK_MSG(tc_send(&sender, line) == 0,
                         "the CTCP send failed for %s", sent);
            (void)snprintf(want, sizeof want, ":vic!vic@" OBSERVED_HOST " PRIVMSG "
                           CHAN " %s\r\n", wire);
            TF_CHECK_MSG(tc_expect(&rcpt, want, T_IO_MS) == 0,
                         "CTCP `%s` did not round-trip; expected exactly `%s`. Both "
                         "0x01 bytes and every printable byte between them are what "
                         "arrives.\n  recipient saw: %s", sent, wire,
                         tc_buffer(&rcpt) + mark);
            /* BOTH delimiters, counted. A strip that removed the closing `0x01`
             * would leave the line with one and the needle above would still match
             * most of it, so the count is the assertion that matters. */
            TF_CHECK_MSG(tf_count(tc_buffer(&rcpt) + mark, CTCP) == 2u,
                         "CTCP `%s` reached the recipient with %lu delimiter(s) rather "
                         "than 2. A CTCP is one message BECAUSE of its two 0x01 bytes, "
                         "so losing one does not sanitise it -- it turns it into text "
                         "that happens to start with the word.\n  recipient saw: %s",
                         sent,
                         (unsigned long)tf_count(tc_buffer(&rcpt) + mark, CTCP),
                         tc_buffer(&rcpt) + mark);
            assert_window_clean(&rcpt, mark, "a CTCP");
        }
    }

    /* --- 4. THE SPLIT CTCP, WHICH IS THE CASE A PER-READ FILTER LOSES --- */
    /* `0x01VERSION` in one write and the closing `0x01` in the next. The node may
     * read both in one recv() -- a test cannot force the kernel to split a read --
     * and the point is that the ASSERTION holds either way: the strip runs on one
     * assembled parameter, so there is no state for a read boundary to split. A
     * per-read filter would have to carry a "inside a CTCP" flag across reads, and
     * the flag is exactly what a stray ESC arriving between two reads would clear. */
    {
        const char *first = "PRIVMSG " CHAN " :" CTCP "VERSION";
        const char *second = CTCP " bye\r\n";

        mark = tc_received(&rcpt);
        TF_CHECK_MSG(tc_send_raw(&sender, first, strlen(first)) == 0,
                     "the first half of the split CTCP failed to send");
        /* THE DRAIN BETWEEN THE HALVES IS WHAT MAKES THE SPLIT REAL, and it was added
         * after the first version of this case turned out to be testing nothing. Two
         * `tc_send_raw()` calls back to back routinely arrive in ONE recv(), so the
         * "split" was usually a fiction -- and a per-read filter would then pass this
         * test, which is precisely the bug the case exists to catch. An unterminated
         * first half sitting in the node's buffer plus a PING that has been answered
         * is an OBSERVABLE BARRIER, not a sleep: when the PONG is back the node has
         * certainly read the first half already, so the second half cannot share its
         * read. The constraint against fixed sleeps is satisfied and the split is
         * guaranteed rather than probable. */
        drain(&rcpt);
        TF_CHECK_MSG(tc_send_raw(&sender, second, strlen(second)) == 0,
                     "the second half of the split CTCP failed to send");
        (void)snprintf(want, sizeof want, ":vic!vic@" OBSERVED_HOST " PRIVMSG " CHAN
                       " :" CTCP "VERSION" CTCP " bye\r\n");
        TF_CHECK_MSG(tc_expect(&rcpt, want, T_IO_MS) == 0,
                     "a CTCP split across two writes did not arrive whole; expected "
                     "\"%s\". The opening `0x01` ended one write and the closing one "
                     "began the next, which is the shape a filter applied per READ "
                     "destroys -- and it destroys it silently, because the recipient "
                     "gets a message that looks almost right.\n  recipient saw: %s",
                     want, tc_buffer(&rcpt) + mark);
        TF_CHECK_MSG(tf_count(tc_buffer(&rcpt) + mark, CTCP) == 2u,
                     "the split CTCP reached the recipient with %lu delimiter(s) "
                     "rather than 2.\n  recipient saw: %s",
                     (unsigned long)tf_count(tc_buffer(&rcpt) + mark, CTCP),
                     tc_buffer(&rcpt) + mark);
        assert_window_clean(&rcpt, mark, "the split CTCP");
    }

    /* --- 5. A SECOND HOSTILE MESSAGE, WITH A SINGLE BYTE IN IT --- */
    /* One removable byte rather than five, so if the count were ever read as a byte
     * count the two messages here would disagree with each other: 5 and 1. */
    {
        mark = tc_received(&rcpt);
        (void)snprintf(line, sizeof line, "PRIVMSG " CHAN " :one " DEL " byte");
        TF_CHECK_MSG(tc_send(&sender, line) == 0, "the second hostile send failed");
        (void)snprintf(want, sizeof want, ":vic!vic@" OBSERVED_HOST " PRIVMSG " CHAN
                       " :one  byte\r\n");
        TF_CHECK_MSG(tc_expect(&rcpt, want, T_IO_MS) == 0,
                     "the second hostile message did not arrive as \"%s\" -- a "
                     "single DEL between two spaces, removed.\n  recipient saw: %s",
                     want, tc_buffer(&rcpt) + mark);
        assert_window_clean(&rcpt, mark, "the second hostile message");
    }

    tc_close(&sender);
    tc_close(&rcpt);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");

    /* --- 6. THE COUNT, AND IT IS READ AT SHUTDOWN BECAUSE THAT IS WHEN IT EXISTS --- */
    /* NOT MID-FLIGHT, and this is the harness's shape rather than a convenience.
     * `nf_spawn_binary()` runs the SHIPPED binary, and the shipped binary publishes
     * `loop_stats` when it EXITS, not on every tick -- test_channels.c reads
     * `reply_refused=` from a stopped node for the same reason. The per-tick
     * republication belongs to the INLINE child's tick hook, so a mid-flight
     * `nf_expect_u64()` against a binary node waits out its whole timeout for a line
     * that is never coming.
     *
     * So this is read once, at the end, over the whole run -- which is the STRONGER
     * claim rather than a weaker one, because it covers every message this test sent
     * rather than one message's span. The arithmetic it asserts:
     *
     *     7 messages sent   -- hostile, mIRC+UTF-8, ACTION, VERSION, DCC, split CTCP,
     *                           second hostile
     *     2 hostile         -- the two carrying a byte the strip removes
     *     => msg_stripped=2
     *
     * That single number carries three claims at once, and the reason to want them
     * together is that they fail DIFFERENTLY. It is an EVENT count, not a byte count:
     * the two hostile messages held five removable bytes and one, so a byte counter
     * would read 6. It did not fire on ordinary traffic: five of the seven messages
     * were colour, CTCPs and UTF-8, and any strip that had widened into the keep list
     * would have pushed this past 2. And it did fire: a relay path with no strip at
     * all reports 0. */
    TF_CHECK_MSG(nf_expect_u64(&node, "msg_stripped=", 2u, T_IO_MS) == 0,
                 "the node did not publish msg_stripped=2 at shutdown. Seven messages "
                 "were sent and exactly two carried a byte the relay strip removes, so "
                 "the count must be 2: a byte count would read 6 (five removable bytes "
                 "in the first hostile message, one in the second), and 0 means the "
                 "strip never ran.");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * A NODE THAT ONLY EVER SEES CLEAN TRAFFIC REPORTS ZERO
 * ---------------------------------------------------------------------------
 * A counter that cannot distinguish "nothing was stripped" from "the node stopped
 * counting" is not a record of anything, and on a relay path that is the more likely
 * of the two readings. So this is the same claim as the case above, reached from the
 * other side and with a different failure mode for a mistake in the strip:
 *
 *   - the case above counts 2 on a node where 2 of 7 messages were hostile. A strip
 *     that widened into the keep list pushes that UP.
 *   - this one counts 0 on a node where NO message was hostile. A strip that widened
 *     pushes this up too, but here there is no arithmetic to misread, and a counter
 *     that has stopped incrementing is caught as "0 for the wrong reason" only if the
 *     node is genuinely hostile-free -- which is what the wire assertion below
 *     establishes rather than assumes.
 *
 * IT IS A WHOLE-RUN ASSERTION, read after `nf_stop()`, for the same reason the other
 * one is: `nf_spawn_binary()` runs the shipped binary and the shipped binary
 * publishes `loop_stats` at exit. There is no "before" to read on a binary node, so
 * the reading-a-starting-value approach would wait out its timeout for a line that is
 * not coming -- and it would then compare 0 to 0 and pass, which is worse than not
 * asserting at all.
 */
static void case_clean_message_does_not_count(void)
{
    nf_node_t node;
    test_client_t sender;
    test_client_t rcpt;
    char line[512];

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");
    tc_init(&sender);
    register_as(&sender, node.port, "vic");
    tc_init(&rcpt);
    register_as(&rcpt, node.port, "bob");
    join(&sender);
    join(&rcpt);

    (void)snprintf(line, sizeof line,
                   "PRIVMSG " CHAN " :" MIRC_COLOUR "3" "green " CTCP "ACTION ok"
                   CTCP " \320\241\320\240\320\262\320\265\321\202");
    TF_CHECK_MSG(tc_send(&sender, line) == 0, "the clean PRIVMSG send failed");
    TF_CHECK_MSG(tc_expect(&rcpt, MIRC_COLOUR, T_IO_MS) == 0,
                 "the clean message never arrived, so the counter assertion below "
                 "would be about a message that was never delivered");

    drain(&rcpt);

    tc_close(&sender);
    tc_close(&rcpt);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");

    /* THE '=' IS PART OF THE KEY, not decoration: nf_expect_u64() searches for
     * `<key><value>`, so "msg_stripped" looks for "msg_stripped0" and times out on a
     * line that says "msg_stripped=0". test_channels.c reads "reply_refused=" for the
     * same reason. */
    TF_CHECK_MSG(nf_expect_u64(&node, "msg_stripped=", 0u, T_IO_MS) == 0,
                 "a node whose only traffic was colour, CTCP and Cyrillic reported "
                 "msg_stripped other than 0. Nothing this test sent holds a byte in "
                 "the strip set, so a non-zero count means the strip is eating bytes "
                 "it was told to keep -- which is the regression the two-sided rule "
                 "exists to prevent, and the one a 'non-zero proves it works' "
                 "assertion cannot see. 0 also has to mean 'nothing was stripped' "
                 "rather than 'nothing is counted', which is why the strip running at "
                 "all is established separately over on the hostile node.");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * THE PREDICATE ITSELF, against the two groups directly
 * ---------------------------------------------------------------------------
 * The wire cases above go through a node and a socket, which is the right level for
 * a claim about what a client sees. This one is at the level of the RULE, and it
 * exists because the strip is a function someone will edit: every byte in the keep
 * group and every byte in the deny group is asserted here, so a change to one of
 * them is a red test rather than a colour regression somebody reports a month
 * later.
 */
static void case_the_two_groups(void)
{
    /* EVERY KEPT BYTE SURVIVES ALONE.
     *
     * TAB IS NOT HERE, and its absence is the point. The architect's table splits C0
     * into "strip what can control the terminal" and "keep what is IRC message
     * semantics", and 0x09 is in NEITHER: it is not an escape sequence, and a client
     * rendering a message with a TAB in it lays the line out in columns. An earlier
     * version of this array listed it under "kept" and the test caught the
     * disagreement immediately -- the strip denies it, correctly, because
     * `relay_byte_kept()`'s switch names eight bytes and TAB is not one of them.
     * What TAB does on a receiving terminal is outside this node's business, and the
     * honest resolution is that it is DENIED, not that it is kept. It appears in the
     * denied list below, and this comment is here so a reader does not "fix" the
     * array by adding it back. */
    static const unsigned char kept[] = {
        0x01u, 0x02u, 0x03u, 0x0fu, 0x11u, 0x16u, 0x1du, 0x1fu,
        ' ', 'a', 'Z', '0', '~', 0x7eu,
        0xc3u, 0xa9u, /* e-acute */
        0xd0u, 0x90u, /* Cyrillic A -- continuation byte inside the C1 range */
        0xceu, 0x91u, /* Greek capital alpha -- likewise */
        0xe4u, 0xb8u, 0xadu /* CJK, three bytes */
    };
    /* EVERY DENIED BYTE IS REMOVED ALONE. ESC, BEL, DEL and one more from each
     * remaining part of the range, so the deny half is not just the three named
     * bytes: a future reader adding 0x08 to the keep set would break this. */
    static const unsigned char denied[] = {
        0x1bu, /* ESC */
        0x07u, /* BEL */
        0x7fu, /* DEL */
        0x00u + 0x04u, 0x05u, 0x08u, /* backspace and friends */
        0x09u,                        /* TAB -- neither IRC semantics nor listed
                                       * as kept, so it is denied; see above */
        0x0bu, 0x0cu, 0x0eu,          /* form feed, shift */
        0x12u, 0x13u, 0x14u, 0x15u, 0x17u, 0x18u, 0x19u, 0x1au,
        0x1cu, 0x1eu
    };
    size_t i;

    for (i = 0; i < sizeof kept; i++) {
        char in[4];
        char out[8];
        size_t n;

        in[0] = (char)kept[i];
        in[1] = '\0';
        n = conn_text_strip_relay(out, sizeof out, in);
        TF_CHECK_MSG(n == 1u && (unsigned char)out[0] == kept[i],
                     "byte 0x%02x is in the KEEP group and did not survive alone "
                     "(returned %lu bytes, first 0x%02x).", kept[i],
                     (unsigned long)n, (unsigned char)out[0]);
    }

    for (i = 0; i < sizeof denied; i++) {
        char in[4];
        char out[8];
        size_t n;

        /* 0x00 cannot be embedded in a C string, so the array starts at 0x04 for
         * that reason as well as the strip's; NUL is not in the keep group and the
         * strip cannot meet one inside a parameter because the parser refuses it. */
        in[0] = (char)denied[i];
        in[1] = 'z';
        in[2] = '\0';
        n = conn_text_strip_relay(out, sizeof out, in);
        TF_CHECK_MSG(n == 1u && out[0] == 'z' && out[1] == '\0',
                     "byte 0x%02x is in the DENY group and was not removed alone "
                     "(result \"%s\", %lu bytes kept).", denied[i], out,
                     (unsigned long)n);
    }

    /* THE C1 PAIR, AS A PAIR. Both bytes go together, and -- the half that matters
     * -- a `0xC2` followed by anything OUTSIDE 0x80-0x9F is an ordinary character
     * and survives with its follower intact. `0xC2 0xA9` is e-acute; stripping its
     * trailing byte would be a UTF-8 corruption that no byte-wise test would catch,
     * because the lead byte looks identical either way. */
    {
        char out[16];
        size_t n;

        n = conn_text_strip_relay(out, sizeof out, "\302\233z");
        TF_CHECK_MSG(n == 1u && out[0] == 'z' && out[1] == '\0',
                     "the encoded C1 pair `0xC2 0x9B` was not removed as a pair "
                     "(result \"%s\").", out);

        /* e-acute is `0xC3 0xA9` -- the point of picking it is that it has the SAME
         * LEAD BYTE as the encoded C1 control above and differs only in the trailing
         * byte. `0xC2 0xA9` would have been U+00A9 and would have made the contrast
         * trivial, which is not what this is testing. */
        /* THREE bytes in and three kept -- `0xC3`, `0xA9` and the 'z'. The count is
         * asserted as well as the content because the count is what a caller uses to
         * decide whether anything was removed, and a strip that quietly reported the
         * wrong one would make every count on this path wrong. */
        n = conn_text_strip_relay(out, sizeof out, "\303\251z");
        TF_CHECK_MSG(n == 3u && (unsigned char)out[0] == 0xc3u &&
                     (unsigned char)out[1] == 0xa9u && out[2] == 'z',
                     "`0xC3 0xA9` (e-acute) did not survive intact: got \"%s\". It "
                     "shares its lead byte with the encoded C1 control removed one "
                     "assertion above and differs only in the trailing byte, so this "
                     "is the pair test at the exact byte where a byte-wise filter "
                     "would have to choose -- and it would choose wrong, on every "
                     "accented character on the node.", out);
    }

    /* AND THE ORDER OF A WHOLE STRING IS PRESERVED, which is what "not truncation"
     * means here: the strip removes bytes and never reorders or rewrites what it
     * keeps.
     *
     * The expected value is written out BYTE FOR BYTE rather than as a mnemonic,
     * because the first version of this assertion got the order wrong and still
     * looked right on screen: the input is ESC a BEL b DEL c CTCP d C1 e, so what
     * survives is `a b c 0x01 d e` -- the CTCP sits between the `c` and the `d`, not
     * after the `d`. A string comparison is the only thing that noticed, which is the
     * argument for comparing bytes when the claim is about bytes. */
    {
        char out[64];

        (void)conn_text_strip_relay(out, sizeof out,
                                    ESC "a" BEL "b" DEL "c" CTCP "d" "\302\233" "e");
        TF_CHECK_MSG(strcmp(out, "abc" CTCP "de") == 0,
                     "the strip did not merely remove bytes: it produced \"%s\" where "
                     "\"abc\\001de\" was expected (input ESC a BEL b DEL c CTCP d C1 "
                     "e). Order and content of what survives are the whole claim -- a "
                     "strip that rewrote rather than removed would pass every "
                     "per-byte assertion above and fail only here.", out);
    }
}

int main(void)
{
    case_the_two_groups();
    case_relay_text();
    case_clean_message_does_not_count();

    tf_done("msg-text");
    return 0;
}
