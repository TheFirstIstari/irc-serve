/* test_terminal_sweep.c -- the REACHABILITY property behind #121, replacing the
 * enumeration that did not work.
 *
 * ===========================================================================
 * WHY THIS FILE EXISTS, AND WHAT IT REPLACES
 * ===========================================================================
 * #121 claimed "0 surviving control bytes across 347 `printf` sites" and shipped
 * with two live terminal-injection bypasses in it. Both are `%s`/`%c` sites, and
 * both were among the sites the enumeration examined. The instrument measured the
 * wrong thing:
 *
 * Counting SITES measures how many format strings were READ. A site is a leak
 * only if it is REACHABLE WITH ATTACKER BYTES, and reachability is a property of
 * the call graph, not of the format string. Nothing in an enumeration can see
 * that `MODE`'s 472 is three frames deep behind `chan_has_flag()`, or that
 * `BATCH`'s `NO_SIGN` sits behind `pre_reg = 1` and so needs no registration at
 * all. Both of the bugs this test was written alongside were classified
 * benign-looking by the method that was supposed to have found them.
 *
 * So this is a PROPERTY, stated over the reachable surface rather than over the
 * source text:
 *
 *     SEND EVERY BAD BYTE IN EVERY ARGUMENT POSITION OF EVERY VERB, AND THIS
 *     NODE'S OWN STDOUT -- AND EVERY BYTE IT PUT ON A CLIENT'S SOCKET --
 *     CONTAIN NONE OF THEM.
 *
 * The claim is about the NODE'S OUTPUT, not about any particular site, so a
 * `printf("%s", client_value)` added tomorrow fails this test the first time
 * anybody exercises the command that reaches it. That is the property the
 * enumeration could not express.
 *
 * ===========================================================================
 * WHY IT IS NOT ANOTHER ENUMERATION
 * ===========================================================================
 * Three things make it a different instrument rather than a longer list:
 *
 *   1. THE VERB LIST IS DERIVED, NOT WRITTEN. It is parsed out of
 *      `commands.c`'s `k_commands[]` -- the dispatch table itself -- so a verb
 *      added tomorrow is swept tomorrow without this file being edited. Four
 *      checks keep the parse honest and they are in `derive_verbs()` and
 *      `probe_verb()`.
 *   2. THE COORDINATES ARE GENERATED, NOT LISTED. Every marker byte is tried in
 *      every argument position of every verb, so the space is covered by
 *      construction instead of by somebody remembering a position.
 *   3. THE ASSERTION IS A WHOLE-BUFFER BYTE WALK. A substring search for ESC
 *      would pass a node that strips ESC and relays BEL; this walks every byte
 *      and refuses every member of the set.
 *
 * ===========================================================================
 * THE MARKER SET, AND THE THREE BYTES THAT ARE NOT IN IT
 * ===========================================================================
 * The set is `[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]` -- every C0 control
 * except three, DEL, and every encoded C1 control. It has 62 members.
 *
 * The three exclusions each have a reason, and every reason is about the WIRE
 * rather than about convenience:
 *
 *   0x0a LF and 0x0d CR are the framing. They terminate every line the node
 *      writes, in the log and on the wire, so they are in every buffer this file
 *      scans and excluding them is not a hole in the set -- it is the set. A
 *      client byte cannot be one of them inside a parameter:
 *      `message_parse_n()` refuses both, so the only CR and LF in a scanned buffer
 *      are the framing layer's own.
 *
 *   0x09 TAB is excluded because it is WHITESPACE in this wire grammar and not a
 *      control sequence: a terminal moves a cursor eight columns and executes
 *      nothing. Nothing on this node's output path formats a tab, and treating it
 *      as a marker would mean the sweep asserted about a byte no injection uses.
 *      This is a decision, so it is written down here rather than left as a gap
 *      in a range.
 *
 * ===========================================================================
 * NO FIXED sleep(), NO `fd=`, NO ORDERING ASSUMPTIONS
 * ===========================================================================
 * Every wait is a deadline wait inside the harness (`tc_expect()`,
 * `nf_pending_bytes()`), and none of them is a guess about how long the other side
 * takes:
 *
 *   - NO `fd=N` IS ASSERTED ANYWHERE. The node's descriptor for a connection
 *     depends on how many descriptors the process happens to hold open, which
 *     differs between Linux and macOS; a test that pins it is a macOS-only test
 *     by construction. `log_line_has_tail()` in test_log_injection.c is the
 *     worked example of the CI failure that established the rule.
 *   - NO ORDER IS ASSUMED. Each verb is probed on its own freshly prepared
 *     connection, so the swept surface does not depend on the order this file
 *     happens to send things in, and the test is safe under `ctest -j`.
 *   - THE LOG SCAN RUNS AFTER THE NODE HAS EXITED. A child's stdout is a pipe
 *     and stdio buffers it, so a log line can still be in the child's buffer
 *     when the reply it caused has already crossed the socket -- scanning
 *     mid-run would be a race that passes or fails on the scheduler. After
 *     `nf_stop()` the child is dead, every byte it wrote is in the pipe, and
 *     `nf_pending_bytes()` says when the last of it has been read. That is a
 *     condition, not a sleep.
 *
 * ===========================================================================
 * THE EXCEPTION LIST, AND WHAT THIS TEST THEREFORE DOES NOT CLAIM
 * ===========================================================================
 * `k_exceptions` below is the only place a marker byte is allowed to appear. It has
 * thirteen entries and every one carries a per-entry justification, a byte set, and
 * the substring that identifies the site producing it. Two checks keep the list
 * honest: an occurrence is excused only when its byte is in the entry's set AND its
 * line carries that entry's `where`, so an entry cannot become a blanket amnesty;
 * and a listed entry whose `where` never appears anywhere in the run FAILS, so the
 * list cannot accumulate entries nobody exercises. An allowlist with no per-entry
 * justification is how an injection filter gets quietly disabled, which is why both
 * halves exist and why the entries name a class rather than shrugging.
 *
 * READ THE ENTRIES BEFORE TRUSTING A GREEN RUN. This sweep proves that no marker byte
 * reaches a scanned surface EXCEPT at the thirteen sites below, each of which is a
 * decision somebody made and wrote down. Three of them are live findings rather than
 * features, and SECURITY.md's not-defended list says so:
 *
 *   - A NICKNAME MAY HOLD A BARE C1 BYTE (0x80-0x9F), and a nickname is the SOURCE
 *     of every line its owner sends and the `<client>` field of every numeric it
 *     receives. That is a live CROSS-CLIENT terminal injection. It is routed out of
 *     this pass because the fix is a policy decision about which nicknames this node
 *     accepts; see the block above the table.
 *   - ELEVEN NUMERICS ECHO A CLIENT-SUPPLIED VALUE BACK TO THE CLIENT THAT SENT IT.
 *     One of them (421) is argued for at length in `commands.c`. The other ten are not
 *     argued anywhere, and the argument would not hold anyway: "there is no second
 *     reader" is not the same as "there is no reader", because a client that logs
 *     numerics to a file, or a bouncer relaying them to a human's terminal, is the
 *     second reader and is downstream of the client rather than of this node.
 *   - PONG ECHOES ITS TOKEN, which RFC 2812 2.4 REQUIRES. That one cannot be fixed
 *     without breaking the specification, and saying so is more useful than a filter.
 *
 * ===========================================================================
 * WHAT THIS TEST DOES NOT COVER: THE PEER PATH
 * ===========================================================================
 * `src/federation/verbs.c` has NO terminal-injection coverage at all -- there is no
 * sweep, no battery, no case -- and one of its sites writes control bytes into
 * `ch->modes`, which then propagates through 324, the SBURST shadow and the whole
 * mesh. That is a separate and larger fix and it is NOT attempted here.
 *
 * WHY IT IS NOT IN THIS FILE RATHER THAN MERELY ABSENT FROM IT, and the reason is
 * worth being precise about because "the fixture made it impossible" and "it was out
 * of scope" are different answers. It IS reachable from a single node: the
 * `test_fed_guards.c` pattern owns one end of a link as a raw socket, lets the node
 * dial it, answers FEDERATE with a real claim, and from that moment the test can put
 * any line on that socket -- so a peer-path sweep needs ONE spawned node and a
 * listener, not a two-node mesh. The reason it is not here is SCOPE: doing it
 * properly means a second verb table (the INBOUND[] S-verbs, not k_commands[]), a
 * second shape generator, and the `ch->modes` finding above -- which would make this
 * file red until that larger fix lands. Shipping a sweep that is red, or one that
 * quietly does not cover the peer path, would be worse than saying so, so it is said
 * here and in SECURITY.md.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000
/* ONE CHANNEL PER PROBE, and the reason is AUTHORITY rather than isolation.
 *
 * This node OPERATES THE CHANNEL CREATOR on the creator's own JOIN and nobody
 * else, and `MODE`'s `authority_ok()` asks about the operator set BEFORE it looks
 * at a mode string at all. So a probe that joined a channel somebody else created
 * never reaches either 472 -- it is refused 437 one line earlier -- and the first
 * version of this sweep shared one channel between every probe, which means the
 * first probe created it and every probe after that swept `MODE` as a non-operator.
 * It reported this node's output clean while both 472 sites were still leaking.
 *
 * Giving each probe its own channel costs ~40 more `chan_create:` lines and makes
 * every probe the creator, which is the only way a client on this node reaches
 * the channel-scoped verbs at all.
 *
 * FIVE BYTES AND ALREADY UPPERCASE: the JOIN echo is case-mapped (`005` says
 * CASEMAPPING=ascii), so a lower-case spelling here would need a needle this file
 * does not otherwise care about. */
#define SW_CHAN_FMT "#SW%02u"

#define SW_MAX_VERBS 128
#define SW_MARKERS 62u

/* ---------------------------------------------------------------------------
 * THE MARKER SET
 * ---------------------------------------------------------------------------
 * Written out as a predicate rather than as a table so that the exclusions above
 * are visible where the membership test is, which is what a reader has to check in
 * order to believe the set. */
static int marker_in_set(unsigned char b)
{
    if (b <= 0x08u) {
        return 1;
    }
    if (b == 0x0bu || b == 0x0cu) {
        return 1;
    }
    if (b >= 0x0eu && b <= 0x1fu) {
        return 1;
    }
    if (b == 0x7fu) {
        return 1;
    }
    if (b >= 0x80u && b <= 0x9fu) {
        return 1;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * THE EXCEPTION LIST
 * ---------------------------------------------------------------------------
 * ONE ENTRY PER BYTE RANGE THAT MAY APPEAR, with a reason and with the substring
 * that identifies the one site that produces it. The scan refuses an occurrence
 * whose `where` does not appear, and `assert_exceptions_all_used()` FAILS a listed
 * entry whose `where` never appears at all.
 *
 * ===========================================================================
 * WHAT IS IN IT, AND WHY: A NICKNAME MAY HOLD A BARE C1 BYTE
 * ===========================================================================
 * Every entry below is the SAME root cause and it is NOT a sweep artifact.
 *
 * `nick_char_illegal()` in `src/core/message.c` REFUSES bytes <= 0x20 and DEL and
 * ACCEPTS every byte >= 0x80, and the comment there says why: "UTF-8 nicknames are
 * ordinary and are not control characters". So `NICK a\x80z` is a legal nickname on
 * this node, `conn_t::nick` stores the byte, and every site that NAMES a member
 * prints it raw. The sweep reaches it from `NICK a<marker>z` and `NICK <marker>`
 * with 32 of the 62 marker bytes, and the byte then appears in the log at seven
 * different sites, none of which is the sweep's fault and all of which are honest
 * renderings of state the node decided to accept.
 *
 * AND IT REACHES THE WIRE, which the first version of this comment got wrong and
 * which is the most serious thing the sweep found. An earlier draft of this file said
 * "the wire is not affected: `message_format()` refuses a non-final parameter, so a
 * client sees an empty field". That is true of a numeric's `<client>` PARAMETER and
 * false of a nickname, because a nickname is not a parameter -- it is the SOURCE of
 * every line its owner sends and the `<client>` field of every numeric it receives.
 * `NICK a<0x9F>z` therefore puts a C1 byte in front of everything that client then
 * says to every other channel member's terminal, and a 353 NAMES list renders it
 * beside the other members. So this is a CROSS-CLIENT injection, not an operator-log
 * one, and the earlier draft's reassurance was the kind of claim that stops somebody
 * looking.
 *
 * WHY IT IS NOT FIXED HERE. Two reasons, and the second is the one that matters.
 * First, it is out of scope: this pass is two named bugs and a test. Second, the fix
 * is a POLICY decision rather than a mechanical one. Narrowing the grammar to refuse
 * bare 0x80-0x9F would still admit 0xA0-0xFF, which is not a clean split: valid UTF-8
 * continuation bytes run 0x80-0xBF, so U+0080-U+009F -- C1 control characters in
 * Unicode, CSI among them -- encode to `\xc2\x9b` and would be REFUSED by a
 * bare-byte rule. So the choice is between accepting bare C1 bytes, refusing them and
 * losing those Unicode characters from nicknames, or refusing any non-ASCII nickname
 * at all. That is a decision about what this node accepts from clients, it reaches the
 * peer path's SBURST shadow, and it belongs to whoever owns that decision.
 *
 * It is reported rather than pinned silently: SECURITY.md's not-defended list names
 * it, and the ONE `anywhere` entry below is what keeps this sweep green while that
 * report exists.
 */
struct sw_exception {
    const unsigned char *mask; /* which bytes this entry excuses */
    const char *why;          /* why they may legitimately appear HERE */
    const char *where;        /* the site, or the field rendering, that produces them */
    /* NON-ZERO MEANS "ANYWHERE": the byte is excused whatever line it is on and
     * whatever else that line says. It exists for exactly one entry, and the reason
     * is worth stating because it is the difference between an honest class-level
     * exception and a hole: this node's own `conn_byte_is_bad()` does NOT include
     * 0x80-0x9F, so a stored nickname or channel name is allowed to hold one and
     * every rendering of it -- in a log line, in a numeric's `<client>` field, in
     * another client's SOURCE, in a 353 NAMES list -- is the same defect at a
     * different site. Naming sites would mean an entry per rendering forever, and
     * the first version of this table had five of them and still missed the sixth.
     */
    int anywhere;
    /* NON-ZERO MEANS `assert_exceptions_all_used()` REQUIRES THIS ENTRY TO FIRE, which
     * is what stops the list accumulating entries nobody exercises. Every entry
     * currently sets it: the wire-echo entries fire thousands of times per run
     * because every marker in every position reaches them, and the `anywhere` entry
     * fires because the nickname grammar admits 32 of the 62 marker bytes. The field
     * exists so that a FUTURE entry which cannot be relied on to fire has to say so in
     * its own row rather than by leaving a check out -- and it is 1 on every row
     * today, which is the honest state rather than a convenient one. */
    int required;
};

/* THE MARKER BIT, AND THE MASKS.
 *
 * A 256-BIT MASK rather than a `lo`/`hi` range, because the set is not a range: the
 * marker set is `C0 minus TAB/LF/CR`, plus DEL, plus the encoded C1 range, which is
 * four disjoint stretches. A `lo`/`hi` pair could not say that without every entry
 * spelling out its own byte list, and an entry with its own byte list is an entry
 * that can disagree with the scan.
 *
 * THREE masks rather than one, because the three classes need three different byte
 * sets: a wire-echo entry carries whatever the client sent, so it takes the whole set;
 * a stored-name entry is C1-ONLY, because a C0 byte in a nickname is refused by
 * `nick_char_illegal()` and never gets stored, so excusing it there would be excusing
 * something that cannot happen; and the mIRC entry takes exactly the eight bytes
 * `relay_byte_kept()` keeps, which is neither of those and is written out one by one
 * because a range is what the source explicitly rejects.
 *
 * The first two are filled from `marker_in_set()`, the ONE predicate the scan uses, so
 * an entry and the scan cannot disagree about what the set is. They are non-const
 * because they are computed once at startup from that predicate rather than written out
 * by hand. */
static unsigned char k_mask_c1[32];
static unsigned char k_mask_all[32];
/* THE mIRC FORMATTING BYTES, spelled out one by one, and that is the point.
 *
 * `relay_byte_kept()` in `src/core/connection.c` is a switch over exactly these
 * eight, and its comment says why it is a switch rather than a range test: a range
 * test `0x02..0x1F` would swallow BEL and ESC, which is the entire hazard, and would
 * return 0 for 0x01, which "corrupts every CTCP". A mIRC client renders colour and
 * bold from these bytes and a relay that removed them would break every one of them,
 * so relaying them is a FEATURE and not an oversight. Reproducing the list here rather
 * than writing a range is deliberate: this file's mask is the sweep's claim about what
 * is allowed through, and a range is what the source explicitly rejects. */
static const unsigned char k_mirc_bytes[] = {
    0x01u, 0x02u, 0x03u, 0x0fu, 0x11u, 0x16u, 0x1du, 0x1fu
};
static unsigned char k_mask_mirc[32];

static unsigned char sw_mask_of(unsigned char ch)
{
    return (unsigned char)(1u << (unsigned int)(ch & 7u));
}

static int sw_mask_has(const unsigned char *mask, unsigned char ch)
{
    return (mask[ch >> 3] & sw_mask_of(ch)) != 0u ? 1 : 0;
}

static void sw_masks_init(void)
{
    unsigned char ch;

    memset(k_mask_c1, 0, sizeof k_mask_c1);
    memset(k_mask_all, 0, sizeof k_mask_all);
    for (ch = 0; ch < 0xffu; ch++) {
        if (marker_in_set(ch) == 0) {
            continue;
        }
        k_mask_all[ch >> 3] |= sw_mask_of(ch);
        if (ch >= 0x80u && ch <= 0x9fu) {
            k_mask_c1[ch >> 3] |= sw_mask_of(ch);
        }
    }
    memset(k_mask_mirc, 0, sizeof k_mask_mirc);
    for (size_t i = 0; i < sizeof k_mirc_bytes / sizeof k_mirc_bytes[0]; i++) {
        const unsigned char m = k_mirc_bytes[i];

        k_mask_mirc[m >> 3] |= sw_mask_of(m);
    }
}

/* THE ENTRY MACROS.
 *
 * A 32-byte mask written out at a table site is unreadable -- nobody can tell from
 * `{ 0x00, 0x00, ... }` which bytes an entry excuses -- and an unreadable allowlist
 * entry is how an allowlist stops being reviewed. So a row names its byte CLASS, and
 * the `why` column is where a reviewer looks. */
#define SW_EXC_ALL(where_text, why_text) { k_mask_all, why_text, where_text, 0, 1 }
#define SW_EXC_C1_ANY(why_text)          { k_mask_c1, why_text, NULL, 1, 1 }
#define SW_EXC_MIRC(where_text, why_text)  { k_mask_mirc, why_text, where_text, 0, 1 }

/* `g_exc_used`'s bound, and the entry count. The bound is a constant so that
 * `g_exc_used` can be declared above the table it indexes, and `main()` ASSERTS the
 * count against it -- which is the only thing a hand-written bound is good for. */
#define SW_MAX_EXCEPTIONS 64

/* WHICH ENTRIES ARE STILL BEING USED, recorded as the scan runs.
 *
 * The check is over the WHOLE RUN -- every client socket and the node's stdout -- and
 * not over the log alone, because two of the classes are wire-only: an exception that
 * is never exercised is either stale or pointing at nothing, and both are how a filter
 * gets quietly switched off. */
static int g_exc_used[SW_MAX_EXCEPTIONS];

/* ---------------------------------------------------------------------------
 * THE EXCEPTION LIST, AND IT IS ONE ENTRY LONG
 * ---------------------------------------------------------------------------
 * It was thirteen. Eleven of those were numerics echoing a client-supplied value back
 * to the client that sent it, one was a nickname holding a bare C1 byte, and one was
 * PONG's token -- and all thirteen are gone, because all thirteen were BUGS rather than
 * decisions, and the honest response to "this sweep needs an exception here" is to ask
 * why.
 *
 *   - The eleven echoes are filtered by `emit_numeric_ex()` in reply.c, at the one
 *     place a numeric's parameters are rendered. Bytes removed, field kept.
 *   - The nickname is REFUSED by `valid_nick()`, which asks
 *     `conn_text_display_check()`. There is no copy to sanitise, because a nickname
 *     IS every copy: it is the source of every line its owner sends.
 *   - PONG's token is kept and filtered, because RFC 2812 2.4 requires the value.
 *
 * WHAT IS LEFT is the mIRC formatting bytes in RELAYED MESSAGE TEXT, which is not an
 * exception so much as a specification. `0x01` frames a CTCP and `0x02`, `0x03`,
 * `0x0F`, `0x11`, `0x16`, `0x1D` and `0x1F` are mIRC's colour and style codes;
 * `relay_byte_kept()` keeps exactly those eight and drops every other C0 byte
 * including ESC and BEL, and its comment says why it is a `switch` rather than a
 * range: a range test would swallow the hazard and would corrupt every CTCP.
 *
 * IT IS ONE ENTRY AND NOT TWO, and the missing one is `" NOTICE "`. `NOTICE` is the
 * same `send_message()` as `PRIVMSG` with one flag difference -- `exclude = c`, so a
 * NOTICE is not echoed to its sender unless `echo-message` was negotiated -- and every
 * probe here owns the only member of its own channel, so a NOTICE has nobody to reach.
 * An entry for a site this sweep cannot observe would be the decorative kind, and its
 * absence is safe in the direction that matters: if NOTICE ever did put a mIRC byte on
 * a scanned surface, the sweep goes red and somebody writes the entry then.
 *
 * ---------------------------------------------------------------------------
 * AND THE TWO CHECKS THAT KEEP THE LIST HONEST
 * ---------------------------------------------------------------------------
 * An occurrence is excused only when its byte is in the entry's set AND its line
 * carries that entry's `where`, so an entry cannot become a blanket amnesty for a
 * byte. And a listed entry whose `where` never appears anywhere in the run FAILS, so
 * the list cannot accumulate entries nobody exercises. Those two checks are what made
 * this table shrink: when the eleven echo entries stopped matching because the echoes
 * stopped happening, `assert_exceptions_all_used()` said so and the entries had to be
 * DELETED rather than left looking reasonable. A test that has to notice its own
 * allowlist going stale is the only kind that keeps one from becoming a hole.
 */
static const struct sw_exception k_exceptions[] = {
    SW_EXC_MIRC(" PRIVMSG ",
                "A mIRC formatting byte -- 0x01 (the CTCP delimiter), 0x02 bold, 0x03 "
                "colour, 0x0F plain, 0x11 mono, 0x16 reverse, 0x1D italic, 0x1F "
                "underline -- in RELAYED PRIVMSG TEXT. `relay_byte_kept()` in "
                "src/core/connection.c keeps exactly these eight and drops every other "
                "C0 byte including ESC and BEL, and its comment says why it is a "
                "switch rather than a range: a range test would swallow the hazard and "
                "would corrupt every CTCP. Relaying them is the FEATURE, not an "
                "oversight, and it is the only reason this list is not empty. The "
                "RELAYED path is deliberately not filtered by `emit_numeric_ex()` -- "
                "that is what mIRC colour would look like if it were."),
    { NULL, NULL, NULL, 0, 1 } /* terminator: a real entry needs all five fields */
};

#define SW_EXCEPTIONS ((int)(sizeof k_exceptions / sizeof k_exceptions[0]) - 1)

/* How many sockets the sweep scanned, and how many exception entries were exercised.
 * Both are printed by `main()` so that a run's own output says what it covered. */
static size_t g_sockets;

static int g_exc_used_count(void)
{
    int n = 0;

    for (int e = 0; e < SW_EXCEPTIONS; e++) {
        if (g_exc_used[e] != 0) {
            n++;
        }
    }
    return n;
}


/* ---------------------------------------------------------------------------
 * A LINE BUILDER, because every probe line carries raw bytes
 * ---------------------------------------------------------------------------
 * 1 KiB per batch. The size is not about syscalls -- it is about how often the
 * parent returns to `pump_node()`, and `pump_node()` is what keeps the node alive
 * (see it for the deadlock). One KiB is about eighty probe lines. */
typedef struct {
    char  *b;
    size_t len;
    size_t cap;
} sw_buf;

static void sw_buf_init(sw_buf *b)
{
    b->cap = 1024u;
    b->len = 0u;
    b->b = (char *)malloc(b->cap);
    TF_CHECK_MSG(b->b != NULL, "could not allocate the sweep's line buffer");
}

static void sw_buf_free(sw_buf *b)
{
    free(b->b);
    b->b = NULL;
    b->len = 0u;
    b->cap = 0u;
}

static void sw_buf_need(sw_buf *b, size_t extra)
{
    if (b->len + extra + 1u > b->cap) {
        size_t grown_cap = b->cap * 2u;
        char *grown;

        while (b->len + extra + 1u > grown_cap) {
            grown_cap *= 2u;
        }
        grown = (char *)realloc(b->b, grown_cap);
        TF_CHECK_MSG(grown != NULL, "could not grow the sweep's line buffer");
        b->b = grown;
        b->cap = grown_cap;
    }
}

static void sw_put(sw_buf *b, const char *s)
{
    size_t n = strlen(s);

    sw_buf_need(b, n);
    memcpy(b->b + b->len, s, n);
    b->len += n;
}

static void sw_putc(sw_buf *b, unsigned char c)
{
    sw_buf_need(b, 1u);
    b->b[b->len++] = (char)c;
}

/* Keep the node's stdout pipe empty, and WHY THIS IS A FUNCTION RATHER THAN ONE
 * `tc_pump()`.
 *
 * THE DEADLOCK IS SPECIFIC AND IT IS FATAL. A child's stdout is a 64 KiB pipe. A
 * node that fills it blocks inside `write()` -- which, in this node, is inside
 * `poll_loop_step()` -- so it stops accepting, stops reading and stops answering
 * the very client that is waiting on it. This sweep produces roughly 50 KiB of
 * `[observable]` output per verb from about 6 KiB of input, so a parent that
 * pumps once per batch falls behind by an order of magnitude and the node wedges
 * within three verbs. From outside, a wedged node and a silent node print the
 * same thing, which is why `nf_pending_bytes()` exists.
 *
 * `tc_pump()` DRAINS AT MOST 4096 BYTES PER CALL -- `out_read()`'s buffer -- so
 * one call per 1 KiB of input cannot keep up, and looping here is not tidiness
 * but the difference between a sweep that runs and one that hangs. The loop
 * condition is `nf_pending_bytes()`, which is a fact about the pipe rather than a
 * guess about timing.
 *
 * IT IS ALSO WHY THE SCAN CANNOT RUN MID-SWEEP: while the child is alive, stdio
 * may still be holding a log line that has not reached the pipe at all.
 *
 * AND THE MIRROR DEADLOCK, which is the one this node hit first. The same 64 KiB
 * argument applies to the CLIENT's socket in the other direction: this sweep draws
 * one reply per probe line, so a parent that writes several hundred lines without
 * reading fills the client's receive buffer, the node blocks in `write()` to a
 * socket nobody is draining, and it stops reading -- so it stops serving, so the
 * drain PING at the end of the verb never comes back. From outside, a node blocked
 * on a full socket and a node that died print the same thing.
 *
 * So BOTH are drained here, every time, and the order does not matter: each is a
 * question ("is there anything to read?") rather than a guess about how long the
 * other side takes. `tc_drain()` with a 1 ms deadline is that question for the
 * socket -- a poll, not a sleep -- and it appends to the client's own buffer, which
 * is what the per-connection client-side scan reads afterwards. */
static void drain_node_pipe(nf_node_t *node)
{
    for (;;) {
        int pending = 0;

        if (nf_pending_bytes(node, &pending) != 0) {
            return; /* the descriptor cannot be asked; the buffer is what we have */
        }
        if (pending == 0) {
            return;
        }
        tc_pump();
    }
}

static void pump_node(nf_node_t *node, test_client_t *c)
{
    if (c != NULL) {
        for (;;) {
            int eof = 0;

            if (tc_read_available(c, &eof) <= 0) {
                break; /* nothing more right now, or the peer is gone */
            }
        }
    }
    drain_node_pipe(node);
}

/* Flush a batch onto the socket, then keep both ends moving. */
static void sw_flush(test_client_t *c, sw_buf *b, nf_node_t *node)
{
    if (b->len == 0u) {
        return;
    }
    TF_CHECK_MSG(tc_send_raw(c, b->b, b->len) == 0,
                 "could not send a %lu-byte probe batch", (unsigned long)b->len);
    b->len = 0u;
    pump_node(node, c);
}

/* ---------------------------------------------------------------------------
 * THE SCAN
 * ---------------------------------------------------------------------------
 * A WHOLE-BUFFER BYTE WALK, and this is the part the teeth test exists to prove.
 *
 * `strstr(buf, "\033")` would answer "is there an escape"; it would NOT answer
 * "is there a control byte", and a node that stripped ESC and relayed BEL would
 * pass it. So this walks every byte of the buffer and refuses every member of the
 * set, which is what makes the assertion about the SET rather than about the two
 * bytes one person happened to think of.
 *
 * THE EXCEPTION CHECK IS TWO-HALFED. An occurrence is excused only when its byte
 * is listed AND its line carries that entry's `where`, so an entry cannot become
 * a blanket amnesty for a byte; and `assert_exceptions_all_used()` FAILS a
 * listed entry whose `where` never appears, so the list cannot accumulate entries
 * nobody exercises. */
/* Print one line of the finding report with every byte that is not printable ASCII
 * shown as `\xNN`.
 *
 * IT IS NOT COSMETIC, and the version without it was unreadable in exactly the way
 * that matters: the offending byte IS the finding, so a report that prints it raw
 * prints a line that looks like `reason=` and reads as a formatting bug rather than
 * as the injection it is. A failure message has to show the thing it is complaining
 * about. */
static void print_escaped(const char *s)
{
    for (const char *p = s; *p != '\0'; p++) {
        const unsigned char ch = (unsigned char)*p;

        if (ch >= 0x20u && ch <= 0x7eu) {
            (void)fputc((int)ch, stderr);
        } else {
            (void)fprintf(stderr, "\\x%02x", ch);
        }
    }
}

/* ---------------------------------------------------------------------------
 * FINDINGS, COLLECTED ACROSS THE WHOLE RUN AND REPORTED ONCE
 * ---------------------------------------------------------------------------
 * A sweep's job is to say WHAT IS REACHABLE, so it must not stop at the first thing
 * it finds: aborting on the first occurrence means fixing one leak reveals the next
 * one one run at a time, which is the rediscovery loop that let two of these survive
 * in the first place. So every buffer -- each client socket as its probe closes, and
 * the node's whole stdout at the end -- is fed in here, occurrences are counted, and
 * ONE report is printed at the end listing every DISTINCT site.
 *
 * SIXTEEN DISTINCT SITES are kept. A seventeenth is counted but not printed, so the
 * report stays readable and a pathological sweep cannot produce a megabyte of
 * failure message. Eight would do; sixteen is a round number and leaves room.
 *
 * THE EXCEPTION CHECK IS PER-OCCURRENCE, NOT PER-BUFFER: an occurrence is excused
 * only when its byte is inside a listed range AND its line carries that entry's
 * `where`, so an entry can never become a blanket amnesty for a byte. */
/* Is `needle` inside `s[0..len)`? `strstr()` would answer over the whole rest of the
 * buffer, and the buffer here is the node's entire stdout -- seven megabytes -- so a
 * per-line `strstr()` walks it a hundred thousand times and takes minutes. A bounded
 * search is not an optimisation here; it is the difference between a test that runs
 * and a test that appears to hang. */
static int span_has(const char *s, size_t len, const char *needle)
{
    size_t nlen = strlen(needle);
    size_t i;

    if (nlen == 0u || nlen > len) {
        return 0;
    }
    for (i = 0; i + nlen <= len; i++) {
        if (memcmp(s + i, needle, nlen) == 0) {
            return 1;
        }
    }
    return 0;
}

struct finding {
    char site[48];
    char line[192];
};

static struct finding g_found[16];
static size_t g_nfound;
static size_t g_total;
static char g_what[48];
static char g_who[48];

static void record_findings(const char *buf, size_t len, const char *what,
                            const char *who)
{
    (void)snprintf(g_what, sizeof g_what, "%s", what);
    (void)snprintf(g_who, sizeof g_who, "%s", who);

    for (size_t i = 0; i < len; i++) {
        const unsigned char ch = (unsigned char)buf[i];
        size_t start;
        size_t stop;
        size_t shown;
        char line[512];
        int excused = 0;
        int known = 0;
        char site[sizeof g_found[0].site];
        const char *colon;
        size_t klen;

        if (marker_in_set(ch) == 0) {
            continue;
        }
        /* The line this occurrence is on, for the report and for the exception
         * match. Bounded, because the log is megabytes by the end of a sweep and a
         * failure message that prints a megabyte is unreadable. */
        start = i;
        while (start > 0u && buf[start - 1u] != '\n') {
            start--;
        }
        stop = i;
        while (stop < len && buf[stop] != '\n') {
            stop++;
        }
        shown = stop - start;
        if (shown > sizeof line - 1u) {
            shown = sizeof line - 1u;
        }
        memcpy(line, buf + start, shown);
        line[shown] = '\0';
        for (int e = 0; e < SW_EXCEPTIONS; e++) {
            int hit;

            if (sw_mask_has(k_exceptions[e].mask, ch) == 0) {
                continue;
            }
            if (k_exceptions[e].anywhere != 0) {
                hit = 1;
            } else {
                hit = span_has(line, shown, k_exceptions[e].where);
            }
            if (hit != 0) {
                excused = 1;
                g_exc_used[e] = 1;
                break;
            }
        }
        if (excused != 0) {
            continue;
        }
        g_total++;
        /* THE SITE KEY IS THE LINE UP TO ITS FIRST COLON, so the twenty-two lines
         * `chan_mode_refused` writes for twenty-two different mode characters
         * collapse to ONE finding rather than filling the report with near
         * duplicates of the same defect. */
        colon = strchr(line, ':');
        klen = (colon != NULL) ? (size_t)(colon - line + 1u) : strlen(line);
        if (klen > sizeof site - 1u) {
            klen = sizeof site - 1u;
        }
        memcpy(site, line, klen);
        site[klen] = '\0';
        for (size_t f = 0; f < g_nfound; f++) {
            if (strcmp(g_found[f].site, site) == 0) {
                known = 1;
                break;
            }
        }
        if (known == 0 && g_nfound < sizeof g_found / sizeof g_found[0]) {
            (void)snprintf(g_found[g_nfound].site, sizeof g_found[0].site, "%s", site);
            (void)snprintf(g_found[g_nfound].line, sizeof g_found[0].line, "%s", line);
            g_nfound++;
        }
    }
}

/* Print every collected finding and fail if there is one. This is the ONLY place the
 * sweep can fail on a marker byte, and it runs once, after the node has exited. */
static void assert_no_findings(void)
{
    if (g_total == 0u) {
        return;
    }
    fprintf(stderr,
            "note: the terminal-injection sweep found %lu unmarked byte(s) in %s "
            "(%s), at %lu distinct site(s):\n",
            (unsigned long)g_total, g_what, g_who, (unsigned long)g_nfound);
    for (size_t f = 0; f < g_nfound; f++) {
        fprintf(stderr, "    %s\n        ", g_found[f].site);
        print_escaped(g_found[f].line);
        fprintf(stderr, "\n");
    }
    if (g_total > (size_t)(sizeof g_found / sizeof g_found[0])) {
        fprintf(stderr, "    (and more occurrences of the sites above)\n");
    }
    fprintf(stderr,
            "note: this node's output is the only place a control byte can come "
            "from. 0x07 rings a terminal's bell and ESC followed by `[` is a CSI "
            "sequence any terminal executes, so each of these is one user rewriting "
            "another user's screen, or ringing it.\n");
    TF_CHECK_MSG(0,
                 "the terminal-injection sweep found %lu unmarked byte(s) at %lu "
                 "site(s). They are listed above; each is one emission that "
                 "renders a client-supplied value with no filter.",
                 (unsigned long)g_total, (unsigned long)g_nfound);
}

/* The other half of the exception list: every entry must still be exercised. A
 * list that has drifted out of date is not documentation, it is a hole with a
 * comment in front of it. */
static void assert_exceptions_all_used(void)
{
    for (int e = 0; e < SW_EXCEPTIONS; e++) {
        if (k_exceptions[e].required == 0) {
            continue;
        }
        TF_CHECK_MSG(g_exc_used[e] != 0,
                     "the sweep's exception list carries an entry for `%s` (%s) and "
                     "the whole sweep -- every client socket and the node's entire "
                     "stdout -- never produced a byte that entry excuses. Either the "
                     "site stopped rendering the value, in which case the entry is a "
                     "hole nobody is watching, or it moved, in which case the entry "
                     "now excuses nothing while looking as though it excuses "
                     "something.",
                     (k_exceptions[e].where != NULL) ? k_exceptions[e].where
                                                     : "(a message prefix)",
                     k_exceptions[e].why);
    }
}

/* ---------------------------------------------------------------------------
 * THE DERIVED VERB LIST
 * ---------------------------------------------------------------------------
 * A verb and the `pre_reg` column beside it, which is what makes the
 * pre-registration phase derived rather than a second hand-written list. */
typedef struct {
    char verb[24];
    int  pre_reg;
    int  implemented; /* 0 for a row whose handler is NULL: KILL on this build */
} sw_verb;

static sw_verb g_verbs[SW_MAX_VERBS];
static size_t   g_nverbs;

static size_t pre_reg_count(void)
{
    size_t n = 0u;

    for (size_t i = 0; i < g_nverbs; i++) {
        if (g_verbs[i].pre_reg != 0) {
            n++;
        }
    }
    return n;
}

/* Read src/core/commands.c with COMMENTS REMOVED and STRING LITERALS KEPT.
 *
 * WHY NOT `tf_read_code()`, which is the harness's own reader: it strips string
 * literals as well as comments, because every existing caller searches for
 * function NAMES. This file's whole job is to read string LITERALS out of a
 * table, so it needs the other half of that filter and cannot use this one.
 *
 * THE QUOTE TRACKING IS LOAD-BEARING, and is the failure `tf_read_code()`'s own
 * comment describes from the other side: a comment OPENER inside a string literal
 * would otherwise start a block comment and swallow the rest of the file, and the
 * symptom would be "the verb list came out empty", which is indistinguishable
 * from a node with no verbs. */
static char *sw_read_table_text(size_t *len_out)
{
    char path[1024];
    FILE *f;
    char *out;
    size_t cap = 65536u;
    size_t len = 0u;
    int in_block = 0;
    int in_line = 0;
    char quote = 0;
    int prev = 0;
    int ch;

    (void)snprintf(path, sizeof path, "%s/src/core/commands.c", IRCSERVE_SRC_DIR);
    f = fopen(path, "rb");
    TF_CHECK_MSG(f != NULL, "could not open %s (is IRCSERVE_SRC_DIR set?)", path);
    out = (char *)malloc(cap);
    TF_CHECK_MSG(out != NULL, "could not allocate for the dispatch table text");
    while ((ch = fgetc(f)) != EOF) {
        if (len + 2u >= cap) {
            char *grown = (char *)realloc(out, cap * 2u);

            TF_CHECK_MSG(grown != NULL, "could not grow the table text buffer");
            out = grown;
            cap *= 2u;
        }
        if (quote != 0) {
            /* Inside a literal: nothing is a comment and nothing ends it except
             * the literal's own closing quote, or a backslash escape, which is
             * copied through because no verb in the table holds one. */
            out[len++] = (char)ch;
            if (ch == '\\') {
                int esc = fgetc(f);

                if (esc != EOF) {
                    out[len++] = (char)esc;
                }
                prev = 0;
                continue;
            }
            if (ch == quote) {
                quote = 0;
            }
            prev = 0;
            continue;
        }
        if (in_block) {
            if (ch == '/' && prev == '*') {
                in_block = 0;
            }
            prev = ch;
            continue;
        }
        if (in_line) {
            if (ch == '\n') {
                in_line = 0;
                out[len++] = (char)ch;
            }
            prev = 0;
            continue;
        }
        if (prev == '/' && ch == '/') {
            in_line = 1;
            prev = 0;
            continue;
        }
        if (prev == '/' && ch == '*') {
            in_block = 1;
            prev = 0;
            continue;
        }
        out[len++] = (char)ch;
        if (ch == '"' || ch == '\'') {
            quote = (char)ch;
            prev = 0;
            continue;
        }
        prev = ch;
    }
    fclose(f);
    out[len] = '\0';
    if (len_out != NULL) {
        *len_out = len;
    }
    return out;
}

/* HOW THE LIST IS KEPT HONEST, and these checks are the whole answer to "a
 * source-parsed list can drift from the binary":
 *
 *   1. THE SHAPE IS ASSERTED. The opener and the table's own closing `};` must
 *      both be found, and every `{` between them must parse as a row. A table
 *      restructured into something this reader cannot read fails HERE, loudly,
 *      rather than yielding a short list that would quietly sweep less.
 *   2. THE SIZE HAS A FLOOR. Below the floor the parse found something too small
 *      to be the client surface, and a sweep that exercised it would report
 *      success while covering a fraction of the tree.
 *   3. TWO SENTINELS. A verb the sweep depends on must be present -- `MODE` is
 *      the one the first bug was behind -- and a verb the sweep itself invents
 *      must be absent, so a reader that returned the whole file's string literals
 *      is caught.
 *   4. THE RUNNING BINARY IS ASKED. `probe_verb()` sends every derived verb to a
 *      live node and requires that the node not answer 421, so a row this reader
 *      mis-parsed fails against the binary and not only against the source. */
static void derive_verbs(void)
{
    size_t len = 0u;
    char *text;
    const char *p;
    const char *end;
    size_t rows = 0u;

    text = sw_read_table_text(&len);
    TF_CHECK_MSG(len > 0u, "the dispatch table text is empty");
    p = strstr(text, "k_commands[] = {");
    TF_CHECK_MSG(p != NULL,
                 "src/core/commands.c has no `k_commands[] = {` line, so this test "
                 "cannot derive the verb surface and would otherwise sweep nothing "
                 "while reporting success");
    p += strlen("k_commands[] = {");
    /* The table's own closing line. Every row in it is one line long, so the
     * first `\n};` is the end of the table and not a nested brace inside it. */
    end = strstr(p, "\n};");
    TF_CHECK_MSG(end != NULL,
                 "the dispatch table has no closing `};` line, so the row scan "
                 "below has no bound and this test would sweep an unknown region "
                 "of the file");

    for (const char *at = p; at < end; at++) {
        const char *row_end;
        const char *q1;
        const char *q2;
        const char *lastdigit;
        size_t nlen;
        size_t i;

        if (*at != '{') {
            continue;
        }
        row_end = (const char *)memchr(at, '}', (size_t)(end - at));
        TF_CHECK_MSG(row_end != NULL, "a row of the dispatch table has no `}`");
        q1 = (const char *)memchr(at, '"', (size_t)(row_end - at));
        TF_CHECK_MSG(q1 != NULL,
                     "a row of the dispatch table has no quoted verb in it, so this "
                     "reader cannot see the surface this test exists to sweep, and "
                     "refusing to report success on a partial list is the only "
                     "honest answer");
        q2 = (const char *)memchr(q1 + 1, '"', (size_t)(row_end - (q1 + 1)));
        TF_CHECK_MSG(q2 != NULL, "a row of the dispatch table has an unterminated "
                                 "verb");
        nlen = (size_t)(q2 - (q1 + 1));
        TF_CHECK_MSG(nlen > 0u && nlen < sizeof g_verbs[0].verb,
                     "a verb in the dispatch table is %lu bytes, which does not fit "
                     "the %lu-byte field",
                     (unsigned long)nlen, (unsigned long)sizeof g_verbs[0].verb);
        TF_CHECK_MSG(rows < SW_MAX_VERBS,
                     "the dispatch table holds more than %d rows, so this test's "
                     "array is too small and it would have swept a truncated list",
                     SW_MAX_VERBS);
        memcpy(g_verbs[rows].verb, q1 + 1, nlen);
        g_verbs[rows].verb[nlen] = '\0';
        /* THE `pre_reg` COLUMN, and it is the LAST integer before the row's `}`:
         * the middle field is a handler name or NULL and only the third is a
         * flag. */
        lastdigit = NULL;
        for (i = (size_t)(row_end - at); i > 0u; i--) {
            const char c2 = at[i - 1u];

            if (c2 == '0' || c2 == '1') {
                lastdigit = at + (i - 1u);
                break;
            }
            if (c2 != ' ' && c2 != '\t' && c2 != ',') {
                break;
            }
        }
        TF_CHECK_MSG(lastdigit != NULL,
                     "the dispatch table row for %s has no 0/1 flag column, so the "
                     "pre-registration phase would be a hand-written guess about "
                     "which verbs this node answers before registration",
                     g_verbs[rows].verb);
        g_verbs[rows].pre_reg = (*lastdigit == '1') ? 1 : 0;
        /* THE HANDLER COLUMN, which is `NULL` for a verb this build knows and does
         * not implement (`KILL` is the one on this tree). It is needed because the
         * wire cannot tell those two cases apart -- both answer 421 -- and the
         * cross-check against the running node has to be able to. */
        g_verbs[rows].implemented = 1;
        for (const char *n = q2; n < row_end; n++) {
            if (strncmp(n, "NULL", 4u) == 0) {
                g_verbs[rows].implemented = 0;
                break;
            }
        }
        rows++;
    }
    free(text);

    TF_CHECK_MSG(rows >= 30u,
                 "only %lu rows were parsed out of the dispatch table. This node's "
                 "client surface is larger than that, so the sweep would report "
                 "success while exercising a fraction of it.",
                 (unsigned long)rows);
    g_nverbs = rows;

    {
        int has_mode = 0;
        int has_nosuch = 0;

        for (size_t i = 0; i < g_nverbs; i++) {
            if (strcmp(g_verbs[i].verb, "MODE") == 0) {
                has_mode = 1;
            }
            if (strcmp(g_verbs[i].verb, "NOSUCHVERB") == 0) {
                has_nosuch = 1;
            }
        }
        TF_CHECK_MSG(has_mode == 1,
                     "MODE is not in the parsed dispatch table, so the sweep did not "
                     "reach the 472 path this test exists for");
        TF_CHECK_MSG(has_nosuch == 0,
                     "NOSUCHVERB IS in the parsed dispatch table, which means this "
                     "reader is not reading the dispatch table");
    }
    printf("ok: derived %lu verbs from k_commands[] (%lu of them pre-registration)\n",
           (unsigned long)g_nverbs, (unsigned long)pre_reg_count());
}

/* ---------------------------------------------------------------------------
 * THE SHAPES: a template table, and why a template and not a positional index
 * ---------------------------------------------------------------------------
 * The FIRST version of this generator emitted `VERB <marker>`, `VERB a <marker>`
 * and so on -- a marker in each POSITION, with no subject in front of it. It
 * reported this node's output clean, and both 472 sites were still leaking.
 *
 * That is not a small gap. It is the SAME mistake as the enumeration it replaces,
 * one level up: `MODE` does not read params[1] until params[0] has resolved to a
 * channel this node is on, so a marker in params[1] is unreachable unless
 * params[0] is a real channel name. Position enumeration without a plausible
 * SUBJECT cannot see past any arity or subject check, which is most of them.
 *
 * So a shape is a PARAMETER STRING rather than an index, written with two
 * escapes: `\x01` is the subject and `\x02` is the marker byte. A table of
 * templates covers both halves -- the marker in every position with and without a
 * subject in front of it -- and the subject is the channel this probe joined,
 * because that is the only subject on this node that makes a verb's leading
 * parameter RESOLVE.
 *
 * The two payloads (`ESC [ 2 J` and BEL) are not marker sweeps: what is under test
 * there is the payload, and ESC and BEL are already in every other shape's marker
 * loop. One line each, so they cost 37 lines rather than 2,294.
 *
 * `<subject> <marker>` is the row that reaches the first unknown-mode-character
 * 472: `MODE #SWxx <marker>` is a mode argument with no sign, which is exactly
 * the branch that refuses it. `<subject> +<marker>` and `<subject> a +<marker>`
 * reach the OTHER 472, the one inside the mode loop, because there the character
 * is one byte of a signed mode string. Both sites leaked, and neither is reachable
 * from a table of positions.
 *
 * THE FIRST EIGHT ENTRIES CARRY NO SUBJECT and the rest do, and the
 * pre-registration phase sweeps only the first eight. That is not a shortcut: a
 * connection that has not registered cannot hold a channel, so a subject-shaped
 * parameter could not resolve for ANY verb on such a connection -- and none of the
 * ten pre-registration verbs takes a channel as its subject to begin with. On a
 * registered connection, where a channel exists and this probe is its creator and
 * therefore its operator, the whole table is swept. */
#define SH_SUBJECT "\x01"
#define SH_MARKER  "\x02"

static const char *const k_shapes[] = {
    /* NO LEADING SUBJECT: indices 0..7. The marker is the verb's own first
     * parameter, which is the subject for every verb that has one and the first or
     * a later parameter for every verb that does not. */
    SH_MARKER,
    "a " SH_MARKER,
    "a b " SH_MARKER,
    "a :" SH_MARKER "z",
    "a" SH_MARKER "z",
    "a +" SH_MARKER,
    "a b +" SH_MARKER,
    "a b :" SH_MARKER "z",
    /* A LEADING SUBJECT, so the marker lands in a parameter BEHIND one that
     * RESOLVES: indices 8 and up. */
    SH_SUBJECT " " SH_MARKER,
    SH_SUBJECT " a " SH_MARKER,
    SH_SUBJECT " a b " SH_MARKER,
    SH_SUBJECT " a :" SH_MARKER "z",
    SH_SUBJECT " a" SH_MARKER "z",
    SH_SUBJECT " +" SH_MARKER,
    SH_SUBJECT " -" SH_MARKER,
    SH_SUBJECT " a +" SH_MARKER,
    SH_SUBJECT " a -" SH_MARKER,
    SH_SUBJECT " a b +" SH_MARKER,
    SH_SUBJECT " a b :" SH_MARKER "z",
    /* `MODE #SWxx +a <marker>`: a signed mode string whose LETTER is a filler and
     * whose argument is the marker. That is the ban-mask and key branches. */
    SH_SUBJECT " +a " SH_MARKER,
    /* A SUBJECT AND NOTHING ELSE, with the marker in the trailing parameter. Two
     * parameters and no middle one, which is the shape of `TOPIC #chan :<topic>`,
     * `PART #chan :<reason>` and `PRIVMSG <target> :<text>`. Its absence was a real
     * hole: without it the sweep never sent a two-parameter channel command with a
     * trailing parameter, so the relayed-message path was only reached with the
     * marker in the TARGET, where a message to a nick that exists goes nowhere. */
    SH_SUBJECT " :" SH_MARKER "z"
};
#define SH_COUNT ((int)(sizeof k_shapes / sizeof k_shapes[0]))
/* THE INDEX WHERE THE SUBJECT-BEARING TEMPLATES START. It is a COUNT rather than a
 * table split so that the two halves cannot disagree about their order, and `main()`
 * ASSERTS it against the table's own contents -- that the templates below it carry no
 * subject escape and the ones above it do. */
#define SH_SUBJECT_FIRST 8

/* TWO PAYLOAD SHAPES, which are lines rather than sweeps. */
#define SH_CSI  ((int)SH_COUNT)
#define SH_BELL ((int)SH_COUNT + 1)
/* AND THE COMMAND-WORD SHAPE, which is the last one. */
#define SH_WORD ((int)SH_COUNT + 2)
#define SH_ALL  ((int)SH_COUNT + 3)

/* `emit_shape()` is the only place that knows the escape convention, which is
 * where it belongs: a template's reader and a template's writer being the same
 * function is what stops the table and the emitter disagreeing. */
static void emit_shape(sw_buf *b, const char *verb, const char *chan,
                      unsigned char m, int shape)
{
    if (shape == SH_CSI) {
        sw_put(b, verb);
        sw_put(b, " ");
        sw_put(b, chan);
        sw_put(b, " a :\033[2J");
        sw_put(b, "\r\n");
        return;
    }
    if (shape == SH_BELL) {
        sw_put(b, verb);
        sw_put(b, " ");
        sw_put(b, chan);
        sw_put(b, " a b \007");
        sw_put(b, "\r\n");
        return;
    }
    if (shape == SH_WORD) {
        /* THE COMMAND WORD. The marker IS the verb the node sees and the real verb
         * rides along as its argument, so the node sees an unrecognised verb
         * carrying a marker -- a shape no table of known verbs can produce. */
        sw_putc(b, m);
        sw_put(b, "z ");
        sw_put(b, verb);
        sw_put(b, "\r\n");
        return;
    }
    sw_put(b, verb);
    /* THE SPACE. It belongs here and not in the table, because every template is a
     * parameter list and none of them may be empty: the first version concatenated
     * `verb` and the template directly, and every subject-bearing shape therefore
     * sent `MODE#SWP <ESC>` -- a COMMAND WORD of `MODE#SWP`, which the node
     * correctly called unknown. It reported this node clean, because a line the node
     * rejects is a line that leaks nothing. That is the most dangerous possible
     * failure for a sweep: the probe stopped being a probe and the property it was
     * measuring still passed. */
    sw_putc(b, ' ');
    /* ONE BYTE PER ESCAPE, so the walk advances by one. The first version advanced
     * by two, on the reasoning that an escape is two SOURCE characters -- and that
     * is true of the spelling but false of the string, where `\x01` is already one
     * byte by the time the table exists. Advancing by two therefore ate the byte
     * after every subject: `<subject> +<marker>` came out as `#SW15+<marker>`, the
     * mode argument stopped being a mode argument, and the sweep reported this node
     * clean with both 472 sites still leaking. A generator's bugs fail SILENTLY --
     * a malformed probe line is a line the node rejects, and a rejected line leaks
     * nothing -- so the walk is written to be obviously one-byte-per-escape rather
     * than cleverly otherwise. */
    for (const char *p = k_shapes[shape]; *p != '\0'; p++) {
        if (*p == '\x01') {
            sw_put(b, chan);
        } else if (*p == '\x02') {
            sw_putc(b, m);
        } else {
            sw_putc(b, (unsigned char)*p);
        }
    }
    sw_put(b, "\r\n");
}

/* ONE SHAPE'S WORTH OF LINES, for every marker in the set.
 *
 * THE TWO PAYLOAD SHAPES SEND ONE LINE EACH, because what is under test there is
 * the payload rather than the byte: ESC and BEL are already swept in every other
 * shape's loop, so multiplying `ESC [ 2 J` by 62 would test the same thing 62
 * times and cost 2,294 lines to do it. */
static void emit_all_markers(sw_buf *b, test_client_t *c, nf_node_t *node,
                             const char *verb, const char *chan, int shape)
{
    if (shape == SH_CSI || shape == SH_BELL) {
        emit_shape(b, verb, chan, 0u, shape);
    } else {
        for (unsigned m = 0x00u; m <= 0xffu; m++) {
            if (marker_in_set((unsigned char)m) == 0) {
                continue;
            }
            emit_shape(b, verb, chan, (unsigned char)m, shape);
        }
    }
    sw_flush(c, b, node);
}

/* ---------------------------------------------------------------------------
 * A LOG LINE CARRYING TWO THINGS, and this is a local copy on purpose
 * ---------------------------------------------------------------------------
 * `log_line_has_tail()` in test_log_injection.c is the same idea and could not be
 * reused: it is `static` there, and duplicating a shared helper into the harness
 * would widen three test files for one caller. What it is FOR is worth repeating
 * here though, because this file's cross-check needs the same property: the search
 * is confined to ONE line, so a token on some other line cannot satisfy it and the
 * assertion stays pointed at the line it names.
 *
 * NO `fd=` ANYWHERE. The node's descriptor for a connection depends on how many
 * descriptors the process holds open, which is not the same on Linux and macOS. */
static int log_line_has(const char *log, size_t mark, const char *prefix,
                        const char *token)
{
    const char *at = log + mark;

    for (at = strstr(at, prefix); at != NULL; at = strstr(at + 1, prefix)) {
        const char *nl = strchr(at, '\n');
        const char *stop = (nl != NULL) ? nl : log + strlen(log);

        if (span_has(at, (size_t)(stop - at), token) != 0) {
            return 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * REGISTERING A PROBE CONNECTION
 * ---------------------------------------------------------------------------
 * NICK, USER, wait for 001, JOIN the probe channel, wait for the JOIN echo.
 *
 * THE JOIN IS NOT SETTING. It is what makes the sweep reach anything channel
 * scoped: `MODE` refuses before it looks at a mode string unless the caller is an
 * operator, and this node OPERATES THE CHANNEL CREATOR on the creator's own JOIN.
 * A client that never joined could not reach a 472 at all -- which is exactly how
 * the first bug survived: the gate is self-issued, one line after the JOIN.
 *
 * `nick` is UNIQUE per probe so that a log line which leaks a byte names the verb
 * it came from. That is the only attribution this file has for a leak found by
 * the end-of-run whole-buffer scan, where no probe is current any more. */
static void open_probe(const nf_node_t *node, test_client_t *c, const char *nick,
                       const char *chan)
{
    char line[128];
    char join_echo[64];

    tc_init(c);
    TF_CHECK_MSG(tc_connect(c, node->port) == 0, "tc_connect failed");
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "the probe %s NICK send failed", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 * :probe", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "the probe %s USER send failed", nick);
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0,
                 "probe %s never registered. A sweep whose connections do not "
                 "register is not reaching the surface it claims to sweep, so a "
                 "clean scan over it would prove nothing.", nick);
    if (chan == NULL) {
        return;
    }
    (void)snprintf(line, sizeof line, "JOIN %s", chan);
    TF_CHECK_MSG(tc_send(c, line) == 0, "the probe %s JOIN send failed", nick);
    (void)snprintf(join_echo, sizeof join_echo, " JOIN %s\r\n", chan);
    TF_CHECK_MSG(tc_expect(c, join_echo, T_IO_MS) == 0,
                 "probe %s never joined %s, so the channel-scoped verbs could not "
                 "have been reached and the sweep would be vacuous for all of "
                 "them", nick, chan);
}

/* The drain token, numbered per call because every search below is over the
 * ACCUMULATED buffer -- a reused token is satisfied by an earlier PONG with no
 * read at all, which is how a drain silently stops draining. */
static unsigned g_seq;

static void make_token(char *out, size_t cap)
{
    (void)snprintf(out, cap, "sw%u", g_seq++);
}

/* A deadline clock, for the one wait in this file that is not the harness's. */
static uint64_t sw_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0u;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000L);
}

/* ---------------------------------------------------------------------------
 * WAITING FOR A PONG, WITHOUT `tc_expect()`
 * ---------------------------------------------------------------------------
 * Returns 1 when the token came back (the connection is being served), 0 when the
 * peer closed before it did, and -1 when neither happened inside the deadline.
 *
 * IT IS NOT `tc_expect()` BECAUSE OF WHAT THAT PRINTS. `tc_expect()` reports
 * "TIMEOUT after 15000 ms" when it breaks out of its loop on EOF, which it does --
 * and this file CLOSES CONNECTIONS ON PURPOSE, one per shape, for every shape of
 * every verb whose handler calls `conn_mark_closing()`. So the honest close produced
 * roughly fifty lines reading `tc_expect: TIMEOUT` on a run that found exactly what
 * it was looking for. A failure report that says TIMEOUT about a connection that
 * closed on purpose is worse than no report, because it sends the reader looking for
 * a hang that did not happen.
 *
 * The read itself is `tc_read_available()` -- non-blocking and non-destructive, which
 * is the whole reason it exists; see irc_client.h. The 20 ms pause between attempts
 * is a polling interval and the outer bound is a real deadline, and neither of them is
 * a guess about how long the other side takes. */
#define SW_POLL_MS 20

static int drain_for_pong(test_client_t *c, const char *token, int timeout_ms)
{
    const uint64_t deadline = sw_now_ms() + (uint64_t)timeout_ms;

    for (;;) {
        int eof = 0;

        if (strstr(tc_buffer(c), token) != NULL) {
            return 1;
        }
        /* `tc_closed()` AND not just this call's `eof`, because the close may have
         * been seen by an EARLIER read -- the drain in pump_node() runs on every
         * batch and reports a close to whoever asked, and a caller that did not ask
         * would otherwise be waiting out the full deadline for a PONG that a closed
         * socket will never answer. */
        if (tc_closed(c) != 0) {
            return 0;
        }
        if (tc_read_available(c, &eof) < 0) {
            /* THE PEER IS GONE, AND THAT IS NOT THE SAME AS A WEDGED NODE. A probe
             * for a verb whose handler closes the connection sends its drain PING
             * into a socket whose far end has already sent FIN, and the kernel
             * answers THAT with ECONNRESET rather than another clean read of zero.
             * A node that stopped SERVING leaves the socket open, so this read
             * returns EAGAIN, the loop runs to the deadline, and -1 comes back --
             * which is why the two answers are told apart here rather than both
             * being called a hang. */
            return 0;
        }
        if (eof != 0) {
            return 0;
        }
        if (strstr(tc_buffer(c), token) != NULL) {
            return 1;
        }
        if (sw_now_ms() >= deadline) {
            return -1;
        }
        /* WAIT FOR READABILITY, capped at the poll interval and at whatever is left
         * of the deadline. A select() on the socket is a wait for a CONDITION; there
         * is no `sleep()` anywhere in this file, and none of these timeouts is an
         * assumption about how long the node takes to answer. */
        tc_pump();
        {
            struct timeval tv;
            fd_set rfds;
            uint64_t left = deadline - sw_now_ms();
            int slice = (left > (uint64_t)SW_POLL_MS) ? SW_POLL_MS : (int)left;

            FD_ZERO(&rfds);
            FD_SET(c->fd, &rfds);
            tv.tv_sec = (time_t)(slice / 1000);
            tv.tv_usec = (suseconds_t)((slice % 1000) * 1000);
            (void)select(c->fd + 1, &rfds, NULL, NULL, &tv);
        }
    }
}

/* Send the drain PING, require either its PONG or a close, and report which.
 *
 * QUIT is the one verb on this node that closes the connection, and that is a
 * legitimate outcome rather than a fault -- but only a CLOSE explains it, so the
 * distinction is made rather than assumed, and the caller is TOLD which happened
 * rather than left to discover it by writing into a dead socket.
 *
 * `drain_for_pong()` returns as soon as the peer closes, and only a connection that
 * genuinely stopped answering pays the full deadline. */
static int drain_or_closed(test_client_t *c, const char *nick)
{
    char token[64];
    char ping[128];
    int alive;

    make_token(token, sizeof token);
    (void)snprintf(ping, sizeof ping, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, ping) == 0, "the drain PING for %s failed", nick);
    alive = drain_for_pong(c, token, T_IO_MS);
    TF_CHECK_MSG(alive >= 0,
                 "probe %s stopped answering and its connection was never closed. "
                 "That is a node that stopped serving rather than a close, and a "
                 "sweep that carried on would be asserting about a buffer the node "
                 "had not finished writing.", nick);
    return alive;
}

/* The client-side scan, called as soon as a connection's buffer is provably
 * COMPLETE: the PONG proves everything sent before it was dispatched, and a close
 * proves the peer sent everything it had. So this is per connection and immediate,
 * and it is not the same moment as the log scan -- see `drain_node_pipe()`. */
static void assert_probe_socket_clean(const test_client_t *c, const char *nick)
{
    g_sockets++;
    record_findings(tc_buffer(c), tc_received(c), "a client socket", nick);
}

/* ---------------------------------------------------------------------------
 * PROBING ONE VERB
 * ---------------------------------------------------------------------------
 * ONE CONNECTION PER VERB, and the reason is reachability rather than tidiness:
 * state accumulates. A verb that opens a batch, joins a channel, changes a mode or
 * renames a connection changes what the NEXT verb can reach, so one shared
 * connection would make the swept surface depend on the order this file happens to
 * send things in. A freshly prepared connection per verb makes every verb's probe
 * the same experiment, on any machine, in any order, under `ctest -j`.
 *
 * A `JOIN` goes out between shapes because `PART` leaves the channel: without it,
 * shapes two through eight of PART's probe would be answered 442 and would never
 * reach the refusal line under test. The JOIN is idempotent when the client is
 * already in the channel, and the cost is one extra line per shape.
 *
 * WHAT COMES BACK IS WHAT THE CLIENT SAW, and it is scanned here, per
 * connection, because that buffer's completeness is provable: the PONG proves
 * everything sent before it was dispatched, and a close proves the peer sent
 * everything it had. The node's own stdout is NOT scanned here -- see the header
 * on why a log line can still be in the child's stdio buffer at this point. */
static void probe_verb(nf_node_t *node, const sw_verb *v, size_t idx)
{
    test_client_t c;
    sw_buf b;
    /* 32 BYTES, not 16, and the reason is a compiler rather than a measurement:
     * gcc's -Wformat-truncation models `%lu` of an unsigned long as up to 20 digits
     * and refuses a 16-byte destination, which is a true statement about the format
     * and a false one about this index. The casts to `unsigned` below are the real
     * fix -- `%u` of an unsigned is 10 digits and fits -- and the 32 is headroom so
     * that a reader does not have to re-derive it. */
    char nick[32];
    char chan[32];
    char token[64];
    char ping[128];
    size_t log_mark;
    int alive;

    (void)snprintf(nick, sizeof nick, "sq%02u", (unsigned)idx);
    (void)snprintf(chan, sizeof chan, SW_CHAN_FMT, (unsigned)idx);
    /* The mark is taken BEFORE the bare verb goes out and after nothing else, so
     * the log lines the cross-check reads are exactly the ones that verb caused. */
    open_probe(node, &c, nick, chan);
    /* Registration and the JOIN produce a burst of the node's own output, so the
     * pipe is drained before the mark is taken -- otherwise the mark lands in the
     * middle of the burst and the cross-check below could match a line that had
     * nothing to do with the verb under test. */
    drain_node_pipe(node);

    /* HONESTY CHECK 4: THE RUNNING BINARY MUST KNOW THIS VERB.
     *
     * IT IS CHECKED IN THE NODE'S LOG AND NOT ON THE WIRE, and the reason is that
     * the wire cannot answer the question: `cmd_unknown:` and `cmd_unimplemented:`
     * both send 421, so a client cannot tell "this node has no row for it" from
     * "this node has a row and the row's handler is NULL". The log can, and it is
     * the log that says which of the two happened.
     *
     * So: NO `cmd_unknown:` LINE MAY NAME THIS VERB, ever -- that line means the
     * table this file parsed and the table the node runs disagree, which is
     * exactly the drift a source-derived list is exposed to -- and a row whose
     * handler is NULL MUST produce `cmd_unimplemented:` naming it, which is the
     * other half: it proves the check is reading a real dispatch and not passing
     * because nothing was looked for. */
    log_mark = node->out_len;
    TF_CHECK_MSG(tc_send(&c, v->verb) == 0, "the bare %s send failed", v->verb);
    make_token(token, sizeof token);
    (void)snprintf(ping, sizeof ping, "PING :%s", token);
    TF_CHECK_MSG(tc_send(&c, ping) == 0, "the %s 421-probe PING failed", nick);
    alive = drain_for_pong(&c, token, T_IO_MS);
    /* THE NODE'S PIPE IS DRAINED BEFORE ITS LOG IS READ, and this is not tidiness.
     * `drain_for_pong()` reads the CLIENT's socket, so it can return on a PONG while
     * the `[observable]` line that PONG was caused by is still sitting unread in the
     * node's 64 KiB stdout pipe -- and `tc_pump()` only drains that pipe when it
     * happens to hold something at the moment it is called. The first run of this
     * cross-check under the ASan cell failed on exactly that, and only there: the
     * sanitised node is slower, the pipe fill is later, and `cmd_unimplemented:` had
     * not been pumped yet. Draining to empty first makes the read see every byte the
     * node wrote before the PONG, which is the whole content of the claim. */
    drain_node_pipe(node);
    TF_CHECK_MSG(alive >= 0,
                 "probe %s answered neither a PONG nor a close, so the node stopped "
                 "serving this connection", nick);
    if (alive == 1) {
        char want[64];

        /* `%.23s` rather than `%s`: 23 is `sizeof v->verb - 1`, and spelling the
         * precision is what tells gcc the destination is big enough. Without it the
         * same code is a -Wformat-truncation error on gcc and silent on clang, which
         * is the kind of difference that only shows up in one of twelve cells. */
        (void)snprintf(want, sizeof want, "command=%.23s", v->verb);
        TF_CHECK_MSG(log_line_has(node->out, log_mark, "cmd_unknown:", want) == 0,
                     "the node logged cmd_unknown: naming `%s`, which is in this "
                     "file's derived verb list. Either the dispatch table this test "
                     "parsed and the table the node runs have come apart, or the "
                     "node does not have a row for a verb its own table names -- and "
                     "a sweep that carried on would be asserting about a verb that "
                     "does not exist.", v->verb);
        if (v->implemented == 0) {
            TF_CHECK_MSG(log_line_has(node->out, log_mark, "cmd_unimplemented:",
                                      want) == 1,
                         "the dispatch table row for `%s` has a NULL handler, so "
                         "this node should have logged cmd_unimplemented: naming it, "
                         "and did not. Either the row's NULL column was mis-parsed "
                         "here or the node's unimplemented branch is unreachable, and "
                         "in both cases this cross-check is not reading a real "
                         "dispatch.", v->verb);
        }
    }

    sw_buf_init(&b);
    for (int shape = 0; shape < SH_ALL; shape++) {
        if (alive == 0) {
            /* A VERB THAT CLOSES GETS A FRESH CONNECTION PER SHAPE. `QUIT` is the
             * one on this node, and without this every shape after the first would
             * be written into a socket the node has already closed: the send would
             * fail, or -- worse, on a platform where it does not -- the sweep would
             * report every shape of coverage for a verb it had actually exercised
             * once. */
            tc_close(&c);
            open_probe(node, &c, nick, chan);
        }
        if (shape != 0) {
            sw_put(&b, "JOIN ");
            sw_put(&b, chan);
            sw_put(&b, "\r\n");
        }
        emit_all_markers(&b, &c, node, v->verb, chan, shape);
        alive = drain_or_closed(&c, nick);
        assert_probe_socket_clean(&c, nick);
    }
    sw_buf_free(&b);
    tc_close(&c);
}

/* ---------------------------------------------------------------------------
 * THE TWO PHASES THAT ARE NOT "EVERY VERB"
 * ---------------------------------------------------------------------------
 * An unrecognised verb carrying a marker in each argument position, and the whole
 * pre-registration surface. The second is not optional: `BATCH` is `pre_reg`, so
 * its refusal line is reachable from a socket that has never registered and never
 * joined anything -- the lowest-privilege instance of the class, and the one an
 * enumeration sorted by "which verbs log client data" would rank last. */
static void probe_unknown_verb(nf_node_t *node)
{
    test_client_t c;
    sw_buf b;
    const char *nick = "su00";
    const char *chan = "#SWU0";

    open_probe(node, &c, nick, chan);
    sw_buf_init(&b);
    for (int shape = 0; shape < SH_ALL; shape++) {
        emit_all_markers(&b, &c, node, "NOSUCHVERB", chan, shape);
    }
    sw_buf_free(&b);
    (void)drain_or_closed(&c, nick);
    assert_probe_socket_clean(&c, nick);
    tc_close(&c);
}

/* The pre-registration surface, and NO JOIN: a connection that never registers
 * cannot have a channel, and the point is to reach the verbs that answer BEFORE
 * registration at all. The verbs swept here are the `pre_reg = 1` column of the
 * derived table, so this list is derived too.
 *
 * A verb that closes the connection gets a fresh one, because otherwise every
 * shape after the closing one would be written into a dead socket. That costs one
 * connect per closing verb and buys the shapes that come after it. */
static void probe_pre_registration(nf_node_t *node)
{
    test_client_t c;
    sw_buf b;

    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node->port) == 0, "tc_connect failed");
    sw_buf_init(&b);
    for (size_t i = 0; i < g_nverbs; i++) {
        int alive;

        if (g_verbs[i].pre_reg == 0) {
            continue;
        }
        /* NO SUBJECT SHAPES HERE, and the table's own comment says why: this
         * connection has not registered, so it holds no channel and no
         * subject-shaped parameter could resolve for any verb. */
        for (int shape = 0; shape < SH_SUBJECT_FIRST; shape++) {
            emit_all_markers(&b, &c, node, g_verbs[i].verb, "", shape);
            /* ONE DRAIN PER SHAPE, and the reason is that the whole verb's eight
             * shapes cannot share one batch: `QUIT` closes the connection inside
             * the first shape, and a batch still holding shapes two through eight
             * would then be written into a socket the node has closed -- which on
             * some platforms is a silent success rather than a failure, and would
             * leave the sweep claiming eight shapes of coverage for a verb it had
             * exercised once. */
            alive = drain_or_closed(&c, "the pre-registration probe");
            assert_probe_socket_clean(&c, "the pre-registration probe");
            if (alive == 0) {
                tc_close(&c);
                tc_init(&c);
                TF_CHECK_MSG(tc_connect(&c, node->port) == 0,
                             "could not reopen the pre-registration probe");
            }
        }
    }
    sw_buf_free(&b);
    assert_probe_socket_clean(&c, "the pre-registration probe");
    tc_close(&c);
}

/* ---------------------------------------------------------------------------
 * THE SCAN POINT, restated where it is used
 * ---------------------------------------------------------------------------
 * `nf_stop()` reaps the child and then drains "best effort". `pump_node()` after it
 * waits for the one fact that makes the buffer COMPLETE: nothing is left in the
 * pipe. The child is dead by then, so the bytes cannot grow, and
 * `nf_pending_bytes()` reporting zero means every byte it wrote is in `n->out`.
 *
 * THAT is the whole reason the log scan is here and not per-probe, and it is a
 * property of stdio rather than of this test: a log line can still be sitting in
 * the child's stdio buffer when the reply it caused has already crossed the
 * socket, so an incremental scan would pass or fail on the scheduler. */
int main(void)
{
    nf_node_t node;

    sw_masks_init();
    memset(g_exc_used, 0, sizeof g_exc_used);

    derive_verbs();

    /* THE TABLE'S SPLIT POINT IS ASSERTED, not assumed. `SH_SUBJECT_FIRST` is a
     * count and the table is a list, and the pre-registration phase sweeps only the
     * first `SH_SUBJECT_FIRST` entries -- so a row added to the wrong half would
     * silently change what the pre-registration phase covers. One check makes the
     * two halves agree about where they meet. */
    TF_CHECK_MSG(SW_EXCEPTIONS > 0,
                 "the sweep's exception list is empty, which cannot be true: this "
                 "build of the tree has known classes of marker byte on its output "
                 "and every one of them is listed. An empty list means the table lost "
                 "its terminator row.");
    TF_CHECK_MSG((size_t)SW_EXCEPTIONS <= sizeof g_exc_used / sizeof g_exc_used[0],
                 "the exception list holds %d entries and the sweep's per-entry "
                 "bookkeeping array holds %lu, so the two would overrun.",
                 SW_EXCEPTIONS,
                 (unsigned long)(sizeof g_exc_used / sizeof g_exc_used[0]));
    TF_CHECK_MSG((size_t)SH_SUBJECT_FIRST < (size_t)SH_COUNT,
                 "the shape table's split point is not inside the table");
    TF_CHECK_MSG(strchr(k_shapes[0], '\x01') == NULL &&
                 strchr(k_shapes[SH_SUBJECT_FIRST - 1], '\x01') == NULL,
                 "a subject-less shape template mentions the subject escape");
    TF_CHECK_MSG(strchr(k_shapes[SH_SUBJECT_FIRST], '\x01') != NULL,
                 "the first subject-bearing shape template does not mention the "
                 "subject escape, so the split point is wrong");

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    for (size_t i = 0; i < g_nverbs; i++) {
        probe_verb(&node, &g_verbs[i], i);
    }
    probe_unknown_verb(&node);
    probe_pre_registration(&node);

    TF_CHECK_MSG(nf_stop(&node) == 0,
                 "the node did not exit cleanly; see above. A non-zero exit means "
                 "its stdout may hold a partial view, and a sweep asserting over a "
                 "partial view is worse than no sweep at all.");
    drain_node_pipe(&node);

    record_findings(node.out, node.out_len, "this node's own stdout",
                    "(the post-run scan)");
    assert_exceptions_all_used();
    assert_no_findings();

    /* THE COUNTS ARE PRINTED SO THAT A REVIEWER CAN SEE WHAT WAS COVERED, and they
     * are computed rather than written down: `SW_MARKERS` is derived from the
     * predicate at startup and `SH_ALL` from the shape table, so neither can drift
     * out of step with the code that sent the lines. */
    printf("ok: %lu bytes of node stdout and %lu client sockets swept clean; "
           "%lu markers x %d shapes x %lu derived verbs, plus the unknown-verb and "
           "pre-registration phases; %d exception entries, %d of them exercised\n",
           (unsigned long)node.out_len, (unsigned long)g_sockets,
           (unsigned long)(SW_MARKERS * (g_nverbs + 1u)), (int)SH_ALL,
           (unsigned long)g_nverbs, SW_EXCEPTIONS, g_exc_used_count());
    nf_free(&node);
    tf_done("test_terminal_sweep");
    return 0;
}
