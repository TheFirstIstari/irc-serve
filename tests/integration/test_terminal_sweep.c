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
 * AND THE TWO CLASSES A VERB SWEEP STRUCTURALLY CANNOT SEE
 * ===========================================================================
 * Everything above drives each verb with SINGLE-LINE, SINGLE-VERB shapes. That
 * is blind to two whole classes, and BOTH of this pass's live leaks were in
 * them:
 *
 *   (a) A VALUE THAT ONLY EXISTS ACROSS TWO MESSAGES OF STATE. `AUTHENTICATE
 *       ESC` is a single parameter, and a single parameter with no exchange in
 *       progress is parsed as a MECHANISM NAME and refused at 908 -- so
 *       `authcid`, which exists only after `AUTHENTICATE PLAIN` has been
 *       answered with a `+` and a payload has come back, was unreachable from
 *       every shape in the table. It was reachable from a socket,
 *       pre-registration, with no credential at all, and it printed raw.
 *   (b) A FIELD STORED NOW AND RENDERED LATER ON A DIFFERENT VERB. `USER
 *       <marker>` is not itself a leak: the value sits in `conn_t::user` and
 *       nothing renders it until that client's next JOIN, PRIVMSG or QUIT. A
 *       sweep that sends one line and reads one line cannot see that, and
 *       `c->user` -- the one field of this node's five identity fields with no
 *       predicate -- reached every co-member's terminal that way.
 *
 * So `k_stateful[]` below is the CLASS, not a patch for two sites. Each row
 * declares which kind of state it needs, so the next field that is stored on
 * one verb and rendered on another has a row to be written into rather than an
 * argument about whether the sweep already covers it. The rows are counted and
 * the count is asserted in main(), which is what makes a stateful phase that
 * reaches nothing FAIL rather than pass.
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
#include "harness/sweep_scan.h"
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
#define SW_MARKERS SWS_MARKER_COUNT

/* THE MARKER SET, THE mIRC BYTES, THE MASKS AND THE WALK ARE IN
 * `harness/sweep_scan.h`, which the PEER sweep includes too. One instrument, two
 * surfaces: the two binaries sweep different sockets and the same threat, and a
 * second copy of the predicate is a copy that can drift out of step with the first
 * without anything going red.
 *
 * The local names below are the shared ones, spelled the way this file used to
 * spell them, so the rest of this file is unchanged and the diff is the removal
 * rather than a rewrite. */
#define marker_in_set     sws_marker_in_set
#define sw_mask_of        sws_mask_of
#define sw_mask_has       sws_mask_has
#define sw_masks_init     sws_masks_init
#define k_mirc_bytes      sws_mirc_bytes
#define k_mask_c1         sws_mask_c1
#define k_mask_all        sws_mask_all
#define k_mask_mirc       sws_mask_mirc

#define SW_MAX_EXCEPTIONS 64

/* One row per BYTE RANGE that may appear on a scanned surface, with the reason and
 * with the substring that identifies the one site that produces it. */
struct sw_exception {
    const unsigned char *mask;
    const char *why;
    const char *where;
    int anywhere;
    int required;
};

/* WHICH ENTRIES ARE STILL BEING USED, recorded by `sw_excuse()` as the scan runs.
 *
 * The check is over the WHOLE RUN -- every client socket and the node's stdout -- and
 * not over the log alone, because two of the classes are wire-only: an exception that
 * is never exercised is either stale or pointing at nothing, and both are how a filter
 * gets quietly switched off. The bound is `SW_MAX_EXCEPTIONS` and `main()` asserts the
 * entry count against it. */
typedef struct {
    int used[SW_MAX_EXCEPTIONS];
} sw_exc_ctx;
static sw_exc_ctx g_exc;

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
        if (g_exc.used[e] != 0) {
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

/* THE WALK IS THE SHARED ONE, in `harness/sweep_scan.h`. This file's contribution
 * is the EXCUSION CALLBACK, which is its own exception list applied to a line: an
 * occurrence is excused only when its byte is in the entry's set AND the line carries
 * the entry's `where`, so an entry can never become a blanket amnesty for a byte.
 * Recording which entries fired is what `assert_exceptions_all_used()` reads. */
static int sw_excuse(unsigned char ch, const char *line, size_t len, void *ctx)
{
    sw_exc_ctx *c = (sw_exc_ctx *)ctx;

    for (int e = 0; e < SW_EXCEPTIONS; e++) {
        int hit;

        if (sw_mask_has(k_exceptions[e].mask, ch) == 0) {
            continue;
        }
        if (k_exceptions[e].anywhere != 0) {
            hit = 1;
        } else {
            hit = span_has(line, len, k_exceptions[e].where);
        }
        if (hit != 0) {
            c->used[e] = 1;
            return 1;
        }
    }
    return 0;
}

static sws_scan g_scan;
static char g_who[SWS_TEXT_MAX];

static void record_findings(const char *buf, size_t len, const char *what,
                            const char *who)
{
    /* One scan for the whole run, so the report is one summary naming every
     * surface rather than a paragraph per socket. */
    if (g_scan.excuse == NULL) {
        (void)snprintf(g_who, sizeof g_who, "%s", who);
        sws_scan_begin(&g_scan, what, sw_excuse, &g_exc);
    }
    sws_scan_bytes(&g_scan, buf, len);
}

/* Print every collected finding and fail if there is one. This is the ONLY place the
 * sweep can fail on a marker byte, and it runs once, after the node has exited. */
static void assert_no_findings(void)
{
    (void)snprintf(g_scan.who, sizeof g_scan.who, "%s", g_who);
    if (sws_scan_clean(&g_scan) != 0) {
        return;
    }
    (void)sws_scan_report(&g_scan);
    fprintf(stderr,
            "note: this node's output is the only place a control byte can come "
            "from. 0x07 rings a terminal's bell and ESC followed by `[` is a CSI "
            "sequence any terminal executes, so each of these is one user rewriting "
            "another user's screen, or ringing it.\n");
    TF_CHECK_MSG(0,
                 "the terminal-injection sweep found %lu unmarked byte(s) at %lu "
                 "site(s). They are listed above; each is one emission that "
                 "renders a client-supplied value with no filter.",
                 (unsigned long)g_scan.total, (unsigned long)g_scan.nfound);
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
        TF_CHECK_MSG(g_exc.used[e] != 0,
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
 * THE STATEFUL PROBES, AND THE CLASS OF LEAK THE SHAPE TABLE CANNOT REACH
 * ---------------------------------------------------------------------------
 * Everything above drives each verb with SINGLE-LINE, SINGLE-VERB shapes
 * (`emit_shape()`), and that is structurally blind to two whole classes:
 *
 *   (a) A VALUE THAT ONLY EXISTS ACROSS TWO MESSAGES OF STATE. `AUTHENTICATE
 *       ESC` is a single parameter, and a single parameter with no exchange in
 *       progress is parsed as a MECHANISM NAME and refused at 908 -- so
 *       `authcid`, which only exists after `AUTHENTICATE PLAIN` has been
 *       answered with a `+` and a payload has come back, was unreachable from
 *       every shape in the table. It was reachable from a socket, pre-
 *       registration, with no credential at all, and it printed raw.
 *
 *   (b) A FIELD THAT IS STORED NOW AND RENDERED LATER ON A DIFFERENT VERB.
 *       `USER <marker>` is not itself a leak: the value sits in `conn_t::user`
 *       and nothing renders it until the client's next JOIN, PRIVMSG or QUIT.
 *       A sweep that sends one line and reads one line cannot see that, and
 *       `c->user` -- the one field of this node's five identity fields with no
 *       predicate -- reached every co-member's terminal that way.
 *
 * BOTH LIVE LEAKS WERE IN THAT BLIND SPOT, and that is the finding rather than
 * the two lines: a reachability sweep that enumerates VERBS is not a
 * reachability sweep over STATE. So these probes are the class, not a patch for
 * two sites. Each row declares WHICH KIND of state it needs, so the next field
 * that is stored on one verb and rendered on another has a row to be written
 * into rather than an argument about whether the sweep already covers it.
 *
 * THE ROWS ARE COUNTED AND THE COUNT IS ASSERTED IN main(): a probe that stops
 * reaching its target is a probe that reports nothing, and a sweep that silently
 * covers less is the failure mode this whole file is written against. A blank
 * stateful phase fails rather than passes.
 */
enum sw_state_kind {
    SW_ST_NONE = 0, /* one line is enough: the shape table already covers it */
    SW_ST_MESSAGES, /* the value exists only across TWO messages of state */
    SW_ST_STORED    /* the field is stored by one verb and rendered by a later one */
};

struct sw_stateful {
    const char *name;    /* attribution, the job a probe's nick does above */
    int needs_state;     /* 0 if a single line would reach it, 1 if it would not */
    int kind;            /* one of the three kinds above, and never SW_ST_NONE */
    const char *covers;  /* what this row reaches that the shape table cannot */
};

static const struct sw_stateful k_stateful[] = {
    /* (a). The two-message exchange RFC 4422 specifies and every real client
     * uses: name the mechanism, take the `+` this node answers it with, then
     * send the payload. `authcid` is inside the payload, which must be a REAL
     * base64 encoding -- `sasl_b64_decode()` refuses a byte outside the
     * alphabet, so a malformed payload is answered BAD_PAYLOAD and never
     * reaches the field at all. The measure of the claim is the log line's
     * `authcid_len=`/`authcid_bad_bytes=` pair, which only exists on the site
     * that now measures the field: with the measurement reverted the line
     * carries the raw byte and no length, and this probe goes red on that
     * site specifically. */
    { "sasl-plain-authcid", 1, SW_ST_MESSAGES,
      "`authcid`, which only exists across `AUTHENTICATE PLAIN` / "
      "`AUTHENTICATE <payload>`; the one-line form is a mechanism name and is "
      "refused at 908 before anything is stored" },
    /* (b). The stored field, rendered on a LATER verb to a CO-MEMBER. The
     * hostile value is offered to `USER`, stored in `conn_t::user`, and
     * rendered into the hostmask of a JOIN echo and of a relayed PRIVMSG --
     * three different verbs, one stored field. The co-member's socket is the
     * surface under test, because that is the one a client cannot see for
     * itself. */
    { "stored-ident-render", 1, SW_ST_STORED,
      "a field stored by `USER` and rendered by `JOIN` and `PRIVMSG` into "
      "another client's hostmask, which no single-line probe can observe" },
};
#define SW_STATEFUL ((int)(sizeof k_stateful / sizeof k_stateful[0]))

/* How many stateful probes PROVED they reached their target, as opposed to
 * having sent something into a socket -- and how many each PLANNED. The two are
 * compared in main() and inside each probe, which is what makes a stateful
 * phase that reaches nothing fail rather than pass. */
static int g_stateful_reached;
static int g_stateful_planned;

/* RFC 4648 base64, with padding, and it has to be a REAL encoding: the probe's
 * whole point is to reach a field behind a decoder that refuses a malformed
 * payload. Written here rather than borrowed because the harness has no
 * encoder and a test-local helper with one caller is a helper nobody
 * maintains. */
static const char sw_b64_alpha[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t sw_b64_encode(const unsigned char *in, size_t n, char *out,
                            size_t cap)
{
    size_t o = 0u;
    size_t i = 0u;

    while (i + 3u <= n) {
        unsigned long v = ((unsigned long)in[i] << 16) |
                          ((unsigned long)in[i + 1u] << 8) |
                          (unsigned long)in[i + 2u];

        if (o + 4u > cap) {
            return 0;
        }
        out[o++] = sw_b64_alpha[(v >> 18) & 63u];
        out[o++] = sw_b64_alpha[(v >> 12) & 63u];
        out[o++] = sw_b64_alpha[(v >> 6) & 63u];
        out[o++] = sw_b64_alpha[v & 63u];
        i += 3u;
    }
    if (n - i == 1u) {
        unsigned long v = (unsigned long)in[i] << 16;

        if (o + 4u > cap) {
            return 0;
        }
        out[o++] = sw_b64_alpha[(v >> 18) & 63u];
        out[o++] = sw_b64_alpha[(v >> 12) & 63u];
        out[o++] = '=';
        out[o++] = '=';
    } else if (n - i == 2u) {
        unsigned long v = ((unsigned long)in[i] << 16) |
                          ((unsigned long)in[i + 1u] << 8);

        if (o + 4u > cap) {
            return 0;
        }
        out[o++] = sw_b64_alpha[(v >> 18) & 63u];
        out[o++] = sw_b64_alpha[(v >> 12) & 63u];
        out[o++] = sw_b64_alpha[(v >> 6) & 63u];
        out[o++] = '=';
    }
    if (o + 1u > cap) {
        return 0;
    }
    out[o] = '\0';
    return o;
}

/* RFC 4616's PLAIN payload, built with the marker as the WHOLE authcid.
 *
 * The authzid is empty -- RFC 4013 says that means "the same as the
 * authentication identity", and it is what irssi sends, so it is the shape a
 * real client produces. The password is two letters. And the authcid is ONE
 * byte, deliberately, so the measurement the node reports back is exact and a
 * reader can check it by hand rather than trusting the node's arithmetic.
 *
 * THE ONE MARKER NEITHER PROBE CAN USE IS 0x00, and the reason is structural
 * rather than convenient, so it is written down rather than left as a gap in
 * the walk: `message_parse_n()` REFUSES a line holding a NUL anywhere in it,
 * because a NUL is how a C string ends and a parameter is not one. So a NUL is
 * not a parameter byte on this wire at all -- it cannot reach `authcid` (where
 * it is also the payload's own field separator, so the byte that terminates
 * the field cannot be inside it) and it cannot reach `conn_t::user` (where the
 * line carrying it is discarded before anything is stored). Both probes ask
 * `sw_param_marker_ok()` rather than each deciding for itself, which is the
 * same one-predicate rule the node itself applies: a value with two writers
 * needs the writers to agree, and here the "writers" are the two probe walks.
 *
 * It returns 0 for that one marker, so the caller's planned count and its walk
 * agree about what is being exercised. */
static int sw_param_marker_ok(unsigned char m)
{
    return (m != 0u) ? 1 : 0;
}

static size_t sw_plain_payload(unsigned char marker, unsigned char *buf,
                               size_t cap)
{
    size_t n = 0u;

    if (cap < 6u) {
        return 0;
    }
    buf[n++] = 0u;     /* authzid: absent */
    buf[n++] = marker; /* authcid: the byte under test */
    buf[n++] = 0u;     /* the separator before the password */
    buf[n++] = 'p';
    buf[n++] = 'w';
    return n;
}

/* ---------------------------------------------------------------------------
 * PROBE (a): THE TWO-MESSAGE SASL EXCHANGE
 * ---------------------------------------------------------------------------
 * One connection per marker. The exchange is restarted rather than reused
 * because a refusal leaves the connection in SASL_FAILED, and a probe whose
 * second iteration is answered differently from its first is a probe measuring
 * the failure state rather than the site.
 *
 * WHAT IS ASSERTED, and it is the whole reason this is a probe rather than a
 * burst: the node must ANSWER the `+` (proving message one was understood), it
 * must answer the payload with the abort (proving message two was decoded), and
 * the operator's log must carry the `authcid_len=`/`authcid_bad_bytes=`
 * MEASUREMENT -- which exists only on the site that now measures the field, so
 * a node that prints the raw byte back again reports no length at all and this
 * fails on that site rather than somewhere else. */
static void probe_sasl_authcid(nf_node_t *node)
{
    const char *nick = "ss01";
    int reached = 0;
    int planned = 0;

    for (unsigned m = 0x00u; m <= 0xffu; m++) {
        test_client_t c;
        unsigned char payload[8];
        char b64[64];
        char line[192];
        char want[64];
        size_t plen;
        size_t blen;

        if (marker_in_set((unsigned char)m) == 0 ||
            sw_param_marker_ok((unsigned char)m) == 0) {
            continue;
        }
        planned++;
        g_stateful_planned++;
        plen = sw_plain_payload((unsigned char)m, payload, sizeof payload);
        TF_CHECK_MSG(plen == 5u, "the PLAIN payload builder produced %lu bytes",
                     (unsigned long)plen);
        blen = sw_b64_encode(payload, plen, b64, sizeof b64);
        TF_CHECK_MSG(blen == 8u,
                     "the base64 of a 5-byte PLAIN payload is 8 bytes and this "
                     "one produced %lu, so the encoder is wrong and the payload "
                     "the node would decode is not the one this file built",
                     (unsigned long)blen);

        /* A FRESH CONNECTION, and 001 is NOT waited for: the attack is
         * pre-registration and pre-credential, and that is the instance the
         * measurement has to hold on. */
        tc_init(&c);
        TF_CHECK_MSG(tc_connect(&c, node->port) == 0,
                     "the sasl probe could not connect");
        (void)snprintf(line, sizeof line, "NICK %s", nick);
        TF_CHECK_MSG(tc_send(&c, line) == 0, "the sasl probe NICK send failed");

        /* MESSAGE ONE. A single parameter with no exchange in progress is a
         * MECHANISM NAME, which is exactly why a one-line probe cannot reach
         * the payload: without this line the next one is read as a mechanism
         * and refused at 908, and nothing downstream of it runs. The answer's
         * shape is RFC 4422's `AUTHENTICATE +` with this node's own prefix and
         * the connection's nick in front of it. */
        TF_CHECK_MSG(tc_send(&c, "AUTHENTICATE PLAIN") == 0,
                     "the sasl mechanism send failed");
        (void)snprintf(line, sizeof line, "AUTHENTICATE %s +\r\n", nick);
        TF_CHECK_MSG(tc_expect(&c, line, T_IO_MS) == 0,
                     "the node never asked for the payload, so message two below "
                     "would be parsed as a mechanism name and the probe would "
                     "reach nothing. This is the state the shape table cannot "
                     "produce: a second line whose meaning depends on the "
                     "first.\n  %s saw: %s", nick, tc_buffer(&c));

        /* MESSAGE TWO, and it carries the marker inside a REAL encoding. */
        (void)snprintf(line, sizeof line, "AUTHENTICATE %s", b64);
        TF_CHECK_MSG(tc_send(&c, line) == 0, "the sasl payload send failed");
        /* RFC 4422's server-chosen abort is the one line in this exchange a
         * client reads with a byte comparison, so it is what proves the payload
         * was decoded rather than rejected as malformed. */
        TF_CHECK_MSG(tc_expect(&c, "AUTHENTICATE *\r\n", T_IO_MS) == 0,
                     "the node did not abort the exchange, so the payload was "
                     "not decoded and `authcid` never existed for this "
                     "marker.\n  %s saw: %s", nick, tc_buffer(&c));

        /* THE MEASUREMENT, which is the reachability claim. With the field
         * measured, a one-byte authcid is `authcid_len=1 authcid_bad_bytes=1`
         * and the value itself is withheld; with the measurement reverted the
         * line carries the raw byte and no length at all, so this assertion
         * names the site that regressed. */
        /* BOTH ENDS ARE KEPT MOVING, and this is not tidiness: the node's stdout
         * is a 64 KiB pipe and a node that fills it blocks inside write(), at
         * which point it stops accepting and stops answering. `pump_node()`
         * asks both questions -- is there anything to read on the socket, is
         * there anything in the pipe -- rather than guessing how long the other
         * side takes. `log_line_has()` below reads `node->out` directly, so the
         * pipe has to be empty for the line to be there at all. */
        pump_node(node, &c);
        (void)snprintf(want, sizeof want, "authcid_len=1 authcid_bad_bytes=1");
        TF_CHECK_MSG(log_line_has(node->out, 0u, "[observable] sasl:", want) == 1,
                     "the node did not report measuring a ONE-BYTE authcid on the "
                     "SASL rejection path (marker 0x%02x). Either the probe never "
                     "reached the site -- which would mean the two-message "
                     "exchange above is not what it looks like -- or the site "
                     "prints the field raw again, which is the regression this "
                     "probe exists to catch. The whole-buffer scan would also "
                     "find the byte, but it would not say WHICH site put it "
                     "there.\n  node said: %s", m, node->out);
        reached++;
        g_stateful_reached++;

        assert_probe_socket_clean(&c, nick);
        tc_close(&c);
    }
    /* THE PROBE'S OWN COVERAGE CLAIM, and it is local rather than left to
     * main() so that a red names the SITE that stopped being reached. A probe
     * that planned 61 exchanges and reached none of them is a probe whose
     * two-message state has stopped being built, and the only honest report is
     * that it covered nothing at all. */
    TF_CHECK_MSG(reached == planned && planned > 0,
                 "the stateful SASL probe reached its target %d times out of %d "
                 "planned (the authcid measurement on the SASL rejection path). "
                 "A stateful probe that reaches nothing reports that surface "
                 "clean, which is worse than no probe: the single-line sweep "
                 "cannot reach `authcid` at all, so this row IS the coverage.",
                 reached, planned);
}

/* ---------------------------------------------------------------------------
 * PROBE (b): A FIELD STORED BY ONE VERB AND RENDERED BY A LATER ONE
 * ---------------------------------------------------------------------------
 * A hostile ident at `USER`, then a JOIN, then a PRIVMSG into a channel a
 * co-member is also in. Three verbs, one stored field, and the co-member's
 * socket is the surface under test because it is the one the sender cannot see
 * for itself.
 *
 * BOTH SOCKETS ARE SCANNED, and the split matters: the mIRC allowlist excuses
 * eight bytes on any line carrying `" PRIVMSG "`, so the eight mIRC
 * formatting bytes are NOT excused on the JOIN echo -- which carries no
 * `PRIVMSG` at all -- but would be on the relayed message. Scanning only the
 * co-member's socket would lose eight markers of coverage to a legitimate
 * allowlist entry; scanning only the sender's would lose the cross-client
 * shape entirely. Neither surface is optional.
 */
static void probe_stored_ident_render(nf_node_t *node)
{
    const char *atk_nick = "sa01";
    const char *wit_nick = "sw01";
    char chan[32];
    test_client_t wit;
    char line[256];
    int reached = 0;
    int planned = 0;

    (void)snprintf(chan, sizeof chan, "#SWID");

    /* The co-member is registered ONCE, with a clean ident: it is the surface
     * the stored field is rendered onto, and a hostile value in its own
     * registration would make a finding ambiguous about whose field it came
     * from. */
    open_probe(node, &wit, wit_nick, chan);

    for (unsigned m = 0x00u; m <= 0xffu; m++) {
        test_client_t atk;
        char ident[8];

        if (marker_in_set((unsigned char)m) == 0 ||
            sw_param_marker_ok((unsigned char)m) == 0) {
            continue;
        }
        planned++;
        g_stateful_planned++;
        /* THE WHOLE IDENT IS ONE MARKER BYTE, so the hostmask that renders it
         * is exactly `nick!<byte>@host` and a reader can see which byte
         * arrived without decoding a compound payload. */
        ident[0] = (char)m;
        ident[1] = '\0';

        tc_init(&atk);
        TF_CHECK_MSG(tc_connect(&atk, node->port) == 0,
                     "the stored-ident probe could not connect");
        (void)snprintf(line, sizeof line, "NICK %s", atk_nick);
        TF_CHECK_MSG(tc_send(&atk, line) == 0,
                     "the stored-ident probe NICK send failed");
        /* THE `USER` LINE IS SENT RAW, and that is not a shortcut: 0x00 is a
         * member of the marker set and it is the ONE marker a `%s`-built line
         * cannot carry, because every C string ends at it. Building the line
         * with snprintf would silently turn `USER <NUL>` into `USER ` -- an
         * empty parameter, a refused registration, and a probe that reports
         * nothing while looking like it measured something. So the byte is put
         * in the buffer by hand and the length is passed explicitly. */
        {
            int n = snprintf(line, sizeof line, "USER ");
            size_t used;

            line[n++] = (char)m;
            line[n++] = ' ';
            (void)snprintf(line + n, sizeof line - (size_t)n, "0 * :probe");
            used = strlen(line);
            line[used++] = '\r';
            line[used++] = '\n';
            TF_CHECK_MSG(used < sizeof line,
                         "the stored-ident USER line did not fit its buffer");
            TF_CHECK_MSG(tc_send_raw(&atk, line, used) == 0,
                         "the stored-ident probe USER send failed");
        }
        /* THE STORING VERB COMPLETES. A registration that did not complete
         * would leave the field unset, and a probe that could not tell "the
         * field was refused" from "the client was never registered" would be
         * measuring nothing. */
        pump_node(node, &atk);
        TF_CHECK_MSG(tc_expect(&atk, " 001 ", T_IO_MS) == 0,
                     "the hostile ident stranded the client instead of "
                     "registering it with an empty one (marker 0x%02x).\n"
                     "  %s saw: %s", (unsigned)m, atk_nick, tc_buffer(&atk));
        pump_node(node, &atk);

        /* THE RENDERING VERB, and a different one from the one that stored the
         * field. The JOIN echo carries the hostmask back to the sender. */
        (void)snprintf(line, sizeof line, "JOIN %s", chan);
        TF_CHECK_MSG(tc_send(&atk, line) == 0, "the stored-ident JOIN failed");
        (void)snprintf(line, sizeof line, " JOIN %s\r\n", chan);
        TF_CHECK_MSG(tc_expect(&atk, line, T_IO_MS) == 0,
                     "the JOIN never echoed, so the stored field was never "
                     "rendered on the sender's own socket and the rest of this "
                     "probe would be asserting about nothing.\n  %s saw: %s",
                     atk_nick, tc_buffer(&atk));
        /* AND THE SECOND RENDERING VERB, which is the cross-client shape: the
         * value goes to somebody else's terminal. */
        (void)snprintf(line, sizeof line, "PRIVMSG %s :hi there", chan);
        TF_CHECK_MSG(tc_send(&atk, line) == 0, "the stored-ident PRIVMSG failed");
        /* AND THE WITNESS'S SOCKET TOO: it is the surface under test and the
         * node writes one relayed line per marker into it, so a parent that
         * only drains the attacker's socket fills the witness's buffer and
         * wedges the node exactly the way `pump_node()`'s own comment describes
         * in the other direction. */
        pump_node(node, &atk);
        pump_node(node, &wit);

        /* BOTH SOCKETS DRAINED TO A PROVABLY COMPLETE STATE before either is
         * scanned: the PONG proves everything sent before it was dispatched,
         * and the co-member's PRIVMSG is one of those things. */
        make_token(line, sizeof line);
        {
            char ping[128];
            char relay[64];

            (void)snprintf(ping, sizeof ping, "PING :%s", line);
            TF_CHECK_MSG(tc_send(&atk, ping) == 0, "the stored-ident PING failed");
            TF_CHECK_MSG(drain_for_pong(&atk, line, T_IO_MS) >= 0,
                         "the stored-ident probe stopped answering");
            (void)snprintf(relay, sizeof relay, "PRIVMSG %s :hi there", chan);
            TF_CHECK_MSG(drain_for_pong(&wit, relay, T_IO_MS) >= 0,
                         "the co-member never received the relayed message, so the "
                         "cross-client hostmask this probe exists to scan was never "
                         "rendered. A probe that cannot reach the surface is worse "
                         "than no probe: it reports the surface clean.\n"
                         "  %s saw: %s", wit_nick, tc_buffer(&wit));
        }

        assert_probe_socket_clean(&atk, atk_nick);
        reached++;
        g_stateful_reached++;
        tc_close(&atk);
    }
    /* THE PROBE'S OWN COVERAGE CLAIM, local for the same reason the SASL probe's
     * is: a red here names the surface that stopped rendering. 62 markers over a
     * field that is stored by one verb and rendered by two others. */
    TF_CHECK_MSG(reached == planned && planned > 0,
                 "the stateful stored-field probe reached its target %d times out "
                 "of %d planned (a co-member receiving the stored ident in a "
                 "relayed hostmask). A probe that reaches nothing reports that "
                 "surface clean, and the single-line sweep cannot see a field "
                 "that is only rendered on a LATER verb, so this row IS the "
                 "coverage.", reached, planned);
    drain_node_pipe(node);
    /* THE STORED FIELD IS MEASURED ON THE OPERATOR'S LINE TOO, which is the
     * third surface `c->user` reaches and the one a co-member's socket cannot
     * show: a refusal is reported as a length and a bad-byte count, and the
     * operator's own `user:` line withholds the value. */
    TF_CHECK_MSG(log_line_has(node->out, 0u, "user_refused:", "len=1") == 1,
                 "the node did not report refusing a one-byte ident, so the "
                 "ingest predicate either never ran or the report does not "
                 "measure what it refused.\n  node said: %s", node->out);
    /* The co-member is scanned LAST, once, over the whole of what it
     * accumulated: its final drain is the PONG inside the loop's last
     * iteration, which is what makes this buffer provably complete. */
    assert_probe_socket_clean(&wit, wit_nick);
    tc_close(&wit);
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
    memset(&g_exc, 0, sizeof g_exc);

    /* THE INSTRUMENT'S OWN EDGE CASES, and the reason this sweep runs them is not
     * politeness: `sws_find_bytes()` is the primitive that decides whether a byte
     * reached a scanned surface, and a version of it that reads one byte past a
     * range reports this sweep CLEAN rather than red. It is verified here and in the
     * peer sweep because both depend on it and because `ps_assert_no_inverted_
     * assertions()` already reads this file's source, so an instrument defect here
     * and a generator defect there are the same failure wearing different hats. */
    {
        const char *bad = sws_find_bytes_self_test();

        TF_CHECK_MSG(bad == NULL,
                     "the bounded-search self-test failed at `%s`, so every "
                     "search this sweep has just made is unverified", bad != NULL ? bad : "");
    }

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
    TF_CHECK_MSG((size_t)SW_EXCEPTIONS <= sizeof g_exc.used / sizeof g_exc.used[0],
                 "the exception list holds %d entries and the sweep's per-entry "
                 "bookkeeping array holds %lu, so the two would overrun.",
                 SW_EXCEPTIONS,
                 (unsigned long)(sizeof g_exc.used / sizeof g_exc.used[0]));
    TF_CHECK_MSG((size_t)SH_SUBJECT_FIRST < (size_t)SH_COUNT,
                 "the shape table's split point is not inside the table");
    TF_CHECK_MSG(strchr(k_shapes[0], '\x01') == NULL &&
                 strchr(k_shapes[SH_SUBJECT_FIRST - 1], '\x01') == NULL,
                 "a subject-less shape template mentions the subject escape");
    TF_CHECK_MSG(strchr(k_shapes[SH_SUBJECT_FIRST], '\x01') != NULL,
                 "the first subject-bearing shape template does not mention the "
                 "subject escape, so the split point is wrong");

    /* THE STATEFUL TABLE'S OWN INVARIANTS, asserted before anything runs: every
     * row must name a kind of state and must declare that it NEEDS state (a row
     * that does not is a row the shape table already covers, and a duplicate is
     * coverage that looks like coverage), and the two verbs the probes depend
     * on must be in the dispatch table this file derived. Without the last
     * check a probe would be asserting against a node that has no such verb and
     * reporting the empty result as a pass. */
    TF_CHECK_MSG(SW_STATEFUL >= 2,
                 "the stateful probe table holds %d rows, so the class of leak "
                 "that only exists across two messages or across two verbs is "
                 "not covered at all -- and both of this pass's live leaks were "
                 "in it", SW_STATEFUL);
    for (int e = 0; e < SW_STATEFUL; e++) {
        TF_CHECK_MSG(k_stateful[e].needs_state == 1,
                     "stateful probe `%s` declares needs_state=0, so it is a row "
                     "the single-line shape table already covers and it is not "
                     "the class this table exists for", k_stateful[e].name);
        TF_CHECK_MSG(k_stateful[e].kind != SW_ST_NONE,
                     "stateful probe `%s` does not name WHICH kind of state it "
                     "needs, so a reader cannot tell what it covers",
                     k_stateful[e].name);
        TF_CHECK_MSG(k_stateful[e].name != NULL && k_stateful[e].covers != NULL,
                     "stateful probe row %d has no name or no coverage text, so "
                     "a finding it produced could not be attributed", e);
    }
    {
        int has_authenticate = 0;
        int has_user = 0;

        for (size_t i = 0; i < g_nverbs; i++) {
            if (strcmp(g_verbs[i].verb, "AUTHENTICATE") == 0) {
                has_authenticate = 1;
            }
            if (strcmp(g_verbs[i].verb, "USER") == 0) {
                has_user = 1;
            }
        }
        TF_CHECK_MSG(has_authenticate == 1 && has_user == 1,
                     "the stateful probes depend on AUTHENTICATE and USER and one "
                     "of them is not in the derived dispatch table, so the "
                     "stateful phase would be probing verbs this node does not "
                     "have and reporting the empty result as clean");
    }

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    for (size_t i = 0; i < g_nverbs; i++) {
        probe_verb(&node, &g_verbs[i], i);
    }
    probe_unknown_verb(&node);
    probe_pre_registration(&node);
    /* THE STATEFUL PHASE, LAST, and the order is not arbitrary: it leaves the
     * node holding a channel and a co-member connection that every earlier
     * phase's own channels are independent of, and running it last means its
     * assertions are about a node nothing else is driving. */
    probe_sasl_authcid(&node);
    probe_stored_ident_render(&node);
    /* AND THE COVERAGE CLAIM. `g_stateful_reached` is bumped only AFTER a probe
     * has proved it reached its target -- the `+` answer, the abort, the
     * measurement, the JOIN echo, the relayed message -- and `g_stateful_planned`
     * is bumped once per marker a probe set out to exercise. A stateful probe
     * that regressed into sending something into a socket and reading nothing
     * back therefore leaves the two unequal, and a phase that was deleted
     * altogether plans nothing. The second clause is what makes the floor a
     * floor: with no probes at all the equality holds trivially, so the total
     * must at least be one exercised marker per row of the table. */
    TF_CHECK_MSG(g_stateful_reached == g_stateful_planned,
                 "the stateful phase planned %d exercises and proved %d of them. "
                 "A stateful probe that reaches nothing is a probe that reports "
                 "the surface clean, which is worse than no probe.",
                 g_stateful_planned, g_stateful_reached);
    TF_CHECK_MSG(g_stateful_planned >= SW_STATEFUL,
                 "the stateful phase planned %d exercises across %d rows, so it "
                 "exercised less than one marker per row. Both classes of leak "
                 "this table exists for were live, and a phase that covers none "
                 "of them is a phase that has stopped existing.",
                 g_stateful_planned, SW_STATEFUL);

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
           "%lu markers x %d shapes x %lu derived verbs, plus the unknown-verb, "
           "pre-registration and %d stateful probes; %d exception entries, %d of "
           "them exercised\n",
           (unsigned long)node.out_len, (unsigned long)g_sockets,
           (unsigned long)(SW_MARKERS * (g_nverbs + 1u)), (int)SH_ALL,
           (unsigned long)g_nverbs, SW_STATEFUL, SW_EXCEPTIONS,
           g_exc_used_count());
    nf_free(&node);
    tf_done("test_terminal_sweep");
    return 0;
}
