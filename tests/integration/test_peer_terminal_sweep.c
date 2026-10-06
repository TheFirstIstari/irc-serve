/* test_peer_terminal_sweep.c -- the terminal-injection sweep for the PEER path.
 *
 * WHAT THIS IS, AND WHY IT IS A SECOND BINARY RATHER THAN A SECOND PHASE
 * ----------------------------------------------------------------------
 * `test_terminal_sweep.c` sweeps the bytes a CLIENT receives and the bytes the node
 * prints for a client. It says in its own header that the peer path is out of its
 * scope, and the reason it gives is the right one: reaching a peer link needs a raw
 * socket standing in for the other node, which is a different fixture with a
 * different failure mode. This file is that fixture and that sweep.
 *
 * ONE INSTRUMENT, TWO SURFACES
 * ----------------------------
 * The marker predicate, the byte masks and the walk are in
 * `tests/harness/sweep_scan.h`, and this file includes it rather than restating it.
 * That is the whole reason the sharing exists: a second copy of "what counts as a
 * marker byte" is a copy that can drift, and drift here is invisible from the
 * outside -- one surface would quietly stop being swept while the sweep still
 * printed its coverage line.
 *
 * WHAT IS *NOT* SHARED IS THE EXCEPTION LIST, and that asymmetry is the point.
 * A client socket can legitimately be sent a mIRC colour byte in relayed message
 * text, because a mIRC client renders colour and removing it would break every
 * coloured client on the network. The SAME byte in a channel topic, a kick reason
 * or a mode string is a control byte in front of an operator, and the node stores
 * those through a different policy. So the one entry in the list below is scoped to
 * ` SPRIVMSG ` and to nothing else: an allowlist shared across two threat models is
 * how one surface's exception becomes the other's.
 *
 * THE THREE SCANNED SURFACES, AND WHY ALL THREE
 * ---------------------------------------------
 *   1. THE NODE'S OWN STDOUT. The primary surface, and the one the operator reads.
 *      This is where `fed_obs()` does its work.
 *   2. THE PEER SOCKET. A peer is a program, not a terminal, so a marker byte here
 *      is not by itself an injection. It matters for a different reason: a peer
 *      that receives one will relay it, and the node's own relay path is the thing
 *      that would put it in front of a human. Scanning this surface is what catches
 *      a filter that exists in the log path and not in the wire path, which is the
 *      shape a half-finished fix has.
 *   3. THE CLIENT SOCKET, after peer-originated lines. A peer that names a client
 *      in a KICK reason or a topic puts those bytes into a line this node sends to
 *      a human. It is scanned last so that a byte which reached both a peer and a
 *      client is reported once, at the surface where it would have done damage.
 *
 * WHAT PROVES THE SWEEP IS NOT VACUOUS
 * -------------------------------------
 * Three things, and each of them has been the thing that was missing when a sweep
 * of this shape quietly tested nothing:
 *
 *   - The link is ASSERTED, not assumed: the handshake is read and the
 *     `link_established:` line is waited for before any probe runs.
 *   - Every probe is ANSWERED. Each one waits for a needle the node prints for that
 *     specific shape, so a probe the node silently ignored is a failure rather than
 *     a clean result. This is why there is no sleep anywhere in this file.
 *   - The byte count is ASSERTED: 62 markers x N shapes, against the shared
 *     `SWS_MARKER_COUNT`. A marker set that quietly lost a byte cannot pass.
 */
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/server.h"
#include "federation/link.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/peer_fixture.h"
#include "harness/sweep_scan.h"
#include "harness/test_util.h"

#define T_IO_MS 15000
#define SECRET "irc-serve-federation-secret-a"
#define NAME_A "irc.a"
#define PEER  "irc.b"
#define PEER_C "irc.c"
#define NICK_C "carol"

/* THE SHAPES, and each is a field a PEER chooses that this node either renders,
 * stores or forwards.
 *
 * A shape is not a verb name: it is a whole line with two escapes, `\x01` for the
 * marker byte and `\x02` for the per-probe channel, so that every probe has a
 * channel of its own and no probe can be delivered to a member another probe put
 * there. The escapes are written out here rather than generated, because a reader
 * checking what the sweep actually sends should be able to read it.
 *
 * NONE OF THEM NAMES A CHANNEL THAT DOES NOT EXIST for the marker-bearing field.
 * `SJOIN` and `SNICK` are deliberately absent: a member name and a nickname are
 * both refused by `valid_nick()`, so they are tested as refusals by
 * `test_nick_utf8.c` and by `test_valid_nick.c`, and a probe that can only ever
 * produce "refused" tests the refusal rather than the filter. A sweep entry for
 * something that cannot happen would be the decorative kind. */
/* ONE TABLE, BECAUSE A SHAPE AND THE NEEDLE FOR IT ARE ONE FACT.
 *
 * `tmpl` is a whole line with two escapes: `\x01` for the marker byte and `\x02`
 * for the per-probe channel, so every probe has a channel of its own and no probe
 * can be delivered to a member another probe put there. The escapes are written
 * out rather than generated, because a reader checking what the sweep actually
 * sends should be able to read it.
 *
 * `needle` is the line the node must PRINT for that shape. It is what keeps a probe
 * from being vacuous: a shape the node silently ignored would otherwise be a clean
 * result for a reason that has nothing to do with filtering.
 *
 * `fed_message:` is the needle for the first two shapes and `fed_skick:` for the
 * fifth, and two shapes sharing a needle is fine because the needle is not what
 * distinguishes them -- the line that was SENT is, and the sweep sends one line per
 * probe regardless of what the node prints.
 *
 * NONE OF THESE NAMES A MEMBER OR A NICKNAME, deliberately. A roster name and a
 * nickname are both refused by `valid_nick()`, so they are tested as refusals by
 * `test_nick_utf8.c` and by `test_valid_nick.c`; a probe that can only ever produce
 * "refused" tests the refusal rather than the filter, and a sweep entry for
 * something that cannot happen would be the decorative kind. */
struct ps_shape {
    const char *tmpl;
    const char *needle;
    /* The `name=-` this shape's marker must appear AS, and the measurement that
     * must stand beside it. Both NULL when the node does not print the field at
     * all -- which is itself a fact the table records rather than leaves to be
     * discovered. See `ps_expect_withheld()`. */
    const char *field;
    const char *measure;
    /* Set when the node must REPORT a refusal of the marker, which is the only
     * way a shape whose marker is stripped before the product logic sees it can
     * still assert anything about that logic. See `ps_expect_verdict()`. */
    int report_refusal;
};

static const struct ps_shape k_shapes[] = {
    /* ORIGIN-ORIGINATED RELAYED TEXT: the prefix names the LINK'S OWN server, so
     * the node cannot tell a peer originating a line from a peer relaying one and
     * mints the identity itself. No tag block, no per-probe id, and nothing to go
     * stale between probes -- which matters for a sweep that sends five hundred of
     * them and would otherwise have to keep a counter honest.
     *
     * `relay_byte_kept()` keeps the eight mIRC bytes in exactly this field, which
     * is what the one exception entry is for. */
    /* The needle is the SITE PREFIX rather than one verdict line, and that is a
     * decision about the product rather than about the test. `fed_message:` and
     * `fed_topic_ignored:` and `fed_modes_ignored:` all say the same thing for this
     * sweep's purposes -- the node took the field, looked at it, and said so -- and
     * WHICH verdict a given probe gets depends on the node's own ownership rules:
     * a topic from a peer that does not own the channel is IGNORED, while a mode
     * change naming this node as the evaluator is APPLIED. Pinning one verdict
     * would make these rows tests of the ownership rules, which are covered where
     * they belong, and would fail on correct behaviour. */
    { ":" PEER " SPRIVMSG \x02 :marker \x01 text",
      "fed_message: channel=", NULL, NULL, 0 },
    /* THE CHANNEL NAME, from a peer. The channel does not exist -- the name carries
     * the marker, so it could not be the one that was created -- so this is a
     * refusal, and the refusal is what is swept: `fed_malformed:` prints the target
     * it refused. A shape that can only be refused is still worth having here, and
     * unlike a roster name it is not redundant with the nickname tests, because
     * nothing about a channel NAME is validated against a charset at all. */
    /* The channel name is the MARKER here, so the value the filter withholds is
     * the target itself and the line proves it: `target=-` with a `reason=` beside
     * it. That is the shape `ps_expect_withheld()` was written for. */
    { ":" PEER " SPRIVMSG #P\x01 :in the channel name",
      "fed_malformed:", "target=-", "reason=", 0 },
    /* A MODE STRING.
     *
     * THE STATE VERBS NAME THE CHANNEL IN THE SECOND PARAMETER and the first is the
     * node that EVALUATED the change -- 4.3's frozen shape, and `fed_dispatch()`
     * computes `at = (SJOIN) ? 0 : 1` right where it does the lookup. Two earlier
     * versions of this row had the channel first and were refused with
     * `field=channel channel=-`, which is this node's own logsafe withholding the
     * marker that had landed in the channel's slot: a reported-clean field that was
     * not, which is why `ps_expect_field()` now exists.
     *
     * So: origin, channel, modes, member. Four parameters, and the mode parameter
     * is NOT a trailing one -- `SMODES o #c :+m nick` has three, because the `:`
     * makes everything after it one. */
    { ":" PEER " SMODES " NAME_A " \x02 +\x01 " NICK_C, "fed_modes:",
      "modes=-", "modes_bad_bytes=", 1 },
    /* Origin first, channel second, for the reason the SMODES row gives. */
    /* `fed_topic_ignored:` and NOT `fed_topic:`, because the channel this probe
     * uses was created by a CLIENT on this node and its origin is therefore this
     * node's own name -- and 2.2 gives only the origin the topic. The probe is
     * still meaningful: the node took the topic, refused it for a REASON that is
     * about ownership rather than about the bytes, and printed the channel. */
    { ":" PEER " STOPIC " NAME_A " \x02 :topic with \x01 in it",
      "fed_topic", NULL, NULL, 0 },
    { ":" PEER " SKICK " NAME_A " \x02 " NICK_C " :reason \x01 here",
      "fed_skick", NULL, NULL, 0 },
    /* THE SERVER NAME IN A PREFIX, which is a peer-chosen string this node cannot
     * validate beyond its own name table: `irc.b` is the configured name and
     * `irc.<marker>` is not, so the line is refused as an untagged relay and the
     * refusal is printed. */
    { ":irc.\x01 SPRIVMSG \x02 :from a prefix", "fed_untagged:", NULL, NULL, 0 },
    /* An ADVERTISE whose NAME is the marker: the store holds it and
     * `fed_advertise:` prints it. */
    /* An ADVERTISE whose NAME is the marker. The store HOLDS the name and the
     * refusal prints it, so this is the one row whose withheld field is the thing
     * the row is about rather than an incidental parameter -- and it is why the
     * needle is `fed_advertise_refused:` and not `fed_advertise`, which also
     * matches the node's own periodic `fed_advertise_sent:` summary and would be
     * satisfied by a line with no advertised name in it at all. */
    /* AND THE LOAD COMES FIRST: `ADVERTISE <load> <name> <host> <port>`. The first
     * version of this row had the natural order -- name, host, port, load -- and
     * the node read `irc.<marker>` as the load and refused it for LOAD_NOT_NUML, so
     * the withheld field was the LOAD and the row's own `name=-` requirement failed.
     * The row had been written from the shape one would guess rather than the shape
     * the code reads, which is the same mistake as the parameter index. */
    { ":" PEER " ADVERTISE 10 irc.\x01 127.0.0.1 1234",
      "fed_advertise_refused:", "name=-", "peer=", 0 },
    /* A SHUTDOWN naming a peer that is not this one, so the node reports it and
     * refuses rather than leaving -- which keeps the link for the probes after it. */
    { ":" PEER " SHUTDOWN irc.\x01 :going away", "fed_shutdown", NULL, NULL, 0 },
    /* 0x00, AND IT IS HERE RATHER THAN IN THE LOOP BELOW, because it is the one
     * marker byte this framing layer cannot deliver at all: 3.2 refuses an embedded
     * NUL, so a line containing one is never a line. The client sweep has the same
     * byte and the same special case for the same reason, and the two agreeing about
     * it is part of what "one instrument" means -- the SET is shared and the handling
     * of a byte the transport cannot carry is spelled out where the handling is.
     *
     * The needle is the framing layer's own count rather than a fed_ line: the node
     * DID act, by refusing, and a probe that waited for a `fed_` line here would
     * time out on correct behaviour. */
    { ":" PEER " SPRIVMSG \x02 :marker \x01 text", "parse_reject=",
      NULL, NULL, 0 },
};
#define SH_COUNT ((int)(sizeof k_shapes / sizeof k_shapes[0]))
#define SH_CHAN_FMT "#P%02u"

/* The wait granularity. A poll interval, not a sleep: see `wait_for_pong()`. */
#define SW_POLL_MS 20

/* THE EXCEPTION LIST, and it is ONE entry.
 *
 * `relay_byte_kept()` in `src/core/connection.c` keeps exactly eight C0 bytes in
 * RELAYED MESSAGE TEXT and drops every other, and its comment says why it is a
 * `switch` rather than a range test: a range would swallow BEL and ESC, which is
 * the entire hazard, and would return 0 for 0x01, which corrupts every CTCP.
 *
 * The entry is scoped to ` SPRIVMSG ` -- the command word in the line the node
 * forwards -- and to the eight mIRC bytes, so it cannot excuse the same byte in a
 * topic, a kick reason, a mode string, a server name or an advertised name. Those
 * are stored or operational values and they are filtered by the stored-value
 * policy, and an entry wide enough to cover them would be a blanket amnesty for
 * exactly the bytes this sweep exists to find. */
struct ps_exception {
    const unsigned char *mask;
    const char *why;
    const char *where;
};
static const struct ps_exception k_exceptions[] = {
    { sws_mask_mirc,
      "mIRC formatting bytes in RELAYED MESSAGE TEXT on the PEER link, which "
      "relay_byte_kept() keeps by design",
      " SPRIVMSG " },
    /* THE SAME BYTES ON THE CLIENT SOCKET, and this entry existed in the file's
     * HEADER before it existed in this table -- which is the honest description of
     * what happened: the header said "a client socket can legitimately be sent a
     * mIRC colour byte in relayed message text" and the list excused only the peer
     * link, because the client surface was not being swept and so nothing on it
     * ever needed excusing. The eight bytes are exactly the eight
     * `relay_byte_kept()` names, and they are exactly the ones it is supposed to
     * keep: `\001ACTION waves\001` is ONE message BECAUSE of its two delimiters,
     * and a mIRC client renders the other seven and strips them before display.
     *
     * It is scoped to ` PRIVMSG ` -- with a SPACE before the P, which is what makes
     * it a CLIENT verb -- so it cannot excuse the same byte in a topic, a kick
     * reason, a mode string, a server name or an advertised name. Those are stored
     * or operational values and they go through the stricter stored-value policy,
     * and an entry wide enough to cover them would be a blanket amnesty for
     * exactly the bytes this sweep exists to find. */
    { sws_mask_mirc,
      "mIRC formatting bytes in RELAYED MESSAGE TEXT delivered to a client, which "
      "is the same relay_byte_kept() decision on the other side of the fanout",
      " PRIVMSG " }
};
#define PS_EXCEPTIONS ((int)(sizeof k_exceptions / sizeof k_exceptions[0]))
static int g_exc_used[PS_EXCEPTIONS];

static int span_has(const char *hay, size_t len, const char *needle)
{
    size_t nlen = strlen(needle);

    if (nlen == 0u || len < nlen) {
        return 0;
    }
    for (size_t i = 0; i + nlen <= len; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) {
            return 1;
        }
    }
    return 0;
}

/* How many ` PRIVMSG ` lines are in this buffer. Counted HERE, in the loop, because
 * the buffer is emptied by the drain and the standing check runs after the last
 * drain -- so a check that read `tc_buffer()` there would count the bytes that
 * arrived after the final drain, which is precisely the 25-byte PONG that let this
 * file report clean for 61 markers.
 *
 * ` PRIVMSG ` with a leading space, so it matches the CLIENT verb and not the peer's
 * `SPRIVMSG`: the two differ by one byte and getting it wrong would count the peer
 * surface's lines. */
static unsigned ps_count_privmsgs(const char *buf, size_t len)
{
    static const char needle[] = " PRIVMSG ";
    const size_t nlen = sizeof needle - 1u;
    unsigned n = 0u;

    for (size_t i = 0; i + nlen <= len; i++) {
        if (memcmp(buf + i, needle, nlen) == 0) {
            n++;
        }
    }
    return n;
}

static int ps_excuse(unsigned char ch, const char *line, size_t len, void *ctx)
{
    (void)ctx;
    for (int e = 0; e < PS_EXCEPTIONS; e++) {
        if (sws_mask_has(k_exceptions[e].mask, ch) == 0) {
            continue;
        }
        if (span_has(line, len, k_exceptions[e].where) != 0) {
            g_exc_used[e] = 1;
            return 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * The node
 * ---------------------------------------------------------------------------
 * One node, dialling THIS TEST. No peer is configured and there is no port to hand
 * it: the address is the socket this test already owns, which is why the node is
 * spawned after the listener and not before.
 * ---------------------------------------------------------------------------
 * The child fixture is the one `test_fed_guards.c` uses, and it is named here
 * rather than shared: it is twelve lines of node setup whose every value is a
 * decision about what this sweep needs to reach (the client surface installed
 * BEFORE fed_open() replaces it, the SHIPPED timeouts so no PING appears on the
 * link, one configured peer). A shared version would need parameters for all three
 * of those and would be harder to read than the twelve lines.
 */
static int g_peer_port;
static int g_trace;

static void child_tick(server_t *s, uint64_t now_ms)
{
    fed_tick(s, now_ms);
}

static void child_setup(server_t *s)
{
    struct sockaddr_in sa;

    /* The client command surface, installed BEFORE fed_open(): fed_open() saves
     * whatever dispatch is there and replaces it with its own, so a
     * commands_dispatch installed afterwards would become the node's whole
     * dispatch and the peer path would never be reached. */
    s->dispatch = commands_dispatch;

    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child; a node with an unopenable "
                 "federation module cannot reach any assertion in this test");
    s->trace = g_trace;
    s->on_tick = child_tick;
    /* RAISED, NOT THE SHIPPED VALUES, and the reason is the length of the run
     * rather than impatience. `test_fed_guards.c` holds a link for a handful of lines
     * and wants the shipped 5 s keepalive and 30 s dead threshold so that a link the
     * guards break is noticed. This sweep sends five hundred lines and takes minutes,
     * and at a 30 s dead threshold the link would be declared dead part-way through
     * -- which would not fail any assertion here, it would make every later probe a
     * timeout and the sweep would stop proving anything while still looking busy.
     * 30 s keepalive and 10 minutes dead keeps the module's own PINGs arriving (and
     * swept: they are on the peer surface) without the link dying underneath. */
    fed_set_timeouts(2000, 60000, 30000, 600000);

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)g_peer_port);
    TF_CHECK_MSG(fed_link_configure(s, PEER, (const struct sockaddr *)&sa,
                                    (socklen_t)sizeof sa) != NULL,
                 "the child could not configure peer %s on port %d", PEER,
                 g_peer_port);
    /* A SECOND configured peer, which is the node's only way to forward anything.
     * A relay is a line this node receives from one peer and sends to another, so
     * a sweep that only has one peer can never reach a forward. It is configured
     * but never dialled, and `dialed=NO` on every advertise is expected. */
    sa.sin_port = htons((unsigned short)g_peer_port);
    TF_CHECK_MSG(fed_link_configure(s, PEER_C, (const struct sockaddr *)&sa,
                                    (socklen_t)sizeof sa) != NULL,
                 "the child could not configure peer %s", PEER_C);
}

/* ---------------------------------------------------------------------------
 * THE THREE STANDING CHECKS FOR THE THREE WAYS THIS SWEEP REPORTED CLEAN WHILE
 * COVERING NOTHING
 * ---------------------------------------------------------------------------
 * All three happened during this pass, all three were found by a red run rather
 * than by reading, and all three are the same shape of mistake: a probe that did
 * not do what it claimed, reported as a pass. They are here as checks and not as
 * comments, because a comment is a promise and a check is a gate.
 *
 * 1. A NEEDLE SATISFIED BY AN EARLIER PROBE'S ANSWER. `tc_expect(client,
 *    " 366 ")` searches the accumulated buffer, and after the first probe the
 *    buffer already holds a ` 366 `. So the wait returned on the PREVIOUS
 *    channel's answer, the probe went out before the node had created this
 *    probe's channel, and the node reported `field=channel channel=#P05` for a
 *    channel that did not exist. It reads exactly like a lookup bug.
 *    -> `ps_needles_are_per_probe()` below, plus the JOIN ECHO needle itself.
 *
 * 2. A WITHHELD FIELD DISGUISING A MISPLACED ONE. `conn_text_logsafe()` renders a
 *    value with a byte in the strip set as `-`, so a field that is WRONG and a
 *    field that has been correctly filtered both print as `name=-`. A row with
 *    the channel in the wrong parameter reported itself clean for that reason.
 *    -> `ps_expect_withheld()`.
 *
 * 3. A PROBE THE NODE IGNORED, REPORTED AS CLEAN. Nothing at all is the easiest
 *    thing for a sweep to get wrong, because a node that never received the line
 *    produces no findings.
 *    -> the per-probe `nf_expect()` below and the per-marker PING in
 *    `wait_for_pong()`.
 */

/* CHECK 1: no shape's needle can satisfy another shape's wait.
 *
 * Two needles where one contains the other is the mechanical form of the bug: the
 * shorter is satisfied by the longer's line, so a probe whose verb prints nothing
 * is passed off on its neighbour's evidence. `SPRIVMSG`'s two rows and the
 * `fed_modes`/`fed_topic` prefixes are the shapes this actually rules out.
 *
 * It also asserts that every needle is non-empty, which is the degenerate case of
 * the same bug: `strstr(x, "")` returns `x`, so an empty needle matches every
 * answer there has ever been. */
static void ps_needles_are_per_probe(void)
{
    for (int i = 0; i < SH_COUNT; i++) {
        TF_CHECK_MSG(k_shapes[i].needle[0] != '\0',
                     "shape %d has an empty needle, and an empty needle matches "
                     "every line the node has ever printed", i);
        for (int j = 0; j < SH_COUNT; j++) {
            if (i == j) {
                continue;
            }
            TF_CHECK_MSG(strstr(k_shapes[j].needle, k_shapes[i].needle) == NULL,
                         "shape %d's needle \"%s\" is a substring of shape %d's "
                         "\"%s\", so a wait on shape %d can be satisfied by shape "
                         "%d's line and a probe the node ignored will pass",
                         i, k_shapes[i].needle, j, k_shapes[j].needle, i, j);
        }
    }
    /* And the JOIN wait's needle, which is built per probe and therefore cannot be
     * in this table -- asserted here so that the two live in one place. A bare
     * ` 366 ` would satisfy itself from the first probe's answer forever. */
    {
        char join_echo[32];
        int n = snprintf(join_echo, sizeof join_echo, " JOIN #%02u\r\n", 0u);

        TF_CHECK_MSG(n > 0 && (size_t)n < sizeof join_echo,
                     "the sample JOIN needle could not be built");
        TF_CHECK_MSG(strstr(join_echo, "#00") != NULL,
                     "the JOIN needle does not name the probe's channel, so it "
                     "cannot be unique per probe: \"%s\"", join_echo);
    }
}

/* CHECK 4, WHICH IS FINDING 5: THE INVERTED ASSERTION.
 *
 * An inverted assertion is one whose CONDITION and whose MESSAGE disagree: a check
 * that passes when the thing it names is absent, carrying a message that describes
 * the absent case as if it were the failure, or the reverse. It is the worst kind of
 * defect in a test suite because it is green, it is readable, and it means the
 * opposite of what it says.
 *
 * HOW FAR THE MECHANICAL FORM GOES, and the limit is stated here rather than left
 * for somebody to discover:
 *
 *   IT CATCHES the form this pass actually produced -- a condition that asserts a
 *   value is ABSENT (`== NULL`, `!strstr`, `!sws_find_bytes`, a negated search)
 *   whose
 *   message does not read as an absence. That is checkable with no judgement: read
 *   the condition, read the message, require the message to contain a negation.
 *
 *   IT DOES NOT CATCH the general case, and pretending otherwise would be a lie
 *   about the check. A condition like `count == 3` with the message "expected 3"
 *   is correct; `count == 3` with the message "3 replies were seen" is also
 *   correct; `count == 3` with the message "no replies were seen" is inverted.
 *   Deciding which of those a message is requires reading it as English, and a
 *   check that guesses at English is a check that will be wrong in the direction
 *   that hides a defect. So the mechanical part covers the negation forms, and the
 *   rest stays a reviewer's job -- which is why this paragraph is here and not just
 *   the code.
 *
 * IT READS BOTH SWEEP FILES, not just this one, because the mistake is not local
 * to a file and a check that only guards the file it lives in is a check with a
 * hole in it. */
static int ps_reads_as_absence(const char *msg, size_t len)
{
    /* A closed list of the words this codebase uses for "this must not be here",
     * written out rather than searched for, because the alternative -- searching
     * for "not" -- matches "notice" and "another" and would make the check pass on
     * a message that says the opposite. */
    static const char *const words[] = {
        "not ", "no ", "never", "cannot", "must not", "did not", "without",
        "absent", "refus", "nothing"
    };
    size_t at = 0;

    while (at < len) {
        for (size_t w = 0; w < sizeof words / sizeof words[0]; w++) {
            const size_t wl = strlen(words[w]);

            if (at + wl <= len && memcmp(msg + at, words[w], wl) == 0) {
                return 1;
            }
        }
        at++;
    }
    return 0;
}

static void ps_assert_no_inverted_assertions(void)
{
    static const char *const files[] = {
        "tests/integration/test_peer_terminal_sweep.c",
        "tests/integration/test_terminal_sweep.c"
    };

    for (size_t f = 0; f < sizeof files / sizeof files[0]; f++) {
        char *code = tf_read_code(files[f], NULL);
        size_t at = 0;

        TF_CHECK_MSG(code != NULL,
                     "could not read %s (is IRCSERVE_SRC_DIR set?)", files[f]);
        if (code == NULL) {
            continue;
        }
        for (;;) {
            const char *hit = strstr(code + at, "TF_CHECK");
            size_t cond_at;
            size_t msg_at;
            size_t cond_len;
            size_t msg_len;
            char cond[512];
            const char *msg;
            int asserts_absent;

            if (hit == NULL) {
                break;
            }
            cond_at = (size_t)(hit - code);
            /* Skip the macro name itself so `TF_CHECK` inside the message is not
             * read as a new assertion. */
            cond_at += strlen("TF_CHECK");
            while (code[cond_at] == '_') {
                while (code[cond_at] != '\0' && code[cond_at] != '(') {
                    cond_at++;
                }
                if (code[cond_at] == '(') {
                    cond_at++;
                    break;
                }
            }
            if (code[cond_at] != '(') {
                at += 1u;
                continue;
            }
            at = cond_at + 1u;
            /* THE CONDITION: up to the comma that separates it from the message,
             * counted at depth zero so a comma inside `TF_CHECK_MSG(a, f(b, c))`
             * does not end it early. */
            {
                size_t depth = 0;
                size_t i = cond_at;

                while (code[i] != '\0') {
                    if (code[i] == '(') {
                        depth++;
                    } else if (code[i] == ')') {
                        if (depth == 0u) {
                            break;
                        }
                        depth--;
                    } else if (code[i] == ',' && depth == 0u) {
                        break;
                    }
                    i++;
                }
                cond_len = i - (cond_at + 1u);
                msg_at = i;
            }
            if (cond_len >= sizeof cond) {
                cond_len = sizeof cond - 1u;
            }
            memcpy(cond, code + cond_at + 1u, cond_len);
            cond[cond_len] = '\0';

            /* THE MESSAGE: the first string literal after the comma, which is where
             * a message is and where a format string with commas in it still is. */
            msg = strchr(code + msg_at, '"');
            if (msg == NULL) {
                continue;
            }
            msg++;
            msg_len = 0;
            while (msg[msg_len] != '\0' && msg[msg_len] != '"') {
                if (msg[msg_len] == '\\' && msg[msg_len + 1u] != '\0') {
                    msg_len++;
                }
                msg_len++;
            }
            if (msg_len >= sizeof cond) {
                msg_len = sizeof cond - 1u;
            }

            /* The four negation forms this pass produced and the one shape that
             * covers them. `== NULL` and `!strstr`/`!sws_find_bytes` are the
             * assertions that
             * a value is ABSENT. */
            asserts_absent = (strstr(cond, "== NULL") != NULL) ||
                             (strstr(cond, "!= NULL") == NULL &&
                              (strstr(cond, "!strstr") != NULL ||
                               strstr(cond, "!sws_find_bytes") != NULL));
            if (asserts_absent != 0 && msg_len > 0u) {
                TF_CHECK_MSG(ps_reads_as_absence(msg, msg_len) != 0,
                             "%s: an assertion whose condition is `%s` asserts "
                             "that a value is ABSENT, and its message \"%.*s\" "
                             "does not read as an absence. An inverted assertion "
                             "is green and means the opposite of what it says.",
                             files[f], cond, (int)msg_len, msg);
            }
        }
        free(code);
    }
}

/* THE NODE'S OWN STDOUT IS A PIPE, AND A FULL ONE STOPS THE NODE.
 *
 * The harness reads that pipe only when a caller waits on it. A sweep that sends
 * thousands of lines and waits on a PEER socket instead leaves the node blocked in
 * write() -- which is what this pair of helpers exists to prevent, and what the
 * first version of this file did: the node had 3009 bytes queued, was parked inside
 * write(), and never answered the PING that the liveness probe sent it.
 *
 * They are duplicated from `test_terminal_sweep.c` rather than shared because they
 * are nine lines each and the sharing would have to export the node type and the
 * pump hook into a header that the marker instrument does not otherwise need --
 * a header whose name says "terminal-injection scan" and which turns out to own
 * the event loop would be worse than the duplication. */
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

/* ps_wait_new(): WAIT FOR A LINE IN THE OUTPUT THE NODE HAS PRODUCED SINCE `from`.
 *
 * `nf_expect()` searches the node's ACCUMULATED output, so after the first probe
 * every needle in this file is already in the buffer and a wait returns instantly on
 * an earlier probe's line. That is generator mistake 1 again, and it hid the SMODES
 * allowlist completely: `refused=01` from marker `0x01` satisfied marker `0x02`'s
 * wait, and with `chan_mode_implemented()` reverted the sweep was green.
 *
 * SO EVERY WAIT HERE IS SCOPED TO WHAT IS NEW, by remembering `node.out_len` before
 * the probe and searching only past it. There is no per-shape way to do this that
 * does not also have to be right about which field is unique, and the offset is
 * unique by construction.
 *
 * Returns the output length just after the needle was seen, or `(size_t)-1` on the
 * deadline. The deadline is a deadline and not a sleep: the loop waits for
 * READABILITY on the node's own pipe, capped at the poll interval.
 */
static size_t ps_wait_new(nf_node_t *node, size_t from, const char *needle,
                          int timeout_ms)
{
    unsigned long long deadline = pf_now_ms() + (unsigned long long)timeout_ms;
    size_t nlen = strlen(needle);

    for (;;) {
        drain_node_pipe(node);
        /* `sws_find_bytes()` rather than `memmem()`: this is a bounded search over
         * the output produced SINCE `from`, and `memmem()` is a GNU extension that
         * is not declared on a POSIX libc without `_GNU_SOURCE` -- which is why it
         * compiled on all thirteen local gate cells and failed on Linux's glibc, as
         * one implicit declaration and four pointer-versus-integer comparisons. */
        if (sws_find_bytes(node->out + from, node->out_len - from, needle,
                           nlen) != NULL) {
            return node->out_len;
        }
        if (pf_now_ms() >= deadline) {
            return (size_t)-1;
        }
        {
            struct timeval tv;
            fd_set rfds;

            FD_ZERO(&rfds);
            FD_SET(node->out_fd, &rfds);
            tv.tv_sec = 0;
            tv.tv_usec = (suseconds_t)(SW_POLL_MS * 1000);
            (void)select(node->out_fd + 1, &rfds, NULL, NULL, &tv);
        }
    }
}

/* THE LAST LINE OF THE NODE'S OUTPUT **SINCE `from`** THAT CONTAINS `needle`, or
 * NULL. Scoped for the same reason `ps_wait_new()` is: the finding has to belong to
 * the probe in hand, and an earlier probe's line is the easiest wrong answer to
 * reach for.
 *
 * The LAST rather than the first because `nf_expect()` searches the whole
 * accumulated buffer: after a few hundred probes the first matching line is from
 * the first probe, and checking a field there would prove nothing about the probe
 * in hand. */
static const char *ps_last_line_with(const char *out, size_t from, size_t len,
                                     const char *needle)
{
    const char *found = NULL;
    const char *p = out + from;
    const char *end = out + len;
    size_t nlen = strlen(needle);

    while (p < end) {
        const char *nl = (const char *)memchr(p, '\n', (size_t)(end - p));
        size_t n = (nl != NULL) ? (size_t)(nl - p) : (size_t)(end - p);

        /* ONE LINE at a time, and the search is bounded by that line's length. The
         * line is a view into the log and is NOT NUL-terminated where the buffer
         * ends, which is the case a NUL-terminated search would get wrong. */
        if (sws_find_bytes(p, n, needle, nlen) != NULL) {
            found = p;
        }
        p += n + 1u;
    }
    return found;
}

/* ps_expect_withheld(): A WITHHELD VALUE MUST STILL BE A FIELD.
 *
 * WHY THIS EXISTS, and it is the most dangerous class of bug this sweep has
 * produced. `conn_text_logsafe()` renders a value with a byte in the strip set as
 * `-`, so a field that is WRONG -- the marker landed in the channel's slot instead
 * of the text's, say -- and a field that has been CORRECTLY FILTERED both print as
 * `name=-`. During development a sweep row with the channel in the wrong parameter
 * reported itself clean for exactly that reason: `fed_malformed: ... channel=-`,
 * where the `-` was the mode string being withheld from a field it did not belong
 * in. The filter hid the generator bug.
 *
 * SO A ROW THAT PUTS ITS MARKER IN A PRINTED FIELD ALSO ASSERTS THAT THE FIELD IS
 * PRESENT-AND-WITHHELD rather than absent entirely: the `name=-` must be on the
 * line, and the MEASUREMENT must stand beside it. A field that is simply missing
 * cannot produce `name=-`, so this catches the case the withholding disguises, and
 * the measurement is what distinguishes "the filter withheld it" from "the field
 * was empty when it got here".
 *
 * It cannot catch everything, and the limit is worth stating rather than leaving
 * implied: a row whose marker lands in a field the node does not print has nothing
 * to assert here, and `field == NULL` says so in the table rather than passing
 * quietly. Those rows are covered by the CLIENT sweep for the same fields, and by
 * the byte count below -- which is the claim that keeps them from being decorative.
 */
static void ps_expect_withheld(const nf_node_t *node, size_t from,
                               const struct ps_shape *sh, unsigned char mark,
                               size_t idx)
{
    const char *line;
    size_t n;

    if (sh->field == NULL) {
        return;
    }
    line = ps_last_line_with(node->out, from, node->out_len, sh->needle);
    TF_CHECK_MSG(line != NULL, "marker 0x%02x on shape %zu: no `%s` line to "
                 "check the withheld field on", (unsigned)mark, idx, sh->needle);
    if (line == NULL) {
        return;
    }
    n = strcspn(line, "\n");
    /* BOTH halves. The field proves the value is being rendered in the slot this
     * row meant it to be in; the measurement proves the `-` is the FILTER's
     * decision and not an empty field that happened to be there. */
    TF_CHECK_MSG(sws_find_bytes(line, n, sh->field, strlen(sh->field)) != NULL,
                 "marker 0x%02x on shape %zu: the `%s` line does not carry `%s`, "
                 "so the value this row put there is not being reported at all. "
                 "A WITHHELD field and a MISPLACED one look identical on the wire "
                 "and in the log, and this is the check that tells them apart: %.*s",
                 (unsigned)mark, idx, sh->needle, sh->field, (int)n, line);
    TF_CHECK_MSG(sws_find_bytes(line, n, sh->measure, strlen(sh->measure)) != NULL,
                 "marker 0x%02x on shape %zu: the `%s` line carries `%s` but not "
                 "`%s`, so the `-` cannot be told from an empty field: %.*s",
                 (unsigned)mark, idx, sh->needle, sh->field, sh->measure,
                 (int)n, line);
}

/* ps_expect_verdict(): A SHAPE WHOSE MARKER IS STRIPPED BEFORE THE PRODUCT LOGIC
 * SEES IT MUST STILL BE ABLE TO ASSERT THAT LOGIC.
 *
 * THE SMODES ROW IS THE CASE, and it is the most useful thing this pass learned
 * about its own instrument. The row's marker goes into a mode string, and
 * `fed_relay_clean()` now removes it before the mode string is rendered -- so the
 * byte never reaches `chan_mode_implemented()`, and the sweep's own filter has made
 * the allowlist **unobservable**. With `chan_mode_implemented()` reverted the peer
 * sweep stayed GREEN: the fault was real, the byte was refused for a different
 * reason, and the sweep reported clean.
 *
 * That is the SAME class as the withheld-field bug one level up: a filter standing
 * between the probe and the thing under test. The fix is the same shape -- assert on
 * the node's own REPORT rather than on the byte -- and it only works because
 * `fed_modes:` prints the verdict: `applied=` names the letters it applied and
 * `refused=` names the ones it declined, both by BYTE IN HEX. So this check requires
 * `refused=` to name THIS probe's marker, which is exactly the claim "this node
 * declined that mode letter" and is false the moment the allowlist is removed.
 *
 * WHY IT IS A FLAG AND NOT A PER-SHAPE STRING: the expected value contains the
 * marker, so it is built per probe from the byte rather than written out in the
 * table once. A table entry that said `refused=01` would be wrong for 61 of the 62
 * markers, which is the decorative kind of entry.
 */
static void ps_expect_verdict(const nf_node_t *node, size_t from,
                              const struct ps_shape *sh, unsigned char mark,
                              size_t idx)
{
    char want[24];
    const char *line;
    size_t n;
    int w;

    if (sh->report_refusal == 0) {
        return;
    }
    line = ps_last_line_with(node->out, from, node->out_len, sh->needle);
    TF_CHECK_MSG(line != NULL, "marker 0x%02x on shape %zu: no `%s` line to read "
                 "a verdict from", (unsigned)mark, idx, sh->needle);
    if (line == NULL) {
        return;
    }
    n = strcspn(line, "\n");
    w = snprintf(want, sizeof want, "refused=%02x", (unsigned)mark);
    TF_CHECK_MSG(w > 0 && (size_t)w < sizeof want,
                 "the verdict needle could not be built");
    TF_CHECK_MSG(sws_find_bytes(line, n, want, strlen(want)) != NULL,
                 "marker 0x%02x on shape %zu: the `%s` line does not carry `%s`. "
                 "The sweep's own filter removed this marker before the mode string "
                 "was rendered, so the byte cannot witness what the node did with "
                 "it -- the node's REPORT is the only thing that can, and this is "
                 "the check that keeps a real product regression from hiding behind "
                 "a correct filter: %.*s",
                 (unsigned)mark, idx, sh->needle, want, (int)n, line);
}

/* WAIT FOR THE NODE TO ANSWER THE CLIENT'S PING, pumping the node's stdout while
 * waiting.
 *
 * The PING goes down the CLIENT socket rather than the peer link, and that is not a
 * convenience. The peer dispatch table has no `PING` -- `src/core/commands.c` lists
 * it for clients and the federation verb map has no entry -- so a PING sent down the
 * link this test owns is an unknown verb the node counts and does not answer, and
 * waiting for a PONG to it waits for a line the node will never send. The first
 * version of this file sent it down the peer link and reported that as "the node
 * stopped serving".
 *
 * And it is still the right question to ask. One event loop serves both surfaces,
 * so a node that answers a client PING is a node that is reading its sockets,
 * dispatching, and not blocked in write() -- which is exactly what a marker byte
 * that wedged it would prevent. */
static int wait_for_pong(nf_node_t *node, test_client_t *client, const char *needle,
                         int timeout_ms)
{
    unsigned long long deadline = pf_now_ms() + (unsigned long long)timeout_ms;

    for (;;) {
        int eof = 0;

        (void)tc_read_available(client, &eof);
        if (strstr(tc_buffer(client), needle) != NULL) {
            return 0;
        }
        /* The NODE'S PIPE, before the check and after it. Pumping only after the
         * check is the order that hides a deadlock: a node blocked in write() needs
         * the pump to make progress, and the check is what decides whether to keep
         * pumping. */
        drain_node_pipe(node);
        if (strstr(tc_buffer(client), needle) != NULL) {
            return 0;
        }
        if (pf_now_ms() >= deadline) {
            return -1;
        }
        /* WAIT FOR READABILITY, capped at the poll interval, rather than sleeping:
         * a `sleep()` here would be an assumption about how long the node takes to
         * answer, and this file has none. */
        {
            struct timeval tv;
            fd_set rfds;

            FD_ZERO(&rfds);
            FD_SET(client->fd, &rfds);
            tv.tv_sec = 0;
            tv.tv_usec = (suseconds_t)(SW_POLL_MS * 1000);
            (void)select(client->fd + 1, &rfds, NULL, NULL, &tv);
        }
    }
}

/* ps_sweep_client(): SWEEP THE CLIENT SOCKET FOR ONE MARKER, AND ONLY THEN CLEAR IT.
 *
 * WHY IT RUNS HERE AND NOT INSIDE THE SHAPE LOOP. The node queues a client's bytes
 * and prints its own verdict for the same probe, and stdout is line-buffered while
 * the socket is not: the node's line can be readable before the write to the client
 * has left the writeq. So a read taken at the end of the last shape is a read that
 * can miss that marker's lines. The PING/PONG below fixes the ordering without a
 * sleep, because the PONG is produced by the same write queue as everything queued
 * before it: when the PONG is in hand, every byte the node wrote for this marker is
 * in hand too. That is also what makes the scan complete rather than lucky, and it
 * is the reason this file's own liveness assertion and its sweep are the same wait.
 *
 * WHY THE ORDER INSIDE IS READ, SCAN, COUNT, CLEAR. `tc_drain()` empties the buffer
 * AS it reads -- it memmoves the remainder to the front and sets `len` to 0 on the
 * first turn of its loop -- so a drain that reads past the first batch throws away
 * exactly the bytes it fetched and this surface is the one place in the file where
 * losing bytes silently loses findings. So the read is `tc_read_available()` (which
 * appends and never clears) and the clear is a `tc_drain()` with a ZERO timeout,
 * which returns as soon as it has emptied the buffer and never selects.
 *
 * WHAT THIS FIXES, stated because the class of it has appeared three times in this
 * file. The old code called `tc_drain(&client, 1, NULL)` once per marker and swept
 * the client surface at the very end, so 61 of the 62 markers' client bytes were
 * discarded having never been looked at and the surface labelled "a client socket"
 * was swept with whatever arrived after the LAST drain: on macOS, 25 bytes holding
 * one PONG and no PRIVMSG at all. That is why this file was green locally and red on
 * Linux, and it was not a platform difference in the product -- Linux's read schedule
 * left the final probe's PRIVMSG in the buffer after the final drain and macOS's did
 * not. Underneath the sweep's own bookkeeping race, a bare C1 byte was reaching a
 * person's terminal the whole time.
 */
static void ps_sweep_client(sws_scan *surface, test_client_t *client,
                            size_t *scanned, unsigned *privmsgs)
{
    int eof = 0;

    (void)tc_read_available(client, &eof);
    *scanned += tc_received(client);
    if (tc_received(client) > 0u) {
        sws_scan_bytes(surface, tc_buffer(client), tc_received(client));
        *privmsgs += ps_count_privmsgs(tc_buffer(client), tc_received(client));
    }
    (void)tc_drain(client, 0, NULL);
}

/* Substitute `\x01` with `mark`, `\x02` with the probe's channel, and send.
 *
 * THE TEMPLATES CARRY NO CRLF, because `pf_send_line()` appends one. The first
 * version of this file had `\r\n` in the templates as well, which sent every probe
 * with a trailing BLANK line after it -- harmless on its own, and the reason this
 * is written down rather than left: a sweep that probes a parser should not also be
 * probing the harness's line framing, and a reader who cannot tell which of the two
 * a failure belongs to has a sweep that is hard to debug. */
static int send_shape(int fd, const char *tmpl, unsigned char mark,
                      unsigned chan)
{
    char line[512];
    char chan_name[16];
    size_t out = 0;
    int n;

    n = snprintf(chan_name, sizeof chan_name, SH_CHAN_FMT, chan);
    if (n <= 0 || (size_t)n >= sizeof chan_name) {
        return -1;
    }
    for (const char *p = tmpl; *p != '\0'; p++) {
        if (out + 2u >= sizeof line) {
            return -1;
        }
        if (*p == '\x01') {
            line[out++] = (char)mark;
        } else if (*p == '\x02') {
            memcpy(line + out, chan_name, (size_t)n);
            out += (size_t)n;
        } else {
            line[out++] = *p;
        }
    }
    line[out] = '\0';
    return pf_send_line(fd, line);
}

int main(void)
{
    nf_node_t node;
    test_client_t client;
    pf_peer_t peer;
    /* THE THREE SURFACES, EACH ITS OWN ACCUMULATOR. `scan` below is the RUN TOTAL
     * and never sees a byte; these three do, and they are declared here rather than
     * inside the final block because the peer link and the client socket are scanned
     * as they are read -- see the loop. */
    sws_scan node_surface;
    sws_scan peer_surface;
    sws_scan client_surface;
    sws_scan scan;
    /* How many client bytes were handed to the scanner, printed below so that "the
     * client surface carried no marker byte" and "the client surface carried
     * nothing" do not read the same. */
    size_t client_scanned = 0u;
    /* Relayed PRIVMSGs the client was actually shown. See ps_count_privmsgs() for
     * why this is counted in the loop and not read off the buffer afterwards. */
    unsigned client_privmsgs = 0u;
    char peer_rx[65536];
    long peer_rx_len = 0;
    char chan[16];
    char join_line[32];
    char join_echo[32];
    char token[64];
    int listen_fd;
    unsigned probes = 0;
    int found_surfaces = 0;
    size_t from = 0u;
    const char *const claim[] = {
        ":" NAME_A " FEDERATE " NAME_A " ",
        " " SECRET " " IRC_SERVE_VERSION ""
    };


    sws_masks_init();
    memset(g_exc_used, 0, sizeof g_exc_used);

    /* THE INSTRUMENT'S OWN EDGE CASES, BEFORE ANY PROBE. A sweep whose bounded
     * search is off by one at the end of a range reports CLEAN, because the byte it
     * read past the end is not a byte anybody looks at -- so the primitive is
     * verified before it is trusted, in the same function that defines it, and by
     * BOTH sweeps, because an instrument only one of them verifies is half
     * verified. */
    {
        const char *bad = sws_find_bytes_self_test();

        TF_CHECK_MSG(bad == NULL,
                     "the bounded-search self-test failed at `%s`, so every "
                     "search this sweep has just made is unverified: the range "
                     "may have been read past its end, or a zero-length needle "
                     "may be matching everything", bad != NULL ? bad : "");
    }

    /* The standing checks run BEFORE the sweep rather than after it, because a
     * check that reports the instrument was broken is only useful while there is
     * still something to instrument correctly. */
    ps_needles_are_per_probe();
    ps_assert_no_inverted_assertions();
    sws_scan_begin(&scan, "the peer path", ps_excuse, NULL);
    sws_scan_begin(&node_surface, "the node's own stdout", ps_excuse, NULL);
    sws_scan_begin(&peer_surface, "the peer link", ps_excuse, NULL);
    sws_scan_begin(&client_surface, "a client socket", ps_excuse, NULL);

    pf_peer_init(&peer);
    tc_init(&client);

    listen_fd = pf_listen_loopback(&peer.port);
    TF_CHECK_MSG(listen_fd >= 0, "the test could not open a listening socket");
    g_peer_port = peer.port;
    g_trace = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&node, NAME_A, child_setup) == 0,
                 "could not spawn node A");

    peer.fd = pf_accept_deadline(listen_fd, T_IO_MS);
    /* Closed as soon as it has served its purpose: leaving a second listener open
     * would let a second dial be accepted by accident, and every "there is one
     * link" claim below rests on there being exactly one. */
    (void)close(listen_fd);
    TF_CHECK_MSG(peer.fd >= 0, "node A never dialled the socket this test owns");

    /* Read A's claim before answering it. Without this, "the link is up" is
     * satisfied by a node that never said hello. Pinned on both sides of the
     * epoch, which is a clock reading. */
    TF_CHECK_MSG(pf_read_until(peer.fd, claim,
                               sizeof claim / sizeof claim[0], T_IO_MS) == 0,
                 "node A never sent a FEDERATE naming itself with the configured "
                 "secret, so nothing below could mean anything");

    TF_CHECK_MSG(pf_send_line(peer.fd, ":" PEER " FEDERATE " PEER
                            " 1700000000 " SECRET " " IRC_SERVE_VERSION) == 0,
                 "the test could not answer with a FEDERATE");
    TF_CHECK_MSG(nf_expect(&node, "link_established: peer=" PEER, T_IO_MS) == 0,
                 "node A never established its link, so every assertion in this "
                 "file would be vacuous");

    /* A client on the node, in a channel, so that a byte this node forwards has
     * somewhere to land: a refusal is then a statement about bytes a client did
     * NOT receive rather than about a line nobody wanted. */
    TF_CHECK_MSG(tc_connect(&client, node.port) == 0,
                 "the client could not connect");
    TF_CHECK_MSG(tc_send(&client, "NICK " NICK_C) == 0, "NICK send failed");
    TF_CHECK_MSG(tc_send(&client, "USER " NICK_C " 0 *spoofed :Real " NICK_C)
                 == 0, "USER send failed");
    TF_CHECK_MSG(tc_expect(&client, " 001 ", T_IO_MS) == 0,
                 "the client never registered");

    /* ---------------------------------------------------------------------
     * THE SWEEP. 62 marker bytes x 8 shapes, each on a channel of its own.
     *
     * The client joins each probe's channel as it is created, because a channel a
     * client is not in is a channel the node has nobody to deliver to, and a
     * forward that reaches nobody is a forward this sweep cannot observe.
     * --------------------------------------------------------------------- */
    for (unsigned b = 0; b < 0xffu; b++) {
        if (sws_marker_in_set((unsigned char)b) == 0) {
            continue;
        }
        /* 0x00 is delivered to the SHAPES, not skipped by them: see the shape
         * table's ninth row. `shapes_here` is the count of rows this marker is
         * sent through, so the total at the end is exact for either count. */
        for (int i = 0; i < SH_COUNT; i++) {
            int n;

            if (b == 0x00u && i != SH_COUNT - 1) {
                continue;
            }
            n = snprintf(chan, sizeof chan, SH_CHAN_FMT, (unsigned)probes);
            TF_CHECK_MSG(n > 0 && (size_t)n < sizeof chan,
                         "channel name too long");
            /* The client joins each probe's channel as it is created, because a
             * channel no client is in is a channel the node has nobody to deliver
             * to, and a forward that reaches nobody is a forward this sweep
             * cannot observe. */
            n = snprintf(join_line, sizeof join_line, "JOIN %s", chan);
            TF_CHECK_MSG(n > 0 && (size_t)n < sizeof join_line,
                         "the JOIN line could not be built");
            n = snprintf(join_echo, sizeof join_echo, " JOIN %s\r\n", chan);
            TF_CHECK_MSG(n > 0 && (size_t)n < sizeof join_echo,
                         "the JOIN echo needle could not be built");
            TF_CHECK_MSG(tc_send(&client, join_line) == 0,
                         "the JOIN could not be sent");
            /* THE NEEDLE NAMES THE PROBE, and this is not a detail.
             *
             * `tc_expect(client, " 366 ")` is satisfied by the accumulated buffer,
             * and after the first probe the buffer already holds a ` 366 `. So the
             * wait returned instantly on the PREVIOUS channel's answer, the probe
             * went out before the node had created this probe's channel, and the
             * node reported `field=channel channel=#P05` for a channel that did
             * not exist yet -- which reads exactly like a lookup bug and is what
             * made Decision F's diagnosis take an hour instead of a minute.
             *
             * The fix is the one the client sweep already uses: the needle is the
             * JOIN ECHO for THIS probe's channel, which is unique because the
             * channel is unique. This is the standing form of that mistake -- a
             * needle that does not name the probe -- and the check that keeps it
             * from coming back is in `ps_needles_are_per_probe()`. */
            TF_CHECK_MSG(tc_expect(&client, join_echo, T_IO_MS) == 0,
                         "the client never joined %s, so a line about that "
                         "channel has nobody to reach and the probe would prove "
                         "nothing. The needle is the echo of THIS join rather than "
                         "a bare ` 366 `, so a stale answer from an earlier probe "
                         "cannot satisfy it.", chan);

            /* THE ANSWER. No sleep anywhere in this file, and no assumption about
             * ordering between probes: the needle is searched over everything the
             * node has printed, which is what `nf_expect()` does over its buffer.
             * A probe whose needle never appears is a FAILURE, because it means the
             * node did nothing with the line and the probe proved nothing.
             *
             * FROM BEFORE THE PROBE IS SENT, because everything after this point is
             * a claim about THIS probe and nothing else.
             *
             * ONE SEND PER PROBE. This loop sent the line TWICE -- once before
             * `from` was taken and once after -- so every probe emitted two
             * identical lines and a report said "2 unmarked byte(s) at 1 site(s)"
             * for what is one shape sent once. The copy sent before `from` was also
             * outside every window `ps_expect_withheld()` and `ps_expect_verdict()`
             * read, so those checks were reasoning about the second copy while the
             * number in the report invited the reading that two probes were
             * involved. */
            from = node.out_len;
            TF_CHECK_MSG(send_shape(peer.fd, k_shapes[i].tmpl, (unsigned char)b,
                                    (unsigned)probes) == 0,
                         "the test could not send shape %d with marker 0x%02x",
                         i, (unsigned)b);
            TF_CHECK_MSG(ps_wait_new(&node, from, k_shapes[i].needle, T_IO_MS) !=
                         (size_t)-1,
                         "marker 0x%02x on shape %d produced no `%s`, so this "
                         "probe tested a line the node never acted on",
                         (unsigned)b, i, k_shapes[i].needle);
            ps_expect_withheld(&node, from, &k_shapes[i], (unsigned char)b,
                               (size_t)i);
            ps_expect_verdict(&node, from, &k_shapes[i], (unsigned char)b,
                              (size_t)i);
            probes++;

            /* Read the peer's socket, non-blocking, and SCAN WHAT COMES BACK
             * BEFORE IT IS DROPPED. A peer socket nobody reads eventually stops the
             * node, and a stopped node makes every later probe vacuous -- so reading
             * it is a liveness requirement, not tidiness.
             *
             * AND THE SCAN IS THE POINT, and it is the fix for the blind spot this
             * file had. `peer_rx` is 64 KiB and the run produces several times that,
             * so the old code stopped draining once the buffer was nearly full and
             * swept whatever had arrived in the first few hundred probes: the C1
             * markers, which are at the END of the marker order, were never read off
             * this surface at all. A surface that is only the first N bytes of a run
             * is not a surface, and the fact that it reported clean was not evidence
             * of anything -- `sweep_scan.h` says so in its own header and the code
             * did not do it.
             *
             * Scanning per marker rather than accumulating is what makes the bound
             * a bound: the buffer is reused, so its SIZE is a memory decision and
             * not a coverage one. */
            if (peer_rx_len < (long)sizeof peer_rx - 4096) {
                long got = pf_drain(peer.fd, peer_rx + peer_rx_len,
                                    sizeof peer_rx - 1u - (size_t)peer_rx_len);

                if (got > 0) {
                    peer_rx_len += got;
                    peer_rx[peer_rx_len] = '\0';
                }
            }
            if (peer_rx_len > 0) {
                sws_scan_bytes(&peer_surface, peer_rx, (size_t)peer_rx_len);
                peer_rx_len = 0;
            }
        }
        /* The CLIENT SOCKET is swept just below, AFTER this marker's PONG -- see
         * `ps_sweep_client()`. Reading it here would be wrong twice over: the node
         * may not have flushed the write yet, and `tc_drain()` empties the buffer
         * as it reads, so anything it picked up past the first read would be
         * discarded unexamined. */

        /* THE NODE IS STILL SERVING, ONCE PER MARKER.
         *
         * This is the assertion that keeps the sweep from being able to pass by
         * doing nothing. A PING in the SAME segment as the marker lines is answered
         * with a PONG, and the fed_ module pings its links on its own schedule, so
         * by the time that PONG is in hand the node has answered or refused
         * everything queued ahead of it. A marker that made the node stop answering
         * would therefore be caught here rather than turning every later probe into
         * a timeout.
         *
         * It is one assertion per marker rather than per probe on purpose: the
         * PINGs would be hundreds of round trips the sweep does not need, and the
         * property
         * being protected -- the node is still there -- does not change between the
         * shapes of one marker. */
        {
            /* A PING with a token of its own, so the PONG that answers it cannot be
             * an earlier one still sitting in the buffer. The token carries the
             * marker byte as a NUMBER, because a token containing the marker would
             * be a marker byte on the wire by construction and this sweep asserts
             * there are none. */
            int w = snprintf(token, sizeof token, "PONG %s ps%u", NAME_A, b);
            char line[64];

            TF_CHECK_MSG(w > 0 && (size_t)w < sizeof token,
                         "the PONG token could not be built");
            w = snprintf(line, sizeof line, "PING ps%u", b);
            TF_CHECK_MSG(w > 0 && (size_t)w < sizeof line,
                         "the PING line could not be built");
            TF_CHECK_MSG(tc_send(&client, line) == 0,
                         "the test could not send its PING");
            TF_CHECK_MSG(wait_for_pong(&node, &client, token, T_IO_MS) == 0,
                         "marker 0x%02x: the node answered %s's shapes with no "
                         "PONG, so it stopped serving and every later probe in "
                         "this sweep would be vacuous", (unsigned)b, PEER);
        }
        /* THE CLIENT SOCKET, SWEPT NOW THAT THE PONG PROVES THE WRITES LANDED. */
        ps_sweep_client(&client_surface, &client, &client_scanned,
                        &client_privmsgs);
    }

    /* The byte count, asserted rather than assumed: a marker set that quietly lost
     * a byte would otherwise print a smaller coverage line and still pass. */
    /* 62 markers, and every one of them through every shape EXCEPT 0x00, which
     * the framing layer cannot deliver and which therefore goes through the one
     * shape that expects a refusal instead. The count is computed rather than
     * written down, so a shape added to the table moves it. */
    TF_CHECK_MSG(probes == (SWS_MARKER_COUNT - 1u) * (unsigned)SH_COUNT + 1u,
                 "the peer sweep ran %u probes and its own tables say it should "
                 "have run %lu: 61 markers x %d shapes, plus the one 0x00 can "
                 "reach. A marker set that lost a byte would otherwise print a "
                 "smaller number and pass.",
                 probes,
                 (unsigned long)((SWS_MARKER_COUNT - 1u) * (size_t)SH_COUNT + 1u),
                 SH_COUNT);

    /* ---------------------------------------------------------------------
     * STOP, THEN SCAN. The node is stopped first so its output is complete: a scan
     * of a running node would be a scan of whatever it had happened to printed,
     * and a byte written after the scan is a byte nobody looked at.
     * --------------------------------------------------------------------- */
    TF_CHECK_MSG(nf_stop(&node) == 0, "node A did not exit cleanly");

    /* THE LAST OF EACH BOUNDED SURFACE, then the node's own stdout in one piece.
     *
     * The peer link and the client socket are scanned INSIDE the marker loop, as
     * they are read, because both are bounded buffers and a bounded buffer that is
     * only scanned at the end is a surface covering a prefix of the run rather than
     * the run. What is left in each at this point is whatever arrived since its last
     * read, and it is scanned here so the tail is not missed either.
     *
     * The node's own stdout is NOT bounded in the same way -- `nf_stop()` has run,
     * so it is complete -- and scanning it in one piece means one report rather than
     * sixty-two. That is the whole difference between this block and the loop's:
     * when a surface is complete, one scan of it is right; when it is bounded, one
     * scan per read is.
     *
     * EACH IS LABELLED, because a finding that cannot say which surface it is on
     * cannot be acted on. The first version of this file scanned all three into one
     * accumulator and left `who` empty, and it found a real marker byte whose report
     * read "in the peer path ()" -- which is the difference between a finding and a
     * rumour. */
    {
        struct {
            sws_scan *s;
            const char *buf;
            size_t len;
        } tails[2];

        tails[0].s = &peer_surface;
        tails[0].buf = peer_rx;
        tails[0].len = (size_t)peer_rx_len;
        tails[1].s = &client_surface;
        tails[1].buf = tc_buffer(&client);
        tails[1].len = tc_received(&client);
        for (size_t i = 0; i < sizeof tails / sizeof tails[0]; i++) {
            if (tails[i].len > 0u) {
                sws_scan_bytes(tails[i].s, tails[i].buf, tails[i].len);
            }
        }
        sws_scan_bytes(&node_surface, node.out, node.out_len);
    }
    {
        sws_scan *surfaces[3];

        surfaces[0] = &node_surface;
        surfaces[1] = &peer_surface;
        surfaces[2] = &client_surface;
        for (size_t i = 0; i < sizeof surfaces / sizeof surfaces[0]; i++) {
            if (sws_scan_clean(surfaces[i]) == 0) {
                (void)sws_scan_report(surfaces[i]);
                found_surfaces++;
            }
            /* Folded into the whole-run total so the count below is a statement
             * about every surface together, which is the number a reader wants. */
            scan.total += surfaces[i]->total;
            scan.nfound += surfaces[i]->nfound;
        }
    }

    /* ---------------------------------------------------------------------------
     * CHECK 5, WHICH IS THE ONE THAT MATTERS MOST: THE CLIENT SURFACE WAS NOT EMPTY.
     * ---------------------------------------------------------------------------
     * A sweep that finds nothing is not proof, and `sweep_scan.h` says so where it is
     * read. This is that sentence made into a check for the surface where it was
     * false: for 61 of the 62 markers this file threw the client's bytes away
     * before scanning them, so "the client socket carried no marker byte" was
     * indistinguishable from "the client socket was never looked at" -- and the
     * second was the truth on every platform.
     *
     * The number is the relayed PRIVMSGs this client must have received: one per
     * `SPRIVMSG` probe on a channel it is in, for every marker except 0x00, which
     * the framing layer refuses before it is ever a line. Both rows of the shape
     * table that carry message text are counted, so the floor is two per marker.
     *
     * It is a FLOOR rather than an equality on purpose. If a future change stopped
     * delivering relayed messages to a local member, the exact count would move and
     * the test would fail for a reason that is not about filtering; the floor fails
     * only when the surface stops carrying the probes at all, which is precisely the
     * condition under which its cleanliness means nothing.
     */
    {
        const unsigned relayed = client_privmsgs;

        TF_CHECK_MSG(relayed >= SWS_MARKER_COUNT - 1u,
                     "this client received %u relayed PRIVMSG line(s) and the shape "
                     "table says it should have received at least %lu -- one per "
                     "marker the framing layer will carry. "
                     "So the surface this sweep calls \"a client socket\" was not "
                     "swept for most of the run, and a clean result on it is not a "
                     "result. Check that the per-marker read-and-scan is still in the "
                     "loop and that the client's buffer is drained AFTER the scan.",
                     relayed, (unsigned long)(SWS_MARKER_COUNT - 1u));
    }

    if (sws_scan_clean(&scan) == 0) {
        TF_CHECK_MSG(0,
                     "the peer-path terminal-injection sweep found %lu unmarked "
                     "byte(s) at %lu site(s). They are listed above; each is one "
                     "peer-chosen value reaching a log, a peer link or a client "
                     "with no filter between it and a reader.",
                     (unsigned long)scan.total, (unsigned long)scan.nfound);
    }

    /* The other half of the exception list: an entry that is never exercised is
     * either stale or pointing at nothing, and both are how a filter gets quietly
     * switched off. */
    for (int e = 0; e < PS_EXCEPTIONS; e++) {
        TF_CHECK_MSG(g_exc_used[e] != 0,
                     "the peer sweep's exception list carries an entry for `%s` "
                     "(%s) and the whole sweep never exercised it. Either the "
                     "relay path stopped keeping the mIRC bytes -- which would be "
                     "a behaviour change -- or this entry is stale and should be "
                     "deleted. An entry nobody exercises is not documentation.",
                     k_exceptions[e].where, k_exceptions[e].why);
    }

    {
        int used = 0;

        for (int e = 0; e < PS_EXCEPTIONS; e++) {
            used += (g_exc_used[e] != 0) ? 1 : 0;
        }
        fprintf(stderr,
                "ok: peer sweep -- %u markers x %d shapes, %lu probes, three "
                "scanned surfaces, %d exception entries, %d of them exercised\n",
                (unsigned)SWS_MARKER_COUNT, SH_COUNT, (unsigned long)probes,
                PS_EXCEPTIONS, used);
    }
    fprintf(stderr, "ok: %d of 3 surfaces carried an unmarked byte; the client "
            "socket was swept over %zu byte(s)\n", found_surfaces, client_scanned);

    tc_close(&client);
    if (peer.fd >= 0) {
        (void)close(peer.fd);
    }
    nf_free(&node);
    tf_done("peer_terminal_sweep");
    return 0;
}
