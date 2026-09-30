/* test_fed_tags.c -- the 2.4 internal tag block, measured.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS FILE IS FOR
 * ---------------------------------------------------------------------------
 * 3.2 derives IRC_MAX_TAG_OVERHEAD as 179 and is emphatic that the derivation is
 * the point: the earlier "~96" was wrong, and a cap that is an estimate rather
 * than the largest legal value is a cap that only fails on the day a name is 63
 * bytes long. Phase 1 froze the FORMAT and pinned 179 with a test of its own
 * (tests/unit/test_message_format.c).
 *
 * This file is the same measurement again, from the other end, and it exists
 * because Phase 6 is the phase that actually puts the block on a peer link:
 *
 *   1. THE BLOCK, BYTE FOR BYTE. 3.2 asserts the block's LENGTH. A length cannot
 *      tell origin from epoch, and a serialiser that emitted the four tags in
 *      the wrong order would have exactly the right length. So the block is
 *      compared against a written-out literal, which pins the order and the
 *      spellings as well as the total.
 *   2. THE OVERHEAD, MEASURED RATHER THAN SUBTRACTED. The stamped line and the
 *      unstamped line are rendered from the same message_t and the difference is
 *      taken, so the number comes from the formatter's actual output -- '@',
 *      block, and the one separating space -- and not from the constant this
 *      file is checking.
 *   3. THAT A RELAYED LINE FITS. 3.2 subtracts 179 from 8192 to get
 *      IRC_MAX_RELAY_LINE and then says an over-long line is dropped with a
 *      notice, never truncated. Both halves are asserted here: the largest body
 *      the node will relay, rendered with the largest legal stamp, is inside the
 *      on-wire cap, and one byte more is refused.
 *
 * ---------------------------------------------------------------------------
 * WHY THE LARGEST LEGAL STAMP AND NOT A TYPICAL ONE
 * ---------------------------------------------------------------------------
 * Because a typical one passes. Every value bound in the derivation -- 63-byte
 * origin, 20-digit epoch and id, 10-digit hops -- is a MAXIMUM, and the maxima
 * are the only values at which the arithmetic is tight. A stamp with a 5-byte
 * origin and single-digit numbers is 158 bytes lighter than the worst case, and
 * a line that overflows with the maxima on it overflows with a typical one on
 * nothing. So every number here is pushed to its bound, and the values are the
 * ones message.h's grammar allows rather than ones chosen for readability.
 *
 * And the boundary is checked on BOTH sides of every constant: the block is
 * exactly 177, the overhead is exactly 179, and the answer to "one byte more"
 * is a refusal rather than a truncated line. An assertion that only proves a
 * constant is not too big is satisfied by any value in a wide range; one that
 * also proves it is not too small is not.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/fanout.h"
#include "core/message.h"
#include "harness/test_util.h"

/* The origin this file's stamp carries, at its bound: IRC_MAX_SERVER_NAME (63)
 * bytes, every one of them legal under 2.4's grammar, and the first a letter.
 * 'a' repeated is used rather than a pattern like "irc.aaa...a" because the
 * expected block below is then not built by repeating anything: the tag names,
 * the separators and the ORDER are literal text, and only the 63 identical
 * origin bytes are generated, because 63 characters counted by hand is exactly
 * the kind of number that is wrong once and then forever. */
#define ORIGIN_MAX_BYTES 63

/* UINT64_MAX and UINT32_MAX written out rather than printed from the type. The
 * expected string has to be a literal for the same reason the origin is: it is
 * the thing being compared against, and a value produced by the code under test
 * proves nothing about itself. These two lines are also 3.2's derivation in
 * test form -- 20 decimal digits and 10 decimal digits, which is what its table
 * claims for them. */
#define EPOCH_MAX_TEXT "18446744073709551615"
#define ID_MAX_TEXT    "18446744073709551615"
#define HOPS_MAX_TEXT  "4294967295"

/* The tail of the expected block, in the frozen order: origin, epoch, id, hops.
 * Spelled out rather than assembled from the four tag names, because a value
 * built by repeating the serialiser's own constants would agree with the
 * serialiser by construction and would catch nothing. */
#define MAX_BLOCK_TAIL                                                      \
    ";irc-serve-epoch=" EPOCH_MAX_TEXT ";irc-serve-id=" ID_MAX_TEXT         \
    ";irc-serve-hops=" HOPS_MAX_TEXT

/* The block's length, as message.h's table derives it:
 *   17 ("irc-serve-origin=") + 63 (origin)
 *     + 17 (";irc-serve-epoch=") + 20 (epoch)
 *     + 14 (";irc-serve-id=")    + 20 (id)
 *     + 16 (";irc-serve-hops=")  + 10 (hops)
 * = 177, which is IRC_MAX_TAG_OVERHEAD's 179 less the '@' and the one space. */
#define MAX_BLOCK_BYTES 177u

/* Fill the origin at its bound and every numeric at its type's bound. */
static void max_stamp(irc_serve_tags_t *t)
{
    memset(t, 0, sizeof *t);
    memset(t->origin, 'a', sizeof t->origin - 1u);
    t->epoch = UINT64_MAX;
    t->id = UINT64_MAX;
    t->hops = UINT32_MAX;
}

/* The expected block, assembled from the literals above plus ORIGIN_MAX_BYTES
 * copies of 'a'. Written as an explicit sequence rather than an snprintf of the
 * whole thing so that the literal tag names stay visible in the source, which is
 * the part of this test a reader is checking by eye. */
static void max_block_expected(char *out, size_t cap)
{
    size_t n = 0;
    size_t i;

    (void)snprintf(out, cap, "irc-serve-origin=");
    n = strlen(out);
    for (i = 0; i < (size_t)ORIGIN_MAX_BYTES; i++) {
        out[n + i] = 'a';
    }
    n += (size_t)ORIGIN_MAX_BYTES;
    (void)snprintf(out + n, cap - n, "%s", MAX_BLOCK_TAIL);
}

/* Render `m` with and without a tag block and return both lengths, so the
 * overhead is a difference between two real renders rather than a subtraction
 * from a constant. `plain` and `tagged` receive the rendered CONTENT (no CRLF),
 * which is what message_format() produces and what verbs.c appends a terminator
 * to afterwards. */
static void render_pair(const char *tags, const char *prefix,
                        const char *command, const char *target,
                        const char *text, char *plain, size_t plain_cap,
                        char *tagged, size_t tagged_cap, size_t *plain_len,
                        size_t *tagged_len)
{
    const char *params[2];

    params[0] = target;
    params[1] = text;

    {
        message_t m;

        TF_CHECK_MSG(message_build(&m, NULL, prefix, command, params, 2) == 0,
                     "message_build() rejected the UNSTAMPED probe line");
        *plain_len = message_format(&m, plain, plain_cap);
        message_free(&m);
    }
    TF_CHECK_MSG(*plain_len != 0u, "the UNSTAMPED probe line did not render");

    {
        message_t m;

        TF_CHECK_MSG(message_build(&m, tags, prefix, command, params, 2) == 0,
                     "message_build() rejected the stamped probe line");
        *tagged_len = message_format(&m, tagged, tagged_cap);
        message_free(&m);
    }
    TF_CHECK_MSG(*tagged_len != 0u, "the STAMPED probe line did not render");
}

int main(void)
{
    irc_serve_tags_t t;
    char block[IRC_MAX_TAG_OVERHEAD];
    char expected[512];
    char plain[IRC_MAX_LINE + 2];
    char tagged[IRC_MAX_LINE + 2];
    size_t blen;
    size_t plain_len = 0;
    size_t tagged_len = 0;
    size_t overhead;

    max_stamp(&t);
    max_block_expected(expected, sizeof expected);

    /* =======================================================================
     * 1. THE STAMP IS LEGAL, AND LEGAL AT ITS BOUND
     * ==================================================================== */
    /* Checked first, because everything after it assumes it. A stamp the
     * grammar rejects would make irc_serve_tags_format() return 0 and every
     * later assertion would be measuring a refusal. */
    TF_CHECK_MSG(irc_serve_tags_valid(&t) == 1,
                 "a stamp at the documented value bounds is not legal, so "
                 "IRC_MAX_TAG_OVERHEAD's derivation does not describe a stamp "
                 "this node can actually put on the wire");
    TF_CHECK_MSG(strlen(t.origin) == (size_t)ORIGIN_MAX_BYTES,
                 "the test's origin is %zu bytes, not the %d the overhead "
                 "derivation assumes",
                 strlen(t.origin), ORIGIN_MAX_BYTES);

    /* =======================================================================
     * 2. THE BLOCK, BYTE FOR BYTE
     * ==================================================================== */
    TF_CHECK_MSG(strlen(expected) == MAX_BLOCK_BYTES,
                 "the expected block assembled by this test is %zu bytes, not "
                 "the %u its own arithmetic derives -- the TEST is wrong, and "
                 "saying so here stops it being read as a serialiser defect",
                 strlen(expected), MAX_BLOCK_BYTES);

    blen = irc_serve_tags_format(&t, block, sizeof block);
    TF_CHECK_MSG(blen != 0u,
                 "irc_serve_tags_format() refused a stamp it had just been "
                 "told was valid");
    TF_CHECK_MSG(blen == MAX_BLOCK_BYTES,
                 "the largest legal block measured %zu bytes, expected %u: the "
                 "derivation in 3.2 and message.h no longer describes what this "
                 "serialiser emits",
                 blen, MAX_BLOCK_BYTES);
    TF_CHECK_MSG(strcmp(block, expected) == 0,
                 "the block is not the frozen one.\n  expected: %s\n  actual:   %s",
                 expected, block);

    /* Compared without its '@' because irc_serve_tags_format() documents that
     * it emits no block marker, and that is part of what is being pinned: a
     * serialiser that added one would put a doubled '@' on the wire, and the
     * length check above would not have caught it. The marker and the single
     * separating space are accounted for in the overhead below, where they are
     * measured rather than asserted. */
    TF_CHECK_MSG(block[0] != '@',
                 "irc_serve_tags_format() emitted a block marker; its contract "
                 "is a block WITHOUT the leading '@'");

    /* =======================================================================
     * 3. THE OVERHEAD, MEASURED
     * ==================================================================== */
    /* The same message, rendered twice: once with the maximum legal stamp and
     * once with no tags at all. Everything else about the two renders is
     * identical, so the difference is the stamp and nothing else.
     *
     * The render buffer and the capacity handed to message_format() are the ones
     * federation/verbs.c uses for a peer line, so this measures the render the
     * peer link actually gets rather than a roomier one. */
    render_pair(block, "irc.example", "SPRIVMSG", "#T", "hello there", plain,
                sizeof plain, tagged, sizeof tagged, &plain_len, &tagged_len);
    TF_CHECK_MSG(tagged_len > plain_len,
                 "a stamped line rendered no longer than an unstamped one "
                 "(%zu vs %zu), so the overhead below is not measurable",
                 tagged_len, plain_len);
    overhead = tagged_len - plain_len;
    TF_CHECK_MSG(overhead == (size_t)IRC_MAX_TAG_OVERHEAD,
                 "the measured stamp overhead is %zu bytes, expected %d. If a "
                 "value bound was raised, IRC_MAX_TAG_OVERHEAD in message.h has "
                 "to be re-derived from the table there -- not adjusted to match "
                 "whatever the serialiser now emits.",
                 overhead, IRC_MAX_TAG_OVERHEAD);

    /* The stamped render must also START with the block, '@' and all, because a
     * length difference cannot tell an '@'-prefixed block from a line that grew
     * somewhere else. */
    TF_CHECK_MSG(tagged[0] == '@',
                 "a stamped line did not begin with '@'; the tag block is not "
                 "on the wire where 3.2 puts it");
    (void)snprintf(expected, sizeof expected, "@%s ", block);
    TF_CHECK_MSG(strncmp(tagged, expected, strlen(expected)) == 0,
                 "the stamped line does not begin with the frozen block.\n"
                 "  expected prefix: %s\n  actual line:      %s",
                 expected, tagged);

    /* And the four values must READ BACK out of a line the formatter produced,
     * which is the round trip the relay path depends on: a node that stamps a
     * block no peer can parse has a silent, unbounded failure rather than a
     * refused one. The same grammar, the same escaping, both directions. */
    {
        message_t m;
        irc_serve_tags_t back;

        TF_CHECK_MSG(message_parse_n(tagged, tagged_len, &m) == 0,
                     "a line this node produced did not parse: %s", tagged);
        TF_CHECK_MSG(irc_serve_tags_parse(&m, &back) == 0,
                     "the 2.4 block this node produced did not read back: %s",
                     tagged);
        TF_CHECK_MSG(back.epoch == t.epoch && back.id == t.id &&
                         back.hops == t.hops &&
                         strcmp(back.origin, t.origin) == 0,
                     "the 2.4 block did not survive a round trip: wrote "
                     "epoch=%llu id=%llu hops=%lu origin=%s, read back "
                     "epoch=%llu id=%llu hops=%lu origin=%s",
                     (unsigned long long)t.epoch, (unsigned long long)t.id,
                     (unsigned long)t.hops, t.origin,
                     (unsigned long long)back.epoch,
                     (unsigned long long)back.id, (unsigned long)back.hops,
                     back.origin);
        message_free(&m);
    }

    /* =======================================================================
     * 4. THE LARGEST RELAYABLE LINE FITS, AND ONE BYTE MORE DOES NOT
     * ==================================================================== */
    /* 3.2's client-facing cap is IRC_MAX_RELAY_LINE, and fanout_line_fits() is
     * what applies it -- the function the relay path actually calls, so this is
     * a test of the node's rule rather than of a second re-derivation of it.
     *
     * The body is grown until the rule refuses, and then the LARGEST accepted
     * body is rendered with the LARGEST legal stamp. That is the pair the two
     * constants have to agree on: a stamp the budget did not allow for pushes
     * an accepted line past IRC_MAX_LINE, and the overflow would only appear for
     * a client that sent a message near the limit. */
    {
        size_t lo = 0;
        size_t hi = (size_t)IRC_MAX_LINE;
        char *body = (char *)malloc(hi + 1u);

        TF_CHECK_MSG(body != NULL, "could not allocate the probe body");

        /* Binary search for the boundary, because "the largest body the rule
         * accepts" and "the smallest it refuses" are the two cases worth having,
         * and guessing either puts the test a whole cap away from the thing it
         * is testing. fanout_line_fits() takes a C string, so the probe is
         * rebuilt at each length rather than passed with a length. */
        while (lo < hi) {
            size_t mid = lo + (hi - lo + 1u) / 2u;

            memset(body, 'x', mid + 1u);
            body[mid] = '\0';
            if (fanout_line_fits("irc.example", "SPRIVMSG", "#T", body) != 0) {
                lo = mid;
            } else {
                hi = mid - 1u;
            }
        }
        memset(body, 'x', lo + 1u);
        body[lo] = '\0';

        TF_CHECK_MSG(lo > 0u,
                     "fanout_line_fits() refuses every body length, including "
                     "an empty one, so the cap this section is checking does "
                     "not exist");
        TF_CHECK_MSG(fanout_line_fits("irc.example", "SPRIVMSG", "#T", body) != 0,
                     "the longest body the search found is itself refused by "
                     "fanout_line_fits()");

        /* One byte more is REFUSED. A cap that accepted one more would be a cap
         * one byte short, and 3.2's whole argument is that the constant equals
         * the largest legal value rather than approximating it. */
        memset(body, 'x', lo + 2u);
        body[lo + 1u] = '\0';
        TF_CHECK_MSG(fanout_line_fits("irc.example", "SPRIVMSG", "#T", body) == 0,
                     "fanout_line_fits() accepted a body one byte longer than "
                     "the longest it accepted (%zu), so the relay cap has at "
                     "least one byte of slack in it",
                     lo);
        memset(body, 'x', lo + 1u);
        body[lo] = '\0';

        render_pair(block, "irc.example", "SPRIVMSG", "#T", body, plain,
                    sizeof plain, tagged, sizeof tagged, &plain_len, &tagged_len);
        /* CRLF counted in, per 3.2: the cap is on the line INCLUDING its
         * terminator, and the +1 is the NUL message_format() reserves. */
        TF_CHECK_MSG(tagged_len + 2u + 1u <= (size_t)IRC_MAX_LINE + 2u,
                     "the largest relayable line, stamped with the largest legal "
                     "tag block, needs %zu content bytes plus a CRLF, which is "
                     "more than IRC_MAX_LINE (%d)",
                     tagged_len, IRC_MAX_LINE);
        /* The stamp really is on this line. Without this the length above would
         * also be satisfied by a line the stamp had been dropped from, which is
         * shorter -- and a relayed line with no origin is a message no peer can
         * loop-guard. */
        TF_CHECK_MSG(strncmp(tagged, "@", 1u) == 0,
                     "the largest relayable line carries no tag block, so the "
                     "measurement above did not include the 2.4 overhead it is "
                     "meant to be measuring");
        free(body);
    }

    /* =======================================================================
     * 5. THE THREE CONSTANTS AGREE WITH EACH OTHER
     * ==================================================================== */
    /* The last word, and it is the one that catches the mistake this file exists
     * for: a stamp that fits IRC_MAX_RELAY_LINE is worthless if
     * IRC_MAX_RELAY_LINE was not derived by subtracting IRC_MAX_TAG_OVERHEAD
     * from IRC_MAX_LINE. Asserting the relationship between the constants is
     * what makes the two measurements above load-bearing on each other rather
     * than two independent facts that could each be right about different
     * numbers. */
    TF_CHECK_MSG((size_t)IRC_MAX_RELAY_LINE ==
                     (size_t)(IRC_MAX_LINE - IRC_MAX_TAG_OVERHEAD),
                 "IRC_MAX_RELAY_LINE is %d but IRC_MAX_LINE - IRC_MAX_TAG_OVERHEAD"
                 " is %d; one of the three constants in message.h is wrong",
                 IRC_MAX_RELAY_LINE, IRC_MAX_LINE - IRC_MAX_TAG_OVERHEAD);
    TF_CHECK_MSG(MAX_BLOCK_BYTES + 2u == (size_t)IRC_MAX_TAG_OVERHEAD,
                 "the measured largest legal block (%u) plus '@' and the "
                 "separating space is not IRC_MAX_TAG_OVERHEAD (%d)",
                 MAX_BLOCK_BYTES, IRC_MAX_TAG_OVERHEAD);

    tf_done("fed_tags");
    return 0;
}
