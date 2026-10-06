/* sweep_scan.h -- the ONE terminal-injection instrument, shared by the client
 * sweep and the peer sweep.
 *
 * WHAT IS SHARED AND WHY IT IS A HEADER AND NOT A MODULE
 * ------------------------------------------------------
 * There are two swept surfaces in this tree -- the bytes a CLIENT receives, and the
 * bytes a PEER link receives -- and they are swept by two test binaries. The thing
 * that makes both sweeps mean anything is that they ask the same question with the
 * same instrument: the same marker predicate decides what counts, the same walk
 * decides where an occurrence is, and the same report shape decides what a failure
 * looks like. Two copies of that would drift, and a drift in the marker set is
 * invisible from the outside: one surface would quietly stop being swept.
 *
 * A header is used rather than a new library target because the shared part is
 * `static` in both translation units and shares no state between them -- a sweep's
 * results are per-run, per-binary, and there is nothing to link against. Adding a
 * target to the build for it would be a wider change than the sharing is worth.
 *
 * WHAT IS *NOT* SHARED, deliberately
 * ---------------------------------
 * The EXCEPTION LIST is per surface, because the two surfaces have different
 * legitimate emissions: a client socket can be sent a relayed mIRC colour byte and a
 * peer link cannot, and a peer link can be sent a server name this node does not
 * control in ways a client socket cannot. Each sweep supplies its own list through a
 * callback (`sws_excuse_fn`), and the walk here knows nothing about any of them. A
 * shared exception list would be a shared ALLOWLIST, and an allowlist shared across
 * two threat models is how one surface's exception becomes the other's.
 *
 * THE MARKER SET
 * --------------
 * `sws_marker_in_set()` is the only predicate the scan uses, and both the exception
 * masks and the walk read it. 62 bytes: the C0 controls that are not CR, LF or TAB,
 * DEL, and the whole C1 range. What is left out is as much of the claim as what is
 * in it:
 *
 *   - CR and LF are the line terminator. They are framing.
 *   - TAB is a legal field separator and mIRC renders it as alignment.
 *   - 0x00 cannot appear: the framing layer refuses an embedded NUL before a line
 *     exists, so there is nothing to find.
 *   - Every byte >= 0xA0 is OUT, and that is the claim most likely to be got wrong.
 *     `0xC4 0x81` is `ā`, and its second byte is 0x81 -- inside the C1 range. A
 *     sweep that reported every high byte would flag every accented Latin character,
 *     Cyrillic and Greek character on the network, and the honest response to that
 *     would be to delete the sweep. What separates them is a SEQUENCE, not a value:
 *     a continuation byte after a lead byte that expects one is ordinary UTF-8, and
 *     `sws_scan_bytes()` is given the raw stream and cannot tell the two apart by
 *     looking at one byte. It does not have to: the finding it reports names the
 *     LINE, and a reviewer reads the line.
 *
 * THE WALK
 * --------
 * One pass per buffer, and each occurrence is reported with the line it is on and a
 * SITE key that is the line up to its first colon. The site key is what makes a
 * twenty-two-line report readable: `chan_mode_refused:` writes one line per mode
 * character, and without the key those are twenty-two near-identical findings instead
 * of one.
 *
 * A SWEEP THAT FINDS NOTHING IS NOT PROOF, and the header says so where it is read
 * rather than leaving it to the sweep: the walk can only see bytes that were
 * emitted. That is why both sweeps derive their verbs from the dispatch table rather
 * than from a hand-written list, and why each probe ends by asserting that its own
 * socket received the response it was waiting for -- a probe that never got a reply
 * has not proved the reply was clean, it has proved nothing.
 */
#ifndef SWEEP_SCAN_H
#define SWEEP_SCAN_H

#include <stdio.h>
#include <string.h>

/* How many bytes `sws_marker_in_set()` accepts. Both sweeps assert their probe count
 * against it, so a marker set that silently lost a byte cannot pass unnoticed. */
#define SWS_MARKER_COUNT 62u

#define SWS_MAX_FINDINGS 16u
#define SWS_TEXT_MAX 48u
#define SWS_SITE_MAX 48u
#define SWS_LINE_MAX 192u
#define SWS_REPORT_LINE_MAX 512u

/* ---------------------------------------------------------------------------
 * sws_find_bytes(): SUBSTRING SEARCH OVER A BOUNDED RANGE
 * ---------------------------------------------------------------------------
 * WHY THIS EXISTS RATHER THAN `memmem()`, and the reason is portability, not taste.
 *
 * `memmem()` is a GNU extension and is NOT POSIX. It is declared by the macOS SDK
 * without a feature-test macro, so all thirteen local gate cells compiled it and
 * used it happily, and Linux's glibc hides it behind `_GNU_SOURCE` -- which this
 * tree is not. So the call compiled on the machine that ran the gate and failed on
 * the machine that ran CI, and it failed as ONE root cause with FIVE symptoms: the
 * implicit declaration made `memmem` an `int`, so every `memmem(...) != NULL`
 * became a comparison between a pointer and an integer.
 *
 * Adding `#define _GNU_SOURCE` would have bought those five call sites by making a
 * test file depend on GNU extensions in a tree that is C11 + POSIX by design, and it
 * would have missed the point: what every call site actually wants is "does this
 * byte RANGE contain these n bytes", and `memmem` is not the portable way to spell
 * it. The bounds are the substance. Both sweeps scan raw wire buffers and raw log
 * buffers that are full of marker bytes -- 0x00 included -- so a search that stops
 * at the first NUL is not a search over what it was given, and a search that may
 * read past its bound is worse than no search at all.
 *
 * SEMANTICS, and each degenerate case is an ANSWER rather than an accident:
 *
 *   hay == NULL        -> NULL. Nothing to search.
 *   needle == NULL     -> NULL. Same.
 *   needle_len == 0    -> NULL, AND THIS IS THE IMPORTANT ONE. A zero-length needle
 *                         is a substring of everything, so returning `hay` would make
 *                         every assertion written with one vacuously true -- which is
 *                         the empty-needle bug the sweeps already guard against
 *                         separately. "Not found" is the answer that cannot lie.
 *   needle_len > hay_len -> NULL. It cannot fit. Checked before the loop rather than
 *                         inside it, so there is no `hay_len - needle_len` to wrap.
 *   otherwise          -> the first occurrence at or after `hay`, or NULL.
 *
 * NUL BYTES IN THE NEEDLE ARE HONOURED, because the length is explicit and
 * `strlen()` appears nowhere in this function. `memmem()` has the same property; the
 * reason to say so here is that a later reader "simplifying" the call sites to pass
 * `strlen(needle)` would quietly reintroduce a truncated needle, and these sweeps
 * legitimately search for byte sequences that are not NUL-terminated strings.
 *
 * COST: a linear scan with a first-byte test, so O(hay_len * needle_len) worst case
 * and near O(hay_len) for the short needles both sweeps use (the longest here is a
 * `refused=%02x` at ten bytes). The sweeps call this on multi-megabyte buffers, so
 * the first-byte test is what keeps it cheap and not a naive memcmp at every
 * offset. Nothing in either sweep needs a search that is linear, because the needles
 * are fixed at compile time and short; if that ever stops being true the fix is
 * Boyer-Moore HERE, in one function, rather than at five call sites.
 */
static const char *sws_find_bytes(const char *hay, size_t hay_len,
                                  const char *needle, size_t needle_len)
{
    size_t last;

    if (hay == NULL || needle == NULL || needle_len == 0u) {
        return NULL;
    }
    if (needle_len > hay_len) {
        return NULL;
    }
    /* THE LAST BYTE AN OCCURRENCE MAY START AT, computed once and named.
     *
     * This line is the whole reason the function exists, and writing it as
     * `last = hay_len - needle_len` rather than as a loop condition of
     * `i + needle_len <= hay_len` is deliberate: the subtraction is checked against
     * underflow by the comparison above, and the bound it produces is a byte
     * OFFSET rather than an index that has to be re-tested on every iteration. A
     * loop bounded at `i <= hay_len` instead -- the off-by-one this primitive is
     * most likely to be "simplified" into, and the one the self-test below is
     * written to catch -- would let the final `memcmp()` read `needle_len - 1` bytes
     * PAST the end of the range. */
    last = hay_len - needle_len;
    for (size_t i = 0; i <= last; i++) {
        if (hay[i] == needle[0] && memcmp(hay + i, needle, needle_len) == 0) {
            return hay + i;
        }
    }
    return NULL;
}

/* sws_find_bytes_self_test(): the edge cases, asserted once, run by BOTH sweeps.
 *
 * It returns NULL when every case holds, or the name of the first case that did not.
 * A string rather than an assertion so that this header needs no test framework and
 * both callers can phrase the failure in their own terms -- and BOTH callers do call
 * it, because an instrument that only one sweep verifies is an instrument half
 * verified.
 *
 * WHY THE CASES ARE ASSERTED RATHER THAN TRUSTED: this file's neighbours have
 * already produced three defects of exactly this family. `test_peer_tls`'s
 * stderr-inheritance hang came from a helper's callers trusting what it did, and
 * the bounded-search off-by-one is the failure mode a bounded search exists to
 * prevent, so "it looked right" is not a standard this primitive gets to meet.
 *
 * AND WHY THE RANGE IS ASSERTED RATHER THAN THE VALUE ALONE: the off-by-one reads
 * bytes that are still inside the process's address space in every ordinary run, so
 * the wrong ANSWER is a matter of what happens to follow the buffer and is not
 * deterministic. Case 6 below makes it deterministic by putting a byte equal to the
 * needle's first byte immediately AFTER the declared range, so a loop bounded one
 * byte too far returns a pointer outside the range -- and a pointer outside the
 * range is checkable everywhere, not only in the runs where it happens to match.
 */
static const char *sws_find_bytes_self_test(void)
{
    /* A buffer whose haystack is followed, IN THE SAME ALLOCATION, by a byte equal
     * to the needle's first byte. Everything the search is allowed to read is
     * inside `buf`; everything it must not read is the last cell. */
    struct {
        char range[8];
        char beyond;
    } guarded;
    /* The overrun case needs its own guard: its byte AFTER the range has to equal the
     * needle's first byte and `guarded.beyond` has to stay `a` for the range cases. */
    struct {
        char range[8];
        char beyond;
    } overrun;
    const char *hit;

    /* 1. A NULL haystack finds nothing, whatever the needle. */
    if (sws_find_bytes(NULL, 8u, "abc", 3u) != NULL) {
        return "a NULL haystack reported a match";
    }
    /* 2. A NULL needle finds nothing. */
    if (sws_find_bytes("abc", 3u, NULL, 3u) != NULL) {
        return "a NULL needle reported a match";
    }
    /* 3. THE EMPTY NEEDLE. Zero-length, and the answer is NOT "found at the
     * start": returning `hay` here would make every caller vacuously true. */
    if (sws_find_bytes("abc", 3u, "", 0u) != NULL) {
        return "a zero-length needle reported a match";
    }
    if (sws_find_bytes(NULL, 0u, "", 0u) != NULL) {
        return "a zero-length needle reported a match in an empty range";
    }
    /* 4. A NEEDLE LONGER THAN THE HAYSTACK cannot fit. This is the case that
     * guards the subtraction in `last` from wrapping: 5 - 8 on a size_t is a very
     * large number, and a loop bounded by it would walk off the end. */
    if (sws_find_bytes("abcde", 5u, "abcdefgh", 8u) != NULL) {
        return "a needle longer than the haystack reported a match";
    }
    /* 5. An EMPTY haystack with a real needle. */
    if (sws_find_bytes("", 0u, "a", 1u) != NULL) {
        return "a needle matched an empty haystack";
    }
    memset(guarded.range, 'a', sizeof guarded.range);
    guarded.range[1] = 'b';
    guarded.range[2] = 'c';
    guarded.range[3] = 'd';
    guarded.range[4] = 'e';
    guarded.range[5] = 'f';
    guarded.range[6] = 'g';
    guarded.range[7] = 'h';
    guarded.beyond = 'a';
    hit = sws_find_bytes(guarded.range, sizeof guarded.range, "a", 1u);
    if (hit != &guarded.range[0]) {
        return "the single-byte search did not find the first byte";
    }
    if (sws_find_bytes(guarded.range, 1u, "ab", 2u) != NULL) {
        return "a needle overran the end of the range and matched anyway";
    }

    /* 7. EXACTLY FILLING THE TAIL. The occurrence ends on the last byte of the
     * range, which is the case an off-by-one at the far end breaks, and it is the
     * ordinary "the answer is at the end" case that a naive `i < hay_len` loop
     * would also break. */
    hit = sws_find_bytes(guarded.range, sizeof guarded.range, "fgh", 3u);
    if (hit != &guarded.range[5]) {
        return "a needle filling the end of the range was not found";
    }
    /* 8. A NEEDLE CONTAINING A NUL. `strlen()` would stop at the NUL and search for
     * `a` instead of `a\0b`, which is in the haystack too -- so this case has to be
     * written with the NUL-bearing needle's ABSENCE to be decisive. */
    {
        static const char with_nul[] = { 'a', '\0', 'b' };
        static const char range8[] = { 'x', 'a', '\0', 'b', 'y' };
        static const char range9[] = { 'x', 'a', '\0', 'c', 'y' };

        hit = sws_find_bytes(range8, sizeof range8, with_nul, sizeof with_nul);
        if (hit != &range8[1]) {
            return "a needle containing a NUL was not found";
        }
        if (sws_find_bytes(range9, sizeof range9, with_nul, sizeof with_nul) != NULL) {
            return "a needle containing a NUL matched the wrong bytes, so the "
                   "length is not being honoured";
        }
        /* And the honest half: `strlen()` of that needle is 1, so a strlen-based
         * implementation would ALSO find this. It is asserted so that the two
         * faults cannot cancel -- the NUL case above is decided by the mismatch,
         * this one by the match. */
        hit = sws_find_bytes(range8, sizeof range8, with_nul, 1u);
        if (hit != &range8[1]) {
            return "a one-byte search for the first byte of a NUL-bearing needle "
                   "did not find it";
        }
    }
    /* 9. A haystack full of NULs, searched for a needle with none. The sweeps scan
     * buffers like this routinely: a marker byte of 0x00 arrives on the wire and
     * the log line about it is what is being searched. */
    {
        static const char nuls[] = { '\0', '\0', 'a', '\0', 'b' };

        if (sws_find_bytes(nuls, sizeof nuls, "a\0b", 3u) != &nuls[2]) {
            return "a search over a NUL-bearing haystack was not found";
        }
    }
    /* 10. A needle that is a PREFIX of the tail but not the whole of it. The most
     * common off-by-one shape after the end-of-range one. */
    if (sws_find_bytes(guarded.range, sizeof guarded.range, "abcdefg", 7u) !=
        &guarded.range[0]) {
        return "a needle matching all but the last byte was not found";
    }
    if (sws_find_bytes(guarded.range, sizeof guarded.range, "abcdefghx", 9u) !=
        NULL) {
        return "a needle one byte past the tail matched";
    }
    /* 11. EVERY RESULT MUST LIE INSIDE THE RANGE. This is the invariant that makes
     * the off-by-one detectable in every run rather than only in the runs where the
     * bytes past the end happen to match, and it is asserted against a real result
     * rather than described. */
    hit = sws_find_bytes(guarded.range, sizeof guarded.range, "cd", 2u);
    if (hit == NULL || hit < guarded.range ||
        hit > guarded.range + sizeof guarded.range - 2u) {
        return "a match was reported outside the declared range";
    }

    /* 12. THE OFF-BY-ONE, and it is THE case this function exists for.
     *
     * A SEPARATE GUARD, because the byte AFTER this range has to equal the needle's
     * first byte and this one's does not -- and reusing the `abcdefgh` buffer for it
     * silently invalidated the cases above, which is its own small lesson: a self
     * test's cases share state, and a case that rewrites the state another case reads
     * turns that other case into a casualty of ordering.
     *
     * The range is eight `x` bytes with NO `a` anywhere in it, and `beyond` IS `a`.
     * A loop bounded one byte too far therefore finds a match at `overrun.range + 8`
     * and returns it; the correct bound returns NULL. The read is inside the same
     * struct, so the fault is not even an allocator violation -- it is a plain wrong
     * answer, which is what makes it worth a case rather than a code review.
     *
     * WHY THE FIRST VERSION OF THIS CASE COULD NOT SEE ITS OWN FAULT, and this is
     * worth more than the case itself. It searched the `abcdefgh` range for `a`,
     * which matches at offset 0 -- so a correct implementation returned `range + 0`,
     * a loop bounded one byte too far ALSO returned `range + 0` because it returns at
     * the FIRST match and never reaches the out-of-range offset at all, and the two
     * answers were IDENTICAL. A fault test whose control case passes is a fault test
     * that cannot fail, and this one looked perfectly reasonable while being one. The
     * needle has to have NO match inside the range for the out-of-range offset to be
     * reachable at all. */
    memset(overrun.range, 'x', sizeof overrun.range);
    overrun.beyond = 'a';
    hit = sws_find_bytes(overrun.range, sizeof overrun.range, "a", 1u);
    if (hit != NULL) {
        return "the search found a match one byte PAST the end of the range, so its "
               "bound is off by one and every result it has ever returned is "
               "unverified";
    }
    /* And the same bound as an explicit RANGE assertion on a real result, because a
     * null check alone cannot catch a loop that returns a pointer one byte past the
     * end when that byte happens NOT to match. */
    hit = sws_find_bytes(overrun.range, sizeof overrun.range, "x", 1u);
    if (hit == NULL || hit < overrun.range ||
        hit > overrun.range + sizeof overrun.range - 1u) {
        return "a match was reported outside the declared range";
    }
    return NULL;
}

/* THE MARKER PREDICATE, and the only one in either sweep. */
static int sws_marker_in_set(unsigned char b)
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

/* THE mIRC FORMATTING BYTES, spelled out one by one, and that is the point.
 *
 * `relay_byte_kept()` in `src/core/connection.c` is a switch over exactly these
 * eight, and its comment says why it is a switch rather than a range test: a range
 * test `0x02..0x1F` would swallow BEL and ESC, which is the entire hazard, and would
 * return 0 for 0x01, which "corrupts every CTCP". A mIRC client renders colour and
 * bold from these bytes, so relaying them is a FEATURE. Reproducing the list here
 * rather than writing a range is deliberate: this is a sweep's claim about what is
 * allowed through, and a range is what the source explicitly rejects. */
static const unsigned char sws_mirc_bytes[] = {
    0x01u, 0x02u, 0x03u, 0x0fu, 0x11u, 0x16u, 0x1du, 0x1fu
};

/* Byte masks, so an allowlist entry can NAME A CLASS instead of writing out 32 bytes
 * of hex that nobody can review. */
static unsigned char sws_mask_of(unsigned char ch)
{
    return (unsigned char)(1u << (unsigned int)(ch & 7u));
}

static int sws_mask_has(const unsigned char *mask, unsigned char ch)
{
    return (mask[ch >> 3] & sws_mask_of(ch)) != 0u ? 1 : 0;
}

/* The three classes both sweeps allowlist against. Built from `sws_marker_in_set()`
 * rather than written out, so an entry and the walk cannot disagree about what the
 * set is; they are non-const because they are computed once per run. */
static unsigned char sws_mask_c1[32];
static unsigned char sws_mask_all[32];
static unsigned char sws_mask_mirc[32];

static void sws_masks_init(void)
{
    unsigned char ch;

    memset(sws_mask_c1, 0, sizeof sws_mask_c1);
    memset(sws_mask_all, 0, sizeof sws_mask_all);
    for (ch = 0; ch < 0xffu; ch++) {
        if (sws_marker_in_set(ch) == 0) {
            continue;
        }
        sws_mask_all[ch >> 3] |= sws_mask_of(ch);
        if (ch >= 0x80u && ch <= 0x9fu) {
            sws_mask_c1[ch >> 3] |= sws_mask_of(ch);
        }
    }
    memset(sws_mask_mirc, 0, sizeof sws_mask_mirc);
    for (size_t i = 0; i < sizeof sws_mirc_bytes / sizeof sws_mirc_bytes[0];
         i++) {
        const unsigned char m = sws_mirc_bytes[i];

        sws_mask_mirc[m >> 3] |= sws_mask_of(m);
    }
}

/* THE PER-SURFACE EXCUSION CALLBACK.
 *
 * Return non-zero to excuse an occurrence. `line` is the whole line the occurrence
 * is on and `ch` is the offending byte, so a sweep can allowlist a SITE
 * (`span_has(line, ..., where)`) or a BYTE CLASS (`sws_mask_has(...)`) or both.
 *
 * The callback also RECORDS the excuse in whatever `ctx` points at, which is what
 * lets a sweep assert that every entry in its own list was actually exercised: a
 * list that has drifted out of date is not documentation, it is a hole with a
 * comment in front of it. Recording is the callback's job rather than this header's
 * because the callback is the only thing that knows which ENTRY it excused. */
typedef int (*sws_excuse_fn)(unsigned char ch, const char *line, size_t len,
                             void *ctx);

typedef struct {
    char site[SWS_SITE_MAX];
    char line[SWS_LINE_MAX];
} sws_finding;

typedef struct {
    sws_finding found[SWS_MAX_FINDINGS];
    size_t nfound;
    size_t total;
    char what[SWS_TEXT_MAX];
    char who[SWS_TEXT_MAX];
    sws_excuse_fn excuse;
    void *ctx;
} sws_scan;

static void sws_scan_begin(sws_scan *s, const char *what, sws_excuse_fn fn,
                           void *ctx)
{
    memset(s, 0, sizeof *s);
    (void)snprintf(s->what, sizeof s->what, "%s", what);
    s->excuse = fn;
    s->ctx = ctx;
}

/* One occurrence's line, bounded. The log is megabytes by the end of a sweep, and a
 * failure message that prints a megabyte is unreadable. */
static void sws_line_at(const char *buf, size_t len, size_t i, char *out,
                        size_t cap, size_t *out_len)
{
    size_t start = i;
    size_t stop = i;
    size_t shown;

    while (start > 0u && buf[start - 1u] != '\n') {
        start--;
    }
    while (stop < len && buf[stop] != '\n') {
        stop++;
    }
    shown = stop - start;
    if (shown > cap - 1u) {
        shown = cap - 1u;
    }
    memcpy(out, buf + start, shown);
    out[shown] = '\0';
    *out_len = shown;
}

static void sws_scan_bytes(sws_scan *s, const char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        const unsigned char ch = (unsigned char)buf[i];
        char line[SWS_REPORT_LINE_MAX];
        char site[SWS_SITE_MAX];
        size_t shown;
        size_t klen;
        const char *colon;
        int known = 0;

        if (sws_marker_in_set(ch) == 0) {
            continue;
        }
        sws_line_at(buf, len, i, line, sizeof line, &shown);
        if (s->excuse != NULL && s->excuse(ch, line, shown, s->ctx) != 0) {
            continue;
        }
        s->total++;
        /* THE SITE KEY IS THE LINE UP TO ITS FIRST COLON, so the many lines one
         * `chan_mode_refused:` writes for many mode characters collapse to ONE
         * finding rather than filling the report with near duplicates. */
        colon = strchr(line, ':');
        klen = (colon != NULL) ? (size_t)(colon - line + 1u) : strlen(line);
        if (klen > sizeof site - 1u) {
            klen = sizeof site - 1u;
        }
        memcpy(site, line, klen);
        site[klen] = '\0';
        for (size_t f = 0; f < s->nfound; f++) {
            if (strcmp(s->found[f].site, site) == 0) {
                known = 1;
                break;
            }
        }
        if (known == 0 && s->nfound < SWS_MAX_FINDINGS) {
            (void)snprintf(s->found[s->nfound].site, sizeof s->found[0].site,
                           "%s", site);
            (void)snprintf(s->found[s->nfound].line, sizeof s->found[0].line,
                           "%s", line);
            s->nfound++;
        }
    }
}

static int sws_scan_clean(const sws_scan *s)
{
    return s->total == 0u ? 1 : 0;
}

/* Write the report to stderr and return 0 when the scan is clean, 1 when it is not.
 *
 * The caller turns that into a failure. Returning rather than asserting is
 * deliberate: a sweep has several scanned surfaces and wants ONE summary at the end
 * rather than one per surface, so the reporting is collected and printed once. */
static int sws_scan_report(const sws_scan *s)
{
    if (s->total == 0u) {
        return 0;
    }
    fprintf(stderr,
            "note: the terminal-injection sweep found %lu unmarked byte(s) in %s "
            "(%s), at %lu distinct site(s):\n",
            (unsigned long)s->total, s->what, s->who, (unsigned long)s->nfound);
    for (size_t f = 0; f < s->nfound; f++) {
        size_t i;

        fprintf(stderr, "    %s\n        ", s->found[f].site);
        for (i = 0; s->found[f].line[i] != '\0'; i++) {
            unsigned char u = (unsigned char)s->found[f].line[i];

            if (u >= 0x20u && u < 0x7fu) {
                (void)fputc((int)u, stderr);
            } else {
                fprintf(stderr, "\\x%02x", (unsigned)u);
            }
        }
        fprintf(stderr, "\n");
    }
    if (s->total > (size_t)SWS_MAX_FINDINGS) {
        fprintf(stderr, "    (and more occurrences of the sites above)\n");
    }
    return 1;
}

#endif /* SWEEP_SCAN_H */
