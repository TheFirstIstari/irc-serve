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
