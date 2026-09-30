/* throughput.c -- parser throughput, over BOTH parsers, with the production one
 * labelled as the production one.
 *
 * ---------------------------------------------------------------------------
 * WHY THERE ARE TWO NUMBERS, AND WHICH IS THE SERVER'S
 * ---------------------------------------------------------------------------
 * The node parses every inbound line through message_parse_n() in
 * src/core/message.c (the framing layer at 3.3 calls it with the byte count it
 * read; poll_loop.c:94 is the call site). That function does real work: prefix
 * and tag-block extraction, tag unescaping, the 15-parameter cap, trailing-
 * parameter absorption, the CRLF scan, and the IRC_MAX_LINE bound.
 *
 * parse_command() in src/protocol_parse.c is the Phase-0 function that only
 * COUNTS whitespace-separated tokens and returns the count. Nothing in the node
 * has called it since Phase 1.
 *
 * So the two measurements below are not two views of one thing:
 *
 *   message_parse_n()   THE PRODUCTION PATH. This is the number that says
 *                       something about server throughput.
 *   parse_command()     A LEGACY BASELINE, retained deliberately. It is ~an
 *                       order of magnitude cheaper because it does a tenth of
 *                       the work, so it is the comparison that shows how much of
 *                       the parse cost is tokenization rather than the rest --
 *                       and dropping it would lose that, along with the ability
 *                       to compare against the baseline already recorded in
 *                       docs/SPEC_TRACKING.md (which is why its workload below is
 *                       the original eight lines, unchanged, rather than a
 *                       tidier set).
 *
 * The legacy baseline is NOT server throughput and the output says so in those
 * words on every run, because the failure this fixes was precisely a number
 * that could not be misread in context.
 *
 * ---------------------------------------------------------------------------
 * WHY THE PRODUCTION WORKLOAD LOOKS LIKE THIS
 * ---------------------------------------------------------------------------
 * Same method as before -- CLOCK_MONOTONIC around each call, batch mean plus
 * p50 and p99 in microseconds, plus operations/second -- and both measurements
 * go through the identical harness, so the two sets of statistics are produced
 * by the same code and are comparable.
 *
 * The lines are the shapes a FEDERATED node actually receives, because that is
 * what the function being measured is asked to handle:
 *
 *   - a leading ':' prefix, which a client line never has and every peer line
 *     does
 *   - an '@tag=value' block, including the escaped-value form that exercises
 *     the unescape path rather than only the split
 *   - the 2.4 internal block this node itself stamps (irc-serve-origin,
 *     -epoch, -id, -hops), which is the longest legal block and the one a
 *     relaying node parses on essentially every line
 *   - a ':trailing' final parameter, and a line at the IRC_MAX_PARAMS cap where
 *     the 15th parameter absorbs the remainder verbatim
 *   - a line at exactly IRC_MAX_LINE, the 8192-byte on-wire cap, and one byte
 *     over it
 *
 * message_parse_n() is not NUL-terminated-line based, so each sample carries an
 * explicit length; the near-cap line is built at run time because it is 8192
 * bytes long and spelling it out as a literal would be unreadable.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS AND IS NOT INSIDE THE TIMED REGION
 * ---------------------------------------------------------------------------
 * The timed region is the parse CALL, and nothing else: clock_gettime() brackets
 * it and message_free() is deliberately outside it. Two consequences worth
 * stating rather than leaving to be guessed:
 *
 *   - the one heap allocation message_parse_n() performs per message IS inside
 *     the number, because it is part of the call. That is correct: the node
 *     allocates once per inbound line too.
 *   - the matching free() is NOT. So this is the cost of parsing, not the cost
 *     of a parse/free pair. A reader comparing these figures against a
 *     whole-message-path measurement should know that.
 *
 * clock_gettime() succeeding and elapsed time being positive are checked, and
 * every workload line is verified to PARSE -- with its expected prefix, tags
 * and parameter count -- before any timing happens. Those are explicit checks
 * and not asserts, so they fire in every configuration; a benchmark that
 * silently measured rejected lines, or measured a workload that had lost its
 * prefixes, would be worse than no benchmark.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/message.h"
#include "protocol_parse.h"

/* Calls per measurement. The production workload contains an 8192-byte line, so
 * the batch is much more work than the legacy one; both are sized so the whole
 * benchmark stays well inside the 60s CTest timeout on a loaded CI runner. */
#define CALLS 20000

/* ---------------------------------------------------------------------------
 * The measurement harness. One copy, used by both, so the two numbers cannot
 * differ because they were computed differently.
 * --------------------------------------------------------------------------- */
typedef struct {
    long long *per;            /* per-call nanoseconds, one per call  */
    long long  total;          /* summed per-call nanoseconds          */
    long long  batched_total;  /* nanoseconds from the batched timing  */
    int        batched_calls;  /* calls that went into batched_total   */
    double     p50_us;
    double     p99_us;
    double     batched_mean_us;
    double     batched_ops_sec;
    double     per_call_ops_sec;
} stats;

static long long now_ns(void)
{
    struct timespec ts;

    /* checked: an error is reported rather than folded into the statistics */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return -1;
    }
    return (long long)ts.tv_sec * 1000000000LL + (long long)ts.tv_nsec;
}

static int cmp_ll(const void *a, const void *b)
{
    long long x = *(const long long *)a;
    long long y = *(const long long *)b;

    return (x > y) - (x < y);
}

static void stats_init(stats *st, int n)
{
    st->per = (long long *)malloc((size_t)n * sizeof(long long));
    if (st->per == NULL) {
        fprintf(stderr, "throughput: allocation failed\n");
        exit(1);
    }
    st->total = 0;
    st->batched_total = 0;
    st->batched_calls = 0;
}

/* Fold a batch's elapsed nanoseconds into the statistics. `calls` is how many
 * parser calls went into it; the per-call figure is the division. */
static void stats_add_batch(stats *st, long long ns, int calls)
{
    st->batched_total += ns;
    st->batched_calls += calls;
}

static void stats_finish(stats *st, int n)
{
    long long *sorted = (long long *)malloc((size_t)n * sizeof(long long));
    int idx99;

    if (sorted == NULL) {
        fprintf(stderr, "throughput: allocation failed\n");
        free(st->per);
        exit(1);
    }
    memcpy(sorted, st->per, (size_t)n * sizeof(long long));
    qsort(sorted, (size_t)n, sizeof(long long), cmp_ll);

    st->p50_us = (double)sorted[n / 2] / 1000.0;
    idx99 = (int)((double)n * 0.99);
    if (idx99 > n - 1) {
        idx99 = n - 1;
    }
    st->p99_us = (double)sorted[idx99] / 1000.0;

    st->batched_mean_us = (st->batched_calls > 0)
        ? ((double)st->batched_total / (double)st->batched_calls / 1000.0)
        : 0.0;
    st->batched_ops_sec = (st->batched_total > 0)
        ? ((double)st->batched_calls / ((double)st->batched_total / 1e9))
        : 0.0;
    /* Reported alongside the batched figure and named for what it is, because
     * it is the estimator the historical baseline in docs/SPEC_TRACKING.md used
     * and dropping it would make that recorded number incomparable. It is the
     * same total with up to one clock tick of rounding error per call. */
    st->per_call_ops_sec = (st->total > 0) ? ((double)n / ((double)st->total / 1e9))
                                           : 0.0;

    free(sorted);
    free(st->per);
    st->per = NULL;
}

/* ---------------------------------------------------------------------------
 * WHY THERE ARE TWO STATISTICS, AND WHY THE BATCHED ONE IS THE HEADLINE
 * ---------------------------------------------------------------------------
 * Timing each call individually gives a per-call DISTRIBUTION, which is what p50
 * and p99 are for, and that part is unchanged. It does not give an accurate
 * average, and on this platform it cannot: CLOCK_MONOTONIC here has 1000 ns
 * granularity, a parse of a typical line costs ~160 ns, so almost every single
 * call reads as either 0 or 1000. The measured granularity is reported on every
 * run for exactly that reason, and the p50/p99 columns should be read as
 * "quantised to the clock tick" -- which is why they are not quoted as latencies
 * anywhere and why the batched figure below exists.
 *
 * The batched figure times BATCH calls between ONE pair of clock reads and
 * divides, so it has resolution finer than a clock tick by a factor of BATCH and
 * is the number to quote. Total and ops/sec are computed from the batched
 * measurement rather than the sum of the quantised per-call deltas, because the
 * latter is the same total with a rounding error of up to one tick per call.
 * --------------------------------------------------------------------------- */
#define BATCH 2000

/* The measured CLOCK_MONOTONIC granularity, in nanoseconds: the smallest non-zero
 * gap between two back-to-back reads. Measured rather than assumed, because the
 * whole reason the batched figure exists is that this value differs by platform
 * and a hardcoded 1000 would be a claim nobody checked. */
static long long clock_granularity_ns(void)
{
    struct timespec a;
    struct timespec b;
    long long smallest = -1;
    int i;

    if (clock_gettime(CLOCK_MONOTONIC, &a) != 0) {
        return -1;
    }
    for (i = 0; i < 20000; i++) {
        long long d;

        if (clock_gettime(CLOCK_MONOTONIC, &b) != 0) {
            return -1;
        }
        d = (long long)(b.tv_sec - a.tv_sec) * 1000000000LL +
            (long long)(b.tv_nsec - a.tv_nsec);
        if (d > 0 && (smallest < 0 || d < smallest)) {
            smallest = d;
        }
        a = b;
    }
    return smallest;
}

static void stats_print(const stats *st, const char *label, const char *fn,
                        const char *workload, size_t nlines, int n)
{
    printf("throughput: %-18s function=%-17s workload=%s(%zu lines) calls=%d "
           "batched_mean=%.4fus batched_ops_sec=%.0f per_call_ops_sec=%.0f "
           "p50=%.3fus p99=%.3fus (p50/p99 quantised to the clock tick)\n",
           label, fn, workload, nlines, n, st->batched_mean_us,
           st->batched_ops_sec, st->per_call_ops_sec, st->p50_us, st->p99_us);
}

/* ---------------------------------------------------------------------------
 * The PRODUCTION workload. Each entry carries the length message_parse_n() is
 * given, which is the framing layer's byte count rather than a NUL.
 * --------------------------------------------------------------------------- */
typedef struct {
    const char *line;
    size_t      len;
    const char *what;        /* what shape this line is, for the verification */
    int         want_prefix; /* -1: do not care */
    int         want_tags;
    int         want_params;
} psample;

/* The 2.4 internal block, which is the longest legal block and the one a node
 * parsing relay traffic sees on nearly every line. */
#define ORIGIN_BLOCK \
    "@irc-serve-origin=peer.example;irc-serve-epoch=17;" \
    "irc-serve-id=4412;irc-serve-hops=0 :peer.example"

static psample make_psample(const char *line, const char *what,
                            int want_prefix, int want_tags, int want_params)
{
    psample s;

    s.line = line;
    s.len = strlen(line);
    s.what = what;
    s.want_prefix = want_prefix;
    s.want_tags = want_tags;
    s.want_params = want_params;
    return s;
}

/* A line of exactly IRC_MAX_LINE bytes including the CRLF terminator, built at
 * run time because spelling out 8000-odd 'a's helps nobody. `cap_line` is
 * static so the pointer stays valid for the life of the process. */
static char cap_line[IRC_MAX_LINE + 8];
static size_t cap_len;
static char over_line[IRC_MAX_LINE + 8];
static size_t over_len;

/* The production workload, filled by a function rather than a static initializer
 * because each entry's length is strlen() of its line rather than a
 * compile-time constant. The table is what the verification pass and the timed
 * loop both read, so there is exactly one description of each line. */
#define PRODUCTION_MAX 16
static psample PRODUCTION[PRODUCTION_MAX];
static size_t PRODUCTION_LEN;

static void build_cap_lines(void)
{
    static const char head[] =
        "@time=2026-01-01T00:00:00.000Z :alice!user@host PRIVMSG #general :";
    const size_t headlen = sizeof head - 1u;
    /* IRC_MAX_LINE counts the terminator, so the content is two bytes shorter */
    const size_t target = (size_t)IRC_MAX_LINE - 2u;
    size_t i;

    memcpy(cap_line, head, headlen);
    for (i = headlen; i < target; i++) {
        cap_line[i] = 'a';
    }
    cap_line[target] = '\r';
    cap_line[target + 1u] = '\n';
    cap_len = target + 2u;

    /* One byte over the cap, terminator included. Not part of the timed
     * workload: it is there to be REJECTED, and a rejected line must never be
     * the thing a throughput figure is computed from. Checked separately. */
    memcpy(over_line, cap_line, target);
    over_line[target] = 'a';
    over_line[target + 1u] = '\r';
    over_line[target + 2u] = '\n';
    over_len = target + 3u;
}

static void build_production_workload(void)
{
    size_t n = 0;

    /* The plain client shape, so the figure is not only about the heavy lines. */
    PRODUCTION[n++] = make_psample("PRIVMSG #general :hello everyone",
                                   "client PRIVMSG", -1, 0, 2);
    /* A peer line: the leading ':' prefix a client never sends. */
    PRODUCTION[n++] = make_psample(":alice!user@host PRIVMSG #general :hello everyone",
                                   "peer PRIVMSG", 1, 0, 2);
    /* Prefix AND a tag block, which is the shape the issue asks for. */
    PRODUCTION[n++] = make_psample(
        "@time=2026-01-01T00:00:00.000Z;+draft/reply=8f3c2a "
        ":alice!user@host PRIVMSG #general :acknowledged",
        "tags + prefix", 1, 1, 2);
    /* The 2.4 internal block, the longest legal one. */
    PRODUCTION[n++] = make_psample(ORIGIN_BLOCK " PRIVMSG #general :relayed body",
                                   "2.4 internal block", 1, 1, 2);
    /* An ESCAPED tag value, so the unescape path is measured and not just the
     * split. '\:' ';', '\s', '\\', '\r' and '\n' are the whole escape set. */
    PRODUCTION[n++] = make_psample(
        "@k=a\\:b\\;c\\sd\\\\e\\r\\n :alice!u@h PRIVMSG #general :escaped",
        "escaped tag value", 1, 1, 2);
    PRODUCTION[n++] = make_psample("JOIN #general", "JOIN", -1, 0, 1);
    PRODUCTION[n++] = make_psample("NICK alice", "NICK", -1, 0, 1);
    PRODUCTION[n++] = make_psample("PING :server", "PING trailing", -1, 0, 1);
    PRODUCTION[n++] = make_psample("MODE #general +o alice", "MODE", -1, 0, 3);
    PRODUCTION[n++] = make_psample(
        "USER alice host.example server.example :Alice Q. User", "USER", -1, 0, 4);
    PRODUCTION[n++] = make_psample(":peer.example CAP * LS :sasl multi-prefix",
                                   "CAP LS", 1, 0, 3);
    /* The IRC_MAX_PARAMS cap: the 15th parameter absorbs the remainder. */
    PRODUCTION[n++] = make_psample(
        "PRIVMSG #general p1 p2 p3 p4 p5 p6 p7 p8 p9 p10 p11 p12 p13 p14 "
        ":the fifteenth absorbs the rest of the line", "15-param cap", -1, 0, 15);
    PRODUCTION[n++] = make_psample(":peer.example QUIT :Leaving", "QUIT", 1, 0, 1);

    PRODUCTION_LEN = n;
}

/* ---------------------------------------------------------------------------
 * The LEGACY workload: the original eight lines, unchanged, so the figure stays
 * comparable with the baseline already recorded in docs/SPEC_TRACKING.md.
 * --------------------------------------------------------------------------- */
static const char *const LEGACY[] = {
    "PRIVMSG #general :hello everyone",
    "JOIN #general",
    "NICK alice",
    "USER alice host.example server.example :Alice Q. User",
    "PING :server",
    "PRIVMSG #dev :this is a longer message to parse",
    "MODE #general +o alice",
    "TOPIC #general :a topic string",
};
#define LEGACY_LEN ((size_t)(sizeof LEGACY / sizeof LEGACY[0]))

/* Verify the production workload before timing anything: every line must PARSE,
 * and carry the prefix, tags and parameter count the table claims for it. A
 * workload that had quietly lost its prefixes, or that the parser rejects, would
 * otherwise produce a confident number about nothing. */
static void verify_production_workload(void)
{
    size_t i;

    for (i = 0; i < PRODUCTION_LEN; i++) {
        message_t m;
        int rc = message_parse_n(PRODUCTION[i].line, PRODUCTION[i].len, &m);

        if (rc != 0) {
            fprintf(stderr,
                    "throughput: production workload line %zu (%s) was REJECTED "
                    "(rc=%d): the benchmark would be measuring rejections\n",
                    i, PRODUCTION[i].what, rc);
            exit(1);
        }
        if (PRODUCTION[i].want_prefix >= 0 &&
            ((m.prefix != NULL) != (PRODUCTION[i].want_prefix != 0))) {
            fprintf(stderr, "throughput: production workload line %zu (%s) has "
                            "prefix=%s, expected %s\n",
                    i, PRODUCTION[i].what, m.prefix ? "one" : "none",
                    PRODUCTION[i].want_prefix ? "one" : "none");
            exit(1);
        }
        if ((m.tags != NULL) != (PRODUCTION[i].want_tags != 0)) {
            fprintf(stderr, "throughput: production workload line %zu (%s) has "
                            "tags=%s, expected %s\n",
                    i, PRODUCTION[i].what, m.tags ? "a block" : "none",
                    PRODUCTION[i].want_tags ? "a block" : "none");
            exit(1);
        }
        if (m.nparams != PRODUCTION[i].want_params) {
            fprintf(stderr, "throughput: production workload line %zu (%s) has "
                            "%d params, expected %d\n",
                    i, PRODUCTION[i].what, m.nparams, PRODUCTION[i].want_params);
            exit(1);
        }
        message_free(&m);
    }

    /* The near-cap line, which is the shape the issue asks for and the one a
     * literal cannot conveniently express. */
    {
        message_t m;

        if (message_parse_n(cap_line, cap_len, &m) != 0) {
            fprintf(stderr, "throughput: the %d-byte line at the cap was "
                            "rejected: the workload is not exercising the "
                            "boundary it claims to\n",
                    IRC_MAX_LINE);
            exit(1);
        }
        message_free(&m);
    }

    /* And the boundary is where it is claimed to be: one byte over, with the
     * terminator, must be refused. If this ever passes, the cap moved and the
     * near-cap figure above is measuring something other than the cap. */
    {
        message_t m;

        if (message_parse_n(over_line, over_len, &m) == 0) {
            fprintf(stderr, "throughput: a %d-byte line was ACCEPTED, so "
                            "IRC_MAX_LINE is not the bound the workload assumes\n",
                    IRC_MAX_LINE + 1);
            exit(1);
        }
    }
}

/* Warm up, measure, report. `label` and `fn` go into the output verbatim so the
 * reader cannot mistake one row for the other. */
static void run_production(stats *st)
{
    int n;

    stats_init(st, CALLS);

    for (n = 0; n < CALLS; n++) {
        const psample *w = &PRODUCTION[n % (int)PRODUCTION_LEN];
        message_t m;
        long long s = now_ns();
        long long e;
        int rc;

        if (s < 0) {
            fprintf(stderr, "throughput: clock_gettime failed\n");
            exit(1);
        }
        rc = message_parse_n(w->line, w->len, &m);
        e = now_ns();
        if (e < 0) {
            fprintf(stderr, "throughput: clock_gettime failed\n");
            exit(1);
        }
        if (rc != 0) {
            fprintf(stderr, "throughput: message_parse_n rejected the %s line "
                            "mid-benchmark\n", w->what);
            exit(1);
        }
        st->per[n] = e - s;
        if (st->per[n] < 0) {
            st->per[n] = 0; /* monotonic clock safety */
        }
        st->total += st->per[n];
        /* Outside the timed region on purpose -- see the header. */
        message_free(&m);
    }

    if (st->total <= 0) {
        fprintf(stderr, "throughput: no positive elapsed time measured\n");
        exit(1);
    }

    /* The batched pass, over the same workload: BATCH calls between one pair of
     * clock reads, so the per-call figure has resolution finer than a clock
     * tick. This is the number to quote. */
    {
        int b;

        for (b = 0; b < CALLS / BATCH; b++) {
            long long s;
            long long e;
            int k;

            s = now_ns();
            if (s < 0) {
                fprintf(stderr, "throughput: clock_gettime failed\n");
                exit(1);
            }
            for (k = 0; k < BATCH; k++) {
                const psample *w = &PRODUCTION[(b * BATCH + k) % (int)PRODUCTION_LEN];
                message_t m;

                if (message_parse_n(w->line, w->len, &m) != 0) {
                    fprintf(stderr, "throughput: message_parse_n rejected the "
                                    "%s line mid-benchmark\n", w->what);
                    exit(1);
                }
                message_free(&m);
            }
            e = now_ns();
            if (e < 0) {
                fprintf(stderr, "throughput: clock_gettime failed\n");
                exit(1);
            }
            stats_add_batch(st, e - s, BATCH);
        }
    }
    if (st->batched_total <= 0) {
        fprintf(stderr, "throughput: no positive batched elapsed time measured\n");
        exit(1);
    }

    stats_finish(st, CALLS);

    /* The near-cap line, reported on its own so a mean dominated by an 8 KB
     * sample is not mistaken for a typical line's cost. Batched for the same
     * reason as everything else. */
    {
        double cap_us = 0.0;
        long long total_cap = 0;
        const int reps = 2000;
        int rep;

        for (rep = 0; rep < reps; rep++) {
            message_t m;
            long long s;
            long long e;

            s = now_ns();
            if (s < 0) {
                fprintf(stderr, "throughput: clock_gettime failed\n");
                exit(1);
            }
            (void)message_parse_n(cap_line, cap_len, &m);
            e = now_ns();
            if (e < 0) {
                fprintf(stderr, "throughput: clock_gettime failed\n");
                exit(1);
            }
            total_cap += (e - s);
            message_free(&m);
        }
        if (total_cap > 0) {
            cap_us = (double)total_cap / (double)reps / 1000.0;
        }
        printf("throughput: %-18s function=%-17s line=%s mean=%.3fus (mean of %d "
               "calls; a single long line, NOT a typical one)\n",
               "PRODUCTION PATH", "message_parse_n", "at IRC_MAX_LINE", cap_us,
               reps);
    }

    stats_print(st, "PRODUCTION PATH", "message_parse_n", "federated-mix",
                PRODUCTION_LEN, CALLS);
}

static void run_legacy(stats *st)
{
    size_t i;
    int n;

    stats_init(st, CALLS);

    for (i = 0; i < LEGACY_LEN; i++) {
        int tc = 0;
        int ec = 0;

        if (parse_command(LEGACY[i], &tc, &ec) != 0) {
            fprintf(stderr, "throughput: warmup parse_command failed-> work=%s\n",
                    LEGACY[i]);
            exit(1);
        }
    }

    for (n = 0; n < CALLS; n++) {
        const char *w = LEGACY[n % (int)LEGACY_LEN];
        int tc = 0;
        int ec = 0;
        long long s = now_ns();
        long long e;

        if (s < 0) {
            fprintf(stderr, "throughput: clock_gettime failed\n");
            exit(1);
        }
        if (parse_command(w, &tc, &ec) != 0) {
            fprintf(stderr, "throughput: parse_command rc!=0 for %s\n", w);
            exit(1);
        }
        e = now_ns();
        if (e < 0) {
            fprintf(stderr, "throughput: clock_gettime failed\n");
            exit(1);
        }
        st->per[n] = e - s;
        if (st->per[n] < 0) {
            st->per[n] = 0;
        }
        st->total += st->per[n];
    }

    if (st->total <= 0) {
        fprintf(stderr, "throughput: no positive elapsed time measured\n");
        exit(1);
    }

    /* The batched pass, identical in shape to the production one so the two
     * ratios below are computed the same way. */
    {
        int b;

        for (b = 0; b < CALLS / BATCH; b++) {
            long long s;
            long long e;
            int k;

            s = now_ns();
            if (s < 0) {
                fprintf(stderr, "throughput: clock_gettime failed\n");
                exit(1);
            }
            for (k = 0; k < BATCH; k++) {
                int tc = 0;
                int ec = 0;

                if (parse_command(LEGACY[(b * BATCH + k) % (int)LEGACY_LEN], &tc,
                                  &ec) != 0) {
                    fprintf(stderr, "throughput: parse_command rc!=0\n");
                    exit(1);
                }
            }
            e = now_ns();
            if (e < 0) {
                fprintf(stderr, "throughput: clock_gettime failed\n");
                exit(1);
            }
            stats_add_batch(st, e - s, BATCH);
        }
    }
    if (st->batched_total <= 0) {
        fprintf(stderr, "throughput: no positive batched elapsed time measured\n");
        exit(1);
    }
    stats_finish(st, CALLS);
    stats_print(st, "LEGACY BASELINE", "parse_command", "client-mix", LEGACY_LEN,
                CALLS);
}

int main(void)
{
    stats prod;
    stats legacy;
    long long gran = clock_granularity_ns();

    build_cap_lines();
    build_production_workload();
    verify_production_workload();

    run_production(&prod);
    run_legacy(&legacy);

    if (gran <= 0) {
        fprintf(stderr, "throughput: could not measure CLOCK_MONOTONIC "
                        "granularity\n");
        return 1;
    }
    printf("throughput: clock=CLOCK_MONOTONIC granularity=%lldns; the p50/p99 "
           "columns are quantised to that and batched_mean is the figure to "
           "quote\n", gran);

    /* The disambiguation, in plain words, on every run. The bug this fixes was a
     * reported number that described a function nothing calls in production, and
     * a footnote nobody reads is not a fix for that. */
    printf("throughput: the PRODUCTION PATH row is the server's parse cost "
           "(message_parse_n, the function every inbound line goes through). "
           "The LEGACY BASELINE row is parse_command, a Phase-0 token COUNTER "
           "that the node has not called since Phase 1; it is a comparison, NOT "
           "server throughput.\n");
    printf("throughput: production_path=message_parse_n batched_mean=%.4fus "
           "legacy_baseline=parse_command batched_mean=%.4fus ratio=%.1fx "
           "(both are the same measurement harness over the same call count)\n",
           prod.batched_mean_us, legacy.batched_mean_us,
           (legacy.batched_mean_us > 0.0)
               ? (prod.batched_mean_us / legacy.batched_mean_us)
               : 0.0);
    return 0;
}
