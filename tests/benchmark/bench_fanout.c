/* bench_fanout.c -- issue #171: the union-broadcast de-duplication cost.
 *
 * fanout_deliver_union_local_gated() must deliver one emission to the UNION of
 * several channels' members. It used to answer "already reached?" with a nested
 * scan (for each member, a linear walk over every earlier channel's roster):
 * O(channels^2 * members^2). The fix is one fd-indexed bitmap cleared once per
 * emission: O(1) per member.
 *
 * This bench runs BOTH predicates over the same synthetic rosters -- 48
 * channels of 192 members drawn from 384 fds, so most members repeat -- and
 * asserts the delivered recipient sequences are byte-identical while printing
 * both wall times. It fails on any decision mismatch.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define BENCH_FDS 1024 /* == SERVER_FD_TABLE (FD_SETSIZE) */
#define BENCH_NCH 48
#define BENCH_NPER 192
#define BENCH_POOL 384
#define BENCH_REPEAT 5

static int g_chans[BENCH_NCH][BENCH_NPER];
static int g_slow_out[BENCH_NCH * BENCH_NPER];
static int g_fast_out[BENCH_NCH * BENCH_NPER];

/* Fixed-seed LCG so every run builds the same rosters. */
static uint32_t g_rng = 0x171u;

static uint32_t next_rand(void)
{
    g_rng = g_rng * 1103515245u + 12345u;
    return (g_rng >> 16u) & 0x7FFFu;
}

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

/* The pre-#171 predicate, verbatim in shape: nested scan over earlier rosters. */
static size_t run_slow(void)
{
    size_t n = 0;

    for (size_t i = 0; i < BENCH_NCH; i++) {
        for (size_t k = 0; k < BENCH_NPER; k++) {
            int m = g_chans[i][k];
            int already = 0;

            for (size_t j = 0; j < i && already == 0; j++) {
                for (size_t q = 0; q < BENCH_NPER; q++) {
                    if (g_chans[j][q] == m) {
                        already = 1;
                        break;
                    }
                }
            }
            if (already == 0) {
                g_slow_out[n++] = m;
            }
        }
    }
    return n;
}

/* The #171 predicate: one bitmap, checked per member, marked per channel. */
static size_t run_fast(void)
{
    static unsigned char seen[BENCH_FDS / 8];
    size_t n = 0;

    memset(seen, 0, sizeof seen);
    for (size_t i = 0; i < BENCH_NCH; i++) {
        for (size_t k = 0; k < BENCH_NPER; k++) {
            const unsigned bit = (unsigned)g_chans[i][k];

            if ((seen[bit / 8u] & (unsigned char)(1u << (bit % 8u))) == 0) {
                g_fast_out[n++] = g_chans[i][k];
            }
        }
        for (size_t k = 0; k < BENCH_NPER; k++) {
            const unsigned bit = (unsigned)g_chans[i][k];

            seen[bit / 8u] |= (unsigned char)(1u << (bit % 8u));
        }
    }
    return n;
}

int main(void)
{
    size_t nslow;
    size_t nfast;
    uint64_t slow_ns = 0;
    uint64_t fast_ns = 0;

    for (size_t i = 0; i < BENCH_NCH; i++) {
        for (size_t k = 0; k < BENCH_NPER; k++) {
            g_chans[i][k] = (int)(next_rand() % BENCH_POOL);
        }
    }

    /* Correctness first: identical recipient sequences, byte for byte. */
    nslow = run_slow();
    nfast = run_fast();
    if (nslow != nfast ||
        memcmp(g_slow_out, g_fast_out, nslow * sizeof(int)) != 0) {
        printf("bench_fanout: MISMATCH slow_n=%zu fast_n=%zu\n", nslow, nfast);
        return 1;
    }

    for (int r = 0; r < BENCH_REPEAT; r++) {
        uint64_t t0 = now_ns();

        nslow = run_slow();
        slow_ns += now_ns() - t0;
        t0 = now_ns();
        nfast = run_fast();
        fast_ns += now_ns() - t0;
        if (nslow != nfast ||
            memcmp(g_slow_out, g_fast_out, nslow * sizeof(int)) != 0) {
            printf("bench_fanout: MISMATCH on repeat %d\n", r);
            return 1;
        }
    }

    printf("bench_fanout: channels=%d per=%d pool=%d deliveries=%zu\n",
           BENCH_NCH, BENCH_NPER, BENCH_POOL, nslow);
    printf("bench_fanout: slow=%llu ns fast=%llu ns speedup=%.1fx\n",
           (unsigned long long)slow_ns, (unsigned long long)fast_ns,
           (double)slow_ns / (double)(fast_ns != 0 ? fast_ns : 1u));
    printf("bench_fanout: recipient sequences byte-identical: yes\n");
    if (fast_ns >= slow_ns) {
        printf("bench_fanout: NO WALL-TIME DROP\n");
        return 1;
    }
    return 0;
}
