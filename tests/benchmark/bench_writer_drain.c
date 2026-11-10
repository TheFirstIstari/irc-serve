/* bench_writer_drain.c -- MT 4.3 (#248): writer on/off throughput + footprint.
 *
 * Queues a fixed payload on NCONN socketpair-backed conns of one server_t,
 * then drains it two ways and times the drain:
 *   N=0  the loop's path: conn_pump() each conn inline (single-threaded).
 *   N=2/4  the writer path: server_writers_start(), server_queue(), kick,
 *          then wait until every queue is empty.
 *
 * Prints one `writer_drain:` line per N (elapsed ms, MiB/s) plus one
 * `writer_rss:` line (getrusage peak, like bench_mem). Fails (nonzero) if any
 * conn still holds bytes at the deadline -- a stalled writer pool is a
 * finding, not a slow number. No thresholds: CI runs it advisory-only and the
 * numbers go into the #248 results note for the future default decision.
 * The default is NOT flipped here.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
/* close()/usleep(): POSIX, no house wrapper (same as other benches). */
#include <unistd.h>
#include "core/connection.h"
#include "core/server.h"
#include "core/transport.h"

#define NCONN 32
#define PAYLOAD 65536u
#define DEADLINE_MS 15000

static char g_payload[PAYLOAD];

static long long now_us(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000LL + (long long)ts.tv_nsec / 1000LL;
}

static double rss_mb(void)
{
    struct rusage ru;

    if (getrusage(RUSAGE_SELF, &ru) != 0) {
        return -1.0;
    }
#if defined(__APPLE__)
    return (double)ru.ru_maxrss / (1024.0 * 1024.0);
#else
    return (double)ru.ru_maxrss / 1024.0;
#endif
}

/* Read and discard whatever the peers hold. Without this nothing over the
 * socket buffer can ever drain: writers pump into a full peer queue and park
 * on EAGAIN, which is a harness artifact rather than a writer stall. Peer
 * ends are nonblocking so this never blocks. */
static void drain_peers(int *peers, int n)
{
    char sink[8192];
    int i;

    for (i = 0; i < n; i++) {
        while (read(peers[i], sink, sizeof sink) > 0) {
        }
    }
}

/* One drain measurement at `writers` threads. Owns its server_t, conns, and
 * peer ends end to end; returns 0 on full drain, 1 on stall/failure. */
static int run_case(int writers)
{
    server_t server;
    conn_t *conns[NCONN];
    int peers[NCONN];
    long long t0, t1;
    double elapsed_ms, mib_s;
    size_t total = (size_t)NCONN * (size_t)PAYLOAD;
    int i;
    int rc = 0;

    memset(&server, 0, sizeof server);
    memset(conns, 0, sizeof conns);
    for (i = 0; i < NCONN; i++) {
        peers[i] = -1;
    }
    if (server_init(&server, "bench.test") != 0) {
        printf("writer_drain: writers=%d FAIL server_init\n", writers);
        return 1;
    }
    for (i = 0; i < NCONN; i++) {
        int pair[2];
        int flags;

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
            printf("writer_drain: writers=%d FAIL socketpair\n", writers);
            server_shutdown(&server);
            return 1;
        }
        /* Both ends nonblocking: conn_pump() is written on the conn end's
         * promise, and drain_peers() must never block on the peer end. */
        flags = fcntl(pair[0], F_GETFL, 0);
        (void)fcntl(pair[0], F_SETFL, flags | O_NONBLOCK);
        flags = fcntl(pair[1], F_GETFL, 0);
        (void)fcntl(pair[1], F_SETFL, flags | O_NONBLOCK);
        conns[i] = conn_new(pair[0], CONN_CLIENT);
        peers[i] = pair[1];
        if (conns[i] == NULL || server_add_conn(&server, conns[i]) != 0) {
            printf("writer_drain: writers=%d FAIL conn setup\n", writers);
            if (conns[i] == NULL) {
                (void)close(pair[0]);
            }
            (void)close(pair[1]);
            server_shutdown(&server);
            return 1;
        }
    }
    server_set_writer_threads(&server, writers);
    if (writers > 0 && server_writers_start(&server) != 0) {
        printf("writer_drain: writers=%d FAIL writers_start\n", writers);
        server_shutdown(&server);
        rc = 1;
        goto close_peers;
    }
    for (i = 0; i < NCONN; i++) {
        if (server_queue(&server, conns[i], g_payload, sizeof g_payload) != 0) {
            printf("writer_drain: writers=%d FAIL queue refused\n", writers);
            server_shutdown(&server);
            rc = 1;
            goto close_peers;
        }
    }
    t0 = now_us();
    if (writers == 0) {
        for (i = 0; i < NCONN; i++) {
            if (conn_pump(conns[i]) != 0) {
                printf("writer_drain: writers=0 FAIL pump conn %d\n", i);
                server_shutdown(&server);
                rc = 1;
                goto close_peers;
            }
        }
    } else {
        long long deadline = t0 + (long long)DEADLINE_MS * 1000LL;
        int drained = 0;

        server_writers_kick(&server);
        while (now_us() < deadline) {
            int j;
            int empty = 1;

            /* Keep the peer ends empty so writers never park on a full
             * socket buffer; what is timed is queue draining, not the
             * kernel's willingness to hold unread bytes. */
            drain_peers(peers, NCONN);
            for (j = 0; j < NCONN; j++) {
                if (conn_write_pending_locked(conns[j]) > 0u) {
                    empty = 0;
                    break;
                }
            }
            if (empty) {
                drained = 1;
                break;
            }
            /* Re-kick: a writer that finished its scan just before EAGAIN
             * freed space sleeps with no further kick coming. */
            server_writers_kick(&server);
            usleep(1000);
        }
        if (!drained) {
            printf("writer_drain: writers=%d FAIL stall: queues not empty at deadline\n",
                   writers);
            server_shutdown(&server);
            rc = 1;
            goto close_peers;
        }
    }
    t1 = now_us();
    elapsed_ms = (double)(t1 - t0) / 1000.0;
    mib_s = elapsed_ms > 0.0 ? ((double)total / (1024.0 * 1024.0)) / (elapsed_ms / 1000.0) : 0.0;
    printf("writer_drain: writers=%d conns=%d bytes_per_conn=%u total_bytes=%zu elapsed_ms=%.2f mib_per_s=%.2f\n",
           writers, NCONN, PAYLOAD, total, elapsed_ms, mib_s);
    server_shutdown(&server);
close_peers:
    for (i = 0; i < NCONN; i++) {
        if (peers[i] >= 0) {
            (void)close(peers[i]);
        }
    }
    return rc;
}

int main(void)
{
    const int cases[] = { 0, 2, 4 };
    size_t k;
    int rc = 0;

    memset(g_payload, 'B', sizeof g_payload);
    /* CRLF-free fill: never framed, only pumped, so content is irrelevant. */
    for (k = 0; k < sizeof cases / sizeof cases[0]; k++) {
        if (run_case(cases[k]) != 0) {
            rc = 1;
            break;
        }
    }
    printf("writer_rss: rss=%.2f MiB\n", rss_mb());
    if (rc == 0) {
        printf("writer_drain: PASS all writers cases drained\n");
    }
    return rc;
}
