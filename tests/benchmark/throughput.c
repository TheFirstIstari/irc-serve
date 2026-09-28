/* Real parser-throughput benchmark over a measured IRC line workload.
 *
 * Method: repeatedly calls parse_command() over a representative set of IRC
 * lines, timing every call with CLOCK_MONOTONIC. Checks that clock_gettime()
 * succeeds and that elapsed time is positive, and reports batch mean / p50 /
 * p99 latency (in microseconds) plus throughput in operations/second. The
 * workload and process are labelled in the output. parse_command() must
 * return 0 (success) for every workload line; any non-zero return aborts the
 * benchmark (this is an explicit check, not an assert, so it fires in every
 * configuration). */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "protocol_parse.h"

typedef struct { const char* line; } sample;

static const sample WORKLOAD[] = {
    { "PRIVMSG #general :hello everyone" },
    { "JOIN #general" },
    { "NICK alice" },
    { "USER alice host.example server.example :Alice Q. User" },
    { "PING :server" },
    { "PRIVMSG #dev :this is a longer message to parse" },
    { "MODE #general +o alice" },
    { "TOPIC #general :a topic string" },
};
#define WORKLOAD_LEN ((size_t)(sizeof WORKLOAD / sizeof WORKLOAD[0]))

static long long now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1; /* checked: error */
    return (long long)ts.tv_sec * 1000000000LL + (long long)ts.tv_nsec;
}

static int cmp_ll(const void* a, const void* b) {
    long long x = *(const long long*)a, y = *(const long long*)b;
    return (x > y) - (x < y);
}

int main(void) {
    enum { N = 20000 };
    long long* per = (long long*)malloc((size_t)N * sizeof(long long));
    if (!per) { fprintf(stderr, "throughput: allocation failed\n"); return 1; }

    /* warmup */
    for (size_t i = 0; i < WORKLOAD_LEN; i++) {
        int tc = 0, ec = 0;
        if (parse_command(WORKLOAD[i].line, &tc, &ec) != 0) {
            fprintf(stderr, "throughput: warmup parse failed-> work=%s\n", WORKLOAD[i].line);
            free(per);
            return 1;
        }
    }

    long long total = 0;
    for (int i = 0; i < N; i++) {
        long long s = now_ns();
        if (s < 0) { fprintf(stderr, "throughput: clock_gettime failed\n"); free(per); return 1; }
        const sample* w = &WORKLOAD[(size_t)(i % (int)WORKLOAD_LEN)];
        int tc = 0, ec = 0;
        if (parse_command(w->line, &tc, &ec) != 0) {
            fprintf(stderr, "throughput: parse_command rc!=0 for %s\n", w->line);
            free(per);
            return 1;
        }
        long long e = now_ns();
        if (e < 0) { fprintf(stderr, "throughput: clock_gettime failed\n"); free(per); return 1; }
        long long d = e - s;
        if (d < 0) d = 0; /* monotonic clock safety */
        per[i] = d;
        total += d;
    }

    if (total <= 0) {
        fprintf(stderr, "throughput: no positive elapsed time measured\n");
        free(per);
        return 1;
    }

    long long* sorted = (long long*)malloc((size_t)N * sizeof(long long));
    if (!sorted) { free(per); fprintf(stderr, "throughput: allocation failed\n"); return 1; }
    for (int i = 0; i < N; i++) sorted[i] = per[i];
    qsort(sorted, (size_t)N, sizeof(long long), cmp_ll);

    double total_us = (double)total / 1000.0;
    double mean_us = (double)total / (double)N / 1000.0;   /* us per call */
    double p50_us = (double)sorted[N / 2] / 1000.0;
    int idx99 = (int)((double)N * 0.99); if (idx99 > N - 1) idx99 = N - 1;
    double p99_us = (double)sorted[idx99] / 1000.0;
    double total_s = (double)total / 1e9;
    double ops_sec = (double)N / total_s;

    printf("throughput: process=self workload=parse_command(%zu irc-lines) "
           "calls=%d total=%.3fus mean=%.3fus p50=%.3fus p99=%.3fus ops_sec=%.0f\n",
           WORKLOAD_LEN, N, total_us, mean_us, p50_us, p99_us, ops_sec);

    free(sorted);
    free(per);
    return 0;
}
