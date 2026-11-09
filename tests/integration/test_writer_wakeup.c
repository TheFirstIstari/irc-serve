/* test_writer_wakeup.c -- MT 2.4 (#243): writer wakeup latency at N > 0.
 *
 * An idle conn queues a burst via server_queue() and the test times how long
 * the burst takes to arrive. At N > 0 the loop never pumps (no POLLOUT-driven
 * drain) and an idle conn sends nothing further, so the ONLY thing that moves
 * the bytes is the kick -> writer-wakeup path. Bounding the drain time --
 * rather than merely asserting eventual delivery -- is what makes this a
 * wakeup test: a lost wakeup (kick landing between a writer's drain-finish
 * and its wait, with no generation predicate) parks the writer with no
 * further kick coming, and the burst stalls past the bound below. The race
 * itself is timing-dependent and no test can fire it on demand; the predicate
 * fix is justified by inspection (a signal with no shared predicate state is
 * the textbook lost-wakeup shape). This test pins the symptom's bound: 30
 * idle-parked bursts, each drained well within one tick.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 10000
#define T_LAT_MS 3000L
#define N_BURST 20
#define N_ROUNDS 30

static void wakeup_dispatch(server_t *s, conn_t *c, const message_t *m)
{
    const char *cmd = (m->command != NULL) ? m->command : "";
    int i;

    if (strcmp(cmd, "BURST") != 0) {
        return;
    }
    /* Queued only -- at N > 0 the loop must not pump; writers drain. */
    for (i = 0; i < N_BURST; i++) {
        char line[96];
        int n = snprintf(line, sizeof line,
                         ":irc.fixture NOTICE you :BURST-%d\r\n", i);

        TF_CHECK_MSG(n > 0 && (size_t)n < sizeof line, "line render failed");
        TF_CHECK_MSG(server_queue(s, c, line, (size_t)n) == 0,
                     "burst line %d was refused", i);
    }
    TF_CHECK_MSG(server_queue(s, c, ":irc.fixture NOTICE you :BURST-END\r\n",
                              strlen(":irc.fixture NOTICE you :BURST-END\r\n")) == 0,
                 "burst end was refused");
}

static void setup(server_t *s)
{
    s->dispatch = wakeup_dispatch;
    server_set_writer_threads(s, 4);
}

static long elapsed_ms(const struct timespec *a, const struct timespec *b)
{
    return (long)(b->tv_sec - a->tv_sec) * 1000L +
           (long)(b->tv_nsec - a->tv_nsec) / 1000000L;
}

int main(void)
{
    nf_node_t node;
    test_client_t c;
    int r;

    TF_CHECK(nf_spawn_inline(&node, setup) == 0);

    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "connect failed");

    for (r = 0; r < N_ROUNDS; r++) {
        struct timespec t0, t1;

        /* Let writers park in cond_wait: the burst then lands on an idle
         * pool, so delivery measures the kick -> wakeup path alone. */
        (void)usleep(25000);
        TF_CHECK_MSG(tc_send(&c, "BURST") == 0, "round %d: send failed", r);
        TF_CHECK_MSG(clock_gettime(CLOCK_MONOTONIC, &t0) == 0,
                     "round %d: no clock", r);
        TF_CHECK_MSG(tc_expect(&c, "BURST-END", T_IO_MS) == 0,
                     "round %d: burst stalled -- writers lost the wakeup:\n%s",
                     r, tc_buffer(&c));
        TF_CHECK_MSG(clock_gettime(CLOCK_MONOTONIC, &t1) == 0,
                     "round %d: no clock", r);
        TF_CHECK_MSG(elapsed_ms(&t0, &t1) < T_LAT_MS,
                     "round %d: burst took %ld ms (bound %ld ms)", r,
                     elapsed_ms(&t0, &t1), T_LAT_MS);
    }

    tc_close(&c);
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    nf_free(&node);
    tf_done("writer_wakeup");
    return 0;
}
