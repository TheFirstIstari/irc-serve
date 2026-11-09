/* test_writer_order.c -- MT 4.1 (#246): ordered delivery per connection.
 *
 * Threading/write-drain Requirement "Ordered delivery per connection":
 * pipelined replies SHALL arrive in queue order. Dispatch queues line A then
 * line B on the same connection; the peer must receive A before B regardless
 * of which writer drains, even with concurrent bursts on other connections
 * competing for the N=4 writer pool.
 *
 * Determinism: the pipeline runs 100 iterations in-test over one node, with
 * burst traffic before every iteration, so one binary run is 100 order
 * samples. Sequence-tagged markers keep iterations distinguishable in the
 * accumulated buffer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 30000
#define ITERATIONS 100
#define N_BURST 4
#define BURST_LINES 20

static void order_dispatch(server_t *s, conn_t *c, const message_t *m)
{
    const char *cmd = (m->command != NULL) ? m->command : "";

    if (strcmp(cmd, "PIPELINE") == 0) {
        char a[128];
        char b[128];
        int n;

        n = (m->nparams > 0 && m->params[0] != NULL) ? atoi(m->params[0]) : 0;
        (void)snprintf(a, sizeof a, ":irc.fixture NOTICE you :ORD-A-%03d\r\n", n);
        (void)snprintf(b, sizeof b, ":irc.fixture NOTICE you :ORD-B-%03d\r\n", n);
        /* Queued back-to-back; at N > 0 writers drain without loop pumps. */
        TF_CHECK_MSG(server_queue(s, c, a, strlen(a)) == 0, "A refused");
        TF_CHECK_MSG(server_queue(s, c, b, strlen(b)) == 0, "B refused");
        return;
    }
    if (strcmp(cmd, "BURST") == 0) {
        for (int i = 0; i < BURST_LINES; i++) {
            char line[96];

            (void)snprintf(line, sizeof line,
                           ":irc.fixture NOTICE you :BURST-%d\r\n", i);
            if (server_queue(s, c, line, strlen(line)) != 0)
                return; /* saturated: enough contention already */
        }
        return;
    }
}

static void setup(server_t *s)
{
    s->dispatch = order_dispatch;
    server_set_writer_threads(s, 4);
}

int main(void)
{
    nf_node_t node;
    test_client_t main_c;
    test_client_t burst[N_BURST];
    char cmd[64];
    char needle_a[32];
    char needle_b[32];

    TF_CHECK(nf_spawn_inline(&node, setup) == 0);

    tc_init(&main_c);
    TF_CHECK_MSG(tc_connect(&main_c, node.port) == 0, "connect failed");
    for (int i = 0; i < N_BURST; i++) {
        tc_init(&burst[i]);
        TF_CHECK_MSG(tc_connect(&burst[i], node.port) == 0,
                     "burst connect %d failed", i);
    }

    for (int it = 0; it < ITERATIONS; it++) {
        const char *buf;
        const char *pa;
        const char *pb;

        for (int i = 0; i < N_BURST; i++)
            TF_CHECK_MSG(tc_send(&burst[i], "BURST") == 0,
                         "burst %d send failed at iter %d", i, it);
        (void)snprintf(cmd, sizeof cmd, "PIPELINE %d", it);
        TF_CHECK_MSG(tc_send(&main_c, cmd) == 0, "send failed at iter %d", it);
        (void)snprintf(needle_a, sizeof needle_a, "ORD-A-%03d", it);
        (void)snprintf(needle_b, sizeof needle_b, "ORD-B-%03d", it);
        TF_CHECK_MSG(tc_expect(&main_c, needle_a, T_IO_MS) == 0,
                     "A missing at iter %d:\n%s", it, tc_buffer(&main_c));
        TF_CHECK_MSG(tc_expect(&main_c, needle_b, T_IO_MS) == 0,
                     "B missing at iter %d:\n%s", it, tc_buffer(&main_c));
        buf = tc_buffer(&main_c);
        pa = strstr(buf, needle_a);
        pb = strstr(buf, needle_b);
        TF_CHECK_MSG(pa != NULL && pb != NULL && pa < pb,
                     "reordered at iter %d:\n%s", it, buf);
    }

    for (int i = 0; i < N_BURST; i++)
        tc_close(&burst[i]);
    tc_close(&main_c);
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    nf_free(&node);
    tf_done("writer_order");
    return 0;
}
