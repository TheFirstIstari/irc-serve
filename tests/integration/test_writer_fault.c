/* test_writer_fault.c -- MT 4.2 (#247): fault containment at N > 0.
 *
 * One inline node with writer_threads = 4. One client (the victim) asks for a
 * ~192 KB flood and then RSTs (SO_LINGER 0 + close with the flood unread), so
 * the writers' next conn_pump() on that conn fails with EPIPE/ECONNRESET. The
 * spec claim (threading/write-drain, Failure containment): the fatal send
 * error closes ONLY that conn -- the loop survives and the three survivor
 * conns keep getting replies before AND after the victim is reaped.
 *
 * Why the flood is big: a single small reply can fit in the server's sndbuf
 * before the RST is processed and drain without error, which would prove
 * nothing. 192 KB (under CONN_WQ_MAX so the queue accepts it) needs many
 * send() calls; once the RST lands every further send fails, so the pump
 * error path is exercised deterministically, not raced.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 30000

/* ~64 bytes a line; 3000 of them ~= 192 KB, under CONN_WQ_MAX (256 KB). */
static const char FLOOD_LINE[] =
    ":irc.fixture NOTICE you :FLOOD-0123456789-abcdefghijklmnopqr\r\n";

static void fault_dispatch(server_t *s, conn_t *c, const message_t *m)
{
    const char *cmd = (m->command != NULL) ? m->command : "";
    size_t i;

    if (strcmp(cmd, "HELLO") == 0) {
        static const char line[] = ":irc.fixture NOTICE you :ALIVE\r\n";

        TF_CHECK_MSG(server_queue(s, c, line, sizeof line - 1u) == 0,
                     "alive reply was refused");
        return;
    }
    if (strcmp(cmd, "FLOOD") == 0) {
        /* Queued for the writers to drain into a peer that is about to be
         * gone. A -1 (queue full) is fine too: either way the conn ends
         * CLOSING with the pump error below being the recorded cause. */
        for (i = 0; i < 3000u; i++) {
            if (server_queue(s, c, FLOOD_LINE, sizeof FLOOD_LINE - 1u) != 0) {
                break;
            }
        }
        return;
    }
}

static void setup(server_t *s)
{
    s->dispatch = fault_dispatch;
    server_set_writer_threads(s, 4);
}

/* RST without reading: queued bytes die in the kernel, the peer sees a reset,
 * and the server's next send() fails instead of draining cleanly. */
static void victim_rst(test_client_t *c)
{
    struct linger lg;

    lg.l_onoff = 1;
    lg.l_linger = 0;
    TF_CHECK_MSG(setsockopt(c->fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg) == 0,
                 "SO_LINGER failed");
    close(c->fd);
    c->fd = -1;
}

int main(void)
{
    nf_node_t node;
    test_client_t v, s1, s2, s3;

    TF_CHECK(nf_spawn_inline(&node, setup) == 0);

    tc_init(&v);
    tc_init(&s1);
    tc_init(&s2);
    tc_init(&s3);
    TF_CHECK_MSG(tc_connect(&v, node.port) == 0, "victim connect failed");
    TF_CHECK_MSG(tc_connect(&s1, node.port) == 0, "survivor 1 connect failed");
    TF_CHECK_MSG(tc_connect(&s2, node.port) == 0, "survivor 2 connect failed");
    TF_CHECK_MSG(tc_connect(&s3, node.port) == 0, "survivor 3 connect failed");

    /* Arm the flood, then reset before reading any of it. */
    TF_CHECK_MSG(tc_send(&v, "FLOOD") == 0, "FLOOD send failed");
    victim_rst(&v);

    /* The loop and the writers are still alive: survivors get replies. */
    TF_CHECK_MSG(tc_send(&s1, "HELLO") == 0, "survivor 1 HELLO failed");
    TF_CHECK_MSG(tc_send(&s2, "HELLO") == 0, "survivor 2 HELLO failed");
    TF_CHECK_MSG(tc_send(&s3, "HELLO") == 0, "survivor 3 HELLO failed");
    TF_CHECK_MSG(tc_expect(&s1, "ALIVE", T_IO_MS) == 0,
                 "survivor 1 got nothing after the victim fault:\n%s",
                 tc_buffer(&s1));
    TF_CHECK_MSG(tc_expect(&s2, "ALIVE", T_IO_MS) == 0,
                 "survivor 2 got nothing after the victim fault:\n%s",
                 tc_buffer(&s2));
    TF_CHECK_MSG(tc_expect(&s3, "ALIVE", T_IO_MS) == 0,
                 "survivor 3 got nothing after the victim fault:\n%s",
                 tc_buffer(&s3));

    /* The fatal send error was recorded against the victim, not swallowed:
     * only a failed conn_pump() prints this line. */
    TF_CHECK_MSG(nf_expect(&node, "reason=write_error", T_IO_MS) == 0,
                 "no failed-send close was recorded for the RST victim");
    TF_CHECK_MSG(nf_expect(&node, "conn_reaped", T_IO_MS) == 0,
                 "the faulted conn was never reaped");

    /* And after the reap the survivors still proceed on the same conns. */
    TF_CHECK_MSG(tc_send(&s1, "HELLO") == 0, "survivor 1 second HELLO failed");
    TF_CHECK_MSG(tc_send(&s2, "HELLO") == 0, "survivor 2 second HELLO failed");
    TF_CHECK_MSG(tc_send(&s3, "HELLO") == 0, "survivor 3 second HELLO failed");
    TF_CHECK_MSG(tc_expect(&s1, "ALIVE", T_IO_MS) == 0,
                 "survivor 1 stalled after the victim was reaped:\n%s",
                 tc_buffer(&s1));
    TF_CHECK_MSG(tc_expect(&s2, "ALIVE", T_IO_MS) == 0,
                 "survivor 2 stalled after the victim was reaped:\n%s",
                 tc_buffer(&s2));
    TF_CHECK_MSG(tc_expect(&s3, "ALIVE", T_IO_MS) == 0,
                 "survivor 3 stalled after the victim was reaped:\n%s",
                 tc_buffer(&s3));

    tc_close(&v);
    tc_close(&s1);
    tc_close(&s2);
    tc_close(&s3);
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    nf_free(&node);
    tf_done("writer_fault");
    return 0;
}
