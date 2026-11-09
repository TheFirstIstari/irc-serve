/* test_writer_drain.c -- MT 2.2 (#241): writers own the drain at N > 0.
 *
 * One inline node with writer_threads = 4. The dispatch queues a fixed marker
 * (no conn_pump call -- the loop must not pump when writers exist) and the
 * client reads it back. Delivery proves writers drained a live conn's FIFO.
 * A second command over-queues, marks CLOSING, and leaves bytes queued; the
 * client then reads the queued bytes AFTER the mark, proving the reaper
 * deferred the close until writers drained (no RST loss of the queued reply).
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

static void drain_dispatch(server_t *s, conn_t *c, const message_t *m)
{
    const char *cmd = (m->command != NULL) ? m->command : "";

    if (strcmp(cmd, "HELLO") == 0) {
        static const char line[] = ":irc.fixture NOTICE you :MARKER-1\r\n";

        /* Queued only. At N > 0 no conn_pump() here: writers drain. */
        TF_CHECK_MSG(server_queue(s, c, line, sizeof line - 1u) == 0,
                     "marker was refused");
        return;
    }
    if (strcmp(cmd, "BYE") == 0) {
        static const char line[] = ":irc.fixture NOTICE you :GOODBYE-2\r\n";

        /* Queued, then marked CLOSING with bytes still queued. The reaper
         * must defer the close until writers drain; the client reads the
         * goodbye below, which is the proof. */
        TF_CHECK_MSG(server_queue(s, c, line, sizeof line - 1u) == 0,
                     "goodbye was refused");
        conn_mark_closing(c);
        return;
    }
}

static void setup(server_t *s)
{
    s->dispatch = drain_dispatch;
    server_set_writer_threads(s, 4);
}

int main(void)
{
    nf_node_t node;
    test_client_t c;

    TF_CHECK(nf_spawn_inline(&node, setup) == 0);

    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "connect failed");
    TF_CHECK_MSG(tc_send(&c, "HELLO") == 0, "HELLO send failed");
    /* Drained by writers, not the loop: the dispatch never pumped. */
    TF_CHECK_MSG(tc_expect(&c, "MARKER-1", T_IO_MS) == 0,
                 "writers never drained the queued marker:\n%s", tc_buffer(&c));
    TF_CHECK_MSG(tc_send(&c, "BYE") == 0, "BYE send failed");
    /* Queued before the CLOSING mark; readable only if the reaper waited. */
    TF_CHECK_MSG(tc_expect(&c, "GOODBYE-2", T_IO_MS) == 0,
                 "queued goodbye lost: the reaper closed before writers "
                 "drained:\n%s", tc_buffer(&c));

    tc_close(&c);
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    nf_free(&node);
    tf_done("writer_drain");
    return 0;
}
