/* test_stop_flag.c -- MT 1.5 (issue #239): per-node stop flag.
 *
 * Two server_t in one process, like test_fed_isolation.c: stopping one node
 * (poll_loop_request_stop_for) must not stop the other, while the process-wide
 * latch (poll_loop_request_stop) still stops any node. No sockets, no children,
 * no loop: the claim is about the stop predicates, plus one poll_loop_step on
 * the unstopped node to show it still runs. server_init() clears the flag via
 * its struct-wide zeroing.
 */
#include <assert.h>
#include <stdio.h>

#include "core/poll_loop.h"
#include "core/server.h"

int main(void)
{
    server_t a;
    server_t b;

    assert(server_init(&a, "irc.a") == 0);
    assert(server_init(&b, "irc.b") == 0);
    assert(poll_loop_stopped_for(&a) == 0);
    assert(poll_loop_stopped_for(&b) == 0);

    /* Stop one node: it reads stopped, the sibling does not. */
    poll_loop_request_stop_for(&a);
    assert(poll_loop_stopped_for(&a) != 0);
    assert(poll_loop_stopped_for(&b) == 0);

    /* The unstopped sibling still runs: one iteration completes. */
    assert(poll_loop_step(&b, 0) == 0);
    assert(poll_loop_stopped_for(&b) == 0);

    /* NULL is a no-op, never a crash. */
    poll_loop_request_stop_for(NULL);
    poll_loop_clear_stop_for(NULL);

    /* Clearing restores the node. */
    poll_loop_clear_stop_for(&a);
    assert(poll_loop_stopped_for(&a) == 0);

    /* server_init() clears a set flag. */
    poll_loop_request_stop_for(&a);
    assert(server_init(&a, "irc.a") == 0);
    assert(poll_loop_stopped_for(&a) == 0);

    /* The process latch still stops every node. */
    poll_loop_request_stop();
    assert(poll_loop_stopped_for(&a) != 0);
    assert(poll_loop_stopped_for(&b) != 0);
    assert(poll_loop_stopped() != 0);
    poll_loop_clear_stop();
    assert(poll_loop_stopped_for(&a) == 0);
    assert(poll_loop_stopped_for(&b) == 0);

    server_shutdown(&a);
    server_shutdown(&b);

    printf("ok: stop_flag\n");
    return 0;
}
