/* test_eintr.c -- a signal during poll() must not kill the loop.
 *
 * docs/SERVER_DESIGN.md 3.4: the loop is EINTR-safe. This is easy to state and
 * easy to get wrong in the way that actually bites: an EINTR handler that
 * `break`s out of the wait looks fine until a signal arrives, and then the
 * process exits with a status nobody is looking at.
 *
 * Two things have to be true and they are tested separately:
 *
 *   1. poll() really is interrupted. Asserted from the node's own trace output
 *      rather than assumed, because a test that sends a signal and then checks
 *      the node still works would also pass if the signal had arrived between
 *      two iterations and never touched poll() at all. The node counts EINTR and
 *      says so, and the test insists on seeing it.
 *
 *   2. the loop survives it. After an interruption the node still accepts,
 *      still frames, still parses, still closes cleanly, and still stops
 *      cleanly on SIGTERM.
 *
 * THE RACE, AND WHY IT IS NOT A FLAKE
 * ------------------------------------
 * A signal sent at an arbitrary instant might land between two poll() calls
 * rather than inside one, and then no EINTR ever happens. Sending it once would
 * therefore be a coin flip.
 *
 * The fix is nf_expect_retry_signal(), which re-sends the signal on every
 * polling iteration of the wait until the thing being waited for appears. The
 * child spends milliseconds blocked inside poll() and microseconds between
 * iterations, so a retried signal lands in the wait essentially immediately, and
 * the retry is driven by the select() loop the wait is already using. There is
 * no timing assumption and no sleep: the test either observes a real EINTR or
 * fails.
 *
 * SIGUSR1 is used because the node's handler for it does nothing at all. A
 * signal whose handler requests a stop would test the wrong thing.
 */
#include <signal.h>
#include <stdio.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

int main(void)
{
    nf_node_t node;
    test_client_t c;

    TF_CHECK(nf_spawn_binary(&node) == 0);

    /* Establish a connection first, so the node is provably serving before it is
     * interrupted, and so there is something to interrupt it over. */
    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "connect failed");
    TF_CHECK_MSG(nf_expect(&node, "client_connect:", T_IO_MS) == 0,
                 "node never reported the accept");

    /* 1: a real, counted interruption. */
    TF_CHECK_MSG(nf_expect_retry_signal(&node, "[observable] eintr:", SIGUSR1,
                                        T_IO_MS) == 0,
                 "the loop never observed an EINTR: either the signal never "
                 "reached poll() or the EINTR path is not being taken");

    /* 2: it still works. A NEW connection is accepted after the interruption
     * and its line is framed and parsed, which is the observable difference
     * between "survived the signal" and "has not got to the signal yet". */
    {
        test_client_t after;

        tc_init(&after);
        TF_CHECK_MSG(tc_connect(&after, node.port) == 0,
                     "connect after the signal failed");
        TF_CHECK_MSG(nf_expect(&node, "client_connect:", T_IO_MS) == 0,
                     "the node stopped accepting after a signal");
        TF_CHECK_MSG(tc_send(&after, "NICK post-signal") == 0,
                     "send after the signal failed");
        TF_CHECK_MSG(nf_expect(&node, "command=NICK", T_IO_MS) == 0,
                     "the node stopped parsing after a signal");
        TF_CHECK_MSG(tc_half_close(&after) == 0, "half close failed");
        TF_CHECK_MSG(tc_expect_eof(&after, T_IO_MS) == 0,
                     "the post-signal connection was not closed cleanly");
        tc_close(&after);
    }

    /* The original connection is still alive and still served: send a line,
     * have it framed and parsed, then hang up and observe a clean close. */
    TF_CHECK_MSG(tc_send(&c, "PING :after-eintr") == 0, "tc_send failed");
    TF_CHECK_MSG(nf_expect(&node, "command=PING", T_IO_MS) == 0,
                 "the node stopped parsing after a signal");
    TF_CHECK_MSG(tc_half_close(&c) == 0, "half close failed");
    {
        int rc = tc_expect_eof(&c, T_IO_MS);

        TF_CHECK_MSG(rc == 0, "expected a clean EOF after the signal, got rc=%d",
                     rc);
    }

    /* A clean stop: the loop exited because it was asked to, not because a
     * signal killed it, and it reported at least one interruption on the way. */
    TF_CHECK_MSG(nf_stop(&node) == 0,
                 "the node did not exit cleanly after being signalled");
    TF_CHECK_MSG(nf_expect_u64_ge(&node, "eintr=", 1, T_IO_MS) == 0,
                 "the node's own count of interruptions should be at least 1");

    tc_close(&c);
    nf_free(&node);
    tf_done("eintr");
    return 0;
}
