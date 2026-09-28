/* test_quit.c -- QUIT closes cleanly, through the reaper, and the nickname goes
 * back into the pool.
 *
 * docs/SERVER_DESIGN.md 3.4: "The send path never closes a connection. It marks
 * CLOSING; a reaper runs at a fixed point in the loop." Phase 3 adds the one
 * command whose entire job is to end a connection, so this is where that rule
 * is most load-bearing: a QUIT handler that called close() would look perfect,
 * would work, and would make every reaper test weaker at once.
 *
 * Three things are asserted, and the third is the one that is easy to skip:
 *
 *   1. the client sees a CLEAN close. A FIN, not an RST. tc_expect_eof()
 *      distinguishes them and a test that accepted both would be asserting
 *      nothing -- the kernel discarding an unread queue also ends a
 *      connection, and it does so for entirely the wrong reason.
 *
 *   2. the close went through the reaper. The node's own accepted= and closed=
 *      counters are read back after it exits, and closed == accepted is what
 *      "closed exactly once" looks like from outside. test_close_sites.c
 *      separately proves by inspection that no file but server.c calls close().
 *
 *   3. the nickname is RELEASED, not merely forgotten. A QUIT that dropped the
 *      conn without unregistering the nick would leak a name for the lifetime
 *      of the node, and the symptom is a user who reconnects, picks the same
 *      nickname, and is told it is in use by nobody. So a second client takes
 *      the name and registers.
 *
 * A fourth thing is asserted because it is a real behaviour of the design and
 * easy to get wrong: a PING that arrives in the SAME TCP segment as a QUIT must
 * NOT be answered. The QUIT marks the conn CLOSING, the loop has already dropped
 * it from its poll set, and anything queued after that would sit in a write
 * queue that is never pumped. A client that pipelines QUIT and PING is not
 * making a mistake, and answering it would mean answering a socket that is on
 * its way out.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS TEST CANNOT SEE, AND WHICH TEST CAN
 * ---------------------------------------------------------------------------
 * Two breaks were tried against this file and neither was caught here. Both are
 * recorded rather than hidden, because a test that quietly does not cover what
 * its header implies is exactly the thing 5 was written to eliminate.
 *
 *   A close() inside the QUIT handler. The client still sees a clean FIN, the
 *   reaper still runs at its fixed point, the second close() on the descriptor
 *   is swallowed as EBADF, and n_closed still ends up equal to n_accepted -- so
 *   every runtime assertion in this file passes. A second close site is
 *   invisible from the wire BY CONSTRUCTION, which is why the rule has to hold
 *   by construction too. test_close_sites.c is the test that catches it: it
 *   reads the sources and fails when any file but server.c calls close().
 *
 *   Dropping the nick release from handle_quit. server_close_conn() releases the
 *   nickname too, and does so for every close whatever caused it, so the name
 *   still becomes reusable and the behaviour asserted below still holds. That is
 *   defence in depth working, not a hole: this test asserts the BEHAVIOUR (the
 *   name is free afterwards), which is the thing a user can observe, and not the
 *   LOCATION of the release. The QUIT handler's release is the semantically
 *   right place and is kept; the reaper's is what makes it safe to forget.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_READY_MS 15000
#define T_IO_MS 15000

int main(void)
{
    nf_node_t node;
    test_client_t first;
    test_client_t second;
    int rc;

    tc_init(&first);
    tc_init(&second);
    TF_CHECK(nf_spawn_binary(&node) == 0);
    TF_CHECK_MSG(node.port > 0, "node reported no usable port");

    /* Register, so the QUIT has a nickname to release. */
    TF_CHECK_MSG(tc_connect(&first, node.port) == 0, "tc_connect failed");
    TF_CHECK_MSG(tc_send(&first, "NICK zoe") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&first, "USER zoe 0 * :Zoe Example") == 0,
                 "tc_send failed");
    TF_CHECK_MSG(tc_expect(&first, " 001 zoe :Welcome", T_IO_MS) == 0,
                 "registration did not complete");

    /* A PING pipelined behind the QUIT. One write, so both lines are in the
     * same segment and the node's read of the first can mark the conn CLOSING
     * before it dispatches the second. */
    TF_CHECK_MSG(tc_send_raw(&first, "QUIT :leaving\r\nPING :are-you-there\r\n",
                             sizeof("QUIT :leaving\r\nPING :are-you-there\r\n")
                                 - 1u) == 0,
                 "tc_send_raw failed");

    /* 1. A clean FIN. */
    rc = tc_expect_eof(&first, T_IO_MS);
    TF_CHECK_MSG(rc == 0, "expected a clean EOF after QUIT, got rc=%d (rc=-3 is "
                 "RST, which is a reset rather than a close; rc=-1 timed out; "
                 "rc=-2 timed out with data pending)", rc);
    /* The needle is the whole PONG line, not the word: the MOTD this node
     * serves mentions PING and PONG by name, and a bare "PONG" would match that
     * prose and make this assertion count one before a single reply was sent. */
    TF_CHECK_MSG(tf_count(tc_buffer(&first), ":irc.test PONG ") == 0,
                 "a PING pipelined behind a QUIT was answered (%zu PONG lines): "
                 "the connection was already CLOSING and the loop has dropped "
                 "it from its poll set, so those bytes would never be pumped",
                 tf_count(tc_buffer(&first), ":irc.test PONG "));

    /* The node said what it did, on its own stream. */
    TF_CHECK_MSG(nf_expect(&node, "reason=leaving", T_IO_MS) == 0,
                 "the node did not record the QUIT reason");
    TF_CHECK_MSG(nf_expect(&node, "cmd_dropped: fd=", T_IO_MS) == 0,
                 "the node did not record dropping the pipelined PING on a "
                 "connection that was already closing");
    tc_close(&first);

    /* 3. The name is back in the pool. A QUIT that closed the conn without
     * releasing the nickname would leak it for the lifetime of the node, and
     * the symptom is a reconnecting user who is told their own name is taken
     * by nobody. */
    TF_CHECK_MSG(tc_connect(&second, node.port) == 0, "tc_connect failed");
    TF_CHECK_MSG(tc_send(&second, "NICK zoe") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&second, "USER zoe 0 * :Zoe Again") == 0,
                 "tc_send failed");
    TF_CHECK_MSG(tc_expect(&second, " 001 zoe :Welcome", T_IO_MS) == 0,
                 "the nickname of a client that QUIT was not released: the "
                 "registry still holds it for a connection that is gone");
    tc_close(&second);

    /* 2. Every accepted connection was closed exactly once, and nothing was
     * refused on the way out.
     *
     * Read AFTER the process exits, and that ordering is not a detail: the
     * node's counters are published on its loop_stats line, which it prints
     * once on shutdown. A test that looked for "closed=" while the node was
     * still running would be looking for a number that has not been printed
     * yet, and the deadline wait would simply expire. */
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", 2, T_IO_MS) == 0,
                 "accepted should be 2");
    TF_CHECK_MSG(nf_expect_u64(&node, "closed=", 2, T_IO_MS) == 0,
                 "closed should be 2: closed == accepted is what 'the reaper "
                 "closed every connection exactly once' looks like from outside");
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0: the pipelined PING should be dropped "
                 "by the registration/closing gate in the dispatcher, before it "
                 "ever reaches reply()");

    nf_free(&node);
    tf_done("quit");
    return 0;
}
