/* test_conn_lifecycle.c -- Phase 2 headline acceptance criterion.
 *
 * docs/SERVER_DESIGN.md 7/Phase 2: "a client connects and is closed cleanly
 * (assert accept -> EOF)". This is that test, and it is also the first test in
 * the project that talks to a real node over a real socket, which is the point
 * of 6.1 ("wire-level integration tests are mandatory from Phase 2").
 *
 * The node under test is the SHIPPED BINARY, forked and exec'd, on an ephemeral
 * port. Not a copy of the loop, not an in-process double: the previous
 * executable accepted a connection and closed it in the same breath, so the only
 * honest way to say the node now serves a connection is to run the node.
 *
 * What is asserted, in order:
 *
 *   1. the node binds port 0 and reports the port the kernel chose, and only
 *      then reports readiness -- so "connect to me now" is meaningful and tests
 *      never collide
 *   2. a client connects, and the node reports the accept          (ACCEPT)
 *   3. a complete line is framed and parsed, and the node says which command
 *      it saw -- this is the message path of 3.3, end to end over TCP
 *   4. the client half-closes; the node sees EOF, closes the descriptor itself,
 *      and the client observes a clean FIN rather than a reset        (EOF)
 *   5. a SECOND connection is served identically, so the close was a close and
 *      not a node that fell over
 *   6. the node stops on SIGTERM, exits 0, and its counters agree: every
 *      accepted connection was closed exactly once
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

/* Deadlines are in seconds, not milliseconds: generous enough for a loaded CI
 * runner, and they still fail fast because every one of them is waiting for
 * something that either happens within milliseconds or never happens. */
#define T_READY_MS 15000
#define T_IO_MS 15000

static void check_stats(nf_node_t *n, uint64_t accepted, uint64_t closed,
                        uint64_t lines)
{
    /* Deadline waits, not read-once checks: the node publishes its counters as
     * they change, and by the time the parent has seen the exit the last
     * republication is the authoritative one. */
    TF_CHECK_MSG(nf_expect_u64(n, "accepted=", accepted, T_IO_MS) == 0,
                 "accepted should be %llu", (unsigned long long)accepted);
    TF_CHECK_MSG(nf_expect_u64(n, "closed=", closed, T_IO_MS) == 0,
                 "closed should be %llu: every connection must be closed "
                 "exactly once", (unsigned long long)closed);
    TF_CHECK_MSG(nf_expect_u64(n, "lines=", lines, T_IO_MS) == 0,
                 "lines should be %llu", (unsigned long long)lines);
}

/* One connection, served and then closed cleanly. */
static void connect_send_and_close(nf_node_t *n, test_client_t *c,
                                   const char *line, const char *command,
                                   int index)
{
    TF_CHECK_MSG(tc_connect(c, n->port) == 0, "tc_connect to port %d failed",
                 n->port);
    TF_CHECK_MSG(nf_expect(n, "client_connect:", T_IO_MS) == 0,
                 "node never reported accepting connection %d", index);

    /* A complete, terminated line. It must be framed out of the byte stream
     * and parsed -- the node reports the command word it extracted, so this
     * asserts message_parse_n() really ran on the bytes the client sent. */
    TF_CHECK_MSG(tc_send(c, line) == 0, "tc_send failed for %s", line);
    TF_CHECK_MSG(nf_expect(n, command, T_IO_MS) == 0,
                 "node never reported command %s for connection %d", command,
                 index);

    /* The client stops sending. The node must see the EOF, close the
     * descriptor itself, and the client must observe a clean FIN. */
    {
        int rc;

        TF_CHECK_MSG(tc_half_close(c) == 0, "tc_half_close failed");
        rc = tc_expect_eof(c, T_IO_MS);
        /* rc == -3 is a reset, not a close. Accepting both would make this
         * test unable to tell a clean close from the kernel discarding an
         * unread queue, which is exactly the distinction "closed cleanly"
         * exists to make. */
        TF_CHECK_MSG(rc == 0, "connection %d: expected a clean EOF, got rc=%d "
                     "(rc=-3 is RST, rc=-1 timed out, rc=-2 timed out after "
                     "data arrived)", index, rc);
    }
    TF_CHECK_MSG(nf_expect(n, "reason=eof", T_IO_MS) == 0,
                 "node never reported closing connection %d", index);
    tc_close(c);
}

int main(void)
{
    nf_node_t node;
    test_client_t c;

    /* tc_connect() zeroes the client, but initialising here keeps tc_close()
     * safe on the failure paths below. */
    tc_init(&c);

    TF_CHECK(nf_spawn_binary(&node) == 0);
    TF_CHECK_MSG(node.port > 0, "node reported no usable port");

    /* 1/2: accept. */
    connect_send_and_close(&node, &c, "PING :first", "command=PING", 1);

    /* 5: a second connection must be served exactly the same way. If the first
     * close had taken the node down -- or leaked the descriptor and wedged the
     * loop -- this is where it shows. */
    connect_send_and_close(&node, &c, "PONG :second", "command=PONG", 2);

    /* 6: a clean stop. Two connections accepted, two closed, two lines framed
     * and parsed. closed == accepted is the load-bearing number: it is what
     * "the reaper closed every connection exactly once" looks like from
     * outside. */
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    check_stats(&node, 2, 2, 2);

    nf_free(&node);
    tf_done("conn_lifecycle");
    return 0;
}
