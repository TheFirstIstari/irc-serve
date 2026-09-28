/* test_dial_fsm.c -- the nonblocking dial state machine.
 *
 * docs/SERVER_DESIGN.md 3.4: "Nonblocking dial with a dial state machine. A
 * blocking connect() stalls every client on the node." The machinery lands in
 * Phase 2 even though no peer uses it until Phase 6, because retrofitting a
 * nonblocking connect() onto a working loop means touching the hot path, and
 * retrofitting a blocking one means stalling every client.
 *
 * NO PEER USES THIS YET, and the test does not pretend otherwise: the node
 * under test dials a plain listening socket that this test process owns. There
 * is no FEDERATE handshake, no peer_name registry entry beyond the dial slot,
 * and no claim that a link is ESTABLISHED. What is asserted is the socket-level
 * state machine and the two properties 3.4 attaches to it:
 *
 *   1. IT DOES NOT BLOCK. server_dial() returns with the connect still in
 *      progress, and the node keeps serving clients on its listener throughout.
 *      A client is accepted, framed and parsed DURING the dial's lifetime,
 *      which is the actual requirement -- a blocking connect() would fail that.
 *   2. ADDRESSES ARE PRE-RESOLVED. server_dial() takes a struct sockaddr and
 *      there is no name anywhere in its signature or its body, so a getaddrinfo
 *      cannot be introduced on this path later. test_close_sites-style
 *      reasoning does not apply here, but the signature does: a resolution
 *      helper would have to be added, and adding it is a visible act.
 *
 * Both terminal states are exercised: a dial to a listening socket becomes a
 * registered CONN_SERVER connection, and a dial to a port with nothing on it
 * becomes DIAL_FAILED without ever entering the poll set as a connection.
 */
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/connection.h"
#include "core/message.h"
#include "core/poll_loop.h"
#include "core/server.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

/* Where the child dials, and the port it dials. Filled in before the spawn. */
static struct sockaddr_in g_good;
static struct sockaddr_in g_bad;

static void setup(server_t *s)
{
    /* The trace is on so the per-line observable is emitted: this test asserts
     * that the node still FRAMES AND PARSES a client's line while a dial is in
     * flight, which is the actual claim (a blocking connect() would fail it). */
    s->trace = 1;

    /* Two dials, started before anyone may connect so the node is already
     * mid-dial when the test's client arrives -- which is what makes (1) a
     * real test rather than a race. */
    TF_CHECK_MSG(server_dial(s, (const struct sockaddr *)&g_good,
                             sizeof g_good, "irc.peer-a") == 0,
                 "server_dial to the live listener failed");
    TF_CHECK_MSG(server_dial(s, (const struct sockaddr *)&g_bad,
                             sizeof g_bad, "irc.peer-b") == 0,
                 "server_dial to the dead port failed");
    TF_CHECK_MSG(server_dial_count(s) == 2, "expected two dials in flight, "
                 "found %zu", server_dial_count(s));

    /* An illegal peer name is refused at the same point, for the same reason a
     * bad node name is: it could never carry an irc-serve-origin tag. */
    TF_CHECK_MSG(server_dial(s, (const struct sockaddr *)&g_good,
                             sizeof g_good, "not a legal name") != 0,
                 "a peer name with a space was accepted");

    printf("[fixture] dials_started=%zu\n", server_dial_count(s));
    fflush(stdout);
}

int main(void)
{
    nf_node_t node;
    test_client_t c;
    int listen_good;
    int listen_bad;
    socklen_t len;
    int rc;

    /* A socket that IS listening, for the successful dial. */
    listen_good = socket(AF_INET, SOCK_STREAM, 0);
    TF_CHECK(listen_good >= 0);
    {
        int one = 1;

        TF_CHECK(setsockopt(listen_good, SOL_SOCKET, SO_REUSEADDR, &one,
                            sizeof one) == 0);
    }
    memset(&g_good, 0, sizeof g_good);
    g_good.sin_family = AF_INET;
    g_good.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    g_good.sin_port = 0;
    TF_CHECK(bind(listen_good, (struct sockaddr *)&g_good, sizeof g_good) == 0);
    TF_CHECK(listen(listen_good, 8) == 0);
    len = sizeof g_good;
    TF_CHECK(getsockname(listen_good, (struct sockaddr *)&g_good, &len) == 0);

    /* A port with nothing behind it: bind and immediately close, so the number
     * is one the kernel is not using. A refused connect is the failure we
     * want; a timeout would be a different machine state. */
    listen_bad = socket(AF_INET, SOCK_STREAM, 0);
    TF_CHECK(listen_bad >= 0);
    memset(&g_bad, 0, sizeof g_bad);
    g_bad.sin_family = AF_INET;
    g_bad.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    g_bad.sin_port = 0;
    TF_CHECK(bind(listen_bad, (struct sockaddr *)&g_bad, sizeof g_bad) == 0);
    len = sizeof g_bad;
    TF_CHECK(getsockname(listen_bad, (struct sockaddr *)&g_bad, &len) == 0);
    close(listen_bad);

    TF_CHECK(nf_spawn_inline(&node, setup) == 0);
    TF_CHECK_MSG(nf_expect(&node, "[fixture] dials_started=2", T_IO_MS) == 0,
                 "the node never reported starting its dials");

    /* (1) The node kept serving while the dial was in flight. A blocking
     * connect() cannot reach this point at all. */
    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0,
                 "the node's listener stopped accepting while a dial was in "
                 "flight: something in the dial path is blocking the loop");
    TF_CHECK_MSG(nf_expect(&node, "client_connect:", T_IO_MS) == 0,
                 "the node never reported the accept");
    TF_CHECK_MSG(tc_send(&c, "PING :during-dial") == 0, "tc_send failed");
    TF_CHECK_MSG(nf_expect(&node, "command=PING", T_IO_MS) == 0,
                 "the node did not parse a line while a dial was in flight");

    /* The successful dial arrives at the listening socket this test owns. That
     * is the proof the FSM reached DIAL_CONNECTED for real and not just that
     * a counter went up. */
    {
        struct timeval tv;
        fd_set rfds;

        FD_ZERO(&rfds);
        FD_SET(listen_good, &rfds);
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        rc = select(listen_good + 1, &rfds, NULL, NULL, &tv);
        TF_CHECK_MSG(rc == 1,
                     "nothing arrived on the listening socket the node was "
                     "asked to dial: the dial never connected");
        {
            int peer = accept(listen_good, NULL, NULL);

            TF_CHECK_MSG(peer >= 0, "accept of the node's dial failed");
            if (peer >= 0) {
                close(peer);
            }
        }
    }

    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    /* The two monotonic dial outcomes, not the size of the dial table: the
     * table is emptied at shutdown, so its size at exit says nothing, whereas
     * connected+failed accounts for every dial that was ever started. */
    TF_CHECK_MSG(nf_expect_u64(&node, "dial_connected=", 1, T_IO_MS) == 0,
                 "exactly one dial should have connected: the one to the "
                 "listening socket this test owns");
    TF_CHECK_MSG(nf_expect_u64(&node, "dial_failed=", 1, T_IO_MS) == 0,
                 "exactly one dial should have failed: the one to a port with "
                 "nothing behind it");
    /* The node's registry saw the client's accept and the successful dial, and
     * nothing else -- the dead-port dial must never have become a connection. */
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", 2, T_IO_MS) == 0,
                 "accepted should be 2: the one successful dial plus the test "
                 "client");
    TF_CHECK_MSG(nf_expect_u64(&node, "closed=", 2, T_IO_MS) == 0,
                 "closed should be 2");
    TF_CHECK_MSG(nf_expect_u64(&node, "nconns=", 0, T_IO_MS) == 0,
                 "nconns should be 0 after shutdown");

    close(listen_good);
    tc_close(&c);
    nf_free(&node);
    tf_done("dial_fsm");
    return 0;
}
