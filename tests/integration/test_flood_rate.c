/* test_flood_rate.c -- per-connection flood rate limit (#168).
 *
 * poll_loop.c gives every client connection a token bucket: burst 256 lines,
 * refilling at 50/sec. Each dispatched client line spends one token; an empty
 * bucket means the sender is flooding, and the node answers that line with one
 * 417, flushes it, marks the connection CLOSING, and lets the reaper collect
 * the fd. CONN_SERVER links are exempt and never spend.
 *
 * Two clients prove the two halves: a flooder that sends 300 PINGs back to
 * back (registration spends 2 tokens, so 302 spend against a 256 burst -- the
 * refill over a back-to-back burst is negligible beside the 46-line margin)
 * must see exactly the one 417, the node must print `[observable]
 * rate_limited:`, and the connection must then EOF. An honest client on its
 * own connection -- its own bucket -- registers (001) and gets its PONG, both
 * before and after the flood, proving the limiter is per-connection rather
 * than node-wide.
 *
 * NO FIXED sleep() ANYWHERE (6.3): every wait is a deadline wait.
 */
#include <stdio.h>
#include <string.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000
#define FLOOD_LINES 300

int main(void)
{
    nf_node_t node;
    test_client_t honest;
    test_client_t flood;
    int i;

    TF_CHECK(nf_spawn_binary(&node) == 0);

    /* The honest client first: it registers and gets a PONG, proving the node
     * serves normally before any flood. */
    tc_init(&honest);
    TF_CHECK_MSG(tc_connect(&honest, node.port) == 0, "honest connect failed");
    TF_CHECK_MSG(tc_send(&honest, "NICK honest") == 0, "honest NICK failed");
    TF_CHECK_MSG(tc_send(&honest, "USER honest 0 * :Honest") == 0,
                 "honest USER failed");
    TF_CHECK_MSG(tc_expect(&honest, " 001 ", T_IO_MS) == 0,
                 "the honest client never registered");
    TF_CHECK_MSG(tc_send(&honest, "PING :honest-hi") == 0,
                 "honest PING failed");
    TF_CHECK_MSG(tc_expect(&honest, "PONG irc.test honest-hi", T_IO_MS) == 0,
                 "the honest client's PING was never answered with a PONG.\n"
                 "  saw: %s", tc_buffer(&honest));

    /* The flooder: registers, then spends past its burst in one back-to-back
     * run. The sends fit in the socket buffers, so no send can fail because
     * the server closed early -- the close only happens after the server has
     * read past the burst. */
    tc_init(&flood);
    TF_CHECK_MSG(tc_connect(&flood, node.port) == 0, "flood connect failed");
    TF_CHECK_MSG(tc_send(&flood, "NICK flooder") == 0, "flood NICK failed");
    TF_CHECK_MSG(tc_send(&flood, "USER flooder 0 * :Flooder") == 0,
                 "flood USER failed");
    TF_CHECK_MSG(tc_expect(&flood, " 001 ", T_IO_MS) == 0,
                 "the flooding client never registered");
    for (i = 0; i < FLOOD_LINES; i++) {
        TF_CHECK_MSG(tc_send(&flood, "PING :flood") == 0,
                     "flood PING %d of %d could not be sent", i, FLOOD_LINES);
    }

    /* One 417 on the wire, carrying the reason. The " 417 " needle is the
     * legacy numeric a client without standard-replies sees. */
    TF_CHECK_MSG(tc_expect(&flood, " 417 ", T_IO_MS) == 0,
                 "the flood was never refused with 417: the limiter did not "
                 "fire within %d lines against a 256 burst.\n  saw: %s",
                 FLOOD_LINES, tc_buffer(&flood));
    TF_CHECK_MSG(strstr(tc_buffer(&flood), "Input rate limit exceeded") != NULL,
                 "the 417 did not carry the rate-limit reason.\n  saw: %s",
                 tc_buffer(&flood));

    /* Counted on the node's own output, so a 417 from any other site cannot
     * satisfy this. */
    TF_CHECK_MSG(nf_expect(&node, "rate_limited:", T_IO_MS) == 0,
                 "the node never reported the rate limit on its observable "
                 "output.\n  node said: %s", node.out);

    /* And then the close: the refusal is flushed before the mark, so the 417
     * above is already in hand and the EOF is a clean FIN, not a reset. */
    {
        int rc = tc_expect_eof(&flood, T_IO_MS);

        TF_CHECK_MSG(rc == 0,
                     "the flooding connection was not closed after the 417 "
                     "(rc=%d)", rc);
    }

    /* The honest client is unaffected: its own bucket still has room, so a
     * PING after the flood is still answered. */
    TF_CHECK_MSG(tc_send(&honest, "PING :honest-after") == 0,
                 "honest PING after the flood failed");
    TF_CHECK_MSG(tc_expect(&honest, "PONG irc.test honest-after", T_IO_MS) == 0,
                 "the honest client stopped getting PONGs after another "
                 "client was rate-limited: the limiter is not "
                 "per-connection.\n  saw: %s", tc_buffer(&honest));

    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");

    tc_close(&honest);
    tc_close(&flood);
    nf_free(&node);
    tf_done("flood_rate");
    return 0;
}
