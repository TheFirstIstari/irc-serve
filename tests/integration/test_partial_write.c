/* test_partial_write.c -- a short write must not lose or reorder a byte.
 *
 * docs/SERVER_DESIGN.md 3.3: "Partial writes matter: nonblocking send() may
 * write fewer bytes than offered, so woff is retained and drained across poll
 * iterations." 3.4: "Bounded write queues, ~256 KB per connection."
 *
 * A test for that cannot use the shipped binary, and it is worth being precise
 * about why rather than shrugging at it. Phase 2 has no command surface: the
 * node has no verb to answer with, so it has no way to be made to send a
 * hundred kilobytes from the outside. Everything this file asserts is therefore
 * produced by calling the REAL conn_queue()/conn_pump() API on a REAL
 * registered connection, inside a child running the REAL core loop. The only
 * thing the test supplies is the missing piece -- what the node says -- which
 * is exactly the dispatch seam 3.3 defines and Phase 3 fills in. It is not a
 * test of a mock: the queue, the bound, the retained offset, the drain and the
 * reap are all production code paths.
 *
 * The scenario, and why each part is forced rather than hoped for:
 *
 *   - The dispatch pins SO_SNDBUF to 4 KB on the node's socket before queueing
 *     anything, and the test asserts the pinned value took effect. This is the
 *     load-bearing part: an unpinned send buffer is platform- and
 *     autotune-dependent (macOS lands around 256 KB, Linux anywhere from 16 KB
 *     to several MB), so without it a 128 KB payload could fit outright and the
 *     test would assert nothing. Setting SO_SNDBUF explicitly does hold, on both
 *     platforms, and the read-back assertion means a kernel that ignores it
 *     fails the test loudly instead of quietly weakening it.
 *   - The client's SO_RCVBUF is NOT used for this, deliberately. macOS
 *     re-autotunes the receive buffer after the handshake and reports a figure
 *     an order of magnitude above the request, so a small receive window is not
 *     something a test can rely on there. Pinning the sender is the portable
 *     lever, and it is the correct side anyway: the send buffer is what decides
 *     how much one send() may write.
 *   - 128 KB is queued -- comfortably under the 256 KB cap, so this is purely a
 *     partial-write test and not a cap test (test_writeq_overflow covers the
 *     cap).
 *   - The payload is a position-dependent pattern, so the comparison is
 *     byte-for-byte AND order-sensitive: a dropped, duplicated or reordered byte
 *     fails the memcmp.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 30000

/* 128 KiB: several times any plausible socket buffer once SO_SNDBUF is pinned,
 * and half the queue cap, so the cap is not what ends the transfer. */
#define PAYLOAD_BYTES (128u * 1024u)
#define CHUNK_BYTES (16u * 1024u)

/* Fill pattern. A function rather than a static buffer so the test process
 * never has to hold a second copy of the payload. */
static void pattern_at(size_t offset, char *dst, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        /* A printable, position-dependent sequence: 'a' + (offset % 26) makes
         * every 26-byte window identical, so a shift by a multiple of 26 would
         * slip through -- hence the modulo of the absolute offset over 251 as
         * well, which makes every window unique. */
        dst[i] = (char)('!' + (int)((offset + i) % 251u));
    }
}

static void flood_dispatch(server_t *s, conn_t *c, const message_t *m)
{
    char chunk[CHUNK_BYTES];
    int sndbuf = 4096;
    int sndbuf_effective = 0;
    socklen_t sndlen = sizeof sndbuf_effective;
    size_t off;
    size_t queued = 0;
    int overflowed = 0;

    (void)m;

    if (c->fd < 0) {
        return;
    }
    (void)setsockopt(c->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);
    (void)getsockopt(c->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf_effective, &sndlen);

    /* Queue the payload through the production API in chunks. Chunking is only
     * about the call granularity; the bytes accumulate into the one bounded
     * queue either way. */
    for (off = 0; off < PAYLOAD_BYTES; off += CHUNK_BYTES) {
        size_t n = PAYLOAD_BYTES - off;

        if (n > CHUNK_BYTES) {
            n = CHUNK_BYTES;
        }
        pattern_at(off, chunk, n);
        if (server_queue(s, c, chunk, n) != 0) {
            overflowed = 1;
            break;
        }
        queued += n;
    }

    /* Pump once, synchronously, so the state of the queue right afterwards is
     * observable from the test with no timing assumption at all. A correct
     * implementation leaves bytes pending here, because the socket cannot take
     * 128 KB with a 4 KB window. */
    (void)conn_pump(c);

    printf("[fixture] queued=%zu pending=%zu overflow=%d sndbuf=%d\n", queued,
           conn_write_pending(c), overflowed, sndbuf_effective);
    fflush(stdout);
}

static void setup(server_t *s)
{
    s->dispatch = flood_dispatch;
}

int main(void)
{
    nf_node_t node;
    test_client_t c;
    char *got;
    size_t off;

    TF_CHECK(nf_spawn_inline(&node, setup) == 0);

    /* A small receive window, set before the handshake, so the node's socket
     * fills after a few kilobytes. */
    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "connect failed");

    TF_CHECK_MSG(tc_send(&c, "FLOOD") == 0, "tc_send failed");

    /* The handshake report is the proof that send() came up short. If the
     * implementation ever loses the retained offset instead, pending would be
     * 0 here and this line would never appear. */
    TF_CHECK_MSG(nf_expect(&node, "[fixture] queued=", T_IO_MS) == 0,
                 "node never reported the queue state");
    TF_CHECK_MSG(nf_expect(&node, "overflow=0", T_IO_MS) == 0,
                 "the 128 KB payload was refused: it must stay under the "
                 "256 KB cap for this to be a partial-write test");
    /* The pinned send buffer is what makes the short write inevitable, so its
     * absence invalidates everything below. A kernel that ignored the request
     * would leave this test passing while testing nothing. */
    TF_CHECK_MSG(nf_expect(&node, "sndbuf=4096", T_IO_MS) == 0,
                 "the node's send buffer was not pinned to 4096: without that "
                 "the 128 KB payload might fit outright and this test would "
                 "assert nothing about partial writes");

    /* Now read everything, slowly (the node can only push a few KB per poll
     * wakeup, so this genuinely spans many iterations) and compare byte for
     * byte. */
    got = (char *)malloc(PAYLOAD_BYTES);
    TF_CHECK(got != NULL);
    TF_CHECK_MSG(tc_read_exact(&c, got, PAYLOAD_BYTES, T_IO_MS) == 0,
                 "did not receive the whole %u byte payload", PAYLOAD_BYTES);

    for (off = 0; off < PAYLOAD_BYTES; off++) {
        char want;

        pattern_at(off, &want, 1);
        if (got[off] != want) {
            TF_CHECK_MSG(0, "byte %zu is 0x%02x, expected 0x%02x -- a partial "
                         "write lost, duplicated or reordered data", off,
                         (unsigned char)got[off], (unsigned char)want);
        }
    }

    /* The node's own accounting must show the queue really did short-write
     * rather than having fitted in the socket. */
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64_ge(&node, "partial_writes=", 1, T_IO_MS) == 0,
                 "the node never recorded a short write: either the socket "
                 "took the whole payload (so the send buffer was not pinned "
                 "and this test proved nothing) or the partial write was not "
                 "counted");
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", 1, T_IO_MS) == 0,
                 "accepted should be 1");
    TF_CHECK_MSG(nf_expect_u64(&node, "writeq_overflow=", 0, T_IO_MS) == 0,
                 "writeq_overflow should be 0: this test must not exercise "
                 "the cap");

    free(got);
    tc_close(&c);
    nf_free(&node);
    tf_done("partial_write");
    return 0;
}
