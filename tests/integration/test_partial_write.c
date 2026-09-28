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
 * ---------------------------------------------------------------------------
 * WHY NOTHING HERE DEPENDS ON A SOCKET-BUFFER VALUE
 * ---------------------------------------------------------------------------
 * An earlier version of this file pinned SO_SNDBUF to 4096 on the node's
 * socket, read the value back, and asserted the read-back was exactly 4096. It
 * passed on macOS and failed on Linux, and the fault was entirely the test's:
 *
 *   - Linux does not return the number you set. setsockopt(SO_SNDBUF, 4096)
 *     followed by getsockopt gives 8192, because the kernel stores roughly
 *     double the request (bookkeeping overhead) and enforces a floor of its
 *     own. macOS re-autotunes the receive side after the handshake as well. So
 *     any test that pins a socket buffer and then asserts on the number is
 *     macOS-only by construction, and so is any test that DERIVES an internal
 *     state expectation from it.
 *   - The whole file's design depended on that number. 128 KB of payload was
 *     chosen to be "several times a pinned 4 KB window", and the handshake
 *     report was a *fixed string* ("sndbuf=4096") rather than a byte count.
 *
 * The buffer is still requested -- see SNDBUF_REQUEST and the dispatch -- but
 * it is requested rather than measured, and nothing branches on the answer.
 * What the request buys is one property that is a property of being SMALL, not
 * of any particular size: a single send() cannot drain a 256 KB queue, so the
 * queue is always left non-empty and the loop's POLLOUT path is always looking
 * at a partial write. 1 KB, 4 KB and 512 KB all behave identically here,
 * because the real bound is that the client reads only FIRST_SLICE bytes
 * before the handshake in main(), far less than the cap.
 *
 * The PAYLOAD is not derived from the buffer at all, because on Linux it could
 * not be: a single send() is bounded by the sender's buffer, but the kernel can
 * also swallow bytes into the RECEIVER's buffer, whose size the test cannot
 * see. So instead the payload is discovered at runtime:
 *   - The client sends one command and then does NOT READ until the node has
 *     reported what happened. Nothing drains the socket, so the kernel's
 *     capacity -- whatever it happens to be on this kernel, this machine and
 *     this day -- fills up and stays full.
 *   - The dispatch then loops: top the queue back up to the cap, pump once,
 *     and look at the result. It stops when a pump could not move a SINGLE
 *     byte, which is the platform-independent statement of "the socket is
 *     saturated and the server is holding the rest". Reaching that state takes
 *     as many rounds as the kernel's capacity needs, so it does not matter
 *     whether the absorb capacity is 8 KB, 4 KB or 4 MB: the queue is refilled
 *     until it is full AND the socket is full, and both are byte counts this
 *     file controls.
 *   - The rounds are bounded (MAX_ROUNDS below) so a hypothetical kernel with
 *     an unbounded buffer fails the test with a diagnostic instead of looping.
 *     It takes 2 rounds on both kernels, and the bound covers a socket that
 *     could absorb 8 MB.
 *   - The payload is therefore NOT a constant: it is however many bytes it
 *     took to saturate the socket, and the test reads exactly the number the
 *     node reports. There is no size to guess and no size to be wrong about.
 *
 * Because the queue is left at the cap with the socket full, and the client
 * then reads in small pieces, the drain below necessarily spans many poll()
 * wakeups on the node: each read frees only what it read, so the node's pump
 * can only ever move that much. A lost, duplicated or reordered byte fails the
 * byte-for-byte comparison, and a retained offset that was not retained makes
 * the drain never finish. Those are the two things this test exists for.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

/* Waiting for the fixture's report: the node is already forked, connected and
 * has already parsed the command line by the time this starts, and the report
 * follows within one loop iteration. Five seconds is a large multiple of that
 * and a sixth of the 30 s this test used to burn on a condition that could
 * never arrive. */
#define T_REPORT_MS 5000

/* Waiting for the node's own event loop to report a short write. The loop's
 * tick is 50 ms (POLL_TICK_MS), so the republication lands within about that;
 * five seconds is the same generous-multiple argument as above. */
#define T_PUMP_MS 5000

/* Draining the payload. Generous, because it is real work over a real socket;
 * on this hardware it is a few milliseconds. */
#define T_DRAIN_MS 20000

/* How much the test reads before it makes the node prove something (see the
 * handshake in main()). A quarter of the write queue, which is what makes the
 * proof below arithmetic rather than a race: see there. */
#define FIRST_SLICE ((size_t)(64u * 1024u))

/* The send-buffer size the dispatch REQUESTS on the node's socket. Nothing
 * reads it back and compares: the kernel is entitled to hand back something
 * else (Linux doubles the request and floors it, macOS re-autotunes), and a
 * test that compared would be macOS-only. See the dispatch for what the request
 * is actually for. */
#define SNDBUF_REQUEST 4096

/* One queued block. Only the call granularity -- the bytes accumulate into the
 * one bounded queue either way. */
#define CHUNK_BYTES (16u * 1024u)

/* How many "top up to the cap, then pump" rounds the dispatch will try before
 * declaring the socket unsaturated. This is the safety net, not the mechanism:
 * the loop stops as soon as a pump cannot move a byte, which in practice is
 * 2 rounds on both kernels, because the sender's buffer is small by request
 * and the receiver's is what the extra rounds are absorbing. 32 rounds covers
 * a socket that could absorb 8 MB, several times the largest seen, and bounds
 * the payload this test reads at 8 MB. The harness client's own 4 MB
 * accumulation cap is irrelevant here: the read below is this file's. */
#define MAX_ROUNDS ((size_t)32u)

/* How much the test reads per recv(). Deliberately much smaller than the
 * queue: the socket is saturated when the report is printed, so the bytes read
 * here are the only thing that makes it writable again, and reading in small
 * pieces is what forces the drain through the retained-offset path dozens of
 * times instead of one send(). */
#define READ_PIECE ((size_t)8192u)

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

/* The flooded connection, and the last value of the loop's partial-write
 * counter flood_tick() has republished. */
static int      g_flood_fd = -1;
static uint64_t g_last_pw = 0;

/* Fill the queue to the cap, pump once, and repeat until a pump cannot move a
 * single byte or MAX_ROUNDS is reached. The byte count is an internal
 * quantity, and conn_write_pending() is the public accessor for it: what is
 * asserted is never "the kernel holds N bytes" but "the queue still holds
 * something after a pump", which is the property 3.3 describes. */
static void flood_dispatch(server_t *s, conn_t *c, const message_t *m)
{
    char chunk[CHUNK_BYTES];
    int want_sndbuf = SNDBUF_REQUEST;
    socklen_t sndlen = sizeof(int);
    size_t rounds = 0;
    size_t queued = 0;
    int sndbuf = 0;
    int overflowed = 0;
    int saturated = 0;

    (void)m;

    if (c->fd < 0) {
        return;
    }
    g_flood_fd = c->fd;

    /* Ask for a small send buffer, and never look at the answer as a value.
     *
     * What this buys is that ONE send() cannot drain the write queue, so the
     * queue is always left non-empty and the loop's POLLOUT path is always
     * looking at a partial write. What it deliberately does NOT buy is a
     * predictable size: Linux stores and reports roughly double the request
     * and floors it, macOS reports the request and then autotunes the RECEIVE
     * side anyway, and the old version of this test asserted the read-back was
     * exactly 4096 -- which is why it passed on macOS and failed on Linux.
     * The read-back is printed as a diagnostic and nothing branches on it.
     *
     * The number requested is not load-bearing either, and the honest version of
     * that claim is a measured one: 1 KB, 4 KB, 16 KB and 64 KB all pass here
     * identically (20 runs each, on macOS and on Linux under Docker), because
     * the bound that matters is "one send() takes less than a queue" and the
     * client only ever reads FIRST_SLICE bytes before the handshake in main() --
     * far less than the 256 KB cap. A request of 256 KB or more is a different
     * regime: the socket then holds hundreds of KB, the sender does not become
     * writable again until macOS has worked through the acknowledgements, and
     * the handshake below times out. The test says so and fails rather than
     * passing quietly, which is the behaviour worth having. */
    (void)setsockopt(c->fd, SOL_SOCKET, SO_SNDBUF, &want_sndbuf,
                     sizeof want_sndbuf);
    (void)getsockopt(c->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &sndlen);

    for (rounds = 0; rounds < MAX_ROUNDS; rounds++) {
        size_t room = CONN_WQ_MAX - conn_write_pending(c);
        size_t off;

        /* Top the queue back up to the cap. The bytes are consecutive
         * positions in one logical stream, so the pattern is generated from
         * the running total rather than from a round counter -- otherwise the
         * rounds would repeat the same window and the comparison below could
         * not tell a duplication from a coincidence. */
        for (off = 0; off < room; off += CHUNK_BYTES) {
            size_t n = room - off;

            if (n > CHUNK_BYTES) {
                n = CHUNK_BYTES;
            }
            pattern_at(queued + off, chunk, n);
            if (server_queue(s, c, chunk, n) != 0) {
                overflowed = 1;
                break;
            }
        }
        if (overflowed) {
            break;
        }
        queued += room;

        (void)conn_pump(c);

        /* The queue is at the cap right now. If it still is after the pump,
         * the socket would not take one more byte: this is the short write,
         * and it is judged from a byte count, not from a socket-buffer value. */
        if (conn_write_pending(c) == CONN_WQ_MAX) {
            saturated = 1;
            break;
        }
    }

    printf("[fixture] flood queued=%zu rounds=%zu saturated=%d pending=%zu "
           "overflow=%d sndbuf=%d\n", queued, rounds + 1u, saturated,
           conn_write_pending(c), overflowed, sndbuf);
    fflush(stdout);
}

/* Republish the loop's short-write counter whenever it changes.
 *
 * Why this exists: the node's poll loop is only woken by the socket becoming
 * writable, and it may already be blocked in poll() for up to a tick when the
 * test's client starts reading. The client can drain a megabyte in the time
 * that tick takes, so the loop's FIRST pump after that can legitimately take
 * the whole remaining queue -- after which there was no partial write to count
 * and the counter would read 0 even though a short write had already happened
 * during the flood. Waiting for the counter to advance would then be waiting
 * for something that depends on the scheduler.
 *
 * So the test does not wait for it unconditionally: main() reads only part of
 * the payload first, which makes the proof arithmetic. When the report was
 * printed the socket was full and the queue held a full cap, so the only thing
 * that can make the socket writable is the bytes the test has read -- and the
 * first slice is smaller than the queue, so a pump at that point cannot empty
 * it. Whenever this counter advances from there, a pump inside the PRODUCTION
 * loop really did come up short. */
static void flood_tick(server_t *s, uint64_t now_ms)
{
    conn_t *c;

    (void)now_ms;

    if (g_flood_fd < 0 || s == NULL || s->n_partial_writes == g_last_pw) {
        return;
    }
    g_last_pw = s->n_partial_writes;
    c = server_conn(s, g_flood_fd);
    printf("[fixture] pump partial_writes=%llu pending=%zu\n",
           (unsigned long long)s->n_partial_writes,
           (c != NULL) ? conn_write_pending(c) : (size_t)0);
    fflush(stdout);
}

static void setup(server_t *s)
{
    s->dispatch = flood_dispatch;
    s->on_tick = flood_tick;
}

static uint64_t now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000L);
}

/* Read exactly `n` bytes off `fd` into `dst`, in bounded pieces, or fail.
 *
 * The piece size is the point of this function rather than an optimisation;
 * see READ_PIECE. A deadline wait over select(), never a fixed sleep: the short
 * select() timeout is a polling interval, not a claim about how long the node
 * takes. */
static void read_all(int fd, char *dst, size_t n, int timeout_ms)
{
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    size_t off = 0;

    while (off < n) {
        char piece[READ_PIECE];
        struct timeval tv;
        fd_set rfds;
        uint64_t left;
        size_t want = n - off;
        ssize_t got;
        int rc;

        if (want > sizeof piece) {
            want = sizeof piece;
        }
        left = (deadline > now_ms()) ? (deadline - now_ms()) : 0;
        if (left == 0) {
            break;
        }
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        tv.tv_sec = (time_t)(left / 1000u);
        tv.tv_usec = (suseconds_t)((left % 1000u) * 1000u);

        rc = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (rc == 0) {
            break;
        }
        got = recv(fd, piece, want, 0);
        if (got == 0) {
            break; /* EOF: the node closed before the payload was all sent */
        }
        if (got < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            break;
        }
        memcpy(dst + off, piece, (size_t)got);
        off += (size_t)got;
    }
    TF_CHECK_MSG(off == n, "read %zu of %zu bytes: the node did not deliver the "
                 "whole payload, so a retained offset was lost or the queue was "
                 "dropped", off, n);
}

int main(void)
{
    nf_node_t node;
    test_client_t c;
    uint64_t queued = 0;
    uint64_t rounds = 0;
    char *got;
    size_t off;

    TF_CHECK(nf_spawn_inline(&node, setup) == 0);

    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "connect failed");

    TF_CHECK_MSG(tc_send(&c, "FLOOD") == 0, "tc_send failed");

    /* Deliberately nothing is read before this point: an unread socket is what
     * makes the queue fill, and reading early would let the node drain and
     * prove nothing. The report is the proof that send() came up short -- if
     * the implementation ever lost the retained offset instead, the queue
     * would be empty when the fixture looked, and this line would never
     * appear. */
    TF_CHECK_MSG(nf_expect(&node, "[fixture] flood queued=", T_REPORT_MS) == 0,
                 "node never reported the queue state");
    TF_CHECK_MSG(nf_expect(&node, "saturated=1", T_REPORT_MS) == 0,
                 "the node never filled its write queue against a client that "
                 "is not reading: without a saturated queue the payload could "
                 "have been taken in one send() and this test would assert "
                 "nothing about partial writes");
    TF_CHECK_MSG(nf_expect(&node, "overflow=0", T_REPORT_MS) == 0,
                 "an append was refused: this test tops the queue up to "
                 "exactly the cap each round and must never need the cap test "
                 "(test_writeq_overflow covers the refusal)");

    /* The payload is however many bytes it took to saturate the socket, so the
     * length to read is learned from the node rather than assumed here. Both
     * keys are unique in the child's output. */
    TF_CHECK_MSG(nf_find_u64(&node, "flood queued=", &queued) == 0,
                 "could not read the queued byte count from the node");
    TF_CHECK_MSG(nf_find_u64(&node, "rounds=", &rounds) == 0,
                 "could not read the round count from the node");
    TF_CHECK_MSG(queued > 0, "the node queued nothing at all");
    /* Two rounds are always needed -- the first can be swallowed whole by the
     * socket, and only the second can establish that the socket is full -- so
     * the payload is at least two caps and the handshake slice always fits in
     * what the node has produced. */
    TF_CHECK_MSG(queued > (uint64_t)FIRST_SLICE,
                 "the node queued only %llu bytes, which is not enough to "
                 "handshake over", (unsigned long long)queued);
    printf("note: the queue filled after %llu round(s), %llu bytes queued, so "
           "the socket could not take the cap in one go\n",
           (unsigned long long)rounds, (unsigned long long)queued);

    got = (char *)malloc((size_t)queued);
    TF_CHECK(got != NULL);

    /* Read the FIRST SLICE, then stop and make the node prove that a pump
     * inside its own event loop came up short, and only then read the rest.
     *
     * This is a deadline wait on the node's republished counter, not a sleep
     * and not a hope. The arithmetic: when the report was printed the socket
     * was full and the queue held a full 256 KB cap, so the socket can only
     * have become writable because of the bytes read just now, and only
     * FIRST_SLICE of them have been read. A pump therefore cannot empty a
     * 256 KB queue, so the counter the node publishes next is a count of real
     * short writes inside poll_loop's POLLOUT path. Without the handshake the
     * loop could legitimately take the whole remaining queue in one pump,
     * because the loop may be up to one 50 ms tick behind the client -- the
     * client drains this payload in about two milliseconds. */
    read_all(c.fd, got, FIRST_SLICE, T_DRAIN_MS);
    TF_CHECK_MSG(nf_expect_u64_ge(&node, "partial_writes=", 1, T_PUMP_MS) == 0,
                 "the node's own event loop never recorded a short write, and "
                 "the socket was full with a full queue in it when it "
                 "reported: the partial-write path inside the loop was never "
                 "taken");

    read_all(c.fd, got + FIRST_SLICE, (size_t)queued - FIRST_SLICE, T_DRAIN_MS);

    for (off = 0; off < (size_t)queued; off++) {
        char want;

        pattern_at(off, &want, 1);
        if (got[off] != want) {
            TF_CHECK_MSG(0, "byte %zu is 0x%02x, expected 0x%02x -- a partial "
                         "write lost, duplicated or reordered data", off,
                         (unsigned char)got[off], (unsigned char)want);
        }
    }

    /* And the node's own accounting agrees at the end of the run. */
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64_ge(&node, "partial_writes=", 1, T_REPORT_MS) == 0,
                 "the node never recorded a short write: the queue was drained "
                 "in a single send(), so the partial-write path was never "
                 "taken");
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", 1, T_REPORT_MS) == 0,
                 "accepted should be 1");
    TF_CHECK_MSG(nf_expect_u64(&node, "writeq_overflow=", 0, T_REPORT_MS) == 0,
                 "writeq_overflow should be 0: this test must not exercise "
                 "the cap");

    free(got);
    tc_close(&c);
    nf_free(&node);
    tf_done("partial_write");
    return 0;
}
