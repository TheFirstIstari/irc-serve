/* test_framing.c -- conn_t's buffer mechanics on a real socket: RFC 1459 2.3
 * line framing, and the write queue's bound and compaction.
 *
 * docs/SERVER_DESIGN.md 3.3: conn_t's read buffer and the framing that turns a
 * byte stream into lines. 3.2 fixes the on-wire cap at IRC_MAX_LINE. 3.4: the
 * write queue is bounded, and a partial write leaves the remainder queued with
 * the offset retained.
 *
 * This one drives conn_t directly over a socketpair rather than going through a
 * spawned node, and the reason is determinism. Almost every interesting framing
 * case is a statement about a PARTIAL line -- "these bytes are not a line yet"
 * -- and the only way to observe that from outside a socket is to control when
 * the bytes arrive. Over real TCP the kernel coalesces whatever it likes, so a
 * test that writes "PI" and then "NG\r\n" cannot promise the server will see
 * them separately. A socketpair plus a call to conn_next_line() can promise it,
 * with no sleeps and no timing assumptions at all, and the code under test is
 * the same conn_fill()/conn_next_line() the loop calls.
 *
 * The line cap is asserted against the boundary rather than a round number,
 * because a cap that is off by one either truncates an honest line or lets an
 * unbounded one through:
 *   - a line of exactly IRC_MAX_LINE bytes (terminator included) is LEGAL
 *   - one byte more, with the terminator, is REFUSED
 *   - IRC_MAX_LINE bytes with NO terminator is REFUSED, and must be refused
 *     before any further byte arrives, so withholding a newline cannot make the
 *     read buffer grow without bound
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "core/connection.h"
#include "core/message.h"
#include "harness/test_util.h"

/* Write everything into the socket, or fail.
 *
 * BOTH ends of the rig are nonblocking. The conn's end must be, because
 * conn_fill() loops to EAGAIN and conn_pump() returns on EAGAIN. The far end
 * must be too, or the drain loop below blocks forever on a read that will never
 * be satisfied -- a test that hangs is worse than one that fails, so the rig
 * removes the possibility rather than the test reasoning about it. */
static void put(int fd, const char *bytes, size_t n)
{
    size_t off = 0;
    int stalls = 0;

    while (off < n) {
        ssize_t w = write(fd, bytes + off, n - off);

        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                      errno == EINTR)) {
            struct timeval tv = { 0, 2000 };
            fd_set wfds;

            /* Yield until the socket has room. Not a fixed wait: select()
             * returns the moment it does. Bounded, so a genuinely stuck write
             * fails the test instead of spinning. */
            FD_ZERO(&wfds);
            FD_SET(fd, &wfds);
            if (++stalls > 2000) {
                TF_CHECK_MSG(0, "write stalled with %zu of %zu bytes written",
                             off, n);
            }
            (void)select(fd + 1, NULL, &wfds, NULL, &tv);
            continue;
        }
        TF_CHECK_MSG(0, "write to the socketpair failed");
    }
}

/* One conn_t over one end of a socketpair, with the other end to feed.
 *
 * The conn's descriptor is made nonblocking, which is not a convenience: the
 * loop guarantees every registered descriptor is nonblocking (server_accept_one
 * and server_dial both set it before the fd becomes reachable), and conn_fill()
 * and conn_pump() are written on that promise -- conn_fill loops until EAGAIN
 * and conn_pump returns on EAGAIN. A blocking descriptor here would make both
 * of them block, so the rig has to match the invariant the loop maintains. */
typedef struct {
    int      pair[2];
    conn_t  *c;
} rig_t;

static void rig_open(rig_t *r)
{
    int i;

    TF_CHECK_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, r->pair) == 0,
                 "socketpair failed");
    for (i = 0; i < 2; i++) {
        int flags = fcntl(r->pair[i], F_GETFL, 0);
        /* A socketpair's default buffer is a few KB, which is smaller than the
         * 8 KB legal line these tests feed it, so a write would block on a
         * reader that is deliberately not running yet. 32 KB per end is
         * comfortably more than a line and comfortably less than the 200 KB
         * flood in test_eof_and_pump(), so the same rig serves both: the line
         * fits, and the flood still cannot. */
        int bufsz = 32768;

        TF_CHECK(flags >= 0);
        TF_CHECK_MSG(fcntl(r->pair[i], F_SETFL, flags | O_NONBLOCK) == 0,
                     "could not make socketpair end %d nonblocking", i);
        (void)setsockopt(r->pair[i], SOL_SOCKET, SO_SNDBUF, &bufsz,
                         sizeof bufsz);
        (void)setsockopt(r->pair[i], SOL_SOCKET, SO_RCVBUF, &bufsz,
                         sizeof bufsz);
    }
    r->c = conn_new(r->pair[0], CONN_CLIENT);
    TF_CHECK(r->c != NULL);
}

static void rig_close(rig_t *r)
{
    conn_free(r->c);
    close(r->pair[0]);
    close(r->pair[1]);
    r->c = NULL;
}

/* Feed bytes, then pull lines. Returns the number of complete lines found and
 * hands the last one back. The framing layer copies each line into the caller's
 * buffer, so `line_out` stays valid across further calls. */
static int drain(rig_t *r, char *line_out, size_t *len_out)
{
    char scratch[IRC_MAX_LINE];
    int n = 0;

    TF_CHECK_MSG(conn_fill(r->c) == 0, "conn_fill reported a hard error");
    for (;;) {
        size_t len = 0;
        int got = conn_next_line(r->c, scratch, sizeof scratch, &len);

        if (got == 0) {
            break;
        }
        TF_CHECK_MSG(got == 1, "conn_next_line reported a framing error");
        if (line_out != NULL && len_out != NULL) {
            *len_out = len;
            memcpy(line_out, scratch, len);
        }
        n++;
    }
    return n;
}

static void test_simple_line(void)
{
    rig_t r;
    char line[64];
    size_t len = 0;

    rig_open(&r);
    put(r.pair[1], "PING :hello\r\n", 13);
    TF_CHECK_MSG(drain(&r, line, &len) == 1, "expected exactly one line");
    /* The terminator is handed on to the parser rather than stripped here: the
     * framing layer holds a length, and message_parse_n() is the entry point
     * that can reject an embedded NUL. */
    TF_CHECK_MSG(len == 13, "line length %zu, expected 13 including CRLF", len);
    TF_CHECK_MSG(memcmp(line, "PING :hello\r\n", 13) == 0,
                 "the framed line is not the bytes that arrived");
    rig_close(&r);
}

static void test_partial_line(void)
{
    rig_t r;
    char line[64];
    size_t len = 0;

    rig_open(&r);
    /* The first two bytes, and no terminator: not a line yet. */
    put(r.pair[1], "PI", 2);
    TF_CHECK_MSG(drain(&r, NULL, NULL) == 0,
                 "an unterminated fragment was treated as a line");
    /* The rest. Now it is a line, and it is the whole thing. */
    put(r.pair[1], "NG :x\r\n", 7);
    TF_CHECK_MSG(drain(&r, line, &len) == 1, "the completed line was not "
                 "delivered");
    TF_CHECK_MSG(len == 9 && memcmp(line, "PING :x\r\n", 9) == 0,
                 "the reassembled line is wrong (len=%zu)", len);
    rig_close(&r);
}

static void test_two_lines_one_read(void)
{
    rig_t r;
    char scratch[IRC_MAX_LINE];
    char first[64];
    char second[64];
    size_t len = 0;

    rig_open(&r);
    /* Two commands in one segment must come out as two lines, with nothing left
     * over -- this is the case a "read one line per read()" implementation
     * silently drops the second of.
     *
     * Both lines are pulled into the caller's buffer and compared, and the
     * first is still intact after the second has been pulled. That is the
     * property being asserted, not an accident of the API: an implementation
     * that hands back a pointer into the read buffer and then compacts over it
     * returns the SECOND line's bytes for the first call, which is exactly what
     * this test caught on the first run. */
    put(r.pair[1], "PRIVMSG #a :one\r\nPRIVMSG #b :two\r\n", 34);
    TF_CHECK_MSG(conn_fill(r.c) == 0, "conn_fill failed");
    TF_CHECK_MSG(conn_next_line(r.c, scratch, sizeof scratch, &len) == 1,
                 "the first line was not framed");
    TF_CHECK_MSG(len == 17, "the first line is %zu bytes, expected 17", len);
    memcpy(first, scratch, len);
    TF_CHECK_MSG(memcmp(first, "PRIVMSG #a :one\r\n", 17) == 0,
                 "the first line is not the bytes that arrived");
    TF_CHECK_MSG(conn_next_line(r.c, scratch, sizeof scratch, &len) == 1,
                 "the second line in the same segment was dropped");
    TF_CHECK_MSG(len == 17, "the second line is %zu bytes, expected 17", len);
    memcpy(second, scratch, len);
    TF_CHECK_MSG(memcmp(second, "PRIVMSG #b :two\r\n", 17) == 0,
                 "the second line is not the bytes that arrived");
    TF_CHECK_MSG(memcmp(first, "PRIVMSG #a :one\r\n", 17) == 0,
                 "the FIRST line was clobbered by pulling the second: the "
                 "framing layer must copy the line out, not hand back a "
                 "pointer into the buffer it just compacted");
    TF_CHECK_MSG(conn_next_line(r.c, scratch, sizeof scratch, &len) == 0,
                 "a third line was invented");
    TF_CHECK_MSG(r.c->rlen == 0, "%zu bytes were left in the read buffer",
                 r.c->rlen);
    rig_close(&r);
}

/* A bare LF is accepted as a terminator because message_parse_n() accepts it,
 * and the parser -- not the framing layer -- is where the line grammar is
 * enforced. RFC 1459 2.3 requires CRLF of the SENDER; rejecting a bare LF here
 * would mean duplicating the grammar in two places, and the two would drift. */
static void test_bare_lf(void)
{
    rig_t r;
    char line[64];
    size_t len = 0;

    rig_open(&r);
    put(r.pair[1], "PING :y\n", 8);
    TF_CHECK_MSG(drain(&r, line, &len) == 1, "a bare LF was not accepted");
    TF_CHECK_MSG(len == 8, "line length %zu, expected 8", len);
    rig_close(&r);
}

static void test_cap_boundary(void)
{
    rig_t r;
    char *big;
    size_t cap = (size_t)IRC_MAX_LINE;

    big = (char *)malloc(cap + 1u);
    TF_CHECK(big != NULL);

    /* Exactly at the cap, terminator included: LEGAL. The cap counts the
     * terminator, so 8192 bytes is the largest legal line and one byte fewer is
     * a truncation the parser has no way to detect -- which is why the
     * boundary is asserted rather than approximated. */
    memset(big, 'A', cap);
    big[cap - 2u] = '\r';
    big[cap - 1u] = '\n';
    rig_open(&r);
    put(r.pair[1], big, cap);
    TF_CHECK_MSG(drain(&r, NULL, NULL) == 1,
                 "a line of exactly IRC_MAX_LINE bytes was refused: the cap "
                 "counts the terminator, so %zu bytes is legal", cap);
    TF_CHECK_MSG(r.c->rcap <= CONN_RBUF_MAX,
                 "the read buffer grew to %zu, past the bound a peer controls",
                 r.c->rcap);
    rig_close(&r);

    /* One byte over the cap, terminator last: REFUSED. Note what happens to
     * the 8193rd byte -- conn_fill() stops at the cap and never reads it, so
     * the framing layer never even sees a terminator. That is the bound being
     * enforced rather than a side effect: the read buffer is capped at the line
     * cap precisely so a peer cannot make it grow by withholding a newline. */
    memset(big, 'A', cap + 1u);
    big[cap] = '\n';
    rig_open(&r);
    put(r.pair[1], big, cap + 1u);
    TF_CHECK_MSG(conn_fill(r.c) == 0, "conn_fill failed");
    TF_CHECK_MSG(r.c->rlen == cap,
                 "the read buffer took %zu bytes; it must stop at the cap %zu",
                 r.c->rlen, cap);
    {
        char scratch[IRC_MAX_LINE + 2u];
        size_t len = 0;

        TF_CHECK_MSG(conn_next_line(r.c, scratch, sizeof scratch, &len) < 0,
                     "a line one byte over IRC_MAX_LINE was accepted");
    }
    rig_close(&r);

    /* A full buffer with no terminator anywhere: refused NOW, not whenever more
     * bytes happen to arrive. */
    memset(big, 'A', cap);
    rig_open(&r);
    put(r.pair[1], big, cap);
    TF_CHECK_MSG(conn_fill(r.c) == 0, "conn_fill failed");
    {
        char scratch[IRC_MAX_LINE + 2u];
        size_t len = 0;

        TF_CHECK_MSG(r.c->rlen == cap, "the read buffer holds %zu bytes, "
                     "expected it to have stopped at the cap %zu",
                     r.c->rlen, cap);
        TF_CHECK_MSG(conn_next_line(r.c, scratch, sizeof scratch, &len) < 0,
                     "IRC_MAX_LINE bytes with no terminator was not reported "
                     "as a framing error: withholding a newline must not be "
                     "able to keep the connection alive forever");
    }
    rig_close(&r);

    free(big);
}

static void test_eof_and_pump(void)
{
    rig_t r;
    char sink[64];

    /* conn_fill distinguishes a clean EOF from a hard error, so the loop can
     * report "the client hung up" rather than "read error". */
    rig_open(&r);
    close(r.pair[1]);
    r.pair[1] = -1;
    TF_CHECK_MSG(conn_fill(r.c) == CONN_FILL_EOF,
                 "a peer that closed its half was not reported as EOF");
    rig_close(&r);

    /* The pump sends what it can and keeps the rest, with the offset retained.
     * The queue is far larger than any socket buffer, so a single pump cannot
     * finish it -- which is the partial-write case, on a plain socketpair and
     * with no test-provided timing of any kind. */
    rig_open(&r);
    {
        /* Larger than CONN_WQ_MAX would be refused outright, so the flood is
         * sized against the cap rather than past it. */
        static char bulk[200u * 1024u];
        size_t drained = 0;

        memset(bulk, 0xA5, sizeof bulk);
        TF_CHECK_MSG(conn_queue(r.c, bulk, sizeof bulk) == 0,
                     "conn_queue refused %zu bytes, which is under the cap",
                     sizeof bulk);
        TF_CHECK_MSG(conn_pump(r.c) == 0, "conn_pump failed");
        TF_CHECK_MSG(conn_write_pending(r.c) > 0,
                     "conn_write_pending is %zu after one pump of %zu bytes: "
                     "the socket cannot have taken all of it, so the retained "
                     "offset is what makes the difference",
                     conn_write_pending(r.c), sizeof bulk);

        /* Drain the far end, pumping whenever there is room, until the whole
         * payload has been read. Every byte must arrive, in order, and none of
         * them twice -- which is only checkable if the pump really did leave
         * work behind for later rounds. The loop stops when a full round moves
         * nothing, so it cannot spin. */
        for (;;) {
            int progress = 0;
            ssize_t got;

            if (conn_write_pending(r.c) > 0) {
                size_t before = conn_write_pending(r.c);

                TF_CHECK_MSG(conn_pump(r.c) == 0, "conn_pump failed");
                if (conn_write_pending(r.c) < before) {
                    progress = 1;
                }
            }
            got = read(r.pair[1], sink, sizeof sink);
            if (got > 0) {
                TF_CHECK_MSG((size_t)got <= sizeof bulk - drained,
                             "read %zd bytes with only %zu left",
                             got, sizeof bulk - drained);
                TF_CHECK_MSG(memcmp(sink, bulk + drained, (size_t)got) == 0,
                             "the bytes at offset %zu are not what was queued",
                             drained);
                drained += (size_t)got;
                continue;
            }
            if (got == 0) {
                break; /* the far end went away */
            }
            /* EAGAIN: the socket is empty. If the pump also moved nothing,
             * nothing can happen without the other side, so stop. */
            if (!progress) {
                break;
            }
        }
        TF_CHECK_MSG(drained == sizeof bulk,
                     "drained %zu of %zu bytes", drained, sizeof bulk);
        TF_CHECK_MSG(conn_write_pending(r.c) == 0,
                     "%zu bytes are still queued after everything was read",
                     conn_write_pending(r.c));
    }
    rig_close(&r);
}

/* The write queue's two bounds, and the compaction that keeps them consistent.
 *
 * The cap is on the UNSENT tail, and the allocation is a different thing that
 * can ratchet. A queue that has grown to the cap and then drained a little has
 * an allocation at the cap and a tail below it; appending to it is legal by the
 * rule, so it must succeed. It used to fail, because growing the allocation to
 * fit would have passed the cap, and the refusal the caller then saw was
 * indistinguishable from an over-cap one.
 *
 * Forced with a small send buffer so a single pump drains an amount below the
 * compaction threshold, which is the only way to reach the state where the sent
 * head is small and the allocation is still at the cap. */
static void test_queue_compaction(void)
{
    rig_t r;
    char *bulk;
    size_t chunk = 4096;
    int sndbuf = 1024; /* below CONN_WQ_COMPACT, so one pump leaves woff < it */
    size_t at_cap;
    size_t headroom;

    bulk = (char *)malloc(CONN_WQ_MAX);
    TF_CHECK(bulk != NULL);
    memset(bulk, 'q', CONN_WQ_MAX);

    rig_open(&r);
    /* A send buffer this small is the only way to make the socket take exactly a
     * few hundred bytes per pump, which is what leaves a small non-zero woff. */
    (void)setsockopt(r.pair[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);

    /* Fill to exactly the cap. */
    at_cap = 0;
    while (at_cap < CONN_WQ_MAX) {
        size_t n = CONN_WQ_MAX - at_cap;

        if (n > chunk) {
            n = chunk;
        }
        TF_CHECK_MSG(conn_queue(r.c, bulk, n) == 0,
                     "filling the queue to the cap was refused at %zu of %zu",
                     at_cap, CONN_WQ_MAX);
        at_cap += n;
    }
    TF_CHECK_MSG(conn_write_pending(r.c) == CONN_WQ_MAX,
                 "the queue holds %zu bytes, expected %zu",
                 conn_write_pending(r.c), CONN_WQ_MAX);
    TF_CHECK_MSG(r.c->wcap == CONN_WQ_MAX,
                 "the allocation is %zu, expected it to have reached the cap "
                 "%zu: the state this test needs is a full allocation", r.c->wcap,
                 CONN_WQ_MAX);

    /* One byte over is refused, and nothing is buffered. */
    TF_CHECK_MSG(conn_queue(r.c, "x", 1) != 0,
                 "an append one byte over the cap was accepted");
    TF_CHECK_MSG(conn_write_pending(r.c) == CONN_WQ_MAX,
                 "a refused append buffered something: %zu bytes pending",
                 conn_write_pending(r.c));

    /* Drain a little: the tail is now below the cap, the allocation is still
     * at it. */
    TF_CHECK_MSG(conn_pump(r.c) == 0, "conn_pump failed");
    TF_CHECK_MSG(conn_write_pending(r.c) < CONN_WQ_MAX,
                 "the pump did not drain anything, so the state this test needs "
                 "was not reached");
    TF_CHECK_MSG(r.c->woff > 0 && r.c->woff < CONN_WQ_COMPACT,
                 "woff is %zu after one pump: the state this test needs is a "
                 "small non-zero sent head, and without it the growth path "
                 "taken is the ordinary one", r.c->woff);

    /* The cap is on the UNSENT tail, so exactly the remaining headroom is a
     * legal append -- and it is the one case where the allocation is at the cap
     * and cannot simply grow. It has to compact instead. */
    headroom = CONN_WQ_MAX - conn_write_pending(r.c);
    TF_CHECK_MSG(headroom > 0, "no headroom left after the drain");
    TF_CHECK_MSG(conn_queue(r.c, bulk, headroom) == 0,
                 "an append of exactly the %zu bytes of headroom the cap allows "
                 "was refused: the allocation is already at the cap, so this "
                 "succeeds only if the sent head is reclaimed first", headroom);
    TF_CHECK_MSG(conn_write_pending(r.c) == CONN_WQ_MAX,
                 "the queue holds %zu bytes, expected %zu after filling the "
                 "headroom", conn_write_pending(r.c), CONN_WQ_MAX);
    TF_CHECK_MSG(conn_queue(r.c, "x", 1) != 0,
                 "an append past the cap was accepted");
    TF_CHECK_MSG(r.c->wcap == CONN_WQ_MAX,
                 "the allocation grew to %zu, past the cap: compacting must "
                 "reclaim space, not raise the limit", r.c->wcap);

    rig_close(&r);
    free(bulk);
}

int main(void)
{
    test_simple_line();
    test_partial_line();
    test_two_lines_one_read();
    test_bare_lf();
    test_cap_boundary();
    test_eof_and_pump();
    test_queue_compaction();
    tf_done("framing");
    return 0;
}
