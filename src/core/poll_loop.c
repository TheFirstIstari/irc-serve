/* poll_loop.c -- poll() dispatch, EINTR-safe, 50 ms tick.
 *
 * Authority: docs/SERVER_DESIGN.md 3.3 (the message path) and 3.4 (the event
 * loop and everything it forces). The order of the steps below is the contract,
 * and it is not arbitrary:
 *
 *   1. build the poll sets          (listeners, connections, in-flight dials)
 *   2. poll()                       EINTR is counted and retried, never fatal
 *   3. accept                       nonblocking, drained, both listeners
 *   4. read + frame + parse + dispatch
 *   5. write                        drain the retained write-queue offsets
 *   6. dial progress                nonblocking connect() completion
 *   7. REAP                         the only step that closes an fd
 *   8. tick                         the only clock the node has
 *
 * Step 7 is a separate, fixed point on purpose. Nothing above it closes a
 * connection: a read error, a write error, an over-cap write queue and a
 * client hangup all merely mark the connection CLOSING. That is 3.4's "the
 * send path never closes a connection", and it is what keeps the close count
 * equal to the number of connections that were ever registered.
 */
#include "core/poll_loop.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>

#include "core/connection.h"
#include "core/message.h"

/* Upper bound on descriptors in one poll() set. By construction this is
 * enough: the listener plus every registered connection plus in-flight dials
 * are all < FD_SETSIZE, because every accept and dial site rejects anything
 * larger. The +2 is headroom for the listener and the dial entries, which are
 * not connections. */
#define POLL_MAX_FDS (FD_SETSIZE + 2)

/* The stop latch. sig_atomic_t because it is written from a signal handler
 * while the loop reads it; volatile so the read is not cached across poll(). */
static volatile sig_atomic_t g_stop = 0;

void poll_loop_request_stop(void)
{
    g_stop = 1;
}

int poll_loop_stopped(void)
{
    return (int)g_stop;
}

void poll_loop_clear_stop(void)
{
    g_stop = 0;
}

/* The readable half of the message path (3.3):
 *
 *   socket read --> framing --> message_parse --> dispatch(cmd_t)
 *
 * Every failure here marks the connection CLOSING and returns; none of them
 * closes the fd. The reaper does that at the end of the iteration.
 *
 * `line` is this frame's scratch, one line at a time. It belongs to the frame
 * rather than to the conn_t so that conn_t keeps the shape 3.3 specifies, and
 * it is large enough for any legal line because the framing layer refuses
 * anything longer. */
static void conn_readable(server_t *s, conn_t *c)
{
    char line[IRC_MAX_LINE];

    for (;;) {
        message_t m;
        size_t len = 0;
        int got;

        got = conn_next_line(c, line, sizeof line, &len);
        if (got == 0) {
            return; /* need more bytes */
        }
        if (got < 0) {
            s->n_frame_error++;
            printf("[observable] frame_error: fd=%d reason=unterminated_line\n",
                   c->fd);
            conn_mark_closing(c);
            return;
        }

        /* message_parse_n(), not message_parse(): the framing layer holds a
         * length, and only the counted entry point rejects an embedded NUL,
         * which is a stated hard requirement of 3.2. */
        if (message_parse_n(line, len, &m) != 0) {
            s->n_parse_reject++;
            message_free(&m); /* rejection leaves it zeroed; free is a no-op */
            continue;
        }

        s->n_lines++;
        if (s->trace) {
            printf("[observable] line: fd=%d len=%zu command=%s\n",
                   c->fd, len, m.command);
        }
        /* NULL dispatch is the honest Phase 2 state: the loop still accepts,
         * frames and parses, it simply has no command surface to answer with
         * yet. Phase 3 supplies one. */
        if (s->dispatch != NULL) {
            s->dispatch(s, c, &m);
        }
        message_free(&m);
    }
}

/* One connection's worth of read work, after poll() said there is something. */
static void conn_on_readable(server_t *s, int fd)
{
    conn_t *c = server_conn(s, fd);
    int rc;

    if (c == NULL || c->state == CONN_CLOSING) {
        return;
    }
    rc = conn_fill(c);
    if (rc == CONN_FILL_EOF) {
        /* ------------------------------------------------------------------------
         * FRAME WHAT conn_fill() ALREADY BUFFERED, BEFORE HONOURING THE EOF, and
         * the reason is that the alternative throws away a line the peer really
         * did send.
         *
         * conn_fill() LOOPS: it recv()s, appends, and goes round again until
         * recv() answers EAGAIN or 0. So a peer that writes its last line and then
         * closes -- or half-closes -- in the same breath gets ONE conn_fill() call
         * that buffers the line AND reports EOF, and an EOF arm that returns
         * without framing discards it. The bytes sit in c->rbuf, were never turned
         * into a line, and are freed with the conn. The node's own counters say so
         * exactly: n_lines does not move, and both parse_reject and frame_error are
         * 0 -- it never became a line.
         *
         * THAT IS NOT A CORNER CASE FOR A GOODBYE. A graceful leave IS "send the
         * line, then go" (link.h's fed_send_shutdown() paragraph), so the one
         * sequence Phase 9's departure verb exists for is the one this ordering ate.
         * A node that announced its departure and closed would have every peer treat
         * the departure as a crash, which is the exact cost fed_send_shutdown() is
         * written to avoid.
         *
         * WHAT IT IS NOT: a "drain on close" that keeps reading. There is nothing
         * more to read -- EOF means the peer closed its half -- so this frames what
         * is IN HAND and nothing else. A trailing fragment with no terminator still
         * dies here: conn_next_line() reports "need more bytes" for it, this loop
         * ends, and the reaper frees the buffer. That is correct, because an
         * unterminated final fragment was never a line under 3.3 and a peer that
         * meant to send one did not send it.
         *
         * ORDERING, and it is the whole of the fix: frame and dispatch FIRST, then
         * print the close and mark CLOSING. Doing it the other way round would
         * dispatch into a connection the reaper is entitled to collect on this same
         * iteration. And the close line is printed AFTER the dispatch, so a reader
         * of the log sees the peer's last words before the news that they were the
         * last words.
         *
         * COST, and it is one pointer comparison on a path that only runs when the
         * buffer is non-empty: on the EOF path with nothing buffered this is
         * identical to what it was, so a peer that closes with an empty buffer pays
         * nothing and the ordinary case is unchanged.
         *
         * It also makes fed_in_shutdown()'s own socket close REACHABLE FROM THE
         * WIRE, which is what the header's third requirement needs: before this,
         * a peer that announced and closed was indistinguishable from one that
         * closed without announcing, because the announcement never arrived.
         *
         * Recorded because it is a CHANGE to a 3.4 path rather than a Phase 9
         * addition, and a reader diffing this function against a description of the
         * loop should be able to see that it happened here and why.
         * ------------------------------------------------------------------------ */
        if (c->rlen > 0u) {
            conn_readable(s, c);
        }
        printf("[observable] conn_close: fd=%d reason=eof\n", c->fd);
        conn_mark_closing(c);
        return;
    }
    if (rc < 0) {
        /* SAME REASON AS THE EOF ARM ABOVE, AND IT MATTERS MORE. A read ERROR is
         * what a peer that closed with data still unread in its receive queue
         * produces: the kernel answers close() with RST rather than FIN, and RST is
         * reported here as ECONNRESET. So this arm is not an exotic failure -- it is
         * the ordinary way a peer link ends when the peer's shutdown found a line
         * from us still sitting unread on its side.
         *
         * WHICH MEANS IT IS THE SAME LINE GETTING EATEN. A graceful leave is "send
         * the line, then go" (link.h's fed_send_shutdown()), so if the departure
         * arrives followed by an RST -- which it does whenever the departing node's
         * last inbound line had not been read when it closed -- the departure is in
         * c->rbuf, was never framed, and is freed with the conn. The peer then
         * declares the link dead, arms the whole retry ladder against a peer that
         * said goodbye, and the cost fed_send_shutdown() exists to avoid is paid in
         * full. The node's counters say exactly what happened: n_lines does not move
         * and frame_error stays 0 -- it never became a line.
         *
         * This was measured rather than assumed: with a peer sending keepalives every
         * 60 ms and a departing node closing immediately, this arm was reached in
         * roughly one run in twenty-five of the test that found it, and
         * `conn_close: reason=read_error errno=54` on the receiver is the signature.
         *
         * WHAT IT IS NOT: a retry loop, and not a "read until it works". A read error
         * is the end of the connection as far as this node is concerned -- the data
         * that survives is whatever conn_fill() already appended, exactly as in the
         * EOF arm, and there is no attempt to read again from a descriptor whose peer
         * has gone. A trailing fragment with no terminator still dies here, for the
         * same reason it does above: it was never a line under 3.3.
         *
         * ORDERING is as above: frame and dispatch FIRST, then report and mark
         * CLOSING. Dispatching into a connection the reaper may collect on this same
         * iteration is the thing to avoid, and the reaper runs at step 7 -- after all
         * of this.
         *
         * COST: one pointer comparison when nothing is buffered, which is the
         * overwhelming majority of times this arm is reached, and a fragment and
         * dispatch of whatever is in hand when something is. */
        if (c->rlen > 0u) {
            conn_readable(s, c);
        }
        printf("[observable] conn_close: fd=%d reason=read_error errno=%d\n", c->fd,
               errno);
        conn_mark_closing(c);
        return;
    }
    conn_readable(s, c);
}

/* One connection's worth of write work. A short write is expected and is not
 * an error: the retained woff keeps the remainder queued for a later
 * iteration, and the counter below is what makes "the queue really did
 * short-write" an observable fact rather than an assumption.
 *
 * PHASE 12: THIS IS NOW REACHED BY POLLOUT FOR A CONNECTION WITH NOTHING TO
 * SEND, and that is the point of the readiness intent. A TLS handshake that has
 * been told it wants writability gets here, conn_pump() makes its one
 * unconditional empty pass over the transport, and the handshake moves. Before
 * Phase 12 the loop only asked for POLLOUT when there were bytes to write, so
 * there was no such thing as "reachable with an empty queue" and no need for
 * conn_pump() to do anything about it. The partial-write counter below is
 * guarded by `before > 0` and so cannot be moved by that pass. */
static void conn_on_writable(server_t *s, int fd)
{
    conn_t *c = server_conn(s, fd);
    size_t before;

    if (c == NULL || c->state == CONN_CLOSING) {
        return;
    }
    before = conn_write_pending(c);
    if (conn_pump(c) < 0) {
        s->n_write_error++;
        printf("[observable] conn_close: fd=%d reason=write_error\n", c->fd);
        conn_mark_closing(c);
        return;
    }
    if (before > 0 && conn_write_pending(c) > 0) {
        s->n_partial_writes++;
    }
}

int poll_loop_step(server_t *s, int timeout_ms)
{
    struct pollfd pfds[POLL_MAX_FDS];
    nfds_t conn_pfd[POLL_MAX_FDS];
    size_t nconn_pfd = 0;
    nfds_t nfds = 0;
    nfds_t dial_nfds = 0;
    nfds_t tls_listen_pfd = 0;
    size_t i;
    int n;

    if (s == NULL || s->by_fd == NULL) {
        return -1;
    }

    /* --- 1. build the sets --- */
    /* TWO LISTENERS, OR ONE. The plaintext listener is slot 0 and is ALWAYS slot
     * 0 when present, because step 3's accept arm tests `pfds[0].fd ==
     * s->listen_fd`. The implicit-TLS listener (Phase 12) is appended after the
     * listener and BEFORE the connections, so a connection's index does not shift
     * when an operator adds --tls-port -- conn_pfd[] records indices, and a set
     * whose meaning changed when an unrelated option appeared would be a very hard
     * bug to find.
     *
     * The TLS listener's INDEX is recorded in tls_listen_pfd rather than assumed,
     * because it depends on whether the plaintext listener was there: with both,
     * the TLS one is slot 1; with only --tls-port and no --port (which the parser
     * allows -- the port argument has a default), it is slot 0. Assuming an index
     * is how a two-listener loop ends up polling the wrong descriptor for the
     * accept, and the symptom would be a node that serves TLS on one port and
     * nothing on the other. */
    if (s->listen_fd >= 0) {
        pfds[nfds].fd = s->listen_fd;
        pfds[nfds].events = POLLIN;
        pfds[nfds].revents = 0;
        nfds++;
    }
    if (s->tls_listen_fd >= 0) {
        pfds[nfds].fd = s->tls_listen_fd;
        pfds[nfds].events = POLLIN;
        pfds[nfds].revents = 0;
        tls_listen_pfd = nfds;
        nfds++;
    }
    for (i = 0; i < SERVER_FD_TABLE && nfds < POLL_MAX_FDS; i++) {
        conn_t *c = s->by_fd[i];
        short events = 0;

        if (c == NULL || c->state == CONN_CLOSING) {
            continue; /* a CLOSING conn is already out of the set */
        }
        /* PHASE 12: THE POLL SET IS NOW THE CONNECTION'S OWN INTENT, and this is
         * the single line the whole phase's structural change amounts to.
         *
         * It used to be derived from data -- POLLIN always, POLLOUT when there
         * were unsent bytes -- and for a plaintext socket those two facts are the
         * same fact, so the derivation was free. It stops being free the moment a
         * transport can be waiting to WRITE with nothing to send, which is what a
         * TLS handshake is: the server flight goes out before this node has an
         * application byte, and then the handshake parks waiting for a write the
         * loop is not asking for. There is no way to recover that information
         * from poll()'s REPORTS -- an empty socket reports nothing, so the loop
         * would sleep through the event entirely -- and the only place the
         * information exists is inside OpenSSL. So the transport publishes it and
         * the loop reads it. See conn_t::want_read for the full argument.
         *
         * FOR A PLAINTEXT CONNECTION THIS IS BYTE-IDENTICAL, and the reason is
         * that plain_recv() and plain_send() publish want_read = 1 on every path
         * and want_write = (unsent bytes), while conn_queue() raises want_write
         * the moment the queue grows. The mask below therefore equals the old
         * derivation at every point the loop can observe one.
         *
         * A CONNECTION THAT WANTS NEITHER IS LEFT OUT OF THE SET ENTIRELY rather
         * than added with a zero mask: poll() would never report it, so including
         * it would only spend a slot in POLL_MAX_FDS and make the cost of a node
         * with many parked TLS handshakes proportional to a number it does not
         * need to be. */
        if (c->want_read) {
            events |= POLLIN;
        }
        if (c->want_write) {
            events |= POLLOUT;
        }
        if (events == 0) {
            continue;
        }
        pfds[nfds].fd = c->fd;
        pfds[nfds].events = events;
        pfds[nfds].revents = 0;
        conn_pfd[nconn_pfd++] = nfds;
        nfds++;
    }
    if (server_dial_collect(s, pfds + nfds, (size_t)(POLL_MAX_FDS - nfds),
                            &dial_nfds) != 0) {
        return -1;
    }
    nfds += dial_nfds;

    /* --- 2. wait --- */
    n = poll(pfds, nfds, timeout_ms);
    if (n < 0) {
        if (errno == EINTR) {
            /* 3.4: a signal during the wait must not kill the loop. Counted so
             * a test can prove the path was taken, and reported to the caller
             * as an ordinary outcome -- the next step re-arms poll(). */
            s->n_eintr++;
            if (s->trace) {
                printf("[observable] eintr: count=%llu state=SURVIVED\n",
                       (unsigned long long)s->n_eintr);
            }
            return 1;
        }
        return -1;
    }

    if (n > 0) {
        /* --- 3. accept, on BOTH listeners ---
         *
         * The plain listener is index 0 when it exists, so the two arms below are
         * independent tests rather than a loop over listener indices -- and each
         * one drains fully, which is the property server_accept_one()'s comment
         * gives: a listener that stays readable with a full backlog would
         * otherwise be re-polled with the queue still full. The fd >= FD_SETSIZE
         * rejection is -2, and it is NOT a reason to stop draining -- the rest of
         * the queue is perfectly good. */
        if (s->listen_fd >= 0 && pfds[0].fd == s->listen_fd &&
            (pfds[0].revents & POLLIN) != 0) {
            for (;;) {
                int rc = server_accept_one(s);

                if (rc == 0) {
                    break;
                }
                if (rc < 0 && rc != SERVER_ACCEPT_REJECTED) {
                    break; /* fatal accept error; the next tick retries */
                }
            }
        }
        if (s->tls_listen_fd >= 0 &&
            (pfds[tls_listen_pfd].revents & POLLIN) != 0) {
            for (;;) {
                int rc = server_accept_tls_one(s);

                if (rc == 0) {
                    break;
                }
                if (rc < 0 && rc != SERVER_ACCEPT_REJECTED) {
                    break;
                }
            }
        }

        /* --- 4/5. read and write --- */
        for (i = 0; i < nconn_pfd; i++) {
            short re = pfds[conn_pfd[i]].revents;
            int fd = pfds[conn_pfd[i]].fd;

            if ((re & POLLOUT) != 0) {
                conn_on_writable(s, fd);
            }
            /* Re-looked-up after the write: the pump may have marked this
             * connection CLOSING on a fatal error, and a connection that is
             * on its way out has nothing left worth reading. A connection
             * accepted in step 3 is not in this set at all, so it is not
             * processed here -- it gets its own iteration. */
            if ((re & POLLIN) != 0) {
                conn_t *c = server_conn(s, fd);

                if (c != NULL && c->state != CONN_CLOSING) {
                    conn_on_readable(s, fd);
                }
            }
        }

        /* --- 6. dial progress --- */
        if (dial_nfds > 0 &&
            server_dial_progress(s, pfds + (nfds - dial_nfds), dial_nfds) != 0) {
            return -1;
        }
    }

    /* --- 7. reap: the only place an fd is closed --- */
    (void)server_reap(s);

    /* --- 8. tick: the only place time advances --- */
    server_tick(s, server_now_ms());
    return 0;
}

int poll_loop_run(server_t *s)
{
    if (s == NULL) {
        return -1;
    }
    while (!poll_loop_stopped()) {
        if (poll_loop_step(s, POLL_TICK_MS) < 0) {
            return -1;
        }
    }
    return 0;
}
