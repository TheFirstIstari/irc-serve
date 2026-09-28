/* poll_loop.c -- poll() dispatch, EINTR-safe, 50 ms tick.
 *
 * Authority: docs/SERVER_DESIGN.md 3.3 (the message path) and 3.4 (the event
 * loop and everything it forces). The order of the steps below is the contract,
 * and it is not arbitrary:
 *
 *   1. build the poll sets          (listener, connections, in-flight dials)
 *   2. poll()                       EINTR is counted and retried, never fatal
 *   3. accept                       nonblocking, drained
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
        printf("[observable] conn_close: fd=%d reason=eof\n", c->fd);
        conn_mark_closing(c);
        return;
    }
    if (rc < 0) {
        printf("[observable] conn_close: fd=%d reason=read_error errno=%d\n",
               c->fd, errno);
        conn_mark_closing(c);
        return;
    }
    conn_readable(s, c);
}

/* One connection's worth of write work. A short write is expected and is not
 * an error: the retained woff keeps the remainder queued for a later
 * iteration, and the counter below is what makes "the queue really did
 * short-write" an observable fact rather than an assumption. */
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
    size_t i;
    int n;

    if (s == NULL || s->by_fd == NULL) {
        return -1;
    }

    /* --- 1. build the sets --- */
    if (s->listen_fd >= 0) {
        pfds[nfds].fd = s->listen_fd;
        pfds[nfds].events = POLLIN;
        pfds[nfds].revents = 0;
        nfds++;
    }
    for (i = 0; i < SERVER_FD_TABLE && nfds < POLL_MAX_FDS; i++) {
        conn_t *c = s->by_fd[i];

        if (c == NULL || c->state == CONN_CLOSING) {
            continue; /* a CLOSING conn is already out of the set */
        }
        pfds[nfds].fd = c->fd;
        pfds[nfds].events = POLLIN;
        if (conn_write_pending(c) > 0) {
            pfds[nfds].events |= POLLOUT;
        }
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
        /* --- 3. accept --- */
        if (s->listen_fd >= 0 && pfds[0].fd == s->listen_fd &&
            (pfds[0].revents & POLLIN) != 0) {
            /* Drain the listener rather than taking one connection per tick: a
             * listener that stays readable with a full backlog would otherwise
             * be re-polled with the queue still full. The fd >= FD_SETSIZE
             * rejection is -2, and it is NOT a reason to stop draining -- the
             * rest of the queue is perfectly good. */
            for (;;) {
                int rc = server_accept_one(s);

                if (rc == 0) {
                    break; /* nothing pending */
                }
                if (rc < 0 && rc != SERVER_ACCEPT_REJECTED) {
                    break; /* fatal accept error; the next tick retries */
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
