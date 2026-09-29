/* connection.c -- conn_t buffers and RFC 1459 2.3 line framing (3.3). */
#include "core/connection.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

/* Grow `*buf` to at least `need` bytes, doubling from the current capacity and
 * clamping to `limit` so a capped buffer cannot be grown past its bound. Sets
 * *cap to the new capacity. Returns 0 on success, -1 if the request is
 * impossible or the allocation fails (leaving the old buffer intact, so a
 * caller that fails here still has a usable conn). */
static int buf_grow(char **buf, size_t *cap, size_t need, size_t limit)
{
    size_t want = (*cap == 0) ? 512u : *cap;
    char *next;

    if (need > limit) {
        return -1;
    }
    while (want < need) {
        if (want > limit / 2u) {
            want = limit;
            break;
        }
        want *= 2u;
    }

    next = (char *)realloc(*buf, want);
    if (next == NULL) {
        return -1;
    }
    *buf = next;
    *cap = want;
    return 0;
}

conn_t *conn_new(int fd, int kind)
{
    conn_t *c = (conn_t *)calloc(1, sizeof *c);

    if (c == NULL) {
        return NULL;
    }
    c->fd = fd;
    c->kind = kind;
    c->state = CONN_REG_PASS;
    /* The two 317 RPL_WHOISIDLE timestamps, stamped where the connection comes
     * into existence rather than where they are asked for. signon_at is the
     * answer to "when did this user connect", which is a fact about accept and
     * is therefore true from this instant; last_active starts equal to it so an
     * idle time measured before the client has said anything is zero rather
     * than whatever the epoch happened to be.
     *
     * This is a wall-clock read, which 3.4 otherwise forbids in handlers ("the
     * poll tick drives time"). The rule is about TIME-OUT logic -- handshake
     * deadlines, link liveness, LRU eviction -- which must be immune to a clock
     * jump. 317 is the opposite case: its <signon time> is a calendar time the
     * client is meant to compare against its own clock, so no monotonic
     * substitute would be the right value. It is read once per connection,
     * never per tick, and commands.c's 003 already established the precedent
     * and the reasoning for exactly one such read on the reply path. */
    c->signon_at = time(NULL);
    c->last_active = c->signon_at;
    return c;
}

void conn_free(conn_t *c)
{
    if (c == NULL) {
        return;
    }
    free(c->rbuf);
    free(c->wbuf);
    free(c->peer_name);
    /* The elements are owned by the channel registry (2.2: a chan_t outlives
     * any single member), so only the index array belongs to the conn. */
    free(c->chans);
    free(c);
}

int conn_fill(conn_t *c)
{
    for (;;) {
        ssize_t n;

        if (c->rlen == c->rcap) {
            if (c->rcap >= CONN_RBUF_MAX) {
                return 0; /* capped: framing decides whether this is legal */
            }
            if (buf_grow(&c->rbuf, &c->rcap, c->rlen + 1u, CONN_RBUF_MAX) != 0) {
                return -1;
            }
        }

        n = recv(c->fd, c->rbuf + c->rlen, c->rcap - c->rlen, 0);
        if (n > 0) {
            c->rlen += (size_t)n;
            /* Bytes arrived, so the connection is not idle. This is the only
             * place in the node that observes the connection DOING something,
             * which is what makes it the right place to stamp 317's <idle>
             * from: stamping it in a command handler would report a client as
             * idle while it was mid-burst, and stamping it nowhere would make
             * the number a constant. */
            c->last_active = time(NULL);
            continue;
        }
        if (n == 0) {
            return CONN_FILL_EOF; /* the peer closed its half */
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
}

int conn_next_line(conn_t *c, char *dst, size_t dstcap, size_t *len)
{
    const char *nl;
    size_t used;
    size_t rest;

    if (dst == NULL || len == NULL || dstcap == 0) {
        return -1;
    }
    nl = (const char *)memchr(c->rbuf, '\n', c->rlen);
    if (nl == NULL) {
        /* No terminator in hand. Once the buffer is at the line cap the line
         * can never become legal, so this is reported now rather than after
         * the peer stops sending. */
        return (c->rlen >= CONN_RBUF_MAX) ? -1 : 0;
    }

    used = (size_t)(nl - c->rbuf) + 1u; /* the LF, and the CR before it */
    rest = c->rlen - used;
    if (used > dstcap) {
        return -1;
    }

    /* Copy BEFORE compacting. The line is the front of the buffer and the
     * remainder has to slide down over it to reclaim the space, so the order
     * of these two operations is load-bearing. */
    memcpy(dst, c->rbuf, used);
    *len = used;

    if (rest > 0) {
        memmove(c->rbuf, c->rbuf + used, rest);
    }
    c->rlen = rest;
    return 1;
}

int conn_queue(conn_t *c, const char *data, size_t len)
{
    size_t pending = c->wlen - c->woff;

    if (len == 0) {
        return 0;
    }
    /* The cap is on the unsent tail, and it is checked BEFORE the buffer is
     * grown, so an over-cap append is refused without allocating anything. */
    if (len > CONN_WQ_MAX - pending) {
        return -1;
    }

    /* Reclaim the already-sent head before growing, so a connection that has
     * been writing for hours reuses one allocation instead of ratcheting.
     *
     * The third condition matters as much as the first two. The cap is on the
     * UNSENT tail, so an allocation that has ratcheted close to the cap can
     * refuse a legitimate append -- one that is well inside the bound -- simply
     * because growing to fit would exceed the allocation limit. When woff is
     * small that leaves the caller with a refusal that means "no room" while
     * the counter says "over the cap", which is a lie the diagnostics cannot
     * tell apart. Compacting whenever the growth would not fit removes that.
     *
     * With woff == 0 the allocation is the tail, so the cap check above already
     * guarantees the growth fits and this cannot trigger. */
    if (c->woff > 0 && (c->woff == c->wlen || c->woff >= CONN_WQ_COMPACT ||
                        c->wlen + len > CONN_WQ_MAX)) {
        if (c->woff == c->wlen) {
            c->wlen = 0;
            c->woff = 0;
        } else {
            memmove(c->wbuf, c->wbuf + c->woff, c->wlen - c->woff);
            c->wlen -= c->woff;
            c->woff = 0;
        }
    }

    if (c->wlen + len > c->wcap) {
        if (buf_grow(&c->wbuf, &c->wcap, c->wlen + len, CONN_WQ_MAX) != 0) {
            return -1;
        }
    }
    memcpy(c->wbuf + c->wlen, data, len);
    c->wlen += len;
    return 0;
}

int conn_pump(conn_t *c)
{
    while (c->woff < c->wlen) {
        /* MSG_NOSIGNAL: a peer that has already gone away must surface as
         * EPIPE from send(), never as a process-killing SIGPIPE. */
        ssize_t n = send(c->fd, c->wbuf + c->woff, c->wlen - c->woff,
                         MSG_NOSIGNAL);
        if (n > 0) {
            c->woff += (size_t)n;
            continue;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break; /* partial write: the rest is drained on a later tick */
            }
        }
        return -1;
    }

    if (c->woff == c->wlen) {
        c->wlen = 0;
        c->woff = 0;
    }
    return 0;
}

size_t conn_write_pending(const conn_t *c)
{
    return c->wlen - c->woff;
}

void conn_mark_closing(conn_t *c)
{
    c->state = CONN_CLOSING;
}

size_t conn_hostmask(const conn_t *c, char *out, size_t cap)
{
    int n;

    if (c == NULL || out == NULL || cap == 0) {
        return 0;
    }
    /* snprintf rather than strcpy/strcat: a hostmask is three
     * client-influenced fields concatenated, and a client that filled nick, user
     * and host to their bounds would overflow a buffer sized for any two of
     * them. snprintf reports the truncation instead of causing it, and returning
     * 0 makes the caller treat the whole line as unrenderable -- 3.2's rule
     * about never delivering a silently shortened field, applied to the
     * prefix. */
    n = snprintf(out, cap, "%s!%s@%s", c->nick, c->user, c->host);
    if (n < 0 || (size_t)n >= cap) {
        out[0] = '\0';
        return 0;
    }
    return (size_t)n;
}
