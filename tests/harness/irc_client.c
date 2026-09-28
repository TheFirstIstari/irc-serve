/* irc_client.c -- see irc_client.h. Wire-level only: no irc_core calls here, on
 * purpose, so the tests assert on the socket rather than on the server's
 * internals (6.1). */
#include "harness/irc_client.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* The polling interval inside every deadline loop. Short, so a response is
 * noticed promptly; it is NOT a claim about how long the server takes. */
#define TC_POLL_MS 20

/* Cap on the accumulated receive buffer. Generous enough for the largest thing
 * the tests read (a few hundred KB) and bounded so a runaway server cannot
 * exhaust the test process. */
#define TC_BUF_MAX (4u * 1024u * 1024u)

/* Connect itself must not hang if something is listening but never accepting;
 * this is far longer than a loopback handshake needs. */
#define TC_CONNECT_TIMEOUT_MS 10000

static uint64_t now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000L);
}

static int append(test_client_t *c, const char *bytes, size_t n)
{
    if (n == 0) {
        return 0;
    }
    if (c->len + n + 1u > c->cap) {
        size_t want = (c->cap == 0) ? 4096u : c->cap;
        char *grown;

        while (want < c->len + n + 1u) {
            want *= 2u;
        }
        if (want > TC_BUF_MAX) {
            return -1;
        }
        grown = (char *)realloc(c->buf, want);
        if (grown == NULL) {
            return -1;
        }
        c->buf = grown;
        c->cap = want;
    }
    memcpy(c->buf + c->len, bytes, n);
    c->len += n;
    c->buf[c->len] = '\0';
    return 0;
}

/* Read whatever is readable, up to the deadline. Returns 1 if bytes were
 * appended, 0 if the deadline passed with nothing, and -1 on a hard error.
 * `eof` is set when the peer closed. */
static int read_once(test_client_t *c, uint64_t deadline, int *eof)
{
    char chunk[16384];
    struct timeval tv;
    fd_set rfds;
    ssize_t n;
    uint64_t left;
    int rc;

    if (eof != NULL) {
        *eof = 0;
    }
    left = (deadline > now_ms()) ? (deadline - now_ms()) : 0;
    if (left == 0) {
        return 0;
    }

    FD_ZERO(&rfds);
    FD_SET(c->fd, &rfds);
    tv.tv_sec = (time_t)(left / 1000u);
    tv.tv_usec = (suseconds_t)((left % 1000u) * 1000u);

    rc = select(c->fd + 1, &rfds, NULL, NULL, &tv);
    if (rc < 0) {
        return (errno == EINTR) ? 0 : -1;
    }
    if (rc == 0) {
        return 0;
    }

    n = recv(c->fd, chunk, sizeof chunk, 0);
    if (n == 0) {
        if (eof != NULL) {
            *eof = 1;
        }
        return 0;
    }
    if (n < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
    return (append(c, chunk, (size_t)n) == 0) ? 1 : -1;
}

void tc_init(test_client_t *c)
{
    memset(c, 0, sizeof *c);
    c->fd = -1;
}

int tc_connect_rcvbuf(test_client_t *c, int port, int rcvbuf)
{
    struct sockaddr_in addr;
    struct timeval tv;
    int fd;

    if (c == NULL || port <= 0 || port > 65535) {
        return -1;
    }
    /* Zero the client here rather than relying on the caller having called
     * tc_init(). An uninitialised receive buffer and its length are what a
     * caller gets by accident, and a realloc against garbage corrupts the heap
     * several calls later -- far from the line that caused it. Connecting is a
     * constructor, so it constructs. */
    tc_init(c);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (rcvbuf > 0) {
        /* Before connect: the receive window is advertised during the
         * handshake, so setting it afterwards would have no effect on how much
         * the peer may push at us. */
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf) != 0) {
            close(fd);
            return -1;
        }
    }
    tv.tv_sec = TC_CONNECT_TIMEOUT_MS / 1000;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(fd);
        return -1;
    }
    c->fd = fd;

    /* Read SO_RCVBUF back, and report nothing about the value. On macOS the
     * kernel re-autotunes the receive buffer after the handshake and reports a
     * figure far above what was requested, so the number is not a bound; on
     * Linux a request of N reads back as roughly 2N, so it is not even the
     * number that was asked for. Asserting on it either way makes a test
     * platform-specific -- which is how test_partial_write failed on Linux
     * before it stopped doing so. A test that needs a peer's send() to come up
     * short must make that unavoidable rather than predict it; see the
     * dispatch in test_partial_write.c. */
    if (rcvbuf > 0) {
        int got = 0;
        socklen_t len = sizeof got;

        (void)getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &got, &len);
    }
    return 0;
}

int tc_connect(test_client_t *c, int port)
{
    return tc_connect_rcvbuf(c, port, 0);
}

int tc_send_raw(test_client_t *c, const char *bytes, size_t n)
{
    size_t off = 0;

    if (c == NULL || c->fd < 0 || bytes == NULL) {
        return -1;
    }
    while (off < n) {
        ssize_t w = send(c->fd, bytes + off, n - off, 0);

        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        if (w < 0 && (errno == EINTR || errno == EAGAIN ||
                      errno == EWOULDBLOCK)) {
            struct timeval tv = { 0, 20000 };
            /* Not a fixed sleep: a short wait between retries of the SAME
             * write, so a test never silently drops input it meant to send. */
            (void)select(0, NULL, NULL, NULL, &tv);
            continue;
        }
        return -1;
    }
    return 0;
}

int tc_send(test_client_t *c, const char *line)
{
    char *framed;
    size_t n;
    int rc;

    if (c == NULL || line == NULL) {
        return -1;
    }
    n = strlen(line);
    framed = (char *)malloc(n + 3u);
    if (framed == NULL) {
        return -1;
    }
    memcpy(framed, line, n);
    framed[n] = '\r';
    framed[n + 1u] = '\n';
    framed[n + 2u] = '\0';
    rc = tc_send_raw(c, framed, n + 2u);
    free(framed);
    return rc;
}

int tc_expect(test_client_t *c, const char *needle, int timeout_ms)
{
    uint64_t deadline;

    if (c == NULL || needle == NULL || c->fd < 0) {
        return -1;
    }
    deadline = now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        if (c->buf != NULL && strstr(c->buf, needle) != NULL) {
            return 0;
        }
        {
            int eof = 0;
            int rc = read_once(c, deadline, &eof);

            if (rc < 0) {
                break;
            }
            if (eof) {
                /* A close ends the wait: nothing more can arrive, and looping
                 * to the deadline would only make the failure slower. */
                if (c->buf != NULL && strstr(c->buf, needle) != NULL) {
                    return 0;
                }
                break;
            }
        }
    }
    fprintf(stderr, "tc_expect: TIMEOUT after %d ms waiting for \"%s\"\n",
            timeout_ms, needle);
    fprintf(stderr, "tc_expect: received %zu bytes: \"", c->len);
    {
        size_t i;
        size_t show = (c->len < 512u) ? c->len : 512u;

        for (i = 0; i < show; i++) {
            unsigned char ch = (unsigned char)c->buf[i];

            if (ch == '\r') {
                fputs("\\r", stderr);
            } else if (ch == '\n') {
                fputs("\\n", stderr);
            } else if (ch < 0x20u || ch > 0x7eu) {
                fprintf(stderr, "\\x%02x", ch);
            } else {
                fputc((int)ch, stderr);
            }
        }
        if (show < c->len) {
            fputs("...", stderr);
        }
    }
    fprintf(stderr, "\"\n");
    return -1;
}

/* Wait for the server to close its half. Returns 0 when a clean EOF was
 * observed (recv() returned 0), -1 on timeout, -2 on a timeout where data had
 * arrived but the close never did, and -3 if the connection was reset.
 *
 * EOF and ECONNRESET are different outcomes and the difference is the point: a
 * clean close is a FIN, while a reset is the kernel discarding an unread queue.
 * A test asserting "closed cleanly" must not accept both.
 *
 * Data on the way to an EOF is not a failure: a test that expects both a
 * response and a close reads the response with tc_expect() first, and the
 * response bytes stay in the buffer either way. */
int tc_expect_eof(test_client_t *c, int timeout_ms)
{
    uint64_t deadline;

    if (c == NULL || c->fd < 0) {
        return -1;
    }
    deadline = now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        int eof = 0;
        int rc = read_once(c, deadline, &eof);

        if (rc < 0) {
            if (errno == ECONNRESET) {
                return -3;
            }
            return -1;
        }
        if (eof) {
            return 0;
        }
    }
}

int tc_read_exact(test_client_t *c, char *dst, size_t n, int timeout_ms)
{
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    size_t off = 0;

    if (c == NULL || c->fd < 0 || dst == NULL) {
        return -1;
    }
    while (off < n) {
        char chunk[65536];
        size_t want = n - off;
        struct timeval tv;
        fd_set rfds;
        uint64_t left;
        ssize_t got;
        int rc;

        if (want > sizeof chunk) {
            want = sizeof chunk;
        }
        left = (deadline > now_ms()) ? (deadline - now_ms()) : 0;
        if (left == 0) {
            fprintf(stderr, "tc_read_exact: TIMEOUT after %d ms with %zu of %zu "
                    "bytes read\n", timeout_ms, off, n);
            return -1;
        }
        FD_ZERO(&rfds);
        FD_SET(c->fd, &rfds);
        tv.tv_sec = (time_t)(left / 1000u);
        tv.tv_usec = (suseconds_t)((left % 1000u) * 1000u);
        rc = select(c->fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (rc == 0) {
            continue;
        }
        got = recv(c->fd, chunk, want, 0);
        if (got == 0) {
            fprintf(stderr, "tc_read_exact: EOF with %zu of %zu bytes read\n",
                    off, n);
            return -1;
        }
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        memcpy(dst + off, chunk, (size_t)got);
        off += (size_t)got;
        /* Also accumulate, so a failure diagnostic can show what came. */
        if (append(c, chunk, (size_t)got) != 0) {
            return -1;
        }
    }
    return 0;
}

int tc_half_close(test_client_t *c)
{
    if (c == NULL || c->fd < 0) {
        return -1;
    }
    return shutdown(c->fd, SHUT_WR);
}

const char *tc_buffer(const test_client_t *c)
{
    return (c != NULL && c->buf != NULL) ? c->buf : "";
}

size_t tc_received(const test_client_t *c)
{
    return (c != NULL) ? c->len : 0u;
}

void tc_close(test_client_t *c)
{
    if (c == NULL) {
        return;
    }
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    free(c->buf);
    c->buf = NULL;
    c->len = 0;
    c->cap = 0;
}
