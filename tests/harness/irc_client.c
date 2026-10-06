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

/* The pump hook: see irc_client.h for why a socket wait needs one. Installed by
 * node_fixture.c and NULL until something installs it, so a test that spawns no
 * children pays one predictable NULL branch per iteration and nothing else. */
static tc_pump_fn g_pump_hook = NULL;

void tc_set_pump_hook(tc_pump_fn fn)
{
    g_pump_hook = fn;
}

static void pump_hook(void)
{
    if (g_pump_hook != NULL) {
        g_pump_hook();
    }
}

/* PHASE 12: THE SAME HOOP, CALLABLE FROM OUTSIDE.
 *
 * tls_fixture.c's tf_tls_expect() has to run its OWN select() loop, because after a
 * TLS handshake the decrypted bytes are inside OpenSSL and reading the descriptor
 * would return the NEXT record rather than the one the test is waiting for. That
 * makes it a wait outside every loop in this file, and therefore a wait that does
 * not keep the parent reading -- which the block above this function's file header
 * says is not a tidiness matter: a child's stdout is a 64 KiB pipe, a child that
 * fills it blocks INSIDE its event loop, and then it serves nobody.
 *
 * So the hook is exported rather than re-implemented. The alternative -- each
 * fixture growing its own reference to node_fixture.c's internals -- is worse,
 * because the two would have to agree about it by convention rather than by
 * linkage. */
void tc_pump(void)
{
    pump_hook();
}

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
        /* The socket had nothing, but the wait is not over: the deadline may
         * have room left and the OTHER readers this test owns -- the child
         * nodes' stdout pipes -- may not. Calling the hook on the timeout branch
         * as well as the readable one is what keeps them drained for the whole
         * of a wait that spends most of its time with an idle socket, which is
         * the normal shape of a cross-node test waiting for a peer to catch up. */
        pump_hook();
        return 0;
    }

    pump_hook();
    n = recv(c->fd, chunk, sizeof chunk, 0);
    if (n == 0) {
        if (eof != NULL) {
            *eof = 1;
        }
        c->closed = 1;
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
        /* MSG_NOSIGNAL, and this is the harness's version of a rule the product
         * already keeps. transport.c sends with MSG_NOSIGNAL so that an EPIPE is
         * RETURNED and never becomes a process-killing SIGPIPE, and node_main.c
         * additionally disarms SIGPIPE in the shipped binary; a test that does
         * neither writes into a peer that has gone, gets SIGPIPE, and dies --
         * taking every assertion after this line with it and reporting nothing
         * about which write did it.
         *
         * That is not hypothetical here. A closed peer is an EXPECTED outcome in
         * this suite rather than a fault: test_tls's --tls-require case has a
         * node that refuses a connection at accept and closes a socket the client
         * has already written to and still writes to. Whether the client's write
         * lands before or after that close is a sub-millisecond race, which is
         * why this killed test_tls on a macOS Release runner and on no cell
         * anywhere else.
         *
         * WHY IT GOES ON THE SEND AND NOT ON THE PROCESS. `signal(SIGPIPE,
         * SIG_IGN)` also stops the death, and it was rejected deliberately: it is
         * permanent and process-wide, so it would disarm the signal for every
         * write in every test -- including the ones this harness does not own,
         * such as a test's own write(2) and OpenSSL's -- and it would convert a
         * loud, immediate, attributable crash into a silent continuation past a
         * broken assumption. MSG_NOSIGNAL suppresses the signal for THIS send(2)
         * and leaves the disposition alone, so a SIGPIPE raised by anything else
         * in a test still kills that test. Nothing is weakened: EPIPE still comes
         * back as a failed return and tc_send_raw() still returns -1. Cost is one
         * flag word per send. */
        ssize_t w = send(c->fd, bytes + off, n - off, MSG_NOSIGNAL);

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
            /* read_once() returns 0 both for "nothing yet" and for "the deadline
             * is already past", and those are not the same thing to a LOOP: the
             * second one never makes progress, so without this check the wait
             * spins at full CPU forever instead of timing out. A timeout that
             * hangs is the worst possible failure mode for a test suite -- the
             * test is not reported as failed, it is reported as a hung CI job
             * with no output. */
            if (now_ms() >= deadline) {
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

/* The body of tc_read_line(), factored out so the wait loop and the scan cannot
 * disagree about what "a complete line at a boundary matching `prefix`" means.
 * Returns 1 and fills the out-params on a match, 0 on "not yet".
 *
 * THE SCAN, and the two boundary conditions are the whole of it:
 *
 *   the line must be TERMINATED -- a run of bytes ending in CRLF -- because a
 *   prefix that has arrived so far is not a reply;
 *   and the prefix must START the line -- the character before it must be the
 *   start of the buffer or an LF -- because a reply that CONTAINS the text is not
 *   the reply.
 *
 * LF rather than CR is the byte tested for the boundary, and deliberately: the
 * stream is CRLF, so the LF of the previous line is the last byte before this
 * line begins, and testing for CR would accept a stream whose lines end in a bare
 * CR. */
static int line_payload(const test_client_t *c, size_t from, const char *prefix,
                        char *out, size_t cap, size_t *len)
{
    size_t plen;
    size_t at = from;

    if (c == NULL || c->buf == NULL || prefix == NULL || out == NULL ||
        cap == 0u) {
        return 0;
    }
    plen = strlen(prefix);
    if (plen >= cap) {
        return 0; /* the prefix alone cannot fit; the caller's buffer is too small */
    }
    /* THE SCAN NEVER STARTS MID-LINE, and that is what makes `from` usable: a caller
     * advancing by `len + 2` lands on the first byte after a CRLF, and a caller that
     * does not is asking for a match somewhere inside a line, which is the substring
     * hazard this function exists to remove. So an offset in the middle of a line is
     * advanced to the start of the NEXT one rather than silently accepted. */
    if (at < c->len && at > 0u && c->buf[at - 1u] != '\n') {
        const char *nl = strchr(c->buf + at, '\n');

        if (nl == NULL) {
            return 0;
        }
        at = (size_t)(nl - c->buf) + 1u;
    }
    while (at < c->len) {
        const char *line = c->buf + at;
        const char *crlf = strstr(line, "\r\n");
        size_t llen;

        if (crlf == NULL) {
            /* The last line in the buffer has no terminator yet. It is either the
             * line being waited for arriving in pieces, or a line the node has not
             * finished sending; either way it is not a match yet. */
            return 0;
        }
        llen = (size_t)(crlf - line);
        if (llen >= plen && strncmp(line, prefix, plen) == 0) {
            /* IT MUST FIT WHOLE, and refusing is the only honest answer. snprintf()
             * would truncate and report `*len` as the FULL length, so the caller
             * would be handed a length that does not describe the string it has --
             * which is precisely the bug this primitive exists to remove, in a new
             * place. A caller whose buffer is too small for a reply it has actually
             * received has a bug in the test, and it should hear about it here
             * rather than diagnose a miscount later. */
            if (llen + 1u > cap) {
                return -1;
            }
            memcpy(out, line, llen);
            out[llen] = '\0';
            if (len != NULL) {
                *len = llen;
            }
            return 1;
        }
        at += llen + 2u; /* past this line's CRLF */
    }
    return 0;
}

int tc_read_line_from(test_client_t *c, size_t from, const char *prefix, char *out,
                      size_t cap, size_t *len, int timeout_ms)
{
    uint64_t deadline;

    if (c == NULL || prefix == NULL || out == NULL || cap == 0u || c->fd < 0) {
        return -1;
    }
    deadline = now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        int eof = 0;
        int rc;
        int found = line_payload(c, from, prefix, out, cap, len);

        if (found > 0) {
            return 0;
        }
        if (found < 0) {
            fprintf(stderr, "tc_read_line: the line starting \"%s\" is longer than "
                            "the %zu-byte buffer this test gave it, so it is REFUSED "
                            "rather than truncated -- a truncated payload with a full "
                            "length beside it is the bug tc_read_line() exists to "
                            "remove\n",
                    prefix, cap);
            return -1;
        }
        rc = read_once(c, deadline, &eof);
        if (rc < 0) {
            break;
        }
        if (eof) {
            /* One last scan: a close can land in the same select() as the last
             * bytes, so what we wanted may be in hand and the socket already gone. */
            found = line_payload(c, from, prefix, out, cap, len);
            if (found != 0) {
                return (found > 0) ? 0 : -1;
            }
            break;
        }
        if (now_ms() >= deadline) {
            break;
        }
    }
    fprintf(stderr, "tc_read_line: TIMEOUT after %d ms waiting for a complete line "
                    "starting \"%s\"\n",
            timeout_ms, prefix);
    fprintf(stderr, "tc_read_line: received %zu bytes: \"", c->len);
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
    }
    fprintf(stderr, "\"\n");
    return -1;
}

int tc_read_line(test_client_t *c, const char *prefix, char *out, size_t cap,
                 size_t *len, int timeout_ms)
{
    return tc_read_line_from(c, 0u, prefix, out, cap, len, timeout_ms);
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
        /* Past the deadline, read_once() returns 0 without blocking. Without
         * this the loop never ends: a client whose close never arrives would
         * hang the suite instead of failing it. -2 distinguishes "timed out,
         * but the server had been talking" from "timed out in silence", which
         * is a useful distinction when a node dies mid-test. */
        if (now_ms() >= deadline) {
            return (c->len > 0) ? -2 : -1;
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
            /* Same reason as read_once(): the timeout branch is where a socket
             * wait spends most of its life, so it is where the other readers
             * have to be kept moving. */
            pump_hook();
            continue;
        }
        pump_hook();
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

/* Drain this client's socket until the deadline passes, waiting on the socket and
 * on the installed pump hook at the same time.
 *
 * This has been DECLARED in irc_client.h, with a full contract, since the pump
 * hook was added -- and had no definition. A caller does not link, which is the
 * worst kind of harness defect: the header says the capability exists, so a test
 * reads it, writes against it, and finds out at link time.
 *
 * It existed because "wait on this client until a deadline, while unrelated
 * readers keep moving" is the operation every deadline loop in this harness wants
 * and each one had grown its own version. test_topic_persist grew a local copy
 * rather than link against this.
 *
 * Returns 0 if nothing was read before the deadline, 1 if bytes were appended,
 * -1 on a hard error, and sets `*eof` when the peer closed. */
int tc_closed(const test_client_t *c)
{
    return (c != NULL) ? c->closed : 0;
}

/* See irc_client.h's block for why the other two read paths cannot serve a caller
 * that needs to keep the whole accumulated buffer AND must not block. The
 * implementation is `recv()` with MSG_DONTWAIT in a loop, appending through the same
 * `append()` every other read here uses -- so the buffer this grows is the one
 * `tc_buffer()` and `tc_received()` already describe, and no caller has to know that
 * a second path exists. */
int tc_read_available(test_client_t *c, int *eof)
{
    char chunk[16384];
    int total = 0;

    if (c == NULL || c->fd < 0) {
        return -1;
    }
    for (;;) {
        ssize_t n = recv(c->fd, chunk, sizeof chunk, MSG_DONTWAIT);

        if (n > 0) {
            if (append(c, chunk, (size_t)n) != 0) {
                return -1;
            }
            total += (int)n;
            continue;
        }
        if (n == 0) {
            if (eof != NULL) {
                *eof = 1;
            }
            c->closed = 1;
            return total;
        }
        if (errno == EINTR) {
            continue;
        }
        /* EAGAIN/EWOULDBLOCK is the ordinary answer: the kernel has nothing more.
         * Anything else is a real error and the caller is told so rather than being
         * handed a short count it would read as "nothing arrived". */
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return total;
        }
        return -1;
    }
}

int tc_drain(test_client_t *c, int timeout_ms, int *eof)
{
    uint64_t deadline;
    int got = 0;

    if (c == NULL) {
        return -1;
    }
    if (eof != NULL) {
        *eof = 0;
    }
    deadline = now_ms() + (uint64_t)timeout_ms;

    for (;;) {
        int e = 0;
        int rc;

        /* Consume what is already buffered before waiting: read_once() appends,
         * and a buffer that is never emptied grows without bound and makes the
         * next strstr() match something from an earlier exchange. */
        if (c->buf != NULL && c->len > 0) {
            memmove(c->buf, c->buf + c->len, c->cap - c->len);
            c->cap -= c->len;
            c->len = 0;
            got = 1;
        }

        rc = read_once(c, deadline, &e);
        if (rc < 0) {
            return got;
        }
        if (e) {
            if (eof != NULL) {
                *eof = 1;
            }
            return got;
        }
        if (rc > 0) {
            got = 1;
            continue;
        }
        /* Deadline reached: read_once() returns 0 with nothing read. */
        return got;
    }
}
