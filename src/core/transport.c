/* transport.c -- the transport interface's plumbing, and the PLAINTEXT
 * implementation of it.
 *
 * This file is compiled in EVERY configuration, including a build with no TLS at
 * all (`-DWITH_TLS=OFF`, which is the default). That is deliberate and it is the
 * shape of the whole dependency decision: the plaintext path is not "TLS with
 * the crypto stubbed out", it is a first-class implementation of the interface
 * that happens to be the one this project shipped for eleven phases, and the
 * zero-dependency build is the one CI compiles on every runner.
 *
 * ---------------------------------------------------------------------------
 * THE PROOF THAT PLAINTEXT IS BYTE-IDENTICAL, stated here because the interface
 * is only worth having if this is checkable
 * ---------------------------------------------------------------------------
 * The pre-Phase-12 loop built a connection's poll mask as
 *
 *     events = POLLIN;
 *     if (conn_write_pending(c) > 0) { events |= POLLOUT; }
 *
 * and the write path was `send(fd, buf, len, MSG_NOSIGNAL)` in a loop that
 * retried on EINTR and stopped on EAGAIN. The plaintext ops below reproduce
 * both, and the reproduction is checkable rather than asserted:
 *
 *   POLLIN   plain_recv() publishes want_read = 1 on EVERY return path without
 *            exception. No plaintext code path can clear it. See
 *            plain_publish().
 *   POLLOUT  conn_queue() raises want_write the instant bytes are queued, and
 *            plain_send() publishes want_write = (unsent bytes remain). The two
 *            are the same predicate at every point the loop can observe, so the
 *            mask is identical.
 *   send()   plain_send() calls recv-free send() with MSG_NOSIGNAL, loops on a
 *            short write, retries EINTR, breaks on EAGAIN/EWOULDBLOCK, and
 *            returns TRANSPORT_FATAL for everything else -- which is what the
 *            old code's fall-through to `return -1` did.
 *   recv()   plain_recv() calls recv() with the same flags argument (0), loops
 *            on EINTR, maps EAGAIN to TRANSPORT_RETRY, and maps n == 0 to the
 *            EOF that conn_fill() turns into CONN_FILL_EOF.
 *
 * tests/integration/test_readiness_intent.c asserts the invariant from the
 * plaintext side and tests/integration/test_close_sites.c's descendant check
 * asserts that nothing outside this file, connection.c and the drain calls the
 * raw syscalls. The other 82 tests are the regression bar.
 */
#include "core/transport.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "tls_backend.h"

/* ---------------------------------------------------------------------------
 * The plaintext ops
 * ---------------------------------------------------------------------------
 * `void *ctx` is not in this signature and that is not an accident of style:
 * connection.h's t_ctx is there because a TLS transport needs somewhere to put
 * an SSL*, and the plaintext transport having no parameter for it is what makes
 * "NULL t_ctx means plaintext" true by construction rather than by a flag.
 *
 * ---------------------------------------------------------------------------
 * MSG_DONTWAIT ON BOTH CALLS, AND IT IS A CONTRACT RATHER THAN A FLAG
 * ---------------------------------------------------------------------------
 * The read used to be `recv(c->fd, buf, len, 0)` and relied on the descriptor
 * being nonblocking; the send was `send(c->fd, buf, len, MSG_NOSIGNAL)` and
 * relied on the same. Both now ask for non-blocking EXPLICITLY, and the reason is
 * a hang rather than a preference.
 *
 * `fed_send_shutdown()`'s drain used to pass MSG_DONTWAIT itself, with a comment
 * explaining that a teardown must not be able to block even if some other code
 * path made the descriptor blocking. Routing that drain through the transport
 * took the flag with it -- the transport is what calls recv(), so the transport
 * has to carry the non-blocking guarantee -- and the result was that two
 * federation tests hung to their 40 s CTest timeout inside `server_shutdown()`,
 * in a blocking recv() on a descriptor a test had created. Two tests were green
 * before the drain moved and red after, and nothing about the drain's own logic
 * had changed: the guarantee had simply moved to a place that did not have it.
 *
 * SO THE RULE IS NOW IN THE INTERFACE, WHERE IT CANNOT BE DROPPED AGAIN:
 * transport_recv() and transport_send() do not block, whatever the descriptor's
 * flags say. For every descriptor the node itself creates that is the behaviour
 * it always had; for a descriptor somebody else made blocking it is the
 * behaviour the teardown path already documented wanting. The cost is one flag
 * ORed into an argument on a path that was already about to be a syscall.
 */
static void plain_publish(conn_t *c, int want_write_extra)
{
    const int pending = (conn_write_pending(c) > 0u) ? 1 : 0;

    conn_want(c, 1, (want_write_extra || pending) ? 1 : 0);
}

static ssize_t plain_recv(conn_t *c, void *buf, size_t len)
{
    for (;;) {
        ssize_t n = recv(c->fd, buf, len, MSG_DONTWAIT);

        if (n > 0) {
            /* Data moved, so readability is still wanted (there may be more) and
             * writability is whatever the queue says. */
            plain_publish(c, 0);
            return n;
        }
        if (n == 0) {
            plain_publish(c, 0);
            return 0; /* the peer closed its half */
        }
        if (errno == EINTR) {
            continue; /* not an outcome: the same call again */
        }
        plain_publish(c, 0);
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return TRANSPORT_RETRY;
        }
        return TRANSPORT_FATAL;
    }
}

static ssize_t plain_send(conn_t *c, const void *buf, size_t len)
{
    /* THE EMPTY PASS. connection.c calls this once with len 0 after the queue has
     * drained, and the answer must not touch the descriptor: send(fd, NULL, 0)
     * is legal on Darwin and Linux but is not something to put in a hot path on
     * the strength of "it happens to work", and there is nothing for it to do
     * anyway. Publishing the intent here is the WHOLE reason the empty pass is
     * not merely an optimisation: a TLS transport's empty pass is a handshake
     * step, so the interface has to make the call, and the plaintext
     * implementation has to answer it in the same vocabulary. */
    if (len == 0u) {
        plain_publish(c, 0);
        return 0;
    }
    for (;;) {
        ssize_t n = send(c->fd, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);

        if (n > 0) {
            plain_publish(c, 0);
            return n;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        plain_publish(c, 0);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return TRANSPORT_RETRY; /* partial write; the rest waits for a tick */
        }
        return TRANSPORT_FATAL;
    }
}

static void plain_close(conn_t *c)
{
    /* NOTHING, and the nothing is load-bearing.
     *
     * Two things it must not do, both of which this function's shape is the
     * record of:
     *
     *   close(c->fd)          3.4 makes server_close_conn() the single close site
     *                         for a connection, and connection.c calls this from
     *                         conn_free() -- which server_close_conn() calls
     *                         AFTER its own close(). Closing here would be a
     *                         second close of a descriptor that may already have
     *                         been reused.
     *   conn_mark_closing()   the reaper has already decided; this runs after it.
     *
     * A TLS close is NOT nothing -- it sends close_notify, which is a write -- so
     * a reader looking for the difference between the two implementations should
     * find it in tls_openssl.c rather than here. */
    (void)c;
}

static const transport_ops_t k_plain_ops = {
    plain_recv,
    plain_send,
    plain_close
};

void transport_init_plaintext(conn_t *c)
{
    if (c == NULL) {
        return;
    }
    c->t_ops = &k_plain_ops;
    c->t_ctx = NULL;
}

/* ---------------------------------------------------------------------------
 * The three doors
 * ---------------------------------------------------------------------------
 * A NULL ops pointer is unreachable through conn_new() -- transport_init_plaintext()
 * runs before the connection is ever reachable from the loop -- so these do not
 * defend against it. They return the conservative answer anyway, because a
 * defensive branch that cannot be reached is still cheaper than a NULL call in a
 * hot path's debugging session. */

ssize_t transport_recv(conn_t *c, void *buf, size_t len)
{
    if (c == NULL || c->t_ops == NULL || c->t_ops->recv == NULL) {
        return TRANSPORT_FATAL;
    }
    return c->t_ops->recv(c, buf, len);
}

ssize_t transport_send(conn_t *c, const void *buf, size_t len)
{
    if (c == NULL || c->t_ops == NULL || c->t_ops->send == NULL) {
        return TRANSPORT_FATAL;
    }
    return c->t_ops->send(c, buf, len);
}

void transport_close(conn_t *c)
{
    if (c == NULL || c->t_ops == NULL || c->t_ops->close == NULL) {
        return;
    }
    c->t_ops->close(c);
    /* The ops are cleared AFTER the call, so a close implementation that freed
     * the ctx cannot be reached twice through a stale pointer. A second
     * conn_free() on the same conn_t is a use-after-free of the conn_t itself
     * and is not something this defends against. */
    c->t_ops = NULL;
    c->t_ctx = NULL;
}

int transport_is_tls(const conn_t *c)
{
    /* The flag, not the ops pointer, and the reason is that the flag is the
     * only one of the two with a WRITER this file controls: conn_new() zeroes it,
     * a successful upgrade sets it, and nothing else may. Asking whether the ops
     * happen to be OpenSSL's would work too and would make this file have to know
     * what OpenSSL's ops look like, which is the coupling the vtable exists to
     * remove. So the answer is one int, and the int is documented at the field. */
    return (c != NULL && c->tls_active) ? 1 : 0;
}

/* ---------------------------------------------------------------------------
 * STARTING TLS, and where the decision actually lives
 * ---------------------------------------------------------------------------
 * The #if is HERE rather than inside connection.c, so that a build with no TLS
 * and a build with it compile the SAME connection.c -- the readiness intent, the
 * 670 ordering arm in conn_pump(), and the loop's poll set are byte-identical
 * source in both, and the difference is one function that either starts a
 * handshake or says it cannot.
 *
 * A build without TLS is not a build where TLS fails: it is a build where the
 * STARTTLS command does not exist, because the capability table never advertises
 * it and commands.c answers it 691. The stub below therefore cannot be reached
 * from a client and is written to be loud if it ever is. */
int transport_starttls(conn_t *c, int as_server)
{
    if (c == NULL) {
        return -1;
    }
#if defined(IRC_WITH_TLS)
    return tls_backend_starttls(c, as_server);
#else
    (void)as_server;
    printf("[observable] tls_unavailable: fd=%d reason=NOT_COMPILED_IN\n", c->fd);
    return -1;
#endif
}

int transport_starttls_peer(conn_t *c, int as_server, const char *peer_host)
{
    if (c == NULL) {
        return -1;
    }
#if defined(IRC_WITH_TLS)
    return tls_backend_starttls_peer(c, as_server, peer_host);
#else
    (void)as_server;
    (void)peer_host;
    printf("[observable] tls_unavailable: fd=%d reason=NOT_COMPILED_IN\n", c->fd);
    return -1;
#endif
}
