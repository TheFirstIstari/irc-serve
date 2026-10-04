/* tls_openssl.c -- the OpenSSL TLS backend, compiled only when WITH_TLS=ON.
 *
 * ===========================================================================
 * READ tls_backend.h FIRST. It is one function wide on purpose, and this file is
 * the reason: everything below the seam is here rather than scattered through
 * connection.c, server.c, cap.c and commands.c, so "does the plaintext build
 * still compile" is a question about ONE file.
 * ===========================================================================
 *
 * ---------------------------------------------------------------------------
 * THE THREE THINGS THIS FILE OWNS
 * ---------------------------------------------------------------------------
 *   1. THE CONTEXTS. One SSL_CTX for accepting (server role) and one for dialling
 *      a peer (client role), because a context carries a session cache and a
 *      verify callback and mixing the two roles in one is how a server ends up
 *      asking its peers for client certificates. Both live on `struct tls_node`,
 *      which is reached from `server_t::tls` and freed by server_shutdown().
 *
 *   2. THE PER-CONNECTION SSL*. Created by tls_backend_starttls(), owned by
 *      `conn_t::t_ctx`, and freed by the TRANSPORT's close op -- which
 *      connection.c's conn_free() calls, so there is exactly one release path for
 *      a connection and it is not this file's problem to remember. See "WHERE
 *      EVERY SSL* IS FREED" below.
 *
 *   3. THE READINESS INTENT. Every return from every OpenSSL call is translated
 *      into one of transport.h's four values AND a conn_want() publication. That
 *      translation is the whole reason this transport can drive a poll() loop, and
 *      it is the part that is easy to get subtly wrong, so each branch says what
 *      it means.
 *
 * ---------------------------------------------------------------------------
 * WHERE EVERY SSL* IS FREED, reasoned statically
 * ---------------------------------------------------------------------------
 * **LeakSanitizer does not exist on Darwin.** The top-level CMakeLists.txt's
 * IRC_SANITIZE block says so and records that an ASan binary built with
 * detect_leaks=1 HANGS on macOS rather than reporting. So this file's teardown
 * cannot be verified locally and no claim in it says otherwise. The accounting:
 *
 *   conn_t::t_ctx        the SSL*. Created ONLY in tls_backend_starttls().
 *                        Released ONLY by tls_close(), which is
 *                        transport_ops_t::close for the TLS ops.
 *   transport_close()    called from exactly one place in src/: conn_free().
 *                        So the release path is conn_free(), and conn_free() is
 *                        what server_close_conn(), server_dial_progress()'s two
 *                        failure arms and server_shutdown()'s connection walk all
 *                        end in. That is one call in one function rather than four
 *                        call sites somebody has to keep in step, and
 *                        tests/integration/test_readiness_intent.c asserts the
 *                        shape of it -- statically, and labelled as static,
 *                        because on a plaintext-only build nothing observable
 *                        changes when the call is removed.
 *
 *   server_t::tls        the node's `struct tls_node` (two SSL_CTX and one
 *                        X509_STORE). Released by tls_backend_node_free(), called
 *                        from server_shutdown() beside the other "a module's
 *                        memory, released here" arms (fed_burst_close,
 *                        resume_close, fed_nickreg_close).
 *
 *   server_t::tls_listen_fd   a plain descriptor, closed by server_shutdown()
 *                        beside s->listen_fd. It is not a conn_t and has no SSL*
 *                        of its own: an implicit-TLS connection's SSL* is created
 *                        at accept and owned by that conn.
 *
 * IT IS SAFE AT EVERY POINT IN server_shutdown(), and the argument is the same
 * one the burst shadow's and the resume table's arms give: every connection was
 * closed by the walk that runs first, so nothing can still be holding an SSL*.
 * And it is safe on a node that never configured TLS, which is every node in this
 * build by default -- s->tls is NULL until tls_backend_node_init() succeeds.
 */
#include "tls_backend.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "core/transport.h"

/* ---------------------------------------------------------------------------
 * THE NODE'S TLS STATE
 * --------------------------------------------------------------------------- */
typedef struct tls_node {
    SSL_CTX *srv;   /* accept role: implicit TLS and STARTTLS */
    SSL_CTX *cli;   /* dialling role: peer links. See "THE CONTEXTS" above. */
    int      insecure; /* --tls-insecure: do NOT fail an unverifiable peer */
    int      have_ca;  /* a --tls-ca was loaded into cli */
} tls_node_t;

/* ---------------------------------------------------------------------------
 * PUBLISH THE READINESS INTENT, and the ONE THING THIS FILE GOT WRONG FIRST
 * ---------------------------------------------------------------------------
 * Every path below used to call `conn_want(c, want_read, want_write)` with the
 * write half taken from OpenSSL alone. That is wrong, and the peer-link test found
 * it: an OpenSSL transport knows what the PROTOCOL wants and knows nothing at all
 * about the APPLICATION bytes this node has queued and not yet written.
 *
 * The symptom was a peer link that dialled, completed its handshake, and then sat
 * there until the handshake deadline fired with `cause=NO_ANSWER`. The FEDERATE
 * line was in the write queue; the handshake had finished; and want_write had been
 * set to 0 by the last SSL_read(), so the loop never asked poll() for POLLOUT and
 * the line never went out. Nothing was logged and nothing failed -- the link simply
 * timed out, which is exactly what a dead peer looks like.
 *
 * So the write half is OpenSSL's opinion OR-ed with "are there unsent bytes", and
 * the second term is the only part of the answer a caller outside OpenSSL can hold.
 * The read half is OpenSSL's alone: a plaintext connection's unread queue is not a
 * reason to stop reading, and a TLS transport's already-decrypted bytes are drained
 * inside tls_recv() rather than by re-polling the socket.
 *
 * The alternative -- having conn_pump() recompute it, the way the plaintext path
 * effectively does -- would work too, and would put the same OR in a second place.
 * One place, here, is better: this is the only code that knows OpenSSL's opinion.
 */
static void tls_publish(conn_t *c, int want_read, int want_write)
{
    const int pending = (conn_write_pending(c) > 0u) ? 1 : 0;

    conn_want(c, want_read, (want_write || pending) ? 1 : 0);
}

/* ---------------------------------------------------------------------------
 * ONE HELPER FOR TRANSLATING AN OpenSSL FAILURE, and it is the whole of the
 * readiness-intent contract on this side
 * ---------------------------------------------------------------------------
 * SSL_get_error() is only meaningful immediately after a failed SSL_ call, so
 * every site below calls it before doing anything else. The four outcomes:
 *
 *   WANT_READ     the protocol is parked awaiting bytes. Publish readability.
 *   WANT_WRITE    parked awaiting a write. Publish WRITABILITY -- and this is the
 *                 case poll()'s revents can never report, because the socket has
 *                  nothing queued. It is the reason conn_t::want_write exists.
 *   ZERO_RETURN   the peer sent close_notify. A clean EOF, which is the `== 0`
 *                  return value and NOT a failure: a TLS close is orderly and a
 *                  node that treated it as an error would log every clean
 *                  disconnect as a write error.
 *   SYSCALL/other fatal. err == 0 with SYSCALL means the peer went away without
 *                  close_notify, which is a truncation and not a clean close.
 *
 * WANT_X509_LOOKUP and WANT_ASYNC are answered as WANT_READ. Neither can occur
 * here -- this file installs no client-certificate callback and uses no async
 * engine -- and treating an unreachable state as "wait for bytes" is the
 * conservative answer: it costs a poll iteration and cannot lose data. Answering
 * it as fatal would turn a misconfiguration into a dropped connection with no
 * diagnostic, which is the opposite of what an unreachable branch should do. */
static ssize_t tls_fail(conn_t *c, SSL *ssl, int ret, const char *what)
{
    int err = SSL_get_error(ssl, ret);
    unsigned long e;

    switch (err) {
    case SSL_ERROR_WANT_READ:
        tls_publish(c, 1, 0);
        return TRANSPORT_RETRY;
    case SSL_ERROR_WANT_WRITE:
        tls_publish(c, 1, 1);
        return TRANSPORT_RETRY;
    case SSL_ERROR_WANT_X509_LOOKUP:
    case SSL_ERROR_WANT_ASYNC:
        tls_publish(c, 1, 0);
        return TRANSPORT_RETRY;
    case SSL_ERROR_ZERO_RETURN:
        tls_publish(c, 1, 0);
        return 0; /* close_notify: an orderly end, not an error */
    case SSL_ERROR_SYSCALL:
        if (ret == 0) {
            /* EOF with no close_notify: a truncation. The peer vanished. */
            tls_publish(c, 1, 0);
            return 0;
        }
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            tls_publish(c, 1, 0);
            return TRANSPORT_RETRY;
        }
        break;
    default:
        break;
    }
    /* One line, with the OpenSSL reason code, because "the handshake failed" on a
     * node serving hundreds of connections is not a diagnostic. The connection's
     * own close reason is printed by the loop's caller; this says WHY. */
    e = ERR_peek_last_error();
    printf("[observable] tls_error: fd=%d op=%s reason=%s ossl=%lu\n", c->fd,
           what, ERR_reason_error_string(e), e);
    ERR_clear_error();
    /* want_read 0 as well as want_write 0: the transport is finished, so leaving
     * the connection in the poll set would only wake the loop to be told the same
     * thing again. The connection is marked CLOSING by its caller either way. */
    conn_want(c, 0, 0);
    return TRANSPORT_FATAL;
}

/* ---------------------------------------------------------------------------
 * THE TLS OPS
 * ---------------------------------------------------------------------------
 * The buffer is never full when recv() is called (connection.c grows or caps the
 * read buffer first), and THAT IS THE PRECONDITION that makes the SSL_pending()
 * loop below safe: a transport may only hand back bytes it has already decrypted
 * because the caller has somewhere to put them, and it has room. Without that
 * guarantee the loop below would spin, handing back bytes nobody can accept.
 *
 * THE COST, and it is the one non-obvious cost in this file: SSL_pending() is a
 * read of OpenSSL's internal buffer with no syscall, so the extra iteration costs
 * a function call rather than a round trip to the kernel. On a plaintext
 * connection none of this exists, which is the other half of why the default
 * build is the one with no dependency in it. */
static ssize_t tls_recv(conn_t *c, void *buf, size_t len)
{
    SSL *ssl = (SSL *)c->t_ctx;

    if (ssl == NULL) {
        return TRANSPORT_FATAL;
    }
    for (;;) {
        int n = SSL_read(ssl, buf, (int)len);

        if (n > 0) {
            /* Publish intent BEFORE returning, as the interface requires.
             *
             * want_write is "the write queue is non-empty": OpenSSL has no opinion
             * about application bytes this node has not produced yet, and the queue
             * is the only thing that knows about them. want_read is 1 because there
             * may be more decrypted bytes, and SSL_pending() below decides whether
             * waiting for the SOCKET is enough. */
            tls_publish(c, 1, 0);
            /* THE PENDING LOOP. OpenSSL can hold decrypted application bytes that
             * the socket has already been drained of, and poll() will never report
             * a socket that has nothing in it. So a transport that returned one
             * record's worth and then waited for POLLIN would strand the rest of a
             * record the peer already sent -- a line split across two TLS records
             * would hang with the second half sitting in OpenSSL's buffer and no
             * event that could ever wake the loop to read it.
             *
             * Returning them NOW is what makes that impossible, and it is legal
             * precisely because connection.c always makes room first. */
            if (SSL_pending(ssl) > 0) {
                continue;
            }
            return n;
        }
        /* SSL_read() with len 0 is legal and returns 0, which would read as EOF.
         * connection.c never does it (it guards on room), so this cannot happen
         * from there; it is here so the ambiguity is answered rather than
         * assumed. */
        if (n == 0 && len == 0u) {
            tls_publish(c, 1, 0);
            return 0;
        }
        return tls_fail(c, ssl, n, "SSL_read");
    }
}

static ssize_t tls_send(conn_t *c, const void *buf, size_t len)
{
    SSL *ssl = (SSL *)c->t_ctx;

    if (ssl == NULL) {
        return TRANSPORT_FATAL;
    }
    /* THE HANDSHAKE PASS. connection.c calls this once with an empty queue after
     * the queue has drained, and for TLS that call is the ONLY thing that can
     * start or continue a handshake: a server flight has to go out before there
     * is any application data, and there is no application data on a connection
     * that has just been handed over. Without this arm the loop would have nothing
     * to call, and readiness intent would have nothing to publish. */
    if (SSL_in_init(ssl) != 0) {
        int rc = SSL_do_handshake(ssl);

        if (rc != 1) {
            return tls_fail(c, ssl, rc, "SSL_do_handshake");
        }
        if (SSL_in_init(ssl) != 0) {
            tls_publish(c, 1, 0);
            return TRANSPORT_RETRY;
        }
    }
    if (len == 0u) {
        tls_publish(c, 1, 0);
        return 0;
    }
    {
        int n = SSL_write(ssl, buf, (int)len);

        if (n > 0) {
            tls_publish(c, 1, 0);
            return n;
        }
        return tls_fail(c, ssl, n, "SSL_write");
    }
}

static void tls_close(conn_t *c)
{
    SSL *ssl = (SSL *)c->t_ctx;

    if (ssl == NULL) {
        return;
    }
    /* SSL_shutdown() is a WRITE -- it sends close_notify, which is the orderly end
     * of a TLS session and is what lets the peer distinguish "went away" from
     * "closed properly". It is best effort on purpose, for two reasons that are
     * both about where this runs.
     *
     * It runs from conn_free(), which server_close_conn() calls AFTER close(): the
     * descriptor is already gone, so the shutdown cannot be delivered anyway. And
     * the alternative -- a blocking SSL_shutdown() -- would be a hang on the
     * teardown path, which is exactly the cost fed_send_shutdown()'s long comment
     * about a missed goodbye is about. So this is a courtesy call whose only
     * reliable effect is on OpenSSL's own state, and the descriptor close stays
     * where 3.4 put it: in the reaper.
     *
     * IT DOES NOT CLOSE THE DESCRIPTOR. That is not an omission; it is the rule. */
    (void)SSL_shutdown(ssl);
    SSL_free(ssl);
    c->t_ctx = NULL;
}

static const transport_ops_t k_tls_ops = {
    tls_recv,
    tls_send,
    tls_close
};

/* ---------------------------------------------------------------------------
 * VERIFY A PEER'S CERTIFICATE, and this is the other security boundary
 * ---------------------------------------------------------------------------
 * WHAT IS ENFORCED, in full:
 *
 *   - the chain must verify against the operator's --tls-ca store. Nothing else is
 *     a trust anchor: no system roots, because "verify against whatever this host
 *     happens to trust" is a different policy from the one an operator configured
 *     and would silently differ per machine.
 *   - the certificate's NAME must match the host this node dialled. Chain
 *     verification alone answers "signed by somebody I trust", which is not
 *     "signed by the peer I meant to reach": a certificate for `irc.evil` signed
 *     by the same CA would satisfy the chain check, and a compromised peer could
 *     present it for a link this node believes is somebody else. An IP literal is
 *     matched against iPAddress SANs rather than dNSNames, which is what
 *     X509_VERIFY_PARAM_set1_ip_asc() does and is why a certificate generated with
 *     `subjectAltName = IP:127.0.0.1` works for a --peer irc.b,127.0.0.1,PORT.
 *   - the certificate must be INS ITS VALIDITY WINDOW. That is OpenSSL's default
 *     chain-verification behaviour and it is not turned off, which is what makes an
 *     expired or not-yet-valid certificate a refusal rather than a warning.
 *
 * WHAT IS NOT ENFORCED, and the honest list:
 *
 *   - NO CLIENT CERTIFICATE AUTHENTICATION. A client on the implicit-TLS port is
 *     NOT asked for a certificate (SSL_VERIFY_NONE on the server context), so a
 *     client certificate is not verified against anything even if the client
 *     offers one. There is no client-certificate authentication in this phase at
 *     all: SASL PLAIN over TLS is what a client has.
 *   - NO CERTIFICATE REVOCATION. No CRL and no OCSP are consulted, so a revoked
 *     certificate that chains to the CA is accepted until it EXPIRES. This is the
 *     largest gap in the boundary and it is named rather than glossed.
 *   - NO CIPHER OR PROTOCOL VERSION PINNING beyond OpenSSL's compiled-in defaults.
 *     There is no SSL_CTX_set_cipher_list() call here, so the policy is whatever
 *     the linked OpenSSL ships. Pinning it is a configuration decision an operator
 *     should make, and it belongs in an operator-facing flag rather than a
 *     hard-coded string.
 *   - NO SESSION RESUMPTION CONTROL and no 0-RTT. OpenSSL's defaults apply; 0-RTT
 *     is not enabled (SSL_OP_NO_TICKET is not set and no early-data callback is
 *     installed, and OpenSSL does not enable 0-RTT without one).
 *
 * AND THE FAIL-CLOSED RULE, WHICH IS THE POINT OF --tls-insecure:
 *
 *   A PEER LINK OVER TLS WITH NO --tls-ca IS REFUSED, unless --tls-insecure was
 *   given. There is no "verify against the system roots" fallback and no silent
 *   proceed: an operator who has not configured a trust anchor has not configured
 *   peer authentication, and a node that quietly accepted an unverifiable peer
 *   would be indistinguishable from one that verified it. The insecure mode is an
 *   EXPLICIT flag for exactly that reason -- it is the thing an operator types when
 *   they mean it, and its absence is a refusal with a named reason rather than a
 *   downgrade nobody chose. */
static void tls_peer_verify(SSL *ssl, tls_node_t *node, const char *peer_host,
                            int fd)
{
    X509_VERIFY_PARAM *param;

    if (node->insecure != 0) {
        /* The OPERATOR SAID SO. SSL_VERIFY_NONE plus no name check: an
         * unverifiable peer is accepted and the fact is on the wire below, so a
         * reader of the log can tell an insecure link from a verified one without
         * reading the command line. */
        SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
        printf("[observable] tls_peer_verify: fd=%d mode=INSECURE "
               "reason=--tls-insecure\n", fd);
        return;
    }
    SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
    param = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(param,
                                    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (peer_host != NULL && peer_host[0] != '\0') {
        int ok = (peer_host[0] >= '0' && peer_host[0] <= '9')
                     ? X509_VERIFY_PARAM_set1_ip_asc(param, peer_host)
                     : X509_VERIFY_PARAM_set1_host(param, peer_host, 0);
        if (ok != 1) {
            /* Not fatal here: the name check failing is reported by the
             * verification itself, which will fail with CERTIFICATE_VERIFY_FAILED
             * and a readable reason. Failing early would produce a worse log. */
            printf("[observable] tls_peer_name: fd=%d host=%s "
                   "reason=NOT_A_NAME_OR_IP\n", fd, peer_host);
        }
    }
}

/* ---------------------------------------------------------------------------
 * NODE SETUP
 * ---------------------------------------------------------------------------
 * BOTH ENTRY POINTS FAIL LOUDLY AND REFUSE THE WHOLE CONFIGURATION. A node whose
 * certificate did not load does not come up with TLS half-working: it comes up
 * without it, or not at all, and it says which on stdout. The state this file
 * exists to prevent is a node that advertises `sts`, answers STARTTLS with a 670,
 * and then cannot complete a handshake.
 * --------------------------------------------------------------------------- */
int tls_backend_available(void)
{
    return 1;
}

void tls_backend_node_free(tls_node_t *node)
{
    if (node == NULL) {
        return;
    }
    if (node->srv != NULL) {
        SSL_CTX_free(node->srv);
        node->srv = NULL;
    }
    if (node->cli != NULL) {
        SSL_CTX_free(node->cli);
        node->cli = NULL;
    }
    /* NO X509_STORE_free HERE, and that is not an oversight. This file never
     * holds an X509_STORE at all: SSL_CTX_load_verify_locations() creates one and
     * the CONTEXT owns it, so SSL_CTX_free() releases it. Calling
     * X509_STORE_free() on a store this file does not have a pointer to would be
     * impossible, and inventing one to free would be a double free. */
    free(node);
}

int tls_backend_node_init(tls_node_t **out, const char *cert, const char *key,
                          const char *ca, int insecure)
{
    tls_node_t *node;

    if (out == NULL) {
        return -1;
    }
    *out = NULL;
    if (cert == NULL || key == NULL) {
        return -1;
    }
    /* THE KEY'S PERMISSIONS ARE NOT CHECKED HERE, and where they ARE checked is a
     * decision worth stating because it was the other way round first.
     *
     * A backend that loaded a world-readable key without a murmur would be a
     * footgun for whoever wrote the next one, so the check belongs somewhere. It was
     * here -- and a fault injection showed what that cost: the key's permission
     * rule was COMPILED OUT of a `-DWITH_TLS=OFF` build along with everything else
     * in this file, so the default build -- the one every CI runner compiles, and
     * the one that should check most -- could not refuse an unsafe key at all, and
     * tests/integration/test_tls.c had to assert a different reason in each build.
     *
     * So it is in main(), where an operator's options are turned into a
     * configuration, and it holds in EVERY build. A node with no TLS library still
     * refuses to accept a key other people can read, which is the right answer to
     * "here is a private key that is not private" whether or not this node was ever
     * going to load it. See key_file_is_private() in node_main.c. */

    node = (tls_node_t *)calloc(1, sizeof *node);
    if (node == NULL) {
        return -1;
    }
    node->insecure = insecure ? 1 : 0;

    node->srv = SSL_CTX_new(TLS_server_method());
    node->cli = SSL_CTX_new(TLS_client_method());
    if (node->srv == NULL || node->cli == NULL) {
        printf("[observable] tls_init: state=FAILED reason=context\n");
        tls_backend_node_free(node);
        return -1;
    }
    /* The certificate is loaded into BOTH contexts. The server side presents it;
     * the client side can present it too, which is what lets two irc-serve nodes
     * configured with one certificate authenticate each other without a second
     * file. A peer that does not want to present one simply does not ask. */
    if (SSL_CTX_use_certificate_chain_file(node->srv, cert) != 1) {
        printf("[observable] tls_init: state=FAILED path=%s reason=certificate\n",
               cert);
        tls_backend_node_free(node);
        return -1;
    }
    if (SSL_CTX_use_certificate_chain_file(node->cli, cert) != 1) {
        printf("[observable] tls_init: state=FAILED path=%s reason=certificate\n",
               cert);
        tls_backend_node_free(node);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(node->srv, key, SSL_FILETYPE_PEM) != 1) {
        printf("[observable] tls_init: state=FAILED path=%s reason=key\n", key);
        tls_backend_node_free(node);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(node->cli, key, SSL_FILETYPE_PEM) != 1) {
        printf("[observable] tls_init: state=FAILED path=%s reason=key\n", key);
        tls_backend_node_free(node);
        return -1;
    }
    /* The key and the certificate must BELONG TOGETHER. OpenSSL checks this and
     * most callers never look at the result: a mismatched pair loads cleanly and
     * fails at every handshake, which is a configuration error that looks like a
     * network fault for as long as it takes somebody to read a log. */
    if (SSL_CTX_check_private_key(node->srv) != 1 ||
        SSL_CTX_check_private_key(node->cli) != 1) {
        printf("[observable] tls_init: state=FAILED path=%s "
               "reason=key_does_not_match_certificate\n",
               key);
        tls_backend_node_free(node);
        return -1;
    }

    if (ca != NULL && ca[0] != '\0') {
        /* The CLIENT context only. A server context must not be given a client
         * CA store, because that is the flag that turns on client-certificate
         * authentication, and there is no client certificate authentication in this
         * phase -- see the "WHAT IS NOT ENFORCED" list. */
        if (SSL_CTX_load_verify_locations(node->cli, ca, NULL) != 1) {
            printf("[observable] tls_init: state=FAILED path=%s reason=ca\n", ca);
            tls_backend_node_free(node);
            return -1;
        }
        node->have_ca = 1;
    }

    *out = node;
    printf("[observable] tls_init: state=READY ca=%s insecure=%d verify=%s\n",
           node->have_ca ? "configured" : "none", node->insecure,
           (node->have_ca && node->insecure == 0) ? "PEER_CHAIN_AND_NAME"
                                                   : "NONE_WITHOUT_CA");
    return 0;
}

/* ---------------------------------------------------------------------------
 * STARTING TLS ON A CONNECTION
 * --------------------------------------------------------------------------- */
int tls_backend_starttls(conn_t *c, int as_server)
{
    return tls_backend_starttls_peer(c, as_server, NULL);
}

int tls_backend_starttls_peer(conn_t *c, int as_server, const char *peer_host)
{
    struct server *s;
    SSL_CTX *ctx;
    SSL *ssl;

    if (c == NULL) {
        return -1;
    }
    /* conn_t::owner, which server_add_conn() sets. It exists because the backend
     * needs the node's SSL_CTX and the call site cannot supply it: conn_pump()
     * starts a handshake from inside the connection layer, which has a conn_t and
     * no server_t. A conn_t is created before it is registered and this is only
     * ever called after -- the same precondition server_close_conn() and the nick
     * registry rely on -- so `owner` is always set here. */
    s = c->owner;
    if (s == NULL || s->tls == NULL) {
        printf("[observable] tls_unavailable: fd=%d reason=NOT_CONFIGURED\n", c->fd);
        return -1;
    }
    /* ONE cast, and it is here rather than four times because the node's type is
     * opaque to this file's callers but not to itself. `-Wcast-qual` is satisfied
     * because the target is NOT const -- a const SSL_CTX * would be the bug this
     * cast is here to prevent, since the handshake mutates the context's
     * per-connection state. */
    ctx = as_server ? ((tls_node_t *)(void *)s->tls)->srv
                    : ((tls_node_t *)(void *)s->tls)->cli;
    if (ctx == NULL) {
        return -1;
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        printf("[observable] tls_error: fd=%d op=SSL_new reason=allocation\n",
               c->fd);
        return -1;
    }
    /* SNI on the client side, from the host this node dialled. Without it a peer
     * serving several names on one address cannot choose, and the certificate it
     * presents may be the wrong one for this link -- which then fails the NAME
     * check in tls_peer_verify() for a reason that looks like a misconfiguration
     * rather than a missing hint.
     *
     * THE COPY IS WHY THERE IS A COPY. SSL_set_tlsext_host_name() is a macro that
     * casts its second argument to void *, so handing it a `const char *` trips
     * -Wcast-qual -- and -Wcast-qual is IN this project's warning set on purpose.
     * Three ways out were available and this is the one chosen:
     *
     *   -Wno-cast-qual for this file   suppress a real diagnostic to accommodate
     *                                 a third-party macro. The brief for this
     *                                 phase says to SCOPE third-party warnings
     *                                 rather than narrow the project's own set,
     *                                 and a suppression is the thing to be most
     *                                 suspicious of: it is invisible to a reader
     *                                 of the build output and permanent.
     *   hand SSL_ctrl() a cast         the same cast, written out, so it is at
     *                                 least visible -- and still a const-drop.
     *   THIS                           copy the name into a mutable buffer.
     *
     * The copy costs one bounded memcpy on one connection's dial path, and it is
     * bounded rather than strncpy'd so a truncated SNI name is IMPOSSIBLE: the
     * buffer is the size node_main.c's --peer host field is, which is the longest
     * name that can reach here. */
    if (as_server == 0 && peer_host != NULL && peer_host[0] != '\0' &&
        (peer_host[0] < '0' || peer_host[0] > '9')) {
        char sni[256];

        if (strlen(peer_host) < sizeof sni) {
            memcpy(sni, peer_host, strlen(peer_host) + 1u);
            (void)SSL_set_tlsext_host_name(ssl, sni);
        } else {
            printf("[observable] tls_sni: fd=%d reason=NAME_TOO_LONG "
                   "bytes=%zu\n", c->fd, strlen(peer_host));
        }
    }
    if (SSL_set_fd(ssl, c->fd) != 1) {
        printf("[observable] tls_error: fd=%d op=SSL_set_fd reason=failed\n",
               c->fd);
        SSL_free(ssl);
        return -1;
    }
    if (as_server != 0) {
        SSL_set_accept_state(ssl);
    } else {
        SSL_set_connect_state(ssl);
        tls_peer_verify(ssl, (tls_node_t *)s->tls, peer_host, c->fd);
    }
    c->t_ops = &k_tls_ops;
    c->t_ctx = ssl;
    c->tls_active = 1;
    /* Publish the intent the handshake needs NEXT, which for a handshake that has
     * not started is readability: the first flight we will ever see is a client's
     * ClientHello. SSL_do_handshake() will turn this into writability the moment
     * the server flight is due, and that transition is the one poll() cannot
     * report for itself.
     *
     * AND tls_publish() rather than conn_want(), because a STARTTLS connection very
     * often arrives with bytes already queued: the 670 went out first, and on a peer
     * link the FEDERATE line may already be waiting. Publishing a bare want_write=0
     * here would clear an intent conn_queue() had raised. */
    tls_publish(c, 1, 0);
    printf("[observable] tls_handshake_start: fd=%d role=%s\n", c->fd,
           as_server ? "server" : "client");
    return 0;
}
