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

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include "core/transport.h"

/* Upper bound on a stapled response read from disk.
 *
 * A TLS CertificateStatus message cannot exceed the handshake message limit, which
 * is 2^14 bytes for the record plus framing, so 64 KiB cannot reject a staple that
 * would have fitted on the wire. It exists because the DER arm hands a length to
 * BIO_read() and an unbounded read of an operator-supplied file is not a thing to
 * write when the value only has to be plausible. The PEM arm does not use it: a PEM
 * arm has no length to respect, it is read by the parser. */
#define OCSP_STAPLE_MAX 65536

/* ---------------------------------------------------------------------------
 * THE NODE'S TLS STATE
 * --------------------------------------------------------------------------- */
typedef struct tls_node {
    SSL_CTX *srv;   /* accept role: implicit TLS and STARTTLS */
    SSL_CTX *cli;   /* dialling role: peer links. See "THE CONTEXTS" above. */
    int      insecure; /* --tls-insecure: do NOT fail an unverifiable peer */
    int      have_ca;  /* a --tls-ca was loaded into cli */
    /* --tls-ocsp-staple: the DER bytes of an OCSP response for this node's own
     * certificate, read ONCE here and stapled on every server-role handshake.
     *
     * IT IS A POINTER INTO A HEAP BLOCK THIS STRUCT OWNS, not a copy per
     * connection, and the reason is OpenSSL's ownership rule: SSL_set_tlsext_
     * status_ocsp_resp() stores the pointer and the length rather than copying
     * the bytes (openssl/ssl/s3_lib.c, SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP,
     * in 1.1.1 and 3.x; 4.x additionally d2i's it and keeps both). So the bytes
     * must outlive every SSL created from this context, and the node outlives
     * every SSL. One read, one block, N handshakes.
     *
     * THE COST, which is the whole reason this cannot be a convenience: a stale
     * staple stays stale until an operator replaces the file and restarts. That
     * is the deliberate trade -- see "STAPLED, NEVER FETCHED". */
    unsigned char *staple;
    size_t         staple_len;
    /* THE FAILURE POLICY, one boolean, and its default is FAIL CLOSED. See
     * "THE FAILURE POLICY, AND WHICH DIRECTION IS THE DEFAULT". */
    int      staple_strict;
    /* What the startup line's `verify=` says. Held on the node rather than
     * recomputed at print time so there is one definition of the four states, and
     * see verify_label_for() for why there are four. */
    const char *verify_label;
} tls_node_t;

/* ---------------------------------------------------------------------------
 * ONE FORWARD DECLARATION, and it is here because of the file's own order
 * ---------------------------------------------------------------------------
 * tls_after_handshake() is the revocation gate and it runs from inside the
 * readiness translation below -- once from tls_send()'s handshake pass and once
 * from tls_recv() -- while its definition sits further down with the rest of the
 * revocation work. The order is deliberate rather than accidental: this file's
 * shape is "contexts, then the SSL*, then the readiness intent", and a peer
 * certificate's status is only knowable once the handshake is done, which is a
 * fact about the SSL rather than about the poll loop. Moving four hundred lines
 * of revocation code above the transport ops to avoid one declaration would make
 * the file harder to read, not easier.
 *
 * It is static, so the declaration cannot widen the backend's surface. */
static int tls_after_handshake(conn_t *c, SSL *ssl);

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
            /* A HANDSHAKE CAN ALSO COMPLETE ON THE READ PATH -- a server-role one
             * does, and so does a client-role one whose last flight arrived before
             * the loop ever asked for writability. The same gate as tls_send's, for
             * the same reason: whichever arm noticed, the check runs once. */
            if (tls_after_handshake(c, ssl) != 0) {
                conn_want(c, 0, 0);
                return TRANSPORT_FATAL;
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
        /* THE HANDSHAKE JUST COMPLETED HERE, which is where revocation is decided on
         * the peer-link path -- see tls_after_handshake(). The refusal it can return
         * is TRANSPORT_FATAL rather than TRANSPORT_RETRY on purpose: a peer whose
         * certificate is revoked is not a peer this node should keep talking to, and
         * retrying would re-present the same revoked staple on every poll iteration. */
        if (tls_after_handshake(c, ssl) != 0) {
            conn_want(c, 0, 0);
            return TRANSPORT_FATAL;
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
 *   - the certificate's NAME must match the peer this node dialled. Chain
 *     verification alone answers "signed by somebody I trust", which is not
 *     "signed by the peer I meant to reach": a certificate for `irc.evil` signed
 *     by the same CA would satisfy the chain check, and a compromised peer could
 *     present it for a link this node believes is somebody else. An IP literal is
 *     matched against iPAddress SANs rather than dNSNames, which is what
 *     X509_VERIFY_PARAM_set1_ip_asc() does and is why a certificate generated with
 *     `subjectAltName = IP:127.0.0.1` works for a --peer 127.0.0.1,127.0.0.1,PORT.
 *     A NAME CHECK THAT COULD NOT BE CONFIGURED IS A REFUSAL, never a handshake
 *     with no name in the verify parameter -- see "FAIL CLOSED" below.
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
 *   - CERTIFICATE REVOCATION IS CONSULTED, AND ONLY AS AN OCSP STAPLE (#135's
 *     audit). It is NOT CRL fetching: no CRL is downloaded, no distribution point is
 *     parsed, and `SSL_CTX_set_crl` is nowhere in this file. What IS consulted is the
 *     OCSP RESPONSE a peer staples to the handshake (`--tls-ocsp-staple`, or one the
 *     peer sends), verified against the CA this node loaded at startup, with the
 *     freshness check and the `nextUpdate` comparison below. See "CERTIFICATE
 *     REVOCATION, AND WHY IT IS OCSP STAPLING AND NOT A CRL FETCH" further down for
 *     the whole of it, and for what it does NOT cover.
 *
 *     THIS BULLET USED TO SAY "NO CERTIFICATE REVOCATION. No CRL and no OCSP are
 *     consulted", about 300 lines ABOVE the revocation code it described -- which is
 *     the most expensive place for a stale claim to be. A reader of the file's header
 *     would have concluded the largest gap in the boundary was unaddressed, and would
 *     have been wrong; the whole of `tls_after_handshake()` is the gate. The claim
 *     was found by an independent audit of the docs and the header, which is exactly
 *     the kind of claim nothing in a build looks at. `scripts/check-docs-truth.py`
 *     cannot reach it -- the claim is in a C file, not a document -- so this one is
 *     fixed by hand and the honest mechanism for the next one is still a person
 *     reading this file's header against its body.
 *
 *     THE PART THAT IS STILL TRUE, and is the part worth keeping: no revocation
 *     check happens for a certificate that arrives with NO staple, and no check
 *     reaches a certificate this node did not itself verify against its own CA store.
 *     A revoked certificate with no staple is accepted until it expires, exactly as
 *     before. `revocation=` on the startup line says which of the two this build has.
 *   - NO SNI / HOSTNAME GATING OF `sts`. The persistence policy is advertised on
 *     every connection to the plaintext port regardless of the hostname the client
 *     arrived with, because this node does not know a hostname for itself: it has
 *     no configuration option that names it. The specification says a persistence
 *     policy SHOULD NOT be advertised when no hostname is known, and the
 *     consequence of getting it wrong is visible -- a client that reached this
 *     node by an unintended name of a wildcard certificate pins the unintended
 *     name. KNOWN GAP, and named here rather than silently shipped.
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

/* ---------------------------------------------------------------------------
 * IS THIS PEER NAME AN ADDRESS RATHER THAN A NAME?
 * ---------------------------------------------------------------------------
 * RFC 6066 3 calls the SNI host_name a "fully qualified domain name", and
 * X509_VERIFY_PARAM_set1_ip_asc() matches an iPAddress SAN rather than a dNSName.
 * The two are different questions, so this is the one place both are asked, and
 * the discriminator is a PARSE rather than a guess.
 *
 * IT WAS THE FIRST CHARACTER, and that was a proxy for "is this an address" which
 * is wrong in the direction that matters. A 2.4 server name may start with a
 * DIGIT -- node_main.c's --name says exactly that, "must start with a letter or
 * digit", and irc_serve_server_name_valid() enforces it -- so `1peer` was read as
 * an address, was refused by the address parser, and lost its SNI. It also lost
 * its certificate NAME CHECK, which is a security boundary and is tls_peer_verify()
 * 's business below; the two were the same mistake reached twice.
 *
 * THE COST: one inet_pton() per OUTBOUND peer dial, on a path that has already run
 * a getaddrinfo() and a connect(). It is asked once per dial rather than per poll
 * tick, so it is on no hot path, and it is two library calls that cannot fail in a
 * way this code has to handle. */
static int peer_name_is_ip_literal(const char *name)
{
    struct in_addr v4;
    struct in6_addr v6;

    if (name == NULL || name[0] == '\0') {
        return 0;
    }
    return (inet_pton(AF_INET, name, &v4) == 1 ||
            inet_pton(AF_INET6, name, &v6) == 1)
               ? 1
               : 0;
}

/* ---------------------------------------------------------------------------
 * THE NAME CHECK ITSELF, and the ONE place it can fail closed
 * ---------------------------------------------------------------------------
 * RETURNS 0 when the handshake may proceed and -1 when the link must be REFUSED,
 * and the return value is the whole point of this function's signature.
 *
 * WHY IT RETURNS ANYTHING AT ALL. This used to return void, print a line when the
 * name could not be configured, and let the handshake continue anyway. A peer name
 * beginning with a DIGIT went to X509_VERIFY_PARAM_set1_ip_asc() because that is
 * what the first-character test chose, was refused by it, and left the verify
 * parameter carrying NO NAME AT ALL. That is not a weaker check, it is NO check:
 * OpenSSL verifies the chain, finds no expected name to compare against, and
 * succeeds. The comment that stood here said the failure "is reported by the
 * verification itself, which will fail with CERTIFICATE_VERIFY_FAILED", and that
 * was FALSE -- demonstrated end to end, with a CA-issued certificate for
 * `DNS:someone.else` presented by a peer this node dialled as `1peer`, and the
 * link reported `link_established: peer=1peer`. On such a link peer authentication
 * degraded to "chains to our mesh CA", and because the federation secret is
 * mesh-wide, ANY node holding ANY CA-issued certificate could impersonate ANY
 * digit-named peer: read and inject the message stream, and be presented as that
 * peer to third parties.
 *
 * So: a name this node cannot configure a check for is a REFUSAL. It is the only
 * correct answer to "what should this handshake be verified against?" when the
 * answer is nothing. */
static int tls_peer_verify(SSL *ssl, tls_node_t *node, const char *peer_host,
                           int fd)
{
    X509_VERIFY_PARAM *param;
    int configured;

    if (node->insecure != 0) {
        /* The OPERATOR SAID SO. SSL_VERIFY_NONE plus no name check: an
         * unverifiable peer is accepted and the fact is on the wire below, so a
         * reader of the log can tell an insecure link from a verified one without
         * reading the command line. */
        SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
        printf("[observable] tls_peer_verify: fd=%d mode=INSECURE "
               "reason=--tls-insecure\n", fd);
        return 0;
    }
    SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
    param = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(param,
                                    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (peer_host == NULL || peer_host[0] == '\0') {
        /* NO NAME AT ALL is the same failure as an unusable name, and it is
         * refused the same way: an outbound peer link that cannot say which peer
         * it dialled has no identity to check a certificate against.
         *
         * THROUGH THE SHIPPED BINARY THIS ARM IS UNREACHABLE, and saying so is
         * part of the point: server_dial_progress() passes link->name, and
         * fed_link_new() refuses a name irc_serve_server_name_valid() rejects, so
         * the name is never NULL and never empty on this path. It is here because
         * the lesson of the bug above is that an unreachable-looking arm which
         * PROCEEDS is what the bug was -- and because tls_backend_starttls() is a
         * public entry point that forwards a NULL host. */
        printf("[observable] tls_peer_name: fd=%d host=%s reason=NO_NAME_TO_CHECK "
               "action=REFUSE\n",
               fd, (peer_host != NULL) ? peer_host : "(null)");
        return -1;
    }
    /* ADDRESS FIRST, FOR ANY INPUT, and the ORDER is the fix rather than a
     * preference: X509_VERIFY_PARAM_set1_ip_asc() parses its argument and rejects
     * anything that is not an address literal WITHOUT TOUCHING `param`, so asking
     * it first costs a name nothing and is the only correct answer for an address.
     * The byte-0 discriminator that used to stand here cannot tell `1peer` (a
     * legal server name) from `127.0.0.1` (an address), which is the whole defect.
     *
     * A peer name that is BOTH is impossible -- an IPv6 literal contains colons,
     * which irc_serve_server_name_valid() refuses -- so there is no input for which
     * this configures the wrong kind of check. */
    configured = X509_VERIFY_PARAM_set1_ip_asc(param, peer_host);
    if (configured != 1) {
        configured = X509_VERIFY_PARAM_set1_host(param, peer_host, 0);
    }
    if (configured != 1) {
        /* BOTH FORMS REJECTED, so there is nothing this link could be verified
         * against and continuing would mean continuing with no name check. Refused.
         *
         * THE COST, stated because fail-closed is not free: a peer name this node
         * cannot parse is a link that never comes up rather than one that comes up
         * unauthenticated. Through the shipped binary the name has already been
         * validated, so this arm is a BACKSTOP rather than the load-bearing half of
         * the fix. The digit-named peer case is fixed by the RETRY above -- an
         * address parse that declines `1peer` followed by a hostname parse that
         * accepts it -- and not by this line. */
        printf("[observable] tls_peer_name: fd=%d host=%s "
               "reason=NOT_A_NAME_OR_IP action=REFUSE\n", fd, peer_host);
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * CERTIFICATE REVOCATION, AND WHY IT IS OCSP STAPLING AND NOT A CRL FETCH
 * ---------------------------------------------------------------------------
 * THE GAP THIS CLOSES, in the auditor's terms: a revoked certificate that chains
 * to the configured CA was accepted until it EXPIRED, so the blast radius of a
 * stolen peer key was bounded only by the leaf's notAfter, and nothing logged when
 * that window closed. Both halves are addressed below -- the check, and the
 * notAfter line.
 *
 * WHY OCSP STAPLING AND NOT CRL, in one sentence: a CRL is a DISTRIBUTION POINT,
 * and an unreachable distribution point has to be treated as revoked or the check
 * is decorative -- which means fetching it, and 3.4 forbids a blocking call inside
 * the event loop. A staple is bytes the peer already had, so nothing is fetched,
 * nothing can be unreachable, and the failure policy is one boolean.
 *
 * ---------------------------------------------------------------------------
 * STAPLED, NEVER FETCHED, and this is the load-bearing constraint
 * ---------------------------------------------------------------------------
 * NOT ONE FUNCTION BELOW OPENS A SOCKET, RESOLVES A NAME, OR READS A FILE. The
 * staple is read ONCE in tls_backend_node_init(), which runs from main() before the
 * loop is armed; everything after that is arithmetic over DER the peer sent and an
 * X509_STORE this node loaded at startup. Concretely: there is no OCSP_sendreq*,
 * no OSSL_HTTP_REQ_CTX, no BIO_new_file and no getaddrinfo in this file's
 * revocation path, and no OCSP RESPONSE is ever issued by this process -- only
 * OCSP_RESPONSE *verifications*. tests/integration/test_tls_revocation.c asserts
 * the negative by reading the source with its comments stripped, which is the only
 * way to make the claim false-able: a call added here shows up as a failing test
 * rather than as a comment that has quietly stopped being true.
 *
 * THE COST, because a design with no cost is a design nobody has thought about:
 *
 *   1. A STALE STAPLE STAYS STALE until an operator replaces the file and restarts.
 *      Nothing refreshes it, and that is the point: the alternative is a refresh
 *      inside the loop. The consequence is that nextUpdate becomes a REAL deadline
 *      rather than an advisory one -- see the freshness rule below, which refuses a
 *      response with no nextUpdate at all -- so an operator who does not refresh
 *      finds out on the next link attempt, with a named reason.
 *   2. THE NODE MUST BE CONFIGURED ON BOTH ENDS. A node with no
 *      --tls-ocsp-staple has nothing to staple, so a strict peer's handshake gets
 *      no CertificateStatus and is refused with MISSING_STAPLE. Upgrading ONE side
 *      of a mesh therefore breaks peer links until both sides are configured, which
 *      is the real operational price of failing closed and the reason the startup
 *      line prints `ocsp_staple=` and --help states the remedy.
 *   3. THE RESPONDER'S OWN CERTIFICATE IS NOT AVAILABLE FOR CHAINING, because
 *      OpenSSL owns the parsed staple and exposes no accessor for the extra
 *      certificates inside it. Nothing here needs them: this is a verification and
 *      not an OCSP client.
 *
 * ---------------------------------------------------------------------------
 * ONLY THE OUTBOUND PEER-LINK PATH, and this is NOT INBOUND COVERAGE
 * ---------------------------------------------------------------------------
 * The check runs in the CLIENT role, once per handshake, after it completes. The
 * client role in this tree IS the outbound peer link: server_dial_progress() is the
 * only caller of transport_starttls_peer() with as_server == 0, and STARTTLS is
 * answered with as_server == 1.
 *
 * NOTHING HERE IS A STATEMENT ABOUT INBOUND CONNECTIONS. There is no inbound
 * client-certificate authentication to check a certificate against: the server
 * context is SSL_VERIFY_NONE and never asks for one, so a client certificate is not
 * verified against anything even when a client offers one. Revocation is therefore
 * MOOT inbound, not implemented inbound -- and building inbound mTLS is deliberately
 * NOT part of this pass, rather than being quietly implied by the word
 * `revocation=` appearing on the startup line. An operator should read that field
 * as exactly "revocation of a PEER's certificate on a link this node dialled" and
 * no more than that.
 *
 * ---------------------------------------------------------------------------
 * THE FAILURE POLICY, AND WHICH DIRECTION IS THE DEFAULT
 * ---------------------------------------------------------------------------
 * ONE BOOLEAN: staple_strict. 1 refuses the link when the status is missing, stale,
 * unverifiable or revoked; 0 prints the reason and continues. It is
 * `struct tls_node`'s field, the `tls_init` line's `revocation=`, and the whole of
 * --tls-staple-permissive.
 *
 * STRICT IS THE DEFAULT, so the INSECURE direction is the one that requires a flag.
 * That is a decision rather than an unexamined default, and the argument is the
 * auditor's: "an unreachable distribution point must be treated as revoked
 * (fail-closed) or the check is decorative." Permissive-by-default IS the decorative
 * check -- it accepts a revoked certificate and writes a line saying so, and every
 * operator who does not read the line believes they have revocation checking because
 * the startup output contains the word `revocation=`. A security feature whose
 * failure mode is a log line nobody reads is worse than a feature that is off,
 * because it changes what people believe about the thing they are running.
 *
 * THE ARGUMENT AGAINST, because there is a real one and this project argues both
 * sides in its comments rather than only the side it implemented. Permissive does
 * not break a mesh whose peers do not staple; STRICT DOES, on the day one side is
 * upgraded, and the operator's first symptom is a link that will not come up. That
 * is answered rather than dismissed:
 *
 *   - a REFUSAL IS NOT SILENT. It names MISSING_STAPLE on the wire, it is beside
 *     `revocation=` on the one startup line an operator reads, and --help says what
 *     to do about it. The alternative symptom is a link that comes up, carries
 *     traffic, and is unprotected against exactly the compromise the feature exists
 *     for -- which is a failure nobody reports because nothing looks broken.
 *   - the remedy is ONE option on each side, not a migration. Both nodes are this
 *     code and both take the flag, and `openssl ocsp` (or any CA) produces the file,
 *     so no operator needs a library this project does not have.
 *   - THE FLAG IS NAMED FOR THE DIRECTION IT MOVES YOU. --tls-staple-permissive is
 *     what an operator types when they mean it, which is the same rule
 *     --tls-insecure follows and the reason it exists. Naming the option after the
 *     strict policy would advertise a switch that changes nothing, because strict is
 *     already what you have.
 */

/* The name this node has for the peer on the far end, for a log line.
 *
 * conn_t::peer_name is set by server_dial_progress() BEFORE it calls
 * transport_starttls_peer(), so on this path it is always the link's server name --
 * which is also what tls_peer_verify() checked the certificate against, so the two
 * lines agree about which peer they are talking about. The fallback is for a
 * hand-called tls_backend_starttls_peer(), which is a public entry point and may be
 * handed a connection with no name. */
static const char *tls_peer_name_of(const conn_t *c)
{
    if (c == NULL || c->peer_name == NULL || c->peer_name[0] == '\0') {
        return "(unnamed)";
    }
    return c->peer_name;
}

/* THE STAPLED RESPONSE'S BYTES, through the one accessor that exists in every
 * OpenSSL this project supports.
 *
 * IT IS THIS MACRO AND NOT SSL_get0_ocsp_resp() because that function was REMOVED
 * in OpenSSL 4.0, and its replacement does not do the same job:
 * SSL_get0_tlsext_status_ocsp_resp_ex() hands back an already-PARSED
 * STACK_OF(OCSP_RESPONSE) * through its argument and returns the COUNT as a long, so
 * it is not a drop-in for a (pointer, length) pair and assigning it to one is a
 * -Wint-conversion error rather than a silent mistake. The ctrl both generations
 * share, SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP, has the same (pointer, length)
 * shape in both:
 *
 *   1.1.1 / 3.x   *(unsigned char **)parg = sc->ext.ocsp.resp;  return resp_len;
 *   4.x           i2d() the first parsed response into a buffer OpenSSL owns,
 *                 writes the pointer, and returns that buffer's length.
 *
 * THE BUFFER IS OPENSSL'S IN BOTH, so it must NOT be freed here: it is released by
 * SSL_free() when the transport's close op runs. Copying it would buy nothing and
 * cost one allocation per handshake. */
static int tls_staple_bytes(SSL *ssl, const unsigned char **out, long *len)
{
    unsigned char *buf = NULL;
    long n = SSL_get_tlsext_status_ocsp_resp(ssl, &buf);

    *out = NULL;
    *len = 0L;
    if (n <= 0L || buf == NULL) {
        return 0;
    }
    *out = buf;
    *len = n;
    return 1;
}

/* An ASN1_TIME as ISO-8601 UTC, into `out`. Returns `out` always, so a caller can
 * use it inline: a time this function cannot read prints as "unreadable" rather than
 * as a number, because the question being answered is "when does my exposure window
 * close" and a confident wrong answer is the failure mode that matters there.
 *
 * ASN1_TIME_to_tm() fills a struct tm whose tm_year is year-minus-1900, so the
 * +1900 below is the conversion and not a fudge. The function is 1.1.1-era and
 * present in 3.x and 4.x, which is the floor src/CMakeLists.txt declares. */
static const char *tls_time_text(char *out, size_t cap, const ASN1_TIME *t)
{
    struct tm tm;

    if (t == NULL) {
        (void)snprintf(out, cap, "absent");
        return out;
    }
    if (ASN1_TIME_to_tm(t, &tm) != 1) {
        (void)snprintf(out, cap, "unreadable");
        return out;
    }
    /* EVERY FIELD IS REDUCED BY A CONSTANT MODULO BEFORE IT IS PRINTED, and that is
     * for the compiler rather than for the format. A bare `tm.tm_year + 1900` is an
     * int of unknown range to a value-range analysis, so `%04d` is a MINIMUM width
     * rather than a maximum, and gcc-16 computed a worst case of 73 bytes into this
     * function's 32-byte buffer -- a refusal, under -Werror, on a build whose two
     * clangs report nothing at all. Reducing each field with an unsigned modulo
     * makes the maximum the minimum: four digits and five pairs of two, six literal
     * characters and a NUL is 21 bytes, and 21 <= 32 is arithmetic a compiler can
     * do without a model of struct tm.
     *
     * AND IT IS NOT COSMETIC. tm_mday, tm_hour and the rest are whatever the library
     * left there, and a notAfter that ASN1_TIME_to_tm() accepted but that carries
     * nonsense would otherwise print eleven characters into a field an operator
     * reads as a date. The modulo makes the formatter's contract TRUE rather than
     * merely hoped for: the result is always a well-formed ISO-8601 instant, and for
     * an impossible field it is the wrong instant rather than a broken line. */
    (void)snprintf(out, cap, "%04u-%02u-%02uT%02u:%02u:%02uZ",
                   (unsigned)((unsigned long)((long)tm.tm_year + 1900L) % 10000UL),
                   ((unsigned)tm.tm_mon + 1u) % 100u, (unsigned)tm.tm_mday % 100u,
                   (unsigned)tm.tm_hour % 100u, (unsigned)tm.tm_min % 100u,
                   (unsigned)tm.tm_sec % 100u);
    return out;
}

/* Seconds from NOW until `t`, as text. "unknown" when ASN1_TIME_diff() cannot answer.
 *
 * NULL is passed for `from`, which is the library's documented way of saying "from
 * the current time", and real out-parameters are passed rather than NULL because
 * OPENSSL_gmtime_diff() -- the function behind it -- has changed its mind about
 * NULL over the versions this file is compiled against. */
static const char *tls_seconds_text(char *out, size_t cap, const ASN1_TIME *t)
{
    int day = 0;
    int sec = 0;

    if (t == NULL || ASN1_TIME_diff(&day, &sec, NULL, t) != 1) {
        (void)snprintf(out, cap, "unknown");
        return out;
    }
    (void)snprintf(out, cap, "%ld", (long)day * 86400L + (long)sec);
    return out;
}

/* ---------------------------------------------------------------------------
 * THE CHECK. Returns 0 to let the handshake stand, -1 to refuse the link.
 *
 * THE ORDER OF THE STEPS IS THE ORDER OF WHAT CAN BE TRUSTED, and each one is
 * decided only after the ones above it have been:
 *
 *   1. the leaf and its ISSUER, taken from the chain OpenSSL already verified and
 *      this node's own store -- never from the staple, which is the untrusted input;
 *   2. the RESPONSE STATUS: a responder answering "I don't know" or "try later" has
 *      not answered, and OCSP_basic_verify() returns 1 for those, so the status is
 *      checked explicitly rather than inferred from a successful verification;
 *   3. the SIGNATURE and the SIGNER'S AUTHORITY, via OCSP_basic_verify() against
 *      this node's store. This is what makes a response signed by somebody who is
 *      not the issuer -- or by a responder the issuer never authorised -- a refusal
 *      rather than a status;
 *   4. the CERTID: the response must be about THIS certificate. The digest inside a
 *      CertID is the responder's choice and OpenSSL exposes no portable accessor for
 *      it (OCSP_SINGLERESP is opaque), so SHA-256 and SHA-1 are both tried and one
 *      must match. That widens which responses are UNDERSTOOD, not which
 *      certificates are ACCEPTED, because the leaf and the issuer on both sides of
 *      the comparison are the ones this node verified for itself;
 *   5. FRESHNESS: nextUpdate must EXIST and must not have passed. A response with no
 *      nextUpdate is refused rather than accepted, and that is the whole reason the
 *      check is worth anything -- OCSP_check_validity() returns 1 when nextUpdate is
 *      absent, which would make an undated staple valid for ever and reproduce the
 *      original gap with more steps around it;
 *   6. the STATUS ITSELF: GOOD is the only value that passes.
 *
 * THE COST, once per outbound peer handshake: four digests of the issuer's name and
 * key (two per candidate CertID algorithm), one signature verification and one
 * chain verification of the responder's certificate. No syscall, no lock, no
 * allocation that outlives the call. On a node with a handful of peers re-dialling
 * every few minutes this is nothing; it is not on the message path and it is not a
 * hot path.
 *
 * AND IT RUNS ONCE per connection rather than once per read: conn_t::tls_checked is
 * the latch. The alternative -- asking after every SSL_read() -- would re-verify a
 * signature per buffered record and print a fresh verdict every time, which is how
 * a diagnostic becomes noise. The latch is set BEFORE the check runs, so a refusal
 * cannot be reached twice. */
static int tls_peer_revocation(conn_t *c, SSL *ssl, tls_node_t *node)
{
    X509 *leaf = NULL;
    X509 *issuer = NULL;
    X509_STORE *store = NULL;
    OCSP_RESPONSE *resp = NULL;
    OCSP_BASICRESP *bs = NULL;
    OCSP_CERTID *cid = NULL;
    STACK_OF(X509) *sent = NULL;
    const OPENSSL_STACK *chain = NULL;
    const unsigned char *raw = NULL;
    const unsigned char *p = NULL;
    ASN1_GENERALIZEDTIME *thisupd = NULL;
    ASN1_GENERALIZEDTIME *nextupd = NULL;
    long raw_len = 0L;
    int pass;
    int status = 0;
    int reason_code = 0;
    int found = 0;
    int good = 0;
    int rc;
    const char *peer = tls_peer_name_of(c);
    const char *verdict = "NO_CHECK";
    const char *why = "";
    const char *policy = (node->staple_strict != 0) ? "strict" : "permissive";
    char not_after[48];
    char not_after_in[48];
    char this_text[48];
    char next_text[48];

    leaf = SSL_get1_peer_certificate(ssl);
    if (leaf == NULL) {
        /* UNREACHABLE ON A VERIFIED LINK, and refused anyway for the reason
         * tls_peer_verify()'s no-name arm gives: a state that PROCEEDS is what the
         * bug there was. A client-role handshake with no peer certificate means the
         * chain was never verified, and a revocation status has nothing to be
         * ABOUT. */
        verdict = "NO_CERTIFICATE";
        why = "peer sent no certificate";
        goto done;
    }
    /* THE ISSUER AND THE STORE. The issuer is the SECOND certificate of the chain
     * OpenSSL already verified, because a certificate with no issuer in its chain
     * is a directly-trusted leaf and there is nobody who could have issued a status
     * for it. That is a reading of the peer's own message, and it is safe to read
     * it that way only because both uses of it are checked against things this node
     * verified for itself: OCSP_basic_verify() below chains the signer to `store`,
     * and OCSP_cert_to_id() below produces a CertID that matches nothing unless the
     * certificate really was issued by the one chosen. A peer that lies about its
     * issuer gets a CertID that matches nothing or a signer that does not chain --
     * it cannot get a status for a certificate it does not hold.
     *
     * OPENSSL_sk_num()/OPENSSL_sk_value() ARE SPELLED OUT RATHER THAN THROUGH
     * sk_X509_num()/sk_X509_value(), and this is forced rather than preferred.
     * OpenSSL 4.0's typed stack macros expand through ossl_check_*_type() helpers
     * that the header marks unused, so under -Weverything EVERY use of an sk_X509_*
     * macro is `-Werror,-Wused-but-marked-unused` on clang 21, 23 and Apple's 21.
     * The alternative the project would otherwise take -- adding
     * -Wno-used-but-marked-unused -- is narrowing the project's own warning set to
     * accommodate a third-party header, which is the opposite of what that set is
     * for. The two functions below have no inline type-check wrapper, so they
     * compile clean on all three compilers and on OpenSSL 1.1.1, 3.x and 4.x. */
    store = SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl));
    sent = SSL_get_peer_cert_chain(ssl);
    chain = (const OPENSSL_STACK *)(const void *)sent;
    if (store == NULL || sent == NULL || OPENSSL_sk_num(chain) < 2 ||
        (issuer = (X509 *)OPENSSL_sk_value(chain, 1)) == NULL) {
        /* A SELF-SIGNED peer certificate -- which is what a two-node mesh of this
         * code is configured with, each node trusting the other's leaf directly --
         * has no separate issuer, so there is nobody who could have issued a status
         * for it. That is a TRUE STATEMENT about the certificate rather than a
         * failure of this check, and it is worth being precise about: a strict node
         * refuses such a link, and the fix is a CA, not a flag. */
        verdict = "NO_ISSUER";
        why = "self-signed peer certificate: nobody could have issued a status for "
              "it; give this mesh a CA";
        goto done;
    }
    if (!tls_staple_bytes(ssl, &raw, &raw_len)) {
        verdict = "MISSING_STAPLE";
        why = "peer stapled no OCSP response";
        goto done;
    }
    p = raw;
    resp = d2i_OCSP_RESPONSE(NULL, &p, raw_len);
    if (resp == NULL || OCSP_response_status(resp) != V_OCSP_CERTSTATUS_GOOD) {
        /* "try later" and "unauthorized" are not certificate statuses. Treating
         * "I could not find out" as "nothing to report" is the fail-open this whole
         * policy exists to prevent. */
        verdict = "BAD_RESPONSE";
        why = "response status is not CERTSTATUS_GOOD";
        goto done;
    }
    bs = OCSP_response_get1_basic(resp);
    if (bs == NULL) {
        verdict = "NO_BASIC_RESPONSE";
        why = "response carried no BasicOCSPResponse";
        goto done;
    }
    /* THE SIGNATURE AND THE SIGNER'S RIGHT TO SIGN. The candidates handed over are
     * the peer's own chain, which is where a conforming issuer's certificate
     * necessarily is, and OpenSSL also looks among the certificates embedded in the
     * response -- so a DELEGATED responder is found and then judged rather than
     * waved through. Zero flags is the strict choice: no OCSP_NOINTERN (the signer
     * must be trusted, not merely asserted), no OCSP_NOVERIFY, no OCSP_TRUSTOTHER.
     * The trust decision is ocsp_verify_signer()'s, and it builds to `store` with
     * the OCSP_HELPER purpose -- so a response signed by anybody this node cannot
     * chain to is refused, which is the case that matters and the one
     * tests/integration/test_tls_revocation.c drives with a rogue responder.
     *
     * PASSING THE PEER'S CHAIN IS NOT A TRUST DECISION. `certs` is OpenSSL's
     * "additional certificates to consider while finding the signer", and every
     * certificate an attacker could put there is one they could equally have put in
     * the Certificate message; the chain still has to terminate in this node's
     * store. What it buys is that a peer which sends leaf + CA -- which is what
     * --tls-cert is for, and what every real deployment has -- is verifiable without
     * this file inventing a stack of its own. */
    if (OCSP_basic_verify(bs, sent, store, 0) != 1) {
        ERR_clear_error();
        verdict = "UNVERIFIED";
        why = "signature or signer did not verify against the configured store";
        goto done;
    }
    /* THE CERTID, BOTH DIGESTS. See step 4 above. Whichever the responder chose,
     * the response must be a status for the leaf this node verified against the
     * issuer it resolved itself. */
    for (pass = 0; pass < 2 && found == 0; pass++) {
        const EVP_MD *md = (pass == 0) ? EVP_sha256() : EVP_sha1();

        if (cid != NULL) {
            OCSP_CERTID_free(cid);
            cid = NULL;
        }
        cid = OCSP_cert_to_id(md, leaf, issuer);
        if (cid == NULL) {
            break;
        }
        thisupd = NULL;
        nextupd = NULL;
        status = 0;
        reason_code = 0;
        if (OCSP_resp_find_status(bs, cid, &status, &reason_code, NULL, &thisupd,
                                  &nextupd) == 1) {
            found = 1;
        }
    }
    if (found != 1) {
        ERR_clear_error();
        verdict = "CERTID_NOT_FOUND";
        why = "no status for this certificate under SHA-256 or SHA-1";
        goto done;
    }
    /* FRESHNESS, AND nextUpdate IS MANDATORY. See step 5 above; that comment is the
     * argument. The (0, -1) arguments are "no clock-skew allowance, and no maximum
     * age beyond nextUpdate", so the responder's own deadline is the only deadline
     * this node applies. */
    if (nextupd == NULL) {
        verdict = "NO_NEXT_UPDATE";
        why = "response carries no nextUpdate, so its freshness is unbounded";
        goto done;
    }
    if (OCSP_check_validity(thisupd, nextupd, 0L, -1L) != 1) {
        ERR_clear_error();
        verdict = "STALE";
        why = "now is outside [thisUpdate, nextUpdate]";
        goto done;
    }
    if (status != V_OCSP_CERTSTATUS_GOOD) {
        /* A GENUINELY REVOKED CERTIFICATE. This is the case the whole feature
         * exists for, and it is the one a response signed by the issuing CA and
         * carrying V_OCSP_CERTSTATUS_REVOKED produces: the signature verifies, the
         * signer is authorised, the CertID matches this leaf, and the answer is
         * still no. tests/integration/test_tls_revocation.c builds exactly that. */
        verdict = "REVOKED";
        why = OCSP_crl_reason_str((long)reason_code);
        goto done;
    }
    verdict = "GOOD";
    why = "in force";
    good = 1;

done:
    /* THE EXPOSURE WINDOW, ON EVERY LINK, GOOD OR BAD. This is the line that did
     * not exist: notAfter is the outer bound on how long a compromised peer key is
     * useful EVEN IF revocation never fires, so an operator who cannot read it from
     * a log cannot answer "how long is my exposure". It prints on the refusal path
     * too, because the two questions are independent -- a link refused for a revoked
     * staple still says how long that certificate would have been good for, which is
     * what tells an operator whether the revocation mattered. */
    /* THE FORMATTERS' OWN BUFFERS ARE PASSED STRAIGHT TO printf(), with no
     * intermediate copy, and that is not a style choice: a `snprintf(dst, sizeof
     * dst, "%s", src)` where both are the same size is a 48-character string plus a
     * NUL into 48 bytes, which gcc-16's -Wformat-truncation correctly refuses. The
     * formatter already returns the buffer it filled, so the copy bought nothing but
     * the diagnostic. */
    printf("[observable] tls_peer_cert: fd=%d peer=%s not_after=%s not_after_in=%ss "
           "ocsp=%s\n",
           c->fd, peer,
           (leaf != NULL) ? tls_time_text(not_after, sizeof not_after,
                                         X509_get0_notAfter(leaf))
                          : "unknown",
           tls_seconds_text(not_after_in, sizeof not_after_in,
                            (leaf != NULL) ? X509_get0_notAfter(leaf) : NULL),
           verdict);
    rc = (good != 0 || node->staple_strict == 0) ? 0 : -1;
    /* THE VERDICT. `action=` is what this node DID, not what it recommends, and it is
     * decided HERE rather than by the caller so the two cannot disagree. In
     * permissive mode this is the whole of what the insecure mode does: the link
     * stands, the reason is on the wire, and the line above has already said how long
     * the window is. */
    printf("[observable] tls_peer_revocation: fd=%d peer=%s status=%s policy=%s "
           "action=%s this_update=%s next_update=%s detail=\"%s\"\n",
           c->fd, peer, verdict, policy, (rc == 0) ? "ACCEPT" : "REFUSE",
           tls_time_text(this_text, sizeof this_text, (ASN1_TIME *)thisupd),
           tls_time_text(next_text, sizeof next_text, (ASN1_TIME *)nextupd), why);
    if (cid != NULL) {
        OCSP_CERTID_free(cid);
    }
    if (resp != NULL) {
        OCSP_RESPONSE_free(resp);
    }
    if (leaf != NULL) {
        X509_free(leaf);
    }
    /* NEITHER `issuer` NOR `sent` IS FREED, and that is not a leak: both are
     * BORROWED from the SSL, which owns them and releases them when the transport's
     * close op runs SSL_free(). There is exactly one owner of every certificate in
     * this function and it is not here. `store` belongs to the SSL_CTX and is
     * released with it. */
    return rc;
}

/* The post-handshake gate: 0 to carry on, -1 to refuse the link.
 *
 * IT IS CALLED FROM BOTH ARMS of the transport -- the handshake pass in tls_send()
 * and the first read in tls_recv() -- because a handshake can complete on either,
 * and whichever it was, the check runs ONCE. conn_t::tls_checked is the latch. */
static int tls_after_handshake(conn_t *c, SSL *ssl)
{
    tls_node_t *node = (tls_node_t *)c->owner->tls;

    if (SSL_in_init(ssl) != 0 || c->tls_checked != 0) {
        return 0;
    }
    /* THE SERVER ROLE IS NOT CHECKED, and this line is the whole of "ONLY THE
     * OUTBOUND PEER-LINK PATH" -- see the block comment above, which is where the
     * argument lives.
     *
     * IT IS NOT COSMETIC, and the version without it is instructive: this gate was
     * missing on the first run and every handshake broke, because a server-role SSL
     * has NO peer certificate to have a status about (the server context is
     * SSL_VERIFY_NONE and never asks for one), so the check reported NO_CERTIFICATE
     * on every inbound connection and -- in strict mode -- closed it. The peer saw an
     * unexplained "unexpected eof while reading" and the operator saw a revocation
     * failure for a certificate that was never sent.
     *
     * So the gate also has to SILENCE the check rather than merely skip its verdict.
     * An inbound client connection that printed `revocation=` or `status=` would be
     * a line claiming coverage this program does not have, and
     * tests/integration/test_tls_revocation.c asserts the absence on the accepting
     * node -- which is the only way "inbound is not covered" can be false-able. */
    if (SSL_is_server(ssl) != 0) {
        return 0;
    }
    c->tls_checked = 1;
    /* --tls-insecure IS AN EXEMPTION, and it is an exemption rather than an
     * oversight because there is nothing to check: SSL_VERIFY_NONE means no chain
     * was verified, so there is no verified issuer for a status to be ABOUT, and
     * running the check anyway would refuse every link on a node the operator
     * explicitly asked not to verify. It says so on the wire rather than being
     * silent, and the startup line's revocation=none is the same fact. */
    if (node->insecure != 0) {
        printf("[observable] tls_peer_revocation: fd=%d peer=%s status=NOT_CHECKED "
               "policy=none action=ACCEPT detail=\"--tls-insecure: the peer "
               "certificate was not verified, so there is no chain for a status to "
               "be about\"\n",
               c->fd, tls_peer_name_of(c));
        return 0;
    }
    return tls_peer_revocation(c, ssl, node);
}

/* ---------------------------------------------------------------------------
 * STAPLING THIS NODE'S CERTIFICATE, and WHY IT NEEDS A CALLBACK
 * ---------------------------------------------------------------------------
 * OpenSSL does not staple a response merely because you set one. On the SERVER side
 * three things have to be true, and only the first of them is documented in the
 * man pages; the other two were found in the source, which is why this comment
 * quotes it:
 *
 *   1. SSL_CTX_set_tlsext_status_cb() IS REGISTERED. `tls_parse_ctos_status_request()`
 *      -- the code that reads the client's status_request extension -- begins with
 *      "we only care about this extension if the application registered a callback",
 *      and RETURNS WITHOUT READING ANYTHING when no callback is registered. So with
 *      no callback a client that asks for a status is asking a node that has never
 *      heard of the question: `openssl s_client -status` reports "OCSP responses: no
 *      responses sent" and nothing in the handshake fails. A node that staples
 *      nothing and a node whose staple was silently dropped are indistinguishable on
 *      the wire, which is why this arm exists rather than an SSL_CTX_set_* call at
 *      the accept site.
 *   2. THE CALLBACK RETURNS SSL_TLSEXT_ERR_OK AND A RESPONSE IS ATTACHED.
 *      `tls_handle_status_request()` sets `status_expected` only on that return AND
 *      only if the response list is non-empty, so attaching the bytes and returning
 *      OK are both load-bearing.
 *   3. THE RESPONSE IS ABOUT THE CERTIFICATE BEING SENT. Since 3.x,
 *      `ossl_get_ocsp_response()` looks the response up by matching the certificate
 *      about to go out -- its serial number, and the hash of its issuer's name under
 *      the digest the response itself declares -- and returns nothing when no
 *      SingleResponse matches. So a staple that does not cover this node's own leaf
 *      is dropped silently, which is the right behaviour and worth knowing before
 *      spending an afternoon on it.
 *
 * SO THE STAPLE IS ATTACHED HERE, from the callback, rather than at accept. That is
 * also the only correct order: the callback runs after the certificate has been
 * chosen and after the cipher, which is when (3) above can be satisfied at all.
 *
 * THE COST, once per server handshake that asks for a status: one d2i of the staple
 * under OpenSSL 4.x (which parses on set) or one pointer store under 3.x, plus the
 * bytes going on the wire. No syscall, no allocation this file owns. */
static int tls_status_cb(SSL *ssl, void *arg)
{
    tls_node_t *node = (tls_node_t *)arg;

    /* NO STAPLE CONFIGURED IS AN HONEST "NO", NOT A FAILURE. SSL_TLSEXT_ERR_NOACK
     * tells OpenSSL not to answer the status_request at all, which is exactly the
     * state a node with no --tls-ocsp-staple is in. The alternative -- returning
     * OK with nothing attached -- would send an empty CertificateStatus and put a
     * malformed message on the wire. */
    if (node == NULL || node->staple == NULL) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    (void)SSL_set_tlsext_status_ocsp_resp(ssl, node->staple, (long)node->staple_len);
    return SSL_TLSEXT_ERR_OK;
}

/* ---------------------------------------------------------------------------
 * READ THIS NODE'S OWN STAPLE, ONCE, AT STARTUP
 * ---------------------------------------------------------------------------
 * The file is DER or PEM; both are accepted because an operator who made one with
 * `openssl ocsp -respin` has a .pem and an operator who sliced the bytes has a .der,
 * and refusing one of them on a format technicality is the kind of thing that ends
 * with a node running with revocation off.
 *
 * IT MUST PARSE HERE OR THE NODE DOES NOT START, and that is the certificate's own
 * rule rather than a new one: a staple this node cannot read is a staple it cannot
 * staple, and a node that staples nothing while its peers verify is a node whose
 * links fail with MISSING_STAPLE naming a cause the operator cannot see from the
 * peer end.
 *
 * THE BYTES ARE COPIED out of the BIO and owned by `struct tls_node`, because
 * OpenSSL stores the pointer rather than the bytes (see the field's comment) and
 * the BIO's buffer does not outlive this function.
 *
 * tests/integration/test_tls_revocation.c counts this function's callers to keep it
 * that way: two occurrences of the name means the definition and one call site. */
static int tls_load_staple(const char *path, unsigned char **out, size_t *outlen)
{
    BIO *bio = NULL;
    BIO *mem = NULL;
    unsigned char *raw = NULL;
    unsigned char *base = NULL;
    const unsigned char *scan = NULL;
    unsigned char *der = NULL;
    OCSP_RESPONSE *probe = NULL;
    char *name = NULL;
    char *hdr = NULL;
    unsigned char *body = NULL;
    const unsigned char *pemscan = NULL;
    long body_len = 0L;
    int raw_len = 0;
    int der_len = 0;

    *out = NULL;
    *outlen = 0u;
    /* ONE READ, BOUNDED. The file is an operator's, but an unbounded read of one is
     * still a thing to avoid, and OCSP_STAPLE_MAX is four times the largest DER that
     * could fit in a TLS CertificateStatus message -- so the cap cannot reject a
     * staple that would have gone on the wire. A file that exceeds it fails to parse
     * below and is refused by name, which is the right outcome rather than a
     * truncation. */
    bio = BIO_new_file(path, "rb");
    if (bio == NULL) {
        ERR_clear_error();
        printf("[observable] tls_init: state=FAILED path=%s reason=ocsp_staple\n",
               path);
        return -1;
    }
    raw = (unsigned char *)OPENSSL_malloc(OCSP_STAPLE_MAX);
    if (raw == NULL) {
        BIO_free(bio);
        printf("[observable] tls_init: state=FAILED path=%s reason=ocsp_staple\n",
               path);
        return -1;
    }
    raw_len = BIO_read(bio, raw, OCSP_STAPLE_MAX);
    BIO_free(bio);
    if (raw_len <= 0) {
        OPENSSL_free(raw);
        ERR_clear_error();
        printf("[observable] tls_init: state=FAILED path=%s "
               "reason=ocsp_staple_empty\n",
               path);
        return -1;
    }
    /* DER FIRST, THEN PEM. The order is a guess about the file rather than about
     * the operator: an `openssl ocsp -respin` writes PEM, and a sliced response is
     * DER, and refusing one of them on a format technicality is how a node ends up
     * running with revocation off.
     *
     * PEM_read_bio() IS SPELLED OUT RATHER THAN PEM_read_bio_OCSP_RESPONSE()
     * because the latter's macro expansion contains OpenSSL's own
     * `d2i_of_void *` compatibility cast, which clang's -Wcast-function-type-strict
     * reports as an error AT THIS FILE under -Weverything. PEM_read_bio() takes no
     * function pointer and has had this signature since 1.0.0, so the block is
     * picked out here and its bytes decoded below with the same direct d2i call the
     * DER arm uses -- one decode path, one place where the answer can be wrong.
     *
     * AND THE DECODED RESPONSE IS RE-ENCODED WITH i2d_ before it is kept. That is
     * one line more than "keep the bytes I read", and it is what makes DER and PEM
     * the same thing to everything downstream: `staple_len` is always the length of
     * a canonical DER encoding, and OpenSSL 4.0 -- which parses the staple when it
     * is set -- and OpenSSL 3.x -- which stores the pointer -- both then see bytes
     * of exactly the length declared. */
    /* `base` IS KEPT BECAUSE d2i ADVANCES ITS POINTER past what it consumed, so
     * `raw` is no longer the start of the buffer by the time the PEM arm wants to
     * re-read the whole file from the beginning. */
    base = raw;
    scan = raw;
    probe = d2i_OCSP_RESPONSE(NULL, &scan, (long)raw_len);
    if (probe == NULL) {
        ERR_clear_error();
        mem = BIO_new_mem_buf(base, raw_len);
        if (mem != NULL) {
            if (PEM_read_bio(mem, &name, &hdr, &body, &body_len) == 1 &&
                name != NULL && strcmp(name, "OCSP RESPONSE") == 0 && body != NULL) {
                /* THROUGH A SECOND POINTER, because d2i_OCSP_RESPONSE() takes a
                 * `const unsigned char **` and ADVANCES what it is given, while
                 * PEM_read_bio() filled an `unsigned char *`. One const copy is
                 * cheaper than a cast that drops it. */
                pemscan = body;
                probe = d2i_OCSP_RESPONSE(NULL, &pemscan, (long)body_len);
            }
            BIO_free(mem);
        }
        OPENSSL_free(name);
        OPENSSL_free(hdr);
        ERR_clear_error();
    }
    if (probe == NULL) {
        OPENSSL_free(raw);
        printf("[observable] tls_init: state=FAILED path=%s "
               "reason=ocsp_staple_unreadable\n",
               path);
        return -1;
    }
    der_len = i2d_OCSP_RESPONSE(probe, &der);
    OCSP_RESPONSE_free(probe);
    OPENSSL_free(raw);
    if (der == NULL || der_len <= 0) {
        printf("[observable] tls_init: state=FAILED path=%s "
               "reason=ocsp_staple_unencodable\n",
               path);
        ERR_clear_error();
        return -1;
    }
    *out = der;
    *outlen = (size_t)der_len;
    return 0;
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
    /* THE STAPLE, and it is freed HERE because OpenSSL only ever held a pointer to
     * it: SSL_set_tlsext_status_ocsp_resp() stores the address, so the bytes belong
     * to the node and the node owns them. This is the fourth arm of the "WHERE EVERY
     * SSL* IS FREED" accounting at the top of the file, and it is the only one of
     * the four that is not reached through a conn_t. */
    if (node->staple != NULL) {
        OPENSSL_free(node->staple);
        node->staple = NULL;
        node->staple_len = 0u;
    }
    /* NO X509_STORE_free HERE, and that is not an oversight. This file never
     * holds an X509_STORE at all: SSL_CTX_load_verify_locations() creates one and
     * the CONTEXT owns it, so SSL_CTX_free() releases it. Calling
     * X509_STORE_free() on a store this file does not have a pointer to would be
     * impossible, and inventing one to free would be a double free. */
    free(node);
}

/* ---------------------------------------------------------------------------
 * WHAT THIS NODE WILL DO WITH A PEER'S CERTIFICATE, IN ONE WORD
 * ---------------------------------------------------------------------------
 * This is the `verify=` field of the `tls_init` startup line, and it is FOUR states
 * rather than the two it was.
 *
 * It was two because it asked one question -- "is the policy chain-and-name?" -- and
 * answered the other three with the same word, NONE_WITHOUT_CA. That is wrong in a
 * way that matters operationally rather than cosmetically: a node configured with
 * BOTH --tls-ca and --tls-insecure prints NONE_WITHOUT_CA, which reads as "no CA
 * configured" to anyone grepping the startup output of exactly the node where the
 * distinction is the whole point. --tls-insecure returns from tls_peer_verify()
 * BEFORE the CA is consulted, so the CA is loaded, held, and never used -- and the
 * label said the store was absent.
 *
 * THE FOUR, and each is one thing an operator can act on:
 *
 *   PEER_CHAIN_AND_NAME             a CA is loaded and nothing overrides it, so a
 *                                   peer certificate is verified against that store
 *                                   AND against the link's server name.
 *   NONE_INSECURE_CA_CONFIGURED     --tls-insecure with a --tls-ca: the store is
 *                                   loaded and deliberately not consulted. This is
 *                                   the state that used to claim otherwise.
 *   NONE_INSECURE_NO_CA             --tls-insecure and no store at all: nothing
 *                                   would be verifiable, so nothing is.
 *   NONE_WITHOUT_CA                 no store and no override, so a peer link that
 *                                   requires TLS is refused by main() before it can
 *                                   be dialled -- which is why this label describes
 *                                   what would happen rather than what is checked.
 *
 * `revocation=` is printed beside all four, and is the same fact in all four -- but
 * it is its own field and its own function (tls_revocation_label below) rather than
 * something derived from this one, because "which peer certificate policy applies"
 * and "what happens to a revoked one" are separate questions with separate answers. */
static const char *verify_label_for(int have_ca, int insecure)
{
    if (have_ca != 0) {
        return (insecure != 0) ? "NONE_INSECURE_CA_CONFIGURED"
                               : "PEER_CHAIN_AND_NAME";
    }
    return (insecure != 0) ? "NONE_INSECURE_NO_CA" : "NONE_WITHOUT_CA";
}

/* ---------------------------------------------------------------------------
 * WHAT THIS NODE WILL DO ABOUT A REVOKED PEER, IN ONE WORD
 * ---------------------------------------------------------------------------
 * Three states, and each names a DIFFERENT thing rather than three spellings of
 * the same one:
 *
 *   staple-strict      a peer link is REFUSED unless the peer's stapled status is
 *                      verifiable, fresh and GOOD. The default, and the whole
 *                      subject of "THE FAILURE POLICY, AND WHICH DIRECTION IS THE
 *                      DEFAULT".
 *   staple-permissive  --tls-staple-permissive: the reason is logged and the link
 *                      stands. A revoked certificate is then accepted, which is
 *                      why the flag has to be typed.
 *   none               --tls-insecure: nothing is verified, so there is no chain
 *                      for a status to be ABOUT and asking for one would be
 *                      incoherent. `verify=NONE_INSECURE_*` on the same line says
 *                      the same thing from the other half.
 *
 * IT IS A FUNCTION rather than a third copy of the boolean at the print site,
 * because the startup line and --help have to agree and this is the one definition
 * they can both be checked against. */
static const char *tls_revocation_label(const tls_node_t *node)
{
    if (node->insecure != 0) {
        return "none";
    }
    return (node->staple_strict != 0) ? "staple-strict" : "staple-permissive";
}

int tls_backend_node_init(tls_node_t **out, const char *cert, const char *key,
                          const char *ca, int insecure, const char *staple,
                          int staple_strict)
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
    node->verify_label = verify_label_for(node->have_ca, node->insecure);

    /* THE STAPLE, and it is loaded AFTER the certificate and the store so a node
     * that cannot verify a peer has already refused before it reads a third file.
     * --tls-insecure does NOT skip it: an insecure node still SERVES stapled status
     * to peers that do verify it, and refusing to staple because this node chose
     * not to check would break the other side of a one-directional mistake. */
    if (staple != NULL && staple[0] != '\0') {
        if (tls_load_staple(staple, &node->staple, &node->staple_len) != 0) {
            tls_backend_node_free(node);
            return -1;
        }
    }
    /* THE POLICY BOOLEAN IS NORMALISED HERE rather than trusted from the caller, so
     * that every read of node->staple_strict downstream is a comparison against a
     * value that is either 0 or 1 and never "whatever the caller passed". */
    node->staple_strict = (staple_strict != 0) ? 1 : 0;
    /* THE STATUS CALLBACK, REGISTERED ON THE ACCEPT CONTEXT ONLY, and before any SSL
     * can be created from it. Registration is what makes this node READ the client's
     * status_request at all -- see tls_status_cb()'s comment for the three conditions
     * and why two of them are invisible from the man pages. The argument is the node,
     * so the callback can reach the staple, and the client context deliberately gets
     * no callback: a dialling node is asked for nothing by this protocol.
     *
     * TWO CALLS, NOT ONE: SSL_CTX_set_tlsext_status_cb() takes the callback and
     * SSL_CTX_set_tlsext_status_arg() takes its argument, which is a 1.1.1-era
     * split that still stands in 3.x and 4.x. */
    (void)SSL_CTX_set_tlsext_status_cb(node->srv, tls_status_cb);
    (void)SSL_CTX_set_tlsext_status_arg(node->srv, node);

    *out = node;
    /* ONE LINE, THE WHOLE POLICY. `verify=` is the peer-certificate policy this
     * node will apply, `ca=` is whether a trust anchor was configured, `ocsp_staple=`
     * is whether this node HAS a staple to offer its peers -- a separate fact from
     * whether it CHECKS one, and the one an operator upgrading one side of a mesh
     * needs to be able to read off the line -- and `revocation=` is the failure
     * policy itself: staple-strict, staple-permissive, or none when --tls-insecure
     * made the whole question moot.
     *
     * IT IS ON THIS LINE RATHER THAN ONLY IN A COMMENT because an operator who greps
     * the startup output should not have to read the source to learn what this node
     * will and will not refuse a peer for.
     *
     * AND `verify=` IS NOT TWO STATES, which is what it was. It read
     * NONE_WITHOUT_CA whenever the policy was not "chain and name" -- including
     * the case where a CA WAS configured and --tls-insecure overrode it, so the
     * label said "no CA configured" to anyone grepping for it on a node that had
     * one. Four states, and each names what is actually enforced. */
    printf("[observable] tls_init: state=READY ca=%s insecure=%d verify=%s "
           "ocsp_staple=%s revocation=%s\n",
           node->have_ca ? "configured" : "none", node->insecure,
           node->verify_label, (node->staple != NULL) ? "configured" : "none",
           tls_revocation_label(node));
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
    /* ONE NAME FOR THE NODE'S STATE, because this function now reads it in three
     * places and it was already being cast at each of them. The cast is from
     * `struct tls_node *` (declared in tls_backend.h, deliberately opaque) to this
     * file's own type; the `(void *)` in the middle is the -Wcast-qual-satisfying
     * shape the SNI comment below describes. It is ASSIGNED after the checks rather
     * than initialised, because at this point `c` may be NULL and `owner->tls` may
     * be NULL, and a dereference to initialise a local would turn a refused call
     * into a crash. */
    tls_node_t *node = NULL;

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
    node = (tls_node_t *)(void *)s->tls;
    /* ONE cast, and it is here rather than three times because the node's type is
     * opaque to this file's callers but not to itself. `-Wcast-qual` is satisfied
     * because the target is NOT const -- a const SSL_CTX * would be the bug this
     * cast is here to prevent, since the handshake mutates the context's
     * per-connection state. */
    ctx = as_server ? node->srv : node->cli;
    if (ctx == NULL) {
        return -1;
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        printf("[observable] tls_error: fd=%d op=SSL_new reason=allocation\n",
               c->fd);
        return -1;
    }
    /* SNI on the client side, from the peer this node dialled. Without it a peer
     * serving several names on one address cannot choose, and the certificate it
     * presents may be the wrong one for this link -- which then fails the NAME
     * check in tls_peer_verify() for a reason that looks like a misconfiguration
     * rather than a missing hint.
     *
     * NOT SENT FOR AN ADDRESS. RFC 6066 3's host_name is a "fully qualified domain
     * name" and an address literal is not one, so peer_name_is_ip_literal() decides
     * it by PARSING rather than by reading byte 0. The byte-0 test used to stand
     * here and it suppressed SNI for every peer whose name began with a digit --
     * including `1peer`, which is a legal 2.4 server name and a legal DNS label.
     * That is the same defect as the one tls_peer_verify() had, in the same commit
     * and for the same reason, so it is fixed here rather than left to be found
     * again.
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
        peer_name_is_ip_literal(peer_host) == 0) {
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
        /* NO STAPLE IS SET HERE, and the absence is deliberate: this node's staple is
         * attached by tls_status_cb() from the status callback, which OpenSSL invokes
         * after it has chosen the certificate -- the only point at which it can know
         * whether the response covers the certificate it is about to send. Setting it
         * here, before any handshake byte, would be earlier than that and therefore
         * earlier than the check that drops a response which does not match. */
        SSL_set_accept_state(ssl);
    } else {
        SSL_set_connect_state(ssl);
        /* OCSP STAPLING IS REQUESTED HERE, AND THE POSITION IS LOAD-BEARING: the
         * `status_request` extension belongs in the ClientHello, which is written by
         * the FIRST SSL_do_handshake() -- and for this transport that happens later,
         * on the poll loop's schedule, in tls_send()'s handshake pass. Calling this
         * inside that pass would send a ClientHello with no status_request in it, and
         * the peer would never staple anything: the request is not "when did you
         * last think about revocation" but a message this node is about to transmit.
         *
         * AN EMPTY `status_request` IS THE RIGHT THING TO SEND. RFC 6961 lets a
         * client include responder-id and CertID extensions; sending none asks the
         * peer for whatever status it has for the certificate it is about to
         * present, which is the stapling case and the only one this node has a
         * verifier for. A request with no extension would also be a request the
         * server's own CertID-matching (see tls_status_cb) could not satisfy for a
         * multi-certificate chain. */
        (void)SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
        if (tls_peer_verify(ssl, node, peer_host, c->fd) != 0) {
            /* THE SSL* IS RELEASED HERE RATHER THAN HANDED TO THE CONNECTION, and
             * this is the only place that can happen: c->t_ctx has NOT been assigned
             * yet, so nothing outside this function has ever held this pointer and
             * there is no second release. Assigning it and then failing would leave
             * the transport ops pointing at a freed SSL*, because conn_free() is the
             * one place that releases them and this is not it.
             *
             * Returning -1 is what makes the link FAIL rather than proceed with no
             * name check: server_dial_progress() closes the connection and marks
             * the dial FAILED, so it cannot reach ESTABLISHED and the retry spends
             * a budget rather than succeeding quietly on the next attempt. */
            printf("[observable] tls_peer_verify: fd=%d result=REFUSED "
                   "reason=NO_NAME_CHECK_CONFIGURED\n", c->fd);
            SSL_free(ssl);
            return -1;
        }
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
