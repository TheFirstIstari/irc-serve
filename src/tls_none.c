/* tls_none.c -- the TLS backend for a build WITHOUT TLS.
 *
 * THIS FILE IS THE WHOLE DEPENDENCY DECISION, so it is worth reading before it
 * is worth reading.
 *
 * The project had no third-party dependencies for eleven phases and the README
 * claimed it in three places. Adding OpenSSL makes the dependency optional
 * (`cmake -DWITH_TLS=ON`, default OFF) rather than mandatory, for three reasons
 * that are each a real cost avoided:
 *
 *   1. THE ZERO-DEPENDENCY BUILD STAYS BUILDABLE AND TESTABLE. Every CI runner
 *      in .github/workflows compiles the default configuration; making OpenSSL
 *      mandatory would mean every one of them grows a package installation step,
 *      and a runner that cannot install it fails the build rather than skipping
 *      the feature. With the default OFF, the default build is the one this
 *      project has always shipped and the one 82 tests exercise.
 *
 *   2. THE REGRESSION BAR IS ONLY WORTH HAVING IF IT IS THE DEFAULT. Phase 12's
 *      central promise is that plaintext is byte-identical. If TLS were on by
 *      default, "byte-identical" would be a claim about a configuration nobody
 *      runs, and the suite could not prove it.
 *
 *   3. A DEPLOYMENT THAT DOES NOT WANT TLS SHOULD NOT HAVE TO LINK IT. There is
 *      no server-side advantage to shipping a TLS stack you never enable.
 *
 * THE COST, stated rather than hidden: with the default build a client cannot
 * upgrade at all, so the `tls` and `sts` capabilities do not exist and STARTTLS is
 * answered 691. That is not a degradation to be papered over -- it is the honest
 * state of a node built without a crypto library -- and the startup line says so,
 * so an operator can tell it from a node with TLS that is misconfigured.
 *
 * NOTHING HERE IS A STUB THAT RETURNS SUCCESS. Every entry point refuses, loudly
 * and identifiably, because the failure mode this file exists to prevent is a
 * silently-insecure node: one that advertised `sts`, accepted a STARTTLS, and
 * then carried the bytes in the clear.
 */
#include "tls_backend.h"

#include <stdio.h>

int tls_backend_available(void)
{
    return 0;
}

int tls_backend_node_init(struct tls_node **out, const char *cert,
                          const char *key, const char *ca, int insecure)
{
    (void)cert;
    (void)key;
    (void)ca;
    (void)insecure;
    printf("[observable] tls_init: state=REFUSED reason=NOT_COMPILED_IN "
           "hint=rebuild_with_-DWITH_TLS=ON\n");
    if (out != NULL) {
        *out = NULL;
    }
    return -1;
}

void tls_backend_node_free(struct tls_node *node)
{
    (void)node; /* there is nothing this build allocated */
}

int tls_backend_starttls(conn_t *c, int as_server)
{
    (void)as_server;
    printf("[observable] tls_unavailable: fd=%d reason=NOT_COMPILED_IN "
           "hint=rebuild_with_-DWITH_TLS=ON\n",
           (c != NULL) ? c->fd : -1);
    return -1;
}

int tls_backend_starttls_peer(conn_t *c, int as_server, const char *peer_host)
{
    (void)as_server;
    (void)peer_host;
    printf("[observable] tls_unavailable: fd=%d reason=NOT_COMPILED_IN "
           "hint=rebuild_with_-DWITH_TLS=ON\n",
           (c != NULL) ? c->fd : -1);
    return -1;
}
