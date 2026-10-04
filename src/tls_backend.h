/* tls_backend.h -- the seam between the transport interface and a TLS library.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS HEADER EXISTS AND IS SO SMALL
 * ---------------------------------------------------------------------------
 * It has one function. That is the point of it, and the reason is a dependency
 * decision rather than an aesthetic one.
 *
 * This project had ZERO third-party dependencies for eleven phases and the
 * README said so in three places. Adding OpenSSL makes the dependency OPTIONAL
 * rather than mandatory (`-DWITH_TLS=ON`, default OFF), so the zero-dependency
 * build stays buildable and stays the one CI compiles on a runner that has no
 * OpenSSL development package installed. But "optional" must mean the rest of
 * the tree compiles unchanged in BOTH configurations, and it cannot: connection.c
 * has to be able to start a handshake, and cap.c has to be able to ask whether
 * TLS exists at all.
 *
 * So the question becomes "how few symbols does a TLS library need to expose to
 * the rest of this tree", and the answer is one: begin a handshake on a
 * connection. Everything else -- the contexts, the certificates, the
 * verification policy, the shutdown -- is behind it, in a file that is compiled
 * OUT of a no-TLS build entirely.
 *
 * The alternative, `#if IRC_WITH_TLS` scattered through connection.c, server.c,
 * cap.c and commands.c, would put the build option into four modules and make
 * "does the plaintext build still compile" a question about all four. This way it
 * is a question about ONE file.
 *
 * ---------------------------------------------------------------------------
 * WHAT A TLS BACKEND MUST PROVIDE, and it is a longer list than one function
 * ---------------------------------------------------------------------------
 * Phase 12's full seam is declared below. Two rules bind every entry point:
 *
 *   1. NOTHING IN HERE TOUCHES conn_t's buffers or conn_t's state machine. The
 *      backend is reached through transport_recv()/transport_send(), which own
 *      the buffers, and it publishes readiness through conn_want(). A backend
 *      that grew a second buffering path would be two I/O implementations rather
 *      than one transport with two encodings.
 *
 *   2. NOTHING IN HERE CLOSES A DESCRIPTOR. server_close_conn() is the single
 *      close site (3.4) and the backend has no way to reach it, which is why an
 *      SSL* is released by the transport's close op and not here.
 */
#ifndef IRC_TLS_BACKEND_H
#define IRC_TLS_BACKEND_H

#include "core/server.h"

/* The node's TLS state, opaque here. `struct server` holds one of these and is
 * the only thing that does; the layout is the backend's, for the same reason the
 * dedup table's layout is federation/dedup.c's. */
struct tls_node;

/* Is TLS compiled into this binary at all? The answer is a property of the BUILD
 * and is a compile-time constant on it, which is why it is a function and not a
 * macro: every caller wants it in the same place, and a macro would be a second
 * spelling (`IRC_WITH_TLS` and `tls_backend_available()`) of one fact that a
 * reader could see used two ways.
 *
 * `cap_available()` asks it. A node built without TLS does not advertise `sts`
 * or `tls`, which is cap.h's rule -- advertise only what is real -- and does not
 * answer STARTTLS at all. */
int tls_backend_available(void);

/* Load the node's certificate and key, and optionally a CA store for verifying
 * PEER certificates. Returns 0 and sets *out, or -1 having printed why.
 *
 * `insecure` is the --tls-insecure flag and it is the ONLY way this node will
 * accept a peer certificate it cannot verify. See tls_openssl.c's "VERIFY A PEER'S
 * CERTIFICATE" for the full list of what is and is not enforced, and for why a
 * missing --tls-ca on a peer link is a refusal rather than a fallback to system
 * roots.
 *
 * THE KEY'S PERMISSIONS ARE CHECKED HERE AND A VIOLATION REFUSES THE WHOLE
 * CONFIGURATION, before anything is loaded: a node that cannot prove its private key
 * is private must not come up offering a certificate. */
int tls_backend_node_init(struct tls_node **out, const char *cert,
                          const char *key, const char *ca, int insecure);

/* Release the node's contexts. Called from server_shutdown() beside the other "a
 * module's memory, released here" arms. Safe on NULL. */
void tls_backend_node_free(struct tls_node *node);

/* Replace `c`'s transport with TLS and START the handshake in role `as_server`.
 * Returns 0 when the handshake has begun (not when it has finished: this is a
 * nonblocking node and the handshake proceeds on the poll loop's schedule), -1
 * if TLS is unavailable or the backend could not allocate. On -1 the caller
 * marks the connection CLOSING.
 *
 * It is NOT idempotent, and the caller is responsible for the check: a second
 * STARTTLS on an upgraded connection is refused by the command handler, and an
 * implicit-TLS listener hands the socket over exactly once at accept. */
int tls_backend_starttls(conn_t *c, int as_server);

/* As tls_backend_starttls(), for an OUTBOUND peer link, naming the host this node
 * dialled so the peer's certificate can be checked against it.
 *
 * THE HOST IS NOT OPTIONAL INFORMATION. Chain verification answers "signed by
 * somebody I trust"; the name check is what makes it "signed by the peer I meant to
 * reach". A certificate for another name, signed by the same CA, satisfies the
 * chain and is the wrong node. tls_openssl.c's verification block gives the
 * argument; the short form is that a peer link whose certificate is not checked
 * against the address it was dialled at is encryption without authentication. */
int tls_backend_starttls_peer(conn_t *c, int as_server, const char *peer_host);

#endif /* IRC_TLS_BACKEND_H */
