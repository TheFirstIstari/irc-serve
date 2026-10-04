/* transport.h -- the ONE place a connection's bytes are read and written.
 *
 * Authority: this is Phase 12 of docs/SERVER_DESIGN.md and it exists because of
 * one structural fact about this tree -- the I/O seam was THREE call sites, not
 * the twelve `grep -n 'recv(\|send('` reports. Nine of those hits are comments,
 * three are in this phase's scope, and the two that are not (socket() in
 * server.c) do not move bytes:
 *
 *   core/connection.c   conn_fill()'s read, and conn_pump()'s write
 *   federation/link.c   fed_send_shutdown()'s drain-into-a-sink
 *
 * So the abstraction is three functions wide and both of them in connection.c
 * are one call each. That is worth saying because it is the reason the interface
 * is this small: an abstraction shaped by the number of call sites is one whose
 * invariants are checkable by reading the call sites, and there are three.
 *
 * ---------------------------------------------------------------------------
 * WHY IT IS A VTABLE AND NOT A BRANCH
 * ---------------------------------------------------------------------------
 * The alternative was `if (c->tls_active) { SSL_read(...) } else { recv(...) }`
 * at each of the three sites. It would have been twenty fewer lines and it is
 * the wrong shape, for two reasons that are both about what a future editor
 * would have to remember:
 *
 *   1. TLS is not the only thing this interface will ever carry. A second
 *      transport (a WebSocket framing, a test double that fails on demand) adds a
 *      branch to three sites instead of a file.
 *   2. The errno policy -- EINTR retried, EAGAIN is not an error -- is a fact
 *      about a SOCKET, and a TLS transport has no errno to speak of: SSL_read()
 *      reports "try again when writable" through SSL_get_error() and there is no
 *      errno for it at all. With a branch, each of the three sites would have to
 *      know which error protocol its current transport speaks. With a vtable, the
 *      transport answers in ONE vocabulary -- TRANSPORT_RETRY -- and the sites
 *      do not learn that the vocabulary has more than one dialect.
 *
 * ---------------------------------------------------------------------------
 * THE RETURN VOCABULARY, and why errno is NOT part of it
 * ---------------------------------------------------------------------------
 *   > 0                   that many bytes moved
 *   == 0                  the peer closed its half (recv only; EOF / close_notify)
 *   TRANSPORT_RETRY       nothing moved, nothing is wrong. The transport has
 *                         already published what it wants next via conn_want(),
 *                         so the caller does NOT need to know whether it wants
 *                         readability, writability, or both -- that distinction
 *                         lives inside the transport, which is the only place
 *                         that can know it.
 *   TRANSPORT_FATAL       the transport is finished. The caller marks the
 *                         connection CLOSING and the reaper closes the fd.
 *
 * A caller that mapped errno itself could not implement the second line: a TLS
 * transport that must wait for writability has no errno to set. The vocabulary is
 * therefore four values wide and errno appears nowhere in it, which is what makes
 * the contract implementable twice.
 *
 * ---------------------------------------------------------------------------
 * AND ONE MORE THING EVERY IMPLEMENTATION PROMISES, which is easy to lose in a
 * refactor and which Phase 12 lost once already
 * ---------------------------------------------------------------------------
 * **NEITHER CALL BLOCKS, whatever the descriptor's flags say.**
 *
 * The plaintext implementation therefore passes MSG_DONTWAIT rather than relying
 * on the descriptor having been made nonblocking at accept or dial time. It did
 * rely on that, and moving `fed_send_shutdown()`'s drain through this interface
 * turned the reliance into a hang: the drain had always passed MSG_DONTWAIT
 * itself, the transport took the call over, and two federation tests blocked in
 * `server_shutdown()` on a descriptor a test had made blocking. The guarantee
 * belongs to the INTERFACE and not to any one call site, because the call sites
 * are exactly the thing a refactor moves.
 *
 * 3.4's "nothing in the loop may block" is the same rule one level up, and a
 * blocking recv() in the read path would stall every client on the node.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS DOES NOT CLAIM
 * ---------------------------------------------------------------------------
 * It is not a stream abstraction, and it does not own the buffers: the read
 * buffer and the bounded write queue are conn_t's, connection.c's, and stay
 * there. Framing, the queue cap, the partial-write accounting and the EOF/error
 * arms of the event loop are all unchanged by this phase. The interface moves
 * BYTES and publishes INTENT, and nothing else.
 */
#ifndef IRC_CORE_TRANSPORT_H
#define IRC_CORE_TRANSPORT_H

#include <stddef.h>
#include <sys/types.h>

#include "core/connection.h"

/* Nothing moved and nothing is wrong. See the return vocabulary above. */
#define TRANSPORT_RETRY ((ssize_t)-1)
/* The transport cannot continue: bad certificate, handshake failure, EPIPE.
 * The caller marks CLOSING; the reaper closes the fd. */
#define TRANSPORT_FATAL ((ssize_t)-2)

/* ---------------------------------------------------------------------------
 * THE OPS, and the one rule about them
 * ---------------------------------------------------------------------------
 * Every op receives the conn_t because every op may need to publish intent
 * (conn_want) and every op but recv's needs the descriptor or the SSL. Passing
 * the conn rather than the fd is what lets an op be a function pointer with no
 * closure, and it is why `t_ctx` exists at all.
 *
 * THE RULE: an op that returns must have published the intent that should hold
 * NEXT, by calling conn_want() exactly once. A caller that cannot work out what
 * the transport needs next is not allowed to guess, which is the whole reason
 * this interface exists. recv and send both obey it; close() is the exception,
 * because a closed connection is out of the poll set before anything else looks.
 *
 * `recv` is handed a buffer that is never full -- connection.c grows or caps the
 * read buffer before the call -- which is the precondition that lets a TLS
 * transport return bytes it has already decrypted, without touching the
 * descriptor, for as long as it holds any. */
typedef struct transport_ops {
    ssize_t (*recv)(conn_t *c, void *buf, size_t len);
    ssize_t (*send)(conn_t *c, const void *buf, size_t len);
    void    (*close)(conn_t *c);
} transport_ops_t;

/* The three doors the rest of the tree uses. None of them closes a descriptor
 * (3.4: the reaper is the single close site) and none of them marks a
 * connection CLOSING. */
ssize_t transport_recv(conn_t *c, void *buf, size_t len);
ssize_t transport_send(conn_t *c, const void *buf, size_t len);
void    transport_close(conn_t *c);

/* Is this connection's transport TLS? Asked, not inferred from a flag, so that a
 * module which needs the answer has exactly one way to get it. False on a
 * build with TLS compiled out AND on a plaintext connection, and the two are
 * deliberately not distinguished: a caller asking this is asking "may I assume
 * the bytes are encrypted", and on a node without TLS the honest answer is no. */
int transport_is_tls(const conn_t *c);

/* Install the plaintext ops on a connection conn_new() has just calloc'd.
 *
 * IT IS CALLED BY conn_new() AND BY NOTHING ELSE, and that is what makes
 * "every connection has a transport from the instant it exists" true rather than
 * a thing each construction site has to remember. A caller that wants a different
 * transport calls transport_starttls() below, which swaps the ops. */
void transport_init_plaintext(conn_t *c);

/* Replace `c`'s transport with TLS and begin the handshake, in the given role.
 *
 *   as_server  1 for an accepted connection (implicit TLS, or a STARTTLS this
 *              node agreed to), 0 for an outbound peer link.
 *
 * Returns 0 on success -- which means the handshake has been STARTED, not
 * finished, because this is a nonblocking node and the handshake proceeds on the
 * poll loop's schedule from here -- and -1 if TLS is not available, in which case
 * the caller must mark the connection CLOSING and say so on the wire.
 *
 * It is NOT idempotent, and the caller is responsible for the check: a second
 * STARTTLS on an upgraded connection is refused by the command handler, and an
 * implicit-TLS listener hands the socket over exactly once at accept. */
int transport_starttls(conn_t *c, int as_server);

/* As transport_starttls(), for an OUTBOUND peer link, naming the host that was
 * dialled. The name is what lets the backend check the peer's certificate against
 * the address this node reached it at rather than against the chain alone: a
 * certificate for a different name, signed by the same CA, passes a chain check
 * and is the wrong node. See tls_backend.h's tls_backend_starttls_peer(). */
int transport_starttls_peer(conn_t *c, int as_server, const char *peer_host);

#endif /* IRC_CORE_TRANSPORT_H */
