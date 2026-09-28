/* server.h -- server_t: node lifecycle, registries, and the dial FSM.
 *
 * Authority: docs/SERVER_DESIGN.md sections 2.1 (identity), 2.2 (channels,
 * registry only), 2.3 (servers and peers), 2.4 (loop prevention and dedup --
 * the per-SERVER id counter), 3.3 (the message path) and 3.4 (the event loop
 * requirements: nonblocking dial, bounded queues, pre-resolved addresses, the
 * explicit FD_SETSIZE check).
 *
 * ---------------------------------------------------------------------------
 * WHY EVERYTHING IS SINGLE-THREADED
 * ---------------------------------------------------------------------------
 * There is no locking anywhere in this file and that is deliberate, not an
 * oversight (2: "everything below is single-threaded behind one event loop").
 * The state is node-LOCAL; federation is distribution, not concurrency, so
 * there is nothing for a lock to guard. Adding a thread would make every
 * registry here require a lock and would make the 2.2 single-writer ownership
 * rules far harder to reason about. The event loop, not the threading model,
 * is what makes federation tractable.
 *
 * ---------------------------------------------------------------------------
 * THE CONNECTION REGISTRY IS INDEXED BY fd
 * ---------------------------------------------------------------------------
 * `by_fd` is an array of FD_SETSIZE pointers, so lookup by descriptor is O(1)
 * with no hashing and no list walk. That is not premature optimisation: poll()
 * hands the loop a set of ready DESCRIPTORS, and a linear scan to turn each
 * one back into a connection is work the loop does on every readable socket on
 * every tick.
 *
 * It also buys the property that matters for correctness rather than speed: a
 * closed slot is set back to NULL and the conn_t is fully torn down, so a
 * descriptor the OS hands out again starts from a zeroed conn_new() and cannot
 * inherit a stale nick, state, write queue or read buffer. A registry that
 * kept freed nodes on a list would need a generation or liveness check for the
 * same guarantee.
 *
 * The cost of the choice is stated rather than hidden: iterating every
 * connection is O(FD_SETSIZE) per tick, because the index is a flat array and
 * the loop has no other way to enumerate. At a 50 ms tick that is about twenty
 * thousand pointer tests a second, which is not a cost worth optimising at
 * this scale -- and the FD_SETSIZE ceiling it inherits is the one 3.4 already
 * accepted in choosing poll() over epoll/kqueue.
 *
 * ---------------------------------------------------------------------------
 * PEER ADDRESSES MUST BE PRE-RESOLVED
 * ---------------------------------------------------------------------------
 * server_dial() takes an already-resolved struct sockaddr. It does not call
 * getaddrinfo() and there is no resolution helper here on purpose: any name
 * lookup inside the event loop stalls every client on the node (3.4). Phase 6
 * resolves peer addresses at configuration time and hands the results to
 * server_dial().
 *
 * ---------------------------------------------------------------------------
 * NO PEER USES THE DIAL PATH YET
 * ---------------------------------------------------------------------------
 * The dial state machine is complete and exercised, but nothing in the shipped
 * binary calls server_dial(): there are no peers until Phase 6, and this file
 * does not fabricate one. It lands now because retrofitting a nonblocking
 * connect() onto a working loop means touching the hot path; retrofitting a
 * blocking one means stalling every client.
 */
#ifndef IRC_CORE_SERVER_H
#define IRC_CORE_SERVER_H

#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "core/connection.h"

/* The version string this build reports in 002, 004 and PONG.
 *
 * It lives here, and not in the node's own banner, so that there is exactly
 * ONE copy of it: a version number stated twice in one binary is a version
 * number that will eventually be wrong in one of the two places, and 004 is
 * the one clients show to report bugs against. This is not a server-identity
 * system -- Phase 6 owns that, and it will want a real version/identity
 * surface -- it is the single constant the Phase 3 numerics need. */
#define IRC_SERVE_VERSION "irc-serve-0.1.0"

typedef struct server server_t;
typedef struct chan chan_t; /* opaque until Phase 4 (2.2) */
/* message_t comes from core/message.h, which connection.h includes. It is an
 * anonymous-struct typedef there, so it must not be forward-declared here. */

/* The message-path seam, 3.3:
 *
 *   socket read --> framing --> message_parse --> dispatch(cmd_t)
 *
 * dispatch is that last box. It is a function pointer rather than a switch so
 * the command surface can arrive in Phase 3 without this file changing, and
 * so a test can install its own policy for the one thing Phase 2 does not
 * implement: what the node SAYS. A NULL dispatch means exactly that -- the
 * loop still accepts, frames and parses, it just has no vocabulary to answer
 * with, which is the honest state of a Phase 2 node.
 *
 * The message is owned by the caller and is released as soon as dispatch
 * returns; a dispatch that needs it later must copy what it wants. */
typedef void (*server_dispatch_fn)(server_t *s, conn_t *c, const message_t *m);

/* The tick seam, 3.4: "the poll tick drives time". One hook, called from a
 * fixed point in the loop with a monotonic millisecond stamp, is where Phase 6
 * puts handshake timeouts, link liveness and dedup LRU eviction. The plumbing
 * lands in Phase 2 precisely because it is cheap now and expensive once the
 * loop carries a peer socket. NULL is fine and is the current state. */
typedef void (*server_tick_fn)(server_t *s, uint64_t now_ms);

/* Dial FSM states, 2.3: a peer link reuses the existing federation handshake
 * FSM for its own lifecycle, but the SOCKET has to get from "connect
 * initiated" to "writable" without blocking, and that transition is this
 * machine. No peer exists yet (see the file header). */
#define DIAL_FREE 0
#define DIAL_CONNECTING 1
#define DIAL_CONNECTED 2
#define DIAL_FAILED 3

typedef struct dial {
    int    fd;
    int    state;
    size_t slot;          /* index into server_t::dials */
    char   peer_name[IRC_MAX_SERVER_NAME + 1];
} dial_t;

/* The connection registry is a flat array indexed by descriptor, and poll()
 * caps a set at FD_SETSIZE descriptors, so the table holds exactly the
 * descriptors a poll set can name: 0 .. FD_SETSIZE-1. Descriptor FD_SETSIZE is
 * NOT registrable, which is the same bound the accept and dial sites enforce,
 * and it has to be the same number: a slot that could hold a descriptor poll()
 * would silently drop is a slot whose connection would be accepted and then
 * never served. */
#define SERVER_FD_TABLE FD_SETSIZE

/* server_accept_one() results. The rejection is a distinct value rather than
 * plain -1 because it is NOT a failure of the loop: the listener is fine, the
 * next connection is fine, and the drain must continue. */
#define SERVER_ACCEPT_REJECTED (-2)

struct server {
    char      name[IRC_MAX_SERVER_NAME + 1];
    int       listen_fd;

    conn_t  **by_fd;          /* FD_SETSIZE slots; NULL when the slot is free */
    size_t    nconns;

    /* Registries. Both are string -> pointer maps. */
    struct strtab *nicks;
    struct strtab *chans;

    /* The channel registry is a hash table, and a hash table cannot be
     * enumerated -- and LIST has to enumerate every channel on the node
     * (RFC 2812 3.3.5), in a deterministic order a test can assert on the wire.
     * So the node also keeps an ordered vector of the same chan_t pointers,
     * appended in creation order. Two indexes over one set of objects, and
     * they must agree: the hash is the O(1) lookup and the vector is the
     * enumeration, and server_chan_attach()/server_chan_detach() are the only
     * places either changes. A channel that is in one and not the other would
     * be a JOIN that resolves to NULL, so the invariant is asserted by
     * test_channels.c rather than left to inspection. */
    chan_t **chan_objs;
    size_t   nchan_objs;
    size_t   chan_objs_cap;

    /* 2.4: ids come from a per-SERVER monotonic counter, not a per-connection
     * one, and epoch is per-boot so a restart cannot collide with ids issued
     * before it. Both start at 1: id 0 is reserved as "unset" so an absent tag
     * is never mistaken for a real id. */
    uint64_t  msg_id;
    uint64_t  epoch;

    server_dispatch_fn dispatch;
    server_tick_fn      on_tick;

    dial_t   *dials;
    size_t    ndials;
    size_t    dials_cap;

    /* Observable counters. Every one of these is a claim the loop makes about
     * itself, and each is a real rejection or event rather than a derived
     * guess, so a test can assert on them. */
    uint64_t  n_accepted;        /* conns registered */
    uint64_t  n_rejected_fd;     /* accepted fds >= FD_SETSIZE, closed unrejected */
    uint64_t  n_closed;          /* conns the reaper closed */
    uint64_t  n_lines;           /* complete lines framed */
    uint64_t  n_parse_reject;    /* message_parse_n() rejections */
    uint64_t  n_frame_error;     /* unterminated over-long lines */
    uint64_t  n_writeq_overflow; /* appends refused over CONN_WQ_MAX */
    uint64_t  n_write_error;     /* fatal send() on a conn */
    uint64_t  n_partial_writes;  /* pumps that left bytes queued */
    uint64_t  n_eintr;           /* poll() calls interrupted by a signal */
    uint64_t  n_ticks;           /* tick hook invocations */
    uint64_t  n_dial_connected;
    uint64_t  n_dial_failed;

    /* ------------------------------------------------------------------------
     * Phase 3 claims. Both are statements the node makes about itself that are
     * real events rather than derived guesses, so a test can assert on them.
     * ------------------------------------------------------------------------ */

    /* PASS lines seen. The RECORD that PASS exists and does not authenticate:
     * the node has no credential store in this phase, so a client that sends
     * PASS with any value is treated exactly like one that sent none. The count
     * is the whole record; the password itself is never logged. */
    uint64_t  n_pass_seen;

    /* Outbound messages reply() REFUSED to send: a numeric addressed to a
     * CONN_SERVER conn, to nothing, or to a connection already on its way out.
     * This one should be zero forever on a single node, so a non-zero value is
     * a bug report rather than a metric -- which is why reply() prints it
     * whether or not tracing is on. */
    uint64_t  n_reply_refused;

    int       trace;             /* emit [observable] per-line output */
};

/* Zero the struct and set the node name plus the per-boot epoch. `name` must
 * satisfy irc_serve_server_name_valid() (the 2.4 tag grammar); it is rejected
 * with -1 because a name this node cannot stamp on its own outbound tags would
 * break loop prevention at the first relay. Returns 0 on success. Does not
 * open anything -- server_listen() does that separately so a test can build a
 * server_t without a socket. */
int server_init(server_t *s, const char *name);

/* Release the registries, the dial table and the by_fd array, close the
 * listener, and close any connection still registered. Safe on a zeroed
 * struct. */
void server_shutdown(server_t *s);

/* Bind and listen on `port` (host 0.0.0.0), nonblocking, with SO_REUSEADDR.
 * `port` may be 0, which asks the kernel for an ephemeral port -- that is how
 * tests get a port nobody else is using, and server_port() then reads back
 * what the kernel chose. Returns 0 on success, -1 on failure with errno set
 * from the failing call. */
int server_listen(server_t *s, int port);

/* The port actually bound, via getsockname(). Returns -1 if the listener is
 * not bound. This is the readback that makes port 0 usable. */
int server_port(const server_t *s);

/* Monotonic milliseconds since an arbitrary epoch. The ONLY clock in the
 * codebase: handlers take a stamp from the tick rather than reading the wall
 * clock themselves, which is what 3.4 means by "the poll tick drives time". */
uint64_t server_now_ms(void);

/* O(1) registry lookup by descriptor. Returns NULL when the slot is free. */
conn_t *server_conn(server_t *s, int fd);

/* Register `c` in the by_fd table, taking ownership. Returns 0, or -1 if
 * server_init() was never called, if the slot is occupied, or if the fd is
 * outside the poll() set (>= FD_SETSIZE), in which case the caller must close
 * the fd itself -- an fd that cannot be indexed cannot be a conn. */
int server_add_conn(server_t *s, conn_t *c);

/* Take ONE pending connection off the listener without blocking. The listener
 * is nonblocking, so this returns 0 immediately when there is nothing to
 * accept. Returns 1 when a connection was accepted and registered, -1 on a
 * fatal accept() error, and -2 when the accepted descriptor was >= FD_SETSIZE
 * and was therefore closed rather than registered (3.4: the check is explicit
 * and at the accept site, because a silent overflow is corruption).
 *
 * The -2 path is the one place in the codebase that closes an fd without
 * going through the reaper, and that is not an inconsistency: by_fd is indexed
 * BY the descriptor, so an out-of-range fd cannot be registered at all, and the
 * reaper only closes registered conns. The fd has not become a connection, so
 * there is no connection to reap. */
int server_accept_one(server_t *s);

/* The single place a registered connection's fd is closed. Tears the conn_t
 * down completely: releases its nick, frees its buffers, zeroes the struct and
 * clears the by_fd slot, so a reused descriptor cannot inherit any of it.
 * Unregistered descriptors are ignored, which makes a second call a no-op
 * rather than a double close. */
void server_close_conn(server_t *s, int fd);

/* Queue bytes to a connection through the bound. Returns 0 on success, -1
 * when the append would exceed CONN_WQ_MAX, in which case nothing is buffered
 * and the connection is marked CLOSING and the overflow is recorded. A
 * saturated link is dropped, not buffered (3.4). Never closes the fd. */
int server_queue(server_t *s, conn_t *c, const char *data, size_t len);

/* Close every connection marked CLOSING. This runs at a fixed point in the
 * loop, after all reads and writes for the iteration, and it is the only thing
 * that calls server_close_conn() on account of the loop. Returns how many were
 * closed. */
int server_reap(server_t *s);

/* ---------------------------------------------------------------------------
 * Nick registry (2.1: uniqueness is per SERVER, so bob@a and bob@b are
 * distinct keys and there is no global collision to resolve)
 * ---------------------------------------------------------------------------
 * server_nick_claim() returns 0 when the name was free and is now owned by `c`,
 * or -1 when it is already claimed. A -1 is the fact Phase 3 turns into 433; it
 * is not turned into a rename here, because rename-the-loser needs a broadcast
 * that does not exist until Phase 9. */
int server_nick_claim(server_t *s, const char *nick, conn_t *c);
void server_nick_release(server_t *s, const char *nick);
conn_t *server_nick_lookup(const server_t *s, const char *nick);

/* ---------------------------------------------------------------------------
 * Channel registry (2.2)
 * ---------------------------------------------------------------------------
 * The key space arrived in Phase 2, when struct chan did not exist and the value
 * had to be NULL. Phase 4 lands the struct and therefore the value, and it does
 * so by ADDING an accessor rather than by changing the probes below:
 *
 *   server_chan_add/remove/lookup   the key space. Case-SENSITIVE, value NULL,
 *                                    answering "is this exact key present". They
 *                                    are unchanged, including their case
 *                                    sensitivity, because a case-insensitive
 *                                    fold is not a silent side effect of holding
 *                                    a value -- it is Phase 4's job and it
 *                                    belongs in the accessor that canonicalises.
 *   server_chan_attach/get/detach   the values, in core/channel.h, over the
 *                                    opaque chan_t. This is the pair the
 *                                    command handlers use.
 *
 * The `cap` suffix difference is not an accident: conn_t::cap and chan_t::cap
 * are different arrays' capacities, and there is no ambiguity in either.
 */
int server_chan_add(server_t *s, const char *name);
void server_chan_remove(server_t *s, const char *name);
const char *server_chan_lookup(const server_t *s, const char *name);

/* ---------------------------------------------------------------------------
 * Peer lookup by server name (2.3)
 * ---------------------------------------------------------------------------
 * Find a registered CONN_SERVER connection whose peer_name is `name`,
 * case-insensitively. Returns NULL when there is none.
 *
 * This is where "can this node route to the origin?" is answered from, and it
 * exists already because Phase 2's dial FSM is what creates a CONN_SERVER
 * connection and it already sets peer_name. It is a linear scan of by_fd, which
 * is O(FD_SETSIZE) -- the same cost 3.4 already accepts for iterating every
 * connection on the node -- and it is short-circuited by the caller on the
 * overwhelmingly common case, because a channel this node owns never reaches
 * here at all.
 *
 * Phase 6 narrows it: a link that exists but has not finished the handshake FSM
 * is not yet a route, and the FSM state lives with the link. The signature does
 * not have to change for that, which is the point of keeping the question in a
 * function rather than in a flag. */
conn_t *server_find_peer(const server_t *s, const char *name);

/* Next id from the per-SERVER monotonic counter (2.4). Never returns 0: id 0
 * is reserved for "unset" so a missing tag is never read as a real id. */
uint64_t server_next_msg_id(server_t *s);

/* ---------------------------------------------------------------------------
 * Nonblocking dial (3.4)
 * ---------------------------------------------------------------------------
 * Start a connect() to an ALREADY-RESOLVED address and return immediately. The
 * connection is not usable when this returns: it appears in the poll set as
 * DIAL_CONNECTING and becomes a registered CONN_SERVER connection once the
 * socket reports writable with no error. `peer_name` is stored on the link and
 * validated with the 2.4 grammar. Returns 0 on success, -1 on failure.
 *
 * No caller exists yet; see the file header. */
int server_dial(server_t *s, const struct sockaddr *sa, socklen_t salen,
                const char *peer_name);

/* Fold the current dial set into the poll sets. Returns 0 on success. */
int server_dial_collect(server_t *s, struct pollfd *pfds, size_t cap,
                        nfds_t *nfds_out);

/* Advance any dial whose socket became ready: writable-with-no-error connects,
 * anything else fails. A successful dial registers a CONN_SERVER connection.
 * Returns 0 on success. */
int server_dial_progress(server_t *s, const struct pollfd *pfds, size_t nfds);

/* Number of dials currently in the table, in any state. Zero until Phase 6. */
size_t server_dial_count(const server_t *s);

/* The tick hook and the clock, called by the loop. server_tick() stamps the
 * clock, counts the invocation and forwards to s->on_tick when set. */
void server_tick(server_t *s, uint64_t now_ms);

#endif /* IRC_CORE_SERVER_H */
