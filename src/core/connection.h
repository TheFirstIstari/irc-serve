/* connection.h -- conn_t: identity fields, buffers, and RFC 1459 2.3 framing.
 *
 * Authority: docs/SERVER_DESIGN.md sections 2.1 (identity), 2.2 (channels,
 * referenced only), 3.2 (line cap, consumed here via message.h), 3.3
 * (connection framing) and 3.4 (bounded write queues; the send path never
 * closes).
 *
 * ---------------------------------------------------------------------------
 * WHAT IS IN HERE NOW AND WHAT IS NOT
 * ---------------------------------------------------------------------------
 * This struct has its FINAL shape as of Phase 2. Two members are present and
 * deliberately UNUSED until later phases, and it would be worse to add them in
 * Phase 3/4 than to declare them now:
 *
 *   peer_name   -- the server name of a CONN_SERVER link. Nothing creates a
 *                  CONN_SERVER yet: peer sockets are Phase 6, and the dial
 *                  state machine that will create them lives in server.c but is
 *                  driven by no caller. It is always NULL here, and conn_free()
 *                  releases it so the Phase 6 owner is already correct.
 *   chans       -- the channels this conn has joined. `struct chan` is still
 *                  incomplete (2.2 lands it in Phase 4), so the array is never
 *                  grown and every element slot stays NULL. Phase 4 fills it
 *                  without changing the layout.
 *
 * The struct's shape has since been FINAL in the sense 7/Phase 4 meant: the
 * fields Phase 4 and Phase 5 added (member flags and the remote caches on
 * chan_t; away, signon_at and last_active here) are additions, not
 * rearrangements, and every one of them is a field a later phase or a numeric
 * needs. A phase that finds itself wanting a DIFFERENT struct is the signal
 * that the design above is wrong, not that the field should be shoved in
 * wherever it happens to fit.
 *
 * There is deliberately NO per-connection message id. Ids come from a
 * per-SERVER monotonic counter owned by server_t (2.4), because a
 * per-connection counter makes two connections on one server both emit the
 * same (server, 1) and a peer then silently drops the second message. That
 * field must not be added back.
 *
 * ---------------------------------------------------------------------------
 * THE PHASE 8 FIELDS, AND WHY THEY ARE HERE RATHER THAN IN cap.c
 * ---------------------------------------------------------------------------
 * 2.1 makes this struct's shape final, so the state a capability negotiation and
 * an authentication exchange need had to be added here or nowhere. They are
 * ADDITIONS, not rearrangements, and each one is a fact about this connection
 * that another module has to ask:
 *
 *   caps              what this client negotiated. A bitmask over the table in
 *                     core/cap.h, so enabling a capability is one OR and asking
 *                     is one AND -- and so a NEW capability is a new bit rather
 *                     than a new field, which is the shape 2.1 predicted.
 *   cap_negotiating   1 while a CAP LS/REQ is in flight. Registration is HELD
 *                     until CAP END arrives, and this is the flag that holds it.
 *                     It is a separate field rather than a bit in `caps` because
 *                     "the client asked" and "the client was granted" are
 *                     different facts and conflating them would make a client
 *                     that asked for nothing look like one that had finished.
 *   sasl              the SASL exchange's observable state, as the sasl_state_t
 *                     sasl_framework.h defines. ABORTED until a client offers a
 *                     mechanism; FAILED is TERMINAL and is what stops registration
 *                     completing, because a client that failed to authenticate
 *                     must not be able to register as though it had.
 *
 * WHAT NONE OF THEM GRANT. There is no operator flag on this struct and none was
 * added: a successful SASL establishes that the client holds a password, and
 * there is nothing in this node that it could legitimately be granted. Saying
 * so here is the point -- the field a future phase adds is the first place a
 * capability would become a privilege, and it should be added when there is a
 * privilege to grant.
 *
 * ---------------------------------------------------------------------------
 * THE WRITE QUEUE
 * ---------------------------------------------------------------------------
 * wbuf[woff .. wlen) is the unsent tail; woff is the retained offset. A
 * nonblocking send() may write fewer bytes than offered, so the offset is
 * retained and the remainder is drained on a later poll iteration rather than
 * being dropped or re-sent. The queue is bounded (3.4): exceeding the cap
 * REFUSES the append. It does not grow, does not spill, and does not
 * block -- the caller marks the connection CLOSING and records why, because a
 * saturated peer link is dropped, not buffered.
 *
 * conn_queue() never closes an fd, and neither does conn_pump() (3.4: "the
 * send path never closes a connection"). A connection is closed exactly once,
 * by the reaper in server.c.
 */
#ifndef IRC_CORE_CONNECTION_H
#define IRC_CORE_CONNECTION_H

#include <stddef.h>
#include <time.h>

#include "core/message.h"

struct chan; /* opaque until Phase 4 (2.2) */

/* conn_t::kind */
#define CONN_CLIENT 0
#define CONN_SERVER 1

/* conn_t::state. REG_PASS is the entry state; there is no "not registered"
 * separate from it because a connection is either unregistered (REG_PASS) or
 * has made progress through the registration sequence. CLOSING is terminal:
 * a conn in that state is not read from and not written to, and the reaper
 * closes it at a fixed point in the loop. */
#define CONN_REG_PASS 0
#define CONN_REG_NICK 1
#define CONN_REG_USER 2
#define CONN_REG_READY 3
#define CONN_CLOSING 4

/* Bounded write queue, 3.4: "~256 KB per connection". The cap is on the
 * UNSENT tail (wlen - woff), not on the allocation, so a long-lived
 * connection that keeps draining does not eventually fail on its own history.
 */
#define CONN_WQ_MAX ((size_t)(256u * 1024u))

/* Read buffer cap. IRC_MAX_LINE (8 KiB, from 3.2) is the largest legal line
 * counting its terminator, so a buffer that reaches that size without having
 * seen a terminator is a line that can never become legal: conn_fill() stops
 * reading there and conn_next_line() reports the framing error. The read
 * buffer is therefore bounded by the same constant the line cap enforces, and
 * a client cannot grow it by withholding a newline. */
#define CONN_RBUF_MAX ((size_t)IRC_MAX_LINE)

/* Reclaim the head of the write queue once this many bytes have been sent and
 * the remainder is smaller than this, so a steady trickle does not leave the
 * allocation pinned at its high-water mark forever. */
#define CONN_WQ_COMPACT ((size_t)4096u)

/* Size of the buffer conn_hostmask() renders into: nick + '!' + user + '@' +
 * host + NUL, written as the three struct widths so raising any of them cannot
 * leave a caller with a buffer that is one byte short. */
#define CONN_HOSTMASK_MAX (sizeof(((conn_t *)0)->nick) + \
                           sizeof(((conn_t *)0)->user) + \
                           sizeof(((conn_t *)0)->host) + 3u)

/* conn_t::away, the AWAY message. Empty means "not away", the same idiom
 * nick[0]/user[0] already use for "this fact is not established yet", so no
 * separate flag is needed and the two can never disagree.
 *
 * THE BOUND, AND WHY IT IS 255
 * -----------------------------
 * Three independent reasons converge on the same number, which is why it is
 * derived rather than picked:
 *
 *   1. RFC 1459 2.4.2 caps the AWAY message at 255 characters. 255 is the RFC's
 *      number, not this project's.
 *   2. 301 RPL_AWAY carries it as a numeric's TRAILING TEXT, and reply() renders
 *      that into REPLY_TEXT_MAX (512). At 255 it fits with room to spare, so an
 *      away message this node accepted is always an away message 301 can report.
 *      A larger bound would make "accepted" and "reportable" different sets.
 *   3. It equals CHAN_MAX_TOPIC (255), the other client-supplied free-text field
 *      this node stores, so there is ONE bound for "a sentence a user typed",
 *      not two that differ for no stated reason.
 *
 * IT IS A CAP, NOT A TRUNCATION POINT
 * ----------------------------------
 * An AWAY message longer than this is REFUSED (417), and the previous away state
 * is left exactly as it was. Truncating would store a message the user did not
 * write and then report the shortened one in 301 as if it were theirs -- which
 * is the same "never silently truncate a parameter" rule 3.2 states and Phase 4
 * applied to a topic and a mode string.
 *
 * ---------------------------------------------------------------------------
 * PHASE 6 NEEDS THIS FIELD: SECTION 4.3's SBURST
 * ---------------------------------------------------------------------------
 * 4.3: "SBURST is the resync verb. On every link establishment the initiator
 * sends full state: ... all nicks: user / host / modes / away". So `away` is
 * NOT a Phase 5 convenience -- it is a field with no other producer, and
 * whoever writes SBURST must populate it. It is here, in the phase that first
 * has a use for it, so that SBURST is a wire format rather than a struct change.
 *
 * The size is part of that contract: 4.3 sends "all nicks", so the away message
 * is a per-nick cost in a burst whose size is O(nicks). A bound of 255 keeps
 * that burst O(nicks) with a KNOWN ceiling; an unbounded message would make one
 * client's AWAY able to inflate a resync for the whole node. */
#define CONN_MAX_AWAY 255

/* conn_fill() outcomes. EOF is a distinct value from a hard error because they
 * are different events on the wire and a caller that reports close reasons has
 * to be able to tell them apart without inspecting errno, which may be stale. */
#define CONN_FILL_EOF 1

/* The connection. Layout is 2.1 (identity) plus 3.3 (buffers), in that order.
 *
 * The three fields Phase 5 adds sit inside the identity block, beside the
 * fields they are derived from, and each earns its place by being REPORTED on
 * the wire -- none of them is bookkeeping a client cannot see:
 *
 *   away        4.3's SBURST must send it for every nick, and 301/352 report
 *               it. See CONN_MAX_AWAY above, which is where the bound and the
 *               over-long policy are argued.
 *   signon_at   317 RPL_WHOISIDLE carries a signon time. There is no other
 *               value on the node that could fill it, and a numeric that lies
 *               about what it is is what Phase 4 refused to do for 329 ("reusing
 *               topic_when for it would be a numeric that lies about what it
 *               is"). Borrowing the node's boot time would be the same lie one
 *               level up: it is when the SERVER started, not when the user
 *               connected.
 *   last_active 317's other half. It is updated in conn_fill(), which is the
 *               only place that observes the connection doing anything, so the
 *               idle time it yields is measured from real socket activity rather
 *               than from the last command that happened to be dispatched.
 *
 * All three are set or updated inside the connection layer, and none of them is
 * something Phase 6 has to add. */
typedef struct conn {
    int         fd;
    int         kind;              /* CONN_CLIENT | CONN_SERVER */
    char       *peer_name;         /* server name, CONN_SERVER only; Phase 6 */
    char        nick[64];          /* local nick, pre-@ */
    char        user[64];
    char        host[128];
    char        realname[256];
    int         state;             /* CONN_REG_* | CONN_CLOSING */
    char        away[CONN_MAX_AWAY + 1];
    time_t      signon_at;         /* accept time; 317's <signon time> */
    time_t      last_active;       /* last byte read; 317's <idle> */
    unsigned    caps;              /* negotiated capabilities; core/cap.h bits */
    int         cap_negotiating;   /* CAP LS/REQ in flight; CAP END clears it */
    int         sasl;              /* sasl_state_t; FAILED is terminal */
    struct chan **chans;           /* channels joined; Phase 4 */
    size_t      nchans;
    size_t      cap;
    char       *rbuf;              /* read buffer */
    size_t      rlen;
    size_t      rcap;
    char       *wbuf;              /* write queue; wbuf[woff..wlen) is unsent */
    size_t      woff;
    size_t      wlen;
    size_t      wcap;
} conn_t;

/* Allocate a zeroed connection for `fd` (state CONN_REG_PASS, kind `kind`,
 * no buffers). Returns NULL if allocation fails. conn_free() is the inverse
 * and is safe on NULL. */
conn_t *conn_new(int fd, int kind);

/* Release the buffers and the peer_name/chans arrays, then the struct. Does
 * NOT close the fd: closing is the reaper's single responsibility (3.4). Safe
 * on NULL. */
void conn_free(conn_t *c);

/* Read whatever is available into rbuf. Returns 0 when the socket has been
 * drained to EAGAIN, CONN_FILL_EOF when the peer closed its half, and -1 on a
 * hard read error or a failed buffer growth; in the latter two cases the
 * caller must mark the connection CLOSING. EINTR is retried internally and
 * EAGAIN is not an error.
 *
 * The buffer is grown geometrically but never past CONN_RBUF_MAX, so a peer
 * that never sends a terminator cannot make this grow without bound. */
int conn_fill(conn_t *c);

/* Pull the next complete line out of rbuf and COPY it into `dst`.
 *
 * Returns 1 on success -- the line is in `dst`, `*len` is its length -- 0 when
 * more bytes are needed (the bytes stay in rbuf, untouched), and -1 when rbuf
 * holds IRC_MAX_LINE bytes with no terminator in them, which is a framing error
 * no future byte can repair. Also -1 if the line does not fit in `dstcap`,
 * which cannot happen when `dstcap` is IRC_MAX_LINE or more.
 *
 * WHY THE CALLER SUPPLIES THE BUFFER
 * ----------------------------------
 * An earlier version of this returned a `char **` pointing into rbuf and then
 * slid the unread remainder to the front of that same buffer to reclaim the
 * space -- which destroys the very bytes the caller was just handed, inside the
 * same call. The returned line was already garbage on return, and the only way
 * to use it was to copy it out by some other route, so the "optimisation" was
 * a trap with a pointer in it.
 *
 * Copying into the caller's buffer makes the lifetime obvious and owned by
 * whoever can see it: `dst` is valid until the caller reuses it, and nothing
 * the connection does can invalidate it underneath. The cost is one memcpy of at
 * most IRC_MAX_LINE bytes per line, which is the same copy the parser is about
 * to make anyway. The struct keeps the shape 3.3 specifies; no scratch field
 * was added for this.
 *
 * The line is copied INCLUDING its terminator, which is why the caller must
 * hand the pair to message_parse_n() rather than message_parse(): the framing
 * layer holds a length, and only the counted entry point rejects an embedded
 * NUL (3.2).
 *
 * Terminator handling: a line ends at the first LF. A CR immediately before it
 * belongs to the line, so the CRLF that RFC 1459 2.3 mandates is passed through
 * to the parser intact rather than being stripped here. A bare LF is also
 * accepted as a terminator because message_parse_n() accepts it and the parser
 * -- not the framing layer -- is where the line grammar is enforced. A CR
 * anywhere else stays inside the line and is rejected by the parser. */
int conn_next_line(conn_t *c, char *dst, size_t dstcap, size_t *len);

/* Append `len` bytes to the write queue. Returns 0 on success, -1 when the
 * append would push the unsent tail past CONN_WQ_MAX, in which case nothing
 * is buffered and nothing is written: the caller marks the connection CLOSING
 * and records the overflow. This function never blocks and never closes. */
int conn_queue(conn_t *c, const char *data, size_t len);

/* Push as much of the write queue as the socket will take. Returns 0 when the
 * queue is empty or the socket is full, -1 on a fatal write error (EPIPE,
 * ECONNRESET, EBADF), in which case the caller must mark the connection
 * CLOSING. A short write is NOT an error and is NOT a failure: the retained
 * woff is advanced by whatever was sent and the rest is drained on a later
 * poll iteration. This function never closes the fd. */
int conn_pump(conn_t *c);

/* Bytes still unsent: wlen - woff. */
size_t conn_write_pending(const conn_t *c);

/* Mark the connection CLOSING. Idempotent, and deliberately the only state
 * transition a send or read path is allowed to make. */
void conn_mark_closing(conn_t *c);

/* Write this connection's client prefix -- "<nick>!<user>@<host>" -- into `out`
 * and return the byte count written, excluding the NUL. Returns 0 if `out` is
 * too small or `c` is NULL, so a caller that cannot render the prefix must
 * treat the line as unrenderable rather than emit a truncated one.
 *
 * WHY IT LIVES HERE AND NOT IN A HANDLER
 * --------------------------------------
 * RFC 2812 3.3.1 requires the JOIN/PART/KICK/TOPIC/MODE echoes to be prefixed
 * with the ACTING USER's hostmask, and that prefix is a rendering of identity
 * fields, so it belongs beside the fields. It is also the second thing a
 * channel broadcast needs after the parameter list, which is why it is a
 * function rather than a struct field: the design's 2.1 is explicit that
 * conn_t's shape is final as of Phase 2.
 *
 * It is NOT 2.1's qualify() ("nick@server"). That is the internal identity
 * form, it is needed to address a user on another server, and nothing in Phase 4
 * addresses one -- there are no peers. qualify() belongs to the phase that
 * first has a remote user to name, and writing it now would be a function with
 * no caller. */
size_t conn_hostmask(const conn_t *c, char *out, size_t cap);

#endif /* IRC_CORE_CONNECTION_H */
