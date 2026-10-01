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
 *
 * The one thing Phase 6 added to it without a caller is dial_t::started_ms, and
 * it is here rather than in the commit that finally dials because the reason it
 * is needed is a property of poll() that is already true: a connect() to a
 * firewalled host never becomes writable and never reports an error, so the
 * DIAL_CONNECTING entry sits in the table forever with nothing in the loop
 * capable of deciding it failed. A dial is the one thing on this node with no
 * peer on the other end to generate an event, so the timeout has to be the
 * tick's to apply -- and the tick can only apply it if the dial recorded when it
 * started.
 */
#ifndef IRC_CORE_SERVER_H
#define IRC_CORE_SERVER_H

#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "core/connection.h"
#include "federation_handshake.h"

/* The per-node dedup store (2.4). It is declared here and DEFINED nowhere in
 * this header on purpose: federation/dedup.h owns the entry layout, and
 * core/server.h holds only the opaque pointers, so the table's geometry is one
 * module's business rather than a fourth thing every reader of server_t has to
 * understand. federation/dedup.h deliberately does NOT include this file -- the
 * dependency runs the other way, through the four functions in it. */
struct fed_dedup_entry;

/* The credential store SASL PLAIN verifies against (Phase 8). It is an OPAQUE
 * pointer for the same reason the dedup entry's and the topic cache's are:
 * sasl_framework.h owns the layout, and this header holds only the pointer, so a
 * reader of server_t does not also have to understand a file format and four
 * size bounds.
 *
 * It is NULL until sasl_store_load() succeeds, which is the honest state of a node
 * started without --sasl-store -- and it is the thing cap.c asks before
 * advertising `sasl`. NULL therefore means "this node can authenticate nobody",
 * and the SASL path treats it that way rather than treating it as "no opinion". */
struct sasl_store;

/* Phase 7's topic cache: one entry per channel whose topic outlived the
 * channel. The layout is channel.h's, for the same reason the dedup entry's is
 * federation/dedup.h's -- this header holds opaque pointers so the geometry of
 * a table is one module's business rather than a fourth thing every reader of
 * server_t has to understand. */
struct chan_topic;

/* Phase 9 item 4: one peer's ADVERTISE, as OBSERVED. The whole structure is
 * OBSERVATIONAL: it is read by logs, by the stats line and by the name-collision
 * check, and it is never read by the dial path. See the comment on
 * server_t::advs for why that separation is a security property rather than an
 * omission, and what a future reader would have to write down before changing it. */
struct fed_advert;

/* Phase 9's remote-nick registry: 2.1's "which server holds the user called X",
 * the table that makes 3.1's `nick@server` row RESOLVABLE rather than merely
 * routable. The layout and its least-recently-used ordering are
 * federation/nickreg.c's, for the same reason the dedup entry's are
 * federation/dedup.h's and the topic cache's are core/channel.c's: the GEOMETRY
 * of a table is one module's business rather than a fourth thing every reader of
 * this struct has to understand. The three counters below are NOT here for that
 * reason -- they are properties of the NODE, which is what this struct is, and a
 * counter in the module would be a counter a second node in the same process
 * could not have. */
struct fed_rnick;

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
    /* When this dial started, from the one clock the node has (server_now_ms).
     * Nothing else about a DIAL_CONNECTING entry is observable: poll() reports
     * nothing at all for a connect() to a host that silently drops the packets,
     * so without a start stamp the entry is un-timeout-able and stays in the
     * table for the life of the process. See the file header. */
    uint64_t started_ms;
    char   peer_name[IRC_MAX_SERVER_NAME + 1];
} dial_t;

/* ---------------------------------------------------------------------------
 * The peer link (2.3)
 * ---------------------------------------------------------------------------
 * ONE STRUCT PER PEER, held in a VECTOR on server_t and not in a `next`-linked
 * list. That is a decision, and the reason is that every operation on this set
 * is a walk anyway: a forward names its destination, so it looks the peer up;
 * the loop's own link accounting iterates them; and Phase 6's link tick visits
 * each one per tick. A list would buy nothing over an array here and would cost
 * the one property the other registries on this struct all share -- a slot
 * index that survives a removal, so an off-by-one cannot strand a pointer.
 *
 * A LINK IS NOT A CONNECTION. `fd` is the descriptor a link currently rides on,
 * and it is -1 whenever there is none: between the two halves of a dial, after a
 * peer goes away, and for a link that exists as a name and nothing else. The
 * connection itself is a conn_t reached through server_t::by_fd, which stays the
 * single index of live connections, and conn_t::peer_name stays a DISPLAY COPY
 * of the name rather than the authority on it. Two copies of a peer's name that
 * can disagree is the failure this arrangement is chosen to make impossible, so
 * nothing routes by the copy.
 *
 * WHY THE HANDSHAKE CONTEXT IS EMBEDDED BY VALUE
 * ------------------------------------------------
 * federation_handshake.h is a per-peer FSM with an explicitly caller-owned
 * context and no module state, and this is that caller. Embedding rather than
 * pointing at it means a link cannot outlive its FSM or have one replaced under
 * it: there is no allocation to leak and no second owner to keep alive.
 *
 * `state` mirrors handshake_state_t and exists because the routing predicates
 * (server_find_peer) and the future link tick both want an int comparison in a
 * hot path, and because -Weverything objects to comparing an enum against
 * anything but an enumerator in a switch. The mirror is the thing that can go
 * stale, so it is written in exactly one place -- fed_link_set_state() -- and
 * never assigned at a call site. hs.state is the truth; `state` is a copy kept
 * honest by that one writer.
 */
typedef struct server_link {
    /* The peer's server name, validated with irc_serve_server_name_valid()
     * (the same grammar the irc-serve-origin tag accepts) because 2.3 makes
     * name uniqueness a handshake-time rejection and a name this node cannot
     * stamp is a name it cannot be addressed by either. */
    char     name[IRC_MAX_SERVER_NAME + 1];

    /* -1 when no socket. A link can be named and handshaked with no descriptor
     * at all, and a link whose descriptor is stale is exactly the case where
     * by_fd[fd] would hand back some OTHER connection. */
    int      fd;

    int      state;             /* mirrors handshake_state_t; see the header */

    handshake_ctx_t hs;         /* the FSM context; hs is the truth, state mirrors */

    /* The PRE-RESOLVED target (3.4). It is on the link rather than in a
     * configuration array so that a link which is re-dialled after a failure
     * carries the address it failed to reach, and so a future reconnect needs
     * no lookup: any name resolution inside the event loop stalls every client
     * on the node, which is why server_dial() takes a struct sockaddr and there
     * is deliberately no resolution helper anywhere in this file. */
    struct sockaddr_storage addr;
    socklen_t               addrlen;

    /* 1 when this node dialled, 0 when it accepted. Needed because the two
     * directions are not symmetric: the initiator sends the handshake and the
     * burst (4.3), and only the initiator may decide a link is dead and close
     * it without first having seen anything wrong from the peer. */
    int      initiator;

    uint64_t created_ms;
    uint64_t last_sent_ms;
    uint64_t last_recv_ms;

    /* The PEER's epoch, which is not this node's and is not derivable from it.
     * A link that reached ESTABLISHED without learning the peer's epoch cannot
     * be burst: 4.3's SBURST carries the origin's epoch, and every id stamped
     * into it has to be attributed to the right boot. It is 0 until the peer
     * says, and a peer link still at 0 is a link that has not been told. */
    uint64_t epoch;

    /* Whether this link's SBURST has been APPLIED. It is the flag that makes
     * a resync replace rather than merge (4.3), so it is on the link and not
     * on a timer: a link that reconnects needs a fresh burst even if its peer
     * never went away. */
    int      burst_done;

    /* ------------------------------------------------------------------------
     * THE RECONNECT SCHEDULE -- Phase 9. Three fields, one policy, and the
     * reason they are HERE rather than in a module-global table is the same
     * reason the link itself is: the policy is per PEER, and a table keyed by
     * name is a second place to look up a name. federation/link.h carries the
     * derivations for the three intervals they are compared against.
     * ------------------------------------------------------------------------
     *
     * retry_at_ms is the earliest stamp at which fed_tick()'s T7 may dial this
     * link. 0 means DUE NOW, which is the state a freshly configured link is in
     * -- so the FIRST dial is immediate and only a FAILED one waits, which is
     * what keeps a healthy mesh from acquiring a start-up delay. The zero is
     * therefore load-bearing rather than a "never stamped" sentinel, and it is
     * the reason a dead link's dump does not read 0 as "unreachable".
     *
     * retries is CONSECUTIVE failed attempts. It is reset to 0 by
     * fed_link_established(), so a peer that flaps gets a fresh budget on every
     * success while a peer that is simply dead runs the budget down. That
     * asymmetry is deliberate: a budget that were a lifetime cap would be a
     * link ban, and a mesh needs a link policy more than it needs a ban.
     *
     * gave_up is the budget SPENT, and it is terminal for the life of the
     * process unless fed_link_reset() clears it. Nothing in the shipped binary
     * calls fed_link_reset() -- there is no operator door -- and that gap is
     * recorded in docs/SERVER_DESIGN.md's Phase 9 block rather than papered
     * over here, because the alternative (a silent give-up) is exactly the
     * failure the budget's report exists to prevent. The field is here because
     * a terminal state with no door is still better than an unbounded retry
     * loop, and the door is one call away.
     *
     * THE COST, in one number: three integers per link, so 48 bytes on a
     * 16-link vector. The alternative -- a module-global side table keyed by
     * server name -- is the same 48 bytes plus a hash lookup on every T7 and a
     * second place where a link's identity is spelled.
     */
    uint64_t retry_at_ms;
    unsigned retries;
    int      gave_up;

    /* PHASE 9 ITEM 4: THIS PEER SAID IT IS LEAVING. It is a FIELD rather than a
     * fifth handshake state because the FSM is 2.1's and has exactly four states,
     * and adding one would be a change to a specification this phase does not own.
     * The distinction it carries needs no new state, either: a departing peer is a
     * link that must not be dialled rather than a link in a new place.
     *
     * WHAT IT SUPPRESSES IS EXACTLY ONE THING: the T7 arm's dial. Not the
     * keepalive, not the dump, not the handshake -- the link stays ESTABLISHED
     * until the peer's own teardown closes its socket, and everything this node
     * knows about the peer stays readable.
     *
     * IT IS A SEPARATE FLAG FROM `gave_up` BECAUSE THE TWO SAY OPPOSITE THINGS, and
     * overloading one for both would make a peer that left on purpose look like a
     * peer that was flaky: `gave_up` is this node's budget SPENT and its counter
     * is a finding about a link an operator should investigate, while this is the
     * peer ANSWERING and there is nothing to investigate. The same reasoning
     * server.h's own comment about the three integers makes, one level up: a
     * number that means two things is a number nobody can act on.
     *
     * IT IS CLEARED BY fed_link_reset() ONLY, because that is the OPERATOR's door:
     * an operator who resets a link is saying "I want this peer back", and a peer
     * that left cleanly comes back if an operator asks for it. Nothing else clears
     * it -- not a tick, not a sweep, not the link's own socket closing -- so a
     * clean leave is not undone by a later event on the same link. */
    int      clean_leave;

    /* PHASE 9 ITEM 4, THE PROPAGATION HALF: the load figure this link's peer last
     * ADVERTISED, and whether T8 has already reported it as shedding.
     *
     * THE FIGURE IS HERE AS WELL AS IN server_t::advs, and the duplication is
     * deliberate and is the reason this is a FIELD rather than a lookup. The store
     * is the OBSERVATIONAL one (the advs block below: reports, logs and a collision
     * check, never a dial target) and this is the ROUTING one -- it is what T8
     * compares against server_t::shed_pct. Keeping the number where the policy
     * reads it means the tick's decision does not depend on the store having been
     * allocated, costs no linear probe per link per tick, and cannot be perturbed by
     * anything that touches the store. Both are written from one statement sequence
     * when an ADVERTISE is applied, so they cannot disagree.
     *
     * `load_seen_ok` IS SEPARATE FROM `load_seen` rather than encoded in it, because a
     * peer that has never advertised is a DIFFERENT FACT from a peer that advertised
     * 0%, and the field says which one this is.
     *
     * IT IS NOT, HOWEVER, WHAT PREVENTS THE ARM FROM REPORTING A PEER IT HAS NEVER
     * HEARD FROM, and the field does not claim to be. An unset figure reads as 0, and
     * 0 cannot reach a non-zero threshold (`0 >= shed_pct` is false for every shed_pct
     * the operator can set), so the arithmetic already prevents it. The flag states
     * the intent where the decision is made rather than making it; see link.c's T8 for
     * why that is a real reason to keep it and NOT a claim a test can check.
     *
     * `shed_reported` is the EDGE LATCH, and it exists so the tick reports a
     * crossing rather than a state: without it a peer sitting at 95% would print a
     * line every POLL_TICK_MS for the life of the link, which is 20 lines a second
     * per peer on a mesh where somebody is busy -- the opposite of reporting. One
     * line per transition up is what an operator reading the log wants, and the
     * latch is cleared when the figure comes back down and by fed_link_reset(), so a
     * peer that sheds twice says so twice. */
    unsigned  load_seen;
    int       load_seen_ok;
    int       shed_reported;
} server_link_t;

/* The initial capacity of server_t::links, and a bound on the PEER DESCRIPTORS
 * one node will hold, which is the part that actually costs something: a peer
 * link is a conn_t in the by_fd table and a slot in the loop's poll set.
 *
 * Derived rather than picked, from two things that are already fixed in this
 * codebase:
 *   - the loop's poll set is FD_SETSIZE-bounded, and SERVER_FD_TABLE is that
 *     bound. 16 peers is under two percent of it, so a node with a full set of
 *     peers still has room for the several hundred clients the set allows.
 *   - 2.2's per-channel member-server set is CHAN_MAX_MEMBER_SERVERS (64). A
 *     node can therefore hold a member of a channel served by a larger set than
 *     it has links to, so 16 is a capacity of the link TABLE, not a promise
 *     about mesh size; the growth below doubles past it rather than refusing.
 *
 * It is also a power of two, which is not the reason to pick it but is the
 * reason it costs nothing: the vector grows geometrically exactly as
 * server_t::dials does, and no test has to care which multiple it starts at. */
#define IRC_FED_MAX_PEERS 16

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

    /* Registries. Both are string -> pointer maps. The nick one is FOLDED
     * (ASCII, case-insensitive keys) and the channel one is EXACT -- for the
     * reason spelled out where the table is defined in server.c: a nickname
     * compares case-insensitively but is DISPLAYED in the case the user chose,
     * whereas a channel name is both stored and displayed uppercase. */
    struct strtab *nicks;
    struct strtab *chans;

    /* The nick registry's ENUMERATION, which is the same arrangement as
     * chan_objs below and for the same reason: a hash table cannot be walked,
     * and WHO with no argument -- or with a mask -- is a query about "every
     * nickname matching X". `*` is what irssi and weechat send on connect, so a
     * WHO that can only name a channel is a WHO most clients never get an
     * answer from.
     *
     * The enumeration is a SET OF CONNECTIONS, in first-claim order, and the
     * invariant that makes it an index rather than a list of names is one
     * sentence: a connection is in it if and only if it holds at least one
     * name, and it is in it at most once. So it has one entry per USER where
     * the table above has one per NAME, and WHO -- which is a question about
     * users, and whose 352 is one line per user -- cannot list anybody twice.
     *
     * server_nick_claim() adds an entry only for a connection that is not in it
     * already, server_nick_release() removes one when a name is given up and
     * the connection holds no other, and server_nick_unclaim() removes one when
     * the connection is retired. Those are the only places the vector changes,
     * and each of them changes the table in the same breath.
     *
     * It is a cache, not the authority: the strtab above answers "is this nick
     * held and by whom" in O(1) and nothing but these three writes either. A
     * name in the vector and absent from the table would be a JOIN that
     * resolved to NULL, which is the failure chan_objs documents; the tests
     * assert the two agree rather than leaving it to inspection.
     *
     * The vector holds POINTERS and nothing is keyed by a nickname string in
     * it, which is deliberate. A string-keyed entry has to be found by string,
     * which meant re-implementing the table's case-fold at the call site (that
     * copy is gone) and meant a connection whose conn_t::nick happened to match
     * a name it did not hold could be removed on someone else's behalf. Both
     * are issue #103 and #102 respectively. */
    conn_t  **nick_objs;
    size_t    nnick_objs;
    size_t    nick_objs_cap;

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

    /* The peer links (2.3), a VECTOR and not a `next`-linked list -- the reason
     * is spelled out where server_link_t is defined. Every field here is a
     * mirror of the by_fd table's world: the vector says WHICH peers this node
     * knows about, the table says which of them currently has a socket. Keeping
     * the two separate is what lets a link exist with fd == -1, which is the
     * state between a dial and its completion and again after a peer is
     * dropped. */
    server_link_t *links;
    size_t    nlinks;
    size_t    links_cap;

    /* The 2.4 dedup store: an open-addressed table of (origin, epoch, id) with
     * an intrusive LRU, sized and owned by federation/dedup.c. The pointers are
     * opaque here on purpose (see the forward declaration at the top), and the
     * table is NULL until the first relayed message arrives rather than being
     * allocated by server_init(): the cost is roughly 416 KiB, and a node that
     * has never been sent a message by a peer has no use for any of it. The
     * price of that choice is a failed allocation INSIDE the first insert, and
     * federation/dedup.c answers it by failing closed -- reporting the message
     * as already seen -- because a dropped message is recoverable and a loop is
     * not. */
    struct fed_dedup_entry *dedup_tab;
    struct fed_dedup_entry *dedup_head;  /* LRU: most recently seen */
    struct fed_dedup_entry *dedup_tail;  /* LRU: least recently seen */
    uint64_t  dedup_used;
    uint64_t  dedup_swept_ms;

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

    /* ------------------------------------------------------------------------
     * Phase 6 federation claims. All four are events the link module
     * (federation/link.c) records, and all four are here rather than in that
     * module because they are properties of the NODE, which is what this
     * struct is: a counter that lives in the module is a counter a second node
     * in the same process could not have, and the one-node-per-process
     * arrangement fed_open() enforces is a constraint rather than a property.
     *
     * The per-reason breakdown of n_link_rejected is deliberately NOT here --
     * eight more fields on this struct for eight rare events, readable from
     * the link_dump line fed_dump() prints instead. Four headline numbers a
     * test waits on, plus a breakdown for a human reading a log. */
    uint64_t  n_link_rejected;  /* FEDERATE claims refused, any reason */
    uint64_t  n_link_duplicate; /* refused because that name was ESTABLISHED */
    uint64_t  n_fed_hs_timeout; /* links that reached no answer within T2 */
    uint64_t  n_fed_dead;       /* ESTABLISHED links that went silent (T4) */

    /* Phase 9: the node has spent a link's retry budget and stopped dialling
     * it. federation/link.c's fed_retry_arm() is the only writer.
     *
     * IT IS A FINDING AND NOT A METRIC, and that is the whole reason it is on
     * this struct rather than only in the log. A non-zero value says this node
     * has decided a peer is gone and is not going to ask again, which is a
     * correct decision and an OPERATIONAL one: nothing in the shipped binary
     * clears it, so the peer stays unreachable from here until somebody restarts
     * this node or reaches fed_link_reset(). A dashboard that showed
     * reconnects per second would show a healthy number while the mesh was
     * quietly partitioned, and this is the number that would not.
     *
     * It is not n_fed_dead: that counts a peer going silent, which is an event,
     * and this counts a DECISION, of which there is at most one per link per
     * streak of failures. A peer that flaps contributes many of the first and
     * none of the second. */
    uint64_t  n_fed_retry_exhausted; /* links whose retry budget ran out */

    /* Phase 9: the remote-nick registry's one event, and a real loss.
     *
     * A count of remote users this node was told about and then had no room for.
     * It is a finding rather than a statistic: a node whose counter climbs is a
     * node being told about more remote users than IRC_FED_MAX_REMOTE_NICKS can
     * hold, and every eviction is a `nick@server` that resolves to nothing until
     * the next resync. The eviction is never a refusal -- the entry that went is
     * the LEAST RECENTLY LEARNED, and the next resync from that peer will supply
     * it again -- so the cost of a high count is latency on routing, not lost
     * state.
     *
     * It is not n_fed_malformed and not n_fed_squit_self, for the same reason
     * those are separate: a malformed line is a peer that does not implement
     * 4.3, and this is a peer that implements it perfectly about a mesh larger
     * than this node's cache. */
    uint64_t  n_rnick_evicted;

    /* The registry itself: a vector of entries, ordered least-recently-LEARNED
     * first (so index 0 is the eviction candidate), LAZILY allocated so a node
     * with no peers pays nothing, and released by fed_nickreg_close() from
     * server_shutdown().
     *
     * `nrnicks` is the ALLOCATED length and `nrnick_used` is how much of it holds
     * an entry, which is a distinction worth making explicit: the eviction policy
     * is a bound on USED entries, not on the allocation, and a node that has
     * learned one nick and then forgotten it still holds the whole 86 KiB. That
     * is deliberate -- freeing and reallocating a table on a quiet mesh would put
     * an allocator call on the path a burst takes, and 86 KiB of untouched heap is
     * cheaper than that.
     *
     * `nrnick_swept_ms` is the sweep throttle and 0 means "never swept", which is
     * also the state of a node that has just learned its first nick, so the first
     * sweep is immediate rather than being delayed by an interval measured from
     * zero. */
    struct fed_rnick *rnicks;
    size_t    nrnicks;   /* allocated entries */
    size_t    nrnick_used; /* entries in use */
    uint64_t  nrnick_swept_ms;

    /* ------------------------------------------------------------------------
     * Phase 6 C3: the INBOUND guard chain, one counter per guard that can drop
     * a line. federation/verbs.c's fed_dispatch() is the only writer.
     * ------------------------------------------------------------------------
     *
     * ONE COUNTER PER GUARD, and that is the property worth having: a single
     * "dropped" counter over a chain of ten guards says that something was
     * dropped and nothing about WHICH, and the ten have entirely different
     * fixes -- a hop ceiling that fires is a mesh problem, an own-origin drop is
     * loop prevention WORKING, a duplicate is dedup working, and a malformed
     * line is a peer that does not implement 4.3. An operator reading one
     * number cannot tell those apart, and the numbers are free.
     *
     * They are all ZERO on a node with no peers, so a non-zero value is a real
     * event and not a derived guess. */
    uint64_t  n_fed_preauth_drop;  /* a line arrived on a link that is not up */
    uint64_t  n_fed_hop_drop;      /* hops had reached IRC_MAX_HOPS (2.4)      */
    uint64_t  n_fed_own_origin;    /* the origin was THIS node (2.4)          */
    uint64_t  n_fed_untagged_relay;/* untagged line from a peer naming another */
    uint64_t  n_fed_unknown_verb;  /* not a verb in 4.3's list                */
    uint64_t  n_fed_verb_deferred; /* a 4.3 verb this build does not do yet   */
    uint64_t  n_fed_malformed;     /* arity or field validation refused it    */
    /* The drop the guard chain took at the dedup guard, and the store's own
     * count of the same event. They are incremented together at G7 and are
     * equal on any node this build produces; they are two names for one fact
     * on purpose, because they are read at two different levels -- a loop test
     * asserts on the guard's drop, and a dedup test asserts on the store's --
     * and a difference between them would be a real bug in the chain rather
     * than a number nobody looked at. */
    uint64_t  n_fed_dup_drop;
    uint64_t  n_fed_dedup_dup;

    /* ------------------------------------------------------------------------
     * Phase 6 C5: a peer that says THIS NODE is gone. federation/verbs.c's
     * fed_in_squit() is the only writer, and the line is REFUSED without the link
     * being touched.
     *
     * IT IS NOT n_fed_malformed, and the reason is that the two say opposite
     * things. A malformed line is a peer running a build that does not implement
     * 4.3 -- a version fact, fixed by an upgrade. This is a peer implementing 4.3
     * and announcing that the node it is talking to no longer exists, which
     * 2.3's uniqueness rule says is the announcement a re-joining node acts on.
     * A node whose counter for this climbs is a finding: a peer is out of step
     * with the network, or is hostile, and neither is visible anywhere else.
     *
     * It is not n_fed_unknown_verb either, for the same reason: a peer speaking a
     * verb this build does not speak is the opposite situation from a peer
     * speaking one it should not have sent. */
    uint64_t  n_fed_squit_self;  /* a SQUIT naming THIS node's own name */

    /* ------------------------------------------------------------------------
     * Phase 6 C4: the 4.3 resync, which is a TRANSACTION and therefore has two
     * ways to fail rather than one. federation/burst.c is the only writer.
     *
     * n_burst_refused counts an OUTBOUND burst this node declined to send
     * because it did not fit the staging budget (IRC_BURST_MAX_BYTES, which is
     * half a link's write queue). It is "declined" rather than "failed": nothing
     * was queued, the link was not touched, and the node's own view is
     * untouched. A non-zero value is a node whose state is larger than half a
     * link's queue, which is a finding rather than a statistic.
     *
     * n_burst_abandoned counts an INBOUND burst discarded before its terminator
     * -- a count mismatch, an over-large transaction, a malformed record, or a
     * link that went away mid-burst. It is the observable half of 4.3's "a
     * resync replaces, never merges": the discard is what leaves the PREVIOUS
     * state in place, so a node whose peer has a broken resync is a node whose
     * roster is quietly stale, and a counter is the only thing that says so.
     *
     * n_burst_truncated counts the ONE of those discards that is a truncation:
     * SBURSTE's counts disagreeing with what actually arrived. It is a second
     * name for a subset of the event above, deliberately, for the same reason
     * n_fed_dup_drop and n_fed_dedup_dup are two names for one fact -- they are
     * read at two different levels. n_burst_abandoned says "a transaction was
     * thrown away" and is the number an operator diagnosing a stale roster
     * wants; n_burst_truncated says "and the reason was that the peer's
     * terminator disagreed with its own records", which is a different fault
     * with a different fix -- a lossy or saturating link rather than a peer that
     * does not implement 4.3. Before it existed, that fault was visible only as
     * one log line. Both are incremented on the same branch and are NOT
     * alternatives to one another.
     *
     * They are NOT the same event as n_burst_refused and are not incremented
     * together, which is why the pair above them -- one guard, one event, two
     * counters at two levels of reading -- is not these. A burst that never left
     * is a different problem from one that arrived and was thrown away, and an
     * operator diagnosing a stale roster wants the second number and an operator
     * diagnosing a node that cannot sync wants the first. */
    uint64_t  n_burst_refused;
    uint64_t  n_burst_abandoned;
    uint64_t  n_burst_truncated;

    /* ------------------------------------------------------------------------
     * Phase 7: the topic cache, and the one event it can have.
     * ------------------------------------------------------------------------
     *
     * WHY A CACHE EXISTS AT ALL, since 2.2 disposes a channel with no members.
     * chan_dispose_if_empty() frees a channel that has no local members and no
     * member-server, and it must: a channel nobody is on has nothing to be
     * authoritative about, and holding one per channel name a client ever typed
     * would be an unbounded store reachable from the wire. The topic is the one
     * field whose loss is visible -- a client that rejoins a channel everybody
     * has left finds a topicless channel, which is indistinguishable from a
     * channel that never had one -- so the topic is copied out on the way down
     * and copied back in when the channel is created again. See
     * server_topic_remember() and server_topic_restore() in channel.h.
     *
     * The alternative designs were considered and rejected rather than
     * overlooked. Keeping the chan_t (a leak per channel name, unbounded from the
     * wire). Persisting to disk (a write inside the event loop, and 3.4's rule
     * that nothing in the loop may block; also a new deployment artifact and a
     * new failure mode for a topic). This is the only one of the three that is
     * bounded, allocation-free on the hot path, and honest about its own scope:
     * it does NOT survive a node restart, and nothing claims that it does.
     *
     * `n_topic_cache_full` counts a channel whose topic could NOT be copied out
     * because the cache was at its bound. It is a real loss -- that channel's
     * topic is gone -- and it is a finding rather than a statistic: a node whose
     * counter climbs is a node that has seen more distinct channel names than it
     * can remember topics for, which is the number an operator needs.
     */
    struct chan_topic *topics;
    size_t    ntopics;
    size_t    topics_cap;
    uint64_t  n_topic_cache_full;

    /* ------------------------------------------------------------------------
     * Phase 9: the client session window. core/resume.c owns the records; this
     * struct holds the table pointer and the count, for the same reason the
     * dedup table's does -- so that the function which ends every other
     * allocation on this struct can also end this one, visibly.
     * ------------------------------------------------------------------------
     *
     * `resume_windows` is a flat array of IRC_RESUME_MAX fixed-size records,
     * LAZILY allocated on the first client that drops without a QUIT, and
     * `nresume_used` is how much of it is live. The array is allocated at its
     * FULL bound rather than grown: the bound is about 85 KiB, a growable
     * vector would be a second thing to keep in step with the count, and a
     * partially filled array is the simplest thing to sweep and to index.
     *
     * IT IS NOT A MEMBER-BY-MEMBER LIST, and the reason is the same one the
     * channel set is a list but this is not: a window is about a client, and the
     * thing a client owns is a fixed-size key plus a bounded array of channel
     * names, so a variable-size record per user would make the table's size a
     * function of how many channels users are in -- a number a client
     * controls. See core/resume.h. */
    struct resume_window *resume_windows;
    size_t    nresume_used;
    /* THE SWEEP THROTTLE, and 0 means "never swept", which is also the state of
     * a node that has just recorded its first window -- so the first sweep is
     * immediate rather than being delayed by an interval measured from zero. */
    uint64_t  resume_swept_ms;

    /* THE RESUME COUNTERS, and they are the ones an operator actually reads.
     * Four of them are events rather than statistics, and the distinctions are
     * the point:
     *
     *   n_resume_noted        a window was recorded: a client dropped with no
     *                         QUIT, was registered, and had joined something.
     *   n_resume_applied      a window was consumed by a returning client. The
     *                         PAIR (noted, applied) is the feature working; a
     *                         node where noted climbs and applied does not is a
     *                         node whose clients are not coming back, or whose
     *                         windows are being missed for another reason.
     *   n_resume_expired      a window aged out, whether by the sweep or by the
     *                         miss at restore time. This is the number that says
     *                         "the bound is too short for this node's clients",
     *                         and it is separated from n_resume_chan_gone because
     *                         an expired window and a vanished channel are
     *                         different problems with different fixes.
     *   n_resume_rejected     a window was refused outright: the table could not
     *                         be allocated, or the client had no channels to
     *                         record. Zero on any healthy node, so a non-zero
     *                         value is a finding.
     *   n_resume_evicted      the table was FULL and the oldest window went. A
     *                         node whose counter climbs is a node where clients
     *                         are dropping faster than IRC_RESUME_MAX can hold
     *                         them, which is the number that says "raise the
     *                         bound".
     *   n_resume_chan_gone    a channel in the window no longer exists. Expected
     *                         after a restart of the client, common after a
     *                         channel was disposed while the client was away, and
     *                         the client is told each time.
     *   n_resume_chan_taken   a channel in the window now has a DIFFERENT local
     *                         member under the same nickname -- another client
     *                         claimed the nick inside the window and joined. The
     *                         restore is refused for that channel rather than
     *                         putting two members with one nickname in a roster.
     *   n_resume_alloc_failed the table could not be allocated. A node that
     *                         cannot remember cannot resume, and saying so is
     *                         better than a feature that silently did not record.
     *   n_resume_swept        windows dropped by the sweep, cumulatively. The
     *                         total, where the others are per-window events. */
    uint64_t  n_resume_noted;
    uint64_t  n_resume_applied;
    uint64_t  n_resume_expired;
    uint64_t  n_resume_rejected;
    uint64_t  n_resume_evicted;
    uint64_t  n_resume_chan_gone;
    uint64_t  n_resume_chan_taken;
    uint64_t  n_resume_alloc_failed;
    uint64_t  n_resume_swept;

    /* ------------------------------------------------------------------------
     * Phase 9 item 4: what a peer ADVERTISES about itself. OBSERVATIONAL ONLY, and
     * that is the load-bearing word in the whole structure.
     * ------------------------------------------------------------------------
     *
     * A peer on an established link may tell this node its own name, its own
     * dial hint (host and port) and a load percentage. This node records all
     * three, reports them, and -- this is the security property, and it is
     * STRUCTURAL rather than a check somebody has to remember -- NEVER uses them
     * as a dial target.
     *
     * WHY THAT MATTERS ENOUGH TO SHAPE THE DATA STRUCTURE. `FEDERATE` carries
     * the shared federation secret, so anything this node accepts as a peer is
     * something that knows the secret. A store of learned addresses that fed the
     * dial path would let a peer -- or anything that has obtained the secret, or
     * a misconfigured peer on the far side of a compromised host -- hand this
     * node an arbitrary host:port and make it open a connection there. That is a
     * server-side request forgery primitive wearing a protocol, and the address
     * it would connect to is exactly the thing an SSRF wants: a host that is not
     * reachable from outside, reached from inside, on a port the attacker chose.
     *
     * SO THE STORE IS NOT `server_t::links` AND NOT `server_t::dials`, and that
     * separation is the enforcement. The only writer of a link's dial address is
     * fed_link_configure(), which takes it from the OPERATOR's command line
     * (3.4: "HOST and PORT are resolved to a address ONCE, at startup, and never
     * inside the event loop"). The tick's T7 arm dials only a link that has
     * `initiator != 0` AND `addrlen != 0`, and both of those are set by that one
     * function. A learned advertisement cannot reach either field because there
     * is no API that would let it, and `fed_advertised_*` below returns TEXT for
     * logs and counters and nothing else.
     *
     * A future reader who wants to dial from this store is about to introduce an
     * SSRF and must first write the threat model that makes it acceptable: which
     * peers are trusted to name which addresses, what stops a compromised peer
     * from naming an internal one, and what an operator does when a peer names an
     * address this node is not allowed to reach. None of those questions has an
     * answer in this build, and "the secret is shared" is not one. */
    struct fed_advert *advs;
    size_t    nadv;      /* live entries; the array is allocated at its bound */
    /* THIS NODE'S OWN LOAD, which is what an outbound ADVERTISE carries. A knob
     * rather than a metric, because this node has no load measurement: the
     * honest thing to put on the wire from a node that cannot measure its own
     * load is a value an operator set, and a fabricated 0% would be a number this
     * node does not believe. */
    unsigned  load_pct;
    uint64_t  advert_sent_ms; /* the per-node advertisement interval stamp */
    /* At or above this percentage, a PEER's advertised load is REPORTED as
     * shedding (link.c's T8 arm). AN OPERATOR KNOB AND NOT A POLICY, for the same
     * reason load_pct above is one: this node measures no load -- not its own and
     * certainly not anybody else's -- so it has no opinion about what figure is too
     * high, and "100%" as a shipped constant would be a threshold this codebase
     * invented and then called a finding. Zero means no opinion, which is the
     * shipped state.
     *
     * WHAT THE ARM IS ALLOWED TO DO WITH IT, and the whole of the value: REPORT.
     * It prints one line per crossing and counts it. It does not route around the
     * busy peer, does not refuse it new channels, does not move anybody anywhere,
     * and does not touch the dial path. Two reasons, both structural rather than
     * cautious:
     *
     *   2.2 makes a channel's origin IMMUTABLE and fails closed when it dies, so
     *       there is no "move the channel to a quieter node" operation to call --
     *       re-homing a channel is origin re-election, which 9's risk table
     *       records as NOT STARTED and not to be begun without re-opening 2.4.
     *   A client's session belongs to the node its socket is connected to. This
     *       codebase has no session-transfer verb and no client-visible redirect,
     *       so "send the load elsewhere" has no mechanism at all: there is nothing
     *       to send and nothing that would accept it.
     *
     * So the honest reaction to a busy peer is to make the fact VISIBLE to whoever
     * can act on it -- an operator, or a supervisor above this codebase, which is
     * where node lifecycle lives. That is the whole of propagation here, and the
     * line says so with action=REPORT_ONLY rather than leaving a reader to guess
     * whether something further happened. */
    unsigned  shed_pct;

    /* THE ADVERTISEMENT COUNTERS. Four, and the distinctions are the point:
     *
     *   n_fed_advertise        ADVERTISE lines applied. An advertisement the node
     *                         did not understand is not this.
     *   n_fed_advertise_bad    ADVERTISE lines REFUSED for a payload that is not
     *                         one: a load outside 0..100, a name that is not a
     *                         legal 2.4 server name, a port outside 1..65535, a
     *                         hint that is not three parameters. Zero on a
     *                         healthy mesh, so a non-zero value is a peer running
     *                         something this build does not speak.
     *   n_fed_advertise_collision
     *                         A peer advertised a name this node already has a
     *                         LINK to, or its own. 2.3 makes two nodes with one
     *                         name "catastrophic and undetectable later", and an
     *                         advertisement is the cheapest way to detect it --
     *                         which is one of the three things this store is
     *                         allowed to be used for. It is a FINDING: the
     *                         handshake refuses the second node, so this counter
     *                         is how an operator finds out that two of their
     *                         peers are about to fight over a name.
     *   n_fed_shutdown         SHUTDOWN lines applied: a peer said it is leaving
     *                         deliberately.
     *   n_fed_shutdown_relayed SHUTDOWNs this node passed ONWARD as a SQUIT for
     *                         the departing server, so a node two hops away
     *                         learns about it. Separate from the first because a
     *                         node that received a SHUTDOWN and did not relay it
     *                         is a node whose third neighbours keep a roster for a
     *                         server that is gone.
     *   n_fed_shutdown_refused
     *                         SHUTDOWN lines refused for a bad payload, and SHUTDOWN
     *                         that arrived from a link that was not ESTABLISHED
     *                         (the guard chain drops those at G1 and counts them
     *                         on n_fed_preauth_drop, so this is only the arity
     *                         half).
     *   n_fed_shutdown_announced
     *                         SHUTDOWNs this node SENT on its own way out, and the
     *                         reason it is counted here rather than being a bare
     *                         observable is that a graceful leave that nobody
     *                         received is indistinguishable from a crash. */
    uint64_t  n_fed_advertise;
    uint64_t  n_fed_advertise_bad;
    uint64_t  n_fed_advertise_collision;
    uint64_t  n_fed_shutdown;
    uint64_t  n_fed_shutdown_relayed;
    uint64_t  n_fed_shutdown_refused;
    uint64_t  n_fed_shutdown_announced;
    /* A PEER REPORTED AS SHEDDING, counted once per threshold CROSSING rather than
     * once per tick -- the latch is server_link_t::shed_reported and server.h's
     * shed_pct block gives the whole argument for why the count is of crossings.
     * Zero on every node with no threshold set, which is the shipped state, so a
     * non-zero value means an operator asked for this and a peer crossed the line
     * they set.
     *
     * It is counted rather than inferred from the `fed_shed:` lines because a log is
     * not a number an operator can watch, and this is the one that answers "has
     * anything on my mesh been busy, and how often". What it does NOT count is any
     * movement of clients or channels, because this node moves none: see
     * shed_pct's block, where the two structural reasons are stated. */
    uint64_t  n_fed_shed;

    /* ------------------------------------------------------------------------
     * Phase 8: authentication. Both counters are events, not derived guesses.
     * ------------------------------------------------------------------------
     *
     * n_sasl_ok counts exchanges that verified against the store. n_sasl_fail
     * counts exchanges that DID NOT -- a bad credential, an unknown authcid, a
     * malformed payload, a refused proxying authzid. Both are zero on a node with
     * no --sasl-store, because a node that cannot authenticate anybody never
     * completes an exchange, and that is what makes the two numbers
     * distinguishable from a node whose store failed to load.
     *
     * A FAILURE IS NOT LOGGED WITH ITS INPUT. There is no password, no base64
     * payload and no authcid on any [observable] line anywhere in the SASL path:
     * the observable facts an operator needs are how many exchanges failed and
     * why (the sasl_state_t), and every one of those is countable without
     * touching a secret. */
    struct sasl_store *sasl_store;
    uint64_t  n_sasl_ok;
    uint64_t  n_sasl_fail;

    int       trace;             /* emit [observable] per-line output */
};

/* Zero the struct and set the node name plus the per-boot epoch. `name` must
 * satisfy irc_serve_server_name_valid() (the 2.4 tag grammar); it is rejected
 * with -1 because a name this node cannot stamp on its own outbound tags would
 * break loop prevention at the first relay. Returns 0 on success. Does not
 * open anything -- server_listen() does that separately so a test can build a
 * server_t without a socket. */
int server_init(server_t *s, const char *name);

/* Release the registries, the dial table, the peer-link vector, the dedup table
 * and the by_fd array, close the listener, and close any connection still
 * registered. Safe on a zeroed struct.
 *
 * The two new arms sit next to the dials arm rather than at the end, and they
 * are ordered BEFORE the by_fd walk conceptually even though they are not: a
 * link names a descriptor, and the only reason the free is safe is that every
 * conn is already gone by the time a link stops being able to name one. That
 * ordering is the whole invariant, so it is worth saying here where a reader
 * adding a fourth arm will see it.
 *
 * The FOURTH ARM -- fed_burst_close(), which releases 4.3's inbound resync shadow
 * -- is the one that is not a field on this struct, and it is a CALL rather than a
 * free for the reason the dedup table's is not: the shadow is a module global in
 * federation/burst.c, so the owner has to do it. It sits with the dedup free
 * because both are "a federation module's memory, released here", and both are
 * ASSERTED NOT VERIFIED on Darwin -- LeakSanitizer does not run on this platform,
 * so the Linux CI job is what proves either free.
 *
 * ---------------------------------------------------------------------------
 * THE FIRST THING IT DOES, AND IT IS NOT A FREE: IT SAYS GOODBYE
 * ---------------------------------------------------------------------------
 * fed_send_shutdown() runs BEFORE the by_fd walk, because the walk is what closes
 * the sockets a goodbye would have to travel on. This is the ONLY caller of
 * fed_send_shutdown() in the tree (link.h says so, and this is where that claim is
 * kept true), and it is the difference between a planned restart and a crash on
 * every peer of the mesh:
 *
 *   without it  this node's peers discover the departure by TIMEOUT. T4 declares
 *               the link dead, fed_retry_arm() spends budget, T7 dials three times
 *               and gives up -- and the departing node's name stays in the roster
 *               of every node until a SQUIT arrives, which it never will, because
 *               the node that would have sent it is the one that went away.
 *   with it     each peer gets a SHUTDOWN, marks the link CLEANLY departed
 *               (link.c's T7 arm refuses a link with clean_leave set), purges that
 *               origin's roster, and tells its own peers onward as a SQUIT.
 *
 * IT IS BEST EFFORT and the limit is real: the line is queued and drained by one
 * conn_pump() per link, and everything after this point in the function closes the
 * descriptors it was queued on. On a lossy path a goodbye can therefore be lost,
 * and that degradation is CORRECT rather than a defect -- the peer that does not
 * hear it applies its retry policy and finds the node gone. The cost of sending it
 * is that a clean leave occasionally reads as a failure; the cost of not sending it
 * is that EVERY clean leave reads as one.
 *
 * IT IS SAFE ON A server_t THAT NEVER FEDERATED, and on one whose links were never
 * established, because the sender counts ESTABLISHED links with a live conn first
 * and returns 0 when there are none -- so the four early server_shutdown() calls in
 * node_main.c (fed_open() failed, a peer would not resolve, listen() failed) cost
 * one pass over a link vector that is empty or has no ESTABLISHED entry. Those four
 * paths are why this cannot sit behind "only if we federated": each of them is a
 * startup failure with a partially built node, and a guard that asked a question of
 * a half-built node would be a new way to fail during startup. */
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
 * that does not exist until Phase 9.
 *
 * ---------------------------------------------------------------------------
 * NICKNAMES ARE CASE-INSENSITIVE, AND THAT IS A PROPERTY OF THIS REGISTRY
 * ---------------------------------------------------------------------------
 * 2.1 and RFC 2812 2.3.1 both say nicknames are case-insensitive, so `BOB` and
 * `bob` are ONE name: exactly one of them can be held at a time, and a lookup of
 * either finds the other. The table folds on the way in, so this holds for every
 * operation above without any of them remembering to fold -- the thing a new
 * caller must not have to get right, because getting it wrong is issue #100: a
 * case-sensitive registry answered 401 to `PRIVMSG BOB :hi` for a user connected
 * as `bob`, and let `bob` and `BOB` both be claimed.
 *
 * The fold is ASCII, matching the CASEMAPPING=ascii this node advertises in 005.
 *
 * ---------------------------------------------------------------------------
 * THE DISPLAYED CASE IS NOT THE STORED CASE, AND MUST NOT BE
 * ---------------------------------------------------------------------------
 * conn_t::nick keeps the spelling the user chose, and every numeric and prefix
 * renders from it (353 in chan_verbs.c, reply.c's target and prefix, 352 and 311
 * in msg_verbs.c). So a user who registers as `Bob` is `Bob` on the wire
 * everywhere, and the folded key is invisible. Only the DUPlicate decision is
 * case-blind: `NICK BOB` from the holder of `bob` is the same nickname and is
 * silent (RFC 2812 3.2), while `NICK BOB` from anybody else is 433.
 *
 * That is why the folded form is a COPY kept inside the table and not the field
 * itself: making conn_t::nick lowercase would be simpler to reason about and
 * would break every client that displays a user's chosen case.
 *
 * ---------------------------------------------------------------------------
 * WHICH OF THESE TO CALL, AND WHY IT IS NOT A MATTER OF TASTE
 * ---------------------------------------------------------------------------
 * Three operations, and picking the wrong one is a memory-safety bug rather
 * than a style question, because the table and the enumeration are one index
 * and neither half may be applied without the other:
 *
 *   server_nick_claim(s, nick, c)   A connection takes a name it was not
 *                                   holding. Refuses a name somebody else
 *                                   holds. Does NOT refuse a connection that
 *                                   already holds another name: the caller may
 *                                   be mid-rename, and refusing would force it
 *                                   to release first and open a window in which
 *                                   the name it is giving up is unowned. The
 *                                   enumeration is a set, so a second name
 *                                   does not add a second entry (issue #103).
 *   server_nick_release(s, nick)    A connection gives up ONE name and stays.
 *                                   The holder is read from the table, so any
 *                                   spelling finds it, and the holder leaves
 *                                   the enumeration only if it holds no other
 *                                   name. This is the rename's release.
 *   server_nick_unclaim(s, c)       A connection is being RETIRED. Both halves,
 *                                   keyed on the connection, and the only thing
 *                                   a teardown may use.
 *
 * server_nick_unclaim() is the one that has to be impossible to get half-wrong,
 * so it is the one that takes a conn_t. A teardown handed a name has to ask
 * whether this connection still holds it and then remove it, and that guard --
 * "a conn that was DENIED the nick must not evict the one that holds it" -- is
 * exactly what issue #102 had: it was correct, and it wrapped ONE half of the
 * index, so the other half was left behind and the freed conn_t stayed in the
 * enumeration for WHO to walk. Keyed on the connection, there is no guard to
 * remember: the table loses the entries whose value IS this conn and the vector
 * loses the entries that ARE this conn, so the two cannot disagree and a
 * connection holding several names loses all of them at once.
 *
 * Every close goes through it, QUIT included: a QUIT releases the name early so
 * it is available sooner, and the reaper's call is then a no-op because the
 * table no longer maps any name to that conn. Two paths, one function, which is
 * the point -- they are the two paths that used to differ.
 */
int server_nick_claim(server_t *s, const char *nick, conn_t *c);
void server_nick_release(server_t *s, const char *nick);
conn_t *server_nick_lookup(const server_t *s, const char *nick);

/* Retire `c` from the nick index: every name it holds leaves the table, and it
 * leaves the enumeration. Idempotent, and a no-op for a connection that never
 * claimed a name -- which is most closes, since a connection can be closed at
 * any point in registration.
 *
 * This is the ONLY nick operation a teardown may use, and it must be called
 * before conn_free(). server_close_conn() and handle_quit() both do, and
 * test_disconnect_nick.c fails the build if either stops, or starts touching
 * the table or the vector itself. */
void server_nick_unclaim(server_t *s, conn_t *c);

/* The enumeration, in first-claim order. server_nick_count()/server_nick_at()
 * answer "every USER on this node" for WHO's <mask> form and for nothing else:
 * one entry per connection, not per name, so the count is a number of people
 * and a 352 sequence is a function of who connected when rather than of
 * allocator behaviour or of how many names one of them happens to hold. A
 * caller that wants a specific user asks server_nick_lookup() first and only
 * falls back to a walk when it has to match case or a glob. */
size_t server_nick_count(const server_t *s);
conn_t *server_nick_at(const server_t *s, size_t i);

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
 * Find the connection carrying an ESTABLISHED link to the peer called `name`
 * (ASCII case-insensitively, per 2.1 and 2.4). Returns NULL when there is no
 * such link, and equally when the link exists and is not ESTABLISHED.
 *
 * The two NULLs are the same answer on purpose. "Can this node route to the
 * origin?" is what callers ask, and a link that has not finished the handshake
 * FSM is not yet a route: forwarding onto it would put an S-verb on a socket
 * whose peer has not authenticated and whose server name is not yet known, and
 * 2.3 requires the name-uniqueness check to happen before ESTABLISHED. This is
 * the narrowing Phase 6 promised here, and it is why the question lives in a
 * function rather than in a flag a caller has to remember to test.
 *
 * THE LOOKUP IS THE LINK, NOT THE NAME
 * ------------------------------------
 * Phase 2 answered this by scanning by_fd for a CONN_SERVER whose
 * conn_t::peer_name matched. That is now the wrong shape: by_fd is the index of
 * LIVE CONNECTIONS, and a peer is not the same thing as a connection to it. The
 * link is the answer, the link names the descriptor, and the descriptor is
 * looked up in by_fd -- so a link with no socket is not a route, a link with a
 * stale descriptor cannot resolve to a different peer's connection, and
 * conn_t::peer_name is left as the display copy it was always described as
 * rather than becoming a second, routing-authoritative name.
 *
 * The cost is two array bounds rather than one: the link vector is walked (O(peers),
 * which is 2.3's own set and is a handful of entries) and the by_fd table is
 * indexed. The FD_SETSIZE scan Phase 2 paid on every miss is gone, and no
 * caller pays it on the common path anyway because chan_origin_is_self() --
 * which fanout_resolve() and the single-writer rule both consult -- answers
 * before this is ever reached for a channel this node owns. */
conn_t *server_find_peer(const server_t *s, const char *name);

/* ---------------------------------------------------------------------------
 * The link registry (2.3), above server_find_peer because it is what that is
 * built from.
 * ---------------------------------------------------------------------------
 * server_find_link() is the name -> link half, with the same ASCII fold, and it
 * answers for a link that is not ESTABLISHED: "do we know a peer called this,
 * and what state is it in" is a different question from "can we route to it",
 * and the link lifecycle needs it. The two are separate functions for the same
 * reason conn_t::peer_name and server_link_t::name are: a predicate that
 * answered both would make the caller choose which question it meant.
 *
 * server_link_count()/server_link_at() are the enumeration, and they have no
 * per-peer use yet -- the link tick and the burst do, and neither is in this
 * commit. They land with the vector rather than with its first reader so the
 * vector is never walked by hand in a file that should not know its layout,
 * which is the same reason nick_objs has an enumeration beside its table.
 */
server_link_t *server_find_link(const server_t *s, const char *name);
size_t server_link_count(const server_t *s);
server_link_t *server_link_at(const server_t *s, size_t i);

/* The connection a link currently rides on: by_fd[link->fd], or NULL when the
 * link has no socket, when the descriptor is outside the poll() set, or when
 * that slot is free. The out-of-range test is not defensive noise -- by_fd is
 * indexed BY the descriptor, so an fd the table cannot hold is a link that
 * cannot name a connection, and indexing it anyway is a read of whatever slot
 * happens to be there. */
conn_t *server_link_conn(const server_t *s, const server_link_t *link);

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
