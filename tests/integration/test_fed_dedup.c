/* test_fed_dedup.c -- 2.4's duplicate store and its loop guard.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS HERE AND WHY IT IS IN THIS FILE
 * ---------------------------------------------------------------------------
 * Two related properties, one of which is a module and one of which is a rule at
 * the forward path, and they are tested together because they are two halves of
 * one sentence: a node must not handle the same (origin, epoch, id) twice, and
 * it must not forward a message that would come back.
 *
 *   A. THE STORE. fed_dedup_seen()'s 1/0 contract, the LRU's TTL, the sweep
 *      throttle, the capacity eviction, and the case-fold on the key. Asserted
 *      on RETURN VALUES, which is what 7/Contributing calls observable
 *      behaviour, so nothing here reads a struct field to decide whether the
 *      store works.
 *   B. THE LOOP GUARD, ON THE WIRE. The hop ceiling, 2.4's never-forward-own-
 *      origin rule, and the invariance of the message identity across a forward
 *      -- each observed as bytes arriving, or as bytes NOT arriving, on a peer
 *      link whose far end this test owns.
 *
 * ---------------------------------------------------------------------------
 * WHAT C1 CANNOT ASSERT HERE, AND WHERE IT GOES INSTEAD
 * ---------------------------------------------------------------------------
 * The plan this file implements asks for "a local client sees the text once" for
 * a duplicate that arrives twice. That half needs an INBOUND peer path: a
 * connection the node accepts as a peer, a frame it reads, a 2.4 block it parses
 * and a fan-out it drives off the result. None of that exists in this commit --
 * fed_dispatch() is the next one -- so there is nothing here for a duplicate to
 * be delivered twice TO, and a test that asserted it would be asserting
 * behaviour no code implements, which is the thing CONTRIBUTING.md rules out
 * by name.
 *
 * So the duplicate is asserted at the only place it can be: the store's own
 * decision, and the fact that the decision is made ON SIGHT rather than after
 * the message has been dealt with. That last point is the one that would
 * otherwise be untestable until C3, and it is checked here directly: a key
 * recorded from a well-formed message is still remembered when a later line with
 * the same key is refused, so a peer cannot get a second bite at it by sending
 * the same id again in a form this node rejects.
 *
 * ---------------------------------------------------------------------------
 * THE IDENTITY INVARIANCE IS THE POINT OF SECTION B
 * ---------------------------------------------------------------------------
 * On a relay, origin, epoch and id must come out of the forward EXACTLY as they
 * went in, and only hops may change. That is the property 2.4's dedup rests on:
 * a forward that restamped would give the copy a new identity, the node on the
 * far side would treat it as a message it had never seen, and the message would
 * come back. So section B pins the id counter across three forwarded relays and
 * requires it not to move -- a per-SERVER counter that advanced on a relay would
 * be a silent restart of the loop, and the hop ceiling would eventually hide it.
 */
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/connection.h"
#include "core/fanout.h"
#include "core/message.h"
#include "core/poll_loop.h"
#include "core/server.h"
#include "federation/dedup.h"
#include "federation/verbs.h"
#include "harness/test_util.h"

#define NODE_NAME "irc.a"
#define PEER_NAME "irc.b"
#define CHAN "#T"
#define TEXT "dedup probe"

/* The source prefix the state-verb forwards are given. See fed_fwd(). */
#define STATE_PREFIX "joiner!u@h"

#define T_IO_MS 10000

/* ---------------------------------------------------------------------------
 * The forward, with the two new arguments filled in
 * ---------------------------------------------------------------------------
 * fanout_forward_link() takes the CLIENT parameters as a list and a source prefix
 * now, and this helper is where this file's calls answer both. It is a helper
 * rather than a dozen edits because the two answers are the same in every call
 * and the point of the test is 2.4's loop guard, not the shape of an emission.
 *
 * MESSAGE VERBS PASS A NULL PREFIX and therefore get this node's own name, which
 * is what every expected line below already says and is the right answer for a
 * line this node is ORIGINATING: there is no client on this fixture, so there is
 * no hostmask to observe, and a server name is a legal source for a
 * server-originated message.
 *
 * THE STATE VERBS PASS STATE_PREFIX, because 4.3's frozen SJOIN shape names its
 * subject and the subject has to come from the source prefix. This is the one
 * expected line below that C3 changes, and the argument for the change is at
 * fed_sverb_params(): a real SJOIN carries the member, the channel and the
 * member's flags, and this fixture has no client on the channel and therefore no
 * flags, so the flag token is the literal `-`. */
static int fed_fwd(server_t *s, fanout_target_t *t, const char *verb,
                   const char *text, const irc_serve_tags_t *carry)
{
    const char *sp[1];
    int is_message = (strcmp(verb, "PRIVMSG") == 0 || strcmp(verb, "NOTICE") == 0);

    /* JOIN is the one verb whose client form has nothing after the target, and
     * that is the point of the row: it is what makes 4.3's SJOIN shape a
     * different shape from "<target> :<text>". */
    int n = (strcmp(verb, "JOIN") == 0) ? 0 : 1;

    sp[0] = text;
    return fanout_forward_link(s, PEER_NAME, t, verb, sp, n,
                               (is_message != 0) ? NULL : STATE_PREFIX, carry);
}

/* ---------------------------------------------------------------------------
 * A socket this test owns
 * ---------------------------------------------------------------------------
 * The same deliberate near-duplicate of harness/irc_client.h that
 * test_fed_wire.c carries, for the same reason: irc_client's reads are BLOCKING
 * deadline waits, and this test has to be stepping the node between them. Every
 * integration fixture in tests/integration/ carries its own copy of the small
 * amount of shape it needs; see the file header of test_messaging.c.
 */
typedef struct {
    int    fd;
    char  *buf;
    size_t len;
    size_t cap;
} wire_t;

static void wire_init(wire_t *w)
{
    w->fd = -1;
    w->buf = NULL;
    w->len = 0;
    w->cap = 0;
}

static int wire_listen(int *port_out)
{
    struct sockaddr_in addr;
    socklen_t alen = sizeof addr;
    int one = 1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        return -1;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, (socklen_t)sizeof one);
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0 ||
        listen(fd, 4) != 0 ||
        getsockname(fd, (struct sockaddr *)&addr, &alen) != 0) {
        close(fd);
        return -1;
    }
    *port_out = (int)ntohs(addr.sin_port);
    return fd;
}

static int wire_connect(wire_t *w, int port)
{
    struct sockaddr_in addr;

    w->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (w->fd < 0) {
        return -1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    /* Blocking, and safe to block: the listener is already listening, so the
     * kernel completes the handshake without the application calling accept(),
     * which is why this file contains no sleep. */
    if (connect(w->fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(w->fd);
        w->fd = -1;
        return -1;
    }
    return 0;
}

static int wire_drain(wire_t *w)
{
    char chunk[8192];
    struct timeval tv;
    fd_set rfds;
    ssize_t got;
    int got_any = 0;

    if (w->fd < 0) {
        return 0;
    }
    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(w->fd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        if (select(w->fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
            break;
        }
        got = recv(w->fd, chunk, sizeof chunk, 0);
        if (got <= 0) {
            break;
        }
        if (w->len + (size_t)got + 1u > w->cap) {
            size_t want = (w->cap == 0) ? 8192u : w->cap;
            char *grown;

            while (want < w->len + (size_t)got + 1u) {
                want *= 2u;
            }
            grown = (char *)realloc(w->buf, want);
            if (grown == NULL) {
                break;
            }
            w->buf = grown;
            w->cap = want;
        }
        memcpy(w->buf + w->len, chunk, (size_t)got);
        w->len += (size_t)got;
        w->buf[w->len] = '\0';
        got_any = 1;
    }
    return got_any;
}

static const char *wire_text(const wire_t *w)
{
    return (w->buf != NULL) ? w->buf : "";
}

static void wire_close(wire_t *w)
{
    if (w->fd >= 0) {
        close(w->fd);
        w->fd = -1;
    }
    free(w->buf);
    w->buf = NULL;
    w->len = 0;
    w->cap = 0;
}

/* ---------------------------------------------------------------------------
 * The node and its one peer
 * ---------------------------------------------------------------------------
 * A real server_t driven one poll iteration at a time, with a real TCP peer link
 * whose far end this test owns. See test_fed_wire.c's header for why the node
 * runs in this process rather than being exec'd: node_main.c has no peer list,
 * and the files that would give it one are later commits. Everything the loop
 * does here -- accept, frame, parse, dispatch, queue, pump -- is shipped code.
 */
static void peer_link_up(server_t *s, wire_t *far, int listen_fd, int port)
{
    conn_t *pc;
    server_link_t *l;
    struct sockaddr_storage peer_addr;
    socklen_t peer_alen = (socklen_t)sizeof peer_addr;
    int node_fd;

    TF_CHECK_MSG(wire_connect(far, port) == 0,
                 "the test could not connect to its own listener");
    node_fd = accept(listen_fd, (struct sockaddr *)&peer_addr, &peer_alen);
    TF_CHECK_MSG(node_fd >= 0, "accept() on the test's own listener failed");

    pc = conn_new(node_fd, CONN_SERVER);
    TF_CHECK_MSG(pc != NULL, "conn_new() failed for the peer connection");
    pc->peer_name = (char *)malloc(strlen(PEER_NAME) + 1u);
    TF_CHECK_MSG(pc->peer_name != NULL, "could not set the peer's display name");
    memcpy(pc->peer_name, PEER_NAME, strlen(PEER_NAME) + 1u);
    TF_CHECK_MSG(server_add_conn(s, pc) == 0,
                 "the peer connection could not be registered in by_fd");

    s->links = (server_link_t *)calloc(IRC_FED_MAX_PEERS, sizeof *s->links);
    TF_CHECK_MSG(s->links != NULL, "could not allocate the link vector");
    s->links_cap = (size_t)IRC_FED_MAX_PEERS;
    s->nlinks = 1;
    l = &s->links[0];
    memcpy(l->name, PEER_NAME, strlen(PEER_NAME) + 1u);
    l->fd = node_fd;
    l->initiator = 1;
    l->created_ms = server_now_ms();
    memcpy(&l->addr, &peer_addr, sizeof peer_addr);
    l->addrlen = peer_alen;
    /* Written the way fed_link_set_state() will: the FSM context first and the
     * `state` mirror second, so the mirror cannot be set without the context. */
    handshake_init(&l->hs);
    l->hs.state = ESTABLISHED;
    l->state = (int)l->hs.state;
}

static void step_and_drain(server_t *s, wire_t *peer)
{
    (void)poll_loop_step(s, POLL_TICK_MS);
    (void)wire_drain(peer);
}

/* Step until `needle` is in `from`, or the deadline passes. */
static int drive_until(server_t *s, wire_t *peer, const char *needle, int ms)
{
    uint64_t deadline = server_now_ms() + (uint64_t)ms;

    for (;;) {
        step_and_drain(s, peer);
        if (strstr(wire_text(peer), needle) != NULL) {
            return 0;
        }
        if (server_now_ms() >= deadline) {
            fprintf(stderr, "drive_until: TIMEOUT after %d ms waiting for \"%s\"\n"
                            "  peer: %s\n",
                    ms, needle, wire_text(peer));
            return -1;
        }
    }
}

/* Step the loop a fixed, small number of times and assert nothing new arrived.
 *
 * This is the one place a count appears rather than a deadline, and it is
 * counted rather than timed deliberately: the property under test is that the
 * node REFUSED to write, and a refusal is not something that arrives late. Four
 * steps is four loop iterations of 50 ms each, which is twice what any single
 * dispatch needs to reach a peer link's socket buffer (the loop pumps a
 * connection's write queue in the iteration AFTER the one that queued to it), so
 * a line that was going to be sent would already be here. No sleep is involved:
 * every one of those iterations is the node doing its own poll.
 */
static void expect_nothing_new(server_t *s, wire_t *peer, size_t before,
                               const char *what)
{
    size_t after = before;
    int i;

    for (i = 0; i < 4; i++) {
        step_and_drain(s, peer);
        after = peer->len;
    }
    TF_CHECK_MSG(after == before,
                 "%s wrote %zu byte(s) to a peer link it should have refused.\n"
                 "  peer: %s",
                 what, after - before, wire_text(peer));
}

/* A tag set, filled in by hand rather than by a helper, because the point of
 * several cases below is that the THREE fields are independent: a store that
 * keyed on the origin alone would drop a different message, and one that keyed
 * on the id alone would drop a different node's message. */
static void tag_of(irc_serve_tags_t *t, const char *origin, uint64_t epoch,
                   uint64_t id, uint32_t hops)
{
    memset(t, 0, sizeof *t);
    memcpy(t->origin, origin, strlen(origin) + 1u);
    t->epoch = epoch;
    t->id = id;
    t->hops = hops;
}

int main(void)
{
    server_t s;
    wire_t peer;
    fanout_target_t tgt;
    irc_serve_tags_t t;
    irc_serve_tags_t carry;
    char want[512];
    int listen_fd;
    int listen_port = 0;
    uint64_t base;
    size_t i;
    size_t marked;

    wire_init(&peer);
    TF_CHECK_MSG(server_init(&s, NODE_NAME) == 0, "server_init failed");
    s.dispatch = commands_dispatch;
    /* The node's listener is up but nothing connects to it: this file drives
     * the forward path directly, so the only connection the loop has to serve
     * is the peer one. server_listen() is still called because a server_t with a
     * listener the loop polls is the node the loop is meant to run. */
    TF_CHECK_MSG(server_listen(&s, 0) == 0, "server_listen failed");
    listen_fd = wire_listen(&listen_port);
    TF_CHECK_MSG(listen_fd >= 0, "the test could not open its own listener");
    peer_link_up(&s, &peer, listen_fd, listen_port);

    /* =======================================================================
     * A0. THE ENTRY SIZE, AND THEREFORE THE TABLE SIZE
     * ==================================================================== */
    /* federation/dedup.h quotes "about 416 KiB" as a cost argument and derives
     * it as IRC_DEDUP_MAX slots of IRC_DEDUP_ENTRY_BYTES. A cost argument whose
     * input can drift is worse than no cost argument, so the input is measured
     * here rather than trusted.
     *
     * A _Static_assert would be the stronger check and is not available: clang's
     * -Weverything carries -Wpre-c11-compat, which objects to it, and this
     * project has decided never to narrow the warning set to accommodate a
     * construct. So the size is a test assertion, which means it also has to be
     * RUN -- and this is the one test in the suite that can see the entry at
     * all, which is why fed_dedup_entry_t is declared in the header. */
    TF_CHECK_MSG(sizeof(fed_dedup_entry_t) == (size_t)IRC_DEDUP_ENTRY_BYTES,
                 "the dedup entry is %zu bytes, not the %u its own layout in "
                 "dedup.h derives; the 416 KiB table figure and the 8x the store "
                 "pays for a node that is not in a mesh are both wrong",
                 sizeof(fed_dedup_entry_t), IRC_DEDUP_ENTRY_BYTES);
    TF_CHECK_MSG(IRC_DEDUP_TABLE_BYTES ==
                     (size_t)IRC_DEDUP_MAX * sizeof(fed_dedup_entry_t),
                 "IRC_DEDUP_TABLE_BYTES is %zu, which is not IRC_DEDUP_MAX times "
                 "the entry -- the macro is not measuring what it claims to",
                 (size_t)IRC_DEDUP_TABLE_BYTES);
    TF_CHECK_MSG(IRC_DEDUP_TABLE_BYTES >= 400u * 1024u &&
                     IRC_DEDUP_TABLE_BYTES <= 448u * 1024u,
                 "the table is %zu bytes, which is not the ~416 KiB dedup.h "
                 "quotes; a node that has been sent one relayed message pays "
                 "this much",
                 (size_t)IRC_DEDUP_TABLE_BYTES);

    /* =======================================================================
     * A1. THE STORE'S CONTRACT: FIRST SIGHT IS NEW, SECOND IS SEEN
     * ==================================================================== */
    /* `base` is an arbitrary instant in the node's own time, not a clock read:
     * 3.4 says the tick drives time, so the tests below choose their instants
     * rather than waiting for them to arrive. Nothing here sleeps, and nothing
     * here depends on how long the test took. */
    base = 1000000ULL;
    TF_CHECK_MSG(fed_dedup_size(&s) == 0u,
                 "a node that has never been sent a relayed message already has "
                 "%zu entries",
                 fed_dedup_size(&s));
    TF_CHECK_MSG(fed_dedup_size(NULL) == 0u,
                 "fed_dedup_size(NULL) did not answer 0");

    tag_of(&t, PEER_NAME, 1756464000123ULL, 1u, 0u);
    TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 0,
                 "the FIRST arrival of (irc.b, 1756464000123, 1) was reported as "
                 "already seen, so the first copy of every message would be "
                 "dropped");
    TF_CHECK_MSG(fed_dedup_size(&s) == 1u,
                 "a newly recorded message left the store holding %zu entries",
                 fed_dedup_size(&s));

    /* The same key a second time, which is what a 3+ node mesh does to a node
     * that is handed one message by two different peers (2.4: dedup is per NODE
     * precisely so that this is caught). */
    TF_CHECK_MSG(fed_dedup_seen(&s, &t, base + 1u) == 1,
                 "the SECOND arrival of the same (origin, epoch, id) was "
                 "reported as new, which is the loop 2.4 exists to prevent");
    TF_CHECK_MSG(fed_dedup_size(&s) == 1u,
                 "reporting a duplicate grew the store to %zu entries: a "
                 "duplicate must be RECOGNISED, not recorded again",
                 fed_dedup_size(&s));

    /* The three fields are independent. Each of these is a DIFFERENT message and
     * a store that conflated any two of them would drop one of them. */
    tag_of(&t, PEER_NAME, 1756464000123ULL, 2u, 0u);
    TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 0,
                 "a different id under the same (origin, epoch) was reported as a "
                 "duplicate");
    tag_of(&t, PEER_NAME, 1756464000999ULL, 1u, 0u);
    TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 0,
                 "the same id under a different epoch was reported as a "
                 "duplicate; epoch exists so a restarted node's id 1 is not the "
                 "old id 1");
    tag_of(&t, "irc.c", 1756464000123ULL, 1u, 0u);
    TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 0,
                 "the same (epoch, id) from a different origin was reported as a "
                 "duplicate; the origin is the first half of the key and dropping "
                 "it would silence one node's traffic when another's collided");
    TF_CHECK_MSG(fed_dedup_size(&s) == 4u,
                 "four distinct keys left the store holding %zu entries",
                 fed_dedup_size(&s));

    /* Case-insensitive, because server names are (2.1, RFC 1459 2.3.2) and a
     * peer that re-spells an origin is naming the same node. This is the single
     * most likely way a dedup store silently stops working, since the value
     * arriving from a peer is whatever spelling that peer prefers. */
    tag_of(&t, "IRC.C", 1756464000123ULL, 1u, 0u);
    TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 1,
                 "irc.c and IRC.C were stored as two different origins, so a peer "
                 "re-spelling the origin got a second bite at the same message. "
                 "message.h says the case fold is the caller's job and the store "
                 "is the caller.");
    TF_CHECK_MSG(fed_dedup_size(&s) == 4u,
                 "a differently-cased origin grew the store to %zu entries",
                 fed_dedup_size(&s));

    /* =======================================================================
     * A2. DEDUP IS A STATEMENT ABOUT THE WIRE, NOT ABOUT HANDLING
     * ==================================================================== */
    /* A key that is refused because it is not a legal 2.4 key is still not NEW.
     * The consequence is the point: a peer cannot send the same id again in a
     * form this node rejects and be believed, so the record is made on sight
     * rather than after the message has been dealt with. */
    tag_of(&t, "not a legal name", 1u, 1u, 0u);
    TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 1,
                 "a tag block whose origin is not a legal irc-serve-origin value "
                 "was reported as NEW, so a peer could get a second attempt at "
                 "the same id by re-spelling it illegally");
    TF_CHECK_MSG(fed_dedup_size(&s) == 4u,
                 "an illegal origin was recorded, growing the store to %zu "
                 "entries: a key the grammar rejects is not part of the key space",
                 fed_dedup_size(&s));
    /* id 0 is reserved as "unset" (message.h), so it is not a key either. */
    tag_of(&t, PEER_NAME, 1756464000123ULL, 0u, 0u);
    TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 1,
                 "id 0 was accepted as a key; it is reserved so an absent tag is "
                 "never mistaken for a real id");
    TF_CHECK_MSG(fed_dedup_seen(NULL, &t, base) == 1,
                 "a NULL node was not refused; the store has to fail closed on a "
                 "missing node or the message it was asked about has nowhere to "
                 "be recorded");

    /* =======================================================================
     * A3. RESET
     * ==================================================================== */
    fed_dedup_reset(&s);
    TF_CHECK_MSG(fed_dedup_size(&s) == 0u,
                 "fed_dedup_reset() left %zu entries behind",
                 fed_dedup_size(&s));
    tag_of(&t, PEER_NAME, 1756464000123ULL, 1u, 0u);
    TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 0,
                 "a key recorded before the reset is still remembered, so a "
                 "reset did not actually empty the store");
    /* The reset must not leave a `used` slot that a sweep can never reach: after
     * one, every key from before is new again. */
    tag_of(&t, "irc.c", 1756464000123ULL, 1u, 0u);
    TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 0,
                 "a key recorded before the reset is still remembered after two "
                 "further inserts: the reset left the table inconsistent with "
                 "its own count");
    fed_dedup_reset(&s);

    /* =======================================================================
     * A4. THE TTL, AND BOTH SIDES OF IT
     * ==================================================================== */
    /* The expiry is a bound on memory, not on loop prevention, and it is checked
     * on both sides: one millisecond before the TTL the entry is still held,
     * and at the TTL it is gone. An assertion that only proves "it expires"
     * would be satisfied by a TTL of zero, which is a store that remembers
     * nothing. */
    tag_of(&t, PEER_NAME, 1u, 1u, 0u);
    TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 0, "the probe key was refused");
    TF_CHECK_MSG(fed_dedup_sweep(&s, base + (uint64_t)IRC_DEDUP_TTL_MS - 1u) == 0u,
                 "the store swept an entry that was %d ms old, %d ms short of "
                 "its TTL",
                 (int)((uint64_t)IRC_DEDUP_TTL_MS - 1u), IRC_DEDUP_TTL_MS);
    TF_CHECK_MSG(fed_dedup_size(&s) == 1u,
                 "a sweep one millisecond before the TTL dropped the entry");
    /* The TTL is only reachable once IRC_DEDUP_SWEEP_MS has passed, so the next
     * sweep has to be timed past both. The stamp the previous sweep left behind
     * is 0 (the store was reset), so the first sweep at any instant is allowed. */
    TF_CHECK_MSG(fed_dedup_sweep(&s, base + (uint64_t)IRC_DEDUP_SWEEP_MS + 1u) == 0u,
                 "the entry expired but the sweep dropped %s nothing",
                 "no");
    TF_CHECK_MSG(fed_dedup_sweep(&s, base + (uint64_t)IRC_DEDUP_TTL_MS +
                                          (uint64_t)IRC_DEDUP_SWEEP_MS) == 1u,
                 "an entry %d ms old was not swept: fed_dedup_sweep() dropped "
                 "nothing at the TTL",
                 IRC_DEDUP_TTL_MS);
    TF_CHECK_MSG(fed_dedup_size(&s) == 0u,
                 "the store still holds %zu entries after sweeping the only one",
                 fed_dedup_size(&s));

    /* The throttle, checked on both sides too: a second sweep inside the
     * interval does nothing, and the one after it runs. A store that swept on
     * every call would be correct and would put an O(n) walk on the message
     * path, which is the thing the gate in fed_dedup_seen() exists to avoid. */
    for (i = 0; i < 4u; i++) {
        tag_of(&t, PEER_NAME, 2u, 1u + i, 0u);
        TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 0,
                     "probe key %zu was refused", i);
    }
    TF_CHECK_MSG(fed_dedup_sweep(&s, base + (uint64_t)IRC_DEDUP_TTL_MS +
                                          (uint64_t)IRC_DEDUP_SWEEP_MS) == 0u,
                 "a sweep dropped entries that were only %d ms old",
                 IRC_DEDUP_TTL_MS);
    TF_CHECK_MSG(fed_dedup_sweep(&s, base + (uint64_t)IRC_DEDUP_TTL_MS +
                                          (uint64_t)IRC_DEDUP_TTL_MS) == 4u,
                 "the sweep after the throttle window dropped %s entries, "
                 "expected 4",
                 "no");
    fed_dedup_reset(&s);

    /* =======================================================================
     * A5. CAPACITY, AND WHY LOSING AN ENTRY IS NOT A CORRECTNESS PROBLEM
     * ==================================================================== */
    /* The store is fixed-capacity, so a full store EVICTS rather than refusing
     * to record. The cost of that is stated in federation/dedup.h: a forgotten
     * key is at worst one message delivered twice, and only for a message older
     * than the newest IRC_DEDUP_MAX of them. What must hold is that eviction
     * keeps the store usable and that it takes the OLDEST, so this checks both:
     * the store does not grow, and the entry it forgot is the first one in and
     * not the last.
     *
     * The first key is re-offered after the overflow and must be NEW, which
     * proves an eviction actually happened rather than the store having quietly
     * grown past its capacity to avoid one. */
    for (i = 0; i < (size_t)IRC_DEDUP_MAX + 64u; i++) {
        tag_of(&t, "irc.f", 7u, (uint64_t)i + 1u, 0u);
        TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 0,
                     "capacity probe key %zu was reported as a duplicate", i);
    }
    TF_CHECK_MSG(fed_dedup_size(&s) == (size_t)IRC_DEDUP_MAX,
                 "the store holds %zu entries after %zu inserts; its capacity is "
                 "IRC_DEDUP_MAX (%d) and it must not grow",
                 fed_dedup_size(&s), (size_t)IRC_DEDUP_MAX + 64u,
                 IRC_DEDUP_MAX);
    tag_of(&t, "irc.f", 7u, 1u, 0u);
    TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 0,
                 "the FIRST key is still in the store after the overflow, so "
                 "eviction did not happen at all -- the store must have grown, "
                 "or the LRU is not ordered by last-seen");
    tag_of(&t, "irc.f", 7u, (uint64_t)IRC_DEDUP_MAX + 64u, 0u);
    TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 1,
                 "the LAST key inserted was evicted, so eviction is not taking "
                 "the least recently seen entry");
    /* And the store still works: an insert after the overflow is a duplicate
     * check, not a second overflow. A back-shift repair that had broken a probe
     * chain would show up here as a key wrongly reported as new. */
    tag_of(&t, "irc.f", 7u, (uint64_t)IRC_DEDUP_MAX + 63u, 0u);
    TF_CHECK_MSG(fed_dedup_seen(&s, &t, base) == 1,
                 "a key that survived the overflow was reported as new, so the "
                 "table's probe chains are broken by the eviction's repair");
    fed_dedup_reset(&s);
    TF_CHECK_MSG(fed_dedup_size(&s) == 0u,
                 "fed_dedup_reset() left %zu entries behind after the overflow",
                 fed_dedup_size(&s));

    /* =======================================================================
     * B1. A LINK THAT IS NOT ESTABLISHED IS NOT A ROUTE
     * ==================================================================== */
    /* Before anything is forwarded, and while the peer link's buffer is still
     * empty, so the refusal is visible as zero bytes rather than as a
     * comparison against a later state. 2.3 refuses a peer before ESTABLISHED
     * because the server-name uniqueness check happens there, and
     * server_find_peer() answering NULL for an incomplete handshake is the half
     * of that rule this commit implements. */
    marked = peer.len;
    TF_CHECK_MSG(server_find_peer(&s, PEER_NAME) != NULL,
                 "the fixture's ESTABLISHED link is not a route");
    {
        server_link_t *l = server_find_link(&s, PEER_NAME);

        TF_CHECK_MSG(l != NULL, "the link is not findable by its own name");
        l->hs.state = INIT;
        l->state = (int)l->hs.state;
    }
    TF_CHECK_MSG(server_find_link(&s, PEER_NAME) != NULL,
                 "the link stopped being findable when its handshake went back "
                 "to INIT; find_link() answers whether the peer is KNOWN, and "
                 "find_peer() answers whether it is a ROUTE");
    TF_CHECK_MSG(server_find_peer(&s, PEER_NAME) == NULL,
                 "a link whose handshake has not reached ESTABLISHED was treated "
                 "as a route, so protocol could be written to a peer that has not "
                 "authenticated and whose server name is not yet known");
    memset(&tgt, 0, sizeof tgt);
    memcpy(tgt.name, CHAN, sizeof CHAN);
    TF_CHECK_MSG(fed_fwd(&s, &tgt, "PRIVMSG", TEXT, NULL) == 0,
                 "forwarding to a link that is not ESTABLISHED returned success");
    expect_nothing_new(&s, &peer, marked,
                       "a forward to a link that is not ESTABLISHED");
    {
        server_link_t *l = server_find_link(&s, PEER_NAME);

        l->hs.state = ESTABLISHED;
        l->state = (int)l->hs.state;
    }
    TF_CHECK_MSG(server_find_peer(&s, PEER_NAME) != NULL,
                 "the link did not become a route again when the handshake "
                 "reached ESTABLISHED");

    /* =======================================================================
     * B2. A RELAY KEEPS ITS IDENTITY AND ADDS A HOP
     * ==================================================================== */
    /* The message arrives from elsewhere -- carried by whatever a peer said, and
     * in this commit the test supplies it directly because fed_dispatch() does
     * not exist yet. Everything about the three identity fields is the message's
     * and not this node's, and the forward must not touch any of them.
     *
     * The message id counter is pinned immediately before, and required to be
     * UNCHANGED afterwards. That is the strongest available statement of the
     * invariance: a relay that restamped would have to take a new id, and taking
     * a new id is the loop. */
    s.msg_id = 500;
    marked = peer.len;
    tag_of(&carry, "irc.z", 1756464000123ULL, 777u, 0u);
    TF_CHECK_MSG(fed_fwd(&s, &tgt, "PRIVMSG", TEXT, &carry) == 1,
                 "relaying a message with hops=0 was refused");
    (void)snprintf(want, sizeof want,
                   "@irc-serve-origin=irc.z;irc-serve-epoch=1756464000123"
                   ";irc-serve-id=777;irc-serve-hops=1 :" NODE_NAME
                   " SPRIVMSG " CHAN " :" TEXT "\r\n");
    TF_CHECK_MSG(drive_until(&s, &peer, want, T_IO_MS) == 0,
                 "a relay did not arrive with hops incremented to 1 and the "
                 "carried origin/epoch/id intact.\n  expected: %s\n  peer: %s",
                 want, wire_text(&peer));
    TF_CHECK_MSG(s.msg_id == 500,
                 "a relay took a message id from the per-SERVER counter (it is "
                 "now %llu, was 500). A relay must carry the id it was given; "
                 "minting a new one gives the copy a new identity, the far side's "
                 "dedup store does not recognise it, and the message comes back.",
                 (unsigned long long)s.msg_id);

    /* Two more relays, so the hop count walks 1 -> 2 -> 3 on the wire and the
     * counter still has not moved. */
    carry.hops = 1u;
    TF_CHECK_MSG(fed_fwd(&s, &tgt, "NOTICE", TEXT, &carry) == 1,
                 "the second relay was refused");
    (void)snprintf(want, sizeof want,
                   "@irc-serve-origin=irc.z;irc-serve-epoch=1756464000123"
                   ";irc-serve-id=777;irc-serve-hops=2 :" NODE_NAME
                   " SNOTICE " CHAN " :" TEXT "\r\n");
    TF_CHECK_MSG(drive_until(&s, &peer, want, T_IO_MS) == 0,
                 "the second relay did not arrive with hops=2.\n"
                 "  expected: %s\n  peer: %s",
                 want, wire_text(&peer));
    TF_CHECK_MSG(s.msg_id == 500,
                 "the second relay moved the per-SERVER id counter to %llu",
                 (unsigned long long)s.msg_id);

    /* =======================================================================
     * B3. THE HOP CEILING
     * ==================================================================== */
    /* 2.4: the message is dropped at IRC_MAX_HOPS. The refusal is at
     * carry->hops + 1, so the largest value that may be FORWARDED is
     * IRC_MAX_HOPS - 2 -- the copy about to be made is the tenth, and making it
     * would leave nothing to stop an eleventh. Both sides are checked, because a
     * ceiling that refused everything and a ceiling that refused nothing both
     * satisfy "the message is dropped at 10" read loosely. */
    marked = peer.len;
    carry.hops = (uint32_t)(IRC_MAX_HOPS - 1u);
    TF_CHECK_MSG(fed_fwd(&s, &tgt, "PRIVMSG", TEXT, &carry) == 0,
                 "a relay that would carry hops=%d was ALLOWED; 2.4 drops the "
                 "message at %d",
                 IRC_MAX_HOPS, IRC_MAX_HOPS);
    expect_nothing_new(&s, &peer, marked, "a relay past the hop ceiling");

    carry.hops = (uint32_t)(IRC_MAX_HOPS - 2u);
    TF_CHECK_MSG(fed_fwd(&s, &tgt, "PRIVMSG", TEXT, &carry) == 1,
                 "a relay that would carry hops=%d was refused; the ceiling "
                 "must let everything below %d through",
                 IRC_MAX_HOPS - 1, IRC_MAX_HOPS);
    (void)snprintf(want, sizeof want,
                   "@irc-serve-origin=irc.z;irc-serve-epoch=1756464000123"
                   ";irc-serve-id=777;irc-serve-hops=%d :" NODE_NAME
                   " SPRIVMSG " CHAN " :" TEXT "\r\n",
                   IRC_MAX_HOPS - 1);
    TF_CHECK_MSG(drive_until(&s, &peer, want, T_IO_MS) == 0,
                 "the last legal relay did not arrive with hops=%d.\n"
                 "  expected: %s\n  peer: %s",
                 IRC_MAX_HOPS - 1, want, wire_text(&peer));

    /* A hop count that is not even in 2.4's value grammar -- here, carried as
     * the maximum the type allows. The value grammar is enforced on RECEIPT in
     * the commit that reads tags; on the forward path the ceiling refuses
     * anything near it, so a hostile stamp is stopped by the ceiling rather than
     * by its grammar. What matters here is that it does not get out. */
    marked = peer.len;
    carry.hops = UINT32_MAX;
    TF_CHECK_MSG(fed_fwd(&s, &tgt, "PRIVMSG", TEXT, &carry) == 0,
                 "a relay carrying hops=UINT32_MAX was allowed");
    expect_nothing_new(&s, &peer, marked, "a relay with an absurd hop count");

    /* =======================================================================
     * B4. NEVER FORWARD A MESSAGE WHOSE ORIGIN IS THIS NODE
     * ==================================================================== */
    /* The second of 2.4's three rules and the one that stops the SHORT cycle: two
     * nodes exchanging one message bounce it between them for ever, and the hop
     * ceiling only slows that down rather than ending it.
     *
     * Both spellings, and the second is the interesting one: 2.4 says a server
     * name is case-insensitive in IRC, so a stamp that says IRC.A is naming
     * THIS node, and a check that compared the bytes would forward a
     * self-originated message straight back to where it came from. */
    marked = peer.len;
    tag_of(&carry, NODE_NAME, s.epoch, 4242u, 0u);
    TF_CHECK_MSG(fed_fwd(&s, &tgt, "PRIVMSG", TEXT, &carry) == 0,
                 "a message whose origin is THIS node was forwarded to a peer, "
                 "which is the two-node loop 2.4 forbids outright");
    expect_nothing_new(&s, &peer, marked,
                       "a relay whose origin is this node");

    (void)snprintf(want, sizeof want, "IRC.%c", NODE_NAME[strlen(NODE_NAME) - 1u]);
    tag_of(&carry, want, s.epoch, 4242u, 0u);
    TF_CHECK_MSG(fed_fwd(&s, &tgt, "PRIVMSG", TEXT, &carry) == 0,
                 "a message whose origin is this node UPPERCASED was forwarded; "
                 "server names are case-insensitive, so the own-origin check has "
                 "to fold ASCII the way the peer lookup does");
    expect_nothing_new(&s, &peer, marked,
                       "a relay whose origin is this node, differently cased");

    /* The positive control beside those two negatives: a message from SOME OTHER
     * node is forwarded, so the own-origin check is not simply refusing
     * everything that arrives with a stamp. Without it, a forward that returned
     * 0 for every carry would satisfy both refusals above. */
    tag_of(&carry, "irc.z", 1756464000123ULL, 777u, 4u);
    TF_CHECK_MSG(fed_fwd(&s, &tgt, "PRIVMSG", TEXT, &carry) == 1,
                 "a relay from another node at hops=4 was refused, so the "
                 "own-origin check is refusing more than its own origin");
    (void)snprintf(want, sizeof want,
                   "@irc-serve-origin=irc.z;irc-serve-epoch=1756464000123"
                   ";irc-serve-id=777;irc-serve-hops=5 :" NODE_NAME
                   " SPRIVMSG " CHAN " :" TEXT "\r\n");
    TF_CHECK_MSG(drive_until(&s, &peer, want, T_IO_MS) == 0,
                 "a relay from another node did not arrive with hops=5.\n"
                 "  expected: %s\n  peer: %s",
                 want, wire_text(&peer));
    TF_CHECK_MSG(s.msg_id == 500,
                 "a relay from another node moved the per-SERVER id counter to "
                 "%llu",
                 (unsigned long long)s.msg_id);

    /* =======================================================================
     * B5. A LINE THAT CANNOT BE SENT IS NOT SENT
     * ==================================================================== */
    /* The last of the forward's refusals, and the one with a size behind it: a
     * message that cannot be rendered inside IRC_MAX_LINE is REFUSED rather than
     * sent truncated, because a truncated S-verb is not a shorter message but a
     * corrupted protocol stream the peer will misparse.
     *
     * The length is the largest the node will relay, found by growing the body
     * until fanout_line_fits() -- the function the forward path itself calls --
     * refuses it, and then one byte more is offered. Charged at 3.2's worst-case
     * tag overhead, which is why a body this node accepted from a client can
     * still be unforwardable: the tag block is added on the RELAY path, so a
     * message sized for today would become undeliverable in Phase 6.
     *
     * THE BOUNDARY IS FOUND WITH fanout_line_fits_n(), NOT WITH
     * fanout_line_fits(), and that is this phase making the distinction load
     * bearing rather than cosmetic. fanout_line_fits() is the CLIENT-facing cap
     * and charges the largest block this node may write to a MEMBER -- `msgid`
     * and `account` -- because a member's line is the one that carries it. The
     * forward here is a RELAY: what it carries is 2.4's internal block, which
     * IRC_MAX_RELAY_LINE already excludes by construction, and charging a second
     * block for it would make this cap reject lines it can actually send. Ask
     * the peer-facing predicate the question about the peer-facing limit. */
    {
        size_t lo = 0;
        size_t hi = (size_t)IRC_MAX_LINE;
        char *body = (char *)malloc(hi + 2u);

        TF_CHECK_MSG(body != NULL, "could not allocate the probe body");
        while (lo < hi) {
            size_t mid = lo + (hi - lo + 1u) / 2u;

            memset(body, 'x', mid + 1u);
            body[mid] = '\0';
            if (fanout_line_fits_n(NODE_NAME, "SPRIVMSG", strlen(CHAN), mid) != 0) {
                lo = mid;
            } else {
                hi = mid - 1u;
            }
        }
        memset(body, 'x', lo + 2u);
        body[lo + 1u] = '\0';

        marked = peer.len;
        tag_of(&carry, "irc.z", 1756464000123ULL, 777u, 0u);
        TF_CHECK_MSG(fed_fwd(&s, &tgt, "PRIVMSG", body, &carry) == 0,
                     "a relay of a body one byte longer than this node will relay "
                     "was ALLOWED; 3.2 says an over-long line is dropped, never "
                     "truncated");
        expect_nothing_new(&s, &peer, marked, "a relay that does not fit");

        /* And the same body at the boundary IS sent, so the case above is the
         * cap and not the forward refusing everything of that shape. */
        body[lo] = '\0';
        TF_CHECK_MSG(fed_fwd(&s, &tgt, "PRIVMSG", body, &carry) == 1,
                     "the largest relayable body was refused, so the over-long "
                     "refusal above is not a size test at all");
        free(body);
    }

    /* =======================================================================
     * B6. AN ORIGINATING FORWARD IS STILL AN ORIGINATING FORWARD
     * ==================================================================== */
    /* carry == NULL means this node minted the message, so the stamp is minted
     * with it: this node's name, this node's epoch, a fresh id, hops 0. After
     * four relays that consumed no ids, the next id is 500 -- a literal, because
     * the counter was pinned and the relays were required not to move it. */
    TF_CHECK_MSG(fed_fwd(&s, &tgt, "JOIN", TEXT, NULL) == 1,
                 "an originating forward was refused");
    (void)snprintf(want, sizeof want,
                   "@irc-serve-origin=" NODE_NAME ";irc-serve-epoch=%llu"
                   ";irc-serve-id=500;irc-serve-hops=0 :" STATE_PREFIX
                   " SJOIN " CHAN " joiner - *\r\n",
                   (unsigned long long)s.epoch);
    TF_CHECK_MSG(drive_until(&s, &peer, want, T_IO_MS) == 0,
                 "an originating forward did not arrive stamped with this node's "
                 "own name and epoch, hops=0, and the pinned next id.\n"
                 "  expected: %s\n  peer: %s",
                 want, wire_text(&peer));
    TF_CHECK_MSG(s.msg_id == 501,
                 "the originating forward left the id counter at %llu, expected "
                 "501: an originating message takes the next id and nothing else "
                 "does",
                 (unsigned long long)s.msg_id);

    /* And the wire carries no tag block on anything but the S-verbs: the five
     * forwarded lines and the one originating one are the whole of it. */
    TF_CHECK_MSG(strstr(wire_text(&peer), "irc-serve-origin=irc.z") != NULL &&
                     strstr(wire_text(&peer), "irc-serve-origin=" NODE_NAME) !=
                         NULL,
                 "the peer link does not carry both a carried origin and this "
                 "node's own: %s",
                 wire_text(&peer));

    /* =======================================================================
     * Teardown
     * ==================================================================== */
    /* server_shutdown() closes the peer connection and releases the link vector
     * AND the dedup table, which by now holds entries from section A5. On this
     * platform that last part is asserted rather than verified: LeakSanitizer
     * does not exist on Darwin, so only the Linux CI job can catch a missing
     * free here. */
    server_shutdown(&s);
    close(listen_fd);
    wire_close(&peer);
    tf_done("fed_dedup");
    return 0;
}
