/* server.c -- server_t lifecycle, the fd-indexed connection registry, the nick
 * and channel registries, the bounded-queue wrapper, and the nonblocking dial
 * FSM. Sections 2.1, 2.2, 2.3, 2.4, 3.3 and 3.4 of docs/SERVER_DESIGN.md. */
#include "core/server.h"

#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "core/message.h"

/* ---------------------------------------------------------------------------
 * A small open-addressed string -> pointer map
 * ---------------------------------------------------------------------------
 * Two registries need it (nicks, channels) and both are keyed by a short ASCII
 * name, so one table type serves both rather than two bespoke structures. It is
 * file-local: nothing outside this file needs to know how a nick is stored.
 *
 * Open addressing with linear probing and a FNV-1a hash. No growth: the table
 * is sized once from a generous bound, and a full table is reported rather than
 * rehashed, so a lookup in the send path cannot fail because of an allocation
 * that would have to block the loop.
 */
#define STRTAB_BUCKETS 1024u

struct strtab_entry {
    char  *key;
    void  *val;
    int    used;
};

struct strtab {
    struct strtab_entry *buckets;
    size_t               nentries;
};

static uint64_t strtab_hash(const char *s)
{
    /* FNV-1a, 64-bit. */
    uint64_t h = 1469598103934665603ull;

    while (*s != '\0') {
        h ^= (uint64_t)(unsigned char)*s;
        h *= 1099511628211ull;
        s++;
    }
    return h;
}

static struct strtab *strtab_new(void)
{
    struct strtab *t = (struct strtab *)calloc(1, sizeof *t);

    if (t == NULL) {
        return NULL;
    }
    t->buckets = (struct strtab_entry *)calloc(STRTAB_BUCKETS, sizeof *t->buckets);
    if (t->buckets == NULL) {
        free(t);
        return NULL;
    }
    return t;
}

static void strtab_free(struct strtab *t)
{
    size_t i;

    if (t == NULL) {
        return;
    }
    for (i = 0; i < STRTAB_BUCKETS; i++) {
        free(t->buckets[i].key);
    }
    free(t->buckets);
    free(t);
}

/* Locate `key` in the table. Returns the bucket index, sets *found to 1 when the
 * key is present or 0 when the returned bucket is free, and returns
 * (size_t)-1 only when the table is completely full. One probe loop, so the
 * const-correct lookup and the mutating insert cannot drift apart. */
static size_t strtab_probe(const struct strtab *t, const char *key, int *found)
{
    size_t idx = (size_t)(strtab_hash(key) % STRTAB_BUCKETS);
    size_t probe;

    *found = 0;
    for (probe = 0; probe < STRTAB_BUCKETS; probe++) {
        size_t at = (idx + probe) % STRTAB_BUCKETS;
        const struct strtab_entry *e = &t->buckets[at];

        if (!e->used) {
            *found = 0;
            return at;
        }
        if (strcmp(e->key, key) == 0) {
            *found = 1;
            return at;
        }
    }
    return (size_t)-1;
}

/* Is `key` present? Distinct from strtab_get(), which cannot answer this for a
 * table whose values are legitimately NULL -- and the channel registry is
 * exactly that, because struct chan does not exist until Phase 4. Reading
 * presence off the value would make every channel look absent. */
static int strtab_contains(const struct strtab *t, const char *key)
{
    int found = 0;
    size_t at;

    if (t == NULL || key == NULL) {
        return 0;
    }
    at = strtab_probe(t, key, &found);
    return (at != (size_t)-1 && found) ? 1 : 0;
}

static int strtab_put(struct strtab *t, const char *key, void *val)
{
    struct strtab_entry *e;
    int found = 0;
    size_t at;
    char *copy;

    if (t == NULL || key == NULL || key[0] == '\0') {
        return -1;
    }
    at = strtab_probe(t, key, &found);
    if (at == (size_t)-1) {
        return -1;
    }
    e = &t->buckets[at];
    if (found) {
        e->val = val; /* overwrite: re-claim of the same key */
        return 0;
    }
    copy = (char *)malloc(strlen(key) + 1u);
    if (copy == NULL) {
        return -1;
    }
    memcpy(copy, key, strlen(key) + 1u);
    e->key = copy;
    e->val = val;
    e->used = 1;
    t->nentries++;
    return 0;
}

static void *strtab_get(const struct strtab *t, const char *key)
{
    int found = 0;
    size_t at;

    if (t == NULL || key == NULL) {
        return NULL;
    }
    at = strtab_probe(t, key, &found);
    if (at == (size_t)-1 || !found) {
        return NULL;
    }
    return t->buckets[at].val;
}

static int strtab_del(struct strtab *t, const char *key)
{
    struct strtab_entry *e;
    int found = 0;
    size_t at;

    if (t == NULL || key == NULL) {
        return -1;
    }
    at = strtab_probe(t, key, &found);
    if (at == (size_t)-1 || !found) {
        return -1;
    }
    e = &t->buckets[at];
    free(e->key);
    e->key = NULL;
    e->val = NULL;
    e->used = 0;
    t->nentries--;
    return 0;
}

/* Put a descriptor into nonblocking mode. Called on the listener, on every
 * accepted socket and on every dialled socket BEFORE the descriptor becomes
 * reachable from the loop, so the loop cannot inherit a blocking fd and stall
 * every other client while it waits. */
static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0) {
        return -1;
    }
    if ((flags & O_NONBLOCK) != 0) {
        return 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Record what the accept told us about the peer. `host` is the address the
 * connection actually came from, which is a fact about the socket rather than
 * anything the peer asserted, so it is recorded at accept time. */
static void describe_peer(conn_t *c, const struct sockaddr *sa)
{
    struct sockaddr_in sin;
    char text[INET_ADDRSTRLEN];

    if (sa->sa_family != AF_INET) {
        return;
    }
    /* memcpy rather than a pointer cast: the caller's buffer is a
     * sockaddr_storage, and copying keeps this free of the aliasing and
     * alignment assumptions a cast would encode. */
    memcpy(&sin, sa, sizeof sin);
    if (inet_ntop(AF_INET, &sin.sin_addr, text, sizeof text) == NULL) {
        return;
    }
    if (strlen(text) < sizeof c->host) {
        memcpy(c->host, text, strlen(text) + 1u);
    }
}


/* ---------------------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------------------
 */

int server_init(server_t *s, const char *name)
{
    if (s == NULL || name == NULL) {
        return -1;
    }
    memset(s, 0, sizeof *s);
    s->listen_fd = -1;

    /* A name this node cannot stamp on its own irc-serve-origin tag would
     * break the never-forward-own-origin rule at the first relay, so it is
     * refused here rather than discovered in Phase 6. */
    if (!irc_serve_server_name_valid(name)) {
        return -1;
    }
    if (strlen(name) > IRC_MAX_SERVER_NAME) {
        return -1;
    }
    memcpy(s->name, name, strlen(name) + 1u);

    s->by_fd = (conn_t **)calloc(SERVER_FD_TABLE, sizeof *s->by_fd);
    s->nicks = strtab_new();
    s->chans = strtab_new();
    if (s->by_fd == NULL || s->nicks == NULL || s->chans == NULL) {
        server_shutdown(s);
        return -1;
    }

    /* 2.4: epoch is per-boot and both counters start at 1, because id 0 is
     * reserved as "unset" so an absent tag is never read as a real id. The
     * epoch is the boot time in milliseconds, which is monotonic enough for a
     * value that only has to differ from the previous boot's. */
    s->epoch = server_now_ms();
    if (s->epoch == 0) {
        s->epoch = 1;
    }
    s->msg_id = 1;
    return 0;
}

void server_shutdown(server_t *s)
{
    size_t i;

    if (s == NULL) {
        return;
    }
    for (i = 0; i < SERVER_FD_TABLE; i++) {
        if (s->by_fd != NULL && s->by_fd[i] != NULL) {
            server_close_conn(s, (int)i);
        }
    }
    if (s->listen_fd >= 0) {
        close(s->listen_fd);
        s->listen_fd = -1;
    }
    if (s->dials != NULL) {
        for (i = 0; i < s->ndials; i++) {
            if (s->dials[i].state == DIAL_CONNECTING ||
                s->dials[i].state == DIAL_CONNECTED) {
                close(s->dials[i].fd);
                s->dials[i].fd = -1;
            }
        }
        free(s->dials);
        s->dials = NULL;
    }
    s->ndials = 0;
    s->dials_cap = 0;
    strtab_free(s->nicks);
    s->nicks = NULL;
    strtab_free(s->chans);
    s->chans = NULL;
    free(s->by_fd);
    s->by_fd = NULL;
    s->nconns = 0;
}

int server_listen(server_t *s, int port)
{
    struct sockaddr_in addr;
    int fd;
    int one = 1;

    if (s == NULL || port < 0 || port > 65535) {
        return -1;
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) {
        close(fd);
        return -1;
    }

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, SOMAXCONN) != 0) {
        close(fd);
        return -1;
    }
    /* Nonblocking BEFORE the fd is reachable by the loop. 3.4: the loop never
     * blocks, and an fd that is briefly blocking is a stall for every other
     * client on the node. */
    if (set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }
    s->listen_fd = fd;
    return 0;
}

int server_port(const server_t *s)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof addr;

    if (s == NULL || s->listen_fd < 0) {
        return -1;
    }
    if (getsockname(s->listen_fd, (struct sockaddr *)&addr, &len) != 0) {
        return -1;
    }
    return (int)ntohs(addr.sin_port);
}

uint64_t server_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000L);
}

void server_tick(server_t *s, uint64_t now_ms)
{
    if (s == NULL) {
        return;
    }
    s->n_ticks++;
    if (s->on_tick != NULL) {
        s->on_tick(s, now_ms);
    }
}

uint64_t server_next_msg_id(server_t *s)
{
    uint64_t id;

    if (s == NULL) {
        return 0;
    }
    id = s->msg_id++;
    if (s->msg_id == 0) {
        s->msg_id = 1; /* never hand out 0: it means "unset" */
    }
    return id;
}

/* ---------------------------------------------------------------------------
 * The fd-indexed connection registry
 * ---------------------------------------------------------------------------
 */

conn_t *server_conn(server_t *s, int fd)
{
    if (s == NULL || s->by_fd == NULL || fd < 0 || fd >= SERVER_FD_TABLE) {
        return NULL;
    }
    return s->by_fd[fd];
}

int server_add_conn(server_t *s, conn_t *c)
{
    if (s == NULL || s->by_fd == NULL || c == NULL) {
        return -1;
    }
    if (c->fd < 0 || c->fd >= SERVER_FD_TABLE) {
        return -1; /* see SERVER_FD_TABLE: a descriptor poll() cannot name */
    }
    if (s->by_fd[c->fd] != NULL) {
        return -1;
    }
    s->by_fd[c->fd] = c;
    s->nconns++;
    s->n_accepted++;
    return 0;
}

int server_accept_one(server_t *s)
{
    struct sockaddr_storage peer;
    socklen_t peerlen = sizeof peer;
    conn_t *c;
    int fd;

    if (s == NULL || s->listen_fd < 0) {
        return -1;
    }
    for (;;) {
        fd = accept(s->listen_fd, (struct sockaddr *)&peer, &peerlen);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0; /* nothing pending */
            }
#if defined(EMFILE) || defined(ENFILE)
            if (errno == EMFILE || errno == ENFILE) {
                /* Out of descriptors. Returning 0 rather than -1 keeps the
                 * loop alive; the connection is refused by the kernel backlog
                 * and retried on the next accept. */
                return 0;
            }
#endif
            return -1;
        }
        break;
    }

    /* 3.4: "explicit if (fd >= FD_SETSIZE) reject at every accept/dial site".
     * The check has to be explicit and immediate. poll() would silently ignore
     * an out-of-range descriptor, and FD_SET on it is undefined behaviour --
     * so a connection that is merely "not registered" is not a harmless drop,
     * it is a write past the end of an fd_set on some paths. */
    if (fd >= FD_SETSIZE) {
        close(fd);
        s->n_rejected_fd++;
        printf("[observable] accept_rejected: fd=%d reason=fd_ge_fdsize limit=%d\n",
               fd, FD_SETSIZE);
        return SERVER_ACCEPT_REJECTED;
    }

    if (set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }
    c = conn_new(fd, CONN_CLIENT);
    if (c == NULL) {
        close(fd);
        return -1;
    }
    describe_peer(c, (const struct sockaddr *)&peer);
    if (server_add_conn(s, c) != 0) {
        conn_free(c);
        close(fd);
        return -1;
    }
    printf("[observable] client_connect: fd=%d host=%s state=REG_PASS\n",
           fd, c->host);
    return 1;
}

void server_close_conn(server_t *s, int fd)
{
    conn_t *c = server_conn(s, fd);

    if (c == NULL) {
        return; /* unregistered: a second close is a no-op, not a double close */
    }

    /* Detach from the registry BEFORE closing, so a descriptor the OS reuses
     * between the close() and the next poll iteration cannot resolve to this
     * conn. */
    s->by_fd[fd] = NULL;
    s->nconns--;

    if (c->nick[0] != '\0') {
        /* Only if this conn still owns the name: a conn that was denied the
         * nick must not evict the one that holds it. */
        if (server_nick_lookup(s, c->nick) == c) {
            strtab_del(s->nicks, c->nick);
        }
    }

    close(fd);
    s->n_closed++;
    conn_free(c);
}

int server_queue(server_t *s, conn_t *c, const char *data, size_t len)
{
    if (c == NULL || conn_queue(c, data, len) == 0) {
        return 0;
    }
    /* 3.4: bounded write queues, and a saturated link is DROPPED, not
     * buffered. Marking CLOSING is all the send path is allowed to do; the
     * reaper closes the fd at the next fixed point. */
    s->n_writeq_overflow++;
    printf("[observable] writeq_overflow: fd=%d pending=%zu cap=%zu\n",
           c->fd, conn_write_pending(c), CONN_WQ_MAX);
    conn_mark_closing(c);
    return -1;
}

int server_reap(server_t *s)
{
    size_t i;
    int closed = 0;

    if (s == NULL || s->by_fd == NULL) {
        return 0;
    }
    for (i = 0; i < SERVER_FD_TABLE; i++) {
        if (s->by_fd[i] != NULL && s->by_fd[i]->state == CONN_CLOSING) {
            server_close_conn(s, (int)i);
            closed++;
        }
    }
    return closed;
}

/* ---------------------------------------------------------------------------
 * Registries
 * ---------------------------------------------------------------------------
 */

int server_nick_claim(server_t *s, const char *nick, conn_t *c)
{
    if (s == NULL || nick == NULL || !valid_nick(nick)) {
        return -1;
    }
    if (server_nick_lookup(s, nick) != NULL) {
        return -1;
    }
    return strtab_put(s->nicks, nick, c);
}

void server_nick_release(server_t *s, const char *nick)
{
    if (s != NULL) {
        (void)strtab_del(s->nicks, nick);
    }
}

conn_t *server_nick_lookup(const server_t *s, const char *nick)
{
    if (s == NULL) {
        return NULL;
    }
    return (conn_t *)strtab_get(s->nicks, nick);
}

int server_chan_add(server_t *s, const char *name)
{
    if (s == NULL || name == NULL || name[0] == '\0') {
        return -1;
    }
    if (strtab_contains(s->chans, name)) {
        return -1; /* already known */
    }
    /* The value is NULL in Phase 2: struct chan does not exist until Phase 4
     * (2.2), and a placeholder value type here would be a shape Phase 4 would
     * have to replace -- exactly the late landing 7/Phase 4 forbids. Presence
     * is therefore tracked by the table's own occupancy, not by the value. */
    return strtab_put(s->chans, name, NULL);
}

void server_chan_remove(server_t *s, const char *name)
{
    if (s != NULL) {
        (void)strtab_del(s->chans, name);
    }
}

const char *server_chan_lookup(const server_t *s, const char *name)
{
    if (s == NULL || !strtab_contains(s->chans, name)) {
        return NULL;
    }
    /* A registered name is present; the chan_t it will point at arrives in
     * Phase 4. Returning the name itself is the only honest value available. */
    return name;
}

size_t server_dial_count(const server_t *s)
{
    return (s == NULL) ? 0 : s->ndials;
}

/* ---------------------------------------------------------------------------
 * Nonblocking dial (3.4)
 * ---------------------------------------------------------------------------
 * The address arrives already resolved: getaddrinfo() inside the loop would
 * stall every client on the node, and there is deliberately no resolution
 * helper here to tempt one into being added later.
 *
 * No caller exists yet -- peer sockets are Phase 6.
 */

int server_dial(server_t *s, const struct sockaddr *sa, socklen_t salen,
                const char *peer_name)
{
    dial_t *slot;
    int fd;

    if (s == NULL || sa == NULL || salen == 0) {
        return -1;
    }
    if (peer_name == NULL || strlen(peer_name) > IRC_MAX_SERVER_NAME ||
        !irc_serve_server_name_valid(peer_name)) {
        return -1;
    }

    fd = socket(sa->sa_family, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    /* The same explicit check as the accept site: 3.4 requires it at every
     * site that produces a descriptor, and a dial that cannot be registered is
     * closed here for the same reason an out-of-range accept is. */
    if (fd >= FD_SETSIZE) {
        close(fd);
        s->n_rejected_fd++;
        return -1;
    }
    if (set_nonblocking(fd) != 0) {
        close(fd);
        return -1;
    }

    /* SOCK_NONBLOCK was already set, so connect() returns immediately with
     * EINPROGRESS instead of blocking the loop. That is the whole point of the
     * state machine.
     *
     * A connect that returns 0 is ALSO put in DIAL_CONNECTING rather than being
     * declared connected here. Two things make that deliberate:
     *
     *  - Probing SO_ERROR at this instant does not prove anything. To a loopback
     *    port with nothing behind it, connect() can return EINPROGRESS and the
     *    RST has not arrived yet, so SO_ERROR reads 0 for a connection that is
     *    already doomed. Treating that as success strands a dead dial in a state
     *    nothing promotes.
     *  - There must be exactly one path from "connect initiated" to "registered
     *    connection", or a second one has to be maintained beside it. An
     *    already-connected socket reports writable on the very next poll with
     *    SO_ERROR 0, so the cost of the uniform path is at most one tick.
     */
    if (connect(fd, sa, salen) != 0 && errno != EINPROGRESS) {
        close(fd);
        s->n_dial_failed++;
        return -1;
    }

    /* The table is grown BEFORE the count is incremented. Testing
     * "ndials == dials_cap" after incrementing would be off by one on the very
     * first dial -- 1 != 0 -- so the growth block would be skipped and the slot
     * below would be a null dereference. */
    if (s->ndials == s->dials_cap) {
        size_t want = (s->dials_cap == 0) ? 4u : s->dials_cap * 2u;
        dial_t *grown = (dial_t *)realloc(s->dials, want * sizeof *grown);

        if (grown == NULL) {
            close(fd);
            s->n_dial_failed++;
            return -1;
        }
        memset(grown + s->dials_cap, 0, (want - s->dials_cap) * sizeof *grown);
        s->dials = grown;
        s->dials_cap = want;
    }
    s->ndials++;

    slot = &s->dials[s->ndials - 1u];
    slot->fd = fd;
    slot->state = DIAL_CONNECTING;
    slot->slot = s->ndials - 1u;
    memcpy(slot->peer_name, peer_name, strlen(peer_name) + 1u);
    return 0;
}

int server_dial_collect(server_t *s, struct pollfd *pfds, size_t cap,
                        nfds_t *nfds_out)
{
    size_t i;

    if (s == NULL || pfds == NULL || nfds_out == NULL) {
        return -1;
    }
    *nfds_out = 0;
    for (i = 0; i < s->ndials; i++) {
        if (s->dials[i].state != DIAL_CONNECTING) {
            continue;
        }
        if (*nfds_out >= cap) {
            return -1;
        }
        pfds[*nfds_out].fd = s->dials[i].fd;
        pfds[*nfds_out].events = POLLOUT;
        pfds[*nfds_out].revents = 0;
        (*nfds_out)++;
    }
    return 0;
}

int server_dial_progress(server_t *s, const struct pollfd *pfds, size_t nfds)
{
    size_t i;

    if (s == NULL || pfds == NULL) {
        return -1;
    }
    for (i = 0; i < s->ndials; i++) {
        struct pollfd ready;
        conn_t *c;
        int err = 0;
        socklen_t errlen = sizeof err;
        size_t j;

        if (s->dials[i].state != DIAL_CONNECTING) {
            continue;
        }
        ready.fd = s->dials[i].fd;
        ready.events = POLLOUT;
        ready.revents = 0;
        for (j = 0; j < nfds; j++) {
            if (pfds[j].fd == ready.fd) {
                ready.revents = pfds[j].revents;
                break;
            }
        }
        if (ready.revents == 0) {
            continue;
        }
        if (getsockopt(s->dials[i].fd, SOL_SOCKET, SO_ERROR, &err, &errlen) != 0) {
            err = errno;
        }
        if (err != 0) {
            close(s->dials[i].fd);
            s->dials[i].fd = -1;
            s->dials[i].state = DIAL_FAILED;
            s->n_dial_failed++;
            continue;
        }

        c = conn_new(s->dials[i].fd, CONN_SERVER);
        if (c == NULL || server_add_conn(s, c) != 0) {
            conn_free(c);
            close(s->dials[i].fd);
            s->dials[i].fd = -1;
            s->dials[i].state = DIAL_FAILED;
            s->n_dial_failed++;
            continue;
        }
        /* peer_name is owned by the conn from here; the dial slot's copy is
         * released when the table is torn down. */
        c->peer_name = (char *)malloc(strlen(s->dials[i].peer_name) + 1u);
        if (c->peer_name == NULL) {
            server_close_conn(s, s->dials[i].fd);
            s->dials[i].state = DIAL_FAILED;
            s->n_dial_failed++;
            continue;
        }
        memcpy(c->peer_name, s->dials[i].peer_name,
               strlen(s->dials[i].peer_name) + 1u);
        s->dials[i].state = DIAL_CONNECTED;
        s->n_dial_connected++;
    }
    return 0;
}
