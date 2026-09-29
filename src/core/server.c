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

#include "core/channel.h"
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
 *
 * ---------------------------------------------------------------------------
 * WHY ONE TABLE IS FOLDED AND THE OTHER IS NOT
 * ---------------------------------------------------------------------------
 * The two registries disagree about case for a REASON, not by accident:
 *
 *   channels  2.2 says a channel name is stored uppercase-normalised and is
 *             displayed uppercase, so the canonical form IS the display form.
 *             The table is exact, and channel.c's accessor canonicalises the
 *             caller's spelling before it probes (see chan_name_upper and the
 *             reasoning at channel.c:48).
 *   nicks     2.1 and RFC 2812 2.3.1 say nicknames are case-INsensitive, so
 *             two spellings are one name -- but IRC convention and every client
 *             display the case the user chose. A user who registers as `Bob` must
 *             appear as `Bob` in 353, in a PRIVMSG prefix, in 352 and in 311.
 *
 * So a nick cannot be stored the way a channel is. `folded` is therefore a
 * property OF THE TABLE, set at construction, and every key that enters a folded
 * table is folded before it is hashed, compared or stored. It is not a
 * discipline every caller has to remember: the failure mode of getting it wrong
 * was issue #100, where `PRIVMSG BOB :hi` answered 401 to a user connected as
 * `bob` and -- worse -- `bob` and `BOB` were two claimable slots on a node whose
 * identity scheme is nick@server.
 *
 * The fold is ASCII and deliberately NOT tolower() in a locale, for
 * channel.c:48's reason: 005 advertises CASEMAPPING=ascii, so this node has
 * already told every client that []\~ and {}|^ are NOT equivalent, and folding
 * them here would break that promise in a way no test elsewhere would catch. A
 * registry key that depended on LC_CTYPE would additionally make two nodes on
 * differently-configured hosts disagree about whether a nickname is taken.
 */
#define STRTAB_BUCKETS 1024u

/* The longest key a FOLDED table can hold, and so the size of the scratch buffer
 * strtab_probe()/strtab_put() fold into. It is the nick bound rather than an
 * invented one: the only folded table is the nick registry, whose every key
 * arrives through server_nick_claim() -> valid_nick(), and valid_nick() caps a
 * nickname at IRC_MAX_NICK (message.h, from conn_t::nick's own width). A longer
 * string therefore cannot be a key of a folded table, and is refused rather than
 * truncated into one that could collide with a real name. */
#define STRTAB_FOLD_MAX (IRC_MAX_NICK + 1)

struct strtab_entry {
    char  *key;
    void  *val;
    int    used;
};

struct strtab {
    struct strtab_entry *buckets;
    size_t               nentries;
    int                  folded;  /* keys are ASCII-folded on the way in */
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

static char down_ascii(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char)(c + ('a' - 'A'));
    }
    return c;
}

/* Fold `key` into `out`, which holds `cap` bytes including the NUL. Returns 0 on
 * success, -1 if the result would not fit.
 *
 * The `char` parameter is passed and returned without an (unsigned char) cast
 * deliberately, and the reason is the same one channel.c:48 gives for not calling
 * toupper() at all: no libc function sees the value, and the range tests are
 * against ASCII literals, so a byte outside 'A'..'Z' is returned unchanged
 * whatever the sign of char is. Casting would be noise here and a cast is
 * exactly what a future caller would have to remember not to drop. */
static int strtab_fold(char *out, size_t cap, const char *key)
{
    size_t i;

    for (i = 0; key[i] != '\0'; i++) {
        if (i + 1u >= cap) {
            return -1;
        }
        out[i] = down_ascii(key[i]);
    }
    out[i] = '\0';
    return 0;
}

static struct strtab *strtab_new(int folded)
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
    t->folded = folded;
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
 * const-correct lookup and the mutating insert cannot drift apart.
 *
 * For a FOLDED table the key is folded first, here, rather than by each of the
 * four operations below. That is the whole point: strtab_get/contains/del/put
 * are the only doors to this table, they all come through this loop, and a caller
 * added later gets the case-insensitive rule whether or not it knows the rule
 * exists. */
static size_t strtab_probe(const struct strtab *t, const char *key, int *found)
{
    char        fold[STRTAB_FOLD_MAX];
    const char *k = key;
    size_t      idx;
    size_t      probe;

    *found = 0;
    if (t->folded && strtab_fold(fold, sizeof fold, key) != 0) {
        /* Too long to be a key of this table, so it can neither match an entry
         * nor become one. The same sentinel as a full table, and deliberately so:
         * every caller treats both as "give up" -- put() returns -1, get() and
         * contains() report absence, del() reports nothing to remove. Which of
         * the two it was is not a fact any caller can act on. */
        return (size_t)-1;
    }
    if (t->folded) {
        k = fold;
    }
    idx = (size_t)(strtab_hash(k) % STRTAB_BUCKETS);
    for (probe = 0; probe < STRTAB_BUCKETS; probe++) {
        size_t at = (idx + probe) % STRTAB_BUCKETS;
        const struct strtab_entry *e = &t->buckets[at];

        if (!e->used) {
            *found = 0;
            return at;
        }
        if (strcmp(e->key, k) == 0) {
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
    char   fold[STRTAB_FOLD_MAX];
    const char *stored = key;
    int    found = 0;
    size_t at;
    char  *copy;

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
    /* The key is STORED folded, so the table's own bytes are the canonical form
     * rather than whichever spelling the first claimer happened to type. Every
     * later probe folds its own key to match, and nothing has to remember that
     * the entry was inserted as "Bob" rather than "bob". */
    if (t->folded) {
        if (strtab_fold(fold, sizeof fold, key) != 0) {
            return -1;
        }
        stored = fold;
    }
    copy = (char *)malloc(strlen(stored) + 1u);
    if (copy == NULL) {
        return -1;
    }
    memcpy(copy, stored, strlen(stored) + 1u);
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

/* Case-insensitive server-name comparison, ASCII-folded.
 *
 * The same fold is required in three places: 2.1's nick@server split, 2.4
 * ("server names are case-insensitive in IRC, so a comparison against our OWN
 * name MUST be case-insensitive") and channel.c's own server-name fold. It is
 * written out here rather than exported because it is six lines and a public
 * helper one of the two callers would never use again is a wider API than the
 * duplication is worth. The two copies are asserted to agree by
 * test_channels.c, which looks a peer up by a name differing only in case. */
static int same_server_name(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    while (*a != '\0' && *b != '\0') {
        char ca = *a;
        char cb = *b;

        if (ca >= 'a' && ca <= 'z') {
            ca = (char)(ca - ('a' - 'A'));
        }
        if (cb >= 'a' && cb <= 'z') {
            cb = (char)(cb - ('a' - 'A'));
        }
        if (ca != cb) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
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
    /* Folded and exact, for the reasons spelled out at the strtab: 2.1 makes
     * nicknames case-insensitive while the case the user chose is what gets
     * displayed, and 2.2 makes a channel name uppercase-normalised, which is
     * also how it is displayed. */
    s->nicks = strtab_new(1);
    s->chans = strtab_new(0);
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
    /* Every conn is already closed by the loop above, so no chan_t can still be
     * listed in a conn_t::chans that is about to be freed. What is left is the
     * channels themselves: a channel can outlive all of its members while a
     * peer still reports members for it, so this is a real list rather than
     * something server_close_conn() has already emptied. Freeing them in
     * creation order, and releasing the ordered index with them. */
    for (i = 0; i < s->nchan_objs; i++) {
        chan_free(s->chan_objs[i]);
        s->chan_objs[i] = NULL;
    }
    free(s->chan_objs);
    s->chan_objs = NULL;
    s->nchan_objs = 0;
    /* Same for the nick enumeration. Every conn was closed above and every one
     * of those closures released its nickname, so this is normally already
     * empty; it is freed unconditionally because a conn that never claimed a
     * nickname leaves nothing here either way, and a list that could still hold
     * a pointer to a freed conn_t must never survive shutdown. */
    free(s->nick_objs);
    s->nick_objs = NULL;
    s->nnick_objs = 0;
    s->nick_objs_cap = 0;    s->chan_objs_cap = 0;
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

    /* Take the connection out of its channels BEFORE it is detached, and
     * before conn_free() releases the array.
     *
     * The ordering is the whole point. A chan_t's member list holds conn_t
     * pointers, so a conn that is freed while still a member leaves every
     * remaining member of every channel it was in with a dangling pointer -- and
     * the node has no way to notice, because nothing dereferences it until the
     * next fan-out. This is the same class of hazard the fd detach below avoids
     * for a reused descriptor, and it is why the reaper is the place both
     * happen.
     *
     * chan_conn_gone() also emits the PART to whoever is left in each channel
     * and disposes of any channel that has run out of reasons to exist. It must
     * run while the conn is still a usable addressable object, which is exactly
     * now. */
    chan_conn_gone(s, c);

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

/* Append `c` to the nick enumeration. Returns 0 on success, -1 on allocation
 * failure or a bad argument. The vector grows geometrically like conn_t's own
 * channel list does, and is not bounded: it holds one entry per registered
 * connection, so the loop's own FD_SETSIZE ceiling is the bound.
 *
 * Growing is the ONLY way it changes size, and it is reached from exactly one
 * caller (server_nick_claim), which is what keeps the two nick indexes in
 * agreement without a periodic reconciliation. */
static int nick_objs_add(server_t *s, conn_t *c)
{
    if (s == NULL || c == NULL) {
        return -1;
    }
    if (s->nnick_objs == s->nick_objs_cap) {
        size_t want = (s->nick_objs_cap == 0) ? 16u : s->nick_objs_cap * 2u;
        conn_t **grown = (conn_t **)realloc(s->nick_objs,
                                           want * sizeof *grown);

        if (grown == NULL) {
            return -1;
        }
        s->nick_objs = grown;
        s->nick_objs_cap = want;
    }
    s->nick_objs[s->nnick_objs] = c;
    s->nnick_objs++;
    return 0;
}

int server_nick_claim(server_t *s, const char *nick, conn_t *c)
{
    if (s == NULL || nick == NULL || !valid_nick(nick)) {
        return -1;
    }
    if (server_nick_lookup(s, nick) != NULL) {
        return -1;
    }
    if (strtab_put(s->nicks, nick, c) != 0) {
        return -1;
    }
    /* The table is written FIRST and the vector second, and a failed append
     * rolls the table entry back. A half-applied claim would be worse than a
     * refused one: the two indexes disagreeing means a nickname this node
     * answers 433 for while WHO does not list it, or the reverse, and there is
     * no event that would ever reconcile them. Refusing the claim leaves the
     * state exactly as it was, which is the only outcome a caller can reason
     * about. */
    if (nick_objs_add(s, c) != 0) {
        (void)strtab_del(s->nicks, nick);
        return -1;
    }
    return 0;
}

/* ASCII-folded nickname equality -- the SAME rule the nick table's keys use, so
 * the two halves of the nick index cannot disagree about what a name is.
 *
 * It has to be spelled out rather than borrowed from the table, because this one
 * compares a nickname against conn_t::nick, which holds the case the user chose
 * and is therefore deliberately NOT the stored key. (Folding both sides into
 * scratch buffers and calling strcmp would be the same six lines with two
 * copies and a capacity argument on top.)
 *
 * This is the third copy of this fold in the node -- same_server_name() below
 * and channel.c's same_name() are the other two -- and it is written out for the
 * reason server.h records for the first pair: the function is six lines, a
 * public helper two of the three callers would never call again is a wider API
 * than the duplication is worth, and test_channels.c already asserts that the
 * copies agree. What must NOT happen is one of them growing a different rule;
 * that is what CASEMAPPING=ascii in 005 is a promise about.
 *
 * Every release path in the tree today passes the holder's OWN spelling, so this
 * fold is what makes a differently-spelled release safe rather than relying on
 * every caller continuing to be careful -- and the check that says so is
 * test_registries.c's, which releases "cAROL" for a nickname claimed as "carol"
 * and then asserts the ENUMERATION shrank too. That half goes wrong quietly: the
 * table entry would be gone and WHO <mask> would still list the connection. */
static int nick_same(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    while (*a != '\0' && *b != '\0') {
        if (down_ascii(*a) != down_ascii(*b)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

/* Drop `nick` from the enumeration, preserving claim order. Idempotent, and a
 * no-op for a name the table does not hold -- server_nick_release() is reached
 * twice on the ordinary QUIT path (once by the handler, once by the reaper)
 * and must not turn the second call into a corruption.
 *
 * The comparison folds, because server_nick_release() may be handed a spelling
 * the holder never typed: a caller that released "BOB" must remove the vector
 * entry for the connection registered as "bob", or the table and the vector
 * disagree about who holds the name -- which is the state server.h names as a
 * JOIN that resolves to NULL, with no event that would ever reconcile it. */
static void nick_objs_del(server_t *s, const char *nick)
{
    for (size_t i = 0; i < s->nnick_objs; i++) {
        if (s->nick_objs[i] != NULL && s->nick_objs[i]->nick[0] != '\0' &&
            nick_same(s->nick_objs[i]->nick, nick)) {
            for (size_t j = i + 1u; j < s->nnick_objs; j++) {
                s->nick_objs[j - 1u] = s->nick_objs[j];
            }
            s->nnick_objs--;
            s->nick_objs[s->nnick_objs] = NULL;
            return;
        }
    }
}

void server_nick_release(server_t *s, const char *nick)
{
    if (s != NULL && nick != NULL) {
        (void)strtab_del(s->nicks, nick);
        nick_objs_del(s, nick);
    }
}

conn_t *server_nick_lookup(const server_t *s, const char *nick)
{
    if (s == NULL) {
        return NULL;
    }
    return (conn_t *)strtab_get(s->nicks, nick);
}

size_t server_nick_count(const server_t *s)
{
    return (s == NULL) ? 0u : s->nnick_objs;
}

conn_t *server_nick_at(const server_t *s, size_t i)
{
    if (s == NULL || i >= s->nnick_objs) {
        return NULL;
    }
    return s->nick_objs[i];
}

int server_chan_add(server_t *s, const char *name)
{
    if (s == NULL || name == NULL || name[0] == '\0') {
        return -1;
    }
    if (strtab_contains(s->chans, name)) {
        return -1; /* already known */
    }
    /* The key is registered here with a NULL value; server_chan_attach() below
     * installs the chan_t. Phase 2 stored NULL because struct chan did not exist,
     * and the two-step shape is what lets the Phase 2 probe keep its exact
     * contract -- see the comment on server_chan_lookup(). */
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
    /* Phase 2's probe, unchanged: "is this EXACT key present". It is
     * deliberately case-SENSITIVE, because a case-insensitive fold is Phase 4's
     * business and belongs in the accessor that canonicalises rather than
     * appearing here as a silent side effect. The channel VALUE is reached
     * through server_chan_get() in core/channel.c. */
    return name;
}

/* ---------------------------------------------------------------------------
 * The channel set: values, and an ordered index
 * ---------------------------------------------------------------------------
 * The Phase 2 probes above answer "is this key present" and carry no value.
 * These are the value-carrying pair declared in core/channel.h, and they live
 * here because the strtab is file-private: a second accessor in another file
 * would mean either exporting the table type or duplicating the probe loop, and
 * the probe loop is the one thing in this file that must not exist twice.
 */
int server_chan_attach(server_t *s, chan_t *ch)
{
    if (s == NULL || ch == NULL) {
        return -1;
    }
    if (server_chan_get(s, ch->name) != NULL) {
        return -1; /* the name is taken */
    }
    if (server_chan_add(s, ch->name) != 0) {
        return -1;
    }
    /* Install the value now that the key is reserved. strtab_put on an
     * existing key overwrites rather than refusing, which is exactly the
     * re-claim case and is why attach can be written in this order. */
    if (strtab_put(s->chans, ch->name, ch) != 0) {
        server_chan_remove(s, ch->name);
        return -1;
    }
    if (s->nchan_objs == s->chan_objs_cap) {
        size_t want = (s->chan_objs_cap == 0) ? 8u : s->chan_objs_cap * 2u;
        chan_t **grown = (chan_t **)realloc(s->chan_objs, want * sizeof *grown);

        if (grown == NULL) {
            /* Undo the registry entry, so a failure here cannot leave a channel
             * that LIST can enumerate and JOIN cannot find. The two indexes
             * agreeing is an invariant, not a nicety. */
            server_chan_remove(s, ch->name);
            return -1;
        }
        s->chan_objs = grown;
        s->chan_objs_cap = want;
    }
    s->chan_objs[s->nchan_objs++] = ch;
    return 0;
}

chan_t *server_chan_get(const server_t *s, const char *name)
{
    char canonical[CHAN_MAX_NAME + 1];

    if (s == NULL || name == NULL) {
        return NULL;
    }
    /* Canonicalise first. A channel's name is stored uppercase (2.2), so a
     * lookup that did not fold would make "JOIN #T" and "JOIN #t" two
     * channels -- which is the one behaviour the Phase 2 probe deliberately
     * does not have. */
    (void)chan_name_upper(canonical, sizeof canonical, name);
    if (canonical[0] == '\0') {
        return NULL;
    }
    if (!strtab_contains(s->chans, canonical)) {
        return NULL;
    }
    return (chan_t *)strtab_get(s->chans, canonical);
}

void server_chan_detach(server_t *s, const char *name)
{
    char canonical[CHAN_MAX_NAME + 1];

    if (s == NULL || name == NULL) {
        return;
    }
    (void)chan_name_upper(canonical, sizeof canonical, name);
    server_chan_remove(s, canonical);
    for (size_t i = 0; i < s->nchan_objs; i++) {
        if (s->chan_objs[i] != NULL &&
            strcmp(s->chan_objs[i]->name, canonical) == 0) {
            /* Order-preserving, like conn_t::chans and chan_t::members: LIST's
             * row order is creation order, and one channel leaving must not
             * reshuffle the rows behind it. */
            (void)memmove(&s->chan_objs[i], &s->chan_objs[i + 1u],
                          (s->nchan_objs - i - 1u) * sizeof s->chan_objs[0]);
            s->nchan_objs--;
            return;
        }
    }
}

size_t server_chan_count(const server_t *s)
{
    return (s == NULL) ? 0u : s->nchan_objs;
}

chan_t *server_chan_at(const server_t *s, size_t i)
{
    if (s == NULL || i >= s->nchan_objs) {
        return NULL;
    }
    return s->chan_objs[i];
}

/* ---------------------------------------------------------------------------
 * Peer lookup by server name (2.3)
 * ---------------------------------------------------------------------------
 * A CONN_SERVER conn's identity is conn_t::peer_name, which Phase 2's dial FSM
 * already sets, so this is a real lookup over real state rather than a
 * placeholder for state Phase 6 will create. O(FD_SETSIZE), which is the cost
 * 3.4 already accepts for enumerating connections, and which no caller pays on
 * the common path: chan_origin_state() short-circuits on origin == self before
 * it ever gets here. */
conn_t *server_find_peer(const server_t *s, const char *name)
{
    if (s == NULL || s->by_fd == NULL || name == NULL || name[0] == '\0') {
        return NULL;
    }
    for (size_t i = 0; i < SERVER_FD_TABLE; i++) {
        const conn_t *c = s->by_fd[i];

        if (c == NULL || c->kind != CONN_SERVER || c->peer_name == NULL) {
            continue;
        }
        if (same_server_name(c->peer_name, name)) {
            return s->by_fd[i];
        }
    }
    return NULL;
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
