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
/* The one include that points the other way. 4.3's inbound resync shadow is a
 * module global rather than a field on server_t, so the shutdown has to reach
 * into its owner to release it -- the same reason the dedup table below is freed
 * here rather than left to federation/dedup.c. core/fanout.c and
 * core/commands.c already include federation/ headers for the same class of
 * reason, so this is a direction this tree already has. */
#include "federation/burst.h"

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

/* Empty the bucket at `at` and count it out of the table, then SHIFT the rest of
 * the probe chain back over the gap. The one place a slot is cleared, so
 * strtab_del() below and strtab_del_owner() further down cannot disagree about
 * what "removed" leaves behind.
 *
 * ---------------------------------------------------------------------------
 * WHY DELETION HAS TO SHIFT (issue #107)
 * ---------------------------------------------------------------------------
 * This used to stop at the assignment below, and that made every key that probed
 * PAST `at` unreachable. strtab_probe() walks forward from the key's home
 * bucket and stops at the first slot with used == 0, so an empty slot is not
 * merely an absence -- it is a WALL, and anything behind it is invisible.
 *
 * The consequence was user-visible rather than theoretical. `u4x` and `u79x` both
 * hash to bucket 14; claim both, release `u4x`, and lookup("u79x") returns NULL
 * while the name is still held. PRIVMSG and WHOIS then answer 401 for a
 * connected, registered user, and a second client can claim the same name while
 * the first is still listed in 353 -- because WHO walks the ENUMERATION and never
 * consults the table for the name. Roughly 1 in 1024 per colliding pair, and
 * every release adds another hole rather than closing one, so a node running for a
 * day accumulates a great many.
 *
 * ---------------------------------------------------------------------------
 * WHY SHIFTING IS CORRECT FOR THIS PROBE, AND NOT BY LUCK
 * ---------------------------------------------------------------------------
 * Backward-shift deletion is only sound if the probe sequence for a key does not
 * depend on the table's HISTORY. Here it does not, and the reason is structural:
 *
 *   strtab_probe() derives everything from the key and the table size alone --
 *   idx = hash(k) % STRTAB_BUCKETS, then at = (idx + probe) % STRTAB_BUCKETS for
 *   probe = 0, 1, 2, ... The one thing that varies with history is where the walk
 *   STOPS, and "stop at the first empty slot" is precisely the thing a deletion
 *   perturbs. So the obligation after a deletion is exactly one: put every entry
 *   back where its own probe sequence will find it again.
 *
 * An entry in slot p is findable iff every slot in the cyclic range [home, p) is
 * occupied. After this function returns, the ONLY slot that is newly empty is
 * the final gap, so re-establishing that invariant for every entry is the whole
 * requirement -- and the rule below is what re-establishes it.
 *
 * The FOLDED flag is irrelevant to this and the reasoning must not be read as
 * depending on it. strtab_put() STORES the folded key (see the note there), so
 * strtab_hash(e->key) on a stored key is the same value strtab_probe() computed
 * for it, folded or not, and the shift therefore computes the same home for a
 * stored entry that a later probe of that key will.
 *
 * ---------------------------------------------------------------------------
 * THE MOVE RULE
 * ---------------------------------------------------------------------------
 * Walking forward from the gap, an entry sitting at `from` gets moved into the
 * gap `hole` when its own probe distance from its home is AT LEAST its distance
 * from the gap:
 *
 *   k  = (from - home) % STRTAB_BUCKETS   -- how far the entry sits from home
 *   pd = (from - hole) % STRTAB_BUCKETS   -- how far the gap sits behind it
 *
 * That single comparison is both directions at once, because the entry's cluster
 * [home, from) is occupied and the gap is empty, so the gap CANNOT be inside that
 * cluster -- which is exactly what `k >= pd` says. Note it admits the equal case:
 * an entry homed exactly on the gap belongs in the gap, and since pd >= 1 always
 * the k == 0 case (the entry sitting in its own home slot, which must not move
 * anywhere) falls out as "stay" with no special case to get backwards.
 *
 *   k >= pd   the gap is at or behind the entry's home, so the entry moves into
 *             it and the gap advances to where the entry was.
 *   k <  pd   the gap is strictly inside the entry's own cluster, so the entry
 *             stays exactly where it is and the walk continues past it.
 *
 * Two things the loop must therefore do, and both are load-bearing:
 *
 *   - CONTINUE past an entry that does not move. Only the gap advances on a move,
 *     so an entry further along can still need the gap even though the one just
 *     examined could not take it.
 *   - STOP at the first EMPTY slot. Nothing beyond a second empty slot can be
 *     probing through this one, so the rest of the table cannot have been
 *     affected.
 *
 * The bound is STRTAB_BUCKETS-1 steps, which visits every other slot exactly once
 * and wraps without ever coming back to `at` -- so an entry can never be moved
 * into the slot the walk started from and read again. */
static void strtab_remove_at(struct strtab *t, size_t at)
{
    size_t hole = at;
    size_t from = (at + 1u) % STRTAB_BUCKETS;
    size_t probe;

    free(t->buckets[at].key);
    t->buckets[at].key = NULL;
    t->buckets[at].val = NULL;
    t->buckets[at].used = 0;
    t->nentries--;

    for (probe = 0; probe + 1u < STRTAB_BUCKETS; probe++) {
        struct strtab_entry *e = &t->buckets[from];
        size_t home;
        size_t k;
        size_t pd;

        if (!e->used) {
            break; /* the rest of the chain is not reachable through here */
        }
        home = (size_t)(strtab_hash(e->key) % STRTAB_BUCKETS);
        k = (from + STRTAB_BUCKETS - home) % STRTAB_BUCKETS;
        pd = (from + STRTAB_BUCKETS - hole) % STRTAB_BUCKETS;
        if (k >= pd) {
            t->buckets[hole] = *e; /* the key pointer moves with the entry */
            e->key = NULL;
            e->val = NULL;
            e->used = 0;
            hole = from;
        }
        from = (from + 1u) % STRTAB_BUCKETS;
    }
}

static int strtab_del(struct strtab *t, const char *key)
{
    int found = 0;
    size_t at;

    if (t == NULL || key == NULL) {
        return -1;
    }
    at = strtab_probe(t, key, &found);
    if (at == (size_t)-1 || !found) {
        return -1;
    }
    strtab_remove_at(t, at);
    return 0;
}

/* ---------------------------------------------------------------------------
 * OWNER-SIDE TABLE OPERATIONS: "which keys point at this conn_t?"
 * ---------------------------------------------------------------------------
 * Every value in the nick table is a conn_t*, and the question "does this
 * connection still hold a name" is not answerable from conn_t::nick -- the
 * table is the only record, and conn_t::nick is a DISPLAY field that a rename
 * writes after the registry has already been updated. So it is asked of the
 * table, by scanning it.
 *
 * A linear scan of 1024 buckets on a table sized for a poll() set is the
 * right trade and not a compromise: these run when a connection is being torn
 * down or renamed, which is neither frequent nor latency-sensitive, and a
 * per-connection name counter would have to be kept correct by every write
 * path to the index -- which is the same class of "two places must agree"
 * hazard the index already has one of.
 *
 * The nick table is FOLDED, so these are spelling-agnostic by construction:
 * there is no comparison here to get wrong in the way a name-keyed scan of the
 * enumeration had to be (that was nick_same(), and it is gone -- see the
 * enumeration below). */
static size_t strtab_count_owner(const struct strtab *t, const void *owner)
{
    size_t i;
    size_t n = 0;

    if (t == NULL) {
        return 0u;
    }
    for (i = 0; i < STRTAB_BUCKETS; i++) {
        if (t->buckets[i].used && t->buckets[i].val == owner) {
            n++;
        }
    }
    return n;
}

/* Remove EVERY key mapped to `owner`, and return how many went. Used by the
 * teardown, which must not leave any reference to a conn_t it is about to free
 * -- and cannot be written as a single strtab_del() because a connection is not
 * guaranteed to hold exactly one name (see server_nick_claim).
 *
 * A single pass is NOT enough now that deletion shifts, and this is the one place
 * the shift changes what a caller has to do rather than being invisible inside
 * the table. strtab_remove_at() can move an entry from the slot AFTER the one
 * being cleared back into that slot -- which is the first thing it examines, and
 * the overwhelmingly common case in a chain of names that share a home bucket. A
 * forward scan has already gone past that slot, so an entry shifted into it
 * belongs to `owner` and is missed: a connection holding two colliding names
 * would have one of them survive its own teardown, pointing at freed memory.
 *
 * So the pass repeats until a whole pass finds nothing left to remove. It is
 * bounded and cheap in the right way: every extra pass removes at least one
 * entry, and a connection holds a handful of names at most, so this is
 * O(STRTAB_BUCKETS) for the ordinary one-name teardown. That is the same linear
 * scan the operation already was. */
static size_t strtab_del_owner(struct strtab *t, const void *owner)
{
    size_t n = 0;
    int again = 1;

    if (t == NULL) {
        return 0u;
    }
    while (again) {
        size_t i;

        again = 0;
        for (i = 0; i < STRTAB_BUCKETS; i++) {
            if (t->buckets[i].used && t->buckets[i].val == owner) {
                strtab_remove_at(t, i);
                n++;
                again = 1;
            }
        }
    }
    return n;
}

/* Case-insensitive server-name comparison, ASCII-folded.
 *
 * The same fold is required in four places now: 2.1's nick@server split, 2.4
 * ("server names are case-insensitive in IRC, so a comparison against our OWN
 * name MUST be case-insensitive"), channel.c's own server-name fold, and
 * fanout.c's own-origin check on the forward path. It is written out here
 * rather than exported because it is six lines and a public helper two of the
 * three callers would never use again is a wider API than the duplication is
 * worth. The copies are asserted to agree by test_channels.c, which looks a
 * peer up by a name differing only in case. */
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
    /* The peer links. Nothing here closes a descriptor: a link only NAMES one,
     * and the conn the loop registered for that descriptor has already been
     * closed by the walk above, so dropping the name is the whole teardown. The
     * vector is a flat array of POD with no allocations of its own, which is
     * why it needs one free and no per-element destructor. */
    free(s->links);
    s->links = NULL;
    s->nlinks = 0;
    s->links_cap = 0;
    /* The dedup table, owned by federation/dedup.c but freed here. The two
     * modules are the same library, and a teardown arm that called into the
     * owner would mean a second entry point whose only job is to be called from
     * one place -- while the alternative, leaving it to the owner, means the
     * table's lifetime is not visible in the function that ends every other
     * allocation on this struct. It is NULL on a node that never received a
     * relayed message, which is the common case today.
     *
     * ASSERTED, NOT VERIFIED, ON THIS PLATFORM: LeakSanitizer does not exist on
     * Darwin, so a missing free here is invisible to the local sanitizer run
     * and is caught only by the Linux CI job. */
    free(s->dedup_tab);
    s->dedup_tab = NULL;
    s->dedup_head = NULL;
    s->dedup_tail = NULL;
    s->dedup_used = 0;
    s->dedup_swept_ms = 0;
    /* 4.3's resync shadow, the second federation allocation this function
     * releases and the only one it has to CALL rather than free. C4 declined to
     * add this arm because it could not be checked on Darwin; that reasoning was
     * backwards, and the correction is the reason this arm exists: an arm that
     * is unverifiable LOCALLY is exactly the one worth adding when LeakSanitizer
     * DOES run on the CachyOS Linux CI runner. A node stopped mid-transaction --
     * a SIGTERM while a peer is bursting -- was leaking up to
     * IRC_BURST_MAX_BYTES to the kernel, and the only evidence was a build nobody
     * ran locally.
     *
     * IT IS SAFE HERE AND AT ANY POINT in the walk above: the shadow is records
     * this node copied out of what a peer said. It holds no conn_t*, no chan_t*
     * and no server_link_t*, so nothing it can be holding has been freed yet.
     * And it is safe on a node that never called fed_open(), which is every
     * test that links this library without the federation fixture -- the shadow
     * is a file-scope static and therefore already zero.
     *
     * ASSERTED, NOT VERIFIED, ON THIS PLATFORM -- and the arm prints an
     * `[observable] fed_burst_close: shadow=OPEN|NONE` line precisely so it is
     * ASSERTED here too: a test can prove the arm ran without a leak checker,
     * and Linux CI can read the same line next to its LSan run. */
    fed_burst_close(s);
    /* Phase 7's topic cache: a plain free of a plain vector, which is the
     * simplest arm on this function and the newest. It sits HERE rather than at
     * the end because the ordering that matters on this struct is "the peer links
     * and the dedup table are federation state, and this is not" -- a reader
     * looking for where the federation allocations go will not pass it by, and
     * a reader looking for the topic cache will not go looking through the
     * federation arms for it. The cache holds three topic fields and a name per
     * entry and no conn_t*, no chan_t* and no server_link_t*, so it is safe at
     * any point in the walk above. */
    free(s->topics);
    s->topics = NULL;
    s->ntopics = 0;
    s->topics_cap = 0;
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

    /* Retire the connection from the nick index, and through the ONE function
     * that does it. This is the whole of issue #102: the close used to remove
     * the conn from the registry's TABLE and then free it, leaving the
     * ENUMERATION -- the vector WHO walks -- holding the pointer. The next bare
     * WHO dereferenced freed memory, and the count stayed one too high for the
     * rest of the process's life.
     *
     * One call, and deliberately not two. The guard that made the old code
     * safe -- "only if this conn is still the holder, or a conn that was denied
     * the nick evicts the one that has it" -- lived in the CALLER, wrapped
     * around one half of the index, so nothing stopped the other half from
     * being applied on its own. server_nick_unclaim() has no name argument at
     * all: it removes the table entries that map to THIS conn and the vector
     * entry that IS this conn, in that order, with no return in between. The
     * ownership question has become the deletion predicate instead of a test
     * somebody has to remember, and there is no longer a way to write half of
     * the operation.
     *
     * It is a no-op for a connection that never claimed a name, so this is not
     * conditional on c->nick -- that field is a display copy, and asking it
     * whether the connection is in the index is the mistake this paragraph is
     * about. */
    server_nick_unclaim(s, c);

    /* The counterpart of the loop's conn_close lines, and deliberately a
     * different word: those say a connection is ON ITS WAY OUT and why, this one
     * says it is GONE and what the node's indexes hold now that it is. The
     * nicks= is the whole reason this line exists -- "the nick was released" is
     * otherwise only checkable by sending a message to the name afterwards, and a
     * client that disconnects without QUIT leaves the question open for good,
     * because the node never receives a line saying the name is free.
     *
     * Printed BEFORE conn_free() because c->nick is read here, and before the
     * counter is bumped so the two bracket the teardown in a readable order. */
    printf("[observable] conn_reaped: fd=%d nick=%s nicks=%zu\n", fd,
           (c->nick[0] != '\0') ? c->nick : "-", server_nick_count(s));

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

/* ---------------------------------------------------------------------------
 * THE NICK INDEX, and the invariant that makes it one index
 * ---------------------------------------------------------------------------
 * A connection is in the enumeration if and only if it holds at least one name,
 * and it is in it AT MOST ONCE. The table holds one entry per name; the vector
 * holds one entry per USER. Those are different cardinalities on purpose, and
 * WHO is a question about users: 352 is one line per user, so a connection that
 * somehow held two names must still produce one line, or the same person appears
 * twice in a client's channel list and twice in every WHO they ask for.
 *
 * Every rule below exists to keep that one sentence true, and the two failures
 * it prevents are the two this registry has already had:
 *
 *   issue #102  a teardown removed the table entry and freed the conn_t, and
 *               the vector kept the pointer. A freed conn_t stayed reachable
 *               from server_nick_at() and WHO dereferenced it.
 *   issue #103  a claim appended unconditionally, so one connection holding two
 *               names was in the vector twice, the enumeration counted a
 *               connection that appears once, and a teardown that removed ONE
 *               copy left the other one dangling -- #102's bug reachable through
 *               #103's.
 *
 * The repair in both cases is the same shape: the vector is keyed by POINTER
 * and the table by NAME, and every operation is expressed on one side in terms
 * of the other so that neither half can be applied alone. There is no
 * name-keyed removal of the vector anywhere in this file, which is what
 * guarantee #102 rests on.
 */

/* Append `c` to the nick enumeration, unless it is already in it. Returns 0 on
 * success, -1 on allocation failure or a bad argument. The vector grows
 * geometrically like conn_t's own channel list does, and is not bounded: it
 * holds one entry per registered connection, so the loop's own FD_SETSIZE
 * ceiling is the bound.
 *
 * "Unless it is already in it" is issue #103. The append used to be
 * unconditional, which meant a connection holding two names appeared twice and
 * the enumeration counted connections and names at once. Making it conditional
 * makes the invariant hold whatever order the caller does things in, rather than
 * holding only because handle_nick() happens to claim before it releases: that
 * ordering is a property of one caller, and a mitigation by accident is not a
 * design. test_registries.c reaches the two-names state by calling this API
 * directly and asserts the count does not move.
 *
 * The cost is a linear scan per claim, over a vector bounded by FD_SETSIZE, on
 * a path that already hashed a key. */
static int nick_objs_add(server_t *s, conn_t *c)
{
    size_t i;

    if (s == NULL || c == NULL) {
        return -1;
    }
    for (i = 0; i < s->nnick_objs; i++) {
        if (s->nick_objs[i] == c) {
            return 0; /* already enumerated: one entry per connection */
        }
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

/* Remove `c` from the enumeration, preserving claim order. Idempotent.
 *
 * Keyed by POINTER, which is the whole point and replaces the name-keyed
 * nick_objs_del() this used to be. Comparing nick strings meant matching a
 * conn_t::nick -- a display field -- against a key, with the ASCII fold
 * re-implemented on the spot, and it could remove the entry of a connection
 * that did not hold the name at all: the case where a conn was DENIED a
 * nickname and had the same string in conn_t::nick anyway, which is exactly what
 * a client that asks for a name somebody else holds looks like from inside.
 *
 * Every copy is removed rather than the first: with the conditional append there
 * can only be one, but a teardown that is correct only because of what the
 * claim path does is the same fragile coupling in the other direction. */
static void nick_objs_drop(server_t *s, conn_t *c)
{
    size_t i = 0;

    while (i < s->nnick_objs) {
        if (s->nick_objs[i] == c) {
            size_t j;

            for (j = i + 1u; j < s->nnick_objs; j++) {
                s->nick_objs[j - 1u] = s->nick_objs[j];
            }
            s->nnick_objs--;
            s->nick_objs[s->nnick_objs] = NULL;
            continue; /* whatever shifted into slot i may also be c */
        }
        i++;
    }
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
     * about.
     *
     * The append is idempotent (see nick_objs_add), so a claim that only ADDS a
     * name to a connection already in the vector cannot fail here -- there is no
     * allocation on that path and nothing to roll back. That is deliberate: the
     * rename in handle_nick() claims the new name before releasing the old one,
     * and an idempotent append is what lets the two halves of a rename meet in
     * the middle without the enumeration briefly losing the connection. */
    if (nick_objs_add(s, c) != 0) {
        (void)strtab_del(s->nicks, nick);
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * WHY THERE IS NO nick_same() ANY MORE
 * ---------------------------------------------------------------------------
 * There used to be a third copy of the node's ASCII fold here, comparing
 * conn_t::nick against a release key, and the reason it could be deleted is the
 * reason it existed: the enumeration was keyed by NAME, so removing an entry
 * meant finding it by name and meant re-implementing the table's own key rule in
 * a second place. The enumeration is keyed by pointer now, so no comparison is
 * needed and the fold exists in exactly one place -- inside the table's probe.
 *
 * The case it was protecting is still protected, and better: test_registries.c
 * releases "cAROL" for a nickname claimed as "carol" and asserts the ENUMERATION
 * shrank too, and that still works, because server_nick_release() below gets
 * the holder from the TABLE, and the table's probe folds. One implementation of
 * the rule instead of two, and the copy that could have drifted is the one that
 * is gone. same_server_name() below and channel.c's same_name() are the other
 * two folds in the node, both still written out for the reason server.h records
 * for the first pair. */

/* Give up ONE name, leaving the connection itself in the registry. This is the
 * release for a connection that is STAYING: handle_nick()'s rename is the only
 * caller in the tree. A caller that is destroying the connection must use
 * server_nick_unclaim() below instead, and the difference is not stylistic --
 * this function is handed a name and knows nothing about which conn_t will be
 * freed afterwards, so it cannot promise that no reference to it survives.
 *
 * Both halves come from the TABLE, in this order:
 *
 *   1. the holder is read out of the table, so a spelling the holder never typed
 *      still finds it: the table's probe folds, and this function does not have
 *      a fold of its own to get wrong. (A name nobody holds is a no-op, which is
 *      what makes the double call on the ordinary QUIT path -- handler, then
 *      reaper -- harmless rather than a corruption.)
 *   2. the name is removed, and the holder leaves the enumeration ONLY if it no
 *      longer holds a name. That second test is why a rename cannot drop the
 *      connection out of WHO's walk: handle_nick() claims the new name first,
 *      so the holder is in the table again by the time the old one is released,
 *      and the enumeration is a set of users rather than a count of names.
 *
 * A connection that holds two names keeps its entry until both are given up,
 * which is the invariant at the top of this section rather than a special case
 * here. */
void server_nick_release(server_t *s, const char *nick)
{
    conn_t *holder;

    if (s == NULL || nick == NULL) {
        return;
    }
    holder = (conn_t *)strtab_get(s->nicks, nick);
    if (holder == NULL) {
        return; /* nobody holds this name: already released */
    }
    (void)strtab_del(s->nicks, nick);
    if (strtab_count_owner(s->nicks, holder) == 0u) {
        nick_objs_drop(s, holder);
    }
}

/* Retire a connection from the nick index. THE teardown path, and the only one:
 * server_close_conn() and handle_quit() both come here, so a QUIT and a client
 * that vanished without one cannot do different things.
 *
 * It takes a conn_t and not a name, and that is the design rather than a
 * convenience. A name-keyed teardown has to ask "does this conn still hold the
 * name" and then remove the name -- the ownership guard that #102 got wrong by
 * applying to one half of the index and forgetting the other. Keyed on the
 * connection there is nothing to ask: the table loses exactly the entries whose
 * VALUE is this conn, and the vector loses exactly the entries that ARE this
 * conn. A connection that was denied a nickname cannot evict the holder's entry
 * (that entry's value is somebody else, and it is not this conn), and a
 * connection that somehow holds several names loses all of them rather than one,
 * which is what makes the subsequent conn_free() safe with no further argument.
 *
 * Idempotent, and a no-op for a connection that never claimed a name: the
 * teardown runs on every close, including every close of a connection that was
 * still in registration. Both halves are in this function with no early return
 * between them, so there is no longer a way to apply one of them alone. */
void server_nick_unclaim(server_t *s, conn_t *c)
{
    if (s == NULL || c == NULL) {
        return;
    }
    (void)strtab_del_owner(s->nicks, c);
    nick_objs_drop(s, c);
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
 * The peer link registry (2.3)
 * ---------------------------------------------------------------------------
 * A vector, and the reason is at server_link_t. These three are the only ways
 * into it, so the layout never has to be known outside this file -- which is the
 * same bargain server_t::nick_objs makes with server_nick_at().
 */
server_link_t *server_find_link(const server_t *s, const char *name)
{
    size_t i;

    if (s == NULL || name == NULL || name[0] == '\0') {
        return NULL;
    }
    for (i = 0; i < s->nlinks; i++) {
        if (same_server_name(s->links[i].name, name)) {
            return &s->links[i];
        }
    }
    return NULL;
}

size_t server_link_count(const server_t *s)
{
    return (s == NULL) ? 0u : s->nlinks;
}

server_link_t *server_link_at(const server_t *s, size_t i)
{
    if (s == NULL || i >= s->nlinks) {
        return NULL;
    }
    return &s->links[i];
}

conn_t *server_link_conn(const server_t *s, const server_link_t *link)
{
    /* Every one of these is a real case and not defensive padding:
     *   link == NULL   the caller had no link, so there is nothing to name
     *   fd < 0          a link with no socket: between dial halves, or after a
     *                   peer was dropped. Common, not degenerate.
     *   fd out of range by_fd is indexed BY the descriptor, so an fd the table
     *                   cannot hold names no slot at all. */
    if (s == NULL || link == NULL || link->fd < 0 ||
        link->fd >= SERVER_FD_TABLE) {
        return NULL;
    }
    return s->by_fd[link->fd];
}

/* ---------------------------------------------------------------------------
 * Peer lookup by server name (2.3)
 * ---------------------------------------------------------------------------
 * A link, a state test and a by_fd index. The reasoning for all three -- and for
 * why this is no longer a scan of by_fd for a conn_t::peer_name -- is at
 * server_find_peer() in the header, which is where a caller of this function
 * will be reading.
 *
 * The ESTABLISHED comparison is an int against a mirror field rather than a
 * switch on handshake_state_t, deliberately: hs.state is an enum, and
 * -Weverything's -Wswitch-default and -Wcovered-switch-default cannot both be
 * satisfied by a switch over it, and a two-way test does not need one. The
 * mirror is written in exactly one place, so the comparison cannot be reading a
 * field nothing has updated. */
conn_t *server_find_peer(const server_t *s, const char *name)
{
    const server_link_t *link;

    if (s == NULL || s->by_fd == NULL) {
        return NULL;
    }
    link = server_find_link(s, name);
    if (link == NULL || link->state != (int)ESTABLISHED) {
        return NULL;
    }
    return server_link_conn(s, link);
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
    /* The one clock the node has, taken HERE rather than by the tick later: a
     * tick that supplied the stamp would stamp every DIAL_CONNECTING entry on
     * the same tick, so a dial that had already been waiting would be handed
     * the timeout it had already used up. Taking it at the start makes the
     * deadline a property of the connect() rather than of the loop's cadence. */
    slot->started_ms = server_now_ms();
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
