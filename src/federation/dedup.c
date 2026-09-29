/* dedup.c -- see dedup.h. The 2.4 per-node (origin, epoch, id) store.
 *
 * ---------------------------------------------------------------------------
 * THE SHAPE, AND WHY EACH PIECE OF IT
 * ---------------------------------------------------------------------------
 * Two indexes over one array, because the two questions the store is asked are
 * different and have different costs:
 *
 *   the TABLE (open addressed, linear probing)  "have I seen this key?"
 *         O(1) on the message path, which is the only place it is consulted.
 *   the LRU  (intrusive, doubly linked)          "which key may I forget?"
 *         O(1) per eviction and a suffix walk per sweep, so forgetting a full
 *         table costs nothing per message.
 *
 * The alternative -- one linked list walked per lookup -- would put a per-message
 * cost on the forwarding path proportional to how many messages the node has
 * been sent, which is exactly the thing that grows without bound. The other
 * alternative, growing the table, would put a rehash on that same path.
 *
 * ---------------------------------------------------------------------------
 * WHY THE LRU NEEDS FIXUPS WHEN THE PROBE CHAIN IS REPAIRED
 * ---------------------------------------------------------------------------
 * Deleting from a linear-probing table is not `entry->used = 0`: a hole above a
 * key's ideal slot truncates the chain that reaches it, and that key becomes
 * unreachable -- silently, since nothing about the entry is wrong. The repair is
 * back-shift deletion: the following entries are moved DOWN into the hole
 * whenever their own ideal slot says the move is safe, and the walk continues
 * from where the last one moved to.
 *
 * That repair MOVES an entry, and the LRU holds POINTERS to entries. A moved
 * entry is now at a different address, so every pointer to it is stale: its two
 * neighbours, and the head or the tail if it was one. Each is a single
 * assignment, made in table_remove() at the point of the move, which is why
 * back-shifting stays O(1) per move here rather than becoming the O(n) fixup a
 * table of INDICES would need.
 *
 * The alternative considered and rejected: a table of (payload + index) slots
 * with the LRU stored as slot indices, so a move updates one uint32 in the ring
 * instead of three pointers. It is the same asymptotics and one fewer pointer
 * chase, and it was not chosen because it makes the eviction path depend on the
 * LRU ring's layout, which is the one piece of this store that is about
 * bookkeeping rather than about correctness. Pointers that are fixed at the one
 * place an entry moves are easier to check by reading than a ring whose every
 * writer has to remember the other one.
 */
#include "federation/dedup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/server.h"

/* One remembered message is fed_dedup_entry_t, declared in dedup.h so that the
 * 104-byte size and the 416 KiB table are things a test can measure rather than
 * things a comment asserts. The reasoning for every field, and for occupancy
 * being `origin[0] != '\0'` rather than a flag, is there. */

/* Is slot `e` occupied? A macro rather than a function because it is the test the
 * probe loop runs on every step of every lookup, on the message path. */
#define DEDUP_USED(e) (((e)->origin[0] != '\0') ? 1 : 0)

/* The probe mask. A power-of-two capacity is required, not preferred: it turns
 * the per-probe modulo into an AND, and the probe runs on the message path. */
#define DEDUP_MASK ((size_t)(IRC_DEDUP_MAX - 1u))

/* ASCII-only case fold, and the reason is the one fanout.c and channel.c and
 * server.c each already give: 005 advertises CASEMAPPING=ascii, so this node has
 * told every client that []\~ and {}|^ are not equivalent, and folding them here
 * would break that promise where nothing else on the wire would show it.
 *
 * Folding the KEY is not optional. message.h is explicit that an
 * irc-serve-origin value is preserved verbatim and that comparing it against
 * our own name is the caller's job -- because server names are case-insensitive
 * (2.1, RFC 1459 2.3.2), so `IRC.A` and `irc.a` are one server. A store that
 * hashed the origin verbatim would treat a peer's re-spelling of the same
 * origin as a new message and forward a duplicate, and the peer that re-spelled
 * it would be entirely within its rights. */
static uint64_t fold_byte(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (uint64_t)(unsigned char)(c - ('A' - 'a'));
    }
    return (uint64_t)(unsigned char)c;
}

/* FNV-1a over the folded origin, then the two numbers, then a final avalanche.
 *
 * The avalanche is not decoration. The table keeps only the low 12 bits of this
 * value, and the multiply that FNV ends on leaves its ENTROPY in the high bits
 * -- masking straight off the low bits of an FNV hash is a known way to get a
 * table that works on the first few keys and clusters on the rest. The two
 * shifts and one multiply below are the standard finaliser and they are cheaper
 * than the clustering they prevent.
 *
 * A key that differs only in epoch or only in id is a DIFFERENT message -- that
 * is the whole reason epoch exists, so a node that has restarted can reuse id 1
 * without the store believing it has seen the old id 1 -- so the two numbers are
 * mixed in as themselves rather than as more string bytes. */
static uint64_t entry_hash(const char *origin, uint64_t epoch, uint64_t id)
{
    uint64_t h = 1469598103934665603ULL; /* FNV-1a 64 offset basis */
    const char *p;

    for (p = origin; *p != '\0'; p++) {
        h ^= fold_byte(*p);
        h *= 1099511628211ULL;           /* FNV-1a 64 prime */
    }
    h ^= epoch;
    h *= 1099511628211ULL;
    h ^= id;
    h *= 1099511628211ULL;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    return h;
}

static int same_origin(const char *a, const char *b)
{
    size_t i;

    for (i = 0; a[i] != '\0' && b[i] != '\0'; i++) {
        if (fold_byte(a[i]) != fold_byte(b[i])) {
            return 0;
        }
    }
    return a[i] == '\0' && b[i] == '\0';
}

/* ---------------------------------------------------------------------------
 * The LRU list
 * ---------------------------------------------------------------------------
 * Four operations on a doubly linked list is the usual four, and they are all
 * inline-able; they are functions because the back-shift fixup in
 * table_remove() has to do two of them piecemeal and a list whose invariants
 * were only in one place would drift between that path and the ordinary one.
 */
static void lru_push_front(fed_dedup_entry_t **head, fed_dedup_entry_t **tail,
                           fed_dedup_entry_t *e)
{
    e->lru_prev = NULL;
    e->lru_next = *head;
    if (*head != NULL) {
        (*head)->lru_prev = e;
    }
    *head = e;
    if (*tail == NULL) {
        *tail = e;
    }
}

static void lru_unlink(fed_dedup_entry_t **head, fed_dedup_entry_t **tail,
                       fed_dedup_entry_t *e)
{
    if (e->lru_prev != NULL) {
        e->lru_prev->lru_next = e->lru_next;
    } else if (*head == e) {
        *head = e->lru_next;
    }
    if (e->lru_next != NULL) {
        e->lru_next->lru_prev = e->lru_prev;
    } else if (*tail == e) {
        *tail = e->lru_prev;
    }
    e->lru_prev = NULL;
    e->lru_next = NULL;
}

/* Move `e` to the head. Touching a remembered message is what keeps it
 * remembered: the TTL is a bound on how long since the LAST time this node was
 * sent the message, so a copy that keeps arriving must not age out from under
 * the arrivals. */
static void lru_touch(fed_dedup_entry_t **head, fed_dedup_entry_t **tail,
                      fed_dedup_entry_t *e)
{
    if (*head == e) {
        return;
    }
    lru_unlink(head, tail, e);
    lru_push_front(head, tail, e);
}

/* ---------------------------------------------------------------------------
 * The table
 * ---------------------------------------------------------------------------
 * The table is allocated on the first insert rather than in server_init(). See
 * the field's comment in server.h for the cost that is being deferred and the
 * failure that the deferral introduces.
 *
 * There is no growth. A fixed table means the message path cannot fail on an
 * allocation, and a store that has to rehash is a store that can block the event
 * loop -- which 3.4 forbids for anything on the path from a socket read to a
 * write. Fullness is answered by evicting, and eviction losing a dedup
 * opportunity is bounded and self-correcting: it costs at most one duplicate
 * delivery, and only for messages older than the newest IRC_DEDUP_MAX of them. */
static int table_alloc(server_t *s)
{
    if (s->dedup_tab != NULL) {
        return 0;
    }
    s->dedup_tab = (fed_dedup_entry_t *)calloc(1u, IRC_DEDUP_TABLE_BYTES);
    if (s->dedup_tab == NULL) {
        return -1;
    }
    return 0;
}

/* Remove the entry at `idx` and repair the probe chain, moving the entries
 * above it down. The LRU fixups are here and not in the caller because the move
 * is what invalidates them, and a fixup done anywhere else would be a thing a
 * second reader has to know about. See the file header.
 *
 * The chain test is the standard one: entry at slot j may move down into the
 * hole at slot idx exactly when j's own ideal slot does not lie cyclically
 * inside (idx, j]. If it did, moving it would put it before its ideal slot and
 * the hole at idx would then sit between that slot and the entry, truncating
 * the chain that finds it. */
static void table_remove(server_t *s, size_t idx)
{
    fed_dedup_entry_t *tab = s->dedup_tab;
    size_t j = idx;

    tab[idx].origin[0] = '\0';
    tab[idx].lru_prev = NULL;
    tab[idx].lru_next = NULL;
    for (;;) {
        size_t ideal;
        int movable;

        j = (j + 1u) & DEDUP_MASK;
        if (DEDUP_USED(&tab[j]) == 0) {
            return; /* end of the chain: nothing above depends on this hole */
        }
        ideal = (size_t)(entry_hash(tab[j].origin, tab[j].epoch, tab[j].id) &
                         DEDUP_MASK);
        if (j > idx) {
            movable = (ideal <= idx || ideal > j) ? 1 : 0;
        } else if (j < idx) {
            /* The wrap case. j < idx means the chain has come round the end of
             * the array, so "after idx" is the region that runs from idx to the
             * top and then from 0 to j. */
            movable = (ideal <= idx && ideal > j) ? 1 : 0;
        } else {
            movable = 0; /* the table is full around the ring; nothing moves */
        }
        if (movable == 0) {
            continue;
        }
        tab[idx] = tab[j];
        tab[j].origin[0] = '\0';
        /* The moved entry now lives at &tab[idx]; everything that pointed at
         * &tab[j] has to be repointed, and there are exactly three possible
         * holders: its two LRU neighbours, and head or tail if it was one. */
        if (tab[idx].lru_prev != NULL) {
            tab[idx].lru_prev->lru_next = &tab[idx];
        } else if (s->dedup_head == &tab[j]) {
            s->dedup_head = &tab[idx];
        }
        if (tab[idx].lru_next != NULL) {
            tab[idx].lru_next->lru_prev = &tab[idx];
        } else if (s->dedup_tail == &tab[j]) {
            s->dedup_tail = &tab[idx];
        }
        tab[j].lru_prev = NULL;
        tab[j].lru_next = NULL;
        idx = j;
    }
}

int fed_dedup_seen(struct server *s, const irc_serve_tags_t *t,
                   uint64_t now_ms)
{
    irc_serve_tags_t key;
    fed_dedup_entry_t *tab;
    size_t start;
    size_t i;

    if (s == NULL || t == NULL) {
        return 1; /* nothing to check against: refuse the message, see the header */
    }
    if (!irc_serve_tags_valid(t)) {
        /* An illegal origin is not a key this store can hold, so it cannot be
         * "new" either. The caller is separately required to drop it (2.4's tag
         * grammar is checked on receipt); reporting it as seen here means the
         * two decisions cannot disagree about the same line. */
        return 1;
    }
    memcpy(key.origin, t->origin, sizeof key.origin);
    key.epoch = t->epoch;
    key.id = t->id;

    if (table_alloc(s) != 0) {
        /* Fail closed. The alternative -- carry on as though nothing had been
         * recorded -- is a store that does not store, which is the loop 2.4
         * exists to prevent. */
        return 1;
    }
    tab = s->dedup_tab;

    /* The sweep runs only from a store that is more than half full, and is
     * throttled inside fed_dedup_sweep(). The gate here is a comparison on the
     * message path, which is worth having: a node whose store is nearly empty
     * has nothing to sweep, and paying a function call to discover that on every
     * message would be the price of a pass that finds nothing. */
    if (s->dedup_used > (size_t)(IRC_DEDUP_MAX / 2u)) {
        (void)fed_dedup_sweep(s, now_ms);
    }

    start = (size_t)(entry_hash(key.origin, key.epoch, key.id) & DEDUP_MASK);
    for (i = 0; i < (size_t)IRC_DEDUP_MAX; i++) {
        size_t at = (start + i) & DEDUP_MASK;

        if (DEDUP_USED(&tab[at]) == 0) {
            /* A free slot, so the key is not present -- and this is the slot it
             * goes in. The emptiness is enough to conclude absence because
             * linear probing with no tombstones leaves no hole above a live key:
             * table_remove() repairs every chain it breaks. */
            memcpy(tab[at].origin, key.origin, sizeof tab[at].origin);
            tab[at].epoch = key.epoch;
            tab[at].id = key.id;
            tab[at].seen_ms = now_ms;
            lru_push_front(&s->dedup_head, &s->dedup_tail, &tab[at]);
            s->dedup_used++;
            return 0;
        }
        if (tab[at].epoch == key.epoch && tab[at].id == key.id &&
            same_origin(tab[at].origin, key.origin)) {
            lru_touch(&s->dedup_head, &s->dedup_tail, &tab[at]);
            tab[at].seen_ms = now_ms;
            printf("[observable] fed_dedup_drop: origin=%s epoch=%llu id=%llu "
                   "hops=%lu reason=DUPLICATE\n",
                   key.origin, (unsigned long long)key.epoch,
                   (unsigned long long)key.id, (unsigned long)t->hops);
            return 1;
        }
    }

    /* The whole table is occupied and every slot belongs to another key, which
     * the size gate above says means the store is at capacity. Evict the least
     * recently seen and take its slot.
     *
     * The LRU is the right victim and not an arbitrary one: capacity eviction is
     * the one place this store is allowed to forget something, and forgetting
     * the OLDEST is what makes the loss least likely to matter. Correctness
     * never depends on it -- a forgotten key is at worst one message delivered
     * twice, and only once the store is genuinely full, which at this capacity
     * means a peer is replaying ids. */
    if (s->dedup_tail != NULL) {
        fed_dedup_entry_t *victim = s->dedup_tail;
        size_t vidx = (size_t)(victim - tab);

        lru_unlink(&s->dedup_head, &s->dedup_tail, victim);
        table_remove(s, vidx);
        s->dedup_used--;
    }
    /* Back at the start of the probe: the eviction above opened a hole, and the
     * hole is the first free slot from here. This cannot loop forever even if
     * the eviction found no victim (a store whose count disagrees with its
     * occupancy), because the loop below still terminates on a free slot or on
     * IRC_DEDUP_MAX probes. */
    for (i = 0; i < (size_t)IRC_DEDUP_MAX; i++) {
        size_t at = (start + i) & DEDUP_MASK;

        if (DEDUP_USED(&tab[at]) == 0) {
            memcpy(tab[at].origin, key.origin, sizeof tab[at].origin);
            tab[at].epoch = key.epoch;
            tab[at].id = key.id;
            tab[at].seen_ms = now_ms;
            lru_push_front(&s->dedup_head, &s->dedup_tail, &tab[at]);
            s->dedup_used++;
            return 0;
        }
    }
    /* Unreachable: the table has IRC_DEDUP_MAX slots, the loop is about to look
     * at all of them, and a full sweep with no free slot means every slot is
     * occupied. Refusing is the only honest answer left, and it is the same
     * fail-closed one as an allocation failure. */
    return 1;
}

size_t fed_dedup_sweep(struct server *s, uint64_t now_ms)
{
    size_t dropped = 0;

    if (s == NULL || s->dedup_tab == NULL) {
        return 0u;
    }
    /* Subtraction, not addition, so the comparison is correct if the clock ever
     * returns a value lower than the last one. 3.4's clock is monotonic, so this
     * is a shape rather than a claim. */
    if ((uint64_t)(now_ms - s->dedup_swept_ms) < (uint64_t)IRC_DEDUP_SWEEP_MS) {
        return 0u;
    }
    s->dedup_swept_ms = now_ms;

    /* The tail walk, and it stops at the first entry that is NOT expired rather
     * than sweeping the whole list. That is what the LRU ordering buys: entries
     * are in last-seen order, so expired entries are a suffix and a sweep costs
     * one comparison per entry it actually drops plus one that ends it. */
    while (s->dedup_tail != NULL) {
        fed_dedup_entry_t *victim = s->dedup_tail;
        size_t vidx;

        if ((uint64_t)(now_ms - victim->seen_ms) < (uint64_t)IRC_DEDUP_TTL_MS) {
            break;
        }
        vidx = (size_t)(victim - s->dedup_tab);
        lru_unlink(&s->dedup_head, &s->dedup_tail, victim);
        table_remove(s, vidx);
        s->dedup_used--;
        dropped++;
    }
    return dropped;
}

void fed_dedup_reset(struct server *s)
{
    if (s == NULL) {
        return;
    }
    if (s->dedup_tab != NULL) {
        /* The whole table rather than a walk of the LRU: after this the store is
         * indistinguishable from one that has never been used, and memset is the
         * only way to be sure of that -- an unlink that missed one entry would
         * leave a `used` slot that no list refers to, which is a slot an insert
         * can find and a sweep can never reach. */
        memset(s->dedup_tab, 0, IRC_DEDUP_TABLE_BYTES);
    }
    s->dedup_head = NULL;
    s->dedup_tail = NULL;
    s->dedup_used = 0u;
    /* Zero rather than left alone, so the first sweep after a reset is not
     * throttled by an interval the pre-reset store had not earned. */
    s->dedup_swept_ms = 0u;
}

size_t fed_dedup_size(const struct server *s)
{
    return (s == NULL) ? 0u : (size_t)s->dedup_used;
}
