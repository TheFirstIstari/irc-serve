/* nickreg.c -- see nickreg.h. 2.1's remote-nick registry, and the rename-the-loser
 * decision that goes with it.
 *
 * ---------------------------------------------------------------------------
 * WHY THE INDEX IS A VECTOR AND NOT A HASH TABLE
 * ---------------------------------------------------------------------------
 * Every other string-keyed index in this node is a strtab: server.c's nicks and
 * chans, and that is the right answer for a registry that can hold a connection
 * PER NAME and whose enumeration is a hot path (WHO walks it).
 *
 * This one is not that. The bound is IRC_FED_MAX_REMOTE_NICKS, which is 256, and
 * a linear scan of 256 POD entries on a path that runs at most once per inbound
 * burst record is a few hundred comparisons -- and a burst is a transaction that
 * is already O(nicks + members) with a staging buffer the size of half a link's
 * write queue. A hash table here would be a second table, a probe function, a
 * growth policy and a second teardown arm, all to turn a comparison that happens
 * inside an O(n) transaction into a comparison that happens once.
 *
 * THE COST, since a costless scan is a claim: a lookup is O(n) in the number of
 * REMOTE users this node has been told about, and the resolution path
 * (fanout_resolve on a `nick@server` target) is O(n) per such message. At the
 * 256-entry bound that is one strcmp-fold over at most 256 entries, and a node
 * large enough for that to be visible would be a node whose mesh has more remote
 * users than its own -- which is a node whose registry is evicting anyway (see
 * n_rnick_evicted) and whose cost is better spent on a bigger bound.
 *
 * ---------------------------------------------------------------------------
 * EVICTION IS LEAST-RECENTLY-SEEN, AND WHY THE ORDER IS AN INDEX NOT A FLAG
 * ---------------------------------------------------------------------------
 * A learn() moves its entry to the END of the vector. That single convention is
 * what makes eviction a scan for the lowest index, what makes the sweep
 * (which drops by AGE) a suffix walk once the vector is ordered by seen_ms, and
 * what makes "most recent" and "last" the same thing without a field saying so.
 * The cost is that a learn() is O(n) rather than O(1) -- a memmove of the tail --
 * and at 256 entries of 336 bytes that is 86 KiB moved, once per inbound nick
 * record, inside a transaction that is already assembling a megabyte on a large
 * node. The honest comparison is against the alternative: an LRU list (dedup.c's
 * arrangement) is O(1) and costs two pointers per entry, so it is strictly better
 * on the write path and strictly worse on nothing. It is not used here because
 * the write path is a burst and a burst's cost is already accounted for
 * elsewhere; a reader who disagrees should reach for the list and the reasoning
 * to change with it, and the comment is here so that the choice is visible rather
 * than inherited.
 */
#include "federation/nickreg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/channel.h"
#include "core/fanout.h"
#include "core/message.h"
#include "core/reply.h"
#include "federation/verbs.h"

/* The bound on the sweep throttle, DERIVED from the TTL rather than picked: a
 * sweep at most every TTL/16 means an entry is dropped within a sixteenth of its
 * real expiry of expiring, and the sweep itself costs one comparison per tick
 * that is not due. */
#define IRC_FED_RNICK_SWEEP_MS (IRC_FED_RNICK_TTL_MS / 16u)

/* One remote user, as some server last reported it.
 *
 * THE LAYOUT IS WRITTEN OUT AS ARITHMETIC rather than left implicit, and it is
 * the same reason dedup.h gives for its entry size: a size that is quoted in a
 * cost argument and not written down is a cost argument whose input can drift
 * silently. The sum is asserted by a TEST rather than by a _Static_assert,
 * because -Wpre-c11-compat is in upstream clang's -Weverything and this project's
 * answer to a diagnostic it cannot satisfy without narrowing the warning set is
 * never to narrow it.
 *
 *   nick[IRC_MAX_NICK + 1]         64
 *   server[IRC_MAX_SERVER_NAME+1]  64
 *   user[64]                       64    (conn_t::user's width; RFC 1459 2.3 caps
 *                                          <username> at 9 characters and nothing
 *                                          in this tree stores more, but the
 *                                          width is the one a report could carry)
 *   host[CHAN_MAX_REMOTE_HOST+1]  128
 *   signon                         8
 *   seen_ms                        8
 *                                  ---
 *                                  336   == IRC_FED_RNICK_ENTRY_BYTES
 *
 * AND IT IS NOT PADDED DELIBERATELY. A `used` flag or an explicit LRU pair would
 * push the entry to 344 or 352 and the table from 86 KiB to 90, and the
 * occupancy is already implied: a freed slot is emptied and a learned one is
 * written whole. The empty-slot marker is `nick[0] == '\0'`, which is
 * unambiguous because 2.1's valid_nick() rejects an empty nickname -- so a zeroed
 * entry is free and a used entry is not, with no field to disagree. */
#define IRC_FED_RNICK_ENTRY_BYTES 336u

struct fed_rnick {
    char     nick[IRC_MAX_NICK + 1];
    char     server[IRC_MAX_SERVER_NAME + 1];
    char     user[IRC_MAX_NICK + 1];
    char     host[CHAN_MAX_REMOTE_HOST + 1];
    uint64_t signon;
    uint64_t seen_ms;
};

/* The ASCII fold, and the FOURTH copy of it in this tree. See the header for why
 * it is a copy rather than a share. Deliberately the narrowest form: one
 * comparison, no table, no branch for a signed char -- and the reason it is that
 * narrow is dedup.c's, which states that 005 has already told every client that
 * []\~ and {}|^ are not equivalent, so folding them here would break that
 * promise in the one place nothing on the wire would show it. */
static char nickreg_fold(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char)(c - ('A' - 'a'));
    }
    return c;
}

/* Two server names, compared as 2.4's grammar says two server names are. The
 * grammar makes them case-insensitive, so this cannot be a strcmp: `IRC.A` and
 * `irc.a` are one server and a registry that stored them as two entries would
 * let a node claim two servers hold a nick when one does. */
static int same_server(const char *a, const char *b)
{
    size_t i;

    if (a == NULL || b == NULL) {
        return 0;
    }
    for (i = 0; a[i] != '\0' && b[i] != '\0'; i++) {
        if (nickreg_fold(a[i]) != nickreg_fold(b[i])) {
            return 0;
        }
    }
    return a[i] == '\0' && b[i] == '\0';
}

/* Two nicknames, compared as 2.1 says two nicknames are: case-insensitively,
 * because a nickname is folded everywhere in this node (server.c's nicks strtab
 * folds) while the case the user chose is what gets DISPLAYED. A registry that
 * compared them exactly would hold `Bob` and `bob` as two remote users. */
static int same_nick(const char *a, const char *b)
{
    size_t i;

    if (a == NULL || b == NULL) {
        return 0;
    }
    for (i = 0; a[i] != '\0' && b[i] != '\0'; i++) {
        if (nickreg_fold(a[i]) != nickreg_fold(b[i])) {
            return 0;
        }
    }
    return a[i] == '\0' && b[i] == '\0';
}

/* A bounded copy: the same rule as channel.c's copy_bounded() -- refuse, never
 * truncate -- for the reason 3.2 gives: a truncated host is a hostmask that is not
 * the one the peer reported. A copy rather than a share because channel.c's is
 * static and a shared helper for two strings is a header dependency this file
 * does not otherwise have. */
static int nickreg_copy(char *dst, size_t cap, const char *src)
{
    size_t n;

    if (dst == NULL || cap == 0u) {
        return 0;
    }
    /* An absent source is an EMPTY value, not a refusal. The three fields a
     * report can legitimately omit are `user` (a relay that only reports a
     * roster), `host` (2.2: an empty host is the normal state for a member
     * learned from a live SJOIN) and `server` (4.3's SJOIN carries no server
     * field). Storing "" is what every reader of these fields already handles --
     * see chan_remote_t's comment on an empty member_server -- and a refusal
     * would throw away the nick, which is the one field the entry exists for. */
    if (src == NULL) {
        dst[0] = '\0';
        return 1;
    }
    n = strlen(src);
    if (n >= cap) {
        dst[0] = '\0';
        return 0;
    }
    memcpy(dst, src, n + 1u);
    return 1;
}

/* Find the entry for (nick, server), or NULL. An EMPTY `server` is a wildcard
 * match rather than an equality test, which is what makes
 * fed_nickreg_forget(s, nick, NULL) able to forget a nick everywhere in one
 * call; the alternative is a second walk in the caller and a second thing to keep
 * in step with the first. */
static struct fed_rnick *nickreg_find(server_t *s, const char *nick,
                                      const char *server)
{
    size_t i;

    if (s == NULL || nick == NULL || s->rnicks == NULL) {
        return NULL;
    }
    /* OVER nrnick_used AND NOT nrnicks, and the difference is a correctness
     * matter rather than a speed one: nrnicks is the ALLOCATED length (see
     * server.h) and the tail of it is calloc-zeroed, so a scan over nrnicks reads
     * 256 entries to find one. The two are equal only when the table is full. */
    for (i = 0; i < s->nrnick_used; i++) {
        struct fed_rnick *e = &s->rnicks[i];

        if (e->nick[0] == '\0') {
            continue; /* free slot */
        }
        if (!same_nick(e->nick, nick)) {
            continue;
        }
        if (server != NULL && server[0] != '\0' && !same_server(e->server, server)) {
            continue;
        }
        return e;
    }
    return NULL;
}

/* Move entry `idx` to the END of the vector, which is what makes the vector
 * ordered least-recently-used first. A memmove rather than a swap: a swap would
 * leave the vector unordered and the eviction scan would have to compare
 * seen_ms across all of them. The cost is O(n) per learn and the benefit is that
 * eviction AND the sweep are both index walks, which the header explains. */
static void nickreg_touch(server_t *s, size_t idx)
{
    struct fed_rnick tmp;

    /* OVER nrnick_used, and the reason is eviction: append() drops index 0 when
     * the table is full, so "the least recently seen" is only index 0 if the
     * vector's LIVE part is ordered. Touching against the allocated length would
     * rotate 200-odd zeroed slots instead of the entries, and the ordering the
     * eviction depends on would never be established at all. */
    if (idx >= s->nrnick_used || (idx + 1u) >= s->nrnick_used) {
        return;
    }
    tmp = s->rnicks[idx];
    memmove(&s->rnicks[idx], &s->rnicks[idx + 1u],
            (s->nrnick_used - idx - 1u) * sizeof *s->rnicks);
    s->rnicks[s->nrnick_used - 1u] = tmp;
}

/* Append a new entry, growing the vector geometrically like every other registry
 * on server_t, and EVICTING the least recently seen when it is at its bound.
 *
 * THE EVICTION IS NOT A REFUSAL, and the reason is 2.2's rule for the topic
 * cache: a cache that can refuse is a cache that can break a client command. A
 * node that has been told about more remote users than it will remember drops
 * the oldest and counts it, because the alternative -- refusing to learn a nick at
 * all -- would make a peer's resync silently incomplete, which is a far worse
 * failure than a forgotten entry that the next resync will supply again. */
static struct fed_rnick *nickreg_append(server_t *s)
{
    if (s->rnicks == NULL) {
        /* LAZILY, and the reason is the cost argument in the header: a node with
         * no peers never learns a remote nick, so allocating 86 KiB at
         * server_init() would be a cost paid by every single-node deployment for
         * a feature none of them can use. This is the same arrangement the dedup
         * table makes and for the same reason. */
        s->rnicks = (struct fed_rnick *)calloc(IRC_FED_MAX_REMOTE_NICKS,
                                               sizeof *s->rnicks);
        if (s->rnicks == NULL) {
            /* A node that cannot allocate the table cannot learn remote nicks,
             * and says so. Failing closed here is right for the same reason
             * fed_dedup_seen() fails closed: a lost nick record is one
             * unresolvable target, where a store that silently did not record is
             * a mesh whose rosters quietly disagree. */
            return NULL;
        }
        s->nrnicks = IRC_FED_MAX_REMOTE_NICKS;
    }
    if (s->nrnick_used >= IRC_FED_MAX_REMOTE_NICKS) {
        /* Oldest first, which the touch() convention makes index 0. The dropped
         * entry is CLEARED rather than merely skipped so a later reuse of the slot
         * cannot inherit a prefix of it.
         *
         * AND THEN THE VECTOR IS COMPACTED, which is the part that makes the
         * append below in-bounds: with the table full, dropping index 0 and
         * appending at index 256 would write one element PAST the calloc, and the
         * only reason that is worth stating is that it is the kind of bug a
         * 256-entry bound makes easy to reach and hard to see. Shifting the tail
         * down by one keeps `nrnick_used` at the bound and the vector dense, at a
         * cost of one memmove that only happens on a table that is already full. */
        memmove(&s->rnicks[0], &s->rnicks[1],
                (IRC_FED_MAX_REMOTE_NICKS - 1u) * sizeof s->rnicks[0]);
        memset(&s->rnicks[IRC_FED_MAX_REMOTE_NICKS - 1u], 0,
               sizeof s->rnicks[0]);
        s->nrnick_used--;
        s->n_rnick_evicted++;
        printf("[observable] fed_nick_evicted: table=%zu bound=%zu\n",
               s->nrnick_used, IRC_FED_MAX_REMOTE_NICKS);
    }
    return &s->rnicks[s->nrnick_used++];
}

/* The shared body of the two learn functions. `server` may be "" and the
 * nick/user/host may be absent; see nickreg.h on which absences are ordinary. */
static void nickreg_learn(server_t *s, const char *nick, const char *server,
                          const char *user, const char *host, uint64_t signon,
                          uint64_t now_ms)
{
    struct fed_rnick *e;
    size_t idx;
    int have;

    if (s == NULL || nick == NULL || nick[0] == '\0' || !valid_nick(nick)) {
        /* 2.1's charset rule is applied HERE rather than trusted, for the reason
         * federation/verbs.c's G9 gives: this is a nickname arriving from a
         * network, and an entry holding one this node could not qualify, compare
         * or render is an entry nothing can use. A malformed nick is counted by
         * the caller's own guard chain as malformed, so this is belt to that
         * braces. */
        return;
    }
    e = nickreg_find(s, nick, server);
    if (e != NULL) {
        idx = (size_t)(e - s->rnicks);
        /* A REPEAT REFRESHES rather than adding, which is what makes this a map
         * and not a log. `server` is deliberately not overwritten when it is
         * empty: an entry that came from a live SJOIN has no holder, and a later
         * report of the same nick with no holder must not erase a holder a burst
         * had already established. */
        if (server != NULL && server[0] != '\0') {
            (void)nickreg_copy(e->server, sizeof e->server, server);
        }
        if (user != NULL && user[0] != '\0') {
            (void)nickreg_copy(e->user, sizeof e->user, user);
        }
        if (host != NULL && host[0] != '\0') {
            (void)nickreg_copy(e->host, sizeof e->host, host);
        }
        /* signon is only overwritten when the report carries one, for the same
         * reason: an absent field is "not told", not "zero", and 0 is a value 2.4
         * would have to be able to express. */
        if (signon != 0u) {
            e->signon = signon;
        }
        e->seen_ms = now_ms;
        nickreg_touch(s, idx);
        return;
    }
    e = nickreg_append(s);
    if (e == NULL) {
        return;
    }
    /* Cleared whole before the copies, so a reused slot cannot keep a field the
     * new report does not carry. This is the reason eviction memsets rather than
     * overwriting only what it knows. */
    memset(e, 0, sizeof *e);
    have = nickreg_copy(e->nick, sizeof e->nick, nick);
    (void)nickreg_copy(e->server, sizeof e->server, server);
    (void)nickreg_copy(e->user, sizeof e->user, user);
    (void)nickreg_copy(e->host, sizeof e->host, host);
    e->signon = signon;
    e->seen_ms = now_ms;
    if (have == 0) {
        /* Unreachable: valid_nick() bounds the nick and the buffer is that same
         * width. Handled rather than asserted because a table entry that was
         * partly written would be an entry nothing can read, and the only way to
         * find that out is a length check. */
        memset(e, 0, sizeof *e);
        s->n_rnick_evicted++;
    }
}

void fed_nickreg_learn(server_t *s, const char *nick, const char *server,
                        const char *user, const char *host, uint64_t signon,
                        uint64_t now_ms)
{
    nickreg_learn(s, nick, server, user, host, signon, now_ms);
}

void fed_nickreg_learn_member(server_t *s, const char *nick,
                              const char *burst_origin,
                              const char *member_server, uint64_t now_ms)
{
    const char *holder = member_server;

    /* THE FALLBACK, and it is the one channel.h's chan_remote_t already makes:
     * an empty member_server means "not told", and the burst origin is the best
     * available answer. On a two-node mesh and for a member the origin hosts
     * itself, the two strings are the same, so the fallback is exact there and an
     * approximation on a larger mesh -- which is the honest limit of a field that
     * 4.3.1 only required to be present. */
    if (holder == NULL || holder[0] == '\0') {
        holder = burst_origin;
    }
    /* The refinement passes the burst origin as the lookup server so a repeat for
     * the SAME origin updates in place rather than adding a second entry -- which
     * is what keeps a resync, which replaces per origin, from leaving a stale
     * entry behind under the old key. A holder that genuinely differs from the
     * origin is a DIFFERENT key and does get its own entry, which is correct: the
     * two names answer different questions (see channel.h on `server` versus
     * `member_server`). */
    nickreg_learn(s, nick, holder, NULL, NULL, 0u, now_ms);
}

void fed_nickreg_forget(server_t *s, const char *nick, const char *server)
{
    size_t i;
    size_t j;

    if (s == NULL || s->rnicks == NULL || nick == NULL) {
        return;
    }
    /* nrnick_used, not nrnicks -- see nickreg_find(). */
    for (i = 0; i < s->nrnick_used; i++) {
        if (s->rnicks[i].nick[0] == '\0' || !same_nick(s->rnicks[i].nick, nick)) {
            continue;
        }
        if (server != NULL && server[0] != '\0' &&
            !same_server(s->rnicks[i].server, server)) {
            continue;
        }
        /* COMPACT rather than clear-and-leave-a-hole, and the reason is the
         * index-based eviction: a hole would mean the least-recently-seen entry is
         * not at index 0, and the eviction would have to scan. Compacting keeps
         * the vector dense and the order intact, and a PART is not a hot path. */
        for (j = i + 1u; j < s->nrnick_used; j++) {
            s->rnicks[j - 1u] = s->rnicks[j];
        }
        s->nrnick_used--;
        memset(&s->rnicks[s->nrnick_used], 0, sizeof s->rnicks[0]);
        if (server == NULL || server[0] == '\0') {
            /* A wildcard forget may have several entries for this nick, and
             * after compacting the next one has moved into `i`, so the loop must
             * re-examine this index rather than advance past it. THE TEST IS
             * `i > 0` AND NOT `i--`: i is a size_t, so an unconditional decrement
             * at i == 0 wraps to SIZE_MAX, the `i < nrnick_used` test passes, and
             * the next iteration indexes the vector at the end of the address
             * space. That is the one place in this file where a loop counter needs
             * a guard rather than an idiom. */
            if (i > 0u) {
                i--;
            }
        }
    }
}

int fed_nickreg_rename(server_t *s, const char *server, const char *old_nick,
                       const char *new_nick, uint64_t now_ms)
{
    size_t i;
    size_t at = s != NULL ? s->nrnick_used : 0u;

    if (s == NULL || s->rnicks == NULL || server == NULL || old_nick == NULL ||
        new_nick == NULL) {
        return 0;
    }
    /* THE NEW NAME IS CHECKED BEFORE THE OLD ONE IS FOUND, and the order is
     * cheap-versus-expensive: a name this node could not be given is refused
     * whether or not the old one is held, and a valid_nick() call per rename
     * costs nothing next to a rejected rename's later consequences. It is checked
     * against the SAME predicate 2.1 uses for a client's NICK, so a rename on the
     * wire cannot put a name on a mesh that a local client would have been
     * refused. */
    if (!valid_nick(new_nick)) {
        return -1;
    }
    if (same_nick(old_nick, new_nick)) {
        /* A rename TO THE SAME NAME is a no-op, and returning 0 for it rather
         * than 1 is what stops a caller from reporting a roster change it did not
         * make. Both names folding equal is the case worth handling, not the byte
         * -equal one: `Bob` and `bob` are the same nickname to 2.1 and a peer
         * that sends both is not asking for a rename. */
        return 0;
    }
    for (i = 0; i < s->nrnick_used; i++) {
        if (s->rnicks[i].nick[0] == '\0' || !same_nick(s->rnicks[i].nick, new_nick)) {
            continue;
        }
        if (!same_server(s->rnicks[i].server, server)) {
            /* HELD BY A DIFFERENT SERVER, and that is NOT a collision: 2.1's
             * duplicate is legal and is resolved by the rename policy, not by
             * refusing the rename. Refusing here would leave the two users
             * holding one name for ever, which is the state the policy exists to
             * end. */
            continue;
        }
        /* HELD BY THE SAME SERVER, which means the server has two of its own
         * users answering to the new name -- impossible in reality and a wire
         * fault if reported, and refused rather than merged because merging would
         * make one of two live users unreachable. */
        return -1;
    }
    for (i = 0; i < s->nrnick_used; i++) {
        if (s->rnicks[i].nick[0] == '\0' || !same_nick(s->rnicks[i].nick, old_nick)) {
            continue;
        }
        if (!same_server(s->rnicks[i].server, server)) {
            continue;
        }
        at = i;
        break;
    }
    if (at == s->nrnick_used) {
        return 0;
    }

    /* THE BOUNDED COPY, through the same helper learn() uses, so a rename cannot
     * produce an entry learn() would have refused -- two entry-creation paths with
     * different bounds is how a table ends up holding a truncated name that no
     * lookup can match. */
    if (!nickreg_copy(s->rnicks[at].nick, sizeof s->rnicks[at].nick, new_nick)) {
        return -1;
    }
    /* THE STAMP MOVES, and the reason is that the most recent fact about this
     * user is now their new name. What does NOT move is `signon`, and the reason
     * is the opposite: a rename is not a reconnection, and a node that gave a
     * renamed user a fresh signon time would make every channel the user is in
     * believe the channel's age restarted, which is what SBURSTM's flags and
     * 2.2's mode timestamps are derived from. */
    s->rnicks[at].seen_ms = now_ms;

    /* TO THE RECENT END, because eviction is index-0-driven and an entry left at
     * its old index would be the next evicted one despite having just been
     * confirmed. The move is a rotate, not a remove-and-append, so the entry's
     * fields are not rebuilt -- in particular `user` and `host` are carried
     * through unchanged, which is the point of a rename over a re-learn. */
    if (at + 1u < s->nrnick_used) {
        struct fed_rnick moved = s->rnicks[at];

        for (i = at + 1u; i < s->nrnick_used; i++) {
            s->rnicks[i - 1u] = s->rnicks[i];
        }
        s->rnicks[s->nrnick_used - 1u] = moved;
    }
    return 1;
}

/* fed_nickreg_resolve_local() -- nickreg.h states the five effects and the three
 * call sites, and what follows is the order they have to happen in. The order is
 * the whole of the correctness argument, so each step says what it is for. */
int fed_nickreg_resolve_local(server_t *s, const char *nick, uint64_t now_ms)
{
    char holder[IRC_MAX_SERVER_NAME + 1];
    char fresh[IRC_MAX_NICK + 1];
    char oldnick[IRC_MAX_NICK + 1];
    conn_t *c;

    if (s == NULL || nick == NULL || nick[0] == '\0' || !valid_nick(nick)) {
        return 0;
    }
    /* THE WINNING REMOTE HOLDER, and it is a SCAN rather than
     * fed_nickreg_holder(). The two ask different questions: holder() is the
     * FORWARDING answer -- "some server that has this nick", where either of two
     * holders is correct and the first one found is as good as the other -- while
     * the policy needs the BEST of the remote holders, because a total order
     * applied to an arbitrary competitor is not the order. With two remote
     * claimants, deciding against whichever the table happened to list first
     * would rename a user on the strength of a competitor that lost, and would
     * decide differently on a node whose table was built in a different order.
     *
     * THE SCAN IS OVER s->rnicks AND NOT fed_nickreg_holder()'s helper, and it is
     * a handful of comparisons against a 256-entry bound: the alternative is an
     * index from nickname to holders, which is a second map to keep in step with
     * this one. */
    {
        int have = 0;

        for (size_t i = 0; i < s->nrnick_used; i++) {
            const struct fed_rnick *e = &s->rnicks[i];

            if (e->nick[0] == '\0' || !same_nick(e->nick, nick)) {
                continue;
            }
            if (e->server[0] == '\0' || chan_same_name(e->server, s->name)) {
                /* This node's own claim, or an entry whose holder was never told
                 * (4.3's SJOIN carries no server field). Neither is a competitor:
                 * an entry with no holder cannot outrank a name, because there is
                 * no name to compare. */
                continue;
            }
            if (!have || fed_nickreg_local_loses(holder, e->server) != 0) {
                /* e->server is the smaller of the two, so it is the new winner. */
                (void)nickreg_copy(holder, sizeof holder, e->server);
                have = 1;
            }
        }
        if (!have) {
            return 0;
        }
    }
    /* THE LOCAL HOLDER IS FOUND BEFORE THE VERDICT IS REACHED, and the order is
     * what keeps the report below meaningful. server_nick_lookup() is the
     * authority for a name this node holds, because server_t::nicks is
     * per-SERVER and this table holds only REMOTE nicks -- so a name this node has
     * no user for is not a duplicate here, it is a user on somebody else's mesh
     * that this function has nothing to decide about.
     *
     * Asking first means the LOCAL_WINS report below fires only for a name a local
     * user actually holds, and a node on a healthy mesh never prints it. The
     * alternative -- deciding first and reporting, then discovering there is no
     * local user -- prints a line for every remote nickname the node has ever
     * heard of, which is a log nobody reads and a report that means nothing. */
    c = server_nick_lookup(s, nick);
    if (c == NULL) {
        /* A REMOTE duplicate this node has no local user for, which is the HALF
         * of the pair that does nothing here: the other node runs this same
         * function against the same two names and renames its own user if it is
         * the loser there. That is the convergence fed_nickreg_local_loses()
         * exists to make possible, and it is why this branch reports nothing --
         * there is no finding, and a line printed on every remote-only duplicate
         * would make the report above unreadable. */
        return 0;
    }
    if (fed_nickreg_local_loses(s->name, holder) == 0) {
        /* THIS NODE WINS, and the fact is REPORTED rather than silently kept, so an
         * operator reading one side's log can see that a duplicate existed and that
         * THIS side was the one told to keep it. Without it "nobody was renamed
         * here" and "every node agreed nobody should be" are the same observation,
         * and a mesh that had resolved the duplicate by BOTH sides renaming would
         * look identical from the renamed side alone.
         *
         * IT IS A LINE AND NOT A COUNTER, and the reason is frequency: this fires
         * only when a local user holds a name a peer also holds, which is a rare
         * and fully-resolved event. A counter an operator has to look up the
         * meaning of is worse than a line nobody has to look for. */
        printf("[observable] nick_duplicate: nick=%s local=%s remote=%s "
               "verdict=LOCAL_WINS\n",
               nick, s->name, holder);
        return 0;
    }
    if (fed_nickreg_next_name(s, nick, fresh, sizeof fresh) != 0) {
        /* EVERY CANDIDATE WAS TAKEN, which is no longer a duplicate-nick problem
         * but an exhausted suffix space. The name is RELEASED rather than kept,
         * because keeping it is exactly the divergence the policy exists to
         * prevent: two servers, one name, no agreement. The user is not
         * disconnected: 2.1 is about which of two users gives way, and dropping
         * the connection would invent a policy about session lifetime that
         * nothing here decided. A released name is what lets the client's next
         * NICK succeed, which is the only recovery a client has. */
        server_nick_release(s, nick);
        (void)reply(s, c, "433", (const char *const[]){ nick }, 1,
                    "Nickname is already in use");
        printf("[observable] nick_reject: fd=%d nick=%s reason=remote_holder "
               "holder=%s detail=NO_FREE_CANDIDATE\n",
               c->fd, nick, holder);
        return 0;
    }

    /* CLAIM BEFORE RELEASE, and this is the order issue #100 established for the
     * local claim path: releasing first leaves a window in which the old name is
     * unowned, and a second client on this node could take it and become a third
     * holder of a name two servers already disagree about. */
    (void)server_nick_claim(s, fresh, c);
    server_nick_release(s, nick);
    /* THE OLD NAME IS COPIED BEFORE c->nick IS OVERWRITTEN, and all four later
     * steps need it: the NICK the client reads, the NICK each channel member
     * reads, the SNICK's two parameters, and the hostmask the peers log. It is
     * copied rather than read from c->nick for the same reason the registry is
     * asked rather than trusted -- `nick` and `c->nick` are the same string
     * folded, and a caller that passed `Bob` must not produce a line that names
     * the client's own spelling. */
    (void)nickreg_copy(oldnick, sizeof oldnick, nick);
    memcpy(c->nick, fresh, strlen(fresh) + 1u);

    /* 1. THE CLIENT, through send_line() and not a fanout: there is exactly one
     * addressee, and 3 makes the reply path the single place that decides where
     * an outbound client message may be written. The prefix is this node's own
     * name rather than the user's old hostmask -- 3.3.1's prefix exists so a
     * receiver can ATTRIBUTE the line, and the receiver here is a connection this
     * node already attributes -- and the observable is the same shape a
     * client-issued rename produces, which is worth more to a reader than the
     * extra bytes. */
    (void)send_line(s, c, NULL, "NICK", (const char *const[]){ fresh }, 1);

    /* 2. THE CHANNELS, through the resolve-then-deliver pair every channel state
     * change already uses, so a rename reaches a channel's clients by the one path
     * that knows how to address them and which of them to skip.
     *
     * IT IS THE LOCAL-ONLY DELIVER and not fanout_deliver(), and the reason is the
     * one fanout.h gives: the mesh is told ONCE, by the single SNICK below, and a
     * per-channel forward would make the number of lines a peer receives a function
     * of how many channels the user happens to be in. */
    for (size_t ci = 0, nch = server_chan_count(s); ci < nch; ci++) {
        chan_t *ch = server_chan_at(s, ci);
        fanout_target_t ct;

        if (ch == NULL || chan_find_member(ch, c) == NULL) {
            continue;
        }
        if (fanout_resolve(s, c, ch->name, FANOUT_STATE_CHANGE, &ct) != 0) {
            (void)fanout_deliver_local(s, &ct, oldnick, "NICK",
                                       (const char *const[]){ fresh }, 1, NULL);
        }
    }

    /* 3. THE MESH, ONCE for the whole node rather than once per channel. A rename
     * is one fact about one user, and a peer receiving it once per shared channel
     * would apply it once per line and count N renames for one user.
     *
     * THE PREFIX IS A HOSTMASK and that is the one thing SNICK needs which the
     * local lines above do not: fed_in_snick() ignores the prefix on receipt -- so
     * a relaying node cannot misattribute the member, which is what 4.3.1's
     * SBURSTM <server> field exists to prevent -- and a hostmask is what a human
     * reading the far side's log has to work with. It is built HERE rather than by
     * conn_hostmask() because that function's only subject is a conn_t and
     * c->nick has already been overwritten; asking it would render the NEW name
     * and produce a line that renames a user from a name its own prefix does not
     * have. The "-" and "*" fallbacks are burst.c's, for the same reason: an
     * unregistered connection has no user and a client may have no host, and
     * 3.2's dash placeholder is what keeps a hostmask with an empty field
     * representable. */
    {
        char mask[CONN_HOSTMASK_MAX];
        const char *nickparams[2];
        const char *user = (c->user[0] != '\0') ? c->user : "-";
        const char *host = (c->host[0] != '\0') ? c->host : "*";

        (void)snprintf(mask, sizeof mask, "%s!%s@%s", oldnick, user, host);
        nickparams[0] = oldnick;
        nickparams[1] = fresh;
        fed_forward_all(s, "SNICK", mask, nickparams, 2);
    }

    (void)now_ms;
    printf("[observable] nick_renamed: fd=%d from=%s to=%s reason=REMOTE_HOLDER "
           "holder=%s\n",
           c->fd, oldnick, fresh, holder);
    return 1;
}

void fed_nickreg_purge_server(server_t *s, const char *server)
{
    size_t i;
    size_t j;

    if (s == NULL || s->rnicks == NULL || server == NULL) {
        return;
    }
    for (i = 0; i < s->nrnick_used; i++) {
        if (s->rnicks[i].nick[0] == '\0' || !same_server(s->rnicks[i].server, server)) {
            continue;
        }
        for (j = i + 1u; j < s->nrnick_used; j++) {
            s->rnicks[j - 1u] = s->rnicks[j];
        }
        s->nrnick_used--;
        memset(&s->rnicks[s->nrnick_used], 0, sizeof s->rnicks[0]);
        i--;
    }
}

size_t fed_nickreg_sweep(server_t *s, uint64_t now_ms)
{
    size_t i;
    size_t dropped = 0;
    uint64_t last = 0;

    if (s == NULL || s->rnicks == NULL) {
        return 0;
    }
    /* The throttle, and it is a comparison on a path that runs EVERY TICK: a node
     * with peers pays one subtraction per 50 ms for a store whose entries live
     * for minutes. 0 means "never swept", which is also the state of a node that
     * has just learned its first nick, so the first sweep is immediate. */
    if (s->nrnick_swept_ms != 0u &&
        (now_ms - s->nrnick_swept_ms) < IRC_FED_RNICK_SWEEP_MS) {
        return 0;
    }
    s->nrnick_swept_ms = now_ms;
    /* A SUFFIX WALK, and the reason it can be one is the touch() convention: the
     * vector is ordered least-recently-USED first, which for a store where
     * "used" means "last learned" is the same order as "least recently SEEN". An
     * entry is expired exactly when every entry after it is, so the walk stops at
     * the first live one rather than examining all of them. */
    for (i = 0; i < s->nrnick_used; i++) {
        struct fed_rnick *e = &s->rnicks[i];

        if (e->nick[0] == '\0') {
            continue;
        }
        if ((now_ms - e->seen_ms) < IRC_FED_RNICK_TTL_MS) {
            break;
        }
        last = e->seen_ms;
        dropped++;
    }
    if (dropped == 0u) {
        return 0;
    }
    /* Shifting the live tail down over the dropped prefix rather than clearing
     * each entry, so a sweep of 200 entries is two memmoves and not 200. */
    for (i = 0; i + dropped < s->nrnick_used; i++) {
        s->rnicks[i] = s->rnicks[i + dropped];
    }
    memset(&s->rnicks[s->nrnick_used - dropped], 0,
           dropped * sizeof s->rnicks[0]);
    s->nrnick_used -= dropped;
    printf("[observable] fed_nick_swept: dropped=%zu ttl_ms=%llu oldest_ms=%llu "
           "left=%zu\n",
           dropped, (unsigned long long)IRC_FED_RNICK_TTL_MS,
           (unsigned long long)last, s->nrnick_used);
    return dropped;
}

size_t fed_nickreg_count(const server_t *s)
{
    if (s == NULL) {
        return 0;
    }
    return s->nrnick_used;
}

void fed_nickreg_close(server_t *s)
{
    size_t held;

    if (s == NULL) {
        return;
    }
    held = s->nrnick_used;
    free(s->rnicks);
    s->rnicks = NULL;
    s->nrnick_used = 0;
    s->nrnick_swept_ms = 0;
    /* WHETHER IT HELD ANYTHING, which is the fact a reader of a node's last line
     * wants and the fact a test can assert on a platform whose LSan cannot check
     * it. Same contract as fed_burst_close(). */
    printf("[observable] fed_nick_close: entries=%s held=%zu\n",
           (held > 0u) ? "OPEN" : "NONE", held);
}

const char *fed_nickreg_holder(const server_t *s, const char *nick, char *out,
                               size_t cap, int *ambiguous_out)
{
    size_t i;
    int found = 0;

    if (ambiguous_out != NULL) {
        *ambiguous_out = 0;
    }
    if (out != NULL && cap > 0u) {
        out[0] = '\0';
    }
    if (s == NULL || s->rnicks == NULL || nick == NULL || out == NULL || cap == 0u) {
        return NULL;
    }
    for (i = 0; i < s->nrnick_used; i++) {
        const struct fed_rnick *e = &s->rnicks[i];

        if (e->nick[0] == '\0' || !same_nick(e->nick, nick)) {
            continue;
        }
        if (found == 0) {
            /* THE FIRST HOLDER IS THE ANSWER and the ambiguity flag is the rest
             * of it. Both are set in ONE pass because a second pass to count the
             * holders would double the cost of a call on the resolution path for
             * an answer most callers do not need -- and the flag is what the
             * rename policy asks for, so it is cheaper to compute it than to
             * leave it out and have a caller walk the table itself. */
            if (nickreg_copy(out, cap, e->server) == 0) {
                return NULL;
            }
            found = 1;
        } else if (!same_server(out, e->server)) {
            if (ambiguous_out != NULL) {
                *ambiguous_out = 1;
            }
            /* Deliberately NOT replacing `out`: the first holder stays the
             * answer for a FORWARDER, and the ambiguity flag is what a caller that
             * needs to resolve the duplicate asks about. Choosing the lexicographic
             * winner here instead would mean a router silently preferring one of
             * two users by an accident of table order. */
        }
    }
    return (found != 0) ? out : NULL;
}

const char *fed_nickreg_render(const server_t *s, const char *nick,
                               const char *server, char *out, size_t cap)
{
    const struct fed_rnick *e;
    size_t n = 0;
    int wrote;

    if (out == NULL || cap == 0u) {
        return NULL;
    }
    out[0] = '\0';
    if (s == NULL || nick == NULL) {
        return NULL;
    }
    e = nickreg_find((server_t *)(uintptr_t)(const void *)s, nick, server);
    if (e == NULL) {
        return NULL;
    }
    /* THE SHAPE IS 2.1's: nick!user@host. It is the only rendering a remote user
     * can be given, and it is assembled by hand rather than through
     * conn_hostmask() because that function takes a conn_t and a remote user has
     * none -- which is the whole reason this function exists. A missing user or
     * host renders as the empty component rather than being refused, because 2.2
     * says an empty host is the NORMAL state for a member learned from a live
     * SJOIN and a renderer that refused would leave the most common entry in the
     * table unrenderable. */
    wrote = snprintf(out, cap, "%s!%s@%s", e->nick, e->user, e->host);
    if (wrote < 0 || (size_t)wrote >= cap) {
        out[0] = '\0';
        return NULL;
    }
    n = (size_t)wrote;
    return (n > 0u) ? out : NULL;
}

int fed_nickreg_local_loses(const char *local, const char *remote)
{
    size_t i;

    if (local == NULL || remote == NULL) {
        return 0;
    }
    /* A REMOTE HOLDER WITH NO NAME cannot win, and the answer is that the local
     * holder keeps the nick. 4.3's SJOIN carries no server field, so an entry
     * learned from one has an empty holder; treating that as a competing claim
     * would let a peer rename a user by sending an SJOIN with no server at all,
     * which is a capability no message in 4.3 is supposed to carry. */
    if (remote[0] == '\0') {
        return 0;
    }
    for (i = 0;; i++) {
        char a = nickreg_fold((local[i] != '\0') ? local[i] : ' ');

        if (local[i] == '\0') {
            /* LOCAL IS A STRICT PREFIX OF REMOTE, so local is the SMALLER name and
             * the rule this function states -- the greater name is renamed -- says
             * the local holder KEEPS it. Returning 1 here would be the opposite of
             * what the one-character-lower loop does for the same pair: for
             * `local = "irc.b"`, `remote = "irc.b1"` the first differing byte says
             * local is smaller and keeps it, so a shorter local name has to keep it
             * too or the order is not a total order and two nodes can disagree
             * about a pair whose names differ only in length.
             *
             * The space is a sentinel that folds above every legal name byte and
             * cannot be confused with a shorter string, which is what makes this
             * loop safe at the terminator. */
            return 0;
        }
        if (remote[i] == '\0') {
            /* Remote is a strict prefix of local, so local is the GREATER name and
             * is renamed -- the mirror of the arm above, and for the same reason:
             * without it `irc.b1` and `irc.b` would resolve the opposite way
             * depending on which is longer, which is precisely the non-convergence
             * this function's whole existence is meant to prevent. */
            return 1;
        }
        if (a != nickreg_fold(remote[i])) {
            return (a > nickreg_fold(remote[i])) ? 1 : 0;
        }
    }
}

int fed_nickreg_next_name(const server_t *s, const char *nick, char *out,
                          size_t cap)
{
    unsigned n;

    if (s == NULL || nick == NULL || out == NULL || cap == 0u) {
        return -1;
    }
    for (n = 1u; n <= (unsigned)IRC_FED_RNICK_SUFFIX_MAX; n++) {
        char candidate[IRC_MAX_NICK + 1];
        int wrote;
        size_t i;

        /* The candidate is built into a buffer of the nick's OWN width and the
         * LENGTH is checked rather than the suffix being dropped, because 2.1
         * says a nickname is IRC_MAX_NICK bytes and a node that stored a longer
         * one could not render it in a hostmask -- the same reason
         * conn_hostmask() sizes its buffer from the struct widths. */
        wrote = snprintf(candidate, sizeof candidate, "%s%.*s", nick, (int)n,
                         "________________");
        if (wrote < 0 || (size_t)wrote >= sizeof candidate) {
            return -1; /* no room even for one suffix: the nick is at the bound */
        }
        /* AND EVERY CANDIDATE IS CHECKED AGAINST THE LOCAL REGISTRY, because a
         * rename that lands on a name somebody else already holds is not a
         * rename, it is a third collision. The caller re-runs
         * fed_nickreg_local_loses() on whatever this returns, which is the
         * check against a REMOTE holder -- this one is against a local one and
         * the two are different tables. */
        for (i = 0; i < s->nrnick_used; i++) {
            if (s->rnicks[i].nick[0] != '\0' && same_nick(s->rnicks[i].nick, candidate)) {
                break;
            }
        }
        if (i < s->nrnick_used) {
            continue;
        }
        /* The LOCAL nick registry is the other thing a candidate can collide
         * with, and it is server_nick_lookup() rather than a walk of this table:
         * a local nickname is held by a conn_t and lives in server_t::nicks, which
         * is the authority for it. A candidate that a local user already holds is
         * not available, and finding that out by asking the registry this file
         * owns would be asking the wrong question. */
        if (server_nick_lookup(s, candidate) != NULL) {
            continue;
        }
        if (nickreg_copy(out, cap, candidate) == 0) {
            return -1;
        }
        return 0;
    }
    return -1;
}
