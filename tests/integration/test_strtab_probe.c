/* test_strtab_probe.c -- the registries' open-addressed table, and the probe
 * chains deletion used to break.
 *
 * docs/SERVER_DESIGN.md 2.1 (nicknames are per-SERVER keys) and 2.2 (the channel
 * key space). Both registries are served by one open-addressed, linearly-probed
 * string table in core/server.c, and the table is file-private -- nothing outside
 * server.c needs to know how a nickname is stored. So this file drives the
 * behaviour through the two registries that use it, which is where the defect
 * actually reached a user.
 *
 * ---------------------------------------------------------------------------
 * THE DEFECT (issue #107)
 * ---------------------------------------------------------------------------
 * strtab_remove_at() used to set used = 0 and stop. In a linearly-probed table an
 * empty slot is not an absence, it is a WALL: strtab_probe() walks forward from a
 * key's home bucket and stops at the first unused slot, so every key that probed
 * PAST the cleared slot became unreachable while still being held.
 *
 * Reproduced against the shipped library: `u4x` and `u79x` both hash to bucket
 * 14. Claim both, release `u4x`, and lookup("u79x") returns NULL while the name
 * is still held. PRIVMSG and WHOIS then answer 401 for a connected, registered
 * user, and a second client can claim the same name while the first is still
 * listed in 353 -- WHO walks the ENUMERATION and never consults the table for
 * the name, which is why this survived the wire tests and why the user-visible
 * symptom is bigger than the defect.
 *
 * ---------------------------------------------------------------------------
 * WHY THESE NAMES, AND WHY THE TEST CHECKS ITS OWN PREMISE
 * ---------------------------------------------------------------------------
 * The interesting cases are COLLISIONS, and a test that merely claims a list of
 * nicknames cannot tell whether they collided: if a future change to the hash or
 * to STRTAB_BUCKETS moved them apart, the assertions below would still pass and
 * would be checking nothing. So the two hand-picked cases name the pair from the
 * issue, and then ASSERT that the table's own FNV-1a really does send both to the
 * same bucket. The hash is reimplemented here for that one purpose. If the table's
 * hash ever changes, this test fails and says so rather than quietly ceasing to
 * test anything -- which is the failure mode a collision-dependent test has, and
 * the reason it is called out in #107's note about the registry being reached
 * only indirectly.
 *
 * That check cannot cover the bulk case, so the bulk case does not depend on it:
 * the sweeps below claim a whole table's worth of names and release them one at
 * a time, asserting after every release that every name still held resolves. Any
 * collision anywhere in the table fails the test, so those blocks keep their
 * teeth whether or not any particular pair of names happens to share a bucket.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS AND IS NOT THE SAME STRUCTURE
 * ---------------------------------------------------------------------------
 * The audit #107 asks for, answered here rather than in prose:
 *
 *   nicks      the folded strtab, through server_nick_claim/release/lookup and
 *              server_nick_unclaim (the owner-keyed deletion).
 *   chans      the SAME strtab type, exact rather than folded, through
 *              server_chan_add/remove/lookup. It had the identical defect,
 *              because the defect is in the table and not in the registry that
 *              uses it.
 *   chan_objs  NOT a hash table. It is an ORDER-PRESERVING VECTOR of chan_t*, and
 *              server_chan_detach() removes from it with a memmove and no
 *              probing at all, so it cannot have this defect. It was checked
 *              because #107 names it, and the answer is that the channel index
 *              pair (strtab + vector) is correct for the same reason the nick one
 *              is: the table keeps the invariant and the vector keeps creation
 *              order, and each is written in one place.
 *   nick_objs  likewise a vector; already asserted in test_nick_index.c.
 *
 * The conns here are made by conn_new() and never registered in by_fd, so
 * server_shutdown() does not own them and each is freed by hand -- the discipline
 * test_registries.c and test_nick_index.c already use.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/channel.h"
#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"
#include "harness/test_util.h"

/* How many names the bulk sweeps hold at once, and how many releases each makes.
 *
 * 384 is not arbitrary and it is not a round number chosen for looks: it is the
 * smallest round figure at which this name shape reliably puts names SOMEWHERE
 * OTHER THAN THEIR OWN HOME BUCKET, which is the precondition for a hole being
 * able to wall anything off. A release can only hide a name that has been
 * DISPLACED, so a sweep whose names all sit in their home buckets passes against
 * a table that never shifted anything -- which is exactly what the 160-name
 * version of this sweep did, and the reason it is worth writing down here. 384 of
 * 1024 buckets leaves roughly fifty displaced names, so the sweeps below fail
 * against an unshifted table on the FIRST release and with a wide margin. */
#define SWEEP_N 384u

/* The pair from the issue, plus the rest of bucket 14's family: every one of
 * these hashes to bucket 14, so claiming them in order lays a chain down buckets
 * 14, 15, 16, 17, 18 and a release of the FIRST one used to wall off the other
 * five. */
static const char *const CHAIN14[] = {
    "u4x", "u79x", "u905x", "u1414x", "u2275x", "u3041x"
};
#define CHAIN14_LEN ((size_t)(sizeof CHAIN14 / sizeof CHAIN14[0]))

/* Two names in the LAST bucket, two in the FIRST: the shift walks forward and
 * wraps, and a rule that got the wrap wrong would pass every case above and fail
 * only here. */
static const char *const WRAP[] = {
    "u939x", "u1701x",   /* bucket 1023 */
    "u1931x", "u2714x"   /* bucket 0    */
};
#define WRAP_LEN ((size_t)(sizeof WRAP / sizeof WRAP[0]))

/* ---------------------------------------------------------------------------
 * The table's own hash, reimplemented for the premise check and nothing else.
 *
 * This is a copy of strtab_hash() in core/server.c and of the STRTAB_BUCKETS it
 * divides by. Both are file-private, so a collision-dependent test cannot ask the
 * table where a name lands. The duplication is confined to the function below and
 * to the two assertions that use it, and it is checked against the table's
 * behaviour rather than trusted -- see check_collides(). Do NOT grow this into a
 * general-purpose reimplementation: if a future change needs the table's hash for
 * something, the right answer is a test-visible accessor, not another copy. */
static size_t premise_bucket(const char *key)
{
    uint64_t h = 1469598103934665603ull;
    size_t i;

    for (i = 0; key[i] != '\0'; i++) {
        h ^= (uint64_t)(unsigned char)key[i];
        h *= 1099511628211ull;
    }
    return (size_t)(h % 1024u);
}

/* Do `b` and `c` really land in one bucket? Asserted rather than assumed, so that
 * a hash or bucket-count change makes this test FAIL instead of quietly ceasing
 * to exercise a collision. */
static void check_collides(const char *b, const char *c)
{
    size_t bb = premise_bucket(b);
    size_t cb = premise_bucket(c);

    TF_CHECK_MSG(bb == cb,
                 "'%s' hashes to bucket %zu and '%s' to %zu, so this case no "
                 "longer tests a collision: the table's hash or its bucket count "
                 "changed, and the names chosen for this case have to be "
                 "re-picked against it or the assertions below prove nothing",
                 b, bb, c, cb);
}

static conn_t *make_conn(int fd, const char *nick)
{
    conn_t *c = conn_new(fd, CONN_CLIENT);

    TF_CHECK(c != NULL);
    if (nick != NULL) {
        memcpy(c->nick, nick, strlen(nick) + 1u);
    }
    return c;
}

/* ---------------------------------------------------------------------------
 * A name of the bulk sweep's shape: distinct, and a legal nickname (it begins
 * with a letter, and carries no sigil, colon, semicolon or space, so
 * server_nick_claim()'s valid_nick() gate accepts it). Built into `out`, which
 * holds IRC_MAX_NICK + 1 bytes. */
static void sweep_nick(char *out, size_t n)
{
    int n_written = snprintf(out, IRC_MAX_NICK + 1u, "sw%04u", (unsigned)n);

    TF_CHECK(n_written > 0 && (size_t)n_written < IRC_MAX_NICK + 1u);
}

/* --- the two registries, driven the way a caller drives them --- */

/* Claim every name in `names`, release the FIRST one, and require the rest to
 * still resolve. `conn_for` gives each name its own connection, so releasing one
 * is a release by a user who holds nothing else -- the ordinary QUIT path. */
static void sweep_release_first(server_t *s, const char *const *names,
                                size_t len, const char *what)
{
    conn_t **conns = (conn_t **)calloc(len, sizeof *conns);
    size_t i;

    TF_CHECK(conns != NULL);
    for (i = 0; i < len; i++) {
        conns[i] = make_conn((int)(200 + (int)i), names[i]);
        TF_CHECK_MSG(server_nick_claim(s, names[i], conns[i]) == 0,
                     "%s: the claim of '%s' failed", what, names[i]);
    }
    for (i = 0; i < len; i++) {
        TF_CHECK_MSG(server_nick_lookup(s, names[i]) == conns[i],
                     "%s: '%s' did not resolve before any release", what,
                     names[i]);
    }

    server_nick_release(s, names[0]);
    TF_CHECK_MSG(server_nick_lookup(s, names[0]) == NULL,
                 "%s: the released name is still in the table", what);
    for (i = 1; i < len; i++) {
        TF_CHECK_MSG(server_nick_lookup(s, names[i]) == conns[i],
                     "%s: releasing '%s' made '%s' unreachable while it was "
                     "still held -- deletion left a hole in the probe chain "
                     "instead of shifting the rest back over it",
                     what, names[0], names[i]);
    }

    for (i = 1; i < len; i++) {
        server_nick_release(s, names[i]);
    }
    for (i = 0; i < len; i++) {
        conn_free(conns[i]);
    }
    free(conns);
}

/* The bulk sweep. Claim SWEEP_N names, each to its own connection, then release
 * them ONE AT A TIME and immediately re-claim them, asserting after every release
 * that every name still held resolves to the connection that holds it and that
 * the enumeration agrees.
 *
 * ---------------------------------------------------------------------------
 * WHY THE RE-CLAIM IS THE POINT, AND NOT A DETAIL
 * ---------------------------------------------------------------------------
 * The first version of this sweep released the names in ascending index order and
 * passed against the UNFIXED table. It was not wrong about anything; it simply
 * never produced a hole that mattered. The names happen to land so that, at every
 * point in the table where one name sits immediately behind another with a
 * different home bucket, the name at the LOWER slot has the HIGHER index -- so
 * ascending order always released the one at the far end of the cluster first, and
 * the one behind the hole had already gone.
 *
 * Keeping the table FULL removes the dependence on the order entirely. Every
 * release then opens a hole with the rest of the cluster still live behind it, so
 * any cluster anywhere in the table is caught on the first pass that touches it --
 * which is why this block needs no particular pair of names to collide, and why
 * it keeps its teeth if the table's hash or bucket count changes. The cost is one
 * extra claim per iteration; 160 x 160 lookups is a few milliseconds.
 *
 * The names are of a shape the table accepts: they begin with a letter and carry
 * no sigil, colon, semicolon or space, so server_nick_claim()'s valid_nick() gate
 * takes them. */
static void sweep_bulk(server_t *s)
{
    char (*names)[IRC_MAX_NICK + 1] =
        (char (*)[IRC_MAX_NICK + 1])calloc(SWEEP_N, IRC_MAX_NICK + 1u);
    conn_t **conns = (conn_t **)calloc(SWEEP_N, sizeof *conns);
    int *held = (int *)calloc(SWEEP_N, sizeof *held);
    size_t i;
    size_t r;
    size_t live = 0;

    TF_CHECK(names != NULL && conns != NULL && held != NULL);
    for (i = 0; i < SWEEP_N; i++) {
        sweep_nick(names[i], i);
        conns[i] = make_conn((int)(400 + (int)i), names[i]);
        TF_CHECK_MSG(server_nick_claim(s, names[i], conns[i]) == 0,
                     "the claim of '%s' failed", names[i]);
        held[i] = 1;
        live++;
    }
    TF_CHECK_MSG(server_nick_count(s) == live,
                 "%zu names are held but the enumeration lists %zu", live,
                 server_nick_count(s));

    for (r = 0; r < SWEEP_N; r++) {
        size_t victim = r;
        size_t k;

        server_nick_release(s, names[victim]);
        held[victim] = 0;
        live--;

        for (k = 0; k < SWEEP_N; k++) {
            if (!held[k]) {
                continue;
            }
            TF_CHECK_MSG(server_nick_lookup(s, names[k]) == conns[k],
                         "after releasing '%s' (%zu releases in), '%s' no longer "
                         "resolves although it is still held: the deletion left "
                         "a hole in its probe chain",
                         names[victim], r + 1u, names[k]);
        }
        /* The enumeration is the other half of the index, and it is what WHO
         * walks. A name the table cannot find is a user this node would answer
         * 401 for while still listing in 353, so the two are checked against each
         * other after every release rather than only at the end. */
        TF_CHECK_MSG(server_nick_count(s) == live,
                     "after releasing '%s' the enumeration holds %zu entries "
                     "for %zu held names",
                     names[victim], server_nick_count(s), live);

        TF_CHECK_MSG(server_nick_claim(s, names[victim], conns[victim]) == 0,
                     "'%s' could not be re-claimed: the table did not accept the "
                     "name back into the gap it had just opened",
                     names[victim]);
        held[victim] = 1;
        live++;
    }

    /* Drain it, and require an index that has been through this many removals to
     * be in the same state as a fresh one. */
    for (i = 0; i < SWEEP_N; i++) {
        server_nick_release(s, names[i]);
    }
    TF_CHECK_MSG(server_nick_count(s) == 0,
                 "the sweep left %zu entries enumerated", server_nick_count(s));
    for (i = 0; i < SWEEP_N; i++) {
        TF_CHECK_MSG(server_nick_lookup(s, names[i]) == NULL,
                     "'%s' is still in the table after the sweep released it",
                     names[i]);
        TF_CHECK_MSG(server_nick_claim(s, names[i], conns[i]) == 0,
                     "'%s' could not be claimed again after the sweep: the "
                     "table did not return to a fresh state",
                     names[i]);
    }

    for (i = 0; i < SWEEP_N; i++) {
        server_nick_release(s, names[i]);
        conn_free(conns[i]);
    }
    free(names);
    free(conns);
    free(held);
}

/* The channel registry is the SAME table, exact rather than folded, reached
 * through a different pair of accessors. It had the identical defect for the
 * identical reason, and nothing else in the suite would have said so.
 *
 * This drives the VALUE pair -- server_chan_attach()/server_chan_detach() -- and
 * not the Phase 2 key-space pair, for two reasons. The key-space pair
 * (server_chan_add/remove) never touches chan_objs at all, so the count assertion
 * below would be checking a vector that pair does not maintain; and the value pair
 * is the one the command handlers use, so a hole in the table would show up as a
 * JOIN that resolves to NULL. Checking both halves against each other after every
 * removal is the point: the strtab has to keep the invariant, the vector has to
 * keep creation order, and they are written in one place each. */
static void channel_sweep(server_t *s)
{
    char (*names)[64] = (char (*)[64])calloc(SWEEP_N, 64u);
    chan_t **chans = (chan_t **)calloc(SWEEP_N, sizeof *chans);
    int *present = (int *)calloc(SWEEP_N, sizeof *present);
    size_t i;
    size_t r;
    size_t live = 0;

    TF_CHECK(names != NULL && chans != NULL && present != NULL);
    for (i = 0; i < SWEEP_N; i++) {
        int n_written = snprintf(names[i], 64u, "#sw%04u", (unsigned)i);

        TF_CHECK(n_written > 0 && (size_t)n_written < 64u);
        chans[i] = chan_new(names[i], s->name, s->epoch);
        TF_CHECK_MSG(chans[i] != NULL, "chan_new failed for '%s'", names[i]);
        TF_CHECK_MSG(server_chan_attach(s, chans[i]) == 0,
                     "attaching channel '%s' failed", names[i]);
        present[i] = 1;
        live++;
    }

    for (r = 0; r < SWEEP_N; r++) {
        size_t victim = r;
        size_t k;

        server_chan_detach(s, names[victim]);
        present[victim] = 0;
        live--;

        TF_CHECK_MSG(server_chan_get(s, names[victim]) == NULL,
                     "the detached channel '%s' is still in the registry",
                     names[victim]);
        for (k = 0; k < SWEEP_N; k++) {
            if (!present[k]) {
                continue;
            }
            TF_CHECK_MSG(server_chan_get(s, names[k]) == chans[k],
                         "after detaching '%s' (%zu detachments in), '%s' is no "
                         "longer findable although it is still attached: the "
                         "channel registry is the same table and had the same "
                         "defect",
                         names[victim], r + 1u, names[k]);
        }
        /* LIST walks the ordered vector, so this is the same cross-check the
         * nick enumeration gets: the key index and the value index have to agree
         * after every removal, not only at the end. */
        TF_CHECK_MSG(server_chan_count(s) == live,
                     "after detaching '%s' the channel index holds %zu entries "
                     "for %zu attached channels",
                     names[victim], server_chan_count(s), live);

        /* Re-attach immediately, for the reason sweep_bulk() gives: keeping the
         * registry full is what makes every detachment produce a hole with live
         * channels behind it, so this block does not depend on the detachment
         * order lining up with the hash. */
        TF_CHECK_MSG(server_chan_attach(s, chans[victim]) == 0,
                     "'%s' could not be re-attached: the registry did not accept "
                     "the channel back into the gap it had just opened",
                     names[victim]);
        present[victim] = 1;
        live++;
    }

    for (i = 0; i < SWEEP_N; i++) {
        server_chan_detach(s, names[i]);
    }
    TF_CHECK_MSG(server_chan_count(s) == 0,
                 "the channel sweep left %zu entries", server_chan_count(s));
    for (i = 0; i < SWEEP_N; i++) {
        TF_CHECK_MSG(server_chan_get(s, names[i]) == NULL,
                     "'%s' is still in the channel registry after the sweep",
                     names[i]);
        TF_CHECK_MSG(server_chan_attach(s, chans[i]) == 0,
                     "'%s' could not be attached again after the sweep",
                     names[i]);
        server_chan_detach(s, names[i]);
        chan_free(chans[i]);
    }

    free(names);
    free(chans);
    free(present);
}

/* ---------------------------------------------------------------------------
 * The OWNER-keyed deletion, which is a different entry point into the same
 * removal and so needs its own case: server_nick_unclaim() -> strtab_del_owner().
 *
 * It is the path every disconnect takes, and it differs from server_nick_release()
 * in a way the shift makes load-bearing rather than cosmetic: it removes a whole
 * connection's names in one call, and a shift can move an entry from a slot the
 * scan has already passed back into the slot it just cleared. A single forward
 * pass therefore misses any name shifted into the gap it is standing in, and
 * that is a name belonging to the connection being retired -- a table entry
 * pointing at a conn_t that is about to be freed, which is issue #102's shape
 * reached by a different route.
 * --------------------------------------------------------------------------- */
static void owner_delete_sweep(server_t *s)
{
    conn_t *a;
    conn_t *b;
    conn_t *c;
    conn_t *d;
    size_t i;
    size_t live;

    check_collides(CHAIN14[0], CHAIN14[1]);
    a = make_conn(600, CHAIN14[0]);
    b = make_conn(601, CHAIN14[1]);
    c = make_conn(602, CHAIN14[2]);
    d = make_conn(603, CHAIN14[3]);

    /* Every name is homed on bucket 14, so this lays a four-deep chain, and a
     * teardown of the connection at the FRONT of it is the case that shifts
     * three entries backwards. */
    TF_CHECK_MSG(server_nick_claim(s, CHAIN14[0], a) == 0, "claim a failed");
    TF_CHECK_MSG(server_nick_claim(s, CHAIN14[1], b) == 0, "claim b failed");
    TF_CHECK_MSG(server_nick_claim(s, CHAIN14[2], c) == 0, "claim c failed");
    TF_CHECK_MSG(server_nick_claim(s, CHAIN14[3], d) == 0, "claim d failed");

    /* a gives up the first name and holds the second: two names, both in the
     * chain, and the shift walks over both. */
    TF_CHECK_MSG(server_nick_claim(s, CHAIN14[4], a) == 0,
                 "the second name for a was refused");
    live = 4u;

    server_nick_unclaim(s, a);
    TF_CHECK_MSG(server_nick_lookup(s, CHAIN14[0]) == NULL &&
                     server_nick_lookup(s, CHAIN14[4]) == NULL,
                 "retiring a connection left one of its names in the table: a "
                 "message to that name resolves to a connection that is gone");
    TF_CHECK_MSG(server_nick_lookup(s, CHAIN14[1]) == b &&
                     server_nick_lookup(s, CHAIN14[2]) == c &&
                     server_nick_lookup(s, CHAIN14[3]) == d,
                 "retiring a connection made another holder's name unreachable: "
                 "the shift over the retired connection's names lost part of the "
                 "chain");
    TF_CHECK_MSG(server_nick_count(s) == 3,
                 "after retiring a two-name connection the enumeration holds %zu "
                 "entries, expected 3", server_nick_count(s));

    /* And the survivors are genuinely usable: claimable-after-release, which is
     * what a reconnecting client does. */
    for (i = 0; i < live; i++) {
        server_nick_release(s, CHAIN14[1 + (long)i]);
    }
    TF_CHECK_MSG(server_nick_count(s) == 0,
                 "the enumeration is not empty after every surviving name was "
                 "released: %zu entries remain", server_nick_count(s));
    for (i = 0; i < live; i++) {
        TF_CHECK_MSG(server_nick_claim(s, CHAIN14[1 + (long)i], b) == 0,
                     "'%s' was not claimable again after the chain was "
                     "drained", CHAIN14[1 + (long)i]);
    }
    for (i = 0; i < live; i++) {
        server_nick_release(s, CHAIN14[1 + (long)i]);
    }

    conn_free(a);
    conn_free(b);
    conn_free(c);
    conn_free(d);
}

int main(void)
{
    server_t s;

    TF_CHECK_MSG(server_init(&s, "irc.test") == 0, "server_init failed");

    /* --- the reproduction from the issue, premise checked --- */
    check_collides("u4x", "u79x");
    TF_CHECK_MSG(premise_bucket(CHAIN14[0]) == 14u,
                 "'%s' no longer hashes to bucket 14 (it is now bucket %zu): the "
                 "collision cases in this file were chosen against bucket 14 and "
                 "have to be re-picked if the table's hash or bucket count moves",
                 CHAIN14[0], premise_bucket(CHAIN14[0]));
    {
        size_t i;
        conn_t *first;
        conn_t *second;

        for (i = 0; i < CHAIN14_LEN; i++) {
            check_collides(CHAIN14[0], CHAIN14[i]);
        }
        first = make_conn(700, CHAIN14[0]);
        second = make_conn(701, CHAIN14[1]);
        TF_CHECK_MSG(server_nick_claim(&s, CHAIN14[0], first) == 0,
                     "claiming '%s' failed", CHAIN14[0]);
        TF_CHECK_MSG(server_nick_claim(&s, CHAIN14[1], second) == 0,
                     "claiming '%s' failed", CHAIN14[1]);

        server_nick_release(&s, CHAIN14[0]);
        TF_CHECK_MSG(server_nick_lookup(&s, CHAIN14[0]) == NULL,
                     "the released name is still in the table");
        /* THE assertion. `u79x` is still held by a connected connection, and
         * answering NULL here is what turned into 401 on a wire a user could
         * see. */
        TF_CHECK_MSG(server_nick_lookup(&s, CHAIN14[1]) == second,
                     "'%s' is held by a connected connection but lookup returns "
                     "NULL: releasing '%s' broke the probe chain. PRIVMSG and "
                     "WHOIS answer 401 for a registered user because of this, "
                     "and a second client can claim the same name while the "
                     "first is still in 353",
                     CHAIN14[1], CHAIN14[0]);
        /* The fold is the table's property and survives the shift: the entry
         * moved buckets, so a differently-cased spelling has to keep finding
         * it. */
        TF_CHECK_MSG(server_nick_lookup(&s, "U79X") == second,
                     "'U79X' does not find the shifted entry: the shift moved "
                     "the stored key somewhere its own probe no longer reaches");
        /* And the name is not claimable, which is the other half of the
         * user-visible damage. */
        TF_CHECK_MSG(server_nick_claim(&s, CHAIN14[1], first) != 0,
                     "'%s' was claimable while a connection still held it",
                     CHAIN14[1]);

        server_nick_release(&s, CHAIN14[1]);
        conn_free(first);
        conn_free(second);
    }

    /* --- the whole of bucket 14's family, and the wrap --- */
    sweep_release_first(&s, CHAIN14, CHAIN14_LEN, "bucket-14 chain");
    check_collides(WRAP[0], WRAP[1]);
    check_collides(WRAP[2], WRAP[3]);
    sweep_release_first(&s, WRAP, WRAP_LEN, "wrapping chain");

    /* --- the bulk sweeps --- */
    sweep_bulk(&s);
    channel_sweep(&s);
    owner_delete_sweep(&s);

    server_shutdown(&s);
    tf_done("strtab_probe");
    return 0;
}
