/* dedup.h -- the 2.4 per-node (origin, epoch, id) duplicate store.
 *
 * Authority: docs/SERVER_DESIGN.md 2.4 ("Loop prevention and dedup"), and the
 * part of 3.4 that says the tick is what drives time.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS IS, IN ONE SENTENCE
 * ---------------------------------------------------------------------------
 * A fixed-capacity table of the messages this NODE has already been sent, so
 * that a message arriving a second time is dropped rather than re-delivered and
 * re-forwarded.
 *
 * ---------------------------------------------------------------------------
 * PER NODE, NOT PER PEER -- the part that is easy to get backwards
 * ---------------------------------------------------------------------------
 * 2.4 fixes the scope, and the reason is the only thing that makes the store
 * worth having. A per-PEER table remembers "peer P sent me id 7" and would let
 * the very same message through from peer Q; in the 3+ node mesh 3.1 specifies,
 * where a node relays onward from P to Q, that is the normal path and not an
 * edge case. The key is therefore (origin, epoch, id) with no peer in it, and
 * the origin is the node that FIRST created the message rather than the node
 * this one heard it from.
 *
 * ---------------------------------------------------------------------------
 * DEDUP IS A STATEMENT ABOUT THE WIRE, NOT ABOUT WHETHER WE HANDLED IT
 * ---------------------------------------------------------------------------
 * This is the one rule a caller has to internalise, and it is why
 * fed_dedup_seen() RECORDS a key on the first call rather than recording it
 * after the message has been dealt with. A peer is not obliged to be correct:
 * nothing stops a buggy or hostile node from sending the same id twice, once
 * well-formed and once not, and a store that recorded only successfully-handled
 * messages would take the second one as new and act on it. Recording on sight
 * means a message is known to the wire exactly once whatever happens to it
 * afterwards -- a malformed body, a hop count past the ceiling, a target that
 * resolves to nothing -- which is the only reading under which the key means
 * anything.
 *
 * The consequence, which is a feature and not a leak of state: a message dropped
 * for being malformed is still remembered, so the peer cannot retry the same line
 * under a new id and be believed either. Retry with a NEW id is a different
 * message, and 2.4's epoch exists precisely so that a node that has been
 * restarted is told to use different ids.
 *
 * ---------------------------------------------------------------------------
 * THE CLOCK IS A PARAMETER, NOT A CALL
 * ---------------------------------------------------------------------------
 * 3.4 says the poll tick drives time, and every timeout on this node hangs off
 * the tick's stamp rather than reading a clock itself. That is why now_ms is
 * handed in: this module has no idea when it is running, which also means its
 * expiry behaviour is a pure function of its arguments and can be tested at a
 * chosen instant rather than by waiting for one to pass.
 *
 * ---------------------------------------------------------------------------
 * SELF-CONTAINED ON PURPOSE
 * ---------------------------------------------------------------------------
 * This file depends on core/message.h for the 2.4 tag struct and on nothing
 * else in the tree -- not on core/server.h (the store it fills is reached
 * through a `struct server *` and the definition lives in core/server.h, so the
 * include graph runs this way on purpose), and not on any other file under
 * federation/. The dedup rule and the S-verb encoder are independent decisions:
 * 2.4's loop prevention does not care what a message says, and an encoder that
 * had to be compiled to test the store would make the store's tests depend on
 * the wire format's stability.
 */
#ifndef IRC_FEDERATION_DEDUP_H
#define IRC_FEDERATION_DEDUP_H

#include <stddef.h>
#include <stdint.h>

#include "core/message.h"

/* Forward declaration only, and `struct server` rather than the `server_t`
 * typedef on purpose. Repeating the typedef here would be legal C11 and would
 * be reported anyway: -Wtypedef-redefinition is in upstream clang's
 * -Weverything, and it fires the moment a translation unit includes this header
 * before core/server.h -- which dedup.c itself has to do, since it needs the
 * struct's definition. Declaring the tag is enough for the four prototypes, and
 * core/server.h supplies the spelling every implementation uses. */
struct server;

/* ---------------------------------------------------------------------------
 * Sizing
 * ---------------------------------------------------------------------------
 * All three are DERIVED and the derivation is written out, because a capacity
 * picked and a capacity computed are different kinds of claim.
 */

/* Slots in the table. It is a power of two, which is not an aesthetic choice:
 * the probe sequence is `h & (IRC_DEDUP_MAX - 1)`, so a non-power-of-two table
 * needs a modulo per probe step on the message path, and the ONLY reason to take
 * that is to save a handful of slots.
 *
 * 4096 is derived from the two bounds this node already has:
 *   - the table is a fixed allocation of about 416 KiB
 *     (IRC_DEDUP_TABLE_BYTES, which is IRC_DEDUP_MAX slots of
 *     IRC_DEDUP_ENTRY_BYTES), a real cost paid only by a node that has actually
 *     been sent a relayed message, because the allocation is made on the first
 *     insert rather than in server_init().
 *   - what it has to hold is bounded by the mesh, and 3.1's full mesh means a
 *     node can receive at most (peers) * (hops) copies of any one message before
 *     2.4's ceiling stops it. With the hop ceiling at IRC_MAX_HOPS and a peer
 *     count in the tens, 4096 is two orders of magnitude more than the duplicates
 *     a node sees -- so reaching it means a peer is replaying ids, not that a
 *     busy node is near the end.
 *
 * The cost of picking it too LOW is not a refusal but an eviction, and that is
 * the property fed_dedup_seen() documents and test_fed_dedup.c checks. */
#define IRC_DEDUP_MAX 4096

/* How long a message id is remembered. Long enough to outlive any legitimate
 * re-arrival by a wide margin, short enough to bound what the store holds:
 *
 * A message's second copy arrives either because it was relayed twice on a path
 * that should have deduplicated at an earlier node, or because the network
 * duplicated it. Neither has anything to do with elapsed time, so the TTL is not
 * there to bound those -- 2.4's hop ceiling and never-forward-own-origin are,
 * and the store is the third line of defence, not the first. What the TTL does
 * bound is the store's FOOTPRINT: a node that relays for months would otherwise
 * remember every message it has ever been sent, and the table would evict live
 * entries at the same rate it filled.
 *
 * The number is the one the Phase 6 plan fixed (30 s), written here as the
 * value rather than derived from anything, because there is nothing in this
 * codebase to derive it from and an invented justification would be worse than
 * an admitted choice. The requirement it does satisfy is checkable: it must
 * exceed the time a message can take to traverse a mesh this size, which is
 * bounded by IRC_MAX_HOPS forwarding decisions, and no forward here waits on
 * anything. */
#define IRC_DEDUP_TTL_MS 30000

/* How often the expiry pass is allowed to walk the store. A pass is O(expired)
 * because the LRU is ordered by last-seen and expired entries are a suffix of
 * it, but the pass is not free and it does not need to be prompt: a second of
 * extra residency is a second of extra bytes in a table that is 416 KiB.
 *
 * 5 s is IRC_DEDUP_TTL_MS / 6, written that way rather than as the number so
 * the relationship survives a change to the TTL. The requirement is only that a
 * store is swept several times over its own residency window, so a single
 * forgotten entry cannot pin a slot until the next full pass. */
#define IRC_DEDUP_SWEEP_MS (IRC_DEDUP_TTL_MS / 6u)

/* ---------------------------------------------------------------------------
 * The entry, and the table
 * ---------------------------------------------------------------------------
 * Bytes in one entry, DERIVED from the layout written out below and asserted by
 * tests/integration/test_fed_dedup.c. It is a named number because the 416 KiB
 * figure is quoted in a cost argument, and a cost argument whose input can drift
 * silently is worse than no cost argument. */
#define IRC_DEDUP_ENTRY_BYTES 104u

/* The one remembered message. Laid out so the struct is exactly
 * IRC_DEDUP_ENTRY_BYTES, and asserted by tests/integration/test_fed_dedup.c
 * rather than by a _Static_assert, for a reason that is worth recording:
 * -Wpre-c11-compat is in upstream clang's -Weverything and objects to
 * _Static_assert, and the project's answer to a diagnostic it cannot satisfy
 * without narrowing the warning set is never to narrow it (see the warning
 * block in the top-level CMakeLists.txt, and test_util.h for the same argument
 * about _Noreturn). A size that no compiler is allowed to check is a size that
 * only a comment can check, so it is a size a TEST checks.
 *
 * The layout is therefore written out as arithmetic rather than left implicit:
 *
 *   2 pointers (lru)          16
 *   epoch, id, seen_ms        24    three uint64_t
 *   origin[64]                64    IRC_MAX_SERVER_NAME + 1
 *                              ---
 *                              104   == IRC_DEDUP_ENTRY_BYTES
 *
 * OCCUPANCY IS `origin[0] != '\0'`, not a flag field, and the reason is the
 * arithmetic: the three identity fields and the LRU links come to 40 bytes and
 * the origin to 64, which is 104 exactly with nothing left over. A `used` field
 * would push the entry to 112 and the table from 416 KiB to 448 KiB, for a bit
 * of state that is already implied.
 *
 * It IS implied, safely: message.h's grammar for irc-serve-origin is 1..63
 * bytes, so an empty origin is not a legal value, and fed_dedup_seen() refuses
 * one before it can reach the table. calloc leaves every slot's origin empty, so
 * a freshly allocated table is entirely free with no initialisation pass, and a
 * freed slot's first byte is overwritten the moment it is reused. */
typedef struct fed_dedup_entry {
    /* Intrusive doubly linked, most recently seen at the head. The order is by
     * last-seen rather than by insertion, which is what makes the sweep a suffix
     * walk: touching an entry moves it, and an entry nobody has touched for a
     * TTL is at the tail whether it arrived first or last. */
    struct fed_dedup_entry *lru_prev;
    struct fed_dedup_entry *lru_next;
    uint64_t epoch;
    uint64_t id;
    uint64_t seen_ms;
    char     origin[IRC_MAX_SERVER_NAME + 1];
} fed_dedup_entry_t;

/* The table's whole size, computed from the entry rather than written as the
 * 416 KiB, so that a field added above changes this number instead of quietly
 * invalidating the figure in the block above. This is the value the allocation
 * in fed_dedup_seen() asks for. */
#define IRC_DEDUP_TABLE_BYTES ((size_t)IRC_DEDUP_MAX * sizeof(fed_dedup_entry_t))

/* ---------------------------------------------------------------------------
 * The four entry points
 * ---------------------------------------------------------------------------
 * `struct server` rather than a pointer to the store, because the store is part
 * of the node: it is allocated, grown and torn down with the rest of server_t
 * and there is no lifecycle in which a node holds a store that server_shutdown()
 * does not release. The struct is named rather than typedef'd here so that
 * including this header BEFORE core/server.h does not redefine a typedef, which
 * -Wtypedef-redefinition reports under -Weverything.
 */

/* Has this exact (origin, epoch, id) been seen on this node before?
 *
 * Returns 1 when it has -- the message is a duplicate and must be dropped --
 * and 0 when it has not, having recorded it. The 1/0 sense is the one that
 * makes the call site safe to write as `if (fed_dedup_seen(...)) { drop; }`:
 * the drop is the thing that happens, and it is the branch a reader expects.
 *
 * Recording happens on the 0 path, BEFORE the caller has done anything with the
 * message. See the header for why.
 *
 * Two refusals, both reported as 1 because both mean "do not act on this":
 *   - `s`, `t` NULL, or `t` failing irc_serve_tags_valid(). An origin that is
 *     not a legal irc-serve-origin value cannot be a member of the key space,
 *     and the right answer to a malformed key is the same as the answer to a
 *     known one.
 *   - the table could not be allocated. Failing CLOSED is the point: a dropped
 *     message is one lost message, whereas a store that silently did not record
 *     is a loop that runs until the hop ceiling stops it, at which point the
 *     mesh is spending all its bandwidth on one message. A node that cannot
 *     allocate 416 KiB has larger problems than one message, and refusing the
 *     message is the one of them it can survive.
 */
int fed_dedup_seen(struct server *s, const irc_serve_tags_t *t,
                   uint64_t now_ms);

/* Drop every entry last seen at least IRC_DEDUP_TTL_MS before now_ms. Returns
 * how many were dropped.
 *
 * Called from fed_dedup_seen() only when the store is more than half full, and
 * by the tick when Phase 6's fed_tick() exists; either way the IRC_DEDUP_SWEEP_MS
 * throttle below applies, so calling it on every tick costs one comparison.
 *
 * The throttle is inside this function rather than at the call sites because
 * there are two call sites and the reason to not-sweep is a property of the
 * store's age, not of the caller. */
size_t fed_dedup_sweep(struct server *s, uint64_t now_ms);

/* Forget everything. The allocation is KEPT, so a store that is reset and
 * refilled costs no allocation and -- which is the reason this exists rather
 * than being a free -- the sweep throttle restarts from zero rather than waiting
 * out whatever interval the pre-reset store happened to be in.
 *
 * Nothing in the shipped node calls this yet. It is here with the other three
 * because a test that exercises the store has to be able to start from a known
 * state without a shutdown, and a function added later is a function the
 * existing tests would not have covered. */
void fed_dedup_reset(struct server *s);

/* Entries currently held. 0 on a node that has never been sent a relayed
 * message, which is every node in this commit. */
size_t fed_dedup_size(const struct server *s);

#endif /* IRC_FEDERATION_DEDUP_H */
