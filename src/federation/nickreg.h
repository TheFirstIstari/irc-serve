/* nickreg.h -- 2.1's remote-nick registry: which server holds the user called X.
 *
 * Authority: docs/SERVER_DESIGN.md 2.1 (identity is a scoped nick, `nick@server`
 * splits at the LAST '@', and "qualify() belongs to the phase that first has a
 * remote user to name"), 3.1 (the last row: "remote user nick@server | either |
 * forward to that server"), 4.3.1 (SBURSTN carries nick/user/host/modes/signon/
 * away, and SBURSTM carries the server that HOLDS the member), 2.4 (every
 * relayed line is a fact about an origin, and a resync replaces rather than
 * merges), and 8 ("network-visible nick ambiguity resolved by rename-the-loser
 * plus a nick-registry broadcast").
 *
 * ---------------------------------------------------------------------------
 * WHY THIS EXISTS AT ALL, AND WHAT IT WAS DEFERRED FOR
 * ---------------------------------------------------------------------------
 * SBURSTN has carried six fields since Phase 6 and the receiver has kept TWO of
 * them. The four it discarded -- `user`, `modes`, `signon`, `away` -- were
 * discarded ON PURPOSE, and the reason is written down in three places that all
 * say the same thing: those fields exist for a COMPLETE nick record, the thing
 * that needs one is this registry, and building it in Phase 6 would have been
 * Phase 9's design decision taken without the rest of Phase 9. 4.3.1 says a
 * reader who finds them discarded "should read this paragraph, not infer an
 * oversight", and this file is the other half of that deferral being paid.
 *
 * 2.1's own words for the gap: a client can name `nick@server` and the node can
 * forward it to that server's link, but it cannot tell whether that server HOLDS
 * the nick, cannot render the user for a WHOIS, and has no way to notice that two
 * servers hold the same name. fanout.h's FANOUT_REMOTE_USER enumerator is
 * documented as "a row deliberately not implemented" and 3.1's last row is
 * documented as "routed but not resolved". This is the resolution.
 *
 * ---------------------------------------------------------------------------
 * WHAT IT IS NOT
 * ---------------------------------------------------------------------------
 * It is NOT a second source of truth for WHO a user is, and the distinction is
 * load-bearing. A LOCAL nickname lives in server_t::nicks, which is the
 * authority, and a connection owns it. An entry HERE is a CACHE of what some
 * other server last reported, and the two are never reconciled against each other
 * -- doing so would be a second authority for identity, which is the exact thing
 * 2.2's single-writer rule exists to prevent, one level up.
 *
 * IT IS NOT PERSISTENT and it does not survive a restart, for the same reason
 * the topic cache does not (2.2: "the cache is heap memory" and 3.4 forbids a
 * write inside the event loop). A restarted node has an empty registry until its
 * peers burst again, and a `nick@server` message sent in that window is a message
 * the node cannot confirm. The cost is stated rather than hidden: it is one lost
 * message, not a loop, and the alternative is a new on-disk artifact.
 *
 * IT IS NOT A SUBSCRIPTION. Nothing here causes a message to be sent, and an
 * entry's existence is not a claim that the entry is still true -- the TTL below
 * is the only thing bounding that, and 2.4's resync is what corrects it.
 *
 * ---------------------------------------------------------------------------
 * THE KEY IS (nick, server) AND THE FOLD IS ASCII
 * ---------------------------------------------------------------------------
 * A duplicate nickname across servers is a LEGAL state, not a collision: 2.1
 * says `bob@a` and `bob@b` are distinct registry keys, and that is what makes a
 * rename-the-loser policy a POLICY rather than a data-integrity problem. So the
 * key is the PAIR and the table holds both, and the only thing a duplicate
 * produces is a decision made elsewhere (nickreg_resolve_conflict below).
 *
 * The fold is ASCII case-insensitive for both halves, which is 2.1's rule for a
 * nickname and 2.4's rule for a server name -- and it is the FOURTH copy of that
 * fold in this tree after server.c's same_server_name(), channel.c's same_name()
 * and dedup.c's fold_byte(). It is a copy rather than a share for the reason those
 * three give: each is private to a module whose key rule is its own, and a fifth
 * exported fold would be a fifth place able to get it subtly wrong -- a Unicode
 * fold, say, in a node that advertises CASEMAPPING=ascii in 005.
 */
#ifndef IRC_FEDERATION_NICKREG_H
#define IRC_FEDERATION_NICKREG_H

#include <stddef.h>
#include <stdint.h>

#include "core/server.h"
/* For IRC_FED_DEAD_MS, which the TTL below is derived from. federation/link.h
 * includes core/server.h, so this is not a cycle; and a derived constant reading
 * a constant from the module that owns the liveness rule is the same arrangement
 * dedup.h's TTL has. */
#include "federation/link.h"

/* ---------------------------------------------------------------------------
 * The bound, and the one number with no derivation
 * ---------------------------------------------------------------------------
 * IRC_FED_MAX_PEERS is 2.3's link-table capacity, and it is a DERIVED bound
 * rather than a peak: this registry is fed by what peers REPORT, so the number of
 * entries is a function of the mesh's size and not of this node's load, and the
 * only number in the tree that bounds it is how many peers a node links to.
 *
 * THE MULTIPLIER IS 16 AND IT IS A CONVENTION, admitted in the same place
 * IRC_FED_DEAD_MS's multiplier of 3 is: there is nothing in a cache to derive a
 * "how many users per peer" figure from. What the multiplier BUYS is stated so a
 * reader can judge it: a peer holding more than sixteen distinct users is already
 * describing a mesh this node relays rather than serves, and at 16 peers this
 * bounds the table at 256 entries.
 *
 * THE COST, in bytes, because a bound with no size is a bound with no cost: one
 * entry is nick (64) + server (64) + user (64) + host (128) + signon (8) +
 * seen_ms (8) = 336 bytes, so the table is 86 KiB when full. That is a THIRD of
 * the dedup table's 416 KiB and is allocated LAZILY -- NULL until the first
 * learned nick, which is never on a node with no peers and is why a single-node
 * deployment pays nothing at all.
 *
 * OVERFLOW IS AN EVICTION AND A COUNT, never a refusal, for the reason 2.2 gives
 * about the topic cache: "the cache can therefore only fail to help; it never
 * refuses a client command." The evicted entry is the LEAST RECENTLY SEEN, and
 * `n_rnick_evicted` records it -- a real loss, and a finding rather than a
 * statistic, because a node whose counter climbs is a node being told about more
 * remote users than it will remember. */
#define IRC_FED_MAX_REMOTE_NICKS ((size_t)(IRC_FED_MAX_PEERS * 16u))

/* How long a learned entry is believed without being refreshed.
 *
 * DERIVED as a multiple of IRC_FED_DEAD_MS rather than as a fresh number: an
 * entry is written when a peer reports a nick, and the question "is that peer
 * still there" is a LIVENESS question, which is exactly what IRC_FED_DEAD_MS
 * measures. Ten dead thresholds is about five minutes at the shipped keepalive,
 * and the multiple is the part with no derivation -- like the 3 in
 * IRC_FED_DEAD_MS, it is a number nobody can derive and everybody argues about.
 *
 * WHY IT IS NEEDED AT ALL, and the answer is a liveness event rather than a
 * tidiness one: 2.2's fail-closed rule and 2.4's replace-never-merge both mean
 * the authoritative correction for a departed server is a SQUIT, and a link that
 * goes down WITHOUT a SQUIT (which is the ordinary case -- see 8's note that a
 * link going down is not a server departing) leaves this node holding entries
 * about a peer it can no longer reach. The TTL is what stops those from
 * accumulating. */
#define IRC_FED_RNICK_TTL_MS ((uint64_t)(10u * IRC_FED_DEAD_MS))

/* The maximum suffix appended when a local user is renamed out of a duplicate's
 * way, and the number of attempts.
 *
 * DERIVED rather than picked in the way that matters: CHAN_MAX_NAME (63) and
 * IRC_MAX_NICK (63) are the same width, so a suffixed nick that overflows
 * IRC_MAX_NICK is a nick the node cannot render in a hostmask, and the
 * candidate is built into a buffer of IRC_MAX_NICK + 1 so the refusal is a
 * length check rather than a truncation. The COUNT is 8, and it is a convention:
 * eight people called `bob`, `bob_`, `bob__` ... on one node is a mesh problem
 * rather than a naming collision, and a loop with no ceiling is a loop a peer can
 * hold a node in. */
#define IRC_FED_RNICK_SUFFIX_MAX 8

/* ---------------------------------------------------------------------------
 * The entry, and the four entry points
 * ---------------------------------------------------------------------------
 * `struct server` rather than a pointer to the table, for the reason dedup.h
 * gives: the table is part of the node, and there is no lifecycle in which a node
 * holds a registry that a teardown does not release. server_t carries the vector
 * as an OPAQUE pointer (see the forward declaration there), so the geometry of a
 * table stays this module's business rather than becoming a fourth thing every
 * reader of server_t has to understand.
 *
 * LEARN, AND WHY IT IS NOT "PUT". A learned entry is a claim by another server
 * about one of its own users, and the two halves of it are not equally
 * trustworthy: the nick and the host come from SBURSTN, whose prefix names the
 * server, and `user`, `signon` and `away` are the fields Phase 6 kept on the wire
 * for exactly this. A repeat of the same (nick, server) REFRESHES the existing
 * entry rather than adding a second one, which is what makes the table a map and
 * not a log -- and it moves the entry to the recent end, which is what makes
 * eviction least-recently-seen.
 *
 * `server` MAY BE EMPTY, meaning "reported by a peer whose holder this node has
 * not been told", which is the ordinary case for a live SJOIN: 4.3's SJOIN carries
 * no server field, so the SENDING LINK is the only answer there is. It is a
 * normal answer and not a defect, and it is why nickreg_holder() below is asked
 * which server it wants rather than being handed one. */
void fed_nickreg_learn(server_t *s, const char *nick, const char *server,
                        const char *user, const char *host, uint64_t signon,
                        uint64_t now_ms);

/* Learn a nick FROM A ROSTER rather than from SBURSTN: the nick belongs to
 * `member_server`, and the holder is the fact 4.3.1's SBURSTM field exists to
 * carry. A member_server of NULL or "" falls back to the burst origin, which on a
 * two-node mesh and for a self-hosted member is the same string.
 *
 * IT EXISTS SEPARATELY rather than as a flag on fed_nickreg_learn() because the
 * two calls carry DIFFERENT amounts of trust and merging them would let a caller
 * pass an unverified holder through the path the burst's own records take. The
 * roster path is a refinement of what SBURSTN said -- same nick, better server --
 * so it must not be able to introduce a nick that was never reported. */
void fed_nickreg_learn_member(server_t *s, const char *nick,
                              const char *burst_origin,
                              const char *member_server, uint64_t now_ms);

/* Forget one (nick, server) pair -- a PART, a nick change, a member gone. The
 * server argument is the HOLDER, and passing NULL forgets every entry for that
 * nick on every server, which is what a nick that is no longer anywhere on the
 * mesh needs. */
void fed_nickreg_forget(server_t *s, const char *nick, const char *server);

/* Rekey the (nick, server) entry to (new_nick, server). `server` is the HOLDER and
 * does not change: a rename changes what a server calls one of its own users, and
 * a rename never moves a user between servers. Returns 1 when an entry was
 * rekeyed, 0 when there was none, -1 when `new_nick` is not a legal nickname or
 * is already held by that server under another name.
 *
 * IT IS A RENAME AND NOT forget()-THEN-learn(), and the difference is the LRU
 * order: forget-then-learn lands the entry at the recent end, which is correct
 * for a RE-LEARN but wrong for a rename -- the entry is the same age it was, and
 * re-stamping it would let a rename extend the life of a claim about a user this
 * node has not heard from since. The rename keeps `last_seen_ms` and only moves
 * the entry to the recent end, which is what "least recently SEEN" means: the
 * most recent fact about this user is that their name changed, and the fact is
 * about the same user.
 *
 * A -1 on a name already held is a refusal rather than a merge, for the same
 * reason 2.1's duplicate policy exists: two entries for one user under one
 * nickname is the ambiguity being resolved, and a rename that created one would
 * reintroduce the problem it was called to fix. */
int fed_nickreg_rename(server_t *s, const char *server, const char *old_nick,
                       const char *new_nick, uint64_t now_ms);

/* Forget EVERY entry for a server, and the server's name from every entry that
 * held it elsewhere. The caller is a SQUIT: 4.3's departure announcement means
 * that server's users are gone, and 2.4's per-origin purge has an exact
 * counterpart here. */
void fed_nickreg_purge_server(server_t *s, const char *server);

/* Drop every entry last learned at least IRC_FED_RNICK_TTL_MS before now_ms.
 * Returns how many were dropped.
 *
 * Called from fed_tick() and NOT from every write, for the reason
 * fed_dedup_sweep()'s own throttle gives: the time half of "is a sweep due" is
 * inside the function that owns the store's age rather than at its call sites,
 * because the property being tested is the store's and not the caller's. The
 * throttle is IRC_FED_RNICK_TTL_MS / 16, which keeps a sweep to one per ~19 s at
 * the shipped numbers while still expiring an entry within a sixth of its TTL of
 * its real expiry. */
size_t fed_nickreg_sweep(server_t *s, uint64_t now_ms);

/* Entries currently held. 0 on a node that has never been told about a remote
 * user, which is every node with no peers and every single-node deployment -- and
 * which is why the whole table is lazily allocated rather than built in
 * server_init(). */
size_t fed_nickreg_count(const server_t *s);

/* Free the table. THE TEARDOWN ARM, and it is an ARM rather than a plain free
 * because the table is a heap vector whose owner is this module while the pointer
 * that holds it is server_t -- the same arrangement as 4.3's resync shadow and for
 * the same reason. A single node that has been sent a burst and then stopped
 * would otherwise hand 86 KiB to the kernel, and LeakSanitizer runs only on the
 * Linux CI job, so the free is invisible locally and real there.
 *
 * IT IS CALLED FROM server_shutdown() next to the other federation arms, and it
 * prints whether the table was OPEN -- i.e. whether it held anything -- so a test
 * can assert the arm RAN on a platform whose LSan cannot check it. The same
 * argument server.h makes about fed_burst_close(). */
void fed_nickreg_close(server_t *s);

/* ---------------------------------------------------------------------------
 * Resolution, and the rename-the-loser decision
 * ---------------------------------------------------------------------------
 */

/* Which server holds `nick`, or NULL when this node has not been told. `out` is
 * at least IRC_MAX_SERVER_NAME + 1 bytes.
 *
 * THE AMBIGUOUS CASE IS NOT AN ERROR, and it is the whole reason this function
 * exists: a nick held by TWO servers is a legal state, so the answer here is the
 * one that the rename policy below will make the loser. `*ambiguous_out`, when
 * not NULL, is set to 1 for that case, and a caller that does not care (a router
 * asking "where do I forward this") takes the first holder it finds -- because
 * for FORWARDING the choice does not matter: the message reaches one of the two
 * holders, and only a rename makes the other one reachable. */
const char *fed_nickreg_holder(const server_t *s, const char *nick, char *out,
                               size_t cap, int *ambiguous_out);

/* The one rendering a remote user can be given, or NULL when there is nothing to
 * render. Returns `nick!user@host` and a final `+i`/`+w` when the away text is
 * known, which is the shape 311 and 301 both want.
 *
 * THE AWAY TEXT IS NOT STORED, and that is a stated limit rather than an
 * oversight: `away` is char[CONN_MAX_AWAY] (256), and storing it on every entry
 * would take the table from 86 KiB to 200 KiB for a field nothing renders yet
 * (there is no remote WHOIS in this build, so 311 for a remote user is a
 * separate piece of work). The capability is what Phase 6 was right to put on the
 * wire: the field is there for the implementation that does render it, and its
 * absence here is a cost that was weighed, not an oversight. */
const char *fed_nickreg_render(const server_t *s, const char *nick,
                               const char *server, char *out, size_t cap);

/* THE RENAME-THE-LOSER DECISION, and it is a function rather than a rule in
 * commands.c because the DECISION and the ACT of renaming have to be in one
 * place: the winner is chosen by a comparison both sides of the mesh can make,
 * and a rule written at the claim site and a rule written at the report site
 * would be two rules.
 *
 * `local` is the server holding the nick on THIS node and `remote` the one
 * reporting it. Returns 1 when the LOCAL holder must be renamed -- that is,
 * when `remote` WINS the comparison -- and 0 otherwise.
 *
 * THE COMPARISON IS LEXICOGRAPHIC ON THE FOLDED SERVER NAME, and the reason is
 * convergence rather than fairness: 2.1's problem is that "bob on two servers is
 * just bob to a user", and a policy whose two nodes DISAGREE about which one keeps
 * the nick is a policy that produces a rename on one side, a rename back on the
 * other, and a pair of users ping-ponging for ever. A total order both nodes can
 * evaluate from the two names alone ends that: the same pair of names always
 * yields the same winner on every node that knows both.
 *
 * IT IS NOT A TIMESTAMP COMPARISON, and the reason is that there is no shared
 * clock. The alternative -- whoever claimed it first wins -- needs the two claims
 * to be ordered, and the only clocks available are each node's own, which
 * disagree. 2.4's epoch is per-boot and is not comparable across nodes, and this
 * is the same reason 2.2's creation-race tie-break is `(epoch, server_name)`
 * rather than `epoch` alone: where a name has to break a tie, it is because the
 * numeric cannot.
 *
 * IT IS NOT RANDOM and not a hash of the nick: a hash would make the winner
 * depend on a value the two servers compute differently, and "random" would make
 * a partition heal differently on each side, which is the failure above with extra
 * steps.
 *
 * THE COST, stated because a policy with no cost is a policy nobody has used: a
 * user can be renamed by a peer they have never spoken to, on the strength of a
 * name that peer happened to report. That is inherent to a mesh that lets two
 * servers report the same nick, and the alternatives are worse -- a policy that
 * does nothing is the "user-visible and undefined" state 2.1 names, and one that
 * lets the node that noticed decide is non-convergent. What this buys is that the
 * rename is rare (it needs an actual duplicate), deterministic, and visible on the
 * wire. */
int fed_nickreg_local_loses(const char *local, const char *remote);

/* ---------------------------------------------------------------------------
 * THE ACT, and it is here rather than at any call site
 * ---------------------------------------------------------------------------
 */

/* Apply the policy above to ONE nickname, right now: if the registry says another
 * server holds `nick`, if this node LOSES the comparison, and if a LOCAL user is
 * holding the name, rename that user and tell everybody who can see them.
 * Returns 1 when a local user was renamed, 0 when nothing needed doing.
 *
 * IT IS A FUNCTION AND NOT A RULE IN ITS CALLERS, and the reason is the one that
 * makes the whole feature work: the rename has FIVE effects, and a caller that
 * implemented four of them would produce a mesh that looks renamed and is not.
 * They are:
 *   1. the decision (fed_nickreg_local_loses, the only place the comparison is
 *      written down);
 *   2. a new name, from fed_nickreg_next_name();
 *   3. the LOCAL registry: claim the new name and release the old, in that order,
 *      because the reverse leaves a window in which the old name is unowned and
 *      a second client can take it;
 *   4. the CLIENT: a NICK line to the connection, and a NICK to every channel it
 *      is in, because a rename a user cannot see is a rename the mesh cannot
 *      trust;
 *   5. the MESH: one SNICK to every ESTABLISHED link, once for the whole node --
 *      not once per channel, which would make a peer apply the rename N times.
 *
 * THE CALLER IS A NICK OR A REPORT, and both are needed. commands.c calls it
 * after a client claims a name, which is the case where this node has the
 * registry entry ALREADY. federation/verbs.c and federation/burst.c call it after
 * learning a REMOTE holder, which is the other direction: a user can register
 * `zed` on a node whose registry is empty, and the competing claim arrives
 * afterwards -- on an SJOIN, or on the next burst. A node that only checked at
 * claim time would let that user keep the name for ever, which is the
 * "user-visible and undefined" state 2.1 names and the reason this function has
 * two callers rather than one.
 *
 * IT RENAMES A CONNECTION THIS NODE HOLDS, and nothing else. A remote duplicate
 * is the OTHER node's business -- its own copy of this function decides, from
 * the same two names, that the same user is the loser there. That is why the
 * policy is a comparison and not a message: there is no "you must rename" verb
 * on the wire, because a peer that could send one could rename a user by
 * asserting a claim. */
int fed_nickreg_resolve_local(server_t *s, const char *nick, uint64_t now_ms);

/* Build the next candidate name for a user being renamed out of a duplicate's
 * way: `nick_`, then `nick__`, and so on, up to IRC_FED_RNICK_SUFFIX_MAX
 * candidates. Copies into `out` (at least IRC_MAX_NICK + 1) and returns 0 on
 * success, -1 when every candidate is taken or the longest would not fit.
 *
 * IT IS A PURE FUNCTION OF THE CANDIDATE NAMES, and the caller is responsible for
 * rejecting one that some OTHER server already holds -- a rename that lands on a
 * third duplicate is not a rename, it is a third collision, and the caller
 * re-runs fed_nickreg_local_loses() on the new name.
 *
 * WHY THE SUFFIX AND NOT A COUNTER: `bob_` is a name a user could have typed, so
 * a collision with a real `bob_` is possible and the caller has to check for it;
 * `bob1`, `bob2` are equally typable and additionally make the roster harder to
 * read, because the difference between `bob2` and `bob_` in a 353 is invisible at
 * a glance. The suffix is chosen for legibility, and its cost is the extra check
 * the caller must make. */
int fed_nickreg_next_name(const server_t *s, const char *nick, char *out,
                          size_t cap);

#endif /* IRC_FEDERATION_NICKREG_H */
