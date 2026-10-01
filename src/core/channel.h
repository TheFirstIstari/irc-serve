/* channel.h -- chan_t: the origin-owned channel, its members, its mode
 * authority, and the two federation invariants of 2.2 that are single-node
 * testable.
 *
 * Authority: docs/SERVER_DESIGN.md section 2.2 (channels: origin, the local
 * member list, the remote cache, the ownership rules, the single-writer rule,
 * the creation race, and fail-closed on owner death), 2.3 (the peer-link type
 * 2.2's server set is built from), 3.1 (the fan-out rules, which is why the
 * remote cache exists at all), 4.1 (JOIN PART TOPIC NAMES MODE KICK) and
 * 4.4 (the numerics the command handlers in commands.c emit).
 *
 * ---------------------------------------------------------------------------
 * THIS IS THE PHASE THAT LANDS THE FINAL STRUCT SHAPES
 * ---------------------------------------------------------------------------
 * 7/Phase 4: "This phase lands the final struct shapes, not a draft that
 * Phase 6 rewrites: ... remote fields present but unpopulated (servers[], ...)
 * so Phase 6 fills them rather than changing the struct."
 *
 * So every field a federated node will need is here, whether or not anything
 * populates it yet, and Phase 6's job is to fill fields rather than add them.
 * Four of the fields below are not in the 2.2 listing, and each is a case where
 * the listing is a sketch rather than a complete declaration. They are called
 * out individually so a reader can check the reasoning rather than take it on
 * trust:
 *
 *   member.flags       2.2 writes `struct member { conn_t *c; }`. The +o/+v
 *                      flags are what make this phase's OWN acceptance
 *                      criterion -- non-op KICK -> 482 -- implementable, and
 *                      4.4 mandates PREFIX=(ov)@+ in 005, so a member carries
 *                      its prefix or 005 is a lie.
 *   chan.origin_epoch  2.2's tie-break is over (creation_epoch, server_name),
 *                      and the winner's epoch has to be STORED or a later
 *                      comparison has nothing to compare. This is the creating
 *                      server's epoch, and it is renamed to origin_epoch
 *                      because after a re-key it is the epoch of the server
 *                      that currently owns the channel.
 *   chan.servers       2.2 writes `struct server **servers`. See below.
 *   chan.bans          2.2 names +b as a mode the origin evaluates, and a
 *                      mode that is evaluated needs somewhere to keep what it
 *                      evaluates. Without this the ban test could only assert
 *                      that a non-origin REFUSES, never that an origin
 *                      enforces, which is the half with teeth.
 *   chan.created_at    4.4 requires 329, and 329 RPL_CREATIONTIME IS a creation
 *                      timestamp. There is no other value it could carry, and
 *                      reusing topic_when for it would be a numeric that lies
 *                      about what it is.
 *
 * ---------------------------------------------------------------------------
 * WHY servers[] HOLDS SERVER NAMES, NOT POINTERS
 * ---------------------------------------------------------------------------
 * The 2.2 declaration is `struct server **servers`, and neither reading of
 * "server" survives contact with the rest of the design:
 *
 *   server_t*      2.4 calls server_t "the per-SERVER monotonic counter
 *                  owned by server_t" and 3.1's fan-out table routes to
 *                  "peers". server_t is the LOCAL node -- there is exactly one
 *                  per process -- so an array of server_t* inside a channel
 *                  would list the same single pointer once per channel. It is
 *                  a type error, not a choice.
 *
 *   server_link_t* 2.3's peer link, and the only type in the design that
 *                  denotes "a server this node is connected to". It is still
 *                  the wrong shape here, for a reason that is about lifetime
 *                  rather than about types: 2.2 says "Re-linking a server of the
 *                  same name resurrects the channel", and a channel that holds
 *                  a pointer cannot be resurrected by a re-link, because the
 *                  pointer dangles the moment the old link is torn down. Every
 *                  link teardown would then have to walk every channel on the
 *                  node to invalidate it -- a coupling Phase 4 should not
 *                  impose on Phase 6, and one whose failure mode is a
 *                  use-after-free on the first peer flap rather than a wrong
 *                  answer.
 *
 * So servers[] holds the server NAME, in a one-field struct that mirrors
 * server_link_t's own `char name[64]`. Three things follow, and they are why
 * this is the shape rather than merely an acceptable one:
 *
 *   - The name is the identity the design already compares: the tie-break in
 *     2.2 is on server_name.
 *   - A name survives a link flap, so "re-linking the same name resurrects the
 *     channel" is a property of the data rather than of a teardown path.
 *   - Resolving a name to a link is a lookup the node has to do anyway at
 *     forward time (3.1: "forward to every peer in servers[]"), and it is the
 *     SAME lookup that answers "can this node reach the origin?" -- see
 *     chan_origin_state() below. A pointer would have pre-resolved the first
 *     and dangled on the second.
 *
 * Nothing Phase 6 has to do to this array requires changing chan_t: it appends
 * a name when a peer reports a member, drops one when the last member behind
 * it goes away, and resolves names to links at forward time.
 *
 * ---------------------------------------------------------------------------
 * LOCALLY ORPHANED IS DERIVED, NEVER STORED
 * ---------------------------------------------------------------------------
 * 2.2's fail-closed rule is "With no ESTABLISHED link to the origin the channel
 * is locally orphaned: local members still see each other, but
 * origin-requiring actions are refused with 437."
 *
 * That is a question about the node's CURRENT link state, so it is answered by
 * a function, chan_origin_state(), and not by a flag on chan_t. The trade is
 * explicit, because a stored flag is genuinely cheaper:
 *
 *   stored flag        one byte, no lookup. But its only honest writer is
 *                      every link state transition, and link transitions are
 *                      Phase 6's. In Phase 4 such a flag would have NO writer
 *                      at all, so it would ship permanently FALSE -- a field
 *                      whose only statement is a lie. Once Phase 6 adds
 *                      writers, a missed transition makes it permanently
 *                      WRONG, and wrong here is not a cosmetic bug: it either
 *                      refuses actions that were legal or applies changes that
 *                      the single-writer rule exists to prevent.
 *   derived            one lookup, and no cache to invalidate, so it cannot be
 *                      stale. The lookup is short-circuited on the common
 *                      case, because origin == self returns before any table
 *                      is touched -- and on a single node that is the only
 *                      case there is.
 *
 * The lookup is not a placeholder for something that becomes true in Phase 6:
 * it consults the connection registry, which already holds a peer's identity
 * in conn_t::peer_name and is already populated by Phase 2's dial FSM. So the
 * predicate is correct today, and Phase 6 narrows it to consult the handshake
 * FSM's ESTABLISHED state (a link that exists but has not finished
 * handshaking is not a route) without chan_t changing.
 *
 * Re-election is NOT here. 2.2 and 9 both put it out of scope, and 9 says why
 * it is dangerous: it needs a per-channel epoch in the dedup key, which breaks
 * 2.4's (origin, epoch, id). Nothing in this file approaches it, and origin is
 * written exactly once by chan_new() and then only by chan_rekey() -- which is
 * the creation-race re-key, not a re-election.
 */
#ifndef IRC_CORE_CHANNEL_H
#define IRC_CORE_CHANNEL_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "core/connection.h"
#include "core/server.h"

/* ---------------------------------------------------------------------------
 * Widths, all derived from a struct the design fixes elsewhere rather than
 * invented, so a bound cannot drift from the storage it protects.
 * ------------------------------------------------------------------------- */

/* chan_t::name is char[64] in 2.2. The value bound is one less than the field,
 * which is the same relationship IRC_MAX_NICK has to conn_t::nick in 2.1. */
#define CHAN_MAX_NAME 63

/* 2.2: topic[256], topic_who[64]. */
#define CHAN_MAX_TOPIC    255
#define CHAN_MAX_TOPIC_WHO 63

/* 2.2: modes[32]. The bound is a capacity, not a protocol limit: a channel with
 * more distinct mode letters than this cannot record them, which is reported
 * rather than silently truncated (3.2's rule, applied to internal state). */
#define CHAN_MAX_MODES 31

/* 2.3: server_link_t::name is char[64], so a server name is at most this. */
#define CHAN_MAX_SERVER 63

/* RFC 1459 2.3.1 gives a channel ban mask 64 bytes, and a mask longer than
 * that cannot be expressed in the MODE that sets it. */
#define CHAN_MAX_BAN 63

/* The remote cache is O(servers), and the origin is the only writer, so these
 * are reached by a peer protocol message rather than by a client. They exist so
 * that neither a peer nor a bug can make the loop allocate without bound. */
#define CHAN_MAX_MEMBER_SERVERS 64

/* Bans ARE client-driven (MODE #c +b mask), so this bound is reached by
 * ordinary input and CHAN_MAX_BANS is a real limit rather than a formality. */
#define CHAN_MAX_BANS 64

/* Entries in the REMOTE roster below. It is filled by peer protocol, so it is
 * bounded for the same reason CHAN_MAX_MEMBER_SERVERS is: a node that trusts a
 * peer's report must not be able to make the loop allocate without bound.
 *
 * 64 is IRC_MAX_NICK-relevant rather than derived from anything in this file:
 * it is the same figure as the per-SERVER nick space this node already bounds
 * every other walk by, and the cost is 64 * sizeof(chan_remote_t) per channel of
 * ADDRESSED array, of which only the used prefix is ever touched. The number is
 * WRITTEN as sizeof() rather than as the literal it used to be (64 * 136 = 8.5
 * KiB) because chan_remote_t has since grown TWICE -- a `host` in Phase 6 C4 and
 * a `member_server` in C5 -- and the literal did not grow with it: the figure was
 * correct when the struct was 136 bytes and would have been wrong the day it was
 * not, which is the failure a written-out product invites. Both additions took
 * the same three properties the `host` note below gives (nothing serialises this
 * struct, the array grows in whole elements, everything addresses it by name), so
 * neither needed a bound change beyond sizeof. The alternative -- sizing it from
 * CHAN_MAX_MEMBERS, the local bound -- would be a 256-entry array on every
 * channel for a mesh this size, and the local bound is a different question (how
 * many CLIENTS this node serves) from this one (how many members a remote server
 * has told us about). */
#define CHAN_MAX_REMOTE_MEMBERS 64

/* conn_t::host is char[128], and the bound is one less than the field -- the
 * same relationship CHAN_MAX_NAME has to chan_t::name. Written as the struct
 * width rather than as a literal for the reason CHAN_MAX_REMOTE_MEMBERS no
 * longer writes one out: a bound that is a copy of a field cannot fall behind
 * it. A member of this roster and a member of channels[].members[] describe the
 * same person, and this is the width a 2.1 hostmask would render the remote one
 * at. */
#define CHAN_MAX_REMOTE_HOST (sizeof(((conn_t *)0)->host) - 1u)

/* 353's trailing parameter is rendered through reply()'s REPLY_TEXT_MAX (512),
 * and RFC 2812 3.3.5 says a 353 MAY be split across several lines. This is the
 * per-line budget, chosen well under 512 so the text always fits. */
#define CHAN_NAMES_LINE 400

/* ---------------------------------------------------------------------------
 * Per-member prefix flags, 4.4's PREFIX=(ov)@+
 * ------------------------------------------------------------------------- */
#define CHAN_MEMBER_OP    0x1u /* +o, the '@' in 353 */
#define CHAN_MEMBER_VOICE 0x2u /* +v, the '+' in 353 */

/* ---------------------------------------------------------------------------
 * The structs
 * ------------------------------------------------------------------------- */

/* ONE LOCAL MEMBER.
 *
 * 2.2: "A chan_t holds only local members. Remote membership is implicit: the
 * peer links that reported it, plus a refcounted servers[] set recording which
 * servers hold at least one member."
 *
 * THE SECOND HALF OF THAT SENTENCE IS NOW PARTLY UNTRUE, and the correction is
 * recorded here rather than left for a reader to discover from the struct: a
 * chan_t holds only local members IN members[], and remote membership is
 * `remotes[]` PLUS the servers[] set. What changed in C3 is that the NAMES are
 * kept, not that they are derivable -- 7/Phase 6's acceptance criterion is that
 * both nodes' 353 carry both names, and a node cannot name a member it has
 * never heard the name of. The servers[] half of 2.2's sentence is still exactly
 * true and is still what 3.1's forward target set is built from.
 *
 * `flags` is 2.2's own omission and it is not optional: see the file header.
 * The values are CHAN_MEMBER_OP and CHAN_MEMBER_VOICE. */
struct member {
    conn_t   *c;
    unsigned  flags;
};

/* ONE REMOTE SERVER HOLDING AT LEAST ONE MEMBER. A name, deliberately; see the
 * file header. Refcounting is the set itself: an entry is present exactly while
 * that server's last member exists, and chan_server_remove() is the decrement.
 *
 * THIS NODE'S OWN NAME IS NOT IN HERE. It is implicit in nmembers > 0, and
 * putting it in would make 3.1's "forward to every peer in servers[]" forward
 * to ourselves -- which 2.4 forbids outright. */
struct chan_server {
    char name[CHAN_MAX_SERVER + 1];
};

/* ONE BAN MASK. 2.2 names +b as a mode the origin evaluates; this is what it
 * evaluates against. Mask matching (chan_mask_match) is glob-style so that the
 * masks operators actually use -- "*@*", "*!*@10.0.0.*" -- work at all. */
struct chan_ban {
    char mask[CHAN_MAX_BAN + 1];
};

/* ONE REMOTE MEMBER: a user on another server, reported to this node over 4.3's
 * SJOIN and removed over its SPART.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS NOT A `struct member`
 * ---------------------------------------------------------------------------
 * The Phase 4 header of this file said "A chan_t holds only local members" and
 * `struct member` is still exactly 2.2's `struct member { conn_t *c; }` plus
 * the flags. That is deliberate and it is the reason this is a separate array
 * rather than a third meaning for `member::c`:
 *
 *   members[] is walked by fan-out, by teardown, by the ban check, by KICK and
 *   by MODE, and every one of those dereferences `c` to reach a conn_t this
 *   node owns. A remote member has NO conn_t, so folding the two together means
 *   either a NULL check in all five of those walks (five new places to forget
 *   one, and a missing one is a NULL dereference on the teardown path) or a
 *   fake conn_t per remote user (which is 2.1's identity model rebuilt as a
 *   lie). Keeping the arrays apart means none of those walks changed at all.
 *
 * The cost of keeping them apart is that 353 renders from TWO lists, and the
 * grouping order has to be computed across both. That is one function, in
 * chan_verbs.c, and the grouping helper is the SAME one the local walk already
 * used -- see send_names_list() there. 7/Phase 4's fixed order (nicks, then
 * ops, then voiced) is a property of the RENDER, not of the storage, and this
 * is the only place it has to be recomputed.
 *
 * `server` is kept per entry rather than derived, because servers[] is a SET
 * (2.2: "a refcounted servers[] set recording which servers hold at least one
 * member") and the decrement needs to know which member went last. Without it
 * an SPART could not tell which entry to remove and the set would only ever
 * grow, at which point 3.1's forward target set is every server this node has
 * ever heard of.
 *
 * ---------------------------------------------------------------------------
 * `server` IS THE ATTRIBUTION KEY, AND `member_server` IS THE FACT
 * ---------------------------------------------------------------------------
 * `server` names the peer whose REPORT put this entry here: for a live SJOIN it
 * is the link that sent it, and for a burst record it is the BURST ORIGIN. It is
 * the key chan_remote_find() and chan_remote_purge() address, and it is what
 * makes 4.3's replace-never-merge per-origin -- a resync has to be able to name
 * exactly the entries the previous resync from the same origin installed, and
 * that set is "everything keyed by the origin that is now re-reporting".
 *
 * `member_server` names the server that actually HOLDS the member. On a two-node
 * mesh the two are always the same string, and on a live SJOIN they still are
 * (4.3's SJOIN carries no server, so the sending link is the only answer there
 * is). They part company on exactly the case 4.3.1 records: a relay reporting a
 * member that lives on a third node knows the member's server but is not it,
 * and keying the entry by the relay would both misattribute the member and make
 * the relay's resync unable to replace what the relay itself installed. That is
 * why the wire grew the field BEFORE a second implementation existed rather
 * than after: a format that cannot carry the fact cannot be repaired by a later
 * phase without a compatibility break.
 *
 * AN EMPTY member_server IS NORMAL, not corrupt, and it means "this entry was
 * learned from a live SJOIN, or from a burst by an implementation that did not
 * carry the field". Every writer treats it as an answer rather than an error, and
 * the one place that needs a value -- the burst sender -- falls back to the key,
 * which on a two-node mesh and for a live SJOIN is the same string.
 *
 * NEITHER FIELD APPEARS IN A 353. 353's names parameter is bare nicknames (RFC
 * 2812 3.3.5) and this node renders it that way, so the attribution is stored
 * rather than displayed; §2.1's `nick@server` qualification is for a local
 * connection this node owns a conn_t for, and a remote member has none.
 *
 * ---------------------------------------------------------------------------
 * A `host` FIELD, which C4 ADDED AND THIS COMMENT USED TO FORECAST
 * ---------------------------------------------------------------------------
 * This field exists because 4.3's SBURST carries a host for every nick, and a
 * remote member this node cannot render as a hostmask is a remote member 2.1
 * cannot describe. It is the additive change this struct's own comment promised
 * C4 would make, and the three properties that comment gave for the addition are
 * what made it safe:
 *
 *   - Nothing serialises this struct. There is no memcpy of a chan_remote_t, no
 *     wire form and no layout key, so a wider element cannot move a byte on the
 *     wire and cannot alias with an index.
 *   - The array is grown with realloc() in whole elements, so a wider struct
 *     needs no allocator and no capacity change beyond sizeof.
 *   - Everything that reads it addresses it by field name, so a new field
 *     cannot change an answer.
 *
 * THE ONE THING IT IS NOT IS RELIABLE, and the asymmetry is the design rather
 * than an oversight. 4.3's SJOIN does not carry a host, so a member learned from
 * a LIVE SJOIN has an EMPTY host and only a resync can fill it -- and a resync
 * is the rarer event. An empty host is therefore the NORMAL state for a member
 * this node has not been re-synced about, not a corruption, and nothing in this
 * tree may report it as one. Anything that renders a remote member has to handle
 * the empty case rather than printing a half-built hostmask.
 */
typedef struct chan_remote {
    char     nick[IRC_MAX_NICK + 1];
    /* The ATTRIBUTION KEY: the peer whose report put this entry here. See the
     * note above -- it is what a resync replaces against, and it is NOT the
     * member's own server. */
    char     server[CHAN_MAX_SERVER + 1];
    /* The server that actually holds the member, from 4.3's SBURSTM
     * <server> field, or "" when this node has not been told. */
    char     member_server[CHAN_MAX_SERVER + 1];
    /* The member's host, or "" when this node learned the member from a live
     * SJOIN rather than from a burst. See the note above. */
    char     host[CHAN_MAX_REMOTE_HOST + 1];
    unsigned flags; /* CHAN_MEMBER_OP / CHAN_MEMBER_VOICE, as for a local one */
} chan_remote_t;

/* THE CHANNEL. Field order is 2.2's, with the four additions above placed next
 * to what they extend rather than appended, so the struct still reads top to
 * bottom as "identity, remote cache, members". */
typedef struct chan {
    /* Always uppercase-normalised (2.2), so "#T" and "#t" are one channel. */
    char     name[CHAN_MAX_NAME + 1];

    /* The server that first created it. Immutable for the channel's lifetime
     * (2.2, "Owner death -- fail closed"), with exactly one exception:
     * chan_rekey(), the creation-race re-key. NOT a re-election -- see the
     * file header. */
    char     origin[CHAN_MAX_SERVER + 1];

    /* 2.2's creation_epoch: the epoch of the server that owns this channel
     * now. It is a tie-break input (chan_origin_wins) and the reason a re-key
     * has to carry the winner's epoch with it. */
    uint64_t origin_epoch;

    /* Remote-originated state. 2.2 is explicit that "a server never stores
     * remote state" is FALSE and that this is a bounded per-channel cache;
     * on a single node the topic is local, and the same three fields serve
     * both. 333 carries topic_who and topic_when, so both are protocol-
     * visible, not bookkeeping. */
    char     topic[CHAN_MAX_TOPIC + 1];
    char     topic_who[CHAN_MAX_TOPIC_WHO + 1];
    time_t   topic_when;

    /* When this channel was created, for 329. Set once by chan_new() and never
     * rewritten -- unlike origin, which the creation race can move. */
    time_t   created_at;

    /* The mode letters currently set, in the order they were set, without
     * '+' or '-'. A CACHE, and on a non-origin node a cache that cannot
     * enforce: see chan_mode_is_origin_only(). */
    char     modes[CHAN_MAX_MODES + 1];

    /* LOCAL members only. Order is join order, and 353 renders it grouped by
     * prefix (7/Phase 4's fixed order: nicks, then ops, then voiced) with
     * join order inside each group. */
    struct member *members;
    size_t         nmembers;
    size_t         cap;

    /* The remote cache, O(servers) and not O(users) -- 2.2's point is that it
     * does not reintroduce per-join broadcast cost. Names, not pointers. */
    struct chan_server *servers;
    size_t              nservers;
    size_t              scap;

    /* Ban masks. Client-driven, so bounded. */
    struct chan_ban *bans;
    size_t           nbans;
    size_t           bcap;

    /* The remote roster: users this node has been TOLD about, keyed by
     * (nick, server). Separate from members[] for the reason the struct's own
     * comment gives, and bounded because it is filled from the network. */
    chan_remote_t *remotes;
    size_t         nremotes;
    size_t         rcap;
} chan_t;

/* How a channel's origin stands from THIS node's point of view. The three
 * values are the whole of 2.2's ownership story; a caller does not inspect the
 * link table itself. */
typedef enum {
    /* origin == s->name. This node created the channel, so it applies state
     * changes here and (in Phase 6) forwards them to servers[]. */
    CHAN_ORIGIN_SELF = 0,
    /* origin != s->name and a peer connection bearing that name exists. The
     * action belongs to the owner's loop: 3.1 says a non-owned channel takes
     * a state-change as FORWARD ONLY, never a local write. */
    CHAN_ORIGIN_LINKED,
    /* origin != s->name and no such connection exists. The channel is LOCALLY
     * ORPHANED and 2.2's single-writer rule refuses origin-requiring actions
     * with 437. Local members still see each other: queries and local fan-out
     * are unaffected. */
    CHAN_ORIGIN_UNREACHABLE
} chan_origin_state_t;

/* ---------------------------------------------------------------------------
 * Names
 * ------------------------------------------------------------------------- */

/* Is `name` a channel this node will accept? 4.4 advertises CHANTYPES=#&, so a
 * channel name starts with one of those two sigils; the rest may not contain a
 * space, a comma (JOIN's argument separator) or a control character, and must
 * fit CHAN_MAX_NAME. Leading/trailing spaces and a bare sigil are refused.
 * 1 legal, 0 not. */
int chan_name_valid(const char *name);

/* Write the canonical form of `name` -- ASCII upper-cased -- into `out`. 2.2
 * stores names uppercase-normalised, and this node advertises
 * CASEMAPPING=ascii, so this is ASCII-only on purpose: message.c's up() does not
 * fold []\~ and {}|^, and 005 says so. Truncates at `cap`; every caller passes
 * a CHAN_MAX_NAME+1 buffer. */
void chan_name_upper(char *out, size_t cap, const char *name);

/* ---------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

/* A new channel, owned by `origin` with `origin_epoch` as its creation epoch.
 * `name` is canonicalised. No members, no topic, no modes, empty caches.
 * Returns NULL on a NULL/invalid argument or an allocation failure. */
chan_t *chan_new(const char *name, const char *origin, uint64_t origin_epoch);

/* Release the member list, the server cache and the ban list, then the struct.
 * Safe on NULL. Does NOT touch any conn_t: a member list holds pointers, and
 * the conn that owns one outlives the channel far more often than not. */
void chan_free(chan_t *ch);

/* ---------------------------------------------------------------------------
 * Members
 * ------------------------------------------------------------------------- */

/* The member record for `c`, or NULL. Returns a CONST-qualified view of a
 * mutable record: a caller reads flags through this and writes them only
 * through chan_set_member_flags(). */
struct member *chan_find_member(const chan_t *ch, const conn_t *c);

/* Add `c` as a local member with `flags`. Returns 0 on success, -1 on a bad
 * argument or allocation failure, and 0-without-adding when `c` is already a
 * member (a repeat JOIN is not an error; the caller decides how to say so).
 * A member is added to the CHANNEL here and to the CONNECTION in
 * chan_attach_conn() -- the two lists are separate and both are needed: the
 * channel's is for fan-out and 353, the connection's is for teardown. */
int chan_add_member(chan_t *ch, conn_t *c, unsigned flags);

/* Remove `who` from `ch` and tell the channel.
 *
 * `echo_to_who` is 1 for a client-issued PART, where the parting client is
 * still a usable connection and RFC 1459 2.3.1 has it receive its own PART.
 * It is 0 for the teardown path (chan_conn_gone), where the connection is going
 * away and emitting to it would be a reply() refusal against the "should be
 * zero forever" n_reply_refused counter.
 *
 * `reason` is the trailing PART parameter, or NULL to omit it.
 *
 * The member is removed BEFORE the remaining members are addressed in the
 * echo_to_who == 0 case and AFTER in the echo_to_who == 1 case; both are the
 * order that makes the broadcast address exactly the right set. The channel is
 * NOT freed here -- see chan_dispose_if_empty(), which is the single place that
 * decides a channel has run out of reasons to exist. */
void chan_member_leave(server_t *s, chan_t *ch, conn_t *who, int echo_to_who,
                       const char *reason);

/* Set or clear one prefix flag on `c`'s membership. Returns 1 when the flag
 * changed, 0 when it was already in that state, -1 when `c` is not a member. */
int chan_set_member_flags(chan_t *ch, conn_t *c, int on, unsigned flag);

/* Does this member record carry `flag`? */
int chan_member_is(const struct member *m, unsigned flag);

/* Is this member still ADDRESSABLE -- is its connection one this node can
 * deliver a message to?
 *
 * Every walk of a member list that ends in an emission asks this, and it is a
 * question rather than a check of a flag on chan_t because the answer is a
 * property of the CONNECTION, which the loop owns: a conn the loop has marked
 * CLOSING has been dropped from the poll set and is waiting for the reaper, so
 * anything queued for it is undeliverable by construction.
 *
 * It exists because the alternative is a guaranteed-false bug report. Two
 * clients on one channel can hit EOF in the same read step -- the loop marks
 * both CLOSING -- and the reaper then parts the first one out, which reaches
 * the second. reply() refuses to write to a CLOSING target, on purpose, so
 * without this the node would end a perfectly ordinary session with a non-zero
 * n_reply_refused. That counter is a bug report rather than a metric (see
 * reply.c), and a teardown that is correct in every other respect must not
 * manufacture one.
 *
 * 1 when the member's conn is non-NULL and not CONN_CLOSING. */
int chan_member_live(const struct member *m);

/* Does `c` hold `flag` in this channel? A shorthand for the query that MODE and
 * KICK both make, so neither of them has to reach through chan_find_member()
 * and re-derive the same test. */
int chan_has_flag(const chan_t *ch, const conn_t *c, unsigned flag);

/* Are these two names the same name? ASCII case-insensitive.
 *
 * ONE fold for BOTH nicknames and server names, because 2.1 makes both of them
 * case-insensitive (RFC 2812 3.3.1 for nicknames, RFC 1459 2.3.2 for servers)
 * and because two exported names for the same six lines is two places to change
 * the fold. channel.c already had a static one doing exactly this for
 * servers[]; it is named rather than copied because the remote roster added a
 * second caller with no other reason to own an ASCII fold, and "is this the same
 * name" must have ONE answer. */
int chan_same_name(const char *a, const char *b);

/* The member record whose connection has this nickname, or NULL. Nickname
 * matching is case-insensitive (2.1: RFC 2812 3.3.1 nicknames are case
 * insensitive), so KICK and MODE +o accept either spelling. */
struct member *chan_find_nick(const chan_t *ch, const char *nick);

/* Add or remove `ch` in `c`'s channel list -- conn_t::chans, whose layout is
 * final as of Phase 2 and is not touched here.
 *
 * Both return 0 on success and -1 on failure (a bad argument, or a list that
 * could not grow). Removal is order-preserving so that LIST's row order and the
 * order a teardown parts in are both a function of join history and not of
 * allocator behaviour. */
int chan_attach_conn(conn_t *c, chan_t *ch);
int chan_detach_conn(conn_t *c, chan_t *ch);

/* Drop `c`'s member record without emitting anything. Returns 1 if it was
 * there. Used where the caller has already broadcast the departure (KICK) and
 * must not produce a second, unprefixed PART. */
int chan_remove_member(chan_t *ch, conn_t *c);

/* ---------------------------------------------------------------------------
 * Topic
 * ------------------------------------------------------------------------- */

/* Set the topic, its setter and its time. `who` is the setter's qualified
 * identity for 333. Returns 0 on success, -1 on a topic that does not fit
 * CHAN_MAX_TOPIC or a setter that does not fit -- refused, not truncated, for
 * the reason 3.2 gives. An empty `topic` CLEARS it (TOPIC #chan : is how a
 * topic is removed) and leaves topic_who and topic_when untouched, because a
 * cleared topic has no setter. */
int chan_set_topic(chan_t *ch, const char *topic, const char *who);

/* 329's value. Named so the numeric and the field it comes from are visibly
 * the same thing. */
time_t chan_created_at(const chan_t *ch);


/* ---------------------------------------------------------------------------
 * The remote server cache
 * ------------------------------------------------------------------------- */

/* Record that `name` holds at least one member. Idempotent: adding a name that
 * is already present returns 0 and does not duplicate it, which is what makes
 * it safe to call on every reported member rather than on a transition.
 * Returns -1 on a bad argument, on a name that does not fit, on a full set
 * (CHAN_MAX_MEMBER_SERVERS), or on allocation failure. */
int chan_server_add(chan_t *ch, const char *name);

/* Drop `name` -- the decrement of the refcount the set represents. Idempotent.
 * Returns 1 when an entry was removed, 0 when there was none. */
int chan_server_remove(chan_t *ch, const char *name);

/* Is `name` in the set? Case-insensitive: server names are case-insensitive in
 * IRC, and 2.1/2.4 both say a server-name comparison MUST be. */
int chan_server_has(const chan_t *ch, const char *name);

/* ---------------------------------------------------------------------------
 * The remote roster
 * ---------------------------------------------------------------------------
 * A member this node cannot deliver to and has never had a socket for. 2.2
 * stores remote state as a CACHE the origin corrects, and 4.3's SJOIN/SPART
 * are what fills it, with SBURST filling what they cannot. These are the whole
 * of that surface.
 */

/* Record `nick` on `server` as a member, with `flags`, held by `member_server`.
 * Idempotent on (server, nick) -- a repeated SJOIN updates the flags and adds
 * nothing, which is what makes it safe to call on every reported member rather
 * than on a transition. Returns 0 on success, -1 on a bad argument, on a full
 * roster (CHAN_MAX_REMOTE_MEMBERS), or on allocation failure.
 *
 * `server` and `member_server` are TWO questions and both are required, because
 * a burst is a relay's report about a member that may live on a third node: the
 * first is who to blame for the entry (and is what a resync replaces against),
 * the second is where the member actually is. On a live SJOIN a caller passes
 * the sending link's name twice -- 4.3's SJOIN carries no server field, so there
 * is nothing else to say -- and on a burst it passes the burst origin first and
 * the record's own <server> second.
 *
 * `member_server` may be NULL or "" and means "not told", which is the ordinary
 * state of an entry learned from a live SJOIN; every reader treats it as an
 * answer rather than an error, and the only consumer that needs a value falls
 * back to `server` (see the struct's own comment).
 *
 * The nickname is validated with valid_nick() and both server names with the 2.4
 * grammar, and by THIS function rather than by its caller: this is the first
 * point in the tree where a nickname arrives from a network rather than from a
 * client, and 2.1's charset rule exists because later phases build on it. A
 * roster entry that failed the charset would be a name the node could not
 * qualify, compare or render.
 *
 * A NEW entry is created with an EMPTY host, and a repeat leaves the host
 * alone. The asymmetry is the point: 4.3's SJOIN carries no host, so a repeat
 * from a live SJOIN has nothing to say about one a burst filled, and clearing
 * it would make a re-assert throw away the only field this struct grew for.
 * `member_server` is NOT treated that way -- it is overwritten on a repeat,
 * because an entry's holder is a fact a later record can correct and a stale
 * one is an entry nobody can act on. */
int chan_remote_add(chan_t *ch, const char *server, const char *member_server,
                    const char *nick, unsigned flags);

/* Drop the (server, nick) member. Returns 1 when one was removed, 0 when there
 * was none. Does NOT touch servers[] -- the caller decrements that, because the
 * set is per SERVER and only the caller can tell whether this entry was the
 * server's last. */
int chan_remote_remove(chan_t *ch, const char *server, const char *nick);

/* Drop EVERY entry belonging to `server`, and return how many went. 0 when the
 * server had none, which is the ordinary case on a node that has not been told
 * about it.
 *
 * IT EXISTS FOR 4.3's REPLACE-RATHER-MERGE, and nothing else uses it. A resync
 * replaces this node's knowledge of what ONE origin holds, so the entries that
 * origin contributed have to go before its new ones arrive: without this, a
 * member who left at the origin stays in the roster forever, because SPART is a
 * per-member line and a burst is the only thing that can say "none of them are
 * here any more". It is a function rather than a loop at the call site because
 * the walk-and-remove is the one place that has to be careful about removing
 * under a cursor, and a caller that wrote it would write it wrong at least once.
 *
 * Entries from OTHER servers are untouched, which is what makes the operation
 * per-ORIGIN and therefore safe to apply to a node that is also holding
 * channels and members of its own. */
size_t chan_remote_purge(chan_t *ch, const char *server);

/* Set the (server, nick) member's host. Returns 0 on success, -1 on a bad
 * argument, on an entry that is not there, or on a host longer than
 * CHAN_MAX_REMOTE_HOST -- REFUSED, not truncated, for 3.2's reason: a truncated
 * host renders a hostmask that is not the one the peer reported.
 *
 * It is a setter rather than a field write because the bounded copy belongs in
 * the module that owns the struct, and a caller doing `memcpy(r->host, h,
 * strlen(h))` against a 128-byte field is the shape of the bug this exists to
 * prevent. */
int chan_remote_set_host(chan_t *ch, const char *server, const char *nick,
                         const char *host);

/* Rekey the (server, old) member to (server, new). Returns 1 when a member was
 * renamed, 0 when there was none, -1 when `new` is not a legal nickname, is
 * already held by another entry, or would overflow the field.
 *
 * IT EXISTS FOR 2.1's RENAME-THE-LOSER, and the reason a rename is not two
 * calls (remove then add) is that it is not atomic: an entry removed and not yet
 * added is a member this node has decided does not exist, and anything walking
 * the roster in between -- which is a single-threaded node, so "in between" means
 * the rest of the function, but a nested call would be a window -- would see it
 * gone. Rekeying also keeps the entry's FLAGS, which a remove-then-add loses, and
 * a renamed op who came back unflagged is a demotion this node would otherwise
 * have caused by resolving a duplicate nick.
 *
 * `new` is refused when it collides, rather than overwriting: two entries for one
 * member server under one nickname is the same ambiguity the policy is resolving,
 * and a rename that created it would reintroduce the problem it was called to fix.
 *
 * AND IT DOES NOT TOUCH servers[], because the member server is unchanged by a
 * rename and the set is a refcount per SERVER. A caller that thought otherwise
 * would decrement a set it did not increment. */
int chan_remote_rename(chan_t *ch, const char *server, const char *old_nick,
                       const char *new_nick);

/* The entry for this (server, nick), or NULL. Nicknames fold (2.1) and server
 * names fold (2.4). The SERVER is part of the key because 2.1's rename-the-loser
 * policy means two nodes may legitimately hold the same nickname -- exactly one of
 * them keeps it, and the other renames -- so a nickname alone is not an identity
 * here either. */
chan_remote_t *chan_remote_find(const chan_t *ch, const char *server,
                                const char *nick);

/* How many remote members this channel holds, and the i'th of them. 0 on a
 * channel no peer has reported a member for, which is every channel on a
 * single node. */
size_t chan_remote_count(const chan_t *ch);
chan_remote_t *chan_remote_at(const chan_t *ch, size_t i);

/* ---------------------------------------------------------------------------
 * Modes
 * ------------------------------------------------------------------------- */

/* Is `m` one of the modes ONLY the origin may evaluate -- 2.2 names +b, +e and
 * +I? This is the predicate that makes channel-mode authority decidable, and it
 * is asked before privilege, so a non-origin node never answers "you are not an
 * operator" about a channel it has no standing to evaluate.
 *
 * 1 for b, e and I; 0 otherwise. Case-insensitive, so an upper-case mode
 * letter from a peer is recognised. */
int chan_mode_is_origin_only(char m);

/* Is `m` currently set on this channel? */
int chan_mode_has(const chan_t *ch, char m);

/* Record or clear a mode letter in modes[]. Returns 1 when modes[] changed, 0
 * when it was already in that state, -1 on a bad argument or a full modes[].
 * This RECORDS; it does not enforce. The caller is responsible for having asked
 * chan_mode_is_origin_only() and the operator check first, which is the whole
 * of "a non-owner's modes[] is a cache and cannot enforce". */
int chan_mode_set(chan_t *ch, char m, int on);

/* Add a ban mask. Returns 0 on success, -1 on a bad or over-long mask, on a
 * full list (CHAN_MAX_BANS) or on allocation failure. The 'b' letter in
 * modes[] is the caller's business, not this function's: a caller that adds a
 * mask and forgets the letter has two bugs, and hiding one inside the other
 * makes both harder to find. */
int chan_ban_add(chan_t *ch, const char *mask);

/* Remove a ban mask. Returns 1 when one was removed, 0 when there was none. */
int chan_ban_remove(chan_t *ch, const char *mask);

/* Is this identity banned? `nick`, `user` and `host` are matched against every
 * mask, and so is the full "<nick>!<user>@<host>" they compose.
 *
 * The full form is not a convenience -- it is the only one that can enforce the
 * masks operators actually write. A mask of the shape "*!*@10.0.0.1" contains a
 * "!" and an "@", so it matches neither a bare nickname nor a bare host, and an
 * implementation comparing only those two fields would report the ban as set
 * (324 shows the "b") while refusing to ban anybody. The separate fields are
 * kept for the bare-nickname and bare-host cases. Case-insensitive. */
int chan_banned(const chan_t *ch, const char *nick, const char *user,
                const char *host);

/* Glob match for a ban mask: '*' matches any run of characters, '?' exactly one,
 * everything else is itself. Case-insensitive, because hostnames and nicks are
 * (2.1). Exposed so the rule is unit-testable on its own rather than only
 * through a JOIN. */
int chan_mask_match(const char *mask, const char *value);

/* ---------------------------------------------------------------------------
 * Ownership -- the three rules of 2.2
 * ------------------------------------------------------------------------- */

/* Does this node own the channel? Shorthand for
 * chan_origin_state(s, ch) == CHAN_ORIGIN_SELF, named because the single-writer
 * rule reads better against it. */
int chan_origin_is_self(const server_t *s, const chan_t *ch);

/* Where the channel's origin stands from here. DERIVED, never stored; see the
 * file header for why. */
chan_origin_state_t chan_origin_state(const server_t *s, const chan_t *ch);

/* THE CREATION-RACE TIE-BREAK, as a pure function over the two pairs.
 *
 * 2.2: "First server to see a channel owns it. The creation race is broken by
 * (creation_epoch, server_name), higher wins; the loser re-keys to the winner's
 * origin. Both halves are single-node-testable in Phase 4."
 *
 * Lexicographic: the higher epoch wins, and only when the epochs are EQUAL does
 * the higher name decide. Name comparison is case-insensitive (2.1) and
 * strcmp-ordered, so the result does not depend on which node asks.
 *
 * It is a pure function over its arguments on purpose. The rule is inherently
 * about two servers, and 6.2's two-node harness is Phase 6, so the alternative
 * would be a function that can only ever be exercised with a real competitor --
 * which on a single node means a fake one. This way both halves of the
 * lexicographic order are testable with arbitrary inputs, including the case
 * that actually exercises the second half (higher epoch but LOWER name, versus
 * equal epoch and higher name).
 *
 * 1 if (a) wins, 0 if (b) wins or the two are indistinguishable. Identical
 * (epoch, name) pairs return 0, so a re-key to the incumbent's own origin is
 * refused rather than treated as a no-op success. */
int chan_origin_wins(uint64_t a_epoch, const char *a_name,
                      uint64_t b_epoch, const char *b_name);

/* THE RE-KEY, the loser half of the same rule: adopt `origin`/`origin_epoch` as
 * this channel's, but ONLY if they win the tie-break against what is there
 * already. Returns 1 on success, 0 when the incumbent keeps it, -1 on a bad
 * argument.
 *
 * Members, topic, modes and both caches are untouched by definition -- the
 * channel does not become a different channel, it becomes the same channel with
 * a different owner -- and the caller is responsible for re-evaluating every
 * cached decision that was made while the old origin owned it. */
int chan_rekey(chan_t *ch, const char *origin, uint64_t origin_epoch);

/* ---------------------------------------------------------------------------
 * THE TOPIC CACHE -- a topic that outlives its channel
 * ---------------------------------------------------------------------------
 * One entry per channel whose topic was set and whose channel has since been
 * disposed. It exists because of a collision between two things 2.2 wants:
 *
 *   chan_dispose_if_empty() frees a channel with no local members and no
 *   member-server, and it is right to -- a channel nobody is on has nothing to
 *   be authoritative about, and holding one per channel NAME a client ever typed
 *   would be an unbounded store reachable from the wire. 2.2's own statement is
 *   that a channel "outlives a connection", which is a statement about OWNERSHIP
 *   and not about never being freed.
 *
 *   And the topic is the one field whose loss a CLIENT can see. A user who
 *   rejoins a channel everybody has left finds it topicless, and that is
 *   indistinguishable from a channel that never had a topic -- so the topic is
 *   copied out on the way down and copied back in when the channel is created
 *   again.
 *
 * ---------------------------------------------------------------------------
 * WHAT IT IS NOT, and each of these is a decision rather than a gap
 * ---------------------------------------------------------------------------
 *   NOT A PERSISTENT STORE. The cache is heap memory on server_t and it is gone
 *   when the node exits. A topic does not survive a node restart, nothing here
 *   claims it does, and a test that asserted it would be asserting a disk write
 *   this phase does not have. 3.4 is the reason: a write inside the event loop
 *   blocks every client on the node, and a new on-disk artifact is a new
 *   deployment surface and a new way for a topic to be wrong.
 *
 *   NOT A CHANNEL. It holds three topic fields and a name. It is authoritative
 *   for nothing, it is consulted on exactly one code path (a channel being
 *   CREATED), and nothing routes through it -- 3.1's table has no row for it,
 *   because a line is never delivered to a topic.
 *
 *   NOT A MEMBER LIST, A MODE SET OR A BAN LIST. Only the topic is carried, and
 *   that is the whole of what a re-created channel needs in order not to look
 *   blank. A channel whose bans and modes were dropped when everybody left is a
 *   channel whose moderation state was reset, and 2.2 says the ORIGIN owns
 *   those: a cache that restored them would be a second authority for channel
 *   state, which is the exact thing the single-writer rule exists to prevent. If
 *   they are wanted later, that is a decision for the phase that owns mode
 *   authority, not a side effect of this one.
 *
 * ---------------------------------------------------------------------------
 * WHY IT IS BOUNDED, AND WHAT HAPPENS AT THE BOUND
 * ---------------------------------------------------------------------------
 * SERVER_TOPIC_MAX is a bound, not a hint, and unlike 2.2's per-channel caches
 * this one is reached by ordinary client input: a client can join a channel, set
 * a topic, leave, and repeat, naming as many distinct channels as it likes --
 * one at a time, with no single line asking for a lot of work. That is the same
 * reason CHAN_MAX_BANS is a real limit rather than a formality.
 *
 * At the bound a topic is NOT remembered, s->n_topic_cache_full counts the loss,
 * and the topic is then lost exactly as it would have been without this cache.
 * The cache therefore never refuses a client command and never makes the node
 * slower; it can only fail to help. That is the right direction for a cache whose
 * bound is reached by traffic rather than by a bug.
 *
 * 64 is not derived from anything: it is a judgement, and it is a judgement about
 * NAMES rather than about topics, because the entry is keyed by channel name. 64
 * names is well under the 1024 descriptors the node can hold and far above the
 * number of channels one client is typically on. The cost when full is the cost
 * when full: one topic, reported.
 */

/* ONE REMEMBERED TOPIC. The name is the key and it is stored canonicalised
 * (2.2), so "#t" and "#T" are one entry -- the same reason the channel registry
 * stores names that way and the nick registry folds its keys instead.
 *
 * `who` and `when` are here because 333 reports BOTH. A cache that restored only
 * the text would make 333 name whoever rejoined and the moment they rejoined,
 * which is a lie about who set the topic -- and the observable difference is that
 * a user reading 333 would believe they had set a topic they did not set. */
typedef struct chan_topic {
    char   name[CHAN_MAX_NAME + 1];
    char   topic[CHAN_MAX_TOPIC + 1];
    char   who[CHAN_MAX_TOPIC_WHO + 1];
    time_t when;
} chan_topic_t;

/* How many channels this node will remember a topic for. See the note above:
 * reached by client input, and a loss at the bound is reported rather than
 * refused. */
#define SERVER_TOPIC_MAX 64

/* Copy `ch`'s topic, setter and time into the cache, replacing any entry for the
 * same channel. Called immediately before the channel is disposed, so the topic
 * outlives the channel.
 *
 * AN EMPTY TOPIC REMOVES the entry rather than remembering an empty one, and that
 * is load-bearing: a user who CLEARS a topic (`TOPIC #chan :`) and then everybody
 * leaves must not find the old topic back when they rejoin. Remembering "" as a
 * value would need a "remembered but empty" state to be told apart from "never
 * remembered", and the ABSENCE of an entry is already that state.
 *
 * A no-op when the channel has no topic and nothing is remembered for it: a
 * channel that never had a topic is not a cache write. Returns 1 when an entry
 * was stored, 0 when there was nothing to do or when an entry was removed, and
 * -1 when the cache was full or an allocation failed -- the case
 * s->n_topic_cache_full counts, and which leaves everything else untouched. */
int server_topic_remember(server_t *s, const chan_t *ch);

/* Copy a remembered topic into a channel that has just been CREATED. A no-op
 * when nothing is remembered for that name, and 1 when a topic was restored.
 * Never called for a channel that already existed: a live channel's topic is
 * authoritative and the cache has nothing to add to it. */
int server_topic_restore(server_t *s, chan_t *ch);

/* How many topics the node is remembering, and the entry at index `i`. For the
 * observable output; the wire assertions in test_topic_persist.c are what
 * actually pin the behaviour. */
size_t server_topic_count(const server_t *s);
const chan_topic_t *server_topic_at(const server_t *s, size_t i);

/* ---------------------------------------------------------------------------
 * The node's channel set
 * ------------------------------------------------------------------------- */

/* Register `ch` under its canonical name and append it to the node's ordered
 * channel index. Returns 0 on success, -1 if the name is already registered or
 * on allocation failure. This is the only way a chan_t enters the node; the
 * Phase 2 key-space probes in server.h cannot carry a value. */
int server_chan_attach(server_t *s, chan_t *ch);

/* Look a channel up by name, case-insensitively (the name is canonicalised
 * first). Returns NULL when the node has no such channel. This is the accessor
 * the Phase 2 probes could not be: they answer "is this key present" and are
 * deliberately case-SENSITIVE, which is a different question. */
chan_t *server_chan_get(const server_t *s, const char *name);

/* Unregister by canonical name, leaving the channel itself alone. The caller
 * frees it. */
void server_chan_detach(server_t *s, const char *name);

/* How many channels the node holds. */
size_t server_chan_count(const server_t *s);

/* The i'th channel in CREATION order, or NULL past the end. The order is
 * creation order rather than hash order so that LIST -- which enumerates every
 * channel on the node -- has a deterministic, assertable output. */
chan_t *server_chan_at(const server_t *s, size_t i);

/* ---------------------------------------------------------------------------
 * Teardown
 * ------------------------------------------------------------------------- */

/* Take `c` out of every channel it is in, emitting the PART to the members
 * left behind, and dispose of any channel that has run out of members. This is
 * what a connection going away means at the channel layer, and it is called by
 * the registry in server.c immediately before conn_free() so that a departing
 * connection cannot leave a dangling conn_t* in a member list.
 *
 * Deliberately NOT called by anything that closes a descriptor: 3.4 keeps the
 * reaper as the single close site, and this function is reached from it. */
void chan_conn_gone(server_t *s, conn_t *c);

/* Free `ch` if nothing needs it any more: no local members AND no entry in the
 * remote server cache. Returns 1 if it was freed.
 *
 * The second half of the condition is 2.2's reason for the cache existing at
 * all, and it is the test that proves the cache is real rather than declared: a
 * channel this node holds no members of, but which a peer has reported members
 * for, SURVIVES -- because 3.1 still has to route that channel's messages to
 * the owner, and a node with zero local members in a channel must keep it. */
int chan_dispose_if_empty(server_t *s, chan_t *ch);

#endif /* IRC_CORE_CHANNEL_H */
