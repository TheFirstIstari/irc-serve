/* burst.h -- 4.3's SBURST: the resync, and the wire format it froze.
 *
 * Authority: docs/SERVER_DESIGN.md 4.3 ("SBURST is the resync verb. On every
 * link establishment the initiator sends full state ... A resync REPLACES state
 * for that origin; it never merges. There is no partial burst and no delta.
 * SBURST is Phase 6, not Phase 9 -- it defines the wire format, and a wire
 * format cannot be invented later"), 2.2 (the per-channel remote cache, the
 * servers[] set, and origin ownership), 2.4 (the tag block and the dedup rule
 * every line of a burst passes through), 3.2 (the line bound and the
 * unrepresentable middle parameter), 3.4 (a saturated link is dropped, not
 * buffered) and 8 (link loss and reconnect re-syncs channel state via SBURST --
 * the verb lands here, the DRIVING is Phase 9).
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS A FILE AND NOT A FUNCTION IN THE MODULE THAT DECIDES SOCKETS
 * ---------------------------------------------------------------------------
 * Because a burst is a TRANSACTION and a transaction is not a message. Every
 * other line the peer path handles is a single fact that can be applied or
 * refused on its own; a burst is a begin, an unbounded number of records, and a
 * terminator, and its whole meaning is that the records between are visible to
 * NOBODY until the terminator arrives. That is state whose size is a channel
 * list, it lives for the duration of one link's traffic, and it has exactly one
 * owner. federation/link.c owns which link is up; this owns what a link said.
 *
 * ---------------------------------------------------------------------------
 * THE WIRE FORMAT -- FIVE VERBS, ONE LINE PER RECORD
 * ---------------------------------------------------------------------------
 *   :<origin> SBURST  <epoch> <nnicks>
 *   :<origin> SBURSTN <nick> <user> <host> <modes> <signon> :<away>
 *   :<origin> SBURSTC <chan> <origin> <topic_who> <topic_when> <modes> :<topic>
 *   :<origin> SBURSTM <chan> <nick> <flags>
 *   :<origin> SBURSTE <epoch> <nnicks> <nchans> <nmembers>
 *
 * Every line carries 2.4's internal tag block, like every other relayed line,
 * and hops is 0 on all of them: a burst originates at the node that sends it.
 * The prefix is the BURST ORIGIN -- the server whose state the transaction is
 * about -- which is this node, on both sides of the exchange.
 *
 * The RECORDS COME BEFORE THE CHANNELS, and that order is a contract rather
 * than a preference: an SBURSTM names a nick, and the nick's host arrives in the
 * SBURSTN that preceded it. A member whose nick was never announced gets an
 * empty host, which is exactly the state a live SJOIN leaves a member in and is
 * not an error.
 *
 * SBURST'S <epoch> IS HOW A PEER RESTART IS DETECTED, and it is also how
 * server_link_t::epoch is populated on the far side: 2.4's dedup key is
 * (origin, epoch, id) and a key whose epoch belongs to a different boot than its
 * id is a key that ALIASES, so a burst that changed the epoch without saying so
 * would put every subsequent id in the wrong id space. The terminator repeats
 * the epoch and the two must agree -- a transaction that changed its mind about
 * which boot it is about is discarded, not applied.
 *
 * SBURSTE'S THREE COUNTS ARE ASSERTED, NEVER TRUSTED. They are what makes a
 * truncated burst detectable: a receiver cannot know a burst has ended unless it
 * is told, and a receiver that has been told nothing has been told nothing. A
 * count that does not match what was accumulated means records were lost between
 * the two ends -- a saturated link, a dropped duplicate, a line this node
 * refused -- and a roster missing a member is worse than a roster that is stale,
 * because nothing downstream can tell the difference.
 *
 * ---------------------------------------------------------------------------
 * WHY ONE LINE PER RECORD AND NOT A PACKED MEMBER LIST
 * ---------------------------------------------------------------------------
 * This is the load-bearing choice in the format, and the reason is that there is
 * NO LEGAL WAY TO PACK THESE FIELDS.
 *
 * topic is char[256] and away is char[256], and both may contain spaces, ':'
 * and ';'. A packed member list therefore needs an escape alphabet, and every
 * escape alphabet is a second grammar that has to be got right on BOTH sides --
 * a wire format that cannot be revised once two nodes run it, being extended by
 * a rule nobody wrote down. 5 already says this project has been wrong about a
 * wire format before and that the fix was to freeze the right one in Phase 1
 * rather than in the phase that needed it.
 *
 * And there is no separator to escape INTO. The obvious candidates are all legal
 * nick characters, because 2.1's charset rule is deliberately narrow in the
 * WRONG DIRECTION for a separator: valid_nick() excludes '@', '#', '&', '+',
 * '!', ':' and ';' and every byte <= 0x20 -- but it ACCEPTS ',' and '%' and every
 * byte >= 0x80. So `nick,nick` and `nick%nick` are both ambiguous nicknames and
 * neither can be forbidden without making a real nickname unrepresentable, and
 * 5's note that "the delimiter set is what later phases build on" is the reason
 * it is not free to widen now. A separator byte that is illegal in a nick would
 * fix this; this node's nick rule has no such byte.
 *
 * One line per record sidesteps all of it, because 3.2 has already solved it:
 * message_format() REFUSES a parameter containing SP, HTAB, CR or LF, REFUSES a
 * value that needs the ':' marker in any position but the last, and renders the
 * final parameter colonned. So a trailing topic or away -- spaces, colons,
 * semicolons and all -- round-trips with no rule of this file's own, and
 * THERE IS NO ESCAPE FUNCTION AND NO DELIMITER TO GET WRONG. The whole cost is
 * that a burst is one line per nick and one per member rather than one per
 * channel, which this codebase already pays elsewhere: T3 puts a line on every
 * link every 30 s, and 3.1's union arm re-shapes and re-stamps every forwarded
 * line rather than packing targets together.
 *
 * THE PRICE IS ACTUAL, and it is bytes, not ambiguity: a channel with 500
 * members costs 500 SJOIN-shaped lines of overhead, 501 bytes each at the
 * worst-case stamp below, against a channel record of under 800. The budget
 * below is what keeps that affordable, and it is derived from the link's queue
 * rather than picked.
 *
 * ---------------------------------------------------------------------------
 * THE BUDGET, AND WHY IT IS NOT fanout_line_fits()
 * ---------------------------------------------------------------------------
 * IRC_MAX_RELAY_LINE (8013) is 3.2's cap for a line carrying a CLIENT payload,
 * and fanout_line_fits() charges the CLIENT envelope against it -- a 64-byte
 * channel name and a 64-byte hostmask per line. A SBURST* line is not client
 * payload: it names no user and carries no hostmask, and using the client
 * budget for it would be wrong in the direction of refusing legal bursts. So the
 * burst is budgeted against IRC_MAX_LINE (8192) directly, and the per-line
 * arithmetic is below.
 *
 *   on the wire                          bytes
 *   ---------------------------------   -----
 *   "@" + 2.4 block + " "               179   IRC_MAX_TAG_OVERHEAD, frozen
 *   ":" + burst origin + " "              65   IRC_MAX_SERVER_NAME + 2
 *   "SBURSTC" + " "                       8   the longest verb word
 *   <chan> + " "                         64   CHAN_MAX_NAME + 1
 *   <origin> + " "                       64   IRC_MAX_SERVER_NAME + 1
 *   <topic_who> + " "                     64   CHAN_MAX_TOPIC_WHO + 1
 *   <topic_when> + " "                   21   20 digits (UINT64_MAX) + 1
 *   <modes> + " "                         32   CHAN_MAX_MODES + 1
 *   ":" + <topic>                       256   CHAN_MAX_TOPIC + 1
 *                                         ---
 *                                         753   worst case, before CRLF
 *
 *   SBURSTN, the largest of the rest: 179 + 65 + 8 ("SBURSTN ") + 64 (nick) +
 *   64 (user, conn_t::user) + 128 (host, conn_t::host) + 2 (the modes token) +
 *   21 (signon) + 256 (away) = 787. SBURSTM is 179 + 65 + 8 + 64 + 64 + 2 = 382.
 *   SBURST and SBURSTE carry only numerics and are under 320.
 *
 * 753 and 787 against 8192 is 9.2% and 9.6% of the cap, so LINE LENGTH IS NOT
 * THE BURST'S CONSTRAINT and a per-line check would be a formality. THE REAL
 * CONSTRAINT IS TOTAL VOLUME, and 3.4 states the answer for a link that cannot
 * keep up: a saturated peer link is DROPPED, not buffered. A burst is O(nicks +
 * members), so a large node's burst can be megabytes, and queueing it all
 * would starve every live message behind it -- and on a saturated link the
 * queue does not degrade, it DROPS, so the burst would be truncated in the
 * middle of a transaction and the receiver would discard the whole thing.
 *
 * So a burst is assembled into a bounded staging buffer and the whole
 * transaction is refused rather than truncated. Half the queue, not all of it:
 * a resync is worth at most half a link's queue so that a live message is never
 * starved by one, and a message is the thing 3.1 routes in steady state while a
 * burst is a once-per-establishment event.
 */
#ifndef IRC_FEDERATION_BURST_H
#define IRC_FEDERATION_BURST_H

#include <stddef.h>
#include <stdint.h>

#include "core/message.h"
#include "core/server.h"

/* The staging bound, DERIVED from the link's write queue and not picked.
 *
 * CONN_WQ_MAX is 3.4's "~256 KB per connection", and it is the number that
 * matters because a peer link IS a conn_t (2.3) -- the burst is queued through
 * server_queue() and is refused by the same bound as everything else. Half of
 * it is the fraction: see the header's argument, which is that a burst must
 * never be able to fill a link's queue.
 *
 * WRITTEN AS THE EXPRESSION rather than as 131072 for the reason
 * IRC_FED_DEAD_MS is written as one: changing the queue bound must move this
 * with it, and a copy of the number is a number that agrees today and disagrees
 * the day somebody raises CONN_WQ_MAX for a client-facing reason. */
#define IRC_BURST_MAX_BYTES (CONN_WQ_MAX / 2u)

/* The shipped bound for THIS PROCESS, and a per-process override of it. 0 keeps
 * the built-in. Call it before the burst runs; the value is read on every
 * comparison, so calling it later is legal but would apply mid-flight.
 *
 * WHY THERE IS A KNOB AT ALL, stated rather than smuggled: IRC_BURST_MAX_BYTES
 * is the SHIPPED bound and a deployment is what it says. Proving the refusal
 * path without a knob needs a fixture that actually exceeds half a link's
 * queue, and at the worst-case line sizes above that is roughly 170 records --
 * so a few hundred client connections and channels, on every run, forever, to
 * exercise one branch. This is the same per-process override the four link
 * timers have and for the same reason (see the #ifndef block at the top of
 * federation/link.h): a build default serves a deployment and a per-process
 * override serves a case whose slowness must not become the next case's
 * slowness.
 *
 * IT IS NOT A TEST HOOK, and the difference is the same one
 * federation/link.h draws between fed_set_timeouts() and a test-only symbol: it
 * is a per-process CONFIGURATION value with the same one-node-per-process
 * property the secret and the timers have, not a door into the implementation.
 * fed_open() is what makes that property safe, and nothing here is reachable
 * before it. The cost of the knob is that a second node in one process would
 * not see it -- which fed_open() already refuses to happen. */
void fed_burst_set_max_bytes(size_t max_bytes);

/* Is `verb` one of the five burst words? The guard chain asks this before its
 * own verb table, because a burst is a TRANSACTION and its five shapes have
 * nothing in common with the seven S-verbs' frozen shapes -- SBURSTC names the
 * channel FIRST and carries six parameters, and SBURSTM names it first and
 * carries three. Squeezing them into the same arity table would be a table whose
 * ranges are individually correct and collectively a lie.
 *
 * 1 for the five, 0 for anything else. Never -1: this is a membership question,
 * not a validation one, and the verb itself has already been checked to exist. */
int fed_burst_verb(const char *verb);

/* Send this node's full state to one peer. 0 on success, -1 on a refusal.
 *
 * WHAT "REFUSED" MEANS, precisely, because it is the whole of the budget
 * argument: NOTHING was queued. The burst is rendered into a staging buffer
 * first and only flushed to the link once every line is in hand, so a burst that
 * does not fit leaves the link, the peer and this node's own state exactly as
 * they were, and counts one n_burst_refused. A burst that WAS flushed and then
 * saturated mid-flush is a different event and a different failure: 3.4 drops
 * the link, the peer sees a transaction with no terminator, and -- because
 * SBURSTE's counts are asserted -- it discards the whole thing. That asymmetry
 * is the design working rather than two holes in it.
 *
 * `link` must be ESTABLISHED with a live connection; anything else is refused
 * and counted, because a burst onto a link that is not a route is a caller's
 * bug rather than a protocol event. */
int fed_burst_send(server_t *s, server_link_t *link);

/* Apply one inbound SBURST* line.
 *
 * IT TAKES THE LINK AS WELL AS THE MESSAGE, and the pass that specified this
 * function as `fed_burst_apply(server_t *, const message_t *)` did not have a
 * caller in mind: the link is how the transaction's peer is identified, and
 * behaviour (3) puts server_link_t::burst_done on the link. Without it there is
 * nothing to mark, and re-deriving the link from the message's prefix would be
 * a SECOND opinion about which link a line arrived on -- a line a peer RELAYED
 * carries a different prefix from the one it arrived on, and the guard chain
 * has already gone to the trouble of resolving the link from the connection's
 * peer name for exactly this reason (federation/verbs.c's G0 note).
 *
 * The message is the one the guard chain already parsed. Nothing here
 * re-parses a line and nothing here is reachable before G4 has decided the line
 * has a legal 2.4 identity: a burst is state replacement, so it is deduped and
 * loop-checked like anything else, and a REPLAYED burst is the worst case this
 * phase has.
 *
 * Returns 0 when the line was consumed -- including the case where it was
 * consumed and DISCARDED, because a malformed record or a lost line abandons the
 * whole transaction -- and -1 when the line was not a shape this module
 * recognises at all. */
int fed_burst_apply(server_t *s, server_link_t *link, const message_t *m);

/* Throw away an in-flight transaction, if there is one. Safe at any time and on
 * a link with no transaction open.
 *
 * THE CALLER IS A LINK GOING DOWN (federation/link.c's fed_link_down), and that
 * is the one discard a counts assertion cannot perform: a transaction that never
 * reaches its terminator because the link died has nothing to compare against,
 * and leaving the shadow open would mean the NEXT burst on the same link's name
 * started by appending to a half-built one.
 *
 * IT IS NOT CALLED FOR A MID-BURST GUARD REJECTION, and the reason is worth
 * stating because "discard on a guard rejection mid-burst" is the obvious rule
 * and this one is better. Every record a burst can carry is COUNTED -- nicks by
 * SBURST, channels by SBURSTC, members by SBURSTE's third count -- so a line
 * the guard chain drops (a replayed SBURSTN at G7, a hop-ceiling drop at G5, a
 * refusal at G9) makes the terminator's count disagree with what was
 * accumulated, and the transaction is discarded by that comparison. One rule
 * that catches every case is better than five call sites that each catch one,
 * and a caller that reached for this on a mid-burst drop would be adding a
 * second mechanism to a problem that has one. */
void fed_burst_abandon(server_link_t *link);

/* The resync, as a PRODUCT of the node rather than as a step in establishing
 * one.
 *
 * It is called from exactly one place today -- fed_link_established() in
 * federation/link.c, which is 2.3's single establishment transition -- and it is
 * a named function rather than an inline pair of lines for the two reasons the
 * other seams in this phase are named functions: Phase 9's link-failure and
 * reconnect handling needs to drive a resync on demand (8's "Link loss and
 * reconnect re-syncs channel state via SBURST"), and a test needs a second
 * caller. A test hook would be a symbol that only exists so a test can reach
 * past the node; this is the operation 8 says must exist, and the test is simply
 * its second caller.
 *
 * `link` must be ESTABLISHED. Anything else is a no-op rather than a refusal,
 * because the two callers are both legitimate reasons to be there and neither
 * is a bug. Returns what fed_burst_send() returned. */
int federation_resync(server_t *s, server_link_t *link);

#endif /* IRC_FEDERATION_BURST_H */
