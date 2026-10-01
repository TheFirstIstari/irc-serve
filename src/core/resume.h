/* resume.h -- a client's session window: what a reconnecting client gets back.
 *
 * Authority: docs/SERVER_DESIGN.md 2.1 (identity, and the channel-membership
 * fact that is a channel's), 2.2 (single writer, origin), 4.2/4.4 (the numerics
 * and verbs a restore is allowed to use), 3.1 (what a state change writes and
 * forwards) and 8 (the `Reconnect` acceptance item this closes).
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS IS, AND THE ONE DECISION THAT SHAPES IT
 * ---------------------------------------------------------------------------
 * A client whose TCP session dies reconnects, sends the same NICK and the same
 * USER, and is put back into the channels it was in with the per-channel prefix
 * flags it held. That is the whole feature.
 *
 * THE DECISION IS THAT IT IS **PLAIN RECONNECT-AND-REJOIN** AND NOT IRCv3
 * `RESUME`, and the reasoning is worth writing down because it is the kind of
 * decision a later reader mistakes for an omission:
 *
 *   IRCv3 `RESUME` is a *token* protocol. The client is issued an opaque token
 *   at registration, presents it on a new connection, and the server matches it
 *   to stored state. It is a real specification with a real client-visible
 *   surface: the `resume` and `sethostname` capabilities in `CAP LS`, a token
 *   the client must keep, a `FAIL RESUME_SESSION_NOT_FOUND` when it does not
 *   match, and a family of numerics (AWAYLEN, HOSTLEN, MODES, UNKNOWNCAP) that
 *   the specification defines.
 *
 *   Advertising `RESUME` in `CAP LS` and implementing the window below would be
 *   THE WORST OF BOTH WORLDS. A client reads `RESUME` in `CAP LS` and concludes
 *   the server keeps session state across a reconnect, so it will not re-JOIN
 *   the channels it was in -- and it will not, because this server restores them
 *   only for a client that presents the same nick and ident, which is a different
 *   condition from holding a token. Worse, a client that DOES implement the token
 *   protocol would send `RESUME <token>` as a CAP REQ, receive `NAK` from a
 *   server that has never heard of the capability, and -- correctly -- treat the
 *   session as lost. So the client is told something false, acts on it, and is
 *   wrong.
 *
 *   The other direction is worse still. A HALF-implemented `RESUME` is a
 *   capability that appears in `005`/`CAP LS` and does not do what it says, and
 *   every future reader's first instinct on finding this gap is to "fix" it by
 *   adding the CAP line. That is the specific outcome this comment exists to
 *   prevent: the fix that looks like tidying is the one that breaks clients.
 *
 *   SO THE CAPABILITY IS NOT ADVERTISED, and there is deliberately no `RESUME`
 *   token anywhere in this build. A client here reconnects, re-registers with the
 *   same nick and ident, and is rejoined. A client that wants to be sure of it
 *   can look for the `[observable] session_resume:` line in the node's own log.
 *
 *   THE COST, stated rather than implied: without a token, the node is matching
 *   on values the CLIENT ASSERTS. Two people behind one NAT share a host; a
 *   client that knows a nick and an ident can claim that window. This is a
 *   property of the design, not a bug in the implementation, and it is the same
 *   property the node already has for every other claim about a nick: there is
 *   no authentication on this node at all, so `NICK bob` from anyone is already
 *   `bob`. What the window adds is not impersonation but CHANNEL MEMBERSHIP and
 *   PREFIX FLAGS, and §2.2's rules about who may hold those are enforced on
 *   restore exactly as they are on a JOIN. See resume_apply() for the specific
 *   check that keeps the privilege half honest.
 *
 * ---------------------------------------------------------------------------
 * THE KEY, AND WHAT ELSE IS COMPARED
 * ---------------------------------------------------------------------------
 * A window is keyed on (nick, ident) and the host is compared as well. Those
 * three are the fields 2.1's hostmask is rendered from, so they are the fields
 * this node has about a client at all -- and each one has a stated reason for
 * being in the comparison rather than being decorative:
 *
 *   nick    2.1's registry key, folded. Without it there is no session.
 *   ident   conn_t::user, the USER parameter, folded. This is the one that
 *           matters most and the reason the feature is keyed on TWO fields rather
 *           than on the nick alone: an ident is chosen to identify a person
 *           across sessions, so a client that reconnects with the same ident is
 *           the ordinary case, while a client that reconnects with the same nick
 *           and a DIFFERENT ident is a different thing wearing the same name.
 *   host    conn_t::host, which is the OBSERVED peer address and not what the
 *           client typed (see handle_user()). It is the only field in the
 *           comparison that the client does not control, and it is therefore the
 *           only one that narrows anything. On a node behind a NAT or a proxy it
 *           narrows nothing, and that is stated here rather than left to be
 *           discovered: the comparison is a mismatch REFUSAL, not an
 *           authentication, and refusing a resume whose host changed is a
 *           correctness property (the session belonged to a different socket) and
 *           not a security claim.
 *
 * AND THE MODES ARE COMPARED, which is the load-bearing part of the whole
 * design and the reason the key is not just the two strings:
 *
 * A window records the per-channel `@`/`+` flags the client held. On restore
 * those flags are **re-derived from the channel**, not copied from the window,
 * and that distinction is the difference between a feature and a privilege bug:
 *
 *   - While the client was gone, an operator could have deopped it (`MODE -o`),
 *     or the channel could have been destroyed, or -- on a mesh -- the ORIGIN
 *     could have changed the prefix. A window that copied its recorded `@` back
 *     would hand the returning client operator status on a channel where it no
 *     longer has it, and the client would not know, because it never left.
 *   - So resume_apply() restores MEMBERSHIP, and then asks the channel for the
 *     flags it is willing to re-grant to this member. 2.2's single-writer rule
 *     is what makes that question answerable: the node that OWNS the channel
 *     decides, and a node that does not own it has only a cache and therefore
 *     re-grants nothing.
 *
 * The observable consequence, which is what the test asserts: a window's
 * recorded `@` is not honoured on a channel this node does not own, and an
 * operator status that the channel can no longer justify is dropped with a line
 * saying so.
 *
 * ---------------------------------------------------------------------------
 * THE WINDOW IS BOUNDED IN TIME, IN COUNT, AND IN SIZE
 * ---------------------------------------------------------------------------
 * Three separate bounds, because they defend against three separate things:
 *
 *   IRC_RESUME_WINDOW_MS   how long a window lives. The default is two minutes,
 *                          which is long enough for a TCP retransmit to finish
 *                          and a client library to reconnect, and short enough
 *                          that an operator who removes somebody's access does
 *                          not have to wait for the window to stop restoring it.
 *                          A client that reconnects after the window gets a
 *                          plain, un-resumed registration -- the same thing it
 *                          would have got with no feature at all.
 *   IRC_RESUME_MAX         how many windows the node holds at once. This is a
 *                          per-node memory bound, and the pressure it answers is
 *                          a scripted client that connects and disconnects in a
 *                          tight loop. Reaching it drops the OLDEST window, not
 *                          the newest, because the newest is the one somebody is
 *                          about to reconnect to.
 *   IRC_RESUME_MAX_CHANS   how many channels ONE window records. A user in four
 *                          hundred channels has a window that is four hundred
 *                          entries, and the entry size is fixed by this header
 *                          rather than by the user, so a user cannot make the
 *                          table grow. The channels beyond the bound are NOT
 *                          restored, and the loss is counted and said out loud
 *                          rather than being silent.
 *
 * WHERE EVERY ENTRY IS RELEASED, and this is the part a leak checker is for:
 *
 *   1. ON USE. resume_apply() removes the entry it matched, in the same call
 *      that applies it, BEFORE any restore work happens. A window is one-shot:
 *      a second connection with the same nick and ident does not get the same
 *      window a second time. That is both the security property (a window cannot
 *      be replayed) and half the leak story (the common path frees immediately).
 *   2. ON EXPIRY PLUS A GRACE. This one has two stages and the second exists
 *      because of a requirement about the WIRE, which is worth setting out
 *      because the obvious implementation cannot satisfy it.
 *
 *      The obvious implementation frees a window the moment it ages out. It is
 *      also wrong, and demonstrably so: the sweep runs on a TICK, so by the time
 *      a client that came back too late actually arrives, the entry is usually
 *      already gone -- and a client whose window was freed rather than refused
 *      gets NOTHING. No restore and no word about it, which is indistinguishable
 *      from a server that never had the feature, and a client cannot report a
 *      bug about a feature it was never told about.
 *
 *      So expiry is two stages. A window that ages out is RETIRED -- marked, kept,
 *      and reported -- and a retired window is refused with a NOTICE the client
 *      renders. It is FREED a further IRC_RESUME_GRACE_DIVISOR-th of the window
 *      later, so a client arriving after the sweep still finds the tombstone and
 *      is told, and a tombstone nobody claims is released anyway.
 *
 *      THE COST, stated because "expired windows are kept for longer" sounds like
 *      a leak and is not: the table's worst-case occupancy is unchanged, because
 *      a window's total life is window + window/divisor rather than window, and
 *      every entry still ends in one of the four paths below. The memory is
 *      bounded by the same IRC_RESUME_MAX at the same size.
 *   3. ON EVICTION. Reaching IRC_RESUME_MAX drops the oldest, and the drop is
 *      counted.
 *   4. ON SHUTDOWN. resume_close() frees the table, and it is an ARM in
 *      server_shutdown() next to fed_burst_close() and fed_nickreg_close(). It
 *      prints whether the table was OPEN, so the arm can be asserted on a
 *      platform whose LeakSanitizer does not run -- the same argument
 *      server_shutdown() makes about the burst shadow.
 *
 * ---------------------------------------------------------------------------
 * THE CHANNEL HOLD, AND IT IS SHORTER THAN THE WINDOW ON PURPOSE
 * ---------------------------------------------------------------------------
 * A window HOLDS the channels it names, and the hold has its own, much shorter,
 * bound. Without it the feature is worthless on the common case: a client that
 * drops is parted out of every channel it was in, so a client who was the only
 * member of every channel it was in leaves every one of them with nothing left
 * to remember it for, and the restore finds nothing to put the client back into
 * -- on a single-client node, silently.
 *
 * THE HOLD IS window/2 CLAMPED TO [1000ms, 5000ms], and the clamp is the part
 * worth arguing about, because the hold is the one thing here that changes a
 * behaviour another phase's test asserts. 2.2's disposal rule is "a channel with
 * no local member and no member-server has nothing left to be authoritative
 * about", and tests/integration/test_topic_persist.c empties a channel by DROPPING
 * one client and QUITting the other -- which is exactly the pair of events that
 * records a window -- and then waits for `chan_destroy` with a fifteen second
 * deadline. A hold of the full window would make that wait fail, because the
 * shipped window is two minutes.
 *
 * So the hold is a SEPARATE, SHORT, DERIVED bound, and the reasoning is about
 * the population the feature serves rather than about the test: a client whose
 * session was lost is reconnecting within a second or two, because its library
 * noticed the socket go away and its user did not. A hold of a few seconds
 * covers that population completely. A hold as long as the window would cover
 * clients that are NOT coming back, at the cost of keeping a channel alive for
 * two minutes after its last member left -- which is 2.2's rule with a hole in
 * it, for a population that does not exist.
 *
 * THE 1000ms FLOOR IS FOR SHORT WINDOWS, and it is what makes the two clamps
 * pull in opposite directions rather than fighting: a test that shortens the
 * window to 400 ms wants a hold it can also wait out, and a shipped window wants
 * a hold long enough to be worth having. The floor is above the sweep interval
 * (window/16) at every window length this build can be given, which is what
 * guarantees a hold is checked at least once while it is in force.
 *
 * AFTER THE HOLD, THE CHANNEL IS OFFERED BACK to chan_dispose_if_empty() by the
 * sweep, and the window is STILL THERE and STILL RESUMABLE -- the hold is about
 * the channel's lifetime, not about the window's. A client that comes back
 * inside the hold finds its channel; one that comes back later is told which of
 * its channels did not survive, which is a fact a client can act on and a silent
 * omission is not.
 *
 * THE TABLE IS LAZILY ALLOCATED, for the reason 2.1's and the dedup table's are
 * lazily allocated: a node that has never had a client drop pays nothing, and a
 * single-node deployment is most nodes.
 */
#ifndef IRC_CORE_RESUME_H
#define IRC_CORE_RESUME_H

#include <stddef.h>
#include <stdint.h>

/* channel.h for CHAN_MAX_NAME and CHAN_MEMBER_*, and it in turn brings
 * connection.h, so this one include is the whole of what the declarations below
 * need. server.h is deliberately NOT included: the functions take a server_t*
 * and never touch a field, and including it here would make every caller of this
 * header pull in the federation handshake for no reason. */
#include "core/channel.h"

/* The window, and the reason it is two minutes rather than a number somebody
 * liked. A dropped TCP session on a lossy path is recovered by the client
 * library within a couple of seconds; the two minutes are slack for a client
 * that is being restarted, and they are SHORT on purpose: a window is a set of
 * channel memberships with prefix flags, and the longest it should be possible
 * for a removed operator to come back with operator status is bounded by
 * something a person can wait out. */
#define IRC_RESUME_WINDOW_MS ((uint64_t)120000u)

/* How much LONGER than the window a retired window is kept, as a divisor of the
 * window: a window is freed a window/3 after it stopped being resumable.
 *
 * IT IS A DIVISOR OF THE WINDOW rather than an absolute interval, for the same
 * reason the sweep throttle is: the tombstone has to outlive the sweep interval
 * by a comfortable margin, and the sweep interval is itself tied to the window,
 * so tying the grace to it as well keeps the ratio -- and therefore the
 * guarantee that a tombstone survives several sweeps -- constant across the whole
 * range of window lengths. An absolute grace would have to be chosen against the
 * shipped two minutes and would be far too long for a test's 400 ms window,
 * which is the failure mode fed_dedup_sweep()'s occupancy half avoids by
 * construction. */
#define IRC_RESUME_GRACE_DIVISOR ((uint64_t)3u)

/* The sweep throttle, as a divisor of the window. server_tick() asks
 * resume_sweep() at most once per window/this, so the walk happens about once
 * every seven seconds at the shipped two minutes while still expiring a window
 * within a sixteenth of its lifetime of its real expiry.
 *
 * IT IS A DIVISOR AND NOT AN ABSOLUTE INTERVAL, and the reason is that a fixed
 * interval is wrong at both ends of the range this constant is tuned for: a
 * 50 ms interval would walk 64 records twenty times a second to expire nothing,
 * and a fixed multi-second interval would be the wrong fraction of a window
 * somebody has shortened to 400 ms for a test. Tied to the window, the sweep
 * cost is a constant fraction of the thing it is bounding.
 *
 * The divisor is clamped at 1 so a window shorter than the divisor still gets
 * swept every tick rather than dividing to zero. */
#define RESUME_TICK_DIVISOR ((uint64_t)16u)

/* Windows per node. A flat array of POD with no per-entry allocation, so the
 * whole table is one calloc and one free; see the teardown argument above. */
#define IRC_RESUME_MAX ((size_t)64u)

/* Channels per window, and therefore the fixed size of a window's channel
 * array. This is what makes a user's membership count unable to grow the table:
 * the array is inside a fixed-size record, so the table's size is a function of
 * IRC_RESUME_MAX alone and not of anything a client did. */
#define IRC_RESUME_MAX_CHANS ((size_t)16u)

/* What resume_note() saw when the client left: one channel it was in and the
 * prefix flags it held. The flags are RECORDED and not re-granted, which is
 * resume.h's whole argument; see resume_apply() for what happens to them. */
struct resume_chan {
    char     name[CHAN_MAX_NAME + 1];
    unsigned flags; /* CHAN_MEMBER_OP | CHAN_MEMBER_VOICE, as for a local one */
};

/* ---------------------------------------------------------------------------
 * The three calls
 * ---------------------------------------------------------------------------
 */

/* Record a window for `c`, which is about to be torn down. Called from
 * server_close_conn() BEFORE chan_conn_gone(), because the channel set lives on
 * the connection and is released by that call -- so a window noted after it would
 * record an empty channel list and restore nothing.
 *
 * A no-op for a connection that is not CONN_REG_READY: a client that never
 * registered has no session to resume, and one that was refused a nick has none
 * either. A no-op for a CONN_SERVER link, which is a peer and not a session.
 *
 * An explicit QUIT DOES NOT RECORD A WINDOW, and that is a decision rather than
 * an omission. A QUIT is a statement that the client is leaving, and a client
 * that says so and then reconnects is a client that re-joins by hand -- which is
 * what every client does today and what would keep working. A window on a QUIT
 * would also mean a user could not sign out: reconnecting with the same nick
 * inside the window would put them back, with no way to decline it. The feature
 * is for a session that was LOST, and a lost session cannot send a QUIT. */
void resume_note(server_t *s, const conn_t *c, uint64_t now_ms);

/* Re-join the connection `c` to whatever `window_for()` matches, and consume
 * that window. Returns 1 if a window was applied, 0 if there was none (which is
 * the ordinary case and is not an error), -1 on a bad argument.
 *
 * IT IS CALLED FROM ONE PLACE -- commands_state_update() on the transition into
 * CONN_REG_READY, after the welcome burst -- and that is the only place a
 * connection has all three of nick, ident and host and is about to be addressed
 * as a client. A restore needs a registered client because it re-joins channels,
 * and a JOIN needs a registered client because 3.1's table is keyed on the
 * connection's class.
 *
 * A window is REMOVED BEFORE THE RESTORE WORK and not after it, so a restore
 * that fails halfway has still consumed the window. The alternative -- leaving it
 * -- would make a partial restore replayable, and a replayable window is a
 * window a second connection can complete. */
int resume_apply(server_t *s, conn_t *c, uint64_t now_ms);

/* The window matching `c`'s (nick, ident, host), or NULL. Exposed for the
 * reason every predicate in this codebase is exposed: a caller that wants to
 * know whether a resume is going to happen should ASK rather than infer it from
 * a struct. Returns NULL on an expired or absent window WITHOUT consuming it --
 * the consumption is resume_take()'s job, and a predicate that freed the thing
 * it was asked about would be a predicate with a side effect. */
const struct resume_chan *resume_window_for(const server_t *s, const conn_t *c,
                                            uint64_t now_ms, size_t *count_out);

/* ---------------------------------------------------------------------------
 * The clock, and the sweep
 * ---------------------------------------------------------------------------
 */

/* Set the window length for this process. The house pattern (fed_set_timeouts(),
 * fed_set_retry()) is a per-process override rather than a flag, because a test
 * that has to wait out a two-minute window is a test that either takes two
 * minutes or lies. Called before the window table is used; a value of 0 is
 * refused rather than clamped, because "no window" and "a window that expires
 * immediately" are different configurations and only one of them is expressible
 * by turning the feature off.
 *
 * THIS IS A TEST AND OPERATIONS KNOB, and it is deliberately not on the command
 * line: a flag that changes how long a removed operator stays restorable is a
 * flag that belongs to whoever embeds this library, not to whoever can reach the
 * process. */
void resume_set_window(uint64_t window_ms);

/* The current window length, in milliseconds. Exposed because the sweep's
 * behaviour is a function of it and a reader should be able to ask. */
uint64_t resume_window_ms(void);

/* Is any LIVE window still holding a claim on `chan`? 1 if so, 0 if not.
 *
 * IT EXISTS BECAUSE OF THE CHANNEL'S LIFETIME, and the reason is the single
 * worst thing that could happen to this feature if it were not here.
 * chan_dispose_if_empty() destroys a channel that has no local members and no
 * remote ones, and a client that drops is parted out of every channel it was in
 * -- so a client who was the ONLY member of every channel it was in destroys all
 * of them at the moment it drops, and the window that was just recorded names
 * channels that no longer exist. The restore would then find nothing to put the
 * client back into, SILENTLY on the common case of a single-client node.
 *
 * So the channel is RETAINED for as long as a window names it, and the cost is
 * stated: a channel kept alive by a window is a channel LIST reports and NAMES
 * answers for, and the window is bounded in time, so the retention is bounded in
 * time too. That is a different thing from chan_dispose_if_empty()'s usual
 * reasoning, which is "has run out of reasons to exist" -- and the retention IS
 * a reason to exist: a client is coming back to it.
 *
 * The caller is channel.c's chan_dispose_if_empty(), and the reclaiming side is
 * resume_sweep(): when a window goes, every channel it was holding is offered
 * back to chan_dispose_if_empty(), which disposes the ones that have run out of
 * other reasons. That is the pair, and having only one half would be a leak in
 * one direction (a window that holds a channel forever) or a broken feature in
 * the other (a channel destroyed before the client returns). */
int resume_holds(const server_t *s, const char *chan);

/* How long a window holds its channels, in milliseconds. Derived from the window
 * and clamped, so a caller that sets the window has set this too and there is no
 * second knob to get out of step. The derivation is stated at the top of this
 * file; the short version is that it is window/2 clamped into [1000, 5000]. */
uint64_t resume_hold_ms(void);

/* Drop every window older than the bound. Returns how many went.
 *
 * DRIVEN FROM server_tick() and not from any client path, because a table whose
 * only expiry is "somebody happened to log in" is a table that never expires on
 * a quiet node -- and a quiet node is exactly the node whose windows are all
 * stale. The sweep also runs on a throttle for the same reason
 * fed_dedup_sweep()'s does: expiry is O(windows) and nothing about it needs
 * doing more than a few times a second.
 *
 * IT IS ALSO THE ARM THAT BOUNDS MEMORY between resumes, and it is the reason
 * IRC_RESUME_MAX is a backstop rather than the primary bound. */
size_t resume_sweep(server_t *s, uint64_t now_ms);

/* ---------------------------------------------------------------------------
 * Teardown, and the counters
 * ---------------------------------------------------------------------------
 */

/* Free the window table. The ARM, called from server_shutdown() next to
 * fed_burst_close() and fed_nickreg_close(), and it prints whether the table was
 * OPEN so the arm can be asserted on a platform whose LeakSanitizer does not
 * run. Safe on a server that never allocated one, and safe on NULL. */
void resume_close(server_t *s);

/* Windows currently held. 0 on a node that has never had a client drop, which is
 * every node with no such history. */
size_t resume_count(const server_t *s);

#endif /* IRC_CORE_RESUME_H */
