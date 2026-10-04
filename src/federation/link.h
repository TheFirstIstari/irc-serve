/* link.h -- 2.3's peer link: the table, the FEDERATE exchange, and the tick.
 *
 * Authority: docs/SERVER_DESIGN.md 2.3 (servers and peers; peer auth is not
 * user SASL; server-name uniqueness is enforced AT the handshake), 4.3
 * (`FEDERATE` is the link handshake and reuses the existing FSM), 3.4 (the
 * poll tick drives time; the send path never closes; a saturated link is
 * dropped), 2.4 (per-boot epoch, per-server ids) and 8 (peers and their FSM
 * states must be dumpable).
 *
 * ---------------------------------------------------------------------------
 * WHAT IS HERE AND WHAT IS NOT
 * ---------------------------------------------------------------------------
 * The link LIFECYCLE and the handshake, and nothing else. This file can take a
 * peer from "configured" to "ESTABLISHED", keep it alive, notice that it is not,
 * say so on stdout, and tell the node's other peers that its own name is going
 * away (a `SQUIT`, queued from fed_link_down() and emitted straight onto the
 * wire rather than through the forwarded-verb table, for the reason the function
 * states). It does not carry messages: the inbound S-verb guard chain and its
 * handlers are federation/verbs.c's fed_dispatch() (C3), and the
 * resync is federation/burst.c's -- which this file CALLS, at establishment and on
 * link-down, and does not implement. The consequence to be aware of while reading
 * the tick is written out under "WHAT T3 COSTS A TEST" below -- it is the one place
 * where this file's behaviour changes a number a Phase 5 test asserts on.
 *
 * ---------------------------------------------------------------------------
 * THE EXCHANGE, AND WHY IT IS SYMMETRIC
 * ---------------------------------------------------------------------------
 *   -> :irc.b FEDERATE irc.b <epoch> <secret> irc-serve-0.1.0
 *   <- :irc.a FEDERATE irc.a <epoch> <secret> irc-serve-0.1.0
 *
 * Both sides send it, because 2.3 says a peer "is rejected before ESTABLISHED"
 * and that is only meaningful if the rejection is symmetric: a node that
 * accepted a claim without ever making one of its own would be a node that
 * authenticates half the mesh. The version word is IRC_SERVE_VERSION, the ONE
 * copy of it in the tree (core/server.h) -- a second copy here would be a
 * version number that is eventually wrong in one of the two places.
 *
 * The accepting side does NOT wait for the reply it queues. It has already
 * learned the peer's name and epoch, and it has proved itself by queueing its
 * own claim; the reply it sends is what the peer needs in order to learn the
 * same. So the accept path is one poll iteration, INIT -> HANDSHAKE_SENT ->
 * ESTABLISHED, rather than a round trip that would put a peer's link lifetime
 * at the mercy of a busy peer. The cost of not confirming is stated: a node
 * that queues its FEDERATE and dies before flushing leaves the peer believing
 * a link that is not there, and the peer discovers it on its own T2/T4 rather
 * than from an answer. That is the same outcome, one timeout later.
 *
 * ---------------------------------------------------------------------------
 * A LINK IS NOT A CONNECTION, AND NOTHING HERE ROUTES BY A COPY OF A NAME
 * ---------------------------------------------------------------------------
 * server_link_t is a name plus at most one descriptor (core/server.h spells out
 * why, and why conn_t::peer_name is a display copy rather than the authority).
 * A link exists from the moment a peer is CONFIGURED -- before there is a
 * socket at all -- and it is a route only while its state is ESTABLISHED,
 * which is server_find_peer()'s job and not this file's.
 *
 * ---------------------------------------------------------------------------
 * WHAT T3 COSTS A TEST -- READ THIS BEFORE ASSERTING ON lines=
 * ---------------------------------------------------------------------------
 * T3 queues a keepalive PING on every ESTABLISHED link every
 * IRC_FED_KEEPALIVE_MS, and every line a node RECEIVES is framed by
 * core/poll_loop.c and counted in s->n_lines. So on a two-node child the
 * peer's keepalives are inbound lines, and `lines=` on a linked node climbs on
 * its own with no client involved.
 *
 * A two-node test must therefore assert `lines=` with nf_expect_u64_ge() and
 * NEVER with equality. A test that asserts lines=N on a linked node is
 * asserting a race against a 30-second timer, and it will pass on a fast
 * machine and fail on a loaded one. This is the same rule 6.3 states for
 * sleeps, applied to a number the node increments by itself.
 *
 * ---------------------------------------------------------------------------
 * WHERE last_recv_ms IS STAMED, AND WHY IT IS NOT IN poll_loop.c
 * ---------------------------------------------------------------------------
 * A received line IS the liveness signal: 3.4 puts link liveness on the tick,
 * but the tick only compares, and the thing it compares against has to be
 * stamped where the line is seen. That is this module's dispatch seam, not
 * core/poll_loop.c -- which stays byte-for-byte unchanged by this phase. A
 * received line from a peer is stamped on the link; a line from a client is
 * not stamped at all, because no client's traffic says anything about whether
 * a peer is alive. (conn_t::last_active exists for the 317 half of the same
 * idea and is deliberately a different field for a different question.)
 *
 * The clock is read with server_now_ms() here rather than taken from the tick.
 * That is the same trade dial_t::started_ms makes and for the same reason: a
 * stamp taken from the tick would be the tick's, and a line that arrived 40 ms
 * into a 50 ms tick would claim to have arrived at the tick boundary.
 *
 * ---------------------------------------------------------------------------
 * THE RECONNECT POLICY, WHICH PHASE 9 ADDED AND WHERE EACH PIECE LIVES
 * ---------------------------------------------------------------------------
 * A link that fails -- a dial that times out (T1), a handshake that never
 * answers (T2), a peer that goes silent (T4) -- returns to INIT with no
 * descriptor, and T7 would then dial it again on the very next tick. That is a
 * hot loop against a black-holed peer, so the tick does not do it: the link
 * carries a SCHEDULE and the tick only acts on it when the schedule says a
 * dial is due. Three numbers, all in the tick's own arithmetic:
 *
 *   server_link_t::retry_at_ms   the earliest stamp at which T7 may dial. 0
 *                                means "due now", which is the state a
 *                                freshly CONFIGURED link is in -- so the first
 *                                dial is immediate and only a FAILED one waits.
 *   server_link_t::retries       consecutive failed attempts, reset to 0 by
 *                                fed_link_established() because a link that
 *                                came up is not in the same state as one that
 *                                never did.
 *   server_link_t::gave_up       the budget is spent; T7 refuses until an
 *                                operator resets the link. A non-zero value
 *                                here is a REPORT, not a metric: this node has
 *                                decided it will not keep knocking.
 *
 * THE BUDGET IS WHAT MAKES THE BACKOFF FINITE, and it is the whole of why a
 * retry forever is a defect rather than a virtue: a node retrying a dead peer
 * for ever spends a descriptor, a timer wake-up and an outbound connect on
 * every tick interval for the life of the process, and reports nothing. The
 * exhaustion is loud -- `[observable] link_retry_exhausted:` -- because the
 * operator's next question is "why has irc.b been unreachable all morning",
 * and a silent stop does not answer it.
 *
 * WHY THE RESET IS PER-LINK AND NOT GLOBAL: a mesh has more than one peer, and
 * a policy that gave up on every link because one of them is dead would turn a
 * single unreachable node into an outage for the rest. `gave_up` is a property
 * of the link that earned it.
 *
 * ---------------------------------------------------------------------------
 * THE INTERVALS, AND WHICH OF THEM ARE DERIVED
 * ---------------------------------------------------------------------------
 * Every one of the four link timers above (IRC_FED_DIAL_TIMEOUT_MS,
 * IRC_FED_HS_TIMEOUT_MS, IRC_FED_KEEPALIVE_MS and the derived IRC_FED_DEAD_MS)
 * has a documented derivation or an admitted convention. The three this phase
 * adds are the same three kinds, and the derivations are:
 *
 *   IRC_FED_RETRY_BASE_MS  DERIVED as a multiple of IRC_FED_DEAD_MS. A link
 *                          that has just been declared dead has been silent
 *                          for a whole dead window, so re-dialling it
 *                          IMMEDIATELY would be dialling a peer that has not
 *                          yet had time to have finished dying. One further
 *                          dead window is the smallest delay that is not
 *                          smaller than the evidence that produced the retry.
 *   IRC_FED_RETRY_MAX_MS   DERIVED as a multiple of the base, and the multiple
 *                          is IRC_FED_RETRY_MAX_STEPS: the cap IS the top of
 *                          the ladder, written as the ladder's own length
 *                          rather than as a number, so raising the step count
 *                          moves the ceiling with it.
 *   IRC_FED_RETRY_BUDGET   NO DERIVATION, and it is a policy number: it is how
 *                          many times this node will knock on one door before
 *                          it stops. Three is the smallest that survives a
 *                          single missed packet, and it is stated here as a
 *                          convention for the same reason the 3 in
 *                          IRC_FED_DEAD_MS is: there is nothing in this
 *                          codebase to derive it from, and an invented
 *                          argument for a specific figure would be worse than
 *                          an admitted one.
 *
 * ---------------------------------------------------------------------------
 * THE TICK'S THREE ARMS, AND WHY THE POLICY IS NOT IN A SEPARATE SUBSYSTEM
 * ---------------------------------------------------------------------------
 * The policy is two static functions and three comparisons inside fed_tick()'s
 * existing per-link walk, not a new module. The reason is the cost: a policy
 * that needed its own table would need its own walk over the same links, and
 * the walk is the only per-tick cost a linked node has. Two integer comparisons
 * against fields the link already has is free; a second loop is not. What this
 * DOES cost is that the policy is not separately testable, and the answer to
 * that is that the tests drive a real link through real failures and read the
 * node's own account of its schedule (test_failover_reconnect), which is the
 * only kind of assertion this project accepts anyway.
 *
 * ---------------------------------------------------------------------------
 * WHICH FAILURES ARM THE SCHEDULE, AND WHICH ONE DOES NOT
 * ---------------------------------------------------------------------------
 * Two of the three do, and the one that does not is the interesting one:
 *
 *   T4  a peer that went silent after being up. THE FAILOVER CASE, and the
 *       heartbeat is what drives it: there is no other event in this node that
 *       means "a peer I had a route to is gone".
 *   T1  a connect() that never completed, i.e. a peer that is down rather than
 *       unreachable. A black-holed host produces no FIN and no ESTABLISHED and
 *       therefore no T4, so a budget that did not cover T1 would bound the wrong
 *       case: the peer that is merely unreachable is the one a mesh spends its
 *       time on.
 *   T2  a handshake that was never answered. A peer that accepts TCP and then
 *       goes silent -- a hung process, a firewall with a half-open table, a node
 *       stopped with SIGSTOP whose kernel still completed the three-way handshake
 *       -- which is the most common way a peer is "there but not talking".
 *
 * ---------------------------------------------------------------------------
 * ALL THREE ARM, AND ONLY ONE OF THEM ANNOUNCES -- WHICH IS WHY THE TEARDOWN
 * TAKES A FLAG
 * ---------------------------------------------------------------------------
 * T4 and T2 both reach the same teardown, and the difference between them is not
 * a detail: **a link that was ESTABLISHED and went away means peers should forget
 * this node's roster; a link whose handshake never completed means they should
 * not, because they never learned anything through it and this node's other links
 * are still up.** Announcing on the T2 path would tell a healthy mesh that a live
 * node had departed, and every peer would purge a live node's roster on the word
 * of one socket that never authenticated.
 *
 * So fed_link_down() takes an `announce` argument, and it is a parameter rather
 * than something the shared body decides because the shared body cannot know --
 * by the time it runs, both cases are "a link with no descriptor and no route".
 * The three call sites are T4 (announces), T2 (does not) and fed_link_reset()
 * (announces, because an operator resetting a link is declaring this node
 * off-peer whatever the link's own state was).
 *
 * ---------------------------------------------------------------------------
 * T2 TAKES THE LINK BACK TO INIT, AND THAT IS A CORRECTION RATHER THAN A NEW RULE
 * ---------------------------------------------------------------------------
 * Phase 6 left TIMED_OUT terminal, on the reasoning -- recorded at the time, and
 * still right about the ANNOUNCEMENT -- that "a handshake that never completed
 * has nothing to tear down". It was over-applied to the STATE, and the cost was
 * that a hung peer cost this node one dial and no retry for the life of the
 * process: the same unbounded waiting the budget exists to bound, reached by a
 * different road.
 *
 * A test found it. tests/integration/test_failover_reconnect.c freezes a peer
 * with SIGSTOP, which leaves the socket open AND leaves the kernel accepting on
 * the listener, so the retry's connect() succeeds and the FEDERATE is never
 * answered -- T2, not T4. Against the Phase 6 behaviour the retry ladder stopped
 * after one rung, and the only reason it was noticed is that the test asserts on
 * the SECOND rung. That is what a teeth test is for, and the fix is four lines:
 * arm the schedule, and take the link back to INIT so there is something for the
 * schedule to act on.
 *
 * The cost of the correction, stated because "TIMED_OUT is now transient" is a
 * change three other readers can see: the link dump shows INIT rather than
 * TIMED_OUT for a link whose handshake expired, and a link dump is a diagnostic
 * tool, so a reader looking for "did the handshake time out" must read the
 * `link_timeout: ... state=TIMED_OUT` line (which still says so) rather than the
 * dump's state field. The alternative was leaving the terminal state and arming
 * a schedule nothing reads, which is a lie told to a log reader.
 *
 * ---------------------------------------------------------------------------
 * C2's LATCH IS GONE, AND THIS PARAGRAPH IS THE RETRACTION
 * ---------------------------------------------------------------------------
 * Until this phase the no-auto-redial rule was a single field:
 * server_link_t::created_ms was stamped at the dial and NEVER cleared, so T7's
 * condition `created_ms == 0` was false for the life of the process and
 * fed_link_reset() was the one-line escape. That field is STILL stamped at the
 * dial -- it is what T2 compares against, and 3.4's file map describes the
 * stamp -- but T7 no longer reads it as a latch. The claim "a failed link is
 * never re-dialled" is now false and is replaced by "a failed link is
 * re-dialled on a backoff, up to a budget, and the exhaustion is reported".
 *
 * ---------------------------------------------------------------------------
 * THE LIMITATION C2 LEAVES, NAMED
 * ---------------------------------------------------------------------------
 * Two nodes that BOTH list each other as a peer both dial, and neither
 * accepts. A's link for B is in HANDSHAKE_SENT when B's inbound FEDERATE
 * arrives on a second descriptor; the name-uniqueness check skips only the
 * link the exchange is ON, finds that HANDSHAKE_SENT link, and answers
 * FED_NAME_IN_USE. Symmetrically, B refuses A. The result is a mesh where both
 * nodes configured each other and neither has a link.
 *
 * This is deliberate, not an oversight: 2.3's rule is "first to ESTABLISHED
 * for a name wins", and reconciling two half-open exchanges into one link is
 * link-failure-and-reconnect work, which 7/Phase 9 owns. Until then a
 * deployment configures each pair in ONE direction, and the two-node fixtures
 * (including this commit's own test) do the same. A C3 or C4 test that
 * configures both directions will see no link at all, and that is the symptom
 * to recognise.
 *
 * A FOUR-node fixture (tests/integration/test_fed_resync.c) configures each of
 * its three pairs in one direction for the same reason, and it needs four nodes
 * for a reason of its own that comes from the same corner: a link that goes down
 * announces this node's departure to the peers that are still up, so a two-node
 * mesh has nobody to announce to and the announcement cannot be observed at all.
 */
#ifndef IRC_FEDERATION_LINK_H
#define IRC_FEDERATION_LINK_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "core/message.h"
#include "core/server.h"

/* ---------------------------------------------------------------------------
 * The four link timeouts
 * ---------------------------------------------------------------------------
 * Every one of them is a #define rather than a literal at its use, for the
 * reason IRC_MAX_HOPS gives: a number written at two comparison sites is a
 * number that agrees today and can drift, and a link timeout that disagrees
 * between the tick that applies it and the test that waits for it is a flaky
 * test rather than a wrong one.
 *
 * Each is wrapped in #ifndef so a build can supply a different one. That is a
 * BUILD-time default and it is not how a test uses it -- every case in
 * tests/integration/test_fed_handshake.c lives in ONE executable, so a
 * compile-time value would make a 5-second wait a property of the binary
 * rather than of the case. fed_set_timeouts() below is the per-process
 * override those cases use, and they call it in the CHILD, after fork, which
 * is why "in the child's own process" is a real statement and not a
 * description.
 */

/* How long a connect() may stay DIAL_CONNECTING before this node gives up on
 * it.
 *
 * The floor is DERIVED and it is a real one: it must be many multiples of
 * POLL_TICK_MS (50), or a dial that completed in less than a tick would be
 * timed out by the very tick that armed it. 10000 is 200 ticks, so the
 * ordinary loopback connect is not in danger by a factor of two hundred.
 *
 * The ceiling is CONVENTIONAL, and saying so is better than inventing a
 * derivation: the property 3.4 actually requires is that a connect() to a host
 * that silently drops the SYN must not sit in the table forever, because poll()
 * reports nothing at all for it. Any figure in the seconds satisfies that.
 * What the figure does buy is that a dial across a real network -- where an
 * RTT is tens of milliseconds and a busy peer's accept queue can be deep --
 * has room to be slow once before it is called a failure. */
#ifndef IRC_FED_DIAL_TIMEOUT_MS
#define IRC_FED_DIAL_TIMEOUT_MS 10000
#endif

/* How long a link may sit in HANDSHAKE_SENT before this node gives up on it.
 *
 * DERIVED from the shape of the exchange rather than picked: the handshake is
 * one line each way on a connection that is ALREADY established (3.4 puts the
 * connect in its own state machine, and a link in HANDSHAKE_SENT is past it),
 * so nothing here waits on anything and the only thing being paid for is one
 * round trip plus the scheduling jitter of a loaded machine. 5000 is 100
 * POLL_TICK_MS ticks, which is a round trip that is four orders of magnitude
 * slower than loopback and still generous. */
#ifndef IRC_FED_HS_TIMEOUT_MS
#define IRC_FED_HS_TIMEOUT_MS 5000
#endif

/* How often an ESTABLISHED link is probed.
 *
 * The cost is one line per peer per interval, and that is the whole of the
 * per-tick cost of a linked node: 30000 ms makes it 0.033 lines per second per
 * peer, which against the ~256 KiB write-queue bound of 3.4 is nothing, and
 * against the 50 ms tick is one comparison.
 *
 * The requirement it has to satisfy is not "be polite" but "be small next to
 * the dead threshold", because the multiplier below is what makes a dead link
 * detectable at all: at 3 missed probes, a keepalive interval of 30 s detects a
 * dead peer in 90 s. Halving it detects in 45 s at twice the line rate;
 * doubling it detects in 180 s at half the line rate. 30 s is the middle of
 * that trade and it is also the conventional IRC link-probe period. */
/* How often this node publishes its own load to each established peer.
 *
 * DERIVED from IRC_FED_KEEPALIVE_MS, deliberately equal to it, and that equality
 * is the requirement rather than a coincidence: an advertisement is a liveness
 * signal as well as a load figure, so the peer must never conclude "this node
 * has stopped advertising" and treat the mesh as degraded while T4 still
 * considers the link healthy. At equal intervals a peer that hears nothing has
 * heard nothing for a whole keepalive period, which is exactly the signal T4 is
 * already using. Making the advertise period SHORTER would spend lines to be
 * early on something T4 already detects; making it LONGER would make a healthy
 * peer look dead. 0 disables advertisement entirely, and the arm below honours
 * that, so a node can be run without publishing its load at all. */
#ifndef IRC_FED_ADVERTISE_MS
#define IRC_FED_ADVERTISE_MS IRC_FED_KEEPALIVE_MS
#endif

#ifndef IRC_FED_KEEPALIVE_MS
#define IRC_FED_KEEPALIVE_MS 30000
#endif

/* How long an ESTABLISHED link may hear nothing before it is declared dead.
 *
 * THE MULTIPLIER IS 3 AND THAT IS THE WHOLE JUSTIFICATION. It is not derived,
 * and it is written as the expression rather than as the literal 90000 for a
 * reason that is not cosmetic: as an expression, changing IRC_FED_KEEPALIVE_MS
 * changes the dead threshold with it, and a node whose probe period was
 * retuned without its dead threshold moving would either never notice a dead
 * peer or declare a live one dead.
 *
 * As for why three missed probes: that is the CONVENTIONAL threshold, and it
 * is the one number in this phase with no derivation behind it -- there is
 * nothing in this codebase to derive a multiple from. The only property that
 * can be stated is the one that makes three a reasonable guess rather than an
 * arbitrary one: it is more than one (a single missed probe is a dropped
 * packet, not a dead peer) and few enough that a link is not declared dead
 * while its peer is merely slow. An invented argument for a specific number
 * would be worse than an admitted convention, so it is admitted. */
#define IRC_FED_DEAD_MS (3 * IRC_FED_KEEPALIVE_MS)

/* ---------------------------------------------------------------------------
 * THE THREE RECONNECT INTERVALS -- Phase 9
 * ---------------------------------------------------------------------------
 * These are the BACKOFF, how far the ladder is allowed to climb, and the retry
 * budget. The derivations are in the header's reconnect-policy block; what is
 * here is the arithmetic and why each is wrapped in #ifndef.
 *
 * The #ifndef is for the reason the four timers above have it, and the two
 * mechanisms must not be confused: a BUILD-time default serves a deployment,
 * and a per-process override serves a test whose case must not make the next
 * case wait out real backoff. fed_set_retry() below is the override, and a
 * compile-time value would make a schedule a property of the binary -- every
 * case in one test executable sharing it -- which is the difference between a
 * test that takes 30 seconds and one that takes 300 ms.
 */

/* The first wait after a link has failed, and the base of the ladder.
 *
 * DERIVED as IRC_FED_DEAD_MS rather than as a fresh number, and the reason is
 * the evidence the retry is answering: a link declared dead has been silent for
 * a whole dead window, so dialling it again the instant it is declared dead
 * would be dialling a peer that has not finished dying. One more dead window is
 * the smallest wait that is not smaller than the evidence. The cost is stated:
 * with the shipped numbers the first retry is 90 s after the link went silent,
 * which for a peer that is genuinely restarting is 90 s of downtime this node
 * chose. A deployment that would rather retry sooner lowers
 * IRC_FED_KEEPALIVE_MS and this moves with it, which is the point of writing it
 * as the expression. */
#ifndef IRC_FED_RETRY_BASE_MS
#define IRC_FED_RETRY_BASE_MS IRC_FED_DEAD_MS
#endif

/* How many times the ladder doubles before the ceiling.
 *
 * NO DERIVATION, and it is a convention: four is the conventional doubling depth
 * (it reaches sixteen times the base in four retries), and there is nothing in a
 * retry policy to derive a step count from. It is admitted as a convention for
 * the reason the 3 in IRC_FED_DEAD_MS is admitted -- an invented argument for a
 * specific number would be worse than an admitted one. The consequence is
 * stated rather than left for a reader to work out: raising this to N lets the
 * wait reach base * 2^N, so it is the single number that decides how patient
 * this node is. */
#ifndef IRC_FED_RETRY_MAX_STEPS
#define IRC_FED_RETRY_MAX_STEPS 4
#endif

/* The ceiling, DERIVED as the top of the ladder rather than picked: the largest
 * wait the doubling can reach is base * 2^steps, and writing the ceiling as that
 * expression is what stops the two disagreeing when a deployment retunes the
 * base or the step count. The cast to uint64_t is deliberate and is what keeps
 * the multiplication from being done in int on a 32-bit target: base is a
 * millisecond count that a deployment may raise, and a shift of a 32-bit int by
 * a small amount is the one way this expression could wrap. */
#ifndef IRC_FED_RETRY_MAX_MS
#define IRC_FED_RETRY_MAX_MS                                                    \
    ((uint64_t)IRC_FED_RETRY_BASE_MS * (uint64_t)(1u << IRC_FED_RETRY_MAX_STEPS))
#endif

/* How many consecutive failures this node accepts for ONE link before it stops
 * knocking.
 *
 * NO DERIVATION -- a policy number, and the header says so where a reader would
 * otherwise look for a reason. The consequence worth stating is the asymmetry:
 * the budget is spent by FAILURES and fed_link_established() resets it, so a
 * peer that flaps gets an unlimited number of chances (one fresh budget per
 * success) while a peer that is simply dead gets exactly this many. That
 * difference is the whole of what separates a link policy from a link ban, and
 * it is why the budget is not a lifetime cap. */
#ifndef IRC_FED_RETRY_BUDGET
#define IRC_FED_RETRY_BUDGET 3
#endif

/* The bound on a configured shared secret.
 *
 * It is a bound on CONFIGURATION, not on the wire: the secret travels as one
 * IRC parameter, so the line bound is IRC_MAX_LINE (8192) and this is the
 * number that says a secret is a shared token rather than a payload. 128 is
 * twice the longest passphrase an operator is plausibly going to type into a
 * command line, and it is also the length of the buffer the constant-time
 * compare in link.c walks, so raising it is a per-rejection cost and not a
 * free edit. A longer secret is REFUSED by fed_open() rather than truncated:
 * a silently truncated secret is a weaker secret than the operator asked for
 * and the peer is configured with the full one, so the failure would be a link
 * that never authenticates. */
#ifndef IRC_FED_MAX_SECRET
#define IRC_FED_MAX_SECRET 128
#endif

/* ---------------------------------------------------------------------------
 * The FEDERATE verdict
 * ---------------------------------------------------------------------------
 * An enum rather than a bare int, because these names are a wire-adjacent
 * contract: they are what fed_federate_reason() prints after `reason=` in the
 * link_rejected line, and a test matches on those strings. The ORDER of the
 * members after FED_OK is the order fed_check_federate() tests them in, and it
 * is not an arbitrary one -- see that function.
 *
 * THE ORDER IS ALSO AN INDEX, and that is a second reason it is not arbitrary.
 * federation/link.c keeps a rejection counter per reason and a stable spelling
 * per reason, and BOTH are indexed by this enum, so a member's position is its
 * counter slot and its row in the name table. Adding a member is therefore
 * three edits that must agree -- here, FED_RESULT_COUNT, and the two tables in
 * link.c -- and link.c's comment on that count says what happens when they do
 * not. Two verdicts that mean different things to an operator sit in the order
 * the function reaches them, which is also the order the function's own comment
 * lists them in, so an enum member and the step that returns it are found in the
 * same place.
 */
typedef enum {
    FED_OK = 0,          /* the claim is acceptable                            */
    FED_BAD_ARITY,       /* not four parameters, or no :prefix at all          */
    FED_BAD_SECRET,      /* the offered secret did not match the configured one*/
    /* No secret is configured, so this node federates with nobody. NOT a form
     * of BAD_SECRET and not folded into it: see fed_check_federate() step 2 for
     * why an operator has to be able to tell a wrong guess from a node that is
     * not configured to authenticate, and for what it costs. */
    FED_NO_SECRET,
    FED_SELF_NAME,       /* the peer claimed THIS node's own name              */
    FED_NAME_IN_USE,     /* another link already holds that name               */
    FED_DUPLICATE_LINK,  /* a link ESTABLISHED to that name already exists     */
    /* This exchange is running on a link that has a DIFFERENT name. A
     * misconfiguration on one side of the pair rather than a second route to a
     * name, so it does not count as a duplicate and does not say DUPLICATE. */
    FED_NAME_MISMATCH,
    FED_BAD_NAME,        /* the claimed name is not a legal 2.4 tag value      */
    FED_BAD_EPOCH,       /* the peer's epoch is not a legal 2.4 epoch value    */
    FED_BAD_VERSION      /* the version word is not this node's                */
} fed_federate_result_t;

/* The stable spelling of a verdict, for the observable line and for tests.
 * Never NULL: an int that is not a member of the enum is reported as
 * "UNKNOWN" rather than as a NULL %s. */
const char *fed_federate_reason(fed_federate_result_t result);

/* Validate an inbound FEDERATE line and answer whether this node may link to
 * the name it claims.
 *
 *   s      the node.
 *   self   the link THIS exchange is running on, or NULL when the connection
 *          arrived on the listener and no link names it yet. It is skipped by
 *          the uniqueness check, because the link a handshake is running on is
 *          not a rival claim on the name it is handshaking about. NULL is the
 *          ordinary case on the accepting side and is not a special one.
 *   m      the parsed line. It is a parsed message_t rather than a string
 *          because the loop has already framed and parsed it (3.3) and
 *          re-parsing it here would be a second grammar that could disagree
 *          with the first.
 *   secret the shared secret to compare against. Passed in rather than read
 *          from a module global so that the check is a pure function of its
 *          arguments and can be reasoned about -- and tested -- without a node.
 *   peer_epoch_out
 *          where the peer's per-boot epoch is written, and ONLY when the answer
 *          is FED_OK. It is an out-parameter rather than a separate call
 *          because the epoch is parsed as part of the shape check -- that is
 *          where its grammar belongs -- and a second parse of the same field
 *          would be a second opinion about it. NULL is allowed and means "the
 *          caller does not want it", which is what a pure validation caller
 *          wants.
 *
 * The checks run in this order, and the order is the argument:
 *
 *   1. SHAPE (FED_BAD_ARITY / FED_BAD_NAME / FED_BAD_EPOCH / FED_BAD_VERSION)
 *      A line that is not a well-formed FEDERATE cannot be interpreted at all,
 *      and every later check would be reading fields that may not exist. The
 *      version is checked here, before the secret, so a peer running a
 *      different build is told that rather than being told its secret is
 *      wrong -- which is the difference between an operator fixing a version
 *      and an operator re-rolling a credential.
 *   2. THE SECRET (FED_NO_SECRET / FED_BAD_SECRET)
 *      Second, and before the identity checks, because a node that is not
 *      allowed to be here should learn as little as possible about who is.
 *      Self-name and uniqueness are information about THIS node's topology,
 *      and a stranger gets neither until it has proven it belongs.
 *
 *      AN EMPTY CONFIGURED SECRET REFUSES (FED_NO_SECRET). Federation is
 *      opt-in: a node federates because it was given a secret, so a node with
 *      no secret is a node that federates with nobody, and the default that
 *      `irc-serve 6667` keeps means a node that accepts no inbound peer at
 *      all. This is its own verdict rather than a BAD_SECRET because the two
 *      are opposites to whoever is reading the log -- a credential under
 *      attack, and a missing --secret -- and `irc-serve 6667` does not break:
 *      the client surface is untouched, and the peer handshake did not exist
 *      before Phase 6. Step 2 in the function states the argument in full and
 *      what it costs.
 *   3. THE CLAIM IS NOT OURS (FED_SELF_NAME)
 *      Third. 2.3 calls two nodes with one name "catastrophic and undetectable
 *      later", and the only cheap place to stop it is here.
 *   4. THE CLAIM IS UNIQUE (FED_NAME_IN_USE / FED_DUPLICATE_LINK /
 *      FED_NAME_MISMATCH)
 *      Last, because it is the only check that consults node state, and every
 *      stateless check that could have rejected the line already has. The third
 *      of those three is not a uniqueness question at all: it is this
 *      connection announcing a name the link it is running on does not have,
 *      which is a misconfiguration rather than a second route, and it does not
 *      count as a duplicate.
 *
 *      "Rival" MEANS A LINK THAT HOLDS A DESCRIPTOR, and that is a correction
 *      rather than a restatement. A link in INIT with fd == -1 is a name and a
 *      pre-resolved destination -- what fed_dead() leaves behind -- and not a
 *      claim on the name. Counting it as one made 2.2's "re-linking a server of
 *      the same name resurrects the channel" unreachable, because the peer that
 *      re-dialled was refused NAME_IN_USE by a link with no socket on it. A link
 *      that HOLDS a descriptor is still a claim in every state, including
 *      FAILED and TIMED_OUT: T2 leaves the descriptor alone on purpose, so
 *      clearing that case is fed_link_reset()'s job and not this check's.
 */
fed_federate_result_t fed_check_federate(const server_t *s,
                                         const server_link_t *self,
                                         const message_t *m, const char *secret,
                                         uint64_t *peer_epoch_out);

/* ---------------------------------------------------------------------------
 * The link table
 * ---------------------------------------------------------------------------
 */

/* Open the federation module on this node: store the shared secret and take
 * over FEDERATE lines arriving on the listener.
 *
 * The secret is NULL or "" to mean "no secret configured", which is the default
 * the CLI keeps for backward compatibility -- and WHICH MEANS THIS NODE
 * REFUSES INBOUND FEDERATE, under its own verdict FED_NO_SECRET, because
 * federation is opt-in. A node that was given no secret is not a node whose
 * peers are unauthenticated; it is a node that federates with nobody. The
 * operator-facing text is in node_main.c's --help and on its startup line, and
 * both say the same thing. Returns 0 on success, -1 on a NULL node, a secret
 * longer than IRC_FED_MAX_SECRET - 1, or a second call for a DIFFERENT node in
 * the same process (see the module-state note below).
 *
 * IT DOES NOT INSTALL THE TICK. srv.on_tick = fed_tick is a separate, visible
 * assignment in node_main.c, so that a reader of the node can see the loop's
 * time seam rather than infer it from a function called "install". A node that
 * opens the module and does not install the tick can accept a peer and can
 * never notice one going away; that is a real hazard and it is visible.
 *
 * MODULE STATE, AND WHY IT IS SAFE HERE: the saved inner dispatch and the
 * secret are file-static, so this module is ONE NODE PER PROCESS. That is true
 * of the shipped binary and of every fixture in the test harness, and the
 * refusal above makes it a diagnosed condition rather than a silent one -- a
 * second node in the same process would otherwise chain a second wrapper round
 * the first. A second call for the SAME node is also refused, because it would
 * wrap the wrapper and recurse.
 */
int fed_open(server_t *s, const char *secret);

/* Override the three link timers for THIS PROCESS. A 0 argument keeps the
 * built-in. Call it before the loop is armed; the values are read on every
 * comparison, so calling it later is legal but would apply mid-flight.
 *
 * This is the per-process half of the #ifndef guards above, and the reason
 * both exist is in the header: a build default serves a deployment, and a
 * per-process override serves a test whose case must not make the next case
 * wait. `dead_ms` is passed separately rather than derived from
 * `keepalive_ms` so that a case can declare a liveness threshold on its own
 * terms -- and a caller that wants the shipped relationship should pass
 * 3 * keepalive_ms, which is what IRC_FED_DEAD_MS already is. */
void fed_set_timeouts(uint64_t dial_ms, uint64_t hs_ms, uint64_t keepalive_ms,
                      uint64_t dead_ms);

/* ---------------------------------------------------------------------------
 * fed_hs_due: T2's DEADLINE, as a predicate, and why it is not inline
 * ---------------------------------------------------------------------------
 * Returns non-zero when a handshake stamped `created_ms` has had the handshake
 * timeout (fed_set_timeouts()'s `hs_ms`, or IRC_FED_HS_TIMEOUT_MS) by `now_ms`.
 * `created_ms == 0` means no attempt is stamped, so nothing is due; that is the
 * reset case link.c's fed_link_reset() creates and T2's own `!= 0u` guard used
 * to spell out.
 *
 * IT IS A FUNCTION AND NOT AN EXPRESSION BECAUSE OF ONE RULE, and the rule is the
 * whole of it: **a stamp that is not yet in the past is not due.** `now_ms <
 * created_ms` is reachable WITHOUT THE CLOCK MISBEHAVING, which is the part that
 * is not obvious and the reason this needed a named predicate to be testable.
 * poll_loop_step() samples now_ms with server_now_ms() and THEN calls
 * server_tick(), so the value the tick compares against was read before any of
 * the tick's work. fed_link_promote() runs inside that tick and stamps
 * created_ms from a FRESH server_now_ms() of its own -- a later reading in real
 * time, on a monotonic clock, that can still be numerically larger. So on any tick
 * that takes at least one millisecond between step 8's clock read and the
 * promotion, created_ms is newer than the now_ms being compared against it.
 *
 * The subtraction is unsigned, so that reads as an age of 2^64-1, which is larger
 * than any timeout: the handshake was declared timed out ON THE TICK THAT
 * CREATED IT, the connection was marked CLOSING with its FEDERATE still queued,
 * and the peer saw a clean close having read nothing. Printed, from a failing
 * run of tests/integration/test_fed_handshake.c:
 *
 *     promote peer=irc.b fd=5 queue_rc=0 pending=80 now=4044447577
 *     T2       created=4044447577 now=4044447576 age=18446744073709551615 hs=1000
 *
 * The cost of getting this wrong is invisible without a load: a tick that
 * reaches the promotion inside the same millisecond produces an age of 0 and is
 * correctly not due, so the defect is a race on the tick's own duration. It is
 * also why raising the timeout is not a fix -- the age is 2^64-1 and no budget is
 * larger than that.
 *
 * tests/federation/test_hs_deadline.c asserts this directly, which is the only
 * reason it is exported: an integration test can only lose this race
 * intermittently, and a defect that can only be observed by winning a race
 * cannot be regression-tested at all.
 */
int fed_hs_due(uint64_t created_ms, uint64_t now_ms);

/* Override the three RECONNECT intervals for THIS PROCESS. A 0 argument keeps
 * the built-in, on the same terms as fed_set_timeouts() above.
 *
 * IT EXISTS BECAUSE A BACKOFF TEST THAT CANNOT SHORTEN ITS OWN LADDER IS A
 * SLOW TEST, and that is not a style complaint: the shipped ladder starts at
 * IRC_FED_DEAD_MS (90 s) and only reaches its ceiling on the fourth retry, so a
 * case that asserts the exhaustion would otherwise take minutes of wall clock
 * and the whole suite would be built around the backoff. A test sets a base of
 * two poll ticks and a budget of three and the LADDER SHAPE -- exponential,
 * capped, and bounded by a budget that reports -- is still exactly what it is in
 * production, because what the test shortened is the SCALE and not the rules.
 * The cost of that trade is stated rather than hidden: a test that sets a base
 * of 100 ms proves the schedule's shape and its termination, and it proves
 * nothing about how a 90 s base behaves in the field. The shipped values are
 * what a deployment runs and the shipped values are the ones in the header.
 *
 * `budget` is a COUNT and 0 keeps the built-in, so a caller that wants "never
 * retry" cannot say so here -- that is deliberate, because a policy with a
 * disable switch is a policy whose default is the thing under test. A test that
 * wants the old no-redial behaviour asserts on the budget being SPENT. */
void fed_set_retry(uint64_t base_ms, uint64_t max_ms, unsigned budget);

/* Configure a peer: a name, and its PRE-RESOLVED address.
 *
 * The address is a struct sockaddr because 3.4 forbids a name lookup in the
 * event loop and core/server.h is explicit that server_dial() must stay
 * un-resolvable -- a resolution helper anywhere near the dial path is a
 * visible act. So resolution happens in node_main.c's main(), before the loop
 * is armed, and this function only records the result.
 *
 * The link is created in INIT with initiator set, no descriptor, and the
 * address attached, so it is a NAME and a DESTINATION from this moment and a
 * route only once it reaches ESTABLISHED.
 *
 * Returns the link, or NULL on a NULL node, a name that is not a legal 2.4 tag
 * value, a name this node already has a link for, an empty address, or a
 * failed vector growth.
 *
 * IRC_FED_MAX_PEERS is the vector's INITIAL capacity, not its limit: past it
 * the vector grows geometrically, exactly as the other registries on server_t
 * do. The CLI's own cap of IRC_FED_MAX_PEERS --peer options is therefore a
 * limit on the command line, not on the table, and the two being different is
 * recorded rather than hidden. */
/* Mark the link to `name` as one that must carry TLS, or as one that need not.
 *
 * THE STICKINESS IS THE POINT and it is why this is a separate call rather than an
 * argument to fed_link_configure(): `require_tls` is set here and is never cleared
 * for the life of the link -- not by a tick, not by the retry arm, not by
 * fed_link_reset(). A link that was TLS and came back in the clear would mean that
 * compromising the plaintext path ONCE was enough to downgrade it permanently,
 * because the attacker would simply answer the next dial.
 *
 * Returns 0 on success and -1 when there is no such link, which is a startup error
 * rather than a runtime possibility: main() calls it once per --peer-tls, right
 * after fed_link_configure(), so a name that matches nothing is a mistyped command
 * line and is reported as one instead of being a setting that quietly does
 * nothing.
 *
 * CALL IT BEFORE THE FIRST DIAL. fed_tick()'s T7 arm dials a link whose retry_at_ms
 * is 0, which is the state a freshly configured link is in -- so a require_tls set
 * after the first tick would be set after the first plaintext attempt. main() does
 * it before the loop is armed, which is the same reason peer resolution happens
 * there. */
int fed_link_set_tls(server_t *s, const char *name, int require_tls);

server_link_t *fed_link_configure(server_t *s, const char *name,
                                  const struct sockaddr *sa, socklen_t salen);

/* ---------------------------------------------------------------------------
 * The tick, and the two link-lifecycle functions
 * ---------------------------------------------------------------------------
 */

/* The one clock-driven pass over the link set. Installed as s->on_tick.
 *
 * A node with NO peers returns after three integer comparisons, which is the
 * cost this adds to a single-node deployment: the link count, the dedup
 * occupancy, and the node itself. Everything below is a per-link cost, and
 * IRC_FED_MAX_PEERS is what bounds it.
 *
 * The steps, in the order they run:
 *   - T5  the dedup sweep, gated on the store being more than half full. The
 *        time half of that gate is inside fed_dedup_sweep(), which owns its own
 *        throttle because the property is the store's age and not the caller's.
 *   - T1  a DIAL_CONNECTING entry older than IRC_FED_DIAL_TIMEOUT_MS. poll()
 *        reports nothing for a connect() to a black-holed host, so without this
 *        the entry sits in the table for the life of the process. This is the
 *        one place this file closes a descriptor, and it closes a DIAL, which
 *        is not a connection: it is not in by_fd, there is no conn_t, and
 *        server.c already closes exactly these on the same grounds.
 *   - promotion of a link whose dial reported DIAL_CONNECTED.
 *   - T6  resynchronise server_link_t::state from hs.state when they disagree.
 *   - T2  HANDSHAKE_SENT older than IRC_FED_HS_TIMEOUT_MS.
 *   - T3  ESTABLISHED and due a keepalive.
 *   - T4  ESTABLISHED and silent for longer than IRC_FED_DEAD_MS.
 *   - T7  INIT, this node dialled it, and the link's RECONNECT SCHEDULE says a
 *        dial is due: dial. The schedule is server_link_t::retry_at_ms against
 *        IRC_FED_RETRY_BASE_MS / _MAX_MS / _BUDGET, it is armed by every arm
 *        that takes a link down (T1, T2 and T4 all reach fed_retry_arm()), and
 *        it is CLEARED by fed_link_established() -- which is the whole of the
 *        "on re-establishment, drive a resync" half: the same call that makes
 *        the link routable again re-arms it with a fresh budget AND bursts.
 */
void fed_tick(server_t *s, uint64_t now_ms);

/* Answer one inbound FEDERATE: validate the claim, accept it or reject it.
 *
 * It is exported, and it is exported as a NAMED function rather than left as
 * three lines inside the dispatch hook, because two callers need it and they
 * are reached by different paths. federation/verbs.c's fed_dispatch() reaches it
 * at its G2 guard, for a FEDERATE that arrives on a link that is ALREADY
 * established -- a re-claim, which fed_check_federate() reports as
 * DUPLICATE_LINK or NAME_MISMATCH. The hook in this file reaches it for the
 * ordinary case, a claim on a connection that is not yet a peer, which is the
 * only way a peer ever arrives: 2.3 makes the HANDSHAKE, not the accept, the
 * place a peer is identified, and c->kind is still CONN_CLIENT here.
 *
 * Both callers hand the line here rather than each doing its own validation,
 * because the verdict set is wire-adjacent (fed_federate_reason() prints it) and
 * a second implementation of the checks would be a second set of answers to
 * questions whose spelling a test matches on.
 */
void fed_on_federate(server_t *s, conn_t *c, const message_t *m);

/* The OPERATOR's reset: return the link to INIT, keeping `initiator` and the
 * pre-resolved address, and spend a fresh retry budget on it.
 *
 * WHAT IT IS FOR NOW, and it is a different job from the one it was written
 * for. It used to be "clear the no-auto-redial latch", a one-line escape from a
 * latch that is GONE (see the retraction block above); what it is now is the
 * thing an operator reaches for when fed_tick() has spent the budget and set
 * `gave_up`, and it is the ONLY way out of that state. A node that has decided
 * a peer is gone stays decided until somebody says otherwise, which is the
 * correct default and is useless without a door -- and this is the door, and it
 * is exported rather than static for that reason.
 *
 * It also clears `gave_up` and `retries`, so a reset is a full second chance
 * rather than one more attempt against a spent budget, and it prints
 * `[observable] link_retry_reset:` so that "somebody told the node to try again"
 * is a fact in the log rather than an inference from a `link_dial:` line
 * appearing.
 *
 * THE ASYMMETRY WITH T2 IS UNCHANGED and is still deliberate: a handshake that
 * never completed has nothing to tear down -- no peer epoch was learned, no
 * burst was applied, and the link was never a route -- whereas a link that WAS
 * established and has gone away is a link the node must stop believing in.
 *
 * AND BOTH PATHS THROUGH fed_link_down() ANNOUNCE THE DEPARTURE, which is a
 * deliberate consequence of the announcement living in the shared body rather
 * than in the dead path alone. A SQUIT for this node's own name goes to every
 * ESTABLISHED peer before the teardown, and a deliberate reset IS a departure:
 * the link it is about to re-dial is not up, so a peer holding this node's
 * roster has a stale one from this moment. The cost is that a reconnect, which
 * reaches this body once per retry decision, tells the mesh the server is gone
 * each time it retries -- which is true, and is the reason the SQUIT is cheap to
 * make idempotent rather than expensive to make quiet.
 *
 * NO CALLER IN THE SHIPPED BINARY, and that is now a FINDING rather than the
 * point of writing it: the operator-facing door exists and nothing in this tree
 * opens it, because node_main.c has no signal or command routed to it. That is
 * recorded in docs/SERVER_DESIGN.md's Phase 9 block as what is still not true,
 * and it is a real gap rather than a rounding error -- `gave_up` is currently
 * terminal for the life of the process. The tests reach this function
 * directly, which is how it stays covered. */
/* ---------------------------------------------------------------------------
 * Phase 9 item 4: ADVERTISE and SHUTDOWN
 * ---------------------------------------------------------------------------
 */

/* How many peer advertisements this node can hold, and it is IRC_FED_MAX_PEERS
 * because that is how many peers a node can be configured with -- so the store
 * cannot grow past this node's own peer set, and an advertisement from a stranger
 * has nowhere to go even if the guard chain were removed. */
#define IRC_FED_MAX_ADVERTISED ((size_t)IRC_FED_MAX_PEERS)

/* Mark a link as CLEANLY DEPARTED (`set != 0`) or as diallable again (`set == 0`).
 * Returns 1 if the flag changed, 0 if it did not or on a bad argument.
 *
 * IT SETS ONE FIELD AND DOES NOTHING ELSE, which is the whole of its contract:
 * no socket is closed, no roster is purged, no retry is armed or disarmed. Those
 * are three other pieces of a departure and they live in three other places; the
 * flag is the one thing they share, so a function that also did one of them would
 * be a function whose callers could not skip it without skipping the rest.
 *
 * `set == 0` HAS EXACTLY ONE CALLER, fed_link_reset(), because that is the
 * OPERATOR's door: an operator who resets a link is saying "I want this peer back".
 * Nothing else clears the flag, so a clean leave is not undone by a later event
 * on the same link -- not a tick, not a sweep, not the socket closing. */
int fed_mark_clean_leave(server_t *s, server_link_t *link, int set);

/* Send `SHUTDOWN` to every ESTABLISHED link and return how many carried it.
 * Called from server_shutdown() and from nowhere else, which is what a graceful
 * leave IS: this node says it is going and then it goes.
 *
 * BEST EFFORT, and the limit is stated because it is real: the line is queued and
 * the queue is drained by a single conn_pump() per link, so on a lossy path a
 * SHUTDOWN can fail to arrive. That degradation is CORRECT rather than a defect:
 * a peer that does not hear it sees a closed socket, applies its retry policy,
 * and finds the node gone. The cost of sending it is that a clean leave
 * occasionally reads as a failure; the cost of not sending it is that EVERY clean
 * leave reads as one. `reason` is taken and not sent -- 4.3 has no SHUTDOWN and
 * its shape is this phase's to choose, and a field a second implementation has to
 * guess about is a compatibility break bought for nothing. */
int fed_send_shutdown(server_t *s, const char *reason);

/* Send `ADVERTISE <load%> [<name> <host> <port>]` to every ESTABLISHED link,
 * minting a SEPARATE 2.4 id per link, and return how many carried it.
 *
 * SEPARATE IDS PER LINK, which is the opposite of fed_send_squit_named()'s one id
 * for the whole fan-out and for a reason worth stating: a SQUIT is ONE logical
 * announcement with several targets, so one id is right and a node reachable by
 * two of this node's peers MUST drop the second copy. An ADVERTISE is a per-link
 * STATE REPORT, the two copies are not the same message, and sharing an id would
 * have the second peer learn nothing at all.
 *
 * WHAT IT PUBLISHES IS THIS NODE'S OWN CONFIGURATION -- its own name, the address
 * the operator gave it, and the load percentage from fed_set_load() -- and never
 * anything a peer told it. A node advertising an address it had resolved or
 * inferred would be publishing a guess, and a peer that dialled a guess would be
 * dialling the wrong server. That is a correctness reason and it is separate from
 * the SSRF reason on server_t::advs, which is about what this node does with what
 * it is TOLD. */
int fed_send_advertise(server_t *s);

/* Set this node's advertised load percentage. A KNOB and NOT A METRIC, because
 * this node measures no load: the honest thing to put on the wire from a node
 * that cannot measure itself is a value an operator set, and a fabricated 0% would
 * be a number this node does not believe. Clamped to 0..100 on the way out. */
void fed_set_load(server_t *s, unsigned pct);

/* Set the level at or above which a PEER's advertised load is reported as shedding,
 * by fed_tick()'s T8 arm. 0 (the shipped value) means no opinion.
 *
 * WHERE THE PROPAGATION HALF STOPS, and this function is the place the decision is
 * written down rather than inferred from an absence:
 *
 *   IT DOES   report. One `[observable] fed_shed: ... action=REPORT_ONLY` line per
 *             crossing, and n_fed_shed counted, so the fact that a peer is busy
 *             reaches whoever can act on it.
 *   IT DOES NOT move clients, channels or load. Three reasons, and the first two are
 *             structural rather than cautious:
 *             - 2.2 makes a channel's origin IMMUTABLE and fails closed when it
 *               dies. Re-homing a channel IS origin re-election, which 9's risk
 *               table records as not started and not to be begun without re-opening
 *               2.4's dedup key. So there is no "move the channel" call to make.
 *             - A client's session belongs to the node its socket is connected to.
 *               There is no session-transfer verb and no client-visible redirect in
 *               4.3, so "send the load elsewhere" has no mechanism on either end.
 *             - Node lifecycle is not this codebase's remit. Spawning and stopping
 *               nodes is a supervisor's job (systemd, an orchestrator), and a node
 *               that cannot measure its own load (see fed_set_load) has nothing
 *               honest to decide with.
 *
 * WHY THE DEFAULT IS 0 AND NOT A CONSTANT: the percentage is an operator's number
 * about the peer's load, so the level at which it matters is a deployment's
 * judgement. Shipping a threshold would be inventing a figure this codebase cannot
 * justify and calling the result a feature. An operator who wants the report sets
 * one, and a node with no threshold prints nothing rather than printing a verdict
 * it has no basis for. */
void fed_set_shed_pct(server_t *s, unsigned pct);

/* What one peer ADVERTISED, for a log or a counter. `name` and `host` are bounded
 * buffers and `port_out`/`load_out` may be NULL; each is zeroed or emptied on
 * entry so a caller that ignores one gets an empty value rather than a stale one.
 * Returns the advertised NAME, which is the peer's own claim and need not equal
 * the link it arrived on -- a relay is a legitimate thing to be -- or NULL when
 * this peer has advertised nothing.
 *
 * THIS FUNCTION IS THE ENTIRE READ SURFACE OF THE ADVERTISEMENT STORE, and its
 * RETURN TYPE IS PART OF THE SSRF ENFORCEMENT and not only a comment. It hands out
 * two bounded strings and two numbers. There is no function anywhere in this
 * module that returns a sockaddr, a server_link_t, or anything the dial path could
 * be built from, and the only writer of a link's dial address is
 * fed_link_configure(), which takes it from the operator's command line. See
 * server.h on server_t::advs for the threat and for what a future reader would
 * have to write down before changing any of this. */
const char *fed_advertised(const server_t *s, const char *peer, char *name,
                           size_t name_cap, char *host, size_t host_cap,
                           unsigned *port_out, unsigned *load_out);

/* How many peers have advertised something. 0 on a node with no peers, and the
 * number a test asserts on to tell "the store recorded nothing" from "the store
 * does not exist". */
size_t fed_advertised_count(const server_t *s);

/* Free the advertisement store. The TEARDOWN ARM, called from
 * server_shutdown() next to the burst shadow's and the nick registry's, and it
 * prints whether the table was OPEN so it can be asserted on a platform whose
 * LeakSanitizer does not run. Safe on a server that never allocated one, and safe
 * on NULL. */
void fed_advert_close(server_t *s);

/* Announce `server` to every ESTABLISHED link as a `SQUIT <server>`, and return how
 * many carried it. `dying` is the link the line must NOT go out on -- NULL for
 * "no such link" -- because a link that is closing cannot read it and counting it
 * as a peer told would be a claim the wire does not support.
 *
 * IT IS ONE FUNCTION FOR TWO SENTENCES. `fed_send_squit_named(s, NULL, link)` says
 * "THIS node's name is gone" and is what fed_link_down() announces with.
 * `fed_send_squit_named(s, name, link)` says "THE SERVER CALLED `name` is gone"
 * and is what the SHUTDOWN handler forwards, so a node two hops away learns about
 * a departing peer. Both mint ONE 2.4 id for the whole fan-out, which is what 2.4's
 * per-node dedup needs for a single logical announcement -- a node reachable by two
 * of this node's peers must drop the second copy.
 *
 * A SQUIT AND NOT A RELAYED `SHUTDOWN`, and the asymmetry is why forwarding is
 * right: a receiver refuses a SQUIT naming ITSELF but accepts one naming a third
 * server, so a third node that has never heard of SHUTDOWN still purges
 * correctly. A peer that predates this build would count an unknown verb and apply
 * nothing, which is a stale roster -- the degradation, not the goal. */
int fed_send_squit_named(server_t *s, const char *server, const server_link_t *dying);

/* How often an ESTABLISHED link is advertised on, and the reason it is a knob
 * and not a constant: the test needs the peer to learn about this node inside its
 * own deadline, and the shipped value is chosen for a mesh where a stale load
 * figure is not worth a line. The ADVERTISE is ALSO sent once on establishment,
 * which is the half that matters for a peer that has just arrived. */
void fed_set_advertise_interval(uint64_t ms);

void fed_link_reset(server_t *s, server_link_t *link);

/* Dump every link and the link counters, one [observable] line for the node and
 * one per link, then flush. `why` is a short stable token naming what caused
 * the dump, so a reader of the log can tell an event dump from a periodic one.
 *
 * 8 requires this ("a way to dump peers + their FSM states ... Split-brain
 * debugging without this is guesswork") and it is emitted on every link event
 * -- establishment, rejection, link-down -- rather than on a timer, because a
 * dump that is a second late is a dump nobody reads while they are looking at
 * the failure. */
void fed_dump(const server_t *s, const char *why);

#endif /* IRC_FEDERATION_LINK_H */
