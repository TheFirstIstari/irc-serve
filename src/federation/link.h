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
 * and say so on stdout. It does not carry messages: the inbound S-verb guard
 * chain and its handlers are federation/verbs.c's fed_dispatch() (C3), and
 * burst.c/`SBURST` is C4. The
 * consequence to be aware of while reading the tick is written out under
 * "WHAT T3 COSTS A TEST" below -- it is the one place where this file's
 * behaviour changes a number a Phase 5 test asserts on.
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
 * C2 DOES NOT AUTO-REDIAL, AND THE LATCH IS THE WHOLE OF THAT
 * ---------------------------------------------------------------------------
 * A link that fails -- a dial that times out (T1), a handshake that never
 * answers (T2), a peer that goes silent (T4) -- returns to INIT, and T7 would
 * then dial it again on the very next tick. That is the auto-redial Phase 9
 * owns, and doing it here would be a hot loop against a black-holed peer.
 *
 * The latch is server_link_t::created_ms, which T7 sets to the current stamp
 * when it dials and NEVER clears. fed_link_reset() below is the one-line
 * escape: it clears the latch, and the next tick dials again. Phase 9 replaces
 * that with a backoff schedule and a retry budget; the seam exists so that is
 * a change to one function rather than to the tick.
 *
 * NOTE that created_ms is stamped when the dial STARTS rather than when the
 * connection completes. Stamping at completion leaves a window in which a dial
 * that failed is still a zeroed latch, and T7 re-dials it on the next tick --
 * which is the auto-redial this phase must not have. The stamp is also set on
 * completion, so the sequence 3.4's file map describes ("on TCP connect,
 * handshake_init(), set created_ms, handshake_send()") still reads true.
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
 *   - T7  INIT and this node dialled it and it has never been dialled: dial.
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

/* The reconnect seam: return the link to INIT, keeping `initiator` and the
 * pre-resolved address, and CLEAR the no-auto-redial latch so the next tick
 * dials it again.
 *
 * NO CALLER IN C2, and that is the point of writing it. 7/Phase 9 owns link
 * failure and reconnect handling, and the difference between C2 and Phase 9 is
 * exactly this function: Phase 9 decides WHEN a failed link is worth another
 * attempt (backoff, a retry budget, whether a peer that was ever established
 * is dialled more eagerly than one that never was) and calls this. C2
 * deliberately does not dial twice, so nothing here is reachable -- and a
 * function added in Phase 9 is a function nothing in this phase's tests has
 * covered, which is the same argument dedup.h makes for keeping
 * fed_dedup_reset() beside the other three while nothing calls it.
 *
 * The link is NOT reset on the handshake-timeout path (T2), and that asymmetry
 * is deliberate: a handshake that never completed has nothing to tear down --
 * no peer epoch was learned, no burst was applied, and the link was never a
 * route -- whereas a link that WAS established and has gone away is a link the
 * node must stop believing in. Resetting a never-established link to INIT would
 * make the two cases look identical, which is exactly the distinction T7's
 * latch and the state dump exist to keep visible. */
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
