/* verbs.h -- 4.3's S-verbs: the ENCODE side of the peer wire.
 *
 * Authority: docs/SERVER_DESIGN.md 4.3 (the internal verbs, and why they are
 * distinct words rather than a reused JOIN/PRIVMSG), 2.4 (the internal tag
 * block every one of them carries) and 3 (the reply-path invariant that keeps
 * numerics off a peer link).
 *
 * ---------------------------------------------------------------------------
 * WHAT IS HERE AND WHAT IS NOT
 * ---------------------------------------------------------------------------
 * Everything OUTBOUND, and nothing inbound. fed_send_sverb() builds a message_t,
 * stamps the 2.4 block on it, renders it and queues it to a peer connection;
 * fed_sverb_for() is the client-verb -> S-verb map. The other half -- reading an
 * inbound line, checking it against the dedup store, the hop ceiling and the
 * never-forward-own-origin rule, and dispatching it -- is fed_dispatch() and it
 * does not exist yet.
 *
 * The split is not tidiness. A wire format cannot be revised once two nodes are
 * running it, so the encode side is written down and frozen first and the decode
 * side is written against it; the reverse order invites a decoder that accepts
 * whatever the encoder happened to emit today, which is exactly the failure 4.3
 * warns about when it says the verbs must be distinct rather than reused.
 *
 * ---------------------------------------------------------------------------
 * WHY THE VERB TABLE IS HERE AND NOT IN A CALLER
 * ---------------------------------------------------------------------------
 * Seven client verbs have seven S-verb spellings, and the spelling is not
 * derivable from the client verb by any rule a reader could reconstruct:
 * PRIVMSG gains a letter, MODE becomes SMODES rather than SMODE, and MODE is the
 * only one of the seven where the obvious transformation is also the WRONG one.
 * A table in one place is therefore the difference between a mapping that is
 * correct and seven `snprintf("%s%s", ...)` sites that are correct until one of
 * them is edited.
 *
 * THE MODE VERB IS SPELLED `SMODES`, and the design says `SSMODE`
 * --------------------------------------------------------------
 * 4.3 lists `SSMODE`. That is not what this node sends, and the rename is
 * recorded here rather than left to be discovered by a peer:
 *
 *   - `SSMODE` is a bad command word. Read aloud or read as a token it looks
 *     like a typo, and the failure mode of a typo in a wire verb is that two
 *     nodes disagree about it and every state change fails silently -- no
 *     numeric, no log, just channels whose modes do not converge.
 *   - `SMODES` is the plural, which is what the verb actually carries: a mode
 *     change is a LIST of mode letters with arguments, and a reader seeing
 *     `SMODES` knows to expect the list without opening the design.
 *
 * The cost of the rename is that this implementation does not match 4.3's
 * spelling, so a node running 4.3 literally would not interoperate on MODE. That
 * is the correct trade while every node is this implementation, and it is the
 * wrong trade the moment a second implementation exists -- which is a decision
 * for the design, not for this file, and the reason the rename is documented
 * rather than silent is so that a second implementation finds it.
 *
 * The OTHER five names are exactly 4.3's: SPRIVMSG, SNOTICE, SJOIN, SPART,
 * STOPIC, SKICK.
 *
 * THE TABLE IS CLOSED, and Phase 6 found out why that matters the hard way.
 * federation/link.c's T3 needs to put a link-liveness PING on a peer link, and
 * the obvious way to do it -- add a `PING -> PING` row so fed_send_sverb() can
 * build it -- is refused by tests/integration/test_fed_wire.c, which asserts
 * that PING has no S-verb and says why: "4.3's list is the forwarded vocabulary,
 * and adding to it is a wire-format change." It is right. This table maps CLIENT
 * verbs a node is RELAYING, and a link keepalive is not a relay of anything, so
 * a row for it would put a word into the forwarded vocabulary that no other
 * implementation has, and a second implementation written from 4.3 would refuse
 * a PING on a peer link as a client verb it does not forward.
 *
 * So the keepalive cannot come through fed_send_sverb(), and it does not: the
 * KEEPALIVE IS A LINE THIS NODE ORIGINATES, NOT A VERB IT RELAYS, and the two
 * are built by the same steps from different inputs. What IS shared -- stamp
 * the 2.4 block, build the message, render it, bound-check it, terminate it and
 * queue it -- is fed_queue_line() below, and both fed_send_sverb() and the T3
 * keepalive in federation/link.c call it. What stays out of it is the verb
 * TABLE, which is why the two callers can share a helper and still not share a
 * vocabulary: a PING on a peer link is not a forwarded PING, and the table is
 * still closed.
 */
#ifndef IRC_FEDERATION_VERBS_H
#define IRC_FEDERATION_VERBS_H

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"

/* The S-verb for a client verb, or NULL when this node has no S-verb for it.
 *
 * `client_verb` is the UPPERCASED command word, which is what message_t holds
 * and what every handler has. The comparison is exact rather than
 * case-insensitive for the same reason 3.2 says `command` is uppercased at the
 * seam: a second opinion about case in a verb table is a second opinion
 * somebody can have, and a handler that has a lowercased verb in hand has a bug
 * upstream that this would hide.
 *
 * NULL is a real answer, not a failure mode. 4.3's list is not every command
 * this node has: WHO, PING, WHOIS and the numerics are node-local, and a
 * forwarded line with no S-verb is refused rather than sent as something the
 * peer would misparse. */
const char *fed_sverb_for(const char *client_verb);

/* ---------------------------------------------------------------------------
 * The shared render-and-queue step
 * ---------------------------------------------------------------------------
 * Why it exists: two callers in two files need "stamp the 2.4 block, build a
 * message_t, render it, bound-check it, terminate it, queue it" and had it
 * written out twice -- fed_send_sverb() here, and T3's keepalive in
 * federation/link.c. The duplication was a deliberate Phase 6 decision with a
 * note saying the shared helper was the honest fix and belonged to whoever made
 * the change deliberately. This is that change.
 *
 * WHAT IS STILL NOT SHARED, and it is the part that matters: the verb TABLE.
 * fed_send_sverb() maps a client verb to an S-verb before it gets here, and the
 * keepalive names PING directly, because a keepalive is a line this node
 * ORIGINATED rather than one it RELAYED (see the note at the top of this file).
 * So the helper takes a verb that is already decided and a parameter list that
 * the CALLER decided, and PING stays out of the forwarded vocabulary --
 * tests/integration/test_fed_wire.c asserts fed_sverb_for("PING") == NULL and
 * that assertion is unaffected by anything on this page.
 *
 * The third thing it deliberately does not do is build the FEDERATE handshake
 * line, which federation/link.c also renders by hand. A FEDERATE carries NO 2.4
 * block -- its epoch and secret are parameters, not tags, because 2.4's block
 * is what a RECEIVER needs in order to deduplicate and loop-check, and a
 * handshake is neither relayed nor looped -- so a helper that stamps a block
 * would have to be told to skip its own first step. That line stays where it is
 * used, and says so.
 */
typedef enum {
    FED_QUEUE_OK = 0,       /* queued                                                */
    FED_QUEUE_BAD_TAGS,     /* the stamp failed irc_serve_tags_valid()              */
    FED_QUEUE_TAG_TOO_LONG, /* the stamp is legal but does not fit the block buffer   */
    FED_QUEUE_UNBUILDABLE,  /* message_build() refused the parts                    */
    FED_QUEUE_UNRENDERABLE, /* message_format() refused, so nothing was written     */
    FED_QUEUE_SATURATED     /* server_queue() dropped it: a saturated link (3.4)    */
} fed_queue_why_t;

/* The stable spelling of a refusal, for the caller's own [observable] line. The
 * tokens are the ones this node has always printed for these five failures, so
 * folding the callers together did not change a word an operator reads: the
 * S-verb line's `reason=TAG_BLOCK_TOO_LONG` and the keepalive's `reason=BAD_TAGS`
 * are both unchanged, because each caller maps this answer onto its own
 * vocabulary. Never NULL: a value that is not a member of the enum is reported
 * as "UNKNOWN" rather than as a NULL %s. */
const char *fed_queue_why_name(fed_queue_why_t why);

/* Stamp, build, render, terminate and queue one line on a peer link. Returns 0
 * when the line was queued, -1 when it was refused, and writes the reason to
 * `why_out` (which may be NULL) -- a reason rather than a bare -1 because the
 * two callers report refusals in their own words and a shared function that
 * picked one set of words would take that vocabulary away from them.
 *
 *   tags      the complete 2.4 stamp, VALIDATED here rather than trusted: a
 *             stamp that fails irc_serve_tags_valid() cannot be put on the wire
 *             in a form a peer would accept, and the alternative to the check
 *             is a tagless line on a peer link, which every node must then
 *             guess about and which defeats loop prevention entirely.
 *   prefix    the source prefix WITHOUT the leading ':'.
 *   verb      the command word, already uppercased or already an S-verb. The
 *             helper does not map it and must not be asked to.
 *   params    the parameters, and nparams of them. NULL is legal when nparams
 *             is 0, which is what message_build() documents.
 *
 * THE SATURATED CASE IS ALREADY COUNTED AND ALREADY MARKED CLOSING by
 * server_queue(): a saturated link is DROPPED, not buffered (3.4), and this
 * function must not count it a second time. And nothing here closes a
 * descriptor -- the refusal is a return value, and the reaper closes.
 */
int fed_queue_line(server_t *s, conn_t *peer, const irc_serve_tags_t *tags,
                   const char *prefix, const char *verb,
                   const char *const *params, int nparams,
                   fed_queue_why_t *why_out);

/* Queue one S-verb on a peer link, with the 2.4 internal tag block stamped on
 * it. Returns 0 when the line was queued, -1 when it was refused.
 *
 *   tags         the complete 2.4 stamp. Passed in rather than derived here
 *                because the POLICY -- this node originated the message, or it
 *                is relaying one, and what the hop count becomes -- belongs to
 *                fanout_forward_link(), which is the one place a message is
 *                decided to leave the node. Deriving it in both places is how
 *                the two would come to disagree about what "one hop" means.
 *                It is validated rather than trusted: a stamp that fails
 *                irc_serve_tags_valid() cannot be put on the wire in a form a
 *                peer would accept, and an invalid one is a bug in the caller.
 *   peer         the link's connection, already established and already
 *                nonblocking. The queue is bounded (3.4) and a saturated link
 *                is refused, not buffered.
 *   client_verb  the CLIENT verb. Not the S-verb: the mapping is applied here so
 *                that no caller can hand this function a verb that is already an
 *                S-verb and get `SSPRIVMSG`.
 *   prefix       the source prefix, WITHOUT the leading ':' -- message_build()
 *                adds the marker, exactly as it does for every other line this
 *                node builds.
 *   target, text the two parameters. A trailing parameter is colonned by the
 *                formatter, so `text` may contain spaces and semicolons.
 *
 * THE PARAMETER SHAPE IS PROVISIONAL, and that is a known gap rather than a
 * decision: 4.3 names the verbs but not their parameters, and the obvious
 * reading of a forwarding API that hands over a target and a text is
 * `<target> :<text>` for all seven. That is correct for SPRIVMSG and SNOTICE and
 * wrong for the five state verbs -- a real SJOIN carries an account, a mode
 * list and a realname (4.3's burst vocabulary), and an S-verb carrying only a
 * channel name loses them. The five state verbs are not reachable from the wire
 * in this commit, so nothing is being emitted in the wrong shape yet; the shape
 * is pinned per verb when the verbs are.
 *
 * THE PREFIX, AND THE GAP NOBODY SHOULD DISCOVER BY DIFFING A TRACE
 * ---------------------------------------------------------------
 * fed_send_sverb() takes a prefix because 4.3 needs one: a peer's
 * `SPRIVMSG #T :hi` has to say WHO said it, or the receiving node cannot put a
 * hostmask on the message it delivers to its own members. The caller that
 * exists today -- fanout_forward_link() -- has no prefix to give it, and passes
 * the node's own name. That is right for the five verbs whose subject is the
 * server and wrong for SPRIVMSG and SNOTICE, whose subject is a user. It is
 * recorded here because the correct fix is a parameter this commit's design does
 * not include, and a wrong line that is documented is a far smaller problem
 * than one that is not.
 *
 * WHY server_queue() AND NOT reply()'s DOOR
 * ------------------------------------------
 * reply.c's emit_to_client() REFUSES a CONN_SERVER destination, and that refusal
 * is the mechanism which keeps numerics off a peer link. It is not a mechanism
 * for putting protocol messages on one: an S-verb is not a reply, it is
 * deliberate outbound protocol, and routing it through the same door would mean
 * either disabling the guard that makes 3's invariant true or adding a flag that
 * turns it off, which is the same thing with a worse name. So this function
 * queues through server_queue() directly, which is also what keeps
 * 3.4's "the send path never closes" and the bounded-queue refusal honest: a
 * saturated peer link is marked CLOSING by server_queue() and the reaper closes
 * it, rather than this function inventing a third way to drop a link.
 */
int fed_send_sverb(server_t *s, conn_t *peer, const irc_serve_tags_t *tags,
                   const char *client_verb, const char *prefix,
                   const char *target, const char *text);

#endif /* IRC_FEDERATION_VERBS_H */
