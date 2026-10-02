/* verbs.h -- 4.3's S-verbs: BOTH SIDES of the peer wire.
 *
 * Authority: docs/SERVER_DESIGN.md 4.3 (the internal verbs, and why they are
 * distinct words rather than a reused JOIN/PRIVMSG), 2.4 (the internal tag
 * block every one of them carries, and the loop-prevention rules every inbound
 * line is checked against) and 3 (the reply-path invariant that keeps numerics
 * off a peer link, and the one-dispatch rule this file's inbound half obeys).
 *
 * ---------------------------------------------------------------------------
 * WHAT IS HERE AND WHAT IS NOT
 * ---------------------------------------------------------------------------
 * fed_sverb_for(), fed_sverb_params() and fed_send_sverb() are the ENCODE side:
 * the client-verb -> S-verb map, the frozen per-verb parameter shapes, and the
 * stamp/render/queue step. fed_dispatch() is the DECODE side: the guard chain
 * every inbound peer line passes before it is allowed to do anything, and the
 * handlers the surviving lines reach.
 *
 * The split is not tidiness. A wire format cannot be revised once two nodes are
 * running it, so the encode side is written down and frozen first and the decode
 * side is written against it; the reverse order invites a decoder that accepts
 * whatever the encoder happened to emit today, which is exactly the failure 4.3
 * warns about when it says the verbs must be distinct rather than reused. C1 and
 * C2 built the encode half and this commit adds the decode half against it.
 *
 * ---------------------------------------------------------------------------
 * THE PREFIX IS A PARAMETER, AND IT IS THE USER'S FOR TWO OF THE SEVEN
 * ---------------------------------------------------------------------------
 * 4.3 needs a prefix on every S-verb, and what it should be depends on the
 * verb. For the five state verbs the subject IS the server -- an SJOIN names a
 * fact about a channel -- so this node's own name is right. SPRIVMSG and
 * SNOTICE are about a USER, and a receiving node handed `:irc.b SPRIVMSG #T :hi`
 * cannot build a hostmask for it: 2.1's `nick!user@host` is the only thing a
 * client can be shown as the author, and a server name is not one.
 *
 * C1 had no prefix to give: fanout_forward_link() passed `s->name` for all
 * seven, and this header recorded the gap rather than hiding it. The gap is
 * CLOSED, and the parameter is on fanout_forward_link() rather than on
 * fanout_target_t -- fanout.h gives the lifetime argument for that choice, and
 * the short version is that a prefix is a property of ONE emission and a
 * resolved target outlives the emission.
 *
 * ---------------------------------------------------------------------------
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
 * ---------------------------------------------------------------------------
 * THE VERB TABLE IS CLOSED, and Phase 6 found out why that matters the hard way.
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

#include "core/channel.h"
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
 *   params        the S-verb's parameters, in the FROZEN order below, and
 *                nparams of them. The caller does not get to invent the order:
 *                fed_sverb_params() is the one function that builds this list
 *                from a client verb, so the shape and the decoder agree by
 *                construction. NULL is legal when nparams is 0.
 *
 * ---------------------------------------------------------------------------
 * THE FROZEN PARAMETER SHAPES -- 4.3 NAMES THE VERBS AND NOT THEIR FIELDS
 * ---------------------------------------------------------------------------
 * 4.3 lists the seven words and freezes nothing else, and the C1 note that the
 * shape was "provisional" was right to call it a gap rather than to invent one:
 * a wire format cannot be revised once two nodes are running it, so the shape is
 * pinned HERE, before anything forwards one. `<target> :<text>` for all seven --
 * what C1 emitted -- is correct for the two message verbs and wrong for the
 * five state verbs, and this table is the correction.
 *
 * In every row, the TARGET is the channel (or the user for the two message
 * verbs) and the source prefix is the one fanout_forward_link() was given. The
 * `member` field is the NICK of that prefix, split at the first '!' -- 2.1's
 * hostmask is `nick!user@host` and nothing else may contain a '!'.
 *
 *   SPRIVMSG  <target> <text>
 *             `:alice!u@example S@1 SPRIVMSG #T :hello there`
 *             The client shape unchanged. A peer that relayed this has said
 *             nothing the client line did not.
 *
 *   SNOTICE   <target> <text>
 *             `:alice!u@example S@1 SNOTICE #T :hello there`
 *
 *   SJOIN     <channel> <member> <flags> <account>
 *             `:alice!u@example S@1 SJOIN #T alice +o *`
 *             The flags are the member's prefix flags as a `+` run, and the
 *             EMPTY CASE IS THE LITERAL `-`. That is not a mode convention: an
 *             empty middle parameter is not representable on this wire at all
 *             (3.2: a value needing ':' is only representable last, and
 *             message_parse() drops an empty uncolonned token), so a shape that
 *             said "nothing if there are no flags" would parse as a two-
 *             parameter SJOIN and the flags would be read as absent on one node
 *             and as an empty token on another. `-` is one byte, never needs a
 *             colon, and is a legal channel-mode letter's negative form.
 *
 *             <account> is Phase 10.3's, and it is `4.3's SJOIN <account>` exactly
 *             as `SBURSTM` carries it: the account name, or `*` for "not logged in
 *             to an account". `*` rather than an empty token for the same reason as
 *             `-`, and it is translated to "" on receipt so that the roster holds an
 *             ABSENCE rather than an account named "*". It is derived from the
 *             MEMBERSHIP, exactly as the flags are -- see fed_member_account().
 *
 *   SPART     <member> <channel> [<reason>]
 *             `:alice!u@example S@1 SPART alice #T :bye`
 *             The reason is OPTIONAL and its absence is an absent parameter, not
 *             an empty one -- which is why it is last: a line that stops after
 *             the channel is a two-parameter SPART and the receiver reads it as
 *             "no reason given", which is what the sender meant.
 *
 *   STOPIC    <member> <channel> <topic>
 *             `:alice!u@example S@1 STOPIC alice #T :the new topic`
 *             The topic is last and always present, so a cleared topic is the
 *             literal `:` -- the RFC's way of saying "there is now no topic",
 *             and the one form message_format() can render and message_parse()
 *             can read back without a second convention.
 *
 *   SMODES    <server> <channel> <modes> [<arg>]
 *             `:irc.a S@1 SMODES irc.a #T +o bob`
 *             The subject is the SERVER, not the user, and that is 2.2's
 *             distinction rather than a formatting choice: only the origin
 *             evaluates +b/+e/+I, and +o/+v are prefix modes whose subject is
 *             the channel's membership, not whoever happened to be typing. The
 *             <server> field is this node's own name, so a receiver can tell a
 *             mode change the ORIGIN evaluated from one a relay passed along,
 *             and only the former may be cached as authority (2.2's "a
 *             non-owner's modes[] is a cache and cannot enforce").
 *
 *   SKICK     <member> <channel> <target> [<reason>]
 *             `:alice!u@example S@1 SKICK alice #T bob :bye`
 *             The member is the KICKER, distinct from <target>: they are two
 *             different users and a shape that carried one would make every
 *             KICK self-inflicted.
 *
 * WHAT IS NOT IN ANY ROW, and why. No account, no realname and no gecos: 4.3
 * names those for the SBURST vocabulary, not for a single state change, and
 * carrying a realname on every JOIN would make each join a few dozen bytes for
 * a field only the burst needs. No timestamp either -- 333's time is the
 * origin's clock, and a relayed clock is worse than no clock, so the receiver
 * reads topic_when from the origin's own record and a re-burst corrects it.
 *
 * ---------------------------------------------------------------------------
 * SQUIT, WHICH IS NOT ONE OF THOSE ROWS, AND WHY
 * ---------------------------------------------------------------------------
 *   SQUIT     <server> [<reason>]
 *             `:irc.b S@1 SQUIT irc.b :bye`
 *
 * It is frozen here rather than in the table above because it is a DIFFERENT KIND
 * of line: every row above is about a CHANNEL, at a parameter position the verb
 * fixes, and this one names a SERVER and no channel at all. The prefix is the
 * server that is going away, which is also this node's own name on the emission
 * federation/link.c makes when one of its links dies.
 *
 * THE REASON IS OPTIONAL AND NEVER SENT BY THIS NODE, and both halves of that
 * are the decision rather than an omission. It is optional because 3.2's rule --
 * a value needing ':' is only representable in the final position -- makes a
 * trailing free-text parameter the one safe place to put a reason, so an
 * implementation that has one can send it without a second grammar. It is never
 * sent because nothing on this node has a reason for a peer to depart: there is
 * no shutdown notice, no kick threshold and no admin action, and an unused field
 * on a wire format is a field a second implementation has to guess about. The
 * receiver reads the first parameter and ignores the rest, so a peer that sends
 * one is interoperable rather than refused.
 *
 * IT IS NOT IN S_VERBS ABOVE, and that is the same conclusion the link keepalive
 * reaches (see the top of this file). That table maps CLIENT verbs a node
 * RELAYS, and a node announcing its own departure relays nothing -- and the
 * column on the left is a client verb, so a row here would claim a client-facing
 * SQUIT that this node does not have. The line is named directly at its one
 * emission site and queued through the same fed_queue_line() as every other
 * outbound peer line, which is the half that genuinely is shared.
 *
 * WHAT IT DOES ON RECEIPT: it purges that server's remote roster entries and its
 * name from every channel's servers[] -- PER ORIGIN, never a global wipe -- and
 * it is REFUSED, counted on its own counter, and does not touch the link when it
 * names THIS node. 2.2's fail-closed rule is about a LINK that is down, which is
 * a different fact from a SERVER that has announced its own departure, and the
 * two are deliberately not treated alike.
 *
 * ---------------------------------------------------------------------------
 * WHY server_queue() AND NOT reply()'s DOOR
 * ---------------------------------------------------------------------------
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
                   const char *const *params, int nparams);

/* How many parameters the S-verb for `client_verb` carries at most. The frozen
 * shapes above are what this is the length of, and it exists so that a caller
 * sizing an array has one number to ask for rather than a copy of the table. */
/* RAISED FROM 4 TO 5 IN PHASE 10.3, and the bound is the SJOIN's four parameters
 * plus nothing else -- so the largest shape the S-verb family has is now FIVE, not
 * four, and a caller that sized an array by the old number would have been one slot
 * short for exactly one verb. Derived from the shapes above rather than picked:
 * SJOIN is <channel> <member> <flags> <account>, SMODES is <server> <chan> <modes>
 * [<arg>], and SKICK is <member> <chan> <target> [:reason]. */
#define FED_SVERB_MAX_PARAMS 5

/* ---------------------------------------------------------------------------
 * WHY THE SCRATCH BUFFER IS THE CALLER'S
 * ---------------------------------------------------------------------------
 * fed_sverb_params() writes POINTERS into `out`, and two of the values those
 * pointers name do not exist anywhere else: the member nick, which is cut out of
 * the source prefix, and the SJOIN flag token, which is RENDERED from the
 * channel's own record. Both are derived, so neither is a caller's string and
 * neither may be a callee's.
 *
 * A callee's own local array would be the obvious thing to use and it is a
 * use-after-return: `out` outlives the call by construction -- the caller is
 * about to render a line from it -- and a pointer into a frame that has been
 * reused by the time the renderer runs reads whatever is there now. That is not
 * a theoretical defect; it is what this file did first, and it put empty
 * parameters on the wire. So the storage is named, sized, and owned by whoever
 * outlives the pointers, and the two `feed_forward_*` entry points in
 * core/fanout.c each declare one.
 */
typedef struct {
    char nick[IRC_MAX_NICK + 1]; /* the member, split from the source prefix */
    char flags[4];               /* the SJOIN flag token: "+o", "+ov" or "-"   */
    /* 4.3's SJOIN <account>, added in Phase 10.3: the account name, or the `*`
     * that means "not logged in to an account". See fed_member_account() for why
     * it is read out of the MEMBERSHIP rather than out of a nick record. */
    char account[CONN_MAX_ACCOUNT + 2];
} fed_sverb_scratch_t;

/* Build the S-verb's parameter list for `client_verb` from a CLIENT emission.
 * Writes at most FED_SVERB_MAX_PARAMS pointers into `out` and returns how many
 * it wrote, or -1 on a bad argument or a client shape it does not know how to
 * re-shape.
 *
 *   client_verb  the uppercased client verb; the one fed_sverb_for() maps.
 *   target       the target -- a channel name (canonicalised) or a user -- which
 *                becomes the FIRST S-verb parameter. It is passed separately
 *                because it is 2.2's canonical form rather than the client's
 *                spelling of it, and every S-verb wants it in a fixed position
 *                that differs per verb.
 *   params        the CLIENT parameters AFTER the target, and nparams of them.
 *   prefix        the source prefix, from which the member nick is taken.
 *   self          this node's name, which SMODES carries as its subject.
 *   ch            the channel the emission is about, or NULL. SJOIN reads the
 *                member's prefix flags out of it rather than being handed them:
 *                the flags are a property of the MEMBERSHIP, and the node
 *                forwarding the join is the node that just made it, so its own
 *                record is the authority. A NULL `ch` yields the `-` empty
 *                case, which is a legal line and not a silent wrong one.
 *
 * WHY A FUNCTION AND NOT A TABLE OF STRINGS. The mapping is a function of the
 * verb's SHAPE -- where the channel goes, where the member goes, which field is
 * optional -- and a table of format strings would be a second grammar that
 * could disagree with the decoder for exactly the reason this file's header
 * gives for freezing the encode side before writing the decode side. The shapes
 * are in the comment above, and this is the only code that builds one.
 */
int fed_sverb_params(const char *client_verb, const char *target,
                     const char *const *params, int nparams, const char *prefix,
                     const char *self, const chan_t *ch,
                     fed_sverb_scratch_t *scratch, const char **out, int cap);

/* ---------------------------------------------------------------------------
 * The DECODE side
 * ---------------------------------------------------------------------------
 */

/* The server half of a source prefix, or NULL when there is none to have.
 *
 * 2.1 splits `nick@server` at the LAST '@', and the split is unambiguous
 * because '@' is not a legal nick character (2.1's own charset rule, which is
 * why valid_nick() exists). A prefix with no '@' at all is a SERVER prefix and
 * is the name itself.
 *
 * The discriminator this exists for is THE PREFIX, not the verb, and getting it
 * wrong is the failure that makes an untagged relay dangerous rather than merely
 * untidy: a peer relaying a message it received FOR A CHANNEL IT HAS A MEMBER IN
 * sends `SPRIVMSG` with a REMOTE prefix, and any rule keyed on the verb would
 * accept that as a fresh origin and inject an un-loop-guarded duplicate of a
 * message the mesh already has. The prefix is what says whether this node is the
 * source of the line or merely the courier, and the courier case is the one that
 * has to be refused.
 *
 * Writes at most `cap` bytes (including the NUL) and returns `out`, or NULL
 * when the prefix is NULL, empty, over-long, or names a server that is not a
 * legal 2.4 tag value. A refusal is a refusal rather than a truncated copy: a
 * server name this node cannot stamp is a name 2.4's dedup key cannot hold, so
 * accepting it would mean a message with an identity the dedup store cannot
 * record.
 */
const char *fed_prefix_server(const char *prefix, char *out, size_t cap);

/* One inbound peer line: the DECODE side, and the guard chain.
 *
 * This is not a second dispatch. commands_dispatch() calls it for a CONN_SERVER
 * connection and returns, which is 3's "dispatch never asks 'is this local or
 * remote?'" with `src->kind` as the only difference -- so there is exactly one
 * entry into a command and one place the peer path diverges from the client one,
 * and that place is above the CONN_CLOSING check for the reason commands.c
 * states there.
 *
 * The guards, in order, each of which either passes the line on or returns:
 *
 *   G0  NULL arguments or no command word. No counter: a caller that got here
 *       with no message has a bug upstream of the wire.
 *   G1  Not FEDERATE and the connection is not an ESTABLISHED link. Dropped and
 *       counted; the link is NOT torn down. A pre-auth line on a listener
 *       connection is a stranger, and the answer to a stranger is the handshake
 *       in federation/link.c, not a closed socket.
 *   G2  FEDERATE. Handed to fed_on_federate() and done -- it is the verb that
 *       ESTABLISHES link->epoch, so it is exempt from every tag rule below by
 *       construction rather than by a special case in the middle of them.
 *   G3  Still not ESTABLISHED. Unreachable after G1 and kept AS the assertion
 *       that the two cannot disagree: a counted return rather than a silent one,
 *       so a future edit that reorders G1 and G3 leaves a number behind instead
 *       of a hole.
 *   G4  No legal 2.4 block. THE TRUST BOUNDARY, and it is FOUR cases rather than
 *       one, discriminated by the prefix and not by the verb -- see below.
 *   G5  hops >= IRC_MAX_HOPS. 2.4's ceiling.
 *   G6  The origin is THIS node. 2.4's never-forward-own-origin, inbound half.
 *   G7  fed_dedup_seen() says this (origin, epoch, id) is already known. The
 *       record happens HERE, at the guard, not after the handler.
 *   G8  The verb is not in 4.3's list. The SBURST family is asked HERE rather
 *       than in the table, because its five verbs have five different shapes and
 *       no common channel position; everything above still applies to it, which
 *       is the point -- a burst is state replacement and is deduplicated like
 *       anything else. SQUIT is asked here too, for the same structural reason
 *       (it names no channel at all, so there is no position to read) and NOT for
 *       the burst's reason: it is a state-destroying line, so being deduplicated
 *       by the chain above is exactly what it needs.
 *   G9  Arity and field validation for that verb. The burst verbs validate
 *       their own arity in federation/burst.c, because the format is stated
 *       there and five shapes do not fit one range column.
 *   G10 The handler.
 *
 * WHY THE CHAIN IS STRAIGHT-LINE AND INSIDE THIS FUNCTION. A guard chain that
 * is a separate function from the dispatch is a guard chain a future verb can
 * route around: `if (verb == "SNAMES") { skip the hop check; }` is the shape
 * that produces a loop, and it is only available if the guards are somewhere a
 * caller can decline to call. One `return` per guard, in one function, is the
 * cheap version of "there is no way to skip a guard".
 *
 * G4, THE FOUR CASES, because "no tag block" is not one situation:
 *   A  the prefix names the link's OWN server. The peer ORIGINATED the line.
 *      Accepted, and the identity is SUPPLIED rather than read: {origin =
 *      link->name, epoch = link->epoch, id = server_next_msg_id(s), hops = 0}.
 *      See the comment at the point of use for why the PEER's epoch is the one
 *      that belongs there.
 *   B  the prefix names anyone else. The peer is RELAYING and did not stamp the
 *      line. Refused, counted, and the link is NOT torn down: every 2.4 guard is
 *      unavailable on an untagged relay, and a node that accepts them has no
 *      loop prevention at all.
 *   C  SNAMES/SQUIT/SHASH and the reply-shaped verbs. Refused untagged for
 *      the same reason as B, and by a different route: they name state the
 *      SENDER holds, so a relayed one is a claim about somebody else's memory.
 *      FEDERATE is exempt by construction (G2).
 *   D  anything else -- an untagged line with a server prefix that is neither
 *      the link's own name nor a legal 2.4 value. Refused as malformed.
 *   E  SBURST and its four record verbs, untagged from the link's own server.
 *      This one is NOT a case A, which mints an identity for the line. A burst
 *      is O(n) lines forming ONE transaction and case A mints per line, which is
 *      right for dedup and wrong for a state replacement: a peer that could send
 *      an untagged burst could make this node replace its whole view of that
 *      origin, repeatedly, on lines whose 2.4 identity this node invented. The
 *      one family that REPLACES state is therefore the one family required to
 *      carry its identity. Counted as malformed rather than as a relay -- a peer
 *      sending this is not relaying somebody else's burst.
 */
void fed_dispatch(server_t *s, conn_t *c, const message_t *m);

/* ---------------------------------------------------------------------------
 * The node-wide forward, for the verbs that are about the NODE and not about a
 * channel
 * ---------------------------------------------------------------------------
 */

/* Put `sverb` on every ESTABLISHED link, with `prefix` as the message prefix and
 * NULL as `carry` -- this node is ORIGINATING, so 2.4's identity is minted at each
 * forward rather than relayed. Returns how many links carried it.
 *
 * IT EXISTS BECAUSE 4.3's VERB SET HAS TWO SHAPES and the SQUIT arm was the only
 * one of them implemented. A verb that names a CHANNEL is forwarded through
 * fanout_forward_channel_sverb(), because the set of links is the set of links
 * holding that channel -- a smaller set, and a different criterion. A verb that
 * names NOTHING is about the node, and every established link is interested,
 * because every one of them holds a claim about the same fact. SQUIT is the
 * implemented example, and its arm is left where it is: it needs to skip the link
 * it arrived on and a link named by the line itself, and expressing those as
 * arguments to a general helper would put a SQUIT's two special cases in a
 * function that has no business knowing about SQUIT.
 *
 * `prefix` MAY BE NULL, which renders the line with this node's own name -- the
 * correct prefix for a state change this node decided on its own. It is a
 * parameter rather than always s->name because the one caller in this build
 * (commands.c's rename-the-loser) has a client's hostmask to render, and a
 * function that could not carry one would force that line to lose the only part of
 * it a reader can use.
 *
 * `carry` IS NOT A PARAMETER, and that is deliberate: everything this node
 * forwards on its own account originates here, and a relay that needed to
 * re-broadcast someone else's node-wide fact would be a third case, which does
 * not exist yet. Adding a `carry` parameter for a caller that does not exist is
 * how a function ends up with an unreachable branch. */
int fed_forward_all(server_t *s, const char *sverb, const char *prefix,
                    const char *const *params, int nparams);

#endif /* IRC_FEDERATION_VERBS_H */
