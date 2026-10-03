/* fanout.h -- the 3.1 routing table, and the target resolution that feeds it.
 *
 * Authority: docs/SERVER_DESIGN.md 3.1 (the fan-out rules, including the verb
 * class), 2.2 (origin-owned channels and the local/remote member split), 3
 * (the reply-path invariants), 2.1 (scoped identity) and 4.3 (the S-verbs the
 * forward leg will use).
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE EXISTS AT ALL
 * ---------------------------------------------------------------------------
 * Section 3.1 is a TABLE, and a table that is transcribed once per verb is a
 * table with six copies to keep in step. Phase 4's channel verbs grew their own
 * broadcast helper for the same reason this module exists (see chan_verbs.h):
 * the moment each handler decides for itself where a message goes, the
 * single-writer discipline of 2.2 becomes a convention rather than a property.
 *
 * So the seam is deliberately shaped as TWO steps, and the split is the point:
 *
 *   fanout_resolve()   "what did this name refer to"  -> a fanout_target_t,
 *                      which carries the 3.1 VERB CLASS alongside the target
 *   fanout_deliver()   "3.1 says where a message of this class goes to that
 *                      target"
 *
 * Resolution is the only place that answers "is this a channel or a nick", and
 * delivery is the only place that answers "local write, forward, or both". The
 * verb class is carried in the resolved target rather than passed separately to
 * the sender, so a handler cannot resolve a target and then deliver it under a
 * different class -- the most likely way a table like 3.1 gets subtly wrong.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS REACHABLE NOW, STATED PLAINLY
 * ---------------------------------------------------------------------------
 * A node with a peer link can reach every row except the last one. What it
 * cannot reach, still, is the last row's RESOLUTION: `nick@server` names a user
 * on another server, and the registry of remote nicks 2.1 says that needs
 * (qualify()'s inverse) only exists once SBURST has run. The row is routed and
 * the resolution is not, which is a different statement from "the row is
 * unreachable" and the honest one.
 *
 *   local user           reachable, both classes
 *   owned channel        reachable, both classes
 *   non-owned channel    reachable, both classes -- a peer reports the channel
 *                        and this node's authority_ok() returns FORWARD rather
 *                        than 437
 *   remote user          NOT resolvable yet (no remote nick registry; SBURST)
 *
 * The unreachable row is implemented anyway, and the reason is not optimism:
 * 3.1 is the contract Phase 6 has to honour, and a row that is not written down
 * is a row Phase 6 re-derives, probably differently. It refuses rather than
 * pretending, and says so on the node's observable output, so a federated node
 * that reached one would be visibly missing something rather than silently
 * dropping a message.
 *
 * ---------------------------------------------------------------------------
 * THE FORWARD LEG IS NOT reply()
 * ---------------------------------------------------------------------------
 * Section 3 is explicit that numerics are never written to a peer link, and
 * reply() is the single place that enforces it. A RELAYED MESSAGE is a
 * different thing from a numeric: it goes to a peer deliberately, as protocol,
 * and reply() would refuse it. So delivery to a peer happens HERE, in the
 * fan-out path, and never in reply(). Keeping the two apart is what lets Phase 6
 * add a forward without unpicking the reply invariant -- and it is why
 * fanout_forward_link() below is a named function with a body rather than a
 * comment where code ought to be.
 */
#ifndef IRC_CORE_FANOUT_H
#define IRC_CORE_FANOUT_H

#include <stddef.h>

#include "core/channel.h"
#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"

/* 3.1's VERB CLASS. This is the column of the table that the previous version
 * of the design got wrong -- a non-owner with local members matched both "remote
 * channel, forward only" and "local channel with remote members, write AND
 * forward" -- and 3.1 resolves it by splitting the verbs:
 *
 *   message       a line of text travelling through the node. It changes no
 *                 state any peer has to agree about, so delivering it locally
 *                 is never a divergence and dropping it is only a lost message.
 *   state-change  a fact about the channel itself: JOIN, PART, TOPIC, MODE,
 *                 KICK. 2.2's single-writer rule applies, so a node that cannot
 *                 route one to the origin must not apply it locally.
 *
 * PRIVMSG and NOTICE are `message`; JOIN, PART, TOPIC, MODE and KICK are
 * `state-change`, and since C3 they reach fanout_deliver() through
 * chan_verbs.c rather than through that file's own broadcast helper. The class
 * is in the resolved target so that there is one place to ask.
 *
 * WHAT THE CLASS NOW DECIDES, after §3.1's owned/`message` row was amended: one
 * thing only -- whether the caller also writes locally. It does NOT choose a
 * forward target set, because the two owned rows name the same one and the two
 * non-owned rows name the same one. The split still earns its keep: it is what
 * keeps 2.2's single-writer rule (no local write for a state change this node
 * cannot route) separate from "a message this node has nobody to deliver to is
 * still worth forwarding". Read the correction in 3.1 before changing either. */
typedef enum {
    FANOUT_MESSAGE = 0,
    FANOUT_STATE_CHANGE = 1
} fanout_class_t;

/* The resolved target's kind, which is 3.1's first column. */
typedef enum {
    FANOUT_NONE = 0,
    /* "local user | either | write to conn_t" */
    FANOUT_LOCAL_USER,
    /* "owned channel" rows. `chan` is non-NULL and chan_origin_state() is
     * CHAN_ORIGIN_SELF. */
    FANOUT_LOCAL_CHANNEL,
    /* "non-owned channel" rows. `chan` is non-NULL and the origin is elsewhere.
     * Unreachable on a single node; see the file header. */
    FANOUT_REMOTE_CHANNEL,
    /* "remote user nick@server | either | forward to that server".
     *
 * 3.1's LAST ROW IS DELIBERATELY NOT HERE, and that is a real omission
 * rather than an oversight: the row's target is a user on another server,
 * and 2.1 says naming one needs qualify()'s inverse -- "which server holds
 * the user called X" -- which is a registry of remote nicks that only
 * exists once SBURST has run. Until then `nick@server` resolves to nothing,
 * and 2.1 already anticipated this ("qualify() belongs to the phase that
 * first has a remote user to name"). Listing an enumerator nothing can
 * produce would be a promise this node does not keep. */
    FANOUT_REMOTE_USER
} fanout_kind_t;

/* A resolved target. `name` is the target AS THE CLIENT WROTE IT, except that
 * a channel name is canonicalised (2.2 stores names uppercase-normalised, so
 * "#t" and "#T" are one channel and the reply and the log must agree).
 *
 * The width is written as the larger of the two things a target can be, so
 * raising conn_t::nick or chan_t::name cannot leave this buffer short: a
 * nickname is IRC_MAX_NICK bytes and a channel name is CHAN_MAX_NAME, and the
 * struct widths they come from are 64 either way. */
#define FANOUT_NAME_MAX 64

typedef struct {
    fanout_kind_t  kind;
    fanout_class_t vclass;   /* 3.1's column, decided once, in resolution */
    conn_t        *user;     /* FANOUT_LOCAL_USER */
    chan_t        *chan;     /* the two channel kinds */
    char           name[FANOUT_NAME_MAX];
} fanout_target_t;

/* ---------------------------------------------------------------------------
 * Resolution
 * ---------------------------------------------------------------------------
 */

/* Resolve `arg` -- a <msgtarget>, exactly as it arrived -- into `*out`.
 *
 * Returns 1 when the target was resolved, 0 when it was not. On 0 `*out->kind`
 * is FANOUT_NONE, and the right numeric has ALREADY been sent to `from` -- so a
 * caller that returns on 0 has said something. A resolve that fails in silence
 * is worse than no resolve at all, because the client waits.
 *
 * `from` MAY BE NULL, which means "a caller with nobody to answer" and skips
 * the numerics without changing what resolves. That is federation/verbs.c's
 * guard chain: a peer naming a channel this node does not hold is a fact about
 * the mesh, not about a client, and a numeric on a CONN_SERVER connection would
 * be refused anyway and would put a non-zero on the counter server.h says should
 * be zero forever.
 *
 * Which numerics, and why these:
 *
 *   401  the name is not a channel and no local user holds it. 401 is the
 *        RFC 2812 3.3.2 answer for a target that does not resolve.
 *   403  the name LOOKS like a channel (it starts with one of 005's CHANTYPES)
 *        but is not a channel name this node can speak about, or it is a
 *        well-formed name the node holds no such channel for. "No such
 *        channel" and "not a nick either" are the same complaint, and 404/442
 *        would both be wrong here: the problem is the NAME, not the caller's
 *        membership.
 *   nothing at all for `nick@server`. See FANOUT_REMOTE_USER.
 *
 * `vclass` is recorded into the result. It is the only way a caller supplies
 * the class, which is what makes "resolve under one class, deliver under
 * another" unrepresentable.
 *
 * The membership question is NOT answered here and deliberately so: whether a
 * sender may address a channel they are not on is a property of the VERB (see
 * the comment on fanout_is_member's caller), not of the target, and 3.1 does
 * not mention it. Put it in this function and a second verb with a different
 * rule would have to special-case its way out of it. */
int fanout_resolve(server_t *s, conn_t *from, const char *arg,
                   fanout_class_t vclass, fanout_target_t *out);

/* Is `c` a member of the channel `t` names? 1 for either channel kind with `c`
 * on the member list, 0 otherwise (including for a user target, which has no
 * membership). */
int fanout_is_member(const fanout_target_t *t, const conn_t *c);

/* ---------------------------------------------------------------------------
 * Delivery -- 3.1's table, transcribed once
 * ---------------------------------------------------------------------------
 */

/* Deliver one line of `verb` carrying `params`, prefixed with `prefix`, to
 * whatever `*t` resolves to under the class recorded in `*t`.
 *
 * `params` are the parameters AFTER the target, and the target is `t->name` --
 * 2.2's canonical form, not the client's spelling. That split is the reason
 * `text` is not a parameter any more: a state change is not one trailing
 * string. `MODE #T +o bob` is three parameters, and rendering it as a single
 * `text` would colon the mode argument and hand every local client
 * `MODE #T :+o bob`, which RFC 2812 3.3.2 does not describe and which the
 * Phase 4 tests correctly refuse. So the list is the list, and the target is the
 * one the resolver already canonicalised.
 *
 * `exclude` is the sender when a verb's RFC rule says it must not see its own
 * message -- NOTICE, and only NOTICE -- and NULL when it must (PRIVMSG). It is
 * a parameter rather than a flag on the class because the two are DIFFERENT
 * things: `message` says how 3.1 routes, `exclude` says whether the author is
 * in the audience. Folding them together would make a second no-echo verb
 * impossible to add without editing 3.1's own vocabulary.
 *
 * Returns the number of CLIENTS the line was queued for. A zero return is not
 * an error by itself: an empty channel has nobody to write to, and a NOTICE to
 * the sender's own nick is suppressed by exactly the rule the caller asked for.
 * Callers that need to tell those apart ask the kind, not the count.
 *
 * THE VERB CLASS IS NOT A PARAMETER AND THAT IS THE POINT. It was decided once,
 * in fanout_resolve(), and is read out of the resolved target here, so a handler
 * cannot resolve a target under one class and deliver it under another. That
 * single fact is what makes "a channel message is delivered exactly once"
 * structural: the row a target took when it was resolved is the row it is
 * delivered by, and there is no second decision in between to disagree.
 *
 * `carry` is 2.4's identity for the emission, or NULL for a line this node is
 * ORIGINATING. Every handler passes NULL, because a handler is handed a line from
 * a client and a client has no 2.4 identity; federation/verbs.c passes the tags
 * the line arrived with, and that is the whole reason this is an argument here
 * rather than a private detail of the relay path.
 *
 * IT NOW REACHES MORE THAN THE FORWARD ARM, and that is the second reason it is
 * an argument. This function computes the emission's 2.4 identity ONCE -- minting
 * it for an originating emission, carrying a received one and adding the hop
 * otherwise -- and hands the SAME stamp to the local write and to every forward
 * target. The local write renders it as the IRCv3 `msgid` a client sees; the
 * forward puts it on the wire. Before, only the forward saw it, which meant an
 * emission forwarded to two peers was stamped with two different ids and a client
 * on this node had no id to show at all.
 *
 * IT IS AN ARGUMENT FOR THE SAME REASON IT IS NOT A FIELD ON THE TARGET, one
 * level up: an identity is a property of ONE emission, and a resolved target is
 * a cache entry that outlives the call. Putting it on the target would make
 * (origin, epoch, id) a property of the channel for as long as the channel
 * exists -- a different fact with the same name, and one that would be wrong on
 * the very next message.
 *
 * IT IS ALSO THE REASON THE RELAY PATH IS NOT A SECOND DELIVERY. Before this
 * parameter, federation/verbs.c's SPRIVMSG handler wrote locally through
 * fanout_deliver() and then forwarded the same line itself, which meant a
 * received `message` was forwarded TWICE on a node that had a forward arm: once
 * by this function, with a FRESH id because it had no carry, and once by the
 * handler with the received one. That was unreachable while an owner forwarded
 * nothing -- a `message` only ever crossed a link leaf -> owner, and an owner
 * had no forward arm to double up on -- and the 3.1 amendment is what made it
 * reachable. The handler now hands its tags here and forwards nothing itself, so
 * one emission is forwarded once, and with the identity it actually has.
 *
 * Never blocks and never closes: the write path marks CLOSING and the reaper
 * closes, as 3.4 requires. */
/* As fanout_deliver(), with NO FORWARD. Writes the target's LOCAL destinations
 * and stops: a peer never sees this line.
 *
 * IT EXISTS FOR 2.1's RENAME-THE-LOSER, and the reason is a count rather than a
 * feature. A rename is ONE fact about ONE user, and the mesh needs it once: the
 * SNICK that fed_nickreg_resolve_local() puts on every established link. A rename
 * fanned out per shared channel would send a peer one SNICK-equivalent per channel
 * the user is in, and a peer that applied each would report N renames for one user
 * -- and one that deduped them would be relying on 2.4's identity to collapse N
 * distinct lines that are, by construction, not the same line. The local members,
 * on the other hand, are a SET TO ADDRESS and every one of them needs the line.
 *
 * So the two halves of a rename go by two paths on purpose: one call per channel
 * for the clients, and exactly one node-wide call for the mesh. A function that
 * did both would make the count of mesh emissions a function of how many channels
 * a user happens to be in.
 *
 * `carry` IS NOT A PARAMETER, and the reason is that a local-only emission
 * ORIGINATES: every current caller produces the fact here and now, and a relay
 * that needed to re-broadcast it has federation/verbs.c's forwarding instead. */
int fanout_deliver_local(server_t *s, const fanout_target_t *t, const char *prefix,
                         const char *verb, const char *const *params, int nparams,
                         conn_t *exclude);

int fanout_deliver(server_t *s, const fanout_target_t *t, const char *prefix,
                   const char *verb, const char *const *params, int nparams,
                   conn_t *exclude, const irc_serve_tags_t *carry);

/* ONE WIRE SHAPE: a parameter list and its length. A struct rather than two more
 * arguments because the thing it carries IS a list, and a shape with a length is
 * the shape every parameter in this file already has. */
typedef struct {
    const char *const *params;
    int         nparams;
} fanout_form_t;

/* As fanout_deliver(), for an emission whose PARAMETERS -- not merely its tags --
 * differ per destination. `plain` is the shape everybody gets; `extended` is the
 * shape a destination that negotiated `extended-join` gets instead. A NULL
 * `extended` means one shape for all, and is exactly fanout_deliver().
 *
 * WHY IT IS A SEPARATE ENTRY POINT AND NOT A FLAG. `extended-join` changes the
 * JOIN from `:nick!user@host JOIN #chan` to `:nick!user@host JOIN #chan <account>
 * :<realname>`, and those are two different messages rather than two decorations
 * of one. Every tag in this file is a per-destination decision because a tag is
 * not part of what the line MEANS; a parameter is. A client that did not ask for
 * the extension and received the two extra ones would read the account name as a
 * topic and the realname as a reason, and it would do that silently.
 *
 * WHAT THE FORWARD DOES WITH IT, because this is where the two shapes have to be
 * reconciled: **the forward always uses `plain`.** The peer-facing form of a JOIN
 * is 4.3's SJOIN, and its shape is decided by federation/verbs.c's
 * fed_sverb_params() from the channel's own membership -- which is where the
 * account and the flags both come from. Handing `extended` to the forward would
 * give a peer two different JOIN shapes depending on which of its clients had
 * negotiated a capability, which is precisely the divergence 4.3's single frozen
 * shape exists to prevent.
 *
 * The identity is minted once for both shapes, exactly as it is for the tags, so
 * a client that receives the plain form and a peer that receives the SJOIN are
 * looking at one emission. */
int fanout_deliver_forms(server_t *s, const fanout_target_t *t, const char *prefix,
                         const char *verb, const fanout_form_t *plain,
                         const fanout_form_t *extended, conn_t *exclude,
                         const irc_serve_tags_t *carry);

/* As fanout_deliver_local(), for an emission whose parameters differ per
 * destination, and with the SAME reason for existing: the extended JOIN is a
 * local emission with no forward leg, and a future caller that resolved a channel
 * and wanted the extension would otherwise have to reimplement the member walk.
 *
 * `carry` is still not a parameter, for fanout_deliver_local()'s reason: a
 * local-only emission originates here. */
int fanout_deliver_local_forms(server_t *s, const fanout_target_t *t,
                               const char *prefix, const char *verb,
                               const fanout_form_t *plain,
                               const fanout_form_t *extended, conn_t *exclude);

/* ---------------------------------------------------------------------------
 * THE THIRD OUTCOME: "SEND THIS MEMBER NOTHING"
 * ---------------------------------------------------------------------------
 * The two wire SHAPES above answer "which of these two lines does this
 * destination get", which is a choice between two answers and therefore cannot
 * express a third one: a member who is not supposed to hear about an emission
 * at all. Three specifications need that third answer, and each needs it for the
 * same reason -- the notification is UNSOLICITED and goes only to clients that
 * asked for it:
 *
 *   setname        "to all clients in common channels, as well as to the client
 *                   from which it originated"
 *   chghost        "to other clients who share channels with the target client
 *                   and who have enabled the `chghost` capability"
 *   away-notify    "clients will be sent an AWAY message when a user sharing a
 *                   channel with them sets, changes or removes their away state"
 *
 * THREE HANDLERS WALKING THE ROSTER THEMSELVES IS THE ALTERNATIVE, and it is the
 * one this module exists to prevent: chan_verbs.c grew a broadcast helper in
 * Phase 4 for the same reason this file exists (see the header), and it had no
 * forward arm, and the missing forward was lost. A second walk in a handler is a
 * walk that can drift from the first, and a walk that skips `chan_member_live()`
 * is a refusal counted on n_reply_refused -- the counter reply.c keeps at zero
 * because a non-zero value is a bug report. So the audience question is asked
 * HERE, once per destination, in the one place that already asks the shape
 * question once per destination.
 *
 * WHY IT IS A PREDICATE AND NOT A THIRD FORM. A third `fanout_form_t` holding an
 * empty parameter list would still be a LINE: `nick!user@host AWAY #chan` with no
 * trailing text says "this user is not away" whether it was sent because they
 * stopped being away or because the client was never told. Absence is the
 * assertion here, exactly as it is for `account-tag`'s tag, so the outcome has to
 * be the absence of a line and not a line that means nothing. (The away case is
 * the sharp one: `AWAY` with no parameter means "no longer away", so a node that
 * sent it to a client which did not ask would be asserting a state change that
 * did not happen.)
 *
 * THE SIGNATURE, and why `dst` is the only destination-side datum: a gate is
 * asked once per destination from inside the walk, so a predicate taking only the
 * destination can be an ordinary function -- `cap_away_notify_enabled` has exactly
 * this shape and is handed over with no glue at all. Everything about the
 * EMISSION that the audience depends on arrives through `ctx`, because the
 * alternative would be a per-emission closure and C has no room for one here.
 *
 * A NULL `gate` means "every destination the emission reaches", and is exactly
 * fanout_deliver_local_forms(). The same sentence, for the same reason: a NULL is
 * the case that already works rather than a second implementation of it.
 *
 * WHAT THE GATE DOES NOT DO. It does not affect the forward arm, and there is
 * nothing for it to affect: a gate is asked about a LOCAL DESTINATION, and the
 * forward arm has none -- a peer is not a client that negotiated anything. That
 * is also why there is no gated variant of fanout_deliver_forms(): the question
 * is unaskable there rather than answerable-but-ignored, and a parameter a caller
 * can set on a path where it cannot mean anything is a parameter that will be set
 * and believed.
 *
 * The order inside the walk is liveness, then `exclude`, then the gate, and it is
 * cheapest-first: a member whose descriptor the loop has already dropped, and a
 * member the caller excluded, are not asked a question about an emission they
 * were never going to receive.
 */
typedef int (*fanout_gate_fn)(const conn_t *dst, void *ctx);

/* As fanout_deliver_local_forms(), and a destination for which `gate` returns 0
 * receives NOTHING: no line, no tag block, no entry in the returned count.
 *
 * Returns the number of CLIENTS the line was queued for, which -- as everywhere
 * else in this file -- is a count of deliveries and not a count of destinations
 * reached. A gated-off member is not a destination that was reached and declined,
 * so a caller cannot tell the two apart from the number; nothing needs to, and a
 * caller that did would be asking the count a question it cannot answer. */
int fanout_deliver_local_gated(server_t *s, const fanout_target_t *t,
                               const char *prefix, const char *verb,
                               const fanout_form_t *plain,
                               const fanout_form_t *extended, fanout_gate_fn gate,
                               void *gate_ctx, conn_t *exclude);

/* ---------------------------------------------------------------------------
 * THE FOURTH OUTCOME: "TO THE PEOPLE WE SHARE A CHANNEL WITH, EXACTLY ONCE"
 * ---------------------------------------------------------------------------
 * The gated entry point above addresses ONE channel, and a caller with more than
 * one would loop it -- which is right for every emission whose line NAMES the
 * channel, and wrong for the one that does not.
 *
 * `setname`'s server-to-client line is `:nick!user@host SETNAME :<realname>`: the
 * specification's shape carries NO channel parameter, because it is a statement
 * about a *person* and not about a channel. So a per-channel emission puts a
 * `#channel` where a client expects the realname, and hands a member of three
 * shared channels three byte-identical copies of one fact. Neither is what the
 * specification says, and the second is `echo-message`'s defect reached from the
 * other side: one announcement, delivered more than once.
 *
 * So this addresses the UNION of `chans[]` -- which is the caller's own
 * `conn_t::chans`, 2.2's second index, kept in step with the channel's list by
 * chan_attach_conn() -- and writes each destination ONCE.
 *
 * DE-DUPLICATION IS A SEARCH AND NOT A SET, which is why there is no bounded
 * cache here and so no teardown arm to forget: "already reached?" is "is this
 * member of a channel at a LOWER index", answered against structures the channel
 * layer already owns and frees. The bound is `nchans * nmembers`, both of which
 * are compile-time constants in headers this node already treats as limits.
 *
 * NO FORWARD, and for the same reason fanout_deliver_local() has none: this is an
 * ORIGINATING emission, one that happens in response to a command this node just
 * read. There is no `carry` parameter for the same reason there is none there.
 *
 * THERE IS NO GATED VARIANT OF THE FORWARDING PATH, still, and this function does
 * not change that: it is a LOCAL emission by construction.
 */
int fanout_deliver_union_local_gated(server_t *s, struct chan *const *chans,
                                     size_t nchans, const char *prefix,
                                     const char *verb, const fanout_form_t *plain,
                                     const fanout_form_t *extended,
                                     fanout_gate_fn gate, void *gate_ctx,
                                     conn_t *exclude);



/* ---------------------------------------------------------------------------
 * The forward leg
 * ---------------------------------------------------------------------------
 * The ONE place a line leaves this node toward a peer, as 4.3's S-verb
 * (SPRIVMSG, SNOTICE, SJOIN, ...) with the 2.4 internal tag block stamped on it.
 *
 * Exposed rather than kept static for one reason: it is the seam. It is the
 * only function in src/ whose job is "put a protocol message on a peer link",
 * and Phase 6 implements it once, here, instead of growing a second place that
 * decides how a message leaves the node.
 *
 * `carry` is the 2.4 identity of the message, or NULL, and it is the whole
 * contract of this function:
 *
 *   carry == NULL   this node is ORIGINATING. The stamp is minted here: origin
 *                   is this node's name, epoch is this node's, the id is the
 *                   next from the per-SERVER counter (2.4), and hops is 0.
 *
 *   carry != NULL   this node is RELAYING. origin, epoch and id are carried
 *                   through UNCHANGED and only hops becomes carry->hops + 1.
 *
 * The invariance of (origin, epoch, id) across every forward is the single most
 * load-bearing property in 2.4, and it is stated here rather than left to be
 * discovered: restamping on relay gives the copy a new identity, the dedup store
 * on the far side treats it as a message it has never seen, and the message
 * comes back. That is the loop, and it is not bounded by the hop ceiling in any
 * useful sense because each pass through the mesh mints a fresh id. hops is the
 * ONLY field a forward may change.
 *
 * The refusals, all of which return 0 and all of which say so on the
 * observable output rather than returning quietly:
 *
 *   no peer by that name, or the link is not ESTABLISHED   NO_ROUTE
 *   a relay whose hops + 1 would reach IRC_MAX_HOPS         hop_limit
 *   a relay whose origin is THIS node (2.4)                own_origin
 *   a line that does not fit the wire                        too_long
 *   a client verb with no S-verb (4.3)                      NO_SVERB
 *
 * The hop and own-origin checks are HERE, at forward time, because 3.1 says
 * "loop guard applies at forward time" and that is the only place the node can
 * see what it is about to do. Neither can be done on receipt: a message that
 * arrives from one peer may still have to go to another, and a node that refused
 * it on arrival would have to decide, at arrival, that no peer should ever
 * receive it.
 *
 * `prefix` IS THE SOURCE PREFIX, without the leading ':', and it is a PARAMETER
 * rather than this node's own name because the seven S-verbs do not agree about
 * what their subject is. For the five state verbs the subject IS the server --
 * an SJOIN names a fact about the channel -- so `s->name` is right. For
 * SPRIVMSG and SNOTICE the subject is a USER, and a receiving node that is
 * handed `:irc.b SPRIVMSG #T :hi` cannot build a hostmask for it: 2.1's
 * `nick!user@host` is the only thing a client can be shown as the author of a
 * message, and a server name is not one. C1 sent the node's own name and the
 * gap was recorded in federation/verbs.h; this parameter is the fix.
 *
 * IT IS AN ARGUMENT AND NOT A FIELD ON fanout_target_t, and the reason is
 * lifetime rather than taste. A resolved target is a CACHE ENTRY that outlives
 * the call: the same fanout_target_t is resolved once and delivered from, and
 * several deliveries may follow. A prefix is a property of ONE emission -- "who
 * said this, in this line" -- and putting it on the target would make it a
 * property of the channel for as long as the channel exists, which is a
 * different fact with the same name. It is the same argument the target-vs-
 * argument split at the top of this file makes, one level down. The cost is one
 * more argument at the two call sites inside fanout_deliver() and one at each
 * verb handler, and it is paid at every call rather than only at the ones that
 * set it.
 *
 * `prefix` may be NULL, in which case this node's own name is used: that is the
 * five-state-verbs answer, and a caller with no better idea is better served by
 * a wrong-but-legal prefix than by a refused forward. It is stated rather than
 * left to be discovered, because a silent fallback is the kind of thing that
 * hides a caller that forgot. */
int fanout_forward_link(server_t *s, const char *peer_name,
                        const fanout_target_t *t, const char *verb,
                        const char *const *params, int nparams,
                        const char *prefix, const irc_serve_tags_t *carry);

/* The same forward for a line that is ALREADY an S-verb in the shape 4.3
 * freezes for it -- which is what a RELAY is. federation/verbs.c calls this
 * when it passes a received state change along; it is a separate entry point
 * because re-shaping an SJOIN's parameters (channel, member, flags) as though
 * they were JOIN's (channel) would produce a line no peer can parse, and
 * silently. Both entry points reach ONE body, so the loop guard and the
 * identity-minting rules are not stated twice.
 *
 * `params` INCLUDES the target as its first element and is the frozen shape,
 * from fed_sverb_params(). `target` is not a separate argument: it is
 * `params[0]` where the shape puts it there, and the log lines use `params[0]`
 * as the subject of the line. */
int fanout_forward_sverb(server_t *s, const char *peer_name, const char *sverb,
                         const char *prefix, const char *const *params,
                         int nparams, const irc_serve_tags_t *carry);

/* 3.1's forward target set for a CHANNEL, and the ONE place it is decided.
 *
 * Two callers, and the duplication is the reason it is exported.
 * fanout_deliver()'s two channel rows call it for a local emission, and
 * federation/verbs.c reaches it the same way for a line it received -- through
 * fanout_deliver()'s `carry` -- which used to be impossible to do without
 * copying the walk, and a copied walk is a walk that can drift.
 * chan_verbs.c's own broadcast helper was already the other half of that
 * duplication and had no forward arm at all.
 *
 * The four rows it implements, which are 3.1's and only 3.1's:
 *
 *   owned     | message      | servers[ch] UNION every ESTABLISHED link
 *   non-owned | message      | the owner
 *   owned     | state-change | servers[ch] UNION every ESTABLISHED link
 *   non-owned | state-change | the owner
 *
 * The first row is the AMENDED one and the two OWNED rows are now the same
 * target set; the definition carries the correction and the reason the original
 * "the origin already holds every member" was false. Read that before changing
 * this table: a roster entry is not a delivery path, and an owner that forwards
 * nothing cannot reach a member it does not hold.
 *
 * The union in the owned rows is what makes the FIRST join to a channel work,
 * and the argument is at the definition: servers[] is a set of servers that
 * have reported a member, so it is empty on both sides of a new channel and a
 * forward over it alone would never start.
 *
 * `params` are the CLIENT parameters after the target, and are re-shaped per
 * verb here rather than taken pre-shaped, so a caller that has a client
 * emission does not have to know the S-verb's shape. Returns how many peers the
 * line was queued to; zero is a normal answer -- a channel with no member-server
 * and no ESTABLISHED link has nowhere to forward to.
 *
 * `stamp` IS THE EMISSION'S IDENTITY AND IS PUT ON THE WIRE AS IT STANDS -- no
 * mint here, no hop added here -- which is a different contract from every other
 * entry point on this leg and is said so because getting it wrong is silent. The
 * caller has already computed it, because it needs the same value for the
 * client-facing `msgid` it is writing to its own members, and an identity that
 * differed between those two would tell a client on this node and a client on the
 * peer two different things about one message.
 *
 * `relayed` says whether `stamp` came from a peer, and it is a parameter rather
 * than a comparison against `s->name` because the two are indistinguishable by
 * value: a stamp this node minted has origin == s->name, and so does a stamp a
 * peer sent naming this node. Only where the value came from tells them apart,
 * and it decides whether 2.4's hop ceiling and never-forward-own-origin guards
 * apply -- they do not to an identity this node just created, which is the whole
 * of a forward this node originates. */
int fanout_forward_channel(server_t *s, const chan_t *ch, fanout_class_t vclass,
                           const char *client_verb, const char *prefix,
                           const char *const *params, int nparams,
                           const irc_serve_tags_t *stamp, int relayed);

/* As fanout_forward_channel(), for a line that is ALREADY an S-verb in the
 * shape 4.3 freezes -- which is what a RELAY of a received state change is.
 * Same target set, same refusals, reached through the same static walk.
 *
 * `carry` here has the OTHER contract, and the difference is deliberate rather
 * than an inconsistency: this one is reached from federation/verbs.c with a stamp
 * a PEER sent, so its job is to add this node's hop and change nothing else, and
 * it computes that once for the whole walk. The two forms cannot be merged
 * because one of them has already had the hop added by the time it arrives. */
int fanout_forward_channel_sverb(server_t *s, const chan_t *ch,
                                 fanout_class_t vclass, const char *sverb,
                                 const char *prefix, const char *const *params,
                                 int nparams, const irc_serve_tags_t *carry);

/* ---------------------------------------------------------------------------
 * Small shared helpers
 * ---------------------------------------------------------------------------
 */

/* Will `:<prefix> <verb> <target> :<text>` fit on the wire? See 3.2's relay
 * cap discussion; the arithmetic is spelled out at the definition. 1 fits, 0
 * does not. Exposed so the verb handlers can refuse an over-long line with a
 * numeric rather than letting the render fail deep inside reply(), where the
 * only available outcome is a refusal on n_reply_refused -- the counter that is
 * a bug report, not a metric. */
int fanout_line_fits(const char *prefix, const char *verb, const char *target,
                     const char *text);

/* As fanout_line_fits(), for a line with SEVERAL parameters: `params_bytes` is
 * the sum of their lengths. It exists because a single-string budget cannot
 * express the frozen state-verb shapes -- an SKICK carries a member, a channel,
 * a target and a reason, and charging only the reason would let the other three
 * run the line over 3.2's cap. The sum is a lower bound on the rendered size,
 * so the cap is approached from the conservative side, and the arithmetic itself
 * is unchanged from fanout_line_fits()'s. */
int fanout_line_fits_n(const char *prefix, const char *verb, size_t target_len,
                       size_t params_bytes);

/* Resolve a nickname to a connection, folding case.
 *
 * The fold is the nick registry's, not this function's: `server_nick_lookup()`
 * folds ASCII on the way into the table (2.1 and RFC 2812 2.3.1 both say
 * nicknames are case-insensitive), so this is a lookup like any other and needs
 * no second opinion about case. It carries the NULL and empty-name guards the
 * registry cannot, because a caller can hand it a target that was never a
 * nickname -- `PRIVMSG :` reaches here with an empty middle parameter.
 *
 * Until the registry folded, this function did instead: an exact lookup, then a
 * case-folded scan of the whole enumeration on a miss. That is issue #100, and
 * it is why the rule now lives at the table rather than here. */
conn_t *fanout_find_nick(server_t *s, const char *nick);

/* `*` and `?` glob over nicknames, case-insensitive, for WHO's <mask> form.
 * Not named after a channel: 3.1 is about routing, but RFC 2812 3.3.4's WHO
 * takes a mask and answering "no such nick" for `WHO alice*` on a node with
 * alice connected is a lie rather than a limitation. */
int fanout_mask_match(const char *mask, const char *value);

#endif /* IRC_CORE_FANOUT_H */
