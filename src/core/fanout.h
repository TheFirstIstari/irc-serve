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
 * WHAT IS REACHABLE TODAY, STATED PLAINLY
 * ---------------------------------------------------------------------------
 * On a single node every channel was created by this node, so
 * chan_origin_state() is CHAN_ORIGIN_SELF for all of them and origin ==
 * s->name. EVERY row of 3.1 that involves a peer is therefore unreachable from
 * the wire, and this header does not pretend otherwise:
 *
 *   local user           reachable, both classes
 *   owned channel        reachable, both classes (PRIVMSG/NOTICE here; the
 *                        state-change verbs reached the same rows through
 *                        chan_verbs.c's own broadcast)
 *   non-owned channel    NOT reachable -- no peer has ever reported a channel
 *   remote user          NOT reachable -- no peer link exists
 *
 * The unreachable rows are implemented anyway, and the reason is not optimism:
 * 3.1 is the contract Phase 6 has to honour, and a row that is not written down
 * is a row Phase 6 re-derives, probably differently. Each of them refuses
 * rather than pretending, and says so on the node's observable output, so a
 * federated node that reached one would be visibly missing something rather
 * than silently dropping a message.
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
 * PRIVMSG and NOTICE are `message`. Nothing in this node is a state-change yet
 * -- the channel verbs of Phase 4 already carry their own local broadcast and
 * their own 437 refusal -- but the class is in the resolved target so that
 * Phase 6 has one place to ask. */
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
 * Returns 1 when the target was resolved, 0 when it was not. On 0 the right
 * numeric has ALREADY been sent to `from` and `*out->kind` is FANOUT_NONE, so a
 * caller that returns on 0 has said something. A resolve that fails in silence
 * is worse than no resolve at all, because the client waits.
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

/* Deliver one line of `verb` carrying `text`, prefixed with `prefix`, to
 * whatever `*t` resolves to under the class recorded in `*t`.
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
 * Never blocks and never closes: the write path marks CLOSING and the reaper
 * closes, as 3.4 requires. */
int fanout_deliver(server_t *s, const fanout_target_t *t, const char *prefix,
                   const char *verb, const char *text, conn_t *exclude);

/* ---------------------------------------------------------------------------
 * The forward leg -- Phase 6 fills this in
 * ---------------------------------------------------------------------------
 */

/* The ONE place a line leaves this node toward a peer, as 4.3's S-verb
 * (SPRIVMSG, SNOTICE, SJOIN, ...) with the 2.4 internal tag block stamped on it.
 *
 * Exposed rather than kept static for one reason: it is the seam. It is the
 * only function in src/ whose job is "put a protocol message on a peer link",
 * and Phase 6 implements it once, here, instead of growing a second place that
 * decides how a message leaves the node.
 *
 * Today it reports, loudly, and sends nothing: there are no peer sockets (2.3
 * -- server_dial() has no caller) and 4.3's S-verbs are Phase 6. It returns 0
 * for "not delivered", which is the same value a real forward returns when the
 * link is refused, so a caller written today keeps its meaning tomorrow. */
int fanout_forward_link(server_t *s, const char *peer_name,
                        const fanout_target_t *t, const char *verb,
                        const char *text);

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
