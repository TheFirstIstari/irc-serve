/* chan_verbs.c -- see chan_verbs.h. The seven channel commands, and the one
 * function every state change goes through to learn whether it may happen.
 *
 * Authority: docs/SERVER_DESIGN.md 2.2, 3.1, 4.1 and 4.4.
 *
 * ---------------------------------------------------------------------------
 * THE SINGLE-WRITER RULE, AND WHY IT IS CHECKED BEFORE ANYTHING ELSE
 * ---------------------------------------------------------------------------
 * 2.2: "A node never applies a channel state change it cannot route to the
 * channel's origin; it refuses the action (437). It does not queue and apply
 * later."
 *
 * "It does not queue and apply later" is the half that is easy to get wrong and
 * the half this file is shaped around. There is deliberately NO deferred queue,
 * NO pending-mutation list and NO "apply when the link comes back" path here,
 * because any of those is a mechanism for producing exactly the permanent
 * divergence the rule exists to prevent: the local copy and the origin's copy
 * both mutate, in a different order, and the node has no way to reconcile them.
 * The absence is the feature, and a grep for a pending-queue in this file
 * finding nothing is the evidence.
 *
 * The consequence, stated so the code below reads correctly: a refused action
 * leaves the channel EXACTLY as it was. No partial application, no half-added
 * member, no topic written before the refusal is noticed, and no clock field
 * advanced. Every handler therefore resolves authority FIRST, before it has
 * touched anything -- and the test that a refused TOPIC left topic, topic_who
 * and topic_when all untouched is a test of that ordering, not of a detail.
 *
 * ---------------------------------------------------------------------------
 * WHAT "CANNOT ROUTE TO THE ORIGIN" MEANS ON ONE NODE
 * ---------------------------------------------------------------------------
 * On a single node, origin == self for every channel the node created, so
 * authority_ok() takes the CHAN_ORIGIN_SELF branch and the refusal is
 * unreachable from the wire. That is the degenerate case section 1 promises, and
 * it is exactly why the rule is tested by CONSTRUCTING a channel whose origin is
 * another server: a rule that can only be observed once a second node exists is a
 * rule that ships unverified.
 */
#include "core/chan_verbs.h"

#include <stdio.h>
#include <string.h>

#include "core/cap.h"
#include "core/channel.h"
#include "core/account.h"
#include "core/fanout.h"
#include "core/reply.h"

/* ---------------------------------------------------------------------------
 * Argument handling
 * ------------------------------------------------------------------------- */

int chan_split_list(char *store, size_t dstcap, const char *src,
                    const char **names, int max)
{
    const size_t stride = (size_t)CHAN_MAX_NAME + 1u;
    const char *p = src;
    int n = 0;

    if (store == NULL || dstcap == 0 || src == NULL || names == NULL ||
        max <= 0) {
        return -1;
    }
    if (dstcap < stride * (size_t)max) {
        return -1; /* the caller's buffer cannot hold `max` names */
    }
    for (;;) {
        const char *comma = strchr(p, ',');
        size_t len = (comma != NULL) ? (size_t)(comma - p) : strlen(p);

        if (n >= max || len == 0 || len >= stride) {
            /* An empty element is not a channel name. "JOIN #a," must not be
             * answered about a channel called ""; it is a malformed list, and
             * the whole list is refused rather than half-honoured. */
            return -1;
        }
        memcpy(store + (size_t)n * stride, p, len);
        store[(size_t)n * stride + len] = '\0';
        names[n] = store + (size_t)n * stride;
        n++;
        if (comma == NULL) {
            break;
        }
        p = comma + 1;
    }
    return n;
}

/* Canonicalise and validate one channel-name argument. Replies 403 and returns
 * 0 when it is not a channel name this node can speak about.
 *
 * Split out from resolve_existing() because the two differ in exactly one way
 * and conflating them was a real bug during this phase: "canonicalise and
 * validate" is needed before a lookup, and "look up what already exists" is
 * needed for every verb EXCEPT JOIN. JOIN is the only verb that may find
 * nothing and create it. */
static int canonical_channel(server_t *s, conn_t *c, const char *arg, char *out,
                             size_t cap)
{
    (void)chan_name_upper(out, cap, arg);
    if (chan_name_valid(out)) {
        return 1;
    }
    /* RFC 2812 3.3.2: 403 is "<client> <channel> :No such channel" -- the
     * channel is a MIDDLE parameter, and a client reading by position takes
     * the trailing text as the complaint and the parameter as the subject. With
     * it omitted the client can only say "no such something", which is the
     * complaint 403 is specifically not. */
    (void)reply(s, c, "403", (const char *const[]){ out }, 1, "No such channel");
    return 0;
}

/* Resolve a channel the client must ALREADY be a member of.
 *
 * Two distinct failures, and conflating them is how this function's first
 * version dropped a reply on the floor:
 *
 *   the name is not a channel     403
 *   the channel does not exist    442, because "you are not there" is the
 *                                 actionable answer and 403 would send a client
 *                                 looking for a channel that may well exist
 *                                 somewhere it cannot see
 *   the channel exists, client is not a member   442
 *
 * Every path REPLIES before returning NULL, so a caller that returns on NULL has
 * said something. A resolve that returns NULL silently is worse than one that
 * does not exist, because the client waits. */
static chan_t *resolve_joined(server_t *s, conn_t *c, const char *arg)
{
    char canonical[CHAN_MAX_NAME + 1];
    chan_t *ch;

    if (!canonical_channel(s, c, arg, canonical, sizeof canonical)) {
        return NULL;
    }
    ch = server_chan_get(s, canonical);
    if (ch == NULL || chan_find_member(ch, c) == NULL) {
        /* RFC 2812 3.3.2: 442 is "<client> <channel> :You're not on that
         * channel", so the channel is a MIDDLE parameter. Without it a client
         * cannot tell WHICH channel it is not on, and this function answers on
         * behalf of every verb that needs a channel the caller is on -- JOIN is
         * the only exception, and it does not come through here. */
        (void)reply(s, c, "442", (const char *const[]){ canonical }, 1,
                    "You're not on that channel");
        return NULL;
    }
    return ch;
}

/* ---------------------------------------------------------------------------
 * The authority decision -- ONE function
 * ---------------------------------------------------------------------------
 * 2.2's single-writer rule is easy to honour in seven places and impossible to
 * keep honest in seven places, so the handlers ask a question instead of
 * answering it.
 *
 * `stateful` says whether this call MUTATES channel state. A query is answered
 * from whatever cache the node holds and is never refused: refusing to tell a
 * client who is in a channel is not a divergence risk, it is a stale answer that
 * a later SJOIN corrects -- and transient, self-healing divergence is precisely
 * what section 1 says the single-writer rule converts permanent divergence into.
 *
 * THREE ANSWERS, and the middle one is why this is no longer an int:
 *
 *   OK        proceed. This node owns the channel, or the call is a query.
 *   FORWARD   do not write locally; hand it to 3.1's forward arm. The origin is
 *             somewhere this node can reach, so the request is carryable.
 *   REFUSED   437, already sent, nothing modified. The origin is unreachable.
 *
 * The pre-C3 version returned 0 for BOTH of the last two and printed one
 * observable line for them with a `state=` field to tell them apart. That was
 * the same information, but the CALLER could only act on it as "do nothing",
 * which is why 3.1's state-change forward arm had no caller at all: the only
 * thing a boolean verdict could say about a non-owned channel was no.
 *
 * AND THE CLIENT IS NOT TOLD. A FORWARD is answered with the verb's own success
 * numeric exactly as an OK would be, because the origin performs the action:
 * the client asked a server to make a change to a channel and the mesh will make
 * it. 437 there would tell a client its own operator status was not accepted,
 * which is a lie about something that is about to be true. The one thing a
 * client is told that is a lie, and it was already a lie before this change --
 * a forward can still be refused further along, at the peer's 437 or at a NO_ROUTE
 * -- so the honest statement is that the node accepted the request and is not
 * promising the mesh accepted it. */
static chan_verdict_t authority_ok(server_t *s, conn_t *c, const chan_t *ch,
                                   const char *verb, int stateful)
{
    chan_origin_state_t st = chan_origin_state(s, ch);

    if (st == CHAN_ORIGIN_SELF) {
        return CHAN_VERDICT_OK;
    }
    if (stateful == 0) {
        /* A query against a channel this node does not own. The answer may be
         * incomplete -- the remote members are in the origin's records -- and it
         * is given anyway, because the alternative is refusing to answer. */
        printf("[observable] chan_query: channel=%s verb=%s origin=%s "
               "state=LINKED_CACHE nservers=%zu\n",
               ch->name, verb, ch->origin, ch->nservers);
        return CHAN_VERDICT_OK;
    }

    if (st == CHAN_ORIGIN_LINKED) {
        /* FORWARD, not 437. 3.1's "non-owned channel | state-change | forward
         * ONLY" has a real destination here: a link bears the origin's name and
         * is ESTABLISHED, which is precisely what server_find_peer() means by a
         * route. The pre-C3 comment here said "there is no forward path in this
         * phase, because 4.3's SJOIN/SPART/STOPIC/SSMODE/SKICK are Phase 6" --
         * that is now FALSE and is retracted: the forward path is
         * fanout_deliver()'s, 4.3's verbs are in federation/verbs.c, and the
         * arm is reachable.
         *
         * NO LOCAL WRITE, and the reason is 2.2's rather than 3.1's: a node that
         * applied a state change on a channel it does not own holds a copy the
         * origin will not reconcile, permanently. Applying it because the action
         * "looks harmless" is the exact failure the single-writer rule exists to
         * prevent, and the node would have no way to notice it had done it. */
        printf("[observable] chan_state_forward: channel=%s verb=%s origin=%s\n",
               ch->name, verb, ch->origin);
        return CHAN_VERDICT_FORWARD;
    }

    /* The refusal, and now only the refusal: 2.2's LOCALLY ORPHANED case, with
     * no ESTABLISHED link bearing the origin's name. This is fail-closed in the
     * whole sense -- local members still see each other, and nothing that needs
     * the origin is permitted. */
    printf("[observable] chan_state_refused: channel=%s verb=%s origin=%s "
           "state=ORPHANED numeric=437\n", ch->name, verb, ch->origin);
    (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                "Cannot change %s: this server is not its origin (%s)", ch->name,
                ch->origin);
    return CHAN_VERDICT_REFUSED;
}

/* ---------------------------------------------------------------------------
 * 353 -- the names list
 * ---------------------------------------------------------------------------
 * 7/Phase 4 fixes the order: "nicks, then ops, then voiced". The alternative --
 * "whatever order members[] happens to be in" -- makes the roster depend on join
 * history, so two clients on one channel with the same members could receive
 * different bytes, and the acceptance criterion could not be asserted at all.
 *
 * Three passes over a small array, no sort, no allocation, no comparison
 * function. O(3n) rather than O(n log n), and it is the same cost a counting
 * sort would be.
 */

/* Which of the three groups a member belongs to: 0 plain, 1 op, 2 voice.
 *
 * The tests are EXCLUSIVE, and that is the whole reason the order is well
 * defined. +o and +v are independent bits, so a member can hold both; an
 * independent test per group would render such a member twice. Op is tested
 * first, so it renders in the op group and nowhere else. */
static int names_group(const struct member *m)
{
    if (chan_member_is(m, CHAN_MEMBER_OP)) {
        return 1;
    }
    if (chan_member_is(m, CHAN_MEMBER_VOICE)) {
        return 2;
    }
    return 0;
}

/* The same three groups for a REMOTE member, as a flag word rather than a
 * `struct member *`. The two lists are walked by the same render below and the
 * grouping has to agree, which is why it is derived from the same two bits
 * rather than being a second rule written somewhere else. */
static int names_group_flags(unsigned flags)
{
    if ((flags & CHAN_MEMBER_OP) != 0u) {
        return 1;
    }
    if ((flags & CHAN_MEMBER_VOICE) != 0u) {
        return 2;
    }
    return 0;
}

/* The sigils drawn in front of `nick`, in the order 005's `PREFIX=(ov)@+` names
 * them, into `out`. Two bytes plus a NUL is the whole of what this node can draw
 * -- the two prefix modes are +o and +v and channel.h says so -- so `out` is
 * sized by that and not by a guess.
 *
 * MULTI-PREFIX OFF IS EXACTLY ONE SIGIL, and it is the HIGHEST the member holds.
 * RFC 2812 4.4.2 describes a prefix as "one or more" but every client that has
 * not negotiated `multi-prefix` indexes the first character it finds and looks
 * it up in PREFIX, so handing it two characters hands it a nickname it cannot
 * resolve. Op outranks voice, which is what names_group() says about the ORDER and
 * what this says about the DRAWING: an op+voice member is one entry in the op
 * group and one '@'.
 *
 * MULTI-PREFIX ON IS THE WHOLE SET, `@+nick`, in PREFIX order rather than in a
 * member-flag order. That order is not taste: a client reading the run left to
 * right and indexing into PREFIX has to reach the same answer this node did, and
 * 005 is where it reads PREFIX from. It is also the order that makes the drawn run
 * self-describing -- the leftmost sigil is the highest status, so a client that
 * only wants one can take the first byte and be right.
 *
 * WHY THE GATE IS A PARAMETER rather than read from `dst` here. It COULD be read
 * from `dst`, and it is passed instead for the reason the rest of this function
 * takes (nick, flags) rather than reading either roster: one decision, taken once
 * per list by the caller that knows the destination, so that a 353 assembled from
 * six passes cannot disagree with itself. `send_names_list()` asks once. */
static const char *names_signs(unsigned flags, int multiprefix, char *out,
                               size_t cap)
{
    size_t n = 0;

    if (out == NULL || cap < 2u) {
        return "";
    }
    out[0] = '\0';
    if (multiprefix == 0) {
        if ((flags & CHAN_MEMBER_OP) != 0u) {
            out[n++] = '@';
        } else if ((flags & CHAN_MEMBER_VOICE) != 0u) {
            out[n++] = '+';
        }
    } else {
        if ((flags & CHAN_MEMBER_OP) != 0u) {
            out[n++] = '@';
        }
        if ((flags & CHAN_MEMBER_VOICE) != 0u) {
            out[n++] = '+';
        }
    }
    out[n] = '\0';
    return out;
}

/* The ROSTER ENTRY for one member, drawn in the shape this DESTINATION asked
 * for, into `out`. Returns `out`, or "" when nothing fits.
 *
 * ---------------------------------------------------------------------------
 * THE PRIVACY DECISION IS IN THIS FUNCTION, NOT IN ITS CALLER
 * ---------------------------------------------------------------------------
 * IRCv3's `userhost-in-names` says a `353` may carry `nick!user@host` rather than
 * a bare nickname. What that means is that **every member's ident and observed
 * host address is disclosed to every other member of the channel**, to clients
 * that member has never spoken to and to clients who joined after them. There is
 * no per-member consent anywhere in it: one client asking puts the whole roster's
 * hostmasks on the wire to that client.
 *
 * So the shape is decided per DESTINATION and nowhere else, and it is decided
 * here rather than in `send_names_list()` so that the LOCAL roster and the REMOTE
 * roster -- two separate arrays walked by two separate loops -- cannot answer the
 * question differently. That was already the reason `multiprefix` is a parameter
 * of `names_signs()`; the difference is the cost of getting it wrong. One sigil
 * drawn in the wrong shape is cosmetic; one hostmask disclosed to a client that
 * did not ask is not.
 *
 * ---------------------------------------------------------------------------
 * WHAT HAPPENS WHEN THE NODE DOES NOT HAVE A HOSTMASK TO DRAW
 * ---------------------------------------------------------------------------
 * It draws the BARE NICK, which is the historical shape and which every client
 * parses, and the asymmetry is genuine rather than an oversight:
 *
 *   - a LOCAL member always has both halves. `c->host` was filled by accept()
 *     before the connection had a nickname, and `c->user` by USER.
 *   - a REMOTE member has them only if 4.3's SBURSTN announced them. A live SJOIN
 *     carries neither (4.3's SJOIN is `<server> <chan> <nick> <flags>`), so the
 *     empty host is the NORMAL state for a member learned from one -- channel.h
 *     says so at `chan_remote_t` and that note is still true.
 *
 * The alternative would be to put `*` in place of a missing half, and that is
 * refused on purpose: `*` would be a byte on the wire that reads as part of a
 * hostmask and means nothing. A client that negotiated this capability and still
 * sees a bare nickname learns exactly the true thing -- that this node has not been
 * told -- and RFC 2812 3.3.5 permits a `353` to hold bare nicknames, so the mixed
 * roster is parseable rather than surprising.
 *
 * THE BUFFER IS PER MEMBER AND NOT HOISTED, for the reason `write_to_members()`
 * gives for its tag buffer: this renders inside the loop because the decision is
 * per destination, and a buffer shared across iterations is one whose contents
 * change under a line already queued. CONN_HOSTMASK_MAX is written from the three
 * struct widths rather than picked, so raising any of `nick`, `user` or `host`
 * cannot leave this one byte short. */
static const char *names_entry(const conn_t *dst, const char *nick,
                               const char *ident, const char *host, char *out,
                               size_t cap)
{
    const int long_form = cap_userhost_in_names_enabled(dst);

    if (out == NULL || cap == 0u || nick == NULL) {
        return "";
    }
    if (long_form == 0 || ident == NULL || ident[0] == '\0' ||
        host == NULL || host[0] == '\0') {
        if (strlen(nick) >= cap) {
            return "";
        }
        memcpy(out, nick, strlen(nick) + 1u);
        return out;
    }
    /* `nick!ident@host` is exactly conn_hostmask()'s own shape, so the local arm
     * could have called it -- and it deliberately does not, because this function
     * also renders REMOTE members, which have no conn_t and therefore no
     * conn_hostmask(). One renderer for both lists is why a remote entry and a local
     * one cannot come out in different shapes, which is the failure this whole
     * capability would otherwise have. */
    {
        const int w = snprintf(out, cap, "%s!%s@%s", nick, ident, host);

        /* snprintf returns what it WOULD have written, so the check is on the
         * return and a truncation is the negative side of it: a half-written
         * hostmask is worse than no hostmask, because a client parses what it is
         * given. Returning "" makes the caller SKIP the member rather than draw it
         * short, which would be a roster entry naming nobody. Unreachable with the
         * current bounds -- a 353 line is CHAN_NAMES_LINE (400) and the widest
         * entry is CONN_HOSTMASK_MAX (259) -- and stated rather than assumed
         * because the roster is the one place a silent omission is invisible. */
        if (w < 0 || (size_t)w >= cap) {
            out[0] = '\0';
            return "";
        }
    }
    return out;
}

/* Emit `nick` into the 353 line under construction, flushing first if it will not
 * fit. Returns the new `used`. The flush is RFC 2819 3.3.5's "a 353 MAY be
 * split across lines" and 3.2's "never deliver a shortened value" together: a
 * half-written nickname is worse than one more line.
 *
 * `entry` is the ALREADY-RENDERED member name: the sigils are drawn by the
 * caller's `names_signs()` because they are 005's PREFIX and `multi-prefix`'s, and
 * the name itself is drawn by `names_entry()` because it is 353's shape and
 * `userhost-in-names`'s. Two decisions about two different things, kept apart so
 * that a caller cannot render a name and forget the gate -- which is the defect
 * `userhost-in-names` invites, and the same one `extended-join` had to be careful
 * about for the same reason.
 *
 * This is the ONE place a name is rendered into a 353, and it takes the two
 * lists as (nick, flags) rather than reading either of them itself. That is what
 * makes 7/Phase 4's fixed order -- nicks, then ops, then voiced -- a property of
 * this function rather than of whichever list a member happens to be in, and it
 * is what lets the LOCAL roster and the REMOTE roster share one order instead of
 * two that could disagree.
 *
 * `flags` is the member's FULL prefix set, and it is what the sigils are derived
 * from. It used to be an `int group` -- the ORDER this member is drawn in, 0 plain
 * 1 op 2 voice -- and that is precisely why a member holding both modes could only
 * ever be drawn with one of them: the order is three exclusive buckets and a
 * member in two of them belongs to exactly one. The ORDER is still decided by the
 * caller's loop and this function still renders the members it is handed in the
 * order it is handed them, so dropping the parameter changes nothing about where a
 * name lands -- only about how much is drawn in front of it. */
static size_t names_emit(server_t *s, conn_t *dst, const char *const *mid,
                         unsigned flags, const char *entry, char *line,
                         size_t used, int *produced, int multiprefix)
{
    char signs[4];
    size_t slen = strlen(names_signs(flags, multiprefix, signs, sizeof signs));
    size_t elen = strlen(entry);
    size_t need = slen + elen + 1u; /* +1 for the joining space */

    if (elen == 0u) {
        /* A member this node cannot draw at all. `names_entry()` returns "" only
         * when the entry would not fit its buffer, which the current bounds make
         * unreachable -- a 353 line is CHAN_NAMES_LINE (400) and the widest entry
         * is CONN_HOSTMASK_MAX (259) -- and it is handled rather than assumed,
         * because the alternative is a silent omission from a names list, and a
         * names list is exactly where a silent omission is invisible.
         *
         * IT IS REPORTED RATHER THAN DRAWN SHORT. Falling back to the bare nick
         * here would be a second opinion about the shape, taken in a function that
         * does not have the capability gate, and it would produce a roster entry
         * asserting that this node does not know a host it does. The refusal goes
         * to the node's own output and the member is left out. */
        printf("[observable] names_entry_refused: channel=%s\n",
               (mid != NULL && mid[1] != NULL) ? mid[1] : "?");
        return used;
    }
    if (used != 0 && used + need > (size_t)CHAN_NAMES_LINE) {
        (void)reply(s, dst, "353", mid, 2, "%s", line);
        *produced = 1;
        used = 0;
    }
    if (used != 0) {
        line[used++] = ' ';
    }
    /* TWO bytes copied rather than one char written twice: with multi-prefix the
     * run is a variable-length string and a `line[used++] = sign[0]` here would
     * silently drop the second sigil, which is the defect this whole change is
     * about. */
    memcpy(line + used, signs, slen);
    used += slen;
    memcpy(line + used, entry, elen);
    used += elen;
    line[used] = '\0';
    return used;
}

/* Six passes over two small arrays, no sort, no allocation, no comparison
 * function. O(6n) rather than O(n log n), and it is the same cost a counting
 * sort would be.
 *
 * WHY SIX AND NOT THREE. The grouping is a property of the RENDER and the two
 * rosters are separate storage, so the order has to be computed across both:
 * every group is walked over members[] and then over remotes[]. The alternative
 * -- two separate 353s, one per roster -- would put the local names before the
 * remote ones regardless of their flags, so a channel with a remote op and a
 * local plain member would render in an order Phase 4 does not specify and
 * 7/Phase 6's acceptance criterion cannot be asserted. Within a group the local
 * list keeps join order and the remote list keeps arrival order, and both are
 * deterministic. */
static void send_names_list(server_t *s, conn_t *dst, const chan_t *ch)
{
    const char *const mid[2] = { "=", ch->name };
    /* ASKED ONCE, and this is the whole of the per-destination decision. A 353 is
     * a line to ONE client, and two clients on this node may disagree about
     * `multi-prefix`; the roster is shared, the rendering is not. 005's
     * `PREFIX=(ov)@+` is what says which sigils exist and what they mean, and it
     * is true either way -- multi-prefix changes how MANY are drawn, not which
     * sigils exist. See cap.h. */
    const int multiprefix = cap_multiprefix_enabled(dst);
    int produced = 0;

    for (int group = 0; group < 3; group++) {
        /* +1 for the NUL, and the budget is CHAN_NAMES_LINE rather than
         * REPLY_TEXT_MAX so the rendered text always fits reply()'s buffer. */
        char line[CHAN_NAMES_LINE + 1];
        size_t used = 0;

        for (size_t i = 0; i < ch->nmembers; i++) {
            const struct member *m = &ch->members[i];
            /* PER MEMBER, and the buffer is per member rather than hoisted for the
             * reason `write_to_members()` gives for its tag buffer: the shape is
             * decided per destination inside the walk, and a buffer shared across
             * iterations is one whose contents change under a line already queued. */
            char entry[CONN_HOSTMASK_MAX];

            if (m->c == NULL || m->c->nick[0] == '\0') {
                continue;
            }
            if (names_group(m) != group) {
                continue;
            }
            used = names_emit(s, dst, mid, m->flags,
                              names_entry(dst, m->c->nick, m->c->user, m->c->host,
                                          entry, sizeof entry),
                              line, used, &produced, multiprefix);
        }
        for (size_t i = 0; i < ch->nremotes; i++) {
            const chan_remote_t *r = &ch->remotes[i];
            /* AND THE SAME RENDERER FOR A REMOTE MEMBER, which is the whole reason
             * `names_entry()` takes (nick, ident, host) rather than a conn_t: a
             * remote member has no conn_t, so a renderer that read one could not
             * have drawn it at all and the roster would carry two shapes by
             * construction. The empty ident and empty host are the documented normal
             * state for a member learned from a live SJOIN, and they render as the
             * bare nick rather than as a half-built hostmask. */
            char entry[CONN_HOSTMASK_MAX];

            if (r->nick[0] == '\0' || names_group_flags(r->flags) != group) {
                continue;
            }
            used = names_emit(s, dst, mid, r->flags,
                              names_entry(dst, r->nick, r->user, r->host, entry,
                                          sizeof entry),
                              line, used, &produced, multiprefix);
        }
        if (used != 0) {
            (void)reply(s, dst, "353", mid, 2, "%s", line);
            produced = 1;
        }
    }
    if (produced == 0) {
        /* Exactly one 353, with an empty trailing parameter, for a channel this
         * node has no local members of. That is the honest answer for a channel
         * whose members are all remote -- and on a node that knows a peer's
         * members exist, it is the answer 2.2's servers[] cache makes possible
         * rather than the answer of pretending the channel does not exist. */
        (void)reply(s, dst, "353", mid, 2, "%s", "");
    }
}

/* 366 terminates a names list, and 7/Phase 4's requirement is that it is LAST.
 * It is emitted after every 353 and after the topic numerics, so nothing this
 * node sends in answer to a JOIN, NAMES or TOPIC query can follow it. */
static void send_end_of_names(server_t *s, conn_t *dst, const char *channel)
{
    (void)reply(s, dst, "366", (const char *const[]){ channel }, 1,
                "End of /NAMES list");
}

/* ---------------------------------------------------------------------------
 * Topic numerics
 * ---------------------------------------------------------------------------
 * 331 when there is no topic, otherwise 332 then 333. 333 carries the setter AND
 * the time, and both are required: a 333 without a time is not a 333, and a time
 * taken from 3.4's monotonic tick would be meaningless to a client.
 *
 * The parameter placement follows RFC 1459 2.3.1 rather than convenience. 332 is
 *   :<server> 332 <nick> <channel> :<topic>
 * so the channel is a MIDDLE parameter and the topic is the trailing one. The
 * same holds for 331. Putting the channel in the trailing text would be
 * representable and wrong, and a client parsing by position would read the
 * channel as the topic. */
static void send_topic(server_t *s, conn_t *dst, const chan_t *ch)
{
    char when[24];

    if (ch->topic[0] == '\0') {
        (void)reply(s, dst, "331", (const char *const[]){ ch->name }, 1,
                    "No topic is set");
        return;
    }
    (void)reply(s, dst, "332", (const char *const[]){ ch->name }, 1, "%s", ch->topic);
    /* 333 is  :<server> 333 <nick> <channel> <setter> <time> :<topic>
     * so the setter AND the time are middle parameters and the topic is
     * repeated as the trailing one. The time is a Unix timestamp in decimal,
     * rendered into a buffer first because it is a middle parameter and
     * message_format() will not format one in place. */
    (void)snprintf(when, sizeof when, "%lld", (long long)ch->topic_when);
    (void)reply(s, dst, "333", (const char *const[]){ ch->name, ch->topic_who, when },
                3, "%s", ch->topic);
}

/* The joiner is told the channel's creation time after its names, as RFC 1459
 * 2.3.1's JOIN reply sequence does. 329 is RPL_CREATIONTIME, so it carries
 * created_at and nothing else -- reusing topic_when for it would be a numeric
 * lying about what it is. */
static void send_creation_time(server_t *s, conn_t *dst, const chan_t *ch)
{
    char stamp[24];

    (void)snprintf(stamp, sizeof stamp, "%lld",
                   (long long)chan_created_at(ch));
    (void)reply(s, dst, "329", (const char *const[]){ ch->name, stamp }, 2,
                "Channel creation time");
}

/* ---------------------------------------------------------------------------
 * 3.1's state-change arm, and the reason every state verb goes through it
 * ---------------------------------------------------------------------------
 * WHY THE FIVE STATE VERBS NO LONGER BROADCAST FOR THEMSELVES.
 *
 * This file used to have its own broadcast() -- the helper above -- and so did
 * core/fanout.c, and the two implemented the same half of 3.1's table with only
 * one of them having a forward arm. That is not tidiness, it is the shape a
 * missing forward takes: a JOIN that reaches every local member and reaches no
 * peer is indistinguishable, from the log, from a JOIN that reached every peer
 * and was refused by all of them. The duplication is where a forward gets lost,
 * so it is gone: these five verbs now resolve their channel, apply the change
 * locally, and hand the EMISSION to fanout_deliver() under
 * FANOUT_STATE_CHANGE, which is the one place that decides "local write, forward
 * to the owner, forward to servers[] -- or all of them".
 *
 * The verb class is NOT a parameter here, and that is what makes "delivered
 * exactly once" structural rather than a convention: fanout_resolve() recorded
 * the class in the resolved target and fanout_deliver() reads it out of that
 * same struct, so a handler cannot resolve a target as a `message` and deliver
 * it as a `state-change`. The row a target took when it was resolved is the row
 * it is delivered by, and there is no second decision in between to disagree
 * with the first.
 *
 * `params` are the CLIENT parameters after the target, which is 3.1's target
 * already resolved and canonicalised. `exclude` is NULL for all five: RFC 1459
 * 2.3.1 has the actor see its own JOIN, PART, TOPIC, MODE and KICK, and
 * excluding anyone would be a second, different rule per verb.
 *
 * THE WHOLE PARAMETER LIST IS DELIVERED, and it used to be possible to say
 * otherwise. There was an `nvisible` argument here, added by C3 to preserve
 * byte-exact Phase 4 assertions -- two of them, both in test_channels.c's
 * test_topic(), on the echo a setter and a second member see. Its only user was
 * TOPIC: the client-facing channel echo was rendered as the bare `:setter TOPIC
 * #chan` with the topic dropped, which RFC 2812 3.3.1 does not describe -- the
 * topic is the trailing parameter of the TOPIC command, and the peer-side STOPIC
 * already carries it. A parameter that exists only to preserve a wrong output is
 * a permanent tax on every future caller in exchange for a one-time migration of
 * our own tests, so it is gone, the echo is RFC-correct, and those two
 * assertions were updated to the RFC form.
 *
 * A verb that ever needs a shorter view wants a DIFFERENT FUNCTION for it,
 * named for the shorter view, rather than a count threaded through the one that
 * routes -- because "how much of this list the client sees" and "where does this
 * line go" are unrelated questions and a caller that can answer the second
 * wrongly by answering the first creatively is a bug waiting for a second verb.
 *
 * IT IS SAFE TO CALL WHEN NOTHING WAS APPLIED LOCALLY. On a CHAN_VERDICT_FORWARD
 * the caller applies nothing -- 2.2 forbids it -- and still calls this, because
 * the non-owned `state-change` row is "forward only, never a local write" and
 * forwarding IS the action. A caller that treated FORWARD as "do nothing" would
 * answer every client on a non-owned channel with success and change nothing
 * anywhere. */
static void deliver_state_change_forms(server_t *s, conn_t *c, chan_t *ch,
                                      const char *verb, const char *prefix,
                                      const fanout_form_t *plain,
                                      const fanout_form_t *extended)
{
    fanout_target_t t;

    if (ch == NULL || !fanout_resolve(s, c, ch->name, FANOUT_STATE_CHANGE, &t)) {
        /* fanout_resolve() answers 403/401 on failure and the channel is one
         * this node holds, so this is a caller that lost its chan_t. Nothing is
         * counted here: it is a bug, and fanout_resolve() has already said
         * something to the client. */
        return;
    }
    /* `carry` is NULL because this is an ORIGINATING emission: a client sent the
     * command and this node is minting its 2.4 identity at the forward. The
     * relay path is federation/verbs.c, and it hands its own tags to
     * fanout_deliver() instead. */
    (void)fanout_deliver_forms(s, &t, prefix, verb, plain, extended, NULL, NULL);
}

/* The one-shape form, and every state change except JOIN uses it: the extension
 * is a JOIN extension, so there is exactly one caller of the two-shape entry point
 * and this wrapper is what the other five get. */
static void deliver_state_change(server_t *s, conn_t *c, chan_t *ch,
                                 const char *verb, const char *prefix,
                                 const char *const *params, int nparams)
{
    const fanout_form_t plain = { params, nparams };

    deliver_state_change_forms(s, c, ch, verb, prefix, &plain, NULL);
}

/* ---------------------------------------------------------------------------
 * JOIN
 * ---------------------------------------------------------------------------
 * The only verb that CREATES a channel, and therefore the only place a creation
 * race can begin.
 *
 * On a single node this node is the first server to see the channel, so it is
 * the origin and there is nothing to race against. chan_new() is called with
 * s->name and s->epoch -- 2.2's (creation_epoch, server_name) pair with both
 * halves real, because server_t's epoch is the per-boot value and it is what
 * makes the tie-break in chan_origin_wins() meaningful across a restart.
 *
 * What is NOT here is a "another server may already own this name" check, and
 * that is not an omission to be papered over: this node cannot perform one,
 * because it has not seen from the other node. That is what SBURST is for
 * (Phase 6, 4.3). So the race is not simulated here and the tie-break is not
 * exercised through JOIN -- it is exercised as the pure function it is, which is
 * what 7/Phase 4 asks for and what makes both halves of the lexicographic order
 * testable without a second node.
 */
void handle_join(server_t *s, conn_t *c, const message_t *m)
{
    char store[CHAN_MAX_LIST_ARGS * (CHAN_MAX_NAME + 1u)];
    const char *names[CHAN_MAX_LIST_ARGS];
    int n;

    if (m->nparams < 1) {
        (void)reply_refused(s, c, "JOIN", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    n = chan_split_list(store, sizeof store, m->params[0], names,
                        CHAN_MAX_LIST_ARGS);
    if (n <= 0) {
        /* ALSO "TOO FEW", and deliberately NOT a different code: a bare `:` names
         * no channel, so from the client's side it sent nothing usable and
         * NEED_MORE_PARAMS is the true statement. Splitting it would invent a
         * distinction between "no parameters" and "an empty one" that this node
         * has no reason to make. */
        (void)reply_refused(s, c, "JOIN", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }

    for (int i = 0; i < n; i++) {
        char canonical[CHAN_MAX_NAME + 1];
        chan_t *ch;
        int created = 0;
        chan_verdict_t verdict;

        if (!canonical_channel(s, c, names[i], canonical, sizeof canonical)) {
            continue; /* 403 already sent */
        }
        ch = server_chan_get(s, canonical);
        if (ch == NULL) {
            /* CREATE. The first server to see a channel owns it (2.2), and on a
             * single node that is always this one -- so origin is s->name and
             * creation_epoch is s->epoch, which is the per-boot value server_t
             * already carries. Both halves of 2.2's (creation_epoch,
             * server_name) pair are therefore real from the first channel, which
             * is what makes a later re-key a comparison between two genuine
             * values rather than between a value and a placeholder. */
            ch = chan_new(canonical, s->name, s->epoch);
            if (ch == NULL || server_chan_attach(s, ch) != 0) {
                chan_free(ch);
                (void)reply(s, c, "437", (const char *const[]){ canonical }, 1,
                            "Cannot create that channel");
                continue;
            }
            created = 1;
            printf("[observable] chan_create: channel=%s origin=%s epoch=%llu "
                   "creator=%s\n", ch->name, ch->origin,
                   (unsigned long long)ch->origin_epoch, c->nick);
            /* A CHANNEL THAT WAS HERE BEFORE may have left a topic behind, and
             * this is the one place in the node where a remembered topic can be
             * put back: the channel did not exist, so nothing here is being
             * overwritten and 2.2's single-writer rule has nothing to say about
             * it. It is a restoration of this node's own record about a channel
             * the node created, not a state change, which is why it is not a peer
             * message and why nothing is forwarded.
             *
             * Order matters: the restore happens BEFORE any 332 is sent below, so
             * the first thing the joiner sees is the topic the channel actually
             * has rather than an empty one followed by the real thing later. */
            (void)server_topic_restore(s, ch);
        }
        /* Authority BEFORE membership and BEFORE the ban check.
         *
         * A refusal that had already added the member would be the exact failure
         * 2.2 warns about, and it would be invisible: the client would be in a
         * channel this node has refused to manage, and nothing would later
         * remove it except its own teardown.
         *
         * The ban check is here and not earlier BECAUSE this node is the origin
         * -- authority_ok() has just established that. A non-owner's modes[] and
         * ban list are a CACHE, and a cache cannot refuse a join: doing so would
         * make this node's divergence from the origin permanent and
         * user-visible, which is the failure the single-writer rule exists to
         * prevent. The authority check is therefore what makes the enforcement
         * below legitimate rather than a cache pretending to enforce. */
        /* A FORWARD VERDICT DOES NOT STOP A JOIN, and this is the ONE exception
         * to "an origin-requiring state change on a non-owned channel applies
         * nothing here", and the exception is the whole of JOIN's meaning.
         *
         * A JOIN is a LOCAL MEMBERSHIP FACT: this node has just decided that one
         * of its own clients is on a channel, and that fact is true whether or
         * not this node owns the channel. The channel's STATE -- its topic, its
         * modes, who is an op -- belongs to the origin, and a JOIN adds none of
         * those except the creator's +o. So the local half runs (chan_add_member,
         * the broadcast, the joiner's own numerics) AND the SJOIN is forwarded,
         * and the origin is the one that decides what the membership means.
         *
         * WRITING THIS AS THE GENERAL RULE INSTEAD GIVES AN EMPTY PEER ROSTER.
         * If a JOIN on a non-owned channel applied nothing locally, then a user
         * who joins a channel their own server does not own would not be a
         * member of it as far as 353 is concerned, would not receive that
         * channel's messages, and the SJOIN that would have told the origin
         * about them would never be sent -- because the forwarding is part of
         * the same call. The user would be on a channel they cannot see and
         * cannot talk in, and the only trace would be their own 366. That is
         * the single most visible way to get this wrong, which is why it is
         * spelled out at the call rather than left to the general rule. */
        verdict = authority_ok(s, c, ch, "JOIN", 1);
        if (verdict == CHAN_VERDICT_REFUSED) {
            continue; /* 437 already sent; nothing has been touched */
        }
        if (chan_banned(ch, c->nick, c->user, c->host)) {
            (void)reply(s, c, "474", (const char *const[]){ ch->name }, 1,
                        "Cannot join channel (banned)");
            printf("[observable] chan_ban_enforced: channel=%s nick=%s host=%s\n",
                   ch->name, c->nick, c->host);
            continue;
        }
        if (chan_find_member(ch, c) != NULL) {
            /* A repeat JOIN is not an error and it is answered with the topic,
             * the names and 366, so a client that re-issues JOIN (which several
             * do on reconnect) can still learn the roster. The membership is
             * left exactly as it is, flags included: a repeat JOIN must not
             * silently revoke an operator's +o. */
            printf("[observable] chan_join_repeat: channel=%s nick=%s\n", ch->name,
                   c->nick);
            send_topic(s, c, ch);
            send_names_list(s, c, ch);
            send_end_of_names(s, c, ch->name);
            continue;
        }

        /* The member goes on the channel, the channel goes on the connection,
         * and the mesh is told. All three are ONE function -- chan_admit() --
         * and Phase 9 is why that matters: core/resume.c re-joins a client to
         * its channels from a window, and a restore that had its own copy of
         * this sequence would be a second place deciding what "this client is
         * now a member" means. See chan_admit() for the extraction. */
        if (chan_admit(s, c, ch, (created != 0) ? CHAN_MEMBER_OP : 0u) == 0) {
            printf("[observable] chan_join: channel=%s nick=%s members=%zu "
                   "origin=%s\n",
                   ch->name, c->nick, ch->nmembers, ch->origin);
        }
    }
}

/* ---------------------------------------------------------------------------
 * chan_admit() -- the ONE definition of "this client is now a member here"
 * ---------------------------------------------------------------------------
 *
 * Four things, in this order, and the order is the correctness argument:
 *
 *   1. THE MEMBER RECORD AND THE CONNECTION'S OWN LIST. Neither derives from the
 *      other -- a channel outlives a connection and a connection outlives a
 *      channel -- so both are written, and a failure of the second ROLLS BACK
 *      the first. A member record with no matching entry in conn_t::chans would
 *      never be removed on teardown: a leak and a dangling pointer, and the two
 *      indexes disagreeing is the failure mode server.h warns about.
 *
 *   2. THE JOIN ECHO, to every member INCLUDING the joiner and BEFORE the
 *      joiner's own numerics, so a client watching the channel sees the join
 *      arrive before the roster that includes it. It goes through 3.1's table
 *      rather than through broadcast(): on an OWNED channel this writes to the
 *      members and forwards to servers[] UNION the ESTABLISHED links, and on a
 *      non-owned one it forwards to the owner without a second local write --
 *      the local one already happened, and the non-owned row is "forward ONLY"
 *      precisely so that the ORIGIN is the node that emits to its members.
 *
 *   3. THE AWAY-NOTIFY ANNOUNCEMENT, IF THE JOINER IS AWAY. `away-notify` says a
 *      user joining with an away message set is announced to the users it shares the
 *      channel with. It goes out AFTER the JOIN echo and BEFORE the joiner's own
 *      numerics, which is the order a client renders: first that the person arrived,
 *      then that they are away, then the joiner's own view of the channel.
 *
 *      IT IS A SEPARATE EMISSION AND NOT ANOTHER PARAMETER, and the specification
 *      requires that rather than this file preferring it. The two messages have
 *      different grammars and different audiences: the extended JOIN is
 *      `:nick!user@host JOIN #chan <account> :<realname>` and is a statement about
 *      the roster, while the announcement is `:nick!user@host AWAY #chan [:message]`
 *      and is a statement about ONE user's away STATE. Folding the away message into
 *      the JOIN would make a line a client parses as a roster carry a fourth field,
 *      and would mean every member learned the away message whether or not it
 *      negotiated `away-notify` -- which is exactly the unsolicited-notification
 *      defect Phase 10.8a's gate exists to prevent.
 *
 *      THE JOINER IS EXCLUDED, for msg_verbs.c's notify_away() reason: a user should
 *      not be sent an AWAY message about their own away status, and on this node they
 *      have `301` and `305` for that. It is `exclude` rather than the gate -- a
 *      different question from "did this destination ask?", which is why both exist.
 *
 *      GATED ON `c->away[0] != '\0'` AND NOTHING ELSE. There is no "is anybody
 *      currently away" question to ask: `conn_t::away` exists on every connection from
 *      accept(), so the only question is whether THIS joiner has a message, and a
 *      joiner with none produces no line at all. A third shape -- an `AWAY` with an
 *      empty trailing parameter -- would render as `AWAY #chan :`, which 3.2 does not
 *      represent in a non-final position and the formatter would refuse.
 *
 *   4. THE JOINER'S OWN FOUR NUMERICS, in the order a client parses them:
 *      topic, names, creation time, end of names. This is what makes a JOIN
 *      self-describing, and it is why a restore can hand a client back its
 *      channels without the client having to ask for anything.
 *
 * RETURNS 0 when the member is on the channel and has been told about it, and
 * -1 with a 437 already sent otherwise. A caller that wants to count its own
 * successes uses the return value rather than re-deriving it.
 *
 * WHY IT IS EXPOSED. core/resume.c's restore is a JOIN that nobody typed, and
 * the alternative -- a resume that re-implemented the sequence -- would be a
 * second definition of local membership, with its own ban check to forget and
 * its own idea of which mesh to tell. Both callers ask the same question of the
 * same channel, so both ask it here. */
static void announce_join_away(server_t *s, conn_t *c, chan_t *ch, const char *prefix);

int chan_admit(server_t *s, conn_t *c, chan_t *ch, unsigned flags)
{
    char prefix[CONN_HOSTMASK_MAX];
    /* THE TWO JOIN SHAPES, BUILT ONCE PER ADMISSION.
     *
     * `plain` is RFC 2812 3.3.1's JOIN echo, with no parameters at all -- the
     * channel name is the target, which fanout prepends. `extended` adds the two
     * parameters `extended-join` defines:
     *
     *   :nick!user@host JOIN #chan <account> :<realname>
     *   :nick!user@host JOIN #chan * :<realname>
     *
     * THE ACCOUNT IS `<account>` OR `*` AND NEVER EMPTY, and the rule is
     * account_logged_in() rather than `c->account[0]`, because the `*` form is the
     * specification's way of saying "this user has not logged in to an account
     * prior to channel ingress" -- and on a node with NO REGISTRY nobody ever is,
     * so `*` is not an absence of information here, it is the information. A node
     * that emitted an empty account field would be sending a parameter that reads
     * as an empty one, which is the exact confusion 2.1.1's invariant exists to
     * prevent, moved from a struct field to the wire.
     *
     * THE REALNAME IS `c->realname` AND MAY BE EMPTY, which is legal: it is the
     * trailing parameter, 3.2 colons it, and an empty one renders as a bare `:`
     * -- the one representation of "no text here". USER fills the field at
     * registration and a client that sent none has an empty realname, which is a
     * fact about the client rather than a limit this node imposes.
     *
     * BOTH LIVES ARE IN THIS FRAME, which is the same reason the hostmask is: the
     * emission happens inside fanout, so the values have to outlive the call that
     * builds them. */
    const char *extended_params[2];
    char acct_token[CONN_MAX_ACCOUNT + 2];
    fanout_form_t plain;
    fanout_form_t extended;

    if (s == NULL || c == NULL || ch == NULL) {
        return -1;
    }
    if (chan_add_member(ch, c, flags) != 0) {
        (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                    "Cannot join channel");
        return -1;
    }
    if (chan_attach_conn(c, ch) != 0) {
        (void)chan_remove_member(ch, c);
        (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                    "Cannot join channel");
        return -1;
    }
    if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
        (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                    "Cannot join channel");
        return -1;
    }
    memcpy(acct_token, account_logged_in(c) != 0 ? c->account : "*",
           strlen(account_logged_in(c) != 0 ? c->account : "*") + 1u);
    /* NEITHER LIST CARRIES THE CHANNEL NAME, because fanout prepends the resolved
     * target: 3.1's row is "write the target, then the caller's parameters", and
     * putting the name in the caller's list as well would render it twice. That is
     * why the plain list is EMPTY rather than holding one entry. */
    extended_params[0] = acct_token;
    extended_params[1] = c->realname;
    plain.params = NULL;
    plain.nparams = 0;
    extended.params = extended_params;
    extended.nparams = 2;
    deliver_state_change_forms(s, c, ch, "JOIN", prefix, &plain, &extended);

    announce_join_away(s, c, ch, prefix);
    send_topic(s, c, ch);
    send_names_list(s, c, ch);
    send_creation_time(s, c, ch);
    send_end_of_names(s, c, ch->name);
    return 0;
}

/* The AWAY-NOTIFY announcement for a user who JOINED while away. Called only from
 * chan_admit(), immediately after the JOIN echo, and the header above carries the
 * argument for its position, its separate shape and its two exclusions.
 *
 * IT IS NOT msg_verbs.c's notify_away() CALLED DIFFERENTLY, and the reason is the
 * count again: notify_away() walks `c->chans` and emits once per channel, which is
 * right for the away STATE CHANGE -- its line names the channel, so a member of three
 * shared channels gets three lines about three different channels, all of them true.
 * Here there is exactly one channel and one fact, so the walk would be a loop of one
 * and the helper would have grown a parameter for a case it does not have. One
 * `fanout_deliver_local_gated()` call is the whole of it, and the gate and the
 * liveness question are inside fanout.c where every other emission asks them.
 *
 * THE PARAMETER LIST IS BUILT HERE, IN THE CALLER'S FRAME, because the emission
 * happens inside fanout: `c->away` is read there and `message_format()` renders
 * there, so a pointer into this frame has to outlive this function, and it does
 * because the call is synchronous. That is the same reason chan_admit()'s extended
 * JOIN parameters are locals. */
static void announce_join_away(server_t *s, conn_t *c, chan_t *ch, const char *prefix)
{
    const char *params[1];
    fanout_form_t plain;
    fanout_target_t t;
    int delivered;

    if (c->away[0] == '\0') {
        return; /* not away: the specification announces an AWAY MESSAGE, not a JOIN */
    }
    if (fanout_resolve(s, c, ch->name, FANOUT_MESSAGE, &t) == 0) {
        return; /* a chan_t this node no longer holds: nothing to address */
    }
    params[0] = c->away;
    plain.params = params;
    plain.nparams = 1;
    /* The class is `message` and not `state_change` for the reason notify_away()
     * gives: this is not a change to the channel's state -- the roster already says
     * the user is on it -- it is an observation about that user. The class decides
     * the forward arm, and the local-only entry point has none to decide. */
    /* FAULT: the joiner is not excluded from the join-time announcement. */
    delivered = fanout_deliver_local_gated(s, &t, prefix, "AWAY", &plain, NULL,
                                            cap_gate_away_notify, NULL, c);
    printf("[observable] away_notify: nick=%s join=1 channel=%s recipients=%d\n",
           c->nick, ch->name, delivered);
}

/* ---------------------------------------------------------------------------
 * PART
 * ---------------------------------------------------------------------------
 * PART of a channel the client is not in is 442, and the arity check keeps that
 * distinct from 461: "you did not name a channel" and "that is not a channel you
 * are in" are different complaints, and only the second tells a client where it
 * stands.
 */
void handle_part(server_t *s, conn_t *c, const message_t *m)
{
    char store[CHAN_MAX_LIST_ARGS * (CHAN_MAX_NAME + 1u)];
    const char *names[CHAN_MAX_LIST_ARGS];
    const char *reason = (m->nparams > 1) ? m->params[1] : NULL;
    int n;

    if (m->nparams < 1) {
        (void)reply_refused(s, c, "PART", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    n = chan_split_list(store, sizeof store, m->params[0], names,
                        CHAN_MAX_LIST_ARGS);
    if (n <= 0) {
        (void)reply_refused(s, c, "PART", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }

    for (int i = 0; i < n; i++) {
        chan_t *ch = resolve_joined(s, c, names[i]);
        char prefix[CONN_HOSTMASK_MAX];
        const char *params[1];
        chan_verdict_t verdict;

        if (ch == NULL) {
            continue;
        }
        verdict = authority_ok(s, c, ch, "PART", 1);
        if (verdict == CHAN_VERDICT_REFUSED) {
            continue; /* 437 already sent */
        }
        if (verdict == CHAN_VERDICT_FORWARD) {
            /* No local write, and the client is NOT told: it left a channel it
             * was on, locally, and that is a fact about this node's membership
             * that no origin can undo. A PART is not a state change to the
             * channel's state -- it is a withdrawal from it -- and 2.2's
             * single-writer rule is about the channel's state, so the local half
             * runs on both paths. What differs is the forward: on a non-owned
             * channel the departure has to reach the origin too, or its roster
             * keeps a member this node no longer has. */
            if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
                continue;
            }
            params[0] = (reason != NULL) ? reason : c->nick;
            deliver_state_change(s, c, ch, "PART", prefix, params,
                                 (reason != NULL) ? 1 : 0);
        }
        /* The echo reaches the parting client too because it is still a usable
         * connection and RFC 1459 2.3.1 has it see its own departure -- which is
         * the SAME emission the origin gets, so the local write is the forwarding
         * row's write on an owned channel and this explicit one on a non-owned
         * one, where 3.1 forbids a second pass through the table. */
        chan_member_leave(s, ch, c, 1, reason);
        (void)chan_detach_conn(c, ch);
        /* Disposal AFTER the departure, and this is the only place a PART frees
         * a channel. A channel with no local members AND no remote members has
         * nothing left to be authoritative about; one with remote members
         * survives, which is the servers[] cache earning its place. */
        (void)chan_dispose_if_empty(s, ch);
    }
}

/* ---------------------------------------------------------------------------
 * TOPIC
 * ---------------------------------------------------------------------------
 * Two commands in one verb, distinguished by arity: TOPIC #chan queries,
 * TOPIC #chan :text sets. 2.2 makes topic/topic_who/topic_when remote-originated
 * cache, so the same three fields serve a locally set topic and one learned from
 * the origin, and 333 exposes all three to a client either way.
 */
void handle_topic(server_t *s, conn_t *c, const message_t *m)
{
    chan_t *ch;
    chan_verdict_t verdict;
    int setting;

    if (m->nparams < 1) {
        (void)reply_refused(s, c, "TOPIC", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    if (m->nparams > 2) {
        (void)reply_refused(s, c, "TOPIC", "TOO_MANY_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    setting = (m->nparams > 1);
    ch = resolve_joined(s, c, m->params[0]);
    if (ch == NULL) {
        return;
    }
    /* Asked ONCE, and the answer held, because authority_ok() reports on the
     * observable output and a reader seeing two `chan_state_forward` lines for
     * one TOPIC would reasonably ask what the second one was. */
    verdict = authority_ok(s, c, ch, "TOPIC", setting);
    if (verdict == CHAN_VERDICT_REFUSED) {
        return; /* 437 already sent */
    }
    if (setting == 0) {
        send_topic(s, c, ch);
        return;
    }
    if (verdict == CHAN_VERDICT_FORWARD) {
        /* THE FORWARD PATH, and it is the clearest case of the two consequences
         * this change has. Nothing is applied locally -- a topic this node does
         * not own is a CACHE, and writing a cache field on a client's say-so is
         * the permanent divergence 2.2 forbids -- and the client is still
         * answered 332/333 with whatever the node currently holds.
         *
         * THE CLIENT IS NOT LIED TO, and that is the point. The origin performs
         * the action, so the client asked a server to change a channel and the
         * mesh will change it; answering 437 would tell the client its own
         * request was rejected, which is false. The honest limits are stated
         * rather than hidden: the forward can still be refused further along --
         * at the peer's 437, or at a NO_ROUTE if the origin's link went down
         * between the authority check and the queue -- so what this node promises
         * is that it ACCEPTED the request, not that the mesh accepted it. */
        char prefix[CONN_HOSTMASK_MAX];
        const char *params[1];

        if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
            return;
        }
        /* The topic IS the parameter, and it goes out to the members as well as
         * to the peer. RFC 2812 3.3.1's TOPIC is `<channel> [:<topic>]`, so the
         * client-facing echo is `:setter TOPIC #CHAN :<topic>` and dropping the
         * trailing parameter would leave every member to re-read 332 to learn
         * what a line it was just sent says. A peer cannot rebuild a topic from a
         * bare `STOPIC #chan` either, which is why the same parameter serves
         * both renderings. */
        params[0] = m->params[1];
        deliver_state_change(s, c, ch, "TOPIC", prefix, params, 1);
        send_topic(s, c, ch);
        return;
    }

    /* The write. Every field changes together or none does: chan_set_topic()
     * refuses an over-long topic BEFORE touching topic_when, so a refused set
     * cannot leave a new time beside an old topic. */
    if (chan_set_topic(ch, m->params[1], c->nick) != 0) {
        (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                    "Topic is too long for this channel");
        return;
    }
    printf("[observable] chan_topic: channel=%s nick=%s len=%zu when=%lld\n",
           ch->name, c->nick, strlen(ch->topic), (long long)ch->topic_when);

    {
        char prefix[CONN_HOSTMASK_MAX];
        const char *params[1];

        if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
            return;
        }
        params[0] = m->params[1];
        deliver_state_change(s, c, ch, "TOPIC", prefix, params, 1);
    }
    /* The setter is told the topic back as 332/333, which is how it learns the
     * canonical form and the server's clock. */
    send_topic(s, c, ch);
}

/* ---------------------------------------------------------------------------
 * NAMES
 * ---------------------------------------------------------------------------
 * NAMES on a channel the client is not in is legal: 353 answers with what THIS
 * node knows, which on a single node is the whole roster. The names of members
 * the origin holds are not available until SNAMES carries them (Phase 6), and
 * 2.2's own argument -- the roster belongs to the origin to answer -- is why
 * answering from the local cache is the right shape and not a shortcut.
 */
void handle_names(server_t *s, conn_t *c, const message_t *m)
{
    if (m->nparams > 0) {
        char canonical[CHAN_MAX_NAME + 1];
        chan_t *ch;

        if (!canonical_channel(s, c, m->params[0], canonical, sizeof canonical)) {
            return; /* 403 already sent */
        }
        ch = server_chan_get(s, canonical);
        if (ch == NULL) {
            /* 366 with no 353, rather than 403. NAMES is a discovery command:
             * a client calls it to find out whether something is there, and
             * "nobody" is a legitimate answer to exactly that question. RFC 1459
             * 2.3.1 has an unknown channel answered with an empty list. */
            (void)reply(s, c, "366", (const char *const[]){ canonical }, 1,
                        "End of /NAMES list");
            return;
        }
        (void)authority_ok(s, c, ch, "NAMES", 0);
        /* The remote cache is reported whenever a roster is built, because a
         * 353 that lists local members only is incomplete BY DESIGN here and the
         * log is where that fact is visible. Phase 6 fills the rest in. */
        printf("[observable] chan_names: channel=%s local=%zu servers=%zu\n",
               ch->name, ch->nmembers, ch->nservers);
        send_names_list(s, c, ch);
        send_end_of_names(s, c, ch->name);
        return;
    }

    /* NAMES with no argument: every channel on the node, in creation order, each
     * with its own 366. */
    if (server_chan_count(s) == 0) {
        (void)reply(s, c, "366", NULL, 0, "End of /NAMES list");
        return;
    }
    for (size_t i = 0; i < server_chan_count(s); i++) {
        chan_t *ch = server_chan_at(s, i);

        if (ch == NULL) {
            continue;
        }
        (void)authority_ok(s, c, ch, "NAMES", 0);
        printf("[observable] chan_names: channel=%s local=%zu servers=%zu\n",
               ch->name, ch->nmembers, ch->nservers);
        send_names_list(s, c, ch);
        send_end_of_names(s, c, ch->name);
    }
}

/* ---------------------------------------------------------------------------
 * LIST
 * ---------------------------------------------------------------------------
 * Enumerates EVERY channel on the node, joined or not, and shows a locally
 * orphaned one normally. Both decisions are argued in chan_verbs.h; what matters
 * here is that neither is accidental.
 *
 * 322's count is the LOCAL member count. On a single node that is the whole
 * membership, so the number is exact; on a federated node it excludes members
 * this node has not been told about, and the log line above each row says how
 * many servers hold members it cannot enumerate, so the gap is visible rather
 * than implied. Inventing a total the node cannot know would be the one thing
 * worse than reporting a partial one honestly.
 */
void handle_list(server_t *s, conn_t *c, const message_t *m)
{
    char count[24];

    if (m->nparams > 0) {
        char canonical[CHAN_MAX_NAME + 1];
        chan_t *ch;

        if (!canonical_channel(s, c, m->params[0], canonical, sizeof canonical)) {
            return; /* 403 already sent */
        }
        ch = server_chan_get(s, canonical);
        if (ch == NULL) {
            (void)reply(s, c, "403", (const char *const[]){ canonical }, 1,
                        "No such channel");
            return;
        }
        (void)authority_ok(s, c, ch, "LIST", 0);
        (void)snprintf(count, sizeof count, "%zu", ch->nmembers);
        (void)reply(s, c, "322", (const char *const[]){ ch->name, count }, 2, "%s",
                    ch->topic);
        printf("[observable] chan_list: channel=%s local=%zu servers=%zu\n",
               ch->name, ch->nmembers, ch->nservers);
        (void)reply(s, c, "323", NULL, 0, "End of LIST");
        return;
    }

    (void)reply(s, c, "321", (const char *const[]){ "Channel" }, 1, "Users  Name");
    for (size_t i = 0; i < server_chan_count(s); i++) {
        chan_t *ch = server_chan_at(s, i);

        if (ch == NULL) {
            continue;
        }
        (void)snprintf(count, sizeof count, "%zu", ch->nmembers);
        (void)reply(s, c, "322", (const char *const[]){ ch->name, count }, 2, "%s",
                    ch->topic);
        printf("[observable] chan_list: channel=%s local=%zu servers=%zu\n",
               ch->name, ch->nmembers, ch->nservers);
    }
    (void)reply(s, c, "323", NULL, 0, "End of LIST");
}

/* ---------------------------------------------------------------------------
 * KICK
 * ---------------------------------------------------------------------------
 * The verb that makes member.flags load-bearing. Without the +o bit there is no
 * way to tell an operator from a plain member and 482 is unimplementable, which
 * is why 2.2's `struct member` had to grow a field in this phase.
 *
 * Check order, and it is not arbitrary:
 *
 *   442  the KICKER is not on the channel. Without this a non-member would be
 *        told 482 about a channel it is not in, which answers a question the
 *        client did not ask.
 *   437  the node may not manage this channel. Authority before privilege: a node
 *        with no standing to evaluate a channel's membership has no standing to
 *        say who may be removed from it either.
 *   482  the kicker holds no privilege -- 7/Phase 4's acceptance criterion, and
 *        meaningful only because +o is what sets it.
 *   401  the target is not a nickname this node knows.
 *   441  the target exists but is not on this channel.
 *
 * 441 is checked after 401 and the two are different facts: "they are not here"
 * is more specific than "no such nick", and a client that acted on 401 would go
 * looking for a user who is simply elsewhere.
 */
void handle_kick(server_t *s, conn_t *c, const message_t *m)
{
    chan_t *ch;
    struct member *target;
    const char *reason;
    char prefix[CONN_HOSTMASK_MAX];
    const char *params[4];

    if (m->nparams < 2) {
        (void)reply_refused(s, c, "KICK", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    if (m->nparams > 3) {
        (void)reply_refused(s, c, "KICK", "TOO_MANY_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    /* RFC 1459 2.3.1: the reason is optional, and a KICK without one names the
     * kicker, which is the most useful default available -- it is in the message
     * already and it is what the target will see. */
    reason = (m->nparams > 2) ? m->params[2] : c->nick;

    /* ------------------------------------------------------------------------
     * THE REASON BOUND, AND WHY IT IS CHECKED HERE AND NOT AT THE END
     * ------------------------------------------------------------------------
     * Immediately after the arity test, which is where a parameter's validity
     * belongs: a KICK carrying a parameter this node will not accept is refused
     * as malformed whatever the sender's standing on the channel, and a node that
     * answered 482 for a client who simply sent too many bytes would be reporting
     * a privilege problem for a syntax problem. Nothing below has run, so nothing
     * below has to be undone.
     *
     * IT WAS MISSING, AND THE CONSEQUENCE WAS WORSE THAN A MISSING 005 TOKEN. With
     * no test here the reason went straight into `deliver_state_change()` ->
     * `fanout_deliver()` -> `send_line()` -> `message_format()`, which refuses a
     * line it cannot represent rather than reshaping it -- and the only outcome at
     * that depth is a refusal counted on `n_reply_refused`, the counter `reply.c`
     * holds at zero because a non-zero value is a bug report. So one client
     * command was a reachable way to put a non-zero on it. Phase 10.4 recorded that
     * as a finding in two places (this bound, and `KICKLEN`'s absence from 005) and
     * named this as the fix for both; this is it.
     *
     * 417 is the numeric this node already uses for "that parameter is longer than
     * I will store" -- msg_verbs.c's AWAY and PRIVMSG and commands.c's SETNAME --
     * and reusing it is the point: a client that has learned one over-long
     * parameter refusal has learned all of them. For a client that negotiated
     * `standard-replies` this is `FAIL KICK ERR_INPUTTOOLONG` instead; the legacy
     * numeric and its text are byte-identical to what they would otherwise be,
     * which is the whole of reply.c's `reply_refused()` contract.
     *
     * THE DEFAULT REASON CANNOT FAIL, and that is worth saying rather than leaving
     * to be checked: it is `c->nick`, and a nickname is bounded by IRC_MAX_NICK
     * (63), so the substituted value is always inside this bound. A future change
     * that defaulted the reason to something client-supplied would have to move
     * this test. */
    if (strlen(reason) > (size_t)CHAN_MAX_KICK_REASON) {
        (void)reply_refused(s, c, "KICK", NULL, "417", NULL, 0,
                            "Kick reason is too long");
        printf("[observable] chan_kick_refused: channel=%s nick=%s reason=too_long "
               "len=%zu max=%d\n",
               m->params[0], c->nick, strlen(reason), CHAN_MAX_KICK_REASON);
        return;
    }

    ch = resolve_joined(s, c, m->params[0]);
    if (ch == NULL) {
        return;
    }
    if (authority_ok(s, c, ch, "KICK", 1) == CHAN_VERDICT_REFUSED) {
        return; /* 437 already sent */
    }
    /* NOT A FORWARD CASE, and the reason is 2.2 rather than 3.1. A KICK is only
     * meaningful on a channel this node ORIGINATES, because the kicker has to be
     * an operator OF THAT CHANNEL and the operator set is the origin's record;
     * a cache cannot decide who may remove whom. So a KICK on a non-owned but
     * linked channel is answered 437 by the verdict path below rather than
     * forwarded -- the privilege check that follows is the origin's rule and
     * applying it here would be the cache pretending to enforce. */
    if (!chan_has_flag(ch, c, CHAN_MEMBER_OP)) {
        /* 482, not 481. 481 is "you need to be a channel operator to do this"
         * for a mode the client may not set at all; 482 is "you are not
         * privileged enough for this action", which is the situation. */
        (void)reply_refused(s, c, "KICK", NULL, "482",
                            (const char *const[]){ ch->name }, 1,
                            "You're not a channel operator");
        printf("[observable] chan_kick_refused: channel=%s nick=%s reason=not_op\n",
               ch->name, c->nick);
        return;
    }
    target = chan_find_nick(ch, m->params[1]);
    if (target == NULL) {
        /* 441 versus 401, and the difference is a fact about the node rather
         * than about the channel. A nickname this node has NEVER heard of is
         * 401. A nickname it holds -- registered, somewhere -- that simply is
         * not on THIS channel is 441, and the two are genuinely different
         * answers: 401 sends a client looking for a user who does not exist,
         * while 441 tells it the user is real and is elsewhere. Conflating them
         * is how a client ends up trying to invite someone it already has. */
        if (server_nick_lookup(s, m->params[1]) != NULL) {
            (void)reply(s, c, "441", (const char *const[]){ m->params[1], ch->name },
                        2, "They're not on that channel");
        } else {
            (void)reply(s, c, "401", (const char *const[]){ m->params[1] }, 1,
                        "No such nick/channel");
        }
        return;
    }
    if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
        return;
    }
    printf("[observable] chan_kick: channel=%s by=%s target=%s\n", ch->name, c->nick,
           target->c->nick);

    /* The echo, in RFC 1459 2.3.1's parameter order: prefix, channel, target,
     * reason. */
    /* Through 3.1's table, and the target is included in the parameter list
     * because the CLIENT shape of a KICK is (channel, target, reason) and 3.1's
     * target is prepended by the fan-out. The frozen SKICK shape puts the
     * KICKER first and the channel second; the re-shaping is fed_sverb_params()'s
     * job and is not something this handler knows about. */
    params[0] = target->c->nick;
    params[1] = reason;
    deliver_state_change(s, c, ch, "KICK", prefix, params, 2);

    {
        conn_t *kicked = target->c;

        /* Remove, then detach from the kicked connection. The broadcast above
         * addressed the target while it was still a member, and the detach is
         * what keeps teardown from trying to remove it a second time. */
        (void)chan_remove_member(ch, kicked);
        (void)chan_detach_conn(kicked, ch);
        (void)chan_dispose_if_empty(s, ch);
    }
}

/* ---------------------------------------------------------------------------
 * MODE
 * ---------------------------------------------------------------------------
 * Three forms, by arity, and they are different operations:
 *
 *   MODE #chan                 a query -> 324 plus 329, answered from modes[].
 *   MODE #chan +o nick         a member privilege change.
 *   MODE #chan +b mask         a ban, which 2.2 reserves to the origin.
 *
 * The ban path is what makes channel-mode AUTHORITY visible rather than
 * asserted, and the shape is deliberate:
 *
 *   1. 442 first (in resolve_joined): membership is the precondition for having
 *      any standing in a channel at all.
 *   2. The single-writer check, because +b IS a state change.
 *   3. 482 for a non-operator. Privilege is asked before evaluation, so a
 *      non-operator is told it lacks privilege rather than being told what the
 *      channel's modes are.
 *   4. chan_mode_is_origin_only() -- and it is checked as a SEPARATE question
 *      from step 2, because they are different questions. Step 2 asks whether
 *      this node may MANAGE the channel; this asks whether it may EVALUATE this
 *      particular mode. 2.2's list is exactly {b, e, I}, and the two only come
 *      apart once Phase 6's forward path exists.
 *
 * +o and +v are NOT origin-only: they are prefix modes, they are in 005's
 * PREFIX=(ov)@+, and relaying a membership fact is forwarding rather than
 * deciding. That is exactly why 2.2 names three modes and not five.
 *
 * Anything this node does not evaluate is answered 472 ERR_UNKNOWNMODE. 004
 * advertises b,k,l,imnpst and this node acts on b alone; answering 421 would be
 * a lie about the verb, and silence is the failure mode 4.4's numerics exist to
 * prevent. 472 says "that mode character means nothing to me", which is true.
 */
/* ---------------------------------------------------------------------------
 * 367 RPL_BANLIST and 368 RPL_ENDOFBANLIST: `MODE <channel> +b` with no mask.
 * ---------------------------------------------------------------------------
 * RFC 2812 3.3.2 names this as a QUERY and not a change, in the same sentence
 * that defines the whole verb: "If the <modestring> parameter is given with a
 * list of mode arguments, then a list of mode arguments is returned for channel
 * modes b, e and I. ... +b, +e and +I are always passed to the server." So
 *
 *     MODE #chan +b          -> one 367 per mask, then 368
 *     MODE #chan -b          -> the same list, because the RFC does not
 *                               distinguish the signs for the LIST form
 *
 * and the mask is absent in both, which is the whole signal. Before this phase a
 * `+b` with no mask was answered 461 ERR_NEEDMOREPARAMS, which is the exact
 * opposite of the RFC: the client did not send too few parameters, it sent the
 * form that ASKS the question, and the answer it got was "you sent too few
 * parameters".
 *
 * WHY THAT MATTERS TO A REAL CLIENT, and it is why this is not a cosmetic fix.
 * irssi, weechat and hexchat all send `MODE <channel> b` when a window is
 * opened, precisely so the client's ban list is populated before the user
 * touches it. A node that answers 461 to that query leaves the client showing an
 * error in a status window and an EMPTY ban list, on a channel where the node is
 * enforcing bans perfectly well -- and a user who then types `/mode +b` on a mask
 * that is already set is told nothing useful, because there was never a list to
 * check against. The ban feature worked and was unreadable, which is the same
 * failure Phase 5 named for 301.
 *
 * THE GRAMMAR, from RFC 2812 5.1:
 *
 *   367 RPL_BANLIST  "<channel> <banmask>"
 *   368 RPL_ENDOFBANLIST "<channel> :End of channel ban list"
 *
 * so 367 has NO trailing field and 368 has one. 367 is emitted with an empty
 * trailing parameter -- `reply()` takes a trailing parameter by construction and
 * `message_format()` renders an empty one as a bare ':' -- which is the same
 * choice `send_names_list()` already makes for the empty 353, and the same
 * reason: a value in the final position is always representable and never has to
 * be invented. A 367 that appended the mask a second time in the text would be
 * one field the RFC does not have, on a numeric some clients read positionally.
 *
 * AND ONE 367 PER MASK, ALWAYS, WITH NO CHUNKING. The mask is a MIDDLE parameter
 * here, so the only bound is the wire line cap and reply() refuses rather than
 * reshapes (3.2). A mask is CHAN_MAX_BAN (63) bytes and a channel name is
 * CHAN_MAX_NAME (63), so one 367 is about 140 bytes -- inside IRC_MAX_LINE with
 * room for a second one, and well inside REPLY_TEXT_MAX. The list cannot be
 * chunked the way a 353 or a 319 is, and does not need to be: RFC 2812 3.3.4
 * permits 367 to repeat, but a loop over a bounded array of bounded strings
 * cannot produce a value the formatter refuses, so nothing is dropped and
 * nothing is truncated.
 *
 * THE AUTHORITY QUESTION IS NOT ASKED AGAIN. This is a QUERY about a channel the
 * caller has already been shown to be on (resolve_joined() sent 442 otherwise) and
 * whose modes 324 already answered from the same array -- and 324 is answered to
 * any member, not only to an operator. Asking "are you an operator" here would
 * make the ban list LESS readable than the mode list beside it, and RFC 2812
 * 3.3.2 attaches no privilege requirement to reading a list that the server is
 * publishing anyway. The masks in `ch->bans` are this node's own state and 2.2
 * puts the origin's ban list in the same struct every member's 353 is drawn from.
 */
static void send_ban_list(server_t *s, conn_t *dst, const chan_t *ch)
{
    for (size_t i = 0; i < ch->nbans; i++) {
        if (ch->bans[i].mask[0] == '\0') {
            continue;
        }
        (void)reply(s, dst, "367", (const char *const[]){ ch->name, ch->bans[i].mask },
                    2, "%s", "");
    }
    /* 368 ALWAYS, including for an empty list, and that is RFC 2812 3.3.4's rule
     * for this family rather than an inference from 353's: "a server is required
     * to send the list back using the RPL_BANLIST and RPL_ENDOFBANLIST messages
     * ... After the banmasks have been listed ... a RPL_ENDOFBANLIST MUST be
     * sent." A client that asked for the list and got no terminator is a client
     * still waiting for it, and the empty-list case is precisely the one where
     * silence and "no bans" are indistinguishable. */
    (void)reply(s, dst, "368", (const char *const[]){ ch->name }, 1,
                "End of channel ban list");
    printf("[observable] chan_ban_list: channel=%s by=%s masks=%zu\n", ch->name,
           dst->nick, ch->nbans);
}

void handle_mode(server_t *s, conn_t *c, const message_t *m)
{
    chan_t *ch;
    chan_verdict_t verdict;
    int plus;
    char prefix[CONN_HOSTMASK_MAX];
    const char *params[3];

    if (m->nparams < 1) {
        (void)reply_refused(s, c, "MODE", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    ch = resolve_joined(s, c, m->params[0]);
    if (ch == NULL) {
        return;
    }

    if (m->nparams < 2) {
        /* The query form. modes[] is what 324 shows, and on a non-origin node it
         * is a CACHE -- so the answer is as complete as this node's knowledge
         * is, and a later SSMODE from the origin corrects it. Refusing to
         * answer would be worse than answering partially, for the reason
         * authority_ok() documents. */
        char modes[CHAN_MAX_MODES + 2];

        (void)authority_ok(s, c, ch, "MODE", 0);
        if (ch->modes[0] == '\0') {
            (void)snprintf(modes, sizeof modes, "-");
        } else {
            (void)snprintf(modes, sizeof modes, "+%s", ch->modes);
        }
        (void)reply(s, c, "324", (const char *const[]){ ch->name, modes }, 2,
                    "Channel modes");
        send_creation_time(s, c, ch);
        return;
    }
    if (m->nparams > 3) {
        (void)reply_refused(s, c, "MODE", "TOO_MANY_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }

    /* A mode change is a state change, so the single-writer rule applies before
     * anything else is examined. The verdict is ASKED HERE AND HELD, because the
     * 482 and 472 refusals below come first in the RFC order and a caller that
     * re-asked would report `chan_state_forward` once per refused attempt. */
    verdict = authority_ok(s, c, ch, "MODE", 1);
    if (verdict == CHAN_VERDICT_REFUSED) {
        return; /* 437 already sent */
    }
    if (m->params[1][0] != '+' && m->params[1][0] != '-') {
        (void)reply(s, c, "472", (const char *const[]){ ch->name }, 1,
                    "Unknown mode character");
        return;
    }
    if (m->params[1][1] == '\0') {
        /* A MODE STRING WITH NO LETTERS: the client sent the mode argument and
         * none of the argument that goes with it, so this is a too-FEW case rather
         * than a malformed one, and NEED_MORE_PARAMS says exactly that. */
        (void)reply_refused(s, c, "MODE", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    if (!chan_has_flag(ch, c, CHAN_MEMBER_OP)) {
        (void)reply_refused(s, c, "MODE", NULL, "482",
                            (const char *const[]){ ch->name }, 1,
                            "You're not a channel operator");
        printf("[observable] chan_mode_refused: channel=%s nick=%s reason=not_op\n",
               ch->name, c->nick);
        return;
    }

    if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
        return;
    }
    plus = (m->params[1][0] == '+');

    /* A multi-letter mode string is legal ("+ovb"), so this is a loop and not a
     * single-letter parse, and each letter is applied in the order given. The
     * argument to a prefix or ban mode is params[2] for EVERY letter in the
     * string, which is what RFC 1459 2.3.1 specifies: "+oov nick" is two
     * promotions of one nick, not two different nicks. */
    /* THE FORWARD CASE IS REFUSED, and this is a DELIBERATE difference from
     * TOPIC. 2.2 says only the origin evaluates +b, +e and +I and that +o and
     * +v are prefix modes -- and 4.3's frozen SMODES shape names the node that
     * EVALUATED the change as its first field, so a forwarded SMODES would have
     * to name a node this one is not. There is no honest line to send, and
     * sending one that names this node as the evaluator would be asserting an
     * authority 2.2 does not grant. So the verdict's FORWARD outcome becomes 437
     * for MODE specifically, and the reason is printed rather than swallowed so
     * an operator can see it is a policy and not a missing forward. */
    if (verdict == CHAN_VERDICT_FORWARD) {
        printf("[observable] chan_mode_refused: channel=%s nick=%s "
               "reason=MODE_NEEDS_ORIGIN\n",
               ch->name, c->nick);
        (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                    "Cannot change %s: channel modes are the origin's to "
                    "evaluate (%s)",
                    ch->name, ch->origin);
        return;
    }

    for (size_t i = 1; m->params[1][i] != '\0'; i++) {
        char mode = m->params[1][i];
        char rendered[4];

        if (chan_mode_is_origin_only(mode) && !chan_origin_is_self(s, ch)) {
            /* Unreachable while authority_ok() gates every state change, and
             * deliberately still here: authority_ok() decides whether the node
             * may MANAGE this channel, this decides whether it may EVALUATE this
             * mode. Phase 6's forward path is the case where they differ, and a
             * check that only exists on the path that reaches it today is a check
             * that will be missing on the path that needs it. */
            (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                        "Only the origin of this channel may evaluate that mode");
            return;
        }

        if (mode == 'o' || mode == 'v') {
            struct member *target;

            if (m->nparams < 3) {
                (void)reply_refused(s, c, "MODE", NULL, "461", NULL, 0,
                                    "Not enough parameters");
                return;
            }
            target = chan_find_nick(ch, m->params[2]);
            if (target == NULL) {
                /* 441/401 for the same reason as in KICK: "real but not here"
                 * and "does not exist" are different facts. A MODE +o naming a
                 * nickname that is not on the channel is a client bug, and 441
                 * says precisely which bug. */
                if (server_nick_lookup(s, m->params[2]) != NULL) {
                    (void)reply(s, c, "441",
                                (const char *const[]){ m->params[2], ch->name }, 2,
                                "They're not on that channel");
                } else {
                    (void)reply(s, c, "401", (const char *const[]){ m->params[2] },
                                1, "No such nick/channel");
                }
                return;
            }
            (void)chan_set_member_flags(
                ch, target->c, plus,
                (mode == 'o') ? CHAN_MEMBER_OP : CHAN_MEMBER_VOICE);
            /* The echo, in RFC 1459 2.3.1's order: prefix, channel, mode, nick.
             * Four parameters, not three with a space in the last -- the wire has
             * no compound parameter, and message_format() would REFUSE one
             * containing a space rather than reshape it. */
            rendered[0] = plus ? '+' : '-';
            rendered[1] = mode;
            rendered[2] = '\0';
            /* The four-parameter echo, split into the two the fan-out wants: the
             * rendered mode is a MIDDLE parameter and the nickname is the
             * trailing one, which is why they are two array slots and not one
             * string with a space in it -- 3.2 refuses to deliver a value
             * containing a separator in a non-final position rather than
             * reshaping it, and RFC 1459 2.3.1 has them as two. */
            params[0] = rendered;
            params[1] = target->c->nick;
            deliver_state_change(s, c, ch, "MODE", prefix, params, 2);
            printf("[observable] chan_member_mode: channel=%s by=%s nick=%s "
                   "mode=%c set=%d\n", ch->name, c->nick, target->c->nick, mode,
                   plus);
            continue;
        }

        if (mode == 'b') {
            if (m->nparams < 3) {
                /* THE QUERY FORM, not a too-few-params case. RFC 2812 3.3.2:
                 * "If the <modestring> parameter is given with a list of mode
                 * arguments, then a list of mode arguments is returned for
                 * channel modes b, e and I." The client sent the mode argument
                 * and no argument to go with it, which is the QUESTION, and
                 * 461 answered it with "you sent too few parameters" -- a
                 * refusal that told the client its own question was malformed.
                 * See send_ban_list() for the full argument. */
                send_ban_list(s, c, ch);
                return;
            }
            if (plus) {
                if (chan_ban_add(ch, m->params[2]) != 0) {
                    /* 478 ERR_BANLISTFULL, whose RFC 2812 5.1 field list is
                     * "<channel> <char> :Channel list is full" -- so the channel
                     * AND the mode letter are middle parameters.
                     *
                     * THIS USED TO BE 696. Two things were wrong with that and the
                     * second is the one a client can see:
                     *
                     *   1. 696 IS NOT THIS CONDITION. RFC 2812 5.1 has no 696 at
                     *      all; 696 is RPL_ENDOFMODES from the historical MODE
                     *      draft, an end-of-list marker with no meaning about
                     *      capacity. A client holding 696 in its numeric table
                     *      renders "End of MODE list" for a refusal to add a ban,
                     *      and a client that does not hold it -- which is most,
                     *      because it is not a registered code -- shows nothing
                     *      at all. So the refusal was invisible or actively
                     *      misleading in both cases.
                     *   2. THE ARITY WAS WRONG EVEN FOR ITS OWN NUMERIC. It sent
                     *      the channel and nothing else, so the <char> the RFC's
                     *      field list names was absent; a client parsing positionally
                     *      read the channel name as the mode character that could
                     *      not be set.
                     *
                     * RFC 2812 3.3.4's own name for the condition is 478, and
                     * every client that knows a ban list at all maps 478 to "ban
                     * list full". Correcting it makes a cap that CHAN_MAX_BANS
                     * has always enforced report itself as the RFC's refusal
                     * instead of as an unexplained absence.
                     */
                    (void)reply(s, c, "478",
                                (const char *const[]){ ch->name, "b" }, 2,
                                "Channel list is full");
                    printf("[observable] chan_ban_refused: channel=%s by=%s "
                           "reason=ban_list_full nbans=%zu max=%d\n",
                           ch->name, c->nick, ch->nbans, CHAN_MAX_BANS);
                    return;
                }
                /* chan_ban_add() deliberately does not touch modes[]: a caller
                 * that adds a mask and forgets the letter has two bugs, and
                 * hiding one inside the other makes both harder to find. */
                (void)chan_mode_set(ch, 'b', 1);
            } else {
                if (chan_ban_remove(ch, m->params[2]) != 0) {
                    (void)reply(s, c, "368",
                                (const char *const[]){ ch->name, m->params[2] }, 2,
                                "Ban mask is not set on this channel");
                    return;
                }
                if (ch->nbans == 0) {
                    (void)chan_mode_set(ch, 'b', 0);
                }
            }
            rendered[0] = plus ? '+' : '-';
            rendered[1] = 'b';
            rendered[2] = '\0';
            params[0] = rendered;
            params[1] = m->params[2];
            deliver_state_change(s, c, ch, "MODE", prefix, params, 2);
            printf("[observable] chan_ban_mode: channel=%s by=%s mask=%s set=%d "
                   "nbans=%zu origin=%s\n", ch->name, c->nick, m->params[2], plus,
                   ch->nbans, ch->origin);
            continue;
        }

        /* 004 advertises b,k,l,imnpst; this node evaluates b, and o/v are prefix
         * modes rather than channel modes. A node that accepted a mode it does
         * not act on would have a 324 that disagrees with its behaviour, so the
         * unevaluated ones are refused by name. */
        (void)reply(s, c, "472", (const char *const[]){ ch->name }, 1,
                    "Unknown mode character");
        return;
    }
}

/* ---------------------------------------------------------------------------
 * INVITE
 * ---------------------------------------------------------------------------
 * 4.2's INVITE, RFC 2812 3.3.6. Two replies and one line to somebody else:
 *
 *   341  RPL_INVITING, to the INVITER: "you have invited them"
 *   INVITE  to the INVITEE, prefixed with the inviter's hostmask
 *
 * THE TWO REPLIES GO TO DIFFERENT CLIENTS, and that is the whole reason the
 * first one is not redundant. reply() addresses one connection (see reply.h), so
 * a 341 is by construction only ever seen by the inviter -- the numerics in 3's
 * reply path are "never written to a peer link and never relayed", and the same
 * one-enforcement-point discipline is what keeps a 341 off the invitee's socket.
 * The invitee is not answered with a numeric at all; it gets an INVITE, which is
 * an ordinary client-to-client line and therefore goes out through 3.1's table
 * rather than through reply().
 *
 * ---------------------------------------------------------------------------
 * WHY authority_ok() IS ASKED WITH `stateful` = 1 EVEN THOUGH INVITE CHANGES
 * NOTHING
 * ---------------------------------------------------------------------------
 * An INVITE adds no member, sets no topic and no mode, so by 2.2's own words it
 * is not a channel state change and the single-writer rule does not apply to it
 * in the way it applies to KICK or MODE. And yet it is asked as though it does,
 * and the reason is the OTHER thing it reads: the +o it checks.
 *
 * member.flags is the origin's record of who is an operator (2.2: the operator
 * set belongs to the origin, which is why MODE +o is a prefix mode and not an
 * origin-only one). So on a channel this node does not own, the +o that decides
 * 482 is a CACHE, and a cache cannot refuse anybody -- a node that let a cached
 * non-op invite would be the origin's policy being decided by a relay, which is
 * the exact failure the single-writer rule exists to prevent. Asking with
 * `stateful` = 1 is what turns that into an explicit 437 rather than a silently
 * wrong answer.
 *
 * And the FORWARD verdict is REFUSED here for the same reason handle_mode()
 * refuses it: 4.3's frozen S-verb table has no SINVITE, so there is no honest
 * line to put on a peer link, and the trailing text names the missing verb rather
 * than pretending the request succeeded somewhere it did not. The cost, stated:
 * on a federated mesh an invite into a channel this node does not own does not
 * work until 4.3 grows an SINVITE, and a client gets a 437 saying so rather than
 * a 341 that may not come true.
 *
 * ---------------------------------------------------------------------------
 * BOTH PARAMETER ORDERS ARE ACCEPTED
 * ---------------------------------------------------------------------------
 * RFC 1459 2.4.7 gave INVITE `<channel> <nick>` and RFC 2812 3.3.6 gave it
 * `<nick> <channel>`. Both are in the field -- the second is what current
 * clients send, the first is what older ones and a fair number of scripts still
 * send -- and a node that implements only one of them 401s half the clients that
 * use it, on a verb whose whole job is to be issued. So the two are told apart by
 * the NAME rather than by position: 4.4 advertises CHANTYPES=#& and this node
 * publishes 005's CHANTYPES=#&, so a parameter that is a valid channel name is
 * the channel. That is the same predicate the channel registry uses, so there is
 * one definition of "that is a channel name" and not two.
 *
 * The cost of accepting both is that `INVITE #a #b` is read as "invite #a to
 * #b" and 401s on #a, where reading it positionally would have produced the
 * nonsense invite of one channel to another either way. No legal line is
 * misread.
 */
static void notify_invite(server_t *s, conn_t *c, chan_t *ch, const char *prefix,
                           const char *target);

void handle_invite(server_t *s, conn_t *c, const message_t *m)
{
    const char *nick_arg;
    const char *chan_arg;
    chan_t *ch;
    fanout_target_t t;
    chan_verdict_t verdict;
    char prefix[CONN_HOSTMASK_MAX];
    const char *params[1];

    if (m->nparams != 2) {
        (void)reply_refused(s, c, "INVITE", "INVALID_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    if (chan_name_valid(m->params[0])) {
        /* RFC 1459 2.4.7's <channel> <nick>: the channel comes first. */
        chan_arg = m->params[0];
        nick_arg = m->params[1];
    } else {
        /* RFC 2812 3.3.6's <nick> <channel>. */
        nick_arg = m->params[0];
        chan_arg = m->params[1];
    }

    /* 442 for a channel the inviter is not on, 403 for a name this node will not
     * speak about, and -- less obviously -- 442 for a channel this node has
     * never heard of, because resolve_joined() answers that with 442 too and on
     * purpose. All three come from that one primitive rather than from three
     * checks here, so every channel verb in the node answers "you are not on
     * that channel" in the same words; the reasoning for the missing-channel
     * case is in resolve_joined()'s own comment. They are all about the
     * request rather than about the invitee, so they come before anything the
     * invitee is told. */
    ch = resolve_joined(s, c, chan_arg);
    if (ch == NULL) {
        return;
    }
    verdict = authority_ok(s, c, ch, "INVITE", 1);
    if (verdict == CHAN_VERDICT_REFUSED) {
        return; /* 437 already sent; nothing has been touched */
    }
    if (verdict == CHAN_VERDICT_FORWARD) {
        printf("[observable] chan_invite_refused: channel=%s nick=%s "
               "reason=INVITE_NEEDS_ORIGIN\n",
               ch->name, c->nick);
        (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                    "Cannot invite to %s: there is no SINVITE to send its origin "
                    "(%s)",
                    ch->name, ch->origin);
        return;
    }
    if (!chan_has_flag(ch, c, CHAN_MEMBER_OP)) {
        /* 482, for the RFC's reason: "Only channel operators may invite new
         * users to a channel" (3.3.6). The same numeric KICK and MODE use for
         * the same situation, and 4.4 has nothing better to say about "you
         * lack privilege for this action". */
        (void)reply_refused(s, c, "INVITE", NULL, "482",
                            (const char *const[]){ ch->name }, 1,
                            "You're not a channel operator");
        printf("[observable] chan_invite_refused: channel=%s nick=%s reason=not_op\n",
               ch->name, c->nick);
        return;
    }

    /* Resolved through 3.1 rather than through a direct registry lookup, so the
     * target is carried as a resolved target with its class already decided --
     * the same discipline every other emitter in the tree follows, and the
     * reason a second write path cannot grow here. A name that resolves to a
     * CHANNEL is 401: an invite names a person, and "no such nick" is the
     * honest answer for a name that is not one. */
    if (fanout_resolve(s, c, nick_arg, FANOUT_MESSAGE, &t) == 0) {
        return; /* 401 or 403 already sent */
    }
    if (t.kind != FANOUT_LOCAL_USER) {
        (void)reply(s, c, "401", (const char *const[]){ t.name }, 1,
                    "No such nick/channel");
        printf("[observable] chan_invite_refused: nick=%s target=%s kind=%d "
               "reason=not_a_nick\n",
               c->nick, t.name, (int)t.kind);
        return;
    }
    if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
        return;
    }

    /* The channel is the ONLY parameter after the target: 3.1's target is
     * prepended by the fan-out, and the client's own shape is
     * `INVITE <target> [:<channel>]`. It is sent whether or not the invitee is
     * already on the channel -- 3.3.6 says the invitee is invited "regardless of
     * its modes" and says nothing about suppressing the channel for somebody who
     * is already there, so the unconditional form is the one that is always
     * answerable by a client. */
    params[0] = ch->name;
    (void)fanout_deliver(s, &t, prefix, "INVITE", params, 1, NULL, NULL);

    /* The inviter is told, and only the inviter. t.user->nick is the spelling
     * the INVITEE chose (2.1: the registry folds the key and the display case is
     * the user's), so the 341 names them the way every other numeric does. */
    (void)reply(s, c, "341", (const char *const[]){ ch->name, t.user->nick }, 2,
                "%s has invited you to channel %s", c->nick, ch->name);
    notify_invite(s, c, ch, prefix, t.user->nick);
    printf("[observable] chan_invite: channel=%s by=%s target=%s\n", ch->name,
           c->nick, t.user->nick);
}

/* ---------------------------------------------------------------------------
 * invite-notify: THE CHANNEL IS TOLD
 * ---------------------------------------------------------------------------
 * `:nick!user@host INVITE <target> <channel>`, per destination, to the members of the
 * channel that negotiated the capability. The SOURCE is the inviter -- which is why this
 * is not a separate `send_line` but a fan-out carrying the inviter's own hostmask, the
 * same prefix the invitee's own copy carries and the same prefix `away-notify` uses.
 *
 * THE AUDIENCE IS THE CHANNEL, and RFC 2812 3.3.6 is the rule this relaxes: "Other
 * channel members SHOULD NOT be notified." The specification's whole purpose is to be the
 * opt-in that lets a client say it wants them, which is why the gate is the RECIPIENT's
 * negotiation and not the inviter's -- a sender-gated notification would put the fact on
 * the wire to members who never asked, which is the defect Phase 10.8a's gate was built
 * to prevent and which §9's risk row names.
 *
 * THE INVITER IS EXCLUDED, and it is excluded rather than gated because the gate would
 * have let it through if it negotiated. Two reasons: the `341` above IS the inviter's
 * answer -- "You have invited <nick> to <channel>" says exactly what this line would say
 * -- and the specification's own phrase is "a standard way that allows clients to learn
 * when ANOTHER client does an /INVITE". One line per event, to the audience it is for.
 *
 * NOT FORWARDED, for the reason `notify_away()` is not forwarded: this is an originating
 * emission and the local-only entry point has no forward arm. The cost is stated at
 * `away-notify`'s §3.1.1 note and applies verbatim -- away STATE federates through 4.3's
 * SBURST and a notification is not state; the same is true of an invitation, which 4.3's
 * frozen verb table has no S-verb for at all, so a mesh member's clients learn of an
 * invitation to a channel they can see by being in it and by nothing else.
 *
 * PER CHANNEL, NOT OVER A UNION, and the reason is the shape: the line's own grammar is
 * `:<inviter> INVITE <target> <channel>` and it NAMES its channel, so a member of three
 * shared channels gets three true statements about three channels. That is the same
 * distinction `setname`'s fan-out turned on, in the other direction. */
static void notify_invite(server_t *s, conn_t *c, chan_t *ch, const char *prefix,
                          const char *target)
{
    const char *params[2];
    fanout_form_t plain;
    struct chan *one[1];
    int delivered;

    /* ONE CHANNEL HANDED TO THE UNION ENTRY POINT, and the reuse is deliberate rather
     * than convenient. `fanout_deliver_local_gated()` PREPENDS the resolved target, so a
     * channel-addressed emission renders `:inv!u@h INVITE #chan <target>` -- and this
     * specification's grammar is `:<inviter> INVITE <target> <channel>`, the other way
     * round. The first version of this used the channel entry point and the line on the
     * wire was `INVITE #I in_g` with the parameters the wrong way round.
     *
     * `fanout_deliver_union_local_gated()`'s CONTRACT IS ABOUT THE AUDIENCE -- "the local
     * members of these channels, each written once, with NO target prepended" -- and a
     * one-element list of one channel is exactly the members of that channel. What it
     * takes is a list of `chan_t *`, not a connection's own list; the de-duplication it
     * does inside the walk is a no-op for one channel. So no new entry point and no new
     * parameter is needed for a line whose shape does not match 3.1's row.
     *
     * (This is the second user of that entry point and it is worth noting that the two
     * have opposite requirements: `setname` needs it because its line names NO channel
     * and would otherwise carry one, and this needs it because its line names the channel
     * in a position 3.1's row would have filled with the channel. Both are the same fact
     * -- the emission's grammar and the routing table's row disagree -- seen from two
     * sides. `away-notify` is the case where they agree, because `AWAY #chan :message`
     * happens to put the target first.) */
    params[0] = target;
    params[1] = ch->name;
    plain.params = params;
    plain.nparams = 2;
    one[0] = ch;
    delivered = fanout_deliver_union_local_gated(s, one, 1u, prefix, "INVITE", &plain,
                                                 NULL, cap_gate_invite_notify, NULL, c);
    printf("[observable] invite_notify: channel=%s by=%s target=%s recipients=%d\n",
           ch->name, c->nick, target, delivered);
}

/* ---------------------------------------------------------------------------
 * KNOCK
 * ---------------------------------------------------------------------------
 * 4.2's KNOCK, and the answer is a refusal. Everything below is why, because a
 * verb whose entire behaviour is one numeric is exactly the kind of thing that
 * looks like a stub and is not.
 *
 * THE GATE IS AN IRC OPERATOR, NOT A CHANNEL ONE, and this node has no operator
 * flags at all. KNOCK asks the ORIGIN to extend an invitation to a client that
 * is not on the channel, so a client has to be able to ask for a favour the
 * origin will not grant to everybody -- and the only thing the RFC names as that
 * authority is an IRC operator. There is no IRCop concept anywhere in this tree:
 * conn_t has no operator field, 004 advertises a user-mode set of "i" that
 * nothing evaluates, and 5's operator model does not exist. A node that answered
 * KNOCK with 704 RPL_KNOCK would be telling a client that a request was lodged
 * with an origin that has never heard of it, which is the 341-without-the-invite
 * failure this file's INVITE comment describes.
 *
 * SO THE ANSWER DOES NOT DEPEND ON THE CHANNEL, and no +k check is performed.
 * The RFC also allows a server to refuse knocks on a channel with +k set, and
 * that is the check this handler looks like it should have. It is not here
 * because it cannot change the answer on this build: nothing in the tree ever
 * records a 'k' in modes[], so chan_mode_has(ch, 'k') is 0 for every channel
 * this node holds, and a check whose answer is constant is not a check. The
 * observable line prints k_mode anyway, so the log says which gate fired and a
 * reader does not have to guess.
 *
 * WHAT WOULD REPLACE IT, and why it is not here: on a federated mesh the honest
 * implementation is a SKNOCK forwarded to the channel's origin, which then
 * decides. 4.3's frozen S-verb table has no SKNOCK, and §7/Phase 6's own
 * statement that a wire format cannot be invented later is the reason it is not
 * improvised here.
 *
 * 482 rather than 480 ERR_KNOCKPROHIBIT, and neither is in 4.4's list. 482 is
 * the numeric 4.4 does have for "you are not privileged enough for this action"
 * -- the same one KICK and MODE use -- and the trailing text says what the
 * privilege is. A client that receives it has been told the truth about why.
 */
void handle_knock(server_t *s, conn_t *c, const message_t *m)
{
    char canonical[CHAN_MAX_NAME + 1];
    chan_t *ch;

    if (m->nparams != 1) {
        (void)reply_refused(s, c, "KNOCK", "INVALID_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    /* A channel-name check and an existence check, both 403, and both BEFORE the
     * refusal -- so `KNOCK nosuch` and `KNOCK not-a-channel` are answered about
     * the thing the client got wrong rather than about the capability it lacks.
     * That distinction is the only difference a client can act on: one of them
     * is fixable by typing a different channel. */
    if (!canonical_channel(s, c, m->params[0], canonical, sizeof canonical)) {
        return;
    }
    ch = server_chan_get(s, canonical);
    if (ch == NULL) {
        (void)reply(s, c, "403", (const char *const[]){ canonical }, 1,
                    "No such channel");
        return;
    }

    /* 482, WHICH ELSEWHERE ON THIS NODE MEANS "NOT A CHANNEL OPERATOR" and here
     * means "not an IRC operator". That is not a near miss: it is the clearest
     * single piece of evidence for the migration, which is why this site overrides
     * the code. For a negotiating client this is `FAIL KNOCK ERR_NOPRIVILEGES` --
     * which is also the right rendering for the CHOPER refusal in commands.c,
     * because it is the same fact. */
    (void)reply_refused(s, c, "KNOCK", "ERR_NOPRIVILEGES", "482",
                        (const char *const[]){ ch->name }, 1,
                        "You're not an IRC operator");
    printf("[observable] knock_refused: channel=%s nick=%s reason=NO_OPER_FLAGS "
           "k_mode=%d local=%zu\n",
           ch->name, c->nick, chan_mode_has(ch, 'k'), ch->nmembers);
}

