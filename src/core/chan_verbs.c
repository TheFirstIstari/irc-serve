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

#include "core/channel.h"
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
 * Returns 1 when the caller may proceed. On 0, 437 has already been sent to `c`
 * and NOTHING has been modified.
 */
static int authority_ok(server_t *s, conn_t *c, const chan_t *ch,
                        const char *verb, int stateful)
{
    chan_origin_state_t st = chan_origin_state(s, ch);

    if (st == CHAN_ORIGIN_SELF) {
        return 1;
    }
    if (stateful == 0) {
        /* A query against a channel this node does not own. The answer may be
         * incomplete -- the remote members are in the origin's records -- and it
         * is given anyway, because the alternative is refusing to answer. */
        printf("[observable] chan_query: channel=%s verb=%s origin=%s "
               "state=LINKED_CACHE nservers=%zu\n",
               ch->name, verb, ch->origin, ch->nservers);
        return 1;
    }

    /* The refusal. Two situations reach here and they are reported differently
     * because they have different causes and different fixes:
     *
     *   ORPHANED           the origin is gone and no link bears its name. This is
     *                     2.2's "locally orphaned" case, and 437 is the whole of
     *                     fail-closed: local members still see each other, and
     *                     nothing that needs the origin is permitted.
     *   LINKED_NO_FORWARD  a peer connection for the origin exists, so 3.1's
     *                     "forward to the owner" is the right destination -- and
     *                     there is no forward path in this phase, because 4.3's
     *                     SJOIN/SPART/STOPIC/SSMODE/SKICK are Phase 6.
     *
     * The second is the honest limit of this phase. The alternative -- apply it
     * locally because the action looks harmless -- is precisely the permanent
     * divergence 2.2 forbids, and the node would have no way to notice it had
     * done it. */
    printf("[observable] chan_state_refused: channel=%s verb=%s origin=%s "
           "state=%s numeric=437\n", ch->name, verb, ch->origin,
           (st == CHAN_ORIGIN_UNREACHABLE) ? "ORPHANED" : "LINKED_NO_FORWARD");
    (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                "Cannot change %s: this server is not its origin (%s)", ch->name,
                ch->origin);
    return 0;
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

static void send_names_list(server_t *s, conn_t *dst, const chan_t *ch)
{
    const char *const mid[2] = { "=", ch->name };
    int produced = 0;

    for (int group = 0; group < 3; group++) {
        /* +1 for the NUL, and the budget is CHAN_NAMES_LINE rather than
         * REPLY_TEXT_MAX so the rendered text always fits reply()'s buffer. */
        char line[CHAN_NAMES_LINE + 1];
        size_t used = 0;

        for (size_t i = 0; i < ch->nmembers; i++) {
            const struct member *m = &ch->members[i];
            const char *sign;
            size_t nicklen;
            size_t need;

            if (m->c == NULL || m->c->nick[0] == '\0') {
                continue;
            }
            if (names_group(m) != group) {
                continue;
            }
            sign = (group == 1) ? "@" : (group == 2) ? "+" : "";
            nicklen = strlen(m->c->nick);
            need = strlen(sign) + nicklen + 1u; /* +1 for the joining space */
            if (used != 0 && used + need > (size_t)CHAN_NAMES_LINE) {
                /* Flush rather than truncate. RFC 2812 3.3.5 explicitly allows a
                 * 353 to be split across lines, and 3.2 forbids delivering a
                 * shortened value -- a half-written nickname is worse than one
                 * more line. */
                (void)reply(s, dst, "353", mid, 2, "%s", line);
                produced = 1;
                used = 0;
            }
            if (used != 0) {
                line[used++] = ' ';
            }
            if (sign[0] != '\0') {
                line[used++] = sign[0];
            }
            memcpy(line + used, m->c->nick, nicklen);
            used += nicklen;
            line[used] = '\0';
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
 * The per-member broadcast
 * ---------------------------------------------------------------------------
 * The ONE place a channel emission reaches more than one connection. A handler
 * states WHO and WHAT; this decides that it goes to every local member, and it
 * does so through reply.h's send_line(), so the peer-link and CLOSING refusals
 * still apply to a JOIN echo as much as to a numeric.
 */
static void broadcast(server_t *s, const chan_t *ch, const char *command,
                      const char *prefix, const char *const *params, int nparams)
{
    for (size_t i = 0; i < ch->nmembers; i++) {
        /* The same rule chan_member_leave() applies, for the same reason: a
         * member whose conn the loop has already marked CLOSING cannot be
         * written to, and attempting it would be a guaranteed n_reply_refused
         * -- the counter reply.c keeps at zero because a non-zero value is a
         * bug report and a teardown is not one. */
        if (chan_member_live(&ch->members[i]) == 0) {
            continue;
        }
        (void)send_line(s, ch->members[i].c, prefix, command, params, nparams);
    }
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
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }
    n = chan_split_list(store, sizeof store, m->params[0], names,
                        CHAN_MAX_LIST_ARGS);
    if (n <= 0) {
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }

    for (int i = 0; i < n; i++) {
        char canonical[CHAN_MAX_NAME + 1];
        chan_t *ch;
        int created = 0;
        char prefix[CONN_HOSTMASK_MAX];
        const char *params[1];

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
        if (!authority_ok(s, c, ch, "JOIN", 1)) {
            continue;
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

        /* The member goes on the channel and the channel goes on the
         * connection. Neither derives from the other: a channel outlives a
         * connection, and a connection outlives a channel.
         *
         * The CREATOR gets +o. This is not a convenience: RFC 1459 2.3.1 grants
         * the creator channel-operator status, and without it a channel on this
         * node would have no operator at all until an operator granted one -- and
         * nobody could, because every MODE +o requires an operator. A channel
         * with no reachable operator is a channel nobody can manage, so the
         * creator's privilege is what makes +o, KICK and MODE reachable at all.
         * It is the degenerate single-node case of 2.2's "first server to see a
         * channel owns it": locally, the creator is the one with authority. */
        if (chan_add_member(ch, c,
                            (created != 0) ? CHAN_MEMBER_OP : 0u) != 0) {
            (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                        "Cannot join channel");
            continue;
        }
        if (chan_attach_conn(c, ch) != 0) {
            /* Roll the membership back. A member record with no matching entry
             * in conn_t::chans would never be removed on teardown -- a leak and a
             * dangling pointer, and the two indexes disagreeing is the failure
             * mode the comment in server.h warns about. */
            (void)chan_remove_member(ch, c);
            (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                        "Cannot join channel");
            continue;
        }
        printf("[observable] chan_join: channel=%s nick=%s members=%zu origin=%s\n",
               ch->name, c->nick, ch->nmembers, ch->origin);

        /* The echo goes to every member INCLUDING the joiner, and BEFORE the
         * joiner's own numerics, so a client watching the channel sees the join
         * arrive before the roster that includes it. */
        if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
            (void)reply(s, c, "437", (const char *const[]){ ch->name }, 1,
                        "Cannot join channel");
            continue;
        }
        params[0] = ch->name;
        broadcast(s, ch, "JOIN", prefix, params, 1);

        send_topic(s, c, ch);
        send_names_list(s, c, ch);
        send_creation_time(s, c, ch);
        send_end_of_names(s, c, ch->name);
    }
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
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }
    n = chan_split_list(store, sizeof store, m->params[0], names,
                        CHAN_MAX_LIST_ARGS);
    if (n <= 0) {
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }

    for (int i = 0; i < n; i++) {
        chan_t *ch = resolve_joined(s, c, names[i]);

        if (ch == NULL) {
            continue;
        }
        if (!authority_ok(s, c, ch, "PART", 1)) {
            continue;
        }
        /* The echo reaches the parting client too (echo_to_who 1) because it is
         * still a usable connection and RFC 1459 2.3.1 has it see its own
         * departure. */
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
    int setting;

    if (m->nparams < 1) {
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }
    if (m->nparams > 2) {
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }
    setting = (m->nparams > 1);
    ch = resolve_joined(s, c, m->params[0]);
    if (ch == NULL) {
        return;
    }
    if (!authority_ok(s, c, ch, "TOPIC", setting)) {
        return;
    }
    if (setting == 0) {
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
        const char *params[2];

        if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
            return;
        }
        params[0] = ch->name;
        broadcast(s, ch, "TOPIC", prefix, params, 1);
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
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }
    if (m->nparams > 3) {
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }
    /* RFC 1459 2.3.1: the reason is optional, and a KICK without one names the
     * kicker, which is the most useful default available -- it is in the message
     * already and it is what the target will see. */
    reason = (m->nparams > 2) ? m->params[2] : c->nick;

    ch = resolve_joined(s, c, m->params[0]);
    if (ch == NULL) {
        return;
    }
    if (!authority_ok(s, c, ch, "KICK", 1)) {
        return;
    }
    if (!chan_has_flag(ch, c, CHAN_MEMBER_OP)) {
        /* 482, not 481. 481 is "you need to be a channel operator to do this"
         * for a mode the client may not set at all; 482 is "you are not
         * privileged enough for this action", which is the situation. */
        (void)reply(s, c, "482", (const char *const[]){ ch->name }, 1,
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
    params[0] = ch->name;
    params[1] = target->c->nick;
    params[2] = reason;
    broadcast(s, ch, "KICK", prefix, params, 3);

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
void handle_mode(server_t *s, conn_t *c, const message_t *m)
{
    chan_t *ch;
    int plus;
    char prefix[CONN_HOSTMASK_MAX];
    const char *params[4];

    if (m->nparams < 1) {
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
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
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }

    /* A mode change is a state change, so the single-writer rule applies before
     * anything else is examined. */
    if (!authority_ok(s, c, ch, "MODE", 1)) {
        return;
    }
    if (m->params[1][0] != '+' && m->params[1][0] != '-') {
        (void)reply(s, c, "472", (const char *const[]){ ch->name }, 1,
                    "Unknown mode character");
        return;
    }
    if (m->params[1][1] == '\0') {
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }
    if (!chan_has_flag(ch, c, CHAN_MEMBER_OP)) {
        (void)reply(s, c, "482", (const char *const[]){ ch->name }, 1,
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
                (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
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
            params[0] = ch->name;
            params[1] = rendered;
            params[2] = target->c->nick;
            broadcast(s, ch, "MODE", prefix, params, 3);
            printf("[observable] chan_member_mode: channel=%s by=%s nick=%s "
                   "mode=%c set=%d\n", ch->name, c->nick, target->c->nick, mode,
                   plus);
            continue;
        }

        if (mode == 'b') {
            if (m->nparams < 3) {
                (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
                return;
            }
            if (plus) {
                if (chan_ban_add(ch, m->params[2]) != 0) {
                    (void)reply(s, c, "696", (const char *const[]){ ch->name }, 1,
                                "Channel ban list is full");
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
            params[0] = ch->name;
            params[1] = rendered;
            params[2] = m->params[2];
            broadcast(s, ch, "MODE", prefix, params, 3);
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
