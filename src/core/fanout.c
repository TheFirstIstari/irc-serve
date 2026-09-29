/* fanout.c -- see fanout.h. The 3.1 routing table, written down once.
 *
 * ---------------------------------------------------------------------------
 * THE TABLE, AND WHERE EACH ROW GOES
 * ---------------------------------------------------------------------------
 * 3.1 verbatim, with the single-node reachability of each row marked honestly
 * (fanout.h has the same table in prose):
 *
 *   local user            | either          | write to conn_t
 *   owned channel         | message         | write to each local member AND forward to
 *   owned channel         | state-change    | servers[] UNION the ESTABLISHED links
 *   non-owned channel     | message         | write to local members AND forward to owner
 *   non-owned channel     | state-change    | FORWARD ONLY -- never a local write
 *   remote user           | either          | forward to that server
 *
 * The two rows that are "forward only" and "write AND forward" are the ones
 * 3.1 exists to separate, and they are separated here by the class and by
 * nothing else. A node with local members in a channel it does not own still
 * WRITES for a message and still does NOT WRITE for a state change; that is the
 * whole content of the table, and it is decided in one switch so no handler can
 * be right while its sibling is wrong.
 *
 * THE OWNED/`message` ROW IS THE AMENDED ONE and it used to say "no forward",
 * because "the origin already holds every member". The reason was false: the
 * origin holds those members in a roster, and a roster entry is not a delivery
 * path. The two owned rows are now the same row, and the correction -- with the
 * cost and the loop it creates -- is at forward_channel_targets() below, which
 * is where the target set is actually decided. Read it there before changing the
 * line above; the table is transcribed from 3.1 and 3.1 carries the amendment.
 *
 * ---------------------------------------------------------------------------
 * THE FORWARD IS AN EXPLICIT REFUSAL, NOT A SILENT DROP
 * ---------------------------------------------------------------------------
 * fanout_forward_link() reports every refusal on the observable output, naming
 * the peer it wanted and the reason it could not reach it, rather than returning
 * quietly: a federated node that lost a message with no trace would look exactly
 * like a node whose peers were silent, and the two have opposite fixes. The
 * local leg of a non-owned `message` still happens first, because 3.1 says it
 * does and because a message is not state -- see fanout.h on the verb class.
 *
 * ---------------------------------------------------------------------------
 * carry, AND WHO PASSES ONE
 * ---------------------------------------------------------------------------
 * Three call sites, all of which pass NULL, and one that passes a real stamp: the
 * three are the local fan-out of a client's own action, where this node is
 * ORIGINATING, and the fourth is federation/verbs.c relaying a line it received
 * -- and it does that by handing its tags to fanout_deliver() rather than by
 * forwarding the line itself, because a relay that both fanned the line out and
 * forwarded it would forward every received `message` twice, once with a fresh
 * id. See fanout.h on the argument.
 * The stamp is minted where the identity is decided -- here, at the
 * forward, for the originating case -- and carried where the message already
 * has one, because a restamp would give a relayed copy an identity the far
 * side's dedup store has never seen, which is the loop. See fanout.h.
 */
#include "core/fanout.h"

#include <stdio.h>
#include <string.h>

#include "core/reply.h"
#include "federation/verbs.h"

/* ASCII-only case folding, deliberately: 005 advertises CASEMAPPING=ascii, so
 * this node has already told every client that []\~ and {}|^ are NOT
 * equivalent, and folding them here would break that promise in a way no test
 * elsewhere would catch. The (unsigned char) cast is what makes that true for
 * every byte rather than only for the ones that are already ASCII. */
static int ascii_lower(int ch)
{
    return (ch >= 'A' && ch <= 'Z') ? (ch - 'A' + 'a') : ch;
}

/* The 2.4 never-forward-own-origin test, case-insensitively. This is the third
 * copy of an ASCII server-name fold (server.c and channel.c have the other two)
 * and the reasons it cannot be one function are spelled out where server.c's
 * copy is: a fold nobody uses twice is a helper exported for the sake of it, and
 * 2.1's nick@server split, 2.4's own-origin rule and 2.2's servers[] set are
 * three genuinely separate questions that happen to need the same six lines.
 * The copies are asserted to agree by test_channels.c, which looks a peer up by
 * a name differing only in case. */
static int same_origin(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    while (*a != '\0' && *b != '\0') {
        if (ascii_lower((unsigned char)*a) != ascii_lower((unsigned char)*b)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

int fanout_mask_match(const char *mask, const char *value)
{
    const char *m;
    const char *v;
    const char *star;
    const char *retry;

    if (mask == NULL || value == NULL) {
        return 0;
    }
    /* Iterative backtracking, not recursion: a mask arrives from a client, so
     * a pathological one must not be able to make this exponential. Same
     * shape as chan_mask_match(), which this is a sibling of rather than a
     * call to -- see the note in fanout.h. */
    m = mask;
    v = value;
    star = NULL;
    retry = NULL;
    while (*v != '\0') {
        if (*m == '*') {
            star = m++;
            retry = v;
        } else if (*m == '?' || ascii_lower((unsigned char)*m) ==
                                    ascii_lower((unsigned char)*v)) {
            m++;
            v++;
        } else if (star != NULL) {
            m = star + 1;
            v = ++retry;
        } else {
            return 0;
        }
    }
    while (*m == '*') {
        m++;
    }
    return *m == '\0';
}

/* Resolve a nickname to a connection.
 *
 * This used to be a workaround rather than a lookup: it asked the registry
 * exactly, and only on a miss walked the whole enumeration comparing
 * case-folded -- which is how `PRIVMSG BOB :hi` found a client registered as
 * `bob` while the registry stayed case-sensitive underneath it. It printed
 * `[observable] nick_resolve ... match=case_folded` when it took that path,
 * because a case-folded hit was evidence of the registry's defect.
 *
 * The registry folds now, so that scan was dead code, and it is gone: a
 * mitigation left standing after the bug is fixed is how the bug comes back.
 * The extra O(n) walk on every miss -- on the message-delivery hot path -- went
 * with it. `bob` and `BOB` can no longer both be held either, which the scan
 * itself could never have prevented: it resolved the ambiguity, it did not
 * remove it. */
conn_t *fanout_find_nick(server_t *s, const char *nick)
{
    if (s == NULL || nick == NULL || nick[0] == '\0') {
        return NULL;
    }
    return server_nick_lookup(s, nick);
}

/* ---------------------------------------------------------------------------
 * Resolution
 * ---------------------------------------------------------------------------
 */

int fanout_resolve(server_t *s, conn_t *from, const char *arg,
                   fanout_class_t vclass, fanout_target_t *out)
{
    conn_t *user;
    size_t len;

    if (out == NULL) {
        return 0;
    }
    memset(out, 0, sizeof *out);
    out->kind = FANOUT_NONE;
    out->vclass = vclass;

    /* `from` MAY BE NULL, and that is not a loophole: it means "a caller with
     * nobody to answer", which is what federation/verbs.c's guard chain is when
     * a peer names a channel this node does not hold. A numeric would be refused
     * to a CONN_SERVER connection anyway (3, and reply.c's emit_to_client), so
     * asking for one here would be a guaranteed n_reply_refused -- the counter
     * server.h says should be zero forever because a non-zero value is a bug
     * report. So the refusals below are conditional on there being a client to
     * refuse to, and the resolution itself is identical either way; that is what
     * keeps this the ONE place that answers "is this a channel or a nick". */
    if (s == NULL || arg == NULL || arg[0] == '\0') {
        return 0;
    }
    /* A name longer than either thing it could be cannot be one, and copying it
     * would overflow `name` -- so it is refused as an unresolvable target
     * rather than silently truncated into something that resolves. 401 is the
     * right complaint: this node has no such user, whatever the client meant. */
    len = strlen(arg);
    if (len >= sizeof out->name) {
        if (from != NULL) {
            (void)reply(s, from, "401", (const char *const[]){ "<too long>" }, 1,
                        "No such nick/channel");
        }
        return 0;
    }

    if (chan_name_valid(arg)) {
        /* A channel. 2.2 canonicalises the name, so the two spellings are one
         * channel and every reply, log line and future SBURST has to use the
         * same bytes. */
        char canonical[CHAN_MAX_NAME + 1];
        chan_t *ch;

        chan_name_upper(canonical, sizeof canonical, arg);
        memcpy(out->name, canonical, strlen(canonical) + 1u);
        ch = server_chan_get(s, canonical);
        if (ch == NULL) {
            if (from != NULL) {
                (void)reply(s, from, "403", (const char *const[]){ canonical }, 1,
                            "No such channel");
            }
            return 0;
        }
        out->chan = ch;
        out->kind = chan_origin_is_self(s, ch) ? FANOUT_LOCAL_CHANNEL
                                                : FANOUT_REMOTE_CHANNEL;
        return 1;
    }

    /* A `nick@server` target. 2.1's scoped identity splits at the LAST '@', and
     * a client may send one at any time; recognising the FORM is what keeps 3.1
     * from growing a new row in Phase 6. There is nothing to route it to yet
     * (fanout.h, on FANOUT_REMOTE_USER), so it resolves to a target with no
     * destination rather than being reported as a missing nickname -- which is
     * the difference between "this node cannot reach that server" and "that
     * user does not exist", and on a federated node only one of those is ever
     * true. */
    if (strrchr(arg, '@') != NULL) {
        memcpy(out->name, arg, len + 1u);
        out->kind = FANOUT_REMOTE_USER;
        return 1;
    }

    user = fanout_find_nick(s, arg);
    if (user == NULL) {
        if (from != NULL) {
            (void)reply(s, from, "401", (const char *const[]){ arg }, 1,
                        "No such nick/channel");
        }
        return 0;
    }
    memcpy(out->name, user->nick, strlen(user->nick) + 1u);
    out->user = user;
    out->kind = FANOUT_LOCAL_USER;
    return 1;
}

int fanout_is_member(const fanout_target_t *t, const conn_t *c)
{
    if (t == NULL || c == NULL) {
        return 0;
    }
    if (t->kind != FANOUT_LOCAL_CHANNEL && t->kind != FANOUT_REMOTE_CHANNEL) {
        return 0;
    }
    return (t->chan != NULL && chan_find_member(t->chan, c) != NULL) ? 1 : 0;
}

/* ---------------------------------------------------------------------------
 * 3.2's client-facing cap
 * ---------------------------------------------------------------------------
 * A relayed line is the client's own line PLUS the 2.4 internal tag block, so a
 * message this node accepted inbound can still be too long to send to anybody.
 * The bound is applied HERE, on the message text, rather than being discovered
 * by message_format() failing inside reply(): a render failure there is a
 * refusal counted on n_reply_refused, which reply.c documents as a bug report
 * and not a metric. A client that sent a long message is not a bug, it is a
 * limit, and a limit answers with a numeric.
 *
 * The number subtracted is 3.2's IRC_MAX_RELAY_LINE, and it is subtracted from
 * the FULL line rather than from the message alone. Two reasons that is the
 * conservative direction:
 *
 *   - the tag block is added on the relay path, which is Phase 6, so a message
 *     delivered locally now and forwarded later must be sized for the LARGER of
 *     the two. Sizing for today would mean a message this node happily delivers
 *     in Phase 5 becoming undeliverable in Phase 6 -- a behaviour change nobody
 *     would notice until it dropped a user's mail.
 *   - 3.2's own derivation is about the largest LEGAL tag set, and it says so
 *     explicitly ("the cap must equal the largest legal tag set rather than an
 *     average"). An average here would be the same error.
 *
 * The remaining envelope -- prefix, verb, target -- is charged at its maximum,
 * written as the struct widths the two of them come from, so raising
 * conn_t::nick or chan_t::name cannot leave the arithmetic short. */
int fanout_line_fits_n(const char *prefix, const char *verb, size_t target_len,
                       size_t params_bytes)
{
    /* message_format() reserves one byte for its NUL and emit_built() renders
     * into a buffer of IRC_MAX_LINE, so the CONTENT of a rendered line has to
     * be at most IRC_MAX_LINE - 1. 3.2 asks for one less than that again on the
     * relay path, and the budget is taken there rather than here:
     *
     *   content = ':' prefix ' ' VERB ' ' target ' ' params...
     *           = 1 + prefix_len + 1 + verb_len + 1 + target_len + 1 + params
     *
     * so the test is the same subtraction, with 3.2's IRC_MAX_RELAY_LINE as the
     * cap. prefix and target are charged at their MAXIMUM and written from the
     * struct widths their values come from, so raising conn_t::nick or
     * chan_t::name cannot leave the arithmetic short of a line that no longer
     * fits. VERB is measured: it is a fixed short list in this node, and
     * guessing at it would be a second opinion about code that already exists.
     *
     * `params_bytes` is the SUM of every parameter's length, separators
     * included by the fixed 1s above, and summing rather than charging only the
     * last one is what makes a line with several medium parameters -- an SKICK
     * with a member, a channel, a target and a long reason, which is the shape
     * 4.3 freezes for it -- come out the same size here as it would render. The
     * sum is a LOWER bound on the rendered size, never an over-estimate of it,
     * so the cap is approached from the conservative side. */
    const size_t charge = 1u /* ':' */ + 1u /* ' ' */ + 1u /* ' ' */ + 1u /* ' ' */
                          + CONN_HOSTMASK_MAX + (CHAN_MAX_NAME + 1u);

    (void)target_len;
    if (verb == NULL) {
        return 0;
    }
    (void)prefix;
    return (params_bytes + charge + strlen(verb)) <= (size_t)IRC_MAX_RELAY_LINE;
}

int fanout_line_fits(const char *prefix, const char *verb, const char *target,
                     const char *text)
{
    if (verb == NULL || text == NULL) {
        return 0;
    }
    return fanout_line_fits_n(prefix, verb, (target != NULL) ? strlen(target) : 0u,
                              strlen(text));
}

/* ---------------------------------------------------------------------------
 * Delivery
 * ---------------------------------------------------------------------------
 */

/* Write one line to every local member of `t->chan`, minus `exclude`.
 *
 * The same chan_member_live() rule every other member walk applies, for the
 * same reason: a member whose conn the loop has already marked CLOSING cannot
 * be written to, and attempting it is a guaranteed n_reply_refused -- a
 * non-zero value of the counter reply.c keeps at zero precisely because a
 * non-zero value means a bug. A teardown that is correct in every other respect
 * must not manufacture one. */
static int write_to_members(server_t *s, const fanout_target_t *t,
                            const char *prefix, const char *verb,
                            const char *const *params, int nparams,
                            conn_t *exclude)
{
    /* The target is `t->name` -- 2.2's CANONICAL form -- and not whatever the
     * caller typed, PREPENDED to the caller's own parameters. That is why the
     * caller's list is the parameters AFTER the target: it is the same
     * substitution this function has always made, and folding it into the
     * parameter list instead would mean every call site had to remember to
     * canonicalise, which is the mistake fanout_resolve() exists to prevent.
     *
     * One slot over the 15-parameter cap, and THE CAP IS ENFORCED HERE rather
     * than left to message_build(). The test is `nparams >= IRC_MAX_PARAMS`, not
     * `>`, and it is `>=` because the array below is IRC_MAX_PARAMS + 1 LONG and
     * the target takes one of those: a caller that hands over 15 tail parameters
     * would get 16 with the target, which message_build() refuses, and the
     * honest outcome for that is ZERO WRITES rather than a line the formatter
     * refused deep inside send_line() -- where the only available outcome is a
     * refusal counted on n_reply_refused, the counter reply.c keeps at zero
     * because a non-zero value of it is a bug report.
     *
     * IT WAS `>` UNTIL C4, and the comment above it said `>` was enough because
     * the comment claimed 15 tail parameters gave "zero writes". It did not: 15
     * passed the guard, filled all 16 slots, and built a 16-parameter line that
     * message_build() refused. Nothing in this node ever passes 15 -- every
     * caller passes two or three -- so the bug was unreachable from any call
     * site, which is exactly how a defect of this shape survives a phase: the
     * comment was the only thing asserting the bound, and the comment and the
     * code disagreed, so neither could be checked. The FANOUT_LOCAL_USER arm
     * below had the same guard and the same comment, and is fixed the same way;
     * both are here rather than in one helper because they are two separate
     * emissions with two separate destinations. */
    const char *all[IRC_MAX_PARAMS + 1];
    int n = 0;

    if (t->chan == NULL || nparams < 0 || nparams >= IRC_MAX_PARAMS) {
        return 0;
    }
    all[0] = t->name;
    for (int i = 0; i < nparams; i++) {
        all[i + 1] = params[i];
    }
    for (size_t i = 0; i < t->chan->nmembers; i++) {
        conn_t *m = t->chan->members[i].c;

        if (!chan_member_live(&t->chan->members[i])) {
            continue;
        }
        if (exclude != NULL && m == exclude) {
            continue;
        }
        (void)send_line(s, m, prefix, verb, all, nparams + 1);
        n++;
    }
    return n;
}

int fanout_deliver(server_t *s, const fanout_target_t *t, const char *prefix,
                   const char *verb, const char *const *params, int nparams,
                   conn_t *exclude, const irc_serve_tags_t *carry)
{
    /* Switched on an int, not on the enum, and that is deliberate rather than
     * lazy.
     *
     * -Weverything turns on BOTH -Wswitch-default (a switch over an enum must
     * carry a `default`) and -Wcovered-switch-default (a `default` is redundant
     * when every enumerator is listed). Writing 3.1's table both ways therefore
     * cannot satisfy both diagnostics at once, and the alternatives are both
     * worse: adding a suppression narrows a warning set this project has
     * deliberately kept maximal (see the top-level CMakeLists.txt), and dropping
     * the `default` means a kind added to fanout_kind_t later would compile
     * cleanly and fall through to the bottom of the function with no report --
     * which, in a routing table, is the one failure mode worth engineering
     * against.
     *
     * Reading the kind into an int satisfies both: the compiler can no longer
     * know the switch is exhaustive, so neither diagnostic fires, while the
     * cases below are still written out one per enumerator and a new one still
     * lands in the `default` that says it is unhandled. The two properties the
     * warnings were after are preserved and the warning set is untouched. */
    int kind;

    if (s == NULL || t == NULL || verb == NULL || (params == NULL && nparams != 0) ||
        nparams < 0) {
        return 0;
    }
    kind = (int)t->kind;

    switch (kind) {
    case FANOUT_LOCAL_USER: {
        const char *all[IRC_MAX_PARAMS + 1];
        int n = 0;

        /* The same `>=` and the same reason as write_to_members() above: the
         * array is one longer than the cap because the target takes one slot, so
         * 15 tail parameters would be 16 and would be refused by the builder.
         * See the comment there for why the claim and the code used to disagree
         * without anything noticing. */
        if (t->user == NULL || nparams >= IRC_MAX_PARAMS) {
            return 0;
        }
        all[0] = t->name;
        for (int i = 0; i < nparams; i++) {
            all[i + 1] = params[i];
        }
        if (exclude != NULL && t->user == exclude) {
            /* The sender addressed itself. For NOTICE that is 3.1's row applied
             * to the "never echoed to the sender" rule and the message is
             * simply not sent -- NOT a refusal, and not a numeric: a client
             * that NOTICEd itself has not done anything wrong. For PRIVMSG
             * `exclude` is NULL and the user hears its own message, which is
             * what lets a client confirm delivery without a second command. */
            return 0;
        }
        (void)send_line(s, t->user, prefix, verb, all, nparams + 1);
        n = 1;
        return n;
    }

    case FANOUT_LOCAL_CHANNEL: {
        int n = write_to_members(s, t, prefix, verb, params, nparams, exclude);

        /* 3.1's two owned rows, AND THEY NOW SHARE ONE FORWARD ARM.
         *
         * The local write is the only thing the verb class changes here, and the
         * forward is unconditional for both. The forward half is
         * fanout_forward_channel()'s, and it is CALLED rather than written out
         * for the reason the rest of this function is a single switch: the target
         * set is 3.1's, and 3.1's target set has a second caller --
         * federation/verbs.c relaying a state change it received -- which would
         * otherwise be a second walk over servers[] and the links, and the exact
         * duplication this module exists to prevent. See fanout.h on that
         * function. */
        (void)fanout_forward_channel(s, t->chan, t->vclass, verb, prefix, params,
                                     nparams, carry);
        return n;
    }

    case FANOUT_REMOTE_CHANNEL:
        if (t->vclass == FANOUT_STATE_CHANGE) {
            /* "FORWARD ONLY -- never a local write." 2.2's single-writer rule
             * is why the local write is the thing that is FORBIDDEN here rather
             * than the thing that is merely insufficient: a node that applied a
             * state change it could not route would hold a copy no one can
             * reconcile, permanently.
             *
             * The verb handlers ASK authority_ok() first, and since C3 the
             * answer for a linked non-owned channel is CHAN_VERDICT_FORWARD
             * rather than 437 -- which is this row reached deliberately. The
             * difference from the previous version is that the row now has a
             * caller, so "FORWARD ONLY" is what the node does rather than a
             * comment promising it would. */
            (void)fanout_forward_channel(s, t->chan, t->vclass, verb, prefix, params,
                                         nparams, carry);
            return 0;
        }
        /* "message": write to local members AND forward to the owner. Both
         * halves, and the local half is not conditional on the forward
         * succeeding -- a message is not state, so delivering it to the members
         * this node does have cannot create a divergence, whereas dropping it
         * would lose it.
         *
         * AND THE FORWARD IS UNCONDITIONAL, which is the whole of 7/Phase 6's
         * fifth acceptance criterion: "a node with ZERO LOCAL MEMBERS in the
         * channel still relays that channel's SPRIVMSG to the owner".
         * write_to_members() returns 0 for a channel with no local members and
         * also returns 0 when every member it had was the sender, so `n` cannot
         * distinguish "nobody to tell" from "told nobody" from "told somebody
         * and the write failed". Gating the forward on it would mean a node
         * with zero members in a channel it does not own silently swallows that
         * channel's traffic -- which is precisely the relay hop the design's
         * topology paragraph is built on, and the membership a node has is not
         * evidence about whether the message should travel.
         *
         * The same argument now applies to the OWNED row above, and that is the
         * amendment recorded in 3.1: a node that owns a channel and holds no
         * member of it still has to carry that channel's message to the servers
         * that do. */
        {
            int n = write_to_members(s, t, prefix, verb, params, nparams, exclude);

            (void)fanout_forward_channel(s, t->chan, t->vclass, verb, prefix, params,
                                         nparams, carry);
            return n;
        }

    case FANOUT_REMOTE_USER:
        /* "remote user nick@server | either | forward to that server". 2.1
         * splits a qualified name at the LAST '@' -- not the first, because '@'
         * is not a legal nick character (2.1's own charset rule) but a
         * server name is an opaque string and may itself contain one. The
         * split is therefore the same one 2.1 specifies, and getting it wrong
         * here would name a peer that does not exist.
         *
         * Nothing resolves the name to a peer yet (fanout.h, on
         * FANOUT_REMOTE_USER), so the report below is what makes the attempt
         * visible instead of a message that vanished. */
        {
            const char *at = strrchr(t->name, '@');
            char server[IRC_MAX_SERVER_NAME + 1];
            size_t n;

            if (at == NULL || at == t->name || at[1] == '\0') {
                (void)fanout_forward_link(s, "", t, verb, params, nparams, prefix,
                                          NULL);
                break;
            }
            n = strlen(at + 1);
            if (n > (size_t)IRC_MAX_SERVER_NAME) {
                n = (size_t)IRC_MAX_SERVER_NAME;
            }
            memcpy(server, at + 1, n);
            server[n] = '\0';
            (void)fanout_forward_link(s, server, t, verb, params, nparams, prefix,
                                      NULL);
        }
        break;

    case FANOUT_NONE:
        /* An unresolved target never reaches delivery -- fanout_resolve() has
         * already answered the client -- so this is a caller bug rather than a
         * protocol case. Counting nothing and saying nothing is the honest
         * outcome; emitting something would be guessing. */
        return 0;

    default:
        /* Unreachable while fanout_kind_t is closed and every value is listed
         * above. It is a BUG REPORT if it is ever reached -- a kind this table
         * does not know how to route -- so it says so rather than returning
         * quietly. */
        printf("[observable] fanout_unhandled_kind: verb=%s target=%s kind=%d\n",
               (verb != NULL) ? verb : "?", t->name, kind);
        return 0;
    }
    return 0;
}

/* 3.1's forward target set for a CHANNEL, in one function.
 *
 * TWO CALLERS AND THAT IS THE POINT. fanout_deliver()'s two channel rows call
 * it for a local emission, and federation/verbs.c reaches it through
 * fanout_deliver()'s own `carry` argument when it relays a message it received.
 * The rows are 3.1's, and after the amendment they are:
 *
 *   owned channel     | message        | servers[ch] UNION every ESTABLISHED
 *   non-owned channel | message        | link                        (the owner)
 *   owned channel     | state-change   | servers[ch] UNION every ESTABLISHED
 *   non-owned channel | state-change   | link                        (the owner)
 *
 * and a second copy of that walk in verbs.c would be exactly the duplication
 * this module exists to prevent: chan_verbs.c's own broadcast was already a
 * second implementation of "tell the members" and had no forward arm at all,
 * which is how a missing forward gets lost. There is now one place that decides
 * where a channel's message goes, and every caller uses it.
 *
 * THE OWNED ROWS ARE ONE ROW NOW, and that is the amendment this pass records.
 * The table used to say an owned channel with a `message` forwards nothing,
 * because "the origin already holds every member" -- and the reason was false.
 * In a mesh of three or more nodes the origin does not hold those members as
 * LOCAL members; it holds them in a remote roster, and a roster entry is not a
 * delivery path. The origin forwards nothing, so a member sitting on a third
 * node never hears a message for a channel it is on, and 7/Phase 6's fifth
 * acceptance criterion -- "a node with zero local members in the channel still
 * relays that channel's SPRIVMSG to the owner" -- was unreachable from the code
 * as specified, because the only path a `message` took across a link was
 * leaf -> owner and no relay ever received one. So the two owned rows now share
 * this one target set, and the class no longer chooses between them.
 *
 * WHAT THAT COSTS, plainly: an owner re-broadcasts, so a channel whose members
 * sit on N member-servers costs N forwards per message where it cost 1, and a
 * node that owns a channel with no local member of it now spends a forward on a
 * message it delivers to nobody. That is the price of the mesh being able to
 * reach its own members, and it is paid per channel rather than per node.
 *
 * AND IT IS WHAT MAKES A LOOP POSSIBLE, which the old row made impossible and
 * which is why the guards matter more rather than less. An owner now forwards a
 * message it received, so owner and relay can hand one message back and forth;
 * 2.4's three rules are what bound that, and each has a job: the `hops` ceiling
 * bounds how far it spreads, never-forward-own-origin stops the copy returning
 * to the server whose client wrote it, and the per-node dedup store drops the
 * copy that comes back to a node that has already seen the (origin, epoch, id).
 * The first hop back is therefore EXPECTED and is visible in the counters --
 * test_fed_loop.c asserts it happens exactly once and then stops, which is a
 * stronger claim than the old row allowed it to make.
 *
 * THE UNION IN THE OWNED ROWS IS LOAD-BEARING, and without it the FIRST join to
 * a channel is invisible. servers[] is a set of servers that have REPORTED a
 * member, so a channel's first join has an empty set on both sides: neither node
 * has heard from the other, so neither has anything in servers[], and a forward
 * over servers[] alone would mean nothing is ever forwarded for a new channel,
 * so no member is ever reported, so nothing is ever forwarded. A peer could
 * never become a relay or answer a 353, and 7/Phase 6's first acceptance
 * criterion would be unimplementable.
 *
 * It IS a broadcast to every linked peer, and 3.1's topology paragraph already
 * concedes that ("Forwarding to each peer holding members *is* a broadcast").
 * What is avoided is the GLOBAL list: the target is the member-server set plus
 * the node's own links, never every node on the network. The cost is that a
 * three-node mesh sends each state change -- and now each message -- to all
 * three rather than to the two that need it, and 3.1 accepts it in exchange for
 * a first join that works and a member on the third node that is not silenced.
 *
 * A peer in BOTH sets is forwarded to ONCE, deduped by name (case-insensitively,
 * because 2.1/2.4 both make server names case-insensitive). "Exactly once" is
 * structural here rather than resting on the far side's dedup store catching a
 * second copy, which matters because the store is bounded and evictable and a
 * bound that can be reached is not a guarantee.
 *
 * Returns how many peers the line was queued to. Zero is a normal answer: a
 * channel with no member-server and no ESTABLISHED link has nowhere to send it,
 * and a leaf that does not own the channel and has no route to the owner gets
 * the NO_ROUTE report from fanout_forward_sverb() rather than a silent drop. */
/* THE TARGET SET WALK, and the only copy of it. Static because both exported
 * entry points below reach it, and because a target set that two functions could
 * each implement is a target set with two answers. */
static int forward_channel_targets(server_t *s, const chan_t *ch,
                                   fanout_class_t vclass, const char *sverb,
                                   const char *prefix, const char *const *params,
                                   int nparams, const irc_serve_tags_t *carry)
{
    int queued = 0;
    int owned;

    if (s == NULL || ch == NULL || sverb == NULL) {
        return 0;
    }
    /* The verb class does NOT choose a target set, and that is the amendment
     * above: 3.1's two owned rows name the same one and 3.1's two non-owned rows
     * name the same one. It is still a parameter because this walk is where
     * 3.1's rows are implemented, and a row that does come to differ -- a
     * `message` that must not go back to the server it came from, say -- is
     * added HERE and not at each of the four callers that would otherwise each
     * have to notice it. Stated rather than left as an unused argument, because
     * an argument that used to matter and does not is exactly the kind of thing
     * a reader assumes is a bug. */
    (void)vclass;
    owned = chan_origin_is_self(s, ch);
    if (owned == 0) {
        /* Both non-owned rows go to the owner, and the two classes differ only
         * in whether the caller also wrote locally -- which is the caller's
         * half of the row, not this one's. */
        return fanout_forward_sverb(s, ch->origin, sverb, prefix, params, nparams,
                                    carry);
    }
    /* servers[] first, because those are the peers this node KNOWS hold
     * members, and a name in that set with no ESTABLISHED link is a finding
     * worth reporting rather than a peer to skip quietly. */
    for (size_t i = 0; i < ch->nservers; i++) {
        queued += fanout_forward_sverb(s, ch->servers[i].name, sverb, prefix, params,
                                       nparams, carry);
    }
    for (size_t j = 0; j < s->nlinks; j++) {
        const server_link_t *lk = &s->links[j];
        int already = 0;

        if (lk->state != (int)ESTABLISHED) {
            continue;
        }
        for (size_t i = 0; i < ch->nservers; i++) {
            if (same_origin(ch->servers[i].name, lk->name)) {
                already = 1;
                break;
            }
        }
        if (already == 0) {
            queued += fanout_forward_sverb(s, lk->name, sverb, prefix, params, nparams,
                                           carry);
        }
    }
    return queued;
}

int fanout_forward_channel(server_t *s, const chan_t *ch, fanout_class_t vclass,
                           const char *client_verb, const char *prefix,
                           const char *const *params, int nparams,
                           const irc_serve_tags_t *carry)
{
    const char *sverb;
    const char *sp[FED_SVERB_MAX_PARAMS];
    fed_sverb_scratch_t scratch;
    int shaped;

    if (s == NULL || ch == NULL || client_verb == NULL) {
        return 0;
    }
    sverb = fed_sverb_for(client_verb);
    if (sverb == NULL) {
        /* 4.3's list is short enough that a verb arriving here that is not in
         * it means something upstream built a line it cannot forward. */
        printf("[observable] fanout_forward_skipped: verb=%s target=%s "
               "reason=NO_SVERB\n",
               client_verb, ch->name);
        return 0;
    }
    /* Shaped ONCE, not once per peer. The shape is a function of the channel,
     * the verb and the source prefix, none of which vary across the target set,
     * and re-deriving it inside the walk would be work multiplied by the number
     * of peers for a value that cannot have changed. */
    shaped = fed_sverb_params(client_verb, ch->name, params, nparams, prefix,
                              s->name, ch, &scratch, sp, FED_SVERB_MAX_PARAMS);
    if (shaped < 0) {
        printf("[observable] fanout_forward_skipped: verb=%s target=%s "
               "reason=BAD_SHAPE\n",
               client_verb, ch->name);
        return 0;
    }
    return forward_channel_targets(s, ch, vclass, sverb, prefix, sp, shaped, carry);
}

int fanout_forward_channel_sverb(server_t *s, const chan_t *ch,
                                 fanout_class_t vclass, const char *sverb,
                                 const char *prefix, const char *const *params,
                                 int nparams, const irc_serve_tags_t *carry)
{
    /* The relay half: the line is ALREADY an S-verb in 4.3's frozen shape, so
     * there is nothing to re-shape and only the target set to decide. Same walk,
     * same rules, same refusals -- which is the whole reason it is a second
     * entry point onto one static function rather than a second function. */
    return forward_channel_targets(s, ch, vclass, sverb, prefix, params, nparams,
                                   carry);
}

/* The shape-free forward: one ALREADY-SHAPED S-verb to one named peer, with the
 * 2.4 loop guard applied at forward time. fanout_forward_link() below is the
 * same function with the shaping step in front of it, and federation/verbs.c
 * calls THIS one when it relays a line that is already an S-verb.
 *
 * It is a separate entry point because re-shaping a relayed S-verb as though it
 * were a client emission would be a bug: fed_sverb_params() reads a client's
 * parameter order, and an SJOIN's order (channel, member, flags) is not JOIN's
 * order (channel). Running one through the other produces a line no peer can
 * parse, silently, which is the failure mode this module's whole design is
 * arranged against.
 *
 * EVERY REFUSAL IS REPORTED on the observable output, naming the peer it wanted
 * and the reason it could not reach it. A federated node that lost a message
 * with no trace would look exactly like a node whose peers were silent, and the
 * two have opposite fixes. */
int fanout_forward_sverb(server_t *s, const char *peer_name, const char *sverb,
                         const char *prefix, const char *const *params,
                         int nparams, const irc_serve_tags_t *carry)
{
    const char *target = (params != NULL && nparams > 0) ? params[0] : "-";
    irc_serve_tags_t tags;
    conn_t *peer;
    fed_queue_why_t why = FED_QUEUE_OK;
    size_t pbytes = 0;
    /* The prefix this line will carry. NULL means the caller had none, and the
     * fallback is this node's own name -- correct for the five state verbs,
     * whose subject IS the server, and wrong for SPRIVMSG/SNOTICE, whose
     * subject is a user. See fanout.h on the parameter for why it exists and
     * why a silent fallback is stated here rather than left to be discovered. */
    const char *src = (prefix != NULL && prefix[0] != '\0')
                          ? prefix
                          : ((s != NULL) ? s->name : "-");

    if (s == NULL || peer_name == NULL || peer_name[0] == '\0' || sverb == NULL ||
        params == NULL || nparams < 0 || nparams > IRC_MAX_PARAMS) {
        printf("[observable] fanout_forward_skipped: verb=%s target=%s "
               "reason=unresolved_peer\n",
               (sverb != NULL) ? sverb : "?", target);
        return 0;
    }
    /* params[0] is charged SEPARATELY, at its maximum width, and only the
     * remaining parameters are summed. That is the same arithmetic the
     * single-string form used -- the target in the charge, the text as the
     * payload -- and it is right for the state verbs too: 4.3's frozen shapes
     * put either the channel or the member in the first slot, and both are
     * bounded by CHAN_MAX_NAME, which is exactly the width the charge uses. */
    for (int i = 0; i < nparams; i++) {
        if (params[i] == NULL) {
            printf("[observable] fanout_forward_skipped: verb=%s target=%s "
                   "reason=unresolved_peer\n", sverb, target);
            return 0;
        }
        if (i > 0) {
            pbytes += strlen(params[i]);
        }
    }

    /* 3.2's cap, applied to the PARAMETERS before anything is stamped or built,
     * for the reason fanout_line_fits() gives: a line that cannot be relayed is
     * a limit and answers with a numeric, not a render failure discovered deep
     * inside the send path where the only outcome is a refusal.
     *
     * It is here, above the stamp, for the same reason the peer lookup is: the
     * checks that can refuse a forward all run before anything is spent on it.
     * Originating takes the next id from the per-SERVER counter, and an id spent
     * on a line that is then refused is a hole in the sequence. Nothing requires
     * the sequence to be contiguous -- a peer's dedup only needs ids to be
     * unique, and to differ from a previous BOOT's ids, which is what epoch is
     * for -- but a hole per dropped forward is a hole per dropped forward, and
     * there is no reason to spend one. */
    if (fanout_line_fits_n(src, sverb, strlen(target), pbytes) == 0) {
        printf("[observable] fanout_forward_dropped: verb=%s target=%s "
               "peer=%s reason=too_long bytes=%zu\n",
               sverb, target, peer_name, pbytes);
        return 0;
    }

    /* The link is resolved before the message is stamped, for the reason above.
     * server_find_peer() is the "can this node route to that server" predicate,
     * and it is the ESTABLISHED one: a link that has not finished the handshake
     * FSM is not a route, and 2.3 requires the server-name uniqueness check to
     * happen before ESTABLISHED for the reason this would otherwise be a
     * duplicate-name bug on the wire. */
    peer = server_find_peer(s, peer_name);
    if (peer == NULL) {
        printf("[observable] fanout_forward_dropped: verb=%s target=%s peer=%s "
               "reason=NO_ROUTE\n",
               sverb, target, peer_name);
        return 0;
    }

    /* ---- 2.4: the stamp, and the loop guard, at forward time ---- */
    if (carry == NULL) {
        /* ORIGINATING. This node minted the message, so the identity is minted
         * with it -- and the origin is this node's name, which is what makes 2.4's
         * never-forward-own-origin rule decidable on the far side without any
         * extra state. */
        memset(&tags, 0, sizeof tags);
        memcpy(tags.origin, s->name, strlen(s->name) + 1u);
        tags.epoch = s->epoch;
        tags.id = server_next_msg_id(s);
        tags.hops = 0u;
    } else {
        /* RELAYING. origin/epoch/id are carried through and only hops moves.
         * `tags = *carry` cannot accidentally restamp, because a restamp would
         * have to be a write after this line and there is none. */
        if ((uint64_t)carry->hops + 1u >= (uint64_t)IRC_MAX_HOPS) {
            printf("[observable] fanout_forward_dropped: verb=%s target=%s "
                   "peer=%s reason=hop_limit hops=%lu ceiling=%d\n",
                   sverb, target, peer_name, (unsigned long)carry->hops,
                   IRC_MAX_HOPS);
            return 0;
        }
        if (same_origin(carry->origin, s->name)) {
            /* 2.4: "A node never forwards a message whose irc-serve-origin is
             * itself." This is the second of the three loop rules, and it is the
             * one that stops the SHORT cycle -- two nodes bouncing one message
             * between them -- which the hop ceiling alone would only slow down.
             *
             * The comparison is ASCII case-insensitive, and message.h says
             * explicitly that this is the caller's job: server names are
             * case-insensitive (2.1, RFC 1459 2.3.2), so a peer that spells this
             * node's name `IRC.A` in a tag is naming THIS node, and treating it
             * as a different server would forward back into the sender for ever
             * up to the hop ceiling. */
            printf("[observable] fanout_forward_dropped: verb=%s target=%s "
                   "peer=%s reason=own_origin origin=%s self=%s\n",
                   sverb, target, peer_name, carry->origin, s->name);
            return 0;
        }
        tags = *carry;
        tags.hops = carry->hops + 1u;
    }

    /* The prefix is the caller's, and for two of the seven S-verbs that is the
     * whole point: SPRIVMSG and SNOTICE are about a USER, so the receiver needs
     * a `nick!user@host` to put on the message it delivers to its own members.
     * verbs.h documents the argument and the fallback.
     *
     * fed_queue_line() and NOT fed_send_sverb(), because the verb here is
     * ALREADY an S-verb: fed_send_sverb() exists to map a client verb and
     * refuses a name it cannot map, and a relay's verb is exactly such a name.
     * The mapping and the shared step are separated for the same reason they are
     * for the T3 keepalive. */
    if (fed_queue_line(s, peer, &tags, src, sverb, params, nparams, &why) != 0) {
        /* fed_queue_why_name() has already been printed by nothing, so this
         * function says it, once. Counting a second, vaguer refusal here would
         * give an operator two lines to read for one event. */
        printf("[observable] fanout_forward_dropped: verb=%s target=%s peer=%s "
               "reason=%s\n",
               sverb, target, peer_name, fed_queue_why_name(why));
        return 0;
    }
    return 1;
}

int fanout_forward_link(server_t *s, const char *peer_name,
                        const fanout_target_t *t, const char *verb,
                        const char *const *params, int nparams,
                        const char *prefix, const irc_serve_tags_t *carry)
{
    const char *sverb;
    const char *sp[FED_SVERB_MAX_PARAMS];
    fed_sverb_scratch_t scratch;
    int shaped;
    const char *target = (t != NULL) ? t->name : "-";

    if (s == NULL || peer_name == NULL || peer_name[0] == '\0' || verb == NULL) {
        printf("[observable] fanout_forward_skipped: verb=%s target=%s "
               "reason=unresolved_peer\n",
               (verb != NULL) ? verb : "?", target);
        return 0;
    }
    /* Resolved before anything else that costs anything, because a verb with no
     * S-verb is a CALLER bug rather than a routing outcome, and 4.3's list is
     * short enough that a verb arriving here that is not in it means something
     * upstream built a line it cannot forward. */
    sverb = fed_sverb_for(verb);
    if (sverb == NULL) {
        printf("[observable] fanout_forward_skipped: verb=%s target=%s "
               "reason=NO_SVERB\n",
               verb, target);
        return 0;
    }
    shaped = fed_sverb_params(verb, target, params, nparams, prefix, s->name,
                              (t != NULL) ? t->chan : NULL, &scratch, sp,
                              FED_SVERB_MAX_PARAMS);
    if (shaped < 0) {
        printf("[observable] fanout_forward_skipped: verb=%s target=%s "
               "reason=BAD_SHAPE\n",
               verb, target);
        return 0;
    }
    return fanout_forward_sverb(s, peer_name, sverb, prefix, sp, shaped, carry);
}
