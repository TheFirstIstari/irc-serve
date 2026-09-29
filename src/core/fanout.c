/* fanout.c -- see fanout.h. The 3.1 routing table, written down once.
 *
 * ---------------------------------------------------------------------------
 * THE TABLE, AND WHERE EACH ROW GOES
 * ---------------------------------------------------------------------------
 * 3.1 verbatim, with the single-node reachability of each row marked honestly
 * (fanout.h has the same table in prose):
 *
 *   local user            | either          | write to conn_t
 *   owned channel         | message         | write to each local member; no forward
 *   owned channel         | state-change    | apply locally AND forward to servers[]
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
 * ---------------------------------------------------------------------------
 * THE FORWARD IS AN EXPLICIT REFUSAL, NOT A SILENT DROP
 * ---------------------------------------------------------------------------
 * fanout_forward_link() has nothing to send to. It says so on the observable
 * output, naming the peer it wanted, rather than returning quietly: a federated
 * node that reached this path with the forward still unimplemented would
 * otherwise lose messages with no trace, and "no trace" is the failure mode
 * 2.2's single-writer rule exists to avoid. The local leg of a non-owned
 * `message` still happens first, because 3.1 says it does and because a message
 * is not state -- see fanout.h on the verb class.
 */
#include "core/fanout.h"

#include <stdio.h>
#include <string.h>

#include "core/reply.h"

/* ASCII-only case folding, deliberately: 005 advertises CASEMAPPING=ascii, so
 * this node has already told every client that []\~ and {}|^ are NOT
 * equivalent, and folding them here would break that promise in a way no test
 * elsewhere would catch. */
static int ascii_lower(int ch)
{
    return (ch >= 'A' && ch <= 'Z') ? (ch - 'A' + 'a') : ch;
}

static int same_nick(const char *a, const char *b)
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

conn_t *fanout_find_nick(server_t *s, const char *nick)
{
    conn_t *exact;
    size_t n;

    if (s == NULL || nick == NULL || nick[0] == '\0') {
        return NULL;
    }
    exact = server_nick_lookup(s, nick);
    if (exact != NULL) {
        return exact;
    }
    n = server_nick_count(s);
    for (size_t i = 0; i < n; i++) {
        conn_t *c = server_nick_at(s, i);

        if (c == NULL || c->nick[0] == '\0') {
            continue;
        }
        if (same_nick(c->nick, nick)) {
            printf("[observable] nick_resolve: asked=%s resolved=%s "
                   "match=case_folded\n",
                   nick, c->nick);
            return c;
        }
    }
    return NULL;
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

    if (s == NULL || from == NULL || arg == NULL || arg[0] == '\0') {
        return 0;
    }
    /* A name longer than either thing it could be cannot be one, and copying it
     * would overflow `name` -- so it is refused as an unresolvable target
     * rather than silently truncated into something that resolves. 401 is the
     * right complaint: this node has no such user, whatever the client meant. */
    len = strlen(arg);
    if (len >= sizeof out->name) {
        (void)reply(s, from, "401", (const char *const[]){ "<too long>" }, 1,
                    "No such nick/channel");
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
            (void)reply(s, from, "403", (const char *const[]){ canonical }, 1,
                        "No such channel");
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
        (void)reply(s, from, "401", (const char *const[]){ arg }, 1,
                    "No such nick/channel");
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
int fanout_line_fits(const char *prefix, const char *verb, const char *target,
                     const char *text)
{
    /* message_format() reserves one byte for its NUL and emit_built() renders
     * into a buffer of IRC_MAX_LINE, so the CONTENT of a rendered line has to be
     * at most IRC_MAX_LINE - 1. 3.2 asks for one less than that again on the
     * relay path, and the budget is taken there rather than here:
     *
     *   content = ':' prefix ' ' VERB ' ' target ':' text
     *           = 1 + prefix_len + 1 + verb_len + 1 + target_len + 1 + text_len
     *
     * so the test is the same subtraction, with 3.2's IRC_MAX_RELAY_LINE as the
     * cap. prefix and target are charged at their MAXIMUM and written from the
     * struct widths their values come from, so raising conn_t::nick or
     * chan_t::name cannot leave the arithmetic short of a line that no longer
     * fits. VERB is measured: it is a fixed short list in this node, and
     * guessing at it would be a second opinion about code that already exists. */
    const size_t charge = 1u /* ':' */ + 1u /* ' ' */ + 1u /* ' ' */ + 1u /* ':' */
                          + CONN_HOSTMASK_MAX + (CHAN_MAX_NAME + 1u);

    if (verb == NULL || text == NULL) {
        return 0;
    }
    (void)prefix;
    (void)target;
    return (strlen(text) + charge + strlen(verb)) <= (size_t)IRC_MAX_RELAY_LINE;
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
                            const char *text, conn_t *exclude)
{
    const char *params[2];
    int n = 0;

    if (t->chan == NULL) {
        return 0;
    }
    params[0] = t->name;
    params[1] = text;
    for (size_t i = 0; i < t->chan->nmembers; i++) {
        conn_t *m = t->chan->members[i].c;

        if (!chan_member_live(&t->chan->members[i])) {
            continue;
        }
        if (exclude != NULL && m == exclude) {
            continue;
        }
        (void)send_line(s, m, prefix, verb, params, 2);
        n++;
    }
    return n;
}

int fanout_deliver(server_t *s, const fanout_target_t *t, const char *prefix,
                   const char *verb, const char *text, conn_t *exclude)
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

    if (s == NULL || t == NULL || verb == NULL || text == NULL) {
        return 0;
    }
    kind = (int)t->kind;

    switch (kind) {
    case FANOUT_LOCAL_USER: {
        const char *params[2];
        int n = 0;

        if (t->user == NULL) {
            return 0;
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
        params[0] = t->name;
        params[1] = text;
        (void)send_line(s, t->user, prefix, verb, params, 2);
        n = 1;
        return n;
    }

    case FANOUT_LOCAL_CHANNEL: {
        int n = write_to_members(s, t, prefix, verb, text, exclude);

        if (t->vclass == FANOUT_STATE_CHANGE) {
            /* "apply locally AND forward to every peer in servers[]". The
             * forward arm is 3.1's, and servers[] is empty on one node, so it
             * iterates nothing -- the loop is here, in the row, rather than in
             * Phase 6, so that adding servers[] entries is a data change and
             * not a code change. It is deliberately NOT in servers[]'s own
             * terms: the local node's name is not in that set (2.2 says so),
             * which is exactly why "forward to every peer in servers[]" cannot
             * mean "forward to us". */
            for (size_t i = 0; t->chan != NULL && i < t->chan->nservers; i++) {
                (void)fanout_forward_link(s, t->chan->servers[i].name, t, verb,
                                          text);
            }
        } else {
            /* "message": the origin already holds every member, so there is
             * nothing to forward. This is 3.1's whole argument for splitting
             * the classes, and the reason a `message` on an owned channel
             * cannot be double-delivered on a two-node mesh. */
        }
        return n;
    }

    case FANOUT_REMOTE_CHANNEL: {
        if (t->vclass == FANOUT_STATE_CHANGE) {
            /* "FORWARD ONLY -- never a local write." 2.2's single-writer rule
             * is why the local write is the thing that is FORBIDDEN here rather
             * than the thing that is merely insufficient: a node that applied a
             * state change it could not route would hold a copy no one can
             * reconcile, permanently.
             *
             * The verb handlers refuse a non-owned channel's state change with
             * 437 before reaching this, so on a single node the row is
             * unreachable. It is written down anyway: 3.1 is the contract, and
             * the one that is easy to get wrong in Phase 6 is precisely the one
             * that says "do not write locally". */
            (void)fanout_forward_link(s, (t->chan != NULL) ? t->chan->origin
                                                           : "",
                                      t, verb, text);
            return 0;
        }
        /* "message": write to local members AND forward to the owner. Both
         * halves, and the local half is not conditional on the forward
         * succeeding -- a message is not state, so delivering it to the members
         * this node does have cannot create a divergence, whereas dropping it
         * would lose it. */
        {
            int n = write_to_members(s, t, prefix, verb, text, exclude);

            (void)fanout_forward_link(s, (t->chan != NULL) ? t->chan->origin
                                                           : "",
                                      t, verb, text);
            return n;
        }
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
                (void)fanout_forward_link(s, "", t, verb, text);
                break;
            }
            n = strlen(at + 1);
            if (n > (size_t)IRC_MAX_SERVER_NAME) {
                n = (size_t)IRC_MAX_SERVER_NAME;
            }
            memcpy(server, at + 1, n);
            server[n] = '\0';
            (void)fanout_forward_link(s, server, t, verb, text);
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

int fanout_forward_link(server_t *s, const char *peer_name,
                        const fanout_target_t *t, const char *verb,
                        const char *text)
{
    const char *target = (t != NULL) ? t->name : "-";
    conn_t *peer;

    (void)text;
    if (s == NULL || peer_name == NULL || peer_name[0] == '\0') {
        printf("[observable] fanout_forward_skipped: verb=%s target=%s "
               "reason=unresolved_peer\n",
               (verb != NULL) ? verb : "?", target);
        return 0;
    }
    /* server_find_peer() is the "can this node reach that server" predicate and
     * it is real today: 2.3's connection registry already holds a peer's name in
     * conn_t::peer_name. On a single node it always answers NULL, because
     * server_dial() has no caller and nothing creates a CONN_SERVER. */
    peer = server_find_peer(s, peer_name);
    if (peer == NULL) {
        printf("[observable] fanout_forward_dropped: verb=%s target=%s peer=%s "
               "reason=NO_ROUTE\n",
               (verb != NULL) ? verb : "?", target, peer_name);
        return 0;
    }
    /* Reachable only once 2.3 has a peer link. The S-verb construction, the
     * 2.4 origin/epoch/id/hops tags and the loop guard all belong to Phase 6,
     * and this is the single line they have to be written into. */
    printf("[observable] fanout_forward_unimplemented: verb=%s target=%s "
           "peer=%s\n",
           (verb != NULL) ? verb : "?", target, peer_name);
    return 0;
}
