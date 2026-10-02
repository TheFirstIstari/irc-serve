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
 *
 * ---------------------------------------------------------------------------
 * AND WHERE THE `account` TAG IS STAMPED, WHICH IS THE SAME QUESTION
 * ---------------------------------------------------------------------------
 * 2.4's (origin, epoch, id) and IRCv3's `account` are both properties of ONE
 * EMISSION, and both are resolved at the single point above the switch in
 * fanout_deliver(): `ident` by fanout_stamp(), and the account by
 * fanout_emitter_account() beside it. Neither is asked again per destination --
 * only the DECISION to render it is per destination, in fanout_tag_block().
 *
 * WHY PER-FORWARD-TARGET RESOLUTION WOULD BE A BUG RATHER THAN A WASTE. The
 * tempting wrong shape is to resolve the sender at each destination, which asks
 * "whoever is at the other end" rather than "who sent this". On the local leg the
 * two happen to agree, so the node looks correct; then a relayed SPRIVMSG -- prefix
 * `:bob@irc.b`, no local connection by that name -- resolves to nothing and the tag
 * silently disappears for exactly the messages whose sender identity is in
 * question. The value has to come from the ONE place that knows who sent it, and
 * there is one such place: fanout_deliver(), above the switch, where `ident`
 * already lives.
 */
#include "core/fanout.h"

#include <stdio.h>
#include <string.h>

#include "core/account.h"
#include "core/cap.h"
#include "core/reply.h"
/* Phase 9: 2.1's remote-nick registry, which is what turns 3.1's `nick@server`
 * row from a shape this node recognises into a target it can resolve. See the
 * resolution comment at the branch below. */
#include "federation/nickreg.h"
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
     * a client may send one at any time.
     *
     * AND NOW IT IS RESOLVED rather than merely recognised, which is the
     * difference Phase 9's registry makes and the reason this branch reads a
     * module rather than parsing a string. Before the registry existed there was
     * nothing to ask "does that server hold that nick" and the row resolved to a
     * target with no destination; now the answer is a server this node has an
     * ESTABLISHED link to, or nothing at all.
     *
     * THE REFUSAL IS 401 AND IT IS RIGHT, and the reason it is a refusal rather
     * than a forward-anyway is the difference 3.1's note draws between "this node
     * cannot reach that server" and "that user does not exist": on a federated
     * node only one of those is ever true, and a node that forwards to a server
     * which has never heard of the nick is a node that cannot tell a client why
     * its message went nowhere. A client is owed the difference.
     *
     * THE TWO HALVES THAT CAN FAIL, and they fail differently:
     *   - the REGISTRY does not know the nick at all, or does not know that server
     *     holding it: 401, because nobody told this node about that user.
     *   - the registry knows, but there is no ESTABLISHED link: still 401, and
     *     deliberately not a different numeric. 4.4 has no numeric for "the user
     *     exists and the node cannot reach them", and 402 (ERR_NOSUMSERVER) is
     *     LUSERS's and ADMIN's `<server>` mask. Inventing one here would be a
     *     numeric every client has to be taught, and 401 is the answer a client
     *     already handles by telling the user.
     */
    if (strrchr(arg, '@') != NULL) {
        const char *at = strrchr(arg, '@');
        char nick[FANOUT_NAME_MAX + 1];
        char server[IRC_MAX_SERVER_NAME + 1];
        char holder[IRC_MAX_SERVER_NAME + 1];
        size_t nlen = (size_t)(at - arg);

        /* THE SPLIT IS AT THE LAST '@' and not the first, and that is 2.1's rule
         * rather than this function's: '@' is not a legal nick character (2.1's
         * own charset rule) but a server name is an opaque string and may itself
         * contain one. Splitting at the first would name a peer that does not
         * exist. */
        if (nlen == 0u || nlen > sizeof nick - 1u) {
            /* A name this node could not be given, or an empty nick: no holder
             * can answer for it, so 401 rather than a parse error the client has
             * no way to act on. */
            (void)reply(s, from, "401", (const char *const[]){ arg }, 1,
                        "No such nick/channel");
            return 0;
        }
        memcpy(nick, arg, nlen);
        nick[nlen] = '\0';
        if (strlen(at + 1) == 0u || strlen(at + 1) > (size_t)IRC_MAX_SERVER_NAME) {
            (void)reply(s, from, "401", (const char *const[]){ arg }, 1,
                        "No such nick/channel");
            return 0;
        }
        memcpy(server, at + 1, strlen(at + 1) + 1u);

        /* THE SCOPE NAMES THIS NODE, and that is a LOCAL user and not a
         * forwarding failure. 2.1's scoped identity is "the user called nick on
         * the server called server", and nothing in it says the server has to be
         * a different one -- a client writing `zed@irc.b` from irc.b is naming a
         * user of its own node through the qualified form, and the honest answer
         * is to deliver it. Refusing it would make the qualified form unusable for
         * exactly the server where the name is unambiguous, and a node that
         * answered 401 there would be telling a client that a user standing next to
         * it does not exist.
         *
         * IT IS A LOCAL LOOKUP AND NOT A REGISTRY ASK, because the registry holds
         * only REMOTE nicks by construction (a local name is server_t::nicks'
         * business, and 2.1's "bob@a and bob@b are distinct registry keys" is a
         * statement about names on DIFFERENT servers). Asking the registry here
         * would find nothing and 401 a user this node is holding.
         *
         * AND THE PARAMETERS ARE REBUILT, not reused: the local rows are addressed
         * by the bare nickname with the client's own parameters, and `name` is the
         * qualified string. Passing the qualified string to a local row would
         * render ":router!u@h PRIVMSG zed@irc.b :text" to a client, which is not
         * what any client parses as a target. */
        if (chan_same_name(server, s->name)) {
            conn_t *lu = server_nick_lookup(s, nick);

            if (lu == NULL) {
                (void)reply(s, from, "401", (const char *const[]){ arg }, 1,
                            "No such nick/channel");
                return 0;
            }
            memcpy(out->name, lu->nick, strlen(lu->nick) + 1u);
            out->user = lu;
            out->kind = FANOUT_LOCAL_USER;
            return 1;
        }

        /* THE REGISTRY IS ASKED ABOUT THE NICK, NOT ABOUT THE PAIR, and the
         * difference is the whole of a duplicate. A client naming
         * `bob@irc.c` where two servers hold bob is naming one of them
         * SPECIFICALLY, so the pair is what it gets: this asks for a holder equal
         * to the named server, and a name nobody holds is a 401 rather than a
         * silent redirect to whichever of two holders came first in the table. */
        if (fed_nickreg_holder(s, nick, holder, sizeof holder, NULL) == NULL) {
            (void)reply(s, from, "401", (const char *const[]){ arg }, 1,
                        "No such nick/channel");
            return 0;
        }
        /* The named server is the CLIENT'S claim about where the user is, and
         * the registry is this node's claim. When they disagree the client is
         * wrong, and this node says so rather than forwarding to a server that
         * does not hold the nick -- which is the "silently redirecting" failure
         * the comment above names. It is 401 rather than a redirect because a
         * client that wanted the redirect should send the name it means. */
        if (!chan_same_name(holder, server)) {
            (void)reply(s, from, "401", (const char *const[]){ arg }, 1,
                        "No such nick/channel");
            return 0;
        }
        /* AND THE LAST THING BEFORE IT IS A ROUTE, so the refusal above names
         * the real reason rather than a derived one. There is deliberately no
         * attempt to reach the server: 3.4 forbids a name lookup in the event
         * loop, and the only addresses this node can dial are the ones its
         * operator configured (3.4's "pre-resolved peer addresses"). A server
         * nobody has a link to is a server this node cannot route to, and that
         * is the same answer for every reason it has no link. */
        if (server_find_peer(s, server) == NULL) {
            (void)reply(s, from, "401", (const char *const[]){ arg }, 1,
                        "No such nick/channel");
            return 0;
        }
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

/* The worst-case CLIENT-VISIBLE tag block for one destination, DERIVED from the
 * two tags this node can write and not picked:
 *
 *   IRC_MAX_MSGTAG   the `msgid` block, derived in message.h
 *        1           the ';' between two pairs
 * ACCOUNT_TAG_MAX   the `account` block, derived in account.h
 *        1           the NUL
 *
 * IT IS USED FOR TWO THINGS, and the second is why it is here rather than beside
 * its renderer: it sizes the per-destination buffer in write_to_members() and in
 * fanout_deliver()'s user row, AND it is the charge fanout_line_fits() adds to the
 * client-facing cap. A buffer sized by eye and a cap that forgot the tag are the
 * same defect in two places -- a line that cannot be rendered -- and the charge is
 * derived from this number so that raising a tag's bound moves both. */
#define FANOUT_TAG_BLOCK_MAX (IRC_MAX_MSGTAG + 1u + ACCOUNT_TAG_MAX + 1u)

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
 * The number subtracted is 3.2's IRC_MAX_RELAY_LINE, and it is subtracted from the
 * FULL line rather than from the message alone. Two reasons that is the
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
    /* THE CLIENT-FACING CAP CHARGES THE LARGEST CLIENT-VISIBLE TAG BLOCK, and
     * charging it is the only difference from fanout_line_fits_n(). The arithmetic
     * in that function is the shared envelope -- prefix, verb, target -- against
     * IRC_MAX_RELAY_LINE, which is IRC_MAX_LINE minus IRC_MAX_TAG_OVERHEAD: 3.2
     * reserves exactly that much for whatever tag block the outbound line carries,
     * and for a PEER line it is the 2.4 internal block, which is bounded by the
     * same reserve. A CLIENT line's block is a different one and it is NOT bounded
     * by that reserve: this node may write `msgid` AND `account`, and
     * FANOUT_TAG_BLOCK_MAX is larger than IRC_MAX_TAG_OVERHEAD.
     *
     * SO IT IS CHARGED HERE, in full, rather than left to the render. The
     * alternative -- discovering the overflow when message_format() refuses the
     * line -- is a refusal counted on n_reply_refused, which reply.c documents as
     * a bug report, and it would cost a user their message to save 250 bytes of
     * headroom. reply.c's comment already names this as the obligation: "whoever
     * adds such an emission must charge the tag against IRC_MAX_RELAY_LINE where
     * fanout_line_fits() is applied."
     *
     * The cost is a smaller maximum message: this charges 2 + FANOUT_TAG_BLOCK_MAX
     * (250 bytes today) against the 8013 of IRC_MAX_RELAY_LINE, so the longest
     * PRIVMSG this node relays is 250 bytes shorter than it was. That is a limit,
     * stated at the point it is applied, and the alternative is losing messages at
     * the cap. */
    return fanout_line_fits_n(prefix, verb, (target != NULL) ? strlen(target) : 0u,
                              strlen(text) + (2u + FANOUT_TAG_BLOCK_MAX));
}

/* ---------------------------------------------------------------------------
 * Delivery
 * ---------------------------------------------------------------------------
 */

/* ---------------------------------------------------------------------------
 * THE EMISSION'S 2.4 IDENTITY, COMPUTED ONCE
 * ---------------------------------------------------------------------------
 * One call, one stamp, and that is the whole point of it being here rather than
 * inside fanout_forward_sverb().
 *
 * WHY IT HAD TO MOVE. The forward leg is called ONCE PER TARGET, so a mint in
 * there is a mint per peer: an emission forwarded to two peers reached them
 * under two different (origin, epoch, id) pairs. For the dedup store that was
 * survivable -- the store is per node, and the two copies of one message to two
 * peers are not copies of one message arriving twice -- but it is fatal for the
 * IRCv3 `msgid`, which is derived from this same triple and is read by CLIENTS.
 * Two members of one channel on two nodes would see two different msgids for one
 * message, which is precisely the "two deliveries look like two messages" failure
 * the capability exists to remove, and it would be this node's own minting that
 * caused it.
 *
 * So the identity is computed once per EMISSION here, before the local write and
 * before the target walk, and both consume the same stamp. This is also the
 * argument fanout.h makes about why `carry` is an argument and not a field on
 * fanout_target_t: an identity is a property of one emission, and an emission is
 * what fanout_deliver() is given.
 *
 * WHAT CHANGED FOR THE FORWARD LEG, and it is worth stating because the hop
 * arithmetic moved with the mint. Before, fanout_forward_sverb() decided between
 * "mint" and "carry and add a hop" and so was the only place that knew either
 * answer. Now the stamp that goes on the wire is computed HERE, which means a
 * caller that already has the stamp must be able to say "this one is already
 * what the wire gets" -- and that is a second entry point onto the same static
 * body, not a second body. fanout_forward_sverb() keeps its public contract
 * exactly (tests/integration/test_fed_dedup.c pins it on the wire, carry in and
 * hops+1 out), so the +1 it did for itself is done by fanout_stamp() instead.
 *
 * `relayed` travels out of here rather than being re-derived at each use, because
 * the two facts it separates are genuinely different and each is checked at one
 * place: a stamp this node minted has origin == s->name and hops == 0 and is
 * EXACTLY what goes on the wire, while a stamp a peer sent is one hop old before
 * this node forwards it and 2.4's own-origin rule applies to it and not to the
 * other. */
static void fanout_stamp(server_t *s, const irc_serve_tags_t *carry,
                         irc_serve_tags_t *out, int *relayed)
{
    if (carry == NULL) {
        /* ORIGINATING. This node minted the emission, so the identity is minted
         * with it: origin is this node's name -- which is what makes 2.4's
         * never-forward-own-origin rule decidable on the far side without any
         * extra state -- epoch is this node's per-boot value, and the id is the
         * next from the per-SERVER counter. hops is 0 because nothing has
         * forwarded it yet, and 2.4 counts forwards rather than hops travelled. */
        memset(out, 0, sizeof *out);
        memcpy(out->origin, s->name, strlen(s->name) + 1u);
        out->epoch = s->epoch;
        out->id = server_next_msg_id(s);
        out->hops = 0u;
        *relayed = 0;
        return;
    }
    /* RELAYING. origin/epoch/id carry through UNCHANGED and only hops moves. A
     * restamp here would give the copy a new identity, the far side's dedup
     * store would treat it as a message it has never seen, and the message would
     * come back -- that is the loop, and it is not bounded by the hop ceiling in
     * any useful sense because each pass would mint a fresh id. hops is the ONLY
     * field a forward may change, and this is the only place it changes.
     *
     * THE INCREMENT SATURATES, and that is not a detail. It is done in a wider
     * type on purpose: `carry->hops + 1u` in uint32_t wraps, and a stamp that
     * arrives carrying hops=UINT32_MAX would become hops=0 -- which is the one
     * value the hop ceiling refuses least, because it is the value that means
     * "nothing has forwarded this yet". A hostile or broken peer sending that
     * stamp would therefore get its message forwarded unboundedly, which is
     * exactly what 2.4's ceiling exists to prevent, and it would get there
     * through arithmetic rather than through a policy decision.
     * tests/integration/test_fed_dedup.c sends that stamp and requires it to be
     * refused; saturating at UINT32_MAX -- the largest value 2.4's value grammar
     * admits for hops -- keeps it refused for the right reason rather than by
     * accident. */
    *out = *carry;
    {
        const uint64_t hops = (uint64_t)carry->hops + 1u;

        out->hops = (hops > (uint64_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)hops;
    }
    *relayed = 1;
}

/* THE SENDER'S ACCOUNT, RESOLVED ONCE FOR THE EMISSION, or "" when this
 * emission has none to assert: a relay (see the decision below), a SERVER prefix
 * with no local connection behind it, or a local sender that is simply not logged
 * in.
 *
 * WHY THE PREFIX IS THE SUBJECT. Every emission this node ORIGINATES carries the
 * acting client's `nick!user@host` -- RFC 2812 3.3.1 requires it on the JOIN,
 * PART, TOPIC, KICK and MODE echoes and PRIVMSG/NOTICE carry it by the same rule,
 * and conn_hostmask() is the one renderer -- so the prefix IS the identity the
 * emission is about, and it is already an argument to this function. A `conn_t *`
 * parameter would have to be threaded through fanout_deliver(), write_to_members()
 * and every call site of the forward for one value this node can read from what
 * it was handed, and each of those additions is a chance for a caller to pass a
 * different connection than the one the prefix names.
 *
 * IT IS A CONNECTION-LOCAL LOOKUP AND NOT A REGISTRY ASK, for the same reason
 * fanout_resolve()'s local branch is: server_nick_lookup() holds exactly this
 * node's own clients, so a prefix naming a REMOTE user finds nothing and there is
 * nothing to say. That is the correct answer rather than a gap, and it is the
 * federation decision below arriving structurally instead of as a check.
 *
 * ---------------------------------------------------------------------------
 * `+account` DOES NOT CROSS TO PEERS. A deliberate decision, stated here because
 * the alternative is defensible and a reader deserves to know which was chosen.
 * ---------------------------------------------------------------------------
 * An account registry is PER NODE and PER OPERATOR: design 2.5.1 says so, and two
 * nodes whose operators each wrote their own --account-store will disagree about
 * who somebody is, with nothing to arbitrate. Forwarding one node's account claim
 * would hand the far side's clients an identity that no registry they can consult
 * holds, and the client has no way to check it -- the `account` tag is precisely
 * the assertion a client trusts. This node asserts only what IT verified.
 *
 * The cost is real and it is worth naming: a member of a shared channel on a peer
 * sees no `account` tag on the peer's messages, so per-message identity stops at
 * the node that authenticated the sender. `extended-join` (Phase 10.3) carries the
 * account as MEMBERSHIP state, which is the claim federation does have a channel
 * for, and closing the per-message gap needs an account authority both nodes trust
 * -- a services registry, not a tag.
 *
 * IT IS ENFORCED BY `relayed` RATHER THAN BY A STRING TEST, so the decision is one
 * branch rather than a property of which characters the prefix happens to hold: a
 * RELAYED emission is never stamped with an account, whatever its prefix says. */
static const char *fanout_emitter_account(server_t *s, const char *prefix,
                                          int relayed)
{
    char nick[IRC_MAX_NICK + 1];
    const char *bang;
    const conn_t *local;
    size_t nlen;

    if (relayed != 0 || s == NULL || prefix == NULL) {
        return "";
    }
    /* The nick is the part before '!', and a prefix with no '!' is the name itself
     * -- which is a SERVER prefix (a relayed state verb, or one forwarded with no
     * actor) and is looked up anyway and finds nothing. The lookup is one walk of
     * the nick table per EMISSION, not per destination, which is noise beside the
     * render it feeds. */
    bang = strchr(prefix, '!');
    nlen = (bang != NULL) ? (size_t)(bang - prefix) : strlen(prefix);
    if (nlen == 0u || nlen > (size_t)IRC_MAX_NICK) {
        return "";
    }
    memcpy(nick, prefix, nlen);
    nick[nlen] = '\0';
    local = server_nick_lookup(s, nick);
    if (local == NULL) {
        return "";
    }
    /* account_name() rather than the field, so the empty-means-anonymous
     * distinction is read through the predicate that owns it: an unidentified
     * client yields "" and an unidentified client gets no tag. */
    return account_name(local);
}

/* The tag block for ONE DESTINATION, or NULL when that destination gets none.
 *
 * PER DESTINATION, twice over and for the same reason both times: the capability
 * is per connection, so two members of one channel can disagree about whether
 * they want to be told who sent a message. The block is therefore written per
 * member INSIDE the member walk rather than once for the emission -- and that is a
 * statement about WHEN the bytes are rendered, not about where the ACCOUNT NAME
 * comes from. The name was resolved once, by fanout_emitter_account(), and every
 * destination below is handed that same value. That is the whole distinction and
 * it is the one a per-target lookup gets wrong.
 *
 * ORDER IS msgid THEN account, and it is fixed rather than incidental: the block
 * is a byte string, and a test that asserts one tag must not be sensitive to
 * which order the node happened to choose.
 *
 * The failure branch is a BUG REPORT and not a fallback. irc_serve_msgid_value()
 * returns 0 only for a stamp 2.4's grammar would refuse or a buffer one byte too
 * small, and both are impossible here (the stamp was just computed by
 * fanout_stamp() from s->epoch and the counter, so it is legal; the buffer is sized
 * from FANOUT_TAG_BLOCK_MAX above). Emitting the line with neither tag would be
 * the quiet half of a claim this file makes -- "a client that asked for msgids
 * gets them" -- so the refusal is reported loudly on the node's own output and the
 * block is left empty, which is what send_line_tagged() reads as "no block". The
 * MESSAGE still goes out: a decoration this node failed to render must never cost
 * a user their message, and the diagnostic is what turns an unreachable branch
 * into something a reader would notice rather than something to rediscover. */
static const char *fanout_tag_block(const conn_t *dst,
                                    const irc_serve_tags_t *ident,
                                    const char *account, char *out, size_t cap)
{
    char msgid[IRC_MAX_MSGTAG + 1u];
    char acct[ACCOUNT_TAG_MAX];
    size_t n = 0;

    if (out == NULL || cap == 0u) {
        return NULL;
    }
    out[0] = '\0';

    if (cap_message_ids_enabled(dst) != 0) {
        if (irc_serve_msgid_value(ident, msgid, sizeof msgid) == 0u) {
            printf("[observable] msgid_refused: fd=%d origin=%s id=%llu\n",
                   (dst != NULL) ? dst->fd : -1, ident->origin,
                   (unsigned long long)ident->id);
            out[0] = '\0';
            return NULL;
        }
        /* snprintf rather than a hand-rolled append, and its return is CHECKED
         * rather than cast: the length it reports is what says the block fits, and
         * an unchecked accumulation is the three-bugs-in-one-expression cap.h
         * documents for CAP_LS_MAX. */
        {
            const int w = snprintf(out, cap, "%s=%s", IRCV3_TAG_MSGTAG, msgid);

            if (w < 0 || (size_t)w >= cap) {
                out[0] = '\0';
                return NULL;
            }
            n = (size_t)w;
        }
    }

    /* NO ACCOUNT, NO TAG -- and the first test is on the VALUE, not on the sender's
     * logged-in flag. account_name() already returns "" for a connection that is
     * not identified, and the specification says the tag MUST NOT be sent for such
     * a user, so an empty name is a tag that must not EXIST rather than a tag with
     * an empty value. The capability gate is per DESTINATION and comes second, so
     * a client that did not ask is never asked about this node's internals. */
    if (account != NULL && account[0] != '\0' &&
        cap_account_tag_enabled(dst) != 0) {
        if (account_tag_block(account, acct, sizeof acct) == 0u) {
            /* The same shape as the msgid refusal above: a bug report, and the
             * message still goes out. account_tag_block() cannot fail for a name
             * account_name() produced -- it is non-empty and shorter than
             * ACCOUNT_MAX_NAME, which is half ACCOUNT_TAG_MAX's value budget even
             * with every byte escaped -- so this arm is a bound that moved. */
            printf("[observable] account_tag_refused: fd=%d\n",
                   (dst != NULL) ? dst->fd : -1);
            out[0] = '\0';
            return NULL;
        }
        /* The ';' goes in front of the pair rather than behind the one already
         * written, so a separator is only ever emitted when there is something on
         * BOTH sides of it -- which is the whole of why this is a branch and not a
         * constant prefix. */
        {
            const int w = snprintf(out + n, cap - n, "%s%s", (n > 0u) ? ";" : "", acct);

            if (w < 0 || (size_t)w >= cap - n) {
                out[0] = '\0';
                return NULL;
            }
            n += (size_t)w;
        }
    }
    return (out[0] != '\0') ? out : NULL;
}

/* WHICH OF TWO PARAMETER LISTS DOES THIS DESTINATION GET?
 *
 * One function, called from the member walk and from the single-user row, because
 * the two arms of the switch are two destinations in all but name and a capability
 * question answered twice is a capability question that can be answered two ways.
 *
 * A NULL or empty `extended` means there is only one shape, which is every
 * emission in this file except the extended JOIN. */
static void fanout_form_for(const conn_t *dst, const fanout_form_t *extended,
                            const char *const **params, int *nparams)
{
    if (extended == NULL || extended->params == NULL ||
        cap_extended_join_enabled(dst) == 0) {
        return;
    }
    *params = extended->params;
    *nparams = extended->nparams;
}

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
                            conn_t *exclude, const irc_serve_tags_t *ident,
                            const char *account, const fanout_form_t *extended)
{
    /* THE SHAPE IS DECIDED PER MEMBER AND EVERYTHING ELSE IS NOT, which is the
     * whole of what `extended` adds to this function. The parameter list, the
     * verb, the prefix, the 2.4 stamp and the account name are one emission's
     * facts and are the same for every member; only the recipient's negotiation
     * decides which of two lists of parameters it will be handed. */

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
    for (size_t i = 0; i < t->chan->nmembers; i++) {
        conn_t *m = t->chan->members[i].c;
        char tags[FANOUT_TAG_BLOCK_MAX + 1u];
        const char *const *use = params;
        int nuse = nparams;

        if (!chan_member_live(&t->chan->members[i])) {
            continue;
        }
        if (exclude != NULL && m == exclude) {
            continue;
        }
        /* PER MEMBER, and the buffer is per member too rather than hoisted: the
         * tag is rendered inside the walk because the capability is per
         * connection, and two members of one channel are free to disagree about
         * it. Hoisting the render would be wrong for a second reason too -- the
         * block is a pointer into this frame, so one buffer re-used across the
         * walk is a buffer whose contents change while the previous member's
         * line is already queued (which is harmless) but whose NUL is assumed by
         * send_line_tagged() (which is not, and would be the bug).
         *
         * `account` IS NOT PER MEMBER, and that is the point of the whole
         * function: it is the SAME resolved name for every destination here and
         * for the forward below. What varies per member is whether it is rendered
         * at all. */
        /* THE SHAPE, RESOLVED. fanout_form_for() is the ONE place that asks a
         * destination which of two parameter lists it gets, and it is a function
         * rather than an inline test so that the user row below cannot answer the
         * question differently from this one. */
        fanout_form_for(m, extended, &use, &nuse);
        /* AND THE EXTENDED LIST IS ARITY-CHECKED PER MEMBER, because the guard
         * above ran on the PLAIN one and an extended list can be longer. Unreachable
         * today -- the only extended caller adds two parameters to a verb that had
         * none -- and reported rather than assumed, for the reason write_to_members()
         * reports its other refusals: a caller that outgrew the array is a bug and
         * this node does not silently drop a member's copy of a line to hide one. */
        if (nuse >= IRC_MAX_PARAMS) {
            printf("[observable] fanout_unhandled_form: verb=%s target=%s "
                   "nparams=%d\n", verb, t->name, nuse);
            continue;
        }
        /* AND `all` IS BUILT PER MEMBER, INSIDE the walk, which it did not have to
         * be before this pass. It is the target plus whichever of the two shapes
         * this member gets, so hoisting it would have baked in whichever shape the
         * function was called with and quietly given every member the same one --
         * which is the bug fanout_form_for()'s comment says this shape decision
         * exists to prevent, reached by the other road. */
        all[0] = t->name;
        for (int k = 0; k < nuse; k++) {
            all[k + 1] = use[k];
        }
        (void)send_line_tagged(s, m, prefix, verb, all, nuse + 1,
                               fanout_tag_block(m, ident, account, tags,
                                                sizeof tags));
        n++;
    }
    return n;
}

int fanout_deliver_local(server_t *s, const fanout_target_t *t, const char *prefix,
                         const char *verb, const char *const *params, int nparams,
                         conn_t *exclude)
{
    const fanout_form_t plain = { params, nparams };

    /* ONE SHAPE, expressed as the two-shape call, for the reason fanout_deliver()
     * gives. */
    return fanout_deliver_local_forms(s, t, prefix, verb, &plain, NULL, exclude);
}

int fanout_deliver_local_forms(server_t *s, const fanout_target_t *t,
                              const char *prefix, const char *verb,
                              const fanout_form_t *plain,
                              const fanout_form_t *extended, conn_t *exclude)
{
    const char *const *params = (plain != NULL) ? plain->params : NULL;
    int nparams = (plain != NULL) ? plain->nparams : 0;
    irc_serve_tags_t ident;
    int relayed = 0;
    const char *account;

    if (s == NULL || t == NULL || verb == NULL || (params == NULL && nparams != 0) ||
        nparams < 0) {
        return 0;
    }
    /* THE STAMP IS MINTED AND THEN NOT USED, and that is deliberate: a local-only
     * emission still needs an identity because a member's client may be tracking
     * 2.4's msgid, and the one this function computes is the one the SAME
     * emission would have carried. It is discarded rather than not computed
     * because write_to_members() takes it as a parameter, and a NULL there would
     * be a second thing to decide about. */
    fanout_stamp(s, NULL, &ident, &relayed);
    /* AND THE ACCOUNT, resolved once for the same reason. IT RESOLVES TO NOTHING
     * for this function's only caller, and that is right independently of the
     * lookup: a rename echo is sent by the NODE, not by a user, and the
     * specification's rule is about commands sent BY A USER. (The lookup agrees --
     * nickreg.c passes the connection's OLD nickname as the prefix, because the
     * field has already been overwritten by then, and that name is no longer in
     * the registry.) Passing it through rather than hard-coding "" keeps the
     * answer a property of the emission rather than a thing this wrapper asserts. */
    account = fanout_emitter_account(s, prefix, relayed);

    switch ((int)t->kind) {
    case FANOUT_LOCAL_USER:
        /* The one-connection row, and it is the same code as fanout_deliver()'s
         * rather than a second rendering of it -- including the sender-excluded
         * case, which is why this is a function over the target rather than a
         * "loop over members". */
        if (t->user == NULL || nparams >= IRC_MAX_PARAMS) {
            return 0;
        }
        if (exclude != NULL && t->user == exclude) {
            return 0;
        }
        {
            const char *all[IRC_MAX_PARAMS + 1];

            all[0] = t->name;
            for (int i = 0; i < nparams; i++) {
                all[i + 1] = params[i];
            }
            (void)send_line(s, t->user, prefix, verb, all, nparams + 1);
        }
        return 1;

    case FANOUT_LOCAL_CHANNEL:
    case FANOUT_REMOTE_CHANNEL:
        /* A REMOTE channel is here as well as a local one because the two share
         * the roster and the caller may not know which it has: 3.1's state-change
         * row for a non-owned channel is "forward only", and a caller that wanted
         * no forward has already decided it does not want one, so asking it which
         * kind of channel it resolved would be asking a question with no answer
         * that changes anything. */
        return write_to_members(s, t, prefix, verb, params, nparams, exclude, &ident,
                                account, extended);

    case FANOUT_REMOTE_USER:
    case FANOUT_NONE:
    default:
        /* NO LOCAL DESTINATION EXISTS, and a caller that reached here with one of
         * these has a bug: there is no connection on this node to write to, and
         * inventing one would be a delivery to nobody counted as a delivery to
         * somebody. Counting nothing is the honest outcome, exactly as
         * fanout_deliver()'s FANOUT_NONE arm states. */
        return 0;
    }
}

int fanout_deliver(server_t *s, const fanout_target_t *t, const char *prefix,
                   const char *verb, const char *const *params, int nparams,
                   conn_t *exclude, const irc_serve_tags_t *carry)
{
    const fanout_form_t plain = { params, nparams };

    /* THE WHOLE OF THIS FUNCTION IS ONE LINE, and it is here so that the single
     * shape case is expressed in terms of the two-shape one rather than the other
     * way round: a NULL `extended` IS "one shape for everybody", and a caller that
     * reached fanout_deliver() gets exactly the behaviour it had before the
     * extension existed. */
    return fanout_deliver_forms(s, t, prefix, verb, &plain, NULL, exclude, carry);
}

int fanout_deliver_forms(server_t *s, const fanout_target_t *t, const char *prefix,
                         const char *verb, const fanout_form_t *plain,
                         const fanout_form_t *extended, conn_t *exclude,
                         const irc_serve_tags_t *carry)
{
    const char *const *params;
    int nparams;
    const char *account;
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
    /* THE EMISSION'S IDENTITY, computed once for every row. It has to be above
     * the switch rather than inside the arms that need it, because the two
     * things it feeds -- the local write and the forward -- live in DIFFERENT
     * arms, and a stamp minted per arm would be a different identity for the
     * copy the members on this node see and the copy the peers see. That is the
     * same "one emission, one identity" argument fanout.h makes about `carry`
     * being an argument and not a field, and it is why the number is spent here
     * and nowhere else. */
    irc_serve_tags_t ident;
    int relayed;

    if (s == NULL || t == NULL || verb == NULL || plain == NULL) {
        return 0;
    }
    params = plain->params;
    nparams = plain->nparams;
    if ((params == NULL && nparams != 0) || nparams < 0) {
        return 0;
    }
    kind = (int)t->kind;
    fanout_stamp(s, carry, &ident, &relayed);
    /* AND THE `account` NAME, AT THE SAME POINT AND FOR THE SAME REASON: it is the
     * other property of THIS emission that both the local write and the forward
     * consume, and both must be handed the same value. `relayed` decides it, so a
     * relay stamps nothing and the decision is one branch rather than a property
     * of the prefix's bytes. See fanout_emitter_account(). */
    account = fanout_emitter_account(s, prefix, relayed);

    switch (kind) {
    case FANOUT_LOCAL_USER: {
        const char *all[IRC_MAX_PARAMS + 1];
        char tags[FANOUT_TAG_BLOCK_MAX + 1u];
        int n = 0;

        /* The same `>=` and the same reason as write_to_members() above: the
         * array is one longer than the cap because the target takes one slot, so
         * 15 tail parameters would be 16 and would be refused by the builder.
         * See the comment there for why the claim and the code used to disagree
         * without anything noticing. */
        if (t->user == NULL || nparams >= IRC_MAX_PARAMS) {
            return 0;
        }
        /* THE SHAPE IS RESOLVED BEFORE `all` IS BUILT, and for the same reason it
         * is resolved per member in write_to_members(): this row is a destination
         * like any other, and a capability question answered in one arm of this
         * switch and not the other is a JOIN that changes shape depending on
         * whether the caller resolved a channel or a nickname. No current caller
         * passes `extended` for a user target -- a JOIN never has one -- and
         * resolving it here anyway costs one AND rather than leaving the question
         * open for the next caller. The arity check is repeated afterwards because
         * the extended list can be longer than the plain one and `all` is one slot
         * longer than the cap. */
        fanout_form_for(t->user, extended, &params, &nparams);
        if (nparams >= IRC_MAX_PARAMS) {
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
        /* The tag gate, asked about THIS destination, which is the one connection
         * this row writes to. A PRIVMSG to a user rather than to a channel is still
         * one emission with one 2.4 identity, and the stamp the identity came from
         * is the same one a channel row would have forwarded, so the value a user
         * sees and the value a peer would see for the same message are the same
         * string -- and the account name, resolved once above, is the same string
         * too. */
        (void)send_line_tagged(s, t->user, prefix, verb, all, nparams + 1,
                               fanout_tag_block(t->user, &ident, account, tags,
                                                sizeof tags));
        n = 1;
        return n;
    }

    case FANOUT_LOCAL_CHANNEL: {
        int n = write_to_members(s, t, prefix, verb, params, nparams, exclude,
                                 &ident, account, extended);

        /* 3.1's two owned rows, AND THEY NOW SHARE ONE FORWARD ARM.
         *
         * AND THE FORWARD GETS `params`, NEVER `extended`. That is not an
         * oversight and it is the whole of fanout.h's argument for this entry
         * point: the peer-facing shape of a JOIN is 4.3's SJOIN, built by
         * federation/verbs.c from the channel's membership, and it is one frozen
         * shape for every peer. Which of a node's CLIENTS negotiated
         * `extended-join` must not change what that node says to a peer.
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
        /* AND IT IS HANDED THE EMISSION'S STAMP rather than `carry`, which is the
         * whole of the change this pass makes to the forward leg: the identity a
         * local member has just seen rendered as a `msgid` and the identity that
         * goes on the wire are the same three numbers, because they are the same
         * stamp. A `carry` of NULL here would mint a SECOND id for one emission,
         * and the two clients -- one on this node, one on the peer -- would then be
         * told two different things about one message. */
        (void)fanout_forward_channel(s, t->chan, t->vclass, verb, prefix, params,
                                     nparams, &ident, relayed);
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
                                         nparams, &ident, relayed);
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
            int n = write_to_members(s, t, prefix, verb, params, nparams, exclude,
                                     &ident, account, extended);

            (void)fanout_forward_channel(s, t->chan, t->vclass, verb, prefix, params,
                                         nparams, &ident, relayed);
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
/* ONE PEER, with the stamp ALREADY DECIDED. The target-set walk above and
 * fanout_forward_sverb() both reach this, and it is the only place the two
 * 2.4 forward-time guards and the render-and-queue live.
 *
 * `relayed` is the one fact that cannot be re-derived from `stamp` and it is a
 * parameter rather than a comparison because the comparison would be wrong. A
 * stamp this node MINTED has origin == s->name, and so does a stamp a peer sent
 * naming this node -- which federation/verbs.c's inbound guard already refuses
 * with `fed_own_origin_drop` before it could reach a forward. The two are told
 * apart by where the value came from, not by what it says, and guessing from the
 * bytes would either refuse every forward this node originates or forward back
 * the message that came home, which is the loop 2.4 exists to stop.
 *
 * NOT STATIC-BY-NECESSITY: it is static because the guards belong with the queue
 * call they report, and the two callers that reach it are the two halves of one
 * operation (a target-set walk, and a single named peer). A third caller would
 * be the moment to ask whether the walk wants the stamp too. */
static int forward_one_peer(server_t *s, const char *peer_name, const char *sverb,
                            const char *src, const char *const *params, int nparams,
                            const irc_serve_tags_t *stamp, int relayed)
{
    const char *target = (params != NULL && nparams > 0) ? params[0] : "-";
    conn_t *peer;
    fed_queue_why_t why = FED_QUEUE_OK;

    /* The link is resolved here rather than by the caller, because the refusals
     * below name the peer and because a caller that had to resolve it would have
     * two places deciding what a route is. server_find_peer() is the ESTABLISHED
     * predicate: a link that has not finished the handshake FSM is not a route,
     * and 2.3 requires the server-name uniqueness check to happen before
     * ESTABLISHED for the reason this would otherwise be a duplicate-name bug on
     * the wire. */
    peer = server_find_peer(s, peer_name);
    if (peer == NULL) {
        printf("[observable] fanout_forward_dropped: verb=%s target=%s peer=%s "
               "reason=NO_ROUTE\n",
               sverb, target, peer_name);
        return 0;
    }

    /* ---- 2.4's two forward-time guards, and they are RELAY guards ---- */
    if (relayed != 0) {
        if ((uint64_t)stamp->hops >= (uint64_t)IRC_MAX_HOPS) {
            /* 2.4: "irc-serve-hops increments per forward and the message is
             * dropped at 10." `stamp->hops` is already the value that WOULD go
             * on the wire -- fanout_stamp() did the increment -- so the test is
             * on it directly and not on hops + 1. It is unchanged in effect: the
             * largest value that may be FORWARDED is IRC_MAX_HOPS - 1. */
            printf("[observable] fanout_forward_dropped: verb=%s target=%s "
                   "peer=%s reason=hop_limit hops=%lu ceiling=%d\n",
                   sverb, target, peer_name, (unsigned long)stamp->hops,
                   IRC_MAX_HOPS);
            return 0;
        }
        if (same_origin(stamp->origin, s->name)) {
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
                   sverb, target, peer_name, stamp->origin, s->name);
            return 0;
        }
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
    if (fed_queue_line(s, peer, stamp, src, sverb, params, nparams, &why) != 0) {
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

/* THE TARGET SET WALK, and the only copy of it. Static because both exported
 * entry points below reach it, and because a target set that two functions could
 * each implement is a target set with two answers. */
static int forward_channel_targets(server_t *s, const chan_t *ch,
                                   fanout_class_t vclass, const char *sverb,
                                   const char *prefix, const char *const *params,
                                   int nparams, const irc_serve_tags_t *stamp,
                                   int relayed)
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
        return forward_one_peer(s, ch->origin, sverb, prefix, params, nparams, stamp,
                                relayed);
    }
    /* servers[] first, because those are the peers this node KNOWS hold
     * members, and a name in that set with no ESTABLISHED link is a finding
     * worth reporting rather than a peer to skip quietly. */
    for (size_t i = 0; i < ch->nservers; i++) {
        queued += forward_one_peer(s, ch->servers[i].name, sverb, prefix, params,
                                   nparams, stamp, relayed);
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
            queued += forward_one_peer(s, lk->name, sverb, prefix, params, nparams,
                                       stamp, relayed);
        }
    }
    return queued;
}

int fanout_forward_channel(server_t *s, const chan_t *ch, fanout_class_t vclass,
                           const char *client_verb, const char *prefix,
                           const char *const *params, int nparams,
                           const irc_serve_tags_t *stamp, int relayed)
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
    return forward_channel_targets(s, ch, vclass, sverb, prefix, sp, shaped, stamp,
                                   relayed);
}

int fanout_forward_channel_sverb(server_t *s, const chan_t *ch,
                                 fanout_class_t vclass, const char *sverb,
                                 const char *prefix, const char *const *params,
                                 int nparams, const irc_serve_tags_t *carry)
{
    /* The relay half: the line is ALREADY an S-verb in 4.3's frozen shape, so
     * there is nothing to re-shape and only the target set to decide. Same walk,
     * same rules, same refusals -- which is the whole reason it is a second
     * entry point onto one static function rather than a second function.
     *
     * AND IT COMPUTES THE STAMP ITSELF, rather than being handed one the way
     * fanout_forward_channel() above is. This one is called by
     * federation/verbs.c with the stamp a PEER sent, and its one obligation is
     * the same one fanout_forward_sverb() has: add this node's hop and change
     * nothing else. The stamp is computed once here rather than per target
     * because for a relay the arithmetic is idempotent -- every target of a walk
     * would compute the same three numbers -- and computing it once means the
     * value a local member sees and the value every peer sees are the same
     * triple even on a mesh where they are the same emission by two routes. */
    irc_serve_tags_t ident;
    int relayed;

    if (s == NULL) {
        return 0;
    }
    fanout_stamp(s, carry, &ident, &relayed);
    return forward_channel_targets(s, ch, vclass, sverb, prefix, params, nparams,
                                   &ident, relayed);
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
    conn_t *peer;
    irc_serve_tags_t tags;
    int relayed;
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
     * duplicate-name bug on the wire.
     *
     * AND IT IS LOOKED UP TWICE, once here and once in forward_one_peer(). That is
     * deliberate rather than an oversight left for a reader to puzzle over: THIS
     * one is the pre-mint refusal, so a forward to a server with no route spends
     * no id -- and tests/integration/test_fed_dedup.c pins exactly that, by
     * refusing an originating forward down a link that is not ESTABLISHED and then
     * requiring the counter to be exactly one id further on. The second lookup is
     * needed because the target-set walk reaches forward_one_peer() with a NAME and
     * no resolved peer. The cost is one linear scan of the link table per forwarded
     * target, which is negligible beside the line render it precedes, and the
     * alternative -- resolving every target in the walk before spending anything --
     * would be a second copy of the target set to keep in step with the first. */
    peer = server_find_peer(s, peer_name);
    if (peer == NULL) {
        printf("[observable] fanout_forward_dropped: verb=%s target=%s peer=%s "
               "reason=NO_ROUTE\n",
               sverb, target, peer_name);
        return 0;
    }

    /* ---- 2.4: the stamp, and the loop guard, at forward time ----
     *
     * THE STAMP IS COMPUTED HERE AND NOT DELEGATED to fanout_stamp()'s callers,
     * because of WHERE it sits: below the size check and below the peer lookup,
     * both of which can refuse, and an id spent on a line that is then refused is
     * a hole in the per-SERVER sequence. That reasoning is the paragraph above and
     * it is why this function's public contract is unchanged even though the walk
     * above it now hands a pre-computed stamp to forward_one_peer(): a caller with
     * one target and no client-facing local write still gets the per-target mint
     * this has always done, and only fanout_deliver() -- which has an identity to
     * share with its own local members -- takes the other route. */
    fanout_stamp(s, carry, &tags, &relayed);
    return forward_one_peer(s, peer_name, sverb, src, params, nparams, &tags, relayed);
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
