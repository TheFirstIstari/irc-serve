/* verbs.c -- see verbs.h. Both sides of 4.3's S-verbs: the encoder that builds
 * them and the guard chain that decides whether an inbound one may act. */
#include "federation/verbs.h"

#include <stdio.h>
#include <string.h>

#include "core/channel.h"
#include "core/fanout.h"
#include "federation/burst.h"
#include "federation/dedup.h"
#include "federation/link.h"

/* The map, once, in the order 4.3 lists the client verbs rather than in the
 * order of the S-verbs, so that a reader comparing this against the design does
 * it by eye and in the same sequence. A `switch` would be the other way to do
 * it and would be worse for a table this small: it duplicates the name of every
 * verb in the source, so a typo in one arm compiles cleanly and returns the
 * wrong thing at run time, and it makes "is this verb forwarded at all" a
 * question about a switch's coverage rather than about one array. */
static const struct {
    const char *client;
    const char *sverb;
} S_VERBS[] = {
    { "PRIVMSG", "SPRIVMSG" },
    { "NOTICE",  "SNOTICE"  },
    { "JOIN",    "SJOIN"    },
    { "PART",    "SPART"    },
    { "TOPIC",   "STOPIC"   },
    /* SMODES, not 4.3's SSMODE and not the obvious SMODE. See verbs.h. */
    { "MODE",    "SMODES"   },
    { "KICK",    "SKICK"    }
};

const char *fed_sverb_for(const char *client_verb)
{
    size_t i;

    if (client_verb == NULL) {
        return NULL;
    }
    for (i = 0; i < sizeof S_VERBS / sizeof S_VERBS[0]; i++) {
        if (strcmp(S_VERBS[i].client, client_verb) == 0) {
            return S_VERBS[i].sverb;
        }
    }
    return NULL;
}

const char *fed_queue_why_name(fed_queue_why_t why)
{
    /* Read into an int, and given a `default`, because of the pair upstream
     * clang's -Weverything puts in one switch: -Wswitch-default wants a
     * `default` on a switch over an enum and -Wcovered-switch-default reports
     * that `default` as redundant when every enumerator is listed, so a switch
     * written both ways satisfies neither. Reading the value into an int
     * satisfies both, and a reason added later lands in the `default` that says
     * it has no name yet rather than off the end of the function. fanout.c
     * documents the pair; fed_federate_reason() in federation/link.c is the
     * same shape. */
    int which = (int)why;

    switch (which) {
    case (int)FED_QUEUE_OK:
        return "OK";
    case (int)FED_QUEUE_BAD_TAGS:
        return "BAD_TAGS";
    case (int)FED_QUEUE_TAG_TOO_LONG:
        return "TAG_BLOCK_TOO_LONG";
    case (int)FED_QUEUE_UNBUILDABLE:
        return "UNBUILDABLE";
    case (int)FED_QUEUE_UNRENDERABLE:
        return "UNRENDERABLE";
    case (int)FED_QUEUE_SATURATED:
        return "LINK_SATURATED";
    default:
        /* Unreachable while fed_queue_why_t is closed and every member is
         * listed. A BUG REPORT if it is ever reached, so it says so rather than
         * returning a name that does not correspond to anything. */
        printf("[observable] fed_queue_unknown: why=%d\n", which);
        return "UNKNOWN";
    }
}

/* A refusal, and the only way out of fed_queue_line() other than the queue
 * succeeding. It exists so that every refusal in that function is one line and
 * so that the out-parameter is written in one place: a function with five
 * refusal paths and five `*why_out = ...; return -1;` pairs is a function where
 * one of the five can forget to set it, and a caller reading a stale reason is
 * worse than a caller reading no reason. */
static int fed_queue_refuse(fed_queue_why_t *why_out, fed_queue_why_t why)
{
    if (why_out != NULL) {
        *why_out = why;
    }
    return -1;
}

/* The stamp, the build, the render, the terminator and the queue, in that
 * order, once. The two callers of this used to be the whole of
 * fed_send_sverb()'s body and T3's keepalive in federation/link.c, and the
 * reasons below are the five ways that sequence can refuse.
 *
 * The buffers are two fixed locals rather than anything on server_t, and the
 * sizes are reply.c's arithmetic for the same reason it is there: IRC_MAX_LINE
 * counts a legal line INCLUDING its CRLF and message_format() reserves a byte
 * for its NUL, so a maximal line plus its terminator plus the NUL needs two
 * more than IRC_MAX_LINE. */
int fed_queue_line(server_t *s, conn_t *peer, const irc_serve_tags_t *tags,
                   const char *prefix, const char *verb,
                   const char *const *params, int nparams,
                   fed_queue_why_t *why_out)
{
    char block[IRC_MAX_TAG_OVERHEAD];
    char line[IRC_MAX_LINE + 2];
    message_t m;
    size_t blen;
    size_t len;

    /* A NULL where a peer, a stamp or a verb belongs is a caller that has
     * already lost track of the line, and there is no word for it distinct from
     * the render refusal -- so it is reported as the render refusal rather than
     * as a reason of its own that an operator would have to learn. Every
     * caller checks its own arguments first and never reaches this. */
    if (s == NULL || peer == NULL || tags == NULL || prefix == NULL ||
        verb == NULL) {
        return fed_queue_refuse(why_out, FED_QUEUE_UNRENDERABLE);
    }
    /* 2.4's tag grammar is enforced on receipt as well, so an invalid stamp
     * here is a caller that built one wrongly rather than a hostile peer. */
    if (!irc_serve_tags_valid(tags)) {
        return fed_queue_refuse(why_out, FED_QUEUE_BAD_TAGS);
    }
    /* IRC_MAX_TAG_OVERHEAD rather than a block-specific bound, and the two
     * numbers are related in a way worth stating: 179 is the '@' plus the one
     * separating space plus the block, so the block alone is at most 177 and
     * the buffer is 179. It is the right constant to name here precisely
     * because it is the constant 3.2 derived, and a second, block-only bound
     * would be a number nobody re-derives when a value limit moves.
     *
     * irc_serve_tags_format() returns 0 for a block that does not fit, which
     * cannot happen for a stamp it just validated -- so a 0 here means the
     * buffer is not big enough, which is a bug in this file. It is still
     * reported rather than assumed away, because the alternative is the same
     * tagless line the arm above refuses. */
    blen = irc_serve_tags_format(tags, block, sizeof block);
    if (blen == 0u) {
        return fed_queue_refuse(why_out, FED_QUEUE_TAG_TOO_LONG);
    }
    if (message_build(&m, block, prefix, verb, params, nparams) != 0) {
        return fed_queue_refuse(why_out, FED_QUEUE_UNBUILDABLE);
    }
    len = message_format(&m, line, sizeof line - 2u);
    message_free(&m);
    if (len == 0u) {
        /* All or nothing, never a partial line: 3.2 forbids truncating a
         * parameter, and a half-written line on a peer link is not a shorter
         * message but a corrupted protocol stream the peer will misparse. */
        return fed_queue_refuse(why_out, FED_QUEUE_UNRENDERABLE);
    }
    /* RFC 1459 2.3: CRLF. message_format() terminates nothing. */
    line[len] = '\r';
    line[len + 1u] = '\n';
    if (server_queue(s, peer, line, len + 2u) != 0) {
        /* Already counted and already marked CLOSING by server_queue(): a
         * saturated link is DROPPED, not buffered (3.4). Not counted twice
         * here, and nothing is closed here either. */
        return fed_queue_refuse(why_out, FED_QUEUE_SATURATED);
    }
    if (why_out != NULL) {
        *why_out = FED_QUEUE_OK;
    }
    return 0;
}

int fed_send_sverb(server_t *s, conn_t *peer, const irc_serve_tags_t *tags,
                   const char *client_verb, const char *prefix,
                   const char *const *params, int nparams)
{
    const char *sverb;
    fed_queue_why_t why = FED_QUEUE_OK;
    const char *target = (params != NULL && nparams > 0) ? params[0] : "-";

    /* The refusals are reported, not returned quietly, for the reason every
     * other [observable] refusal in this node is: a federated node that dropped
     * a forwarded message for want of a verb name would otherwise look exactly
     * like a node whose peers were silent, and the two have opposite fixes. */
    if (s == NULL || peer == NULL || client_verb == NULL || prefix == NULL ||
        (params == NULL && nparams != 0)) {
        printf("[observable] fed_sverb_refused: verb=%s reason=bad_args\n",
               (client_verb != NULL) ? client_verb : "?");
        return -1;
    }
    /* An ALREADY-MAPPED verb is not mapped again. A caller that hands this an
     * S-verb by mistake would otherwise put `SSPRIVMSG` on the wire, and the
     * refusal below is the same one a client verb with no S-verb gets -- which
     * is the right answer for both, because both are "this node has no S-verb
     * for that". The one caller that legitimately has an S-verb in hand
     * (fanout_forward_sverb(), relaying) calls fed_queue_line() directly. */
    sverb = fed_sverb_for(client_verb);
    if (sverb == NULL) {
        printf("[observable] fed_sverb_refused: verb=%s target=%s "
               "reason=NO_SVERB\n",
               client_verb, target);
        return -1;
    }

    /* The stamp and the wire are the shared half; the verb and the two refusal
     * words above and below are this function's own, because a keepalive is
     * not an S-verb and reports under a different [observable] line. See
     * fed_queue_line() in verbs.h. */
    if (fed_queue_line(s, peer, tags, prefix, sverb, params, nparams, &why) != 0) {
        printf("[observable] fed_sverb_refused: verb=%s target=%s "
               "reason=%s\n",
               client_verb, target, fed_queue_why_name(why));
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * The frozen shapes
 * ------------------------------------------------------------------------- */

/* The nick of a `nick!user@host` prefix, or `prefix` itself when it has no '!'.
 * Writes at most `cap` bytes. 2.1 defines the hostmask with exactly one '!' and
 * the nick before it, so this is a cut and not a parse: nothing a client can
 * send makes a second '!' part of the nick, because '!' is not a legal nick
 * character (2.1's own charset rule). */
static const char *fed_prefix_nick(const char *prefix, char *out, size_t cap)
{
    const char *bang = strchr(prefix, '!');
    size_t n = (bang != NULL) ? (size_t)(bang - prefix) : strlen(prefix);

    if (n >= cap) {
        return NULL;
    }
    memcpy(out, prefix, n);
    out[n] = '\0';
    return out;
}

/* The member's prefix flags as the single token 4.3's SJOIN carries, and the
 * `-` that means "none".
 *
 * THE EMPTY CASE IS A LITERAL, and the reason is the wire rather than taste: an
 * empty middle parameter is not representable here at all. 3.2 says a value that
 * needs the ':' marker is only representable in the FINAL position, and
 * message_parse() drops an uncolonned empty token, so a shape that said "omit
 * the flags when there are none" would arrive as a TWO-parameter SJOIN on one
 * node and the receiver would have to guess whether the third field was missing
 * or empty. `-` is one byte, never needs a colon, and cannot be confused with a
 * flag run. */
static const char *fed_flag_token(unsigned flags, char *out, size_t cap)
{
    size_t used = 0;

    if (cap < 2u) {
        return NULL;
    }
    if (flags == 0u) {
        out[0] = '-';
        out[1] = '\0';
        return out;
    }
    out[used++] = '+';
    if ((flags & CHAN_MEMBER_OP) != 0u && used + 1u < cap) {
        out[used++] = 'o';
    }
    if ((flags & CHAN_MEMBER_VOICE) != 0u && used + 1u < cap) {
        out[used++] = 'v';
    }
    out[used] = '\0';
    return out;
}

/* The member's flags, looked up on the channel the emission is about.
 *
 * READ OUT OF THE CHANNEL RATHER THAN PASSED IN, and the reason is authority:
 * the flags are a property of the MEMBERSHIP, and the node forwarding the join
 * is the node that just made it, so its own record is the authority for what it
 * granted. A parameter would have to be threaded through fanout_deliver() and
 * fanout_forward_link() for one value that one caller (handle_join) knows and
 * every other caller does not -- and a default of 0 on the other five would be a
 * way for an SJOIN to lose +o without anybody noticing. */
static unsigned fed_member_flags(const chan_t *ch, const char *nick)
{
    const struct member *local;

    if (ch == NULL || nick == NULL) {
        return 0u;
    }
    local = chan_find_nick(ch, nick);
    if (local != NULL) {
        return local->flags;
    }
    for (size_t i = 0; i < ch->nremotes; i++) {
        if (chan_same_name(ch->remotes[i].nick, nick)) {
            return ch->remotes[i].flags;
        }
    }
    return 0u;
}

int fed_sverb_params(const char *client_verb, const char *target,
                     const char *const *params, int nparams, const char *prefix,
                     const char *self, const chan_t *ch,
                     fed_sverb_scratch_t *scratch, const char **out, int cap)
{
    const char *member = NULL;
    int n = 0;

    if (client_verb == NULL || target == NULL || out == NULL || cap <= 0 ||
        scratch == NULL || (params == NULL && nparams != 0)) {
        return -1;
    }
    if (prefix != NULL) {
        member = fed_prefix_nick(prefix, scratch->nick, sizeof scratch->nick);
        if (member == NULL) {
            return -1;
        }
    }

    /* The table is the gate, and it is asked FIRST: a client verb with no S-verb
     * has no shape here either, and returning -1 is what makes the caller report
     * NO_SVERB rather than build a two-parameter line the peer would misread.
     * The per-verb arms below then cover all seven, and each refuses a client
     * shape it cannot honour rather than emitting a default. */
    if (fed_sverb_for(client_verb) == NULL) {
        return -1;
    }
    (void)self;

    out[n++] = target;
    if (cap < 2) {
        return -1;
    }

    if (strcmp(client_verb, "PRIVMSG") == 0 || strcmp(client_verb, "NOTICE") == 0) {
        /* <target> <text>: the client shape, unchanged. A peer that relayed this
         * has said nothing the client line did not. */
        if (nparams < 1 || params[0] == NULL) {
            return -1;
        }
        out[n++] = params[nparams - 1];
        return n;
    }
    if (member == NULL) {
        /* Every state verb names its subject, and without a prefix there is
         * none. A state change with no actor cannot be relayed, and emitting the
         * shape with an empty member would put a zero-length name on the wire. */
        return -1;
    }

    if (strcmp(client_verb, "JOIN") == 0) {
        /* <channel> <member> <flags>. */
        if (n != 1 || nparams != 0 || cap < 3) {
            return -1;
        }
        if (fed_flag_token(fed_member_flags(ch, member), scratch->flags,
                           sizeof scratch->flags) == NULL) {
            return -1;
        }
        out[n++] = member;
        out[n++] = scratch->flags;
        return n;
    }
    if (strcmp(client_verb, "PART") == 0) {
        /* <member> <channel> [<reason>]: the member comes FIRST, so the channel
         * is not in a fixed position and a reader cannot assume it. */
        if (nparams > 1 || (nparams == 1 && params[0] == NULL) || cap < 3) {
            return -1;
        }
        out[0] = member;
        out[1] = target;
        n = 2;
        if (nparams == 1) {
            out[n++] = params[0];
        }
        return n;
    }
    if (strcmp(client_verb, "TOPIC") == 0) {
        /* <member> <channel> <topic>. The topic is always present, so a cleared
         * topic is the literal `:` rather than an absent parameter. */
        if (nparams != 1 || params[0] == NULL || cap < 3) {
            return -1;
        }
        out[0] = member;
        out[1] = target;
        out[2] = params[0];
        return 3;
    }
    if (strcmp(client_verb, "MODE") == 0) {
        /* <server> <channel> <modes> [<arg>]. */
        if (nparams < 1 || nparams > 2 || cap < 4 || self == NULL) {
            return -1;
        }
        out[0] = self;
        out[1] = target;
        out[2] = params[0];
        n = 3;
        if (nparams == 2) {
            out[n++] = params[1];
        }
        return n;
    }
    if (strcmp(client_verb, "KICK") == 0) {
        /* <member> <channel> <target> [<reason>]. The member is the KICKER,
         * distinct from <target>: they are two users and a shape that carried
         * one would make every KICK look self-inflicted. */
        if (nparams < 1 || nparams > 2 || cap < 4 || params[0] == NULL) {
            return -1;
        }
        out[0] = member;
        out[1] = target;
        out[2] = params[0];
        n = 3;
        if (nparams == 2) {
            out[n++] = params[1];
        }
        return n;
    }
    return -1;
}

const char *fed_prefix_server(const char *prefix, char *out, size_t cap)
{
    const char *at;
    size_t n;

    if (prefix == NULL || prefix[0] == '\0' || out == NULL || cap == 0u) {
        return NULL;
    }
    /* 2.1 splits at the LAST '@', and the split is unambiguous because '@' is
     * not a legal nick character. A server name, by contrast, is an opaque
     * string under the 2.4 tag grammar -- which does admit no '@' either, but
     * the SPLIT still has to be the one 2.1 specifies or a name containing one
     * would be cut in the wrong place. A prefix with no '@' is a SERVER prefix
     * and is the name itself. */
    at = strrchr(prefix, '@');
    if (at == NULL) {
        n = strlen(prefix);
    } else {
        n = strlen(at + 1);
        if (n == 0u) {
            return NULL;
        }
        at++;
        if (n >= cap) {
            return NULL;
        }
        memcpy(out, at, n);
        out[n] = '\0';
        return out;
    }
    if (n >= cap) {
        return NULL;
    }
    memcpy(out, prefix, n);
    out[n] = '\0';
    return out;
}

/* ---------------------------------------------------------------------------
 * The DECODE side: the handlers G10 reaches
 * ---------------------------------------------------------------------------
 *
 * Every one of them does the same two things and nothing else: apply the fact to
 * this node's local state, and pass the line on. Neither is optional -- an
 * inbound state change that is applied but not relayed stops the mesh
 * converging, and one that is relayed but not applied leaves this node's cache
 * permanently behind the origin's.
 *
 * WHY THERE IS NO LOCAL CLIENT EMISSION, and it is a gap rather than a decision.
 * An inbound SJOIN names a member but carries only a SERVER prefix, because the
 * member's hostmask is not on the wire and 4.3's burst vocabulary is where it
 * belongs. A client cannot be shown ":bob!user@host JOIN #T" from a prefix that
 * says only "irc.b", and a JOIN with a server prefix is a line no client
 * understands. So a local member learns about a remote member through the
 * ROSTER -- 353, which 7/Phase 6's acceptance criterion is about -- and not yet
 * through a channel echo. The gap closes when SBURST carries the per-member host
 * and realname (4.3, driven in Phase 9). Writing a JOIN with an invented host
 * would be worse than the gap: 2.1's whole point is that a hostmask is OBSERVED
 * rather than asserted.
 */

/* Parse the SJOIN flags token back into a flag word. The token is 4.3's frozen
 * single token (see fed_flag_token()), so this is a two-letter scan and not a
 * grammar: `+`, then `o` and/or `v`, or the literal `-`. A duplicate letter is
 * refused rather than collapsed, because a flags word this node does not
 * understand is a membership it would render wrongly in 353 and a line whose
 * author we could not describe. */
static int fed_parse_flags(const char *tok, unsigned *out)
{
    unsigned f = 0u;

    if (tok == NULL || tok[0] == '\0' || out == NULL) {
        return -1;
    }
    if (strcmp(tok, "-") == 0) {
        *out = 0u;
        return 0;
    }
    if (tok[0] != '+') {
        return -1;
    }
    for (size_t i = 1; tok[i] != '\0'; i++) {
        if (tok[i] == 'o' && (f & CHAN_MEMBER_OP) == 0u) {
            f |= CHAN_MEMBER_OP;
        } else if (tok[i] == 'v' && (f & CHAN_MEMBER_VOICE) == 0u) {
            f |= CHAN_MEMBER_VOICE;
        } else {
            return -1;
        }
    }
    if ((f & (CHAN_MEMBER_OP | CHAN_MEMBER_VOICE)) == 0u) {
        return -1; /* `+` with no letters names nothing */
    }
    *out = f;
    return 0;
}

/* Keep a channel's member-server set in step with the roster, where the set is
 * a refcount the ORIGIN keeps and the only count this node can take locally is
 * of its own cache.
 *
 * THE COST, stated because it is a real one: a member the origin has and this
 * node has not been told about is invisible here, so an SPART for the last
 * KNOWN member from a server that still has others behind it removes the
 * servers[] entry early -- and the channel is then no longer in that peer's
 * forward set, so a state change for it stops reaching them until the origin
 * re-reports a member. 2.2 says a non-owner's state is a cache and that caches
 * are allowed to be incomplete and self-healing; the alternative -- never
 * decrementing -- makes the set grow for the life of the channel and turns 3.1's
 * target set into "every server this node has ever heard of", which is the
 * global list the design explicitly rejects. */
static void fed_touch_server(chan_t *ch, const char *server, int adding)
{
    if (adding != 0) {
        (void)chan_server_add(ch, server);
        return;
    }
    for (size_t i = 0; i < ch->nremotes; i++) {
        if (chan_same_name(ch->remotes[i].server, server)) {
            return; /* somebody from that server is still known */
        }
    }
    (void)chan_server_remove(ch, server);
}

/* The channel an inbound S-verb names, canonicalised, or NULL.
 *
 * A channel this node has never heard of is created HERE, from an SJOIN only,
 * and that is the one place a channel enters a federated node other than through
 * a local JOIN: an SJOIN proves the SENDER has a member, so by 2.2's "first
 * server to see a channel owns it" the origin is the sender. The other four state
 * verbs do not create -- they describe a change to a channel that already exists,
 * and a peer that could invent a channel here by parting from it could make this
 * node hold channels nobody joined. It is created with
 * the link's own epoch as its origin_epoch, which is the one field the wire
 * gives us about the creating boot and is what makes a later creation-race
 * comparison between two real values rather than between a value and a
 * placeholder.
 *
 * 2.2's full tie-break also needs the (epoch, name) of the FIRST creator, which
 * a bare SJOIN cannot distinguish from a relayed one -- that is 4.3's SBURST
 * vocabulary and 4.3 says the burst REPLACES rather than merges. So a
 * re-keying decision is NOT made here and a node that receives two SJOINs for
 * the same channel from two peers keeps the first origin it learned. That is a
 * known gap with a known owner (Phase 9's resync), and it is stated here rather
 * than left to be discovered as a split-brain. */
static chan_t *fed_in_channel(server_t *s, server_link_t *link, const char *name,
                              int create)
{
    char canonical[CHAN_MAX_NAME + 1];
    chan_t *ch;

    if (s == NULL || link == NULL || name == NULL || !chan_name_valid(name)) {
        return NULL;
    }
    (void)chan_name_upper(canonical, sizeof canonical, name);
    ch = server_chan_get(s, canonical);
    if (ch == NULL && create == 0) {
        /* Only SJOIN creates. An SPART, STOPIC, SMODES or SKICK for a channel
         * this node has never heard of is REFUSED rather than creating it: those
         * verbs describe a change to a channel that already exists, and a peer
         * that could invent a channel here by parting from it would be able to
         * make this node hold channels nobody joined. */
        return NULL;
    }
    if (ch == NULL) {
        ch = chan_new(canonical, link->name, link->epoch);
        if (ch == NULL || server_chan_attach(s, ch) != 0) {
            chan_free(ch);
            return NULL;
        }
        printf("[observable] chan_create: channel=%s origin=%s epoch=%llu "
               "creator=%s\n",
               ch->name, ch->origin, (unsigned long long)ch->origin_epoch,
               link->name);
    }
    return ch;
}

/* SPRIVMSG / SNOTICE: <target> <text>.
 *
 * A `message` class line, so 3.1 applies both channel rows at once: write to
 * local members AND forward -- to the owner if this node does not own the
 * channel, to servers[] UNION the ESTABLISHED links if it does. The local write
 * goes through fanout_deliver() with the CLIENT verb (a client is never sent an
 * S-verb) and the prefix is the one the line arrived with, which for a
 * peer-relayed SPRIVMSG is a real hostmask and is therefore the only thing this
 * node could put on the message for its own clients.
 *
 * AND THIS FUNCTION FORWARDS NOTHING ITSELF. It used to: it wrote locally
 * through fanout_deliver() and then called fanout_forward_channel_sverb() with
 * the received `tags`. That was a SECOND forward of the same emission, and it
 * was invisible until 3.1's owned/`message` row was amended, because until then
 * the only node that received a `message` was the owner and an owner had no
 * forward arm for the first of the two to double up on. With the amendment every
 * node that receives a `message` has a forward arm, and the two calls together
 * would have sent the owner TWO copies of one client message: one from
 * fanout_deliver()'s forward, which had no `carry` and therefore MINTED A FRESH
 * id, and one from here, which carried the real one. The fresh id is the worse
 * of the two -- 2.4 says a relay changes hops and nothing else, and a restamp is
 * how a message comes back.
 *
 * So the tags go INSTEAD, as fanout_deliver()'s `carry`, and the forward happens
 * once, in the one place 3.1's table is transcribed. What that argument buys is
 * not tidiness: it is that the local write and the forward cannot be given
 * different identities, which is the failure this whole function is shaped to
 * make unrepresentable. */
static void fed_in_message(server_t *s, fanout_target_t *t, const char *prefix,
                           const irc_serve_tags_t *tags, const char *client_verb,
                           const char *const *params, int nparams);
static void fed_in_message(server_t *s, fanout_target_t *t, const char *prefix,
                           const irc_serve_tags_t *tags, const char *client_verb,
                           const char *const *params, int nparams)
{
    int delivered = fanout_deliver(s, t, prefix, client_verb, params, nparams, NULL,
                                   tags);

    /* The LOCAL half, reported. The client-side path reports its own
     * deliveries in msg_verbs.c's `msg:` line, and a relayed message has no
     * such line anywhere -- it arrives on a peer link and is fanned out from
     * here -- so without this a node's log shows a message arriving from a
     * peer and nothing about what it did with it. The count is the number of
     * local members written to, which is 0 on a node that is purely a relay,
     * and that zero is the interesting value rather than a disappointing one.
     *
     * It is also the countable line a loop shows up in: a message that keeps
     * circulating prints this again, so "delivered exactly once" can be
     * asserted from the node as well as from the client. */
    printf("[observable] fed_message: channel=%s from=%s delivered=%d "
           "origin=%s hops=%lu\n",
           t->name, (prefix != NULL) ? prefix : "?", delivered, tags->origin,
           (unsigned long)tags->hops);
}

/* SJOIN: <channel> <member> <flags>. */
static void fed_in_sjoin(server_t *s, server_link_t *link, chan_t *ch,
                         const char *prefix, const irc_serve_tags_t *tags,
                         const char *const *params, int nparams)
{
    unsigned flags = 0u;

    if (nparams != 3 || fed_parse_flags(params[2], &flags) != 0 ||
        /* link->name TWICE, and that is the whole of what an SJOIN can say: 4.3's
         * SJOIN carries no server field, so the member's holder is inferred from
         * the link the record arrived on -- exact on a two-node mesh and a
         * relaying peer's best guess on a larger one, which is why the BURST
         * format grew a <server> field and this one has not. See
         * channel.h's chan_remote_t for the two-server split. */
        chan_remote_add(ch, link->name, link->name, params[1], flags) != 0) {
        printf("[observable] fed_sjoin_reject: channel=%s member=%s server=%s\n",
               ch->name, (nparams > 1) ? params[1] : "?", link->name);
        return;
    }
    fed_touch_server(ch, link->name, 1);
    printf("[observable] fed_sjoin: channel=%s member=%s server=%s flags=%u "
           "local=%zu remote=%zu origin=%s owned=%d\n",
           ch->name, params[1], link->name, flags, ch->nmembers, ch->nremotes,
           ch->origin, chan_origin_is_self(s, ch));
    (void)fanout_forward_channel_sverb(s, ch, FANOUT_STATE_CHANGE, "SJOIN", prefix,
                                       params, nparams, tags);
}

/* SPART: <member> <channel> [<reason>]. */
static void fed_in_spart(server_t *s, server_link_t *link, chan_t *ch,
                         const char *prefix, const irc_serve_tags_t *tags,
                         const char *const *params, int nparams)
{
    if (nparams < 2 || nparams > 3) {
        return;
    }
    (void)chan_remote_remove(ch, link->name, params[0]);
    fed_touch_server(ch, link->name, 0);
    printf("[observable] fed_spart: channel=%s member=%s server=%s remote=%zu\n",
           ch->name, params[0], link->name, ch->nremotes);
    (void)fanout_forward_channel_sverb(s, ch, FANOUT_STATE_CHANGE, "SPART", prefix,
                                       params, nparams, tags);
    (void)chan_dispose_if_empty(s, ch);
}

/* STOPIC: <member> <channel> <topic>. */
static void fed_in_stopic(server_t *s, server_link_t *link, chan_t *ch,
                          const char *prefix, const irc_serve_tags_t *tags,
                          const char *const *params, int nparams)
{
    if (nparams != 3) {
        return;
    }
    /* ONLY THE ORIGIN'S TOPIC IS TAKEN, and the test is the LINK, not the
     * channel: a line that arrived on a link bearing a name other than the
     * channel's origin is a second opinion about a field whose authority is
     * elsewhere, and caching it is the permanent divergence 2.2's single-writer
     * rule exists to prevent. A topic from the origin -- whether it came
     * directly or through a relay -- is the authority and is applied. */
    if (!chan_same_name(link->name, ch->origin)) {
        printf("[observable] fed_topic_ignored: channel=%s from=%s origin=%s\n",
               ch->name, link->name, ch->origin);
        return;
    }
    if (chan_set_topic(ch, params[2], params[0]) != 0) {
        printf("[observable] fed_topic_ignored: channel=%s reason=too_long\n",
               ch->name);
        return;
    }
    printf("[observable] fed_topic: channel=%s member=%s len=%zu\n", ch->name,
           params[0], strlen(ch->topic));
    (void)fanout_forward_channel_sverb(s, ch, FANOUT_STATE_CHANGE, "STOPIC", prefix,
                                       params, nparams, tags);
}

/* SMODES: <server> <channel> <modes> [<arg>]. */
static void fed_in_smodes(server_t *s, server_link_t *link, chan_t *ch,
                          const char *prefix, const irc_serve_tags_t *tags,
                          const char *const *params, int nparams)
{
    if (nparams < 3 || nparams > 4) {
        return;
    }
    /* 2.2: a non-owner's modes[] is a CACHE, and only the origin evaluates
     * +b/+e/+I. The frozen shape names the node that EVALUATED the change as its
     * first field, so a cache update is taken from a line claiming this node's
     * origin -- not from one that merely arrived here. */
    if (!chan_same_name(params[0], ch->origin)) {
        printf("[observable] fed_modes_ignored: channel=%s from=%s origin=%s\n",
               ch->name, params[0], ch->origin);
        return;
    }
    (void)link;
    for (size_t i = 0; params[2][i] != '\0'; i++) {
        char m = params[2][i];
        int on = (m != '-');

        if (m == '+' || m == '-') {
            continue; /* the sign, not a mode */
        }
        (void)chan_mode_set(ch, m, on);
    }
    printf("[observable] fed_modes: channel=%s by=%s modes=%s cached=%s\n",
           ch->name, params[0], params[2], ch->modes);
    (void)fanout_forward_channel_sverb(s, ch, FANOUT_STATE_CHANGE, "SMODES", prefix,
                                       params, nparams, tags);
}

/* SKICK: <member> <channel> <target> [<reason>]. */
static void fed_in_skick(server_t *s, server_link_t *link, chan_t *ch,
                         const char *prefix, const irc_serve_tags_t *tags,
                         const char *const *params, int nparams)
{
    if (nparams < 3 || nparams > 4) {
        return;
    }
    (void)chan_remote_remove(ch, link->name, params[2]);
    fed_touch_server(ch, link->name, 0);
    printf("[observable] fed_skick: channel=%s by=%s target=%s\n", ch->name,
           params[0], params[2]);
    (void)fanout_forward_channel_sverb(s, ch, FANOUT_STATE_CHANGE, "SKICK", prefix,
                                       params, nparams, tags);
    (void)chan_dispose_if_empty(s, ch);
}

/* ---------------------------------------------------------------------------
 * SQUIT: <server> [<reason>]
 * ---------------------------------------------------------------------------
 * "That server is gone; forget everything you learned through it."
 *
 * WHY IT IS NOT A ROW IN INBOUND, and the answer is the same one the burst family
 * gets at G8 with one difference in the reasoning. Every INBOUND row describes a
 * line ABOUT A CHANNEL, at a parameter position the verb fixes, and the
 * dispatch reads the channel out of that position -- position 0 for SJOIN, 1 for
 * the rest. A SQUIT names no channel at all, and a row for it would have to lie
 * about that. The burst family is the other shape the table cannot hold, and it
 * is asked separately for the same structural reason.
 *
 * IT IS NOT THE BURST CASE EITHER, and that is the part worth stating because a
 * reader who has just read case E will assume the resemblance is deliberate. Case
 * E refuses an UNTAGGED burst because case A would mint a fresh identity PER
 * LINE for it, and a burst is O(n) lines forming one transaction -- so a peer
 * could replace this node's entire view of an origin, as often as it liked, on
 * lines whose 2.4 identity this node invented. A SQUIT is ONE line destroying
 * ONE origin's state, and the authority to do that is the authority the peer
 * already has: any peer may report a roster, and may report a smaller one. So a
 * SQUIT is allowed the same untagged-originated treatment as any other state
 * change, and it is a RELAYED one that is refused (case B), because a claim that
 * somebody ELSE is gone is a claim about a third party's memory. No case of its
 * own, and the chain is unchanged above this point -- which is the point: a
 * SQUIT is deduplicated, hop-checked and own-origin-checked like every other
 * state-destroying line, and a REPLAYED SQUIT is refused by G7 rather than
 * purging twice.
 *
 * 3.1: it is a state change, so it is applied to this node's cache and FORWARDED
 * onward, exactly as the table's rows are. See the forwarding note at the end of
 * the function for what "onward" means when the subject of the change is a server
 * rather than a channel.
 */
static void fed_in_squit(server_t *s, server_link_t *link,
                         const irc_serve_tags_t *tags, const char *const *params,
                         int nparams)
{
    const char *gone;
    size_t purged = 0;
    size_t chans = 0;
    size_t i = 0;

    if (s == NULL || params == NULL) {
        return;
    }
    /* Arity here rather than in G9's table, for the reason the burst verbs give:
     * this shape is not a table row, so there is no row to hold its bounds. One
     * or two -- the reason is the OPTIONAL trailing parameter SPART and SKICK
     * also carry, and it is never acted on. A line with any other count is a peer
     * running a different format and is refused rather than guessed at. */
    if (nparams < 1 || nparams > 2) {
        s->n_fed_malformed++;
        printf("[observable] fed_malformed: command=SQUIT field=arity nparams=%d "
               "want=1..2\n",
               nparams);
        return;
    }
    gone = params[0];

    /* A SQUIT NAMES THIS NODE, and it is REFUSED, and the link is NOT torn down.
     *
     * This is the one line a peer can send that, taken literally, would have a
     * listening node delete itself from the mesh, and 2.3's uniqueness rule is
     * what makes it worse than a nuisance: 2.3 calls two nodes with one name
     * "catastrophic and undetectable later", and a peer announcing that name is
     * the announcement a re-joining node would act on. So the claim is refused on
     * the only evidence available -- this node is here, and it is answering --
     * and the LINK SURVIVES, because a peer sending this is either broken or
     * hostile and neither of those is a reason to hang up on a peer that is
     * otherwise the only route to half the network.
     *
     * It is counted separately from n_fed_malformed because the two say opposite
     * things to an operator: a malformed line is a peer that does not implement
     * 4.3, and this is a peer that implements 4.3 and is telling this node it no
     * longer exists. The first is a version fact and the second is a finding. */
    if (chan_same_name(gone, s->name)) {
        s->n_fed_squit_self++;
        printf("[observable] fed_squit_refused: fd=%d peer=%s server=%s self=%s "
               "reason=SELF_NOT_GONE\n",
               (link != NULL) ? link->fd : -1, (link != NULL) ? link->name : "?",
               gone, s->name);
        return;
    }

    /* THE PURGE, AND IT IS PER ORIGIN. Everything this node learned THROUGH the
     * departed server goes, and nothing else does: chan_remote_purge() is keyed
     * by the reporting origin -- the same key SBURSTM's records are installed
     * under, which federation/burst.c's install step states -- so a member that
     * arrived from some other server is untouched.
     *
     * THE GLOBAL WIPE IS THE BUG THIS SHAPE IS SHAPED AGAINST, and it is worth
     * naming because it is the obvious shortcut: "a server is gone, drop the
     * rosters" reads as one loop with no key, and it destroys every other
     * origin's members on this node in the same pass. On a two-node mesh the two
     * are indistinguishable, which is exactly why tests/integration/
     * test_fed_resync.c gives the receiving node two origins over two different
     * links.
     *
     * servers[] LOSES THE NAME, unlike a link that merely went down (2.2's
     * fail-closed note, and fed_link_down()'s neighbours): a SQUIT is positive
     * evidence that the server is gone rather than a socket this node cannot
     * reach, so keeping the name would keep a channel alive for the rest of the
     * process for a server that has said it is finished. The two cases are
     * different facts and are treated differently on purpose.
     *
     * THE WALK DOES NOT ADVANCE PAST A DISPOSED CHANNEL, and the reason is
     * server_chan_detach()'s: it shifts the array down, so an index that is
     * incremented after a removal skips the channel that moved into the hole --
     * silently, and a channel that silently survives a purge is a roster the
     * operator is told is gone. chan_remote_purge() walks the same way for the
     * same reason. */
    while (i < server_chan_count(s)) {
        chan_t *ch = server_chan_at(s, i);
        int disposed;

        if (ch == NULL) {
            i++;
            continue;
        }
        purged += chan_remote_purge(ch, gone);
        if (chan_server_remove(ch, gone) > 0) {
            chans++;
        }
        /* The same disposition the burst's replace arm does: a channel left with
         * no local member and no member-server has nothing left to remember, and
         * holding it for the life of the process is a channel LIST reports and
         * NAMES answers for, forever. One this node still holds members in is
         * kept, which is 2.2's locally-orphaned case: the members still see each
         * other and origin-requiring actions are refused with 437. */
        disposed = chan_dispose_if_empty(s, ch);
        if (disposed == 0) {
            i++;
        }
    }
    printf("[observable] fed_squit: server=%s chans=%zu purged=%zu remote=%zu\n", gone,
           chans, purged, (size_t)server_chan_count(s));

    /* 3.1's non-owner row: apply here, forward onward. "Onward" for a
     * server-scoped state change is the OTHER ESTABLISHED LINKS, and the two
     * exclusions are the whole of the rule:
     *
     *   - the link it arrived on, because it came from there. Forwarding it back
     *     is 2.4's never-forward-own-origin rule in the only shape that applies
     *     here: the sender already has it.
     *   - a link whose name IS the departed server, because that node is by
     *     definition not gone and the line would arrive there as a SQUIT naming
     *     itself, which the arm above refuses. Skipping it saves a line and does
     *     not change any outcome.
     *
     * THE COST, because a reader deserves it: this is a broadcast, and it is
     * bounded by 2.4 rather than by the hop ceiling alone. A node two hops away
     * receives the same (origin, epoch, id) by two paths, and the per-node dedup
     * store drops the second; a node three hops away never receives it at all,
     * because the ceiling is ten hops and a full mesh is two. So on a large mesh
     * the announcement reaches a bounded neighbourhood rather than the whole
     * network, and what it does not reach is corrected by the next burst -- which
     * is Phase 9's to drive, and is stated rather than relied on here. */
    for (size_t k = 0; k < server_link_count(s); k++) {
        server_link_t *lk = server_link_at(s, k);

        if (lk == NULL || lk == link || lk->state != (int)ESTABLISHED ||
            chan_same_name(lk->name, gone)) {
            continue;
        }
        (void)fanout_forward_sverb(s, lk->name, "SQUIT", NULL, params, nparams, tags);
    }
}

/* ---------------------------------------------------------------------------
 * The inbound table, and the verbs it does not have
 * ---------------------------------------------------------------------------
 *
 * G8 asks this table for the VERB the peer sent, which is an S-verb -- the
 * encode direction's output is this table's input, which is what makes the two
 * halves of this file one format rather than two. A table rather than a switch
 * for the reason fed_sverb_for() gives: a switch duplicates every name in the
 * source, so a typo in one arm compiles cleanly and returns the wrong thing at
 * run time.
 *
 * `min`/`max` are the parameter bounds, and they are the FROZEN shapes' bounds
 * rather than a range: an SJOIN is always three parameters, an SPART is two or
 * three, and a verb arriving with a different count is a peer running a
 * different format and is REFUSED rather than guessed at. Refusing is the safe
 * direction because the alternative -- reading params[1] of a two-parameter
 * SPRIVMSG -- is a read of a field that does not exist.
 */
static const struct {
    const char *verb;
    int min;
    int max;
    void (*fn)(server_t *, server_link_t *, fanout_target_t *, const char *,
               const irc_serve_tags_t *, const char *const *, int);
    int vclass; /* what the target is resolved under, and the row it takes */
    const char *client_verb; /* what a RELAY of it is called */
} INBOUND[] = {
    { "SPRIVMSG", 2, 2, NULL, FANOUT_MESSAGE,  "PRIVMSG" },
    { "SNOTICE",  2, 2, NULL, FANOUT_MESSAGE,  "NOTICE"  },
    { "SJOIN",    3, 3, NULL, FANOUT_STATE_CHANGE, "JOIN"  },
    { "SPART",    2, 3, NULL, FANOUT_STATE_CHANGE, "PART"  },
    { "STOPIC",   3, 3, NULL, FANOUT_STATE_CHANGE, "TOPIC" },
    { "SMODES",   3, 4, NULL, FANOUT_STATE_CHANGE, "MODE"  },
    { "SKICK",    3, 4, NULL, FANOUT_STATE_CHANGE, "KICK"  }
};

static int inbound_index(const char *verb)
{
    if (verb == NULL) {
        return -1;
    }
    for (size_t i = 0; i < sizeof INBOUND / sizeof INBOUND[0]; i++) {
        if (strcmp(INBOUND[i].verb, verb) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* The 4.3 words this build does not speak yet, and WHY THAT IS NOT "unknown".
 *
 * SNAMES and SHASH are in 4.3's list and are not in INBOUND, because they are
 * later commits of this phase. They are listed here so that a peer sending one
 * is told this node has not implemented it rather than that it is not a verb -- a
 * distinction an operator needs, because the first means "a peer is running a
 * build I do not have" and the second means "a peer is talking nonsense".
 * Reporting them through n_fed_unknown_verb would make the counter mean two
 * incompatible things and stop being evidence of anything.
 *
 * SQUIT IS NOT HERE ANY MORE, and its removal is the change C5 made: the
 * departure announcement landed, so a peer sending one gets the purge rather than
 * a version fact. A verb that arrives and is handled must not leave its name in a
 * table that says it is not handled, or the table becomes a place where a reader
 * learns which half of the phase is finished -- which is what the list said about
 * SBURST before C4 removed it, and is why this paragraph exists.
 *
 * FEDERATE is NOT here: it never reaches G8, because G2 consumes it, and it is
 * the verb that ESTABLISHES the epoch every other tag rule is stated against. */
static const char *const DEFERRED[] = { "SNAMES", "SHASH" };

static int is_deferred(const char *verb)
{
    for (size_t i = 0; i < sizeof DEFERRED / sizeof DEFERRED[0]; i++) {
        if (strcmp(DEFERRED[i], verb) == 0) {
            return 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * fed_dispatch -- the guard chain
 * ---------------------------------------------------------------------------
 */
void fed_dispatch(server_t *s, conn_t *c, const message_t *m)
{
    irc_serve_tags_t tags;
    server_link_t *link;
    fanout_target_t t;
    char peer[IRC_MAX_SERVER_NAME + 1];
    const char *pserver;
    /* message_t::params is `char *[]` and every handler here takes
     * `const char *const *`, and C will not add that qualification silently to
     * an array of pointers. A local array is the copy that makes it legal, and
     * it does the arity bound as a side effect: G9 has already checked nparams
     * against the verb's frozen shape, so nothing past cap can be written and
     * the handlers cannot be handed a longer list than the wire shape allows. */
    const char *sp[IRC_MAX_PARAMS];
    int idx;

    /* --- G0: NULL args, no command -------------------------------------- */
    if (s == NULL || c == NULL || m == NULL || m->command == NULL) {
        return;
    }

    /* THE LINK IS LOOKED UP BY THE CONNECTION'S PEER NAME, and that is safe
     * here for a reason the connection's name being a display copy does not
     * obviously give. A connection only becomes CONN_SERVER in
     * fed_link_established(), which sets peer_name from the claim the handshake
     * accepted, and 2.3's uniqueness check guarantees at most one link holds
     * that name. So a CONN_SERVER conn names exactly one link, and
     * server_find_link() is that link. It is deliberately NOT a search by
     * descriptor: federation/link.c's fed_link_of_conn() documents the
     * recycled-descriptor trap a `link->fd == c->fd` lookup falls into, and this
     * path does not have it. */
    link = (c->peer_name != NULL) ? server_find_link(s, c->peer_name) : NULL;

    /* --- G1: pre-auth ---------------------------------------------------- */
    if (strcmp(m->command, "FEDERATE") != 0 &&
        (link == NULL || link->state != (int)ESTABLISHED)) {
        /* Dropped, and the link is NOT torn down. A line on a connection that is
         * not an established peer link is a stranger talking, and the answer to
         * a stranger is the handshake, not a closed socket: the same connection
         * is one second away from sending a FEDERATE. Tearing it down here would
         * make a peer that speaks before it says hello permanently
         * unconnectable, and the handshake FSM has no way to recover from that.
         *
         * Counted, because a node whose pre-auth drops climb is a node that is
         * being spoken to by something that is not a peer, and that is a finding
         * rather than a statistic. */
        s->n_fed_preauth_drop++;
        printf("[observable] fed_preauth_drop: fd=%d command=%s state=%s\n", c->fd,
               m->command,
               (link != NULL) ? ((link->state == (int)ESTABLISHED) ? "ESTABLISHED"
                                                                     : "PENDING")
                              : "NONE");
        return;
    }

    /* --- G2: FEDERATE ---------------------------------------------------- */
    if (strcmp(m->command, "FEDERATE") == 0) {
        /* The one verb that is exempt from every tag rule below, and it is
         * exempt BY CONSTRUCTION rather than by a special case: the epoch this
         * line is about to be judged against is the one it ESTABLISHES. A
         * FEDERATE carries no 2.4 block because 2.4's block is what a receiver
         * needs in order to deduplicate and loop-check a message, and a
         * handshake is neither relayed nor looped. */
        fed_on_federate(s, c, m);
        return;
    }

    /* --- G3: still not ESTABLISHED --------------------------------------- */
    if (link == NULL || link->state != (int)ESTABLISHED) {
        /* UNREACHABLE after G1, and kept as the assertion that the two cannot
         * disagree. A counted return rather than a silent one, so an edit that
         * reorders G1 and G3 leaves a number behind instead of a hole. */
        s->n_fed_preauth_drop++;
        printf("[observable] fed_preauth_drop: fd=%d command=%s state=UNREACHABLE\n",
               c->fd, m->command);
        return;
    }

    /* --- G4: the 2.4 tag block, and the trust boundary -------------------- */
    if (irc_serve_tags_parse(m, &tags) != 0) {
        pserver = fed_prefix_server(m->prefix, peer, sizeof peer);

        if (pserver == NULL) {
            /* CASE D. A prefix that is not a usable server name at all: absent,
             * empty, over-long, or a name the 2.4 tag grammar would refuse. There
             * is no identity to synthesise and no server to say it belongs to
             * someone else, so this is malformed rather than a relay -- and
             * counting it as a relay would tell an operator their peer is
             * misbehaving in a specific way when the line is simply not a line
             * this node can reason about. */
            s->n_fed_malformed++;
            printf("[observable] fed_untagged: fd=%d peer=%s command=%s "
                   "prefix=%s reason=BAD_PREFIX\n",
                   c->fd, link->name, m->command,
                   (m->prefix != NULL) ? m->prefix : "(none)");
            return;
        }

        if (is_deferred(m->command)) {
            /* CASE C. A 4.3 verb this build does not speak, arriving untagged.
             * Refused, but reported as what it is: a peer running a build with
             * the resync verbs is a version fact, and calling it an untagged
             * relay would send the operator looking for a loop. */
            s->n_fed_verb_deferred++;
            printf("[observable] fed_verb_deferred: fd=%d peer=%s command=%s\n",
                   c->fd, link->name, m->command);
            return;
        }

        if (fed_burst_verb(m->command) != 0) {
            /* CASE E, AND IT EXISTS BECAUSE A BURST IS NOT A MESSAGE. Every other
             * verb in this chain is happy to have its identity MINTED for it by
             * case A below, because a message's identity is per line and a
             * missing one costs that line. A burst is O(n) lines forming ONE
             * transaction, and case A mints a fresh id PER LINE -- which is
             * exactly right for dedup and exactly wrong for the thing the
             * transaction is for. A peer that could send an untagged burst would
             * therefore be able to make this node replace its entire view of
             * that origin, as often as it liked, with lines whose 2.4 identity
             * this node invented. So the one verb family that is state REPLACEMENT
             * is required to carry its identity on the wire, and the refusal is
             * counted as malformed rather than as a relay: a peer sending it is
             * not relaying somebody else's burst, it is sending a burst it did
             * not stamp. */
            s->n_fed_malformed++;
            printf("[observable] fed_untagged: fd=%d peer=%s command=%s "
                   "reason=BURST_UNTAGGED\n",
                   c->fd, link->name, m->command);
            return;
        }

        if (!chan_same_name(pserver, link->name)) {
            /* CASE B. The peer is RELAYING and did not stamp the line. REFUSED,
             * and the link is NOT torn down.
             *
             * Every 2.4 guard is unavailable on this line: there is no origin to
             * check against our own name, no hop count to apply the ceiling to,
             * and no (origin, epoch, id) to record, so a store that "saw" it
             * would be recording a key it invented. A node that accepts untagged
             * relays therefore has NO loop prevention at all, and 2.4's three
             * rules are the whole of what stops two nodes bouncing a message for
             * ever. There is no partial acceptance available: either the
             * identity is on the wire or it is not.
             *
             * The discriminator is THE PREFIX and never the verb, and a peer
             * relaying a message it received FOR A CHANNEL IT HAS A MEMBER IN
             * sends `SPRIVMSG` with a REMOTE prefix -- so any rule keyed on the
             * verb would accept exactly the dangerous case and refuse the
             * harmless one. */
            s->n_fed_untagged_relay++;
            printf("[observable] fed_untagged: fd=%d peer=%s command=%s prefix=%s "
                   "reason=RELAY_UNTAGGED\n",
                   c->fd, link->name, m->command, pserver);
            return;
        }

        /* CASE A. The peer ORIGINATED the line: its prefix is its own server
         * name. Accepted, with the identity SUPPLIED rather than read.
         *
         * MINTING THE ID LOCALLY IS THE POINT. An untagged originated line has
         * no identity of its own, and a node that forwarded it with a
         * synthesised one has to invent an id; inventing it from the
         * per-SERVER counter is what makes the invented value unique to this
         * node and therefore safe to put in a key the far side will store.
         *
         * AND IT IS THE PEER'S EPOCH, not s->epoch, and the reason is subtle
         * enough to be worth the paragraph. The key is (origin, epoch, id) and
         * the origin here is the PEER, so the epoch has to be the boot the
         * peer's own id stream belongs to: a key whose epoch belongs to a
         * different boot than its id is a key that aliases. If this node stamped
         * s->epoch here, every relay node on a path would pair ITS counter with
         * an epoch that is not the counter's, and two of them relaying the same
         * untagged line would mint two DIFFERENT keys for one message -- so a
         * third node would accept both copies and deliver the message twice, with
         * dedup unable to collapse them because there is nothing shared to
         * collapse on. With the peer's epoch, both relayers mint into the SAME
         * (peer, peer-boot) id space, two relays of one untagged line collapse
         * onto one key, and the second copy is dropped as the duplicate it is.
         *
         * THE COST, because a bound that cannot be reached is not a bound: the
         * id is drawn from THIS node's counter while the epoch is the peer's, so
         * a synthetic id can in principle collide with the peer's own id of the
         * same number, and the peer would then have its genuine message dropped
         * as a duplicate. That is the recoverable direction: dedup.h states it,
         * that a dropped message is one lost message whereas a store that failed
         * to record is a loop, and it is reachable only by a peer that sent an
         * untagged line in the first place. A colliding key is the correct
         * answer to a line that claims to be from a boot we cannot see the
         * counter of. */
        memset(&tags, 0, sizeof tags);
        memcpy(tags.origin, link->name, strlen(link->name) + 1u);
        tags.epoch = link->epoch;
        tags.id = server_next_msg_id(s);
        tags.hops = 0u;
        printf("[observable] fed_untagged: fd=%d peer=%s command=%s origin=%s "
               "epoch=%llu id=%llu reason=ORIGINATED_UNTAGGED\n",
               c->fd, link->name, m->command, tags.origin,
               (unsigned long long)tags.epoch, (unsigned long long)tags.id);
    }

    /* --- G5: the hop ceiling --------------------------------------------- */
    if (tags.hops >= (uint32_t)IRC_MAX_HOPS) {
        /* 2.4: "irc-serve-hops increments per forward and the message is dropped
         * at 10." Checked on RECEIPT as well as at forward time, and the two are
         * not the same check: the forward-time one refuses to SPREAD a message
         * that is at the ceiling, and this one refuses to ACT on one that
         * arrived at it. A node that only checked at forward time would apply a
         * message that some other node had already decided to stop. */
        s->n_fed_hop_drop++;
        printf("[observable] fed_hop_drop: fd=%d peer=%s command=%s hops=%lu "
               "ceiling=%d\n",
               c->fd, link->name, m->command, (unsigned long)tags.hops, IRC_MAX_HOPS);
        return;
    }

    /* --- G6: never act on our own origin ---------------------------------- */
    if (chan_same_name(tags.origin, s->name)) {
        /* 2.4: "A node never forwards a message whose irc-serve-origin is
         * itself." The INBOUND half of it, and the half that makes "a two-node
         * ping-pong does not loop" true: a message this node originated came
         * back, and applying it would re-deliver to the local members it was
         * already delivered to and then forward it onward again. On a two-node
         * mesh that is the whole cycle; on a three-node mesh it is the short one
         * inside a longer one.
         *
         * The comparison is ASCII case-insensitive because server names are
         * (2.1, RFC 1459 2.3.2) and a peer that spells this node's name `IRC.A`
         * is naming THIS node. Treated as a different server, the hop ceiling
         * would be the only thing left and it is ten, so a two-node mesh would
         * bounce one message ten times before it stopped.
         *
         * IT IS REDUNDANT WITH G7, and it stays anyway. The dedup store is
         * bounded (IRC_DEDUP_MAX slots) and evictable (IRC_DEDUP_TTL_MS), so a
         * bound that CAN be reached is not a loop guard -- a node that has been
         * up for a while, or one on a busy mesh, can legitimately have evicted
         * the very entry that would have caught this. A rule that is a
         * belt-and-braces today is the only rule left when the braces are
         * dropped, and the hop ceiling is the second belt rather than the first:
         * it bounds the damage, it does not stop the loop. */
        s->n_fed_own_origin++;
        printf("[observable] fed_own_origin_drop: fd=%d peer=%s command=%s "
               "origin=%s self=%s hops=%lu\n",
               c->fd, link->name, m->command, tags.origin, s->name,
               (unsigned long)tags.hops);
        return;
    }

    /* --- G7: the dedup store --------------------------------------------- */
    if (fed_dedup_seen(s, &tags, server_now_ms()) != 0) {
        /* RECORDED HERE, AT THE GUARD, AND NOT AFTER THE HANDLER.
         *
         * Dedup is a statement about the WIRE, not about whether this node
         * handled the message: a peer is not obliged to be correct, and nothing
         * stops a buggy or hostile one from sending the same id twice, once
         * well-formed and once not. A store that recorded only successfully
         * handled messages would take the second as new and act on it. So the
         * key is recorded on SIGHT, which is why this guard is above the verb
         * lookup and above the field validation: a message dropped by G8 or G9
         * is already recorded, and a peer cannot retry the same line under a new
         * id and get a different answer. A retry with a NEW id is a different
         * message, and 2.4's epoch exists so that a restarted peer is told to
         * use different ids.
         *
         * The two counters are incremented together because they are the same
         * event read at two levels -- the guard's drop and the store's duplicate
         * -- and a difference between them would be a bug in the chain rather
         * than a number nobody looked at. */
        s->n_fed_dup_drop++;
        s->n_fed_dedup_dup++;
        printf("[observable] fed_duplicate: fd=%d peer=%s command=%s origin=%s "
               "epoch=%llu id=%llu hops=%lu\n",
               c->fd, link->name, m->command, tags.origin,
               (unsigned long long)tags.epoch, (unsigned long long)tags.id,
               (unsigned long)tags.hops);
        return;
    }

    /* --- G8: the verb ----------------------------------------------------- */
    /* THE BURST FAMILY IS ASKED BEFORE THE TABLE, and it is a separate branch
     * rather than five rows because it is not this kind of verb. INBOUND's rows
     * all describe a line about a CHANNEL, at a position the verb fixes, within
     * a two-or-three parameter arity; SBURSTC names the channel first and
     * carries six parameters, SBURSTM carries three, and SBURST carries two
     * numerics and names no channel at all. Rows for them would have arity ranges
     * that are individually correct and collectively a lie, and the handler
     * dispatch below reads the channel out of a position that means something
     * different for each verb.
     *
     * THEY ARE STILL GATED BY EVERYTHING ABOVE, which is the point of asking
     * here rather than earlier: a burst is state REPLACEMENT, so it is
     * hop-checked, own-origin-checked and deduplicated like anything else, and a
     * REPLAYED burst is the worst case this phase has. G9's arity check is not
     * applied to these five -- their shapes are five different shapes and the
     * format is where they are stated -- so each arm validates its own, and
     * federation/burst.c owns that because federation/burst.c is where the wire
     * format is. */
    if (fed_burst_verb(m->command) != 0) {
        (void)fed_burst_apply(s, link, m);
        return;
    }

    /* SQUIT, and the same placement argument one paragraph up: it names no
     * channel, so INBOUND's position-indexed read cannot reach it, and it is
     * asked HERE -- after the burst family and before the table -- so that
     * everything above still applies to it. That is the load-bearing part. A
     * SQUIT is the most state-destroying line in 4.3, and it is deduplicated
     * (G7), hop-checked (G5) and own-origin-checked (G6) by the same chain as an
     * SJOIN, which is why it is here and not in a second entry point. */
    if (strcmp(m->command, "SQUIT") == 0) {
        /* The same local array the table arms below use, and for the same reason
         * (message_t::params is `char *[]` and the handler takes a qualified
         * one). It is filled here rather than handed over as `m->params` because
         * the handler reads up to two entries and the wire can carry fifteen. */
        for (int i = 0; i < m->nparams && i < IRC_MAX_PARAMS; i++) {
            sp[i] = m->params[i];
        }
        fed_in_squit(s, link, &tags, sp, m->nparams);
        return;
    }

    idx = inbound_index(m->command);
    if (idx < 0) {
        if (is_deferred(m->command) != 0) {
            s->n_fed_verb_deferred++;
            printf("[observable] fed_verb_deferred: fd=%d peer=%s command=%s\n",
                   c->fd, link->name, m->command);
            return;
        }
        s->n_fed_unknown_verb++;
        printf("[observable] fed_unknown_verb: fd=%d command=%s peer=%s\n", c->fd,
               m->command, link->name);
        return;
    }

    /* --- G9: arity and fields -------------------------------------------- */
    /* Every field is validated with the SAME rule the local surface uses, and
     * that is the point rather than a detail: a nickname arrives here from a
     * network for the first time, and 2.1's charset exists because later phases
     * build on it. chan_remote_add() applies it to the nickname and the 2.4
     * grammar to the server name, so the roster cannot hold a name this node
     * could not qualify or render. */
    if (m->nparams < INBOUND[idx].min || m->nparams > INBOUND[idx].max) {
        s->n_fed_malformed++;
        printf("[observable] fed_malformed: fd=%d command=%s field=arity "
               "nparams=%d want=%d..%d\n",
               c->fd, m->command, m->nparams, INBOUND[idx].min, INBOUND[idx].max);
        return;
    }
    /* --- G10: the handler -------------------------------------------------- */
    if (INBOUND[idx].vclass == FANOUT_MESSAGE) {
        /* The message verbs name the TARGET first, and there is nothing to
         * create: a SPRIVMSG does not prove a channel exists, it only says
         * somebody spoke in it. A channel this node does not hold is the
         * ordinary "not a member of my mesh" case, counted as malformed rather
         * than created, because creating a channel from a message would let any
         * peer invent channels on this node by talking in them.
         *
         * fanout_resolve() is asked with a NULL sender: the numerics it would
         * send have no client to go to, and asking for one would put a non-zero
         * on the counter server.h says should be zero forever. It is still the
         * one resolver, and `t.vclass` is still what it decides the row from. */
        if (fanout_resolve(s, NULL, m->params[0], FANOUT_MESSAGE, &t) == 0) {
            s->n_fed_malformed++;
            printf("[observable] fed_malformed: fd=%d command=%s field=target "
                   "target=%s reason=NO_SUCH_TARGET\n",
                   c->fd, m->command, m->params[0]);
            return;
        }
        /* The TEXT is the second parameter and it is the whole payload; the
         * target is the first and fanout_deliver() prepends t->name itself. */
        for (int i = 0; i < m->nparams - 1; i++) {
            sp[i] = m->params[i + 1];
        }
        fed_in_message(s, &t, m->prefix, &tags, INBOUND[idx].client_verb, sp,
                       m->nparams - 1);
        return;
    }
    {
        /* The state verbs name the channel in DIFFERENT PARAMETER POSITIONS --
         * first for SJOIN, second for the rest -- which is 4.3's frozen shape
         * and the reason this lookup is here rather than a single index. A
         * handler that read the wrong position would apply a state change to the
         * wrong channel, and "the wrong channel" is not a crash, it is a
         * divergence. */
        size_t at = (strcmp(m->command, "SJOIN") == 0) ? 0u : 1u;
        chan_t *ch = fed_in_channel(s, link, m->params[at],
                                    strcmp(m->command, "SJOIN") == 0);

        if (ch == NULL) {
            s->n_fed_malformed++;
            printf("[observable] fed_malformed: fd=%d command=%s field=channel "
                   "channel=%s\n",
                   c->fd, m->command, m->params[at]);
            return;
        }
        for (int i = 0; i < m->nparams; i++) {
            sp[i] = m->params[i];
        }
        if (strcmp(m->command, "SJOIN") == 0) {
            fed_in_sjoin(s, link, ch, m->prefix, &tags, sp, m->nparams);
        } else if (strcmp(m->command, "SPART") == 0) {
            fed_in_spart(s, link, ch, m->prefix, &tags, sp, m->nparams);
        } else if (strcmp(m->command, "STOPIC") == 0) {
            fed_in_stopic(s, link, ch, m->prefix, &tags, sp, m->nparams);
        } else if (strcmp(m->command, "SMODES") == 0) {
            fed_in_smodes(s, link, ch, m->prefix, &tags, sp, m->nparams);
        } else if (strcmp(m->command, "SKICK") == 0) {
            fed_in_skick(s, link, ch, m->prefix, &tags, sp, m->nparams);
        } else {
            /* Unreachable: every enumerator of INBOUND is named above, and
             * G8 is the only way here. It is a BUG REPORT rather than a silent
             * return, because a table row with no arm is a verb this node
             * advertises by handling and does not do. */
            printf("[observable] fed_unhandled_verb: command=%s\n", m->command);
        }
    }
}
