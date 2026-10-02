/* msg_verbs.c -- see msg_verbs.h. Messaging, query and status.
 *
 * Authority: docs/SERVER_DESIGN.md 3.1 (the routing, which lives in
 * core/fanout.c), 3.2 (the client-facing line cap), 4.4 (the numerics), 4.2
 * (WHO/WHOIS/ISON/AWAY) and 7/Phase 5.
 */
#include "core/msg_verbs.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "core/cap.h"
#include "core/channel.h"
#include "core/fanout.h"
#include "core/reply.h"

/* ---------------------------------------------------------------------------
 * PRIVMSG and NOTICE
 * ---------------------------------------------------------------------------
 * One implementation, two verbs, and the ONLY difference is the `exclude`
 * argument handed to fanout_deliver(). That is not a simplification for its own
 * sake: RFC 2812 3.3.2 defines NOTICE as PRIVMSG with a non-reply guarantee,
 * and the guarantee belongs in the one place that writes lines rather than in
 * two handlers that could drift.
 */

/* ---------------------------------------------------------------------------
 * PRIVMSG and NOTICE
 * ---------------------------------------------------------------------------
 * One implementation, two verbs. The echo difference is the `exclude` argument
 * handed to fanout_deliver(), and the membership difference is the one `if`
 * below; everything else -- arity, the line cap, 401, 403 -- is shared, which is
 * what makes "the two verbs behave alike except where the RFC says they must
 * not" a property of the code rather than a claim about it.
 */
static void send_message(server_t *s, conn_t *c, const message_t *m,
                         const char *verb, int is_notice)
{
    fanout_target_t t;
    char prefix[CONN_HOSTMASK_MAX];
    const char *text;
    int is_channel;
    int member;
    int delivered;

    /* Arity. RFC 2812 3.3.1 gives PRIVMSG <msgtarget> <text> and 3.3.2 gives
     * NOTICE the same two. A third parameter is not text the client meant to
     * send -- the grammar has already absorbed everything after a ':' -- so it
     * is refused rather than guessed at, which is the same call Phase 3 made
     * for "NICK a b". */
    if (m->nparams != 2) {
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }
    text = m->params[1];

    /* The source prefix, built BEFORE resolution because it is needed to render
     * the line and because it is a precondition of the delivery rather than of
     * the lookup. conn_hostmask() is the one rendering of 2.1's identity fields
     * (RFC 2812 3.3.1 requires a client-originated message to carry the acting
     * user's hostmask), and c->host is what accept() OBSERVED -- not what USER
     * claimed. commands.c's handle_user() is why that is deliberate; this is
     * where the decision stops being internal and becomes visible to a third
     * party reading the wire. */
    if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
        (void)reply(s, c, "404", NULL, 0, "Cannot send: unrenderable source");
        return;
    }

    /* 3.2's client-facing cap, applied to the TEXT rather than discovered by a
     * failed render. See fanout_line_fits(): a render failure inside reply() is
     * a refusal counted on n_reply_refused, which reply.c documents as a bug
     * report and not a metric, and a client that sent a long message is not a
     * bug. It is a limit, and a limit answers with a numeric. */
    if (fanout_line_fits(prefix, verb, m->params[0], text) == 0) {
        (void)reply(s, c, "417", NULL, 0, "Message too long to send");
        printf("[observable] msg_refused: verb=%s nick=%s reason=too_long "
               "len=%zu\n",
               verb, c->nick, strlen(text));
        return;
    }

    if (fanout_resolve(s, c, m->params[0], FANOUT_MESSAGE, &t) == 0) {
        return; /* 401 or 403 already sent */
    }
    /* A `nick@server` target: 3.1's LAST ROW, and it used to be refused here with
     * 401 because fanout_resolve() recognised the SHAPE and had no registry to
     * resolve it against -- fanout.h's FANOUT_REMOTE_USER is documented as "a row
     * deliberately not implemented" and this was the refusal that documented it.
     *
     * IT IS NOT REFUSED NOW, and the reason is that resolution now ANSWERS: a
     * target of this kind only survives fanout_resolve() when the registry says
     * that server holds the nick AND there is an ESTABLISHED link to it, so
     * everything the 401 used to cover is now covered by the two refusals inside
     * resolution, where they are precise about WHY. What is left here is a
     * `message`-class target with a route, and 3.1's row for it is "forward to
     * that server".
     *
     * THE NUMERIC STAYS OUT OF fanout_deliver(), which is the separation 3's
     * reply-path paragraph requires and the reason this deletion is safe rather
     * than a numeric that leaked onto a peer link: a numeric is a reply, a
     * forward is not, and the two live in different files so a future verb cannot
     * reach one through the other. */
    if (t.kind == FANOUT_REMOTE_USER) {
        /* The parameter list is the TEXT ALONE, with the target left to
         * fanout_deliver(): a target is a parameter of a PRIVMSG to a USER, not
         * of the forward. 3.1's row and 3.2's formatter agree on this -- the
         * S-verb's first parameter IS the target, and fanout_forward_link() puts
         * t->name there -- so passing the client's own parameters through
         * unchanged would render SPRIVMSG with the target twice. */
        const char *textp[1];

        textp[0] = text;
        fanout_deliver(s, &t, prefix, verb, textp, 1, NULL, NULL);
        return;
    }

    is_channel = (t.kind == FANOUT_LOCAL_CHANNEL ||
                  t.kind == FANOUT_REMOTE_CHANNEL);
    member = fanout_is_member(&t, c);

    /* ------------------------------------------------------------------------
     * MEMBERSHIP -- the first of the two places PRIVMSG and NOTICE differ
     * ------------------------------------------------------------------------
     * PRIVMSG to a channel the sender is not on is 404 ERR_CANNOTSENDTOCHAN,
     * not the 442 the channel verbs use. 4.4 mandates BOTH, so the choice has
     * to be argued, and the argument is that they answer different questions:
     *
     *   - 442 is "You're not on that channel": a statement about MEMBERSHIP, and
     *     the right answer for a verb that cannot do anything at all without it
     *     (PART, TOPIC, MODE, KICK -- Phase 4's usage, unchanged).
     *   - 404 is "Cannot send to channel": a REFUSAL of one specific ACTION.
     *     PRIVMSG is an action, not a standing, and it is the numeric ircd
     *     clients already special-case for messaging, so a client that follows
     *     it behaves correctly.
     *   - 3.1 makes the distinction load-bearing. PRIVMSG is `message` class,
     *     explicitly NOT a state change, and the entire reason 3.1 splits the
     *     classes is that the two are routed differently. Reusing the
     *     state-change verifier on a message-class verb would apply the rule
     *     for the class 3.1 says this is not.
     *   - Otherwise 404 would have NO producer anywhere in this node, and 4.4
     *     lists it. A numeric in the design's list that nothing can emit is a
     *     list entry that is a lie -- the same standard Phase 4 applied to a
     *     324 that disagreed with the node's actual behaviour.
     *
     * A channel that does not exist is 403 for both verbs: that is a complaint
     * about the NAME, and neither 404 nor 442 is true of it.
     */
    if (is_channel != 0 && member == 0 && is_notice == 0) {
        (void)reply(s, c, "404", (const char *const[]){ t.name }, 1,
                    "Cannot send to channel");
        printf("[observable] msg_refused: verb=%s nick=%s target=%s "
               "reason=not_on_channel\n",
               verb, c->nick, t.name);
        return;
    }

    /* ------------------------------------------------------------------------
     * AND FOR NOTICE, THAT CHECK IS SKIPPED ENTIRELY
     * ------------------------------------------------------------------------
     * RFC 1459 2.4.2 says it outright: "The NOTICE message is sent to a user or
     * channel, whether or not the sender is on the channel." Three reasons
     * that is the right reading rather than a convenient one:
     *
     *   - It is the reason NOTICE exists. A bot announcing into a channel it
     *     has not joined is the canonical use; demanding a JOIN would make the
     *     verb useless at the job it was given.
     *   - 3.1's table puts no membership precondition on a `message`. The
     *     design keeps ROUTING (3.1) and POLICY (membership) apart on purpose,
     *     and inventing a policy inside the routing table would put them back
     *     together and make 3.1 the place a verb's semantics are decided.
     *   - The hazard 2.4.2 guards against cannot arise. It is about
     *     auto-REPLY, and a NOTICE is never returned to the client that sent
     *     it -- so nothing on this path can start a loop. The same reasoning
     *     does NOT extend to a NUMERIC, which is a reply the client asked for
     *     and would be acted on: that is why an unresolvable NOTICE still gets
     *     its 401 or 403, and why those are described as replies rather than as
     *     delivery.
     *
     * So the verbs differ in two places, not one: the echo, and this. Every
     * other outcome is identical, and the tests run the same scenarios against
     * both.
     */
    /* The parameters AFTER the target: fanout_deliver() prepends t->name, which
     * is 2.2's canonical spelling rather than whatever the client typed, and
     * that substitution is the reason this function takes a list rather than a
     * single trailing string.
     *
     * The local copy is because message_t::params is `char *[]` and the
     * destination is `const char *const *`, and C will not add that
     * qualification silently to an array of pointers. There is one parameter
     * after the target in both verbs (RFC 2812 3.3.1: <msgtarget> <text>) and
     * the arity check at the top of this function has already refused anything
     * else, so the array cannot overflow. */
    {
        const char *sp[1];

        sp[0] = m->params[1];
        /* `carry` is NULL: a client sent this line, so this node is ORIGINATING
         * it and fanout_forward_sverb() mints the 2.4 identity at the forward. */
        delivered = fanout_deliver(s, &t, prefix, verb, sp, 1,
                                   (is_notice != 0) ? c : NULL, NULL);
    }
    printf("[observable] msg: verb=%s from=%s target=%s kind=%d members=%zu "
           "delivered=%d echo=%s member=%d\n",
           verb, c->nick, t.name, (int)t.kind,
           (t.chan != NULL) ? t.chan->nmembers : 0u, delivered,
           (is_notice != 0) ? "no" : "yes", member);
}

void handle_privmsg(server_t *s, conn_t *c, const message_t *m)
{
    send_message(s, c, m, "PRIVMSG", 0);
}

void handle_notice(server_t *s, conn_t *c, const message_t *m)
{
    send_message(s, c, m, "NOTICE", 1);
}

/* ---------------------------------------------------------------------------
 * WHO
 * ---------------------------------------------------------------------------
 */
/* 352 RPL_WHOREPLY's <flags>. RFC 2812 3.3.4 defines 'H' for a user who is here
 * and 'G' for one who is gone, and separately allows '@' and '+' for channel
 * operator and voice. Away therefore changes one letter and nothing else, which
 * is what lets a client render "away" out of a WHO without asking a second
 * question.
 *
 * MULTI-PREFIX APPLIES HERE TOO, and it is the reason this function takes a
 * `multiprefix` argument rather than reading the destination itself: IRCv3's
 * `multi-prefix` names BOTH 353 and 352, so answering it in one and not the other
 * would be a node that honours the capability halfway and a client that reads 353
 * as authoritative and 352 as a summary. RFC 2812 3.3.4's field is free text
 * beginning with H or G, so `@+` after that first letter is within the grammar.
 *
 * WHY IT IS A PARAMETER AND NOT `dst`: WHO is answered to one client, so the
 * answer is the same for every row of the reply, and asking per entry would ask
 * the same question once per row of a reply this node builds in a loop. The
 * question is asked once, in handle_who().
 *
 * THE COST, stated rather than left for a reader to wonder about: a client WITHOUT
 * the capability still gets one sigil here, and a member who is both op and voiced
 * is reported as the higher of the two -- a lossy answer, and the same lossy
 * answer it gets in 353 without the capability. That is what the capability is
 * for. */
static void who_flags(char *out, size_t cap, const conn_t *c, const chan_t *ch,
                      int multiprefix)
{
    size_t n = 0;

    out[0] = (c->away[0] != '\0') ? 'G' : 'H';
    n = 1u;
    if (multiprefix != 0) {
        /* INDEPENDENT TESTS, not an `else if` chain: +o and +v are
         * independent bits and an op+voice member is exactly the case the
         * capability exists for. In PREFIX order, for the reason cap.h gives. */
        if (ch != NULL && chan_has_flag(ch, c, CHAN_MEMBER_OP)) {
            out[n++] = '@';
        }
        if (ch != NULL && chan_has_flag(ch, c, CHAN_MEMBER_VOICE)) {
            out[n++] = '+';
        }
    } else if (ch != NULL && chan_has_flag(ch, c, CHAN_MEMBER_OP)) {
        out[n++] = '@';
    } else if (ch != NULL && chan_has_flag(ch, c, CHAN_MEMBER_VOICE)) {
        out[n++] = '+';
    }
    if (n >= cap) {
        n = cap - 1u;
    }
    out[n] = '\0';
}

/* One 352: <client> <channel> <user> <host> <server> <nick> <flags>
 *         :<hopcount> <realname>. `channel` is '*' for a WHO that was not about
 * a channel, which is the RFC's own placeholder and the only way a client can
 * tell the two forms apart.
 *
 * <hopcount> is 0 and 0 is true: it counts FORWARDS, and a user this node holds
 * the socket for has been forwarded nowhere. A node answering 1 here would be
 * claiming a relay that did not happen. */
static void who_entry(server_t *s, conn_t *dst, const conn_t *who,
                      const char *channel, const chan_t *ch, int multiprefix)
{
    /* Five bytes, not four: 'G' or 'H', then '@', then '+', then the NUL. The
     * fourth byte the old four-byte buffer had was room for ONE sigil, and
     * multi-prefix is two. */
    char flags[5];

    who_flags(flags, sizeof flags, who, ch, multiprefix);
    (void)reply(s, dst, "352",
                (const char *const[]){ (channel != NULL) ? channel : "*",
                                        who->user, who->host, s->name, who->nick,
                                        flags },
                6, "0 %s",
                (who->realname[0] != '\0') ? who->realname : who->nick);
}

void handle_who(server_t *s, conn_t *c, const message_t *m)
{
    const char *mask = "*";
    char canonical[CHAN_MAX_NAME + 1];
    /* ONE ANSWER FOR THE WHOLE REPLY, asked once because a WHO is answered to a
     * single client and asking per entry would ask the same question once per row
     * of a reply this node builds in a loop. See who_flags(). */
    const int multiprefix = cap_multiprefix_enabled(c);

    if (m->nparams > 1) {
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }
    if (m->nparams == 1) {
        mask = m->params[0];
    }

    if (chan_name_valid(mask)) {
        chan_t *ch;

        chan_name_upper(canonical, sizeof canonical, mask);
        ch = server_chan_get(s, canonical);
        if (ch == NULL) {
            /* 403, and 315 anyway. RFC 2812 3.3.4 lists ERR_NOSUCHCHANNEL
             * among WHO's replies precisely because "I found no users" would
             * otherwise be the only answer available, and that answer cannot
             * distinguish "no such channel" from "an empty channel". Both are
             * sent: 403 says which, 315 says the list is over. */
            (void)reply(s, c, "403", (const char *const[]){ canonical }, 1,
                        "No such channel");
            (void)reply(s, c, "315", (const char *const[]){ canonical }, 1,
                        "End of WHO list");
            return;
        }
        /* A QUERY against a channel this node does not own is answered from
         * whatever cache it holds and is never refused, for the reason
         * chan_verbs.c's authority_ok() gives: refusing to answer is not a
         * divergence risk, and a later SJOIN from the origin corrects the
         * answer. The server count below is what makes the incompleteness
         * visible rather than implied. */
        printf("[observable] who: nick=%s target=%s local=%zu servers=%zu\n",
               c->nick, ch->name, ch->nmembers, ch->nservers);
        for (size_t i = 0; i < ch->nmembers; i++) {
            if (chan_member_live(&ch->members[i]) == 0 ||
                ch->members[i].c->nick[0] == '\0') {
                continue;
            }
            who_entry(s, c, ch->members[i].c, ch->name, ch, multiprefix);
        }
        (void)reply(s, c, "315", (const char *const[]){ ch->name }, 1,
                    "End of WHO list");
        return;
    }

    printf("[observable] who: nick=%s mask=%s nicks=%zu\n", c->nick, mask,
           server_nick_count(s));
    for (size_t i = 0; i < server_nick_count(s); i++) {
        conn_t *who = server_nick_at(s, i);

        if (who == NULL || who->nick[0] == '\0' || who->state == CONN_CLOSING) {
            continue;
        }
        if (fanout_mask_match(mask, who->nick) == 0) {
            continue;
        }
        who_entry(s, c, who, NULL, NULL, multiprefix);
    }
    (void)reply(s, c, "315", (const char *const[]){ mask }, 1,
                "End of WHO list");
}

/* ---------------------------------------------------------------------------
 * WHOIS
 * ---------------------------------------------------------------------------
 * 311, 312, 317, 318, and 301 when the target is away.
 *
 * 301 is NOT in 4.4's list, and the reason for using it is the one Phase 3 gave
 * for 432: the LIST has a hole, the protocol does not. RFC 2812 3.3.4 requires
 * 301 for an away user and it is the ONLY numeric that can carry the fact at
 * all -- 311 holds user/host/realname, 312 holds a server name, 317 holds two
 * timestamps, and none of them has a field for away. Without it, "WHO/WHOIS
 * reflect AWAY" -- this phase's own acceptance criterion -- is not implementable
 * and the alternative is a WHOIS that silently omits the one thing it was asked
 * about. Flagged here and in the report rather than papered over. */
void handle_whois(server_t *s, conn_t *c, const message_t *m)
{
    conn_t *who;
    char idle[24];
    char signon[24];
    long secs;
    time_t now;

    if (m->nparams != 1) {
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }
    who = fanout_find_nick(s, m->params[0]);
    if (who == NULL) {
        /* 401 and then 318. 318 is not optional: a client that asked about a
         * nick and received only 401 cannot tell "that user does not exist" from
         * "the server is still working on it", and 318 is the end-of-list marker
         * the RFC pairs with every other WHOIS reply. */
        (void)reply(s, c, "401", (const char *const[]){ m->params[0] }, 1,
                    "No such nick/channel");
        (void)reply(s, c, "318", (const char *const[]){ m->params[0] }, 1,
                    "End of /WHOIS list");
        return;
    }

    /* 311: <client> <nick> <user> <host> * :<real name>. The '*' is RFC 2812's
     * placeholder for the superseded <hostmask> field, and it is a MIDDLE
     * parameter rather than part of the trailing text. c->host is the OBSERVED
     * peer address -- the same field the message prefix renders -- so WHOIS and
     * a delivered message cannot disagree about who somebody is, and neither can
     * be moved by anything the client asserted in USER. */
    (void)reply(s, c, "311",
                (const char *const[]){ who->nick, who->user, who->host, "*" }, 4,
                "%s", (who->realname[0] != '\0') ? who->realname : who->nick);

    /* 312 names the node holding the nick, which on a single node is always us.
     * That is not a placeholder: 2.1 makes the nick table per-server, so naming
     * the server IS the honest answer, and it is what lets a client decide
     * whether a `nick@server` target is local before sending to it. */
    (void)reply(s, c, "312", (const char *const[]){ who->nick, s->name }, 2, "%s",
                IRC_SERVE_VERSION);

    if (who->away[0] != '\0') {
        (void)reply(s, c, "301", (const char *const[]){ who->nick }, 1, "%s",
                    who->away);
    }

    /* 317: <idle> <signon>, both real values. conn_t records them at accept and
     * on every read (see connection.c), so neither number is a placeholder --
     * which is the standard Phase 4 set for 329, where borrowing topic_when
     * would have been "a numeric that lies about what it is". */
    now = time(NULL);
    secs = (long)(now - who->last_active);
    if (secs < 0) {
        secs = 0; /* a clock that went backwards reports 0, never a negative */
    }
    (void)snprintf(idle, sizeof idle, "%ld", secs);
    (void)snprintf(signon, sizeof signon, "%lld", (long long)who->signon_at);
    (void)reply(s, c, "317", (const char *const[]){ who->nick, idle, signon }, 3,
                "seconds idle");

    (void)reply(s, c, "318", (const char *const[]){ who->nick }, 1,
                "End of /WHOIS list");
    printf("[observable] whois: by=%s nick=%s host=%s away=%d\n", c->nick,
           who->nick, who->host, (who->away[0] != '\0') ? 1 : 0);
}

/* ---------------------------------------------------------------------------
 * ISON
 * ---------------------------------------------------------------------------
 * 303, and nothing else. A nickname this node does not hold is simply ABSENT
 * from the list, and that absence IS the answer: there is no numeric for "that
 * user is not online", and inventing one would turn a set query into a run of
 * errors, which is how an ISON of fifty nicks becomes fifty lines of noise on a
 * network where one of them happens to be away.
 *
 * 303 is not in 4.4's list either -- it names "311-319" for queries and 303 is
 * below that range -- and it is the same gap 301 is: RFC 2812 3.3.4 defines 303
 * as the reply to ISON, and nothing else is a reply to it.
 *
 * The nickname list is CHUNKED at REPLY_MAX_MID rather than refused past that
 * point. The wire grammar caps a message at IRC_MAX_PARAMS and the client itself
 * holds one of those slots, so a single 303 can carry at most 13 nicknames, and
 * reply() refuses a longer one outright. RFC 1459 2.4.3 anticipates exactly
 * this: a client MAY ask about more nicknames than fit in one reply, and the
 * server reports those it can. Refusing the whole command past 13 would be worse
 * than splitting it, because the caller could not tell a refusal from an answer
 * that happened to be empty. */
void handle_ison(server_t *s, conn_t *c, const message_t *m)
{
    /* Sized by the WIRE, not by the reply. The parser accepts up to
     * IRC_MAX_PARAMS parameters, so an ISON may name 15 nicknames, and a 303
     * may carry only REPLY_MAX_MID of them. Sizing this array to REPLY_MAX_MID
     * and then writing however many were found is a one-line buffer overflow on
     * a perfectly ordinary command -- `ISON a b ... o` with fourteen nicks this
     * node holds -- and it is exactly the kind of defect the two sizes being
     * different is meant to prevent. */
    const char *found[IRC_MAX_PARAMS];
    size_t nfound = 0;
    size_t nout = 0;

    if (m->nparams < 1 || m->nparams > (int)(sizeof found / sizeof found[0])) {
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }

    for (int i = 0; i < m->nparams; i++) {
        conn_t *who = fanout_find_nick(s, m->params[i]);

        if (who == NULL || who->nick[0] == '\0') {
            continue; /* absent from the reply: that IS this nick's answer */
        }
        found[nfound++] = who->nick;
    }

    /* At least one 303, even with nothing found: RFC 1459 2.4.3 is explicit
     * that an empty 303 is the answer when no nickname matches, and silence
     * would be indistinguishable from a dropped command. */
    do {
        size_t batch = nfound - nout;
        const char *const *slice = (batch > 0u) ? (found + nout) : NULL;

        if (batch > (size_t)REPLY_MAX_MID) {
            batch = (size_t)REPLY_MAX_MID;
        }
        (void)reply(s, c, "303", slice, batch, "are online");
        nout += batch;
    } while (nout < nfound);

    printf("[observable] ison: by=%s asked=%d online=%zu\n", c->nick, m->nparams,
           nfound);
}

/* ---------------------------------------------------------------------------
 * AWAY
 * ---------------------------------------------------------------------------
 * `AWAY :message` sets, bare `AWAY` clears. The bound is CONN_MAX_AWAY and an
 * over-long message is REFUSED with 417, leaving the previous state exactly as
 * it was; the argument is on the constant, and it is 3.2's argument for a
 * message that will not fit on the wire -- delivering a shortened parameter is
 * delivering something the user did not write.
 *
 * 417 is the third hole in 4.4's numeric list, for the same reason as 301 and
 * 303: the list has a gap rather than the protocol doing so. RFC 2812 3.3.1
 * defines 417 ERR_INPUTTOOLONG and every client understands it, while 4.4's own
 * candidates are all false here -- 461 says "you did not send enough", and the
 * client sent exactly what it meant to.
 *
 * 305 and 306 are not in 4.4 either, and this one is not a close call. A
 * state-changing command that answers nothing leaves a client unable to tell
 * success from a dropped line, which is precisely the silence 4.4's numerics
 * exist to prevent; Phase 4's 472, 474, 696 and 368 took the same decision for
 * the same reason. */
void handle_away(server_t *s, conn_t *c, const message_t *m)
{
    const char *message;
    size_t len;

    if (m->nparams > 1) {
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }

    if (m->nparams == 0 || m->params[0][0] == '\0') {
        /* Bare AWAY, and `AWAY :` which parses to one empty parameter. Both
         * mean "not away": RFC 1459 2.4.2 has no separate syntax for clearing,
         * so a client that sends an empty trailing parameter means exactly what
         * a client that sends none does. */
        c->away[0] = '\0';
        (void)reply(s, c, "305", NULL, 0, "You are no longer marked as being away");
        printf("[observable] away: nick=%s state=clear\n", c->nick);
        return;
    }

    message = m->params[0];
    len = strlen(message);
    if (len > (size_t)CONN_MAX_AWAY) {
        (void)reply(s, c, "417", NULL, 0, "Away message is too long");
        printf("[observable] away: nick=%s state=refused reason=too_long "
               "len=%zu max=%d\n",
               c->nick, len, CONN_MAX_AWAY);
        return;
    }

    memcpy(c->away, message, len + 1u);
    (void)reply(s, c, "306", NULL, 0, "You have been marked as being away");
    printf("[observable] away: nick=%s state=set len=%zu\n", c->nick, len);
}

/* ---------------------------------------------------------------------------
 * USERHOST
 * ---------------------------------------------------------------------------
 * 4.2's USERHOST, RFC 2812 3.3.4: "used to return a list of matches between the
 * given <nickname> parameters and the nicknames of users on the server. Users
 * are listed in the following format: <nickname> [+|*] [<user>@]<host>."
 *
 * ONE 302 PER NICKNAME, and each is a single-parameter answer to a
 * single-parameter question. The alternative -- one 302 carrying every answer,
 * which is how a batching client would want it -- is not the RFC's shape and
 * 4.4 does not have a numeric for it.
 *
 * ---------------------------------------------------------------------------
 * 302 IS THE FOURTH HOLE IN 4.4's LIST, and the same gap as 301, 303 and 417
 * ---------------------------------------------------------------------------
 * 4.4 enumerates "query `311`-`319`" and 302 is below that range, so the list
 * has a hole where the protocol does not. RFC 2812 3.3.4 defines 302
 * RPL_USERHOST as the reply to USERHOST and nothing else is a reply to it, so
 * 302 is used and the discrepancy is flagged here and in the report, exactly as
 * Phase 5 flagged 301, 303 and 417 rather than inventing a numeric.
 *
 * The trailing text is a SECOND COPY of the same value the middle parameter
 * carries, which is the RFC's wire form and the reason both are filled: real
 * clients read a 302 by position and the two positions are documented to be
 * equal. A one-parameter 302 would be a line whose meaning depends on which end
 * a reader happened to look at.
 *
 * WHAT THE WIRE ACTUALLY LOOKS LIKE, because it is not what the RFC's notation
 * suggests. RFC 1459 2.3.2 writes `:<parameter>` for the trailing one, and every
 * RFC in the family writes 302 as `302 <client> <reply> :<reply>` -- but 2.3.1's
 * actual rule is that the LAST parameter is the trailing one whether or not it
 * was colonned, and 3.2's formatter colons a value only when it has to (empty,
 * leading ':', or holding a separator). A `<nick>+<user>@<host>` value needs
 * none of those, so the line on the wire is
 *
 *     :<server> 302 <client> <nick>+<user>@<host> <nick>+<user>@<host>
 *
 * with NO colon before the second copy. Both parameters are the value; a client
 * reading it positionally -- which is every client -- is unaffected, and a test
 * that writes the colon into its needle will wait for a byte this node
 * deliberately does not send. test_queries.c records the same thing about 301 and
 * the AWAY message.
 *
 * ---------------------------------------------------------------------------
 * THE `*` PREFIX, AND WHY IT CANNOT CHANGE THE ANSWER ON THIS BUILD
 * ---------------------------------------------------------------------------
 * RFC 2812 3.3.4: "If the <nickname> parameter begins with a '*' then only those
 * users who have set a user mode to be invisible will be returned."
 *
 * This node has no user modes. 004 advertises a user-mode set of "i" and MODE
 * evaluates none of it -- `MODE <nick> +i` reaches handle_mode() and is refused
 * with 472, because a user is not a channel -- so the set of invisible users is
 * EMPTY and the honest answer to `USERHOST *bob` is that bob is not in it.
 *
 * That is answered with the '*' branch, not with a special case, and the reason
 * is that '*' is the RFC's own marker for "not on this server in the sense you
 * asked about". Using the marker rather than inventing a third outcome is what
 * keeps this ONE code path instead of two, and a client cannot tell the two
 * apart anyway: both say "not here". What it CAN tell apart is the case this
 * refuses to fake -- a node that answered `USERHOST *bob` with the '+' form
 * would be claiming a user is invisible, and this node has no way to know.
 *
 * THE ABSENCE OF A USER IS ALSO REPORTED, as `<nick>*` rather than by staying
 * silent. There is no numeric for "that nickname is not connected" in USERHOST's
 * reply set, the same reason 303 omits an offline nickname rather than erroring
 * on it, and a client that asked about a specific name needs the name back to
 * know the question was answered. Every parameter therefore produces exactly one
 * 302 and no parameter produces a 401.
 *
 * The host is the OBSERVED one, for the reason it is in 311 and 352 and in the
 * message prefix: c->host is what accept() saw, and nothing a client asserted in
 * USER moves it (see commands.c's handle_user()).
 */
void handle_userhost(server_t *s, conn_t *c, const message_t *m)
{
    size_t online = 0;

    if (m->nparams < 1) {
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }

    for (int i = 0; i < m->nparams; i++) {
        const char *arg = m->params[i];
        /* A bare '*' is not the invisibility prefix: there has to be something
         * after it for the prefix to mean anything, and `USERHOST *` asks about
         * a nickname called "*", which no client can hold. */
        int want_invisible = (arg[0] == '*' && arg[1] != '\0');
        const char *want = want_invisible ? arg + 1 : arg;
        conn_t *who = fanout_find_nick(s, want);
        /* nick + '+' + user + '@' + host + NUL, which is CONN_HOSTMASK_MAX with
         * '!' replaced by '@' -- the two bounds are the same expression of the
         * three struct widths, so raising conn_t::nick, ::user or ::host cannot
         * leave this buffer one byte short. */
        char nuh[CONN_HOSTMASK_MAX];

        if (who == NULL || want_invisible) {
            /* See the header comment: the `*` branch covers BOTH "no such user"
             * and "asked about a user that is not invisible", and they are the
             * same answer because this node has no invisibility.
             *
             * An empty name has nothing to repeat, so it gets the bare marker.
             * The alternative -- "%s*" with an empty name -- renders "**", and
             * while that is technically "the name you asked about, marked
             * absent" for a name that does not exist, it reads as a two
             * character answer to a question about a zero character one. */
            if (want[0] == '\0') {
                (void)snprintf(nuh, sizeof nuh, "*");
            } else {
                (void)snprintf(nuh, sizeof nuh, "%s*", want);
            }
        } else {
            (void)snprintf(nuh, sizeof nuh, "%s+%s@%s", who->nick, who->user,
                           who->host);
            online++;
        }
        (void)reply(s, c, "302", (const char *const[]){ nuh }, 1, "%s", nuh);
    }
    printf("[observable] userhost: by=%s asked=%d online=%zu umodes=0\n", c->nick,
           m->nparams, online);
}
