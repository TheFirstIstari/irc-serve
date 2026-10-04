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

#include "core/account.h"
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
    conn_t *exclude;

/* Arity. RFC 2812 3.3.1 gives PRIVMSG <msgtarget> <text> and 3.3.2 gives
     * NOTICE the same two. A third parameter is not text the client meant to
     * send -- the grammar has already absorbed everything after a ':' -- so it is
     * refused rather than guessed at, which is the same call Phase 3 made for
     * "NICK a b".
     *
     * `MSG_MAX_TARGETS + 1` rather than a written 2, because 005 advertises
     * `MAXTARGETS=` from the same number (msg_verbs.h) and two spellings of it
     * is one too many. */
    if (m->nparams != MSG_MAX_TARGETS + 1) {
        (void)reply_refused(s, c, verb, "INVALID_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
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
        (void)reply_refused(s, c, verb, NULL, "417", NULL, 0, "Message too long to send");
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
        /* NO echo-message GATE HERE, and the omission is deliberate rather than a
         * gap: 3.1's last row is "forward to that server", so the target has no
         * local destination at all and there is nobody on this node to send an
         * acknowledgement to. A negotiating client whose PRIVMSG went to
         * `bob@irc.b` gets no copy back, and the honest reason is that the
         * acknowledgement would have to be a local-only emission invented here for a
         * user who is not here. SPEC_TRACKING 10.7 records it. */
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
    /* ------------------------------------------------------------------------
     * `exclude`, AND IT IS DECIDED HERE AND NOWHERE ELSE
     * ------------------------------------------------------------------------
     * `exclude` is the sender for a verb whose RFC rule says it must not see its
     * own message, and NULL when it must. RFC 2812 3.3.2 defines NOTICE that way
     * and nothing else does, so before IRCv3's `echo-message` the whole expression
     * was `(is_notice != 0) ? c : NULL`.
     *
     * WHAT `echo-message` CHANGES, AND WHY IT IS NOT A SECOND DELIVERY. The
     * specification says a server MUST send PRIVMSG and NOTICE back to the client
     * that sent them, and its own example --
     *
     *     --> PRIVMSG Attila :hi
     *     :example!ex@example.com PRIVMSG Attila :hi
     *
     * -- is BYTE-IDENTICAL to what this node's normal path has produced for a
     * channel PRIVMSG since Phase 5, because `fanout.c`'s write_to_members() writes
     * to every live local member INCLUDING the author, and `exclude` has been NULL
     * for PRIVMSG for exactly that reason. The copy the specification asks for is
     * already on the wire. What is NOT already on the wire is a sender's own NOTICE,
     * which 2.4.2 takes away and which `echo-message` -- for a client that negotiated
     * it -- puts back.
     *
     * SO THE IMPLEMENTATION IS THIS ONE ARGUMENT. There is no second call to
     * fanout_deliver(), no second emission, and therefore no way for one message to
     * arrive twice: a node that "implemented" this by sending an acknowledgement
     * after the normal delivery would deliver EVERY message from every negotiating
     * client twice, which is the bug the capability exists to remove reached from the
     * other side. One delivery, one 2.4 stamp minted above fanout's switch, one
     * `msgid` shared by the sender and every other recipient.
     *
     * IT IS PER DESTINATION IN THE SENSE THAT MATTERS, which is that the decision
     * is about THIS connection's own capability rather than about the target or
     * about the node. Two members of one channel, one with the capability and one
     * without, get different audiences out of the same emission -- which is why the
     * `echo=` field on the observable line below reports the decision that was
     * actually taken rather than re-deriving it from the verb.
     *
     * `nick@server` IS NOT COVERED, and that is a named limit rather than an
     * oversight: 3.1's last row is forward-only, so the target has no local
     * destination and there is nobody here to send an acknowledgement to. Building
     * one would be inventing a local emission for a target that does not exist on
     * this node. The branch above returns before this one, and it is commented. */
    /* `labeled-response`'s ONE EXCEPTION, decided HERE and only here: "When a client
     * sends a message to itself, the server MUST NOT include the label tag." A message
     * ADDRESSED to itself is a resolved local user target that IS the sender -- and this
     * is the only place in the tree that knows both the resolved target and the sender,
     * because `reply.c`'s one queueing site knows the line and the destination and has no
     * third thing.
     *
     * IT IS SET FOR EVERY MESSAGE, not only for the self-addressed one, because it is a
     * property of the command in flight: clearing it here and setting it here means no
     * other handler has to know the field exists. The first version of `label.c` decided
     * this by comparing the emitted line's PREFIX against the destination's hostmask,
     * which is a source test rather than a target test -- so it withheld the label from
     * the echo-message copy of a CHANNEL message too, and a labelled `PRIVMSG #chan` came
     * back unlabelled followed by an `ACK`. */
    c->label_self = ((t.kind == FANOUT_LOCAL_USER) && (t.user == c)) ? 1 : 0;
    exclude = ((is_notice != 0) && (cap_echo_message_enabled(c) == 0)) ? c : NULL;
    {
        const char *sp[1];

        sp[0] = m->params[1];
        /* `carry` is NULL: a client sent this line, so this node is ORIGINATING
         * it and fanout_forward_sverb() mints the 2.4 identity at the forward. */
        delivered = fanout_deliver(s, &t, prefix, verb, sp, 1, exclude, NULL);
    }
    printf("[observable] msg: verb=%s from=%s target=%s kind=%d members=%zu "
           "delivered=%d echo=%s member=%d\n",
           verb, c->nick, t.name, (int)t.kind,
           (t.chan != NULL) ? t.chan->nmembers : 0u, delivered,
           (exclude != NULL) ? "no" : "yes", member);
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
        (void)reply_refused(s, c, "WHO", "TOO_MANY_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
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
 * 319 RPL_WHOISCHANNELS
 * ---------------------------------------------------------------------------
 *   :<server> 319 <client> <nick> :<sigil><channel> <sigil><channel> ...
 *
 * RFC 2812 5.1 gives the field list as "<nick> :*( ( "@" / "+" ) <channel> " " )",
 * so the NICK is a MIDDLE parameter and the channel run is the trailing one, and
 * the grammar has three states per channel: '@' for an operator, '+' for a voice,
 * and nothing at all for neither. It is a three-way choice rather than two
 * independent sigils -- the same "op wins over voice" rendering 353 does without
 * `multi-prefix`, and for the same reason: the grammar has one slot.
 *
 * ONE SIGIL, HIGHEST FIRST. '@' when the user holds CHAN_MEMBER_OP, else '+'
 * when it holds CHAN_MEMBER_VOICE, else nothing. That is RFC 2812 3.3.4's own
 * rule for 319 as well as 353 ("The '@' and '+' characters next to the channel
 * name indicate whether a client is a channel operator or has been granted
 * permission to speak"), and it is deliberately NOT this node's `multi-prefix`
 * behaviour: 319 has no capability that widens it, and rendering "@+" here would
 * be outside the grammar rather than a richer answer inside it.
 *
 * THE WALK IS OVER `who->chans` -- THE SUBJECT'S OWN MEMBERSHIP LIST, not the
 * destination's and not the channel registry. That is the difference between
 * answering "where is this person" and answering "where am I", and it is the
 * whole content of this numeric. `conn_t::chans` is the second of 2.2's two
 * membership lists and it is maintained by channel.c's join/leave on both the
 * local and the remote side, so a user learned from an SJOIN is reported here
 * exactly as a local member is.
 *
 * WHY THIS WAS THE ONE REAL GAP IN handle_whois(). Until this phase the handler
 * emitted 311, 312, 301 and 317 and then 318, and every one of those answers a
 * question about a person -- who they are, where they are connected, whether
 * they are away, when they signed on. NONE of them says where they are. A
 * `away-notify` client could learn that a friend went away and could not learn
 * where to find them; a client that had not negotiated `away-notify` could not
 * learn either. The claim that WHOIS "reflects" the node's state was true of
 * every field except the one a client uses WHOIS for.
 *
 * IT IS ALSO WHAT MAKES `away-notify`'s OWN DOCUMENTED PROMISE TRUE. The
 * specification's reason for excluding the setter from the notification is that
 * "they can rely on RPL_NOWAWAY and RPL_UNAWAY" -- and the comment above
 * notify_away() says the same. Those two numerics tell the SETTER their own
 * state; they tell nobody else where that person is, which is the question a
 * third party actually has after seeing the notification. 319 is the answer to
 * that question, and without it the notification reported a state change with
 * no way to act on it.
 *
 * CHUNKED AT `WHOIS_CHANNELS_LINE`, and RFC 2812 3.3.4 sanctions it in the same
 * sentence that defines the numeric: "For each reply set, only
 * RPL_WHOISCHANNELS may appear more than once (for long lists of channel
 * names)." Without the chunk a user in nine channels would produce a trailing
 * value reply() REFUSES rather than reshapes -- which is a refusal on
 * `n_reply_refused`, the counter reply.c holds at zero because a non-zero value
 * is a bug report. One entry can never be longer than WHOIS_CHANNELS_LINE (see
 * the constant), so the "flush before append" guard is sufficient and no single
 * channel can overflow the buffer.
 *
 * NOTHING AT ALL WHEN THE USER IS IN NO CHANNELS, and that is a real decision
 * rather than an omission. An empty 319 would be a line whose only content is a
 * nick, and a client that renders "is in:" for every WHOIS would print a
 * dangling label for every user who happens not to be in a channel -- which on
 * this node is every client until it joins one. Absence is the RFC-conventional
 * "none", and it is the same reasoning 330's absence uses for "no account".
 * The cost is that a client cannot distinguish "no channels" from "a node too
 * old to answer", which is the cost every absence on this node already pays.
 */
#define WHOIS_CHANNELS_LINE 400

static void send_whois_channels(server_t *s, conn_t *dst, const conn_t *who)
{
    char line[WHOIS_CHANNELS_LINE + 1];
    size_t used = 0;
    int lines = 0;

    for (size_t i = 0; i < who->nchans; i++) {
        const chan_t *ch = who->chans[i];
        const char *sigil;
        size_t slen;
        size_t nlen;

        if (ch == NULL || ch->name[0] == '\0') {
            continue; /* a chan_t this node no longer holds: nothing to name */
        }
        if (chan_has_flag(ch, who, CHAN_MEMBER_OP) != 0) {
            sigil = "@";
        } else if (chan_has_flag(ch, who, CHAN_MEMBER_VOICE) != 0) {
            sigil = "+";
        } else {
            sigil = "";
        }
        slen = strlen(sigil);
        nlen = strlen(ch->name);
        /* One entry is at most strlen("@") + CHAN_MAX_NAME (63) = 64 bytes, plus
         * the joining space, which is inside WHOIS_CHANNELS_LINE with room to
         * spare. That is what makes the `used != 0u` guard below sufficient: a
         * line is only flushed when it already holds something, so the append
         * that follows is always of a value known to fit. */
        if (used != 0u && used + slen + nlen + 1u > WHOIS_CHANNELS_LINE) {
            (void)reply(s, dst, "319", (const char *const[]){ who->nick }, 1, "%s", line);
            lines++;
            used = 0;
        }
        if (used != 0u) {
            line[used++] = ' ';
        }
        memcpy(line + used, sigil, slen);
        used += slen;
        memcpy(line + used, ch->name, nlen);
        used += nlen;
        line[used] = '\0';
    }
    if (used != 0u) {
        (void)reply(s, dst, "319", (const char *const[]){ who->nick }, 1, "%s", line);
        lines++;
    }
    printf("[observable] whois_channels: by=%s nick=%s chans=%zu lines=%d\n",
           dst->nick, who->nick, who->nchans, lines);
}

/* ---------------------------------------------------------------------------
 * WHOIS
 * ---------------------------------------------------------------------------
 * 311, 312, 319, 317, 318, plus 301 when the target is away and 330 when it is
 * identified. RFC 2812 3.3.4's own order is 311, 312, 313, 319, 317, 318, and
 * this is that order with 313 absent (there are no IRC operators -- 258 says so)
 * and 301/330 inserted next to the fact they carry: 301 with 319 because away and
 * presence are what a client reads together, and 330 after 317 because it is
 * supplementary.
 *
 * 301 and 319 and 330 are all NOT in 4.4's list, and the reason for using them
 * is the one Phase 3 gave for 432: the LIST has a hole, the protocol does not.
 * For 301 the RFC is not optional -- RFC 2812 3.3.4 requires it for an away user
 * and it is the ONLY numeric that can carry the fact at all: 311 holds
 * user/host/realname, 312 holds a server name, 317 holds two timestamps, and none
 * of them has a field for away. For 319 the same argument is stronger still,
 * because nothing else in the reply set names a channel at all. Flagged here and
 * in the conformance document rather than papered over.
 */
void handle_whois(server_t *s, conn_t *c, const message_t *m)
{
    conn_t *who;
    char idle[24];
    char signon[24];
    long secs;
    time_t now;

    if (m->nparams != 1) {
        (void)reply_refused(s, c, "WHOIS", "INVALID_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
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

    /* 319 BEFORE 317, because that is RFC 2812 3.3.4's order (311, 312, 313, 319,
     * 317, 318) and because a client reading a WHOIS left to right reads "who,
     * where from, away, where, idle" and 319 is the "where". See
     * send_whois_channels() for the grammar and the chunking argument. */
    send_whois_channels(s, c, who);

    /* ------------------------------------------------------------------------
     * 317: <idle> <signon>, both real values. conn_t records them at accept and
     * on every read (see connection.c), so neither number is a placeholder --
     * which is the standard Phase 4 set for 329, where borrowing topic_when
     * would have been "a numeric that lies about what it is".
     *
     * ------------------------------------------------------------------------
     * TWO MIDDLE PARAMETERS WHERE RFC 2812 3.3.4 SPECIFIES ONE, AND THE
     * TRAILING TEXT IS DELIBERATELY LEFT AT THE RFC'S OWN LITERAL STRING.
     * ------------------------------------------------------------------------
     * Both halves of that are decisions this phase took and is recording rather
     * than accidents, so here is the argument.
     *
     * THE EXTRA NUMBER. RFC 2812 5.1 writes 317 as "<nick> <integer> :seconds
     * idle" -- one number. This line carries <nick> <idle> <signon>, two. That is
     * the de-facto convention every widely deployed client parses (irssi,
     * weechat and hexchat all read two, and fall back gracefully), and it is the
     * form that makes 317 carry the signon time at all: 311 gives a real name,
     * 312 gives a server, 317 is the only place a WHOIS reply carries a
     * timestamp of any kind, and dropping <signon> to satisfy the RFC's field
     * count would delete the only signon information on the wire. The cost is
     * that a client reading 317 STRICTLY positionally against the RFC's field
     * list will find a second number where it expected the trailing parameter.
     * The mitigating fact is that <signon> is a middle parameter, not text, so
     * the trailing text stays exactly where the RFC puts it and a client that
     * reads only the trailing text is unaffected. That is the shape the whole
     * reply path is built around -- 3.2 will not format a number into a
     * non-final position -- so <signon> had to be a parameter rather than be
     * folded into the sentence.
     *
     * THE TRAILING TEXT, which is the question the phase asked and the one worth
     * being explicit about because "seconds idle, signon time" is the other
     * convention in circulation. RFC 2812 3.3.4 makes the trailing parameter
     * free text, so BOTH strings are conformant, and the choice between them
     * cannot be made on conformance grounds. It is left as "seconds idle" for
     * three reasons, in descending order of weight:
     *
     *   1. It is the RFC's OWN literal string for this numeric. A client whose
     *      numeric table carries the RFC's text matches this line byte for byte,
     *      and would not match a rewritten sentence. When two forms are equally
     *      legal, the one that is the specification's literal is the one that
     *      cannot lose.
     *   2. Clients do not read it. Every client that matters dispatches 317 on
     *      the NUMERIC and reads the middle parameters by position; none parses
     *      the trailing text of 317, because the numeric exists to carry two
     *      numbers and the text is decoration. Changing decoration that nothing
     *      reads buys no compatibility.
     *   3. An anchored match is the only consumer the rewrite would help, and
     *      anchored matches break. A client, script or log parser anchored on
     *      ":seconds idle" -- a suffix, not a substring -- is a real thing in
     *      the wild, and "seconds idle, signon time" does not satisfy it. The
     *      rewrite trades a hypothetical reader who reads decoration for a
     *      concrete reader who matches it.
     *
     * The observation behind the question -- that a line carrying two numbers
     * reads oddly against a sentence describing one -- is fair, and the reason
     * it is not acted on is that the sentence is not this numeric's contract.
     * RFC 2812 3.3.4's field list is, and it is satisfied. A reader who wants
     * both numbers already has both.
     */
    now = time(NULL);
    secs = (long)(now - who->last_active);
    if (secs < 0) {
        secs = 0; /* a clock that went backwards reports 0, never a negative */
    }
    (void)snprintf(idle, sizeof idle, "%ld", secs);
    (void)snprintf(signon, sizeof signon, "%lld", (long long)who->signon_at);
    (void)reply(s, c, "317", (const char *const[]){ who->nick, idle, signon }, 3,
                "seconds idle");

    /* ------------------------------------------------------------------------
     * 330 RPL_WHOISACCOUNT, and it is the ONE wire surface the account subsystem
     * has in Phase 10.1. Read this before concluding that is the wrong scope.
     *
     * A FIFTH HOLE IN 4.4's LIST, in exactly the way 301, 303, 417 and 302 are:
     * RFC 1459 3.3.4 defines 330 as the reply carrying "<nick> <account> :is
     * logged in as", and this tree had nothing to put in <account> -- because it
     * had no account. The list has a gap and the protocol does not.
     *
     * WHY IT IS IN THIS PHASE RATHER THAN P10.2. The forbidden list for 10.1 is
     * `account-tag` EMISSION, `account-notify`, `extended-join`, `oper-tag`,
     * `chghost`, `account-extban` and `away-notify` -- all of which push an
     * identity onto a line UNSOLICITED, and all of which are what "account-tag"
     * means. 330 is not that: it answers a question the client ASKED, on a
     * connection that already registered, about a person it named. Nothing is
     * stamped on anybody's traffic.
     *
     * AND WITHOUT IT THE PASS'S CENTRAL INVARIANT HAS NO WIRE PROOF AT ALL.
     * The claim is that `account == ""` is indistinguishable from "this node has
     * no account system", and the way to show that on the wire is that a client
     * that is not logged in and a node that has no accounts produce BYTE-IDENTICAL
     * WHOIS output. That is only checkable if a logged-in client produces
     * something different, and 330 is that something. Leaving it out would mean
     * the account name exists, is set from a verified credential, is free at
     * teardown -- and is invisible to every client and every operator except as
     * one log line, which is an identity only this node can see.
     *
     * SENT ONLY WHEN THERE IS AN ACCOUNT, and the absence is the RFC-conventional
     * "not identified". That is NOT the same hazard as `account-tag`'s absent
     * tag, which the specification makes meaningful: 330's absence means "no
     * account", and on this node that is exactly and only true -- account_name()
     * returns "" precisely when the predicate is false. The two were argued
     * separately; see cap.h on why `account-tag` is withheld and this is not.
     *
     * THE COST, stated: one more line in a WHOIS for every identified user, so
     * a client that parses WHOIS positionally must find 330 by number rather
     * than by offset -- which is what the numerics are for. And it is the only
     * place a person's account name is revealed to another user, so an operator
     * who does not want that has no way to turn it off short of not loading a
     * registry. That trade is worth one sentence here rather than being left to
     * be discovered.
     */
    if (account_logged_in(who) != 0) {
        (void)reply(s, c, "330", (const char *const[]){ who->nick, account_name(who) },
                    2, "is logged in as");
    }

    (void)reply(s, c, "318", (const char *const[]){ who->nick }, 1,
                "End of /WHOIS list");
    printf("[observable] whois: by=%s nick=%s host=%s away=%d account=%d\n",
           c->nick, who->nick, who->host, (who->away[0] != '\0') ? 1 : 0,
           account_logged_in(who));
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
 * The nickname list is CHUNKED rather than refused past what one reply can carry,
 * and the bound is a BYTE count (ISON_CHUNK_MAX, below) rather than a count of
 * names, because RFC 2812 5.1 puts the whole list in one trailing parameter and
 * the thing that limits it is the size of that parameter. Refusing the whole
 * command instead would be worse than splitting it, because the caller could not
 * tell a refusal from an answer that happened to be empty. The chunking argument
 * in full is at the loop; what matters here is that a split is forced by the wire
 * and not chosen. */
/* The trailing parameter's budget, IN BYTES, and derived from the buffer that
 * refuses it rather than written out here: reply() renders the trailing text into
 * a char[REPLY_TEXT_MAX] and REFUSES a write that would reach sizeof text, so
 * REPLY_TEXT_MAX - 1 is the largest trailing parameter this node can put on the
 * wire. Raising REPLY_TEXT_MAX moves this with it.
 *
 * IT IS BYTES AND NOT A NICK COUNT, which is what conforming 303 cost. With the
 * list in middle parameters the bound was REPLY_MAX_MID -- a count -- because that
 * was the limit the renderer enforced. With the list in ONE trailing parameter the
 * limit that bites is the buffer's size, so a count would be the wrong bound and a
 * chunk of thirteen 63-byte nicknames would be refused by reply() as
 * "text_too_long", which reply.c documents as a bug report rather than a metric. */
#define ISON_CHUNK_MAX (REPLY_TEXT_MAX - 1)

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
    /* The nick list as ONE trailing parameter, NUL-terminated at `used`. + 1 is
     * the terminator and ISON_CHUNK_MAX is the most bytes reply() will render, so
     * `chunk[ISON_CHUNK_MAX]` is the last index this can write. */
    char chunk[ISON_CHUNK_MAX + 1u];
    size_t used = 0u;

    if (m->nparams < 1 || m->nparams > (int)(sizeof found / sizeof found[0])) {
        (void)reply_refused(s, c, "ISON", "INVALID_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }

    for (int i = 0; i < m->nparams; i++) {
        conn_t *who = fanout_find_nick(s, m->params[i]);

        if (who == NULL || who->nick[0] == '\0') {
            continue; /* absent from the reply: that IS this nick's answer */
        }
        found[nfound++] = who->nick;
    }

    /* RFC 2812 5.1 gives 303 exactly ONE field:
     *
     *     303 RPL_ISON  ":*1<nick> *( " " <nick> )"
     *
     * which is a TRAILING parameter holding the whole nick list, space-separated,
     * and nothing else. So the list is rendered into one trailing parameter here
     * rather than into middle parameters with a sentence after them.
     *
     * WHY THAT IS NOT COSMETIC, and why it is the opposite of 302's shape. This
     * used to send the nicks as middle parameters and the string "are online" as
     * the trailing one. 302 sends the SAME VALUE in both positions, so a client
     * reading either one gets a correct answer and the duplication is inert.
     * 303 did not: the trailing slot held a sentence, so the two readers
     * disagreed. A client written to the RFC reads the trailing parameter -- the
     * only position the RFC defines -- and gets "are online", i.e. a nick list of
     * ["are", "online"], and concludes that every nickname it asked about is
     * OFFLINE. ISON exists to answer exactly that question, so the old shape was
     * a FALSE NEGATIVE on a query numeric, not decoration: the worst failure a
     * query reply can have. Conforming also costs no compatibility, because every
     * deployed ircd sends the RFC's shape and none sends this one.
     *
     * "are online" is therefore GONE rather than moved, and it has to be: the
     * trailing parameter is the list, so appending the sentence would hand a
     * client two phantom nicks at the end of it.
     *
     * THE SPLIT ACROSS REPLIES IS NOT THE DEVIATION AND IS NOT BEING REMOVED,
     * because it cannot be. A nick list too long for one line cannot be rendered
     * in one line whatever the parameter position, so some split is forced by the
     * wire and not by a choice here. RFC 1459 2.4.3 anticipates it, and RFC 2812
     * 5.1's own prose for 366 speaks of "a series of RPL_NAMEREPLY messages". A
     * client that concatenates the chunks gets the whole list under this shape --
     * which is what concatenation is for -- whereas truncating instead would
     * report online users as offline for everyone past the cut, the same false
     * negative as the defect above. Truncation is not on the table.
     */
    do {
        chunk[0] = '\0';
        used = 0u;
        while (nout < nfound) {
            size_t len = strlen(found[nout]);
            size_t sep = (used > 0u) ? 1u : 0u; /* no leading space on the first */

            /* `used > 0u` IS LOADING-BEARING and is what makes this terminate.
             * A nickname is at most IRC_MAX_NICK (63) bytes -- conn_t::nick is
             * IRC_MAX_NICK + 1 -- and ISON_CHUNK_MAX is 511, so an EMPTY chunk
             * always has room for the nickname about to go into it. `break` is
             * therefore reachable only with a non-empty chunk, so every pass of
             * the outer loop consumes at least one nickname and nout strictly
             * increases. Without the guard an over-long nickname would break on an
             * empty chunk, emit it, and re-enter the loop with nout unmoved: an
             * infinite loop rather than a wrong reply. */
            if (used > 0u && used + sep + len > (size_t)ISON_CHUNK_MAX) {
                break;
            }
            /* THE SEPARATOR IS WRITTEN, NOT JUST SKIPPED. `sep` moves the
             * destination one byte along, and the byte it moves past is the NUL the
             * previous iteration left at `chunk[used]` -- so without this line the
             * list renders as "Bob\0carol" and `%s` reports "Bob". That is not a
             * hypothetical: it is what the first version of this loop did, and the
             * unit test that would have caught it asserts a two-nickname ISON while
             * every other 303 assertion in the suite names one nickname. */
            if (sep != 0u) {
                chunk[used] = ' ';
            }
            memcpy(chunk + used + sep, found[nout], len);
            used += sep + len;
            chunk[used] = '\0';
            nout++;
        }
        /* reply_colon(), not reply(): see the long argument above and reply.h's. A
         * ONE-nickname list contains no space, so RFC 1459's "colonned only when it
         * has to be" rule would render it bare -- and `:irc.test 303 alice Bob` is
         * byte for byte the shape the middle-parameter version sent, so the
         * conformance change would have been invisible on the most common case. */
        (void)reply_colon(s, c, "303", NULL, 0, "%s", chunk);
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
 * client sent exactly what it meant to. Since Phase 10.9 it is a `FAIL AWAY
 * ERR_INPUTTOOLONG` for a client that negotiated `standard-replies` and the same
 * 417 for one that did not; design 4.4.3 has the migration rule.
 *
 * 305 and 306 are not in 4.4 either, and this one is not a close call. A
 * state-changing command that answers nothing leaves a client unable to tell
 * success from a dropped line, which is precisely the silence 4.4's numerics
 * exist to prevent; Phase 4's 472, 474, 696 and 368 took the same decision for
 * the same reason.
 *
 * ---------------------------------------------------------------------------
 * away-notify: THE NOTIFICATION, AND WHY IT IS A SEPARATE FUNCTION
 * ---------------------------------------------------------------------------
 * `notify_away()` is called on BOTH edges of the change and is the whole of
 * `away-notify`. It walks the user's own channel list and asks `fanout.c` to tell
 * each channel's members -- and the two things it does NOT do are the interesting
 * half:
 *
 *   THE SETTER IS EXCLUDED. The specification says so directly ("Clients SHOULD
 *   NOT be sent AWAY messages to notify them of their own away status (as they
 *   can rely on RPL_NOWAWAY and RPL_UNAWAY)"), and `305`/`306` above are those
 *   two numerics. So `exclude` is the setter: a member who negotiated the
 *   capability is still not told their own state. That is `exclude` and not the
 *   gate, and the two are different questions -- the gate asks "did this
 *   destination ask?", `exclude` asks "is this the author?" -- which is why both
 *   exist and why neither is expressed with the other.
 *
 *   THE NOTIFICATION IS NOT FORWARDED. It goes out through
 *   `fanout_deliver_local_gated()`, the LOCAL-ONLY entry point, so there is no
 *   forward arm and no question about whether a peer should be told: a peer is not
 *   a client that negotiated anything, and design 3.1.1's argument for there being
 *   no gated variant of the forwarding path is exactly this case. Away STATE
 *   federates -- 4.3's SBURST carries it and a resync rebuilds it -- and a
 *   notification is not state.
 *
 * THE CLEARED CASE IS NOT AN OMISSION, and it is the half implementations get
 * wrong: `AWAY` with no message must still notify, because the notification is the
 * only thing that tells a client the user is BACK. A node that emitted the
 * notification only on the way out would leave every member believing their friend
 * was still at lunch for ever. So the notification is one call on both edges and
 * the wire shape is decided by whether the parameter list has anything in it.
 *
 * NO CHANNEL MEANS NO NOTIFICATION, and that is `c->nchans` rather than a check
 * anywhere else: the audience is "users sharing a channel", so with no channels
 * there is no audience, and the 305/306 above are the whole answer. There is no
 * loop over the connection registry here and there never will be one -- that walk
 * is `fanout.c`'s. */
static void notify_away(server_t *s, conn_t *c, const char *message)
{
    const char *params[1];
    fanout_form_t plain;
    char prefix[CONN_HOSTMASK_MAX];
    int delivered = 0;

    if (c->nchans == 0u) {
        printf("[observable] away_notify: nick=%s recipients=0 reason=NO_SHARED_CHANNEL\n",
               c->nick);
        return;
    }
    /* THE PREFIX IS THE SETTER'S OWN HOSTMASK, for the reason every server-to-client
     * line this node emits uses one: the notification NAMES who changed, and
     * `conn_hostmask()` renders it from the fields §2.1 owns -- including the
     * OBSERVED host, which USER does not touch. */
    if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
        printf("[observable] away_notify: nick=%s reason=UNRENDERABLE\n", c->nick);
        return;
    }
    /* THE TWO SHAPES, AND NOTHING ELSE. With a message the line carries it as the
     * trailing parameter (`:nick!user@host AWAY #chan :message`); without one the
     * parameter list is EMPTY and the line is `:nick!user@host AWAY #chan`, which
     * is what "the user is removing their away state" looks like on the wire. A
     * third shape -- an empty string in the parameter list -- would render as
     * `AWAY #chan :`, and 3.2 says an empty value is not representable in a
     * non-final position, so the formatter would refuse the whole line rather than
     * sending it. Emptiness is expressed by ABSENCE and that is not an accident of
     * the shape. */
    plain.params = (message != NULL) ? params : NULL;
    plain.nparams = (message != NULL) ? 1 : 0;
    if (message != NULL) {
        params[0] = message;
    }

    /* ONE FANOUT CALL PER CHANNEL, and the walk is over `c->chans` -- the
     * connection's own membership, which 2.2 keeps as a second list beside the
     * channel's for exactly this kind of teardown-and-notification use. Each
     * channel is resolved through `fanout_resolve()` rather than looked up in the
     * registry, because resolution is the only place that answers "is this a
     * channel" and a caller that went around it would have to answer the question
     * a second way. The class is `message`: this is not a state change, it is an
     * observation, and the class decides the forward arm -- which the local-only
     * entry point does not have. */
    for (size_t i = 0; i < c->nchans; i++) {
        fanout_target_t t;

        if (c->chans[i] == NULL ||
            fanout_resolve(s, c, c->chans[i]->name, FANOUT_MESSAGE, &t) == 0) {
            continue; /* a chan_t this node no longer holds: nothing to address */
        }
        delivered += fanout_deliver_local_gated(s, &t, prefix, "AWAY", &plain, NULL,
                                                cap_gate_away_notify, NULL, c);
    }
    printf("[observable] away_notify: nick=%s channels=%zu recipients=%d state=%s\n",
           c->nick, c->nchans, delivered, (message != NULL) ? "set" : "cleared");
}

void handle_away(server_t *s, conn_t *c, const message_t *m)
{
    const char *message;
    size_t len;

    if (m->nparams > 1) {
        (void)reply_refused(s, c, "AWAY", "TOO_MANY_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }

    if (m->nparams == 0 || m->params[0][0] == '\0') {
        /* Bare AWAY, and `AWAY :` which parses to one empty parameter. Both
         * mean "not away": RFC 1459 2.4.2 has no separate syntax for clearing,
         * so a client that sends an empty trailing parameter means exactly what
         * a client that sends none does.
         *
         * AND THE NOTIFICATION FIRES ON THIS EDGE TOO, which is the half that is
         * usually missed: without it a member's client believes the user is still
         * away for ever, because the ONLY thing that tells it otherwise is the
         * parameterless `AWAY` and nothing else carries the fact. The `305` below
         * is for the user and the notification is for everybody else; neither
         * substitutes for the other. */
        c->away[0] = '\0';
        (void)reply(s, c, "305", NULL, 0, "You are no longer marked as being away");
        notify_away(s, c, NULL);
        printf("[observable] away: nick=%s state=clear\n", c->nick);
        return;
    }

    message = m->params[0];
    len = strlen(message);
    if (len > (size_t)CONN_MAX_AWAY) {
        (void)reply_refused(s, c, "AWAY", NULL, "417", NULL, 0,
                            "Away message is too long");
        printf("[observable] away: nick=%s state=refused reason=too_long "
               "len=%zu max=%d\n",
               c->nick, len, CONN_MAX_AWAY);
        return;
    }

    memcpy(c->away, message, len + 1u);
    (void)reply(s, c, "306", NULL, 0, "You have been marked as being away");
    notify_away(s, c, c->away);
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
 * before any mode is looked at, because the first parameter is canonicalised as a
 * channel name and a nickname is not one, so the refusal is 403 ERR_NOSUCHCHANNEL
 * naming the upper-cased nickname -- so the set of invisible users is EMPTY and the
 * honest answer to `USERHOST *bob` is that bob is not in it.
 *
 * (That paragraph said 472 until Phase 11's RFC 2812 sweep checked it, and it was
 * wrong: handle_mode() resolves its first parameter through canonical_channel()
 * and refuses a nickname as an unknown CHANNEL long before the mode loop, so the
 * answer is 403 and never 472. Which of the two numerics is right is a separate
 * question and an open one -- RFC 2812 3.3.2 answers a MODE naming a nickname with
 * 221 RPL_UMODEIS, or 501/502 for a change, so 403 is a category error and 472
 * would have been a different one. See docs/RFC2812_CONFORMANCE.md.)
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
        (void)reply_refused(s, c, "USERHOST", NULL, "461", NULL, 0,
                            "Not enough parameters");
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
