/* commands.c -- see commands.h. Registration, the welcome burst, the four
 * commands that need no channel and no other user, and THE DISPATCH SEAM that
 * both a client line and a peer line arrive at.
 */
#include "core/commands.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "core/chan_verbs.h"
#include "core/msg_verbs.h"
#include "core/reply.h"
#include "federation/verbs.h"

/* ---------------------------------------------------------------------------
 * THE STATE ENUM IS A PROJECTION OF TWO FACTS
 * ---------------------------------------------------------------------------
 * conn_t's shape is final as of Phase 2 (2.1), so there are no got_nick /
 * got_user flags to add and the state enum has to carry both. It can, because
 * there are four combinations and four states:
 *
 *   no nick,  no  user  ->  CONN_REG_PASS   the entry state
 *   nick,     no  user  ->  CONN_REG_NICK
 *   no nick,  user      ->  CONN_REG_USER   USER sent before NICK; the state
 *                                           exists for exactly this client
 *   nick,     user      ->  CONN_REG_READY  and the welcome burst has gone
 *
 * The underlying facts are still the fields, not the enum -- c->nick[0] and
 * c->user[0] -- so the projection is recomputed after every command rather
 * than incremented, and a client that sends its lines in an unusual order ends
 * up in the same state as one that does not. Reading it the other way round
 * ("the state counts how far it has got") is what makes a "USER before NICK"
 * client regress, and this enum has no value to regress INTO.
 *
 * PASS does not appear in the table because it is neither fact. It is
 * recorded, not remembered: see handle_pass().
 */
static int have_nick(const conn_t *c)
{
    return c->nick[0] != '\0';
}

static int have_user(const conn_t *c)
{
    return c->user[0] != '\0';
}

int commands_registered(const conn_t *c)
{
    return c != NULL && c->state == CONN_REG_READY;
}

/* ---------------------------------------------------------------------------
 * Node identity, and how much of it exists yet
 * ---------------------------------------------------------------------------
 * 005's NETWORK= and 001's wording both need a network name, and 002/004/PONG
 * need the node's own name. server_t already carries `name`, validated at
 * server_init() against the 2.4 tag grammar, so that is used directly and no
 * new field is added.
 *
 * The NETWORK name is a DEPLOYMENT property rather than a node property -- a
 * mesh has many nodes and one network name -- and a second per-server field
 * would be the first half of a server-identity system. So it is a single
 * compile-time constant here, and the honest limitation is stated rather than
 * papered over: a node serving more than one network is not expressible in
 * Phase 3, and Phase 6's server identity is where that belongs.
 */
#define NODE_NETWORK "irc-serve"

/* 004's mode tokens. THIS NODE EVALUATES NEITHER UMODES NOR CMODES -- mode
 * handling is Phase 4 and Phase 7 -- and the tokens are advertised anyway
 * because 004's wire format has no way to express an empty mode set: a
 * non-empty string is the only thing message_format() will render in a
 * middle-parameter position. The same reasoning is why 4.4 mandates
 * PREFIX=(ov)@+ and CHANTYPES=#& that no code here acts on yet -- a client
 * that does not receive those misbehaves, and a client that offers a mode this
 * node ignores gets a visible 421 rather than silent divergence. The cost is
 * stated rather than hidden: a client may offer a mode that is not honoured,
 * and the 421 it gets back is the honest answer until that phase lands. */
#define NODE_USER_MODES "i"
#define NODE_CHAN_MODES "b,k,l,imnpst"

/* NICKLEN is derived from IRC_MAX_NICK rather than typed out, so raising the
 * struct width cannot leave 005 advertising a length the node then refuses. */
#define IRC_STR_(x) #x
#define IRC_STR(x) IRC_STR_(x)

static const char *const k_005[] = {
    "NETWORK=" NODE_NETWORK,
    "CHANTYPES=#&",     /* 4.4: many real clients misbehave without it */
    "PREFIX=(ov)@+",    /* 4.4: and without this one */
    /* True, and not a detail: message.c's up() is ASCII-only, so this node does
     * NOT treat []\~ and {}|^ as equivalent. Advertising rfc1459 here would be
     * a lie a client could act on. */
    "CASEMAPPING=ascii",
    "NICKLEN=" IRC_STR(IRC_MAX_NICK)
};

/* The MOTD body, sent as one 372 per line. It describes what the node IS
 * rather than what it pretends to be: a client reading it should not be led to
 * expect channels or federation, because neither exists yet. */
static const char *const k_motd[] = {
    "- irc-serve: a federation-native IRC node.",
    "- this build answers PASS, NICK, USER, MOTD, PING, PONG and QUIT.",
    "- channels, messaging and federation are not implemented."
};

/* ---------------------------------------------------------------------------
 * 372-376: the MOTD
 * ------------------------------------------------------------------------ */

/* 003 names when this node came up, which is a fact about the boot. 3.4 says
 * handlers take their time from the tick rather than reading the wall clock,
 * and server_t::epoch cannot help: it is CLOCK_MONOTONIC milliseconds, which
 * has no calendar meaning. So this is the one deliberate wall-clock read on
 * the reply path, it is here rather than smuggled into a handler, and it is
 * read once per registration rather than once per tick. */
static void boot_stamp(char *out, size_t cap)
{
    time_t now = time(NULL);
    struct tm tm_utc;

    if (gmtime_r(&now, &tm_utc) == NULL ||
        strftime(out, cap, "%a %b %e %H:%M:%S %Y", &tm_utc) == 0) {
        (void)snprintf(out, cap, "%s", "an unknown time");
    }
}

static void send_motd(server_t *s, conn_t *c)
{
    for (size_t i = 0; i < sizeof k_motd / sizeof k_motd[0]; i++) {
        (void)reply(s, c, "372", NULL, 0, "%s", k_motd[i]);
    }
    (void)reply(s, c, "375", NULL, 0, "- Message of the day -");
    (void)reply(s, c, "376", NULL, 0, "End of /MOTD command.");
}

/* 001-005 then the MOTD, in that order, in one pass over reply(). This is the
 * first thing a client sees and the first burst this node has ever produced,
 * which is why the test asserts its bytes rather than looking for "001"
 * somewhere in the stream: a malformed numeric is worse than a missing one, and
 * clients are unforgiving about the difference. */
static void send_welcome(server_t *s, conn_t *c)
{
    char created[64];
    const char *modes_004[4];

    /* 001: the qualified name is <nick>!<user>@<host>, and `host` is the
     * OBSERVED peer address filled in at accept -- see handle_user(). A user
     * reading this line is being told where the node sees them from, not what
     * they typed. */
    (void)reply(s, c, "001", NULL, 0, "Welcome to the %s network %s!%s@%s",
                NODE_NETWORK, c->nick, c->user, c->host);
    (void)reply(s, c, "002", NULL, 0, "Your host is %s, running version %s",
                s->name, IRC_SERVE_VERSION);
    boot_stamp(created, sizeof created);
    (void)reply(s, c, "003", NULL, 0, "This server was created %s (UTC)",
                created);

    modes_004[0] = s->name;
    modes_004[1] = IRC_SERVE_VERSION;
    modes_004[2] = NODE_USER_MODES;
    modes_004[3] = NODE_CHAN_MODES;
    (void)reply(s, c, "004", modes_004, 4, "are supported by this server");

    (void)reply(s, c, "005", k_005, sizeof k_005 / sizeof k_005[0],
                "are supported by this server");

    printf("[observable] welcome: fd=%d nick=%s\n", c->fd, c->nick);
    send_motd(s, c);
}

/* Recompute the state from the two facts, and emit the welcome burst on the
 * transition into CONN_REG_READY.
 *
 * Idempotent by construction: a repeated NICK or a second USER line leaves both
 * facts true, the projection is unchanged, and nothing is re-sent. A nickname
 * CHANGE after registration also leaves both facts true, so a nick change never
 * produces a second welcome burst -- which matters, because the burst is what a
 * client uses to decide it has connected. */
static void update_state(server_t *s, conn_t *c)
{
    int state;

    if (have_nick(c) && have_user(c)) {
        state = CONN_REG_READY;
    } else if (have_nick(c)) {
        state = CONN_REG_NICK;
    } else if (have_user(c)) {
        state = CONN_REG_USER;
    } else {
        state = CONN_REG_PASS;
    }
    if (state == c->state) {
        return;
    }
    c->state = state;
    if (state == CONN_REG_READY) {
        send_welcome(s, c);
    }
}

/* ---------------------------------------------------------------------------
 * Field copies
 * ------------------------------------------------------------------------ */

/* Copy an asserted identity field into a fixed 2.1 field, truncating at the
 * struct width rather than refusing the registration.
 *
 * Truncation is a choice and it is a compromise: a realname longer than 255
 * bytes is legal on the wire and refusing it would lock out a client with a
 * long name, while storing it would need a field 2.1 does not have. So the
 * stored value is a prefix of what was asserted, and the caller is told, so it
 * can say so rather than quietly disagreeing with the client about what it
 * sent. (The nick has no such problem: valid_nick() caps it at IRC_MAX_NICK,
 * which is sizeof(conn_t::nick) - 1 by construction.) */
static void copy_field(char *dst, size_t cap, const char *src, int *trunc)
{
    size_t n = strlen(src);

    if (n >= cap) {
        n = cap - 1u;
        *trunc = 1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* ---------------------------------------------------------------------------
 * Handlers
 * ------------------------------------------------------------------------ */

/* PASS: RECORDED, NOT AUTHENTICATED.
 *
 * There is no password mechanism in this phase and no credential store to check
 * one against, so the line is acknowledged by counting it and refused by
 * nothing. A client that sends PASS with any value, including a wrong one, is
 * treated exactly like a client that sent none. That is the whole of the
 * feature and it is deliberately not dressed up as anything more: real
 * authentication is SASL, and SASL is Phase 8.
 *
 * The password is NOT logged. The count is the record -- s->n_pass_seen -- and a
 * node that printed a secret to its own stdout would leak it into every log
 * collector downstream. */
static void handle_pass(server_t *s, conn_t *c, const message_t *m)
{
    if (m->nparams < 1) {
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }
    s->n_pass_seen++;
    printf("[observable] pass: fd=%d recorded=1 authenticated=0\n", c->fd);
}

/* NICK: the one place a nickname is chosen, and the first production caller of
 * valid_nick().
 *
 * Three rejections, and they are different rejections:
 *   431  no nickname at all -- zero parameters, or one empty parameter
 *   432  a nickname that is not a legal nickname
 *   433  a legal nickname this node already holds for somebody else
 *
 * 432 is NOT in 4.4's list of error numerics, and that is a gap in the list
 * rather than a gap in the protocol: 4.4 names 431 and 433 but no numeric for
 * "the nickname you sent is malformed", and 432 ERR_ERRONEUSNICKNAME is the one
 * every client understands. Sending 433 instead would be a lie about the
 * reason -- the name is not in use, it is illegal -- and a client that retried
 * with a "different name" on a 433 would be acting on a false premise. So the
 * RFC numeric is used and the discrepancy is flagged for the design.
 *
 * 432 carries the offending nickname in the TRAILING TEXT rather than in a
 * middle parameter, which departs from the RFC's parameter order and is forced:
 * a nickname illegal enough to be refused may be empty, may start with ':', or
 * may contain a space, and a value that cannot be represented in a non-final
 * parameter position is REFUSED by the formatter rather than reshaped. Naming
 * the bad nickname in the text cannot fail, because the trailing parameter is
 * always representable.
 *
 * 433 does use the middle parameter, and safely so: the nickname got that far
 * by passing valid_nick(), so it is non-empty and cannot start with ':'. */
static void handle_nick(server_t *s, conn_t *c, const message_t *m)
{
    const char *want;
    const char *mid[1];

    if (m->nparams < 1 || m->params[0][0] == '\0') {
        (void)reply(s, c, "431", NULL, 0, "No nickname given");
        return;
    }
    if (m->nparams > 1) {
        /* Also how a nickname containing a space is refused: the wire cannot
         * express a space inside one parameter, so a client that sends
         * "NICK a b" has sent two parameters, and this is the answer it gets. */
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }
    want = m->params[0];
    if (!valid_nick(want)) {
        (void)reply(s, c, "432", NULL, 0, "Erroneous nickname: %s", want);
        printf("[observable] nick_reject: fd=%d reason=erroneous\n", c->fd);
        return;
    }

    /* Re-asserting the nickname you already hold is silent: RFC 2812 3.2 says a
     * NICK to the name you already have changes nothing and generates no error.
     *
     * Asked as a REGISTRY question rather than as `strcmp(want, c->nick) == 0`,
     * and the difference is the whole of issue #100. The registry folds case, so
     * `NICK BOB` from the client registered as `bob` is the same name -- and a
     * string comparison here would miss that, fall through to the claim, find
     * the name already held by this very connection, and answer 433 to a client
     * for the nickname it already holds. Asking the registry also keeps this
     * correct for the same reason the fix lives there: the definition of "the
     * same nickname" is a property of the table, so there is no second copy of
     * the rule here to fall out of step with it. */
    if (server_nick_lookup(s, want) == c) {
        return;
    }
    if (server_nick_claim(s, want, c) != 0) {
        /* The incumbent keeps it: server_nick_claim() is a lookup-and-insert,
         * so the loser never displaces the holder, and nothing here writes to
         * the holder's conn. */
        mid[0] = want;
        (void)reply(s, c, "433", mid, 1, "Nickname is already in use");
        printf("[observable] nick_reject: fd=%d reason=in_use\n", c->fd);
        return;
    }

    /* The new name is ours, so the old one can go. Released only AFTER the new
     * claim succeeded: releasing first would leave a window in which the name
     * is unowned and a second client could take it.
     *
     * The order is also what makes the enumeration survive a rename. A claim
     * adds an entry for a connection not already in the vector, and a release
     * removes one only from a connection left holding no name at all -- so at
     * this instant the table maps `want` to this conn, the release of `previous`
     * finds it still holding `want`, and the connection stays exactly where it
     * was in WHO's walk. Claim-then-release is not an accident of the order
     * these two lines happen to be in; it is the order the two operations are
     * defined to require. */
    if (c->nick[0] != '\0') {
        char previous[sizeof c->nick];

        memcpy(previous, c->nick, sizeof previous);
        server_nick_release(s, previous);
        printf("[observable] nick_change: fd=%d from=%s to=%s\n", c->fd,
               previous, want);
    }
    memcpy(c->nick, want, strlen(want) + 1u);
    update_state(s, c);
}

/* USER: USER <user> <mode> <unused> :<realname> (RFC 1459 2.4 / RFC 2812 3.1).
 *
 * ---------------------------------------------------------------------------
 * THE HOSTNAME IS NOT STORED. THE OBSERVED ADDRESS IS.
 * ---------------------------------------------------------------------------
 * Worth being precise, because the natural assumption is backwards here: USER
 * has NO hostname parameter. RFC 2812 3.1 defines four of them -- user, mode,
 * unused, realname -- and the third is literally named <unused>. What older
 * clients and some current ones put in that slot is a hostname, which is where
 * the idea that USER carries a claimed host comes from, and it is a WEAKER
 * claim than that: the slot is specified as ignored, so a value there is a
 * client filling in a field the protocol says means nothing.
 *
 * Either way the answer is the same. c->host keeps what accept() put there, the
 * observed peer address, and USER does not touch it. A node that stored the
 * assertion has its identity model controlled by the party being identified:
 * anyone can claim to be `host.example.com`, and everything downstream -- 001,
 * WHOIS, and every access control rule a later phase writes against c->host --
 * would then be a decision the client made about itself.
 *
 * The cost is that a legitimately different hostname (a client behind NAT with
 * a real one) is unavailable to this node, and that c->host holds an address
 * rather than a name. Both are the right trade at a point where the alternative
 * is a spoofable identity field, and it is CHEAP NOW: a one-line omission here,
 * against un-spoofing every c->host consumer in Phase 5 and Phase 6 later.
 *
 * The assertion is not thrown away silently -- it goes to the observable
 * output, so a mismatch between what a client claims and where it connected from
 * is visible when diagnosing something -- but it is not identity. */
static void handle_user(server_t *s, conn_t *c, const message_t *m)
{
    int trunc_user = 0;
    int trunc_real = 0;

    if (m->nparams < 4) {
        (void)reply(s, c, "461", NULL, 0, "Not enough parameters");
        return;
    }
    copy_field(c->user, sizeof c->user, m->params[0], &trunc_user);
    copy_field(c->realname, sizeof c->realname, m->params[3], &trunc_real);
    printf("[observable] user: fd=%d user=%s realname_trunc=%d "
           "asserted_host=%s host=%s host_source=observed\n",
           c->fd, c->user, trunc_real, m->params[2], c->host);
    if (trunc_user != 0) {
        printf("[observable] field_truncated: fd=%d field=user\n", c->fd);
    }
    update_state(s, c);
}

/* PING. Legal before registration, like every liveness probe: a client that
 * sent NICK and USER in one segment and then PINGs must get its answer, and a
 * client stuck mid-registration must be able to tell the node is alive. */
static void handle_ping(server_t *s, conn_t *c, const message_t *m)
{
    const char *token = (m->nparams > 0) ? m->params[0] : NULL;

    /* A PING with no argument is answered with the server name (RFC 1459 2.4);
     * send_pong() applies that to an absent or empty token. */
    (void)send_pong(s, c, token);
    printf("[observable] ping: fd=%d token=%s\n", c->fd,
           (token != NULL) ? token : "-");
}

/* PONG. Accepted and answered with nothing: a PONG is a reply to something the
 * client believes is outstanding, so the protocol is satisfied by the client
 * having received it. Answering a PONG with a PONG is how a naive
 * implementation starts a storm. */
static void handle_pong(server_t *s, conn_t *c, const message_t *m)
{
    (void)s; /* the accepted PONG answers nothing, so it needs no node state */
    printf("[observable] pong: fd=%d token=%s\n", c->fd,
           (m->nparams > 0) ? m->params[0] : "-");
}

/* QUIT. Release the nickname, then mark the connection CLOSING.
 *
 * It does NOT close the descriptor. 3.4: the send path never closes a
 * connection, and a reaper at a fixed point in the loop is the single place an
 * fd is closed. Closing here would break that invariant in the most
 * load-bearing way available -- the close count is what the reaper's
 * idempotence is checked against, and a second close path makes every one of
 * those tests weaker.
 *
 * c->nick is deliberately left set. The reaper retires the connection again, and
 * because the table no longer maps any name to this conn by then, that call is a
 * no-op -- unless some other client has already taken the name, in which case
 * retiring the connection removes the new holder's entry only if the table still
 * points at THIS conn, which is exactly what stops a closing conn from evicting
 * its successor on the way out.
 *
 * The release here is therefore belt to those braces rather than the only thing
 * holding them up: server_close_conn() retires the nickname for every close
 * whatever caused it, so the name is safe even if this line were forgotten. It
 * is kept because this is the semantically right place for it, and because "safe
 * if you forget" is a property of the design worth being able to rely on rather
 * than a reason to stop being explicit.
 *
 * It is the same function the reaper calls, and that is not tidiness. QUIT and a
 * client that vanishes without one are the two ways a connection ends, and they
 * used to release the name by different routes -- the handler through the
 * name-keyed release, the reaper by hand. That difference is issue #102: the
 * reaper's hand-written half removed the table entry and left the enumeration
 * entry, so a freed conn_t stayed in WHO's walk. A QUIT hid it, because the
 * handler had already done the vector's half correctly. */
static void handle_quit(server_t *s, conn_t *c, const message_t *m)
{
    const char *reason = (m->nparams > 0) ? m->params[0] : NULL;

    server_nick_unclaim(s, c);
    /* The reason is logged, never stored: there is no NickServ, no quit cache,
     * and no reason for one to exist until Phase 9. */
    printf("[observable] quit: fd=%d nick=%s reason=%s\n", c->fd, c->nick,
           (reason != NULL) ? reason : "-");
    conn_mark_closing(c);
}

static void handle_motd(server_t *s, conn_t *c, const message_t *m)
{
    (void)m;
    send_motd(s, c);
}

/* ---------------------------------------------------------------------------
 * The command table
 * ------------------------------------------------------------------------ */

/* Every verb 4.1 lists is HERE, with a NULL handler for the ones a later phase
 * implements. That is not padding: it is what lets the node tell "I have never
 * heard of JOIN" (421) from "JOIN arrives in Phase 4" (also 421, because the
 * wire has no numeric for "not yet"), and the [observable] line records which of
 * the two it was. Without the table, a verb could only be answered by falling
 * through to the unknown-command path -- the quiet failure the 421 test exists
 * to catch. */
typedef struct {
    const char *verb;
    void (*fn)(server_t *, conn_t *, const message_t *);
    int pre_reg; /* legal before CONN_REG_READY */
} command_t;

static const command_t k_commands[] = {
    { "PASS",    handle_pass,  1 },
    { "NICK",    handle_nick,  1 },
    { "USER",    handle_user,  1 },
    { "PING",    handle_ping,  1 },
    { "PONG",    handle_pong,  1 },
    { "QUIT",    handle_quit,  1 },
    { "MOTD",    handle_motd,  0 },
    /* 7/Phase 4: the channel surface. LIST is here rather than being left for
     * Phase 7, because a channel this node will not tell a client about is a
     * channel whose origin, members and topic are all invisible, and the whole
     * 2.2 data model would be observable only from the [observable] log. */
    { "LIST",    handle_list,  0 },
    /* 4.1, later phases. */
    { "JOIN",    handle_join,  0 },
    { "PART",    handle_part,  0 },
    { "TOPIC",   handle_topic, 0 },
    { "NAMES",   handle_names, 0 },
    { "MODE",    handle_mode,  0 },
    { "KICK",    handle_kick,  0 },
    { "KILL",    NULL,         0 },
    /* 7/Phase 5: the messaging surface, and the point at which the node becomes
     * usable. PRIVMSG and NOTICE are 4.1 MUST; WHO, WHOIS, ISON and AWAY are
     * 4.2 SHOULD, pulled forward here because 4.2's own list puts them in the
     * same phase as the message path and a client that cannot ask "who is here"
     * or "is this nick online" is a client this milestone has not delivered.
     *
     * The table is ordered by the RFC's 4.1/4.2 order, and 3.3.2's grouping, so
     * the surface reads as the specification does. */
    { "PRIVMSG", handle_privmsg, 0 },
    { "NOTICE",  handle_notice,  0 },
    { "WHO",     handle_who,     0 },
    { "WHOIS",   handle_whois,   0 },
    { "ISON",    handle_ison,    0 },
    { "AWAY",    handle_away,    0 },
    /* 7/Phase 7: the rest of 4.2, in 4.2's own order. INVITE and KNOCK are in
     * chan_verbs.c because both are about a channel; USERHOST is in
     * msg_verbs.c because it has no channel in it; the server-info family is
     * below, next to the MOTD it belongs with. The order in the table is
     * 4.2's and not the order of the files, for the same reason the table is
     * ordered by the RFC's rather than by the history: a reader comparing the
     * surface against the specification should be able to do it down this list
     * without a map. */
    { "INVITE",  handle_invite,  0 },
    { "USERHOST", handle_userhost, 0 },
    { "KNOCK",   handle_knock,   0 }
};

static const command_t *lookup(const char *verb)
{
    if (verb == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < sizeof k_commands / sizeof k_commands[0]; i++) {
        if (strcmp(k_commands[i].verb, verb) == 0) {
            return &k_commands[i];
        }
    }
    return NULL;
}

void commands_dispatch(server_t *s, conn_t *c, const message_t *m)
{
    const command_t *cmd;

    if (s == NULL || c == NULL || m == NULL || m->command == NULL) {
        return;
    }

    /* 3: the peer path is the SAME dispatch, and dispatch "never asks 'is this
     * local or remote?' -- src->kind is the only difference". So a peer line is
     * not routed around this function; it arrives here and is handed to the
     * guard chain on the strength of src->kind and nothing else. That is the
     * whole of the difference between the two paths, and putting it here rather
     * than in poll_loop.c's read step is what keeps there ONE door into a
     * command: a second entry point into fed_dispatch() would be a second way
     * for a future line to arrive without passing 2.4's guards.
     *
     * ABOVE THE CONN_CLOSING CHECK, deliberately and specifically. A peer link
     * is a TCP connection like any other, so one segment can carry a peer's last
     * line AND its close; the close marks the conn CLOSING, and the check below
     * would then drop the line that arrived in the same read. Losing a peer's
     * final state change because it happened to share a segment with a FIN is
     * exactly the kind of loss 2.2's cache is supposed to self-heal from and
     * usually does not: there is no later burst to correct it until Phase 9.
     * The check itself still applies to CLIENTS, where a dropped line after a
     * QUIT is correct behaviour.
     *
     * The `c == NULL` guard above means a peer line cannot reach here without a
     * connection, and fed_dispatch() repeats it. */
    if (c->kind == CONN_SERVER) {
        fed_dispatch(s, c, m);
        return;
    }

    /* A connection on its way out gets nothing. The reaper closes it at the
     * next fixed point, so a reply here would be queued onto a socket the loop
     * has already dropped from its poll set. Reachable: one TCP segment
     * carrying "QUIT :bye" and "PING :are you there" hands this function a
     * second line after the first has already marked the conn CLOSING. */
    if (c->state == CONN_CLOSING) {
        printf("[observable] cmd_dropped: fd=%d command=%s reason=closing\n",
               c->fd, m->command);
        return;
    }

    cmd = lookup(m->command);

    /* The registration gate comes BEFORE the unknown-command check, which is
     * the order RFC 2812 3.1 specifies and the one clients expect: an
     * unrecognised verb from an unregistered connection is 451, because "you
     * have not registered" is both true and actionable, while "unknown command"
     * would be neither. */
    if (!commands_registered(c) && (cmd == NULL || cmd->pre_reg == 0)) {
        (void)reply(s, c, "451", NULL, 0, "You have not registered");
        return;
    }

    if (cmd == NULL) {
        const char *mid[1];

        mid[0] = m->command;
        (void)reply(s, c, "421", mid, 1, "Unknown command");
        printf("[observable] cmd_unknown: fd=%d command=%s\n", c->fd, m->command);
        return;
    }
    if (cmd->fn == NULL) {
        const char *mid[1];

        /* A known 4.1 verb this build does not implement. 421 is a slight lie
         * about the reason -- the wire has no numeric for "not yet" -- but the
         * alternative is silence, and silence is the failure mode these
         * numerics exist to prevent. The [observable] line says which of the
         * two it was, so a log reader is not misled. */
        mid[0] = m->command;
        (void)reply(s, c, "421", mid, 1, "Unknown command");
        printf("[observable] cmd_unimplemented: fd=%d command=%s\n", c->fd,
               m->command);
        return;
    }

    cmd->fn(s, c, m);
}
