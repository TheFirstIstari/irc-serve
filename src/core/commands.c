/* commands.c -- see commands.h. Registration, the welcome burst, the four
 * commands that need no channel and no other user, and THE DISPATCH SEAM that
 * both a client line and a peer line arrive at.
 */
#include "core/commands.h"
#include "core/batch.h"
#include "core/label.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "core/account.h"
#include "core/cap.h"
#include "core/chan_verbs.h"
#include "core/channel.h"
#include "core/fanout.h"
#include "core/msg_verbs.h"
#include "core/resume.h"
#include "core/reply.h"
#include "federation/nickreg.h"
#include "federation/verbs.h"
#include "sasl_framework.h"
/* Phase 12: one question -- is TLS compiled in -- and the transport, for nothing here:
 * handle_starttls() sets a flag and conn_pump() does the handoff, so this file
 * never calls into OpenSSL and never names an SSL. */
#include "tls_backend.h"

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
 * struct width cannot leave 005 advertising a length the node then refuses. The
 * same argument is the reason EVERY `*LEN` token below is written this way, and
 * the reason the derivation is visible at all: an ISUPPORT length a client uses
 * to size its own buffers is a promise, and a promise that is a typed-out number
 * stops being true the moment somebody raises a bound in another file. */
#define IRC_STR_(x) #x
#define IRC_STR(x) IRC_STR_(x)

/* ---------------------------------------------------------------------------
 * 005 IS A LIST OF CLAIMS THIS NODE HONOURS, AND BOTH HALVES MATTER
 * ---------------------------------------------------------------------------
 * An ISUPPORT token is read by a client as a FACT about this server: it sizes a
 * buffer from CHANNELLEN, it decides whether a message may name six targets from
 * MAXTARGETS, it wraps a name at NAMELEN. So the list has two obligations and
 * they are opposites:
 *
 *   DERIVED, where a bound exists. Every `*LEN` and the one arity number below
 *   come from the constant that ENFORCES the thing, never from a literal. The
 *   test is not "the number looks right" but "is there a check in this tree that
 *   would refuse more than this", and a token whose answer is no is omitted.
 *   `KICKLEN` was the worked example of the second kind for two phases: Phase
 *   10.4 found that `handle_kick()` took `<reason>` verbatim with no test, so no
 *   number described the largest reason accepted AND an over-long one reached
 *   `message_format()`, which refuses rather than reshapes -- a reachable
 *   `n_reply_refused`, the counter `reply.c` holds at zero because a non-zero
 *   value is a bug report. Phase 10.9 added `CHAN_MAX_KICK_REASON`, the 417 and
 *   the token, so the worked example is now `USERLEN` below.
 *
 *   HONOURED, where a feature exists. A token a client acts on and this node does
 *   not implement is worse than the token's absence: absence is a client that
 *   carries on, presence is a client that switches the feature on and then
 *   behaves as though the server agreed. That is the same rule cap.h holds CAP LS
 *   to, applied to the other list every client reads.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS DELIBERATELY NOT HERE, AND WHY -- the absences are the interesting half
 * ---------------------------------------------------------------------------
 * Each of these is a token a client may look for, and each is absent because
 * there is nothing behind it on this node. They are named here rather than left
 * for a reader to assume, because an absent token and a forgotten one look
 * identical on the wire.
 *
 *   BOT=B          004 advertises `i` for users and `b,k,l,imnpst` for channels,
 *                  and this node evaluates NEITHER set (commands.c's own note).
 *                  There is no BOT mode, no services, and nothing that would ever
 *                  read `BOT`. 4.3's SERVICES/bot verbs are not in 4.1 or 4.2.
 *
 *   EXTBAN=        `+b` stores a ban mask verbatim and chan_has_ban() tests it by
 *                  string equality (2.2). There is no ban EXPRESSION parser, so
 *                  there is no `~&account:name` to advertise and no `EXTBAN`
 *                  value to write. This is the same missing evaluator that
 *                  blocks IRCv3's `account-extban` (SPEC_TRACKING 10.2) -- one
 *                  gap, named twice.
 *
 *   SAFELIST       there is no safelist: `+S` is not a mode 004 advertises, and
 *                  chan_t has no safe-mask store. 2.2's ban list is a ban list.
 *
 *   MONITOR        there is no MONITOR verb. `WATCH` and `WATCHNICK` with it:
 *                  there is no WATCH verb either, so there is no watch list and
 *                  no ceiling on one.
 *
 *   MSGREFTYPES=   no message reference is recognised. `PRIVMSG @#chan :hi`
 *                  reaches fanout_resolve() with `@#chan` as the WHOLE target,
 *                  which is not a valid channel name, so it is 403 rather than a
 *                  reference to a history window. draft/message-reference is not
 *                  implemented, and this token's whole content is the list of
 *                  reference types.
 *
 *   ACCEPT         no EXCEP or INVEX mode, no accept-list storage, and no
 *                  evaluation of either. 2.2's model is one mask array for bans.
 *
 *   silence        there is no SILENCE verb and no silence store. Its absence is
 *                  a fact rather than a gap: this node has no operator concept
 *                  at all (CHOPER answers 464 for every request), and a silence
 *                  list is an operator list.
 *
 *   draft/CHATHISTORY
 *                  no channel history. resume.c's restore hands a client back the
 *                  channels it was in at disconnect, which is a SESSION and not a
 *                  history: it does not answer "what was said in #t last week"
 *                  because it does not keep anything that was not said while the
 *                  client was connected. Advertising the capability would put a
 *                  client into a state it cannot leave.
 *
 *   MODES          this token is a COUNT of mode changes permitted in one MODE
 *                  command, not a mode string (004 carries those). This node puts
 *                  no count on a MODE command, so there is no count to write.
 *
 *   USERLEN        the bound that EXISTS (CONN_USER_MAX) is not ENFORCED: USER's
 *                  ident is truncated into the field rather than refused, so
 *                  advertising a length would promise a limit this node does not
 *                  apply to the one parameter it is about. NAMELEN below is
 *                  advertised for the opposite reason: that bound IS what can be
 *                  stored, and SETNAME refuses beyond it.
 *
 * ---------------------------------------------------------------------------
 * THE `CASEMAPPING=ascii` LIE THAT IS NOT A LIE, AND WHAT rfc1459 WOULD COST
 * ---------------------------------------------------------------------------
 * message.c's up() folds A-Z and nothing else, and fanout.c's ascii_lower() is
 * the same six lines written twice for the reason its own comment gives. So this
 * node does NOT treat `[]\~` as equivalent to `{}|^`, which is exactly what
 * rfc1459 says it should, and advertising ascii is the truth rather than the
 * shorter answer.
 *
 * WHAT CHANGING IT WOULD COST, since the honest answer is only useful if the
 * alternative is on the record: `[]\~` and `{}\|^` become fold-equivalent, which
 * means it becomes UNSAFE to use any of those bytes in a nickname, a channel name
 * or a hostmask component -- a channel named `#a[b` and one named `#a{b` become
 * one channel. Then every comparison that folds has to fold the same way or two
 * of them disagree: server_nick_lookup(), chan_same_name(), fanout.c's
 * ascii_lower(), channel.c's up_ascii(), and the WHO mask matcher. That is five
 * call sites plus the SET of bytes the validators refuse, and the validators are
 * the expensive half -- message.h's valid_nick() and chan_name_valid() would both
 * have to grow a deny-list. It is a change to what a nickname MAY BE, which is
 * why it is not something a 005 token decides. */
static const char *const k_005[] = {
    "NETWORK=" NODE_NETWORK,
    "CHANTYPES=" CHAN_TYPES, /* 4.4: many real clients misbehave without it */
    "PREFIX=(ov)@+",         /* 4.4: and without this one */
    /* True, and not a detail: message.c's up() is ASCII-only, so this node does
     * NOT treat []\~ and {}|^ as equivalent. Advertising rfc1459 here would be
     * a lie a client could act on. */
    "CASEMAPPING=ascii",
    /* ------------------------------------------------------------------------
     * THE DERIVED LENGTHS. Each one is a bound this node REFUSES to exceed, not
     * a figure of speech: raise the constant and this token moves with it.
     * ---------------------------------------------------------------------- */
    "AWAYLEN=" IRC_STR(CONN_MAX_AWAY),         /* 417, msg_verbs.c */
    "CHANNELLEN=" IRC_STR(CHAN_MAX_NAME),      /* chan_name_valid() */
    /* ADDED IN PHASE 10.9, AND IT IS THE CLOSE OF A FINDING RATHER THAN A NEW
     * TOKEN. Phase 10.4 recorded that `handle_kick()` took `<reason>` verbatim with
     * no length test, so (a) no number in the tree described the largest reason
     * this node accepts and (b) an over-long one reached `message_format()`, which
     * refuses rather than reshapes, tripping `n_reply_refused` -- the counter
     * `reply.c` holds at zero because a non-zero value is a bug report. That is a
     * reachable way to make a client command file a bug report.
     *
     * `CHAN_MAX_KICK_REASON` now enforces it and `handle_kick()` answers 417, so
     * the bound below is a fact rather than a figure of speech: it is the same
     * shape as TOPICLEN beside it, derived from the constant that refuses. */
    "KICKLEN=" IRC_STR(CHAN_MAX_KICK_REASON),  /* 417, chan_verbs.c */
    "LINELEN=" IRC_STR(IRC_MAX_LINE),          /* conn_fill() + message_parse_n() */
    "MAXTARGETS=1",                            /* MSG_MAX_TARGETS, msg_verbs.h */
    "NAMELEN=" IRC_STR(CONN_MAX_REALNAME),     /* conn_t::realname; SETNAME 417s */
    "NICKLEN=" IRC_STR(IRC_MAX_NICK),
    "TOPICLEN=" IRC_STR(CHAN_MAX_TOPIC)         /* 417, chan_verbs.c */
};

/* The MOTD body, sent as one 372 per line. It describes what the node IS
   * rather than what it pretends to be.
   *
   * This said "channels, messaging and federation are not implemented", false
   * from Phase 4 onward and a claim shipped to every client that connected. It
   * stayed false because a test asserted those exact bytes, and a test asserting
   * a falsehood is the usual way one survives: it looks like the thing
   * protecting the value while it is the thing keeping it wrong. The test was
   * updated with the text. INFO (371-374) is now the truthful, checkable
   * surface; the MOTD only had to stop lying. */
  static const char *const k_motd[] = {
      "- irc-serve: a federation-native IRC node.",
      "- registration, channels, messaging and peer federation are implemented.",
      "- INFO lists what this node actually does; try it."
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
    /* AND THE account-notify LINE, AFTER 376 AND NOT BEFORE IT.
     *
     * This is the first moment on this node at which a client can be told which
     * account it is associated with: SASL ran before registration, so before 001
     * the connection had no hostmask to attribute the line to and no nickname to
     * put in the prefix. It is after the MOTD rather than interleaved with the
     * numerics because a client parses the registration burst as one thing and an
     * extra verb in the middle of it is a line it does not expect yet.
     *
     * IT IS GATED ON THE CAPABILITY AND NOT ON WHETHER THERE IS AN ACCOUNT, which
     * is the whole of what account-notify's unconditional availability means: a
     * client that asked is told `ACCOUNT *` on a node with no registry, because
     * "you are not associated with an account" is a true and useful answer rather
     * than an absence. */
    if (cap_account_notify_enabled(c) != 0) {
        account_notify_current(s, c);
    }
}

/* Recompute the state from the two facts, and emit the welcome burst on the
 * transition into CONN_REG_READY.
 *
 * Idempotent by construction: a repeated NICK or a second USER line leaves both
 * facts true, the projection is unchanged, and nothing is re-sent. A nickname
 * CHANGE after registration also leaves both facts true, so a nick change never
 * produces a second welcome burst -- which matters, because the burst is what a
 * client uses to decide it has connected. */
void commands_state_update(server_t *s, conn_t *c)
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
    /* ------------------------------------------------------------------------
     * THE CAP END GATE, and it is here rather than in cap.c because this is the
     * ONE place a connection becomes CONN_REG_READY.
     * ------------------------------------------------------------------------
     * A client that sent `CAP LS` or `CAP REQ` has a negotiation in flight, and
     * registration is HELD until `CAP END` arrives. Getting this wrong is not a
     * compatibility detail: a server that completes registration as soon as it
     * holds NICK and USER sends 001-005 in the middle of the client's CAP
     * exchange, every current client reads the burst as the answer to something
     * else, and the connection hangs with nothing in either log. cap_do_end()
     * calls back into this function, so the release is the same code path as a
     * NICK and a USER rather than a second promotion.
     *
     * The state field is left ALONE while negotiation is open, rather than being
     * set to something like CONN_REG_CAP: the enum is a projection of the two
     * facts the file header describes ("no nick, no user", ...), and inventing a
     * fourth combination for a fact that is not either of those would break that
     * projection. A connection held by CAP is a connection whose projection
     * says REG_NICK or REG_USER and whose gate says no, and the two answers are
     * about different questions.
     */
    if (state == CONN_REG_READY && cap_negotiating(c) != 0) {
        printf("[observable] reg_held: fd=%d reason=CAP_NEGOTIATING\n", c->fd);
        return;
    }
    /* And a client whose SASL exchange FAILED never registers at all. The
     * alternative -- registering it unauthenticated -- would make a client that
     * mistyped a password indistinguishable from one that chose not to
     * authenticate, and it is the second of those two that a server must be
     * able to tell apart from the first. handle_authenticate() marks the
     * connection CLOSING after the 464, so this arm is the belt to that
     * braces: it holds for any path that sets SASL_FAILED without closing. */
    if (state == CONN_REG_READY && c->sasl == (int)SASL_FAILED) {
        printf("[observable] reg_held: fd=%d reason=SASL_FAILED\n", c->fd);
        return;
    }
    c->state = state;
    if (state == CONN_REG_READY) {
        send_welcome(s, c);
        /* THE SESSION WINDOW IS APPLIED HERE AND NOWHERE ELSE, and the position
         * is the whole of what makes it possible: this is the one place a
         * connection has all three of nick, ident and host -- the window's key
         * -- AND is about to be addressed as a client, which is what a re-join
         * needs because 3.1's table is keyed on the connection's class. Applying
         * it at NICK time would compare an EMPTY ident against every window and
         * match none; applying it at USER time would be a second place that
         * promotes a connection to ready.
         *
         * IT IS AFTER THE WELCOME BURST, and that is a client-visible ordering
         * choice rather than an accident: 001-005 and the MOTD are the server
         * introducing itself, and a client that has not been told what it
         * connected to should not be told what it is already a member of. Every
         * real client parses 376 as "the server has finished talking", and the
         * JOINs and rosters that follow read as the session coming back rather
         * than as part of the handshake.
         *
         * IT IS A NO-OP FOR EVERY CONNECTION THAT DID NOT COME BACK FROM A DROP,
         * which is every connection on a node whose clients never drop, and it
         * costs one pointer comparison when there is no table. */
        (void)resume_apply(s, c, server_now_ms());
    }
}

static void update_state(server_t *s, conn_t *c)
{
    commands_state_update(s, c);
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
    /* BEFORE THE ARITY CHECK, and that is the whole point of the placement. A PASS
     * with no parameter carries no credential, but a PASS with a parameter that is
     * refused a few lines below has still put one on the wire in the clear, and a
     * client that STARTTLSes afterwards must be refused: see
     * conn_t::credential_seen and handle_starttls(). */
    c->credential_seen = 1;
    if (m->nparams < 1) {
        (void)reply_refused(s, c, "PASS", NULL, "461", NULL, 0,
                            "Not enough parameters");
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
         * "NICK a b" has sent two parameters, and this is the answer it gets --
         * which is a TOO MANY case that the legacy text calls "not enough". The
         * text is left exactly as it is, because changing it would change the wire
         * for every client that negotiated nothing; for one that negotiated
         * `standard-replies` the code above says which of the two it was. */
        (void)reply_refused(s, c, "NICK", "TOO_MANY_PARAMS", "461", NULL, 0,
                            "Not enough parameters");        return;
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

    /* 2.1's RENAME-THE-LOSER, and the whole policy is
     * fed_nickreg_resolve_local() rather than anything here. That is the point of
     * it being a function: a rule written at the claim site and a rule written at
     * the report site would be TWO rules, and a rename needs FIVE effects -- the
     * decision, a new name, the local registry, the client and its channels, and
     * the mesh -- of which a call site implementing four would produce a mesh
     * that LOOKS renamed and is not.
     *
     * IT IS CALLED HERE AND ALSO AFTER A REMOTE CLAIM IS LEARNED (on an SJOIN and
     * on a burst), because a user can register a name on a node whose registry is
     * empty and have the competing claim arrive afterwards. Checking only at claim
     * time would leave that user holding a name for ever, which is the
     * "user-visible and undefined" state 2.1 names. The other half of the
     * convergence argument is that the OTHER node runs this same function against
     * the same two names and renames its own user if it is the loser there -- so
     * nothing has to tell a node to rename anybody.
     *
     * NOTHING BELOW THIS CALL TOUCHES THE NAME, because the function owns all of
     * it -- including the case where it declines to act, which is most calls. */
    /* A CLIENT-INITIATED CHANGE, for a connection that already held a name, and
     * this is the block the rename-the-loser policy does NOT replace: a user
     * choosing a new name is a different event from a user being told their name
     * is taken, and the two observables are kept apart so a reader of a log can
     * tell them. The release happens BEFORE the claim, which is the opposite
     * order from fed_nickreg_resolve_local()'s and for the same reason stated
     * there -- except that here the name being released is THIS connection's own
     * and is being given up deliberately, so there is no third user who could
     * take it in the window.
     *
     * IT IS REPORTED AND NOT FANNED OUT, which is a real limit rather than an
     * oversight and is unchanged by anything above: a client-issued rename is
     * visible to the client and to this node's registry, and NOT to the other
     * members of its channels nor to the mesh. §7/Phase 4 has never claimed
     * otherwise, and making it true is a separate piece of work from 2.1's
     * duplicate policy -- which is a statement about DUPLICATES and does not
     * need a general rename broadcast to be correct. */
    if (have_nick(c)) {
        char previous[sizeof c->nick];

        memcpy(previous, c->nick, sizeof previous);
        server_nick_release(s, previous);
        printf("[observable] nick_change: fd=%d from=%s to=%s\n", c->fd, previous,
               want);
    }
    /* c->nick IS SET BEFORE THE POLICY RUNS and not after, and the order is
     * load-bearing in both directions. Before: fed_nickreg_resolve_local() finds
     * the local holder with server_nick_lookup() and then writes c->nick itself,
     * so a connection still carrying an empty nick would be renamed to nothing and
     * a connection carrying its PREVIOUS nick would be renamed from the wrong
     * name. After: the rename the policy performs would be undone by the memcpy,
     * leaving the registry claiming `fresh` and the connection answering to
     * `want` -- the divergence 2.1's policy exists to end. */
    memcpy(c->nick, want, strlen(want) + 1u);
    (void)fed_nickreg_resolve_local(s, want, server_now_ms());
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
 * is visible when diagnosing something -- but it is not identity.
 *
 * ---------------------------------------------------------------------------
 * A SECOND `USER` IS REFUSED: 462, AND THE IDENT IS NOT WRITTEN
 * ---------------------------------------------------------------------------
 * `USER` is `pre_reg` in k_commands[] because CAP, SASL, NICK, USER, PING, PONG
 * and QUIT are the seven verbs a client may send BEFORE it has registered. That
 * is a statement about what may arrive FIRST, and it is not a statement about
 * what may arrive again: the dispatch table's registration gate is
 *
 *     if (!commands_registered(c) && (cmd == NULL || cmd->pre_reg == 0))
 *
 * which a REGISTERED connection passes for every row including `pre_reg`, so
 * this handler used to run for a second `USER` on a live connection and wrote
 * `conn_t::user` unconditionally. A client could therefore move its own ident
 * with no line to itself and no line to anybody sharing a channel.
 *
 * THE THREAT MODEL, and the part of it that is not the obvious one. Three
 * candidate harms, and only two are real:
 *
 *   NOT IMIMPERSONATION, and the reason is worth stating because it is the
 *   answer that makes "just refuse it" feel arbitrary otherwise. Nothing on
 *   this node is GRANTED to an ident. No privilege, no account and no access
 *   decision reads `c->user` alone -- `account-logged-in` and every operator
 *   check are keyed on other things, and the ident is client-asserted and
 *   UNVERIFIED at registration, so two users may already hold the same one and
 *   a client could equally have REGISTERED with the ident it now moves to. There
 *   is no identity here to impersonate.
 *
 *   YES, A CHANNEL BAN MASK. This is the part that makes the write a defect
 *   rather than a shrug. `chan_banned()` is called on every JOIN and matches a
 *   stored mask against the NICK, against the HOST, and against the COMPOSITE
 *   `nick!user@host` -- and the suite exercises exactly that composite form
 *   (`MODE #mo +b *!*@127.0.0.1`, refused with 474). A mask of the shape
 *   `mallory!*@*` or `mallory!badident@*` can only match through the composite,
 *   so on this node a client that changes its ident, PARTs and re-JOINs is
 *   ADMITTED to a channel it is banned from. That is an access-control bypass
 *   reachable from a single client command, and it is why the answer is not (b)
 *   "accept but notify": a notification does not stop the rejoin.
 *
 *   YES, THE SILENCE ITSELF, to two audiences. Every roster this node draws --
 *   311, 352, 353, the message prefix, 302 -- then reports an ident nobody was
 *   told about, so a `userhost-in-names` client (Phase 10.5) is shown a hostmask
 *   that changed without a word. And `resume.c` REQUIRES (nick, ident, host) to
 *   all match to resume, so the write silently invalidates the client's own
 *   session record. On a mesh the peer's roster keeps the old ident until the
 *   next SBURST, because nothing tells it.
 *
 * WHY 462, AND IT IS NOT A CHOICE. RFC 2812 3.1.3 lists the numeric replies to
 * `USER` as exactly two -- `ERR_NEEDMOREPARAMS` and `ERR_ALREADYREGISTRED` -- and
 * the numeric's own entry in RFC 2812 9 names the case: "user details from second
 * USER message". So a second `USER` is 462 because the RFC says so, not because
 * 462 is the nearest available complaint. (Design 9's risk row previously recorded
 * the opposite -- that refusing "is a behaviour change to an RFC 1459 MUST command
 * with nothing in the RFC requiring it" -- and that was wrong: it had read RFC
 * 1459, whose `USER` section says nothing about a second one, and not RFC 2812
 * 3.1.3. The finding the row was built on is correct; the reason it did not act
 * on it was not.)
 *
 * WHY 462 IS NOT MIGRATED, which looks inconsistent beside the four numerics
 * 4.4.3 does migrate: those four answer MORE THAN ONE QUESTION on this node, so
 * the number alone cannot say which refusal happened. `462` answers exactly one
 * -- "you are already registered" -- so by the rule it stays legacy, and
 * reply_refused()'s NULL code is what selects that branch. A client that
 * negotiated `standard-replies` gets the 462; it is unambiguous.
 *
 * THE GATE IS `commands_registered()`, NOT "HAS SEEN A `USER` BEFORE", and the
 * difference is the whole of the compatibility cost. A client that sends `USER`
 * twice BEFORE completing registration still works, last-one-wins, because it is
 * pre-registration in the sense every other gate in this file means. What is
 * refused is the write to a connection that has already been told `001`, which
 * is where the hole was.
 *
 * THE GATE IS BEFORE THE ARITY TEST, and this is the one place it differs from
 * handle_setname()'s order, deliberately: the arity complaint is a fact about the
 * MESSAGE and the registration state is a fact about the CONNECTION, and for a
 * registered connection the message cannot be processed at all. Answering `461
 * Not enough parameters` to a client that sent the very same four parameters a
 * moment ago and was answered `001` would be a numeric describing a problem the
 * client does not have.
 *
 * WHAT IT COSTS, honestly. A client that re-sends `USER` after registration gets
 * one numeric it did not ask for and keeps its connection, its nickname, its
 * channels and its realname -- the refusal does not close anything. The only
 * thing taken away is the ability to move its own ident, which is the defect. The
 * ident a client wants is the one it should have sent at registration, where it
 * can still be refused (417/empty) rather than silently truncated. */
static void handle_user(server_t *s, conn_t *c, const message_t *m)
{
    int trunc_user = 0;
    int trunc_real = 0;
    conn_realname_verdict_t v;
    size_t asserted_len;
    int asserted_ok;
    size_t asserted_bad;

    if (commands_registered(c)) {
        (void)reply_refused(s, c, "USER", NULL, "462", NULL, 0,
                            "Unauthorized command (already registered)");
        printf("[observable] user_refused: fd=%d nick=%s reason=ALREADY_REGISTERED "
               "nparams=%d\n",
               c->fd, c->nick, m->nparams);
        return;
    }

    if (m->nparams < 4) {
        (void)reply_refused(s, c, "USER", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    copy_field(c->user, sizeof c->user, m->params[0], &trunc_user);
    /* THE REALNAME IS CHECKED BY THE SAME PREDICATE `SETNAME` USES, and it is
     * checked BEFORE the field is written rather than after, so a refused value is
     * never briefly stored. conn_realname_check()'s argument is at its definition;
     * what is decided here is what happens when it says no, and the decision is not
     * "truncate".
     *
     * A realname carrying a C0 control is LEFT EMPTY rather than refused, and the
     * asymmetry with SETNAME is deliberate rather than an inconsistency:
     *
     *   - SETNAME arrives on an already-REGISTERED connection, where refusing leaves
     *     the connection usable and the previous value in place -- 417 and nothing
     *     changes.
     *   - USER arrives BEFORE registration completes. Refusing it would leave the
     *     client half-registered with no way to recover except reconnecting, for a
     *     value no current client sends (a realname containing ESC or BEL is a
     *     rendering accident, and CR/LF/NUL cannot reach here at all because the
     *     parser refuses them first). So the registration is allowed to complete
     *     with an EMPTY realname, which is already a legal state in this node --
     *     `extended-join` renders it as a bare `:`, and the comment there says a
     *     client that sent none has an empty realname "which is a fact about the
     *     client rather than a limit this node imposes".
     *
     * IT IS REPORTED, because the failure is otherwise invisible: the only
     * observable difference between "the client sent nothing" and "the client sent
     * something this node threw away" would be a realname that is missing from
     * every later roster, which is exactly the kind of discrepancy 3.4's observable
     * output exists to make findable.
     *
     * LENGTH IS STILL TRUNCATED HERE and refused by SETNAME, and that difference is
     * the same argument from the other side: 3.2's rule against a silently shortened
     * parameter is about a value the node then REPORTS as the user's, and at
     * registration the alternative is a stranded connection. copy_field() says so
     * at its own definition and the truncation is announced rather than silent. */
    v = conn_realname_check(m->params[3]);
    if (v == CONN_REALNAME_BAD_BYTE) {
        printf("[observable] realname_refused: fd=%d nick=%s verb=USER "
               "reason=BAD_BYTE len=%zu\n",
               c->fd, c->nick, strlen(m->params[3]));
        c->realname[0] = '\0';
    } else {
        copy_field(c->realname, sizeof c->realname, m->params[3], &trunc_real);
    }
    /* ------------------------------------------------------------------------
     * `<servername>` IS NOT PRINTED, AND THAT IS THE FIX (#121)
     * ------------------------------------------------------------------------
     * `m->params[2]` used to be rendered raw on the line below. One pre-
     * registration command from the wire put arbitrary bytes into an operator's
     * terminal: `USER vic 0 <ESC>[2J<BEL> :x` produced
     *
     *     [observable] user: ... asserted_host=<ESC>[2J<BEL> host=127.0.0.1
     *
     * with the ESC and the BEL surviving, and 0x07 rings a terminal's bell while
     * ESC `[` is a CSI sequence any terminal executes. No credential, no channel,
     * no second client -- one line on a socket, before registration completes.
     *
     * THE FIX IS NOT A BYTE FILTER, and the reason is the only thing that decides
     * it: **this node has no consumer for this field.** `host_source=observed` --
     * the host on that same line is `c->host`, what accept() saw, and nothing a
     * client asserts in `USER` moves it. So a filter would buy nothing for the
     * bytes that pass it while still logging a value no reader can act on, and the
     * hazard would remain for every byte the filter's author did not think of.
     * A field with no consumer is not logged raw; it is summarised.
     *
     * WHAT IS REPORTED INSTEAD, and why each of the three is worth a column:
     *
     *   asserted_host_len          Is the client sending something at all? A
     *                              client with no servername (or one sending an
     *                              empty one) is a fact about the client, and
     *                              `USER`'s parameters are all required, so it
     *                              is a fact worth having.
     *   asserted_host_wellformed   Did it send a name this node's OWN server-name
     *                              grammar would accept?
     *                              irc_serve_server_name_valid() is that grammar,
     *                              and it is the predicate `server_init()` and the
     *                              federation handshake already apply to a server
     *                              name -- so this column answers "is this the
     *                              shape of thing this node would call a server",
     *                              using a rule that already exists rather than a
     *                              third spelling of it. Its grammar is alnum, '-'
     *                              and '.', so a value that passes it cannot carry
     *                              a control byte, and this column is safe by
     *                              construction rather than by luck.
     *   asserted_host_bad_bytes    How many bytes were in the injection set. The
     *                              count is measured, never the bytes, and it is
     *                              what turns "something odd happened" into a
     *                              number an operator can watch.
     *
     * WHY `417` IS NOT USED HERE, which is the third of §9's options and the one
     * that would have been simplest. Every real client sends a servername --
     * usually its own FQDN -- so refusing `USER` over it strands a half-registered
     * client for a field nothing reads. That is the same argument handle_user()'s
     * realname makes at length above, and it is why the policy for THIS field is
     * "print less" rather than "print differently".
     *
     * THE COST, named: an operator can no longer read back what a client claimed
     * it was talking to. The length, the well-formedness verdict and the bad-byte
     * count survive; the string does not. That is the intended trade -- a
     * diagnostic that cannot be acted on is not worth an injection vector -- and
     * if an operator ever needs the value, the place to get it is a log line this
     * node writes from a source it controls, not one a client dictates. */
    asserted_len = strlen(m->params[2]);
    asserted_ok = irc_serve_server_name_valid(m->params[2]);
    asserted_bad = conn_text_bad_count(m->params[2]);
    printf("[observable] user: fd=%d user=%s realname_trunc=%d "
           "asserted_host_len=%zu asserted_host_wellformed=%d "
           "asserted_host_bad_bytes=%zu host=%s host_source=observed\n",
           c->fd, c->user, trunc_real, asserted_len, asserted_ok, asserted_bad,
           c->host);
    if (asserted_bad != 0u) {
        printf("[observable] asserted_host: fd=%d reason=BAD_BYTES dropped=%zu "
               "detail=SUMMARISED_ONLY\n",
               c->fd, asserted_bad);
    }
    if (trunc_user != 0) {
        printf("[observable] field_truncated: fd=%d field=user\n", c->fd);
    }
    update_state(s, c);
}

/* ---------------------------------------------------------------------------
 * SETNAME -- IRCv3's `setname`, and the three gates in front of it
 * ---------------------------------------------------------------------------
 * `SETNAME :<realname>` changes `conn_t::realname` on a live connection. Three
 * gates, in this order, and the order is the argument:
 *
 *   1. REGISTERED. 451 if not. Not `pre_reg` in k_commands[], so this is answered
 *      by the dispatch table's own rule rather than here -- and it has to be a gate
 *      rather than an accident of the field being empty, because a pre-registration
 *      connection HAS an empty realname and would otherwise "succeed" at setting it
 *      to something, which is a command acting on state that does not exist yet.
 *
 *   2. THE CAPABILITY. Refused SILENTLY, with no reply and no change.
 *
 *      This is the specification's own instruction and it is the opposite of what
 *      every other capability in cap.h does, so it is worth being explicit: `setname`
 *      says a server MUST support the command even while the capability is not
 *      negotiated, and that a SETNAME from a client which did not negotiate it
 *      SHOULD be handled silently. "Silently" IS the refusal -- nothing arrives and
 *      nothing changes -- and it is observable, because a protocol test can assert
 *      that nothing arrived.
 *
 *      THE SILENCE IS NOT BECAUSE `standard-replies` WAS ABSENT. It used to be
 *      justified that way and that justification was WRONG the moment the
 *      capability landed in Phase 10.9: `FAIL SETNAME CANNOT_CHANGE_REALNAME` is
 *      now expressible, and sending it would still be wrong, because the
 *      specification asks for SILENCE here and a `FAIL` is a response. The reason
 *      for silence is the specification's instruction and nothing else. (The other
 *      half of that sentence is now handled: the refusal below for an
 *      unacceptable VALUE is a `FAIL` for a client that negotiated
 *      `standard-replies`, which is a different refusal from not being permitted to
 *      try.)
 *
 *   3. VALIDATION, through conn_realname_check() -- the SAME predicate handle_user()
 *      runs, which is what makes this not a looser path than registration. A
 *      refusal is 417 and the previous realname is left exactly as it was. It is
 *      NOT truncated: 3.2's rule, and the reason is that this value is then shown
 *      to every member of every channel the user is on as though it were theirs.
 *
 *      417 IS STILL THE NUMERIC, and for a client that negotiated
 *      `standard-replies` it is `FAIL SETNAME ERR_INPUTTOOLONG` or
 *      `ERR_INVALID_PARAM` depending on which of the two refusals this was -- a
 *      distinction the number never carried and the verdict `v` already knows.
 *      reply.c's `reply_refused()` is what makes the swap per destination, so a
 *      client that negotiated nothing still receives the 417 and the same text.
 *
 * THE CONFIRMATION. On success this node sends the server-to-client form back to
 * the originating client:
 *
 *     :nick!user@host SETNAME :<new realname>
 *
 * which is the specification's MUST for "to all clients in common channels, as well
 * as to the client from which it originated" -- PARTIALLY. The originating client
 * gets it; **the common-channel fan-out does not happen**, and that is a named
 * limit rather than an oversight. `core/fanout.c`'s per-destination decision is a
 * choice between two wire SHAPES (the `fanout_form_t` the extended JOIN
 * introduced), and "send this member NOTHING" is a THIRD outcome that the form
 * cannot express; adding it is a contract change to the routing module, and the
 * alternative -- a second member walk inside a handler -- is the exact duplication
 * fanout.c exists to prevent. So the originating client is told, and a member of a
 * shared channel is not. SPEC_TRACKING 10.5 records it.
 *
 * THE PREFIX IS THE ACTING CLIENT'S OWN HOSTMASK, which is the specification's
 * server-to-client shape and is also what makes the line trustworthy: it names who
 * changed, and `conn_hostmask()` renders it from the fields §2.1 owns (including the
 * OBSERVED host, which USER does not touch). */

/* THE COMMON-CHANNEL FAN-OUT, and the disclosure decision is the whole of it.
 *
 * The specification: "they MUST send the server-to-client version of the SETNAME
 * message **to all clients in common channels**, as well as to the client from which
 * it originated" and "The SETNAME message **MUST NOT** be sent to clients which do
 * not have the `setname` capability negotiated."
 *
 * THE GATE IS THE RECIPIENT'S, which is the specification's condition read
 * literally ("clients", plural) and the answer that agrees with `cap.h`'s existing
 * rule for the CONFIRMATION above. Gating on the SENDER -- which is the other thing
 * one could implement, and which is one line -- would let a client who negotiated
 * `setname` put a member's realname on the wire to every other member of a shared
 * channel by asking for a capability those members never requested, and would
 * contradict the confirmation's own rule in the same handler. A realname is personal
 * data; the per-destination answer is the only one that does not require trusting
 * the person disclosing it to be careful about who finds out.
 *
 * THE ORIGIN IS EXCLUDED, and the reason is the ORDER rather than a rule about
 * authors: the confirmation above has ALREADY delivered this line to the client that
 * asked, and the specification counts that as the origin's half of the MUST. Leaving
 * the origin in the audience would give it two byte-identical `SETNAME` lines for one
 * command, which is the same double-delivery defect `echo-message` has a fault for.
 * So `exclude` is `c`, exactly as msg_verbs.c's notify_away() excludes the away
 * setter because 306/305 are that user's own answer.
 *
 * IT IS THE UNION, NOT ONE CALL PER CHANNEL, and the SHAPE is why:
 * `:nick!user@host SETNAME :<realname>` has no channel parameter, so a per-channel
 * emission would put a `#channel` where a client expects the realname, and would hand
 * a member of three shared channels three copies of one fact. fanout.h's
 * `fanout_deliver_union_local_gated()` is the one walk that gets both right, and its
 * de-duplication is a search over the caller's own `conn_t::chans` rather than a
 * cache -- which is why there is no bounded store here with a teardown arm to forget.
 *
 * NOT FORWARDED, for the same reason away-notify is not: this is an originating
 * emission and the local-only entry points have no forward arm. Worth being honest
 * about what that costs: 4.3's frozen `SBURSTN` carries no realname, so a mesh
 * member's clients learn a peer's realname from its own roster -- `extended-join` --
 * and never learn that it CHANGED, because there is no S-verb to carry the change and
 * a wire format cannot be invented after Phase 6. Closing that needs a new 4.3 verb
 * and a version bump, not a decision. */
static void setname_notify_channels(server_t *s, conn_t *c)
{
    const char *params[1];
    fanout_form_t plain;
    char prefix[CONN_HOSTMASK_MAX];
    int delivered;

    /* NO CHANNELS MEANS NO AUDIENCE, and that is `c->nchans` rather than a check
     * anywhere else: the audience is "users sharing a channel", so with no channels
     * there is nobody to tell. The confirmation above has already reached the only
     * client the specification requires an answer to. */
    if (c->nchans == 0u) {
        printf("[observable] setname_notify: nick=%s recipients=0 "
               "reason=NO_SHARED_CHANNEL\n",
               c->nick);
        return;
    }
    if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
        /* Unrenderable is a bug report rather than a refusal, and it cannot have
         * happened: the caller rendered this same prefix a few lines ago and got here
         * because it succeeded. Reported rather than assumed, because the alternative
         * is a silent reason for a notification that never went out. */
        printf("[observable] setname_notify: nick=%s reason=UNRENDERABLE\n", c->nick);
        return;
    }
    params[0] = c->realname;
    plain.params = params;
    plain.nparams = 1;
    delivered = fanout_deliver_union_local_gated(s, c->chans, c->nchans, prefix,
                                                 "SETNAME", &plain, NULL,
                                                 cap_gate_setname, NULL, c);
    printf("[observable] setname_notify: nick=%s channels=%zu recipients=%d\n",
           c->nick, c->nchans, delivered);
}

static void handle_setname(server_t *s, conn_t *c, const message_t *m)
{
    conn_realname_verdict_t v;
    char prefix[CONN_HOSTMASK_MAX];
    const char *params[1];

    /* Arity before anything else, and the gate order above says why: a malformed
     * command from a client that cannot use it is answered 461 rather than
     * silently, because 461 is the shape the specification's own "handle silently"
     * does NOT apply to -- silence is for a well-formed SETNAME, not for a missing
     * parameter. */
    if (m->nparams != 1) {
        (void)reply_refused(s, c, "SETNAME", "INVALID_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        printf("[observable] setname_refused: fd=%d nick=%s reason=ARITY nparams=%d\n",
               c->fd, c->nick, m->nparams);
        return;
    }
    if (cap_setname_enabled(c) == 0) {
        /* THE SILENT REFUSAL. No reply, no change, and the only trace is this line,
         * which is the same observable output every other refusal in this file uses.
         * It is deliberately NOT a 417 and NOT a 482: a client that did not ask for
         * `setname` has not done anything wrong, and the specification asks for
         * silence rather than for an error a client cannot act on. */
        printf("[observable] setname_ignored: fd=%d nick=%s "
               "reason=NOT_NEGOTIATED len=%zu\n",
               c->fd, c->nick, strlen(m->params[0]));
        return;
    }
    v = conn_realname_check(m->params[0]);
    if (v != CONN_REALNAME_OK) {
        /* THE DISTINCTION THE NUMBER NEVER CARRIED, and it is the clearest small
         * argument for the migration: `v` already knows whether the realname was
         * too long or held a byte this node will not store, and both were 417
         * carrying the same text. For a client that negotiated `standard-replies`
         * they are now two codes, and only the length one is the numeric's own
         * complaint. */
        (void)reply_refused(s, c, "SETNAME",
                            (v == CONN_REALNAME_TOO_LONG) ? "ERR_INPUTTOOLONG"
                            : "ERR_INVALID_PARAM",
                            "417", NULL, 0, "Realname is not acceptable");
        printf("[observable] setname_refused: fd=%d nick=%s reason=%s len=%zu "
               "max=%d\n",
               c->fd, c->nick,
               (v == CONN_REALNAME_TOO_LONG) ? "TOO_LONG" : "BAD_BYTE",
               strlen(m->params[0]), CONN_MAX_REALNAME);
        return;
    }
    /* NOT copy_field(), and the difference is the point of gate 3. copy_field()
     * truncates; this must not, because the stored value is one this node will
     * report to third parties. The length has just been checked against
     * CONN_MAX_REALNAME, which is sizeof(conn_t::realname) - 1, so this copy
     * cannot truncate -- and it is written out rather than delegated so that a
     * future change to the bound cannot silently reintroduce the truncation
     * through the helper. */
    memcpy(c->realname, m->params[0], strlen(m->params[0]) + 1u);
    if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
        /* The value is already stored at this point, because the check happened
         * first and the store is unconditional once it passed. A connection whose
         * hostmask will not render is a bug report rather than a refusal, and the
         * honest outcome is that the change happened and could not be confirmed. */
        printf("[observable] setname_unconfirmed: fd=%d nick=%s reason=UNRENDERABLE\n",
               c->fd, c->nick);
        return;
    }
    params[0] = c->realname;
    (void)send_line(s, c, prefix, "SETNAME", params, 1);
    setname_notify_channels(s, c);
    printf("[observable] setname: fd=%d nick=%s len=%zu\n", c->fd, c->nick,
           strlen(c->realname));
}

/* PING. Legal before registration, like every liveness probe: a client that
 * sent NICK and USER in one segment and then PINGs must get its answer, and a
 * client stuck mid-registration must be able to tell the node is alive. */
/*
 * ---------------------------------------------------------------------------
 * EVERY LOG LINE IN THIS FILE THAT NAMES A CLIENT-SUPPLIED STRING
 * ---------------------------------------------------------------------------
 * `conn_text_logsafe()` is the one rule for all of them, and it exists because
 * there were fourteen of them and each had been written as `%s`.
 *
 * A command word, a PING token, a QUIT reason, a server mask, a nickname a client
 * offered and a SASL mechanism are all bytes off a socket, and every one of them
 * reached this node's own stdout unfiltered. The reachable ones needed no
 * credential and no registration: one unrecognised verb carrying ESC in its word,
 * one `PING`, one `QUIT`. `0x07` rings a terminal's bell and ESC `[` is a CSI
 * sequence any terminal executes, so this was a way for anyone who could open a
 * socket to rewrite an operator's screen.
 *
 * WHY NOT STRIP THESE. A STRIP is for a field that is RELAYED to other people --
 * an away message, a topic, a kick reason -- where removing the byte changes what
 * they read. Every value below is LOG-ONLY: nothing else ever sees it, so there is
 * nothing to protect by rewriting it and a great deal to lose. `cmd_unknown:
 * command=NICK` is the entire diagnostic; printed with a byte removed it would
 * name a verb the client never sent. So these are MEASURED: the value is kept when
 * every byte is printable ASCII, withheld when one is not, and the length and the
 * bad-byte count go beside it either way.
 *
 * NOT ALL FOURTEEN WERE BROKEN, and the ones that were not are named at their own
 * definitions rather than here. `commands.c` prints `c->nick`, `c->user`,
 * `c->host`, `c->realname`, `c->account` and `ch->name` throughout: every one of
 * those passed `valid_nick()`, `chan_name_valid()`, `conn_realname_check()` or
 * `account_name_wire_safe()` on the way in, and a field that cannot hold a byte
 * from the set needs no second opinion on the way out.
 * ---------------------------------------------------------------------------
 */

static void handle_ping(server_t *s, conn_t *c, const message_t *m)
{
    const char *token = (m->nparams > 0) ? m->params[0] : NULL;

    /* A PING with no argument is answered with the server name (RFC 1459 2.4);
     * send_pong() applies that to an absent or empty token. */
    (void)send_pong(s, c, token);
    {
        char shown[CONN_LOG_FIELD_MAX + 1u];

        /* The token is an OPAQUE STRING THE CLIENT MADE UP, and this is the only
         * place it is ever rendered. It reaches the wire too -- inside the PONG --
         * but that goes back to the client that sent it, so the log is where the
         * hazard is: `PING <ESC>[2J` put a control byte in an operator's terminal
         * from one line, before registration. */
        (void)conn_text_logsafe(shown, sizeof shown, token);
        printf("[observable] ping: fd=%d token=%s token_len=%zu token_bad_bytes=%zu\n",
               c->fd, shown, (token != NULL) ? strlen(token) : 0u,
               conn_text_bad_count(token));
    }
}

/* PONG. Accepted and answered with nothing: a PONG is a reply to something the
 * client believes is outstanding, so the protocol is satisfied by the client
 * having received it. Answering a PONG with a PONG is how a naive
 * implementation starts a storm. */
static void handle_pong(server_t *s, conn_t *c, const message_t *m)
{
    (void)s; /* the accepted PONG answers nothing, so it needs no node state */
    {
        const char *tok = (m->nparams > 0) ? m->params[0] : NULL;
        char shown[CONN_LOG_FIELD_MAX + 1u];

        /* The same rule as PING, and the same reason: this token is echoed to the
         * log and to nobody else. A PONG is the one line a client can send whose
         * entire content is attacker-chosen and unexamined, so it is the cheapest
         * injection on this node and it is closed by the same shared predicate. */
        (void)conn_text_logsafe(shown, sizeof shown, tok);
        printf("[observable] pong: fd=%d token=%s token_len=%zu token_bad_bytes=%zu\n",
               c->fd, shown, (tok != NULL) ? strlen(tok) : 0u,
               conn_text_bad_count(tok));
    }
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
     * and no reason for one to exist until Phase 9.
     *
     * WHICH MAKES IT A LOG-ONLY FIELD, and that is the whole policy: measured, not
     * filtered. A `QUIT :<ESC>[2J` reached an operator's terminal raw, and unlike
     * the away message this value is never relayed to another client, so there is
     * no reader downstream to protect and a stripped copy would only be a shorter
     * lie about what the client sent. The length is reported beside the value
     * because a reason is free text of unbounded length -- up to the line cap --
     * and a withheld one has to be diagnosable.
     *
     * NOT TRUNCATED, which is why the field is withheld rather than shortened when
     * it exceeds the print width. A log line that cut a sentence in half would be
     * a different sentence from the one the client sent, and 3.2's rule against
     * silently shortening a parameter is about exactly that even here. */
    {
        char shown[CONN_LOG_FIELD_MAX + 1u];

        (void)conn_text_logsafe(shown, sizeof shown, reason);
        printf("[observable] quit: fd=%d nick=%s reason=%s reason_len=%zu "
               "reason_bad_bytes=%zu\n",
               c->fd, c->nick, shown, (reason != NULL) ? strlen(reason) : 0u,
               conn_text_bad_count(reason));
    }
    conn_mark_closing(c);
}

static void handle_motd(server_t *s, conn_t *c, const message_t *m)
{
    (void)m;
    send_motd(s, c);
}

/* ---------------------------------------------------------------------------
 * 4.2's LUSERS, ADMIN and INFO -- the server-info family
 * ---------------------------------------------------------------------------
 * All three answer questions about the NODE rather than about a channel or a
 * person, and all three are RFC 2812 3.4.2/3.4.4 commands that a client sends
 * unprompted when it connects. That is why they live next to the MOTD and not in
 * chan_verbs.c or msg_verbs.c: the family a verb belongs to is decided by what
 * it asks about, and these three ask about this server.
 *
 * STATIC, like every other handler in this file, and for the reason the file
 * header gives about the four Phase 3 commands: a `command_t::fn` with no caller
 * outside the table has no business being a link-time symbol. The handlers that
 * DO have callers outside this file are in chan_verbs.c and msg_verbs.c, and
 * they are declared in their own headers -- which is also where a reader looking
 * for "what does this node answer to LUSERS" would not find these, and should
 * look at the table instead.
 *
 * ---------------------------------------------------------------------------
 * EVERY NUMBER IN HERE IS MEASURED, AND THE ONE THAT IS NOT IS SAID SO
 * ---------------------------------------------------------------------------
 * A node that answered LUSERS with a plausible constant would be the same defect
 * as a 324 that disagrees with the node's actual modes, which Phase 4 refused to
 * ship: "a numeric that lies about what it is". So:
 *
 *   <clients>       server_nick_count(): the connections on this node holding a
 *                   nickname. A connection that has not chosen a name is not a
 *                   user of this network and is not counted, and a connection
 *                   that has sent NICK but not USER IS counted -- it is a client,
 *                   which is what the word means. The distinction is in the
 *                   comment rather than in a different counter because there is
 *                   only one counter and 3.4's single event loop has no other
 *                   place to keep a second one.
 *   <servers>       the peers this node has an ESTABLISHED link to. NOT
 *                   server_link_count(), which counts a link that exists and has
 *                   no socket -- a name and a destination, or a peer that is
 *                   still handshaking. 2.3 is explicit that a link is not
 *                   ESTABLISHED until the handshake finished, and a server count
 *                   that included a half-linked peer would overstate the mesh.
 *   <hops>          0, and 0 is TRUE: the value counts forwards, and this node
 *                   originated every count it is reporting. A node answering 1
 *                   here would be claiming a relay that did not happen -- the
 *                   same argument msg_verbs.c makes for 352's <hopcount>.
 *   <max clients>   NO CONFIGURED MAXIMUM EXISTS on this node, and the numeral
 *                   carries the next honest thing, which is the hard bound:
 *                   server.h's SERVER_FD_TABLE, which is FD_SETSIZE, because
 *                   server_t::by_fd is a flat array indexed by descriptor and the
 *                   accept site refuses an fd at or above it (3.4). A node with
 *                   more clients than that cannot exist, so it is a real ceiling
 *                   rather than a configured wish. It is deliberately a CEILING
 *                   and not a promise: the listener and every peer link occupy
 *                   slots in the same table, so the figure a client could
 *                   actually reach is lower, and nothing here claims otherwise.
 *                   No client compares against it -- 004 advertises no
 *                   MAXCLIENTS and 005 does not either, so there is nothing to
 *                   disagree with.
 *   252, 253, 254   NOT SENT, and that is a decision rather than an omission.
 *                   RFC 2812 3.4.4 lists them among LUSERS's replies because a
 *                   server MAY keep separate counters for total connections, NEW
 *                   clients, and channel-visibility groups. This node keeps
 *                   exactly one user counter and has no connection-class
 *                   configuration, so producing those three would mean splitting
 *                   one real number into three invented ones. 4.4's range is
 *                   covered by 251, 255, 265 and 266, all of which are real.
 *
 * ---------------------------------------------------------------------------
 * 402 ERR_NOSUMSERVER, AND IT IS A FIFTH HOLE IN 4.4's LIST
 * ---------------------------------------------------------------------------
 * LUSERS and ADMIN both take an optional <server> mask (3.4.2, 3.4.4). On a mesh
 * a server that is asked about another one FORWARDS the question, and 402 is the
 * numeric that says there is nowhere to forward it to. On a single node there is
 * no route, so 402 is exactly the answer -- and it is not in 4.4's error list,
 * which is a gap in the list rather than in the protocol, for the same reason
 * 301, 303, 417 and 302 are (see the note above 4.4's list and
 * msg_verbs.c's handle_userhost()). The RFC numeric is used because it is the
 * one a client understands, and the trailing text names what was actually
 * wrong. Proposed for 4.4's list; recorded in the report.
 */

/* <max clients> -- see the file-header comment for why this is the connection
 * table's bound rather than a configured maximum. SERVER_FD_TABLE rather than
 * FD_SETSIZE written out, so the numeral cannot disagree with the table it
 * describes if that table is ever resized. */
#define NODE_MAX_CLIENTS SERVER_FD_TABLE

/* Is this <server> mask naming THIS node? Case-insensitive, and the fold is
 * channel.h's rather than a strcmp(): 2.4 requires a server-name comparison to
 * be case-insensitive, and chan_same_name() is the one fold the tree exports for
 * exactly that reason -- "is this the same name" must have ONE answer, or a
 * second copy of it is a second rule to fall out of step. */
static int server_mask_is_self(const server_t *s, const char *arg)
{
    return chan_same_name(s->name, arg);
}

/* Peers with an ESTABLISHED link. The state mirror is compared as an int, which
 * is what federation/link.c does at its three other call sites, because
 * server_link_t::state is documented as mirroring handshake_state_t and is only
 * ever written by fed_link_set_state(). */
static size_t established_peers(const server_t *s)
{
    size_t n = 0;

    for (size_t i = 0; i < server_link_count(s); i++) {
        const server_link_t *link = server_link_at(s, i);

        if (link != NULL && link->state == (int)ESTABLISHED) {
            n++;
        }
    }
    return n;
}

/* A <server> mask that is not this node. 402, naming the mask, and NO other
 * numeric: a client that asked about a server this node cannot reach has exactly
 * one thing to do about it, and answering with a 403 (the channel family's
 * "no such channel") would send it looking for a channel. */
static int refuse_foreign_server(server_t *s, conn_t *c, const char *verb,
                                 const char *arg)
{
    (void)reply(s, c, "402", (const char *const[]){ arg }, 1,
                "No such server: %s cannot reach %s", s->name, arg);
    /* `arg` is `m->params[i]` from whichever verb asked -- LUSERS, VERSION, TIME,
     * STATS, LINKS, MOTD -- so it is whatever the client put there, and this line
     * named it. Measured, like every other log-only value in this file: the 402
     * above still echoes the same string back to the client that sent it, which is
     * the right thing for a refusal and is not a hazard, because there is no second
     * reader. */
    {
        char shown[CONN_LOG_FIELD_MAX + 1u];

        (void)conn_text_logsafe(shown, sizeof shown, arg);
        printf("[observable] srv_query: verb=%s nick=%s server=%s server_len=%zu "
               "server_bad_bytes=%zu reason=NO_SUMSERVER\n",
               verb, c->nick, shown, strlen(arg), conn_text_bad_count(arg));
    }
    return 1;
}

/* 251, 254, 255, 265, 266. Order is the RFC's and it matters only to a human
 * reading a log; a client reads all five. */
static void send_lusers(server_t *s, conn_t *c)
{
    size_t clients = server_nick_count(s);
    size_t servers = established_peers(s);
    size_t channels = server_chan_count(s);
    /* The two numbers 265 and 266 need are carried as STRINGS because they are
     * MIDDLE parameters, and 3.2's formatter will not format a number into a
     * non-final parameter position -- it reports the message as unrepresentable
     * instead, which is a refusal on n_reply_refused, the counter reply.c calls
     * a bug report. The same dance send_topic() does for 333's timestamp. */
    char now_clients[24];
    char now_max[24];

    (void)snprintf(now_clients, sizeof now_clients, "%zu", clients);
    (void)snprintf(now_max, sizeof now_max, "%d", NODE_MAX_CLIENTS);

    (void)reply(s, c, "251", NULL, 0, "%s %d %zu %zu %d", s->name, 0, clients,
                servers, NODE_MAX_CLIENTS);
    /* ------------------------------------------------------------------------
     * 254 RPL_LUSERCHANNELS, AND IT IS THE ONE OF THE THREE OPTIONAL REFINEMENT
     * NUMERICS THAT IS NOT OPTIONAL HERE.
     * ------------------------------------------------------------------------
     * RFC 2812 5.1 defines it as "<integer> :channels formed", and 3.4.2 draws
     * the line that matters: "When replying, a server MUST send back
     * RPL_LUSERCLIENT and RPL_LUSERME. The other replies are only sent back if a
     * non-zero count is found for them." So the test is not "is this server's
     * feature set rich" -- it is "is the count zero".
     *
     *   252 RPL_LUSEROP     operators online.   This node has none: 258 says so
     *                      on the wire and CHOPER is unconditionally refused,
     *                      so the count is zero and its absence is CONFORMANT.
     *   253 RPL_LUSERUNKNOWN unknown connections. This node has none: every
     *                      accepted connection becomes either a registered
     *                      client or a peer link, and an unregistered socket is
     *                      not a category the node keeps a count of. Zero, and
     *                      so correctly absent.
     *   254 RPL_LUSERCHANNELS channels formed. NOT zero. This node creates
     *                      channels on the first JOIN and keeps them in the
     *                      registry 2.2 requires, so once anybody has joined
     *                      anything the count is positive and RFC 2812 3.4.2
     *                      requires the numeric.
     *
     * THE NUMBER IS `server_chan_count()`, WHICH IS THE SAME COUNT `LIST` WALKS,
     * and that is worth stating rather than leaving implied: a client can ask
     * LUSERS for the figure and LIST for the items and compare them, and on this
     * node the two agree because they are one counter read twice.
     *
     * SENT ONLY WHEN NON-ZERO, which is the condition RFC 2812 states rather
     * than a preference. A node with no channels emits no 254, and a client
     * reading /LUSERS output sees the same three lines it saw before this phase.
     *
     * THE COST, stated: one more line in every LUSERS answer once a channel
     * exists, which is a line-count change for any test that counts them -- and
     * test_away_notify.c's and test_batch.c's WHOIS counts are the precedent for
     * how this tree handles that. The benefit is that /LUSERS on a node with
     * channels stops omitting a figure a client displays, which is the same
     * "an away state no client can see is not an away state" argument Phase 5
     * made about 301.
     */
    if (channels > 0u) {
        char formed[24];

        (void)snprintf(formed, sizeof formed, "%zu", channels);
        (void)reply(s, c, "254", (const char *const[]){ formed }, 1, "channels formed");
    }
    (void)reply(s, c, "255", NULL, 0, "I have %zu clients and %zu servers", clients,
                servers);
    (void)reply(s, c, "265", (const char *const[]){ now_clients, now_max }, 2,
                "Current local users %s, max %s", now_clients, now_max);
    /* 266's <global> is the same number as 265's <local> on this node, and that
     * is a fact rather than a shortcut: a single node IS the whole of the
     * network it serves, so the two counts coincide until there is a second
     * node. A node that reported a larger global figure would be inventing one. */
    (void)reply(s, c, "266", (const char *const[]){ now_clients, now_max }, 2,
                "Current global users %s, max %s", now_clients, now_max);
    printf("[observable] lusers: nick=%s clients=%zu servers=%zu channels=%zu "
           "max=%d hops=0\n",
           c->nick, clients, servers, channels, NODE_MAX_CLIENTS);
}

static void handle_lusers(server_t *s, conn_t *c, const message_t *m)
{
    /* Every mask must name this node. A mask that named another would be a
     * forwarding question, and refuse_foreign_server() is the honest answer on
     * a node with no route -- the alternative is answering with this node's
     * numbers for a server the client did not ask about. */
    for (int i = 0; i < m->nparams; i++) {
        if (server_mask_is_self(s, m->params[i]) == 0) {
            (void)refuse_foreign_server(s, c, "LUSERS", m->params[i]);
            return;
        }
    }
    send_lusers(s, c);
}

/* 256-259. The two RPL_ADMINLOC slots and the RPL_ADMINEMAIL slot carry FACTS
 * about this node rather than a stand-in for a person, and the honest ones are
 * the two that say there is nothing to report:
 *
 *   257  the node's own identity, which 2.1's fields really hold: its server
 *        name, the network it serves, and the version it reports in 002 and 004.
 *   258  that there is no services and no operator, which is what makes
 *        CHOPER a refusal rather than a grant. A node whose 258 said nothing
 *        about operators would be leaving a client to discover the answer by
 *        trying.
 *   259  that no administrative contact address is configured. RFC 2812 3.4.2
 *        makes 259 a contact address and there is none; putting a string that
 *        reads as an address here would be inventing a mailbox, and a client
 *        that rendered it would offer it to a human.
 */
static void handle_admin(server_t *s, conn_t *c, const message_t *m)
{
    if (m->nparams > 1) {
        (void)reply_refused(s, c, "ADMIN", "TOO_MANY_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    if (m->nparams == 1 && server_mask_is_self(s, m->params[0]) == 0) {
        (void)refuse_foreign_server(s, c, "ADMIN", m->params[0]);
        return;
    }
    (void)reply(s, c, "256", NULL, 0, "Administrative info");
    (void)reply(s, c, "257", NULL, 0, "Server %s on the %s network, version %s",
                s->name, NODE_NETWORK, IRC_SERVE_VERSION);
    (void)reply(s, c, "258", NULL, 0,
                "No services and no operator flags on this node: CHOPER cannot "
                "succeed.");
    (void)reply(s, c, "259", NULL, 0,
                "No administrative contact address is configured for this node.");
    printf("[observable] admin: nick=%s server=%s services=0 oper=0\n", c->nick,
           s->name);
}

/* 371 RPL_INFO, one per line, terminated by 374 RPL_ENDOFINFO.
 *
 * 371 and 374 are a SIXTH hole in 4.4's numeric list -- it has 372-376 for the
 * MOTD and 251-266 for LUSERS and ADMIN, and INFO sits in the gap between the
 * two ranges. Same class of gap as 301, 303, 417, 302 and 402: the RFC defines
 * them, 4.4 does not list them, and the RFC's is the one a client understands.
 * 375 and 376 are NOT used instead, because they are RPL_MOTDSTARTING and
 * RPL_MOTDEND and reusing them for INFO would make the MOTD's terminator lie.
 *
 * The body describes what this node IS and does NOT, and every line is a claim
 * a reader could check against the tree. A description that promised services,
 * authentication or operator support would be a lie with a numeric attached --
 * which is the standard the 324, the 432 and the 301 in this node were all held
 * to. */
static const char *const k_info[] = {
    "- " NODE_NETWORK ": a federation-native IRC node, running " IRC_SERVE_VERSION ".",
    "- client commands: the 4.1 MUST set, plus WHO WHOIS ISON LIST AWAY INVITE",
    "  MOTD LUSERS ADMIN INFO USERHOST KNOCK from 4.2. Unknown verbs are 421.",
    "- channels: JOIN PART TOPIC NAMES LIST KICK MODE, on origin-owned channels",
    "  with the single-writer rule; a state change on a channel this node cannot",
    "  route to is 437.",
    "- channel modes evaluated here: +b. 004 advertises b,k,l,imnpst and every",
    "  other letter is refused with 472 rather than silently ignored.",
    "- user modes: none. 004 advertises i and nothing evaluates it, so a user mode",
    "  offered with MODE is refused too.",
    "- federation: FEDERATE link handshake, the S-verb set, SBURST resync,",
    "  per-node (origin,epoch,id) dedup, hop ceiling 10.",
    "- no authentication, no services, no operator flags: PASS is recorded and not",
    "  checked, and CHOPER is refused with 464 because there is nothing to grant.",
    "- free software under the GNU AGPL v3.0 or later; see LICENSE and NOTICE."
};

static void handle_info(server_t *s, conn_t *c, const message_t *m)
{
    (void)m; /* INFO takes no parameters; RFC 2812 3.4.2 defines none */

    for (size_t i = 0; i < sizeof k_info / sizeof k_info[0]; i++) {
        (void)reply(s, c, "371", NULL, 0, "%s", k_info[i]);
    }
    (void)reply(s, c, "374", NULL, 0, "End of /INFO list");
    printf("[observable] info: nick=%s lines=%zu\n", c->nick,
           sizeof k_info / sizeof k_info[0]);
}

/* ---------------------------------------------------------------------------
 * 4.2's CHOPER, and the REFUSAL POLICY for operator commands
 * ---------------------------------------------------------------------------
 * RFC 2812 3.4.1: `CHOPER <user> <password>`, answered with 381 RPL_YOUREOPER
 * on success. This node cannot produce that, and the reason is a capability
 * rather than a configuration:
 *
 *   - There is no OPERATOR anywhere in the tree. conn_t (2.1) has no operator
 *     field, `struct member` (2.2) carries +o and +v and those are CHANNEL
 *     privileges, and 004's user-mode set is "i" with nothing evaluating it.
 *   - There is no CREDENTIAL STORE. handle_pass() above is the honest version of
 *     this: PASS is recorded and never checked, and s->n_pass_seen is the whole
 *     of the record. A node with nothing to compare a password against cannot
 *     authenticate one, so it must not pretend to have tried.
 *
 * The alternative -- a CHOPER that answers 381 and grants an operator flag that
 * does not exist -- would be the single most damaging thing this command could
 * do: a client would show its owner as an IRCop, every access decision the owner
 * makes would be made by a client acting on a flag the node never set, and
 * nothing in the node's state would contradict it. So the answer is a refusal
 * whose trailing text says what is missing, and 381 is never emitted.
 *
 * ---------------------------------------------------------------------------
 * 464, AND WHY NOT 481/482
 * ---------------------------------------------------------------------------
 * 4.4's error list has 462, 464 and 482 among the numerics a CHOPER could use.
 * 461 answers the arity, because that is the numeral every handler in this node
 * uses and 4.4 lists it; 462 means the same thing and is not the house wording.
 *
 * Between 464 and 481/482 the choice is 464, and the argument is about whose
 * claim each numeric makes:
 *
 *   481 / 482  "you need to be a channel operator to use this" / "you're not a
 *              channel operator". Both are about the CALLER's privileges, and both
 *              are about CHANNEL privilege. handle_kick() uses 482 that way and
 *              is right to: there, a client with no +o really is under-privileged
 *              and the fix is real.
 *   464        "the credentials did not match". The FAILURE is not a fact about
 *              the caller, it is a fact about the SERVER: the same caller would
 *              get this with every password because there is no password. The
 *              trailing text says exactly that, and 464 is also what RFC 2812
 *              3.4.1 names for a CHOPER that did not take effect.
 *
 * Reporting it as a privilege problem would be the false claim, and a false claim
 * in a numeric that a client acts on is what this node has refused to ship
 * everywhere else -- see the 324 that must agree with the node's modes, the 432
 * that must not claim a malformed nick is taken, and the 401 that must not claim
 * an absent user is elsewhere.
 *
 * 401 IS STILL CHECKED, and it comes first, because it is a real question with a
 * real answer and a different failure: CHOPER names a person, and this node
 * either holds that nickname or does not. A node that answered 464 to every
 * CHOPER without looking would be refusing a request about a user who is
 * demonstrably here, and 464's text would be about the wrong thing entirely.
 *
 * THE PASSWORD IS NOT LOGGED, on either path. The 401 and 464 lines name the
 * target and never the password, and the observable line does the same -- the
 * same discipline handle_pass() follows, and for the same reason: a node that
 * printed a secret to its own stdout would leak it into every log collector
 * downstream of it.
 */
static void handle_choper(server_t *s, conn_t *c, const message_t *m)
{
    conn_t *who;

    if (m->nparams != 2) {
        (void)reply_refused(s, c, "CHOPER", "INVALID_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    /* fanout_find_nick() rather than server_nick_lookup(): both are the same
     * folded registry, and the wrapper is the one that carries the NULL and
     * empty-name guards. The empty-name guard is DEFENCE IN DEPTH and not a
     * reachable case from this command: 3.2 has no way to express an empty
     * middle parameter -- 4.3.1 says the same about a wire format -- so a
     * `CHOPER :<password>` reaches the arity check as a message with ONE
     * parameter and is refused there, and any name that gets past it is
     * non-empty by construction. The wrapper is used rather than the raw lookup
     * because it is the one that would be correct if that ever stopped being
     * true, and because a caller must not have to know it. */
    who = fanout_find_nick(s, m->params[0]);
    if (who == NULL) {
        (void)reply(s, c, "401", (const char *const[]){ m->params[0] }, 1,
                    "No such nick/channel");
        /* Measured, for the reason every other log-only value here is: this
         * branch is reached precisely when the name is one this node does NOT
         * hold, so it is the one place a nickname-shaped string arrives that has
         * not been through `valid_nick()`. The 401 above still names it back to
         * its sender. */
        {
            char shown[CONN_LOG_FIELD_MAX + 1u];

            (void)conn_text_logsafe(shown, sizeof shown, m->params[0]);
            printf("[observable] choper_refused: by=%s target=%s target_len=%zu "
                   "target_bad_bytes=%zu reason=NO_SUCH_NICK\n",
                   c->nick, shown, strlen(m->params[0]),
                   conn_text_bad_count(m->params[0]));
        }
        return;
    }

    /* 464, WHICH THE SAME NUMBER ALSO ANSWERS FOR A FAILED SASL EXCHANGE. For a
     * client that negotiated `standard-replies` this is
     * `FAIL CHOPER ERR_NOPRIVILEGES`, which says "you are not an operator" rather
     * than leaving the client to work out that an operator request and a
     * credential failure share a number. */
    (void)reply_refused(s, c, "CHOPER", NULL, "464", NULL, 0,
                        "%s cannot become an operator: this server holds no "
                        "operator flags and no operator credentials",
                        who->nick);
    printf("[observable] choper_refused: by=%s target=%s reason=NO_OPER_FLAGS "
           "oper=0 pass_seen=%llu\n",
           c->nick, who->nick, (unsigned long long)s->n_pass_seen);
}

/* CAP. A one-line pass-through to cap.c, and it is here rather than a function
 * pointer straight into cap_handle() so that the dispatch table's entry has the
 * same shape as every other entry in it. The logic is cap.c's; this says only
 * that `CAP` reaches it. */
/* ---------------------------------------------------------------------------
 * STARTTLS, and THE FOUR REFUSALS ARE THE FEATURE
 * ---------------------------------------------------------------------------
 * The upgrade itself is three lines: queue 670, flush it, let the transport take
 * over the socket. Everything that matters is in what this refuses, and each
 * refusal is a rule from a specification rather than a judgement call.
 *
 * ---------------------------------------------------------------------------
 * FIRST: THERE IS NO STARTTLS IN RFC 2812
 * ---------------------------------------------------------------------------
 * This project's Phase 11 pass built an RFC 2812 conformance table by reading the
 * RFC. RFC 2812 defines NO STARTTLS: the string does not appear in it, nor do the
 * numerics 670 and 691, and neither does the word TLS. STARTTLS is an IRCv3
 * extension -- the `tls` capability specification, which is DEPRECATED in favour
 * of `sts` -- and it is the normative source for everything below. Saying so here
 * rather than leaving a future reader to assume the RFC says it is the difference
 * between a documented citation and a plausible one, and the `sts` specification's
 * own relationship section is what makes the point: STS "is incompatible with
 * servers that offer secure connections only via STARTTLS on an insecure port."
 * STARTTLS is implemented because the command is real and clients use it; `sts` is
 * advertised because it is the mechanism that actually protects anything.
 *
 * ---------------------------------------------------------------------------
 * THE REFUSALS, in the order they are checked, and why that order
 * ---------------------------------------------------------------------------
 *   1. NOT CONFIGURED     this build has no TLS, or this node has no certificate.
 *                         691. Checked FIRST because it is the only one that is a
 *                         permanent property of the node: everything below is a
 *                         statement about this connection.
 *
 *   2. ALREADY TLS        691. Refusing is not politeness -- it is arithmetic. A
 *                         second STARTTLS would mean a second handshake layered
 *                         inside the first one's session, and a client that
 *                         expected one would read the ServerHello as IRC and hang.
 *
 *   3. AFTER A CREDENTIAL 691, AND THIS IS THE ONE THAT IS EASY TO GET WRONG. The
 *                         whole point of upgrading is that what follows is private.
 *                         If a client has already sent a password, upgrading does
 *                         not un-send it: an attacker who has been reading the
 *                         plaintext prefix has the credential, and everything after
 *                         the upgrade being encrypted is a very comfortable
 *                         theatre. So a connection that has carried a PASS value or
 *                         an AUTHENTICATE payload is REFUSED -- including when the
 *                         credential was refused, which is what
 *                         conn_t::credential_seen's comment is about.
 *
 *                         IT IS CHECKED BEFORE THE REGISTRATION RULE BELOW, and
 *                         that is a decision rather than an ordering accident: see
 *                         the comment at the check.
 *
 *   4. AFTER REGISTRATION 691. The `tls` specification: "To use STARTTLS a client
 *                         simply sends the STARTTLS command to the server BEFORE
 *                         THE CLIENT REGISTERS WITH THE SERVER USING THE NICK AND
 *                         USER COMMANDS". After registration this node has already
 *                         emitted 001-005, MOTD and possibly a JOIN; a client that
 *                         re-handshakes mid-registration has a burst half-sent in
 *                         the clear and the rest encrypted, and a peer relaying
 *                         those lines sees two different transports on one
 *                         connection. There is no version of this that is safe to
 *                         allow, and the specification's position is that it is not
 *                         a thing to allow.
 *
 * A legitimate client costs nothing by this: every current client that wants TLS
 * either connects to the implicit-TLS port (RFC 7194) or sends STARTTLS first
 * thing, before NICK and USER. The order is not an inconvenience; it is the
 * specification's.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS DISCARDED ON SUCCESS, and it is a security step rather than a tidy-up
 * ---------------------------------------------------------------------------
 * `c->rlen = 0` below. The read buffer may hold lines the client PIPELINED behind
 * its STARTTLS -- `STARTTLS\r\nJOIN #x\r\n` in one segment, which every capable
 * client library will do -- and those lines arrived IN THE CLEAR, before the peer
 * proved anything. Leaving them in the buffer would mean dispatching them after the
 * handshake, as though they had arrived over the encrypted connection: an attacker
 * who could inject into the plaintext prefix could have them executed on a
 * connection the operator believes is authenticated and encrypted.
 *
 * The write queue is NOT cleared, and the asymmetry is deliberate: everything in it
 * was queued before the upgrade and is being sent in the clear legitimately (the
 * 670 itself is in there), and the node has nothing it would be ashamed to send
 * before a handshake.
 *
 * ---------------------------------------------------------------------------
 * 670 AND 691 ARE NOT IN RFC 2812 EITHER
 * ---------------------------------------------------------------------------
 * They come from the same deprecated `tls` extension, which gives them verbatim:
 * "the server then sends numeric 670 (RPL_STARTTLS)" and "If there is an error
 * with setting up TLS on the server side, the server must send numeric 691
 * (ERR_STARTTLS) containing a human-readable description of the error as its
 * parameter." RFC 2812 4.5 assigns 6xx to ERR_* and 670/691 fall in that range, so
 * the shape is the RFC's even though the two numbers are not. Every 691 below
 * carries a distinct text, because the specification says the text is for a human
 * and a client cannot machine-parse it: an operator reading the log needs to know
 * WHICH rule fired, and one shared "STARTTLS failed" would be the least useful
 * thing in the file. */
static void handle_starttls(server_t *s, conn_t *c, const message_t *m)
{
    /* ARITY FIRST, and it is 461 rather than 691. A STARTTLS with a parameter is a
     * malformed command, and 461 is this node's answer for that everywhere else; a
     * 691 here would claim the server tried and failed at TLS on a line that never
     * named TLS. */
    if (m->nparams > 0) {
        (void)reply_refused(s, c, "STARTTLS", NULL, "461", NULL, 0,
                            "Not enough parameters");
        return;
    }
    if (tls_backend_available() == 0 || s->tls == NULL) {
        (void)reply(s, c, "691", NULL, 0, "STARTTLS failed: TLS is not available "
                                            "on this server");
        printf("[observable] starttls_refused: fd=%d reason=TLS_NOT_CONFIGURED\n",
               c->fd);
        return;
    }
    if (c->tls_active != 0) {
        (void)reply(s, c, "691", NULL, 0,
                    "STARTTLS failed: this connection is already using TLS");
        printf("[observable] starttls_refused: fd=%d reason=ALREADY_TLS\n", c->fd);
        return;
    }
    /* THE CREDENTIAL CHECK COMES BEFORE THE REGISTRATION CHECK, and the order is
     * the point.
     *
     * Both are refusals and both are correct, so the only question is which reason
     * an operator and a client are told -- and a client that has sent a password
     * AND then registered has done both things, and the one it needs to hear about
     * is that its password went out in the clear. "it is only available before
     * registration" would be true and would hide the finding that matters: that this
     * node is being asked to make an encrypted connection out of a socket that has
     * already leaked a credential, and that somebody needs to go and change it.
     *
     * Checking registration first was the first version, and it produced exactly
     * that: a client which sent PASS, NICK, USER, STARTTLS -- which is what a
     * client that has decided to authenticate does -- was told it was too late,
     * with no mention of the password. A refusal that is true and incomplete is
     * worse than one that is verbose. */
    if (c->credential_seen != 0) {
        (void)reply(s, c, "691", NULL, 0,
                    "STARTTLS failed: a credential has already been sent on this "
                    "connection in the clear");
        printf("[observable] starttls_refused: fd=%d "
               "reason=AFTER_CREDENTIAL\n", c->fd);
        return;
    }
    if (c->state != CONN_REG_PASS) {
        (void)reply(s, c, "691", NULL, 0,
                    "STARTTLS failed: it is only available before registration");
        printf("[observable] starttls_refused: fd=%d reason=AFTER_REGISTRATION "
               "state=%d\n", c->fd, c->state);
        return;
    }
    /* THE DISCARD, before the confirmation and not after it: a line that arrived
     * in the clear must never be dispatched after the handshake. */
    c->rlen = 0;
    /* The 670, in the clear, with the specification's own wording. It is QUEUED
     * and not sent, and this handler never touches the socket -- which is not a
     * style preference but reply.c's whole rule, the one
     * tests/integration/test_reply_guard.c asserts by inspection: a handler that
     * reaches past reply() into the transport is a second place that decides what
     * reaches a connection.
     *
     * THE ORDERING IS NONE THE WORSE FOR IT, and that is the part worth checking.
     * conn_queue() raises want_write, so the loop's very next poll set asks for
     * POLLOUT; conn_on_writable() drains the queue through conn_pump(); and
     * conn_pump() starts the handshake only once the queue is EMPTY. So the 670 is
     * on the wire before the first byte of the handshake by construction, and it is
     * on the wire because the LOOP put it there.
     *
     * An earlier version of this handler called conn_pump() directly, to make the
     * 670 prompt. That cost test_reply_guard's invariant for no benefit: the loop
     * flushes within one tick either way, because the socket is writable. That is
     * what a suite is for -- the rule was written before this handler existed and
     * it was right. */
    c->starttls_pending = 1;
    (void)reply(s, c, "670", NULL, 0, "STARTTLS successful, proceed with TLS "
                                      "handshake");
    printf("[observable] starttls_agreed: fd=%d\n", c->fd);
}

static void handle_cap_wrapper(server_t *s, conn_t *c, const message_t *m)
{
    cap_handle(s, c, m);
}

/* ---------------------------------------------------------------------------
 * REGISTER and UNREGISTER -- REFUSED, and this is the decision rather than the
 * omission. Read the argument before changing the answer.
 * ---------------------------------------------------------------------------
 * The IRCv3 `account-registration` specification is in k_caps[]' absence and in
 * both of these handlers. Four independent reasons, and each of them is
 * sufficient on its own; they are given in the order they would stop a reviewer.
 *
 * 1. THE SPECIFICATION SAYS NOT TO. `account-registration` is a
 *    work-in-progress document whose own header says implementations "MUST NOT
 *    use the unprefixed account-registration capability name", SHOULD use
 *    `draft/account-registration` instead, and that the specification "may change
 *    at any time and we do not recommend implementing it in a production
 *    environment". Shipping a stable command named `REGISTER` that a draft will
 *    later redefine is how a server ends up un-upgradable without anyone noticing.
 *
 * 2. ITS WIRE FORM WAS NOT AVAILABLE WHEN THIS WAS WRITTEN, and half of that
 *    reason has since expired. The draft answers with the standard replies
 *    framework -- `FAIL ACCOUNT_REGISTER <reason>` -- and this node had no FAIL at
 *    the time, so there was no numeric a real client parses as a registration
 *    answer. Phase 10.9 landed `standard-replies`, so the form EXISTS now and the
 *    refusal below renders as `FAIL REGISTER ERR_ACCOUNTREGISTRATIONDISABLED` for
 *    a client that negotiated it.
 *
 *    WHAT THE ARRIVAL DID NOT CHANGE IS THE DECISION, and that is worth being
 *    blunt about rather than leaving a reader to wonder whether reason 2 quietly
 *    expired and took the refusal with it: **being able to say the right thing is
 *    not a reason to say it.** Reasons 3 and 4 are the ones that hold, and neither
 *    mentions the wire form. A node that could answer the command truthfully
 *    should still refuse it, and the refusal is now the more precise of the two
 *    renderings rather than a compromise.
 *
 * 3. OPEN REGISTRATION IS NOT A FEATURE HERE, IT IS A NAME-CLAIMING PRIMITIVE.
 *    REGISTER takes a password and an optional email and, without a verification
 *    mail and without a rate limit, the ONLY thing stopping an unauthenticated
 *    client from taking any name is the speed of the connection. And taking a
 *    name is not a nuisance here: once `account-tag` exists, an account name is
 *    stamped on every message a client sends, and the entire value of the tag is
 *    that it means "this is who this is". An open registry makes that value
 *    worthless to every honest user while remaining perfectly usable as an
 *    impersonation tool against them -- so the failure mode is not "the feature
 *    is half-built", it is "the feature actively harms the people it was built
 *    for". There is no rate limiter, no captcha and no mail path in this tree,
 *    and the account store is READ-ONLY after startup: there is no write in this
 *    tree that could record a registration even if one were allowed.
 *
 * 4. UNREGISTER IS WORSE THAN NOTHING, which is why it is refused too and not
 *    implemented. The store is an operator's file, loaded once before the loop
 *    (3.4 forbids a blocking write inside it), so an in-memory removal would
 *    vanish on the next restart. A client told "your account has been deleted"
 *    and then finding it intact after a restart has been told a falsehood by a
 *    server that is supposed to be the authority on whether an account exists --
 *    and account deletion is precisely the case where a user is relying on the
 *    answer. Refusing is the only answer that is true at every moment.
 *
 * THE THREAT MODEL, stated once and plainly: on a node with this pair of
 * commands refused, an attacker can still connect, register a nickname, send
 * messages, and join channels -- everything this node has always allowed. What
 * they CANNOT do is assert an account identity, because the only writer of
 * conn_t::account is account_set() and it requires a credential the operator's
 * credential store holds AND a registry entry the operator's registry holds.
 * That is the whole of the model, and the cost of it is that accounts on this
 * node are created by an operator editing a file. That cost is stated rather than
 * hidden: it is real, it is the reason a deployment with open registration
 * should not use this node, and it is cheaper than the alternative.
 *
 * ---------------------------------------------------------------------------
 * 482, AND WHY IT IS WRONG
 * ---------------------------------------------------------------------------
 * 482 ERR_CHANOPRIVSNEEDED. Not in RFC 1459's sense -- it is not about a channel
 * -- but its own RFC text is "Permission Denied- You're not an IRC operator",
 * and that is the truest available answer: this node has NO operator concept at
 * all, so a client that has not been made one is being told the truth. It is also
 * the numeric CHOPER already answers with, for the same reason, and reusing it
 * keeps "there is no operator here" to one numeric.
 *
 * The honest numeric is `FAIL ACCOUNT_REGISTRATION NOT_ENABLED`, and it does not
 * exist until standard-replies does. That gap is recorded in the design rather
 * than papered over, and it is the third of the four reasons above.
 */
static void account_refuse(server_t *s, conn_t *c, const char *verb,
                           const char *text)
{
    /* 482, WHICH ON THIS NODE ALSO MEANS "NOT A CHANNEL OPERATOR" (KICK, MODE,
     * INVITE) and "NOT AN IRC OPERATOR" (KNOCK). A REGISTER refused because the
     * deployment has no open registration is a third fact wearing the same number,
     * and `verb` is already the command word the `FAIL` needs -- which is why this
     * site's code is an override rather than the table's. */
    (void)reply_refused(s, c, verb, "ERR_ACCOUNTREGISTRATIONDISABLED", "482", NULL, 0,
                        "%s", text);
    printf("[observable] account_cmd_refused: fd=%d nick=%s verb=%s "
           "reason=OPERATOR_SIDE_REGISTRY registry=%s\n",
           c->fd, (c->nick[0] != '\0') ? c->nick : "*", verb,
           (s->account_store != NULL) ? "loaded" : "none");
}

/* REGISTER <password> [email]. Refused unconditionally and without reading the
 * arguments, and the arity is NOT checked first: a `REGISTER` with no password
 * and a `REGISTER` with one both get the same answer, because answering one of
 * them differently would be a way to probe which inputs the node recognises --
 * which is the shape of every oracle this tree has refused to build. */
static void handle_register(server_t *s, conn_t *c, const message_t *m)
{
    (void)m;
    account_refuse(s, c, "REGISTER",
                   "REGISTER is not available: this node's accounts are created "
                   "by its operator in a registry file");
}

/* ---------------------------------------------------------------------------
 * ACCOUNT -- the account-notify query, and the collision that had to be resolved
 * deliberately rather than by accident
 * ---------------------------------------------------------------------------
 * `ACCOUNT` was, in the retired draft, the NICKNAME-CHANGE command: a client
 * changed its nick and supplied a password in one command, and `ACCOUNT
 * <password>` is the shape every server of that era accepted.
 *
 * **WHAT THIS NODE DISPATCHED BEFORE THIS PASS: NOTHING.** There was no
 * `ACCOUNT` row in k_commands[] at all, so a client that sent it got 421 -- "I
 * have never heard of this verb" -- and a nickname change was, and still is, `NICK
 * <newnick>` and nothing else (handle_nick(), above). So there was no live
 * nick-change verb to collide with, and adding this row cannot break a nick
 * change: the two words have never reached the same switch.
 *
 * The IRCv3 position is that the nick-change MEANING is gone rather than merely
 * unfashionable: an account association changed through the account service, not
 * through the server, and a server that took a password on a nickname change was
 * a server asking for a credential it had no way to verify. What survives is the
 * name, reused by `account-notify` for a completely different fact.
 *
 * THE TWO SHAPES ARE ALSO DISJOINT, which is worth saying because it is the reason
 * the collision costs nothing rather than merely nothing today:
 *
 *   the retired nick-change form  ACCOUNT <password>   ONE parameter
 *   the query below               ACCOUNT              ZERO parameters
 *
 * So a client still speaking the retired dialect gets 461 for a verb with a
 * parameter, not a nickname change. That is the right answer and it is also the
 * reason a future phase that wanted a one-parameter ACCOUNT would have to decide
 * to take it back rather than find it already spoken for.
 *
 * WHAT IS *NOT* HERE, and is the honest limit of this implementation:
 * `ACCOUNT <account> FAIL`. There is no logout on this node -- SASL PLAIN has no
 * logout and there is no account service to log out of, and account_clear() runs
 * only from server_close_conn(), where the connection is already gone -- so there
 * is no event the form describes. account.h says where an emitter would go if a
 * phase adds one. */
static void handle_account(server_t *s, conn_t *c, const message_t *m)
{
    if (m->nparams != 0) {
        (void)reply_refused(s, c, "ACCOUNT", "INVALID_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        printf("[observable] account_cmd_refused: fd=%d nick=%s verb=ACCOUNT "
               "reason=arity nparams=%d\n", c->fd, c->nick, m->nparams);
        return;
    }
    /* ANSWERED REGARDLESS OF THE CAPABILITY, because the client ASKED. The
     * capability governs the unsolicited line at the end of the welcome burst;
     * refusing a question a client put on the wire would be a node that knows the
     * answer and will not give it. */
    account_notify_current(s, c);
}

/* UNREGISTER [password]. Refused unconditionally, for reason 4 above. */
static void handle_unregister(server_t *s, conn_t *c, const message_t *m)
{
    (void)m;
    account_refuse(s, c, "UNREGISTER",
                   "UNREGISTER is not available: this node's accounts are created "
                   "by its operator in a registry file");
}

/* ---------------------------------------------------------------------------
 * CAP and AUTHENTICATE (Phase 8)
 * ---------------------------------------------------------------------------
 * Both are pre-registration verbs, and BOTH HAVE TO BE: the protocol puts CAP
 * before NICK and USER, and RFC 4422's SASL is answered inside the registration
 * burst rather than after it. Marking either `pre_reg = 0` would answer 451 to a
 * client that is doing exactly what the specification says, which is the failure
 * that hangs every modern client.
 *
 * The handlers live here rather than in cap.c and a new sasl handler file because
 * this is the dispatch table and a verb with no entry here cannot be reached at
 * all. The LOGIC lives in cap.c and sasl_framework.c; these two functions are the
 * wire. */

/* AUTHENTICATE, RFC 4422 3.1 / IRCv3 sasl.
 *
 *   AUTHENTICATE PLAIN                 -> server: AUTHENTICATE +
 *   AUTHENTICATE PLAIN <base64>        -> one-shot, verified
 *   AUTHENTICATE <base64>              -> the response to the '+'
 *   AUTHENTICATE *                     -> the client abandons the exchange
 *
 * The '+' is the initial-response request: it asks the client to send a
 * PLAIN payload without naming the mechanism again, which is the form every
 * client actually uses and the form that would be impossible to answer if this
 * node only understood a mechanism on the first line.
 *
 * ---------------------------------------------------------------------------
 * WHAT A BAD CREDENTIAL DOES
 * ---------------------------------------------------------------------------
 * It fails REGISTRATION, and that is the requirement this design is explicit
 * about rather than incidental. The three responses are, in order:
 *
 *   1. `AUTHENTICATE *` -- RFC 4422's server-chosen abort. It tells the client the
 *      exchange is over, so a client that is waiting for a verdict gets one and
 *      does not wait for a deadline.
 *   2. `464 ERR_PASSWDMISMATCH` -- the RFC numeric for credentials that did not
 *      take. NOT 908 (RPL_SASLMECHS, which would offer the client a second try at
 *      a credential it just got wrong, turning one failure into an unlimited
 *      guessing loop) and NOT 451.
 * The connection is NOT closed here, and the reason is a property of the loop
 * rather than a judgement about the client: poll_loop.c refuses to pump the write
 * queue of a CONN_CLOSING connection, and the reaper frees that queue with the
 * conn_t. Marking CLOSING in the same dispatch that queues the abort and the 464
 * would DISCARD BOTH, so a client whose credential failed would see a bare FIN
 * with no explanation -- strictly worse than telling it. So the connection is
 * left open and unusable: commands_state_update() refuses the transition while
 * c->sasl is SASL_FAILED, so every non-registration command is 451 and 001 can
 * never arrive.
 *
 * THE COST, stated rather than hidden: a client that neither disconnects nor
 * gives up holds one slot in by_fd and one write queue until it goes away, and
 * nothing here closes it for it. The slot is bounded by SERVER_FD_TABLE, so this
 * is a cap on how many such connections can exist rather than an unbounded leak,
 * and the alternative -- an immediate close that throws away the explanation --
 * is worse. Closing them on the next poll iteration would need a second state
 * that distinguishes "closing after the reason was queued" from every other
 * CLOSING, which is a loop change and not an authentication one.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS AND IS NOT IN THE [observable] LINE
 * ---------------------------------------------------------------------------
 * The authcid and the outcome. NEVER the password, the base64 payload, or the
 * authzid -- and the authzid is excluded for a reason beyond tidiness: it is a
 * third field of the payload and a caller-supplied string that a client can put
 * anything in, so logging it adds an injection vector to the log for no
 * diagnostic gain. The authcid is a login name and the operator needs it; the
 * other two are the credential.
 *
 * The payload is also not rendered into a buffer anywhere on this path: it is
 * decoded into a stack array, split, verified, and dropped. There is no place in
 * this function where a credential could be printed by accident later, because
 * there is no variable holding one afterwards. */
static void handle_authenticate(server_t *s, conn_t *c, const message_t *m)
{
    const char *mech = NULL;
    const char *arg = NULL;
    unsigned char payload[SASL_MAX_PAYLOAD];
    char authzid[SASL_MAX_AUTHCID + 1];
    char authcid[SASL_MAX_AUTHCID + 1];
    char passwd[SASL_MAX_PASSWORD + 1];
    long decoded;
    const char *params[2];

    /* BEFORE EVERYTHING, INCLUDING THE ABORT. See conn_t::credential_seen: what
     * this records is that a credential was OFFERED, and an offer that was then
     * refused is the interesting case rather than an edge one. `AUTHENTICATE *`
     * carries no payload at all and so arguably offers nothing -- but it is set
     * anyway, deliberately, because "the client got as far as starting SASL and
     * then asked to upgrade the socket" is a shape an attacker produces, and
     * refusing it costs a legitimate client nothing: a client that wants to
     * STARTTLS sends STARTTLS. */
    c->credential_seen = 1;

    /* AUTHENTICATE * is the ABORT (RFC 4422 3.1), and it is answered before any
     * parsing: a client abandoning an exchange must not have to supply a
     * well-formed one to be allowed to stop. It leaves the connection
     * registerable, because declining to authenticate is not failing to. */
    if (m->nparams >= 1 && strcmp(m->params[0], "*") == 0) {
        c->sasl = (int)SASL_ABORTED;
        printf("[observable] sasl: fd=%d outcome=ABORTED\n", c->fd);
        return;
    }

    /* WHICH PARAMETER IS THE MECHANISM, AND WHICH IS THE RESPONSE.
     *
     * RFC 4422's first form is `AUTHENTICATE <mechanism> [<initial-response>]`,
     * so two parameters is unambiguous. The SECOND form -- the client answering
     * the '+' this node sent -- is a single parameter that is NOT a mechanism
     * name, and there is no syntactic way to tell the two apart: a base64 blob
     * may have no '=' padding and may begin with any of the 64 alphabet
     * characters, so "does it contain '='" and "does it start with a plausible
     * name" are both guesses that break on a real client.
     *
     * The answer is the STATE, and that is why c->sasl is a field on the
     * connection at all. A single parameter while an exchange is in progress is
     * the response; a single parameter with no exchange in progress is a
     * mechanism name. The alternative -- guessing from the bytes -- is how a
     * server accepts a credential it never asked for. */
    if (m->nparams >= 2) {
        mech = m->params[0];
        arg = m->params[1];
    } else if (m->nparams == 1) {
        if (c->sasl == (int)SASL_IN_PROGRESS) {
            mech = "PLAIN";
            arg = m->params[0];
        } else {
            mech = m->params[0];
        }
    }
    if (mech == NULL) {
        /* Either a bare `AUTHENTICATE` or a first line that is neither a known
         * mechanism nor a payload. 908 offers the one mechanism this node has,
         * which is the answer a client needs and the only honest one: a node with
         * no credential store has NO mechanism, and saying so is what 908's list
         * being empty means. */
        params[0] = (sasl_store_count(s->sasl_store) > 0u) ? "PLAIN" : "";
        (void)reply(s, c, RPL_SASLMECHS, params, 1,
                    "are available SASL mechanisms");
        printf("[observable] sasl: fd=%d outcome=NO_MECHANISM store=%zu\n", c->fd,
               sasl_store_count(s->sasl_store));
        return;
    }
    if (strcasecmp(mech, "PLAIN") != 0) {
        /* A mechanism this node names but does not implement, or one it does not
         * know at all. 908 rather than a refusal: the client asked what it can
         * use, and the answer is what it can use. */
        params[0] = (sasl_store_count(s->sasl_store) > 0u) ? "PLAIN" : "";
        (void)reply(s, c, RPL_SASLMECHS, params, 1,
                    "are available SASL mechanisms");
        /* THE MECHANISM IS MEASURED, NOT ASSUMED SAFE. It is worth saying
         * explicitly because an earlier reading of this pass claimed `mech` was
         * "already bounded and named by 908" -- it is NEITHER. Nothing bounds it
         * before this line: it is `m->params[0]`, so it may be as long as the line
         * cap, and 908 names the mechanism in a REPLY to the client rather than
         * constraining what the log may print. Measured on the pre-fix binary, a
         * single `AUTHENTICATE <ESC>[2J` put both bytes in the log.
         *
         * `authzid` is excluded from this line and from every other line on this
         * path deliberately, and the header at handle_authenticate() gives the
         * reason: it is the other half of a credential and adding it to a log buys
         * nothing. That exclusion is unchanged. */
        {
            char shown[CONN_LOG_FIELD_MAX + 1u];

            (void)conn_text_logsafe(shown, sizeof shown, mech);
            printf("[observable] sasl: fd=%d outcome=MECH_REFUSED mech=%s "
                   "mech_len=%zu mech_bad_bytes=%zu\n",
                   c->fd, shown, strlen(mech), conn_text_bad_count(mech));
        }
        return;
    }

    if (arg == NULL) {
        /* Start the exchange. The '+' is a trailing parameter with no space in
         * it, and RFC 4422 requires it to be exactly that. */
        c->sasl = (int)SASL_IN_PROGRESS;
        params[0] = c->nick[0] != '\0' ? c->nick : "*";
        params[1] = "+";
        (void)send_line(s, c, NULL, "AUTHENTICATE", params, 2);
        printf("[observable] sasl: fd=%d outcome=STARTED mech=PLAIN\n", c->fd);
        return;
    }

    decoded = sasl_b64_decode(arg, strlen(arg), payload, sizeof payload);
    if (decoded < 0 ||
        sasl_plain_parse((const char *)payload, (size_t)decoded, authzid,
                         sizeof authzid, authcid, sizeof authcid, passwd,
                         sizeof passwd) != 0) {
        c->sasl = (int)SASL_FAILED;
        s->n_sasl_fail++;
        /* ONE parameter, so the line is exactly `AUTHENTICATE *`. With two the
         * formatter would colonned the '*' (a value beginning with ':' or
         * holding a space needs the marker, and this one needs neither) and the
         * client would see a trailing parameter where RFC 4422 3.1 specifies a
         * single one. The abort is the one line in this exchange a client reads
         * with a byte comparison, so it is written as the RFC writes it. */
        params[0] = "*";
        (void)send_line(s, c, NULL, "AUTHENTICATE", params, 1);
        /* `INVALID_AUTHENTICATE` is the code the SASL specification defines for
         * exactly this -- an AUTHENTICATE whose payload this node cannot read --
         * and standard-replies says an existing code MUST be used where one is
         * defined. The other two 464 sites are NOT this, which is why they carry
         * different codes. */
        (void)reply_refused(s, c, "AUTHENTICATE", "INVALID_AUTHENTICATE", "464",
                            NULL, 0,
                            "SASL PLAIN payload was not base64 or not three "
                            "NUL-separated fields");
        conn_mark_closing(c);
        printf("[observable] sasl: fd=%d outcome=REJECTED reason=BAD_PAYLOAD\n",
               c->fd);
        return;
    }

    /* The verification itself. No store means no authentication, and the node
     * does not pretend otherwise: cap.c has already withheld `sasl` from CAP LS,
     * so a client that reached here has either ignored the advertisement or
     * arrived with a hard-coded configuration. */
    if (!sasl_plain_verify(s->sasl_store, authzid, authcid, passwd)) {
        const int no_store = (sasl_store_count(s->sasl_store) == 0u);

        c->sasl = (int)SASL_FAILED;
        s->n_sasl_fail++;
        params[0] = "*";
        (void)send_line(s, c, NULL, "AUTHENTICATE", params, 1);
        /* The text says WHICH failure, because the operator needs to know
         * whether to fix the store or to look for an attack, and the client
         * needs to know not to retry the same password. It never says anything
         * about the credential itself. */
        /* NOT `SAASL_FAIL`, which the registry defines as an account that is
         * TEMPORARILY locked: neither of this node's two failures is that, and a
         * client reading `SAASL_FAIL` would offer the user to wait and retry a
         * password that will never verify. The registry has no code for "the
         * credentials did not verify", so this one is `ERR_`-prefixed as ours. */
        (void)reply_refused(s, c, "AUTHENTICATE", "ERR_AUTHENTICATIONFAILED", "464",
                            NULL, 0, "SASL authentication failed: %s",
                            no_store ? "this node holds no client credential store"
                            : "the credentials did not verify");
        printf("[observable] sasl: fd=%d authcid=%s outcome=REJECTED reason=%s\n",
               c->fd, authcid, no_store ? "NO_STORE" : "BAD_CREDENTIAL");
        return;
    }

    /* Verified. What is recorded is the fact and the identity, so a later numeric
     * could report it; the counter is the node's own claim and it is incremented
     * here because this is the only place a credential is ever accepted.
     *
     * AND THE ACCOUNT IS ESTABLISHED HERE, which is the whole of what Phase 10.1
     * added to this function. Until now `c->sasl = SASL_COMPLETED` granted
     * nothing and recorded an authcid nothing could read, which is why seven
     * IRCv3 specs were blocked on an account concept that did not exist: SASL
     * authenticates a CONNECTION and an account is what you are ACROSS
     * connections.
     *
     * THE PASSWORD IS HANDED TO account_set() AND NOT STORED, and it is the same
     * `passwd` local that sasl_plain_verify() just read. account_set() re-checks
     * it against the OPERATOR'S ACCOUNT REGISTRY -- a different table from the
     * credential store this function verified against -- so a node whose two
     * files disagree about `alice` logs her in as nobody rather than logging her
     * in as an account that does not exist. That is the fail-closed direction and
     * it costs one bounded constant-time walk on a path that runs once per login.
     *
     * A REFUSAL HERE IS NOT AN AUTHENTICATION FAILURE. The credential verified;
     * the client is authenticated and is simply not identified to an account,
     * which is the same state as a client that declined to authenticate. So
     * `c->sasl` stays COMPLETED, registration proceeds, and the node says why on
     * its own output -- because the alternative (refusing the whole exchange
     * because an account was not configured) would make adding an account
     * registry a change to who can log in, and it must not be.
     */
    c->sasl = (int)SASL_COMPLETED;
    s->n_sasl_ok++;
    if (account_set(s, c, authcid, passwd) != 0) {
        s->n_account_refused++;
        printf("[observable] account: fd=%d authcid=%s outcome=REFUSED reason=%s "
               "registry=%s\n",
               c->fd, authcid,
               (s->account_store == NULL) ? "NO_REGISTRY" : "NOT_IN_REGISTRY",
               (s->account_store != NULL) ? "loaded" : "none");
    }
    /* TWO KEYS AND NOT ONE, and the split is deliberate: `logged_in` is the
     * BOOLEAN and `account=` on account_set()'s line is a NAME. Rendering both
     * as `account=` would put a name and a 0/1 behind one key on two different
     * lines, and a reader (or a grep, or a test) asking "what is this user's
     * account" would have to know which of the two it had found. */
    printf("[observable] sasl: fd=%d authcid=%s outcome=COMPLETED granted=0 "
           "logged_in=%d\n",
           c->fd, authcid, account_logged_in(c));
    /* Registration is not forced here. A client that sent NICK and USER before
     * its AUTHENTICATE has already satisfied the state machine, and if it was
     * held for CAP it is still held -- so the gate is re-evaluated rather than
     * bypassed. */
    commands_state_update(s, c);
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
    /* 7/Phase 8. Both are pre-registration verbs: CAP is sent BEFORE NICK and
     * USER by every current client, and SASL is answered inside the registration
     * burst. `pre_reg = 1` on both is load-bearing -- see the comment above
     * handle_cap() and handle_authenticate(). */
    { "CAP",     handle_cap_wrapper, 1 },
    { "AUTHENTICATE", handle_authenticate, 1 },
    /* Phase 12: STARTTLS. `pre_reg = 1` is the whole of the specification's rule
     * and it is enforced a second time inside the handler, because a client that
     * sends STARTTLS after NICK and USER must be answered 691 rather than 451 --
     * "you have not registered" is a lie about a connection that HAS registered,
     * and the honest answer names the real problem. So `pre_reg = 1` gets the
     * command to the handler on a registered connection, and the handler decides.
     * That is why this row sits with CAP and AUTHENTICATE and not with MOTD: it
     * is a command whose legality DEPENDS ON HOW FAR REGISTRATION GOT, and a
     * connection in the middle of registering is the case it exists for. */
    { "STARTTLS", handle_starttls, 1 },
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
    { "KNOCK",   handle_knock,   0 },
    /* 7/Phase 7, the rest of 4.2: the server-info family, which lives next to
     * the MOTD above because it is the same question -- what is this node -- and
     * CHOPER, which is the operator half of the same surface and is answered by
     * a refusal policy rather than a feature. */
    { "LUSERS",  handle_lusers,  0 },
    { "ADMIN",   handle_admin,   0 },
    { "INFO",    handle_info,    0 },
    { "CHOPER",  handle_choper,   0 },
    /* 7/Phase 10.1: the account-registration pair, REFUSED rather than
     * unimplemented, and in the table rather than left to the 421 path for the
     * reason handle_register()/handle_unregister() give. A client that sends
     * REGISTER and gets 421 would read "this server has never heard of
     * REGISTER"; this node HAS heard of it and has decided. The distinction is
     * the whole of what a refusal is, and 421 cannot express it. */
    { "REGISTER",   handle_register,   0 },
    { "UNREGISTER", handle_unregister, 0 },
    /* 7/Phase 10.6: IRCv3's `setname`. NOT `pre_reg`, which is gate 1 of the three
     * in handle_setname() -- an unregistered connection has an EMPTY realname, so
     * without the gate a SETNAME would "succeed" at setting state that does not
     * exist yet. The verb is IN the table even though the capability gates what it
     * does, because the specification requires the command to be supported whether
     * or not the client negotiated it: a client that sent SETNAME and got 421 would
     * read "this server has never heard of it". */
    { "SETNAME",    handle_setname,    0 },
    /* 7/Phase 10.12: IRCv3 `batch`. `pre_reg`, and that is a decision worth the
     * comment: a client that batches its OWN registration lines is legal -- the
     * reference tags are a property of any command -- and holding the gate closed
     * until `001` would mean the `001`-`005` burst escaped the batch a client had
     * legitimately opened around it. The batch state is per connection and lives in
     * conn_t, so nothing here can reach another client's. */
    { "BATCH",      handle_batch,      1 },
    /* 7/Phase 10.2b: the account-notify query. NOT `pre_reg`, because the answer
     * carries this connection's hostmask and a pre-registration connection has no
     * nickname to put in it -- an unregistered client sending ACCOUNT gets 451,
     * which is the RFC's own answer for "you have not registered yet". */
    { "ACCOUNT",    handle_account,    0 }
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
        /* Measured, like poll_loop.c's `line:` and for the same reason: this is a
         * verb off a socket and a verb is an identifier, so the value is kept when
         * it is printable and withheld when it is not. */
        char shown[CONN_LOG_FIELD_MAX + 1u];

        (void)conn_text_logsafe(shown, sizeof shown, m->command);
        printf("[observable] cmd_dropped: fd=%d command=%s command_len=%zu "
               "command_bad_bytes=%zu reason=closing\n",
               c->fd, shown, strlen(m->command), conn_text_bad_count(m->command));
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

        /* THE 421 ECHOES THE VERB BACK VERBATIM AND THAT STAYS. The verb is going
         * to the client that sent it, so there is no second reader and no hazard,
         * and RFC 2812 3.3.4's 421 names the command precisely so a client can
         * match it. It is the LOG that needed the measurement, and only the log.
         *
         * This is also the most exposed single line on the node: an unrecognised
         * verb is answerable before registration, needs no credential, and nothing
         * examined the word before it was printed. */
        char shown[CONN_LOG_FIELD_MAX + 1u];

        mid[0] = m->command;
        (void)reply(s, c, "421", mid, 1, "Unknown command");
        (void)conn_text_logsafe(shown, sizeof shown, m->command);
        printf("[observable] cmd_unknown: fd=%d command=%s command_len=%zu "
               "command_bad_bytes=%zu\n",
               c->fd, shown, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }
    if (cmd->fn == NULL) {
        const char *mid[1];

        /* A known 4.1 verb this build does not implement. 421 is a slight lie
         * about the reason -- the wire has no numeric for "not yet" -- but the
         * alternative is silence, and silence is the failure mode these
         * numerics exist to prevent. The [observable] line says which of the
         * two it was, so a log reader is not misled. */
        /* As `cmd_unknown` above: the 421 names the verb to its own sender, the
         * log measures it. `KILL` is the verb that reaches this branch on this
         * build, so the line is not hypothetical. */
        char shown[CONN_LOG_FIELD_MAX + 1u];

        mid[0] = m->command;
        (void)reply(s, c, "421", mid, 1, "Unknown command");
        (void)conn_text_logsafe(shown, sizeof shown, m->command);
        printf("[observable] cmd_unimplemented: fd=%d command=%s command_len=%zu "
               "command_bad_bytes=%zu\n",
               c->fd, shown, strlen(m->command), conn_text_bad_count(m->command));
        return;
    }

    /* THE `batch` HOOK, AND WHY IT BRACKETS THE HANDLER RATHER THAN PRECEDING IT.
     *
     * `batch_begin_command()` is what turns an inbound line's `@`/`+` reference tags
     * into two things this dispatch then makes true: a `batch=` tag on the response
     * (a one-shot, consumed by the reply path) and a SUPPRESSION that lasts exactly as
     * long as the command. Both have to be set BEFORE `cmd->fn` runs -- a handler's
     * first byte of output is already too late for the first, and the second would be
     * cleared by `batch_end_command()` before it was ever set.
     *
     * AND `batch_end_command()` IS NOT OPTIONAL ON ANY PATH, which is why it is after
     * the call rather than inside an error branch: a suppressed flag that survived a
     * command would swallow the NEXT command's replies too, and the symptom would be
     * a client that goes silent for no reason it can see. There is exactly one exit
     * from `cmd->fn()` that is not a `return`, because every handler returns.
     *
     * IT IS HERE AND NOT IN reply.c, because reply.c cannot know when a command
     * starts: it only sees outbound lines, and "which of them is the FIRST line of
     * this command's response" is not a property of any one of them. */
    batch_begin_command(c, m);
    label_begin_command(c, m);
    cmd->fn(s, c, m);
    /* THE TAIL. Two things have to happen after the handler and not inside it, and both
     * are "what remains to be said" questions that a handler cannot answer because it
     * does not know what the handler emitted:
     *
     *   label_finish_command()  closes the `labeled-response` batch if one was opened,
     *                           or answers `ACK` if the command produced nothing. A
     *                           handler returning early on a refusal has still produced
     *                           a response -- the refusal -- so the label goes on THAT,
     *                           which is why the tail asks what was emitted rather than
     *                           asking whether the handler returned.
     *   batch has no tail       a client batch is closed by the client.
     *
     * IT IS NOT OPTIONAL ON ANY PATH, and every path here ends in this call: a
     * `label_live` that outlived its command would label the NEXT command's first line
     * with a value the client was already told was finished.
     */
    label_finish_command(s, c);
}
