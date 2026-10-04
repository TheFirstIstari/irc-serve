/* cap.c -- see cap.h. The capability table, the negotiation state machine, and
 * the one place `CAP` is answered.
 *
 * The wire form of a CAP reply is NOT a numeric, so it does not go through
 * reply(): a CAP line is `:server CAP <target> <subcommand> [<args>]` where the
 * subcommand is a WORD, and reply() can only render a three-digit code. It goes
 * through send_line(), which is the same door and therefore obeys the same
 * destination rules -- a CAP line can never reach a peer link because
 * emit_to_client() refuses a CONN_SERVER target, which is 3's federation
 * invariant arriving unchanged.
 */
#include "core/cap.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "core/commands.h"
#include "core/reply.h"
#include "account_store.h"
#include "sasl_framework.h"
/* Phase 12: the ONE question cap.c asks about TLS, which is "is TLS compiled in". The
 * certificate itself is a field on server_t, so this file never names a TLS type
 * -- which is what keeps the zero-dependency build the default one. */
#include "tls_backend.h"

/* --------------------------------------------------------------------------
 * The table
 * ------------------------------------------------------------------------ */

/* Bit positions. 1u << 0 is CAP_MULTIPREFIX and so on; the names are the
 * wire spelling and the bits are private, so nothing outside this file can hold a
 * stale bit index. A client holding a bit this build no longer defines cannot
 * happen -- the field is zeroed by conn_new() and only ever written here. */
enum {
    CAPBIT_MULTIPREFIX = 1u << 0,
    CAPBIT_MESSAGE_TAGS = 1u << 1,
    CAPBIT_MESSAGE_IDS = 1u << 2,
    CAPBIT_SASL = 1u << 3,
    CAPBIT_ACCOUNT_TAG = 1u << 4,
    CAPBIT_ACCOUNT_NOTIFY = 1u << 5,
    CAPBIT_EXTENDED_JOIN = 1u << 6,
    CAPBIT_USERHOST_IN_NAMES = 1u << 7,
    CAPBIT_SETNAME = 1u << 8,
    CAPBIT_ECHO_MESSAGE = 1u << 9,
    CAPBIT_STANDARD_REPLIES = 1u << 10,
    CAPBIT_AWAY_NOTIFY = 1u << 11,
    CAPBIT_BATCH = 1u << 12,
    CAPBIT_LABELED_RESPONSE = 1u << 13,
    CAPBIT_INVITE_NOTIFY = 1u << 14,
    /* Phase 12. 1u << 15 and 1u << 16 are the LAST two of the 32 an `unsigned`
     * holds, and taking them last is what keeps every existing bit index stable:
     * conn_t::caps is a bitmask that a conn_t can hold across an upgrade of the
     * binary only within one process, but the point is that adding a capability
     * never MOVES one, which is the failure CAPBIT_*'s own comment warns about. */
    CAPBIT_TLS = 1u << 15,
    CAPBIT_STS = 1u << 16
};

/* THE BIT ORDER IS FIXED AND THE TABLE BELOW IS THE CLAIM.
 *
 * Two of these four bits were reserved for months before their capability
 * existed -- CAPBIT_MULTIPREFIX and CAPBIT_MESSAGE_IDS -- and each was added to
 * the table in the same change that made the feature real. Reserving first means
 * a bit that moves is never a bit some already-stored conn_t value is read with
 * the wrong meaning; adding the NAME second means a capability is never
 * advertised before the feature exists, which is precisely the failure this file
 * was written to prevent. A reader who finds a bit here with no name below it is
 * looking at a capability whose implementation has not landed, and the correct
 * response is to finish it -- not to advertise it. */

typedef struct {
    const char *name;
    unsigned    bit;
} cap_def_t;

/* THE LIST OF THINGS THIS NODE DOES. Adding a name here is a claim that the
 * feature exists; do not add one to make a client stop complaining. */
static const cap_def_t k_caps[] = {
    { CAP_MULTIPREFIX, CAPBIT_MULTIPREFIX },
    { CAP_MESSAGE_TAGS, CAPBIT_MESSAGE_TAGS },
    { CAP_MESSAGE_IDS, CAPBIT_MESSAGE_IDS },
    { CAP_SASL, CAPBIT_SASL },
    { CAP_ACCOUNT_TAG, CAPBIT_ACCOUNT_TAG },
    { CAP_ACCOUNT_NOTIFY, CAPBIT_ACCOUNT_NOTIFY },
    { CAP_EXTENDED_JOIN, CAPBIT_EXTENDED_JOIN },
    { CAP_USERHOST_IN_NAMES, CAPBIT_USERHOST_IN_NAMES },
    { CAP_SETNAME, CAPBIT_SETNAME },
    { CAP_ECHO_MESSAGE, CAPBIT_ECHO_MESSAGE },
    { CAP_STANDARD_REPLIES, CAPBIT_STANDARD_REPLIES },
    { CAP_AWAY_NOTIFY, CAPBIT_AWAY_NOTIFY },
    { CAP_BATCH, CAPBIT_BATCH },
    { CAP_LABELED_RESPONSE, CAPBIT_LABELED_RESPONSE },
    { CAP_INVITE_NOTIFY, CAPBIT_INVITE_NOTIFY },
    /* Phase 12. `tls` and `sts` are in the table BECAUSE the features exist: a
     * node with no certificate refuses both at cap_available() below, which is
     * this file's whole rule applied to a property of the node's configuration
     * rather than of its build. Neither is in the table on a build compiled
     * without TLS -- see tls_node_possible() for why that is a RUNTIME question
     * rather than a build-time one. */
    { CAP_TLS, CAPBIT_TLS },
    { CAP_STS, CAPBIT_STS }
};

static const size_t k_ncaps = sizeof k_caps / sizeof k_caps[0];

/* Is this node able to authenticate anybody?
 *
 * `sasl` is the only capability whose availability is not a property of the
 * build: it is a property of the CONFIGURED NODE, because a node with no
 * `--sasl-store` holds no credentials and would refuse every PLAIN payload. A
 * `CAP LS` that lists `sasl` there is a client switching on authentication and
 * then being told it failed, so the store is consulted and the capability is
 * withheld when there is nothing behind it.
 *
 * The cost is that a node whose store failed to LOAD advertises no SASL rather
 * than a broken one, and an operator has to read the startup log to find out why
 * -- which is the trade this whole rule is about: a missing capability is a
 * client that carries on, a wrong one is a client that acts on a lie. */
static int sasl_possible(const server_t *s)
{
    return (s != NULL && sasl_store_count(s->sasl_store) > 0u) ? 1 : 0;
}

/* Is this node able to say WHO somebody is? `account-tag`, and the question is
 * asked of the REGISTRY rather than of the credential store, because the two files
 * answer different things and only one of them is about identity: --sasl-store
 * says who may AUTHENTICATE, --account-store says which accounts EXIST (design
 * 2.5.1).
 *
 * IT IS sasl_possible()'s SHAPE AND sasl_possible()'s REASON. A node with no
 * registry cannot establish an account on ANY connection -- account_set()'s
 * second check consults it and a missing registry fails that check -- so a CAP LS
 * that listed `account-tag` there would be a client switching on a tag this node
 * will never write, and the specification's "the tag MUST NOT be sent" for an
 * unidentified user means the only lines it could ever see are ones whose silence
 * it would read as "anonymous". Withholding the name is the same answer as
 * withholding `sasl` with no credential store.
 *
 * THE COST, stated rather than implied: an operator who loads a registry and
 * whose credential store FAILED to load has accounts nobody can log in to, so
 * nobody is ever identified, so this returns 1 and the tag is advertised -- and
 * every client that negotiates it correctly sees no tag. That is the truth about
 * the node, and the alternative (refusing the name because a different file
 * failed) would be a capability gated on something that does not decide whether
 * this one is real. */
static int account_possible(const server_t *s)
{
    return (s != NULL && account_store_count(s->account_store) > 0u) ? 1 : 0;
}

int cap_known(const char *name)
{
    if (name == NULL || name[0] == '\0') {
        return 0;
    }
    for (size_t i = 0; i < k_ncaps; i++) {
        if (strcasecmp(k_caps[i].name, name) == 0) {
            return 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * CAN THIS NODE ENCRYPT ANYTHING AT ALL?
 * ---------------------------------------------------------------------------
 * TWO QUESTIONS AND THE ORDER THEY ARE ASKED IN, because the answer is not one
 * thing:
 *
 *   tls_backend_available()  is TLS COMPILED IN? A false here is a build fact and
 *                           is a false on every node running that binary.
 *   s->tls != NULL           did an operator give this NODE a certificate and key
 *                           that loaded? A false here is a configuration fact and
 *                           can differ between two nodes running the SAME binary.
 *
 * BOTH ARE ASKED, and a node that fails either does not advertise `tls`. That is
 * cap.h's rule and it is why neither name is advertised by default: the default
 * build has neither, and a node built with -DWITH_TLS=ON that was not given a
 * certificate has neither either.
 *
 * `tls` IS NOT THE SAME QUESTION AS `sts`, and the second question has a THIRD
 * condition. `tls` says "this node speaks STARTTLS", which is a statement about a
 * command. `sts` says "here is a policy; act on it", and the specification makes
 * `port` REQUIRED on an insecure connection -- see sts_possible() below, which is
 * why `sts` is not answered from tls_node_possible().
 *
 * THE COST of asking at runtime rather than at build time is one pointer test per
 * CAP LS, and the benefit is that "advertise only what is real" survives a build
 * flag -- which is the same reason `sasl` consults a store instead of a macro. */
static int tls_node_possible(const server_t *s)
{
    return (tls_backend_available() != 0 && s != NULL && s->tls != NULL) ? 1 : 0;
}

/* CAN THIS NODE STATE AN `sts` POLICY THE SPECIFICATION WOULD HONOUR?
 *
 * `tls_node_possible()` is NOT sufficient, and the missing condition is the whole
 * of this function. The IRCv3 strict-transport-security specification makes the
 * `port` key REQUIRED on an insecure connection -- and `CAP LS` travels on the
 * plaintext port, which is exactly what "insecure connection" means here -- and
 * then says what a client does when a required part is missing: "If any required
 * part is missing, clients MUST continue as if no STS policy was advertised."
 *
 * SO WHAT A `sts` WITH NO PORT IS, on a node with a certificate and no --tls-port:
 *
 *   1. AN OPERATOR READING `CAP LS` concludes downgrade protection exists. It does
 *      not. This node can still be reached in the clear on its plain port and can
 *      only ever be upgraded with STARTTLS, which the same specification says `sts`
 *      is incompatible with: "STS expects that servers instead offer a port that
 *      directly services secure connections and it is incompatible with servers
 *      that offer secure connections only via STARTTLS on an insecure port." That
 *      is this node's exact shape when --tls-port is absent, and it is the "advertise
 *      before the feature exists" failure cap.h's own rule exists to prevent.
 *
 *   2. A LENIENT CLIENT HONOURING ONLY `duration` caches a persistence policy for a
 *      hostname with no secure port, and then refuses to connect -- which is a
 *      self-inflicted outage, and is the specification's own denial-of-service
 *      section naming the hazard that "a client that saw `sts` on a node with no
 *      secure port" produces.
 *
 * So `sts` is WITHHELD and plain `tls` is not. `tls` stays because it is TRUE:
 * this node does answer STARTTLS, and a client that wants to upgrade has to be
 * able to find that out. Withholding it would be refusing to tell a client
 * something real, which is the opposite mistake.
 *
 * `duration=0` IS NOT WHAT IS BEING FIXED HERE. A `sts=duration=0,port=N` on a
 * node that HAS a secure port is correct and is the specification's own recommended
 * shipped default; it states a policy of "no persistence" and names where to get
 * TLS. Only the missing REQUIRED KEY is suppressed.
 *
 * THE COST, stated because it is one: a node that was configured with a certificate
 * and no --tls-port now advertises no `sts`, so a client learns nothing about its
 * transport posture. That is the true posture. The alternative -- and it is the one
 * this fixes -- is a client learning something false. An operator who wants the
 * policy stated must give the node a secure port to state it against, which is what
 * --tls-port is for. */
static int sts_possible(const server_t *s)
{
    return (tls_node_possible(s) != 0 && server_tls_port(s) > 0) ? 1 : 0;
}

int cap_available(const server_t *s, const char *name)
{
    if (cap_known(name) == 0) {
        return 0;
    }
    if (strcasecmp(name, CAP_SASL) == 0) {
        return sasl_possible(s);
    }
    if (strcasecmp(name, CAP_ACCOUNT_TAG) == 0) {
        return account_possible(s);
    }
    if (strcasecmp(name, CAP_TLS) == 0) {
        return tls_node_possible(s);
    }
    if (strcasecmp(name, CAP_STS) == 0) {
        return sts_possible(s);
    }
    return 1;
}

/* ---------------------------------------------------------------------------
 * A CAPABILITY'S VALUE, or the empty string for the ones that have none
 * ---------------------------------------------------------------------------
 * ONLY `sts` HAS ONE, and the asymmetry is the specification's rather than this
 * file's: IRCv3's capability negotiation describes a value as something a client
 * REQUESTS, and `sts` is the one capability in this table that must not be
 * requested -- "Clients MUST NOT request this capability with `CAP REQ`." So the
 * value is rendered into CAP LS and the REQ is refused, which is a shape the
 * negotiation specification does not otherwise describe.
 *
 * WHICH KEYS APPEAR is argued at CAP_STS_VALUE_MAX in cap.h. What is worth
 * repeating here is that `port` is NOT CONDITIONAL in this function any more: it
 * used to be, and a `sts=duration=0` with no port on a node with no implicit-TLS
 * listener was a policy the specification calls malformed -- `port` is REQUIRED on
 * an insecure connection, and "if any required part is missing, clients MUST
 * continue as if no STS policy was advertised". So the decision moved to
 * sts_possible(), which withholds the whole NAME when there is no secure port, and
 * this function is only ever reached for a node that has one.
 *
 * WHICH MAKES THE PORT BELOW A REAL PORT, and that is an invariant rather than an
 * assumption: cap_available_list() consults cap_available() before cap_value() for
 * every name, so a `sts` that reaches here has already passed sts_possible(). A
 * future caller that rendered a value without asking would be writing `port=0`. */
static size_t cap_value(const server_t *s, const char *name, char *out, size_t cap)
{
    int n;

    out[0] = '\0';
    if (s == NULL || cap == 0u || strcasecmp(name, CAP_STS) != 0) {
        return 0;
    }
    n = snprintf(out, cap, "duration=%u,port=%d", (unsigned)s->sts_duration,
                 server_tls_port(s));
    if (n < 0 || (size_t)n >= cap) {
        out[0] = '\0';
        return 0;
    }
    return (size_t)n;
}

size_t cap_available_list(const server_t *s, char *out, size_t cap)
{
    size_t n = 0;

    if (out == NULL || cap == 0) {
        return 0;
    }
    out[0] = '\0';
    for (size_t i = 0; i < k_ncaps; i++) {
        const size_t klen = strlen(k_caps[i].name);
        char value[CAP_STS_VALUE_MAX];
        size_t vlen;

        if (cap_available(s, k_caps[i].name) == 0) {
            continue;
        }
        /* THE VALUE IS PART OF THE NAME ON THE WIRE, so it is accounted for in the
         * same bound as the name. Rendering it without that is how a capability
         * list gets silently truncated exactly when the one capability with a
         * policy is the one being written -- and a truncated `sts=duration=` is a
         * policy no client can parse, which the specification says makes every
         * client behave as though no policy had been advertised at all. */
        vlen = cap_value(s, k_caps[i].name, value, sizeof value);
        if (n != 0u) {
            if (n + 1u >= cap) {
                out[0] = '\0';
                return 0;
            }
            out[n++] = ' ';
        }
        if (n + klen + vlen + 1u > cap) {
            out[0] = '\0';
            return 0;
        }
        memcpy(out + n, k_caps[i].name, klen);
        n += klen;
        if (vlen > 0u) {
            out[n++] = '=';
            memcpy(out + n, value, vlen);
            n += vlen;
        }
    }
    out[n] = '\0';
    return n;
}

/* --------------------------------------------------------------------------
 * Connection state
 * ------------------------------------------------------------------------ */

void cap_init(conn_t *c)
{
    if (c == NULL) {
        return;
    }
    c->caps = 0u;
    c->cap_negotiating = 0;
}

void cap_reset(conn_t *c)
{
    cap_init(c);
}

int cap_negotiating(const conn_t *c)
{
    return (c != NULL && c->cap_negotiating != 0) ? 1 : 0;
}

int cap_enabled(const conn_t *c, const char *name)
{
    if (c == NULL || name == NULL) {
        return 0;
    }
    for (size_t i = 0; i < k_ncaps; i++) {
        if (strcasecmp(k_caps[i].name, name) != 0) {
            continue;
        }
        return ((c->caps & k_caps[i].bit) != 0u) ? 1 : 0;
    }
    return 0;
}

int cap_multiprefix_enabled(const conn_t *c)
{
    return cap_enabled(c, CAP_MULTIPREFIX);
}

int cap_message_tags_enabled(const conn_t *c)
{
    return cap_enabled(c, CAP_MESSAGE_TAGS);
}

int cap_message_ids_enabled(const conn_t *c)
{
    /* BOTH GATES, and the second is not a convenience. `msgid` is a TAG, so a
     * client that enabled `draft/message-ids` and not `message-tags` has asked
     * for a tag inside a tag support it declined, and a node that wrote one
     * anyway would be putting a tag block on a line the client has said it does
     * not want to parse -- which is the whole of what the capability-negotiation
     * specification is for. 3.2's parser reads a block or it does not, so this
     * is not a "best effort" gate: the value is either on the line or it is not.
     *
     * The cost, stated: a client whose REQ lists `draft/message-ids` alone gets
     * no msgid while believing it asked for one. That is the honest answer --
     * the client opted out of tags -- and the alternative (stamping anyway) is a
     * node that lies about a negotiated protocol. */
    return (cap_enabled(c, CAP_MESSAGE_IDS) != 0 &&
            cap_enabled(c, CAP_MESSAGE_TAGS) != 0)
               ? 1
               : 0;
}

/* account-tag: BOTH GATES, and the second for the same reason as above -- the
 * `account` tag is a message tag, and 3.2's parser reads a block or it does not.
 *
 * THE FIRST GATE IS THE ONE THE SPECIFICATION IS ABOUT. `account-tag` names the
 * account of the SENDER, so a client that did not ask must not be told: the tag is
 * not decoration, its ABSENCE is the assertion that a sender is anonymous, and
 * writing it to a client that declined to negotiate tags is a node putting a block
 * on a line the client has said it does not want to parse.
 *
 * THE COST, stated because it is a cost: a client that sends
 * `CAP REQ :account-tag` without `message-tags` gets an ACK for account-tag and no
 * tag on any line. That is the honest answer -- the REQ said it wanted one tag
 * inside a tag support it declined -- and it is the same answer
 * cap_message_ids_enabled() gives for the same reason. */
int cap_account_tag_enabled(const conn_t *c)
{
    return (cap_enabled(c, CAP_ACCOUNT_TAG) != 0 &&
            cap_enabled(c, CAP_MESSAGE_TAGS) != 0)
               ? 1
               : 0;
}

/* account-notify: ONE GATE, and there is no second one because there is no
 * message tag involved. The line this capability turns on is a plain IRC command,
 * so there is no `message-tags` question to ask -- which is also why it needs no
 * per-destination render and why it is not this file's problem at all beyond the
 * bit.
 *
 * It is NOT gated on the account system, and the reason is cap.h's: `ACCOUNT *` is
 * an answer this node can give truthfully on a node with no registry, so the
 * availability check that account-tag has would make this node keep a true fact
 * from a client that asked for it. */
int cap_account_notify_enabled(const conn_t *c)
{
    return cap_enabled(c, CAP_ACCOUNT_NOTIFY);
}

/* extended-join: ONE GATE AND NO AVAILABILITY CHECK, and the absence is the point.
 *
 * The line this capability turns on is a JOIN this node emits EITHER WAY, and the
 * `*` account form is a complete answer on a node with no registry -- so there is
 * no configuration in which this node cannot honour the capability. A store check
 * here would mean a node with accounts silently sends a plainer JOIN to every
 * client, which is a capability advertised and then declined rather than one
 * advertised and honoured. */
int cap_extended_join_enabled(const conn_t *c)
{
    return cap_enabled(c, CAP_EXTENDED_JOIN);
}

/* userhost-in-names: ONE GATE AND NO AVAILABILITY CHECK. The capability is a
 * question about what a `353` may DRAW, and every member this node can draw has a
 * host: a local one had accept() fill `c->host` before it had a nickname, and a
 * remote one has the host 4.3's SBURSTN carries. There is no configuration under
 * which this node has a roster and no host in it, so there is nothing to withhold
 * the name over -- which is the same shape as account-notify's answer and the
 * opposite of account-tag's.
 *
 * THE PRIVACY IS THE DOCUMENTATION, and cap.h carries it in full. What is worth
 * saying here is where the gate is READ: `chan_verbs.c`'s `send_names_list()`,
 * once per destination, for the connection being answered. A node that asked once
 * per channel -- or once per node -- would hand every member's hostmask to every
 * member whether they negotiated it or not. */
int cap_userhost_in_names_enabled(const conn_t *c)
{
    return cap_enabled(c, CAP_USERHOST_IN_NAMES);
}

/* setname: ONE GATE, and the asymmetry that the NAME is advertised while this
 * gates is the specification's rather than this file's -- the command has to work
 * whether or not the client negotiated it, and a non-negotiating client's SETNAME
 * is handled SILENTLY. So the name is in `k_caps[]` (the verb exists) and this
 * decides whether this connection's SETNAME changes anything or produces no line at
 * all. See cap.h for why a silent refusal is the specified behaviour rather than a
 * gap in this implementation. */
int cap_setname_enabled(const conn_t *c)
{
    return cap_enabled(c, CAP_SETNAME);
}

/* echo-message: ONE GATE. Whether the SENDER stays in the audience of the delivery
 * that is happening anyway is decided in msg_verbs.c and nowhere else; this
 * function exists so the answer has a name in cap.h beside the others and so no
 * caller spells the capability string out a second time. See cap.h for why there is
 * no second emission here. */
int cap_echo_message_enabled(const conn_t *c)
{
    return cap_enabled(c, CAP_ECHO_MESSAGE);
}

/* standard-replies: ONE GATE, AND IT IS THE ONLY ONE THAT CHANGES A SHAPE A
 * CLIENT CAN ALREADY PARSE.
 *
 * Every other capability in this file decides what this node DRAWS -- an extra
 * parameter on a JOIN, a tag block, a sigil run, a roster entry. This one decides
 * whether a refusal arrives as `417` or as `FAIL KICK ERR_INPUTTOOLONG`, which is
 * a different message with a different command word. That is why the gate is
 * asked in `reply.c` rather than at a handler: the reply path is the one place
 * that says what an outbound message to a client MAY BE, and a capability that
 * could be honoured or ignored per handler would be honoured on one path and
 * forgotten on the next.
 *
 * ONE GATE AND NO AVAILABILITY CHECK, for the reason `extended-join` gives: what
 * there is to say is not a property of an operator file. Every refusal on this
 * node has something truthful to render, and `FAIL` is a rendering of the same
 * refusal rather than a new one. */
int cap_standard_replies_enabled(const conn_t *c)
{
    return cap_enabled(c, CAP_STANDARD_REPLIES);
}

/* away-notify: whether this node tells THIS client, unprompted, when a user it
 * shares a channel with sets, changes or removes their away state.
 *
 * ONE GATE AND NO AVAILABILITY CHECK, and the question is not "is there an away
 * message to report" but "is there away STATE to report at all". `conn_t::away`
 * exists on every connection from accept() and `AWAYLEN` is advertised from
 * `CONN_MAX_AWAY`, so this node has away state whether or not any client is
 * currently away -- which is the same shape of answer as `userhost-in-names`
 * (does the data exist) and the opposite of `account-tag` (is there something to
 * SAY). A node that withheld the name whenever nobody happened to be away would be
 * a capability that appears and disappears with the traffic.
 *
 * IT IS HANDED TO `fanout.c` DIRECTLY, through `cap_gate_away_notify()` below
 * rather than through a wrapper in msg_verbs.c, so that the adaptation between
 * this file's one-argument predicates and fanout.h's two-argument gate lives in
 * ONE place next to the capability it is about. */
int cap_away_notify_enabled(const conn_t *c)
{
    return cap_enabled(c, CAP_AWAY_NOTIFY);
}

/* fanout.h's `fanout_gate_fn` is `int (*)(const conn_t *, void *)`; every
 * predicate in this file is `int (*)(const conn_t *)`. The gate's second argument
 * is per-EMISSION context and none of this file's predicates wants any, but the
 * signature is not changed for them: five other callers already hold the one-
 * argument shape and it is the shape cap.h's own table documents. So the
 * adaptation is a named function rather than a macro, and it lives here rather
 * than at the call site so that "every capability predicate here is one-argument,
 * and the gate that adapts them is this" is a single readable claim. */
int cap_gate_away_notify(const conn_t *dst, void *ctx)
{
    (void)ctx;
    return cap_away_notify_enabled(dst);
}

/* setname: the SAME adaptation, for the common-channel fan-out. `cap.c`'s
 * away-notify comment above says the adaptation lives here rather than at the
 * call site so that "every capability predicate here is one-argument, and the
 * gate that adapts them is this" is one readable claim; this is the second user
 * of that claim and it is why the claim was written that way.
 *
 * WHICH SIDE THE GATE IS ASKED ABOUT IS A DISCLOSURE DECISION, and it is the
 * specification's: "The SETNAME message MUST NOT be sent to clients which do not
 * have the setname capability negotiated." Clients, plural, and the gate takes the
 * DESTINATION -- so a realname reaches a member who asked to learn about realnames
 * and nobody else.
 *
 * THE SENDER'S NEGOTIATION IS NOT THE RIGHT ANSWER, and saying why is the point:
 * gating on the sender would let one client put a member's realname on the wire to
 * every other member of a shared channel by asking for a capability the RECIPIENT
 * never requested, which is a disclosure nobody agreed to and would also contradict
 * `cap.h`'s own rule that the CONFIRMATION is gated on the recipient -- so the two
 * halves of one specification would decide opposite questions about the same field.
 * A realname is personal data, and the per-destination answer is the only one that
 * does not require trusting the person disclosing it to be careful. */
int cap_invite_notify_enabled(const conn_t *c)
{
    return cap_enabled(c, CAP_INVITE_NOTIFY);
}

/* labeled-response. One predicate for all three of the specification's effects -- the
 * label, the grouping batch and the `ACK` -- because the specification puts all three in
 * one sentence about what a client "requesting this capability" can handle, and
 * separating them would mean deciding that a client could handle a label but not the
 * `ACK` it exists to be correlated with. */
int cap_labeled_response_enabled(const conn_t *c)
{
    return cap_enabled(c, CAP_LABELED_RESPONSE);
}

/* invite-notify. `cap.c`'s away-notify comment says the gate adaptation lives here
 * rather than at the call site so that the claim about one-argument predicates is one
 * readable sentence; this is the third user of that claim and the reason it was written
 * that way. */
int cap_gate_invite_notify(const conn_t *dst, void *ctx)
{
    (void)ctx;
    return cap_invite_notify_enabled(dst);
}

int cap_gate_setname(const conn_t *dst, void *ctx)
{
    (void)ctx;
    return cap_setname_enabled(dst);
}

/* --------------------------------------------------------------------------
 * The wire
 * ------------------------------------------------------------------------ */

/* `<target>` per RFC 2812 3.3: the nickname, or "*" when the client has not
 * chosen one. CAP is answered during registration, so the "*" case is the
 * NORMAL case and not an edge: a client sends `CAP LS` before NICK, as it is
 * supposed to. A CAP line addressed to "" is unparseable by a client that
 * expects the RFC's form. */
static const char *cap_target(const conn_t *c)
{
    return (c != NULL && c->nick[0] != '\0') ? c->nick : "*";
}

/* `:server CAP <target> <sub> :<args>`. The subcommand is a middle parameter and
 * the argument list is the trailing one, so a capability list with spaces in it
 * renders exactly as the specification's examples show -- which is why the
 * arguments go in the LAST slot and not joined into the middle. */
static void cap_reply(server_t *s, conn_t *c, const char *sub, const char *args)
{
    const char *params[3];

    params[0] = cap_target(c);
    params[1] = sub;
    params[2] = (args != NULL) ? args : "";
    /* Three parameters always, so the trailing one is always the third and is
     * therefore colonned by message_format() whenever it needs it -- which an
     * empty argument list does. */
    (void)send_line_colon(s, c, NULL, "CAP", params, 3);
}

/* --------------------------------------------------------------------------
 * Capability lists: splitting a request, and rendering a subset
 * ------------------------------------------------------------------------ */

/* Split a space-separated capability list into at most `max` names, copying
 * each into `out[i]` (which must hold CAP_NAME_MAX + 1 bytes each). Returns the
 * count, or -1 if there were more than `max`.
 *
 * Split on the wire, in place: the argument is the caller's message buffer and
 * the split writes NULs into it. `m` is const in cap_handle()'s signature and
 * message_t::params is `char *[]`, so this takes the `char *` and the mutation is
 * confined to a buffer the caller has already parsed and will not re-read. The
 * alternative -- copying the list into a local -- allocates on the path of a
 * command a client sends on every connect. */
/* How many capability names one REQ or DEL may name. 16 is generous for a
 * request a client composes from a CAP LS it received, and the bound is here so
 * that `names` below is a fixed array: a client naming ten thousand
 * capabilities must be refused, not allocated for. */


/* Append one capability name to an accumulator, and return how much was WRITTEN.
 *
 * WHY THIS EXISTS. All three CAP ACK/NAK arms used to read
 *
 *     rn += (size_t)snprintf(buf + rn, sizeof buf - rn, "%s%s", sep, name);
 *
 * and `snprintf` returns the length it WOULD have written, not the length it did.
 * So on truncation `rn` jumps past the end of `buf`, the next iteration computes
 * `sizeof buf - rn` on an already-underflowed size_t, and the arm writes outside
 * the buffer. That is the shape of the Phase-8 stack overflow -- a remotely
 * reachable CAP REQ overflowing a stack array -- which was fixed by DERIVING
 * CAP_LS_MAX so the arithmetic could not exceed the buffer.
 *
 * The derivation makes it safe TODAY and that is the whole problem: it is safe by
 * 17 bytes of headroom (1039 bytes of names against CAP_LS_MAX = 1056), and
 * nothing at the call site says so. A later CAP_NAME_MAX, a later CAP_MAX_REQ, or
 * a separator added to the format string reopens it silently, and CodeQL flags
 * exactly these three lines for that reason.
 *
 * So the accumulator advances by what was WRITTEN, which is `cap` - 1 - remaining,
 * and a truncation is reported rather than absorbed. The bound is unchanged and no
 * name is dropped: CAP_LS_MAX is derived to hold CAP_MAX_REQ names of CAP_NAME_MAX
 * plus their separators, so this function's truncation arm is unreachable for a
 * conforming cap_split() and exists so that a future change to the derivation
 * fails loudly here instead of quietly in a client's face.
 *
 * The separator is written only when the buffer is non-empty, and the empty case
 * is a genuine 0 return rather than an assumed one -- so `rn` and `nwritten`
 * cannot disagree about where the buffer ends. */
static size_t cap_append_name(char *buf, size_t cap, size_t off, const char *name)
{
    const char *sep = (off != 0u) ? " " : "";
    int n;

    if (buf == NULL || name == NULL || off >= cap) {
        return 0u;
    }
    n = snprintf(buf + off, cap - off, "%s%s", sep, name);
    if (n < 0) {
        /* Encoding error, which cannot happen for these two arguments but is
         * reported rather than assumed: the alternative is a caller advancing by
         * a negative-turned-huge size_t. */
        buf[off] = '\0';
        return 0u;
    }
    if ((size_t)n >= cap - off) {
        /* Truncated. The text that WAS written is capped and NUL-terminated by
         * snprintf, and the caller is told the true written length so the next
         * append cannot start inside the NUL. */
        return cap - off - 1u;
    }
    return (size_t)n;
}

static int cap_split(char *arg, char out[][CAP_NAME_MAX + 1], int max)
{
    int n = 0;
    char *p = arg;

    if (arg == NULL) {
        return 0;
    }
    for (;;) {
        char *sep = p;
        size_t len;

        while (*sep != '\0' && *sep != ' ' && *sep != '\t') {
            sep++;
        }
        len = (size_t)(sep - p);
        if (len > (size_t)CAP_NAME_MAX) {
            return -1; /* a capability name this long is not one */
        }
        if (len > 0u && n < max) {
            memcpy(out[n], p, len);
            out[n][len] = '\0';
            n++;
        } else if (len > 0u) {
            return -1; /* more capabilities than we will consider */
        }
        if (*sep == '\0') {
            break;
        }
        *sep = '\0';
        p = sep + 1;
    }
    return n;
}

/* --------------------------------------------------------------------------
 * The subcommands
 * ------------------------------------------------------------------------ */

/* CAP LS and CAP LIST.
 *
 * `CAP LS 302` asks for the continuation mechanism, which exists because a server
 * may have more capabilities than fit in one line. This node has three, so the
 * answer always fits and there is nothing to continue: the 302 parameter is
 * ACCEPTED and IGNORED rather than refused, because refusing it would make a
 * client that offers it -- and every current client offers it -- fail
 * negotiation against a node whose only reason for not continuing is that it has
 * nothing to continue. The [observable] line says which form arrived, so a reader
 * is not left guessing whether 302 was honoured.
 *
 * `CAP LIST` answers with what THIS CLIENT has enabled, which is a different
 * question from LS and conflating them is how a client ends up believing it
 * negotiated something it did not. */
static void cap_do_ls(server_t *s, conn_t *c, const message_t *m, int is_list)
{
    char list[CAP_LS_MAX];

    /* LS starts a negotiation: registration is held until CAP END. LIST does
     * NOT, because a client asking what it has already negotiated is mid-session
     * and must not be able to stall its own registration by asking. */
    if (!is_list) {
        c->cap_negotiating = 1;
    }
    if (is_list) {
        /* Only what this client actually enabled. A server that answered LIST
         * with its whole table would be telling the client it may use things it
         * did not ask for. */
        size_t n = 0;

        list[0] = '\0';
        for (size_t i = 0; i < k_ncaps; i++) {
            if (cap_enabled(c, k_caps[i].name) == 0) {
                continue;
            }
            if (n != 0u) {
                list[n++] = ' ';
            }
            memcpy(list + n, k_caps[i].name, strlen(k_caps[i].name));
            n += strlen(k_caps[i].name);
        }
        list[n] = '\0';
    } else {
        (void)cap_available_list(s, list, sizeof list);
    }
    cap_reply(s, c, is_list ? "LIST" : "LS", list);
    printf("[observable] cap: fd=%d sub=%s 302=%d caps=%s\n", c->fd,
           is_list ? "LIST" : "LS", (m->nparams > 1) ? 1 : 0, list);
}

/* CAP REQ.
 *
 * ---------------------------------------------------------------------------
 * PARTIAL ACK, AND WHY
 * ---------------------------------------------------------------------------
 * A `CAP REQ` naming four capabilities where this node has two is answered with
 * one `CAP ACK` carrying the two granted and one `CAP NAK` carrying the two
 * refused. The specification allows exactly this, and it is the right answer here
 * for a reason that is about clients rather than about the protocol: a client
 * that asked for `sasl multi-prefix server-time chghost` against a node with the
 * first two gets SASL, which is the one it cannot do without, instead of being
 * told it may have nothing. A whole-request NAK would be an accurate answer to a
 * question nobody asked.
 *
 * It is also the RARE path rather than the common one, because CAP LS only lists
 * what this node has -- so a well-behaved client's REQ names capabilities that all
 * exist, and the ACK is complete. Partial ACK is what happens when a client asks
 * for something it was never offered, and the honest handling of that is to say
 * which half of the request this node can honour.
 *
 * The ordering rule that keeps the two answers unambiguous: every name in the
 * ACK appears in the REQ and no name appears in both, and the NAK carries
 * everything in the REQ that is not in the ACK. A client that counted ACK+NAK
 * sizes gets the request size back. */
static void cap_do_req(server_t *s, conn_t *c, const message_t *m)
{
    char *arg = (m->nparams > 1) ? m->params[1] : NULL;
    char names[CAP_MAX_REQ][CAP_NAME_MAX + 1];
    char granted[CAP_LS_MAX];
    char refused[CAP_LS_MAX];
    size_t gn = 0;
    size_t rn = 0;
    int n;

    granted[0] = '\0';
    refused[0] = '\0';
    if (arg == NULL) {
        /* A REQ with no list asks for nothing, and answering it with an ACK
         * would tell the client it had negotiated an empty capability set --
         * which is a thing it would then believe. */
        cap_reply(s, c, "NAK", "");
        printf("[observable] cap: fd=%d sub=REQ reason=empty\n", c->fd);
        return;
    }
    n = cap_split(arg, names, CAP_MAX_REQ);
    if (n <= 0) {
        cap_reply(s, c, "NAK", "");
        printf("[observable] cap: fd=%d sub=REQ reason=malformed\n", c->fd);
        return;
    }
    c->cap_negotiating = 1;

    for (int i = 0; i < n; i++) {
        const int known = cap_known(names[i]);
        const int have = cap_available(s, names[i]);

        /* `sts` IS REFUSED EVEN THOUGH THIS NODE OFFERS IT, and that is the
         * specification's rule rather than this file's opinion: "Clients MUST NOT
         * request this capability with `CAP REQ`. Servers MAY reply with a `CAP
         * NAK` message if a client requests this capability."
         *
         * ACKING IT WOULD BE WORSE THAN THE SPECIFICATION THREATENS. `sts` is not
         * a feature a client switches on; it is a POLICY the server states, and a
         * client that has "negotiated" one has been told the server believes the
         * client's own request has a bearing on what the client may connect to.
         * A client that cached a policy on the strength of an ACK and then had
         * that policy dropped would have been told it was under a constraint it is
         * not. So the NAK is the honest answer to a request that should not have
         * been made, and the policy is delivered in CAP LS where it belongs.
         *
         * IT IS CHECKED BEFORE `have`, so the refusal is the SAME on a node with no
         * certificate: a client that sent `CAP REQ :sts` to a plaintext node gets
         * a NAK naming a capability that exists, not one that does not, and the
         * difference between "not implemented" and "not for you" is visible. */
        if (strcasecmp(names[i], CAP_STS) == 0) {
            rn += cap_append_name(refused, sizeof refused, rn, names[i]);
            continue;
        }
        if (known == 0 || have == 0) {
            rn += cap_append_name(refused, sizeof refused, rn, names[i]);
            continue;
        }
        /* ENABLE IT. A capability is granted by writing the bit here and nowhere
         * else, so "did this client get multi-prefix" has one answer. */
        for (size_t k = 0; k < k_ncaps; k++) {
            if (strcasecmp(k_caps[k].name, names[i]) == 0) {
                c->caps |= k_caps[k].bit;
                break;
            }
        }
        gn += cap_append_name(granted, sizeof granted, gn, names[i]);
    }

    /* ACK first, then NAK, and only for the non-empty halves. A client waits
     * for one of each; sending an ACK with an empty list would be an ACK the
     * client would have to interpret. */
    if (gn != 0u) {
        cap_reply(s, c, "ACK", granted);
    }
    if (rn != 0u) {
        cap_reply(s, c, "NAK", refused);
    }
    if (gn == 0u && rn == 0u) {
        cap_reply(s, c, "NAK", "");
    }
    printf("[observable] cap: fd=%d sub=REQ requested=%d granted=%s refused=%s\n",
           c->fd, n, (granted[0] != '\0') ? granted : "-",
           (refused[0] != '\0') ? refused : "-");
}

/* CAP DEL.
 *
 * Not implemented as a feature -- there is no capability here that is negotiable
 * and then un-negotiable, so there is nothing to disable -- but it is ANSWERED
 * rather than ignored, and the answer is NAK.
 *
 * The specification is explicit that a server which cannot disable a capability
 * MUST NAK it, and the reason is not politeness: a client that sent DEL and
 * received silence has no way to know whether the capability is still on. A
 * client that asks to turn off something it negotiated and is then told no can
 * stop relying on it; a client that is told nothing keeps relying on it. */
static void cap_do_del(server_t *s, conn_t *c, const message_t *m)
{
    char *arg = (m->nparams > 1) ? m->params[1] : NULL;
    char names[CAP_MAX_REQ][CAP_NAME_MAX + 1];
    char refused[CAP_LS_MAX];
    size_t rn = 0;
    int n;

    refused[0] = '\0';
    if (arg != NULL) {
        n = cap_split(arg, names, CAP_MAX_REQ);
        for (int i = 0; i < n; i++) {
            /* Nothing here is ever disabled, so EVERY requested name is refused
             * -- including one this node never had. Claiming to know a
             * capability is a smaller lie than claiming to have disabled one. */
            rn += cap_append_name(refused, sizeof refused, rn, names[i]);
        }
    }
    cap_reply(s, c, "NAK", refused);
    printf("[observable] cap: fd=%d sub=DEL refused=%s reason=NOT_NEGOTIABLE\n",
           c->fd, (refused[0] != '\0') ? refused : "-");
}

/* CAP END.
 *
 * The release. Registration is re-evaluated here and ONLY here for the
 * negotiation half of the gate, which is the whole point: a server that completes
 * registration when it has NICK and USER, regardless of CAP, hangs every modern
 * client. The state is cleared first and the gate re-run second, so a CAP END that
 * arrives after NICK and USER -- the common order, and the order every current
 * client uses -- registers on the spot. */
static void cap_do_end(server_t *s, conn_t *c)
{
    c->cap_negotiating = 0;
    printf("[observable] cap: fd=%d sub=END negotiation=closed\n", c->fd);
    /* The gate lives in commands.c, which owns update_state(); it is reached
     * through the same entry point a NICK or a USER uses, so there is one
     * promotion to CONN_REG_READY and not two. */
    commands_state_update(s, c);
}

void cap_handle(server_t *s, conn_t *c, const message_t *m)
{
    const char *sub;

    if (s == NULL || c == NULL || m == NULL || c->kind == CONN_SERVER) {
        return;
    }
    /* No parameter is a malformed CAP, and 410 says so rather than the node
     * guessing. */
    if (m->nparams < 1 || m->params[0] == NULL || m->params[0][0] == '\0') {
        (void)reply(s, c, RPL_INVALIDCAPSUBCOMMAND, (const char *const[]){ "-" }, 1,
                    "Invalid CAP subcommand");
        return;
    }
    sub = m->params[0];

    /* message_parse() uppercases the COMMAND but not its parameters, and a
     * client may send `cap ls` as readily as `CAP LS`. Every current client sends
     * upper case, and a server that only answers upper case is a server some
     * client will hang against for a reason no log will show. */
    if (strcasecmp(sub, "LS") == 0) {
        cap_do_ls(s, c, m, 0);
        return;
    }
    if (strcasecmp(sub, "LIST") == 0) {
        cap_do_ls(s, c, m, 1);
        return;
    }
    if (strcasecmp(sub, "REQ") == 0) {
        cap_do_req(s, c, m);
        return;
    }
    if (strcasecmp(sub, "DEL") == 0) {
        cap_do_del(s, c, m);
        return;
    }
    if (strcasecmp(sub, "END") == 0) {
        cap_do_end(s, c);
        return;
    }

    /* An UNKNOWN SUBCOMMAND IS ANSWERED, not ignored.
     *
     * Silence here is the failure the specification exists to prevent: a client
     * that asked something and got nothing cannot tell "not understood" from
     * "message lost", and it waits. 410 names the subcommand it did not
     * recognise, so the operator can see which client asked for what. */
    (void)reply(s, c, RPL_INVALIDCAPSUBCOMMAND, (const char *const[]){ sub }, 1,
                "Invalid CAP subcommand: %s", sub);
    printf("[observable] cap: fd=%d sub=%s reason=UNKNOWN\n", c->fd, sub);
}
