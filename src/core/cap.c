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
#include "sasl_framework.h"

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
    CAPBIT_SASL = 1u << 3
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
    { CAP_SASL, CAPBIT_SASL }
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

int cap_available(const server_t *s, const char *name)
{
    if (cap_known(name) == 0) {
        return 0;
    }
    if (strcasecmp(name, CAP_SASL) == 0) {
        return sasl_possible(s);
    }
    return 1;
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

        if (cap_available(s, k_caps[i].name) == 0) {
            continue;
        }
        if (n != 0u) {
            if (n + 1u >= cap) {
                out[0] = '\0';
                return 0;
            }
            out[n++] = ' ';
        }
        if (n + klen + 1u > cap) {
            out[0] = '\0';
            return 0;
        }
        memcpy(out + n, k_caps[i].name, klen);
        n += klen;
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

        if (known == 0 || have == 0) {
            rn += (size_t)snprintf(refused + rn, sizeof refused - rn, "%s%s",
                                   (rn != 0u) ? " " : "", names[i]);
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
        gn += (size_t)snprintf(granted + gn, sizeof granted - gn, "%s%s",
                               (gn != 0u) ? " " : "", names[i]);
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
            rn += (size_t)snprintf(refused + rn, sizeof refused - rn, "%s%s",
                                   (rn != 0u) ? " " : "", names[i]);
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
