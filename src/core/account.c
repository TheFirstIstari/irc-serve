/* account.c -- see account.h. The predicate every consumer asks, and the only
 * writer of a connection's account identity. */
#include "core/account.h"

#include <stdio.h>
#include <string.h>

#include "core/cap.h"
#include "core/message.h"
#include "core/reply.h"
#include "sasl_framework.h"

int account_logged_in(const conn_t *c)
{
    /* BOTH facts, deliberately. `logged_in` alone would be a verification with
     * no name and `account[0]` alone would be a name with no verification; the
     * conjunction is what makes the pair non-redundant, and writing it here
     * rather than at each call site is what stops a consumer from picking the
     * one that is convenient. See account.h on why there are two fields. */
    return (c != NULL && c->logged_in != 0 && c->account[0] != '\0') ? 1 : 0;
}

const char *account_name(const conn_t *c)
{
    return (account_logged_in(c) != 0) ? c->account : "";
}

int account_set(server_t *s, conn_t *c, const char *name, const char *password)
{
    size_t nlen;

    if (s == NULL || c == NULL || name == NULL || password == NULL) {
        return -1;
    }
    if (name[0] == '\0') {
        /* An EMPTY ACCOUNT IS NOT AN ACCOUNT. It is the value conn_t::account
         * holds before anything happens, so accepting one would write the
         * "not logged in" state with the "logged in" flag set -- the exact
         * confusion the invariant in account.h is about, reachable through the
         * only writer. */
        return -1;
    }
    /* AND IT MUST BE WRITABLE AS A PARAMETER. This check is the reason
     * account_name_wire_safe() exists, and it is HERE rather than only at a
     * renderer because this is the ONE writer of the field: a connection can only
     * be logged in once, so an account established here can be handed to 330, to a
     * JOIN echo and to two S-verbs, and a renderer that refused one of them would
     * be refusing a line rather than a name. See account.h for why the tag and the
     * parameter have different rules.
     *
     * THE COST, stated: an operator cannot create an account whose name holds a
     * space, so `account_store_add()` refuses one too and the file loader fails
     * the record rather than storing a name this node could not publish. That is a
     * restriction, and the alternative is an account that exists and is
     * unreportable. */
    if (account_name_wire_safe(name) == 0) {
        return -1;
    }
    nlen = strlen(name);
    if (nlen > sizeof c->account - 1u) {
        /* REFUSED, not truncated. An account is a name other people are shown
         * and a future `account-tag` will stamp it on every line this connection
         * sends; storing a prefix would produce an identity that differs from
         * the one the client authenticated as, which is the lying-numeric
         * failure this tree refuses repeatedly and for the same reason.
         *
         * IN PRACTICE UNREACHABLE FROM SASL: an authcid is bounded at
         * SASL_MAX_AUTHCID (63) and conn_t::account is 64 wide, so a name that
         * got here verified against the credential store and therefore already
         * fits. The check stays because it is the only thing standing between a
         * future caller with a different source and a one-byte overflow, and
         * because "unreachable" is a claim about today's callers rather than a
         * property of the struct. */
        return -1;
    }
    /* THE EXCHANGE MUST HAVE COMPLETED. Not "must not have failed": the flag this
     * checks is the one the SASL path sets after a verified credential, so a
     * client that failed and a client that never tried are both refused here. A
     * caller that reached for this function on an aborted exchange would be
     * minting an account for a client that proved nothing. */
    if (c->sasl != (int)SASL_COMPLETED) {
        return -1;
    }
    /* NO REGISTRY, NO ACCOUNT. The fail-closed direction, and the whole reason
     * `account == ""` cannot be told apart from "this node has no account
     * system": on a node with no registry this arm is always taken, so
     * account_logged_in() is 0 on every connection there, which is the same
     * answer a client that did not authenticate gets on a node that has one. */
    if (!account_store_verify(s->account_store, name, password)) {
        return -1;
    }

    memcpy(c->account, name, nlen + 1u);
    c->logged_in = 1;
    printf("[observable] account: fd=%d account=%s verified=1 registry=%zu\n",
           c->fd, c->account, account_store_count(s->account_store));
    return 0;
}

void account_clear(conn_t *c)
{
    if (c == NULL) {
        return;
    }
    /* Both fields, in one function. Zeroing only the name would leave a
     * verification with nothing attached, and zeroing only the flag would leave
     * a name no predicate would ever report -- and a caller that read
     * `c->account` directly rather than through account_name() would believe
     * it. See server_close_conn() for who calls this. */
    c->account[0] = '\0';
    c->logged_in = 0;
}

size_t account_tag_block(const char *name, char *out, size_t cap)
{
    /* Initialised here rather than assigned field by field below, so that every
     * path through this function sees a fully-formed pair. */
    message_tag_t one[1];

    if (out == NULL || cap == 0u) {
        return 0u;
    }
    /* `out` is cleared FIRST and unconditionally, so the caller's "no block" is
     * true on every path including the ones that cannot render.
     * send_line_tagged() treats an empty string as a CALLER BUG and refuses it, so
     * a function that left a stale block behind on a failure would turn "I could
     * not render this" into "you passed nonsense" -- and the caller cannot tell
     * those apart. */
    out[0] = '\0';
    /* NO NAME, NO TAG. Not an `account=` with an empty value: the specification
     * says the tag MUST NOT be sent for a user who is not identified, so an empty
     * account is a tag that must not EXIST rather than a tag with no value. The
     * check is here as well as at the call site because this is the function that
     * would render one. */
    if (name == NULL || name[0] == '\0') {
        return 0u;
    }
    /* ONE PAIR THROUGH THE ONE SERIALISER, rather than a hand-written "account="
     * followed by the value. message_tags_format() owns the '=' and the escaping,
     * and it is the same call irc_serve_msgid_tag() makes -- so the key/value shape
     * of this tag and of that one cannot come to disagree. */
    one[0].key = ACCOUNT_TAG_KEY;
    one[0].value = name;
    return message_tags_format(one, 1u, out, cap);
}

void account_notify_current(server_t *s, conn_t *c)
{
    char prefix[CONN_HOSTMASK_MAX];
    const char *acct;

    if (s == NULL || c == NULL) {
        return;
    }
    if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
        /* The same refusal conn_admit() makes for the JOIN echo, and for the same
         * reason: a connection whose identity fields cannot be rendered has no
         * hostmask to attribute the line to, and emitting one without would be a
         * line no client can attribute. It is not counted as a numeric refusal
         * because it is a CALLER bug rather than something a client did. */
        printf("[observable] account_notify_refused: fd=%d\n", c->fd);
        return;
    }
    acct = account_name(c);
    if (acct[0] != '\0') {
        (void)send_line(s, c, prefix, "ACCOUNT",
                        (const char *const[]){ acct, "PASS" }, 2);
        printf("[observable] account_notify: fd=%d nick=%s account=%s state=PASS\n",
               c->fd, c->nick, acct);
        return;
    }
    /* `*` IS THE ANSWER, not a placeholder: the specification names it precisely
     * so that "no account" is a value a client can hold, and it is the reason
     * this capability is available on a node with no registry. */
    (void)send_line(s, c, prefix, "ACCOUNT", (const char *const[]){ "*" }, 1);
    printf("[observable] account_notify: fd=%d nick=%s state=EMPTY\n", c->fd,
           c->nick);
}
