/* account.c -- see account.h. The predicate every consumer asks, and the only
 * writer of a connection's account identity. */
#include "core/account.h"

#include <stdio.h>
#include <string.h>

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
