/* account.h -- ACCOUNT IDENTITY ON A CONNECTION: the predicate every consumer
 * asks, and the only function that may set it.
 *
 * Authority: docs/SERVER_DESIGN.md 2.1 (scoped identity, and the second axis
 * this adds), 7/Phase 10.1.
 *
 * ---------------------------------------------------------------------------
 * THE IDEA, IN ONE SENTENCE, BECAUSE IT IS THE WHOLE OF THIS PHASE
 * ---------------------------------------------------------------------------
 * An account is a named identity that OUTLIVES A SOCKET. Everything this tree
 * had before it authenticated a CONNECTION: SASL PLAIN proves a socket holds a
 * password, the proof dies with the socket, and `c->sasl` is therefore a fact
 * about a connection and about nothing else. It was correct that SASL granted
 * nothing -- there was nothing here it could legitimately grant -- and it was
 * also the reason seven IRCv3 specs were blocked: every one of them needs to
 * know WHO is logged in, on a connection, at a moment that is not the one at
 * which the password was checked.
 *
 * ---------------------------------------------------------------------------
 * THE ONE INVARIANT THIS FILE EXISTS TO HOLD
 * ---------------------------------------------------------------------------
 * **`account == ""` IS INDISTINGUISHABLE FROM "THIS NODE HAS NO ACCOUNT
 * SYSTEM".**
 *
 * It is not a convention. It is structural, and it is structural because there
 * is exactly ONE writer -- account_set(), below, whose contract requires a
 * verified `sasl_store_t` AND a verified `account_store_t` -- and because the
 * predicate every consumer asks (account_logged_in()) is local to the
 * connection and needs no store of its own:
 *
 *   a node with no account registry can never produce an account_set() call,
 *   because the registry is what the second check consults, and a registry that
 *   is absent makes that check fail. So `logged_in` is 0 on every connection on
 *   such a node, which is the SAME ANSWER a node with a registry gives a client
 *   that did not authenticate. A consumer therefore needs no knowledge of
 *   whether an account system exists, and cannot get a different answer on the
 *   two nodes by asking a different question.
 *
 * That matters because the consumer CAP LS is not yet one: cap.c has one rule --
 * "advertise only what is real" -- and it answers it by asking a CONFIGURATION
 * question ("is there a registry loaded"), which is a different question from
 * this one and lives in cap.c. `account-tag` is NOT in that table in this phase
 * and cap.h carries the whole argument for why; the check it will need is the
 * same shape as sasl_possible() and goes in beside it. If those two questions
 * could disagree, the node would advertise an account capability and then answer
 * "not logged in" to the client that asked for it, or refuse to advertise one
 * while still putting an account in front of somebody.
 *
 * ---------------------------------------------------------------------------
 * WHY THERE ARE TWO FIELDS AND NOT ONE
 * ---------------------------------------------------------------------------
 * conn_t carries `account` (the NAME) and `logged_in` (the FACT THAT A PASSWORD
 * WAS VERIFIED FOR IT), and they are two fields rather than one because they are
 * two different facts, not one fact with a sentinel:
 *
 *   - The NAME is a claim the connection is making about itself. It is what a
 *     future `account-tag` would stamp on every line, and its emptiness is
 *     MEANINGFUL to a client: the `account-tag` specification says the tag
 *     "MUST NOT be sent" for a user who is not identified, which makes the tag's
 *     ABSENCE an assertion. So the absence has to be a first-class state, and
 *     the flag is what makes it one that no consumer has to infer.
 *   - The FACT is what this node verified, and it is what nothing but this
 *     module may assert. A name with no fact is a client claiming to be whoever
 *     it likes; a fact with no name is a verification of nothing.
 *
 * They cannot disagree in practice because account_set() writes both in one
 * function and account_clear() erases both, and because there is no third
 * writer. A consumer that wants "is this connection identified" asks
 * account_logged_in() and gets an answer that requires BOTH, which is why the
 * predicate is written as the conjunction rather than as `c->logged_in`.
 *
 * The cost is four bytes on a struct that already carries a 256-byte realname,
 * and one invariant that a future field could break -- which is the reason the
 * invariant is written down here rather than left as a habit.
 */
#ifndef IRC_CORE_ACCOUNT_H
#define IRC_CORE_ACCOUNT_H

#include "account_store.h"
#include "core/connection.h"
#include "core/server.h"

/* Record `name` as this connection's account. Returns 0 on success, -1 if
 * `name` is NULL, empty, or longer than the connection's field, if the
 * connection has not completed a SASL exchange (`c->sasl != SASL_COMPLETED`), or
 * if `store` is absent or does not hold `name` with `password`.
 *
 * THE TWO CHECKS ARE THE POINT and they are what makes the invariant at the top
 * of this file structural rather than aspirational:
 *
 *   - the caller must pass the SAME authcid the credential store verified. The
 *     function does not take it from `c->account` (which is empty until here)
 *     and does not take it from the SASL context (which is not on conn_t); it is
 *     a parameter, so a caller has to say which identity it is claiming and
 *     cannot claim one while authenticating as another.
 *   - the account registry must hold that name with that password. The
 *     credential store says the client may AUTHENTICATE AS this name; the
 *     registry says the account EXISTS. Both, or the connection is not logged
 *     in -- which is what stops a node whose credential store is broader than
 *     its registry from minting accounts out of nothing, and it is the
 *     fail-closed direction if the two files disagree.
 *
 * WHY A PASSWORD IS A PARAMETER. This function does not need one, and passing
 * it is deliberate: the function that establishes an identity should not be
 * able to establish it from a name alone. The caller has already verified the
 * password (that is what SASL means) and re-checking it against the registry is
 * a bounded 64-record constant-time walk on a path that runs once per login --
 * noise next to the base64 decode that preceded it -- and it means the ONLY way
 * to get an account onto a connection is through a check rather than through an
 * assignment.
 *
 * NOT the writer for anything else. There is no "set the account because the
 * client said so", and there must never be one: `account-tag`'s entire reason
 * for existing is that a client's own claim about its account is not evidence. */
int account_set(server_t *s, conn_t *c, const char *name, const char *password);

/* Forget this connection's account. Both fields, in one function, so the pair
 * cannot be left half-erased.
 *
 * WHO CALLS IT, and why it is here rather than only in conn_free(): a connection
 * is freed by conn_free() and never re-used, so on its own this would be belt to
 * those braces. It is on the same list as cap_reset() and server_nick_unclaim()
 * for the same reason -- the state must not outlive the connection that owns it,
 * and `server_close_conn()` is the one function every retirement goes through --
 * and because a reader of conn_t's teardown wants to see the account released
 * where the nickname is, rather than having to know that account_free() is
 * somewhere else entirely. */
void account_clear(conn_t *c);

/* Is this connection identified to an account? 1 logged in, 0 not.
 *
 * THE ANSWER IS LOCAL AND THAT IS THE WHOLE ARGUMENT: it reads two fields of
 * `c` and consults no store, so there is no node-state a consumer could observe
 * as a difference between a node with accounts and one without. See the
 * invariant block at the top of this file. */
int account_logged_in(const conn_t *c);

/* The account name, or "" when this connection is not identified.
 *
 * "" rather than NULL for a client that is not logged in, because "" is the
 * same value the field holds in that state and a consumer that special-cases
 * NULL would be handling a state the struct cannot be in. A caller that has not
 * established the identity and wants to be sure is asking the wrong question
 * should call account_logged_in() first; this is the VALUE. */
const char *account_name(const conn_t *c);

#endif /* IRC_CORE_ACCOUNT_H */
