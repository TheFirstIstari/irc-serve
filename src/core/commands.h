/* commands.h -- the client command surface, and the registration state machine.
 *
 * Authority: docs/SERVER_DESIGN.md 2.1 (the identity fields and the state
 * enum), 2.3 (a peer link is exempt from this state machine entirely), 3 (the
 * dispatch seam and the reply-path invariants), 3.3 (the message path ends at
 * dispatch), 4.1 (PASS NICK USER PING PONG QUIT MOTD) and 4.4 (numerics).
 *
 * ---------------------------------------------------------------------------
 * THIS IS THE FIRST PHASE WHERE THE NODE ANSWERS
 * ---------------------------------------------------------------------------
 * Phases 1 and 2 built the tokenizer and the loop. Nothing had ever called
 * valid_nick(), so the rule that 2.1's whole `nick@server` identity scheme
 * depends on was specified and tested but not enforced anywhere at runtime, and
 * a nickname could in principle have been any bytes at all. Registration is
 * where a nickname is chosen, so it is the only place that call belongs.
 *
 * Everything here answers through reply()/send_pong() (see reply.h) and never
 * touches a socket. A handler states what it wants to say; reply.h decides
 * where it is allowed to be said.
 */
#ifndef IRC_CORE_COMMANDS_H
#define IRC_CORE_COMMANDS_H

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"

/* The Phase 3 command surface: PASS, NICK, USER, PING, PONG, QUIT, MOTD, and
 * the pre-registration gate plus 451/421 for everything else. Matches
 * server_dispatch_fn, so it is installed by assigning it:
 *
 *     srv.dispatch = commands_dispatch;
 *
 * Assigned rather than hidden behind an install() helper so that what the
 * shipped binary does is visible at the point where it does it. A NULL
 * dispatch -- the honest Phase 2 state -- accepts, frames and parses and then
 * says nothing, which is what this replaces.
 *
 * `c` is the connection the command arrived ON and `m` is owned by the caller
 * and released as soon as this returns, so a handler that needs a field later
 * must copy it. */
void commands_dispatch(server_t *s, conn_t *c, const message_t *m);

/* Is this connection past the registration gate? CONN_REG_READY is the only
 * state in which a client command other than the registration verbs is legal,
 * and it is the state the welcome burst has already been sent for. Exposed
 * because the rule "a command before registration is 451, not silence" is a
 * property of the state encoding rather than of any one handler, and a test
 * that cannot ask the question cannot check it. */
int commands_registered(const conn_t *c);

/* Recompute this connection's registration state from its two facts and emit the
 * welcome burst if the transition into CONN_REG_READY happened.
 *
 * EXPOSED, and it is one function rather than the static it was, because Phase 8
 * has a second caller: `CAP END` releases the negotiation hold, and a client that
 * sent NICK, USER, CAP LS and then CAP END must register from THAT call. Exposing
 * it keeps one promotion to CONN_REG_READY in the tree rather than two, and the
 * two gates it enforces -- the CAP hold and the SASL failure hold -- stay in one
 * place for the same reason. Idempotent: a repeated NICK or USER leaves both
 * facts true, the projection is unchanged, and nothing is re-sent. */
void commands_state_update(server_t *s, conn_t *c);

#endif /* IRC_CORE_COMMANDS_H */
