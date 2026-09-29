/* msg_verbs.h -- the Phase 5 verb surface: messaging, query and status.
 *
 * Authority: docs/SERVER_DESIGN.md 7/Phase 5 ("PRIVMSG/NOTICE with fan-out
 * through 3.1, WHO/WHOIS/ISON, AWAY"), 4.1 (PRIVMSG, NOTICE), 4.2 (WHO, WHOIS,
 * ISON, AWAY -- listed as SHOULD/Phase 6 and pulled forward here, which is what
 * 4.2's own table says 4.4 expects), 3.1 (the routing), 3.2 (the line cap), 4.4
 * (the numerics) and 4.3 (the away field SBURST will have to send).
 *
 * ---------------------------------------------------------------------------
 * WHY THE VERBS ARE NOT IN commands.c
 * ---------------------------------------------------------------------------
 * commands.c keeps the verb->handler table, because that is where Phase 3 put
 * it and because a table is a table. The HANDLERS live here for the same reason
 * chan_verbs.c's do: the per-target emission is a routing decision (3.1) and the
 * reply-path rules are a reply concern (3), and neither belongs in a switch that
 * only meant to name a verb. Each handler here therefore does the same three
 * things in the same order:
 *
 *   1. arity          -- what the client did not send, answered 461
 *   2. resolution     -- fanout_resolve(), which owns every 401/403
 *   3. the verb's own rule -- the one place that differs between verbs
 *
 * and then nothing else. No handler writes to a socket: every byte leaves
 * through reply() or through fanout_deliver(), which is 3's single
 * enforcement point.
 *
 * ---------------------------------------------------------------------------
 * THE FOUR DECISIONS 7/LEAVES TO THE PHASE, MADE HERE
 * ---------------------------------------------------------------------------
 * They are decided here rather than in the design because a client cannot tell
 * the difference between a choice and an oversight. Each is argued at the
 * definition; this is the index.
 *
 *   1. PRIVMSG to a channel the sender is not on is 404 ERR_CANNOTSENDTOCHAN,
 *      NOT the 442 the channel verbs use. 4.4 lists both, so the question is
 *      which question each answers. See handle_privmsg().
 *   2. NOTICE to a channel the sender is not in is DELIVERED. See
 *      send_message().
 *   3. conn_t::away is bounded at 255 bytes and an over-long message is
 *      REFUSED, never truncated. See handle_away() and CONN_MAX_AWAY.
 *   4. 4.4's numeric list has three holes this phase walks through -- 301,
 *      303 and 417. Each is used because the protocol needs it and the list
 *      does not have it, and each is flagged where it is emitted, exactly as
 *      Phase 3 flagged 432. They are collected in the report.
 */
#ifndef IRC_CORE_MSG_VERBS_H
#define IRC_CORE_MSG_VERBS_H

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"

/* The command surface. Each is a `command_t::fn`, and each obeys the shape above.
 * The declarations are here rather than static in commands.c for the reason
 * chan_verbs.h gives: the verb table stays where it is, and the handlers are
 * grouped by what they have in common. */
void handle_privmsg(server_t *s, conn_t *c, const message_t *m);
void handle_notice(server_t *s, conn_t *c, const message_t *m);
void handle_who(server_t *s, conn_t *c, const message_t *m);
void handle_whois(server_t *s, conn_t *c, const message_t *m);
void handle_ison(server_t *s, conn_t *c, const message_t *m);
void handle_away(server_t *s, conn_t *c, const message_t *m);

#endif /* IRC_CORE_MSG_VERBS_H */
