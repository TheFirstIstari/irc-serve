/* chan_verbs.h -- the seven channel commands.
 *
 * Authority: docs/SERVER_DESIGN.md 4.1 (JOIN PART TOPIC NAMES MODE KICK), 2.2
 * (the single-writer rule, mode authority, and the local/remote member split)
 * and 3.1 (which decides, for each verb, whether the action is a local write, a
 * forward, or both). The data model and the ownership predicates are in
 * core/channel.h; the reply-path rules are in core/reply.h. This header is the
 * seam between the two: it takes a parsed message and a connection and answers
 * it, and it has no state of its own.
 *
 * ---------------------------------------------------------------------------
 * WHY THE HANDLERS ARE NOT IN THE COMMAND TABLE'S OWN FILE
 * ---------------------------------------------------------------------------
 * The table that maps a verb to a handler stays in commands.c, where Phase 3
 * put it. The handlers are declared here instead because of the rule section 3
 * states most strongly: numerics are never written to a peer link, and that is
 * enforced "in exactly one reply() function, never ad hoc per handler". The
 * obvious way to fan a JOIN out to every member is to walk the member list
 * inside the handler -- correct, and also the shape that scales into "each
 * handler decides where messages go". So the per-member emission is one function
 * in chan_verbs.c, every handler reaches it through it, and no verb can be right
 * while its sibling is wrong.
 *
 * ---------------------------------------------------------------------------
 * THE DECISIONS 7/Phase 4 LEAVES OPEN, MADE HERE
 * ---------------------------------------------------------------------------
 * Three of them, because a client cannot tell the difference between a choice
 * and an oversight:
 *
 *   1. NAMES/LIST enumerate EVERY channel on the node, including ones the
 *      requester has not joined. A list restricted to joined channels carries no
 *      information: the only way to learn a channel exists is to be told it
 *      exists. 2.2 makes channels globally shared objects, so "what is on this
 *      network" is the question a client is actually asking.
 *
 *   2. A LOCALLY ORPHANED channel is listed and named normally. Its topic and
 *      local member count are facts this node holds, and a client has no way to
 *      know they may be stale. 2.2's fail-closed rule refuses origin-requiring
 *      ACTIONS; it does not make the node pretend the channel does not exist,
 *      and hiding it would be a worse answer than showing it.
 *
 *   3. NAMES on a channel this node has never heard of is 366 with no 353, and
 *      LIST on one is 403. The asymmetry is the RFC's: LIST <channel> names a
 *      specific channel whose absence is an error (RFC 2812 3.3.5), while NAMES
 *      is a discovery command that a client calls precisely to find out whether
 *      something is there, and "nobody" is a legitimate answer to it.
 */
#ifndef IRC_CORE_CHAN_VERBS_H
#define IRC_CORE_CHAN_VERBS_H

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"

/* How many channels one JOIN/PART may name. RFC 1459 2.3.1 has no limit, so a
 * cap has to exist for the same reason every other client-driven bound in this
 * node does: a comma-separated list is the one place a single line can ask for
 * unbounded work in the event loop. Beyond this the whole command is refused
 * with 461 rather than part-executed, because a PART that half-succeeds is a
 * state change the client did not ask for as a unit. */
#define CHAN_MAX_LIST_ARGS 16

/* Split a comma-separated channel list into NUL-terminated names.
 *
 * `store` is scratch of at least `dstcap` bytes and `names` receives up to
 * `max` pointers into it. Returns the number of names, or -1 on a bad argument,
 * on an empty or over-long element, or on more elements than `max`.
 *
 * Why in-place splitting is safe HERE and is not a general technique: a
 * parameter of a parsed message cannot contain a space (the wire grammar has no
 * quoting), so a comma inside one is unambiguously a separator rather than part
 * of a name, and the length of the whole list is known. That is a property of
 * this call site, not of the string. */
int chan_split_list(char *store, size_t dstcap, const char *src,
                    const char **names, int max);

/* The command surface. Each is a `command_t::fn` and each obeys the same shape:
 * validate arity, resolve the channel, ask the authority question, and only then
 * touch state. The authority question is asked in chan_verbs.c's own
 * authority_ok(), which every one of these calls -- there is no verb that
 * decides it for itself. */
void handle_join(server_t *s, conn_t *c, const message_t *m);
void handle_part(server_t *s, conn_t *c, const message_t *m);
void handle_topic(server_t *s, conn_t *c, const message_t *m);
void handle_names(server_t *s, conn_t *c, const message_t *m);
void handle_list(server_t *s, conn_t *c, const message_t *m);
void handle_kick(server_t *s, conn_t *c, const message_t *m);
void handle_mode(server_t *s, conn_t *c, const message_t *m);

#endif /* IRC_CORE_CHAN_VERBS_H */
