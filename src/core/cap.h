/* cap.h -- IRCv3 capability negotiation, and the connection state it owns.
 *
 * Authority: docs/SERVER_DESIGN.md 7/Phase 8 ("CAP negotiation (LS/REQ/ACK/NAK)")
 * and the IRCv3 capability-negotiation specification.
 *
 * ---------------------------------------------------------------------------
 * WHAT "CAP" IS FOR, IN ONE PARAGRAPH, BECAUSE IT IS NOT OPTIONAL DECORATION
 * ---------------------------------------------------------------------------
 * A modern client connects and sends `CAP LS` before it says NICK or USER,
 * because it has extensions to find out about and it must not be told 451 in the
 * middle of asking. The server answers with the capabilities it has, the client
 * picks the ones it wants with `CAP REQ`, and then it sends `CAP END` to say
 * "I am done negotiating" -- and THE REGISTRATION MUST NOT COMPLETE UNTIL THAT
 * ARRIVES. That last clause is the whole point of the subcommand: a server that
 * completes registration as soon as it has NICK and USER sends 001-005 in the
 * middle of the client's CAP exchange, the client treats the burst as the answer
 * to something else, and the connection hangs with no error on either side. Every
 * modern client hangs against such a server. Getting it wrong is not a
 * compatibility detail.
 *
 * ---------------------------------------------------------------------------
 * THE RULE THIS MODULE EXISTS TO ENFORCE: ADVERTISE ONLY WHAT IS REAL
 * ---------------------------------------------------------------------------
 * `CAP LS` lists capabilities THIS NODE IMPLEMENTS. A listed capability that is
 * not implemented is worse than a missing one, and it is worse in a specific way:
 * a missing one is a client that carries on without the feature, which works,
 * while a listed one is a client that switches the feature on and then behaves
 * as though this node honoured it. That is the same rule this project has held
 * numerics to since Phase 3 -- a 324 that disagrees with the node's modes, a 433
 * that claims a malformed nick is taken, an INFO that lists features nothing
 * implements. CAP LS is that rule applied to a list rather than a numeric.
 *
 * So the table below is a list of implementations, not a list of intentions, and
 * `sasl` is in it CONDITIONALLY: a node started without `--sasl-store` holds no
 * credential store and therefore cannot authenticate anybody, so it does not
 * advertise `sasl`. A client that saw `sasl` and then got 908 would have been
 * told a capability existed and does not.
 *
 * ---------------------------------------------------------------------------
 * RELATIONSHIP TO 005's PREFIX=, STATED RATHER THAN LEFT IMPLICIT
 * ---------------------------------------------------------------------------
 * `005 PREFIX=(ov)@+` names the SIGILS this node uses for prefix modes: '@' is
 * op, '+' is voice. It says which sigils exist and what they mean, and it is
 * true regardless of whether `multi-prefix` is enabled. `multi-prefix` is a
 * separate thing and says only whether a `353` may render MORE THAN ONE sigil
 * per member -- it changes how much is drawn, not what the sigils mean. The two
 * therefore do not have to agree, and they do not contradict each other: a node
 * that renders one sigil per member is still a node whose sigils are '@' and
 * '+'. See cap_multiprefix_enabled() and the comment in chan_verbs.c's
 * send_names_list().
 *
 * The consistency that DOES have to hold is between `CAP LS` and the code: every
 * name in cap_available() must be a name something here implements. That is why
 * there is no `cap-notify` (this node never sends an unsolicited CAP NEW), no
 * `away-notify`, `chghost`, `account-notify` or `echo-message` (it sends none of
 * those), and no `server-time` or `userhost-in-names` (it stamps neither).
 */
#ifndef IRC_CORE_CAP_H
#define IRC_CORE_CAP_H

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"

/* Capability names, as one constant each.
 *
 * Named rather than written as literals at the call sites because a capability
 * that is spelled two ways is a capability that is ACKed once and NAKed once, and
 * that looks like a bug in the negotiation rather than a typo. */
#define CAP_MULTIPREFIX "multi-prefix"
#define CAP_MESSAGE_TAGS "message-tags"
#define CAP_MESSAGE_IDS "draft/message-ids"
#define CAP_SASL "sasl"

/* 410 ERR_INVALIDCAPSUBCOMMAND. Not in design 4.4's numeric list, which is a gap
 * in the list rather than in the protocol, for the same reason 301, 303, 417,
 * 302, 371/374 and 402 are: the RFC defines it and it is the one a client
 * understands. The alternative -- 421, which the wire DOES have for an unknown
 * command -- would be a lie about what happened, because CAP is a known command
 * with an unknown SUBcommand, and a client that retried `CAP` on a 421 would get
 * the same answer for ever. */
#define RPL_INVALIDCAPSUBCOMMAND "410"

/* 908 RPL_SASLMECHS: the mechanisms this node offers. It is sent in answer to
 * `AUTHENTICATE` with a mechanism this node does not implement, which is the only
 * place a client learns what to try instead. */
#define RPL_SASLMECHS "908"

/* Initialise `c`'s capability state. conn_new() gets this right for free because
 * it callocs, and it is here so that a caller which already has a conn_t can say
 * so explicitly. Idempotent. */
void cap_init(conn_t *c);

/* Is `name` a capability THIS BUILD knows about at all? Distinct from
 * cap_available(), which also asks whether this NODE can do it right now: a
 * capability this build has never heard of is answered 410, and one this build
 * knows but this node cannot currently do is answered NAK. */
int cap_known(const char *name);

/* Can this node offer `name` RIGHT NOW? 1 offered, 0 not. */
int cap_available(const server_t *s, const char *name);

/* Render the available set into `out` as the space-separated list a `CAP LS`
 * trailing parameter carries. Returns the byte count written, or 0 if it does not
 * fit -- which cannot happen for a buffer sized CAP_LS_MAX, and is reported
 * rather than truncated if it somehow does. */
size_t cap_available_list(const server_t *s, char *out, size_t cap);

/* A buffer that holds every capability this node can advertise plus their
 * separators and a NUL. It is a constant rather than a caller-chosen size so a
 * new capability cannot be added without the buffer growing with it -- which is
 * the failure where a truncated LS silently hides a capability from every client
 * that asks. */
#define CAP_LS_MAX 256

/* Is the client still mid-negotiation, and therefore is registration held?
 * TRUE from the first `CAP LS` or `CAP REQ` until `CAP END`. This is the one
 * boolean the registration gate in commands.c asks, and it lives here so that the
 * thing that STARTS the negotiation and the thing that RELEASES it are in one
 * file. */
int cap_negotiating(const conn_t *c);

/* Has the client enabled `name`? 1 enabled, 0 not. Case-insensitive on the name,
 * because IRCv3 capability names are. */
int cap_enabled(const conn_t *c, const char *name);

/* multi-prefix specifically, because two modules need it and the bit index
 * should be written down once. */
int cap_multiprefix_enabled(const conn_t *c);

/* message-tags: the gate on whether this node writes ANY tag on an outbound line
 * to this client. Not the same question as draft/message-ids, which is the gate
 * on whether it writes a msgid -- but a client that asked for msgids without
 * asking for message-tags has asked for a tag inside a tag support it did not
 * enable, and gets nothing rather than a tag in a protocol it opted out of. */
int cap_message_tags_enabled(const conn_t *c);

/* Handle one `CAP` line. Returns 1 if it was handled, 0 if it was not a CAP at
 * all (which cannot happen: the caller has already dispatched on the verb). */
void cap_handle(server_t *s, conn_t *c, const message_t *m);

/* Release negotiation state. Called when a connection is torn down, so a
 * conn_t that is freed and re-used at the same descriptor cannot inherit a
 * capability it negotiated in a previous life. conn_t is calloc'd by conn_new()
 * and freed by conn_free(), so this is belt to those braces -- and it is on the
 * same list as "there is no per-connection message id" for the same reason: the
 * state must not outlive the connection that owns it. */
void cap_reset(conn_t *c);

#endif /* IRC_CORE_CAP_H */
