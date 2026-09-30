/* reply.h -- the ONE place a numeric is emitted.
 *
 * Authority: docs/SERVER_DESIGN.md section 3, the reply-path invariants:
 *
 *   - "Numerics are NEVER written to a peer link and never relayed. Enforced in
 *      exactly one reply() function, never ad hoc per handler."
 *   - "`src` may be NULL for server-originated messages -- SQUIT, a peer KILL,
 *     a resync burst. reply() documents what NULL means per numeric."
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE EXISTS AT ALL
 * ---------------------------------------------------------------------------
 * Because a handler that writes a numeric to a CONN_SERVER socket sends
 * ":server 433 nick x" at a peer, whose framing layer then parses "433" as a
 * COMMAND WORD and asks the peer what it meant. The failure is silent, it is
 * expensive to debug from a log, and Phase 6 inherits whatever this phase gets
 * right. So the invariant lives here, in one function, rather than in the
 * discipline of whoever writes the next handler.
 *
 * That is the whole reason reply() and send_pong() are the only two functions
 * in src/ that call server_queue() for an outbound message. A handler states
 * WHAT it says; this module decides WHERE it may be said.
 *
 * ---------------------------------------------------------------------------
 * THE WIRE FORM IS BUILT BY THE PHASE 1 FORMATTER, NOT BY A SNPRINTF
 * ---------------------------------------------------------------------------
 *   :<server> <code> [<middle params> :] <trailing text>
 *
 * reply() assembles a message_t with message_build() and renders it with
 * message_format(), both of Phase 1 and both under test. That is deliberate:
 * message_format() is where the RFC 1459 2.3 rules actually live -- the
 * trailing parameter is colonned only when it has to be, an unrepresentable
 * value is REPORTED rather than silently reshaped, and a CR or LF in any field
 * is refused so no field can inject a second line onto the connection. A
 * hand-rolled snprintf in a handler would re-implement a subset of those rules
 * and would get the "which parameter needs a colon" part wrong eventually.
 *
 * The two middle-parameter cases the format needs are real: 004 and 005 carry
 * their payload in middle parameters, and 421/433 name the offending thing in
 * one. So `mid` exists, and it is an array rather than a single string because
 * a single string would put hand-joined token lists back into the callers.
 */
#ifndef IRC_CORE_REPLY_H
#define IRC_CORE_REPLY_H

#include <stddef.h>

#include "core/connection.h"
#include "core/server.h"

/* Reply outcomes, named because the caller has to be able to tell a delivered
 * numeric from a refused one, and both failures count the same way on the
 * node's own counters. */
#define REPLY_OK       0
#define REPLY_REFUSED (-1)

/* Longest trailing text reply() will render, and the wire cap on what it
 * renders into. A numeric's text is a short sentence, so 512 is generous; a
 * longer one is a caller bug and is REFUSED rather than truncated, because 3.2
 * forbids silent mid-parameter truncation for the same reason. */
#define REPLY_TEXT_MAX 512

/*
 * Emit one numeric to one client.
 *
 *   s     the node. s->name is the prefix on the wire, and s->trace is NOT
 *         consulted: a refusal below is a bug, and a diagnostic that only
 *         appears when tracing is on is not a diagnostic.
 *   src   the connection the numeric is ADDRESSED TO, and the source of the
 *         <target> field. See the NULL contract below.
 *   code  the three-digit numeric, as a string ("001", "433"). Non-empty.
 *   mid   the middle parameters between <target> and the trailing text, or
 *         NULL with nmid == 0. At most REPLY_MAX_MID of them. A value that
 *         cannot be represented in a non-final position (an empty string, or
 *         one containing a space or a leading colon) is REFUSED, not
 *         reshaped -- message_format() reports it and so does this.
 *   fmt   the trailing text, printf-formatted. Never truncated: if it does not
 *         fit REPLY_TEXT_MAX the call is refused.
 *
 * <target> is src->nick when the client has a nickname and "*" when it does
 * not, which is what RFC 2812 requires and what makes a pre-registration
 * numeric parseable by a client.
 *
 * WHAT A NULL `src` MEANS
 * -----------------------
 * NULL means the message is server-originated and has no client to answer, and
 * that is NOT a licence to broadcast it. Nothing is emitted and REPLY_REFUSED
 * is returned, with the refusal counted on s->n_reply_refused and named on the
 * node's observable output.
 *
 * The reason this is a refusal and not a fan-out is worth being explicit
 * about, because 3 names the three cases and none of them is a numeric:
 * SQUIT, a peer KILL and the Phase 6 resync burst are all PROTOCOL MESSAGES
 * that go out through the relay path to whatever their target is, and none of
 * them is a reply to a client. A numeric addressed to no one is a caller that
 * reached for reply() when it wanted a broadcast, so the honest thing is to
 * refuse loudly rather than invent an addressee. Phase 6's deferred-reply
 * cases (SNAMES, remote WHO/ISON) are the ones that will genuinely need to
 * answer a client after the loop has moved on, and they get a queue keyed by
 * connection rather than a NULL src here.
 *
 * RETURN VALUE AND WHY SOMETHING IS REFUSED AT ALL
 * -------------------------------------------------
 * REPLY_REFUSED, always counted on s->n_reply_refused and always printed --
 * whether or not tracing is on, because a bug report a flag can silence is not
 * a bug report. The reason is in the line, so a reader does not have to guess
 * which rule fired:
 *
 *   peer_target src->kind is CONN_SERVER. THIS IS THE FEDERATION INVARIANT.
 *              It is a refusal and not an assert() on purpose: an assert would
 *              take the whole node -- every other client on it -- down for one
 *              bad call, and a drop with a loud diagnostic is both observable
 *              and survivable. The bytes are never queued, so a numeric cannot
 *              reach a peer even transiently.
 *   no_target  src is NULL. See the contract above.
 *   closing    src is marked CLOSING. Its descriptor is about to be closed by
 *              the reaper and the loop has already dropped it from the poll
 *              set, so anything queued here would sit in the write queue
 *              until the fd died. One connection's PING arriving in the same
 *              segment as its QUIT reaches this, which is why it is a
 *              refusal rather than a note in a comment.
 *
 * Plus four that mean the CALL is wrong rather than the destination: bad_args
 * (a NULL node or an empty code), too_many_params (more middle parameters than
 * the 15-parameter cap leaves room for), text_too_long (the formatted text does
 * not fit, which is refused rather than truncated -- 3.2 forbids delivering a
 * silently shortened parameter), and bad_param / unrepresentable (a value
 * message_format() cannot render in that position).
 *
 * Refusing is the right answer in every one of those cases rather than emitting
 * a best effort: a client that receives a malformed numeric behaves wrongly for
 * the rest of the session, and a client that receives NOTHING can at least
 * time out and reconnect.
 */
int reply(server_t *s, conn_t *src, const char *code,
          const char *const *mid, size_t nmid, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 6, 7)))
#endif
    ;

/*
 * Emit ONE non-numeric message to one client, through exactly the same
 * destination rules as reply().
 *
 *   prefix     the message prefix, WITHOUT the leading ':', or NULL for this
 *              node's own name. A client-originated broadcast needs the acting
 *              user's hostmask here (RFC 2812 3.3.1), which is why this is a
 *              parameter rather than always s->name.
 *   command    the command word, upper-cased by message_build() like every
 *              other one.
 *   params     the full parameter list, as message_build() wants it. For a
 *              KICK the last parameter is the reason, which the formatter
 *              colons automatically.
 *
 * Returns REPLY_OK, or REPLY_REFUSED for every reason reply() has: a peer
 * target, a CLOSING target, a value the wire cannot represent in that
 * position, or a line that does not fit IRC_MAX_LINE. The refusals are counted
 * on s->n_reply_refused exactly as reply()'s are, because they are the same
 * faults arriving by a different door.
 *
 * WHY THIS IS HERE RATHER THAN A FAN-OUT IN commands.c
 * ---------------------------------------------------
 * Phase 4's JOIN, PART, TOPIC, KICK and MODE all have to say something that is
 * not a numeric -- ":nick!user@host JOIN #chan" -- and they all have to be able
 * to say it to MORE THAN ONE client. Both of those are reply-path concerns, and
 * section 3 is explicit that the reply path is the single enforcement point for
 * "numerics are never written to a peer link". A broadcast helper that reached
 * past reply() would be a second place that decides where an outbound message
 * may be written, which is the exact duplication this module exists to prevent.
 *
 * A REFUSAL TO RENDER IS NOT THE SAME AS A REFUSAL TO SEND, and both count on
 * the same counter on purpose: "this line is not representable" and "you may not
 * send it here" are both bugs in a caller, and a caller that produces either
 * should be noticed.
 */
int send_line(server_t *s, conn_t *dst, const char *prefix,
              const char *command, const char *const *params, int nparams);

/* As send_line(), with the final parameter colonned whether or not RFC 1459
 * requires it. Exists for IRCv3's CAP, whose capability list every server writes
 * as `CAP * LS :a b` and which RFC 1459's "colonned only when it has to be"
 * rule would render bare; see message_format_ex() for why the specification's
 * bytes win there. Everything else about the destination rules, the refusals and
 * the counters is send_line()'s, because it is the same door. */
int send_line_colon(server_t *s, conn_t *dst, const char *prefix,
                    const char *command, const char *const *params, int nparams);

/* As send_line(), with a tag block on the outbound line. This is the ONLY way a
 * tag reaches a client, and it exists as a separate function rather than as a
 * NULL-tags sentinel inside send_line() because a tag block on a line is a
 * per-destination decision (one client negotiated `message-tags` and the next
 * did not) while the other six arguments are the same message: the callers that
 * write to a LIST of members each ask the question once per member, and a flag
 * would have to be threaded through the same walk either way.
 *
 * `tags` is a block WITHOUT the leading '@' and NUL-terminated -- the contract
 * irc_serve_tags_format() and irc_serve_msgid_tag() both produce. NULL means no
 * tag block, and is exactly send_line().
 *
 * 3.2's rule that the internal `irc-serve-*` tags are STRIPPED before delivery
 * to a client is enforced by what is passed in here, not by this function: the
 * caller decides, and the only caller that has a client-visible tag to pass is
 * the one that negotiated for it. That is deliberate -- a filter here would be a
 * second place that decides what a client may see about this node's internals,
 * and 2.4's rule is one sentence a reader can check at the call site. */
int send_line_tagged(server_t *s, conn_t *dst, const char *prefix,
                     const char *command, const char *const *params, int nparams,
                     const char *tags);

/* As many middle parameters as the 15-parameter cap leaves room for once
 * <target> and the trailing text have taken two slots. */
#define REPLY_MAX_MID (IRC_MAX_PARAMS - 2)

/* Answer a PING with a PONG. PONG is not a numeric -- it is a command, and it
 * is the one command this node originates -- but it travels the same path and
 * obeys the same peer-link refusal, because the reason a numeric must not
 * reach a peer applies byte for byte to a PONG.
 *
 * The token is echoed verbatim, which is what a client's own liveness check
 * compares against. An absent or empty token becomes the server name, which
 * is what RFC 1459 2.4 specifies for a PING with no argument; an empty
 * trailing parameter would render as a bare ':' and read back as an empty
 * token, which is not the same thing. */
int send_pong(server_t *s, conn_t *src, const char *token);

#endif /* IRC_CORE_REPLY_H */
