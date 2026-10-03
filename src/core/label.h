/* label.h -- IRCv3 `labeled-response`.
 *
 * Authority: IRCv3 `labeled-response`. Design: docs/SERVER_DESIGN.md §4.4.8.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS A MODULE AND NOT A FLAG ON conn_t
 * ---------------------------------------------------------------------------
 * Because the specification's requirement is not "echo the tag" but **"the tag appears
 * in EXACTLY ONE LOGICAL MESSAGE"**, and on this node a response is frequently several
 * lines -- a `WHOIS` is four and a chunked `NAMES` roster can be twenty. The
 * specification's answer to a multi-message response is a batch: "If a response consists
 * of more than one message, a batch MUST be used to group them into a single logical
 * response. The start of the batch MUST be tagged with the label tag."
 *
 * So the implementation has to know three things a flag cannot hold -- what the label
 * was, whether the grouping batch has been started, and whether anything was emitted at
 * all -- and it has to be able to answer "what tag does THIS line carry" from inside
 * `reply.c`'s single queueing site and "what remains to be said" from inside
 * `commands.c`'s dispatch tail. Those are two different questions asked at two different
 * depths of the stack, and putting them in one module is what keeps them consistent.
 *
 * ---------------------------------------------------------------------------
 * THE ORDER, AND WHY IT IS WHAT IT IS
 * ---------------------------------------------------------------------------
 *   dispatch()  ->  label_begin_command()   copies the client's label, if any
 *   handler     ->  ... every numeric, every emission ... goes through
 *                  emit_built_ex() -> label_line_tag()  for the FIRST line
 *                                              -> label_mint_batch()  for the grouping
 *   dispatch()  ->  label_finish_command()  closes the batch, or answers `ACK`
 *
 * The batch is opened **lazily, on the first line**, and that is forced by the
 * specification rather than chosen. The `BATCH +<ref> labeled-response` line has to come
 * BEFORE the first line of the response, so the decision to open it has to be taken
 * before the first line is emitted -- but a one-line response must not be wrapped in an
 * empty batch, and the node cannot know how many lines a command will produce without
 * running it. Opening eagerly would put a `BATCH +`/`BATCH -` pair around every
 * single-line response, including the `404` for a `PRIVMSG` to a channel with no members,
 * which is the case a client most wants to read. So the first line is what decides, and
 * the state has to remember that it has decided.
 *
 * `batch` is a **dependency of this specification** ("This specification depends on the
 * `batch` capability which MUST be negotiated to use labeled responses"), which is why
 * Phase 10.12 landed first.
 */
#ifndef IRC_CORE_LABEL_H
#define IRC_CORE_LABEL_H

/* The width of a WRITTEN `label=<value>` tag, INCLUDING its NUL: the key, the '=', and
 * the widest value `CONN_MAX_LABEL` admits.
 *
 * DERIVED RATHER THAN WRITTEN, for the same reason BATCH_TAG_MAX is: a buffer sized by
 * eye for "a label" is a buffer that is wrong the moment the bound moves, and the bound
 * moves when a specification's number is quoted somewhere else. The caller in
 * `reply.c` adds it to BATCH_TAG_MAX and to the block it already had, so every
 * client-visible tag this node can put on one line is in that one expression.
 */
#define LABEL_TAG_KEY "label="
#define LABEL_TAG_MAX (sizeof(LABEL_TAG_KEY) + (size_t)CONN_MAX_LABEL)

#include <stddef.h>

#include "core/connection.h"
#include "core/server.h"

/* ---------------------------------------------------------------------------
 * THE DISPATCH HOOKS
 * ---------------------------------------------------------------------------
 * `label_begin_command()` copies an inbound `label=<value>` into `conn_t::label` and
 * arms the machinery. `label_finish_command()` closes the grouping batch if one was
 * opened, answers `ACK` if nothing at all was emitted, and disarms.
 *
 * `label_finish_command()` IS NOT OPTIONAL ON ANY PATH, and that is the property that
 * makes the state safe: a `label_live` that outlived its command would label the NEXT
 * command's first line with a value the client has already been told is finished, which
 * is a correlation bug the client cannot detect.
 *
 * A NULL connection, or a message with no `label` tag, is a no-op -- NOT an error and
 * not a refusal, because the specification says a client "MAY send this tag for any
 * messages that need to be correlated" and most messages do not.
 */
void label_begin_command(conn_t *c, const message_t *m);
void label_finish_command(server_t *s, conn_t *c);

/* ---------------------------------------------------------------------------
 * THE REPLY HOOK
 * ---------------------------------------------------------------------------
 * The tag block this destination's NEXT line should carry, or 0 for none.
 *
 * `code` is the line's own command word, and it is asked because the grouping `BATCH`
 * lines are emitted through this same path and must not be tagged by it.
 *
 * `prefix` IS TAKEN AND NOT USED, which is recorded rather than tidied away: it was the
 * first attempt at deciding "is this the client's own message", by comparing the line's
 * source prefix against the destination's own hostmask. That is a SOURCE test and the
 * specification's exception is about a message ADDRESSED to itself -- so it withheld the
 * label from every echo-message copy, including the echo of a channel message. The
 * question is now `conn_t::label_self`, set by `msg_verbs.c` where the resolved target is
 * available, and the parameter stays because it is where a future rule about which lines
 * may carry a label belongs.
 *
 * `out` receives a WHOLE tag block WITHOUT a leading '@', and it is either
 * `label=<value>` (the first line) or `batch=<ref>` (every line after it) -- never
 * both, because "exactly one logical message" is the entire requirement.
 */
int label_line_tag(server_t *s, conn_t *c, const char *code, const char *prefix,
                   char *out, size_t cap);

/* Whether a `BATCH` verb is one of THIS MODULE's own grouping lines, and so must not
 * have the automatic tag applied to it.
 *
 * IT IS A STRING COMPARISON AND NOT A FLAG, and the reason is that the grouping lines
 * are emitted THROUGH the same queueing site as everything else -- which is what puts
 * them in the right order on the wire -- so the only way to keep them out of their own
 * tagging is to recognise them here. The comparison is against the one command word
 * this module emits and nothing else: a client's own `BATCH` does not go through
 * `emit_built_ex()` with a grouping batch open, and if it did, wrapping a client's
 * `BATCH -ref` in a batch would be wrong in a way no test would notice.
 */
int label_is_grouping_verb(const char *code);

#endif /* IRC_CORE_LABEL_H */
