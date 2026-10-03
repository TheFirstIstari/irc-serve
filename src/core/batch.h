/* batch.h -- IRCv3's `batch`, the CLIENT-FACING half, and the reference tags.
 *
 * Authority: IRCv3 `batch` (the BATCH verb and the `batch` message tag) and IRCv3
 * `client-tags/reference-tags` (the `@` and `+` tags). Design: docs/SERVER_DESIGN.md
 * §4.4.7.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS A MODULE AND NOT FOUR LINES IN reply.c
 * ---------------------------------------------------------------------------
 * Because the question it answers is asked in THREE places that must agree, and the
 * three are: `commands.c`'s dispatch (does this command open, close or reference a
 * batch?), `reply.c`'s single queueing site (does this outbound line carry
 * `batch=<ref>`?), and `commands.c`'s verb table (does `BATCH` exist at all?). Put
 * the decision in any one of them and the other two have to reach into it, which is
 * how "the batch reference is applied on the way out but read on the way in" — a
 * batch tag on a line that is not in any batch — becomes possible.
 *
 * So this module owns the four `conn_t` fields and answers four questions, and
 * nothing else in the tree reads those fields.
 *
 * ---------------------------------------------------------------------------
 * SCOPE, AND IT IS NARROWER THAN THE SPECIFICATION
 * ---------------------------------------------------------------------------
 * `batch` as a specification has a server half this node does not implement: the
 * SERVER opening a `netsplit` or `netjoin` batch around its own emissions. Two
 * reasons that is not a gap in this phase:
 *
 *   - **the capability does not claim it.** The specification says explicitly that
 *     "batch types are not advertised by servers nor explicitly requested by
 *     clients", and that "Client MAY ignore the type and process messages one by
 *     one." So advertising `batch` promises a client the FRAMING, not a netsplit
 *     suppressor, and a client that gets no `netsplit` batches is getting exactly
 *     what `batch` promises.
 *   - **the only batch type this node emits is `labeled-response`**, which is
 *     Phase 10.13's and exists because IRCv3's `labeled-response` specification
 *     requires one: a multi-line response must be grouped so that the label appears
 *     in exactly one LOGICAL message.
 *
 * `draft/multiline` is **not** in scope and is named at every place it would have
 * touched. It is the specification `client-tags/reference-tags` exists for, and
 * implementing it means interpreting `;draft/multiline-concat` values and splitting
 * one command into several — a different feature with a different surface.
 */
#ifndef IRC_CORE_BATCH_H
#define IRC_CORE_BATCH_H

#include <stddef.h>

#include "core/connection.h"
#include "core/server.h"

/* ---------------------------------------------------------------------------
 * THE WIDTH OF A WRITTEN `batch=` TAG, WHICH IS NOT THE WIDTH OF A REFERENCE
 * ---------------------------------------------------------------------------
 * TWO BOUNDS, and conflating them is a bug this module shipped once. The first version
 * of `reply.c` asked for a `char[CONN_MAX_BATCH_REF + 1]`, and a 64-byte reference --
 * which `batch_ref_valid()` ACCEPTS -- produces a 71-byte tag: `snprintf()` reported a
 * truncation, `batch_line_tag()` returned 0, and the tag was silently dropped for
 * exactly the references AT the boundary. `test_batch.c`'s 64/65 case is the assertion,
 * and it is there because a bound tested only below its own edge passes.
 *
 * So the two are named separately and neither is written as the other:
 *
 *   CONN_MAX_BATCH_REF  how long a reference tag may BE -- connection.h's bound, on
 *                       the stored field
 *   BATCH_TAG_MAX       how many bytes a WRITTEN `batch=<ref>` pair may occupy,
 *                       INCLUDING the NUL: the key, the '=', and the widest reference
 *                       `batch_ref_valid()` will ever pass
 *
 * `BATCH_TAG_MAX` is what every caller of `batch_line_tag()` must size its buffer
 * with, and it is a macro so that raising `CONN_MAX_BATCH_REF` moves it -- which is
 * the whole point of deriving it rather than writing it out.
 */
#define BATCH_TAG_KEY "batch="
#define BATCH_TAG_MAX (sizeof(BATCH_TAG_KEY) + (size_t)CONN_MAX_BATCH_REF)

/* ---------------------------------------------------------------------------
 * REFERENCE TAGS -- the one question everything else hangs off
 * ---------------------------------------------------------------------------
 * A reference tag is `[ '+' | '@' ] <ref>`, and the character class of `<ref>` is
 * IRCv3's: "ASCII letters, numbers, and/or hyphen", case-sensitive, non-empty.
 *
 * WHY IT IS A PREDICATE AND NOT A SCAN IN THE HANDLER. Three call sites read a
 * reference tag — `BATCH +ref`, `BATCH -ref`, and the `@`/`+` dispatch scan — and a
 * scan written three times is a scan that will eventually disagree with itself about
 * whether `+abc-def` is a legal tag. One function, three callers.
 *
 * IT IS ASCII AND NOT `isalnum()`, deliberately: `isalnum()` is locale-dependent, and
 * a reference tag is defined over ASCII letters and digits. In a UTF-8 locale
 * `isalnum()` accepts bytes above 0x7f, which would put a non-ASCII byte into a
 * value this node then writes back out on the wire inside a tag block — and
 * `ircv3_tags.c` refuses a raw SP/HTAB/CR/LF in a value but has no opinion about
 * high bytes, so the byte would travel.
 *
 * RETURNS 1 for a legal tag of at most CONN_MAX_BATCH_REF bytes, 0 otherwise. It
 * does not allocate and it does not copy: the caller copies.
 */
int batch_ref_valid(const char *ref);

/* ---------------------------------------------------------------------------
 * THE DISPATCH HOOK -- called once per client command, around the handler
 * ---------------------------------------------------------------------------
 * `batch_begin_command()` reads the inbound line's `@`/`+` reference tags and records
 * what they mean. `batch_end_command()` clears the per-command state.
 *
 * THEY ARE TWO FUNCTIONS AND NOT ONE because of WHEN the second has to run, and the
 * reason is `@`:
 *
 *   `+<ref>`  ONE-SHOT. The next line emitted to this connection carries
 *             `batch=<ref>`, and the reference is consumed by it. That is the whole
 *             of `+`, and it is one-shot because a reference names ONE response, not
 *             a period of time.
 *
 *   `@<ref>`  A SUPPRESSION, held for the DURATION of the command. The meaning of
 *             `@` is that the response is sent NOWHERE — not "tag it, and a client
 *             that ignores the tag drops it" — so it cannot be a one-shot reference
 *             the way `+` is: a response is frequently more than one line (`WHOIS` is
 *             four on this node, and `NAMES` is chunked when a roster overflows one
 *             `353`), and `@` has to mean all of it. Hence a flag that `dispatch()`
 *             clears on the way out rather than a field the reply path consumes.
 *
 * THE SUPPRESSION IS CHECKED IN `reply.c`'s ONE QUEUEING SITE, which means it applies
 * to everything the node writes to that connection during the command: numerics, a
 * `SETNAME` confirmation, and an `echo-message` copy of the sender's own PRIVMSG.
 * That is the consistent reading — `@` asks for the response to go nowhere, and an
 * echo is part of what the command produced — and it is also the only one
 * implementable without a per-emission distinction between "a reply" and "an
 * emission", which is not a distinction this node's reply path makes anywhere else.
 *
 * A CALLER THAT PASSES A PEER CONNECTION GETS NOTHING DONE, and that is
 * `dispatch()`'s ordering rather than a check here: a peer line is routed to
 * `fed_dispatch()` and never reaches the client verb table.
 *
 * `m == NULL` IS A NO-OP, so a caller does not have to know that a command always
 * has a message. */
void batch_begin_command(conn_t *c, const message_t *m);
void batch_end_command(conn_t *c);

/* ---------------------------------------------------------------------------
 * THE REPLY HOOK -- what `reply.c` asks, once per outbound line
 * ---------------------------------------------------------------------------
 * `batch_line_tag()`: the `batch=` tag this destination's NEXT line should carry, or
 * 0 for none. It is `conn_t *` and not `const conn_t *` because consuming a one-shot
 * reference IS the caller's job and doing it in a `const` function would be a lie
 * about the effect.
 *
 * THE ORDER IS OPEN BATCH FIRST, THEN THE ONE-SHOT, and it is not an arbitrary
 * precedence: an open batch means everything this connection says is inside that
 * batch, and a `+ref` inside an open batch either names the batch already open
 * (nothing to do) or names a batch that does not exist (refused at the point the
 * command was dispatched, by `batch_begin_command()`). So the one-shot can only be
 * live when no batch is open, and the two cases cannot both be true.
 *
 * THE WRITTEN FORM INCLUDES THE `batch=` KEY, so a caller concatenates rather than
 * formatting: `batch_ref_valid()` has already established the character class, so
 * there is nothing to escape and nothing to reject here.
 */
int batch_line_tag(conn_t *dst, char *out, size_t cap);

/* Whether the INBOUND line carried a `batch=` tag. `client-batch` says a client may
 * not send `BATCH` commands with a batch tag -- that is the whole of its no-nesting
 * rule -- and a `BATCH` is the only verb on this node for which that is checkable, so
 * the question is asked by the handler rather than by the dispatch hook.
 *
 * IT IS A SCAN AND NOT `message_tag_get()` FOR THE SAME REASON `batch.c`'s own scan
 * is: the key is a literal here (`batch`, with no sigil), so `message_tag_get()` would
 * work, and the scan is NOT used. This predicate exists to be one obvious question with
 * one answer, and the answer lives in the handler that needs it. */
int batch_line_tagged_inbound(const message_t *m);

/* The reference tag of the batch this connection has open, or `""` for none. Read
 * only, and exposed for `server.c`'s teardown reporting and for the log line the
 * `BATCH` handler prints — nothing branches on it. */
const char *batch_open_ref(const conn_t *c);

/* ---------------------------------------------------------------------------
 * THE VERB
 * ---------------------------------------------------------------------------
 * `BATCH +<ref> <type> [<params>...]` opens a batch; `BATCH -<ref>` closes it. This
 * is the client-facing direction; the server-facing direction is the `labeled-response`
 * batch `reply_std()` emits, and it does not go through here because it is not a
 * client's batch — a client cannot close a batch this node opened on its behalf.
 */
void handle_batch(server_t *s, conn_t *c, const message_t *m);

#endif /* IRC_CORE_BATCH_H */
