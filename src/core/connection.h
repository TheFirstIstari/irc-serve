/* connection.h -- conn_t: identity fields, buffers, and RFC 1459 2.3 framing.
 *
 * Authority: docs/SERVER_DESIGN.md sections 2.1 (identity), 2.2 (channels,
 * referenced only), 3.2 (line cap, consumed here via message.h), 3.3
 * (connection framing) and 3.4 (bounded write queues; the send path never
 * closes).
 *
 * ---------------------------------------------------------------------------
 * WHAT IS IN HERE NOW AND WHAT IS NOT
 * ---------------------------------------------------------------------------
 * This struct has its FINAL shape as of Phase 2. Two members are present and
 * deliberately UNUSED until later phases, and it would be worse to add them in
 * Phase 3/4 than to declare them now:
 *
 *   peer_name   -- the server name of a CONN_SERVER link. Nothing creates a
 *                  CONN_SERVER yet: peer sockets are Phase 6, and the dial
 *                  state machine that will create them lives in server.c but is
 *                  driven by no caller. It is always NULL here, and conn_free()
 *                  releases it so the Phase 6 owner is already correct.
 *   chans       -- the channels this conn has joined. `struct chan` is still
 *                  incomplete (2.2 lands it in Phase 4), so the array is never
 *                  grown and every element slot stays NULL. Phase 4 fills it
 *                  without changing the layout.
 *
 * The struct's shape has since been FINAL in the sense 7/Phase 4 meant: the
 * fields Phase 4 and Phase 5 added (member flags and the remote caches on
 * chan_t; away, signon_at and last_active here) are additions, not
 * rearrangements, and every one of them is a field a later phase or a numeric
 * needs. A phase that finds itself wanting a DIFFERENT struct is the signal
 * that the design above is wrong, not that the field should be shoved in
 * wherever it happens to fit.
 *
 * There is deliberately NO per-connection message id. Ids come from a
 * per-SERVER monotonic counter owned by server_t (2.4), because a
 * per-connection counter makes two connections on one server both emit the
 * same (server, 1) and a peer then silently drops the second message. That
 * field must not be added back.
 *
 * ---------------------------------------------------------------------------
 * THE PHASE 8 FIELDS, AND WHY THEY ARE HERE RATHER THAN IN cap.c
 * ---------------------------------------------------------------------------
 * 2.1 makes this struct's shape final, so the state a capability negotiation and
 * an authentication exchange need had to be added here or nowhere. They are
 * ADDITIONS, not rearrangements, and each one is a fact about this connection
 * that another module has to ask:
 *
 *   caps              what this client negotiated. A bitmask over the table in
 *                     core/cap.h, so enabling a capability is one OR and asking
 *                     is one AND -- and so a NEW capability is a new bit rather
 *                     than a new field, which is the shape 2.1 predicted.
 *   cap_negotiating   1 while a CAP LS/REQ is in flight. Registration is HELD
 *                     until CAP END arrives, and this is the flag that holds it.
 *                     It is a separate field rather than a bit in `caps` because
 *                     "the client asked" and "the client was granted" are
 *                     different facts and conflating them would make a client
 *                     that asked for nothing look like one that had finished.
 *   sasl              the SASL exchange's observable state, as the sasl_state_t
 *                     sasl_framework.h defines. ABORTED until a client offers a
 *                     mechanism; FAILED is TERMINAL and is what stops registration
 *                     completing, because a client that failed to authenticate
 *                     must not be able to register as though it had.
 *
 * WHAT NONE OF THEM GRANT. There is no operator flag on this struct and none was
 * added: a successful SASL establishes that the client holds a password, and
 * there is nothing in this node that it could legitimately be granted. Saying
 * so here is the point -- the field a future phase adds is the first place a
 * capability would become a privilege, and it should be added when there is a
 * privilege to grant.
 *
 * PHASE 10.1 ADDS ONE AND IT GRANTS NOTHING EITHER, which is worth saying in
 * this same block because the paragraph above reads like a permanent position.
 * `account`/`logged_in` are a NAME and a VERIFICATION, not a privilege: being
 * logged in to an account on this node authorises nothing here, no operator
 * flag, no channel privilege, no mode, no exemption. What it will eventually buy
 * is VISIBILITY -- `account-tag` stamping it on lines so other users can see who
 * is who -- and that is a different thing from authority, which is why the field
 * could be added without anyone having to decide what a logged-in client may do.
 * If a later phase wants `logged_in` to mean a privilege, that is the change
 * that needs a threat model, and it does not belong in a field.
 *
 * ---------------------------------------------------------------------------
 * THE WRITE QUEUE
 * ---------------------------------------------------------------------------
 * wbuf[woff .. wlen) is the unsent tail; woff is the retained offset. A
 * nonblocking send() may write fewer bytes than offered, so the offset is
 * retained and the remainder is drained on a later poll iteration rather than
 * being dropped or re-sent. The queue is bounded (3.4): exceeding the cap
 * REFUSES the append. It does not grow, does not spill, and does not
 * block -- the caller marks the connection CLOSING and records why, because a
 * saturated peer link is dropped, not buffered.
 *
 * conn_queue() never closes an fd, and neither does conn_pump() (3.4: "the
 * send path never closes a connection"). A connection is closed exactly once,
 * by the reaper in server.c.
 */
#ifndef IRC_CORE_CONNECTION_H
#define IRC_CORE_CONNECTION_H

#include <stddef.h>
#include <time.h>

#include "core/message.h"

struct chan; /* opaque until Phase 4 (2.2) */

/* PHASE 12: the transport ops vtable, OPAQUE HERE ON PURPOSE.
 *
 * connection.h must not include core/transport.h, because transport.h includes
 * connection.h -- the ops take a conn_t. So this struct is forward-declared and
 * the two fields above hold a pointer to it; a reader who wants the operations
 * opens transport.h, which is where the three I/O sites' shared contract is
 * written down. The relationship runs transport.h -> connection.h, never back. */
struct transport_ops;

/* PHASE 12: the node this connection belongs to.
 *
 * It exists because the TLS backend needs the node's SSL_CTX and the call site
 * cannot supply it. conn_pump() starts a STARTTLS handshake from inside the
 * CONNECTION layer -- that is where the ordering guarantee lives, that the 670 has
 * to reach the client in the clear before the handshake begins -- and the
 * connection layer has a conn_t and no server_t.
 *
 * It is set by server_add_conn() and by nothing else, which is the same rule
 * server.h's by_fd table follows one field over: a connection is registered exactly
 * once, so it acquires its node exactly once, and a conn_t that was never
 * registered has owner == NULL -- which the backend treats as "not configured"
 * rather than dereferencing. */
struct server;

/* conn_t::kind */
#define CONN_CLIENT 0
#define CONN_SERVER 1

/* conn_t::state. REG_PASS is the entry state; there is no "not registered"
 * separate from it because a connection is either unregistered (REG_PASS) or
 * has made progress through the registration sequence. CLOSING is terminal:
 * a conn in that state is not read from and not written to, and the reaper
 * closes it at a fixed point in the loop. */
#define CONN_REG_PASS 0
#define CONN_REG_NICK 1
#define CONN_REG_USER 2
#define CONN_REG_READY 3
#define CONN_CLOSING 4

/* ---------------------------------------------------------------------------
 * THE `batch` REFERENCE TAG BOUND, and why there is one
 * ---------------------------------------------------------------------------
 * IRCv3's `batch` specification constrains a reference tag to "ASCII letters,
 * numbers, and/or hyphen", case-sensitive, and says nothing about its LENGTH. So
 * the character class is a validation and this constant is a bound this node
 * imposes, and the distinction is worth making rather than blurring: a
 * specification with no length bound does not license unbounded state.
 *
 * 64 is IRC's own nickname bound (`IRC_MAX_NICK`, 63) plus one, and it is the
 * bound IRCv3's own reference-tag vocabulary converges on in practice. What
 * matters for the argument is not the number but that it is a COMPILE-TIME
 * CONSTANT in a fixed-size array on `conn_t`: a client cannot grow it, so
 * `batch_open` is a field with a compile-time bound rather than an allocation,
 * which is what makes "there is nothing to free" a structural fact and not a
 * promise.
 *
 * THE COST: a reference tag of 65 bytes is REFUSED (`417`), not truncated. 3.2
 * forbids delivering a shortened value, and a truncated reference tag would be a
 * tag that names a batch nobody opened.
 */
#define CONN_MAX_BATCH_REF 64

/* The batch TYPE, which the specification calls "an opaque identifier" and does
 * not bound. Bounded for the same reason and with the same cost. `batch/react`
 * and `draft/multiline-concat` are the longest names in the vocabulary this node
 * has any reason to meet, and both are well inside 96.
 *
 * IT IS STORED AND THEN NOT USED, and that is worth saying rather than leaving
 * a reader to wonder: a batch type describes how a CLIENT should present the
 * events inside a batch, and this node emits no batch types of its own. The
 * field exists so that the log can say which type a client declared and so that
 * a future type has somewhere to be read from; nothing branches on it. */
/* ---------------------------------------------------------------------------
 * `labeled-response`'s LABEL BOUND, and it is the SPECIFICATION'S and not ours
 * ---------------------------------------------------------------------------
 * "The value MUST NOT exceed 64 bytes." Unlike `CONN_MAX_BATCH_REF`, which the batch
 * specification does not bound and this node bounds itself, this number is quoted, and
 * it is quoted at the constant so that raising it is visibly a departure from a
 * specification rather than a tuning decision.
 *
 * WHAT HAPPENS TO A LONGER VALUE IS `label.c`'s decision and the reason is there; the
 * short version is that it is IGNORED rather than truncated, because 3.2 forbids
 * delivering a shortened value and a truncated label is a value the client did not send
 * -- and a client correlating by label would silently correlate against the wrong one.
 */
#define CONN_MAX_LABEL 64

#define CONN_MAX_BATCH_TYPE 96

/* Bounded write queue, 3.4: "~256 KB per connection". The cap is on the
 * UNSENT tail (wlen - woff), not on the allocation, so a long-lived
 * connection that keeps draining does not eventually fail on its own history.
 */
#define CONN_WQ_MAX ((size_t)(256u * 1024u))

/* Read buffer cap. IRC_MAX_LINE (8 KiB, from 3.2) is the largest legal line
 * counting its terminator, so a buffer that reaches that size without having
 * seen a terminator is a line that can never become legal: conn_fill() stops
 * reading there and conn_next_line() reports the framing error. The read
 * buffer is therefore bounded by the same constant the line cap enforces, and
 * a client cannot grow it by withholding a newline. */
#define CONN_RBUF_MAX ((size_t)IRC_MAX_LINE)

/* Reclaim the head of the write queue once this many bytes have been sent and
 * the remainder is smaller than this, so a steady trickle does not leave the
 * allocation pinned at its high-water mark forever. */
#define CONN_WQ_COMPACT ((size_t)4096u)

/* Size of the buffer conn_hostmask() renders into: nick + '!' + user + '@' +
 * host + NUL, written as the three struct widths so raising any of them cannot
 * leave a caller with a buffer that is one byte short. */
#define CONN_HOSTMASK_MAX (sizeof(((conn_t *)0)->nick) + \
                           sizeof(((conn_t *)0)->user) + \
                           sizeof(((conn_t *)0)->host) + 3u)

/* The widths of conn_t::user and conn_t::host, derived from the struct rather
 * than written down, for the reason CONN_HOSTMASK_MAX above is derived: a
 * caller that sizes a buffer from a literal and the struct is raised is a buffer
 * one byte short, and the symptom is a bounded copy that silently truncates an
 * identity field.
 *
 * Phase 9 needs them for the resume window, whose key is (nick, ident, host) --
 * see core/resume.h. Neither field has a bound of its own: USER has no RFC
 * length limit, and 2.1 records the OBSERVED address rather than what the client
 * typed, so the host is truncated to a fixed width at accept time by
 * describe_peer() and this is that width. */
#define CONN_USER_MAX (sizeof(((conn_t *)0)->user) - 1u)
#define CONN_HOST_MAX (sizeof(((conn_t *)0)->host) - 1u)

/* conn_t::realname, the GECOS field USER's fourth parameter carries and the one
 * IRCv3's `setname` changes in place.
 *
 * WHY IT IS 255 AND NOT A `sizeof()` EXPRESSION, which the two constants above
 * both are. Three things already agree on 255 for "a sentence a user typed":
 *
 *   1. the field is char[256], so the value bound is one less than the field --
 *      the same relationship IRC_MAX_NICK has to conn_t::nick.
 *   2. realname is 005's NAMELEN, which IRCv3's `setname` specification makes
 *      MANDATORY for a node advertising that capability, so the number has to
 *      exist whether or not the command does.
 *   3. it equals CHAN_MAX_TOPIC and CONN_MAX_AWAY, the other two client-supplied
 *      free-text fields this node stores. One bound for "a sentence a user
 *      typed", not three that differ for no stated reason.
 *
 * AND THE REAL REASON, WHICH IS A COMPILER FACT: 005 renders this number with
 * commands.c's IRC_STR(), and `#x` stringifies an argument's TOKEN SEQUENCE
 * rather than evaluating it. A `sizeof(((conn_t *)0)->realname) - 1u` in this
 * position renders the 43-character string
 *
 *     sizeof(((conn_t *)0)->realname) - 1u
 *
 * as the token's value, which contains spaces -- and a middle parameter holding
 * a space is `unrepresentable`, so the whole 005 is REFUSED and every client
 * connecting to the node gets no ISUPPORT at all. This is the same bound
 * CONN_MAX_AWAY already carries as a literal for a related reason, and it is
 * why the token is derived from a NUMBER here and the number is written down
 * here: the derivation that can be stringified runs one level up, in k_005[].
 *
 * Raising conn_t::realname therefore means changing this AND the NAMELEN token,
 * and tests/integration/test_registration.c asserts NAMELEN=255 as a literal
 * precisely so that a change to the field without a change to 005 fails a test.
 *
 * IT IS A CAP NOT A TRUNCATION POINT, and that is the part with teeth. USER's
 * realname is truncated into this field rather than refused, because a client
 * that has sent NICK and USER is otherwise left half-registered with no way to
 * recover (see handle_user()); SETNAME, which arrives on an already-registered
 * connection, REFUSES rather than truncates, for the reason 3.2 states -- a
 * truncated realname is one the user did not write, and it is reported to every
 * member of every channel they are on as though it were theirs. */
#define CONN_MAX_REALNAME 255

/* The verdict on a candidate realname. Only CONN_REALNAME_OK may be stored, and
 * each other value names WHICH refusal it was rather than only that there was one:
 * the two have different reasons on the wire (one is a limit, the other is a
 * character that must never be logged) and a caller that cannot tell them apart
 * reports a vague message and learns nothing.
 *
 * The function is here, in connection.h, rather than in a command handler, because
 * `conn_t::realname` is a CONNECTION field with two writers -- `USER` and IRCv3's
 * `SETNAME` -- and the whole point of one predicate is that neither writer can
 * drift from the other. See conn_realname_check(). */
typedef enum {
    CONN_REALNAME_OK = 0,
    CONN_REALNAME_TOO_LONG = 1,
    CONN_REALNAME_BAD_BYTE = 2
} conn_realname_verdict_t;

/* May `name` be stored in `conn_t::realname`? CONN_REALNAME_OK for yes.
 *
 * An EMPTY (or NULL) name is admissible: an empty realname is a legal state this
 * node already renders, and a client clearing its own realname has to be able to
 * say so. The two refusals are CONN_REALNAME_TOO_LONG (longer than
 * CONN_MAX_REALNAME, which 005 advertises as NAMELEN) and CONN_REALNAME_BAD_BYTE
 * (a C0 control or DEL -- the log-injection set; CR, LF and NUL cannot arrive
 * because the parser refuses them first, but the rest can).
 *
 * Never truncates and never rewrites. The argument for both refusals is at the
 * definition. */
conn_realname_verdict_t conn_realname_check(const char *name);

/* ---------------------------------------------------------------------------
 * THE LOG-INJECTION SET: ONE BYTE TEST, TWO OPERATIONS, THREE POLICIES
 * ---------------------------------------------------------------------------
 * §9 names this class: "`0x07` rings a recipient's bell and ESC `[` is a CSI
 * sequence a terminal executes". A client-supplied string reaches either this
 * node's own `printf("%s")` or another client's terminal, and in both cases the
 * dangerous bytes are the same ones -- a C0 control (0x00-0x1f) or DEL (0x7f).
 * `message_parse_n()` refuses CR, LF and NUL ahead of every consumer, so what
 * gets through is everything else in that range plus DEL.
 *
 * WHY THE SET IS DEFINED HERE AND NOT AT EACH FIELD. The three fields that reach
 * output with client bytes in them have THREE DIFFERENT CONSUMERS, and the
 * consumer is what decides the policy -- see the table at the bottom of this
 * block. Three policies written three times is three chances to spell the byte
 * test differently, and a fourth field would then have no rule at all. So the
 * byte test exists once, here, and a field chooses only its POLICY.
 *
 * THE TWO OPERATIONS, AND WHY ONLY TWO.
 *
 *   conn_text_bad_count()  MEASURE. How many bytes of this string are in the set.
 *                         Zero means "needs no policy", which is what lets a
 *                         caller make the log line for the common case cost one
 *                         integer rather than a branch. It is also the ONLY place
 *                         the count exists, so a caller reporting "3 bytes were
 *                         dropped" and a caller asking "was this clean" cannot
 *                         disagree about how many there were.
 *
 *   conn_text_strip()     MUTATE. Copy with the set's bytes removed, and report
 *                         how many bytes were KEPT -- the caller derives "how many
 *                         were dropped" from its own strlen() of the input, so the
 *                         measure and the mutation are the same pass.
 *
 * WHAT IS DELIBERATELY NOT HERE, because each is a policy and not a predicate:
 * truncation (3.2 refuses a silently shortened field), escaping (nothing in this
 * node escapes, so a reader would have to un-escape it), and a per-field byte
 * filter. A caller that wants a field REFUSED does not call strip() and then
 * notice an empty string -- it calls conn_text_bad_count() and refuses.
 *
 * THE COST OF THE SET, named once so every caller does not have to name it:
 *
 *   - SPACE is NOT in the set and TAB IS. Space is the single most common byte in
 *     every one of these fields and removing it would mangle ordinary text. TAB
 *     (0x09) is inside the C0 range, so it goes: a TAB in a sentence somebody
 *     typed is a rendering accident, and a terminal is entitled to expand it to
 *     eight columns in a field the sender did not measure.
 *   - BYTES >= 0x80 ARE NOT IN THE SET and never will be. UTF-8 is the ordinary
 *     encoding of a real nickname, a real topic and a real away message, and its
 *     continuation bytes are all >= 0x80. A filter that removed them would break
 *     every non-ASCII user on the node, SILENTLY -- a mangled multi-byte sequence
 *     is indistinguishable from text the sender wrote. That failure is worse than
 *     the one this block exists to close, which is why the set stops at 0x7f.
 *   - Consequently the set cannot be split or shortened by a read boundary: the
 *     stripper sees one already-assembled NUL-terminated parameter, and a
 *     multi-byte sequence the client sent in two TCP writes is one string by then.
 */
size_t conn_text_bad_count(const char *s);

/* Copy `src` into `dst`, dropping every byte the set contains, and
 * NUL-terminate. Returns the number of bytes KEPT.
 *
 * `cap` counts the terminator, as everywhere else in this header. `src` shorter
 * than `cap` minus one is the only case that can arise: every caller has already
 * applied the field's own length bound, and removing bytes can only make the
 * result shorter, so a caller that got here with a value that fitted still fits.
 *
 * WHAT IT COSTS, and what a strip is NOT: it is not truncation, so it never
 * shortens a field that had no bad byte in it, and it never reorders or rewrites
 * anything it keeps. `0x00` cannot arrive (the parser refuses it) and is in the
 * set anyway, so the result is always a well-formed C string.
 *
 * SILENT MUTATION IS ITS OWN DEFECT, which is why nothing in this node strips
 * without also logging that it did. A caller that uses this MUST emit a line
 * saying so; the byte count it returns is what that line reports. */
size_t conn_text_strip(char *dst, size_t cap, const char *src);

/* ---------------------------------------------------------------------------
 * conn_text_strip_relay(): THE SAME STRIP, FOR A FIELD THAT IS *MESSAGE TEXT*
 * ---------------------------------------------------------------------------
 * Strip what can CONTROL A TERMINAL. Keep what is IRC MESSAGE SEMANTICS.
 *
 * This is NOT conn_text_strip() and the difference is load-bearing, so it is a
 * separate function rather than a flag. BOTH now share one UTF-8 walk -- see the
 * block at connection.c's `text_step()` -- and they differ in exactly one thing: the
 * eight mIRC bytes below, which message text keeps and nothing else does. They used
 * to differ in two things: this one, and a narrower understanding of "control" that
 * let a raw `0x80`-`0x9F` byte through BOTH of them. A stored topic holding one was
 * broadcast to every member of its channel, which is a live cross-client injection of
 * the same shape as the nickname one, and it was found by a sweep rather than by
 * reading. The reason two groups of C0 bytes are kept here is that two groups of C0
 * bytes are how IRC has carried meaning for thirty years and every ircd relays them:
 *
 *   | STRIP                                   | KEEP                            |
 *   |-----------------------------------------|---------------------------------|
 *   | 0x1B ESC -- moves the cursor, retitles | 0x01 -- the CTCP DELIMITER       |
 *   |   the window, sets the clipboard, and   | 0x02 bold, 0x0F plain, 0x03     |
 *   |   switches terminal modes               |   colour, 0x11 mono, 0x16       |
 *   | 0x07 BEL -- rings the terminal's bell   |   reverse, 0x1D italic, 0x1F    |
 *   | 0x7F DEL -- invisible in a log, an      |   underline: the mIRC codes     |
 *   |   ordinary glyph in most fonts          |                                 |
 *   | 0xC2 0x80-0x9F -- C1, the 8-bit        |                                 |
 *   |   equivalent of the same escapes        |                                 |
 *
 * WHY THE SPLIT IS WHERE IT IS, group by group, because a reader who does not
 * know this will "simplify" it back into a deny-list and silently break colour.
 *
 *   ESC IS THE INJECTION. It is what a CSI sequence, an OSC title-set, a DECSC
 *     and a clipboard write are made of, so it is the byte that actually lets one
 *     user rewrite another's screen. Stripping it removes the hazard entirely.
 *
 *   BEL IS NOISE, NOT CONTROL -- but it is stripped anyway. It cannot rewrite a
 *     screen, and a client that wants an audible alert has one. It goes because it
 *     is a byte no message text needs and it is the loudest thing a stranger can
 *     put in your terminal.
 *
 *   THE mIRC CODES ARE NOT A TERMINAL HAZARD AND ARE NOT PROSE. They are how IRC
 *     carries colour and emphasis, a client renders them and strips them before
 *     display, and an operator reading a raw log has never seen them. STRIPPING
 *     THEM WOULD BREAK COLOUR ON EVERY CLIENT THAT USES IT -- a functional
 *     regression traded for a cosmetic one, and the reason this function exists
 *     rather than being conn_text_strip().
 *
 *   CTCP IS `0x01`-DELIMITED AND THE DELIMITER IS THE MEANING. `ACTION
 *     waves` is one message because of the two `0x01`s. Remove either and it
 *     stops being a CTCP and becomes text that happens to start with the word
 *     ACTION -- so stripping `0x01` does not sanitise, it CORRUPTS. This is also
 *     why no reader may be placed inside the kept group.
 *
 *   C1 IS STRIPPED AS A CONTROL AND KEPT AS A LETTER, and this is the one
 *     subtlety in the function, because the two are the same BYTES. In UTF-8 a C1
 *     control is `0xC2` followed by `0x80-0x9F` -- and those trailing bytes are also
 *     the continuation bytes of ordinary text:
 *
 *         0xC2 0x9B   CSI          a control      -> both bytes removed
 *         0xD0 0x90   Cyrillic A   a letter       -> both bytes kept
 *         0xCE 0x91   Greek alpha  a letter       -> both bytes kept
 *         0xC3 0xA9   e-acute      a letter       -> both bytes kept
 *         0x9B        CSI on an 8-bit terminal   -> removed
 *
 *     So the walk keeps ONE piece of state -- how many continuation bytes the sequence
 *     in progress still expects -- and asks it BEFORE anything looks at the byte on its
 *     own. A byte in 0x80-0x9F with nothing expecting a continuation is a raw C1 and
 *     is removed; the identical byte inside a valid sequence is somebody's letter and
 *     is kept.
 *
 *     The failure this replaces is worth naming because it is the obvious
 *     implementation. A filter over the RANGE `0x80-0x9F` -- which is what the table
 *     literally says, and what the first version of this function did -- removes every
 *     accented, Greek and Cyrillic character on the node: measured, 8128 code points
 *     below U+3000 have a continuation byte in that range. It is not a filter, it is a
 *     character-set downgrade, and it fails silently on the messages that matter.
 *
 *     BYTES 0xA0 AND ABOVE ARE LEFT ALONE, and that is a decision rather than an
 *     oversight. They are not on the deny list, and `0xC0`/`0xC1` can never lead a
 *     UTF-8 sequence while `0xF5`-`0xFF` lie outside it entirely -- so neither group
 *     can move a cursor. This function removes what is on the list rather than what it
 *     does not recognise.
 *
 * IT RUNS ON AN ASSEMBLED PARAMETER, NOT ON A READ, and that is what makes the
 * read-boundary case a non-case. `message_parse_n()` hands `m->params[]` one
 * complete NUL-terminated parameter per line, so a `0x01` at the end of one recv()
 * and the word after it at the start of the next are already one string by the
 * time anything here runs. A per-read filter would have to carry state across
 * reads to avoid splitting a sequence; this one has nothing to carry because it
 * never sees a fragment. That is the same argument as the UTF-8 case at
 * conn_text_strip() and it is why there is no partial-sequence handling below.
 *
 * `cap` counts the terminator. `src` shorter than `cap` minus one is the only
 * case that can arise: the caller has already applied 3.2's line cap, and this
 * only ever removes bytes. Returns the number of bytes KEPT, which is what lets a
 * caller count the difference without walking the string twice.
 *
 * WHAT IT COSTS, named: a message containing ESC, BEL, DEL or an encoded C1
 * reaches the recipient with those bytes missing, SILENTLY -- the relay path does
 * not announce, and msg_verbs.c says why at the call. A caller that needs to know
 * whether anything was removed compares the return value against strlen() of the
 * input, which is exact because this only ever removes bytes and never reorders
 * them. */
size_t conn_text_strip_relay(char *dst, size_t cap, const char *src);

/* ---------------------------------------------------------------------------
 * conn_text_strip_wire(): A VALUE RENDERED BACK INTO A FIELD ITS SENDER WILL READ
 * ---------------------------------------------------------------------------
 * The STRICT half of the split. Removes every C0 control, DEL, a raw C1
 * (`0x80`-`0x9F` with nothing expecting a continuation) and the encoded C1 pair
 * `0xC2 0x80`-`0xC2 0x9F`. Keeps every VALID multi-byte sequence, for the reason
 * `conn_text_strip_relay()`'s own header gives at length: a filter over the range
 * `0x80`-`0x9F` removes every accented, Greek and Cyrillic character on the node,
 * and it does it silently.
 *
 * IT IS NOT `conn_text_strip_relay()`, and the difference is eight named bytes. A
 * relayed message is IRC message text, where `0x01` is CTCP and `0x02`/`0x03`/
 * `0x0F`/`0x11`/`0x16`/`0x1D`/`0x1F` are mIRC's colour and style codes -- removing
 * them CORRUPTS rather than sanitises. A numeric's parameter is not message text:
 * there is no client rendering formatting codes out of a `401`, so the strict policy
 * is right there and the split is a real difference rather than an accident of
 * which function somebody reached for.
 *
 * WHY IT EXISTS, and the argument is a POLICY rather than an observation: a value
 * echoed back to the client that sent it is still filtered. The argument this tree
 * used for a long time was "there is no second reader", and that argument is
 * WRONG -- a client that writes numerics to a log file, or a bouncer relaying them
 * to a human's terminal, is the second reader, and it is downstream of the client
 * rather than of this node. The decisive argument is simpler and it is
 * INFORMATION: **the echo carries nothing the sender does not already have.** The
 * client sent the value on the line before. So filtering it costs no information at
 * all and removes a real hazard, which makes it a decision rather than a trade-off.
 * See `SECURITY.md`'s control-byte section for the policy in full.
 *
 * IT REMOVES BYTES AND KEEPS THE FIELD. A parameter that becomes empty is still a
 * parameter, and a positional parser still finds it where the RFC says it is -- which
 * is the whole reason this is a strip and not the placeholder substitution the `472`
 * uses. The placeholder is a different case: there the value is a single byte that is
 * structurally not a mode character, so there is nothing to strip and something has
 * to stand in its place.
 *
 * COST: one pass over one value, on a path that runs once per numeric. The caller
 * supplies the destination. */
size_t conn_text_strip_wire(char *dst, size_t cap, const char *src);

/* ---------------------------------------------------------------------------
 * conn_text_display_check(): MAY THIS STRING BE STORED AND RENDERED TO OTHER PEOPLE
 * ---------------------------------------------------------------------------
 * The VERDICT form of the same walk, and it exists for the one field whose value is
 * not merely rendered into a log line but becomes part of every line its owner
 * sends: `conn_t::nick`. A nickname is the SOURCE of everything one client says and
 * the `<client>` field of every numeric it receives, so an unsafe byte in one is a
 * cross-client injection rather than an operator-log one.
 *
 * Three verdicts, and each is a different bug:
 *
 *   CONN_DISPLAY_CONTROL  a C0 control or DEL. `message_parse_n()` already refuses
 *                         CR, LF and NUL, so what arrives is the rest of C0.
 *   CONN_DISPLAY_C1       U+0080-U+009F, whether it arrived as a bare `0x80`-`0x9F`
 *                         byte or encoded as `0xC2 0x80`-`0xC2 0x9F`. U+009B is CSI in
 *                         Unicode, so this is a control sequence whatever the encoding
 *                         says.
 *   CONN_DISPLAY_UTF8     invalid or truncated UTF-8: a bare continuation byte, a
 *                         sequence that stops early, an overlong `0xC0`/`0xC1`, or a
 *                         lead byte outside UTF-8 entirely.
 *
 * AND IT IS ABOUT CODE POINTS, NOT BYTES, which is the whole subtlety. `ā` is
 * `0xC4 0x81`, and `0x81` is inside `0x80`-`0x9F`; a range test on bytes would refuse
 * every accented Latin character on the network and do it silently. What separates
 * the letter from the control is only whether a sequence is in progress, which is
 * state this function shares with the two strippers above rather than reimplementing.
 * So `ā`, `café` and `日本` pass, a bare `0x9F` and a `0xC2 0x9B` do not, and a
 * truncated `0xE6 0x97` does not either.
 *
 * COST: two passes over a string of at most `IRC_MAX_NICK` bytes, on a path that runs
 * once at registration and once per `NICK`. The second pass is the trailing-sequence
 * check and the comment at the call says why it exists rather than folding it into
 * the first. */
typedef enum {
    CONN_DISPLAY_OK = 0,
    CONN_DISPLAY_CONTROL = 1, /* a C0 control or DEL */
    CONN_DISPLAY_C1 = 2,      /* U+0080-U+009F, bare or as 0xC2 0x80..0x9F */
    CONN_DISPLAY_UTF8 = 3     /* invalid or truncated UTF-8 */
} conn_display_verdict_t;

conn_display_verdict_t conn_text_display_check(const char *s);

/* ---------------------------------------------------------------------------
 * conn_text_logsafe(): RENDERING A CLIENT STRING INTO A LOG LINE
 * ---------------------------------------------------------------------------
 * Rule 1's operation, and the one the log-only fields need. Where
 * `conn_text_strip()` MUTATES a field that is relayed to other people, this one
 * decides whether a value may be PRINTED -- and it is a different question, which
 * is why it is a different function rather than a flag on the strip.
 *
 * WRITES `s` INTO `out` VERBATIM when every byte is printable ASCII (0x20-0x7e),
 * and a single `-` otherwise. Returns the number of bytes written, excluding the
 * terminator. A NULL or empty `s` yields `-`.
 *
 * WHY VERBATIM-OR-`-` AND NOT A STRIP. A stripped command word is no longer the
 * command word: `cmd_unknown: command=NICK` printed as `command=NICK` is the whole
 * diagnostic, and printed as `command=NI` (ESC removed from `NICK\x1b`) would name
 * a command the client did not send and would defeat the line's only purpose. So
 * for a log the value is kept when it is KNOWN SAFE and withheld when it is not,
 * with the measurement beside it -- which is also why this is not the same
 * operation as the strip: one is about what a terminal will execute, the other
 * about what an operator can read.
 *
 * WHY 0x20 AND NOT 0x21. Space is printable, it is the byte a nick or a verb can
 * legitimately hold in a log field, and nothing here needs to be a shell argument.
 * The set this screens out is exactly `conn_byte_is_bad()`'s -- C0 and DEL -- plus
 * nothing else, so `conn_text_logsafe()` and `conn_text_bad_count()` can never
 * disagree about a string.
 *
 * `cap` IS THE WIDEST VALUE THIS NODE WILL PRINT, AND A LONGER ONE PRINTS AS `-`.
 * That is not a truncation and it is deliberate: a log line that shortened a value
 * mid-word would name a different thing than the client sent, which is 3.2's rule
 * and is exactly the failure this function exists to prevent. So a value too long
 * for the field is WITHHELD rather than shortened, and the caller's `len=` beside
 * it is what says how long it really was. The cost is that a verb longer than the
 * field prints as `-`; every verb in `commands.c`'s table is under 20 bytes and the
 * field is 64, so no real input reaches it.
 *
 * WHAT IT DOES NOT DO, and the caller must: it writes the value, not the
 * measurement. Every caller pairs it with `strlen()` and
 * `conn_text_bad_count()` on the SAME string, so the line carries
 * `<field>=<value or -> <field>_len=N <field>_bad_bytes=M` and a reader learns
 * both what was said and what was not safe to say. The two counts come from the
 * same predicate as the decision, which is the property that makes the line
 * trustworthy rather than merely quiet.
 *
 * COST: one pass, on a string already in memory, on a path that runs once per
 * command. `cap` must be at least 2. */
/* The widest client-supplied string this node prints VERBATIM into one of its own
 * log lines, and the buffer size every `conn_text_logsafe()` caller derives from it.
 *
 * 64 is `CONN_MAX_BATCH_REF`, which is the widest identifier-shaped value in the
 * tree, and it is chosen for the stack rather than for the wire: every call site is
 * a local in a handler or in the read step, so this is bytes on the stack per frame
 * and nothing else. It is deliberately NOT `IRC_MAX_LINE` -- an 8 KiB buffer in the
 * read step, on a path that runs once per received line, to hold a command word
 * whose longest real value is 12 bytes, is the kind of cost that gets paid on every
 * connection forever to serve an input no client sends.
 *
 * WHAT A LONGER VALUE COSTS, and it is a real cost rather than a rounding error: it
 * prints as `-` instead of as itself. `conn_text_logsafe()` withholds rather than
 * shortens, so nothing on the line names something the client did not send, and
 * every caller prints the value's true `len=` beside the `-`, which is what makes
 * the withholding diagnosable instead of mysterious. */
#define CONN_LOG_FIELD_MAX 64

size_t conn_text_logsafe(char *out, size_t cap, const char *s);

/* ---------------------------------------------------------------------------
 * THE POLICY TABLE, and why three fields do not get three copies of this comment
 * ---------------------------------------------------------------------------
 * The field decides what to DO with a string in this set, and the decision is
 * made by its CONSUMER rather than by the string:
 *
 *   REALNAME   (conn_t::realname)     REFUSED. It is rendered to every member of
 *                                     every channel the user is on and to two
 *                                     peers, so a rewritten value is reported to
 *                                     third parties as though they wrote it.
 *                                     conn_realname_check() above, and both
 *                                     writers run it.
 *   AWAY TEXT  (conn_t::away)         STRIPPED. It is legitimate user content a
 *                                     real client sends, so refusing it breaks a
 *                                     working feature; and a member's terminal is
 *                                     where it lands.
 *
 *   NICKNAME   (conn_t::nick)         REFUSED, and it is the only field on this
 *                                     table with no copy to sanitise. A nickname is
 *                                     not rendered into a log or a message: it IS
 *                                     the source of every line its owner sends and
 *                                     the `<client>` field of every numeric that
 *                                     owner receives, so a byte in one is in front
 *                                     of everything that client says to everybody.
 *                                     `valid_nick()` asks `conn_text_display_check()`,
 *                                     which refuses a C0 control, U+0080-U+009F in
 *                                     either encoding, and invalid or truncated
 *                                     UTF-8 -- and which is about CODE POINTS, not
 *                                     bytes, so `ā` (`0xC4 0x81`) stays.
 *
 *   A VALUE ECHOED BACK TO ITS OWN   FILTERED, and this row is a POLICY rather than
 *     SENDER, in a server numeric   a field. Eleven numerics echoed a client value
 *                                     back to the client that sent it; all eleven are
 *                                     now filtered at `emit_numeric_ex()` in
 *                                     reply.c, the one place a numeric's parameters
 *                                     are rendered. Bytes go, the FIELD stays, and
 *                                     the argument is that **the echo carries no
 *                                     information the sender does not already have**:
 *                                     the client sent the value on the line before,
 *                                     so filtering costs nothing and removes a
 *                                     hazard. The argument this replaces -- "there
 *                                     is no second reader" -- was wrong, because a
 *                                     client that logs numerics, or a bouncer
 *                                     relaying them to a human's terminal, is the
 *                                     second reader.
 *   TOPIC      (chan_t::topic)        STRIPPED. Same answer for the same reason,
 *                                     and worse in exposure: a topic is stored,
 *                                     replayed to every future joiner by 332/333
 *                                     and forwarded to peers, so one write is a
 *                                     long-lived injection rather than an
 *                                     immediate one.
 *   KICK REASON                       STRIPPED. Relayed to every remaining member
 *                                     of the channel; there is no stored copy, so
 *                                     a strip is what "do not relay the client's
 *                                     bytes" means here.
 *   PART REASON                       STRIPPED. Relayed to every member AND put on
 *                                     the link by the forward arm. The one field
 *                                     with no length bound in the RFC or here.
 *   BAN MASK          (MODE +b)       STRIPPED, and ONE copy: the stored mask and
 *                                     the announced mask are the same bytes,
 *                                     because the stored one is what
 *                                     chan_banned() enforces and two different
 *                                     answers to "what is this channel's ban"
 *                                     is the defect this set exists to prevent.
 *   SERVERNAME (USER's <servername>)  NOT LOGGED AT ALL. This node ignores it --
 *                                     the host is observed -- so emitting it buys
 *                                     no diagnostic and creates the whole hazard.
 *                                     commands.c's handle_user() reports its LENGTH
 *                                     and whether it was well-formed instead, and
 *                                     that needs no call into this block at all.
 *
 * A field with a different consumer gets a different entry, and the entry is the
 * argument. What no field may do is print the raw value.
 *
 * ---------------------------------------------------------------------------
 * AND WHAT IS *LOGGED* RATHER THAN STORED -- conn_text_logsafe(), NOT A STRIP
 * ---------------------------------------------------------------------------
 * A client string this node puts only into its own stdout is a different question
 * and gets a different operation. There is no second reader to protect, so there
 * is nothing to protect by rewriting one and a great deal to lose:
 * `cmd_unknown: command=NICK` is the entire diagnostic, and printed with a byte
 * removed it would name a verb the client never sent. So those are MEASURED --
 * verbatim when every byte is printable ASCII, withheld with a length and a
 * bad-byte count when one is not. See conn_text_logsafe()'s own block, and §9.
 *
 * WHAT IS NEITHER, and is named because leaving it out of this table would be the
 * same overstatement this table exists to avoid: PRIVMSG and NOTICE text. It is
 * relayed verbatim, because relaying a message is what the node is for and
 * `0x01` is how CTCP works, so a deny-list would have to become an allow-list and
 * the answer would be a decision about IRC rather than about this class. Peer
 * strings are the other one, behind the FEDERATE secret. */

/* conn_t::account -- the second axis of scoped identity (2.1), added in Phase
 * 10.1.
 *
 * ---------------------------------------------------------------------------
 * TWO AXES, AND WHY 2.1's SCOPED NICK ALONE IS NOT AN IDENTITY
 * ---------------------------------------------------------------------------
 * 2.1 makes identity `nick@server`: two clients on two nodes may both be `bob`,
 * they are distinct, and no policy or lock is needed to say so. That is a
 * correct answer to "how does this node address a user" and it is NOT an answer
 * to "who is this person" -- `bob@irc.a` and `bob@irc.b` are two registry keys,
 * and both are true, and neither of them survives the person reconnecting.
 *
 * An ACCOUNT is the other axis: a name that outlives the socket and is the same
 * on every node that knows about it. It is the difference between an address and
 * an identity, and 2.1's rename-the-loser policy is exactly what the account
 * axis makes survivable -- a user who loses a duplicate nick is still the same
 * account afterwards.
 *
 * ---------------------------------------------------------------------------
 * THE BOUND, DERIVED RATHER THAN PICKED
 * ---------------------------------------------------------------------------
 * The field is 64 wide, so CONN_MAX_ACCOUNT is 63, and 63 is ACCOUNT_MAX_NAME in
 * account_store.h. The derivation runs one way only: an account on a connection
 * is written by exactly one function (account_set(), in core/account.h), whose
 * only source of a name is the authcid of a completed SASL exchange, and
 * SASL_MAX_AUTHCID is 63 because conn_t::nick's bound minus one is. So 63 is the
 * LONGEST VALUE THAT CAN REACH THIS FIELD AT ALL. A wider field would be bytes
 * nothing could ever fill and a narrower one would refuse a client that
 * successfully authenticated -- which would be worse than the truncation the
 * design refuses everywhere else, because it would tell somebody their account
 * does not exist.
 *
 * ---------------------------------------------------------------------------
 * `logged_in` IS NOT DERIVABLE FROM THE NAME AND IS NOT REDUNDANT WITH IT
 * ---------------------------------------------------------------------------
 * Empty means "not logged in", exactly as `nick[0]` means "no nickname chosen
 * yet" and `away[0]` means "not away" -- the idiom this struct already uses so
 * that a field and a fact about it cannot drift apart. `logged_in` is
 * nevertheless a separate field, and the reason is which question each answers:
 * the NAME is a claim the connection makes about itself, and the FLAG is a
 * verification this node performed. core/account.h's account_logged_in() is the
 * conjunction of the two, which is what makes "an empty account" and "a real
 * account named the empty string" not merely equal but UNREPRESENTABLE: there is
 * no sequence of bytes that leaves this struct meaning "logged in as nothing".
 */
#define CONN_MAX_ACCOUNT 63

/* conn_t::away, the AWAY message. Empty means "not away", the same idiom
 * nick[0]/user[0] already use for "this fact is not established yet", so no
 * separate flag is needed and the two can never disagree.
 *
 * THE BOUND, AND WHY IT IS 255
 * -----------------------------
 * Three independent reasons converge on the same number, which is why it is
 * derived rather than picked:
 *
 *   1. RFC 1459 2.4.2 caps the AWAY message at 255 characters. 255 is the RFC's
 *      number, not this project's.
 *   2. 301 RPL_AWAY carries it as a numeric's TRAILING TEXT, and reply() renders
 *      that into REPLY_TEXT_MAX (512). At 255 it fits with room to spare, so an
 *      away message this node accepted is always an away message 301 can report.
 *      A larger bound would make "accepted" and "reportable" different sets.
 *   3. It equals CHAN_MAX_TOPIC (255), the other client-supplied free-text field
 *      this node stores, so there is ONE bound for "a sentence a user typed",
 *      not two that differ for no stated reason.
 *
 * IT IS A CAP, NOT A TRUNCATION POINT
 * ----------------------------------
 * An AWAY message longer than this is REFUSED (417), and the previous away state
 * is left exactly as it was. Truncating would store a message the user did not
 * write and then report the shortened one in 301 as if it were theirs -- which
 * is the same "never silently truncate a parameter" rule 3.2 states and Phase 4
 * applied to a topic and a mode string.
 *
 * ---------------------------------------------------------------------------
 * PHASE 6 NEEDS THIS FIELD: SECTION 4.3's SBURST
 * ---------------------------------------------------------------------------
 * 4.3: "SBURST is the resync verb. On every link establishment the initiator
 * sends full state: ... all nicks: user / host / modes / away". So `away` is
 * NOT a Phase 5 convenience -- it is a field with no other producer, and
 * whoever writes SBURST must populate it. It is here, in the phase that first
 * has a use for it, so that SBURST is a wire format rather than a struct change.
 *
 * The size is part of that contract: 4.3 sends "all nicks", so the away message
 * is a per-nick cost in a burst whose size is O(nicks). A bound of 255 keeps
 * that burst O(nicks) with a KNOWN ceiling; an unbounded message would make one
 * client's AWAY able to inflate a resync for the whole node. */
#define CONN_MAX_AWAY 255

/* conn_fill() outcomes. EOF is a distinct value from a hard error because they
 * are different events on the wire and a caller that reports close reasons has
 * to be able to tell them apart without inspecting errno, which may be stale. */
#define CONN_FILL_EOF 1

/* The connection. Layout is 2.1 (identity) plus 3.3 (buffers), in that order.
 *
 * The three fields Phase 5 adds sit inside the identity block, beside the
 * fields they are derived from, and each earns its place by being REPORTED on
 * the wire -- none of them is bookkeeping a client cannot see:
 *
 *   away        4.3's SBURST must send it for every nick, and 301/352 report
 *               it. See CONN_MAX_AWAY above, which is where the bound and the
 *               over-long policy are argued.
 *   signon_at   317 RPL_WHOISIDLE carries a signon time. There is no other
 *               value on the node that could fill it, and a numeric that lies
 *               about what it is is what Phase 4 refused to do for 329 ("reusing
 *               topic_when for it would be a numeric that lies about what it
 *               is"). Borrowing the node's boot time would be the same lie one
 *               level up: it is when the SERVER started, not when the user
 *               connected.
 *   last_active 317's other half. It is updated in conn_fill(), which is the
 *               only place that observes the connection doing anything, so the
 *               idle time it yields is measured from real socket activity rather
 *               than from the last command that happened to be dispatched.
 *
 * All three are set or updated inside the connection layer, and none of them is
 * something Phase 6 has to add. */
typedef struct conn {
    int         fd;
    int         kind;              /* CONN_CLIENT | CONN_SERVER */
    char       *peer_name;         /* server name, CONN_SERVER only; Phase 6 */
    char        nick[64];          /* local nick, pre-@ */
    char        user[64];
    char        host[128];
    char        realname[256];
    int         state;             /* CONN_REG_* | CONN_CLOSING */
    char        away[CONN_MAX_AWAY + 1];
    time_t      signon_at;         /* accept time; 317's <signon time> */
    time_t      last_active;       /* last byte read; 317's <idle> */
    unsigned    caps;              /* negotiated capabilities; core/cap.h bits */
    int         cap_negotiating;   /* CAP LS/REQ in flight; CAP END clears it */
    int         sasl;              /* sasl_state_t; FAILED is terminal */
    /* Phase 10.1: the account identity, which is what `c->sasl` was missing.
     * An ADDITION and not a rearrangement, like the three fields above, and for
     * the same reason: it is a fact another module has to ask about and one
     * place has to own. `logged_in` is written only by account_set() in
     * core/account.c and cleared only by account_clear(); a caller reads
     * account_logged_in()/account_name() rather than these fields, so that the
     * two can never be read apart. See the CONN_MAX_ACCOUNT block above. */
    char        account[CONN_MAX_ACCOUNT + 1];
    int         logged_in;
    struct chan **chans;           /* channels joined; Phase 4 */
    size_t      nchans;
    size_t      cap;
    /* Phase 10.12: IRCv3 `batch`, the client-facing half. FOUR fields, and each
     * answers one question; the batch capability's whole protocol surface is the
     * difference between them.
     *
     *   batch_ref      the reference tag of the batch this client has OPEN, or ""
     *                  empty for none. Non-empty means "every line this node emits
     *                  to this connection is inside that batch", which is what a
     *                  client asked for by sending `BATCH +ref <type>`.
     *   batch_type     the type that batch was opened with. Logged, never branched
     *                  on -- see CONN_MAX_BATCH_TYPE.
     *   batch_once     a ONE-SHOT reference from a `+<ref>` tag on a single
     *                  command: the NEXT line emitted to this connection carries
     *                  `batch=<ref>` and the reference is consumed. This is the form
     *                  the modern message-tag grammar preserves (batch.c's header has
     *                  the parser probe that established it) and it is what lets a
     *                  client group the response to ONE command without holding a
     *                  batch open.
     *
     * THERE IS NO `@<ref>` FIELD, and its absence is a FINDING rather than an
     * oversight. The retired `reference-tags` specification defined `@<ref>` as "send
     * the response nowhere", but on the wire `@` is the TAG-BLOCK MARKER: this node's
     * parser consumes exactly one leading `@` and keeps the rest as keys, so
     * `@ref WHOIS bob` parses to the valueless tag `ref` and `@@ref WHOIS bob` is
     * **refused outright** by `message_parse_n()`. Both were checked, not reasoned
     * about -- see batch.c. Making the form work would mean changing what the framing
     * layer keeps, which 3.2 owns and which every peer line depends on, so the drop
     * form is not implemented and the reason is written where a future editor reads.
     *
     * ALL THREE ARE FIXED-SIZE FIELDS IN A CALLOC'D STRUCT. That is deliberate and it
     * is why there is no teardown arm for any of them: `conn_new()` zeroes the
     * struct and `conn_free()` frees it whole, so "a batch reference cannot
     * outlive its connection" is a property of the allocation rather than of a
     * cache somebody has to remember to empty. The same paragraph applies to the
     * `label` field Phase 10.13 adds beside them. */
    /* Phase 10.13: IRCv3 `labeled-response`. FOUR fields, and they are a small state
     * machine rather than a flag, because the specification's requirement is not "echo
     * the tag" but "the tag appears in EXACTLY ONE LOGICAL MESSAGE" -- and on this node
     * a response is frequently several lines, which the specification says MUST then be
     * grouped in a batch whose START carries the label.
     *
     *   label            the client's `label=` value, COPIED, for the command in flight.
     *                   The copy is the whole of the lifetime argument: `m->tags` points
     *                   into the parser's heap and the command's response outlives the
     *                   message, so a stored POINTER is a use-after-free. It is a
     *                   fixed-size field rather than a pointer for the second half of
     *                   the same reason -- nothing to free, nothing to leak.
     *   label_live       1 while a label is owed a response. Cleared at the end of the
     *                   command by `label_finish_command()`.
     *   label_batch      the reference tag of the `labeled-response` batch this node
     *                   minted for this command, or empty.
     *   label_batch_open 1 once that batch has been STARTED on the wire. The distinction
     *                   matters: a command that produced ONE line must not emit an empty
     *                   batch, and the only way to know the response was one line is to
     *                   discover it by emitting the first one.
     *
     * ALL FOUR ARE FIXED-SIZE FIELDS IN A CALLOC'D STRUCT, like batch's, so there is no
     * teardown arm for any of them: `conn_new()` zeroes the struct and `conn_free()`
     * frees it whole. */
    char        label[CONN_MAX_LABEL + 1];
    int         label_live;
    char        label_batch[CONN_MAX_LABEL + 1];
    int         label_batch_open;
    /* 1 while the command in flight is a message the client ADDRESSED TO ITSELF, which
     * is what `labeled-response` means by "a client sends a message to itself" -- and
     * which is NOT the same as "a line whose source is this client", which is true of
     * every echo-message copy this node makes. The first version of label.c decided it
     * by comparing the line's PREFIX against the destination's own hostmask, and that
     * withheld the label from the echo of a channel message as well -- so a labelled
     * `PRIVMSG #chan` got an unlabelled echo and an `ACK`, which is the opposite of what
     * the specification asks for and was caught by `test_labeled_response.c` case 7.
     *
     * IT IS SET BY `msg_verbs.c` AND BY NOTHING ELSE, because the reply path cannot know
     * a message's target: `emit_built_ex()` has the line and the destination and no
     * third thing. */
    int         label_self;
    unsigned    label_seq;          /* per-connection counter; see label.c */
    char        batch_ref[CONN_MAX_BATCH_REF + 1];
    char        batch_type[CONN_MAX_BATCH_TYPE + 1];
    char        batch_once[CONN_MAX_BATCH_REF + 1];
    int         batch_suppress;
    /* ------------------------------------------------------------------------
     * PHASE 12: THE READINESS INTENT, and it is the first thing on this struct
     * that POLL LOOP MAY NOT DERIVE FOR ITSELF.
     * ------------------------------------------------------------------------
     * Until this phase the loop built a connection's event mask from DATA --
     * POLLIN always, plus POLLOUT when there were unsent bytes -- and that was
     * correct, because for a plaintext socket the two facts are the same fact.
     *
     * THEY ARE NOT THE SAME FACT ONCE THE TRANSPORT CAN GO WANTS-WRITING-WITHOUT-
     * HAVING-BYTES. A nonblocking TLS handshake writes the server's flight
     * (ServerHello, Certificate, ...) before this node has a single application
     * byte to send, and then blocks waiting for the client's flight. At that
     * instant the write queue is EMPTY -- so the old derivation asks poll() for
     * POLLIN only -- and the handshake can never advance, because the only thing
     * that would wake the loop is a write that the loop is not asking for. The
     * connection hangs at 100% CPU-free, indefinitely, with no error anywhere.
     *
     * WHY POLL REVENTS CANNOT SUBSTITUTE FOR THIS, and it is worth being exact
     * because the obvious alternative is to look at what poll() REPORTED and
     * decide then:
     *
     *   revents is a report about the SOCKET, and the question the transport
     *   must answer is about the PROTOCOL STATE. SSL_read() returning
     *   SSL_ERROR_WANT_WRITE means "the handshake is parked awaiting a write",
     *   and the socket at that instant may be entirely uninteresting -- no bytes
     *   queued in either direction. POLLIN | POLLOUT would report nothing, so
     *   poll() would return a zero count and the loop would go straight back to
     *   sleep having learned nothing. The information exists ONLY inside
     *   OpenSSL, and the only way to get it out is to ask, which means asking at
     *   the moment the call is made -- which is what the fields below are for.
     *
     * SO THESE ARE WRITTEN BY THE I/O PATH AND READ BY THE LOOP, and that
     * direction is the whole contract: whoever last touched the socket says what
     * it wants next. On a plaintext connection they are 1 and "there are unsent
     * bytes", which is exactly what the loop computed for itself, so the
     * plaintext poll set is byte-for-byte what it has always been -- a property
     * tests/integration/test_readiness_intent.c asserts and the rest of the suite
     * proves.
     *
     * THE COST, in the two fields and one predicate: two ints per connection
     * (eight bytes on a conn_t that is already several hundred), set in three
     * places, read in one. The alternative -- a transport type test inside the
     * loop -- was rejected because it would put the transport's knowledge in the
     * loop, which is the coupling Phase 12 exists to remove.
     *
     * A CONNECTION WITH NEITHER SET IS LEFT OUT OF THE POLL SET ENTIRELY, and
     * that is correct rather than a liveness bug: poll() reports nothing for an
     * entry whose mask is zero, so including it would only spend a slot. It is
     * reachable only for a transport that has said it wants nothing, and the
     * plaintext transport never says it (want_read is always 1). */
    int         want_read;         /* poll() must include POLLIN */
    int         want_write;        /* poll() must include POLLOUT */
    /* PHASE 12: THE TRANSPORT this connection's bytes go through. `t_ops` is
     * NULL until conn_new() installs the plaintext ops, and `t_ctx` is the
     * transport's own state -- NULL for plaintext, the SSL* for TLS. The ops
     * POINTER is a vtable rather than a boolean so that "is this connection
     * encrypted" is not a second thing a reader has to keep in step with the
     * dispatch: it is asked, through transport_is_tls(), by every module that
     * needs the answer. */
    const struct transport_ops *t_ops;
    void       *t_ctx;
    struct server *owner;        /* the node this conn is registered with */
    /* 1 once this connection's transport is TLS, and 1 while a STARTTLS has been
     * agreed and the 670 is queued but the handshake has not been started. The
     * second is the ordering guarantee that the upgrade's confirmation is sent in
     * the CLEAR and the handshake begins only after it has been written: see
     * conn_pump(). */
    int         tls_active;
    int         starttls_pending;
    /* 1 once this connection's TLS HANDSHAKE has been checked for the things that
     * can only be checked once it is finished -- currently the peer's revocation
     * status, in tls_openssl.c.
     *
     * IT IS A FIELD AND NOT A QUESTION ABOUT the SSL because there is nowhere else
     * to keep it: the backend is reached through transport_send()/transport_recv(),
     * which hand back three outcomes and nothing else, so a "have I checked yet"
     * answer has to live on the connection rather than in the transport's state.
     *
     * WHY IT IS NEEDED AT ALL: a handshake can complete on the send path or on the
     * read path depending on which flight arrived, and both arms must ask -- so
     * without a latch the check would run twice on some connections and print two
     * verdicts, and a verdict printed twice is a diagnostic nobody reads. It is
     * set BEFORE the check runs, so a refusal cannot be reached twice either.
     *
     * THE COST IS ONE INT on a struct that already carries several hundred, and it
     * is READ by one backend and by nothing else: on a plaintext connection it is
     * 0 for ever and no code path consults it. */
    int         tls_checked;
    /* 1 once this connection has carried a CREDENTIAL in the clear: a PASS value
     * or an AUTHENTICATE payload, offered or not.
     *
     * IT IS A FIELD RATHER THAN A QUESTION ABOUT c->sasl, and the reason is that
     * `c->sasl != SASL_ABORTED` does NOT answer it. An AUTHENTICATE that was
     * REFUSED -- a mechanism this node does not implement, a payload that would
     * not decode, a credential with no store behind it -- has still put a
     * credential on the wire, and a STARTTLS after it is exactly the downgrade
     * the field exists to prevent. `c->sasl` records whether the exchange reached
     * a verdict; this records whether there was one to reach.
     *
     * TWO WRITERS, handle_pass() and handle_authenticate(), and they are set at
     * the TOP of each handler -- before any parsing, before any refusal -- because
     * the interesting case is precisely the one that failed. It is written in two
     * places rather than through a helper because both are one line and a helper
     * called from two handlers would be a function whose only job is to make the
     * rule less visible at the sites where the rule matters.
     *
     * IT GRANTS NOTHING and revokes nothing; it is a fact about the connection's
     * history and nothing reads it except STARTTLS's refusal. */
    int         credential_seen;
    char       *rbuf;              /* read buffer */
    size_t      rlen;
    size_t      rcap;
    char       *wbuf;              /* write queue; wbuf[woff..wlen) is unsent */
    size_t      woff;
    size_t      wlen;
    size_t      wcap;
} conn_t;

/* Allocate a zeroed connection for `fd` (state CONN_REG_PASS, kind `kind`,
 * no buffers). Returns NULL if allocation fails. conn_free() is the inverse
 * and is safe on NULL. */
conn_t *conn_new(int fd, int kind);

/* Release the buffers and the peer_name/chans arrays, then the struct. Does
 * NOT close the fd: closing is the reaper's single responsibility (3.4). Safe
 * on NULL. */
void conn_free(conn_t *c);

/* Read whatever is available into rbuf. Returns 0 when the socket has been
 * drained to EAGAIN, CONN_FILL_EOF when the peer closed its half, and -1 on a
 * hard read error or a failed buffer growth; in the latter two cases the
 * caller must mark the connection CLOSING. EINTR is retried internally and
 * EAGAIN is not an error.
 *
 * The buffer is grown geometrically but never past CONN_RBUF_MAX, so a peer
 * that never sends a terminator cannot make this grow without bound. */
int conn_fill(conn_t *c);

/* Pull the next complete line out of rbuf and COPY it into `dst`.
 *
 * Returns 1 on success -- the line is in `dst`, `*len` is its length -- 0 when
 * more bytes are needed (the bytes stay in rbuf, untouched), and -1 when rbuf
 * holds IRC_MAX_LINE bytes with no terminator in them, which is a framing error
 * no future byte can repair. Also -1 if the line does not fit in `dstcap`,
 * which cannot happen when `dstcap` is IRC_MAX_LINE or more.
 *
 * WHY THE CALLER SUPPLIES THE BUFFER
 * ----------------------------------
 * An earlier version of this returned a `char **` pointing into rbuf and then
 * slid the unread remainder to the front of that same buffer to reclaim the
 * space -- which destroys the very bytes the caller was just handed, inside the
 * same call. The returned line was already garbage on return, and the only way
 * to use it was to copy it out by some other route, so the "optimisation" was
 * a trap with a pointer in it.
 *
 * Copying into the caller's buffer makes the lifetime obvious and owned by
 * whoever can see it: `dst` is valid until the caller reuses it, and nothing
 * the connection does can invalidate it underneath. The cost is one memcpy of at
 * most IRC_MAX_LINE bytes per line, which is the same copy the parser is about
 * to make anyway. The struct keeps the shape 3.3 specifies; no scratch field
 * was added for this.
 *
 * The line is copied INCLUDING its terminator, which is why the caller must
 * hand the pair to message_parse_n() rather than message_parse(): the framing
 * layer holds a length, and only the counted entry point rejects an embedded
 * NUL (3.2).
 *
 * Terminator handling: a line ends at the first LF. A CR immediately before it
 * belongs to the line, so the CRLF that RFC 1459 2.3 mandates is passed through
 * to the parser intact rather than being stripped here. A bare LF is also
 * accepted as a terminator because message_parse_n() accepts it and the parser
 * -- not the framing layer -- is where the line grammar is enforced. A CR
 * anywhere else stays inside the line and is rejected by the parser. */
int conn_next_line(conn_t *c, char *dst, size_t dstcap, size_t *len);

/* Append `len` bytes to the write queue. Returns 0 on success, -1 when the
 * append would push the unsent tail past CONN_WQ_MAX, in which case nothing
 * is buffered and nothing is written: the caller marks the connection CLOSING
 * and records the overflow. This function never blocks and never closes.
 *
 * PHASE 12: RAISES `want_write`, and this is the ONLY writer that may. The
 * transport publishes the intent after every read and every write, and those
 * two moments are the only places a transport's own opinion can be mistaken for
 * a fact; a queue that grew after the last publish is invisible to it. So the
 * one thing that can create unsent bytes raises the intent itself, and the
 * loop's next poll set is built after this returns. Without this arm, a reply
 * queued by a handler would sit in the write queue until the peer happened to
 * send something -- which on an idle client is never. */
int conn_queue(conn_t *c, const char *data, size_t len);

/* Push as much of the write queue as the socket will take. Returns 0 when the
 * queue is empty or the socket is full, -1 on a fatal write error (EPIPE,
 * ECONNRESET, EBADF), in which case the caller must mark the connection
 * CLOSING. A short write is NOT an error and is NOT a failure: the retained
 * woff is advanced by whatever was sent and the rest is drained on a later
 * poll iteration. This function never closes the fd.
 *
 * PHASE 12: IT ALSO MAKES ONE UNCONDITIONAL PASS OVER THE TRANSPORT WITH AN
 * EMPTY QUEUE, and that is what lets a handshake finish. A TLS handshake writes
 * the server's flight before this node has any application data at all, so a
 * pump that only called the transport when the queue was non-empty could never
 * start one -- and readiness intent (see conn_t::want_read) is what lets poll()
 * then wake the loop for a connection that still has nothing to send. On a
 * plaintext connection the empty pass is a call the plaintext transport answers
 * without touching the descriptor, so the ordinary path is unchanged. */
int conn_pump(conn_t *c);

/* Publish this connection's readiness intent: poll() must include POLLIN when
 * `read`, POLLOUT when `write`.
 *
 * IT IS THE INTERFACE, NOT A HELPER. The transport implementations call it and
 * nothing else may, which is what makes "the loop reads an intent and the
 * transport writes it" a structural property rather than a convention: there is
 * no second function that sets either field. conn_queue() is the single
 * documented exception, for the reason its own comment gives.
 *
 * A value of 0 for `read` is NOT "keep whatever was there": it clears it. A
 * transport that wants neither leaves the connection out of the poll set, and
 * that is the state a handshake parked on SSL_ERROR_WANT_WRITE-with-nothing-to-
 * write must NOT be in -- the whole point of the field is that the two states
 * are distinguishable. */
void conn_want(conn_t *c, int read, int write);

/* Bytes still unsent: wlen - woff. */
size_t conn_write_pending(const conn_t *c);

/* Mark the connection CLOSING. Idempotent, and deliberately the only state
 * transition a send or read path is allowed to make. */
void conn_mark_closing(conn_t *c);

/* Write this connection's client prefix -- "<nick>!<user>@<host>" -- into `out`
 * and return the byte count written, excluding the NUL. Returns 0 if `out` is
 * too small or `c` is NULL, so a caller that cannot render the prefix must
 * treat the line as unrenderable rather than emit a truncated one.
 *
 * WHY IT LIVES HERE AND NOT IN A HANDLER
 * --------------------------------------
 * RFC 2812 3.3.1 requires the JOIN/PART/KICK/TOPIC/MODE echoes to be prefixed
 * with the ACTING USER's hostmask, and that prefix is a rendering of identity
 * fields, so it belongs beside the fields. It is also the second thing a
 * channel broadcast needs after the parameter list, which is why it is a
 * function rather than a struct field: the design's 2.1 is explicit that
 * conn_t's shape is final as of Phase 2.
 *
 * It is NOT 2.1's qualify() ("nick@server"). That is the internal identity
 * form, it is needed to address a user on another server, and nothing in Phase 4
 * addresses one -- there are no peers. qualify() belongs to the phase that
 * first has a remote user to name, and writing it now would be a function with
 * no caller. */
size_t conn_hostmask(const conn_t *c, char *out, size_t cap);

#endif /* IRC_CORE_CONNECTION_H */
