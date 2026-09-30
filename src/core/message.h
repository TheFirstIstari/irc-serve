/* message.h -- the IRC syntax seam: tokenizer, tag block, and nick rule.
 *
 * Authority: docs/SERVER_DESIGN.md sections 2.1 (identity), 2.4 (loop
 * prevention and dedup), 3.2 (message representation), 5 (the nick charset
 * rule that is missing) and 7/Phase 1 (the acceptance criteria).
 *
 * This is a federation seam, not a convenience. It is deliberately first
 * because retrofitting it is expensive: nothing else in the project can use
 * it yet, but every later phase inherits its parse rules, its tag format and
 * its nick rule.
 *
 * ---------------------------------------------------------------------------
 * MEMORY MODEL -- one allocation, documented contract
 * ---------------------------------------------------------------------------
 * message_parse() performs EXACTLY ONE heap allocation. `tags`, `prefix`,
 * `command`, `params[]` and `raw` are all pointers into that single buffer
 * (`buf`); there is nothing to free but `buf`.
 *
 * The buffer holds two regions: the received line, verbatim, at the front
 * (that is what `raw` points at), and the parsed fields packed after it. The
 * two are kept separate on purpose -- parsing cannot punch NULs through the
 * separators of the copy `raw` points at, so `raw` really is the original
 * line and stays readable after a parse.
 *
 * Contract on rejection: message_parse() ZEROES *out before it does anything
 * else and only publishes the finished message into *out on success, so
 * every rejection path leaves *out in the all-zero state. The consequence the
 * caller can rely on:
 *
 *     message_t m;
 *     if (message_parse(line, &m) != 0) { reject(); }   // nothing to free
 *     ...
 *     message_free(&m);                                  // always safe
 *
 * message_free() is idempotent: it frees buf (free(NULL) is a no-op) and
 * zeroes every field, so it is safe on a zeroed struct, safe on a NULL
 * pointer, and safe to call twice. There is no partially built message that
 * a caller can observe, and therefore no half-built message to free.
 *
 * The other half of the contract, which is easy to get wrong: message_parse()
 * and message_build() ZERO *out, they do not free what was already in it. A
 * message_t that already holds a parsed or built message must be released with
 * message_free() before being handed to either one, or its buffer leaks. This
 * is not a corner case -- parse-then-parse into the same variable is the
 * natural way to write a loop, so the safe shape is one message_t per live
 * message.
 *
 * ---------------------------------------------------------------------------
 * WHY message_format NEVER ECHOES raw
 * ---------------------------------------------------------------------------
 * The formatter always re-renders the line from the message's own fields.
 * It never copies `raw` back out. Echoing `raw` would relay whatever tag
 * block arrived on the wire -- including the irc-serve-* internal tags of
 * 2.4, which MUST be stripped before delivery to clients -- and would
 * additionally defeat any field rewrite the relay path performs (stamp the
 * origin, bump the hop count). The previous design draft contradicted itself
 * on exactly this point; this header is the resolution.
 *
 * Also enforced by the formatter, and testable: no byte of CR or LF can ever
 * leave message_format(), no matter what a caller hand-built into the
 * struct. That is the line-injection defence, and it lives at the seam.
 */
#ifndef IRC_CORE_MESSAGE_H
#define IRC_CORE_MESSAGE_H

#include <stddef.h>
#include <stdint.h>

/* Maximum number of parameters, per the struct definition in 3.2. The 15th
 * parameter absorbs the remainder of the line verbatim (3.2). */
#define IRC_MAX_PARAMS 15

/* On-wire line cap, counted INCLUDING the trailing CRLF (3.2). RFC 1459 2.3
 * states a 512 floor, but irssi and weechat send 8192 and ratbox uses 8192
 * server-to-server, so a 512 cap truncates honest clients. 3.2 fixes the
 * rule here because this is the place it is enforced. */
#define IRC_MAX_LINE 8192

/* Maximum nickname length in bytes, excluding the terminator.
 *
 * Source: conn_t::nick is char[64] in 2.1, so a nickname that must fit the
 * registry entry cannot exceed 63 bytes. The design specifies no shorter cap
 * (RFC 1459 says "almost any character", and common deployments use 9-30),
 * so the struct size is the bound rather than an invented number. */
#define IRC_MAX_NICK 63

/* Maximum server-name length in bytes, excluding the terminator. Source:
 * server_link_t::name is char[64] in 2.3. */
#define IRC_MAX_SERVER_NAME 63

/* Worst-case byte cost of the 2.4 internal tag block, derived from the value
 * bounds defined for irc_serve_tags_t below. Left column is the tag block as
 * it goes on the wire, right column is what that row costs:
 *
 *   on the wire                          bytes
 *   ---------------------------------   -----
 *   "@"                                    1   block marker
 *   "irc-serve-origin="                   17   16 name + '='
 *   ";" "irc-serve-epoch="                17   1 + 15 name + '='
 *   ";" "irc-serve-id="                   14   1 + 12 name + '='
 *   ";" "irc-serve-hops="                 16   1 + 14 name + '='
 *   " "  (block/prefix separator)          1
 *                                        ---
 *                                         66   fixed
 *
 *   origin   <= IRC_MAX_SERVER_NAME        63
 *   epoch    <= 20 digits (UINT64_MAX)     20
 *   id       <= 20 digits (UINT64_MAX)     20
 *   hops     <= 10 digits (UINT32_MAX)     10
 *                                        ---
 *                                        113   values
 *                                        ===
 *   worst case                             179
 *
 * Cross-check on one line:
 *   1 + 17 + 17 + 14 + 16 + 1  +  63 + 20 + 20 + 10  =  66 + 113  =  179
 *
 * 3.2 states this as "~96". That estimate is too small to be safe -- the
 * four tag names with their '=' are 61 bytes on their own, and a 63-byte
 * server name plus three max-width numerics are 113 more. The measured worst
 * case is used instead. Note that 179 is the EXACT worst case, not a padded
 * one: the largest legal block measures 177 and the '@' plus the one
 * separating space are the remaining 2, so there is no slack. That is
 * deliberate rather than lucky. The cap has to equal the largest LEGAL tag set
 * rather than an average or a rounded-up guess, because a relayed line that
 * overruns the on-wire limit is exactly the failure this constant exists to
 * prevent, and slack would only hide a wrong derivation until the day it did
 * not. A ~500-byte client PRIVMSG to a remote channel (the case 3.2 cares
 * about) stays legal by a wide margin either way.
 *
 * test_message_format.c formats a maximally-long legal block and asserts the
 * measured overhead EQUALS this constant, so raising a value bound without
 * re-deriving the constant fails the suite instead of the network.
 */
#define IRC_MAX_TAG_OVERHEAD 179

/* Client-facing cap for a relayed line (3.2, "Relay truncation policy").
 *
 * A relayed line is a client line PLUS the internal tag block, so a line that
 * is legal inbound can still be illegal outbound. The client-facing cap is
 * therefore the on-wire cap minus the worst-case tag overhead.
 *
 * A line still over this cap is DROPPED WITH A CLIENT-SIDE NOTICE, never
 * silently truncated mid-parameter: truncating a PRIVMSG body would deliver
 * a message the sender never wrote. Phase 1 owns the constant and the parse
 * rejection above it. The drop-with-notice itself is Phase 6 relay work and
 * is NOT implemented yet -- do not read this constant as meaning it is. */
#define IRC_MAX_RELAY_LINE (IRC_MAX_LINE - IRC_MAX_TAG_OVERHEAD) /* 8013 */

/* The parsed message.
 *
 * Field semantics, precisely:
 *   tags     -- the tag block WITHOUT the leading '@', NUL-terminated, or
 *               NULL when the message carried no tags. Byte-for-byte the
 *               block as received, so the separator structure stays walkable;
 *               escaping is undone on lookup (message_tag_get), not here.
 *               An empty block is rejected by the parser.
 *   prefix   -- the source after ':', or NULL when absent. A leading ':'
 *               prefix is accepted, which is what makes a peer message parse
 *               identically to a local one (3.2).
 *   command  -- uppercased, never NULL on a successful parse.
 *   params   -- nparams interior pointers, each NUL-terminated. params[0] is
 *               NOT colonned: a leading ':' on the wire is the trailing-param
 *               marker and is stripped by the parser.
 *   raw      -- the line exactly as handed to message_parse(), including any
 *               trailing terminator, NUL-terminated and stored verbatim, so
 *               parsing does not disturb it. This is a SECOND region of the
 *               one allocation, not the same bytes as the fields: the fields
 *               are packed in their own region after it, which is what lets
 *               `raw` stay the original line. NUL-terminating the fields
 *               IN PLACE inside the line is the natural-looking approach and
 *               it destroys `raw`. Informational only; message_format() must
 *               never copy it (see the top of this file). After
 *               message_build() there is no received line, and raw points at
 *               the start of the buffer instead.
 *   buf      -- the one heap allocation. Owned by the struct; free it only
 *               through message_free().
 */
typedef struct {
    char  *tags;
    char  *prefix;
    char  *command;
    char  *params[IRC_MAX_PARAMS];
    int    nparams;
    const char *raw;
    char  *buf;
} message_t;

/* A tag key/value pair, for authoring a tag block. `key` must be non-NULL and
 * non-empty; `value` may be NULL, which means the empty value. `value` is
 * written ESCAPED, so this is the serialize direction of IRCv3 tag escaping
 * (message_tags_format). */
typedef struct {
    const char *key;
    const char *value;
} message_tag_t;

/* ---------------------------------------------------------------------------
 * THE FOUR ENTRY POINTS -- which is which, so they are not read as redundant
 * ---------------------------------------------------------------------------
 * There are three ways a message_t comes into existence and one way it goes
 * back out. They are not alternatives to each other; pick by direction:
 *
 *   message_parse_n()   inbound, with a byte count   -- the framing entry
 *   message_parse()     inbound, from a C string     -- a convenience wrapper
 *   message_build()     outbound, from parts         -- the constructor
 *   message_format()    outbound, to a wire line      -- the serializer
 *
 * The two parse functions are the same parser with a different input, and the
 * difference is load-bearing rather than stylistic. A NUL terminates a C
 * string, so message_parse() is structurally BLIND to bytes after the first
 * NUL and cannot reject an embedded one. The framing layer of 3.3 knows the
 * frame length -- that is what it read -- so it uses message_parse_n() and
 * gets the embedded-NUL rejection that is a stated hard requirement. Code that
 * genuinely holds a NUL-terminated line may use message_parse(); code that
 * holds a length MUST use message_parse_n(). Neither supersedes the other and
 * they are not a convenience pair to be chosen between by taste.
 */

/*
 * Parse `line` into `*out`. Returns 0 on success, -1 on reject.
 *
 * Rejects (all leave *out zeroed, see the contract at the top):
 *   - NULL arguments
 *   - total line longer than IRC_MAX_LINE, counted including the terminator
 *   - an embedded CR, LF or NUL anywhere in the line
 *   - a line with no command word
 *   - an empty tag block, or a malformed tag block
 *
 * Accepted:
 *   - one optional trailing CRLF / CR / LF, which is the terminator and is
 *     ignored. The scan then rejects any further CR or LF, so a second
 *     command smuggled onto the line is refused rather than parsed.
 *   - one or more SP or HTAB as the field separator
 *   - a leading ':' prefix
 *   - a param starting with ':', which consumes the rest of the line
 *   - up to IRC_MAX_PARAMS params; the last one absorbs the remainder verbatim
 *
 * The "embedded NUL" rejection above is only reachable when the line is really
 * a counted buffer: strlen() has already hidden the NUL by the time this
 * function is called. This entry point is for callers that hold a
 * NUL-terminated string; the framing layer (3.3) holds a length and must call
 * message_parse_n() instead.
 *
 * *out is overwritten, not appended to: see the note above about freeing a
 * message_t before reusing it.
 */
int message_parse(const char *line, message_t *out);

/* As message_parse(), over an explicit byte count. THIS is the entry point the
 * framing layer uses. `len` bytes are read from `line`; a NUL inside those
 * `len` bytes is an embedded NUL and is rejected, as are embedded CR and LF.
 * `line` need not be NUL-terminated at len -- the terminator, if any, is the
 * CR/LF pair counted inside `len`.
 *
 * Rejection here is strictly stronger than message_parse()'s, never weaker:
 * every line message_parse() accepts from the same bytes, this accepts too. */
int message_parse_n(const char *line, size_t len, message_t *out);

/* Free the one allocation and zero every field. Safe on NULL, safe on a
 * zeroed struct, safe to call more than once. */
void message_free(message_t *m);

/* Assemble a message_t from parts, honouring the same one-allocation model.
 * This is the OUTBOUND constructor: message_format() renders from a
 * message_t's fields, so without message_build() there is no way to hand it an
 * outgoing line and every phase that sends anything would have to hand-roll a
 * struct. Returns 0 on success, -1 on reject (and *out is then zeroed, as with
 * message_parse). `tags` is the block without the leading '@'; NULL means no
 * tags. `command` is uppercased, keeping the "command is uppercased" invariant
 * of 3.2 true for constructed messages as well as parsed ones. `params` may
 * be NULL when nparams is 0.
 *
 * A constructed message may hold a param the wire cannot represent (a space
 * in a non-final param, for instance). message_build() does not police that;
 * message_format() reports it, so there is exactly one place that decides
 * what is representable. */
int message_build(message_t *out,
                  const char *tags,
                  const char *prefix,
                  const char *command,
                  const char *const *params,
                  int nparams);

/* Render `m` into `out` (always re-rendered from the fields; never from
 * `raw`). Returns the byte count written, excluding the NUL terminator, or 0
 * on failure -- 0 is unambiguous because no successful render is empty.
 *
 * On failure `out[0]` is set to '\0' when cap > 0, and the render is never
 * partial: an over-cap or unrepresentable message produces an empty string
 * rather than a truncated line, for the same reason 3.2 forbids mid-parameter
 * truncation. Fails on:
 *   - NULL arguments, or cap == 0
 *   - a missing or empty command
 *   - a param that the wire cannot represent in that position: empty,
 *     containing SP or HTAB, or starting with ':' -- legal for the final
 *     param, which is colonned automatically, and a failure anywhere else
 *   - CR or LF in any field, which would inject a second line (rejected
 *     rather than emitted, in every field, always)
 *   - a tag block containing SP, HTAB, CR or LF, or starting with '@'
 *   - nparams outside [0, IRC_MAX_PARAMS]
 */
size_t message_format(const message_t *m, char *out, size_t cap);

/*
 * Tag lookup and serialization. The tag list is queryable because Phase 6
 * has to read irc-serve-origin / -epoch / -id / -hops off an inbound line
 * before deciding whether to relay, dedup or drop it.
 *
 * Keys are case-insensitive, per IRCv3. A tag written without '=' has the
 * empty value and is therefore found with an empty result.
 */
int message_tag_get(const message_t *m, const char *key, char *out, size_t cap);

/* Escape `value` per IRCv3 into `out` (NUL-terminated), returning the byte
 * count written or 0 if it does not fit -- never truncating. The escape set is
 * the one 3.2 and 5 name: a backslash before ':', ';', ' ', '\', CR or LF, so
 * the escaped forms are "\:", "\;", "\s", "\\", "\r" and "\n". A lone trailing
 * '\' is DROPPED when unescaping, which is what makes a literal backslash have
 * to be SENT as "\\" rather than as a single byte. */
size_t message_tag_escape(const char *value, char *out, size_t cap);

/* The inverse of message_tag_escape. Returns 0 on success, -1 if `value` does
 * not fit in `out`. A '\' before any character outside the escape set yields
 * that character literally; a lone trailing '\' is dropped, per the rule
 * above. */
int message_tag_unescape(const char *value, char *out, size_t cap);

/* Serialize a whole block from key/value pairs: "k=v;k2=v2", NO leading '@'.
 * Values are escaped. A NULL key is skipped; a NULL value means empty.
 * Returns the byte count written, or 0 if it does not fit. This is how Phase 6
 * authors the internal block; message_parse() never calls it. */
size_t message_tags_format(const message_tag_t *tags, size_t ntags,
                           char *out, size_t cap);

/* The hop ceiling (2.4: "irc-serve-hops increments per forward and the message
 * is dropped at 10").
 *
 * The number is 2.4's, not a value derived here, and the DERIVATION is the
 * reason it is written as a named constant rather than left as a 10 inside two
 * comparison sites: a forward test and a receipt test that each wrote their own
 * 10 would agree today and could drift apart, and a message that crossed a
 * disagreeing pair would loop -- which is the one failure 2.4 exists to
 * prevent.
 *
 * IT WAS ABSENT UNTIL THIS PHASE, and that is recorded rather than papered
 * over: the 2.4 tag FORMAT was frozen in Phase 1 and the hop LIMIT was not, so
 * there was a place to put the block and no place to put the bound that
 * governs whether the block is honoured. The `hops` value grammar above already
 * allows up to UINT32_MAX, which is the tell that the ceiling lived somewhere
 * else and had not been written down.
 *
 * The cost of the bound is stated rather than assumed: a message is refused when
 * the value it WOULD carry reaches this ceiling, so a message is delivered to at
 * most IRC_MAX_HOPS - 1 peers. On the full mesh 3.1 specifies, that is a
 * diameter of nine, which is far more than a deployment of the size this design
 * targets will ever have, and it is the price of never bouncing a message
 * forever.
 */
#define IRC_MAX_HOPS 10

/* ---------------------------------------------------------------------------
 * The 2.4 internal tag set -- FROZEN by Phase 1, not a placeholder
 * ---------------------------------------------------------------------------
 *   irc-serve-origin=<server>
 *   irc-serve-epoch=<n>
 *   irc-serve-id=<n>
 *   irc-serve-hops=<n>
 *
 * Epoch is PER-BOOT and id comes from a PER-SERVER monotonic counter owned by
 * server_t. Not a per-connection counter: a per-connection counter makes two
 * connections on server A both emit (a,1), and a peer then silently drops
 * the second message as a duplicate. That is the bug this format replaced,
 * which is why it is specified now instead of as a placeholder -- Phase 1
 * tests would have frozen the wrong format into the suite.
 *
 * Value grammar, enforced on parse and documented so Phase 6 can rely on it:
 *   origin  1..63 bytes; ASCII letters, digits, '-', '.'; must start with a
 *           letter or digit. Preserved verbatim -- server names are
 *           case-insensitive in IRC, so a comparison against our OWN name
 *           (the 2.4 never-forward-own-origin test) MUST be
 *           case-insensitive. That is the caller's job, not the format's.
 *   epoch   unsigned decimal, 1..20 digits, <= UINT64_MAX, no leading zero
 *           unless the value is exactly "0". Per-boot, so a restart resets
 *           the counter without colliding with pre-restart ids.
 *   id      same grammar as epoch, and additionally >= 1. Zero is reserved as
 *           "unset" so an absent tag is never mistaken for a real id.
 *   hops    unsigned decimal, 1..10 digits, <= UINT32_MAX, no leading zero.
 *           2.4 increments it per forward and drops the message at 10.
 */
typedef struct {
    char     origin[IRC_MAX_SERVER_NAME + 1];
    uint64_t epoch;
    uint64_t id;
    uint32_t hops;
} irc_serve_tags_t;

/* Is `name` a legal irc-serve-origin value, per the grammar above? Exposed
 * because Phase 2/6 must validate a configured server name with the same
 * rule the tag format accepts. 1 valid, 0 invalid. */
int irc_serve_server_name_valid(const char *name);

/* Read the four internal tags out of a parsed message into `*out`. Returns 0
 * when all four are present and legal, -1 otherwise (and *out is zeroed).
 * Extra unrelated tags are ignored, so a line may carry client tags too. */
int irc_serve_tags_parse(const message_t *m, irc_serve_tags_t *out);

/* Serialize the four tags into `out` in the frozen order (origin, epoch, id,
 * hops), as a block with NO leading '@' and with values escaped. Returns the
 * byte count written, or 0 if `t` is not itself legal or does not fit --
 * 0 is unambiguous because a legal block is never empty. */
size_t irc_serve_tags_format(const irc_serve_tags_t *t, char *out, size_t cap);

/* Is every field of `*t` inside the value grammar above? 1 legal, 0 not. */
int irc_serve_tags_valid(const irc_serve_tags_t *t);

/* ---------------------------------------------------------------------------
 * The nick rule 2.1 depends on and 5 says is missing
 * ---------------------------------------------------------------------------
 * The whole identity scheme is `nick@server`. 2.1 splits a qualified name at
 * the LAST '@', which is only unambiguous if '@' cannot appear inside a nick.
 * parse_nick() performs no character validation at all -- it returns 1 for
 * "NICK a@evil" and hands back the nickname "a@evil" -- so the predicate
 * below is what makes the scheme sound. It is a local rule, enforced at
 * registration, and it deliberately does not change parse_nick().
 *
 * The rule, in full. `nick` is valid iff ALL of the following hold:
 *
 *   1. `nick` is non-NULL and is not the empty string.
 *   2. strlen(nick) <= IRC_MAX_NICK (63). The bound comes from
 *      conn_t::nick[64] in 2.1, not from an invented limit.
 *   3. The FIRST character is not an ASCII digit '0'-'9'. RFC 2812 2.3.1
 *      allows a letter or a "special" there, and a digit is neither. A peer
 *      may enforce the same rule, depending on its implementation, and a
 *      nick this node holds that a peer will not accept is already
 *      divergence -- federation stays cheap only while the nodes agree.
 *      It is NOT a wire-parsing rule: message_parse() above puts the prefix
 *      and the command word into separate fields, so ":123 PRIVMSG #c :hi"
 *      and ":server 123 target :text" are distinct. Only the legibility
 *      cost survives.
 *   4. NO character is any of: '@' '#' '&' '+' '!' ':' ';'
 *        '@'  breaks the nick@server split at the last '@' (2.1).
 *        '#' '&' '+' '!'  are channel and mode sigils, so they would make a
 *            qualified name ambiguous or turn a leading '+' into a mode
 *            marker.
 *        ':'  is the prefix marker and the trailing-parameter marker in the
 *            grammar message_parse() implements above.
 *        ';'  is the IRCv3 tag separator. The tag serializer escapes it, so
 *            allowing it is not an immediate corruption, but it is a
 *            delimiter later phases use in mode strings and channel lists.
 *   5. NO character is a space, a control character, or DEL -- that is, no
 *      byte <= 0x20 and none equal to 0x7F. This covers SP, HTAB, VT, FF, CR,
 *      LF and the rest of C0. A nickname containing a space would also break
 *      tokenization at every hop.
 *
 * Bytes >= 0x80 are ACCEPTED. A UTF-8 nickname is ordinary and is not a
 * control character, so the rule does not exclude one.
 *
 * One consequence callers should know: valid_nick() takes a `const char *`,
 * so a NUL inside the nickname is invisible to it -- strlen() ends the string
 * and the shorter prefix is what gets judged. Rejecting an embedded NUL is
 * the framing layer's job (message_parse_n() above), not this predicate's.
 */
int valid_nick(const char *nick);

#endif /* IRC_CORE_MESSAGE_H */
