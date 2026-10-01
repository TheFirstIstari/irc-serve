/* ircv3_tags.h -- the IRCv3 message-tags escape table, and a real
 * parse -> tag list -> serialize pair built on it.
 *
 * Authority: docs/SERVER_DESIGN.md 3.2 (the tag block), 5 (the row that says
 * "tags_parse and tags_serialize are the same function; roundtrip is vacuous;
 * no escaping"), and the IRCv3 message-tags specification.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE IS THE ESCAPE TABLE AND message.c IS NOT
 * ---------------------------------------------------------------------------
 * There is exactly ONE escaping implementation in this tree and it is here.
 * core/message.c's message_tag_escape()/message_tag_unescape() delegate to the
 * two functions below rather than carrying their own switch, because the failure
 * mode of two copies is a tree that disagrees with itself about what `\;` means:
 * a block written by one and read by the other is a tag value that silently
 * gains or loses a character, and the bug is only visible in the one
 * combination nobody tested.
 *
 * ---------------------------------------------------------------------------
 * THE ESCAPE SET, AND IT IS NOT THE PARAMETER SET
 * ---------------------------------------------------------------------------
 * IRCv3 message-tags, "Escaping Values", maps exactly five characters:
 *
 *      ';'  ->  \:        SPACE -> \s        '\' -> \\
 *      CR   ->  \r        LF    -> \n        everything else -> itself
 *
 * Two things about that table are worth stating because getting either wrong
 * produces a value that parses and is not the value that was sent:
 *
 *   1. A COLON is not escaped. `\:` is the encoding of a SEMICOLON, which reads
 *      backwards and is not a typo -- it is the specification's table. A
 *      previous version of core/message.c escaped ':' as '\:' and ';' as '\;',
 *      which is a plausible-looking guess and is wrong in both directions. It is
 *      retracted here rather than kept, because a tag value that a peer decodes
 *      differently from the way this node encodes it is a corrupted value, not
 *      a compatibility question.
 *   2. A TAG VALUE's escape set is not a PARAMETER's. RFC 1459 has no parameter
 *      escaping at all: a value that cannot be represented in its position is
 *      refused or colonned, never escaped. This file is therefore about tag
 *      VALUES ONLY, and nothing here may be applied to m->params[].
 *
 * ---------------------------------------------------------------------------
 * UNESCAPING IS NOT SYMMETRIC WITH ESCAPING, AND THAT IS THE SPEC
 * ---------------------------------------------------------------------------
 * A '\' before a character outside the five-item set has its BACKSLASH DROPPED
 * and the character yielded literally (`\b` unescapes to `b`), and a lone
 * trailing '\' produces no output character at all. So `\:` and `\;` BOTH
 * unescape to ';': the second is not a valid encoding, and the rule for an
 * invalid escape is "drop the backslash", not "reject the block". Rejecting
 * would be a stricter server than the specification and would refuse a peer
 * rather than relay its message.
 *
 * The consequence for a literal backslash is the one that bites: it is SENT as
 * `\\` and there is no shorter form that survives. A round trip that treats
 * escaping as symmetric with unescaping loses the last byte of any value
 * ending in one, and the property test below asserts exactly that case.
 */
#ifndef IRC_IRCV3_TAGS_H
#define IRC_IRCV3_TAGS_H

#include <stddef.h>

/* Bounds on one parsed block, and on a single value inside it.
 *
 * DERIVED, NOT PICKED, where a derivation existed:
 *
 *   IRCV3_TAG_KEY_MAX    64   IRC_MAX_NICK (63) plus one. Every tag this node
 *                                writes or reads keys on a nickname-shaped
 *                                string, and a key is written into a fixed
 *                                buffer on the relay path where a longer one
 *                                would mean refusing the message.
 *   IRCV3_TAG_VALUE_MAX  128   Doubled for the ESCAPED form: a value of raw
 *                                bytes is at most twice as long on the wire,
 *                                since every escapable byte becomes two. A
 *                                128-byte raw value needs 256 wire bytes, so a
 *                                buffer that holds the raw form and not the
 *                                escaped form would refuse exactly the values
 *                                the escaping exists for.
 *   IRCV3_TAGS_MAX_PAIRS  16   The internal 2.4 block is four tags and
 *                                message-ids adds a fifth; a relay that cannot
 *                                carry a client's own tags plus five of ours is
 *                                not a relay that has run out of room, it is a
 *                                relay whose buffer was chosen too small.
 *
 * The COST of all three is that a block beyond them is REFUSED rather than
 * truncated, and 3.2 forbids the alternative (delivering a shortened value).
 * A hostile client cannot grow any of these buffers: every one is a compile-time
 * constant in a caller-owned struct, and nothing in the parse path allocates. */
#define IRCV3_TAG_KEY_MAX    64
#define IRCV3_TAG_VALUE_MAX  128
#define IRCV3_TAGS_MAX_PAIRS 16

/* A pair carried no '=', so its value is the empty string. Recorded rather than
 * inferred, because "k" and "k=" are different BYTES on the wire and this
 * module's contract is that a canonical block round-trips byte for byte. */
#define IRCV3_TAG_HAS_EQ 0x1u

/* One decoded pair. `value` is UNESCAPED: this is the caller's value, not its
 * wire form. ircv3_tags_serialize() escapes it on the way out, which is the
 * whole point of separating the two representations. */
typedef struct {
    char     key[IRCV3_TAG_KEY_MAX + 1];
    char     value[IRCV3_TAG_VALUE_MAX + 1];
    unsigned flags;              /* IRCV3_TAG_HAS_EQ, or 0 */
} ircv3_tag_t;

/* A whole decoded block.
 *
 * `has_at` records whether the block arrived with a leading '@', because the
 * two forms are byte-different on the wire and a serialize that always adds
 * one would not round-trip a block that did not have it. `npairs` may be 0
 * with `has_at` set (a block of "@" is not legal -- see ircv3_tags_parse --
 * but a list built by a caller is allowed to be empty). */
typedef struct {
    ircv3_tag_t pairs[IRCV3_TAGS_MAX_PAIRS];
    size_t      npairs;
    int         has_at;
} ircv3_tags_t;

/*
 * Escape `value` (a NUL-terminated raw value) into `out`, NUL-terminated.
 * Returns the byte count written, which is 0 both for an empty value and for a
 * refusal, and the two are told apart by `out[0]`: a refused escape leaves
 * `out` as the empty string and an empty value writes the empty string, so the
 * caller distinguishes them with out[0] == '\0' plus a length check where it
 * matters. NEVER TRUNCATES -- a cap too small refuses.
 */
size_t ircv3_escape_value(const char *value, char *out, size_t cap);

/* The inverse. Unescape exactly `len` bytes of `value` (which is NOT
 * necessarily NUL-terminated -- it is a span inside a parsed block) into `out`.
 * Returns 0 on success, -1 if `value` does not fit in `out`. Never grows the
 * value, so `len` bytes plus a NUL always suffices. */
int ircv3_unescape_value(const char *value, size_t len, char *out, size_t cap);

/*
 * Parse a tag block into `*out`. Returns 0 on success, -1 on reject, and
 * `*out` is zeroed on reject so there is no partially populated list to free.
 *
 * `block` is the block WITHOUT the leading '@' or with it -- both are accepted,
 * and which one it was is recorded in `out->has_at`.
 *
 * Rejects: a NULL or empty block, a lone '@', an empty pair, a key containing
 * SP, HTAB, CR, LF, ';' or '=', a value containing a raw SP, HTAB, CR or LF
 * (they have escaped forms; a raw one is not a legal encoding), and more than
 * IRCV3_TAGS_MAX_PAIRS pairs or a value over IRCV3_TAG_VALUE_MAX bytes.
 *
 * THE KEY GRAMMAR IS A DELIBERATE SUPERSET of IRCv3's, which is
 * `[ '+' ] [ vendor '/' ] key_name` with key_name over letters, digits and
 * hyphens. This accepts any non-empty run of bytes that are not SP, HTAB, CR,
 * LF, ';', '=' or '@'. The reason is direction of failure: the strict rule
 * refuses a peer that sent `foo_bar`, and refusing is the expensive half of a
 * federation, while accepting a key another implementation does not recognise
 * costs nothing -- it is carried and dropped.
 */
int ircv3_tags_parse(const char *block, ircv3_tags_t *out);

/*
 * Serialize `t` into `out` as a block, NO trailing NUL counted, returning the
 * byte count written or 0 if it does not fit (which never happens for a list
 * that parsed, because parsing bounds the same things).
 *
 * The leading '@' is emitted if and only if `t->has_at` is set, so
 * parse -> serialize of a canonical block is byte-for-byte identical. Values
 * are ESCAPED here; they are stored unescaped.
 */
size_t ircv3_tags_serialize(const ircv3_tags_t *t, char *out, size_t cap);

/* Zero `*t` and mark it as carrying a block marker, which is the state a list
 * built by a caller starts from.
 *
 * REQUIRED BEFORE ircv3_tags_set() on a stack-allocated list, and the reason is
 * worth naming: set() appends at t->npairs and cannot tell an empty list from a
 * struct full of whatever was on the stack. A list that came from
 * ircv3_tags_parse() is already initialised and does not need this. */
void ircv3_tags_init(ircv3_tags_t *t);

/* Append or replace the pair named `key`, comparing keys ASCII
 * case-insensitively (IRCv3: tag keys are case-insensitive). Returns 0 on
 * success, -1 on a NULL/empty key, an over-long key or value, a full list, or a
 * value containing a NUL -- in which case `*t` is unchanged. `*t` must have
 * been initialised by ircv3_tags_init() or produced by ircv3_tags_parse(). */
int ircv3_tags_set(ircv3_tags_t *t, const char *key, const char *value);

/* The DECODED value for `key`, or NULL when absent. The returned pointer is
 * into `t` and is valid until `t` is modified. */
const char *ircv3_tags_get(const ircv3_tags_t *t, const char *key);

/* ---------------------------------------------------------------------------
 * THE LEGACY PAIR -- KEPT BECAUSE TWO EXISTING TESTS CALL THEM
 * ---------------------------------------------------------------------------
 * tags_parse()/tags_serialize() used to be the SAME function called twice, which
 * is what made the round trip they were tested for vacuous: a copy of the input
 * is trivially equal to the input. They are now parse -> list -> serialize, so a
 * block that survives them has survived a real decode and a real encode, and
 * they are no longer the same code path.
 *
 * Their contract is unchanged, because tests/protocol and tests/compliance call
 * them and the module is in irc_core for no other reason: they validate a block
 * and copy it byte-for-byte, returning the length or -1.
 */
int tags_parse(const char *input, char *out, int max_len);
int tags_serialize(const char *input, char *out, int max_len);

#endif /* IRC_IRCV3_TAGS_H */
