#ifndef IRC_IRCV3_TAGS_H
#define IRC_IRCV3_TAGS_H

/* IRCv3 message-tags validate-and-copy interface. This is a structural
 * roundtrip helper, NOT a full IRCv3 tag semantic parser: it validates the
 * tag block grammar and copies the canonical string, but does not decode or
 * expand escapes.
 *
 * Grammar accepted (roundtrips byte-for-byte, including the leading '@'):
 *     tags = [ "@" ] pair *(";" pair)
 *     pair = key [ "=" value ]
 *     key  = 1* ( char excluding ' ' ';' '=' '@' )
 *     value = * ( char excluding ' ' ';' )
 * A value may therefore contain '=' (and may be empty). Whitespace and ';'
 * are rejected so embedded command/line-wrapping is not smuggled into the
 * tag value.
 *
 * Both functions:
 *   - return the copied byte length on success (always a non-negative int);
 *   - return -1 on invalid input: NULL arguments, an empty tag string, a
 *     lone '@', malformed grammar, or an `out` buffer too small to hold the
 *     value plus its NUL terminator;
 *   - never truncate: if the output capacity is insufficient they reject
 *     with -1 and leave `out` untouched;
 *   - do not log into the parse path.
 * On success `out` receives NUL-terminated bytes identical to `input`.
 *
 * tags_parse() and tags_serialize() each perform their own independent input
 * validation and capacity check; neither depends on the other.
 */
int tags_parse(const char* input, char* out, int max_len);
int tags_serialize(const char* input, char* out, int max_len);

#endif /* IRC_IRCV3_TAGS_H */
