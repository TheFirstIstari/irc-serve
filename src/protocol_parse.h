#ifndef IRC_PROTOCOL_PARSE_H
#define IRC_PROTOCOL_PARSE_H

/* Basic IRC line parsing helpers.
 *
 * Lengths: all copy target capacities are caller-provided (`*_len`). Copies
 * are bounded and REJECT (return -1) when a field does not fit its output
 * buffer; they never silently truncate. On any error the caller's output
 * fields are cleared (NUL terminator written, token count set to 0) so
 * consumers observe a defined state.
 *
 * Embedded line breaks: no function accepts a newline (LF / CR) anywhere
 * except an optional single trailing CRLF (or lone CR / LF) which is treated
 * as the line terminator and ignored. An embedded newline means malformed /
 * multi-command input and is rejected with -1. Leading whitespace before the
 * command word is accepted.
 */

/* Tokenizes `line` on whitespace (space, tab, CR, LF). Returns 0 on success
 * (sets *token_count to the number of whitespace-separated tokens and
 * *error_code to 0), or -1 on error (NULL argument, or input too long to fit
 * in an int). On error *token_count is set to 0 and *error_code to a
 * non-zero value when the respective pointer is non-NULL. */
int parse_command(const char* line, int* token_count, int* error_code);

/* Parse "NICK <nickname>".
 *
 * Returns 1 on success (copies the nickname and sets *token_count = 2).
 * Requires the exact command word "NICK" (case-insensitive), exactly one
 * nickname token, and no further non-whitespace trailing content. Returns -1
 * on NULL arguments, an empty/missing nickname, a non-whitespace character
 * beyond the nickname (i.e. an embedded second command), any embedded line
 * break, or if the nickname does not fit in `nickname_len` bytes (no
 * truncation). */
int parse_nick(const char* line, char* nickname, int nickname_len, int* token_count);

/* Parse "USER <username> <hostname> <servername> :<realname>".
 *
 * Returns 1 on success (copies username, hostname, servername and the
 * trailing realname, and sets *token_count = 5). Requires the exact command
 * word "USER" (case-insensitive) and the three single-token fields.
 * `realname` is everything after the servername field, preserving interior
 * AND trailing spaces verbatim; a single leading ':' (if present) is
 * stripped. Returns -1 on NULL arguments, a missing/empty field, extra
 * non-whitespace content that would shift field positions, any embedded line
 * break, or if any field (including realname) does not fit its output buffer
 * (no truncation). */
int parse_user(const char* line,
               char* username, int username_len,
               char* hostname, int hostname_len,
               char* servername, int servername_len,
               char* realname, int realname_len,
               int* token_count);

#endif /* IRC_PROTOCOL_PARSE_H */
