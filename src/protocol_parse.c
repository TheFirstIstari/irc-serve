#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include "protocol_parse.h"

/* parse_command: tokenizes `line` on whitespace (space, tab, CR, LF).
 *
 * Return convention (matches the caller in server.c):
 *   0  on success -- *token_count holds the token count, *error_code is 0
 *  -1  on error -- NULL argument, or input too long to fit in an int
 *
 * On error, *token_count is set to 0 and *error_code to a non-zero code
 * whenever the respective pointers are non-NULL, so callers can safely
 * consume both outputs regardless of the return value. */
int parse_command(const char* line, int* token_count, int* error_code) {
    if (!line || !token_count || !error_code) {
        if (token_count) *token_count = 0;
        if (error_code) *error_code = 1;
        return -1;
    }

    size_t len = strlen(line);
    if (len > (size_t)INT_MAX) {
        *token_count = 0;
        *error_code = 2; /* input too long */
        return -1;
    }

    int count = 0;
    int in_token = 0;

    for (size_t i = 0; i < len; i++) {
        if (!isspace((unsigned char)line[i])) {
            if (!in_token) {
                in_token = 1;
                count++;
            }
        } else {
            in_token = 0;
        }
    }

    *token_count = count;
    *error_code = 0;
    return 0;
}

/* Returns the length of `s` with one optional trailing CRLF / CR / LF terminator
 * removed, or (size_t)-1 if `s` contains an embedded line break (malformed /
 * multi-command input). */
static size_t line_text_len(const char* s) {
    size_t n = strlen(s);
    if (n > 0 && s[n - 1] == '\n') n--;
    if (n > 0 && s[n - 1] == '\r') n--;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '\n' || s[i] == '\r') return (size_t)-1;
    }
    return n;
}

/* Case-insensitive exact command match: `tok` (len bytes) must equal `word`. */
static int cmd_is(const char* tok, size_t len, const char* word) {
    return len == strlen(word) && strncasecmp(tok, word, len) == 0;
}

int parse_nick(const char* line, char* nickname, int nickname_len, int* token_count) {
    if (token_count) *token_count = 0;
    if (nickname && nickname_len > 0) nickname[0] = '\0';
    if (!line || !nickname || !token_count || nickname_len <= 0) return -1;

    size_t n = line_text_len(line);
    if (n == (size_t)-1) return -1; /* embedded line break */
    const char* end = line + n;
    const char* p = line;

    /* exact command word "NICK" */
    while (p < end && isspace((unsigned char)*p)) p++;
    const char* cmd = p;
    while (p < end && !isspace((unsigned char)*p)) p++;
    if (!cmd_is(cmd, (size_t)(p - cmd), "NICK")) return -1;

    /* skip whitespace between command and nickname */
    while (p < end && isspace((unsigned char)*p)) p++;
    if (p >= end) return -1; /* missing nickname */

    const char* nick = p;
    while (p < end && !isspace((unsigned char)*p)) p++;
    size_t nick_len = (size_t)(p - nick);
    if (nick_len == 0) return -1;

    /* reject any remaining non-whitespace (embedded second command) */
    const char* q = p;
    while (q < end && isspace((unsigned char)*q)) q++;
    if (q < end) return -1;

    if (nick_len >= (size_t)nickname_len) return -1; /* insufficient capacity */
    memcpy(nickname, nick, nick_len);
    nickname[nick_len] = '\0';
    *token_count = 2;
    return 1;
}

int parse_user(const char* line,
               char* username, int username_len,
               char* hostname, int hostname_len,
               char* servername, int servername_len,
               char* realname, int realname_len,
               int* token_count) {
    if (token_count) *token_count = 0;
    if (username && username_len > 0) username[0] = '\0';
    if (hostname && hostname_len > 0) hostname[0] = '\0';
    if (servername && servername_len > 0) servername[0] = '\0';
    if (realname && realname_len > 0) realname[0] = '\0';
    if (!line || !username || !hostname || !servername || !realname || !token_count ||
        username_len <= 0 || hostname_len <= 0 || servername_len <= 0 || realname_len <= 0) {
        return -1;
    }

    size_t n = line_text_len(line);
    if (n == (size_t)-1) return -1; /* embedded line break */
    const char* end = line + n;
    const char* p = line;

    /* exact command word "USER" */
    while (p < end && isspace((unsigned char)*p)) p++;
    const char* cmd = p;
    while (p < end && !isspace((unsigned char)*p)) p++;
    if (!cmd_is(cmd, (size_t)(p - cmd), "USER")) return -1;

    /* three whitespace-delimited, single-token fields */
    char* dsts[3];
    int caps[3];
    dsts[0] = username; caps[0] = username_len;
    dsts[1] = hostname; caps[1] = hostname_len;
    dsts[2] = servername; caps[2] = servername_len;

    for (int f = 0; f < 3; f++) {
        while (p < end && isspace((unsigned char)*p)) p++;
        if (p >= end) return -1; /* missing field */
        const char* field = p;
        while (p < end && !isspace((unsigned char)*p)) p++;
        size_t field_len = (size_t)(p - field);
        if (field_len == 0) return -1;
        if (field_len >= (size_t)caps[f]) return -1; /* insufficient capacity */
        memcpy(dsts[f], field, field_len);
        dsts[f][field_len] = '\0';
    }

    /* realname: everything after the servername field, preserving interior and
     * trailing spaces verbatim; a single leading ':' is stripped.
     * A field separator run of whitespace is skipped, but trailing realname
     * whitespace is retained. */
    while (p < end && isspace((unsigned char)*p)) p++;
    const char* rn = p;
    if (rn < end && *rn == ':') rn++; /* strip one leading ':' */
    size_t rn_len = (size_t)(end - rn);
    if (rn_len == 0) return -1; /* empty realname */
    if (rn_len >= (size_t)realname_len) return -1; /* insufficient capacity */
    memcpy(realname, rn, rn_len);
    realname[rn_len] = '\0';

    *token_count = 5;
    return 1;
}