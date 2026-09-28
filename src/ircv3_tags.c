#include <stddef.h>
#include <limits.h>
#include <string.h>

#include "ircv3_tags.h"

/* IRCv3 message-tags structural roundtrip helper. See ircv3_tags.h for the
 * accepted grammar and return semantics. No logging is emitted from the
 * parse/serialize path.
 *
 * Both tags_parse() and tags_serialize() perform identical independent
 * validation + copy so neither depends on the other. Lengths are carried as
 * size_t and only narrowed to int after the value is proven to fit both the
 * return type and the caller's output capacity. */

/* Returns 1 if `input` is a structurally valid tag block (see header), else 0.
 * NULL and empty input are invalid. */
static int tags_valid(const char* input) {
    if (input == NULL || *input == '\0') return 0;

    const char* p = input;
    if (*p == '@') p++;
    if (*p == '\0') return 0; /* lone '@': no key=value pair */

    int any_pair = 0;
    for (;;) {
        /* key: one or more chars that are not ' ', ';', '=', '@' */
        if (*p == '\0' || *p == ' ' || *p == ';' || *p == '=' || *p == '@') return 0;
        while (*p != '\0' && *p != ' ' && *p != ';' && *p != '=' && *p != '@') p++;

        /* optional "=value"; value excludes ' ' and ';' but allows '=' and '@' */
        if (*p == '=') {
            p++;
            while (*p != '\0' && *p != ' ' && *p != ';') p++;
        } else if (*p != ';' && *p != '\0') {
            return 0; /* key followed by ' ' or '@' with no '=': invalid */
        }

        any_pair = 1;
        if (*p == ';') { p++; continue; }
        if (*p == '\0') break;
        return 0; /* stray ' ' not consumed as a value char */
    }
    return any_pair;
}

/* Validate `input` and, if valid and it fits `out`'s capacity, copy it in
 * with a NUL terminator. Returns the copied length or -1. */
static int tags_validate_copy(const char* input, char* out, int max_len) {
    if (input == NULL || out == NULL || max_len <= 0) return -1;
    if (!tags_valid(input)) return -1;

    size_t len = strlen(input);
    if (len > (size_t)INT_MAX) return -1;   /* cannot be returned as int */
    if (len + 1u > (size_t)max_len) return -1; /* insufficient capacity */

    memcpy(out, input, len);
    out[len] = '\0';
    return (int)len;
}

int tags_parse(const char* input, char* out, int max_len) {
    return tags_validate_copy(input, out, max_len);
}

int tags_serialize(const char* input, char* out, int max_len) {
    return tags_validate_copy(input, out, max_len);
}
