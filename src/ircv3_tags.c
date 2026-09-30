#include <stddef.h>
#include <limits.h>
#include <string.h>

#include "ircv3_tags.h"

/* IRCv3 message-tags: the escape table (see the header for the specification
 * table and for why a colon is NOT escaped), and the parse -> list -> serialize
 * pair built on it.
 *
 * Nothing here allocates, and nothing here logs. Both are load-bearing rather
 * than stylistic: this is on the parse path of every message on the node, and
 * LeakSanitizer runs on the Linux CI job, so a per-message allocation here would
 * be a leak to be audited rather than a convenience. The cost is that a block
 * longer than IRCV3_TAGS_MAX_PAIRS is refused instead of grown -- see the
 * header for why the bound is where it is.
 */

/* ASCII lowercase of one byte, and nothing else. IRCv3 folds tag KEYS case
 * insensitively and nothing else: 005 already advertises CASEMAPPING=ascii, and
 * folding a tag VALUE would merge `label=Yes` and `label=yes`, which the
 * specification treats as two different values. Deliberately not tolower(): that
 * is locale-sensitive, and 005's promise is that this node does not do it. */
static char ascii_lower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char)(c - 'A' + 'a');
    }
    return c;
}

/* Do the NUL-terminated key `a` and the `alen`-byte span `b` name the same tag?
 * The span form exists because a key inside a block being parsed is not
 * NUL-terminated -- the '=' or ';' after it is. */
static int key_eq_span(const char *a, size_t alen, const char *b)
{
    if (strlen(a) != alen) {
        return 0;
    }
    for (size_t i = 0; i < alen; i++) {
        if (ascii_lower(a[i]) != ascii_lower(b[i])) {
            return 0;
        }
    }
    return 1;
}

static int key_eq(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    return key_eq_span(a, strlen(a), b);
}

/* --------------------------------------------------------------------------
 * The escape table
 * ------------------------------------------------------------------------ */

size_t ircv3_escape_value(const char *value, char *out, size_t cap)
{
    size_t n = 0;

    if (out == NULL || cap == 0) {
        return 0;
    }
    out[0] = '\0';
    if (value == NULL) {
        return 0;
    }

    for (size_t i = 0; value[i] != '\0'; i++) {
        char c = value[i];
        const char *rep = NULL;

        /* The specification's five. Note that ':' is not among them: `\:` is
         * how a SEMICOLON is written, so escaping ':' as '\:' would make the
         * two indistinguishable on the wire and a decoder following the spec
         * would read one as the other. */
        switch (c) {
        case ';':  rep = "\\:"; break;
        case ' ':  rep = "\\s"; break;
        case '\\': rep = "\\\\"; break;
        case '\r': rep = "\\r"; break;
        case '\n': rep = "\\n"; break;
        default:   break;
        }

        if (rep != NULL) {
            if (n + 2u + 1u > cap) {
                out[0] = '\0';
                return 0;
            }
            out[n] = rep[0];
            out[n + 1u] = rep[1];
            n += 2u;
        } else {
            if (n + 1u + 1u > cap) {
                out[0] = '\0';
                return 0;
            }
            out[n] = c;
            n += 1u;
        }
    }
    out[n] = '\0';
    return n;
}

int ircv3_unescape_value(const char *value, size_t len, char *out, size_t cap)
{
    size_t n = 0;

    if (value == NULL || out == NULL || cap == 0) {
        return -1;
    }
    out[0] = '\0';
    /* Unescaping never grows a value -- every escape becomes at least one
     * output byte -- so `len` plus a NUL always fits, and the only capacity
     * refusal possible is a buffer smaller than the input span. */
    if (len + 1u > cap) {
        return -1;
    }

    for (size_t i = 0; i < len; i++) {
        char c = value[i];

        if (c == '\\') {
            if (i + 1u >= len) {
                break; /* a lone trailing '\' produces no output character */
            }
            c = value[++i];
            switch (c) {
            case ':':  c = ';';  break;
            case 's':  c = ' ';  break;
            case '\\': c = '\\'; break;
            case 'r':  c = '\r'; break;
            case 'n':  c = '\n'; break;
            /* An escape before a character outside the set: the BACKSLASH is
             * dropped and the character is yielded literally, per the
             * specification. That is why `\;` decodes to ';' just as `\:`
             * does -- the second is not a valid encoding and the rule for an
             * invalid escape is "drop the backslash", not "reject". */
            default:   break;
            }
        }
        out[n] = c;
        n++;
    }
    out[n] = '\0';
    return 0;
}

/* --------------------------------------------------------------------------
 * Parse
 * ------------------------------------------------------------------------ */

/* Bytes that may not appear RAW in a key. SP/HTAB/CR/LF end the block or
 * inject a line, ';' separates pairs, and '=' is the value marker -- a key
 * holding one makes the pair ambiguous. */
static int key_byte_forbidden(char c)
{
    return c == ' ' || c == '\t' || c == ';' || c == '=' || c == '@' || c == '\r' ||
           c == '\n';
}

/* Bytes that may not appear RAW in a value. SP and ';' have escaped forms
 * (`\s`, `\:`), CR and LF have escaped forms (`\r`, `\n`), and a raw one of
 * either four is a sender that has broken the block grammar rather than one
 * using it. */
static int value_byte_forbidden(char c)
{
    return c == ' ' || c == ';' || c == '\r' || c == '\n';
}

int ircv3_tags_parse(const char *block, ircv3_tags_t *out)
{
    const char *p;

    if (out == NULL) {
        return -1;
    }
    memset(out, 0, sizeof *out);
    if (block == NULL || *block == '\0') {
        return -1;
    }

    p = block;
    if (*p == '@') {
        p++;
    }
    out->has_at = (p != block);
    if (*p == '\0') {
        /* A lone '@' and an empty block are the same thing after the marker,
         * and both are invalid: there is no pair to carry. */
        memset(out, 0, sizeof *out);
        return -1;
    }

    for (;;) {
        const char *kstart = p;
        size_t klen;
        const char *vstart = NULL;
        size_t vlen = 0;

        while (*p != '\0' && !key_byte_forbidden(*p)) {
            p++;
        }
        klen = (size_t)(p - kstart);
        if (klen == 0u || klen > (size_t)IRCV3_TAG_KEY_MAX) {
            memset(out, 0, sizeof *out);
            return -1;
        }

        if (*p == '=') {
            vstart = ++p;
            while (*p != '\0' && !value_byte_forbidden(*p)) {
                p++;
            }
            vlen = (size_t)(p - vstart);
            if (vlen > (size_t)IRCV3_TAG_VALUE_MAX) {
                memset(out, 0, sizeof *out);
                return -1;
            }
        }

        /* A DUPLICATE KEY KEEPS THE FIRST OCCURRENCE.
         *
         * IRCv3 says a tag MUST NOT appear twice in a block. This tree has to
         * choose a behaviour for a peer that does it anyway, and "last one
         * wins" is the wrong one: the relay path carries tags it does not
         * interpret, so "last wins" is a way for a node to rewrite a tag another
         * node set -- and `irc-serve-origin` is exactly the tag whose rewrite
         * would defeat 2.4's never-forward-own-origin rule. First wins means a
         * duplicate can never change what a tag says.
         *
         * The duplicate is DROPPED rather than stored twice, so a block that
         * carries one does not serialize back to a block that carries two, which
         * is what keeps parse -> serialize a byte-for-byte operation on a
         * canonical block. */
        {
            int dup = 0;

            for (size_t i = 0; i < out->npairs; i++) {
                if (key_eq_span(out->pairs[i].key, strlen(out->pairs[i].key),
                                kstart) == 0) {
                    continue;
                }
                dup = 1;
                break;
            }
            if (dup == 0) {
                ircv3_tag_t *dst;

                if (out->npairs >= (size_t)IRCV3_TAGS_MAX_PAIRS) {
                    memset(out, 0, sizeof *out);
                    return -1;
                }
                dst = &out->pairs[out->npairs];
                memcpy(dst->key, kstart, klen);
                dst->key[klen] = '\0';
                if (vstart != NULL) {
                    /* Unescaping cannot grow a value, so vlen bytes always fit
                     * in dst->value; the -1 arm is unreachable and is still
                     * reported rather than ignored. */
                    if (ircv3_unescape_value(vstart, vlen, dst->value,
                                             sizeof dst->value) != 0) {
                        memset(out, 0, sizeof *out);
                        return -1;
                    }
                    dst->flags = IRCV3_TAG_HAS_EQ;
                } else {
                    dst->value[0] = '\0';
                    dst->flags = 0u;
                }
                out->npairs++;
            }
        }

        if (*p == ';') {
            p++;
            if (*p == '\0') {
                /* A trailing ';' is an empty pair after the last one, and it is
                 * refused: accepting it would mean serialize() emitted a block
                 * that does not round-trip byte-for-byte, and the block grammar
                 * this module froze has no empty pair. */
                memset(out, 0, sizeof *out);
                return -1;
            }
            continue;
        }
        if (*p != '\0') {
            /* SP, HTAB, CR or LF between a pair and what follows. The block
             * grammar this module froze has exactly three continuations after a
             * pair -- '=', ';', end of block -- and a separator is none of them,
             * so `@a b` is a block plus a command rather than a block. It is
             * REFUSED here rather than silently truncated at the separator,
             * because a caller that accepted the pair would then read a tag
             * value that is not the value the sender wrote. */
            memset(out, 0, sizeof *out);
            return -1;
        }
        break;
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * Serialize
 * ------------------------------------------------------------------------ */

size_t ircv3_tags_serialize(const ircv3_tags_t *t, char *out, size_t cap)
{
    size_t n = 0;

    if (t == NULL || out == NULL || cap == 0) {
        return 0;
    }
    out[0] = '\0';

    for (size_t i = 0; i < t->npairs; i++) {
        char esc[IRCV3_TAG_VALUE_MAX * 2u + 1u];
        const ircv3_tag_t *pair = &t->pairs[i];
        const size_t klen = strlen(pair->key);
        size_t vlen;
        size_t need;

        if (pair->key[0] == '\0') {
            out[0] = '\0';
            return 0;
        }
        vlen = ircv3_escape_value(pair->value, esc, sizeof esc);
        if (vlen == 0u && pair->value[0] != '\0') {
            /* A refusal (cap is 2x the value bound, so this cannot happen for a
             * value that parsed) rather than an empty value. */
            out[0] = '\0';
            return 0;
        }

        /* One separator byte ('@' before the first pair, ';' before the rest),
         * the key, an '=' when the pair carried one, and the escaped value. The
         * trailing +1 is the NUL, which the capacity has to leave room for. */
        need = 1u + klen + 1u + vlen + 1u;
        if (n + need > cap) {
            out[0] = '\0';
            return 0;
        }
        /* The separator: '@' before the first pair when the block carried a block
         * marker, ';' before every other pair, and NOTHING before the first pair
         * of a block that arrived without one. The last case is the reason has_at
         * is recorded at all: a serializer that always wrote '@' would not
         * round-trip `k=v;m=n`, a block this module's legacy entry points accept
         * and core/message.c's internal tags never carry. */
        if (i != 0u) {
            out[n++] = ';';
        } else if (t->has_at != 0) {
            out[n++] = '@';
        }
        memcpy(out + n, pair->key, klen);
        n += klen;
        if ((pair->flags & IRCV3_TAG_HAS_EQ) != 0u) {
            out[n++] = '=';
        }
        memcpy(out + n, esc, vlen);
        n += vlen;
    }
    out[n] = '\0';
    /* A list with no pairs serializes to nothing, and 0 is the "did not fit"
     * value -- so an EMPTY block cannot be produced by this function. That is
     * deliberate: an empty tag block is not a legal block (a receiver would
     * have to guess whether '@' was sent), and callers that need to know have
     * t->npairs. */
    return n;
}

/* --------------------------------------------------------------------------
 * Lookup and mutation
 * ------------------------------------------------------------------------ */

void ircv3_tags_init(ircv3_tags_t *t)
{
    if (t == NULL) {
        return;
    }
    memset(t, 0, sizeof *t);
    t->has_at = 1;
}

const char *ircv3_tags_get(const ircv3_tags_t *t, const char *key)
{
    if (t == NULL || key == NULL || key[0] == '\0') {
        return NULL;
    }
    for (size_t i = 0; i < t->npairs; i++) {
        if (key_eq(t->pairs[i].key, key) != 0) {
            return t->pairs[i].value;
        }
    }
    return NULL;
}

int ircv3_tags_set(ircv3_tags_t *t, const char *key, const char *value)
{
    size_t klen;
    size_t vlen;
    size_t at = (size_t)-1;

    if (t == NULL || key == NULL || key[0] == '\0' || value == NULL) {
        return -1;
    }
    klen = strlen(key);
    vlen = strlen(value);
    if (klen > (size_t)IRCV3_TAG_KEY_MAX || vlen > (size_t)IRCV3_TAG_VALUE_MAX) {
        return -1;
    }
    for (size_t i = 0; i < klen; i++) {
        if (key_byte_forbidden(key[i])) {
            return -1;
        }
    }

    for (size_t i = 0; i < t->npairs; i++) {
        if (key_eq(t->pairs[i].key, key) != 0) {
            at = i;
            break;
        }
    }
    if (at == (size_t)-1) {
        if (t->npairs >= (size_t)IRCV3_TAGS_MAX_PAIRS) {
            return -1;
        }
        at = t->npairs;
        t->npairs++;
    }
    memcpy(t->pairs[at].key, key, klen + 1u);
    memcpy(t->pairs[at].value, value, vlen + 1u);
    t->pairs[at].flags = IRCV3_TAG_HAS_EQ;
    return 0;
}

/* --------------------------------------------------------------------------
 * The legacy pair -- parse -> list -> serialize, NOT a copy
 * ------------------------------------------------------------------------ */

/* Validate `input` and, if it parses, copy the CANONICAL form out.
 *
 * For a canonical block the canonical form is the input byte-for-byte, so the
 * contract the two existing tests assert is unchanged; what changed is that the
 * bytes now went through a decode and an encode to get here. For a block that
 * is merely *equivalent* (a valueless pair written `k=` where `k` will do, or a
 * `\x` escape with a dropped backslash) the output is the canonical spelling,
 * which is the behaviour a serializer is for.
 *
 * max_len is an `int` because that is the signature two existing tests call;
 * lengths are carried as size_t and narrowed only after being proven to fit. */
static int tags_copy_canonical(const char *input, char *out, int max_len)
{
    ircv3_tags_t list;
    char canonical[IRCV3_TAGS_MAX_PAIRS * (IRCV3_TAG_KEY_MAX + 1u +
                                          IRCV3_TAG_VALUE_MAX * 2u + 4u) + 2u];
    size_t n;

    if (input == NULL || out == NULL || max_len <= 0) {
        return -1;
    }
    if (ircv3_tags_parse(input, &list) != 0) {
        return -1;
    }
    n = ircv3_tags_serialize(&list, canonical, sizeof canonical);
    if (n == 0u) {
        return -1;
    }
    if (n > (size_t)INT_MAX) {   /* cannot be returned as an int */
        return -1;
    }
    if (n + 1u > (size_t)max_len) {
        return -1; /* insufficient capacity: refuse, never truncate */
    }
    memcpy(out, canonical, n + 1u);
    return (int)n;
}

int tags_parse(const char *input, char *out, int max_len)
{
    return tags_copy_canonical(input, out, max_len);
}

int tags_serialize(const char *input, char *out, int max_len)
{
    return tags_copy_canonical(input, out, max_len);
}
