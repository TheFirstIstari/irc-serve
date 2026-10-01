/* message.c -- the IRC syntax seam. See message.h for the contracts; the
 * header is authoritative and this file must include it. That omission is
 * exactly the defect that let ircv3_tags.c ship with its declarations unseen
 * by the compiler. */
#include "message.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* The ONE escape table in this tree. message_tag_escape()/message_tag_unescape()
 * below delegate here rather than carrying their own switch; see the comments on
 * those two wrappers for why, and ircv3_tags.h for the table itself. */
#include "ircv3_tags.h"

/* Longest decimal we read or write for a uint64_t: UINT64_MAX is 20 digits.
 * Bounds the numeric tag parse and the size computations below. */
#define NUM_DIGITS_U64 20
#define NUM_DIGITS_U32 10

/* Separator between fields. RFC 1459 3.1 mandates SP; HTAB is accepted too
 * because real clients emit it and rejecting it buys nothing. */
static int is_sep(char c)
{
    return c == ' ' || c == '\t';
}

static char up(char c)
{
    if (c >= 'a' && c <= 'z') {
        return (char)(c - 'a' + 'A');
    }
    return c;
}

static int digit_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    return -1;
}

/* --------------------------------------------------------------------------
 * Tag block grammar and escaping
 * ------------------------------------------------------------------------ */

/* Advance to the end of a tag value: the pair's ';' or `end`, skipping over a
 * backslash-escaped character, so an escaped ';' is part of the value rather
 * than a separator. This is the only place the escape grammar affects the
 * STRUCTURE of a block; everything else about escaping is undone on lookup.
 *
 * `end` is a bound and deliberately not a NUL. A parsed tag block is a copy
 * that happens to be NUL-terminated, but the block handed to tag_block_valid()
 * points into the pristine received line, where the next byte is a space and
 * then the rest of the command. Scanning to a NUL there reads past the field
 * and rejects perfectly good lines. */
static const char *value_end_n(const char *v, const char *end)
{
    while (v < end && *v != ';') {
        if (*v == '\\' && v + 1 < end) {
            v++;
        }
        v++;
    }
    return v;
}

static const char *value_end(const char *v)
{
    return value_end_n(v, v + strlen(v));
}

/* A tag block is "pair *(';' pair)"; a pair is "key" or "key=value". The key
 * admits no ';' or '@'; the value admits no raw SP, may be empty, may contain
 * '=', and is walked verbatim, because unescaping happens on lookup rather
 * than at parse time. The block has already been split at the first SP by the
 * caller, so no SP can occur inside it. Rejects an empty key, a ';' or '@'
 * inside a key, and a leading or trailing ';' (an empty pair). */
static int tag_block_valid(const char *block, size_t len)
{
    const char *const end = block + len;
    const char *p = block;
    if (p == end || *p == ';') {
        return 0;
    }
    while (p < end) {
        const char *const key = p;
        while (p < end && *p != '=' && *p != ';') {
            if (*p == '@' || is_sep(*p)) {
                return 0;
            }
            p++;
        }
        if (p == key) {
            return 0; /* empty key */
        }
        if (p < end && *p == '=') {
            p = value_end_n(p + 1, end);
        }
        if (p == end) {
            break;
        }
        if (*p != ';') {
            return 0;
        }
        p++;
        if (p == end) {
            return 0; /* trailing ';' */
        }
    }
    return 1;
}

/* Does `pair` (a whole "key" or "key=value") name `key`? IRCv3 keys are
 * case-insensitive. */
static int tag_pair_matches(const char *pair, size_t plen, const char *key)
{
    const size_t klen = strlen(key);
    if (plen != klen) {
        return 0;
    }
    return strncasecmp(pair, key, klen) == 0 ? 1 : 0;
}

/* Locate a pair in a block. Returns 1 and sets the value span through the
 * `value` and `len` out-parameters to the pair's raw (still escaped) value, or
 * returns 0 if the key is absent. A tag written without '=' has a zero-length
 * value. */
static int tag_block_find(const char *block, const char *key,
                          const char **value, size_t *len)
{
    if (block == NULL || key == NULL) {
        return 0;
    }
    const char *p = block;
    while (*p != '\0') {
        const char *const pair = p;
        /* The key runs to this pair's own '=' or terminator. Searching for the
         * '=' with strchr() would run on into the NEXT pair, so a valueless tag
         * followed by a valued one would report the later key's name. */
        const char *keyend = p;
        while (*keyend != '\0' && *keyend != '=' && *keyend != ';') {
            keyend++;
        }
        const int has_value = (*keyend == '=') ? 1 : 0;
        const char *const vend = (has_value != 0) ? value_end(keyend + 1) : keyend;
        if (tag_pair_matches(pair, (size_t)(keyend - pair), key) != 0) {
            if (has_value != 0) {
                *value = keyend + 1;
                *len = (size_t)(vend - (keyend + 1));
            } else {
                *value = p; /* valueless tag: the value is empty */
                *len = 0;
            }
            return 1;
        }
        p = (*vend == ';') ? vend + 1 : vend; /* vend is the block's NUL here */
    }
    return 0;
}

/* Escape `value` per IRCv3 into `out` and write the byte count to *written.
 * Returns 0 on success, -1 if it does not fit. Never truncates.
 *
 * A THIN WRAPPER, and deliberately so. ircv3_tags.c owns the escape table --
 * there is exactly one in this tree, because two copies are a tree that
 * disagrees with itself about what a value means. This function used to carry
 * its own switch, and it carried the WRONG one: it escaped ':' as '\:' and ';'
 * as '\;', which is a plausible reading of the table and is not the
 * specification's. IRCv3 maps ';' to '\:' and leaves a colon raw. The mistake is
 * retracted here rather than preserved for a test that asserted it.
 *
 * The cost of the delegation is one call per value on the serialize path, which
 * is one per relayed message, and it is not measurable next to the render that
 * follows it. */
static int tag_escape_into(const char *value, char *out, size_t cap,
                           size_t *written)
{
    const size_t n = ircv3_escape_value(value, out, cap);

    if (n == 0u && value != NULL && value[0] != '\0') {
        out[0] = '\0';
        return -1;
    }
    *written = n;
    return 0;
}

size_t message_tag_escape(const char *value, char *out, size_t cap)
{
    if (value == NULL || out == NULL || cap == 0) {
        return 0;
    }
    out[0] = '\0';
    size_t n = 0;
    if (tag_escape_into(value, out, cap, &n) != 0) {
        out[0] = '\0';
        return 0;
    }
    return n;
}

/* Unescape exactly `len` bytes of `value` into `out`. Split out so that
 * message_tag_get, which knows a value's span inside a block and not just its
 * length, does not have to copy the value out of the block first. Returns 0 on
 * success, -1 if it does not fit. Never grows the value.
 *
 * Also a thin wrapper, for the reason tag_escape_into() gives. The rule it now
 * inherits is the specification's: a '\' before a character outside the escape
 * set has its BACKSLASH DROPPED and yields the character, and a lone trailing
 * '\' produces nothing. It used to keep the backslash as a literal character,
 * which meant a peer sending `\x` produced a value no peer would agree with --
 * the same value, spelled two ways, on two nodes. */
static int tag_unescape_span(const char *value, size_t len, char *out, size_t cap)
{
    if (out == NULL || cap == 0) {
        return -1;
    }
    return ircv3_unescape_value(value, len, out, cap);
}

int message_tag_unescape(const char *value, char *out, size_t cap)
{
    if (value == NULL || out == NULL || cap == 0) {
        return -1;
    }
    out[0] = '\0';
    return tag_unescape_span(value, strlen(value), out, cap);
}

int message_tag_get(const message_t *m, const char *key, char *out, size_t cap)
{
    if (m == NULL || key == NULL || out == NULL || cap == 0) {
        return -1;
    }
    out[0] = '\0';
    const char *value = NULL;
    size_t len = 0;
    if (tag_block_find(m->tags, key, &value, &len) == 0) {
        return -1;
    }
    /* Unescaping never grows a value, so `len` bytes always fit in `out`, and
     * it can be done straight into the caller's buffer. */
    return tag_unescape_span(value, len, out, cap);
}

size_t message_tags_format(const message_tag_t *tags, size_t ntags,
                           char *out, size_t cap)
{
    if (out == NULL || cap == 0) {
        return 0;
    }
    out[0] = '\0';
    if (ntags > 0 && tags == NULL) {
        return 0;
    }
    size_t n = 0;
    size_t emitted = 0;
    for (size_t i = 0; i < ntags; i++) {
        if (tags[i].key == NULL || tags[i].key[0] == '\0') {
            continue;
        }
        if (emitted > 0) {
            if (n + 2 > cap) {
                out[0] = '\0';
                return 0;
            }
            out[n] = ';';
            n++;
        }
        const size_t klen = strlen(tags[i].key);
        if (n + klen + 2 > cap) {
            out[0] = '\0';
            return 0;
        }
        memcpy(out + n, tags[i].key, klen);
        n += klen;
        out[n] = '=';
        n++;
        size_t vlen = 0;
        if (tag_escape_into(tags[i].value != NULL ? tags[i].value : "",
                            out + n, cap - n, &vlen) != 0) {
            out[0] = '\0';
            return 0;
        }
        n += vlen;
        emitted++;
    }
    if (emitted == 0) {
        out[0] = '\0';
        return 0; /* no pairs is not a block */
    }
    return n;
}

/* --------------------------------------------------------------------------
 * message_parse / message_parse_n
 * ------------------------------------------------------------------------ */

/* --------------------------------------------------------------------------
 * The one allocation
 * --------------------------------------------------------------------------
 * buf holds two regions:
 *
 *   [0, text]        the line exactly as received, NUL-terminated. This is
 *                    `raw`, and nothing ever writes to it again -- which is
 *                    what makes `raw` the ORIGINAL line rather than a field
 *                    soup with NULs punched through the separators.
 *   [text+1, end)    the parsed fields, NUL-terminated and packed. Every one
 *                    of tags/prefix/command/params[] points in here.
 *
 * Sizing: the fields are disjoint substrings of the line, so their bytes
 * total at most `text`, and there are at most IRC_MAX_PARAMS + 3 of them (tags,
 * prefix, command and the params), each needing one terminator byte. The
 * region is therefore text + IRC_MAX_PARAMS + 3 bytes at most.
 *
 * field_put() bounds-checks anyway and turns an overflow into a rejection, so
 * a mistake in that reasoning cannot become a heap overflow. */
typedef struct {
    char  *w;
    size_t room;
    int    overflow;
} field_t;

static char *field_put(field_t *f, const char *s, size_t n)
{
    if (f->overflow != 0) {
        return NULL;
    }
    if (n + 1 > f->room) {
        f->overflow = 1;
        return NULL;
    }
    char *const dst = f->w;
    memcpy(dst, s, n);
    dst[n] = '\0';
    f->w += n + 1;
    f->room -= n + 1;
    return dst;
}

/* The command word is uppercased, per 3.2, and the copy is ours to edit. */
static char *field_put_up(field_t *f, const char *s, size_t n)
{
    char *const dst = field_put(f, s, n);
    if (dst != NULL) {
        for (size_t i = 0; i < n; i++) {
            dst[i] = up(dst[i]);
        }
    }
    return dst;
}

int message_parse_n(const char *line, size_t len, message_t *out)
{
    if (out == NULL) {
        return -1;
    }
    memset(out, 0, sizeof *out);
    if (line == NULL) {
        return -1;
    }

    /* On-wire cap, counted INCLUDING the terminator (3.2). */
    if (len > (size_t)IRC_MAX_LINE) {
        return -1;
    }

    /* One optional trailing CRLF / CR / LF is the terminator and is ignored;
     * the scan below then rejects any further CR or LF, so a second command
     * smuggled onto the line is refused rather than parsed. Mirrors
     * line_text_len() in protocol_parse.c. */
    size_t text = len;
    if (text > 0 && line[text - 1] == '\n') {
        text--;
    }
    if (text > 0 && line[text - 1] == '\r') {
        text--;
    }
    for (size_t i = 0; i < text; i++) {
        const unsigned char c = (unsigned char)line[i];
        if (c == '\r' || c == '\n' || c == '\0') {
            return -1;
        }
    }

    char *const buf = (char *)malloc(2 * text + (size_t)IRC_MAX_PARAMS + 4);
    if (buf == NULL) {
        return -1;
    }
    if (text > 0) {
        memcpy(buf, line, text);
    }
    buf[text] = '\0';

    /* Everything is built in locals and published into *out only on success,
     * so a reject part-way through cannot leave a half-built message. */
    char  *tags = NULL;
    char  *prefix = NULL;
    char  *command = NULL;
    char  *params[IRC_MAX_PARAMS];
    int    nparams = 0;
    field_t f;
    f.w = buf + text + 1;
    f.room = text + (size_t)IRC_MAX_PARAMS + 3;
    f.overflow = 0;
    const char *p = buf;
    const char *const end = buf + text;

    /* Optional '@' tag block. */
    if (p < end && *p == '@') {
        p++;
        const char *const block = p;
        while (p < end && !is_sep(*p)) {
            p++;
        }
        const size_t blocklen = (size_t)(p - block);
        if (p == block || tag_block_valid(block, blocklen) != 1) {
            free(buf);
            return -1;
        }
        tags = field_put(&f, block, blocklen);
        if (p < end) {
            p++;
        }
    }

    /* Optional ':' source. Accepting it is what makes a peer message parse
     * identically to a local one (3.2). */
    if (p < end && *p == ':') {
        p++;
        const char *const source = p;
        while (p < end && !is_sep(*p)) {
            p++;
        }
        if (p == source) {
            free(buf); /* a source is never empty */
            return -1;
        }
        prefix = field_put(&f, source, (size_t)(p - source));
        if (p < end) {
            p++;
        }
    }

    /* The command word. */
    while (p < end && is_sep(*p)) {
        p++;
    }
    const char *const cmd = p;
    while (p < end && !is_sep(*p)) {
        p++;
    }
    if (p == cmd) {
        free(buf); /* no command word */
        return -1;
    }
    command = field_put_up(&f, cmd, (size_t)(p - cmd));
    if (p < end) {
        p++;
    }

    /* Parameters. A ':' param consumes the rest of the line; so does the
     * 15th, which is why there is no "too many params" rejection. */
    while (nparams < IRC_MAX_PARAMS) {
        while (p < end && is_sep(*p)) {
            p++;
        }
        if (p >= end) {
            break;
        }
        if (nparams == IRC_MAX_PARAMS - 1) {
            /* The 15th absorbs the remainder verbatim, spaces included. */
            const char *const v = (*p == ':') ? p + 1 : p;
            params[nparams] = field_put(&f, v, (size_t)(end - v));
            nparams++;
            p = end;
            break;
        }
        if (*p == ':') {
            params[nparams] = field_put(&f, p + 1, (size_t)(end - p) - 1);
            nparams++;
            p = end;
            break;
        }
        const char *const value = p;
        while (p < end && !is_sep(*p)) {
            p++;
        }
        params[nparams] = field_put(&f, value, (size_t)(p - value));
        nparams++;
        if (p < end) {
            p++;
        }
    }

    if (f.overflow != 0) {
        free(buf);
        return -1;
    }

    out->tags = tags;
    out->prefix = prefix;
    out->command = command;
    for (int i = 0; i < nparams; i++) {
        out->params[i] = params[i];
    }
    out->nparams = nparams;
    out->raw = buf;
    out->buf = buf;
    return 0;
}

int message_parse(const char *line, message_t *out)
{
    if (out != NULL) {
        memset(out, 0, sizeof *out);
    }
    if (line == NULL) {
        return -1;
    }
    return message_parse_n(line, strlen(line), out);
}

void message_free(message_t *m)
{
    if (m == NULL) {
        return;
    }
    free(m->buf);
    memset(m, 0, sizeof *m);
}

/* --------------------------------------------------------------------------
 * message_build
 * ------------------------------------------------------------------------ */

int message_build(message_t *out,
                  const char *tags,
                  const char *prefix,
                  const char *command,
                  const char *const *params,
                  int nparams)
{
    if (out == NULL) {
        return -1;
    }
    memset(out, 0, sizeof *out);
    if (command == NULL || command[0] == '\0') {
        return -1;
    }
    if (nparams < 0 || nparams > IRC_MAX_PARAMS) {
        return -1;
    }
    if (nparams > 0 && params == NULL) {
        return -1;
    }

    size_t need = strlen(command) + 1;
    if (tags != NULL) {
        need += strlen(tags) + 1;
    }
    if (prefix != NULL) {
        need += strlen(prefix) + 1;
    }
    for (int i = 0; i < nparams; i++) {
        if (params[i] == NULL) {
            return -1;
        }
        need += strlen(params[i]) + 1;
    }

    char *const buf = (char *)malloc(need);
    if (buf == NULL) {
        return -1;
    }

    char *w = buf;
    char *tags_field = NULL;
    char *prefix_field = NULL;
    char *params_field[IRC_MAX_PARAMS];

    if (tags != NULL && tags[0] != '\0') {
        const size_t n = strlen(tags);
        tags_field = w;
        memcpy(w, tags, n + 1);
        w += n + 1;
    }
    if (prefix != NULL && prefix[0] != '\0') {
        const size_t n = strlen(prefix);
        prefix_field = w;
        memcpy(w, prefix, n + 1);
        w += n + 1;
    }
    out->command = w;
    for (const char *q = command; *q != '\0'; q++) {
        *w++ = up(*q);
    }
    *w++ = '\0';
    for (int i = 0; i < nparams; i++) {
        const size_t n = strlen(params[i]);
        params_field[i] = w;
        memcpy(w, params[i], n + 1);
        w += n + 1;
    }

    out->tags = tags_field;
    out->prefix = prefix_field;
    out->nparams = nparams;
    for (int i = 0; i < nparams; i++) {
        out->params[i] = params_field[i];
    }
    out->raw = buf;
    out->buf = buf;
    return 0;
}

/* --------------------------------------------------------------------------
 * message_format
 * ------------------------------------------------------------------------ */

typedef struct {
    char  *out;
    size_t cap;
    size_t len;
    int    ok;
} sink_t;

static void sink_putc(sink_t *s, char c)
{
    if (!s->ok) {
        return;
    }
    /* One byte is reserved for the NUL terminator. */
    if (s->len + 1 >= s->cap) {
        s->ok = 0;
        return;
    }
    s->out[s->len] = c;
    s->len++;
}

static void sink_puts(sink_t *s, const char *str)
{
    for (size_t i = 0; str[i] != '\0'; i++) {
        sink_putc(s, str[i]);
    }
}

/* An embedded line break in any field would inject a second command onto the
 * connection, so the formatter refuses to emit one. */
static int has_line_break(const char *s)
{
    for (size_t i = 0; s[i] != '\0'; i++) {
        if (s[i] == '\r' || s[i] == '\n') {
            return 1;
        }
    }
    return 0;
}

/* Does this param need the ':' marker to survive a re-parse? Empty, already
 * starting with ':', or holding a separator all lose information without it. */
static int needs_colon(const char *s)
{
    if (s[0] == '\0' || s[0] == ':') {
        return 1;
    }
    return strpbrk(s, " \t") != NULL ? 1 : 0;
}

size_t message_format(const message_t *m, char *out, size_t cap)
{
    return message_format_ex(m, out, cap, 0);
}

size_t message_format_ex(const message_t *m, char *out, size_t cap,
                         int force_colon)
{
    if (m == NULL || out == NULL || cap == 0) {
        return 0;
    }
    out[0] = '\0';
    if (m->command == NULL || m->command[0] == '\0') {
        return 0;
    }
    if (m->nparams < 0 || m->nparams > IRC_MAX_PARAMS) {
        return 0;
    }

    /* Validate before emitting anything, so a failure never leaves a partial
     * line in `out`. */
    if (m->tags != NULL) {
        if (m->tags[0] == '@' || strpbrk(m->tags, " \t\r\n") != NULL) {
            return 0;
        }
    }
    if (m->prefix != NULL) {
        if (m->prefix[0] == '\0' || m->prefix[0] == ':' ||
            has_line_break(m->prefix)) {
            return 0;
        }
    }
    if (has_line_break(m->command)) {
        return 0;
    }
    for (int i = 0; i < m->nparams; i++) {
        const char *const v = m->params[i];
        if (v == NULL || has_line_break(v)) {
            return 0;
        }
        /* ':' is only representable on the final param, and the formatter puts
         * it there itself. A value needing it elsewhere is unrepresentable,
         * reported rather than silently reshaped. */
        if (needs_colon(v) != 0 && i != m->nparams - 1) {
            return 0;
        }
    }

    sink_t s;
    s.out = out;
    s.cap = cap;
    s.len = 0;
    s.ok = 1;

    if (m->tags != NULL && m->tags[0] != '\0') {
        sink_putc(&s, '@');
        sink_puts(&s, m->tags);
        sink_putc(&s, ' ');
    }
    if (m->prefix != NULL && m->prefix[0] != '\0') {
        sink_putc(&s, ':');
        sink_puts(&s, m->prefix);
        sink_putc(&s, ' ');
    }
    sink_puts(&s, m->command);
    for (int i = 0; i < m->nparams; i++) {
        /* force_colon applies to the LAST parameter only, and only when there is
         * one. Applying it to every parameter would put a ':' in a target field,
         * which is not a marker at all. */
        const int last = (i == m->nparams - 1);

        sink_putc(&s, ' ');
        if (needs_colon(m->params[i]) != 0 ||
            (force_colon != 0 && last)) {
            sink_putc(&s, ':');
        }
        sink_puts(&s, m->params[i]);
    }

    if (!s.ok) {
        out[0] = '\0';
        return 0;
    }
    out[s.len] = '\0';
    return s.len;
}

/* --------------------------------------------------------------------------
 * The 2.4 internal tag set
 * ------------------------------------------------------------------------ */

static const char TAG_ORIGIN[] = "irc-serve-origin";
static const char TAG_EPOCH[]  = "irc-serve-epoch";
static const char TAG_ID[]     = "irc-serve-id";
static const char TAG_HOPS[]   = "irc-serve-hops";

int irc_serve_server_name_valid(const char *name)
{
    if (name == NULL) {
        return 0;
    }
    const size_t n = strlen(name);
    if (n == 0 || n > (size_t)IRC_MAX_SERVER_NAME) {
        return 0;
    }
    const char first = name[0];
    const int alnum = (first >= 'A' && first <= 'Z') ||
                      (first >= 'a' && first <= 'z') ||
                      (first >= '0' && first <= '9');
    if (!alnum) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        const char ch = name[i];
        const int ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                       (ch >= '0' && ch <= '9') || ch == '-' || ch == '.';
        if (!ok) {
            return 0;
        }
    }
    return 1;
}

/* Unsigned decimal, canonical form only: no leading zero unless the value is
 * exactly "0". Returns 0 on success, -1 otherwise. */
static int parse_decimal(const char *s, size_t len, uint64_t limit,
                         uint64_t *out)
{
    if (len == 0 || len > NUM_DIGITS_U64) {
        return -1;
    }
    if (s[0] == '0' && len > 1) {
        return -1;
    }
    const uint64_t q = limit / 10u;
    const uint64_t r = limit % 10u;
    uint64_t v = 0;
    for (size_t i = 0; i < len; i++) {
        const int d = digit_value(s[i]);
        if (d < 0) {
            return -1;
        }
        /* Overflow-safe: refuse before the multiply rather than after. */
        if (v > q || (v == q && (uint64_t)d > r)) {
            return -1;
        }
        v = v * 10u + (uint64_t)d;
    }
    *out = v;
    return 0;
}

static size_t format_decimal(uint64_t v, char *out, size_t cap)
{
    if (cap == 0) {
        return 0;
    }
    char digits[NUM_DIGITS_U64 + 1];
    size_t n = 0;
    if (v == 0) {
        digits[n] = '0';
        n++;
    }
    while (v > 0 && n < sizeof digits) {
        digits[n] = (char)('0' + (int)(v % 10u));
        v /= 10u;
        n++;
    }
    if (n + 1 > cap) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        out[i] = digits[n - 1 - i];
    }
    out[n] = '\0';
    return n;
}

int irc_serve_tags_valid(const irc_serve_tags_t *t)
{
    if (t == NULL) {
        return 0;
    }
    /* epoch and hops need no check: any uint64_t / uint32_t renders to a
     * canonical decimal of at most 20 / 10 digits and re-parses to itself, and
     * 0 is legal for both (a boot counter may start at 0, and hops 0 is a
     * locally originated message that has not been forwarded yet). */
    return irc_serve_server_name_valid(t->origin) == 1 && t->id != 0 ? 1 : 0;
}

size_t irc_serve_tags_format(const irc_serve_tags_t *t, char *out, size_t cap)
{
    if (out == NULL || cap == 0) {
        return 0;
    }
    out[0] = '\0';
    if (irc_serve_tags_valid(t) != 1) {
        return 0;
    }
    char epoch[NUM_DIGITS_U64 + 1];
    char id[NUM_DIGITS_U64 + 1];
    char hops[NUM_DIGITS_U32 + 1];
    if (format_decimal(t->epoch, epoch, sizeof epoch) == 0 ||
        format_decimal(t->id, id, sizeof id) == 0 ||
        format_decimal(t->hops, hops, sizeof hops) == 0) {
        return 0;
    }
    const message_tag_t tags[4] = {
        { TAG_ORIGIN, t->origin },
        { TAG_EPOCH,  epoch },
        { TAG_ID,     id },
        { TAG_HOPS,   hops },
    };
    return message_tags_format(tags, 4, out, cap);
}

int irc_serve_tags_parse(const message_t *m, irc_serve_tags_t *out)
{
    if (out == NULL) {
        return -1;
    }
    memset(out, 0, sizeof *out);
    if (m == NULL || m->buf == NULL) {
        return -1;
    }
    char origin[IRC_MAX_SERVER_NAME + 1];
    char epoch[NUM_DIGITS_U64 + 1];
    char id[NUM_DIGITS_U64 + 1];
    char hops[NUM_DIGITS_U32 + 1];

    if (message_tag_get(m, TAG_ORIGIN, origin, sizeof origin) != 0 ||
        message_tag_get(m, TAG_EPOCH, epoch, sizeof epoch) != 0 ||
        message_tag_get(m, TAG_ID, id, sizeof id) != 0 ||
        message_tag_get(m, TAG_HOPS, hops, sizeof hops) != 0) {
        return -1;
    }
    if (irc_serve_server_name_valid(origin) != 1) {
        return -1;
    }

    uint64_t e = 0;
    uint64_t i_id = 0;
    uint64_t h = 0;
    if (parse_decimal(epoch, strlen(epoch), UINT64_MAX, &e) != 0 ||
        parse_decimal(id, strlen(id), UINT64_MAX, &i_id) != 0 ||
        parse_decimal(hops, strlen(hops), UINT32_MAX, &h) != 0) {
        return -1;
    }
    if (i_id == 0) {
        return -1; /* 0 is reserved as "unset" */
    }

    memcpy(out->origin, origin, strlen(origin) + 1);
    out->epoch = e;
    out->id = i_id;
    out->hops = (uint32_t)h;
    return 0;
}

/* --------------------------------------------------------------------------
 * The IRCv3 `msgid` -- see the block comment on irc_serve_msgid_tag() in
 * message.h, which is where the format and the argument for it live. What is
 * here is the renderer and the one check that keeps the promise in that comment
 * true.
 * ------------------------------------------------------------------------ */

static const char TAG_MSGID[] = "msgid";

/* The '_' that separates the three fields. Spelled as a constant rather than
 * written into the format string because it is the load-bearing byte of the
 * whole format: message.h's argument is that 2.4's origin grammar excludes it,
 * so the three fields stay separable. A reader changing the separator to '-'
 * should have to find this line. */
#define MSGID_SEP '_'

size_t irc_serve_msgid_value(const irc_serve_tags_t *t, char *out, size_t cap)
{
    if (out == NULL || cap == 0) {
        return 0;
    }
    out[0] = '\0';
    /* The same legality gate irc_serve_tags_format() uses, for the same reason:
     * a stamp the 2.4 grammar would refuse must not be able to become a
     * client-visible identity, because a client cannot check it and a peer
     * cannot re-derive the dedup key from a value that was never legal. */
    if (irc_serve_tags_valid(t) != 1) {
        return 0;
    }
    char epoch[NUM_DIGITS_U64 + 1];
    char id[NUM_DIGITS_U64 + 1];
    if (format_decimal(t->epoch, epoch, sizeof epoch) == 0 ||
        format_decimal(t->id, id, sizeof id) == 0) {
        return 0;
    }
    /* snprintf rather than concatenation, because the bound is three variable
     * lengths and a hand-rolled sum is the kind of arithmetic that is wrong
     * once and then forever. The cap is checked by snprintf and 0 is returned,
     * so a caller that sized its buffer from the derivation in message.h is
     * right and one that did not is refused rather than overrunning. */
    const int n = snprintf(out, cap, "%s%c%s%c%s", t->origin, MSGID_SEP, epoch,
                           MSGID_SEP, id);
    if (n < 0 || (size_t)n >= cap) {
        out[0] = '\0';
        return 0;
    }
    /* THE ESCAPE CLAIM, CHECKED. message.h says this value needs no escaping
     * because every byte is a letter, a digit, '_' or '.'; that is a claim about
     * the grammar above, and a grammar that later widens -- an origin rule that
     * admitted ';' or a space -- would turn it into a value that corrupts the
     * block it is written into. Refusing here is a bug report, not a fallback:
     * there is no second spelling of this tag and silently emitting an
     * unescaped one is the failure ircv3_tags.h exists to prevent. */
    for (const char *p = out; *p != '\0'; p++) {
        const unsigned char ch = (unsigned char)*p;

        const int alnum = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                          (ch >= '0' && ch <= '9');
        if (alnum == 0 && ch != (unsigned char)MSGID_SEP && ch != (unsigned char)'.') {
            out[0] = '\0';
            return 0;
        }
    }
    return (size_t)n;
}

size_t irc_serve_msgid_tag(const irc_serve_tags_t *t, char *out, size_t cap)
{
    if (out == NULL || cap == 0) {
        return 0;
    }
    out[0] = '\0';
    /* The one tag rather than the four, so message_tags_format() does the
     * assembling -- including the `key=value` join and the block's own contract
     * -- instead of a second copy of it here. A hand-written "msgid=" prefix
     * would be a place where the key spelling and the separator could drift from
     * the one message.h documents. */
    char value[IRC_MAX_MSGTAG + 1];
    const size_t vlen = irc_serve_msgid_value(t, value, sizeof value);

    if (vlen == 0u) {
        return 0;
    }
    const message_tag_t one[1] = { { TAG_MSGID, value } };

    return message_tags_format(one, 1, out, cap);
}

/* --------------------------------------------------------------------------
 * valid_nick
 * ------------------------------------------------------------------------ */

/* 2.1 splits `nick@server` at the LAST '@', which is only unambiguous if '@'
 * cannot appear inside a nick -- without this rule the whole scoped-identity
 * scheme is unsound. '#', '&', '+' and '!' are the other sigils that would
 * make a qualified name ambiguous, either by colliding with a channel prefix
 * or by turning a leading '+' into a mode marker. */
static int nick_char_illegal(char c)
{
    /* ':' is the prefix marker and the trailing-parameter marker in the very
     * grammar message_parse() implements, so a colon inside a nick blurs both
     * the construction of a prefix and its parsing back apart.
     *
     * ';' is the IRCv3 tag separator. The tag serializer escapes it, so it is
     * not an immediate corruption, but it is a delimiter later phases use in
     * mode strings and channel lists, and refusing it now is cheaper than
     * debugging it there. */
    if (c == ':' || c == ';') {
        return 1;
    }
    if (c == '@' || c == '#' || c == '&' || c == '+' || c == '!') {
        return 1;
    }
    /* Space and control characters, including DEL. A nickname containing a
     * space would also break tokenization at every hop. Bytes >= 0x80 are
     * accepted: UTF-8 nicknames are ordinary and are not control characters. */
    const unsigned char u = (unsigned char)c;
    return (u <= 0x20u || u == 0x7fu) ? 1 : 0;
}

/* RFC 2812 2.3.1: the first character of a nickname is a letter or a
 * "special", and a digit is neither. Independently, a peer may enforce the
 * same rule -- that is its implementation's business -- and a nick this node
 * holds that a peer will not accept is already divergence, since federation
 * stays cheap only while the nodes agree. Enforced at registration, the
 * only place a nick is ever chosen.
 *
 * What is NOT the reason is on-the-wire ambiguity. ":123 PRIVMSG #c :hi"
 * and ":server 123 target :text" are distinct, because message_parse()
 * above reads the prefix and the command word into separate fields and
 * "PRIVMSG" is not a three-digit numeric. Only the legibility cost
 * survives: ":123" reads as a numeric prefix in a log. */
static int nick_first_char_illegal(char c)
{
    const unsigned char u = (unsigned char)c;
    return (u >= '0' && u <= '9') ? 1 : 0;
}

int valid_nick(const char *nick)
{
    if (nick == NULL) {
        return 0;
    }
    const size_t n = strlen(nick);
    if (n == 0 || n > (size_t)IRC_MAX_NICK) {
        return 0;
    }
    if (nick_first_char_illegal(nick[0]) != 0) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        if (nick_char_illegal(nick[i]) != 0) {
            return 0;
        }
    }
    return 1;
}
