/* message_format tests -- the render half of the syntax seam, and the tag
 * escaping that the previous draft left vacuous (SERVER_DESIGN.md 3.2, 2.4,
 * 5/ircv3_tags, 7/Phase 1).
 *
 * Assertions are on return values and on output bytes only. No test inspects
 * the allocator, an interior pointer, or any other internal plumbing. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/message.h"

/* format(m) == expected, and the return value agrees with the length. The
 * mismatch is printed first so a failure names the case instead of just
 * pointing at this helper. */
static void assert_format(const message_t *m, const char *expected)
{
    char out[IRC_MAX_LINE + 64];
    const size_t n = message_format(m, out, sizeof out);
    if (n != strlen(expected) || strcmp(out, expected) != 0) {
        fprintf(stderr, "format mismatch\n  got      [%s] (%zu)\n"
                        "  expected [%s] (%zu)\n",
                out, n, expected, strlen(expected));
    }
    assert(n == strlen(expected));
    assert(strcmp(out, expected) == 0);
}

/* parse -> format -> parse preserves command, prefix, tags and every param. */
static void assert_round_trip(const char *line)
{
    char a[IRC_MAX_LINE + 64];
    char b[IRC_MAX_LINE + 64];
    message_t m1;
    message_t m2;

    assert(message_parse(line, &m1) == 0);
    const size_t n1 = message_format(&m1, a, sizeof a);
    assert(n1 > 0);

    /* Leg one: the rendered line must re-parse to the same message. */
    assert(message_parse(a, &m2) == 0);
    if (m1.tags == NULL) {
        assert(m2.tags == NULL);
    } else {
        assert(m2.tags != NULL);
        assert(strcmp(m1.tags, m2.tags) == 0);
    }
    if (m1.prefix == NULL) {
        assert(m2.prefix == NULL);
    } else {
        assert(m2.prefix != NULL);
        assert(strcmp(m1.prefix, m2.prefix) == 0);
    }
    assert(strcmp(m1.command, m2.command) == 0);
    assert(m1.nparams == m2.nparams);
    for (int i = 0; i < m1.nparams; i++) {
        assert(strcmp(m1.params[i], m2.params[i]) == 0);
    }

    /* Leg two: rendering is idempotent, so the seam is a fixed point. */
    const size_t n2 = message_format(&m2, b, sizeof b);
    assert(n2 == n1);
    assert(strcmp(a, b) == 0);

    message_free(&m1);
    message_free(&m2);
}

int main(void)
{
    char out[IRC_MAX_LINE + 64];
    message_t m;
    message_t r;

    /* --- the render is exactly "@tags :prefix COMMAND params" --- */
    {
        const char *const params[] = { "#chan", "hello world" };
        assert(message_build(&m, "a=1;b=2", "irc.a", "PRIVMSG", params, 2) == 0);
        assert_format(&m, "@a=1;b=2 :irc.a PRIVMSG #chan :hello world");
        message_free(&m);
    }
    {
        const char *const params[] = { "#chan" };
        /* No tags: no '@'. No prefix: no ':' before the command. */
        assert(message_build(&m, NULL, NULL, "JOIN", params, 1) == 0);
        assert_format(&m, "JOIN #chan");
        message_free(&m);
    }
    {
        const char *const params[] = { "irc.b" };
        assert(message_build(&m, NULL, "irc.a", "SQUIT", params, 1) == 0);
        assert_format(&m, ":irc.a SQUIT irc.b");
        message_free(&m);
    }
    /* Zero params renders as the bare command. */
    assert(message_build(&m, NULL, "irc.a", "PING", NULL, 0) == 0);
    assert_format(&m, ":irc.a PING");
    message_free(&m);

    /* message_build uppercases the command, so the 3.2 invariant holds for a
     * constructed message as well as a parsed one. */
    assert(message_build(&m, NULL, NULL, "pInG", NULL, 0) == 0);
    assert_format(&m, "PING");
    message_free(&m);
    assert(message_build(&m, NULL, NULL, NULL, NULL, 0) == -1);
    assert(message_build(&m, NULL, NULL, "", NULL, 0) == -1);
    assert(message_build(NULL, NULL, NULL, "PING", NULL, 0) == -1);
    {
        const char *const params[] = { "x" };
        assert(message_build(&m, NULL, NULL, "PING", params,
                             IRC_MAX_PARAMS + 1) == -1);
        assert(message_build(&m, NULL, NULL, "PING", params, -1) == -1);
        assert(message_build(&m, NULL, NULL, "PING", NULL, 1) == -1);
    }

    /* --- the formatter RE-RENDERS: it never echoes raw --- */
    /* This is the property the previous draft contradicted itself about. If the
     * formatter echoed m.raw, the 2.4 internal tags below would be relayed to
     * a client, which 2.4 forbids outright. */
    {
        const char *const tagged =
            "@irc-serve-origin=irc.a;irc-serve-epoch=1;irc-serve-id=2;"
            "irc-serve-hops=0 :irc.a PRIVMSG #c :hi";
        assert(message_parse(tagged, &m) == 0);
        /* m.raw really does still hold the internal tags: the formatter had
         * every opportunity to echo them. */
        assert(strstr(m.raw, "irc-serve-origin") != NULL);

        /* Stripping the internal tags is the relay path's job (Phase 6); here
         * it is simulated with a plain field assignment. Note that the ':' on
         * the body is NOT re-emitted: it is a marker, not data, and is only
         * written back when the value needs it. "hi" re-parses identically
         * without it, so the render is minimal and still lossless. */
        m.tags = NULL;
        const size_t n = message_format(&m, out, sizeof out);
        assert(n == strlen(":irc.a PRIVMSG #c hi"));
        assert(strcmp(out, ":irc.a PRIVMSG #c hi") == 0);
        assert(strstr(out, "irc-serve-") == NULL);
        assert(strstr(out, "epoch") == NULL);
        message_free(&m);
    }
    /* The output derives from the fields, not from raw: replacing the tag
     * block changes the output, and replacing the command does too. */
    assert(message_parse("@a=1 :irc.a PING x", &m) == 0);
    m.tags = "b=2";
    assert_format(&m, "@b=2 :irc.a PING x");
    m.command = (char *)"PONG";
    assert_format(&m, "@b=2 :irc.a PONG x");
    message_free(&m);

    /* A parsed line's terminator is not re-emitted. */
    assert(message_parse("NICK alice\r\n", &m) == 0);
    assert_format(&m, "NICK alice");
    message_free(&m);

    /* --- params needing the ':' marker get it, and only the last may --- */
    /* The ':' marker is a marker, not data: it is written back only when the
     * value needs it to survive a re-parse. These are the cases where it
     * does and does not. */
    {
        const char *const params[] = { "#c", "hi" };
        assert(message_build(&m, NULL, NULL, "PRIVMSG", params, 2) == 0);
        assert_format(&m, "PRIVMSG #c hi"); /* no space, so no marker needed */
        assert_round_trip("PRIVMSG #c :hi"); /* and it re-parses the same */
        assert_round_trip("PRIVMSG #c hi");
        message_free(&m);
    }
    {
        /* A space forces the marker. */
        const char *const params[] = { "#c", "a b" };
        assert(message_build(&m, NULL, NULL, "PRIVMSG", params, 2) == 0);
        assert_format(&m, "PRIVMSG #c :a b");
        message_free(&m);
    }
    {
        /* An empty final param must keep its position. */
        const char *const params[] = { "#c", "" };
        assert(message_build(&m, NULL, NULL, "PRIVMSG", params, 2) == 0);
        assert_format(&m, "PRIVMSG #c :");
        message_free(&m);
    }
    {
        /* A final param already starting with ':' is escaped, so the leading
         * character survives a re-parse. */
        const char *const params[] = { ":colon" };
        assert(message_build(&m, NULL, NULL, "PRIVMSG", params, 1) == 0);
        assert_format(&m, "PRIVMSG ::colon");
        assert_round_trip("PRIVMSG ::colon");
        message_free(&m);
    }
    {
        /* A non-final param that cannot be represented is refused, not
         * silently reshaped. */
        const char *const params[] = { "a b", "c" };
        assert(message_build(&m, NULL, NULL, "PRIVMSG", params, 2) == 0);
        out[0] = 'X';
        assert(message_format(&m, out, sizeof out) == 0);
        assert(out[0] == '\0');
        message_free(&m);

        const char *const params2[] = { ":early", "c" };
        assert(message_build(&m, NULL, NULL, "PRIVMSG", params2, 2) == 0);
        assert(message_format(&m, out, sizeof out) == 0);
        message_free(&m);

        const char *const params3[] = { "", "c" };
        assert(message_build(&m, NULL, NULL, "PRIVMSG", params3, 2) == 0);
        assert(message_format(&m, out, sizeof out) == 0);
        message_free(&m);
    }
    {
        /* A 15th param is colonned when it holds a separator, and bare when it
         * does not -- both re-parse to the same 15 params. */
        const char *const params[15] = { "1", "2",  "3",  "4",  "5",
                                         "6", "7",  "8",  "9",  "10",
                                         "11", "12", "13", "14", "a b" };
        assert(message_build(&m, NULL, NULL, "CMD", params, 15) == 0);
        assert_format(&m,
                      "CMD 1 2 3 4 5 6 7 8 9 10 11 12 13 14 :a b");
        assert_round_trip("CMD 1 2 3 4 5 6 7 8 9 10 11 12 13 14 :a b");
        message_free(&m);

        const char *const bare[15] = { "1", "2",  "3",  "4",  "5",
                                       "6", "7",  "8",  "9",  "10",
                                       "11", "12", "13", "14", "15" };
        assert(message_build(&m, NULL, NULL, "CMD", bare, 15) == 0);
        assert_format(&m, "CMD 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15");
        assert_round_trip("CMD 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15");
        message_free(&m);
    }

    /* --- the formatter can never emit a line break, whatever the caller built
     * ---. This is the line-injection defence, and it lives at the seam. */
    {
        const char *const params[] = { "#c", "a\rb" };
        assert(message_build(&m, NULL, NULL, "PRIVMSG", params, 2) == 0);
        out[0] = 'X';
        assert(message_format(&m, out, sizeof out) == 0);
        assert(out[0] == '\0');
        message_free(&m);

        const char *const nparams[] = { "#c", "a\nb" };
        assert(message_build(&m, NULL, NULL, "PRIVMSG", nparams, 2) == 0);
        assert(message_format(&m, out, sizeof out) == 0);
        message_free(&m);

        assert(message_build(&m, NULL, "irc.a\rb", "PING", NULL, 0) == 0);
        assert(message_format(&m, out, sizeof out) == 0);
        message_free(&m);

        assert(message_build(&m, NULL, NULL, "PI\nNG", NULL, 0) == 0);
        assert(message_format(&m, out, sizeof out) == 0);
        message_free(&m);

        /* A tag block containing a separator would break the framing. */
        assert(message_build(&m, "a=1 2", NULL, "PING", NULL, 0) == 0);
        assert(message_format(&m, out, sizeof out) == 0);
        message_free(&m);
        /* And so would a tag block that already carries the '@'. */
        assert(message_build(&m, "@a=1", NULL, "PING", NULL, 0) == 0);
        assert(message_format(&m, out, sizeof out) == 0);
        message_free(&m);
        /* An empty prefix string is treated as no prefix, not as ":". */
        assert(message_build(&m, NULL, "", "PING", NULL, 0) == 0);
        assert_format(&m, "PING");
        message_free(&m);
        /* A prefix already starting with ':' would be re-prefixed wrongly. */
        assert(message_build(&m, NULL, ":irc.a", "PING", NULL, 0) == 0);
        assert(message_format(&m, out, sizeof out) == 0);
        message_free(&m);
    }

    /* --- capacity: refused, never truncated, and never partially written --- */
    {
        const char *const params[] = { "#c", "hello world" };
        assert(message_build(&m, NULL, "irc.a", "PRIVMSG", params, 2) == 0);
        const size_t need = strlen(":irc.a PRIVMSG #c :hello world") + 1;
        assert(message_format(&m, out, need) == need - 1);
        assert(strcmp(out, ":irc.a PRIVMSG #c :hello world") == 0);
        /* One byte short: refuse, and leave nothing behind. */
        memset(out, 'X', sizeof out);
        assert(message_format(&m, out, need - 1) == 0);
        assert(out[0] == '\0');
        message_free(&m);
    }
    out[0] = 'X';
    assert(message_format(NULL, out, sizeof out) == 0);
    assert(message_format(&m, NULL, sizeof out) == 0);
    assert(message_format(&m, out, 0) == 0);
    {
        /* A message with no command renders nothing. */
        message_t bad;
        memset(&bad, 0, sizeof bad);
        assert(message_format(&bad, out, sizeof out) == 0);
        bad.command = "";
        assert(message_format(&bad, out, sizeof out) == 0);
        bad.command = "PING";
        bad.nparams = IRC_MAX_PARAMS + 1;
        assert(message_format(&bad, out, sizeof out) == 0);
    }

    /* --- the round-trip property --- */
    assert_round_trip("PING");
    assert_round_trip("NICK alice");
    assert_round_trip("JOIN #chan");
    assert_round_trip(":irc.a PRIVMSG #chan :hi");
    assert_round_trip("@a=1 :irc.b PONG :token");
    assert_round_trip("@a=1;b=2 :irc.b PONG x y z");
    assert_round_trip("CMD a b c d e f g h i j k l m n o p");
    assert_round_trip("CMD a b c d e f g h i j k l m n :tail here");

    /* The values 3.2 names: a tag value and a param value each containing a
     * space, ';', ':' and a backslash, all through parse -> format -> parse. */
    {
        const char *const params[] = {
            "#chan",            /* a ':' sigil */
            "nick!user@host",   /* an '@', which qualified names depend on */
            "a;b",              /* ';' */
            "c:d",              /* ':' */
            "back\\slash",      /* a literal backslash */
            "a b;c:d\\e",       /* all four at once, in the final param */
        };
        /* tags[] holds the block in wire form, i.e. already escaped. */
        assert(message_build(&m, "note=a\\sb\\:c:d\\\\e", "irc.a!u@h",
                             "PrIvMsG", params, 6) == 0);
        assert_format(&m,
                      "@note=a\\sb\\:c:d\\\\e :irc.a!u@h PRIVMSG #chan "
                      "nick!user@host a;b c:d back\\slash :a b;c:d\\e");
        {
            /* One leg of the round trip: the rendered line re-parses to the
             * same values, and the tag lookup returns the DECODED value. */
            char line[IRC_MAX_LINE + 64];
            const size_t n = message_format(&m, line, sizeof line);
            assert(n > 0);
            assert(message_parse(line, &r) == 0);
            assert(strcmp(r.command, "PRIVMSG") == 0);
            assert(strcmp(r.prefix, "irc.a!u@h") == 0);
            assert(strcmp(r.tags, "note=a\\sb\\:c:d\\\\e") == 0);
            assert(r.nparams == 6);
            for (int i = 0; i < 6; i++) {
                assert(strcmp(r.params[i], params[i]) == 0);
            }
            char value[64];
            assert(message_tag_get(&r, "note", value, sizeof value) == 0);
            assert(strcmp(value, "a b;c:d\\e") == 0);
            /* The decoded value re-renders to the same wire form, so the
             * escaping is a genuine two-way round trip. */
            char rescaped[64];
            assert(message_tag_escape(value, rescaped, sizeof rescaped) > 0);
            assert(strcmp(rescaped, "a\\sb\\:c:d\\\\e") == 0);
            message_free(&r);
        }
        assert_round_trip("PRIVMSG #chan nick!user@host a;b c:d "
                          "back\\slash :a b;c:d\\e");
        message_free(&m);
    }
    /* A value that is exactly a lone backslash, in a tag and in a param. In
     * the tag the wire form is '\\' -- two characters -- because a literal
     * backslash is SENT escaped. In a param there is no escaping layer, so the
     * value is the single character. */
    {
        const char *const params[] = { "#c", "\\" };
        assert(message_build(&m, "k=\\\\", NULL, "PRIVMSG", params, 2) == 0);
        assert_format(&m, "@k=\\\\ PRIVMSG #c \\");
        {
            char line[256];
            assert(message_format(&m, line, sizeof line) > 0);
            assert(message_parse(line, &r) == 0);
            char value[64];
            /* Unescaping '\\\\' yields ONE backslash, not zero. */
            assert(strcmp(r.tags, "k=\\\\") == 0);
            assert(message_tag_get(&r, "k", value, sizeof value) == 0);
            assert(strcmp(value, "\\") == 0);
            assert(strcmp(r.params[1], "\\") == 0);
            /* And re-escaping that single backslash gives the wire form back. */
            char re[64];
            assert(message_tag_escape(value, re, sizeof re) == 2);
            assert(strcmp(re, "\\\\") == 0);
            message_free(&r);
        }
        message_free(&m);
    }

    /* --- IRCv3 escaping, serialize direction --- */
    {
        char e[64];
        /* A COLON IS NOT ESCAPED. IRCv3's table is ';' -> \:, ' ' -> \s,
         * '\' -> \\, CR -> \r, LF -> \n, and everything else raw -- so a
         * colon is one of "everything else". This asserted "\:" and "\;",
         * which is the wrong table in BOTH directions and was asserted here
         * for months. The assertion is corrected rather than the behaviour. */
        assert(message_tag_escape(":", e, sizeof e) == 1);
        assert(strcmp(e, ":") == 0);
        assert(message_tag_escape(";", e, sizeof e) == 2);
        assert(strcmp(e, "\\:") == 0);
        assert(message_tag_escape(" ", e, sizeof e) == 2);
        assert(strcmp(e, "\\s") == 0);
        assert(message_tag_escape("\\", e, sizeof e) == 2);
        assert(strcmp(e, "\\\\") == 0);
        assert(message_tag_escape("\r", e, sizeof e) == 2);
        assert(strcmp(e, "\\r") == 0);
        assert(message_tag_escape("\n", e, sizeof e) == 2);
        assert(strcmp(e, "\\n") == 0);
        /* Every escapable byte at once, in order, with the colon raw: the
         * value is ':' ';' ' ' '\\' CR LF. */
        assert(message_tag_escape(":; \\\r\n", e, sizeof e) == 11);
        assert(strcmp(e, ":\\:\\s\\\\\\r\\n") == 0);
        /* Nothing to escape stays byte-identical. */
        assert(message_tag_escape("plain", e, sizeof e) == 5);
        assert(strcmp(e, "plain") == 0);
        /* An empty value is empty, not a failure. */
        assert(message_tag_escape("", e, sizeof e) == 0);
        assert(e[0] == '\0');
        /* Never truncates: a cap one byte short is a refusal. */
        assert(message_tag_escape("ab", e, 3) == 2);
        assert(strcmp(e, "ab") == 0);
        assert(message_tag_escape("ab", e, 2) == 0);
        assert(e[0] == '\0');
        /* An escapable byte costs THREE bytes on the wire ('a', '\\', ':') and
         * a fourth for the NUL, so cap 4 is exactly enough and cap 3 is one
         * short. The byte tested is ';' rather than ':' because ':' is no
         * longer escaped at all: with the corrected table "a:" needs two. */
        assert(message_tag_escape("a:", e, 3) == 2);
        assert(strcmp(e, "a:") == 0);
        assert(message_tag_escape("a;", e, 4) == 3);
        assert(strcmp(e, "a\\:") == 0);
        assert(message_tag_escape("a;", e, 3) == 0);
        assert(e[0] == '\0');
        assert(message_tag_escape(NULL, e, sizeof e) == 0);
        assert(message_tag_escape("a", NULL, sizeof e) == 0);
        assert(message_tag_escape("a", e, 0) == 0);
    }

    /* --- IRCv3 escaping, deserialize direction --- */
    {
        char u[64];
        /* '\:' is the encoding of a SEMICOLON, not of a colon. */
        assert(message_tag_unescape("\\:", u, sizeof u) == 0);
        assert(strcmp(u, ";") == 0);
        /* '\;' is not a valid encoding at all, and the specification's rule for
         * an invalid escape is to DROP THE BACKSLASH, so this is a semicolon
         * too. Refusing the block instead would make this node stricter than
         * the specification and would drop a peer's message over a byte that
         * costs nothing. */
        assert(message_tag_unescape("\\;", u, sizeof u) == 0);
        assert(strcmp(u, ";") == 0);
        assert(message_tag_unescape("\\s", u, sizeof u) == 0);
        assert(strcmp(u, " ") == 0);
        assert(message_tag_unescape("\\\\", u, sizeof u) == 0);
        assert(strcmp(u, "\\") == 0);
        assert(message_tag_unescape("\\r", u, sizeof u) == 0);
        assert(strcmp(u, "\r") == 0);
        assert(message_tag_unescape("\\n", u, sizeof u) == 0);
        assert(strcmp(u, "\n") == 0);
        /* The lone-trailing-backslash rule: dropped on the way in, and a
         * literal backslash is therefore SENT as '\\' (above). */
        assert(message_tag_unescape("\\", u, sizeof u) == 0);
        assert(strcmp(u, "") == 0);
        assert(message_tag_unescape("ab\\", u, sizeof u) == 0);
        assert(strcmp(u, "ab") == 0);
        /* An escape before a character outside the set DROPS the backslash and
         * yields the character, so `\b` is `b`. */
        assert(message_tag_unescape("a\\qb", u, sizeof u) == 0);
        assert(strcmp(u, "aqb") == 0);
        /* Refuses rather than truncating. */
        assert(message_tag_unescape("abc", u, 3) == -1);
        assert(u[0] == '\0');
        assert(message_tag_unescape("abc", u, 4) == 0);
        assert(message_tag_unescape(NULL, u, sizeof u) == -1);
        assert(message_tag_unescape("a", NULL, sizeof u) == -1);
        assert(message_tag_unescape("a", u, 0) == -1);
    }

    /* Every escaped form above unescapes back to its original value, and
     * re-escaping gives the identical wire bytes. That is the both-directions
     * requirement, as a property rather than as six pairs. */
    {
        static const char *const values[] = {
            "",       "plain",     ":",       ";",        " ",       "\\",
            "\r",     "\n",        ":; \\\r\n", "a=b",  "a;b",     "a\\b",
            "\\s",    "\\\\",      "irc.a",   "a b c",   ";;;",     "\\:",
        };
        char w[64];
        char d[64];
        char re[64];
        for (size_t i = 0; i < sizeof values / sizeof values[0]; i++) {
            const size_t n = message_tag_escape(values[i], w, sizeof w);
            assert(message_tag_unescape(w, d, sizeof d) == 0);
            /* escape -> unescape is the identity, except for the documented
             * lone-trailing-backslash drop, which cannot arise here because
             * escape never emits one. */
            assert(strcmp(d, values[i]) == 0);
            /* And unescape -> escape returns the same wire bytes. */
            assert(message_tag_escape(d, re, sizeof re) == n);
            assert(strcmp(re, w) == 0);
        }
    }

    /* --- serializing a whole block --- */
    {
        char block[128];
        const message_tag_t tags[] = {
            { "a", "1" },
            { "b", "x y" },     /* a space must be escaped */
            { "c", "p;q" },
            { "d", NULL },      /* NULL means the empty value */
            { NULL, "skipped" }, /* a NULL key is skipped */
        };
        const size_t n = message_tags_format(tags, 5, block, sizeof block);
        assert(n == strlen("a=1;b=x\\sy;c=p\\:q;d="));
        assert(strcmp(block, "a=1;b=x\\sy;c=p\\:q;d=") == 0);

        /* Reject rather than truncate. */
        assert(message_tags_format(tags, 5, block, n) == 0);
        assert(block[0] == '\0');
        assert(message_tags_format(tags, 5, block, n + 1) == n);
        /* A block with no usable pair is not a block. */
        const message_tag_t none[] = { { NULL, "x" } };
        assert(message_tags_format(none, 1, block, sizeof block) == 0);
        assert(message_tags_format(tags, 0, block, sizeof block) == 0);
        assert(message_tags_format(NULL, 1, block, sizeof block) == 0);
        assert(message_tags_format(tags, 1, NULL, sizeof block) == 0);
        assert(message_tags_format(tags, 1, block, 0) == 0);
    }

    /* --- the 2.4 internal tag set, serialized byte-exactly --- */
    {
        irc_serve_tags_t t;
        char block[256];
        memset(&t, 0, sizeof t);
        strcpy(t.origin, "irc.a");
        t.epoch = 3;
        t.id = 41;
        t.hops = 2;
        const size_t n = irc_serve_tags_format(&t, block, sizeof block);
        assert(n == strlen("irc-serve-origin=irc.a;irc-serve-epoch=3;"
                           "irc-serve-id=41;irc-serve-hops=2"));
        assert(strcmp(block,
                      "irc-serve-origin=irc.a;irc-serve-epoch=3;"
                      "irc-serve-id=41;irc-serve-hops=2") == 0);
        /* The frozen order is origin, epoch, id, hops. */
        assert(strncmp(block, "irc-serve-origin=", 17) == 0);
        assert(strstr(block, ";irc-serve-epoch=") != NULL);
        assert(strstr(block, ";irc-serve-id=") != NULL);
        assert(strstr(block, ";irc-serve-hops=") != NULL);

        /* And it round-trips through a real line. */
        char line[512];
        int w = snprintf(line, sizeof line, "@%s :irc.a PRIVMSG #c :hi", block);
        assert(w > 0);
        assert(message_parse(line, &m) == 0);
        {
            irc_serve_tags_t back;
            assert(irc_serve_tags_parse(&m, &back) == 0);
            assert(strcmp(back.origin, t.origin) == 0);
            assert(back.epoch == t.epoch);
            assert(back.id == t.id);
            assert(back.hops == t.hops);
        }
        message_free(&m);

        /* id 0 is reserved as "unset", so it is never serialized. */
        t.id = 0;
        assert(irc_serve_tags_format(&t, block, sizeof block) == 0);
        assert(block[0] == '\0');
        t.id = 1;
        /* An empty or over-long origin is refused. */
        t.origin[0] = '\0';
        assert(irc_serve_tags_format(&t, block, sizeof block) == 0);
        memset(t.origin, 'a', sizeof t.origin);
        assert(irc_serve_tags_format(&t, block, sizeof block) == 0);
        memset(t.origin, 'a', (size_t)IRC_MAX_SERVER_NAME);
        t.origin[IRC_MAX_SERVER_NAME] = '\0';
        assert(irc_serve_tags_format(&t, block, sizeof block) > 0);
        assert(irc_serve_tags_format(NULL, block, sizeof block) == 0);
        assert(irc_serve_tags_format(&t, NULL, sizeof block) == 0);
        assert(irc_serve_tags_format(&t, block, 0) == 0);
        assert(irc_serve_tags_valid(NULL) == 0);
    }

    /* --- the worst-case tag overhead, measured --- */
    {
        /* IRC_MAX_TAG_OVERHEAD is derived from the value bounds in message.h.
         * Formatting the largest LEGAL tag set and measuring it keeps the
         * constant honest: raise a bound without re-deriving the constant and
         * this fails here rather than on the network. */
        irc_serve_tags_t t;
        char block[512];
        memset(&t, 0, sizeof t);
        memset(t.origin, 'a', (size_t)IRC_MAX_SERVER_NAME);
        t.origin[IRC_MAX_SERVER_NAME] = '\0';
        t.epoch = UINT64_MAX;
        t.id = UINT64_MAX;
        t.hops = UINT32_MAX;
        const size_t n = irc_serve_tags_format(&t, block, sizeof block);
        assert(n > 0);
        /* '@' and the one space after the block are the rest of the overhead. */
        assert(n + 2 <= (size_t)IRC_MAX_TAG_OVERHEAD);
        /* ...and the constant is not wastefully large either. */
        assert(n + 2 == (size_t)IRC_MAX_TAG_OVERHEAD);
    }

    /* --- the relay cap arithmetic (3.2, "Relay truncation policy") --- */
    {
        /* The cap is the on-wire cap less the worst-case tag block, and the
         * two bytes of CRLF still have to fit inside the on-wire cap. */
        assert(IRC_MAX_RELAY_LINE < IRC_MAX_LINE);
        assert((size_t)IRC_MAX_RELAY_LINE + 2 <= (size_t)IRC_MAX_LINE);
        assert(IRC_MAX_TAG_OVERHEAD == IRC_MAX_LINE - IRC_MAX_RELAY_LINE);

        /* A client line that exactly fills the cap renders; one byte less of
         * capacity refuses. Phase 6 drops such a line with a client-side
         * notice rather than truncating it, which is NOT implemented here. */
        const char head[] = "PRIVMSG #c ";
        const size_t headlen = sizeof head - 1;
        const size_t bodylen = (size_t)IRC_MAX_RELAY_LINE - headlen;
        char body[IRC_MAX_RELAY_LINE + 1];
        memset(body, 'a', bodylen);
        body[bodylen] = '\0';
        const char *const params[] = { "#c", body };
        assert(message_build(&m, NULL, NULL, "PRIVMSG", params, 2) == 0);
        assert(message_format(&m, out, (size_t)IRC_MAX_RELAY_LINE + 1) ==
               (size_t)IRC_MAX_RELAY_LINE);
        assert(message_format(&m, out, (size_t)IRC_MAX_RELAY_LINE) == 0);
        assert(out[0] == '\0');
        message_free(&m);

        /* The ~500-byte case 3.2 calls out stays legal under the relay cap, and
         * a line of that size survives the whole seam. */
        memset(body, 'a', 500);
        body[500] = '\0';
        assert(message_build(&m, NULL, NULL, "PRIVMSG", params, 2) == 0);
        char line[IRC_MAX_RELAY_LINE + 8];
        assert(message_format(&m, line, sizeof line) == headlen + 500);
        message_free(&m);
        /* A fresh message_t for the parse: reusing `m` here would drop the
         * built message on the floor (parse zeroes *out without freeing it). */
        assert(message_parse(line, &r) == 0);
        assert(message_format(&r, out, (size_t)IRC_MAX_RELAY_LINE + 1) > 0);
        message_free(&r);

        /* An inbound line right at the cap also formats, which is the case the
         * relay path actually hits. Its render is one byte shorter than the
         * input because the trailing ':' is a marker, not data, and is not
         * re-emitted when the value does not need it. The body is one byte
         * shorter here so that the ':' it needs brings the line back to
         * exactly the cap. */
        memset(body, 'a', bodylen);
        body[bodylen] = '\0';
        assert(message_build(&m, NULL, NULL, "PRIVMSG", params, 2) == 0);
        {
            char capped[IRC_MAX_RELAY_LINE + 8];
            const int w = snprintf(capped, sizeof capped, "PRIVMSG #c :%.*s",
                                   (int)(bodylen - 1), body);
            assert(w == (int)IRC_MAX_RELAY_LINE);
            message_free(&m);
            assert(message_parse(capped, &r) == 0);
            assert(message_format(&r, out, (size_t)IRC_MAX_RELAY_LINE + 1) >
                   0);
            assert(out[0] != '\0');
        }
        message_free(&r);
    }

    return 0;
}
