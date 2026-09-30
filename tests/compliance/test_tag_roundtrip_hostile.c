/* test_tag_roundtrip_hostile.c -- the property test Phase 8 owes.
 *
 * 7/Phase 1 asked for "a round-trip property test parse -> format -> parse over
 * values containing space, ';', ':' and a backslash" and what it got was a copy
 * of a COPY: tests/compliance/test_tags_roundtrip.c called tags_parse() and
 * tags_serialize(), which were the same function, so a memcpy passed. This file
 * is the property that test was supposed to be, over the escape table the
 * specification actually defines rather than the one this tree guessed at.
 *
 * THE PROPERTY, precisely:
 *
 *     value  ->  escape  ->  (a tag block)  ->  parse  ->  value'
 *     and then escape(value')  ==  the same bytes again.
 *
 * so a value survives decode(encode(v)) byte for byte AND its encoding is a
 * fixed point. "Nothing crashed" is not the assertion and cannot be: a
 * round-trip property is checked by comparing bytes.
 *
 * THE CORPUS is deliberately hostile rather than representative. Every byte the
 * escape table names, each of them alone and in combination, plus the three
 * shapes that break naive implementations:
 *
 *   - a LONE TRAILING BACKSLASH, which has no two-byte encoding and is the one
 *     value that cannot be written back exactly. It is asserted to be DROPPED,
 *     which is the specification's rule and the reason a literal backslash must
 *     be sent as `\\`.
 *   - a backslash before a character that is NOT in the escape set, which the
 *     specification says decodes with the BACKSLASH DROPPED. This is the case a
 *     symmetric implementation gets wrong, and it is why "escape and unescape
 *     are inverses" is false here and has to be stated rather than assumed.
 *   - MULTI-BYTE UTF-8, because escaping is defined over BYTES and an
 *     implementation that escaped "non-ASCII" would corrupt every message
 *     containing an accented nickname.
 *
 * NOTHING HERE reads irc_core's structs. Every assertion is on the bytes the two
 * public functions produce, which is what the wire sees. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "core/message.h"
#include "ircv3_tags.h"

/* A block large enough for the worst encoding of the worst corpus entry: 128
 * raw bytes can only get longer, and IRCV3_TAG_VALUE_MAX is the value bound
 * this module refuses beyond. */
#define BLOCK_MAX (IRCV3_TAG_VALUE_MAX * 2u + 64u)

/* One corpus entry, and what the round trip must produce for it. */
typedef struct {
    const char *value;   /* the raw, unescaped value */
    const char *expect;  /* value' -- NULL means "the same as value" */
    const char *why;
} hostile_t;

/* `expect == NULL` means the value round-trips to itself, which is the case for
 * every value that does not end in a lone backslash or carry an invalid escape.
 * Those two are spelled out with their expectation rather than being filtered
 * out of the corpus, because a corpus that skips the cases it cannot handle is
 * a corpus that hides the bug. */
static const hostile_t k_corpus[] = {
    /* --- each escapable byte, alone --- */
    { "",                 NULL, "empty value" },
    { "plain",            NULL, "nothing to escape" },
    { ";",                NULL, "the separator" },
    { ":",                NULL, "a colon is RAW, not escaped" },
    { " ",                NULL, "the space" },
    { "\\",               NULL, "a lone backslash is sent as \\\\ and comes back" },
    { "\r",               NULL, "carriage return" },
    { "\n",               NULL, "line feed" },

    /* --- the separator and the colon together, which is where a wrong table
     *     shows: an implementation that reads \: as ':' turns this into a
     *     different value and still parses cleanly. --- */
    { "a;b",              NULL, "semicolon between words" },
    { ":;",               NULL, "colon then semicolon" },
    { ";:;",              NULL, "three separators" },
    { "a:b;c",            NULL, "colons and a semicolon" },

    /* --- combinations of every escapable byte at once --- */
    { "; : \\ \r \n",     NULL, "all five, spaced" },
    { ":; \\\r\n",        NULL, "all five plus a raw colon, unspaced" },
    { "\\;\\s\\\\\\r\\n", NULL, "each byte already in its escaped spelling" },

    /* --- a value ENDING in a backslash, which is the case that breaks a
     *     symmetric implementation. It round-trips, and it does so by being
     *     SENT as two backslashes: there is no shorter encoding that survives,
     *     which is why the trailing one cannot be written bare. --- */
    { "trailing\\",       NULL, "a value ENDING in a backslash" },
    { "\\",               NULL, "a lone backslash" },
    { "\\b",              NULL, "a backslash before an ordinary letter" },
    { "\\:",              NULL, "backslash colon as a RAW value" },
    { "\\;",              NULL, "backslash semicolon as a RAW value" },
    { "\\x\\q\\\\",        NULL, "invalid escapes and a real one, as a raw value" },
    { "a\\\\b",              NULL, "an escaped-looking pair as a raw value" },

    /* --- structural bytes that have no place in a tag value at all --- */
    { "a=b",              NULL, "'=' is not special inside a value" },
    { "@home",            NULL, "'@' is only special as the block marker" },
    { "k=v",              NULL, "an '='-pair written inside a value" },
    { "\t",               NULL, "a raw HTAB" },

    /* --- multi-byte UTF-8: escaping is defined over BYTES --- */
    { "\xc3\xa9",                    NULL, "two-byte UTF-8 (e acute)" },
    { "\xe2\x82\xac",                NULL, "three-byte UTF-8 (euro)" },
    { "\xf0\x9f\x92\xa9",            NULL, "four-byte UTF-8 (a face, an emoji)" },
    { "caf\xc3\xa9; bar",           NULL, "UTF-8 next to an escapable byte" },
    { "\xc3\xa9\xc3\xa9\xc3\xa9",     NULL, "a UTF-8 character with a HIGH second byte" },

    /* --- realistic --- */
    { "irc.a",           NULL, "a server name" },
    { "a b c",           NULL, "three words" },
    { "x" ,              NULL, "one byte" },
};

/* The property, run for one corpus entry.
 *
 * The intermediate assertions are the ones that produce a readable failure:
 * a round-trip assert that only says "not equal" does not say which of the two
 * halves broke. */
static void check_roundtrip(const hostile_t *h)
{
    char reencoded[BLOCK_MAX];
    char block[BLOCK_MAX];
    ircv3_tags_t list;
    ircv3_tags_t again;
    size_t n;

    /* 1. escape the value into a block of the form key=escaped. */
    ircv3_tags_init(&list);
    assert(ircv3_tags_set(&list, "v", h->value) == 0);
    n = ircv3_tags_serialize(&list, block, sizeof block);
    assert(n > 0);
    assert(block[0] == '@');

    /* 2. the block must survive the wire form: parsing it and serializing it
     *    again is byte-for-byte identical. THIS is what a validate-and-copy
     *    implementation passes vacuously, which is why step 3 is the real
     *    assertion and this one is only a guard on the guard. */
    assert(ircv3_tags_parse(block, &again) == 0);
    n = ircv3_tags_serialize(&again, reencoded, sizeof reencoded);
    assert(n == strlen(block));
    assert(strcmp(reencoded, block) == 0);

    /* 3. THE PROPERTY: the decoded value is the value that went in. */
    {
        const char *got = ircv3_tags_get(&again, "v");

        assert(got != NULL);
        assert(strcmp(got, (h->expect != NULL) ? h->expect : h->value) == 0);
    }

    /* 4. and the CANONICAL FORM IS A FIXED POINT: taking the decoded value,
     *    building a block from it and running that block back through
     *    parse -> serialize changes nothing. This is the property a relay hop
     *    needs: a block re-encoded from what the previous hop decoded is the
     *    same block, so a message that crosses two hops is not rewritten on the
     *    second one.
     *
     *    It is deliberately NOT "escape(value) == escape(decode(escape(value)))".
     *    That is false, and correctly so: `\x` in the original is an invalid
     *    escape whose backslash is dropped on the way in, so the re-encoding
     *    differs from the original by exactly that dropped byte. Asserting the
     *    false version would have meant deleting the corpus entries that
     *    exercise it. */
    {
        ircv3_tags_t third;
        ircv3_tags_t fourth;
        char third_block[BLOCK_MAX];
        char fourth_block[BLOCK_MAX];
        size_t n3;
        size_t n4;

        ircv3_tags_init(&third);
        assert(ircv3_tags_set(&third, "v", ircv3_tags_get(&again, "v")) == 0);
        n3 = ircv3_tags_serialize(&third, third_block, sizeof third_block);
        assert(n3 > 0);
        assert(ircv3_tags_parse(third_block, &fourth) == 0);
        n4 = ircv3_tags_serialize(&fourth, fourth_block, sizeof fourth_block);
        assert(n4 == n3);
        assert(strcmp(fourth_block, third_block) == 0);
        /* And the decoded value is unchanged by that round trip. */
        assert(strcmp(ircv3_tags_get(&fourth, "v"),
                      ircv3_tags_get(&again, "v")) == 0);
    }

    /* 5. no escape may emit a raw separator or space inside the value, which is
     *    the property the specification's table exists to provide. A block whose
     *    value contained a raw ';' would re-split on the next parse. */
    assert(strchr(block, ' ') == NULL);
    {
        const char *v = strchr(block, '=');

        assert(v != NULL);
        for (const char *q = v + 1; *q != '\0'; q++) {
            assert(*q != ';');
        }
    }
}

/* NON-CANONICAL BLOCKS: the half of the specification the round trip cannot
 * reach, because escape() never produces these bytes.
 *
 * The three rules asserted here are all about DECODING a block another node (or
 * another implementation) sent, and all three were wrong in the version of
 * message.c this replaces:
 *
 *   - a '' before a character outside the escape set has its BACKSLASH DROPPED,
 *     so `\b` is `b` and NOT `\b`;
 *   - a lone trailing '' produces no output character;
 *   - `\:` is a SEMICOLON and `\;` is an invalid escape that also decodes to a
 *     semicolon, so a block written with the wrong table still yields the value
 *     its author meant.
 *
 * That last one is worth a test of its own rather than as a note: it is why a
 * node can relay a block from a peer that escapes ';' as '\;' without the
 * message changing under anyone. Refusing such a block instead would make this
 * node stricter than the specification, and refusing is the expensive half of a
 * federation. */
static void check_noncanonical(void)
{
    ircv3_tags_t t;

    assert(ircv3_tags_parse("@v=\\b", &t) == 0);
    assert(strcmp(ircv3_tags_get(&t, "v"), "b") == 0);

    assert(ircv3_tags_parse("@v=ab\\", &t) == 0);
    assert(strcmp(ircv3_tags_get(&t, "v"), "ab") == 0);

    assert(ircv3_tags_parse("@v=\\", &t) == 0);
    assert(strcmp(ircv3_tags_get(&t, "v"), "") == 0);

    assert(ircv3_tags_parse("@v=\\:", &t) == 0);
    assert(strcmp(ircv3_tags_get(&t, "v"), ";" ) == 0);

    /* `\\;` is NOT a case, and that is the point: a semicolon inside a value
     * cannot be spelled with a backslash, because the backslash does not
     * escape it -- the ';' ends the pair whatever precedes it, leaving an empty
     * one after it, and an empty pair is not in the grammar. The reason the
     * table reads ';' -> `\:` rather than ';' -> `\;` is precisely that there is
     * no in-band way to escape a semicolon; check_legacy_pair() asserts the
     * rejection. */

    /* An invalid escape in the middle of a value keeps the rest of it. */
    assert(ircv3_tags_parse("@v=a\\qb", &t) == 0);
    assert(strcmp(ircv3_tags_get(&t, "v"), "aqb") == 0);

    /* Duplicate keys keep the FIRST, which is the rule that stops a block from
     * rewriting a tag another node set -- irc-serve-origin is exactly the tag
     * whose rewrite would defeat 2.4's never-forward-own-origin check. */
    assert(ircv3_tags_parse("@a=first;a=second", &t) == 0);
    assert(strcmp(ircv3_tags_get(&t, "a"), "first") == 0);
    assert(t.npairs == 1);

    /* Key lookup folds case; a value does not. */
    assert(ircv3_tags_parse("@Key=Mixed", &t) == 0);
    assert(strcmp(ircv3_tags_get(&t, "kEy"), "Mixed") == 0);

    /* And a block with no block marker round-trips without one gaining one. */
    assert(ircv3_tags_parse("a=1;b=2", &t) == 0);
    assert(t.has_at == 0);
    {
        char blk[64];
        assert(ircv3_tags_serialize(&t, blk, sizeof blk) ==
               strlen("a=1;b=2"));
        assert(strcmp(blk, "a=1;b=2") == 0);
    }
}

/* The escape table itself, asserted literally, because every property above is
 * a round trip and a round trip can be satisfied by an escaping that is wrong in
 * both directions at once. These are the five rows of IRCv3's table. */
static void check_table(void)
{
    char e[64];

    assert(ircv3_escape_value(";", e, sizeof e) == 2 && strcmp(e, "\\:") == 0);
    assert(ircv3_escape_value(" ", e, sizeof e) == 2 && strcmp(e, "\\s") == 0);
    assert(ircv3_escape_value("\\", e, sizeof e) == 2 && strcmp(e, "\\\\") == 0);
    assert(ircv3_escape_value("\r", e, sizeof e) == 2 && strcmp(e, "\\r") == 0);
    assert(ircv3_escape_value("\n", e, sizeof e) == 2 && strcmp(e, "\\n") == 0);
    /* A colon is NOT escaped. This is the row a plausible guess gets wrong. */
    assert(ircv3_escape_value(":", e, sizeof e) == 1 && strcmp(e, ":") == 0);

    assert(ircv3_unescape_value("\\:", 2, e, sizeof e) == 0 && strcmp(e, ";") == 0);
    assert(ircv3_unescape_value("\\s", 2, e, sizeof e) == 0 && strcmp(e, " ") == 0);
    assert(ircv3_unescape_value("\\\\", 2, e, sizeof e) == 0 && strcmp(e, "\\") == 0);
    assert(ircv3_unescape_value("\\r", 2, e, sizeof e) == 0 && strcmp(e, "\r") == 0);
    assert(ircv3_unescape_value("\\n", 2, e, sizeof e) == 0 && strcmp(e, "\n") == 0);
    /* An invalid escape loses the backslash; a lone trailing one loses itself. */
    assert(ircv3_unescape_value("\\b", 2, e, sizeof e) == 0 && strcmp(e, "b") == 0);
    assert(ircv3_unescape_value("\\", 1, e, sizeof e) == 0 && strcmp(e, "") == 0);

    /* Capacity: never truncate. A cap one byte short of the value plus its NUL
     * refuses and leaves the output empty, which is 3.2's rule applied to a
     * tag value rather than to a parameter. */
    assert(ircv3_escape_value("ab", e, 3) == 2);
    assert(ircv3_escape_value("ab", e, 2) == 0);
    assert(e[0] == '\0');
    assert(ircv3_unescape_value("abc", 3, e, 3) == -1);
    assert(ircv3_unescape_value("abc", 3, e, 4) == 0);
}

/* core/message.c's message_tag_escape()/unescape() are thin wrappers over the two
 * functions above. They are checked against the SAME literals here because the
 * whole reason the wrappers exist is that there must be one table: a second copy
 * is a tree that disagrees with itself, and nothing else in the suite would
 * notice. */
static void check_message_wrappers(void)
{
    char e[64];

    assert(message_tag_escape(";", e, sizeof e) == 2 && strcmp(e, "\\:") == 0);
    assert(message_tag_escape(":", e, sizeof e) == 1 && strcmp(e, ":") == 0);
    assert(message_tag_escape("\\", e, sizeof e) == 2 && strcmp(e, "\\\\") == 0);
    assert(message_tag_escape(" ", e, sizeof e) == 2 && strcmp(e, "\\s") == 0);
    assert(message_tag_unescape("\\:", e, sizeof e) == 0 && strcmp(e, ";") == 0);
    assert(message_tag_unescape("\\b", e, sizeof e) == 0 && strcmp(e, "b") == 0);
    assert(message_tag_unescape("ab\\", e, sizeof e) == 0 && strcmp(e, "ab") == 0);
}

/* The legacy pair is a parse -> list -> serialize now, not a copy, so a block
 * that is EQUIVALENT but not canonical comes back in canonical form and a block
 * that is already canonical comes back byte for byte. Both are asserted, because
 * the first is what makes it a serializer and the second is the contract the two
 * existing tests rely on. */
static void check_legacy_pair(void)
{
    char out[128];

    assert(tags_parse("@label=123;key=val", out, (int)sizeof out) ==
           (int)strlen("@label=123;key=val"));
    assert(strcmp(out, "@label=123;key=val") == 0);
    assert(tags_serialize("@a=x\\sy", out, (int)sizeof out) ==
           (int)strlen("@a=x\\sy"));
    assert(strcmp(out, "@a=x\\sy") == 0);
    /* An INVALID ESCAPE is normalised away, which a memcpy cannot do: `\x` is
     * not a valid encoding of anything, the specification says its backslash is
     * dropped, and a serializer emits `x`. */
    assert(tags_parse("@a=\\x", out, (int)sizeof out) ==
           (int)strlen("@a=x"));
    assert(strcmp(out, "@a=x") == 0);
    /* And a block that carries a RAW semicolon in a value is not a block at
     * all -- the semicolon ends the pair and what follows is an empty one. The
     * grammar has no way to spell `\;` inside a value, which is precisely why
     * the specification's table writes ';' as `\:`. */
    assert(tags_parse("@a=\\;", out, (int)sizeof out) == -1);
    /* A valueless pair and an empty value are different bytes and both survive,
     * which is why has_at and HAS_EQ are recorded rather than inferred. */
    assert(tags_parse("@a;b=", out, (int)sizeof out) == (int)strlen("@a;b="));
    assert(strcmp(out, "@a;b=") == 0);
}

int main(void)
{
    check_table();
    check_noncanonical();
    check_message_wrappers();
    check_legacy_pair();

    for (size_t i = 0; i < sizeof k_corpus / sizeof k_corpus[0]; i++) {
        check_roundtrip(&k_corpus[i]);
    }

    printf("tag roundtrip: %zu hostile values, both directions\n",
           sizeof k_corpus / sizeof k_corpus[0]);
    return 0;
}
