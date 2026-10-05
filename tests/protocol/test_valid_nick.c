/* valid_nick tests -- the nick charset rule that SERVER_DESIGN.md 5 says is
 * MISSING, and that 2.1's `nick@server` identity scheme is unsound without.
 *
 * parse_nick() performs no character validation at all: it returns 1 for
 * "NICK a@evil" and yields the nickname "a@evil". These tests pin the
 * predicate that closes that, and the last block demonstrates the gap
 * concretely against the real parse_nick(). */
#include <assert.h>
#include <string.h>

#include "core/message.h"
#include "protocol_parse.h"

static void assert_valid(const char *nick)
{
    assert(valid_nick(nick) == 1);
    /* The property 2.1 depends on: if '@' cannot appear in a nick, then
     * `nick@server` splits unambiguously at the LAST '@'. Asserting it per
     * input is what makes "nick@server is sound" a tested claim rather than an
     * assertion in a comment. */
    assert(strrchr(nick, '@') == NULL);
}

static void assert_invalid(const char *nick)
{
    assert(valid_nick(nick) == 0);
}

int main(void)
{
    char nick[128];

    /* --- ordinary nicknames are accepted --- */
    /* Note what is NOT here: "123" and "0" (leading digit), and "a:b", "a;b"
     * and "a:b.c" (embedded ':' or ';'). Those were legal under the first
     * version of the rule and are covered as rejects in the block below, so no
     * input has lost coverage -- the expectation moved with the rule. */
    static const char *const good[] = {
        "a",     "alice",  "bob",     "Bob",     "ALICE",
        "a_b",   "a-b",    "a.b",     "a'b",     "a^b",    "a`b",    "a[b",
        "a]b",   "a\\b",   "a\"b",    "a/b",     "a?b",    "a=b",    "a<b",
        "a>b",   "a$b",    "a%b",     "a,b",     "a*b",    "a(b",    "a)b",
        "a|b",   "a{b",    "a}b",     "a~b",
        "_",     "-",      ".",       "'",       "~",      "`",
        "caf\xc3\xa9",              /* UTF-8 is ordinary and legal */
    };
    for (size_t i = 0; i < sizeof good / sizeof good[0]; i++) {
        assert_valid(good[i]);
    }

    /* --- the illegal sigils: the exact cases 7/Phase 1 names --- */
    assert_invalid("a@evil");  /* the motivating case: breaks nick@server */
    assert_invalid("a#b");     /* channel sigils */
    assert_invalid("a&b");
    assert_invalid("a+b");
    assert_invalid("a!b");
    /* A nickname that is nothing but a sigil is invalid too. */
    assert_invalid("@");
    assert_invalid("#");
    assert_invalid("&");
    assert_invalid("+");
    assert_invalid("!");

    /* --- ':' and ';' anywhere in the nick --- */
    /* ':' is the prefix marker and the trailing-param marker, so a colon
     * inside a nick blurs both the construction of a prefix and its parse. */
    assert_invalid(":");
    assert_invalid(";");
    assert_invalid("a:b");
    assert_invalid("a;b");
    assert_invalid("a:b.c");
    assert_invalid("a:");      /* trailing colon */
    assert_invalid(":a");      /* leading colon */
    assert_invalid("a b:c");   /* both, plus a space */
    assert_invalid("a;b:c");

    /* --- a leading digit --- */
    /* RFC 2812 2.3.1: the first character is a letter or a "special", and a
     * digit is neither. The concrete reason is wire ambiguity -- ":123
     * PRIVMSG #c :hi" versus ":server 123 target :text". */
    assert_invalid("0");
    assert_invalid("1");
    assert_invalid("9");
    assert_invalid("123");
    assert_invalid("0abc");
    assert_invalid("1abc");
    assert_invalid("9zzz");
    assert_invalid("00");      /* not a leading-zero exemption: still a digit */
    /* The rule is FIRST-CHARACTER only. A digit after a legal opener is
     * ordinary, so these stay valid -- the asymmetry is the point. */
    assert_valid("a1");
    assert_valid("a123");
    assert_valid("z9");
    assert_valid("a0b1c2");
    assert_valid("bob2");

    /* --- whitespace and control characters --- */
    assert_invalid("a b");
    assert_invalid("a\tb");
    assert_invalid("a\rb");
    assert_invalid("a\nb");
    assert_invalid("a b ");
    assert_invalid("a\vb");
    assert_invalid("a\fb");
    assert_invalid(" ");
    assert_invalid("\t");
    {
        /* A control byte in the middle, built explicitly so the source is
         * unambiguous. Each array is NUL-terminated: valid_nick() takes a C
         * string, so an unterminated one is a read past the end. */
        const char soh[] = { 'a', '\x01', 'b', '\0' };
        assert_invalid(soh);
        const char del[] = { 'a', '\x7f', 'b', '\0' };
        assert_invalid(del);
        const char nul_mid[] = { 'a', '\0', 'b', '\0' };
        /* A NUL ends the C string, so the nickname is "a" and is valid; the
         * framing layer's job is to reject the NUL (message_parse_n does).
         * Asserting the C-string behaviour here keeps the two rules apart. */
        assert(valid_nick(nul_mid) == 1);
    }

    /* --- UTF-8 that is WELL FORMED: kept ---
     *
     * This block exists because the obvious way to refuse a raw 0x80-0x9F byte is to
     * refuse the RANGE, and `ā` is `0xC4 0x81`: its second byte is inside that very
     * range. A byte-range refusal eats every accented Latin character, Cyrillic and
     * Greek character on the network, so `ā` is asserted here BY NAME and in
     * isolation. It is the single input a "simplified" refusal gets wrong, and the
     * fault evidence for that lives in tests/integration/test_nick_utf8.c, where the
     * same nicks go out on the wire to a second client. */
    static const char *const utf8_ok[] = {
        "\xc4\x81",              /* a-macron: the 2-byte case, lead 0xC4 + 0x81 */
        "\xc3\xa9",              /* e-acute: the same in 3 bytes as C3 A9 */
        "caf\xc3\xa9",           /* and inside an ASCII nick, as clients write it */
        "\xe6\x97\xa5\xe6\x9c\xac", /* nihon: two 3-byte sequences back to back */
        "a\xe4\xb8\xad" "b",     /* a 3-byte sequence with ASCII on BOTH sides */
        "\xd0\x96",              /* Cyrillic zhe: lead 0xD0, a second 2-byte range */
        "\xd1\x80",              /* Cyrillic be, one step further up */
        "\xf0\x9f\x98\x80",      /* U+1F600: the 4-byte case, lead 0xF0 */
        "\xc4\x81" "1",             /* a multibyte nick may still end in a digit */
    };
    for (size_t i = 0; i < sizeof utf8_ok / sizeof utf8_ok[0]; i++) {
        assert_valid(utf8_ok[i]);
    }
    /* The one that matters most, asserted on its own so a narrowing fault cannot be
     * masked by a longer case that happens to pass. */
    assert_valid("\xc4\x81");

    /* --- UTF-8 that is NOT well formed: refused ---
     *
     * A nickname is STORED and re-rendered into every prefix this node emits, so
     * bytes that do not decode are refused at the door rather than copied around the
     * mesh forever with no way to tell what they were meant to be. Four shapes, each
     * built explicitly so the source is unambiguous:
     *
     *   1. A RAW C1 byte, 0x80-0x9F, with nothing expecting a continuation.
     *   2. An ENCODED C1, 0xC2 followed by 0x80-0x9F. This is U+0080-U+009F written
     *      the way a modern client writes it, and U+009B is CSI in Unicode -- a
     *      nickname carrying it is carrying an escape sequence whatever the encoding.
     *      It is the shape a raw-range refusal does NOT catch, which is why it is
     *      here as its own case.
     *   3. A TRUNCATED or INTERRUPTED sequence: a lead byte that never gets its
     *      continuations, or gets ASCII where one was required.
     *   4. A byte that can never appear in UTF-8 at all: 0xC0/0xC1 (which could only
     *      ever encode an overlong NUL) and 0xF5-0xFF. */
    {
        char buf[8];
        size_t kept = 0;

        for (unsigned b = 0x80u; b <= 0x9fu; b++) {
            /* shape 1: bare, on its own and inside a nick */
            buf[0] = (char)b;
            buf[1] = '\0';
            assert_invalid(buf);
            buf[0] = 'a';
            buf[1] = (char)b;
            buf[2] = 'b';
            buf[3] = '\0';
            assert_invalid(buf);
            /* shape 2: the same code point, properly encoded */
            buf[0] = 'a';
            buf[1] = '\xc2';
            buf[2] = (char)b;
            buf[3] = 'b';
            buf[4] = '\0';
            assert_invalid(buf);
            kept += 3u;
        }
        /* The loop really did run over all 32 code points, so the pair of blocks
         * above is testing the range rather than passing on one input. */
        assert(kept == 96u);
    }
    {
        /* shape 3 */
        static const char *const truncated[] = {
            "a\xc3",        /* lead, then the string ends */
            "a\xe6\x97",    /* 3-byte lead with one continuation */
            "a\xf0\x9f\x98", /* 4-byte lead with two */
            "a\xc3" "b",       /* lead where ASCII arrived instead */
            "a\xe6\x97" "b",   /* same, three bytes in */
            "\xc3",         /* and a lead byte as the entire nickname */
        };
        for (size_t i = 0; i < sizeof truncated / sizeof truncated[0]; i++) {
            assert_invalid(truncated[i]);
        }
    }
    {
        /* THE OVERLONG AND SURROGATE SHAPES, asserted in BOTH directions, which
         * is the point of putting them here rather than in a list of known-bad
         * inputs. They survived the first version of the UTF-8 rule because
         * `text_step()` validated the SHAPE of a sequence -- a lead byte followed
         * by continuations -- and not whether the sequence was CANONICAL. Every one
         * of these is a well-shaped sequence of the wrong code point:
         *
         *   0xE0 0x80 0xAF  overlong '/'   encodes U+002F, which 0x2F encodes
         *   0xF0 0x80 0x80 0xAF  overlong '/'  the same, in four bytes
         *   0xC0 0xAF      overlong '/'   the classic, and 0xC0 can never lead
         *   0xED 0xA0 0x80  U+D800       a surrogate half, which is not a character
         *   0xED 0xBF 0xBF  U+DFFF       the other end of the surrogate range
         *   0xF4 0x90 0x80 0x80  beyond U+10FFFF, which is not Unicode at all
         *
         * AND WHY IT IS A FILTER-BYPASS VECTOR rather than pedantry: an overlong
         * encoding decodes to the same code point as a shorter one, so a filter
         * that DECODES before it compares and a filter that compares BYTES disagree
         * about one value, and `0xC0 0xAF` is the case where they do. Two filters
         * disagreeing about one value is the whole of that attack.
         *
         * THE ACCEPTED SIDE IS ASSERTED TOO, and it is the half that would be easy
         * to leave out and that makes this a test of a rule rather than of a
         * blacklist: the four leads the check carves out of the ranges are the four
         * NEAREST legal values, and a check written as `u <= 0xDF || u >= 0xF5`
         * instead of as four exclusions would refuse all of them and every accented
         * character on the network. Those cases are in `utf8_ok` above; this block
         * is here so that both directions live in one place and neither can be
         * changed without the other being looked at. */
        static const char *const noncanonical[] = {
            "a\xe0\x80\xaf" "b",       /* overlong solidus, three bytes */
            "a\xf0\x80\x80\xaf" "b",   /* overlong solidus, four bytes */
            "a\xc0\xaf",                /* overlong solidus, the C0 lead */
            "a\xc1\xbf",                /* overlong solidus, the C1 lead */
            "a\xed\xa0\x80" "b",       /* U+D800, the low surrogate */
            "a\xed\xbf\xbf" "b",       /* U+DFFF, the high surrogate */
            "a\xf4\x90\x80\x80" "b",   /* U+110000, past the end of Unicode */
            "\xed\xa0\x80",             /* and one with nothing around it */
        };
        for (size_t i = 0; i < sizeof noncanonical / sizeof noncanonical[0]; i++) {
            assert_invalid(noncanonical[i]);
        }
    }
    {
        /* shape 4 */
        static const char *const impossible[] = {
            "a\xc0\xaf",    /* overlong solidus, the classic path-traversal shape */
            "a\xc1\xbf",    /* the other of the two overlong-NUL leads */
            "a\xf5\x80\x80\x80",
            "a\xfe",
            "a\xff",
        };
        for (size_t i = 0; i < sizeof impossible / sizeof impossible[0]; i++) {
            assert_invalid(impossible[i]);
        }
    }

    /* --- empty, NULL, and length --- */
    assert_invalid("");
    assert_invalid(NULL);
    /* The bound is IRC_MAX_NICK == 63, from conn_t::nick[64] in 2.1. */
    {
        char exact[IRC_MAX_NICK + 1];
        char over[IRC_MAX_NICK + 2];
        memset(exact, 'n', (size_t)IRC_MAX_NICK);
        exact[IRC_MAX_NICK] = '\0';
        memset(over, 'n', (size_t)IRC_MAX_NICK + 1);
        over[IRC_MAX_NICK + 1] = '\0';
        assert(strlen(exact) == (size_t)IRC_MAX_NICK);
        assert_valid(exact);
        assert_invalid(over);
        /* One byte shorter is still fine, so the boundary is exact. */
        exact[IRC_MAX_NICK - 1] = '\0';
        assert_valid(exact);
        /* Over-long AND illegal: the illegal character still loses. */
        over[0] = '@';
        assert_invalid(over);
    }

    /* --- the gap this predicate closes, against the real parse_nick() --- */
    {
        static const char *const lines[] = {
            "NICK a@evil",  /* the case 5 calls out by name */
            "NICK a#b",
            "NICK a&b",
            "NICK a+b",
            "NICK a!b",
            "NICK @",
            "NICK a:b",     /* a colon in a nick muddies the prefix grammar */
            "NICK a;b",     /* a tag separator in a nick */
            "NICK 1abc",    /* a leading digit is neither letter nor "special" */
            "NICK 9",
            "NICK a b",     /* parse_nick rejects this one itself */
        };
        size_t accepted = 0;
        int tokens = 0;
        for (size_t i = 0; i < sizeof lines / sizeof lines[0]; i++) {
            if (parse_nick(lines[i], nick, (int)sizeof nick, &tokens) != 1) {
                continue;
            }
            accepted++;
            /* parse_nick says yes; the charset rule must be able to say no. */
            assert(valid_nick(nick) == 0);
        }
        /* parse_nick really did accept the illegal ones, so the block is
         * testing something real rather than passing vacuously. Ten of the
         * eleven: everything except the nickname containing a space, which
         * parse_nick rejects on its own. */
        assert(accepted == 10);

        /* And a legitimate nickname passes both. */
        assert(parse_nick("NICK alice", nick, (int)sizeof nick, &tokens) == 1);
        assert(strcmp(nick, "alice") == 0);
        assert(valid_nick(nick) == 1);
        /* A qualified name is two nicks, and both halves are valid, so the
         * whole thing is a nick@server pair that splits at the last '@'. */
        assert(parse_nick("NICK alice@", nick, (int)sizeof nick, &tokens) == 1);
        assert(valid_nick("alice") == 1);
        assert(valid_nick("irc.a") == 1);
    }

    return 0;
}
