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
