/* message_parse tests -- the tokenizer half of the syntax seam
 * (SERVER_DESIGN.md 3.2, 2.4, 7/Phase 1).
 *
 * Every assertion here is on a return value or on the bytes a caller reads out
 * of the message_t. Nothing asserts on how the buffer is allocated, on
 * interior-pointer arithmetic, or on any other internal plumbing. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/message.h"

/* Reuse one message_t across every rejection below and then parse a good line
 * into it. This is the observable form of the rejection contract: a rejected
 * parse must leave the struct clean, so the NEXT parse through the same struct
 * cannot inherit a half-built field. Nothing to assert about the internals --
 * if a half-built field did survive, the good parse below would be wrong. */
static void assert_reject(const char *line)
{
    message_t m;
    assert(message_parse(line, &m) == -1);
    /* Safe by contract, and a second call must be safe too. */
    message_free(&m);
    message_free(&m);

    assert(message_parse(":irc.a privmsg #c :after", &m) == 0);
    assert(strcmp(m.command, "PRIVMSG") == 0);
    assert(m.nparams == 2);
    assert(strcmp(m.params[0], "#c") == 0);
    assert(strcmp(m.params[1], "after") == 0);
    message_free(&m);
}

int main(void)
{
    message_t m;
    char buf[IRC_MAX_LINE + 64];

    /* --- tags, prefix, command and params all parsed, command uppercased -- */
    assert(message_parse("@time=2026-09-28T00:00:00.000Z :nick!user@host "
                         "pRiVmsG #chan :hello there", &m) == 0);
    assert(strcmp(m.command, "PRIVMSG") == 0);
    assert(strcmp(m.prefix, "nick!user@host") == 0);
    assert(strcmp(m.tags, "time=2026-09-28T00:00:00.000Z") == 0);
    assert(m.nparams == 2);
    assert(strcmp(m.params[0], "#chan") == 0);
    assert(strcmp(m.params[1], "hello there") == 0); /* the ':' marker is gone */
    assert(m.raw != NULL);
    message_free(&m);

    /* A minimal message: no tags, no prefix, no params. */
    assert(message_parse("PING", &m) == 0);
    assert(m.tags == NULL);
    assert(m.prefix == NULL);
    assert(m.nparams == 0);
    assert(strcmp(m.command, "PING") == 0);
    message_free(&m);

    /* No prefix, params present. */
    assert(message_parse("JOIN #a", &m) == 0);
    assert(m.prefix == NULL);
    assert(m.tags == NULL);
    assert(m.nparams == 1);
    assert(strcmp(m.params[0], "#a") == 0);
    message_free(&m);

    /* Uppercasing is ASCII-only and applies to the command word alone. */
    assert(message_parse("quit :Bye Now", &m) == 0);
    assert(strcmp(m.command, "QUIT") == 0);
    assert(strcmp(m.params[0], "Bye Now") == 0); /* the body keeps its case */
    message_free(&m);

    /* --- a leading ':' prefix is accepted, which is the peer-message case -- */
    /* This is the defect that motivated the phase: the old parser skipped only
     * whitespace before the command word, so a peer-style line was rejected. */
    assert(message_parse(":irc.b 001 alice :Welcome", &m) == 0);
    assert(strcmp(m.prefix, "irc.b") == 0);
    assert(strcmp(m.command, "001") == 0);
    assert(m.nparams == 2);
    assert(strcmp(m.params[0], "alice") == 0);
    assert(strcmp(m.params[1], "Welcome") == 0);
    message_free(&m);

    /* Prefix and no params. */
    assert(message_parse(":irc.b QUIT", &m) == 0);
    assert(strcmp(m.prefix, "irc.b") == 0);
    assert(m.nparams == 0);
    message_free(&m);

    /* The full 2.4 internal tag line, as a peer would receive it. */
    assert(message_parse("@irc-serve-origin=irc.a;irc-serve-epoch=3;"
                         "irc-serve-id=41;irc-serve-hops=0 :irc.a "
                         "PRIVMSG #chan :hi", &m) == 0);
    assert(strcmp(m.prefix, "irc.a") == 0);
    assert(strcmp(m.command, "PRIVMSG") == 0);
    assert(m.nparams == 2);
    assert(strcmp(m.params[1], "hi") == 0);
    {
        irc_serve_tags_t it;
        assert(irc_serve_tags_parse(&m, &it) == 0);
        assert(strcmp(it.origin, "irc.a") == 0);
        assert(it.epoch == 3);
        assert(it.id == 41);
        assert(it.hops == 0);
    }
    message_free(&m);

    /* --- a ':' param consumes the rest of the line --- */
    assert(message_parse("PRIVMSG #c :a b  c   d", &m) == 0);
    assert(m.nparams == 2);
    assert(strcmp(m.params[1], "a b  c   d") == 0); /* interior runs kept */
    message_free(&m);

    /* A ':' param may be empty. */
    assert(message_parse("PRIVMSG #c :", &m) == 0);
    assert(m.nparams == 2);
    assert(strcmp(m.params[1], "") == 0);
    message_free(&m);

    /* Everything after a ':' param is body, never another param. */
    assert(message_parse("PRIVMSG #c :one two three", &m) == 0);
    assert(m.nparams == 2);
    assert(strcmp(m.params[1], "one two three") == 0);
    message_free(&m);

    /* --- the 15-param cap, and the 15th absorbing the remainder --- */
    assert(message_parse("CMD a b c d e f g h i j k l m n o", &m) == 0);
    assert(m.nparams == 15);
    assert(strcmp(m.params[13], "n") == 0);
    assert(strcmp(m.params[14], "o") == 0);
    message_free(&m);

    /* 17 tokens: the 15th keeps everything left, verbatim and un-tokenized. */
    assert(message_parse("CMD a b c d e f g h i j k l m n o p q", &m) == 0);
    assert(m.nparams == 15);
    assert(strcmp(m.params[13], "n") == 0);
    assert(strcmp(m.params[14], "o p q") == 0);
    message_free(&m);

    /* The 15th absorbs the remainder even with no ':' marker. */
    assert(message_parse("CMD a b c d e f g h i j k l m n o p", &m) == 0);
    assert(m.nparams == 15);
    assert(strcmp(m.params[14], "o p") == 0);
    message_free(&m);

    /* A ':' on the 15th is the trailing marker and is stripped, not kept. */
    assert(message_parse("CMD a b c d e f g h i j k l m n :o p", &m) == 0);
    assert(m.nparams == 15);
    assert(strcmp(m.params[14], "o p") == 0);
    message_free(&m);

    /* Exactly 14 params then a trailing param: 15 total. */
    assert(message_parse("CMD a b c d e f g h i j k l m n :tail", &m) == 0);
    assert(m.nparams == 15);
    assert(strcmp(m.params[13], "n") == 0);
    assert(strcmp(m.params[14], "tail") == 0);
    message_free(&m);

    /* A 20-token line does not fail: it saturates at 15 rather than being
     * rejected, because 3.2 says the 15th absorbs the remainder. */
    {
        char line[128];
        size_t w = 0;
        /* Each snprintf's return value is the length it WOULD have written, not
         * the length it did, so accumulating it unchecked is the classic
         * overflowing-snprintf bug: on truncation `w` runs past the end of the
         * buffer and `sizeof line - w` wraps to a huge size_t. The total here is
         * 73 bytes into 128, so it does not fire today, but one edit to the loop
         * bounds would make it undefined behaviour rather than a test failure.
         * Accumulate only what was actually written, and assert the headroom
         * explicitly so a future change that overflows fails here. */
        int n = snprintf(line + w, sizeof line - w, "CMD");
        assert(n > 0 && (size_t)n < sizeof line - w);
        w += (size_t)n;
        for (int i = 0; i < 20; i++) {
            n = snprintf(line + w, sizeof line - w, " t%d", i);
            assert(n > 0 && (size_t)n < sizeof line - w);
            w += (size_t)n;
        }
        assert(w < sizeof line);
        assert(message_parse(line, &m) == 0);
        assert(m.nparams == 15);
        assert(strcmp(m.params[14], "t14 t15 t16 t17 t18 t19") == 0);
        message_free(&m);
    }

    /* --- the trailing terminator is stripped, one of CRLF/CR/LF --- */
    assert(message_parse("NICK alice\r\n", &m) == 0);
    assert(strcmp(m.command, "NICK") == 0);
    assert(strcmp(m.params[0], "alice") == 0);
    message_free(&m);
    assert(message_parse("NICK alice\n", &m) == 0);
    assert(strcmp(m.params[0], "alice") == 0);
    message_free(&m);
    assert(message_parse("NICK alice\r", &m) == 0);
    assert(strcmp(m.params[0], "alice") == 0);
    message_free(&m);
    /* The terminator is not part of the trailing param's value. */
    assert(message_parse("PRIVMSG #c :body\r\n", &m) == 0);
    assert(strcmp(m.params[1], "body") == 0);
    message_free(&m);

    /* --- embedded CR / LF anywhere in the middle is rejected --- */
    assert_reject("PRIVMSG #c :bo\ndy");
    assert_reject("PRIVMSG #c :bo\rdy");
    assert_reject("PRI\nVMSG #c");
    assert_reject(":irc.a PING\r\nQUIT");
    assert_reject("@a=1\r\nPING");
    /* A second terminator is not "one optional terminator". */
    assert_reject("PING\r\r\n");
    assert_reject("PING\n\n");

    /* --- an embedded NUL is rejected --- */
    {
        const char raw[] = { 'P', 'R', 'I', 'V', 'M', 'S', 'G', ' ', '#',
                             'c',  ' ',  ':',  'a', '\0', 'b' };
        assert(message_parse_n(raw, sizeof raw, &m) == -1);
        message_free(&m);
        /* The same bytes without the NUL parse fine, so the rejection is the
         * NUL and not the content. */
        const char ok[] = "PRIVMSG #c :ab";
        assert(message_parse_n(ok, sizeof ok - 1, &m) == 0);
        assert(strcmp(m.params[1], "ab") == 0);
        message_free(&m);
        /* A NUL in the command word is rejected too. */
        const char cmd[] = { 'P', 'I', 'N', 'G', '\0', 'X' };
        assert(message_parse_n(cmd, sizeof cmd, &m) == -1);
        message_free(&m);
        /* message_parse cannot see PAST a NUL: it is the C string's end, so
         * the message is the part before it. That is the documented difference
         * from message_parse_n, and it is why the framing layer uses the _n
         * form. */
        assert(message_parse("PING\0X", &m) == 0);
        assert(strcmp(m.command, "PING") == 0);
        assert(m.nparams == 0);
        message_free(&m);
    }

    /* --- a line over IRC_MAX_LINE is rejected; the boundary is inclusive --- */
    {
        /* "PRIVMSG #c :" is 12 bytes, so pad so that len + CRLF == IRC_MAX_LINE */
        const char head[] = "PRIVMSG #c :";
        const size_t headlen = sizeof head - 1;
        const size_t want = (size_t)IRC_MAX_LINE;
        const size_t pad = want - headlen - 2;
        size_t w = headlen;
        memcpy(buf, head, headlen);
        memset(buf + w, 'a', pad);
        w += pad;
        buf[w] = '\r';
        buf[w + 1] = '\n';
        w += 2;
        assert(w == want);
        assert(message_parse_n(buf, w, &m) == 0);
        assert(m.nparams == 2);
        assert(strcmp(m.params[0], "#c") == 0);
        message_free(&m);

        /* One byte over is rejected. */
        assert(message_parse_n(buf, want + 1, &m) == -1);
        message_free(&m);
        /* And through the NUL-terminated entry point too. */
        buf[w] = 'a';
        buf[w + 1] = '\0';
        assert(message_parse(buf, &m) == -1);
        message_free(&m);
    }

    /* --- structural rejects --- */
    assert_reject("");
    assert_reject("\r\n");
    assert_reject("   ");
    assert_reject("@");               /* lone '@': no command, no block */
    assert_reject("@ PING");          /* empty tag block */
    assert_reject(": PING");          /* empty source */
    assert_reject("@a=1 ");          /* a tag block and then no command */
    assert_reject("@;a=1 PING");      /* leading ';' is an empty pair */
    assert_reject("@a=1; PING");      /* trailing ';' is an empty pair */
    assert_reject("@=1 PING");        /* empty key */
    assert_reject("@a@=1 PING");      /* '@' is not legal in a key */
    /* NULL arguments. */
    assert(message_parse(NULL, &m) == -1);
    message_free(&m);
    assert(message_parse("PING", NULL) == -1);
    assert(message_parse_n(NULL, 4, &m) == -1);
    message_free(&m);
    assert(message_parse_n("PING", 4, NULL) == -1);

    /* A SP inside a value ends the block, so this is a tag block plus a
     * command, not a value with a space. Pinned so the behaviour is
     * deliberate: a space in a tag value must be escaped. */
    assert(message_parse("@a=1 2", &m) == 0);
    assert(strcmp(m.tags, "a=1") == 0);
    assert(strcmp(m.command, "2") == 0);
    message_free(&m);
    /* Runs of separators before the command word are tolerated. */
    assert(message_parse("@a=1 \t PING x", &m) == 0);
    assert(strcmp(m.tags, "a=1") == 0);
    assert(strcmp(m.command, "PING") == 0);
    assert(m.nparams == 1);
    message_free(&m);

    /* --- tab is accepted as a separator, and runs of them too --- */
    assert(message_parse("\tPING\t\talice", &m) == 0);
    assert(strcmp(m.command, "PING") == 0);
    assert(m.nparams == 1);
    assert(strcmp(m.params[0], "alice") == 0);
    message_free(&m);

    /* --- tag lookup: unescaped values, case-insensitive keys --- */
    /* The wire form is IRCv3's: ';' is written \:, a colon is RAW, ' ' is
     * \\s and \\ is \\. The previous spelling here read \; as ';' and \: as
     * ':', which is a plausible guess and is not the table. */
    assert(message_parse("@note=a\\sb\\:c:d\\\\e;flag;other=v PING", &m) == 0);
    {
        char value[64];
        assert(message_tag_get(&m, "note", value, sizeof value) == 0);
        assert(strcmp(value, "a b;c:d\\e") == 0);
        /* Keys are case-insensitive. */
        assert(message_tag_get(&m, "NOTE", value, sizeof value) == 0);
        assert(strcmp(value, "a b;c:d\\e") == 0);
        /* A tag with no '=' has the empty value, and is still found. */
        assert(message_tag_get(&m, "flag", value, sizeof value) == 0);
        assert(strcmp(value, "") == 0);
        /* The walk continues past a valueless tag. */
        assert(message_tag_get(&m, "other", value, sizeof value) == 0);
        assert(strcmp(value, "v") == 0);
        /* An absent tag is not found, and out[] is emptied. */
        strcpy(value, "dirty");
        assert(message_tag_get(&m, "nope", value, sizeof value) == -1);
        assert(value[0] == '\0');
    }
    message_free(&m);

    /* A value containing '=' is not truncated at the first '='. */
    assert(message_parse("@k=a=b=c PING", &m) == 0);
    {
        char value[64];
        assert(message_tag_get(&m, "k", value, sizeof value) == 0);
        assert(strcmp(value, "a=b=c") == 0);
    }
    message_free(&m);

    /* A one-character key must not prefix-match a longer one, in either
     * order. */
    assert(message_parse("@abc=1;a=2 PING", &m) == 0);
    {
        char value[64];
        assert(message_tag_get(&m, "a", value, sizeof value) == 0);
        assert(strcmp(value, "2") == 0);
        assert(message_tag_get(&m, "ab", value, sizeof value) == -1);
    }
    message_free(&m);

    /* Lookup argument and capacity rejects, on a message that does have a tag
     * so each argument is the only possible cause. */
    assert(message_parse("@k=abcdef PING", &m) == 0);
    {
        char value[64];
        assert(message_tag_get(&m, "k", value, 7) == 0); /* "abcdef" + NUL */
        assert(strcmp(value, "abcdef") == 0);
        assert(message_tag_get(&m, "k", value, 6) == -1); /* no truncation */
        assert(message_tag_get(&m, "k", value, 0) == -1);
        assert(message_tag_get(&m, "k", NULL, 4) == -1);
        assert(message_tag_get(&m, NULL, value, sizeof value) == -1);
        assert(message_tag_get(NULL, "k", value, sizeof value) == -1);
    }
    message_free(&m);

    /* Lookup on a message with no tags fails cleanly. */
    assert(message_parse("PING", &m) == 0);
    {
        char value[64];
        assert(message_tag_get(&m, "k", value, sizeof value) == -1);
    }
    message_free(&m);

    /* --- the 2.4 internal tag set: value grammar enforced on parse --- */
    {
        static const struct {
            const char *line;
            int expect; /* 0 accepted, -1 rejected */
        } cases[] = {
            { "@irc-serve-origin=irc.a;irc-serve-epoch=1;irc-serve-id=1;"
              "irc-serve-hops=0 :a PING", 0 },
            /* epoch 0 is a legal per-boot counter; hops 0 is a message that
             * has not been forwarded yet. */
            { "@irc-serve-origin=irc.a;irc-serve-epoch=0;irc-serve-id=1;"
              "irc-serve-hops=0 :a PING", 0 },
            /* id 0 is reserved as "unset" and must be rejected, so an absent
             * tag is never mistaken for a real id. */
            { "@irc-serve-origin=irc.a;irc-serve-epoch=1;irc-serve-id=0;"
              "irc-serve-hops=0 :a PING", -1 },
            /* non-canonical numerics are rejected */
            { "@irc-serve-origin=irc.a;irc-serve-epoch=01;irc-serve-id=1;"
              "irc-serve-hops=0 :a PING", -1 },
            { "@irc-serve-origin=irc.a;irc-serve-epoch=x;irc-serve-id=1;"
              "irc-serve-hops=0 :a PING", -1 },
            /* a sign is not a digit */
            { "@irc-serve-origin=irc.a;irc-serve-epoch=-1;irc-serve-id=1;"
              "irc-serve-hops=0 :a PING", -1 },
            { "@irc-serve-origin=irc.a;irc-serve-epoch= 1;irc-serve-id=1;"
              "irc-serve-hops=0 :a PING", -1 },
            /* 21 digits overflows uint64 */
            { "@irc-serve-origin=irc.a;irc-serve-epoch=184467440737095516150;"
              "irc-serve-id=1;irc-serve-hops=0 :a PING", -1 },
            /* uint64_max itself is fine */
            { "@irc-serve-origin=irc.a;irc-serve-epoch=18446744073709551615;"
              "irc-serve-id=1;irc-serve-hops=0 :a PING", 0 },
            /* hops above uint32_max is rejected */
            { "@irc-serve-origin=irc.a;irc-serve-epoch=1;irc-serve-id=1;"
              "irc-serve-hops=4294967296 :a PING", -1 },
            /* uint32_max is fine */
            { "@irc-serve-origin=irc.a;irc-serve-epoch=1;irc-serve-id=1;"
              "irc-serve-hops=4294967295 :a PING", 0 },
            /* an illegal origin character is rejected */
            { "@irc-serve-origin=irc_a;irc-serve-epoch=1;irc-serve-id=1;"
              "irc-serve-hops=0 :a PING", -1 },
            /* so is an origin with a '@', which would break nick@server */
            { "@irc-serve-origin=a@b;irc-serve-epoch=1;irc-serve-id=1;"
              "irc-serve-hops=0 :a PING", -1 },
            /* an empty origin is rejected */
            { "@irc-serve-origin=;irc-serve-epoch=1;irc-serve-id=1;"
              "irc-serve-hops=0 :a PING", -1 },
            /* a missing member tag is rejected, never defaulted to zero */
            { "@irc-serve-origin=irc.a;irc-serve-epoch=1;irc-serve-id=1"
              " :a PING", -1 },
            { "@irc-serve-origin=irc.a;irc-serve-id=1;irc-serve-hops=0"
              " :a PING", -1 },
            { "@irc-serve-epoch=1;irc-serve-id=1;irc-serve-hops=0"
              " :a PING", -1 },
            /* keys are matched case-insensitively, per IRCv3 */
            { "@IRC-Serve-Origin=irc.a;IRC-Serve-Epoch=1;IRC-Serve-Id=1;"
              "IRC-Serve-Hops=0 :a PING", 0 },
        };
        size_t n = sizeof cases / sizeof cases[0];
        for (size_t i = 0; i < n; i++) {
            assert(message_parse(cases[i].line, &m) == 0);
            irc_serve_tags_t t;
            assert(irc_serve_tags_parse(&m, &t) == cases[i].expect);
            message_free(&m);
        }
    }

    /* An escaped origin is unescaped before validation, so an origin that is
     * only legal once decoded is accepted. */
    assert(message_parse("@irc-serve-origin=irc\\.a;irc-serve-epoch=1;"
                         "irc-serve-id=1;irc-serve-hops=0 :a PING", &m) == 0);
    {
        irc_serve_tags_t t;
        assert(irc_serve_tags_parse(&m, &t) == 0);
        assert(strcmp(t.origin, "irc.a") == 0);
    }
    message_free(&m);

    /* A message with no tags at all has no internal tag set. */
    assert(message_parse("PING :irc.a", &m) == 0);
    {
        irc_serve_tags_t t;
        assert(irc_serve_tags_parse(&m, &t) == -1);
        assert(irc_serve_tags_parse(NULL, &t) == -1);
        assert(irc_serve_tags_parse(&m, NULL) == -1);
    }
    message_free(&m);

    return 0;
}
