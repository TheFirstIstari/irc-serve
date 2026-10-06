/* test_nick_utf8.c -- the nickname grammar is UTF-8-AWARE, proven on the wire
 * between two clients.
 *
 * tests/protocol/test_valid_nick.c proves the PREDICATE: `ā` is a legal
 * nickname, a bare 0x9F and an encoded 0xC2 0x9B are not, and a lead byte that
 * never gets its continuations is not. A predicate test cannot tell a rule from
 * a rule that is never consulted, and it cannot tell "kept" from "kept in the
 * node and then mangled on the way out". So this file asks the two questions a
 * predicate cannot:
 *
 *   1. WHAT DOES THE OTHER CLIENT SEE? A nickname is not a string this node
 *      holds, it is a string this node puts in front of every message that
 *      member sends. If the UTF-8 rule were enforced at NICK time and then
 *      re-encoded or re-checked somewhere downstream, client B would be the
 *      only one who could see it. So B receives a PRIVMSG from a member whose
 *      nickname is `ā` and the prefix is asserted BYTE FOR BYTE, including the
 *      two bytes C4 81.
 *
 *   2. WHAT HAPPENS TO A REFUSED NICKNAME ON THE WIRE? 432 echoes the nickname
 *      back in its text. With a rejected nickname that echo would put the very
 *      bytes that were just refused back in front of the client that sent them
 *      -- and, more to the point here, the numeric filter from `reply.c` has to
 *      remove them without removing the FIELD, so these expected lines are
 *      built from the shape of the rule rather than copied from the input.
 *
 * WHY THE REFUSAL LINES LOOK THE WAY THEY DO, because it is surprising and it
 * is the whole point: `Erroneous nickname: ` keeps its trailing space and its
 * trailing colon, followed by nothing. `emit_numeric_ex()` strips the bytes and
 * KEEPS the parameter, because `needs_colon()` puts the `:` marker on an empty
 * final parameter and a positional parser then finds the field exactly where the
 * RFC says it is. A node that dropped the field instead would render
 * `:irc.test 432 * :` -- one positional field instead of two -- and a client
 * reading the offending name out of the text would get the wrong answer. So the
 * empty field is asserted, not tolerated.
 *
 * ---------------------------------------------------------------------------
 * WHAT THE WIRE CANNOT EXPRESS
 * ---------------------------------------------------------------------------
 * Two of the shapes the rule refuses are not expressible as one IRC parameter,
 * and the honest thing is to say which:
 *
 *   a space            parameters are space-separated, so a nickname containing
 *                      one arrives as two parameters and the node answers 461
 *                      instead of 432. test_nick_rule.c asserts that; repeating
 *                      it here would test the arity check, not the UTF-8 rule.
 *
 *   a LEADING ':'      `:` at the start of a parameter is the trailing-parameter
 *                      marker and the parser strips it, so `NICK :bob` is a
 *                      request for "bob". Not expressible, not tested. A ':'
 *                      INSIDE a nickname is expressible and is covered by
 *                      test_nick_rule.c, which is the half the nick@server split
 *                      turns on.
 *
 * A TRUNCATED sequence at the very end of a nickname is also expressible but is
 * NOT tested here, and the reason is worth recording rather than hiding: it is
 * tested at the predicate, and the two paths that matter -- accepted nicks and
 * refused ones -- are each covered once on the wire rather than 96 times. The
 * whole 0x80-0x9F range, bare and encoded, is swept on the wire in the loop at
 * the end of this file, which is where a range bug would show up.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

/* Assert `want` arrives on `c` as a COMPLETE line, byte for byte.
 *
 * The trailing CRLF is part of the needle so a match proves the line is
 * terminated on the wire rather than being a prefix of a longer one, and the
 * leading boundary is checked explicitly so a numeric that is a SUFFIX of a
 * longer line cannot pass. Same shape as test_nick_rule.c's helper, duplicated
 * rather than shared: these two files assert different things about the same
 * byte and a shared helper would hide which of them moved. */
static void expect_line(test_client_t *c, const char *what, const char *want)
{
    const char *at;

    TF_CHECK_MSG(tc_expect(c, want, T_IO_MS) == 0, "%s: expected the exact "
                 "line \"%s\"", what, want);
    at = strstr(tc_buffer(c), want);
    TF_CHECK_MSG(at != NULL, "%s: the line vanished from the buffer", what);
    TF_CHECK_MSG(at == tc_buffer(c) || at[-1] == '\n',
                 "%s: \"%s\" is not at the start of a line: it is the tail of "
                 "a longer one", what, want);
}

/* A nickname the node must refuse, with the exact line it must answer.
 *
 * `echo` is what the numeric's text field must come to. It is passed in rather
 * than derived from `nick` because the answer is NOT the input with the bad
 * bytes removed -- it depends on what the wire filter's set contains, and for
 * two of the shapes the interesting fact is that it removes NOTHING. Naming the
 * expectation per case is what keeps this from becoming a second copy of the
 * filter: a case whose expectation was computed by calling the filter would pass
 * for any filter.
 *
 * `tc_send_raw()` is used because `tc_send()` appends the CRLF and several of
 * these shapes are not comfortable as C string literals. The terminator is
 * therefore appended HERE, which is the whole difference between a line the
 * node frames and bytes that sit in its receive buffer forever. */
/* How many refusals this file has asked for and SEEN. A file-scope counter
 * rather than a count of the buffer: `tc_expect()` advances past what it
 * matched, so after a few dozen cases the earlier numerics are gone from
 * `tc_buffer()` and counting what is left there measures the harness rather than
 * the node. */
static size_t g_refusals;

static void expect_bad_refused(test_client_t *c, const char *what,
                               const char *nick, size_t nick_len,
                               const char *echo, size_t echo_len)
{
    char cmd[256];
    char want[512];
    size_t pre;
    size_t used;
    int n;

    n = snprintf(cmd, sizeof cmd, "NICK ");
    TF_CHECK_MSG(n > 0 && (size_t)n < sizeof cmd, "could not build the command");
    pre = (size_t)n;
    TF_CHECK_MSG(pre + nick_len + 3u < sizeof cmd, "nickname too long to send");
    memcpy(cmd + pre, nick, nick_len);
    used = pre + nick_len;
    cmd[used++] = '\r';
    cmd[used++] = '\n';
    cmd[used] = '\0';

    n = snprintf(want, sizeof want, ":irc.test 432 * :Erroneous nickname: ");
    TF_CHECK_MSG(n > 0 && (size_t)n < sizeof want, "expected line too big");
    memcpy(want + (size_t)n, echo, echo_len);
    want[(size_t)n + echo_len] = '\r';
    want[(size_t)n + echo_len + 1u] = '\n';
    want[(size_t)n + echo_len + 2u] = '\0';

    TF_CHECK_MSG(tc_send_raw(c, cmd, used) == 0, "tc_send_raw(NICK) failed");
    expect_line(c, what, want);
    g_refusals++;
}

int main(void)
{
    nf_node_t node;
    test_client_t ann; /* holds the nickname under test */
    test_client_t bee; /* the second client: the one who SEES it */
    test_client_t probe; /* sends the illegal nicknames */
    size_t r432;
    unsigned b;
    int n;

    tc_init(&ann);
    tc_init(&bee);
    tc_init(&probe);

    TF_CHECK(nf_spawn_binary(&node) == 0);
    TF_CHECK_MSG(tc_connect(&ann, node.port) == 0, "tc_connect failed");

    /* ---------------------------------------------------------------------
     * A nickname that is not ASCII registers, and the welcome burst carries it
     * back verbatim. `ā` is 0xC4 0x81 -- written in two pieces because
     * "\xc4\x811" would be read by the compiler as the single escape \x811.
     * --------------------------------------------------------------------- */
    TF_CHECK_MSG(tc_send(&ann, "NICK \xc4\x81") == 0, "tc_send(NICK) failed");
    TF_CHECK_MSG(tc_send(&ann, "USER ann 0 * :Ann Example") == 0,
                 "tc_send(USER) failed");
    expect_line(&ann, "001 with a UTF-8 nickname",
                ":irc.test 001 \xc4\x81 :Welcome");

    /* ---------------------------------------------------------------------
     * WHAT B SEES. This is the assertion the predicate test cannot make.
     *
     * `ann` and `bee` share #T; `ann` sends one PRIVMSG; `bee` must receive it
     * with `:ā!` in the prefix. If the nick bytes were dropped, replaced, or
     * re-encoded on the way out, this is the line that would change, and the
     * assertion is byte for byte so a Latin-1 fallback (one byte, 0xE4) fails
     * as well as a dropped nickname does. The host half is `127.0.0.1` because
     * that is the peer address of the socket, which is what every other prefix
     * assertion in this directory expects.
     * --------------------------------------------------------------------- */
    TF_CHECK_MSG(tc_connect(&bee, node.port) == 0, "tc_connect failed");
    TF_CHECK_MSG(tc_send(&bee, "NICK bee") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&bee, "USER bee 0 * :Bee Example") == 0,
                 "tc_send failed");
    TF_CHECK_MSG(tc_expect(&bee, " 001 bee :Welcome", T_IO_MS) == 0,
                 "the second client did not register");

    TF_CHECK_MSG(tc_send(&ann, "JOIN #T") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_expect(&ann, " 366 \xc4\x81", T_IO_MS) == 0,
                 "the member with the UTF-8 nickname never completed its JOIN: "
                 "a nickname accepted at registration is not usable");
    TF_CHECK_MSG(tc_send(&bee, "JOIN #T") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_expect(&bee, " 366 bee", T_IO_MS) == 0, "tc_send failed");

    TF_CHECK_MSG(tc_send(&ann, "PRIVMSG #T :hello from a macron") == 0,
                 "tc_send failed");
    expect_line(&bee, "the prefix as the second client receives it",
                ":\xc4\x81!ann@127.0.0.1 PRIVMSG #T :hello from a macron\r\n");
    /* And the same line on the sender's own socket, because the echo of a
     * message you sent must carry your own nickname the same way. */
    expect_line(&ann, "the echo's prefix on the sender's socket",
                ":\xc4\x81!ann@127.0.0.1 PRIVMSG #T :hello from a macron\r\n");

    /* ---------------------------------------------------------------------
     * The rest of the well-formed set, each accepted as a RENAME.
     *
     * A rename is silent on the wire in this tree (there is no client-to-client
     * NICK broadcast yet -- SNICK covers the mesh), so acceptance is asserted
     * through the node's own log line, which records both the old and the new
     * name. Asserting it any other way would either require a second channel
     * membership dance per name or assert something that is not true.
     * --------------------------------------------------------------------- */
    {
        static const char *const renames[] = {
            "caf\xc3\xa9",              /* e-acute, 3 bytes */
            "\xe6\x97\xa5\xe6\x9c\xac", /* nihon, two 3-byte sequences */
            "\xd0\x96",                  /* Cyrillic, a different 2-byte lead */
            "\xf0\x9f\x98\x80",          /* U+1F600, 4 bytes */
            ("\xc3\xa9" "9"),         /* multibyte then a digit */
        };
        size_t r432_before = tf_count(tc_buffer(&ann), " 432 ");

        for (size_t i = 0; i < sizeof renames / sizeof renames[0]; i++) {
            char needle[160];
            int w = snprintf(needle, sizeof needle, "to=%s", renames[i]);

            TF_CHECK_MSG(w > 0 && (size_t)w < sizeof needle,
                         "needle too long for %s", renames[i]);
            char line[160];
            int v = snprintf(line, sizeof line, "NICK %s", renames[i]);

            TF_CHECK_MSG(v > 0 && (size_t)v < sizeof line,
                         "rename line too long for %s", renames[i]);
            TF_CHECK_MSG(tc_send(&ann, line) == 0, "tc_send failed");
            /* The node logs `nick_change: fd=N from=<old> to=<new>`, and waiting
             * for THAT is what proves the rename was accepted rather than merely
             * not refused: a refusal logs nothing and sends 432. A PING in the
             * same segment would only prove the connection survived. */
            TF_CHECK_MSG(nf_expect(&node, needle, T_IO_MS) == 0,
                         "the node did not record a nickname change to %s, so "
                         "the rename was not accepted", renames[i]);
        }
        /* Not one 432 for the whole block. A refused rename leaves the old name
         * in place and logs nothing, which the loop above would have caught, but
         * a count says it directly and names the number. */
        TF_CHECK_MSG(tf_count(tc_buffer(&ann), " 432 ") == r432_before,
                     "the UTF-8 rename block produced %zu 432s: a well-formed "
                     "multibyte nickname was refused",
                     tf_count(tc_buffer(&ann), " 432 ") - r432_before);

        /* AND THE LAST NAME IS THE ONE IN THE PREFIX B SEES, which is the only
         * way to tell "the rename was accepted" from "the node logged a string
         * it never stored". Four multibyte names have come and gone by now; the
         * node is holding the fifth. */
        TF_CHECK_MSG(tc_send(&ann, "PRIVMSG #T :after the renames") == 0,
                     "tc_send failed");
        expect_line(&bee, "the prefix after five multibyte renames",
                    ":\xc3\xa9" "9!ann@127.0.0.1 PRIVMSG #T :after the renames\r\n");
    }

    /* ---------------------------------------------------------------------
     * Every byte of the C1 range, bare AND encoded, refused on the wire.
     *
     * The loop is the wire-level twin of the range loop in
     * test_valid_nick.c. Both shapes matter and they fail differently: a
     * refusal that dropped the 0x80-0x9F RANGE would refuse `ā` (whose second
     * byte is 0x81) and the rename block above would have caught it; a refusal
     * that only looked for a raw byte would let the encoded pair through, and
     * this loop is the only thing here that would notice.
     * --------------------------------------------------------------------- */
    TF_CHECK_MSG(tc_connect(&probe, node.port) == 0, "tc_connect failed");
    r432 = tf_count(tc_buffer(&ann), " 432 ");
    TF_CHECK_MSG(r432 == 0u,
                 "the UTF-8 nickname block above produced %zu 432s: a well-formed "
                 "multibyte nickname was refused", r432);
    for (b = 0x80u; b <= 0x9fu; b++) {
        char bare[4];
        char encoded[6];
        char what[64];

        bare[0] = 'a';
        bare[1] = (char)b;
        bare[2] = 'b';
        bare[3] = '\0';
        n = snprintf(what, sizeof what, "bare C1 byte 0x%02x", b);
        TF_CHECK_MSG(n > 0 && (size_t)n < sizeof what, "label too long");
        /* Both bytes of the value go: the bare C1 byte, and the 0xC2 0x80-0x9F
         * pair the node recognises as the encoded form of the same code point.
         * The surrounding 'a' and 'b' survive, which is the FIELD being kept --
         * `Erroneous nickname: ab`, not `Erroneous nickname: `. */
        expect_bad_refused(&probe, what, bare, 3u, "ab", 2u);

        encoded[0] = 'a';
        encoded[1] = '\xc2';
        encoded[2] = (char)b;
        encoded[3] = 'b';
        encoded[4] = '\0';
        n = snprintf(what, sizeof what, "encoded C1 byte C2 %02x", b);
        TF_CHECK_MSG(n > 0 && (size_t)n < sizeof what, "label too long");
        expect_bad_refused(&probe, what, encoded, 4u, "ab", 2u);
    }
    /* A lead byte with no continuations, and one that never can have any. Sent
     * raw because the shapes are not comfortable as C string literals. */
    {
        /* And the malformed shapes, where the filter removes NOTHING, which is
         * the more interesting half and is why the expectation is per case.
         *
         * `conn_text_strip_wire()` removes the log-injection SET: C0 controls,
         * DEL, a bare 0x80-0x9F, and the encoded 0xC2 pair. It is not a UTF-8
         * validator, and it is sequence-aware: a continuation byte the stripper
         * believes is inside a sequence it already emitted is KEPT, because the
         * recipient's client is the thing that decides what to do with a byte it
         * cannot interpret. So `a\xe6\x97` echoes whole -- the stripper saw a
         * 3-byte lead and one continuation and had no reason to object -- while a
         * BARE `\x97` on its own is dropped.
         *
         * That is why the whole-buffer scan at the end of this file looks for C0
         * controls and DEL and not for the C1 range: the C1 protection is proven
         * byte-exactly by the two loops above, and a range scan here would be
         * flagging a byte the policy deliberately keeps.
         *
         * NO SECURITY CONTENT IS LOST BY THIS. Every one of these echoes goes
         * back to the socket that sent it, and Decision A's argument is exactly
         * that the echo carries nothing the sender does not already have. */
        static const struct {
            const char *what;
            const char *bytes;
            size_t len;
            const char *echo;
            size_t echo_len;
        } broken[] = {
            { "truncated 2-byte lead", "a\xc3", 2u, "a\xc3", 2u },
            { "truncated 3-byte lead", "a\xe6\x97", 3u, "a\xe6\x97", 3u },
            { "truncated 4-byte lead", "a\xf0\x9f\x98", 4u,
              "a\xf0\x9f\x98", 4u },
            { "lead where ASCII arrived", "a\xc3" "b", 3u, "a\xc3" "b", 3u },
            { "overlong lead C0", "a\xc0\xaf", 3u, "a\xc0\xaf", 3u },
            { "overlong lead C1", "a\xc1\xbf", 3u, "a\xc1\xbf", 3u },
            /* 0xF5 cannot lead, and the three 0x80s that follow ARE bare C1 with
             * nothing expecting them, so this one loses three bytes and keeps
             * two. It is the case that shows the filter is sequence-aware rather
             * than set-only. */
            { "F5 is not UTF-8", "a\xf5\x80\x80\x80", 5u, "a\xf5", 2u },
            { "FF is not UTF-8", "a\xff", 2u, "a\xff", 2u },
        };
        for (size_t i = 0; i < sizeof broken / sizeof broken[0]; i++) {
            expect_bad_refused(&probe, broken[i].what, broken[i].bytes,
                               broken[i].len, broken[i].echo,
                               broken[i].echo_len);
        }
    }
    /* 32 bare + 32 encoded + 8 malformed, and the loop ran: the byte loop's own
     * `kept` total in the predicate test covers that side, and this count is the
     * wire's version of the same claim. */
    TF_CHECK_MSG(g_refusals == 72u,
                 "expected 72 refusals on the wire (32 bare + 32 encoded + 8 "
                 "malformed), saw %zu", g_refusals);

    /* ---------------------------------------------------------------------
     * NOT ONE OF THE REFUSED BYTES IS ANYWHERE ON THE WIRE.
     *
     * The 432 expectations above prove the bytes are not in the text field.
     * This proves they are not on the socket AT ALL -- a different claim, and the
     * one that would catch a second echo site, a logged-and-replayed value, or a
     * numerics-with-a-different-trailing-parameter path. It scans the whole
     * buffer rather than searching for one needle, for the reason
     * test_terminal_sweep.c does: a search for the byte you expect can be
     * satisfied by a byte that is legitimate, and a scan cannot.
     *
     * The bytes scanned for are the C0 controls and DEL. CR and LF are the line
     * terminator and are excluded. The C1 range is NOT in the scan, and the
     * reason is the policy rather than a convenience: the filter is
     * sequence-aware, so a continuation byte inside a sequence it already
     * emitted is kept, and the malformed cases above put such a byte on the wire
     * on purpose. The C1 protection -- the part that is a security claim -- is
     * proven byte-exactly by the two loops above, where a bare 0x80-0x9F and
     * the encoded 0xC2 pair both have to come back as `ab`.
     * --------------------------------------------------------------------- */
    {
        const char *buffers[3];
        size_t lens[3];
        size_t nbuf;

        buffers[0] = tc_buffer(&ann);
        lens[0] = tc_received(&ann);
        buffers[1] = tc_buffer(&bee);
        lens[1] = tc_received(&bee);
        buffers[2] = tc_buffer(&probe);
        lens[2] = tc_received(&probe);
        for (nbuf = 0; nbuf < 3u; nbuf++) {
            size_t bad_at = 0u;
            unsigned byte = 0u;

            TF_CHECK_MSG(lens[nbuf] == strlen(buffers[nbuf]),
                         "buffer %zu reports %zu bytes but holds %zu, so the "
                         "scan would not see the whole stream",
                         nbuf, lens[nbuf], strlen(buffers[nbuf]));
            for (size_t i = 0; i < strlen(buffers[nbuf]); i++) {
                unsigned char u = (unsigned char)buffers[nbuf][i];

                if (u == '\r' || u == '\n') {
                    continue;
                }
                if (u < 0x20u || u == 0x7fu) {
                    bad_at = i;
                    byte = u;
                    break;
                }
            }
            TF_CHECK_MSG(bad_at == 0u,
                         "client %zu received byte 0x%02x at offset %zu: a "
                         "control byte reached the wire", nbuf, byte, bad_at);
        }
    }

    /* ---------------------------------------------------------------------
     * And the node is still healthy: every refusal was a 432 rendered and sent,
     * not a reply the node gave up on. `reply_refused` counts replies that
     * could not be rendered, so it staying 0 is what says the strip worked
     * rather than the reply being dropped.
     * --------------------------------------------------------------------- */
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0: a numeric was dropped rather than "
                 "sent with its field kept and its bytes removed");
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", 3, T_IO_MS) == 0,
                 "accepted should be 3");
    TF_CHECK_MSG(nf_expect_u64(&node, "closed=", 3, T_IO_MS) == 0,
                 "closed should be 3");

    tc_close(&ann);
    tc_close(&bee);
    tc_close(&probe);
    nf_free(&node);
    tf_done("nick_utf8");
    return 0;
}
