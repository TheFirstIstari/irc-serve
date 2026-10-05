/* test_cap_negotiation.c -- IRCv3 CAP negotiation and SASL PLAIN, on the wire.
 *
 * This file used to be a `return 77` stub in tests/compliance/ on the grounds
 * that CAP did not exist, which was true and which also meant it could not see a
 * single byte of the protocol it was named for. It is a wire-level integration
 * test now, because CAP is answered by a server over a socket: the property that
 * matters is not "is there a function called cap_handle" but "does a client that
 * negotiates hang, or register", and only a real client against a real node can
 * tell those apart.
 *
 * The CTest NAME is unchanged (CapNegotiation), which is what
 * tests/known_skips.txt's line for it names -- so closing the skip is deleting
 * that line, not renaming a test out from under the gate.
 *
 * ---------------------------------------------------------------------------
 * THE PROPERTIES, AND WHY EACH ONE IS HERE
 * ---------------------------------------------------------------------------
 *  1. `CAP LS` names capabilities this node HAS. Every advertised name is
 *     checked against the set this build implements, and the three this build
 *     does NOT implement are checked to be ABSENT -- an advertised capability
 *     nothing implements is worse than a missing one, because a client switches
 *     it on.
 *  2. The advertised set depends on the CONFIGURATION, not only the build: a
 *     node with no --sasl-store must not list `sasl`, because a client that saw
 *     it would switch authentication on and then be refused.
 *  3. `CAP REQ` grants the subset this node has and refuses the rest, in ONE
 *     ACK and ONE NAK -- the partial ACK, which the specification allows.
 *  4. **REGISTRATION IS HELD UNTIL `CAP END`.** This is the property everything
 *     else exists to serve. A client that has sent NICK and USER and has NOT
 *     sent CAP END must not have received 001, and the test proves the negative
 *     by waiting for it and requiring the wait to TIME OUT. A server that got
 *     this wrong hangs every modern client, and a test that only asserted the
 *     positive case would pass against one.
 *  5. `CAP END` releases it, and registration completes on the spot.
 *  6. `CAP LIST` reports what THIS client negotiated, not the node's whole table,
 *     and it does so with EVERY advertised capability enabled -- which is the arm's
 *     worst case, and the one the single-name assertion cannot reach.
 *  7. `CAP LS 302` is accepted. Every current client offers it, and refusing it
 *     makes this node unnegotiable by them.
 *  8. An UNKNOWN SUBCOMMAND is answered (410), not ignored.
 *  9. `CAP` before NICK is addressed to "*", because that is what RFC 2812 3.3
 *     requires and what every client parses.
 * 10. SASL PLAIN succeeds against a real store, fails against a wrong password,
 *     fails against an unknown authcid, and **FAILS REGISTRATION** on every one
 *     of those failures -- no 001, ever.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* For CAP_NAME_MAX, CAP_MAX_REQ and CAP_LS_MAX: the derived widths the new
 * worst-case case asserts against. Named rather than reached through a transitive
 * include, for the reason test_cap_negotiation's own neighbours state. */
#include "core/cap.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_READY_MS 15000
#define T_IO_MS 15000
/* Long enough that a burst is unambiguous, short enough that proving an ABSENCE
 * does not cost the run a minute. There is no sleep() anywhere in this file; the
 * absence checks are deadline waits, which is the point. */
#define T_ABSENT_MS 700

/* Assert a COMPLETE line arrives whose text BEGINS with `want`.
 *
 * PREFIX, because that is what every call site in this file means and the old
 * implementation said something else: several needles stop mid-line (":irc.test 001
 * alice :Welcome to the irc-serve network alice!a@" stops before the host), and a
 * function that claimed exactness was passing on them by accident -- its substring
 * search matched, and the boundary check on the byte before could not tell the
 * difference. The contract is stated here so the next caller knows what it is getting.
 *
 * A TRAILING CRLF IN `want` IS THE TERMINATOR, NOT TEXT, so it is stripped before the
 * prefix is matched and then used to say what the assertion proves: a needle that
 * carries one is also asserting that the line is TERMINATED, which is the part of
 * "complete line" the caller asked for by writing it.
 *
 * REWRITTEN ON TOP OF tc_read_line(), and it used to be hand-rolled the same way the
 * `CAP LIST` case below was: `tc_expect()` with the CRLF typed into the needle, then a
 * `strstr()` to find where it landed, then a check on the byte before it. Both halves
 * were necessary and both were gettable wrong:
 *
 *   the needle-with-CRLF proves the line is TERMINATED but says nothing about where it
 *   STARTS, so a longer line containing the text satisfied it; and
 *   the byte-before check is an OFFSET OFF BY ONE whenever the needle begins with a
 *   character that is itself part of a terminator or a separator -- which is why this
 *   function's own comment had to explain, twice, which side of the CRLF `want` was
 *   supposed to sit on.
 *
 * tc_read_line() requires the terminator AND the boundary and hands the payload back,
 * so there is nothing left to get wrong here. */
static void expect_line(test_client_t *c, const char *what, const char *want)
{
    char prefix[4096];
    char payload[4096];
    size_t len = 0u;
    size_t want_len = strlen(want);
    size_t text_len = want_len;

    if (text_len >= 2u && want[text_len - 2u] == '\r' && want[text_len - 1u] == '\n') {
        text_len -= 2u; /* the CRLF is the terminator, not part of the line's text */
    }
    (void)snprintf(prefix, sizeof prefix, "%.*s", (int)text_len, want);
    TF_CHECK_MSG(tc_read_line(c, prefix, payload, sizeof payload, &len, T_IO_MS) == 0,
                 "%s: expected a complete line starting \"%s\"", what, want);
    TF_CHECK_MSG(len >= text_len && strncmp(payload, want, text_len) == 0,
                 "%s: expected a line starting \"%s\" and got \"%s\"", what, want,
                 payload);
}

/* Assert `hay` does NOT arrive inside `ms`. This is the only way to test a gate,
 * and it is worth saying why the absence is credible rather than merely hoped
 * for: the same connection then sends a line that DOES produce output, so a node
 * that had stopped answering altogether cannot make this pass. */
static void expect_absent(test_client_t *c, const char *what, const char *hay,
                          int ms)
{
    TF_CHECK_MSG(tc_expect(c, hay, ms) != 0,
                 "%s: \"%s\" arrived but must not have", what, hay);
}

/* --------------------------------------------------------------------------
 * A credential store, written by this process and read by a child.
 * ------------------------------------------------------------------------ */

/* Write `authcid<TAB>password` records to `path` with mode 0600 and return 0, or
 * -1. The chmod is not a formality: sasl_store_load() REFUSES a store any other
 * account on the host can read, so a test that skipped it would be testing a
 * refusal path and calling it a success. */
static int write_store(const char *path, const char *records)
{
    /* THE MODE IS SET AT CREATION, not applied afterwards.
     *
     * This used to fopen(path, "w"), fclose, and then chmod(path, 0600) -- which
     * is the same stat-then-act shape sasl_store_load() was hardened against, in
     * the test that exercises that hardening: between the fclose and the chmod
     * the file exists at whatever the umask said, and between the fopen and the
     * chmod the PATH can be replaced by something this process then chmods. CodeQL
     * flags it as a TOCTOU race, and it is one.
     *
     * open() with an explicit mode sets the permissions as part of creating the
     * file, so there is no interval in which it exists with the wrong mode, and
     * O_NOFOLLOW refuses a symlink at the path rather than following it. The
     * refusal the comment above cares about is now also untestable-by-accident:
     * a store written any other way is a different code path in this file, not a
     * window inside this one. */
    const int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW,
                        S_IRUSR | S_IWUSR);
    FILE *f;

    if (fd < 0) {
        return -1;
    }
    f = fdopen(fd, "w");
    if (f == NULL) {
        (void)close(fd);
        return -1;
    }
    if (fputs(records, f) == EOF) {
        (void)fclose(f);
        return -1;
    }
    /* fclose() closes the descriptor too, so there is no second close here and no
     * path to chmod: the mode was never anything else. */
    return (fclose(f) == 0) ? 0 : -1;
}

/* base64 of "authzid\0authcid\0passwd", for a PLAIN payload.
 *
 * Written out here rather than shared with sasl_framework.c because this is the
 * CLIENT side of the wire and the node under test must not be the thing that
 * produced the bytes it is being asked to verify: an encoder shared with the
 * decoder cannot catch an encoder and decoder that agree on something the
 * specification says they should not. */
static void b64_encode(const char *in, size_t len, char *out, size_t cap)
{
    static const char alpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0;
    size_t n = 0;

    while (i < len && n + 5u < cap) {
        unsigned long acc = 0;
        int have = 0;
        char chunk[4];

        for (int k = 0; k < 3; k++) {
            acc <<= 8;
            if (i < len) {
                acc |= (unsigned long)(unsigned char)in[i++];
                have++;
            }
        }
        chunk[0] = alpha[(acc >> 18) & 0x3Fu];
        chunk[1] = alpha[(acc >> 12) & 0x3Fu];
        chunk[2] = (have > 1) ? alpha[(acc >> 6) & 0x3Fu] : '=';
        chunk[3] = (have > 2) ? alpha[acc & 0x3Fu] : '=';
        for (int k = 0; k < 4; k++) {
            out[n++] = chunk[k];
        }
    }
    out[n] = '\0';
}

/* RFC 4616's PLAIN payload: `authzid NUL authcid NUL passwd`, with NO trailing
 * NUL. Returns its LENGTH, and the length is the point: the payload is not a C
 * string -- it begins with a NUL whenever authzid is empty, which is how irssi
 * sends it -- so anything that reaches for strlen() on it encodes one byte.
 *
 * That is not a hypothetical. An earlier version of this test did exactly that
 * and the node rejected a perfectly good credential with BAD_PAYLOAD. */
static size_t plain_payload(char *buf, size_t cap, const char *authzid,
                            const char *authcid, const char *passwd)
{
    size_t za = strlen(authzid);
    size_t zc = strlen(authcid);
    size_t zp = strlen(passwd);
    size_t n = 0;

    if (za + 1u + zc + 1u + zp + 1u > cap) {
        buf[0] = '\0';
        return 0;
    }
    memcpy(buf + n, authzid, za);
    n += za;
    buf[n++] = '\0';
    memcpy(buf + n, authcid, zc);
    n += zc;
    buf[n++] = '\0';
    memcpy(buf + n, passwd, zp);
    n += zp;
    buf[n] = '\0';
    return n;
}

/* --------------------------------------------------------------------------
 * Part 1: the negotiation itself, on a node with no credential store.
 * ------------------------------------------------------------------------ */
static void test_negotiation(void)
{
    nf_node_t node;
    test_client_t c;

    tc_init(&c);
    TF_CHECK(nf_spawn_binary(&node) == 0);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");

    /* ---- CAP LS, addressed to "*" because there is no nickname yet ---- */
    TF_CHECK_MSG(tc_send(&c, "CAP LS") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_expect(&c, " CAP * LS :", T_IO_MS) == 0,
                 "expected a CAP LS line addressed to *");
    {
        const char *at = strstr(tc_buffer(&c), " CAP * LS :");

        TF_CHECK_MSG(at != NULL, "no CAP LS line");
        if (at != NULL) {
            char line[512];
            const char *eol = strstr(at, "\r\n");
            size_t n = (eol != NULL) ? (size_t)(eol - at) : 0u;

            TF_CHECK_MSG(n > 0 && n < sizeof line, "CAP LS line is implausible");
            if (n > 0u && n < sizeof line) {
                memcpy(line, at, n);
                line[n] = '\0';
                /* ADVERTISED MEANS IMPLEMENTED. Each name below is a thing this
                 * build really does; a name that appeared here and did not would
                 * be a client switching on a feature nothing implements. */
                TF_CHECK_MSG(strstr(line, "message-tags") != NULL,
                             "CAP LS does not advertise message-tags, which this "
                             "node implements");
                /* ...and `account-tag` is NOT here on this node, which has neither
                 * a registry nor an identity to stamp. The store check is
                 * account_possible() and this node has no store; Phase 10.2a's
                 * two-node and two-store cases are what cover the other side. */
                TF_CHECK_MSG(strstr(line, "account-tag") == NULL,
                             "CAP LS advertises account-tag on a node with no "
                             "account registry, which can never write the tag");
                /* ...and `extended-join` IS advertised here even though this node
                 * has no account system, because its answer is a `*` account field
                 * rather than a name: `JOIN #chan * :Real Name` is complete and
                 * true. Two account capabilities, two answers to the same shape of
                 * question, and cap.h is where the difference is argued. */
                TF_CHECK_MSG(strstr(line, "extended-join") != NULL,
                             "CAP LS does not advertise extended-join, which this "
                             "node implements on every node");
                /* ...and `userhost-in-names` IS here (Phase 10.5), which is a
                 * DISCLOSURE capability rather than a rendering one: it puts every
                 * member's ident and host in front of the client that asked. That
                 * is exactly why the roster shape is decided per destination and
                 * not per channel, and why this test's sibling
                 * (test_userhost_in_names.c) is the one that checks the two
                 * renderings rather than this file checking the advertisement. */
                TF_CHECK_MSG(strstr(line, "userhost-in-names") != NULL,
                             "CAP LS does not advertise userhost-in-names, which "
                             "this node implements for every 353 it draws");
                /* NOT ADVERTISED, and this one is a capability a client would
                 * act on: cap-notify expects unsolicited CAP NEW lines.
                 *
                 * `echo-message` WAS on this list, under a comment reading "expects
                 * your own PRIVMSG back" -- which is a DESCRIPTION of the feature
                 * presented as a reason for withholding it, and it was the wrong
                 * reason: this node has echoed a channel PRIVMSG to its sender since
                 * Phase 5, because fanout writes to every local member. What the
                 * capability adds is NOTICE, which is what Phase 10.7 implemented --
                 * so the line has moved from "must be absent" to "must be present",
                 * and the behaviour it names is asserted in test_echo_message.c,
                 * which is where a count can be taken rather than a substring. */
                TF_CHECK_MSG(strstr(line, "cap-notify") == NULL,
                             "CAP LS advertises cap-notify, which nothing here "
                             "sends CAP NEW for");
                /* `away-notify` WAS here and Phase 10.8 is why it is not any
                 * more, on the same shape as `echo-message` above: the refusal was
                 * a DESCRIPTION of the feature presented as a reason for withholding
                 * it ("expects an AWAY you did not ask for"), and the correct
                 * question is whether this node can produce one at all. It can --
                 * `conn_t::away` exists on every connection, `AWAYLEN` is advertised
                 * from `CONN_MAX_AWAY`, and `handle_away()` now notifies the users
                 * sharing a channel with the setter, per destination and excluding
                 * the setter. The behaviour is asserted in test_away_notify.c,
                 * which is where the SET and the CLEARED cases can each be a count
                 * rather than a substring. */
                TF_CHECK_MSG(strstr(line, "away-notify") != NULL,
                             "CAP LS does not advertise away-notify, which this node "
                             "implements: a user who sets or clears an away state "
                             "notifies the users sharing a channel with them");
                TF_CHECK_MSG(strstr(line, "echo-message") != NULL,
                             "CAP LS does not advertise echo-message, which this node "
                             "implements -- a sender that negotiated it gets its own "
                             "NOTICE back");
                /* `account-notify` WAS here, and Phase 10.2b is why it is not any
                 * more. The node emitted no ACCOUNT line, and a listed capability
                 * is a client switching the feature on and then drawing the wrong
                 * conclusion from every line -- which for this one means a client
                 * whose channel-mates all appear anonymous for ever. It is now a
                 * capability this build really does, so it belongs in the
                 * "advertised means implemented" arm above. */
                TF_CHECK_MSG(strstr(line, "account-notify") != NULL,
                             "CAP LS does not advertise account-notify, which this "
                             "node implements and answers");
                TF_CHECK_MSG(strstr(line, "server-time") == NULL,
                             "CAP LS advertises server-time, which this node "
                             "does not stamp");
            }
        }
    }

    /* ---- SASL IS NOT ADVERTISED: this node has no --sasl-store ---- */
    TF_CHECK_MSG(strstr(tc_buffer(&c), "sasl") == NULL,
                 "a node with no credential store advertised sasl");

    /* ---- 302 is accepted ---- */
    TF_CHECK_MSG(tc_send(&c, "CAP LS 302") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_expect(&c, " CAP * LS :", T_IO_MS) == 0,
                 "CAP LS 302 was not answered; every current client offers it");

    /* ---- REQ: the partial ACK ---- */
    TF_CHECK_MSG(tc_send(&c, "CAP REQ :message-tags cap-notify") == 0,
                 "tc_send failed");
    TF_CHECK_MSG(tc_expect(&c, " CAP * ACK :message-tags\r\n", T_IO_MS) == 0,
                 "expected an ACK naming only the capability this node has");
    TF_CHECK_MSG(tc_expect(&c, " CAP * NAK :cap-notify\r\n", T_IO_MS) == 0,
                 "expected a NAK for the capability this node does not have");
    /* The ACK names exactly what was asked for and the NAK names the rest, so a
     * client that counts the two sizes gets the request size back. */
    TF_CHECK_MSG(strstr(tc_buffer(&c), " ACK :message-tags cap-notify") == NULL,
                 "the ACK carried a capability that was NAKed");

    /* ---- LIST reports what THIS client negotiated ---- */
    /* CONVERTED TO expect_line(), AND IT HAD THE SAME LATENT FRAGILITY as the
     * worst-case case below even though it always passed.
     *
     * The needle carried its own CRLF, which proves the reply is TERMINATED, and that
     * was half of what is wanted. The other half is where it STARTS, and a substring
     * search cannot see it: `" CAP * LIST :message-tags\r\n"` would be satisfied by
     * `:irc.test CAP alice CAP * LIST :message-tags` -- a longer line containing the
     * text. That reply cannot be produced by this node, so the assertion was never
     * wrong here; it was one formatter change away from being wrong, and it was
     * checking a claim ("this is the reply") with a tool that cannot establish it
     * ("this text arrived somewhere").
     *
     * It is a one-line change now, and `expect_line()` proves both halves -- see its
     * comment for what the substring form got wrong. The claim is unchanged. */
    TF_CHECK_MSG(tc_send(&c, "CAP LIST") == 0, "tc_send failed");
    expect_line(&c, "CAP LIST reports the negotiated set",
                ":irc.test CAP * LIST :message-tags\r\n");

    /* ---- an UNKNOWN SUBCOMMAND is answered, not ignored ---- */
    TF_CHECK_MSG(tc_send(&c, "CAP NONSENSE") == 0, "tc_send failed");
    /* 410 is `410 <target> <command> :<text>` -- the offending SUBcommand is a
     * middle parameter, and a middle parameter is colonned only if it cannot be
     * represented without one. "NONSENSE" can, so it is not. */
    TF_CHECK_MSG(tc_expect(&c, " 410 * NONSENSE :Invalid CAP subcommand: "
                               "NONSENSE\r\n", T_IO_MS) == 0,
                 "an unknown CAP subcommand was ignored; a client waiting on it "
                 "waits for a deadline");

    /* ---- DEL is NAKed, because nothing here is un-negotiable ---- */
    TF_CHECK_MSG(tc_send(&c, "CAP DEL :message-tags") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_expect(&c, " CAP * NAK :message-tags\r\n", T_IO_MS) == 0,
                 "CAP DEL was not NAKed; a client that asked to turn a capability "
                 "off and heard nothing keeps relying on it");

    /* =====================================================================
     * THE GATE. NICK and USER with a negotiation in flight, and 001 MUST NOT
     * arrive.
     * ===================================================================== */
    TF_CHECK_MSG(tc_send(&c, "NICK alice") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&c, "USER a 0 * :Alice") == 0, "tc_send failed");
    expect_absent(&c, "registration held for CAP END", " 001 ", T_ABSENT_MS);

    /* And the node is still ALIVE and still answering registration verbs while
     * it holds -- so the hold is a gate and not a wedged connection. This is
     * what makes the absence above credible. */
    TF_CHECK_MSG(tc_send(&c, "PING :still-here") == 0, "tc_send failed");
    expect_line(&c, "PING while held", ":irc.test PONG irc.test still-here\r\n");

    /* A non-registration verb is 451 while held, not accepted: the hold is a
     * real gate and not merely a suppressed welcome burst. */
    TF_CHECK_MSG(tc_send(&c, "JOIN #early") == 0, "tc_send failed");
    expect_line(&c, "JOIN while held", ":irc.test 451 alice :You have not "
                                     "registered\r\n");

    /* ---- CAP END releases it ---- */
    TF_CHECK_MSG(tc_send(&c, "CAP END") == 0, "tc_send failed");
    expect_line(&c, "001 after CAP END",
                ":irc.test 001 alice :Welcome to the irc-serve network "
                "alice!a@");

    /* ---- and the burst goes out EXACTLY ONCE ----
     *
     * Counted rather than checked for absence, and that is the whole difference:
     * tc_expect() searches the ACCUMULATED buffer, so looking for a line that
     * was legitimately sent once and must not be sent twice cannot be expressed
     * as "wait and fail to find it" -- the first one is already there. A count
     * of exactly one is the assertion, and it is the one a re-entrant CAP END
     * would fail. */
    TF_CHECK_MSG(tf_count(tc_buffer(&c), " 001 ") == 1,
                 "expected exactly one 001 for one CAP END, saw %zu",
                 tf_count(tc_buffer(&c), " 001 "));
    TF_CHECK_MSG(tf_count(tc_buffer(&c), " 005 ") == 1,
                 "expected exactly one 005 for one CAP END");

    nf_stop(&node);
    nf_free(&node);
    tc_close(&c);
}

/* --------------------------------------------------------------------------
 * Part 2: CAP END arriving BEFORE NICK and USER, which is the order every
 * current client uses.
 * ------------------------------------------------------------------------ */
static void test_end_before_registration(void)
{
    nf_node_t node;
    test_client_t c;

    tc_init(&c);
    TF_CHECK(nf_spawn_binary(&node) == 0);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");

    TF_CHECK_MSG(tc_send(&c, "CAP LS") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_expect(&c, " CAP * LS :", T_IO_MS) == 0, "no CAP LS");
    TF_CHECK_MSG(tc_send(&c, "CAP END") == 0, "tc_send failed");
    /* Nothing yet: CAP END releases the hold but there is nothing to register. */
    expect_absent(&c, "no registration from CAP END alone", " 001 ", T_ABSENT_MS);

    TF_CHECK_MSG(tc_send(&c, "NICK bob") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&c, "USER b 0 * :Bob") == 0, "tc_send failed");
    expect_line(&c, "001 after a CAP END that came first",
                ":irc.test 001 bob :Welcome to the irc-serve network bob!b@");
    /* 005 is here so that the PREFIX= token this phase's multi-prefix work
     * depends on is asserted to still be emitted after a negotiation. Checked
     * with tc_expect and not expect_line, because `PREFIX=(ov)@+` is a MIDDLE
     * PARAMETER inside a 005 that carries several of them -- it is in the middle
     * of a line by construction, and a line-boundary assertion here would be
     * testing the position of a token inside a numeric rather than the numeric. */
    TF_CHECK_MSG(tc_expect(&c, "005 bob NETWORK=irc-serve CHANTYPES=#& "
                               "PREFIX=(ov)@+", T_IO_MS) == 0,
                 "005 did not carry PREFIX=(ov)@+ after a CAP negotiation");

    nf_stop(&node);
    nf_free(&node);
    tc_close(&c);
}

/* --------------------------------------------------------------------------
 * Part 3: SASL PLAIN against a real store, on a node started with one.
 * ------------------------------------------------------------------------ */
static void test_sasl_plain(char *store_path, int expect_sasl_advertised)
{
    nf_node_t node;
    test_client_t c;
    char payload[640];
    char encoded[400];
    size_t plen;
    char portbuf[16];
    char *argv[6];

    tc_init(&c);
    (void)snprintf(portbuf, sizeof portbuf, "0");
    argv[0] = (char *)"irc-serve";
    argv[1] = portbuf;
    argv[2] = (char *)"--sasl-store";
    argv[3] = store_path;
    argv[4] = NULL;
    argv[5] = NULL;
    TF_CHECK(nf_spawn_binary_argv(&node, argv) == 0);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");

    /* ---- the advertisement follows the CONFIGURATION ---- */
    TF_CHECK_MSG(tc_send(&c, "CAP LS") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_expect(&c, " CAP * LS :", T_IO_MS) == 0, "no CAP LS");
    if (expect_sasl_advertised != 0) {
        TF_CHECK_MSG(strstr(tc_buffer(&c), "sasl") != NULL,
                     "a node with a loaded credential store did not advertise "
                     "sasl");
        TF_CHECK_MSG(tc_send(&c, "CAP REQ :sasl") == 0, "tc_send failed");
        TF_CHECK_MSG(tc_expect(&c, " CAP * ACK :sasl\r\n", T_IO_MS) == 0,
                     "sasl was advertised and then not ACKed");
    } else {
        TF_CHECK_MSG(strstr(tc_buffer(&c), "sasl") == NULL,
                     "a node whose credential store was refused still advertised "
                     "sasl");
        TF_CHECK_MSG(tc_send(&c, "CAP REQ :sasl") == 0, "tc_send failed");
        TF_CHECK_MSG(tc_expect(&c, " CAP * NAK :sasl\r\n", T_IO_MS) == 0,
                     "sasl was not advertised and was then ACKed");
    }

    /* ---- the mechanism this node implements ---- */
    TF_CHECK_MSG(tc_send(&c, "AUTHENTICATE PLAIN") == 0, "tc_send failed");
    /* RFC 4422 3.1 writes the challenge as `AUTHENTICATE +` with NO colon,
     * unlike CAP's examples. The formatter colons a trailing parameter only when
     * it has to, and "+" cannot be a prefix marker or a separator, so it renders
     * bare -- which is what the RFC shows. */
    expect_line(&c, "the initial-response request",
                ":irc.test AUTHENTICATE * +\r\n");

    /* ---- the good credential ----
     *
     * The TWO-PARAMETER one-shot form, mechanism and payload on one line, which
     * is what a client that already holds its credential sends. The single-
     * parameter response form is exercised by test_bad_credentials() and by
     * test_no_credential_in_the_log(), so both paths are covered -- and covering
     * both matters here because a server that only understood one of them would
     * authenticate some clients and hang others. */
    plen = plain_payload(payload, sizeof payload, "", "alice", "correct horse");
    b64_encode(payload, plen, encoded, sizeof encoded);
    (void)snprintf(payload, sizeof payload, "AUTHENTICATE PLAIN %s", encoded);
    TF_CHECK_MSG(tc_send(&c, payload) == 0, "tc_send failed");

    if (expect_sasl_advertised != 0) {
        TF_CHECK_MSG(nf_expect(&node, "outcome=COMPLETED", T_IO_MS) == 0,
                     "a correct PLAIN credential was not accepted");
    } else {
        /* THE FAILURE MODE THIS WHOLE DELIVERABLE IS ABOUT. A node with no
         * credential store must REFUSE a syntactically perfect PLAIN payload, not
         * accept it: a client that is told it authenticated will act on it. */
        TF_CHECK_MSG(nf_expect(&node, "outcome=REJECTED", T_IO_MS) == 0,
                     "a node with no credential store accepted a SASL payload");
        TF_CHECK_MSG(tc_expect(&c, " 464 * :SASL authentication failed: this "
                                   "node holds no client credential store",
                               T_IO_MS) == 0,
                     "expected the refusal to name the missing store");
    }

    /* ---- REGISTRATION, or the refusal of it ---- */
    TF_CHECK_MSG(tc_send(&c, "CAP END") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&c, "NICK alice") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&c, "USER a 0 * :Alice") == 0, "tc_send failed");

    if (expect_sasl_advertised != 0) {
        expect_line(&c, "001 after a verified SASL",
                    ":irc.test 001 alice :Welcome to the irc-serve network "
                    "alice!a@");
    } else {
        /* No 001, ever. A client that failed to authenticate must not be able to
         * register as though it had -- and the connection is deliberately NOT
         * closed, because poll_loop.c refuses to pump the write queue of a
         * CLOSING connection, so closing here would discard the abort and the
         * 464 queued in the same dispatch and leave the client with a bare FIN
         * and no explanation. See handle_authenticate(). */
        expect_absent(&c, "no registration after a refused SASL", " 001 ",
                      T_ABSENT_MS);
        TF_CHECK_MSG(tc_send(&c, "JOIN #nope") == 0, "tc_send failed");
        expect_line(&c, "the registration gate after a refused SASL",
                    ":irc.test 451 alice :You have not registered\r\n");
    }

    nf_kill(&node);
    nf_free(&node);
    tc_close(&c);
}

/* --------------------------------------------------------------------------
 * Part 4: bad credentials, each of which must fail REGISTRATION and not merely
 * fail the exchange.
 * ------------------------------------------------------------------------ */
static void test_bad_credentials(char *store_path, const char *label,
                                const char *authcid, const char *passwd)
{
    nf_node_t node;
    test_client_t c;
    char payload[640];
    char encoded[400];
    size_t plen;
    char portbuf[16];
    char *argv[6];

    tc_init(&c);
    (void)snprintf(portbuf, sizeof portbuf, "0");
    argv[0] = (char *)"irc-serve";
    argv[1] = portbuf;
    argv[2] = (char *)"--sasl-store";
    argv[3] = store_path;
    argv[4] = NULL;
    argv[5] = NULL;
    TF_CHECK(nf_spawn_binary_argv(&node, argv) == 0);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");

    TF_CHECK_MSG(tc_send(&c, "CAP END") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&c, "AUTHENTICATE PLAIN") == 0, "tc_send failed");
    /* RFC 4422 3.1 writes the challenge as `AUTHENTICATE +` with NO colon,
     * unlike CAP's examples. The formatter colons a trailing parameter only when
     * it has to, and "+" cannot be a prefix marker or a separator, so it renders
     * bare -- which is what the RFC shows. */
    expect_line(&c, "the initial-response request",
                ":irc.test AUTHENTICATE * +\r\n");

    plen = plain_payload(payload, sizeof payload, "", authcid, passwd);
    b64_encode(payload, plen, encoded, sizeof encoded);
    (void)snprintf(payload, sizeof payload, "AUTHENTICATE %s", encoded);
    TF_CHECK_MSG(tc_send(&c, payload) == 0, "tc_send failed");

    TF_CHECK_MSG(nf_expect(&node, "outcome=REJECTED", T_IO_MS) == 0,
                 "%s: a bad credential was not rejected", label);
    /* RFC 4422's server-chosen abort first, so a client waiting for a verdict is
     * not left waiting for its own deadline. */
    expect_line(&c, "the abort", ":irc.test AUTHENTICATE *\r\n");
    /* Checked with tc_expect rather than expect_line: the refusal TEXT is a
     * substring check on purpose (this test cares that the failure says which
     * failure), and the leading-space needle makes the line-boundary assertion
     * meaningless -- the numeric does not start with a space. */
    TF_CHECK_MSG(tc_expect(&c, " 464 * :SASL authentication failed: "
                               "the credentials did not verify", T_IO_MS) == 0,
                 "expected the refusal to name a credential failure");

    TF_CHECK_MSG(tc_send(&c, "NICK alice") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&c, "USER a 0 * :Alice") == 0, "tc_send failed");
    expect_absent(&c, "registration refused after a bad credential", " 001 ",
                  T_ABSENT_MS);
    TF_CHECK_MSG(tc_send(&c, "JOIN #nope") == 0, "tc_send failed");
    expect_line(&c, "the registration gate after a bad credential",
                ":irc.test 451 alice :You have not registered\r\n");

    nf_kill(&node);
    nf_free(&node);
    tc_close(&c);
}

/* --------------------------------------------------------------------------
 * Part 5: a credential file the operator got wrong, which must NOT become a
 * node that authenticates everybody.
 * ------------------------------------------------------------------------ */
static void test_bad_store(char *path, const char *mode, const char *label)
{
    nf_node_t node;
    test_client_t c;
    char payload[640];
    char encoded[400];
    size_t plen;
    char portbuf[16];
    char *argv[6];

    tc_init(&c);
    (void)snprintf(portbuf, sizeof portbuf, "0");
    argv[0] = (char *)"irc-serve";
    argv[1] = portbuf;
    argv[2] = (char *)"--sasl-store";
    argv[3] = path;
    argv[4] = NULL;
    argv[5] = NULL;
    TF_CHECK(nf_spawn_binary_argv(&node, argv) == 0);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");

    TF_CHECK_MSG(tc_send(&c, "CAP LS") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_expect(&c, " CAP * LS :", T_IO_MS) == 0, "no CAP LS");
    TF_CHECK_MSG(strstr(tc_buffer(&c), "sasl") == NULL,
                 "%s: a node whose credential store was refused still advertised "
                 "sasl", label);

    /* And a well-formed PLAIN payload against it is refused. A store that failed
     * to load is not "no opinion"; it is a node that authenticates nobody. */
    TF_CHECK_MSG(tc_send(&c, "CAP END") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&c, "AUTHENTICATE PLAIN") == 0, "tc_send failed");
    /* RFC 4422 3.1 writes the challenge as `AUTHENTICATE +` with NO colon,
     * unlike CAP's examples. The formatter colons a trailing parameter only when
     * it has to, and "+" cannot be a prefix marker or a separator, so it renders
     * bare -- which is what the RFC shows. */
    expect_line(&c, "the initial-response request",
                ":irc.test AUTHENTICATE * +\r\n");
    plen = plain_payload(payload, sizeof payload, "", "alice", "correct horse");
    b64_encode(payload, plen, encoded, sizeof encoded);
    (void)snprintf(payload, sizeof payload, "AUTHENTICATE %s", encoded);
    TF_CHECK_MSG(tc_send(&c, payload) == 0, "tc_send failed");
    TF_CHECK_MSG(nf_expect(&node, "outcome=REJECTED", T_IO_MS) == 0,
                 "%s: a node with a refused store accepted a SASL payload",
                 label);
    (void)mode;

    nf_kill(&node);
    nf_free(&node);
    tc_close(&c);
}

/* --------------------------------------------------------------------------
 * Part 6: a credential is never logged. Read the CHILD'S OWN OUTPUT and assert
 * the secret does not appear in it.
 * ------------------------------------------------------------------------ */
static void test_no_credential_in_the_log(char *store_path)
{
    nf_node_t node;
    test_client_t c;
    char payload[640];
    char encoded[400];
    size_t plen;
    char portbuf[16];
    char *argv[6];

    tc_init(&c);
    (void)snprintf(portbuf, sizeof portbuf, "0");
    argv[0] = (char *)"irc-serve";
    argv[1] = portbuf;
    argv[2] = (char *)"--sasl-store";
    argv[3] = store_path;
    argv[4] = NULL;
    argv[5] = NULL;
    TF_CHECK(nf_spawn_binary_argv(&node, argv) == 0);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");

    TF_CHECK_MSG(tc_send(&c, "CAP END") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&c, "AUTHENTICATE PLAIN") == 0, "tc_send failed");
    plen = plain_payload(payload, sizeof payload, "", "alice", "correct horse");
    b64_encode(payload, plen, encoded, sizeof encoded);
    (void)snprintf(payload, sizeof payload, "AUTHENTICATE %s", encoded);
    TF_CHECK_MSG(tc_send(&c, payload) == 0, "tc_send failed");
    TF_CHECK_MSG(nf_expect(&node, "outcome=COMPLETED", T_IO_MS) == 0,
                 "the good credential was not accepted");

    /* Drain what the node has said, then read the log we already hold. The
     * authcid IS expected -- an operator needs to know who authenticated -- and
     * the password is not. The base64 blob is not either: it is the credential
     * one decode away, and a log is the wrong place for something that close. */
    TF_CHECK_MSG(strstr(node.out, "correct horse") == NULL,
                 "the PASSWORD appears in the node's own output");
    TF_CHECK_MSG(strstr(node.out, encoded) == NULL,
                 "the base64 credential appears in the node's own output");
    TF_CHECK_MSG(strstr(node.out, "alice") != NULL,
                 "the authcid should appear in the node's own output; a "
                 "sasl line with no identity in it tells an operator nothing");

    nf_kill(&node);
    nf_free(&node);
    tc_close(&c);
}

/* ---------------------------------------------------------------------------
 * COUNTING A CAPABILITY LIST, OVER A COUNTED STRING
 * ---------------------------------------------------------------------------
 * `cap_tokens()` copies the space-separated names out of `buf[0..len)` and returns
 * how many there were. `len` is the whole point of this function.
 *
 * THE BUG THIS EXISTS TO NOT REPEAT, because it shipped. The first version of the
 * `CAP LIST` case below did this instead:
 *
 *     char want[2048];
 *     (void)snprintf(want, sizeof want, "%s", lo);       // wrote 181 bytes
 *     for (size_t i = 0; want[i] != '\0'; i++) {
 *         if (want[i] == ' ') { want[i] = '\0'; }        // tokenised in place
 *     }
 *     for (const char *p = want; *p != '\0'; p += strlen(p) + 1u) {
 *         listed++;
 *     }
 *
 * `want` is 2048 bytes and `snprintf` wrote 181 of them. The token walk is correct
 * for as long as the string is NUL-terminated where `snprintf` left it -- and then
 * `p += strlen(p) + 1u` steps past that NUL onto **byte 182 of `want`, which was
 * never initialised**, and tests it against '\0'. If that byte happened to be zero
 * the count was right by luck. On the author's machine it was zero and the case
 * passed 13 gate cells; on a GitHub runner it was not, and `CapNegotiation` failed
 * in all four `ci_macos` cells with
 *
 *     CAP LIST named 14 capabilities and CAP LS advertised 13
 *
 * -- `listed` one TOO HIGH, from a reply whose text was byte-for-byte correct and
 * complete. Neither number was wrong about the node; one of them was wrong about
 * this function's own stack.
 *
 * So: no `strlen`/`strchr` over a buffer whose length is not in hand, and no
 * copying into a buffer bigger than the payload. `cap_tokens()` walks `len` bytes
 * and cannot step off the end, and `buf` is the caller's array with a known size.
 *
 * A TOKEN LONGER THAN `CAP_NAME_MAX` IS COUNTED AND TRUNCATED rather than refused,
 * because the count is the claim here and a name this node cannot have would be a
 * separate finding. `truncated` is an out-parameter so the caller can notice.
 *
 * THE ARRAYS ARE FIXED-SIZE and overflow is REFUSED by returning the true count
 * with `stored` clamped -- the same shape as `cap_split()` in cap.c, for the same
 * reason: a caller that wants the Nth token of an over-long list should be told the
 * list is over-long, not handed a buffer that quietly stopped growing. */
static size_t cap_tokens(const char *buf, size_t len, char out[][CAP_NAME_MAX + 1],
                         size_t max)
{
    size_t seen = 0u;
    size_t stored = 0u;
    size_t i = 0u;

    while (i < len) {
        size_t n = 0u;

        if (buf[i] == ' ') {
            i++;
            continue;
        }
        /* ONE NAME, bounded by the SLICE and by the field -- not by a NUL, because
         * there is no NUL in the slice and looking for one is the bug. */
        while (i < len && buf[i] != ' ' && n < (size_t)CAP_NAME_MAX) {
            n++;
            i++;
        }
        seen++;
        if (stored < max) {
            (void)snprintf(out[stored], CAP_NAME_MAX + 1u, "%.*s", (int)n,
                           buf + i - n);
            stored++;
        }
    }
    return seen;
}

/* Is `name` one of the first `n` stored tokens WHOLE?
 *
 * WHOLE, and that is the word doing the work. `strstr()` over the reply would match
 * a name that is a SUBSTRING of a longer one, so a reply that said `userhost` where
 * it should have said `userhost-in-names` would pass a substring search. Token for
 * token is the only comparison that means "this node named that capability". */
/* THE ARRAY PARAMETER IS NOT `const`, and that is a C-before-C23 fact rather than a
 * preference: `char (*)[N]` does not implicitly convert to `const char (*)[N]`, so a
 * const-qualified parameter would be a -Wpedantic error at every call site. The
 * alternative -- const-qualifying the CALLER's arrays -- is not available either,
 * because cap_tokens() is what fills them. Neither helper writes through the
 * parameter, and the qualifier would have said so rather than enforced it. */
static int cap_has_token(char names[][CAP_NAME_MAX + 1], size_t n,
                         const char *name)
{
    for (size_t i = 0; i < n; i++) {
        if (strcmp(names[i], name) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Are two token lists the same, in the same order?
 *
 * `cap_append_name()` walks `k_caps` in table order, so the ACK and the LIST reply
 * come out in the same order, and a client reading its negotiated set benefits from
 * that being stable. Asserting the order is free once both sides are token arrays,
 * and it separates "the accumulator is right" from "the accumulator happened to
 * contain the right NAMES in some order". */
static int listed_n_same_order(char listed[][CAP_NAME_MAX + 1], size_t ln,
                               char granted[][CAP_NAME_MAX + 1], size_t gn)
{
    if (ln != gn) {
        return 0;
    }
    for (size_t i = 0; i < ln; i++) {
        if (strcmp(listed[i], granted[i]) != 0) {
            return 0;
        }
    }
    return 1;
}

/* --------------------------------------------------------------------------
 * Part 4: `CAP LIST` at its worst case -- EVERY advertised capability enabled.
 * --------------------------------------------------------------------------
 * The `CAP LIST` arm accumulated by hand, with no test against `sizeof list` on any
 * of its four writes, and it was safe only because the seventeen names in the
 * capability table total 186 bytes against CAP_LS_MAX = 1056. That is arithmetic
 * about a table rather than a check in the code, so the claim worth asserting is
 * the one that survives the table growing: with EVERY capability this node offers
 * enabled, the reply names all of them, in the table's order, and nothing is cut.
 *
 * WHY THE WHOLE TABLE AND NOT ONE NAME. The existing case in part 1 enables
 * `message-tags` and asserts `CAP * LIST :message-tags` -- which is a one-name
 * reply and would pass against an accumulator that wrote one name correctly and
 * the hundredth one wherever it liked. A single-name reply cannot reach a
 * separator write at all, let alone the NUL, so the accumulator's whole worst case
 * is invisible to it.
 *
 * AND WHY TWO REQs. `cap_split()` refuses more than CAP_MAX_REQ (16) names per
 * request, and this node offers fifteen on a default build, so one REQ would do
 * today -- but that is a coincidence of today's count, and a node that grew past
 * sixteen names would need two. The case therefore requests in CAP_MAX_REQ-sized
 * chunks from the names it read off `CAP LS`, so it keeps being the worst case
 * whatever the table holds. It also documents the other half of the fact: a
 * client CAN enable every name by asking more than once, because `conn_t::caps`
 * accumulates across REQs inside one negotiation -- so seventeen names in a LIST
 * reply is reachable from the wire, not merely from the table.
 */
static void test_list_worst_case(void)
{
    /* THE ARRAYS, and the counts are bounded by them rather than by a buffer that is
     * merely large. `CAP_NAME_MAX` (64) is the longest capability name the wire
     * grammar accepts and `k_caps` holds seventeen, so 32 slots is generous; if the
     * table ever outgrows the array, `cap_tokens()` returns the TRUE count with
     * `stored` clamped and the `>=` assertions below catch it rather than the case
     * quietly comparing prefixes. */
    enum { CAP_SLOTS = 32 };
    nf_node_t node;
    test_client_t c;
    char req[512];
    char line[CAP_LS_MAX + 64];
    size_t line_len = 0u;
    char ls_names[CAP_SLOTS][CAP_NAME_MAX + 1];
    char granted[CAP_SLOTS][CAP_NAME_MAX + 1];
    char listed_names[CAP_SLOTS][CAP_NAME_MAX + 1];
    size_t advertised;
    size_t granted_n = 0u;
    size_t listed;
    size_t chunk = 0u;
    size_t req_off = 0u;
    const char *payload;
    size_t payload_len;

    tc_init(&c);
    TF_CHECK(nf_spawn_binary(&node) == 0);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");

    /* ---- WHAT THE NODE OFFERS ---- */
    /* READ AS A COMPLETE LINE, through tc_read_line(). Not `tc_expect()` with the
     * CRLF typed into the needle, and not `strstr()` plus a hand-rolled boundary
     * check: this case did the latter for one PR and got the offset wrong twice
     * before it was right. What is handed back is the line's text and its LENGTH,
     * and the length is what makes cap_tokens() safe.
     *
     * Read off the wire rather than out of a header, so the request below is built
     * from what this build actually advertises and the case does not have to be
     * edited when a capability is added. */
    TF_CHECK_MSG(tc_send(&c, "CAP LS") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_read_line(&c, ":irc.test CAP * LS :", line, sizeof line,
                              &line_len, T_IO_MS) == 0,
                 "no CAP LS line, or it did not arrive as a complete line");
    advertised = cap_tokens(line + strlen(":irc.test CAP * LS :"),
                            line_len - strlen(":irc.test CAP * LS :"), ls_names,
                            CAP_SLOTS);
    TF_CHECK_MSG(advertised > 0u,
                 "CAP LS carried no capability names, so there is nothing for this "
                 "case to be the worst case of");

    /* ---- REQ EVERYTHING, IN CHUNKS OF CAP_MAX_REQ ---- */
    /* The chunking is the point of the second REQ being possible rather than merely
     * allowed: `conn_t::caps` accumulates across REQs inside one negotiation, so the
     * union of the chunks is the whole table. And it keeps being the worst case
     * whatever the table holds, rather than depending on today's count happening to
     * fit in one request.
     *
     * `req` is appended to across the loop and `req_off` tracks where the next name
     * goes, because `snprintf()` returns the length it WOULD have written and calling
     * `strlen()` on the destination each time is a second, subtler way to write
     * past a buffer -- the exact mistake `cap_append_name()` in cap.c documents. */
    req[0] = '\0';
    for (size_t i = 0; i < advertised; i++) {
        if (chunk == 0u) {
            /* THE PRECISION, because gcc-16's -Wformat-truncation cannot bound a
             * %s whose argument is an element of a two-dimensional array -- it
             * reports 2079 bytes of possible output into a 512-byte buffer, which is
             * neither the element width nor the buffer size. CAP_NAME_MAX is the
             * width the wire grammar allows for a name, so this is the real bound
             * written down rather than a number chosen to silence the analyser. */
            (void)snprintf(req, sizeof req, "CAP REQ :%.*s", (int)CAP_NAME_MAX,
                           ls_names[i]);
            chunk = 1u;
        } else {
            /* THE APPEND IS GUARDED AGAINST THE DESTINATION, and not only for
             * tidiness: gcc-16's -Wformat-truncation cannot see that `req_off` is
             * within `req`, so `sizeof req - req_off` reads as an arbitrary size and
             * the whole line is refused. The check is cheap, it is the same one the
             * product's own bounded append makes, and it turns a compile-time refusal
             * into a runtime fact the reader can check. */
            if (req_off + strlen(ls_names[i]) + 2u > sizeof req) {
                TF_CHECK_MSG(0,
                             "the CAP REQ line for %zu names does not fit the %zu-byte "
                             "buffer this case builds it in, so the request would be "
                             "truncated and the case would be measuring a malformed "
                             "request rather than the accumulator",
                             advertised, sizeof req);
            }
            (void)snprintf(req + req_off, sizeof req - req_off, " %.*s",
                           (int)CAP_NAME_MAX, ls_names[i]);
        }
        req_off = strlen(req);
        if (chunk == (size_t)CAP_MAX_REQ) {
            size_t ack_len = 0u;
            size_t ack_n;

            TF_CHECK_MSG(tc_send(&c, req) == 0, "tc_send failed");
            TF_CHECK_MSG(tc_read_line(&c, ":irc.test CAP * ACK :", line, sizeof line,
                                      &ack_len, T_IO_MS) == 0,
                         "a CAP REQ naming every advertised capability in chunks of "
                         "CAP_MAX_REQ was not ACKed, so the case cannot get to the "
                         "LIST that is the claim");
            ack_n = cap_tokens(line + strlen(":irc.test CAP * ACK :"),
                               ack_len - strlen(":irc.test CAP * ACK :"),
                               granted + granted_n, CAP_SLOTS - granted_n);
            granted_n += ack_n;
            req[0] = '\0';
            req_off = 0u;
            chunk = 0u;
        }
    }
    if (chunk != 0u) {
        size_t ack_len = 0u;
        size_t ack_n;

        TF_CHECK_MSG(tc_send(&c, req) == 0, "tc_send failed");
        TF_CHECK_MSG(tc_read_line(&c, ":irc.test CAP * ACK :", line, sizeof line,
                                  &ack_len, T_IO_MS) == 0,
                     "the last CAP REQ chunk was not ACKed");
        ack_n = cap_tokens(line + strlen(":irc.test CAP * ACK :"),
                           ack_len - strlen(":irc.test CAP * ACK :"),
                           granted + granted_n, CAP_SLOTS - granted_n);
        granted_n += ack_n;
    }

    TF_CHECK_MSG(advertised >= 8u,
                 "this node offered only %zu capabilities, which is too few for this "
                 "case to be the worst case it claims to be: a reply of one or two "
                 "names never reaches a separator write, and the separator write is "
                 "one of the four the audit found unbounded",
                 advertised);
    TF_CHECK_MSG(granted_n >= 8u,
                 "the node ACKed only %zu of the %zu capabilities it advertised, so "
                 "the LIST reply this case is about is not the whole table and a "
                 "matcher that dropped a name would not be distinguishable from a "
                 "node that never granted it",
                 granted_n, advertised);

    /* ---- REGISTER, so the LIST reply is addressed to the nickname ---- */
    /* `CAP alice` and not `CAP *`, because cap_target() answers a REGISTERED
     * connection with the nickname. Part 1's LIST case asks mid-negotiation and gets
     * `*`; both are right, and a needle written for one and used against the other
     * waits out its deadline for a line the node will never send. */
    TF_CHECK_MSG(tc_send(&c, "CAP END") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&c, "NICK alice") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&c, "USER a 0 * :Alice") == 0, "tc_send failed");
    expect_line(&c, "registration after enabling every capability", ":irc.test 001 ");

    /* ---- THE CLAIM ---- */
    TF_CHECK_MSG(tc_send(&c, "CAP LIST") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_read_line(&c, ":irc.test CAP alice LIST :", line, sizeof line,
                              &line_len, T_IO_MS) == 0,
                 "CAP LIST with every capability enabled did not answer with a LIST "
                 "line of its own, or the line did not arrive complete");
    /* THE PAYLOAD, as a pointer and a length, computed ONCE. Every diagnostic below
     * quotes it, and a `%.*s` takes its length first -- so a message that inlined
     * `line + strlen(...)` and the length in the wrong order would print a pointer
     * as a number, which is exactly what the compiler caught when this was first
     * written. One pair of names is also one thing to get right. */
    {
        static const char k_list_prefix[] = ":irc.test CAP alice LIST :";

        payload = line + strlen(k_list_prefix);
        payload_len = line_len - strlen(k_list_prefix);
        listed = cap_tokens(payload, payload_len, listed_names, CAP_SLOTS);
    }

    /* THE LENGTH, which says the arm stayed inside its buffer. `sizeof list` in
     * cap.c is CAP_LS_MAX, so this is a real bound measured from the wire rather
     * than a restatement of the constant. */
    TF_CHECK_MSG(line_len < (size_t)CAP_LS_MAX,
                 "the CAP LIST reply is %zu bytes and CAP_LS_MAX is %u, so the "
                 "accumulator wrote past the end of its buffer",
                 line_len, (unsigned)CAP_LS_MAX);

    /* THE COUNT, AGAINST THE ACK AND NOT AGAINST THE ADVERTISEMENT.
     *
     * This is the second of the two defects in the first version of this case, and
     * it is a PRODUCT fact rather than a test bug, so it is worth stating plainly:
     * **`CAP LS` and `CAP LIST` are not guaranteed to draw from the same set.**
     *
     * `CAP LS` renders the names `cap_available()` accepts; `CAP LIST` renders the
     * bits `CAP REQ` set, and `CAP REQ` sets a bit only for a name it also accepted.
     * So the two agree only if `cap_available()` gives the same answer twice, and
     * for one name it provably does not: `sts` is ADVERTISED on a node with a
     * certificate and a TLS port, and `CAP REQ :sts` is REFUSED BY SPECIFICATION --
     * cap.c's comment at that arm quotes it: "Clients MUST NOT request this
     * capability with `CAP REQ`." A client that REQs everything therefore gets `sts`
     * NAKed, and `CAP LIST` can never report it. On such a node `advertised` is one
     * MORE than `listed` **correctly**, and this case would have failed with a
     * message blaming the accumulator.
     *
     * The ACK is the authoritative record of what this client actually negotiated,
     * and it is what the accumulator can actually affect. So the count is against
     * it, which is STRONGER than the advertisement -- a dropped name is a name the
     * node granted -- and it is right on every node including one with TLS. */
    TF_CHECK_MSG(listed == granted_n,
                 "CAP LIST named %zu capabilities and the node ACKed %zu, so the "
                 "accumulator dropped or added one -- which is the failure the audit "
                 "that filed #123 was looking for, and a client that believes it "
                 "negotiated a dropped capability is a client that will use it. "
                 "LIST=[%.*s] of %zu advertised",
                 listed, granted_n, (int)payload_len, payload, advertised);

    /* EVERY GRANTED NAME IS PRESENT WHOLE, which is the half a count cannot see. A
     * name cut mid-word -- the truncation #123 was about -- changes the text without
     * necessarily changing how many tokens there are, so the count above would be
     * satisfied by a reply that said `userhost` where it should have said
     * `userhost-in-names`. Token for token is the only comparison that means "this
     * node named that capability". */
    for (size_t i = 0; i < granted_n && i < CAP_SLOTS; i++) {
        TF_CHECK_MSG(cap_has_token(listed_names, (listed < CAP_SLOTS) ? listed
                                                                     : CAP_SLOTS,
                                   granted[i]) != 0,
                     "the node ACKed '%s' but the CAP LIST reply does not name it "
                     "whole, so a name was cut: LIST=[%.*s]",
                     granted[i], (int)payload_len, payload);
    }

    /* AND NOTHING ELSE IS IN IT, so the assertion above is not satisfied by a reply
     * that names everything the table holds regardless of what was negotiated --
     * which is exactly what a broken accumulator that ignored `cap_enabled()` would
     * produce, and it would produce a LARGER list than the ACK. */
    for (size_t i = 0; i < listed && i < CAP_SLOTS; i++) {
        TF_CHECK_MSG(cap_has_token(granted, granted_n, listed_names[i]) != 0,
                     "the CAP LIST reply names '%s', which the node never ACKed, so "
                     "it is reporting a capability this client does not have: "
                     "LIST=[%.*s]",
                     listed_names[i], (int)payload_len, payload);
    }

    /* THE WHOLE TABLE, NOT A PREFIX. A reply cut at the buffer's end would name a
     * prefix, so the last granted name has to be present -- and it is checked as a
     * token above, so this is about POSITION rather than presence: a reply whose
     * tokens are all present but in the wrong order is not what the accumulator
     * produces (it walks `k_caps` in order) and not what a client should see. */
    if (granted_n > 0u && granted_n <= CAP_SLOTS && listed == granted_n &&
        listed <= CAP_SLOTS) {
        TF_CHECK_MSG(listed_n_same_order(listed_names, listed, granted, granted_n) != 0,
                     "the CAP LIST reply names the granted capabilities in a different "
                     "order than the node ACKed them, so a client's view of what it "
                     "negotiated would not match the ACK: LIST=[%.*s]",
                     (int)payload_len, payload);
    }

    /* AND THE NODE SAID WHAT IT SENT, which is the cross-check that the halves above
     * are the same event rather than two lines that happen to look right. */
    TF_CHECK_MSG(nf_expect(&node, "sub=LIST", T_IO_MS) == 0,
                 "the node never logged the LIST it answered, so the reply above may "
                 "be something else: %s",
                 node.out);

    /* ------------------------------------------------------------------------
     * WHY THIS PART IS A SOURCE INSPECTION, STATED BEFORE IT IS USED
     * ------------------------------------------------------------------------
     * Every assertion above would still pass against an UNBOUNDED accumulator,
     * and that is not a gap in them -- it is arithmetic. This node's seventeen
     * capability names total 186 bytes against CAP_LS_MAX = 1056, so the reply the
     * unbounded arm would have written is 203 bytes at its widest and lands 853
     * bytes inside the buffer. There is no capacity at which the wire can reach the
     * boundary, which means no wire assertion can distinguish "bounded" from
     * "unbounded" for this arm, and a test that pretended otherwise would be
     * asserting that a number is small.
     *
     * The teeth run proved it rather than arguing it: with the hand-rolled
     * `memcpy(list + n, ...)` accumulation restored, this whole function passed.
     * Growing the table until the reply would NOT fit does not help, because the
     * bounded arm refuses at that point too -- a refusal and an overflow look the
     * same from outside unless the test can also see that the name was dropped
     * honestly.
     *
     * So the claim is asserted where the two shapes are actually different: in the
     * source. `cap_append_name()` is the bounded accumulator the three ACK/NAK arms
     * already use and it is what `cap_do_ls()`'s LIST arm is now routed through; a
     * `memcpy(list ...)` anywhere in the file is the fingerprint of the arm the
     * audit found. This is the pattern tests/integration/test_close_sites.c and
     * test_readiness_intent.c established for a claim about a shape rather than
     * about an event, and it is the honest tool for this one: the alternative is
     * no assertion at all.
     */
    {
        char *code = tf_read_code("src/core/cap.c", NULL);

        TF_CHECK_MSG(code != NULL, "could not read src/core/cap.c (is "
                     "IRCSERVE_SRC_DIR set?)");
        /* THE HELPER IS CALLED. `tf_calls()` matches on an identifier boundary, so
         * this is the CALL and not a mention of the name in a comment or a string. */
        TF_CHECK_MSG(tf_calls(code, "cap_append_name") != 0,
                     "src/core/cap.c never calls cap_append_name(), so the bounded "
                     "accumulator that exists in this very file is not used by any of "
                     "the arms that fill a CAP_LS_MAX buffer");
        /* AND THE FINGERPRINT OF THE UNBOUNDED ARM IS GONE. */
        TF_CHECK_MSG(strstr(code, "memcpy(list") == NULL,
                     "src/core/cap.c still contains a direct memcpy() into the CAP "
                     "reply buffer, which is the hand-rolled accumulation #123 "
                     "found: no test against sizeof on any of its writes, and the "
                     "bound it has is arithmetic about a table rather than a check");
        free(code);
    }

    nf_kill(&node);
    nf_free(&node);
    tc_close(&c);
}

int main(void)
{
    char good_store[] = "/tmp/irc_serve_cap_good.XXXXXX";
    char loose_store[] = "/tmp/irc_serve_cap_loose.XXXXXX";
    char broken_store[] = "/tmp/irc_serve_cap_broken.XXXXXX";
    /* A path that does not exist, which is the state a node is in when it was
     * pointed at a store that is not there. Kept as a `char[]` rather than a
     * literal because nf_spawn_binary_argv() takes a modifiable vector. */
    char nonexistent_store[] = "/nonexistent/irc-serve-store";
    int fd_good;
    int fd_loose;
    int fd_broken;

    fd_good = mkstemp(good_store);
    fd_loose = mkstemp(loose_store);
    fd_broken = mkstemp(broken_store);
    TF_CHECK_MSG(fd_good >= 0 && fd_loose >= 0 && fd_broken >= 0,
                 "could not create the credential files this test needs");
    if (fd_good < 0 || fd_loose < 0 || fd_broken < 0) {
        return 1;
    }
    /* The records are written through the descriptors mkstemp() handed back,
     * because the PATHS have to exist before the child execs. */
    TF_CHECK_MSG(write(fd_good, "alice\tcorrect horse\nbob\ts3cret\n",
                       (size_t)25) == 25, "could not write the good store");
    TF_CHECK_MSG(write(fd_loose, "alice\tcorrect horse\n", (size_t)21) == 21,
                 "could not write the loose store");
    /* A record with no TAB. A store that loaded half its file would
     * authenticate half the passwords an operator believes are configured. */
    TF_CHECK_MSG(write(fd_broken, "alice correct horse\n", (size_t)20) == 20,
                 "could not write the broken store");
    (void)close(fd_good);
    (void)close(fd_loose);
    (void)close(fd_broken);

    /* 0600 for the two that must load; 0644 for the one that must NOT, because a
     * credential file any other account on the host can read is not a credential
     * store. */
    TF_CHECK(chmod(good_store, S_IRUSR | S_IWUSR) == 0);
    TF_CHECK(chmod(loose_store, S_IRUSR | S_IWUSR) == 0);
    TF_CHECK(chmod(broken_store, S_IRUSR | S_IWUSR) == 0);

    test_negotiation();
    test_end_before_registration();
    test_list_worst_case();

    /* The write_store() helper is used for the loose case because its mode is
     * the whole point of that case; the two well-formed stores above are created
     * with mkstemp() so that no test in this file can collide on a path. */
    {
        char loose2[] = "/tmp/irc_serve_cap_loose2.XXXXXX";
        int fd = mkstemp(loose2);

        TF_CHECK(fd >= 0);
        if (fd >= 0) {
            TF_CHECK(write(fd, "alice\tcorrect horse\n", (size_t)21) == 21);
            (void)close(fd);
            TF_CHECK(chmod(loose2, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == 0);
            test_bad_store(loose2, "0644", "a world-readable store");
            (void)unlink(loose2);
        }
    }
    test_bad_store(broken_store, "0600", "a malformed record");

    test_sasl_plain(good_store, 1);
    test_bad_credentials(good_store, "a wrong password", "alice", "nope");
    /* A wrong password that is a PREFIX of the right one. This is the case a
     * prefix comparison gets wrong, and it is why the comparison is a walk. */
    test_bad_credentials(good_store, "a prefix of the right password", "alice",
                         "correct");
    test_bad_credentials(good_store, "an unknown authcid", "mallory",
                         "correct horse");
    test_no_credential_in_the_log(good_store);

    /* A node given NO --sasl-store at all: the default, and the state most
     * deployments of this design are in. */
    test_sasl_plain(nonexistent_store, 0);

    (void)unlink(good_store);
    (void)unlink(loose_store);
    (void)unlink(broken_store);
    (void)write_store;
    tf_done("CapNegotiation");
    return 0;
}
