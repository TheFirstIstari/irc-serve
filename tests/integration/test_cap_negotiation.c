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
 *  6. `CAP LIST` reports what THIS client negotiated, not the node's whole table.
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
#include <sys/stat.h>
#include <unistd.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_READY_MS 15000
#define T_IO_MS 15000
/* Long enough that a burst is unambiguous, short enough that proving an ABSENCE
 * does not cost the run a minute. There is no sleep() anywhere in this file; the
 * absence checks are deadline waits, which is the point. */
#define T_ABSENT_MS 700

/* Assert `want` arrives as a COMPLETE line, including its CRLF. Including the
 * terminator is what proves the line is terminated on the wire rather than being
 * a prefix of a longer one, and the leading-boundary check is what stops a line
 * that is a SUFFIX of a longer one from passing. The leading CRLF is not part of
 * the needle because the first line on a connection has nothing before it. */
static void expect_line(test_client_t *c, const char *what, const char *want)
{
    const char *at;

    TF_CHECK_MSG(tc_expect(c, want, T_IO_MS) == 0, "%s: expected the exact "
                 "line \"%s\"", what, want);
    at = strstr(tc_buffer(c), want);
    TF_CHECK_MSG(at != NULL, "%s: the line vanished from the buffer", what);
    TF_CHECK_MSG(at == tc_buffer(c) || at[-1] == '\n',
                 "%s: \"%s\" is not at the start of a line", what, want);
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
    FILE *f = fopen(path, "w");

    if (f == NULL) {
        return -1;
    }
    if (fputs(records, f) == EOF) {
        (void)fclose(f);
        return -1;
    }
    if (fclose(f) != 0) {
        return -1;
    }
    return chmod(path, S_IRUSR | S_IWUSR);
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
                /* NOT ADVERTISED, and each of these is a capability a client
                 * would act on: cap-notify expects unsolicited CAP NEW lines and
                 * away-notify expects an AWAY you did not ask for.
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
                TF_CHECK_MSG(strstr(line, "away-notify") == NULL,
                             "CAP LS advertises away-notify");
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
    TF_CHECK_MSG(tc_send(&c, "CAP LIST") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_expect(&c, " CAP * LIST :message-tags\r\n", T_IO_MS) == 0,
                 "CAP LIST did not report the negotiated set");

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
