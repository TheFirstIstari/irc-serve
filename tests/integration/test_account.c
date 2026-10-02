/* test_account.c -- Phase 10.1: the account subsystem, on the wire, against the
 * real binary.
 *
 * An account is a named identity that OUTLIVES A SOCKET. Everything this tree
 * could do before it authenticated a CONNECTION -- SASL PLAIN proves a socket
 * holds a password, and the proof dies with the socket -- which is why seven
 * IRCv3 specifications were blocked on an account concept that did not exist.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS ASSERTED, AND WHERE THE ASSERTIONS ARE ALLOWED TO LIVE
 * ---------------------------------------------------------------------------
 * Two kinds of observation, and the split is deliberate:
 *
 *   THE WIRE, for everything a client could see. `330 RPL_WHOISACCOUNT`,
 *   `482` for the two refused account commands, `CAP LS` / `CAP REQ` /
 *   `CAP NAK`, and the registration burst. These are bytes.
 *
 *   THE NODE'S OWN `[observable]` OUTPUT, for the two facts that have no wire
 *   form in this phase: WHICH IDENTITY a verified credential produced, and
 *   whether the teardown arm ran. node_main.c's header says the `[observable]`
 *   lines are part of the contract and the integration tests parse them, and the
 *   LeakSanitizer arm is REQUIRED to be assertable this way because LSan does
 *   not run on Darwin -- `fed_burst_close: shadow=OPEN|NONE` is the pattern this
 *   file follows, as `account_store_close: store=OPEN|NONE`.
 *
 * NEVER a struct field. Nothing here reads conn_t, server_t or any store's
 * layout, so every assertion below survives a restructuring that kept the
 * protocol honest.
 *
 * ---------------------------------------------------------------------------
 * THE PROPERTIES, AND WHY EACH ONE IS HERE
 * ---------------------------------------------------------------------------
 *  1. **THE IDENTITY IS OBSERVABLE.** A client that authenticated against an
 *     operator's registry WHOISes itself and gets `330 <nick> <account> :is
 *     logged in as`; and so does a SECOND, unauthenticated client asking about
 *     it, which is the point of an account rather than a private label.
 *  2. **AN EMPTY ACCOUNT CANNOT BE CONFUSED WITH AN ACCOUNT.** Three separate
 *     checks, because the failure has three shapes: a not-logged-in client's
 *     WHOIS carries no `330` at all; the node's output never renders an account
 *     name that is empty (`account=` is always followed by a byte); and
 *     `logged_in=1` is printed exactly as often as `verified=1`, so the boolean
 *     and the name cannot drift apart.
 *  3. **THE REGRESSION CASE, WHICH IS THE IMPORTANT ONE.** A node with NO
 *     account registry must behave as though this phase did not exist: the same
 *     `CAP LS`, the same registration burst, the same `482` for REGISTER, and a
 *     `WHOIS` with no `330`. The same assertions run against a node WITH a
 *     registry and against one WITHOUT, for the same not-logged-in client, and
 *     both must hold -- which is how "`account == ""` is indistinguishable from
 *     no account system" becomes a check rather than a claim.
 *  4. **THE FAIL-CLOSED CASE.** An operator whose credential store and whose
 *     registry disagree is not "no opinion": the client authenticates and is not
 *     identified, which is byte-identical to case 3. That is the whole of
 *     account_set()'s second check.
 *  5. **`account-tag` IS ADVERTISED ONLY WHERE IT IS EMITTED.** With a registry
 *     loaded it is in `CAP LS` and a `CAP REQ` ACKs it; with NO registry it is
 *     absent from `CAP LS` and NAKed, byte for byte the list a node configured
 *     with neither option advertises. That is Phase 10.2's whole argument: the
 *     tag's ABSENCE is meaningful to a client, so the capability and the emission
 *     have to appear together or not at all.
 *  6. **THE TAG IS PER DESTINATION.** A client that negotiated
 *     `message-tags account-tag` gets `account=` on the lines a logged-in sender
 *     emits to it; a client that negotiated `message-tags` alone gets a block
 *     with a `msgid` and NO `account`; a client that negotiated nothing gets no
 *     block at all. And an ANONYMOUS sender's lines carry no `account` even for
 *     the client that asked, which is the half the specification's "MUST NOT be
 *     sent" is about.
 *  7. **THE TAG DOES NOT CROSS TO A PEER.** Two linked nodes, a logged-in client
 *     on one and a client that asked for `account-tag` on the other: the far side
 *     receives the message with a `msgid` and with no `account`. The decision and
 *     its cost are at fanout.c's fanout_emitter_account().
 *  8. **`account-notify` IS ANSWERED AND IS NOT SOLICITED.** A client that
 *     negotiated it is told `ACCOUNT <account> PASS` or `ACCOUNT *` at the end of
 *     its own registration burst; a client that negotiated nothing is told
 *     nothing; a client that ASKS with a bare `ACCOUNT` is answered; and the
 *     retired one-parameter nickname-change dialect is refused with 461 rather
 *     than read as a nick change.
 *  9. **REGISTER AND UNREGISTER ARE REFUSED WITH 482, NOT 421.** A client that
 *     got 421 would read "this server has never heard of REGISTER"; this node
 *     has heard of it and has decided.
 * 10. **THE STORE IS A SECRET FILE.** A world-readable registry, a malformed
 *     record and a path that does not exist are each REFUSED, and each refusal
 *     lands the node in exactly the state case 3 asserts.
 * 11. **AN ACCOUNT PASSWORD IS NEVER LOGGED.** The password is handed to
 *     account_set() and there is no variable holding it afterwards, so the
 *     node's own output is read and checked.
 * 12. **THE TEARDOWN ARM RAN**, with the state it found.
 *
 * ---------------------------------------------------------------------------
 * NO sleep() ANYWHERE (6.3), AND NO PORT COLLISION
 * ---------------------------------------------------------------------------
 * Every node binds port 0 and reports what the kernel chose, every wait is a
 * deadline inside tc_expect()/nf_expect(), and every negative assertion is
 * closed by a PING/PONG drain rather than by a wait -- the window primitive
 * test_queries.c uses, and for the same reason: tc_expect() searches the whole
 * accumulated buffer, so a second ` 318 ` would match the first and the wait
 * that was supposed to cover the command under test would never happen.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/account.h"
#include "core/channel.h"
#include "core/fanout.h"
#include "core/message.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"
#include "sasl_framework.h"

#define T_READY_MS 15000
#define T_IO_MS 15000

#define BIN_NAME "irc.test"

/* Enough for every path this file creates: the mkstemp() templates below are all
 * under /tmp and the shortest, /nonexistent/irc-serve-accounts, is 31 bytes. */
#define PATH_MAX_TEST 512

/* ---------------------------------------------------------------------------
 * Fixtures on disk. mkstemp() rather than a literal path, because CTest runs the
 * suite at -j8 and every node in this file is a separate process reading one of
 * these at start-up.
 * --------------------------------------------------------------------------- */

/* base64 of "authzid\0authcid\0passwd", for a PLAIN payload.
 *
 * Written out here rather than shared with sasl_framework.c because this is the
 * CLIENT side of the wire: an encoder shared with the decoder cannot catch an
 * encoder and a decoder that agree on something the specification says they
 * should not. test_cap_negotiation.c carries the same function for the same
 * reason. */
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

/* RFC 4616's PLAIN payload. Returns its LENGTH, and the length is the point:
 * the payload is not a C string -- it BEGINS with a NUL whenever authzid is
 * empty, which is how irssi sends it -- so anything that reaches for strlen()
 * on it encodes one byte. */
static size_t plain_payload(char *buf, size_t cap, const char *authzid,
                            const char *authcid, const char *passwd)
{
    const size_t za = strlen(authzid);
    const size_t zc = strlen(authcid);
    const size_t zp = strlen(passwd);
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

/* ---------------------------------------------------------------------------
 * The window primitive. Identical in purpose and in code to test_queries.c's and
 * test_messaging.c's, and for the same reason: a bare tc_expect() searches the
 * WHOLE accumulated buffer, so a second ` 318 alice :End of /WHOIS list` matches
 * the first and returns instantly, and the wait that was supposed to cover the
 * command under test never happens.
 *
 * A window is [from, end): `from` is a PING's PONG sent before the command under
 * test and `end` a second PING's PONG sent after it. A connection's answers are
 * written in order, so the closing PONG proves every earlier answer is already
 * in the buffer -- which makes "nothing arrived" a fact about the node rather
 * than a guess about its speed, and involves no fixed sleep.
 * --------------------------------------------------------------------------- */
static unsigned g_drain_seq;

typedef struct {
    test_client_t c;
    char          nick[72];
} client_t;

/* The client a helper is acting on. One at a time rather than a parameter on
 * every function, so the window helpers cannot be given a client that is not the
 * one the command was sent on -- which is how a window assertion goes wrong
 * without failing loudly. */
static client_t *CUR_CLIENT;


/* Send a complete, correct PLAIN credential in the two-parameter one-shot form.
 * The expectation is on the node's own output rather than on the wire, because
 * a successful exchange produces NO numeric in this tree: SASL grants nothing
 * and says so with `granted=0`. Asserting a numeric here would be asserting a
 * feature Phase 8 deliberately does not have. */
static void authenticate(const char *authcid, const char *passwd)
{
    char payload[512];
    char encoded[400];
    char line[600];
    size_t plen;

    plen = plain_payload(payload, sizeof payload, "", authcid, passwd);
    b64_encode(payload, plen, encoded, sizeof encoded);
    (void)snprintf(line, sizeof line, "AUTHENTICATE PLAIN %s", encoded);
    TF_CHECK_MSG(tc_send(&CUR_CLIENT->c, line) == 0, "AUTHENTICATE send failed");
}

static size_t drain(client_t *cl)
{
    char line[64];
    char needle[96];
    const char *at;

    g_drain_seq++;
    (void)snprintf(line, sizeof line, "PING :q%u", g_drain_seq);
    (void)snprintf(needle, sizeof needle, "PONG %s q%u\r\n", BIN_NAME,
                   g_drain_seq);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0, "no PONG for %s",
                 line);
    at = strstr(tc_buffer(&cl->c), needle);
    TF_CHECK_MSG(at != NULL, "the drain PONG vanished from the buffer");
    return (at != NULL) ? (size_t)(at - tc_buffer(&cl->c)) : 0u;
}

/* drain() FOR A NODE WHOSE NAME IS NOT BIN_NAME, and the reason it cannot be
 * drain() is the whole of what the two-node case does differently.
 *
 * A PONG is `:\<server> PONG \<server> <token>`, so it carries the NAME of the
 * node that answered it. drain() builds its needle from BIN_NAME, which is right
 * for every single-node case here and wrong for this one: waiting for
 * `PONG irc.test q27` on a node called irc.a waits fifteen seconds for a PONG the
 * node already sent, and reports it as "the node stopped answering".
 *
 * It is a second function rather than a parameter because the name is a property
 * of the NODE and every other helper in this file takes the client -- a
 * client-side `server` field would be one more fact a test could set wrong
 * silently, and the one thing worth being explicit about here is that the name is
 * NOT the client's to choose. */
static size_t drain_on(client_t *cl, const char *server)
{
    char line[64];
    char needle[96];
    const char *at;

    g_drain_seq++;
    (void)snprintf(line, sizeof line, "PING :q%u", g_drain_seq);
    (void)snprintf(needle, sizeof needle, "PONG %s q%u\r\n", server, g_drain_seq);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0, "no PONG for %s", line);
    at = strstr(tc_buffer(&cl->c), needle);
    TF_CHECK_MSG(at != NULL, "the drain PONG vanished from the buffer");
    return (at != NULL) ? (size_t)(at - tc_buffer(&cl->c)) : 0u;
}

static void expect_in_window(client_t *cl, size_t from, size_t end,
                             const char *what, const char *want)
{
    const char *base = tc_buffer(&cl->c);
    const char *at;

    TF_CHECK_MSG(end > from, "%s: the window was never closed", what);
    at = strstr(base + from, want);
    TF_CHECK_MSG(at != NULL, "%s: expected the exact line \"%s\"", what, want);
    if (at == NULL) {
        return;
    }
    TF_CHECK_MSG(at < base + end,
                 "%s: \"%s\" appears only AFTER the window closed, so it was not "
                 "an answer to the command under test",
                 what, want);
    TF_CHECK_MSG(at == base + from || at[-1] == '\n',
                 "%s: \"%s\" is not at the start of a line", what, want);
}

/* A needle ANYWHERE in the window, with no line-start requirement.
 *
 * It exists for exactly one shape: a delivered line that carries BOTH `msgid` and
 * `account`, where the value under test is the SECOND pair and the bytes before it
 * are a msgid whose epoch and id this test cannot spell. Asserting from the start
 * of that line would mean asserting a number the node chooses, and asserting a
 * substring of it is still an assertion about the account tag's own spelling and
 * its position after the prefix. */
static void expect_text_in_window(client_t *cl, size_t from, size_t end,
                                  const char *what, const char *needle)
{
    const char *base = tc_buffer(&cl->c);

    TF_CHECK_MSG(end > from, "%s: the window was never closed", what);
    TF_CHECK_MSG(strstr(base + from, needle) != NULL,
                 "%s: expected \"%s\" somewhere in the window", what, needle);
}

static void expect_absent_in_window(client_t *cl, size_t from, size_t end,
                                    const char *what, const char *needle)
{
    const char *base = tc_buffer(&cl->c);
    size_t count = 0;

    TF_CHECK_MSG(end > from,
                 "%s: the window was never closed (from=%zu end=%zu), so \"did "
                 "not appear\" would prove nothing",
                 what, from, end);
    for (const char *p = base + from; p < base + end;) {
        const char *hit = strstr(p, needle);

        if (hit == NULL || hit >= base + end) {
            break;
        }
        count++;
        p = hit + strlen(needle);
    }
    TF_CHECK_MSG(count == 0,
                 "%s: \"%s\" appeared %zu time(s) and must not have appeared at "
                 "all",
                 what, needle, count);
}

/* Complete a WHOIS of `target` and assert what the window did or did not say.
 *
 * `expect_account` is the whole of property 1 and property 3 in one helper: pass
 * the account name to require a 330, and NULL to require its absence. The SAME
 * helper makes both assertions, which is what makes "a node with accounts and a
 * node without answer a not-logged-in client identically" a statement about two
 * runs of one piece of code rather than about two hand-written checks that
 * happen to agree. */
static void whois_and_check(client_t *cl, const char *target,
                            const char *expect_account)
{
    char line[256];
    char needle[384];
    size_t from = drain(cl);
    size_t end;

    (void)snprintf(line, sizeof line, "WHOIS %s", target);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "WHOIS send failed");
    /* 318 is the RFC's end-of-list marker and this node always sends it, so it
     * is what closes the WHOIS window.
     *
     * THE NICK APPEARS TWICE AND BOTH ARE WRITTEN OUT, because they are two
     * different things: reply() renders <target> from the ASKING connection and
     * handle_whois() passes the ASKED-FOR nick as a middle parameter. So a
     * client WHOISing somebody else sees `:irc.test 318 alice bob :End of
     * /WHOIS list` and a client WHOISing ITSELF sees the same nickname twice.
     * Spelling both here rather than matching a shorter substring is what stops
     * this assertion from passing against a 318 that named the wrong user. */
    (void)snprintf(needle, sizeof needle, ":%s 318 %s %s :End of /WHOIS list\r\n",
                   BIN_NAME, cl->nick, target);
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0,
                 "WHOIS %s by %s did not terminate with 318", target, cl->nick);
    end = tc_received(&cl->c);

    if (expect_account != NULL) {
        char want[384];

        (void)snprintf(want, sizeof want, ":%s 330 %s %s %s :is logged in as\r\n",
                       BIN_NAME, cl->nick, target, expect_account);
        expect_in_window(cl, from, end, "330 RPL_WHOISACCOUNT", want);
        /* The account is a MIDDLE parameter, so it must render bare. A value that
         * needed a leading colon would have been colonned, and a client indexing
         * the parameter list would see four parameters where the specification
         * says three. */
        TF_CHECK_MSG(strstr(tc_buffer(&cl->c), " :330 ") == NULL,
                     "330 rendered its account with a colon");
    } else {
        expect_absent_in_window(cl, from, end, "330 for an unidentified user",
                                " 330 ");
        /* And nothing at all says "logged in": an empty account must not leak
         * into another shape, and the trailing text is where a server that
         * wanted to be helpful would put it. */
        expect_absent_in_window(cl, from, end, "any account wording",
                                "logged in");
    }
}

static void client_connect(client_t *cl, nf_node_t *node, const char *nick)
{
    tc_init(&cl->c);
    (void)snprintf(cl->nick, sizeof cl->nick, "%s", nick);
    TF_CHECK_MSG(tc_connect(&cl->c, node->port) == 0, "tc_connect(%s) failed",
                 nick);
    CUR_CLIENT = cl;
}

static void client_register(client_t *cl)
{
    char line[512];
    char needle[512];

    (void)snprintf(line, sizeof line, "NICK %s", cl->nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "NICK send failed");
    (void)snprintf(line, sizeof line, "USER %s 0 * :Real %s", cl->nick, cl->nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "USER send failed");
    (void)snprintf(needle, sizeof needle, " 001 %s :", cl->nick);
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0, "%s did not register",
                 cl->nick);
}

/* Connect, negotiate (or not), and register -- the whole opening every case
 * needs before it can ask anything. `cap_req` is the capability list to ask for,
 * or NULL to send no CAP at all. */
static void client_open(client_t *cl, nf_node_t *node, const char *nick,
                        const char *cap_req)
{
    client_connect(cl, node, nick);
    if (cap_req != NULL) {
        TF_CHECK_MSG(tc_send(&cl->c, "CAP LS") == 0, "CAP LS send failed");
        TF_CHECK_MSG(tc_expect(&cl->c, " CAP * LS :", T_IO_MS) == 0, "no CAP LS");
        (void)snprintf(cl->nick, sizeof cl->nick, "%s", nick);
        TF_CHECK_MSG(tc_send(&cl->c, cap_req) == 0, "CAP REQ send failed");
        TF_CHECK_MSG(tc_send(&cl->c, "CAP END") == 0, "CAP END send failed");
    }
    client_register(cl);
}

/* --------------------------------------------------------------------------
 * REGISTER AND UNREGISTER ARE REFUSED, AND THE ASSERTION IS ABOUT WHAT DID NOT
 * HAPPEN AS MUCH AS ABOUT WHAT DID
 * --------------------------------------------------------------------------
 * Three checks, because a refusal has three ways of being wrong:
 *
 *   - each command's 482 arrives as a COMPLETE line, with the text that says
 *     WHY. The text is the part a client can act on and an operator can read,
 *     and it names the operator-side registry rather than saying "not
 *     supported", which would be a lie about a node that has heard of the verb.
 *   - neither command produces a 421. A client told "unknown command" concludes
 *     this server has never heard of REGISTER; this node has heard of it and has
 *     decided. The difference is the whole of what a refusal is.
 *   - NEITHER PRODUCES A 9001-STYLE SUCCESS. There is no numeric here that a
 *     client could read as "registered", because the command's entire behaviour
 *     in this phase is to not register anybody.
 *
 * The arity is deliberately not checked first by the node, and the test sends a
 * well-formed REGISTER (password AND email) rather than a bare one, so this is
 * the refusal a client that read the specification would receive. */
static void expect_account_commands_refused(client_t *cl)
{
    char want[512];
    size_t from = drain(cl);
    size_t end;

    TF_CHECK_MSG(tc_send(&cl->c, "REGISTER hunter2 alice@example.com") == 0,
                 "REGISTER send failed");
    TF_CHECK_MSG(tc_send(&cl->c, "UNREGISTER hunter2") == 0,
                 "UNREGISTER send failed");

    /* The window is closed with a PING rather than by any expected numeric,
     * because these two commands produce no 3xx and the whole claim is that the
     * only thing they produce is a 482. A closing PONG proves the 482s are
     * already in the buffer without assuming anything about how fast they came. */
    end = drain(cl);

    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 482 %s :REGISTER is not available: this node's "
                   "accounts are created by its operator in a registry file\r\n",
                   cl->nick);
    expect_in_window(cl, from, end, "the REGISTER refusal", want);
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 482 %s :UNREGISTER is not available: this "
                   "node's accounts are created by its operator in a registry "
                   "file\r\n",
                   cl->nick);
    expect_in_window(cl, from, end, "the UNREGISTER refusal", want);
    expect_absent_in_window(cl, from, end, "a 421 for REGISTER", " 421 " " REGISTER");
    expect_absent_in_window(cl, from, end, "a 421 for UNREGISTER",
                            " 421 " " UNREGISTER");
    /* And nothing claims a name was taken, because nothing took one. */
    expect_absent_in_window(cl, from, end, "any claim that a name was taken",
                            "already in use");
    /* Exactly two numerics: a node that also answered 901/902 -- the numerics a
     * later phase would use to confirm a registration -- would be a node that
     * registered somebody. */
    TF_CHECK_MSG(tf_count(tc_buffer(&cl->c), " 482 ") == 2,
                 "expected exactly two 482s for one REGISTER and one UNREGISTER, "
                 "saw %zu",
                 tf_count(tc_buffer(&cl->c), " 482 "));
}

/* Spawn a node with an OPTIONAL credential store and an OPTIONAL registry. NULL
 * for either omits the option, which is the state most deployments of this
 * design are in and the one property 3 is about. */
static void spawn_node(nf_node_t *node, const char *sasl, const char *registry,
                       const char *label)
{
    /* The vector is FILLED IN ORDER and terminated immediately, rather than
     * leaving spare NULLs after the terminator: nf_spawn_binary_argv() execs this
     * argv directly, and a NULL where a flag's VALUE belongs is read as "this
     * option is the last argument", which the node reports as a usage error. */
    /* The paths are COPIED into writable buffers rather than cast. A `char *`
     * argv slot holding a `const char *` needs a cast, and upstream clang's
     * -Weverything turns -Wcast-qual on, so the cast is an error rather than a
     * style choice on two of the three compilers. A string LITERAL is not the
     * same problem -- in C it is `char[]`, not `const char[]`, so `(char *)"0"`
     * below is a no-op and needs no comment. */
    char sasl_buf[PATH_MAX_TEST];
    char reg_buf[PATH_MAX_TEST];
    char *argv[7];
    size_t n = 0;

    sasl_buf[0] = '\0';
    reg_buf[0] = '\0';
    if (sasl != NULL) {
        (void)snprintf(sasl_buf, sizeof sasl_buf, "%s", sasl);
    }
    if (registry != NULL) {
        (void)snprintf(reg_buf, sizeof reg_buf, "%s", registry);
    }
    argv[n++] = (char *)"irc-serve";
    argv[n++] = (char *)"0";
    if (sasl != NULL) {
        argv[n++] = (char *)"--sasl-store";
        argv[n++] = sasl_buf;
    }
    if (registry != NULL) {
        argv[n++] = (char *)"--account-store";
        argv[n++] = reg_buf;
    }
    argv[n] = NULL;
    TF_CHECK_MSG(n < 7u, "%s: the argument vector overflowed", label);
    TF_CHECK_MSG(nf_spawn_binary_argv(node, argv) == 0,
                 "%s: could not spawn a node", label);
}

/* --------------------------------------------------------------------------
 * THE EMPTY-ACCOUNT CANNOT BE AN ACCOUNT-NAMED-"" CHECK
 * --------------------------------------------------------------------------
 * The node renders an account NAME on exactly one line, and that line is
 * `[observable] account: fd=N account=<name> verified=1 ...`. So "an empty
 * account" would show up as the byte after `account=` being a space, a CR, an LF
 * or nothing -- and this checks all four, over every occurrence in the node's
 * whole output.
 *
 * It is a byte check rather than a string check because the failure is a
 * RENDERING of an empty name and a rendering is bytes. A test that asserted
 * "the line contains account=" would pass against the very thing it is for. */
static void expect_account_name_never_empty(const nf_node_t *node)
{
    const char *out = node->out;
    const char *key = "account=";
    size_t seen = 0;

    TF_CHECK_MSG(out != NULL, "the node produced no output to check");
    if (out == NULL) {
        return;
    }
    for (const char *p = out; (p = strstr(p, key)) != NULL; p += strlen(key)) {
        const char v = p[strlen(key)];

        seen++;
        TF_CHECK_MSG(v != ' ' && v != '\r' && v != '\n' && v != '\0',
                     "the node rendered an EMPTY account name at \"%.40s\"; an "
                     "empty account and an account named \"\" must not be "
                     "distinguishable",
                     p);
    }
    TF_CHECK_MSG(seen > 0,
                 "no `account=` line was printed at all, so this check had "
                 "nothing to look at");
}

/* --------------------------------------------------------------------------
 * A LINE IN A WINDOW, AND WHAT IS OR IS NOT ON IT
 * --------------------------------------------------------------------------
 * Two shapes of assertion the tag needs and neither of which the primitives
 * above can express, so both are here rather than spelled out at each call site:
 *
 *   expect_tag_block_present()  -- some line in the window begins with `@`, which
 *     is what proves the DESTINATION was written to with a block at all. Without
 *     it "no `account` tag" is also satisfied by a node that wrote no tags to
 *     anybody, which is a different bug with the same symptom.
 *   expect_no_tag_block()        -- no line in the window begins with `@`, so
 *     "no `account` tag" cannot be satisfied by there having been no block to
 *     put one in.
 *
 * BOTH WALK LINES rather than searching for a byte, because a `@` inside a
 * message body is not a tag block and a test that cannot tell the difference is a
 * test that will fail the day somebody says PRIVMSG to a channel about an email
 * address. */
/* Does any LINE in the window begin with `c`? A tag block always starts a line
 * and a '@' anywhere else is a character in somebody's message, so this is a
 * line-start walk rather than a strstr(). */
static int window_line_starts_with(const client_t *cl, size_t from, size_t end,
                                   char c)
{
    const char *base = tc_buffer(&cl->c);

    if (end <= from) {
        return 0;
    }
    for (const char *p = base + from; p < base + end; p++) {
        if ((p == base + from || p[-1] == '\n') && *p == c) {
            return 1;
        }
    }
    return 0;
}

static void expect_tag_block_present(client_t *cl, size_t from, size_t end,
                                     const char *what)
{
    TF_CHECK_MSG(end > from, "%s: the window was never closed", what);
    /* The window is DUMPED on failure, and that is not decoration: this is the one
     * assertion in the file whose failure has two quite different causes -- a node
     * that wrote no block, and a window that was closed before the message was
     * delivered -- and the bytes tell them apart immediately. */
    if (window_line_starts_with(cl, from, end, '@') == 0) {
        TF_CHECK_MSG(0, "%s: no line in the window carries a tag block at all, so "
                        "\"the account tag is absent\" would be satisfied by a node "
                        "that wrote no tags to anybody\n  nick=%s\n  window=[%s]",
                     what, cl->nick, tc_buffer(&cl->c) + from);
    }
}

static void expect_no_tag_block(client_t *cl, size_t from, size_t end,
                                const char *what)
{
    TF_CHECK_MSG(end > from, "%s: the window was never closed", what);
    TF_CHECK_MSG(window_line_starts_with(cl, from, end, '@') == 0,
                 "%s: a tag block was written to a connection that negotiated "
                 "nothing", what);
}

/* ==========================================================================
 * THE TEARDOWN ARM IS NOT JUST A LINE, IT IS A FREE -- and that half cannot be
 * seen from a parent process
 * ==========================================================================
 * `[observable] account_store_close: store=OPEN|NONE` proves the ARM RAN, which
 * is what `fed_burst_close: shadow=OPEN|NONE` is for and what LeakSanitizer's
 * absence on Darwin leaves us with locally. It does NOT prove the free happened:
 * a build that printed the line and dropped the free() satisfies it exactly, and
 * that is one of the faults in this phase's teeth list.
 *
 * So the free is asserted the only other way available -- by looking at the code
 * -- using test_util.h's source inspection, which exists for precisely this
 * class of property ("nothing outside the reaper closes a descriptor", "the one
 * function that emits numerics is the one that refuses to write to a peer"): no
 * runtime test can check them, because the failure mode is a missing call that
 * leaves every runtime invariant intact.
 *
 * WHAT THIS DOES AND DOES NOT ESTABLISH. It establishes that
 * server_shutdown() contains a call to account_store_free() -- so the arm is not
 * a line with no free behind it, which is the shape of teardown that C4 declined
 * to add and §4.3.1 later retracted for exactly this reason. It does NOT
 * establish that the call is reached, and only LeakSanitizer on the Linux CI job
 * establishes that. Both halves are stated rather than one being read as the
 * other. */
static void expect_shutdown_frees_the_account_store(void)
{
    char *code = tf_read_code("src/core/server.c", NULL);

    TF_CHECK_MSG(code != NULL, "could not read src/core/server.c");
    if (code == NULL) {
        return;
    }
    TF_CHECK_MSG(tf_calls(code, "account_store_free") == 1,
                 "server_shutdown() must release the account registry exactly "
                 "once, and it must not be a line with no free behind it: "
                 "account_store_free() appears %d time(s) in src/core/server.c",
                 tf_calls(code, "account_store_free"));
    free(code);
}

/* ==========================================================================
 * THE ACCOUNT PASSWORD IS NEVER LOGGED
 * ==========================================================================
 * Phase 10.1 hands the password to a SECOND module, so the property
 * test_cap_negotiation.c asserts for the credential store has to be asserted
 * again -- and it is a new risk rather than a repeated one, because
 * account_set() is code that did not exist when that test was written. A module
 * that takes a secret as an argument is a module that can print one.
 *
 * Read on the SAME node as the successful case rather than on a second one,
 * because that is where the password is: this needs a node whose registry
 * LOADED and whose credential verified, and spawning a twelfth node to watch the
 * same two files would buy no additional coverage and one more thing competing
 * for the machine the suite shares. */
static void expect_account_password_never_logged(const nf_node_t *node)
{
    TF_CHECK_MSG(strstr(node->out, "correct horse") == NULL,
                 "the ACCOUNT PASSWORD appears in the node's own output");
    /* The base64 form is one decode away, and a log is the wrong place for
     * something that close. */
    TF_CHECK_MSG(strstr(node->out, "AGFsaWNlAHBvcnJlY3QgaG9yc2U=") == NULL,
                 "the base64 credential appears in the node's own output");
    /* The account NAME is expected -- an operator needs to know who is logged in
     * -- so what this really checks is that the two facts are SEPARABLE at all:
     * a node that logged the name instead of the password is passing, and a node
     * that logged the password instead of the name is failing. */
    TF_CHECK_MSG(strstr(node->out, "alice") != NULL,
                 "the account name should appear in the node's own output; a log "
                 "line with no identity in it tells an operator nothing");
}

/* ==========================================================================
 * CASE 1: BOTH STORES. The identity is established, and it is observable.
 * ========================================================================== */
static void test_logged_in(const char *sasl, const char *registry)
{
    nf_node_t node;
    client_t alice;
    client_t watcher;
    const char *out;

    spawn_node(&node, sasl, registry, "both stores");
    /* The startup line is the half of "advertise only what you have" that an
     * operator reads without opening either file. */
    TF_CHECK_MSG(nf_expect(&node, "accounts=loaded", T_IO_MS) == 0,
                 "a node with a loaded registry did not say so at start-up");

    client_connect(&alice, &node, "alice");

    /* ---- `account-tag` IS ADVERTISED, AND IT IS EMITTED (below) --------------
     *
     * Phase 10.1 deliberately withheld this name, and the reason -- the tag's
     * ABSENCE is an assertion, so advertising without emitting tells every client
     * that every logged-in user here is anonymous -- is the reason it may be
     * advertised now: the emission is in the same pass. Both halves at once is
     * the whole of the requirement, so the advertisement is asserted here and the
     * tag is asserted on the wire in the case below rather than by a comment.
     *
     * Checked in three forms so no single one can be the thing doing the work:
     * present in LS, ACKED by REQ, and -- the one that would catch a node that
     * ACKed it and then wrote nothing -- the tag itself, asserted exactly on a
     * delivered line. */
    TF_CHECK_MSG(tc_send(&alice.c, "CAP LS") == 0, "CAP LS send failed");
    TF_CHECK_MSG(tc_expect(&alice.c, " CAP * LS :", T_IO_MS) == 0, "no CAP LS");
    TF_CHECK_MSG(strstr(tc_buffer(&alice.c), "account-tag") != NULL,
                 "CAP LS did not advertise account-tag on a node with a loaded "
                 "registry; the tag is emitted, so the name must be listed");
    TF_CHECK_MSG(tc_send(&alice.c, "CAP REQ :account-tag") == 0,
                 "CAP REQ send failed");
    TF_CHECK_MSG(tc_expect(&alice.c, " CAP * ACK :account-tag\r\n", T_IO_MS) == 0,
                 "account-tag was not ACKed on a node that implements it");
    TF_CHECK_MSG(strstr(tc_buffer(&alice.c), " CAP * NAK :account-tag") == NULL,
                 "the node NAKed a capability it implements");
    /* `sasl` is present because the credential store loaded, and the WHOLE list
     * is spelled out rather than spot-checked: this is the one node in this file
     * where every capability is available, so it is the one place a capability
     * can be missing from the assertion and still pass. */
    /* `account-notify` IS here even on this node, and the reason is that its
     * answer is not a name: `ACCOUNT *` is a true answer on a node with no
     * registry, so the capability is available unconditionally. `account-tag`
     * above is the one that is conditional. */
    TF_CHECK_MSG(strstr(tc_buffer(&alice.c),
                        " CAP * LS :multi-prefix message-tags draft/message-ids "
                        "sasl account-tag account-notify "
                        "extended-join userhost-in-names setname\r\n") != NULL,
                 "the advertised list on a node with BOTH stores is not the whole set "
                 "of capabilities this node implements: %s", tc_buffer(&alice.c));

    /* ---- the credential, and the identity it establishes ---- */
    authenticate("alice", "correct horse");
    TF_CHECK_MSG(nf_expect(&node, "outcome=COMPLETED", T_IO_MS) == 0,
                 "a correct credential against both stores was not accepted");
    TF_CHECK_MSG(nf_expect(&node, "account=alice verified=1", T_IO_MS) == 0,
                 "a verified credential did not establish the account identity");
    TF_CHECK_MSG(nf_expect(&node, "logged_in=1", T_IO_MS) == 0,
                 "the node does not report the connection as logged in");

    TF_CHECK_MSG(tc_send(&alice.c, "CAP END") == 0, "CAP END send failed");
    client_register(&alice);

    /* ---- 330: THE IDENTITY IS OBSERVABLE, BY THE CLIENT AND BY A THIRD PARTY
     *
     * The second half is the one that matters. An account nobody else can see is
     * a private label; the whole reason the `account` axis exists beside 2.1's
     * scoped nick is that OTHER PEOPLE can tell who this is. */
    whois_and_check(&alice, "alice", "alice");

    client_open(&watcher, &node, "watcher", NULL);
    whois_and_check(&watcher, "alice", "alice");
    /* ...and the watcher itself is NOT identified, which is the other half of
     * property 3 on the very same node that has a registry. */
    whois_and_check(&watcher, "watcher", NULL);

    /* ...and even on a node that HAS accounts and a logged-in client, the
     * account-registration pair is refused. This is the case that makes the
     * refusal a policy rather than a missing feature: everything REGISTER would
     * need is present except the decision. */
    expect_account_commands_refused(&alice);

    expect_account_name_never_empty(&node);
    expect_account_password_never_logged(&node);

    /* ---- the boolean and the name cannot drift apart ---- */
    out = node.out;
    TF_CHECK_MSG(tf_count(out, "logged_in=1") == tf_count(out, "verified=1"),
                 "the node printed logged_in=1 %zu time(s) but verified=1 %zu "
                 "time(s); the two facts are written together and must be "
                 "counted together",
                 tf_count(out, "logged_in=1"), tf_count(out, "verified=1"));

    /* ---- the teardown arm, ASSERTED on every platform (LSan is Linux-only) --
     *
     * `store=OPEN` is the record that a registry was loaded and has been
     * released with its passwords overwritten, and it is the same convention as
     * `fed_burst_close: shadow=OPEN|NONE` for the same reason. */
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not stop cleanly");
    TF_CHECK_MSG(strstr(node.out, "account_store_close: store=OPEN") != NULL,
                 "server_shutdown() did not report releasing an account "
                 "registry");
    nf_free(&node);
    tc_close(&alice.c);
    tc_close(&watcher.c);
}

/* ==========================================================================
 * CASE 2: A CREDENTIAL STORE AND NO REGISTRY. The regression case.
 * ========================================================================== */
static void test_no_registry(const char *sasl, const char *label)
{
    nf_node_t node;
    client_t alice;
    char ls[128];
    char nak[128];

    spawn_node(&node, sasl, NULL, label);
    TF_CHECK_MSG(nf_expect(&node, "accounts=none", T_READY_MS) == 0,
                 "%s: a node with no registry did not say so at start-up", label);

    client_open(&alice, &node, "alice", NULL);

    /* ---- AND THE CAPABILITY IS WITHHELD, WHICH IS THE POINT OF THE REGISTRY
     * CHECK ----
     *
     * This node has accounts configured to LOAD and loaded -- `accounts=loaded` is
     * asserted above -- and it cannot put a name on a tag, because account_set()'s
     * second check has nothing to consult. So `account-tag` is absent from LS and
     * NAKed, for exactly the reason `sasl` is withheld on a node with no
     * credential store: a listed capability is a client switching the feature on
     * and then drawing the wrong conclusion from every line it receives.
     *
     * The list is compared WHOLE, because the two absences are different and a
     * spot check cannot tell them apart -- which is correct, because a client
     * cannot either.
     *
     * THE TARGET IS THE NICKNAME AND NOT `*`, and that is not a detail this test
     * invents: it asks AFTER registration, so cap.c's cap_target() has a nickname
     * to answer with. The other cases here negotiate before NICK, which is what
     * every real client does, and they see `*`. A test that spelled `*` here would
     * be asserting about a moment this node is never in, and it would fail for a
     * reason that has nothing to do with accounts. */
    (void)snprintf(ls, sizeof ls, " CAP %s LS :", alice.nick);
    (void)snprintf(nak, sizeof nak, " CAP %s NAK :account-tag\r\n", alice.nick);
    TF_CHECK_MSG(tc_send(&alice.c, "CAP LS") == 0, "CAP LS send failed");
    TF_CHECK_MSG(tc_expect(&alice.c, ls, T_IO_MS) == 0, "%s: no CAP LS", label);
    TF_CHECK_MSG(strstr(tc_buffer(&alice.c),
                        " CAP " "alice" " LS :multi-prefix message-tags "
                        "draft/message-ids sasl account-notify "
                        "extended-join userhost-in-names setname\r\n") != NULL,
                 "%s: the advertised list on a node with a credential store and "
                 "NO registry is not exactly the whole set it really "
                 "has; a client would read an account-tag here as an identity it "
                 "can never get", label);
    /* AND ONLY account-tag, which is why this cannot be a sweep for the substring
     * "account": `account-notify` legitimately contains it. */
    TF_CHECK_MSG(strstr(tc_buffer(&alice.c), "account-tag") == NULL,
                 "%s: account-tag is advertised by a node with no account "
                 "registry, and the tag can never be written there", label);
    TF_CHECK_MSG(tc_send(&alice.c, "CAP REQ :account-tag") == 0,
                 "CAP REQ send failed");
    TF_CHECK_MSG(tc_expect(&alice.c, nak, T_IO_MS) == 0,
                 "%s: account-tag was ACKed by a node that can never write the "
                 "tag", label);

    /* ---- the credential still verifies, because --sasl-store is untouched ----
     *
     * This is the whole of "additive". A registry is not what makes a login
     * work, it is what makes a login ALSO an identity, and refusing the login
     * because no account was configured would make adding a registry a change to
     * who can authenticate at all. */
    CUR_CLIENT = &alice;
    authenticate("alice", "correct horse");
    TF_CHECK_MSG(nf_expect(&node, "outcome=COMPLETED", T_IO_MS) == 0,
                 "%s: a correct credential was refused", label);
    TF_CHECK_MSG(nf_expect(&node, "outcome=REFUSED reason=NO_REGISTRY", T_IO_MS) == 0,
                 "%s: the node did not refuse an account claim with NO_REGISTRY",
                 label);
    TF_CHECK_MSG(nf_expect(&node, "logged_in=0", T_IO_MS) == 0,
                 "%s: a node with no registry reported a logged-in client", label);

    /* ---- 451 never happens and 001 already happened: the client is fine ---- */
    TF_CHECK_MSG(tf_count(tc_buffer(&alice.c), " 451 ") == 0,
                 "%s: the connection was held up by the missing registry", label);

    /* ---- and the WHOIS is exactly what it was before this phase existed ---- */
    whois_and_check(&alice, "alice", NULL);
    /* And nothing this connection has been sent carries an account VALUE: the
     * connection authenticated, so the credential verified, and the only thing
     * that did NOT happen is the registry check -- which is precisely the state
     * that must be indistinguishable from having no account system at all. */
    TF_CHECK_MSG(strstr(tc_buffer(&alice.c), "account=") == NULL,
                 "%s: an `account` tag reached a client on a node with no "
                 "registry, and no client there can be identified", label);
    expect_account_name_never_empty(&node);
    TF_CHECK_MSG(tf_count(node.out, "verified=1") == 0,
                 "%s: the node verified an account on a node with no registry",
                 label);

    TF_CHECK_MSG(nf_stop(&node) == 0, "%s: the node did not stop cleanly", label);
    TF_CHECK_MSG(strstr(node.out, "account_store_close: store=NONE") != NULL,
                 "%s: server_shutdown() did not report having no registry to "
                 "release",
                 label);
    nf_free(&node);
    tc_close(&alice.c);
}

/* ==========================================================================
 * CASE 3: NO STORES AT ALL, AND THE CAP LIST IS EXACTLY WHAT IT WAS
 * ==========================================================================
 * The bluntest regression case: a default-configured node. Two assertions carry
 * it, and the second is the one with teeth against anything that adds a
 * capability name.
 *
 * `sasl` is ABSENT here because there is no credential store, which is Phase
 * 8's rule and is unchanged. `account-tag` is absent for a different reason --
 * see cap.h -- and the test cannot tell those two apart, which is correct: a
 * client cannot either. `account-notify` is PRESENT, because its answer is a fact
 * rather than a name and this node has it. */
static void test_default_node(void)
{
    nf_node_t node;
    client_t alice;
    const char *at;
    char caps[512];

    spawn_node(&node, NULL, NULL, "a node configured with neither option");
    client_connect(&alice, &node, "alice");

    TF_CHECK_MSG(tc_send(&alice.c, "CAP LS") == 0, "CAP LS send failed");
    TF_CHECK_MSG(tc_expect(&alice.c, " CAP * LS :", T_IO_MS) == 0, "no CAP LS");
    at = strstr(tc_buffer(&alice.c), " CAP * LS :");
    TF_CHECK_MSG(at != NULL, "no CAP LS line");
    if (at == NULL) {
        return;
    }
    {
        const char *eol = strstr(at, "\r\n");
        size_t n = (eol != NULL) ? (size_t)(eol - at) : 0u;

        TF_CHECK_MSG(n > 0u && n < sizeof caps, "implausible CAP LS length");
        if (n > 0u && n < sizeof caps) {
            memcpy(caps, at, n);
            caps[n] = '\0';
        } else {
            caps[0] = '\0';
        }
    }
    /* THE WHOLE LIST, spelled out. An equality rather than a set of "absent"
     * checks on purpose: adding a name to k_caps[] must break this line, which
     * is the property that makes the table a list of implementations rather than
     * a list of intentions. A node with no stores offers exactly the capabilities
     * capabilities that need no configuration. */
    /* The copy stops AT the CRLF rather than including it -- `n` is measured to
     * the CR -- so the expected literal has no terminator either. */
    TF_CHECK_MSG(strcmp(caps, " CAP * LS :multi-prefix message-tags "
                              "draft/message-ids account-notify "
                              "extended-join userhost-in-names setname") == 0,
                 "the advertised capability list on a node with no stores is "
                 "\"%s\"; it must be exactly the ones that need no "
                 "configuration", caps);
    /* `account-notify` IS in that list and `account-tag` is NOT, and the
     * difference is the whole of the store check. `ACCOUNT *` is an answer a node
     * with no registry can give truthfully; an `account=` tag is a name it can
     * never produce. The assertion names the first and says so rather than
     * sweeping for "account", which would now be matching the wrong name. */
    TF_CHECK_MSG(strstr(caps, "account-tag") == NULL,
                 "account-tag is advertised on a node with no account system, and "
                 "the tag can never be written there");

    TF_CHECK_MSG(tc_send(&alice.c, "CAP END") == 0, "CAP END send failed");
    client_register(&alice);

    /* REGISTER and UNREGISTER are refused here too, so a client gets the same
     * answer whether or not an operator ever configures anything. */
    expect_account_commands_refused(&alice);
    whois_and_check(&alice, "alice", NULL);

    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not stop cleanly");
    TF_CHECK_MSG(strstr(node.out, "account_store_close: store=NONE") != NULL,
                 "server_shutdown() did not report having no registry");
    nf_free(&node);
    tc_close(&alice.c);
}

/* ==========================================================================
 * CASE 4: THE TWO OPERATOR FILES DISAGREE
 * ==========================================================================
 * The credential store holds `alice` and the registry holds `bob`. The client
 * authenticates -- that part is Phase 8's and it still works -- and is not
 * identified, because nothing on this node says an account called `alice`
 * exists. This is the fail-closed direction, and it is what stops a broad
 * credential store from minting accounts out of nothing. */
static void test_registry_disagrees(const char *sasl, const char *registry)
{
    nf_node_t node;
    client_t alice;

    spawn_node(&node, sasl, registry, "two files that disagree");
    TF_CHECK_MSG(nf_expect(&node, "accounts=loaded", T_READY_MS) == 0,
                 "the registry did not load");

    client_open(&alice, &node, "alice", NULL);
    CUR_CLIENT = &alice;
    authenticate("alice", "correct horse");
    TF_CHECK_MSG(nf_expect(&node, "outcome=COMPLETED", T_IO_MS) == 0,
                 "the credential did not verify; this case is about the REGISTRY, "
                 "not about authentication");
    TF_CHECK_MSG(nf_expect(&node, "outcome=REFUSED reason=NOT_IN_REGISTRY",
                           T_IO_MS) == 0,
                 "an authcid the registry does not hold was reported as something "
                 "other than NOT_IN_REGISTRY");
    TF_CHECK_MSG(nf_expect(&node, "logged_in=0", T_IO_MS) == 0,
                 "a name the registry does not hold was logged in anyway");

    /* BYTE-IDENTICAL TO CASE 2. Same helper, same assertion, and that is the
     * entire content of the invariant "`account == \"\"` is indistinguishable
     * from no account system": a client that is not identified answers a WHOIS
     * the same way whether the node has accounts, does not, or disagrees about
     * which ones. */
    whois_and_check(&alice, "alice", NULL);

    nf_stop(&node);
    nf_free(&node);
    tc_close(&alice.c);
}

/* ==========================================================================
 * CASE 5: A REGISTRY THE OPERATOR GOT WRONG
 * ==========================================================================
 * Four ways to get the file wrong, and all four must land the node in exactly
 * the state case 2 asserts -- not in a state where the node believes it has
 * accounts and cannot say which. Each refusal names itself on the node's own
 * output, so the operator learns why without reading any source. */
static void test_registry_refused(const char *sasl, const char *path,
                                  const char *reason, const char *label)
{
    nf_node_t node;
    client_t alice;

    spawn_node(&node, sasl, path, label);
    TF_CHECK_MSG(nf_expect(&node, "reason=", T_READY_MS) == 0,
                 "%s: the loader printed no refusal at all", label);
    TF_CHECK_MSG(nf_expect(&node, reason, T_READY_MS) == 0,
                 "%s: the refusal did not name \"%s\"", label, reason);
    TF_CHECK_MSG(nf_expect(&node, "accounts=none", T_READY_MS) == 0,
                 "%s: a node whose registry was refused still reported accounts",
                 label);

    /* And the behaviour is case 2's behaviour, not a third one. */
    client_open(&alice, &node, "alice", NULL);
    CUR_CLIENT = &alice;
    authenticate("alice", "correct horse");
    TF_CHECK_MSG(nf_expect(&node, "outcome=COMPLETED", T_IO_MS) == 0,
                 "%s: a correct credential was refused", label);
    TF_CHECK_MSG(nf_expect(&node, "logged_in=0", T_IO_MS) == 0,
                 "%s: a refused registry still logged somebody in", label);
    whois_and_check(&alice, "alice", NULL);

    nf_stop(&node);
    nf_free(&node);
    tc_close(&alice.c);
}

/* ==========================================================================
 * CASE 6: A REGISTRY AND NO CREDENTIAL STORE
 * ==========================================================================
 * The other direction, and it exists because the two options are independent:
 * accounts without logins. `sasl` must NOT be advertised (Phase 8's rule, Phase
 * 10.1 has not changed it), the registry is still loaded, and nobody can log in
 * so nobody is identified. A test that only checked "no --account-store" would
 * not catch a change that made the two options into one. */
static void test_registry_without_credentials(const char *registry)
{
    nf_node_t node;
    client_t alice;

    spawn_node(&node, NULL, registry, "a registry with no credential store");
    TF_CHECK_MSG(nf_expect(&node, "accounts=loaded", T_READY_MS) == 0,
                 "the registry did not load");

    client_connect(&alice, &node, "alice");
    TF_CHECK_MSG(tc_send(&alice.c, "CAP LS") == 0, "CAP LS send failed");
    TF_CHECK_MSG(tc_expect(&alice.c, " CAP * LS :", T_IO_MS) == 0, "no CAP LS");
    TF_CHECK_MSG(strstr(tc_buffer(&alice.c), "sasl") == NULL,
                 "a node with no credential store advertised sasl; the account "
                 "registry must not change that");
    TF_CHECK_MSG(tc_send(&alice.c, "CAP END") == 0, "CAP END send failed");
    client_register(&alice);

    /* No credential store means no login, and the mechanism is still offered so
     * the client's credential is REFUSED rather than silently ignored. */
    CUR_CLIENT = &alice;
    authenticate("alice", "correct horse");
    TF_CHECK_MSG(nf_expect(&node, "outcome=REJECTED", T_IO_MS) == 0,
                 "a node with no credential store accepted a SASL payload");
    whois_and_check(&alice, "alice", NULL);

    nf_stop(&node);
    nf_free(&node);
    tc_close(&alice.c);
}

/* ==========================================================================
 * CASE 7: THE `account` TAG, PER DESTINATION
 * ==========================================================================
 * Five clients on one node with a registry, chosen so that each row of the
 * capability question has a subject:
 *
 *   alice   logged in, asks for message-tags + account-tag
 *   bob     anonymous, asks for message-tags + account-tag
 *   carol   anonymous, asks for message-tags + draft/message-ids
 *   dave    anonymous, asks for NOTHING
 *   erin    anonymous, asks for message-tags + account-tag, and SPEAKS
 *
 * So there are three recipient capabilities and two sender states, which is the
 * whole grid the tag has an answer for. Every assertion below is on a WIRE LINE
 * inside a closed window.
 */
static void join_chan(client_t *cl, const char *chan)
{
    char line[128];

    (void)snprintf(line, sizeof line, "JOIN %s", chan);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "%s JOIN send failed", cl->nick);
    /* 366 is the end of the JOIN's own numerics, so it proves the membership
     * exists -- which is what the message below needs, and what makes a
     * "delivered" assertion mean anything. */
    TF_CHECK_MSG(tc_expect(&cl->c, " 366 ", T_IO_MS) == 0,
                 "%s never completed its JOIN", cl->nick);
}

/* The whole opening, in the ONE order the protocol allows: CAP, then SASL, then
 * CAP END, then registration. SASL between the REQ and the END is not a choice --
 * account_set() requires a COMPLETED exchange, so a client that registered first
 * and authenticated afterwards would be in a state no client is meant to be in.
 *
 * THE ACK IS WAITED FOR rather than skipped, because a test that asserts a tag
 * later and never checked the grant is a test that would pass against a node
 * which NAKed and then wrote nothing -- as long as only the "no tag" rows ran. */
static void client_open_logged_in(client_t *cl, nf_node_t *node, const char *nick,
                                  const char *cap_req, const char *authcid,
                                  const char *passwd, const char *label)
{
    client_connect(cl, node, nick);
    if (cap_req != NULL) {
        TF_CHECK_MSG(tc_send(&cl->c, "CAP LS") == 0, "%s: CAP LS send failed",
                     label);
        TF_CHECK_MSG(tc_expect(&cl->c, " CAP * LS :", T_IO_MS) == 0,
                     "%s: no CAP LS", label);
        TF_CHECK_MSG(tc_send(&cl->c, cap_req) == 0, "%s: CAP REQ send failed",
                     label);
        TF_CHECK_MSG(tc_expect(&cl->c, " CAP * ACK :", T_IO_MS) == 0,
                     "%s: CAP REQ of \"%s\" was not granted: %s", label, cap_req,
                     tc_buffer(&cl->c));
    }
    if (authcid != NULL) {
        CUR_CLIENT = cl;
        authenticate(authcid, passwd);
    }
    TF_CHECK_MSG(tc_send(&cl->c, "CAP END") == 0, "%s: CAP END send failed",
                 label);
    client_register(cl);
}

#define CHAN_TAGGED "#TAGGED"

/* THE BARRIER IS THE SENDER'S OWN PONG, and getting this wrong is a test that
 * passes or fails by accident rather than one that passes.
 *
 * The windows below are opened by a PING on each RECIPIENT's connection, and two
 * connections have no order between them: a node that reads carol's PING before
 * it reads erin's PRIVMSG answers carol first, and a window closed by carol's
 * PONG then contains no message at all. A negative assertion over such a window
 * passes for the wrong reason and a positive one fails for the wrong reason --
 * and both look like the feature being broken.
 *
 * So the SENDER's PING is the barrier. The node reads one socket in order, and it
 * delivers to every member inside the PRIVMSG handler, so a PONG on the SENDER's
 * connection after the message proves the deliveries were already queued before
 * any recipient's window is closed. Nothing here is a sleep, and nothing depends
 * on which socket the kernel hands over first.
 *
 * EVERY WINDOW IS OPENED BEFORE THE SEND, because a window opened afterwards
 * covers nothing: the drain PONG that closes it would be the first thing in it. */
static size_t speak_and_close(client_t *from, const char *line,
                              client_t *const *watched, size_t nwatched,
                              size_t *ends)
{
    size_t i;
    size_t sender_end;

    TF_CHECK_MSG(tc_send(&from->c, line) == 0, "%s could not send \"%s\"",
                 from->nick, line);
    /* The barrier. See above: this is what makes the recipients' windows mean
     * anything at all. */
    sender_end = drain(from);
    for (i = 0; i < nwatched; i++) {
        ends[i] = drain(watched[i]);
    }
    return sender_end;
}

static void test_account_tag_on_the_wire(const char *sasl, const char *registry)
{
    nf_node_t node;
    client_t alice;
    client_t bob;
    client_t carol;
    client_t dave;
    client_t erin;
    client_t *watched[3];
    size_t ends[3];
    char want[256];
    char line[160];
    size_t ab;
    size_t ae;
    size_t bb;
    size_t cb;
    size_t db;

    spawn_node(&node, sasl, registry,
               "the account tag, on a node with a registry");
    TF_CHECK_MSG(nf_expect(&node, "accounts=loaded", T_READY_MS) == 0,
                 "the registry did not load, so nothing below could be about an "
                 "account");

    client_open_logged_in(&alice, &node, "alice",
                          "CAP REQ :message-tags account-tag", "alice",
                          "correct horse", "alice");
    TF_CHECK_MSG(nf_expect(&node, "account=alice verified=1", T_IO_MS) == 0,
                 "alice did not establish an account, so nothing below is about a "
                 "logged-in sender");
    client_open_logged_in(&bob, &node, "bob", "CAP REQ :message-tags account-tag",
                          NULL, NULL, "bob");
    client_open_logged_in(&carol, &node, "carol",
                          "CAP REQ :message-tags draft/message-ids", NULL, NULL,
                          "carol");
    client_open_logged_in(&dave, &node, "dave", NULL, NULL, NULL, "dave");
    client_open_logged_in(&erin, &node, "erin", "CAP REQ :message-tags account-tag",
                          NULL, NULL, "erin");

    join_chan(&alice, CHAN_TAGGED);
    join_chan(&bob, CHAN_TAGGED);
    join_chan(&carol, CHAN_TAGGED);
    join_chan(&dave, CHAN_TAGGED);
    join_chan(&erin, CHAN_TAGGED);

    watched[0] = &bob;
    watched[1] = &carol;
    watched[2] = &dave;

    /* ---- A LOGGED-IN SENDER SPEAKS TO A CHANNEL ---- */
    ab = drain(&alice);
    bb = drain(&bob);
    cb = drain(&carol);
    db = drain(&dave);
    (void)snprintf(line, sizeof line, "PRIVMSG " CHAN_TAGGED " hello");
    ae = speak_and_close(&alice, line, watched, 3u, ends);

    /* ---- BOB ASKED, AND GETS THE TAG, AS A WHOLE LINE ----
     *
     * The WHOLE line, not a substring, and that is the assertion with the most
     * teeth in this case: bob's block is `@account=alice ` and nothing else,
     * because bob asked for `message-tags account-tag` and NOT for msgids. A node
     * that stamped the tag, kept a msgid bob never asked for, or put the tag
     * after the prefix fails this line three different ways. */
    (void)snprintf(want, sizeof want,
                   "@account=alice :alice!alice@127.0.0.1 PRIVMSG " CHAN_TAGGED
                   " hello\r\n");
    expect_in_window(&bob, bb, ends[0],
                     "the account tag for a recipient that asked for it", want);
    /* And the sender hears her own PRIVMSG the same way, because the sender is
     * also a destination and the capability that decides is the RECIPIENT's.
     * Her window is the one closed by the barrier, so it is the one line of this
     * message that is certainly inside it. */
    expect_in_window(&alice, ab, ae, "the account tag on the sender's own copy",
                     want);

    /* ---- CAROL ASKED FOR TAGS AND NOT FOR THIS ONE ----
     *
     * Two assertions, and the first is what makes the second mean anything: carol
     * IS given a block -- `msgid`, because she asked for that one -- so "no
     * account" is a statement about which tags she negotiated rather than about a
     * node that wrote her nothing at all. */
    expect_tag_block_present(&carol, cb, ends[1],
                             "carol, who asked for draft/message-ids");
    expect_absent_in_window(&carol, cb, ends[1],
                            "an account tag for a recipient that did not negotiate "
                            "account-tag", "account=");

    /* ---- DAVE ASKED FOR NOTHING ---- */
    expect_no_tag_block(&dave, db, ends[2], "a connection that negotiated nothing");
    expect_absent_in_window(&dave, db, ends[2],
                            "an account tag for a connection that negotiated "
                            "nothing", "account=");

    /* ---- AND THE SAME, TO A NICK RATHER THAN A CHANNEL ----
     *
     * 3.1's first row is a different arm of fanout_deliver() from the channel
     * ones, with its own render, and a feature that only works on one of them is
     * a feature a client discovers as a bug. */
    bb = drain(&bob);
    (void)snprintf(line, sizeof line, "PRIVMSG bob direct");
    ae = speak_and_close(&alice, line, watched, 1u, ends);
    (void)snprintf(want, sizeof want,
                   "@account=alice :alice!alice@127.0.0.1 PRIVMSG bob direct\r\n");
    expect_in_window(&bob, bb, ends[0], "the account tag on a direct message", want);

    /* ---- AN ANONYMOUS SENDER, TO A RECIPIENT THAT ASKED ----
     *
     * The other half of the specification's rule, and the one that is easy to get
     * wrong by stamping the tag whenever the DESTINATION asked: erin negotiated
     * `account-tag`, so a node that gates on the recipient alone would tell bob
     * that erin is somebody. The assertion is made on carol as well -- who is
     * receiving a block and can therefore show that the tag was OMITTED from a
     * block rather than that no block existed. */
    cb = drain(&carol);
    bb = drain(&bob);
    (void)snprintf(line, sizeof line, "PRIVMSG " CHAN_TAGGED " anonymous");
    ae = speak_and_close(&erin, line, watched, 2u, ends);
    TF_CHECK_MSG(ae > 0u, "the anonymous sender's barrier PONG did not arrive");
    expect_tag_block_present(&carol, cb, ends[0],
                             "carol, for a message from an anonymous sender");
    expect_absent_in_window(&carol, cb, ends[0],
                            "an account tag for an ANONYMOUS sender", "account=");
    expect_absent_in_window(&bob, bb, ends[1],
                            "an account tag for an anonymous sender, to the "
                            "recipient that asked hardest for one", "account=");

    /* ---- AND A CLIENT CANNOT ASSERT ITS OWN ACCOUNT TO ANOTHER ONE ----
     *
     * The other direction entirely, and the one the specification exists to
     * close: erin sends a line carrying an `account` tag of her own, and the tag
     * must not come back on the delivered copies. fanout's local write is driven
     * by the parameters and by the two tags this node COMPUTES, never by what the
     * client tagged -- and this is the only assertion in the file that would
     * notice if that ever stopped being true, because an echoed inbound tag
     * looks exactly like a tag the node wrote.
     *
     * Both recipients are watched: bob, who would see `@account=spoofed` if the
     * node echoed it, and carol, who is checked because her copy is the one that
     * proves the omission happened inside a block rather than that no block
     * existed. */
    cb = drain(&carol);
    bb = drain(&bob);
    (void)snprintf(line, sizeof line,
                   "@account=spoofed PRIVMSG " CHAN_TAGGED " spoof");
    ae = speak_and_close(&erin, line, watched, 2u, ends);
    TF_CHECK_MSG(ae > 0u, "the barrier PONG after the spoofed tag did not arrive");
    expect_absent_in_window(&carol, cb, ends[0],
                            "an echoed `account` tag from the INBOUND direction",
                            "account=");
    expect_absent_in_window(&bob, bb, ends[1],
                            "an echoed `account` tag from the inbound direction, "
                            "to the recipient that asked hardest for one",
                            "account=");
    /* ...and the text went through, as a WHOLE UNTAGGED LINE, so the case above is
     * about the tag rather than about a message that silently vanished. It is
     * untagged because erin is anonymous and asked for no msgid, which is the
     * same rule the two rows above are about -- stated here as a rendering rather
     * than as an absence, so the line's bytes are pinned. */
    (void)snprintf(want, sizeof want,
                   ":erin!erin@127.0.0.1 PRIVMSG " CHAN_TAGGED " spoof\r\n");
    expect_in_window(&bob, bb, ends[1],
                     "the message carrying the spoofed tag", want);

    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not stop cleanly");
    nf_free(&node);
    tc_close(&alice.c);
    tc_close(&bob.c);
    tc_close(&carol.c);
    tc_close(&dave.c);
    tc_close(&erin.c);
}

/* ==========================================================================
 * CASE 8: THE TAG DOES NOT CROSS TO A PEER
 * ==========================================================================
 * Two SHIPPED binaries over real TCP, linked, both configured with a registry --
 * so `account-tag` is available on both and bob's request for it is granted. bob
 * then receives alice's message and it carries a `msgid` and NOT an `account`.
 *
 * WHY IT NEEDS TWO NODES rather than an inspection of the code. The decision is
 * one branch -- fanout.c's fanout_emitter_account() returns "" when the emission
 * was RELAYED -- and the way that branch is reached in practice is federation/
 * verbs.c handing a received stamp to fanout_deliver(). A one-node test cannot
 * produce a relayed emission at all, so it can only assert the absence of the
 * feature; this asserts that the feature is present on both sides and stops at
 * the link.
 *
 * THE `msgid` ON BOB'S COPY IS WHAT MAKES IT MEANINGFUL. bob negotiated
 * draft/message-ids, so the far side IS writing a tag block to him, from the
 * carried 2.4 identity -- and the `account` is absent from a block that exists.
 * Without that, "no account tag" would also be satisfied by a node that wrote bob
 * nothing tagged at all, which is a different failure with the same symptom.
 */
#define SECRET_FED "irc-serve-federation-secret-a"
#define CHAN_FED   "#FEDTAG"

static void spawn_fed_node(nf_node_t *node, const char *name, const char *sasl,
                           const char *registry, const char *peer,
                           const char *label)
{
    char name_buf[64];
    char secret_buf[96];
    char sasl_buf[PATH_MAX_TEST];
    char reg_buf[PATH_MAX_TEST];
    char peer_buf[128];
    char *argv[16];
    size_t n = 0;

    /* Copied into writable buffers for the reason spawn_node() gives: a `char *`
     * argv slot holding a `const char *` needs a cast, and upstream clang's
     * -Weverything turns -Wcast-qual into an error. */
    name_buf[0] = '\0';
    secret_buf[0] = '\0';
    sasl_buf[0] = '\0';
    reg_buf[0] = '\0';
    peer_buf[0] = '\0';
    (void)snprintf(name_buf, sizeof name_buf, "%s", name);
    (void)snprintf(secret_buf, sizeof secret_buf, "%s", SECRET_FED);
    if (sasl != NULL) {
        (void)snprintf(sasl_buf, sizeof sasl_buf, "%s", sasl);
    }
    if (registry != NULL) {
        (void)snprintf(reg_buf, sizeof reg_buf, "%s", registry);
    }
    if (peer != NULL) {
        (void)snprintf(peer_buf, sizeof peer_buf, "%s", peer);
    }
    argv[n++] = (char *)"irc-serve";
    argv[n++] = (char *)"--name";
    argv[n++] = name_buf;
    argv[n++] = (char *)"--secret";
    argv[n++] = secret_buf;
    if (sasl != NULL) {
        argv[n++] = (char *)"--sasl-store";
        argv[n++] = sasl_buf;
    }
    if (registry != NULL) {
        argv[n++] = (char *)"--account-store";
        argv[n++] = reg_buf;
    }
    if (peer != NULL) {
        argv[n++] = (char *)"--peer";
        argv[n++] = peer_buf;
    }
    argv[n++] = (char *)"0";
    argv[n] = NULL;
    TF_CHECK_MSG(n < 16u, "%s: the argument vector overflowed", label);
    TF_CHECK_MSG(nf_spawn_binary_argv(node, argv) == 0,
                 "%s: could not spawn a node", label);
}

static void test_account_tag_does_not_cross_to_peers(const char *sasl,
                                                     const char *registry)
{
    nf_node_t a;
    nf_node_t b;
    client_t alice;
    client_t bob;
    char peer_arg[128];
    size_t ab;
    size_t ae;
    size_t bb;
    size_t be;

    /* A first, and with no --peer: a node configured with BOTH ends of a pair
     * dials from both and the pair never comes up, so each pair is configured in
     * ONE direction (federation/link.h). B then dials A, which is also the
     * assertion that the address was resolved before the loop was armed -- 3.4's
     * no-name-lookup-in-the-loop rule, held by construction rather than by
     * inspection. */
    spawn_fed_node(&a, "irc.a", sasl, registry, NULL, "node A");
    TF_CHECK_MSG(nf_expect(&a, "accounts=loaded", T_READY_MS) == 0,
                 "node A did not load the registry, so nothing below is about an "
                 "account identity");
    (void)snprintf(peer_arg, sizeof peer_arg, "irc.a,127.0.0.1,%d", a.port);
    spawn_fed_node(&b, "irc.b", sasl, registry, peer_arg, "node B");
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=irc.b", T_READY_MS) == 0,
                 "the link never came up on A, so nothing below crosses a link: %s",
                 a.out);
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=irc.a", T_READY_MS) == 0,
                 "the link never came up on B: %s", b.out);

    /* alice LOGGED IN on A. bob on B, asking for the tag and for msgids, and not
     * logged in -- which is the whole point: even a client that logged in on its
     * OWN node gets no account claim about somebody else's user. */
    client_open_logged_in(&alice, &a, "alice",
                          "CAP REQ :message-tags draft/message-ids account-tag",
                          "alice", "correct horse", "alice on A");
    TF_CHECK_MSG(nf_expect(&a, "account=alice verified=1", T_IO_MS) == 0,
                 "alice did not establish an account on A");
    client_open_logged_in(&bob, &b, "bob",
                          "CAP REQ :message-tags draft/message-ids account-tag",
                          NULL, NULL, "bob on B");
    /* bob's own `account-tag` request was GRANTED on his node -- asserted by
     * client_open_logged_in()'s wait for the ACK -- so the absence below cannot
     * be explained by his side withholding the capability. */
    TF_CHECK_MSG(strstr(b.out, "account-tag") != NULL,
                 "node B did not advertise account-tag even with a registry, so "
                 "the case below would pass for the wrong reason");

    join_chan(&alice, CHAN_FED);
    join_chan(&bob, CHAN_FED);

    /* THE BARRIER IS ALICE'S OWN PONG, and it is alice's rather than bob's for
     * the reason test_account.c's case 7 states at length: two connections have
     * no order between them, and this message crosses a link before it reaches
     * bob, so a window closed by bob's PING would be asserting about the order two
     * sockets arrived in. alice's PONG is answered only after the node has
     * processed her PRIVMSG, and processing it queues the forward -- so the
     * forward is already on the wire's queue when bob's window is closed. */
    ab = drain_on(&alice, "irc.a");
    bb = drain_on(&bob, "irc.b");
    TF_CHECK_MSG(tc_send(&alice.c, "PRIVMSG " CHAN_FED " federated") == 0,
                 "alice's PRIVMSG could not be sent");
    ae = drain_on(&alice, "irc.a");
    be = drain_on(&bob, "irc.b");

    /* ---- ON B, THE LINE CROSSED AND THE TAG DID NOT ---- */
    expect_tag_block_present(&bob, bb, be,
                             "the relayed line on the far side of the link");
    expect_absent_in_window(&bob, bb, be,
                            "an account tag for a message this node did not "
                            "authenticate the sender of", "account=");

    /* ---- ON A, THE LOCAL DELIVERY HAS IT, WHICH IS THE CONTRAST ----
     *
     * The same message, the same sender, the same requested capability, on the
     * node that verified the credential and not on the node that did not. If
     * this row were absent, "no tag on B" would also be satisfied by a node that
     * emits no tags anywhere -- and case 7 already covers that, but it covers it
     * on a different message, and a contrast is cheaper to read than a memory. */
    /* A SUBSTRING rather than a whole line, and the reason is in
     * expect_text_in_window(): alice negotiated msgids as well, so her copy
     * carries `msgid=irc.a_<epoch>_<id>;account=alice ` and the first pair holds
     * two numbers this test cannot spell. Everything the assertion is about --
     * the account name, and its position after the msgid and before the prefix --
     * is inside it. */
    expect_text_in_window(&alice, ab, ae,
                          "the local delivery of the very same message",
                          "account=alice :alice!alice@127.0.0.1 PRIVMSG " CHAN_FED
                          " federated");

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not stop cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not stop cleanly");
    nf_free(&a);
    nf_free(&b);
    tc_close(&alice.c);
    tc_close(&bob.c);
}

/* ==========================================================================
 * THE TAG BLOCK AND THE LINE CAP MUST STILL AGREE, AS A DERIVATION
 * ==========================================================================
 * `fanout_line_fits()` is the node's own answer to "is this message too long to
 * relay", and Phase 10.2 changed it: the client-facing form now charges the
 * LARGEST CLIENT-VISIBLE TAG BLOCK, because a member's line carries `msgid` and
 * `account` while a forwarded line carries only 2.4's internal block.
 *
 * WHY THIS IS A DERIVATION AND NOT A WIRE TEST. Every wire version of this
 * property runs from a test client on loopback, whose hostmask is 25 bytes --
 * which leaves about 280 bytes of slack between what the cap charges and what the
 * line actually occupies. A cap that had stopped charging the tag would therefore
 * pass every wire test and still lose a message: `fanout_line_fits_n()` charges
 * the prefix and target at their MAXIMUM widths, so the real envelope is far
 * smaller than the charge, and a client whose host is a long FQDN is exactly the
 * case where the two meet. `conn_t::host` is 128 bytes wide and this node records
 * what accept() OBSERVED, so such a client is not hypothetical.
 *
 * So the assertion is the property itself: take the largest body the node's cap
 * accepts for the widest possible hostmask, add the widest possible tag block and
 * the envelope the formatter will really write, and require the result to be a
 * legal line. It is in process and on a return value, like the account_set() rules
 * below, for the same reason they are: no sequence of client input reaches this
 * state, because a test cannot make its own hostmask 255 bytes long.
 */
static void expect_the_tag_charge_is_real(void)
{
    /* The widest hostmask conn_hostmask() can build: the three field widths and
     * the three separators, which is CONN_HOSTMASK_MAX rather than a guess. */
    char hostmask[CONN_HOSTMASK_MAX];
    const size_t tags_max = 1u /* '@' */ + IRC_MAX_MSGTAG + 1u /* ';' */
                            + ACCOUNT_TAG_MAX + 1u /* NUL */ - 1u;
    size_t lo = 0;
    size_t hi = (size_t)IRC_MAX_LINE;
    char *body = NULL;
    size_t rendered;

    memset(hostmask, 'h', sizeof hostmask - 1u);
    hostmask[sizeof hostmask - 1u] = '\0';
    body = (char *)malloc(hi + 1u);
    TF_CHECK_MSG(body != NULL, "could not allocate the probe body");
    if (body == NULL) {
        return;
    }
    /* The largest body THIS node accepts, found with the node's own predicate
     * rather than by re-deriving the arithmetic: a second derivation is a second
     * opinion about code that already exists. */
    while (lo < hi) {
        const size_t mid = lo + (hi - lo + 1u) / 2u;

        memset(body, 'x', mid + 1u);
        body[mid] = '\0';
        if (fanout_line_fits(hostmask, "PRIVMSG", "#TAGGED", body) != 0) {
            lo = mid;
        } else {
            hi = mid - 1u;
        }
    }
    TF_CHECK_MSG(lo > 0u, "fanout_line_fits() refuses every body length, so the "
                 "cap this checks does not exist");
    memset(body, 'x', lo + 1u);
    body[lo] = '\0';

    /* What the formatter will really write, in the order message_format_ex()
     * writes it: the tag block, then ':' + prefix, then the verb, the target and
     * the text, then the CRLF reply.c adds. */
    rendered = tags_max + 1u /* ' ' */ + 1u /* ':' */ + strlen(hostmask) + 1u
              + strlen("PRIVMSG") + 1u + strlen("#TAGGED") + 1u + strlen(body)
              + 2u /* CRLF */;
    TF_CHECK_MSG(rendered <= (size_t)IRC_MAX_LINE,
                 "the largest body this node accepts renders to %zu bytes once "
                 "the widest client tag block (%zu) and the widest hostmask "
                 "(%zu) are on it, which is over IRC_MAX_LINE (%d): a client "
                 "with a long host would lose the message to a decoration. The "
                 "cap must charge the tag block it may actually write.",
                 rendered, tags_max, strlen(hostmask), IRC_MAX_LINE);

    /* AND ONE BYTE MORE IS REFUSED, so the assertion above is about the CAP and
     * not about a predicate that refuses everything. */
    memset(body, 'x', lo + 2u);
    body[lo + 1u] = '\0';
    TF_CHECK_MSG(fanout_line_fits(hostmask, "PRIVMSG", "#TAGGED", body) == 0,
                 "fanout_line_fits() accepted a body one byte longer than the "
                 "longest it accepted, so the measurement above is off the "
                 "boundary");
    free(body);
}

/* ==========================================================================
 * CASE 9: `account-notify`
 * ==========================================================================
 * Four clients on one node with a registry, and one property each:
 *
 *   alice   logged in, negotiated account-notify  -> `ACCOUNT alice PASS`
 *   bob     NOT logged in, negotiated it            -> `ACCOUNT *`
 *   carol   logged in, negotiated NOTHING           -> nothing at all
 *   dave    logged in, negotiated nothing but SENDS `ACCOUNT` -> answered anyway
 *
 * And two on the retired dialect, because that is the collision the handler's
 * comment is about and a comment is not a check: `ACCOUNT hunter2` must be
 * refused with 461, and NICK must still work afterwards -- because a handler that
 * had swallowed the retired nickname-change verb would leave a client unable to
 * change its nickname, and nothing else in this file would notice.
 *
 * Every window is closed by a PING on the SAME connection the command went out on,
 * which is the only shape that is ordered; see speak_and_close()'s comment for the
 * case where it is not.
 */
static void test_account_notify(const char *sasl, const char *registry)
{
    nf_node_t node;
    client_t alice;
    client_t bob;
    client_t carol;
    client_t dave;
    char want[256];
    char line[256];
    size_t from;
    size_t end;

    spawn_node(&node, sasl, registry, "the account-notify line");
    TF_CHECK_MSG(nf_expect(&node, "accounts=loaded", T_READY_MS) == 0,
                 "the registry did not load, so nothing below is about an account");

    /* ---- alice: the unsolicited notification, on a connection that asked ---- */
    client_open_logged_in(&alice, &node, "alice", "CAP REQ :account-notify",
                          "alice", "correct horse", "alice");
    TF_CHECK_MSG(nf_expect(&node, "account=alice verified=1", T_IO_MS) == 0,
                 "alice did not establish an account, so the PASS below would be "
                 "about nothing");
    /* The line is UNSOLICITED and arrives after the MOTD, so the wait is for the
     * line itself and the drain follows it. `ACCOUNT <account> PASS` is the form
     * the task names; the specification's older form omits the PASS, and both are
     * rendered from one function. */
    (void)snprintf(want, sizeof want,
                   ":alice!alice@127.0.0.1 ACCOUNT alice PASS\r\n");
    TF_CHECK_MSG(tc_expect(&alice.c, want, T_IO_MS) == 0,
                 "a client that negotiated account-notify and logged in was not "
                 "told its association at the end of its registration burst:\n  "
                 "%s", tc_buffer(&alice.c));

    /* ---- bob: the same capability, and the SAME answer with no account ---- */
    client_open_logged_in(&bob, &node, "bob", "CAP REQ :account-notify", NULL,
                          NULL, "bob");
    (void)snprintf(want, sizeof want, ":bob!bob@127.0.0.1 ACCOUNT *\r\n");
    TF_CHECK_MSG(tc_expect(&bob.c, want, T_IO_MS) == 0,
                 "a client that negotiated account-notify and did NOT log in was "
                 "not told `ACCOUNT *`:\n  %s", tc_buffer(&bob.c));
    /* ...and NOT told a PASS, which is the same assertion in the other direction
     * and is what a node that defaulted the parameter would get wrong. */
    TF_CHECK_MSG(strstr(tc_buffer(&bob.c), "ACCOUNT alice") == NULL,
                 "an unidentified client was told somebody ELSE's account");

    /* ---- carol: an account, and no capability, and therefore SILENCE ---- */
    client_open_logged_in(&carol, &node, "carol", NULL, "alice", "correct horse",
                          "carol");
    from = drain(&carol);
    end = drain(&carol);
    expect_absent_in_window(&carol, from, end,
                            "an unsolicited ACCOUNT line to a connection that "
                            "negotiated nothing", " ACCOUNT ");
    /* ...and nothing anywhere in her whole stream, so the silence is not an
     * artefact of the window. */
    TF_CHECK_MSG(strstr(tc_buffer(&carol.c), "ACCOUNT") == NULL,
                 "a connection that negotiated nothing was sent an ACCOUNT line "
                 "at some point:\n  %s", tc_buffer(&carol.c));

    /* ---- dave: no capability, but he ASKS, so he is ANSWERED ---- */
    client_open_logged_in(&dave, &node, "dave", NULL, "alice", "correct horse",
                          "dave");
    from = drain(&dave);
    (void)snprintf(line, sizeof line, "ACCOUNT");
    TF_CHECK_MSG(tc_send(&dave.c, line) == 0, "ACCOUNT send failed");
    end = drain(&dave);
    (void)snprintf(want, sizeof want, ":dave!dave@127.0.0.1 ACCOUNT alice PASS\r\n");
    expect_in_window(&dave, from, end,
                     "the answer to a bare ACCOUNT from a client that never "
                     "negotiated the capability", want);

    /* ---- THE RETIRED DIALECT, WHICH IS THE COLLISION ----
     *
     * `ACCOUNT hunter2` is the old nickname-change command. This node had no
     * ACCOUNT row in its dispatch table at all before Phase 10.2b -- it was 421 --
     * and nickname changes are `NICK`, so the two words never reached the same
     * switch. What is asserted here is that adding the row did not make the
     * retired shape mean something: it is refused on ARITY, and the nickname is
     * still changeable afterwards. */
    from = drain(&dave);
    (void)snprintf(line, sizeof line, "ACCOUNT hunter2");
    TF_CHECK_MSG(tc_send(&dave.c, line) == 0, "the retired ACCOUNT form could not "
                                              "be sent");
    end = drain(&dave);
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 461 dave :Not enough parameters\r\n");
    expect_in_window(&dave, from, end,
                     "the refusal of the retired one-parameter ACCOUNT form",
                     want);
    expect_absent_in_window(&dave, from, end,
                            "a nickname change from the retired ACCOUNT form",
                            "ACCOUNT dave2");

    /* ---- AND NICK STILL WORKS, WHICH IS THE WHOLE POINT ----
     *
     * Not a tautology: it is the assertion that fails if a future ACCOUNT handler
     * ever takes the retired meaning, and nothing else in this file would notice
     * that a client could no longer change its nickname.
     *
     * THE RENAME IS NOT OBSERVED THROUGH A `NICK` ECHO, because a client-issued
     * rename on this node emits none -- handle_nick() reports it on the node's own
     * output and does not fan it out, which 3.1 has never claimed otherwise. It is
     * observed through the PREFIX of the very next line the node sends that
     * connection, which is rendered from the nickname it now holds: the ACCOUNT
     * answer below. One command proves both that the rename took effect and that
     * ACCOUNT still works afterwards, which is the pair the collision is about. */
    from = drain(&dave);
    (void)snprintf(line, sizeof line, "NICK dave2");
    TF_CHECK_MSG(tc_send(&dave.c, line) == 0, "NICK send failed");
    (void)snprintf(line, sizeof line, "ACCOUNT");
    TF_CHECK_MSG(tc_send(&dave.c, line) == 0, "the second ACCOUNT send failed");
    end = drain(&dave);
    (void)snprintf(want, sizeof want,
                   ":dave2!dave@127.0.0.1 ACCOUNT alice PASS\r\n");
    expect_in_window(&dave, from, end,
                     "the nickname change that ACCOUNT must not have broken, seen "
                     "in the prefix of the next line the node sends that "
                     "connection", want);
    TF_CHECK_MSG(nf_expect(&node, "nick_change: fd=", T_IO_MS) == 0,
                 "the node did not report the rename at all");

    /* ---- AND NO `FAIL`, BECAUSE THERE IS NO EVENT FOR IT ----
     *
     * Not a claim of coverage: a check that the wire form is absent, with the
     * reason recorded. SASL PLAIN has no logout and there is no account service,
     * so `ACCOUNT <account> FAIL` describes a transition this node cannot have --
     * and a test that asserted the form's presence would be asserting a feature. */
    TF_CHECK_MSG(strstr(tc_buffer(&alice.c), "FAIL") == NULL &&
                     strstr(tc_buffer(&dave.c), "FAIL") == NULL,
                 "an `ACCOUNT ... FAIL` line appeared, and there is no logout on "
                 "this node for it to describe");

    /* ---- AND THE ACCOUNT NAME IS NEVER RENDERED EMPTY BY ANY OF IT ---- */
    expect_account_name_never_empty(&node);

    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not stop cleanly");
    nf_free(&node);
    tc_close(&alice.c);
    tc_close(&bob.c);
    tc_close(&carol.c);
    tc_close(&dave.c);
}

/* ==========================================================================
 * CASE 10: `extended-join`
 * ==========================================================================
 * The JOIN echo carries the account and the realname, and the account field is
 * `<account>` or `*` -- which is the whole of what has to be true, so the
 * assertions are on whole lines and on the `*` case as much as on the name.
 *
 *   bob     NOT logged in, negotiated extended-join
 *   carol   logged in, negotiated NOTHING
 *   alice   logged in, negotiated extended-join -- JOINS LAST
 *
 * ORDER IS THE POINT. A JOIN echo goes to the channel's EXISTING members, so alice
 * has to arrive after the other two or there is nobody to observe her JOIN -- and
 * one emission observed by a recipient who asked and by one who did not is the only
 * way to show the choice is per destination rather than per verb. The JOIN is sent
 * on the SENDER's connection and the sender's PONG closes the barrier, for the
 * reason speak_and_close() gives.
 */
#define CHAN_XJOIN "#XJOIN"

static void test_extended_join(const char *sasl, const char *registry)
{
    nf_node_t node;
    client_t alice;
    client_t bob;
    client_t carol;
    char want[256];
    char line[128];
    size_t ab;
    size_t ae;
    size_t bb;
    size_t be;
    size_t cb;
    size_t ce;

    spawn_node(&node, sasl, registry, "the extended JOIN echo");
    TF_CHECK_MSG(nf_expect(&node, "accounts=loaded", T_READY_MS) == 0,
                 "the registry did not load, so nothing below is about an account");

    client_open_logged_in(&bob, &node, "bob", "CAP REQ :extended-join", NULL, NULL,
                          "bob");
    /* carol is logged in TOO and negotiated nothing, so her JOIN echo says nothing
     * about accounts -- which is the point of the third row of this table: the
     * difference between her line and bob's is the capability, not whether there is
     * an account. */
    client_open_logged_in(&carol, &node, "carol", NULL, "alice", "correct horse",
                          "carol");
    client_open_logged_in(&alice, &node, "alice", "CAP REQ :extended-join", "alice",
                          "correct horse", "alice");
    TF_CHECK_MSG(nf_expect(&node, "account=alice verified=1", T_IO_MS) == 0,
                 "alice did not establish an account, so the name below would be "
                 "about nothing");

    /* ==================== carol IS THERE FIRST ==================== */
    /* A JOIN echo goes to the channel's EXISTING members, so somebody has to be in
     * the channel before there is anybody to observe the next JOIN. carol goes in
     * first precisely so that bob's and alice's joins are both observable, and her
     * own echo is unobserved -- which is fine, because what this case is about is
     * what an EXISTING member is shown. */
    (void)snprintf(line, sizeof line, "JOIN " CHAN_XJOIN);
    TF_CHECK_MSG(tc_send(&carol.c, line) == 0, "carol's JOIN could not be sent");
    (void)drain(&carol);

    /* ==================== bob JOINS, and has NO ACCOUNT ==================== */
    bb = drain(&bob);
    cb = drain(&carol);
    (void)snprintf(line, sizeof line, "JOIN " CHAN_XJOIN);
    TF_CHECK_MSG(tc_send(&bob.c, line) == 0, "bob's JOIN could not be sent");
    be = drain(&bob); /* the barrier: bob sent it */
    ce = drain(&carol);

    /* `*` AND NOT AN EMPTY FIELD. This is the specification's whole claim about the
     * anonymous case, and 2.1.1's invariant one layer down: a value a client reads
     * as "this user has no account" must be the protocol's own token for it and not
     * an empty parameter -- which 3.2 cannot even represent. */
    (void)snprintf(want, sizeof want,
                   ":bob!bob@127.0.0.1 JOIN " CHAN_XJOIN " * :Real bob\r\n");
    expect_in_window(&bob, bb, be, "the extended JOIN for a member with NO account",
                     want);

    /* AND CAROL GETS RFC 2812 3.3.1's JOIN AND NOTHING ELSE. The whole line is
     * asserted rather than a prefix of it, because the failure this guards against
     * is a client reading the account name as a topic and the realname as a
     * reason -- and a prefix assertion would pass on the very line that does it. */
    (void)snprintf(want, sizeof want, ":bob!bob@127.0.0.1 JOIN " CHAN_XJOIN "\r\n");
    expect_in_window(&carol, cb, ce,
                     "the PLAIN JOIN for a member that negotiated nothing", want);
    expect_absent_in_window(&carol, cb, ce,
                            "an extended JOIN for a member that negotiated nothing",
                            "Real bob");

    /* ---- AND NO `account` MESSAGE TAG LEAKS INTO THE JOIN, WHICH IS A DIFFERENT
     * FEATURE ON A DIFFERENT CAPABILITY ---- */
    expect_absent_in_window(&bob, bb, be,
                            "an account message tag on the extended JOIN, which is "
                            "`account-tag`'s job and needs its own negotiation",
                            "@account=");

    /* ==================== alice JOINS, WITH AN ACCOUNT ==================== */
    ab = drain(&alice);
    bb = drain(&bob);
    cb = drain(&carol);
    (void)snprintf(line, sizeof line, "JOIN " CHAN_XJOIN);
    TF_CHECK_MSG(tc_send(&alice.c, line) == 0, "alice's JOIN could not be sent");
    ae = drain(&alice); /* the barrier: alice sent it */
    be = drain(&bob);
    ce = drain(&carol);

    /* THE ACCOUNT AND THE REALNAME, AS A WHOLE LINE. RFC 1459 2.3.1's realname is
     * what USER sent, and client_register() sends `:Real alice`, so the trailing
     * parameter is exactly that. */
    (void)snprintf(want, sizeof want,
                   ":alice!alice@127.0.0.1 JOIN " CHAN_XJOIN " alice :Real "
                   "alice\r\n");
    expect_in_window(&alice, ab, ae, "the extended JOIN the joiner sees", want);
    /* ...and bob, who asked, sees the same extended form: ONE emission, and both
     * recipients are handed the shape they asked for rather than the shape the
     * first member happened to negotiate. */
    expect_in_window(&bob, bb, be, "the extended JOIN for the member that asked",
                     want);

    /* AND CAROL STILL GETS THE PLAIN ONE, for the same alice. This is the contrast
     * the case exists for: the same sender, the same account, two recipients, two
     * shapes -- so neither line can be explained by anything about the JOIN. */
    (void)snprintf(want, sizeof want, ":alice!alice@127.0.0.1 JOIN " CHAN_XJOIN "\r\n");
    expect_in_window(&carol, cb, ce,
                     "the PLAIN JOIN for a member that did not negotiate "
                     "extended-join", want);
    expect_absent_in_window(&carol, cb, ce,
                            "an extended JOIN for a member that did not negotiate "
                            "it", "Real alice");
    expect_absent_in_window(&carol, cb, ce,
                            "the ACCOUNT of the joiner, to a member that did not "
                            "negotiate extended-join", "XJOIN alice");

    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not stop cleanly");
    nf_free(&node);
    tc_close(&alice.c);
    tc_close(&bob.c);
    tc_close(&carol.c);
}

/* ==========================================================================
 * THE REFUSAL RULES OF account_set(), IN PROCESS, ON RETURN VALUES
 * ==========================================================================
 * These are the assertions CONTRIBUTING.md calls observable ("return values,
 * state transitions, and bytes on the wire") and they are in process against a
 * real server_t because -- exactly as test_nick_index.c puts it about itself --
 * **no command sequence reaches these states**. An empty account name is not
 * something a client can produce: sasl_plain_parse() requires the authcid field
 * and sasl_plain_verify() refuses an empty one, so by the time account_set() is
 * called the name is non-empty. A 64-byte name is the same story. A connection
 * that never completed an exchange is reachable only by writing
 * `c->sasl` directly, which a socket cannot do.
 *
 * That is the WHOLE argument for this section, and it is also the honest limit on
 * the teeth of the empty-account property: `logged_in && account != ""` cannot be
 * reached from the wire, so the wire cases above cannot prove the conjunction --
 * they prove the OUTCOME (no 330, no name), which is what a client can see, and
 * this section proves the RULE that makes the outcome unreachable.
 *
 * IT IS NOT A STRUCT-FIELD ASSERTION. Every assertion below is on account_set()'s
 * return value or on account_logged_in()'s, both of which are functions. Nothing
 * here reads conn_t or account_store_t. */
static void expect_account_set_refuses(void)
{
    server_t s;
    conn_t *c;
    char too_long[80];

    /* A registry with one record, built IN MEMORY rather than from a file: this
     * case is about the function's rules, and a file would add a loader failure
     * mode that has its own case in the wire section above. */
    account_store_t *reg = account_store_new();

    TF_CHECK_MSG(reg != NULL, "account_store_new() failed");
    if (reg == NULL) {
        return;
    }
    TF_CHECK_MSG(account_store_add(reg, "alice", "correct horse", 0) == 0,
                 "account_store_add() refused a valid record");
    /* THE KEY SPACE IS WHERE THE EMPTY-ACCOUNT PROPERTY IS ACTUALLY ENFORCED,
     * and this assertion is the one that says so.
     *
     * account_set() refuses an empty name and account_store_verify() refuses one
     * too, but neither of those is what makes the property true: a name that no
     * registry record can carry is a name no connection can ever be logged in
     * as, whatever account_set() does with the string it is handed. So the
     * load-bearing guard is HERE -- and it is the reason the in-process empty-name
     * case below cannot be made to fail by breaking account_set()'s own check:
     * with the key space intact, "no record is named ''" already refuses it. */
    TF_CHECK_MSG(account_store_add(reg, "", "correct horse", 0) == -1,
                 "account_store_add() accepted a record named \"\"; an account "
                 "whose name is the empty string must not be representable at "
                 "all");
    TF_CHECK_MSG(server_init(&s, "irc.a") == 0, "server_init failed");
    s.account_store = reg;
    c = conn_new(-1, CONN_CLIENT);
    TF_CHECK_MSG(c != NULL, "conn_new failed");
    if (c == NULL) {
        /* NOT freed here: server_t already owns it and server_shutdown() is the
         * ONE place in this tree that releases an account registry, so freeing it
         * here as well would be a DOUBLE FREE on a path nothing should ever
         * reach. "Belongs to server_t" is recorded in one statement rather than
         * in two call sites, which is the shape issue #102 was. */
        server_shutdown(&s);
        return;
    }
    /* A connection that completed a SASL exchange, which is the precondition for
     * everything below and which no wire sequence can leave unset. */
    c->sasl = (int)SASL_COMPLETED;

    /* THE EMPTY NAME. The OUTCOME the pass turns on: an account named "" is
     * refused, so it cannot exist to be confused with "no account". Read this
     * together with the account_store_add() assertion above: this one is the
     * consequence, that one is the cause, and neither is redundant. */
    TF_CHECK_MSG(account_set(&s, c, "", "correct horse") == -1,
                 "account_set() accepted an EMPTY account name; an empty account "
                 "and an account named \"\" must not be the same state");
    /* ...and the refusal left the connection exactly as it was: not logged in.
     * A refusal that half-applied would be the same confusion one layer down. */
    TF_CHECK_MSG(account_logged_in(c) == 0,
                 "a refused account_set() still left the connection logged in");

    TF_CHECK_MSG(account_set(&s, c, NULL, "correct horse") == -1,
                 "account_set() accepted a NULL account name");

    /* NO COMPLETED EXCHANGE. */
    c->sasl = (int)SASL_ABORTED;
    TF_CHECK_MSG(account_set(&s, c, "alice", "correct horse") == -1,
                 "account_set() accepted an account on a connection that never "
                 "completed a SASL exchange");
    c->sasl = (int)SASL_COMPLETED;

    /* A FAILED exchange, which is the terminal one: a client that failed to
     * authenticate must not be holding an account. */
    c->sasl = (int)SASL_FAILED;
    TF_CHECK_MSG(account_set(&s, c, "alice", "correct horse") == -1,
                 "account_set() accepted an account on a connection whose SASL "
                 "exchange FAILED");
    c->sasl = (int)SASL_COMPLETED;

    /* A NAME THE FIELD CANNOT HOLD. 64 bytes into a 63-byte bound, and it is
     * REFUSED rather than truncated: a truncated account is a different identity
     * from the one the client authenticated as. */
    memset(too_long, 'x', sizeof too_long - 1u);
    too_long[sizeof too_long - 1u] = '\0';
    TF_CHECK_MSG(account_set(&s, c, too_long, "correct horse") == -1,
                 "account_set() accepted a 70-byte account name; it must be "
                 "REFUSED, not truncated");
    TF_CHECK_MSG(account_logged_in(c) == 0,
                 "an over-long account name left the connection logged in");

    /* THE WRONG PASSWORD, against a registry that holds the name. */
    TF_CHECK_MSG(account_set(&s, c, "alice", "wrong") == -1,
                 "account_set() accepted an account with the wrong password");

    /* NO REGISTRY. The other half of the invariant, and the one that makes a node
     * with no account system indistinguishable from a client with no account. */
    {
        account_store_t *saved = s.account_store;

        s.account_store = NULL;
        TF_CHECK_MSG(account_set(&s, c, "alice", "correct horse") == -1,
                     "account_set() established an account with NO registry "
                     "configured");
        s.account_store = saved;
    }
    TF_CHECK_MSG(account_logged_in(c) == 0,
                 "a node with no registry left a connection logged in");

    /* ---- AND A NAME THAT IS NOT WRITABLE AS A PARAMETER ----
     *
     * The rule is account_name_wire_safe()'s, and Phase 10.3 made it
     * LOAD-BEARING: an account name is a MIDDLE parameter of 330
     * RPL_WHOISACCOUNT, of the extended JOIN echo and of two S-verbs, and a message
     * PARAMETER can escape nothing -- 3.2 refuses SP outright. A name holding a
     * space would be a `330` with four parameters where the specification says
     * three, and a JOIN echo a client reads as carrying a topic.
     *
     * It is asserted on RETURN VALUES and on the store's key space, and no wire
     * sequence reaches either: a registry holding such a name is refused at load,
     * so a client could never authenticate as one, so there is nothing for the wire
     * to carry. That is the same argument the in-process section makes about the
     * empty name, and for the same reason -- no command sequence produces these
     * states. */
    TF_CHECK_MSG(account_set(&s, c, "two words", "correct horse") == -1,
                 "account_set() accepted an account name holding a SPACE; it has "
                 "to be refused, because an account name is an IRC middle "
                 "parameter and 3.2 cannot escape a space in one");
    TF_CHECK_MSG(account_set(&s, c, "alice bob", "correct horse") == -1,
                 "account_set() accepted an account name holding a space in the "
                 "middle");
    TF_CHECK_MSG(account_set(&s, c, "alice\tctl", "correct horse") == -1,
                 "account_set() accepted an account name holding a TAB");
    TF_CHECK_MSG(account_set(&s, c, ":alice", "correct horse") == -1,
                 "account_set() accepted an account name with a LEADING COLON, "
                 "which is 3.2's parameter marker and cannot be told from one");
    TF_CHECK_MSG(account_set(&s, c, "*", "correct horse") == -1,
                 "account_set() accepted the protocol's \"no account\" token as "
                 "an account name; 2.1.1's invariant is about not being able to "
                 "represent one, and `*` is the name that would break it");
    TF_CHECK_MSG(account_logged_in(c) == 0,
                 "a refused account name left the connection logged in");
    /* ...and `*` IS ACCEPTED BY THE PREDICATE, because it is what a client reads
     * as "no account" and the RENDERERS must be able to say it. */
    TF_CHECK_MSG(account_name_wire_safe("*") == 1,
                 "account_name_wire_safe() refuses `*`, which is the protocol's own "
                 "token for the absence of an account; every renderer here depends "
                 "on being able to write it");
    /* ...and the store's KEY SPACE refuses it too, which is the whole of why a
     * registry cannot contain a name this node could not publish. */
    TF_CHECK_MSG(account_store_add(reg, "two words", "correct horse", 0) == -1,
                 "account_store_add() accepted an account name holding a space; a "
                 "registry must not be able to hold a name this node cannot show a "
                 "user");

    /* AND THE GOOD CASE, because a function that refuses everything passes every
     * refusal above. */
    TF_CHECK_MSG(account_set(&s, c, "alice", "correct horse") == 0,
                 "account_set() refused a correct credential against a registry "
                 "that holds it");
    TF_CHECK_MSG(account_logged_in(c) == 1,
                 "a correct account was established and the connection does not "
                 "report itself logged in");

    /* account_clear() erases BOTH facts, which is what makes the teardown
     * arm's call to it a real release rather than a half of one. */
    account_clear(c);
    TF_CHECK_MSG(account_logged_in(c) == 0,
                 "account_clear() left the connection reported as logged in");

    conn_free(c);
    /* The registry is released by server_shutdown() here, which is the same arm
     * the wire cases assert a line for -- so this section does not leak it a
     * second way and does not create one. */
    server_shutdown(&s);
}

int main(void)
{
    char sasl_good[] = "/tmp/irc_serve_acct_sasl.XXXXXX";
    char sasl_only[] = "/tmp/irc_serve_acct_sasl2.XXXXXX";
    char acct_good[] = "/tmp/irc_serve_acct_reg.XXXXXX";
    char acct_mis[] = "/tmp/irc_serve_acct_mis.XXXXXX";
    char acct_bad[] = "/tmp/irc_serve_acct_bad.XXXXXX";
    char acct_two_fields[] = "/tmp/irc_serve_acct_2f.XXXXXX";
    char acct_loose[] = "/tmp/irc_serve_acct_loose.XXXXXX";
    char acct_empty[] = "/tmp/irc_serve_acct_empty.XXXXXX";
    char acct_missing[] = "/nonexistent/irc-serve-accounts";
    int fd_sasl;
    int fd_sasl2;
    int fd_acct;
    int fd_mis;
    int fd_bad;
    int fd_2f;
    int fd_loose;
    int fd_empty;

    /* mkstemp() creates each path AND its descriptor, and the paths have to
     * exist before a child execs onto them. */
    fd_sasl = mkstemp(sasl_good);
    fd_sasl2 = mkstemp(sasl_only);
    fd_acct = mkstemp(acct_good);
    fd_mis = mkstemp(acct_mis);
    fd_bad = mkstemp(acct_bad);
    fd_2f = mkstemp(acct_two_fields);
    fd_loose = mkstemp(acct_loose);
    fd_empty = mkstemp(acct_empty);
    TF_CHECK_MSG(fd_sasl >= 0 && fd_sasl2 >= 0 && fd_acct >= 0 && fd_mis >= 0 &&
                     fd_bad >= 0 && fd_2f >= 0 && fd_loose >= 0 && fd_empty >= 0,
                 "could not create the store files this test needs");
    if (fd_sasl < 0 || fd_sasl2 < 0 || fd_acct < 0 || fd_mis < 0 || fd_bad < 0 ||
        fd_2f < 0 || fd_loose < 0 || fd_empty < 0) {
        return 1;
    }

    /* The credential store: `authcid<TAB>password`, sasl_store_load()'s format.
     * Two identical files, because two cases need the same store and neither
     * case may mutate it. */
    TF_CHECK_MSG(write(fd_sasl, "alice\tcorrect horse\n", (size_t)21) == 21,
                 "could not write the credential store");
    (void)close(fd_sasl);
    TF_CHECK_MSG(write(fd_sasl2, "alice\tcorrect horse\n", (size_t)21) == 21,
                 "could not write the second credential store");
    (void)close(fd_sasl2);

    /* The registry: `name<TAB>password<TAB>created`. */
    TF_CHECK_MSG(write(fd_acct, "alice\tcorrect horse\t1750000000\n", (size_t)30) == 30,
                 "could not write the account registry");
    (void)close(fd_acct);
    /* A registry that knows a DIFFERENT account: the two files disagree about
     * `alice`, which is the fail-closed case. */
    TF_CHECK_MSG(write(fd_mis, "bob\tcorrect horse\t1750000000\n", (size_t)29) == 29,
                 "could not write the disagreeing registry");
    (void)close(fd_mis);
    /* A non-numeric `created`: a record this loader must refuse rather than
     * half-read. */
    TF_CHECK_MSG(write(fd_bad, "alice\tcorrect horse\tsoon\n", (size_t)25) == 25,
                 "could not write the malformed registry");
    (void)close(fd_bad);
    /* Only two fields: the "no usable record" refusal, and the reason the format
     * has three is that a two-field record would have to invent a default for
     * the registration metadata. */
    TF_CHECK_MSG(write(fd_2f, "alice\tcorrect horse\n", (size_t)21) == 21,
                 "could not write the two-field registry");
    (void)close(fd_2f);
    /* A registry that is byte-for-byte valid and WORLD-READABLE. Same record as
     * the good one, so the only thing this case can be failing on is the mode --
     * which is the point: a registry any other account on the host can read is a
     * list of passwords, and the refusal is a refusal rather than a warning. */
    TF_CHECK_MSG(write(fd_loose, "alice\tcorrect horse\t1750000000\n",
                       (size_t)30) == 30,
                 "could not write the world-readable registry");
    (void)close(fd_loose);
    /* A file with nothing but a comment: records == 0, which is a refusal and
     * not an empty-but-valid registry. */
    TF_CHECK_MSG(write(fd_empty, "# no accounts yet\n", (size_t)17) == 17,
                 "could not write the empty registry");
    (void)close(fd_empty);

    /* 0600 for the two that must load, and for the rest it is set per case
     * because the MODE is what two of the refusals are about. */
    TF_CHECK(chmod(sasl_good, S_IRUSR | S_IWUSR) == 0);
    TF_CHECK(chmod(sasl_only, S_IRUSR | S_IWUSR) == 0);
    TF_CHECK(chmod(acct_good, S_IRUSR | S_IWUSR) == 0);
    TF_CHECK(chmod(acct_mis, S_IRUSR | S_IWUSR) == 0);
    TF_CHECK(chmod(acct_bad, S_IRUSR | S_IWUSR) == 0);
    TF_CHECK(chmod(acct_two_fields, S_IRUSR | S_IWUSR) == 0);
    TF_CHECK(chmod(acct_empty, S_IRUSR | S_IWUSR) == 0);
    TF_CHECK(chmod(acct_loose, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == 0);

    /* ---- the free itself, which no runtime observation can reach ---- */
    expect_shutdown_frees_the_account_store();

    /* ---- the rules no wire sequence can reach, asserted on return values ---- */
    expect_account_set_refuses();
    expect_the_tag_charge_is_real();

    /* ---- the positive case, first: everything below is a contrast with it -- */
    test_logged_in(sasl_good, acct_good);

    /* ---- the tag, per destination, and then not across a link ---- */
    test_account_tag_on_the_wire(sasl_good, acct_good);
    test_account_tag_does_not_cross_to_peers(sasl_good, acct_good);

    /* ---- and the unsolicited ACCOUNT line ---- */
    test_account_notify(sasl_good, acct_good);

    /* ---- and the JOIN that carries the account ---- */
    test_extended_join(sasl_good, acct_good);

    /* ---- the regression cases ---- */
    test_no_registry(sasl_only, "a credential store and no registry");
    test_default_node();

    /* ---- the fail-closed case ---- */
    test_registry_disagrees(sasl_good, acct_mis);

    /* ---- the four ways to get the registry wrong ---- */
    test_registry_refused(sasl_good, acct_bad, "reason=malformed_record",
                          "a non-numeric creation timestamp");
    test_registry_refused(sasl_good, acct_two_fields, "reason=malformed_record",
                          "a record with two fields");
    test_registry_refused(sasl_good, acct_empty, "reason=no_records",
                          "a registry with no records");
    test_registry_refused(sasl_good, acct_missing, "reason=open",
                          "a path that does not exist");

    /* The world-readable case. The file's CONTENTS are the good registry's; only
     * the mode differs, so this case fails for one reason and one reason only. */
    test_registry_refused(sasl_good, acct_loose, "reason=mode_644",
                          "a world-readable registry");

    /* ---- accounts without logins ---- */
    test_registry_without_credentials(acct_good);

    (void)unlink(sasl_good);
    (void)unlink(sasl_only);
    (void)unlink(acct_good);
    (void)unlink(acct_mis);
    (void)unlink(acct_bad);
    (void)unlink(acct_two_fields);
    (void)unlink(acct_loose);
    (void)unlink(acct_empty);
    tf_done("Account");
    return 0;
}
