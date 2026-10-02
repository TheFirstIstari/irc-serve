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
 *  5. **`account-tag` IS NOT ADVERTISED, EVEN WITH A REGISTRY LOADED.** This is
 *     "advertise only what is real" in the sharpest form available: the tag's
 *     ABSENCE is meaningful to a client (the specification says it MUST NOT be
 *     sent for an unidentified user), so advertising the capability without
 *     emitting the tag tells every client that every logged-in user here is
 *     anonymous. A `CAP REQ :account-tag` is NAKed.
 *  6. **NOTHING IN THIS PHASE EMITS THE TAG.** `@account=` and `+account` appear
 *     nowhere on the wire, from a client that negotiated nothing and from a node
 *     with a full registry.
 *  7. **REGISTER AND UNREGISTER ARE REFUSED WITH 482, NOT 421.** A client that
 *     got 421 would read "this server has never heard of REGISTER"; this node
 *     has heard of it and has decided.
 *  8. **THE STORE IS A SECRET FILE.** A world-readable registry, a malformed
 *     record and a path that does not exist are each REFUSED, and each refusal
 *     lands the node in exactly the state case 3 asserts.
 *  9. **AN ACCOUNT PASSWORD IS NEVER LOGGED.** The password is handed to
 *     account_set() and there is no variable holding it afterwards, so the
 *     node's own output is read and checked.
 * 10. **THE TEARDOWN ARM RAN**, with the state it found.
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
 * ASSERT THAT NO account TAG REACHED THE WIRE, in either direction.
 * --------------------------------------------------------------------------
 * `account-tag` is P10.2's emission and this phase does not do it. The check
 * has to be a CHECK and not an omission, because "the code has no +account
 * anywhere" is exactly the kind of claim that a future edit can invalidate
 * silently.
 *
 * BOTH DIRECTIONS, and the distinction is worth recording: this node never
 * echoes a client's inbound tag block on an outgoing line (fanout's local write
 * is driven by the parameters and the internal 2.4 stamp, not by what the client
 * tagged), so `@account=` cannot appear either -- and if it ever did, a client
 * would be able to ASSERT its own account to another, which is the impersonation
 * primitive the specification exists to close. */
static void expect_no_account_tag_on_the_wire(const test_client_t *cl)
{
    TF_CHECK_MSG(strstr(tc_buffer(cl), "@account=") == NULL,
                 "an `account` tag was written onto the wire; that is P10.2's "
                 "emission and this phase does not do it");
    TF_CHECK_MSG(strstr(tc_buffer(cl), "+account") == NULL,
                 "an `account` tag reached the wire from the inbound direction");
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

    /* ---- `account-tag` IS NOT ADVERTISED, EVEN THOUGH THERE ARE ACCOUNTS ----
     *
     * Checked in three forms so that no single one of them can be the thing doing
     * the work: absent from LS, NAKed by REQ, and not granted by the refusal. The
     * reason is the specification's own sentence -- an absent `account` tag means
     * "not identified" -- so advertising this without emitting the tag would
     * tell every client that every logged-in user on this node is anonymous. */
    TF_CHECK_MSG(tc_send(&alice.c, "CAP LS") == 0, "CAP LS send failed");
    TF_CHECK_MSG(tc_expect(&alice.c, " CAP * LS :", T_IO_MS) == 0, "no CAP LS");
    TF_CHECK_MSG(strstr(tc_buffer(&alice.c), "account-tag") == NULL,
                 "CAP LS advertised account-tag on a node that does not emit the "
                 "tag");
    TF_CHECK_MSG(tc_send(&alice.c, "CAP REQ :account-tag") == 0,
                 "CAP REQ send failed");
    TF_CHECK_MSG(tc_expect(&alice.c, " CAP * NAK :account-tag\r\n", T_IO_MS) == 0,
                 "account-tag was not NAKed");
    TF_CHECK_MSG(strstr(tc_buffer(&alice.c), " ACK :account-tag") == NULL,
                 "the node ACKed a capability it does not implement");
    /* And the advertised set is otherwise exactly what a node with a credential
     * store and a registry advertised before this phase: `sasl` is present
     * because the credential store loaded. */
    TF_CHECK_MSG(strstr(tc_buffer(&alice.c), "sasl") != NULL,
                 "a node with a loaded credential store did not advertise sasl");

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

    expect_no_account_tag_on_the_wire(&alice.c);
    expect_no_account_tag_on_the_wire(&watcher.c);
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

    spawn_node(&node, sasl, NULL, label);
    TF_CHECK_MSG(nf_expect(&node, "accounts=none", T_READY_MS) == 0,
                 "%s: a node with no registry did not say so at start-up", label);

    client_open(&alice, &node, "alice", NULL);

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
 * client cannot either. */
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
     * a list of intentions. A node with no stores offers exactly the three
     * capabilities that need no configuration. */
    /* The copy stops AT the CRLF rather than including it -- `n` is measured to
     * the CR -- so the expected literal has no terminator either. */
    TF_CHECK_MSG(strcmp(caps, " CAP * LS :multi-prefix message-tags "
                              "draft/message-ids") == 0,
                 "the advertised capability list on a node with no stores is "
                 "\"%s\"; it must be exactly the three that need no "
                 "configuration", caps);
    TF_CHECK_MSG(strstr(caps, "account") == NULL,
                 "a name containing \"account\" is advertised on a node with no "
                 "account system");

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

    /* ---- the positive case, first: everything below is a contrast with it -- */
    test_logged_in(sasl_good, acct_good);

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
