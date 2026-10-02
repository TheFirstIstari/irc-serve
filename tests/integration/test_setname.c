/* test_setname.c -- IRCv3's `setname`, on the wire.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS BEING CLAIMED, WHICH IS MOSTLY ABOUT REFUSALS
 * ---------------------------------------------------------------------------
 * The feature is one line on the wire: `:nick!user@host SETNAME :<realname>` back
 * to the client that asked. Almost all of the specification's content is in what
 * must NOT happen, and this file spends its cases there:
 *
 *   1. REFUSED BEFORE REGISTRATION. A pre-registration connection has an EMPTY
 *      realname, so a SETNAME with no gate would "succeed" at setting state that
 *      does not exist yet. 451.
 *   2. SILENTLY IGNORED WITHOUT THE CAPABILITY. This is the specification's own
 *      instruction and it is the opposite of what every other capability here does:
 *      a server must support the command whether or not the client negotiated it,
 *      and a non-negotiating client's SETNAME should be handled with NO RESPONSE.
 *      So the assertion is that nothing arrives -- not a 417, not a 421, not a
 *      `FAIL`. A numeric would be wrong here: `FAIL SETNAME CANNOT_CHANGE_REALNAME`
 *      needs standard-replies, which this node does not have, and inventing a `FAIL`
 *      to stand in for it would put a command word on the wire no client on this
 *      node has been told to expect.
 *   3. AN OVER-LONG REALNAME IS REFUSED, NOT TRUNCATED. This is the case the whole
 *      validation path exists for. `USER` truncates -- a client that has sent NICK
 *      and USER is otherwise stranded with no way to recover -- but SETNAME arrives
 *      on a live connection where refusing costs nothing, and a truncated realname
 *      is one the user did not write which this node then reports to every member of
 *      every channel they are on. The previous value is left EXACTLY as it was and
 *      that is asserted, not assumed.
 *   4. A HOSTILE REALNAME IS REFUSED TOO. A realname reaches this node's own log
 *      with no escaping, and 3.2 says the host is OBSERVED rather than asserted --
 *      so the only injection vector left into a terminal or a log pipeline is the
 *      other C0 controls and DEL, which message_parse_n() does not filter. ESC is
 *      the one worth naming: ESC followed by `[` is a CSI sequence a terminal will
 *      execute. The test sends one and requires the refusal.
 *   5. THE SAME PREDICATE RUNS AT REGISTRATION. `handle_user()` and
 *      `handle_setname()` both call `conn_realname_check()`, and case 4 below is
 *      only meaningful if USER runs it too: otherwise SETNAME is the strict path and
 *      USER the loose one, which is the looser-path failure in reverse.
 *
 * ---------------------------------------------------------------------------
 * THE 255/256 BOUNDARY, ASSERTED FROM BOTH SIDES
 * ---------------------------------------------------------------------------
 * One case sends exactly CONN_MAX_REALNAME bytes and one sends one more. The first
 * is there because a bound that rejects everything is not a bound; the second is
 * the actual refusal. Both use a realname of a SINGLE repeated printable byte, so a
 * failure says "the length test" rather than "some character test".
 *
 * NO FIXED sleep() ANYWHERE (6.3): every wait is tc_expect()'s deadline loop, and
 * every window is closed by a PING whose PONG is the drain token -- numbered per
 * call, because tc_expect() searches the ACCUMULATED buffer and a reused token
 * would be satisfied by an earlier PONG with no read at all.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/cap.h"
#include "core/connection.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define CHAN "#T"

/* The realname length at the boundary. Spelled out as a literal rather than as
 * CONN_MAX_REALNAME so that raising the bound in src/ breaks this line -- the same
 * argument test_registration.c makes about the 005 tokens, and for the same reason:
 * a test that follows the constant cannot notice the constant moved. */
#define AT_LIMIT 255
/* And the observed host, which is the <host> half of the confirmation's prefix.
 * USER's third parameter is `*spoofed` on every connection in this file, so a node
 * that stored the assertion instead of what accept() saw fails here. */
#define OBSERVED_HOST "127.0.0.1"

static unsigned g_drain_seq;

static void drain(test_client_t *c)
{
    char token[64];
    char line[128];

    (void)snprintf(token, sizeof token, "snm%u", g_drain_seq++);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING failed");
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG for drain token %s, so the buffer is not yet drained and "
                 "every claim below would be about the read schedule", token);
}

/* How many complete CRLF-terminated lines the region `from`..end of `c` holds.
 *
 * THIS EXISTS BECAUSE A LIST OF ABSENT NUMERICS IS NOT AN EXHAUSTIVE TEST OF
 * SILENCE. The first version of the "ignored without the capability" case asserted
 * the absence of 417, 421, 451 and the SETNAME line, and a fault that answered
 * with 482 instead of staying silent PASSED it -- the check was a list of the
 * numerics somebody thought of. Counting lines closes that: the drain PONG is the
 * only thing that may be in the window, so any reply of any kind adds a line and
 * fails. The specific absences are still asserted, because a failure that says
 * which numeric arrived is worth more than one that says how many lines did. */
static size_t lines_since(const test_client_t *c, size_t from)
{
    const char *at = tc_buffer(c) + from;
    size_t n = 0;

    for (; *at != '\0'; at++) {
        if (at[0] == '\r' && at[1] == '\n') {
            n++;
        }
    }
    return n;
}

/* Register `c` as `nick`, negotiating `caps` first (NULL for no CAP exchange). The
 * REQ is ACKed whole, so a capability this node does not have fails the wait rather
 * than being quietly NAKed -- which means no case below can pass because the gate
 * was never reached. */
static void register_caps(test_client_t *c, int port, const char *nick,
                          const char *caps)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    if (caps != NULL) {
        (void)snprintf(line, sizeof line, "CAP REQ :%s", caps);
        TF_CHECK_MSG(tc_send(c, line) == 0, "%s CAP REQ send failed", nick);
        (void)snprintf(line, sizeof line, " ACK :%s\r\n", caps);
        TF_CHECK_MSG(tc_expect(c, line, T_IO_MS) == 0,
                     "%s was not ACKed \"%s\", so the node does not have the "
                     "capability and the cases below would be asserting a negative "
                     "for the wrong reason", nick, caps);
    }
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s NICK send failed", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s USER send failed", nick);
    if (caps != NULL) {
        TF_CHECK_MSG(tc_send(c, "CAP END") == 0, "%s CAP END send failed", nick);
    }
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered", nick);
}

/* ---------------------------------------------------------------------------
 * THE CASE
 * ---------------------------------------------------------------------------
 */
static void case_setname(void)
{
    nf_node_t node;
    test_client_t polite;  /* negotiated: the command works */
    test_client_t blunt;   /* no CAP exchange: silently ignored */
    test_client_t early;   /* negotiated, but not registered yet */
    char line[1024];

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    /* ---- ADVERTISED, because the command exists ---- */
    {
        test_client_t c;

        tc_init(&c);
        TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");
        TF_CHECK_MSG(tc_send(&c, "CAP LS") == 0, "CAP LS send failed");
        TF_CHECK_MSG(tc_expect(&c, " CAP * LS :", T_IO_MS) == 0,
                     "CAP LS was not answered");
        TF_CHECK_MSG(strstr(tc_buffer(&c), CAP_SETNAME) != NULL,
                     "CAP LS does not advertise %s, which this node now implements. "
                     "The specification REQUIRES the advertisement unconditionally -- "
                     "the command must work whether or not the client negotiated it -- "
                     "so this is not gated on a store the way account-tag is",
                     CAP_SETNAME);
        /* 005's NAMELEN, which the same specification makes MANDATORY for a node
         * advertising this capability, is asserted in test_registration.c against
         * the whole 005 byte for byte. It is not duplicated here: one place that
         * asserts a token is one place to update, and the boundary cases below are
         * what actually pin the bound the token names. */
        tc_close(&c);
    }

    /* ============================ GATE 1 ============================
     * REFUSED BEFORE REGISTRATION, WITH THE CAPABILITY NEGOTIATED. */
    tc_init(&early);
    TF_CHECK_MSG(tc_connect(&early, node.port) == 0, "early could not connect");
    TF_CHECK_MSG(tc_send(&early, "CAP REQ :" CAP_SETNAME) == 0,
                 "early CAP REQ send failed");
    TF_CHECK_MSG(tc_expect(&early, " ACK :" CAP_SETNAME "\r\n", T_IO_MS) == 0,
                 "early was not ACKed " CAP_SETNAME ", so the capability gate is not "
                 "what the next assertion is about");
    TF_CHECK_MSG(tc_send(&early, "NICK early") == 0, "early NICK send failed");
    /* NO USER, so the connection is CONN_REG_NICK and never CONN_REG_READY. */
    {
        const size_t mark = tc_received(&early);

        TF_CHECK_MSG(tc_send(&early, "SETNAME :Too Early") == 0,
                     "early SETNAME send failed");
        drain(&early);
        TF_CHECK_MSG(tc_expect(&early, " 451 ", T_IO_MS) == 0,
                     "a SETNAME from a connection that has not registered was not "
                     "refused with 451. Without the gate this would \"succeed\": a "
                     "pre-registration connection has an EMPTY realname, so the "
                     "command would be setting state that does not exist yet.");
        TF_CHECK_MSG(strstr(tc_buffer(&early) + mark, " SETNAME") == NULL,
                     "the refused SETNAME was also CONFIRMED. 451 is the refusal and "
                     "the confirmation is the success, and a line doing both means "
                     "the field was written.\n  client saw: %s",
                     tc_buffer(&early) + mark);
    }
    /* And it is still usable: the connection completes registration afterwards, which
     * is what "not registered" means rather than "broken". */
    TF_CHECK_MSG(tc_send(&early, "USER early 0 *spoofed :Real early") == 0,
                 "early USER send failed");
    TF_CHECK_MSG(tc_send(&early, "CAP END") == 0, "early CAP END send failed");
    TF_CHECK_MSG(tc_expect(&early, " 001 ", T_IO_MS) == 0,
                 "a connection refused for a pre-registration SETNAME could not then "
                 "register");
    tc_close(&early);

    /* ============================ GATES 2 AND 3 ============================ */
    tc_init(&polite);
    tc_init(&blunt);
    /* `polite` negotiates BOTH capabilities and `blunt` only `extended-join`. The
     * second one is not incidental: the only wire surface that carries a realname is
     * the extended-JOIN echo (Phase 10.3), so reading the field back REQUIRES
     * extended-join -- and the pair differs by exactly `setname`, which is the whole
     * of gate 2 being tested. A `blunt` that negotiated nothing would be unable to
     * tell "the field did not change" from "this client cannot see the field". */
    register_caps(&polite, node.port, "polite", CAP_SETNAME " " CAP_EXTENDED_JOIN);
    register_caps(&blunt, node.port, "blunt", CAP_EXTENDED_JOIN);

    /* ---- THE HAPPY PATH: the confirmation, byte for byte ---- */
    /* RFC-shaped `:nick!user@host SETNAME :<realname>`, and the host is the OBSERVED
     * one -- `USER` sent `*spoofed` as its third parameter and §2.1 says that slot
     * does not touch c->host. A node that stored the assertion fails here, and that
     * is the point: a confirmation nobody can check is not a confirmation. */
    TF_CHECK_MSG(tc_send(&polite, "SETNAME :Bruce Wayne") == 0,
                 "the SETNAME send failed");
    TF_CHECK_MSG(tc_expect(&polite,
                           ":polite!polite@" OBSERVED_HOST " SETNAME :Bruce Wayne\r\n",
                           T_IO_MS) == 0,
                 "the confirmation is not the specified line.\n  client saw: %s",
                 tc_buffer(&polite));
    drain(&polite);

    /* ---- AT THE BOUNDARY: 255 bytes is ACCEPTED ---- */
    {
        char realname[AT_LIMIT + 1];
        char expect[AT_LIMIT + 128];

        memset(realname, 'a', sizeof realname - 1u);
        realname[sizeof realname - 1u] = '\0';
        (void)snprintf(line, sizeof line, "SETNAME :%s", realname);
        TF_CHECK_MSG(tc_send(&polite, line) == 0, "the boundary SETNAME failed");
        /* NO LEADING COLON BEFORE THE REALNAME, and that is not an oversight in the
         * expectation -- it is the other half of a property worth asserting. 3.2
         * colons a trailing parameter only when the value needs it, so
         * `SETNAME :Bruce Wayne` above carries one (the value holds a space) and
         * this 255-byte run of `a` does not. A node that coloned unconditionally
         * would still be legal, and one that never did would not; the point is that
         * the two confirmations in this file have DIFFERENT shapes and both are
         * asserted exactly. */
        (void)snprintf(expect, sizeof expect,
                       ":polite!polite@" OBSERVED_HOST " SETNAME %s\r\n", realname);
        TF_CHECK_MSG(tc_expect(&polite, expect, T_IO_MS) == 0,
                     "a realname of exactly the advertised NAMELEN was refused. A "
                     "bound that rejects everything is not a bound, and 005's "
                     "NAMELEN=%d says this node accepts it.\n  client saw: %s",
                     AT_LIMIT, tc_buffer(&polite));
        drain(&polite);
    }

    /* ---- ONE OVER THE BOUNDARY: REFUSED, AND THE PREVIOUS VALUE SURVIVES ---- */
    /* The second half is the half that matters. "Refused" could also be satisfied by
     * a node that stored 256 bytes and then declined to confirm it, so the field's
     * contents are checked afterwards -- through a JOIN, because that is the only
     * wire surface that carries a realname. */
    {
        char realname[AT_LIMIT + 2];
        char before[AT_LIMIT + 128];
        const size_t mark = tc_received(&polite);

        memset(realname, 'b', sizeof realname - 1u);
        realname[sizeof realname - 1u] = '\0';
        /* The confirmation the node WOULD send if it truncated: 255 of the b's. If
         * the previous case is skipped, this string is what a truncating node would
         * produce and its absence is the assertion. */
        (void)snprintf(before, sizeof before,
                       ":polite!polite@" OBSERVED_HOST " SETNAME %.*s\r\n",
                       AT_LIMIT, realname);
        (void)snprintf(line, sizeof line, "SETNAME :%s", realname);
        TF_CHECK_MSG(tc_send(&polite, line) == 0,
                     "the over-long SETNAME send failed");
        drain(&polite);
        TF_CHECK_MSG(tc_expect(&polite, " 417 ", T_IO_MS) == 0,
                     "an over-long realname was not refused with 417. It must be "
                     "REFUSED and not truncated: a shortened realname is one the user "
                     "did not write, and this node reports it to every member of every "
                     "channel they are on as though it were theirs.\n  client saw: %s",
                     tc_buffer(&polite) + mark);
        TF_CHECK_MSG(strstr(tc_buffer(&polite) + mark, before) == NULL,
                     "the over-long realname was TRUNCATED and confirmed: %s", before);
        TF_CHECK_MSG(strstr(tc_buffer(&polite) + mark, " SETNAME :") == NULL,
                     "a SETNAME confirmation was sent for a realname that was "
                     "refused.\n  client saw: %s", tc_buffer(&polite) + mark);
        /* AND THE FIELD IS UNCHANGED, read off the wire rather than assumed. A
         * refusal with no confirmation is only half a refusal; the other half is that
         * the value this node will show to third parties is the PREVIOUS one.
         *
         * `polite` joins a channel nobody else is on, and the extended-JOIN echo
         * carries this client's own realname -- Phase 10.3 -- so this reads the field
         * the same way every other member of every other channel will. The `*` is
         * the account field: this node has no registry configured, so no member is
         * logged in, and `*` is the complete answer there rather than an absence. */
        TF_CHECK_MSG(tc_send(&polite, "JOIN " CHAN) == 0, "polite JOIN failed");
        TF_CHECK_MSG(tc_expect(&polite, " 366 ", T_IO_MS) == 0,
                     "polite never completed its JOIN");
        drain(&polite);
        {
            char prev[AT_LIMIT + 1];
            char shown[AT_LIMIT + 160];

            memset(prev, 'a', sizeof prev - 1u);
            prev[sizeof prev - 1u] = '\0';
            (void)snprintf(shown, sizeof shown,
                           ":polite!polite@" OBSERVED_HOST " JOIN " CHAN
                           " * %s\r\n", prev);
            TF_CHECK_MSG(strstr(tc_buffer(&polite), shown) != NULL,
                         "the realname after a refused SETNAME is not the PREVIOUS "
                         "value. It must be the 255 a's this client set before the "
                         "over-long attempt -- the field is what every member of "
                         "every channel this user is on will be shown.\n  "
                         "client saw: %s", tc_buffer(&polite));
            /* And it is not the refused value either, in either the full or the
             * truncated form. Naming both is exhaustive rather than a sample: those
             * are the only two things a truncating node could have stored. */
            (void)snprintf(shown, sizeof shown,
                           ":polite!polite@" OBSERVED_HOST " JOIN " CHAN
                           " * %s\r\n", realname);
            TF_CHECK_MSG(strstr(tc_buffer(&polite), shown) == NULL,
                         "the refused realname reached the wire anyway.\n  "
                         "client saw: %s", tc_buffer(&polite));
            (void)snprintf(shown, sizeof shown,
                           ":polite!polite@" OBSERVED_HOST " JOIN " CHAN
                           " * %.*s\r\n", AT_LIMIT, realname);
            TF_CHECK_MSG(strstr(tc_buffer(&polite), shown) == NULL,
                         "the refused realname was TRUNCATED into the field rather "
                         "than refused.\n  client saw: %s", tc_buffer(&polite));
        }
    }

    /* ---- A HOSTILE REALNAME: REFUSED, NOT STORED ---- */
    /* 0x1b is ESC. On a terminal ESC followed by `[` begins a CSI sequence, so a
     * realname carrying one is a member rewriting somebody else's screen from a
     * channel, and it also lands in this node's own log with no escaping. 0x07 (BEL)
     * is in the same set. The parser already refuses CR, LF and NUL before this
     * point, so these are the bytes that CAN reach here. */
    {
        const size_t mark = tc_received(&polite);
        char hostile[64];

        (void)snprintf(hostile, sizeof hostile, "Escape\x1b" "[2Jand\x07" "bell");
        (void)snprintf(line, sizeof line, "SETNAME :%s", hostile);
        TF_CHECK_MSG(tc_send(&polite, line) == 0, "the hostile SETNAME failed");
        drain(&polite);
        TF_CHECK_MSG(tc_expect(&polite, " 417 ", T_IO_MS) == 0,
                     "a realname carrying ESC and BEL was accepted. There is no "
                     "escaping between the socket and this node's log, and ESC [ is "
                     "a sequence a terminal executes -- a member could rewrite an "
                     "operator's screen from a channel.\n  client saw: %s",
                     tc_buffer(&polite) + mark);
        TF_CHECK_MSG(strstr(tc_buffer(&polite) + mark, "\x1b" "[") == NULL,
                     "the ESC reached the wire in a confirmation.\n  client saw: %s",
                     tc_buffer(&polite) + mark);
    }

    /* ---- EMPTY IS LEGAL ---- */
    /* A realname may be empty: `extended-join` renders it as a bare `:` and its own
     * comment says a client that sent none has an empty realname "which is a fact
     * about the client rather than a limit this node imposes". A client clearing its
     * own realname has to be able to say so, so this is checked rather than left. */
    TF_CHECK_MSG(tc_send(&polite, "SETNAME :") == 0, "the clearing SETNAME failed");
    TF_CHECK_MSG(tc_expect(&polite,
                           ":polite!polite@" OBSERVED_HOST " SETNAME :\r\n", T_IO_MS) == 0,
                 "an empty realname was not accepted, and it is a legal state.\n  "
                 "client saw: %s", tc_buffer(&polite));
    drain(&polite);

    /* ============================ GATE 2 ============================
     * WITHOUT THE CAPABILITY: SILENTLY IGNORED. Nothing arrives, and nothing
     * changes. The two halves are separate assertions because "silently" is only
     * half the requirement. */
    {
        const size_t mark = tc_received(&blunt);

        TF_CHECK_MSG(tc_send(&blunt, "SETNAME :Not Negotiated") == 0,
                     "blunt's SETNAME send failed");
        drain(&blunt);
        TF_CHECK_MSG(strstr(tc_buffer(&blunt) + mark, " SETNAME") == NULL,
                     "a client that did NOT negotiate %s got a SETNAME line. The "
                     "specification asks for this to be handled SILENTLY, and the "
                     "server-to-client SETNAME line MUST NOT be sent to a client "
                     "without the capability.\n  client saw: %s",
                     CAP_SETNAME, tc_buffer(&blunt) + mark);
        TF_CHECK_MSG(strstr(tc_buffer(&blunt) + mark, " 417 ") == NULL,
                     "a client that did not negotiate %s got a 417. Silence is the "
                     "specified behaviour: the client has not done anything wrong, "
                     "and `FAIL SETNAME CANNOT_CHANGE_REALNAME` needs "
                     "standard-replies, which this node does not have -- inventing a "
                     "FAIL would put a command word on the wire no client here has "
                     "been told to expect.\n  client saw: %s",
                     CAP_SETNAME, tc_buffer(&blunt) + mark);
        TF_CHECK_MSG(strstr(tc_buffer(&blunt) + mark, " 421 ") == NULL,
                     "a client that did not negotiate %s got 421, which reads as "
                     "\"this server has never heard of SETNAME\". The specification "
                     "requires the command to be SUPPORTED whether or not it was "
                     "negotiated, so 421 would be a lie about a verb this dispatch "
                     "table has a row for.\n  client saw: %s",
                     CAP_SETNAME, tc_buffer(&blunt) + mark);
        TF_CHECK_MSG(strstr(tc_buffer(&blunt) + mark, " 451 ") == NULL,
                     "a REGISTERED client that did not negotiate %s got 451.\n  "
                     "client saw: %s", CAP_SETNAME, tc_buffer(&blunt) + mark);
        /* AND THE EXHAUSTIVE ONE: the drain PONG and nothing else. Every reply of
         * any kind is a second line here, which is what makes this a test of
         * SILENCE rather than a test of four numerics somebody remembered. */
        TF_CHECK_MSG(lines_since(&blunt, mark) == 1u,
                     "%zu lines arrived in answer to a SETNAME from a client that "
                     "did not negotiate %s; exactly one may -- the drain PONG. "
                     "Silence is the specified behaviour and any numeric at all is a "
                     "reply.\n  client saw: %s", lines_since(&blunt, mark),
                     CAP_SETNAME, tc_buffer(&blunt) + mark);
    }

    /* ---- AND THE FIELD REALLY DID NOT CHANGE ---- */
    /* Same route as the truncation check above: JOIN, and read the realname off the
     * extended-JOIN echo. Silence on the wire alone would also be satisfied by a
     * node that changed the field and declined to say so. */
    TF_CHECK_MSG(tc_send(&blunt, "JOIN " CHAN) == 0, "blunt JOIN failed");
    TF_CHECK_MSG(tc_expect(&blunt, " 366 ", T_IO_MS) == 0,
                 "blunt never completed its JOIN");
    drain(&blunt);
    TF_CHECK_MSG(strstr(tc_buffer(&blunt),
                        ":blunt!blunt@" OBSERVED_HOST " JOIN " CHAN
                        " * :Not Negotiated") == NULL,
                 "the realname changed even though nothing was confirmed. Silence is "
                 "only half the requirement; the other half is that the value on the "
                 "wire is unchanged.\n  client saw: %s", tc_buffer(&blunt));

    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
    tc_close(&polite);
    tc_close(&blunt);
}

/* ---------------------------------------------------------------------------
 * TEETH, AND WHERE THEY WERE INJECTED
 * ---------------------------------------------------------------------------
 * Each was watched go red with the behaviour broken, and the build was checked
 * before the run was believed -- an uncompilable fault leaves the previous binary
 * in place and reports a pass, which has happened in this repo seven times.
 *
 *   SETNAME accepted BEFORE REGISTRATION
 *       commands.c, k_commands[]: `{ "SETNAME", handle_setname, 0 }` changed to
 *       `pre_reg = 1`. Fails the 451 case, and the "still usable afterwards" case
 *       still passes -- which is the point: without the gate the command would
 *       succeed AND the connection would still register, so only the 451 assertion
 *       can see it.
 *
 *   SETNAME accepted WITHOUT the capability
 *       commands.c, handle_setname(): the `cap_setname_enabled(c) == 0` branch
 *       removed. Fails the three silence assertions at once, and NOT the arity or
 *       validation cases.
 *
 *   the capability gate turned into an ERROR rather than silence
 *       commands.c, handle_setname(): the silent branch answers 482 instead. PASSED
 *       the first version of this file, which asserted the absence of 417, 421, 451
 *       and the SETNAME line -- because those are the numerics somebody thought of,
 *       and a list of absent numerics is not a test of silence. That is why
 *       lines_since() exists: the drain PONG must be the ONLY line in the window, so
 *       any reply at all fails. Kept in the list because it is the fault that found
 *       the missing assertion.
 *
 *   over-long realname TRUNCATED instead of refused
 *       commands.c, handle_setname(): `conn_realname_check()` replaced with a call
 *       that always returns OK and the store replaced with copy_field(). Fails the
 *       417 case AND the "previous value survives" case, which is the one that
 *       cannot be satisfied by a node that stores 256 bytes and declines to confirm.
 *
 *   the length bound moved
 *       connection.h: CONN_MAX_REALNAME raised to 512. Fails the 255-byte boundary
 *       case and the 256-byte refusal, and it is the fault that proves the bound is
 *       tested rather than assumed.
 *
 *   the validation predicate split, so SETNAME is its own path
 *       connection.c: conn_realname_check() made to return OK always, leaving
 *       handle_user() unchanged. Fails the hostile-realname case. This one exists to
 *       show the predicate is shared rather than duplicated -- if the two writers had
 *       each grown their own check, this edit would have had nowhere to go.
 */
int main(void)
{
    case_setname();
    tf_done("setname");
    return 0;
}
