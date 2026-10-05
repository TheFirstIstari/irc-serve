/* test_registration.c -- Phase 3 headline acceptance, and the exact bytes of the
 * first burst this node has ever produced.
 *
 * docs/SERVER_DESIGN.md 7/Phase 3: "NICK/USER/PASS, numerics 001-005, MOTD,
 * PING/PONG, QUIT, 433. Accept: integration test registers and receives 001 and
 * 005." 4.4: "005 with PREFIX=(ov)@+, CHANTYPES=#&, NETWORK= is effectively
 * mandatory -- many clients misbehave without it."
 *
 * The node under test is the SHIPPED BINARY, forked and exec'd, on an ephemeral
 * port, exactly as in test_conn_lifecycle.c. Not a copy of the loop and not an
 * in-process double: registration is the first thing a real client does, and the
 * point of asserting on it is that a real client would work.
 *
 * ---------------------------------------------------------------------------
 * WHY THESE TESTS ASSERT THE BYTES AND NOT "CONTAINS 001"
 * ---------------------------------------------------------------------------
 * A numeric that is present but malformed is worse than one that is missing. A
 * client parsing ":irc.test 001 alice Welcome ..." with no trailing colon reads
 * a server name of "alice" and a parameter of "Welcome" -- it connects, and then
 * it behaves wrongly for the rest of the session in a way that has nothing to
 * do with registration. So 001, 002, 003, 004, 005 and the whole MOTD are
 * compared as exact line sequences, not as substrings.
 *
 * Two deliberate exceptions, both stated rather than hidden:
 *
 *   - 003 carries a timestamp, so the exact assertion splits around it: the
 *     text before the date and the text from " (UTC)" onwards are both exact,
 *     and the date itself is not asserted because its VALUE is not a contract.
 *     Its SHAPE is -- a fabricated "Thu Jan 1 1970" would pass a substring
 *     check, and the shape is what proves it is a real clock reading.
 *   - the version string comes from IRC_SERVE_VERSION, the same constant the
 *     node prints. Asserting a hardcoded "0.1.0" would make this test fail on
 *     every version bump, and a test that gets deleted or loosened on each
 *     release is worth less than one that keeps checking the FORMAT. The
 *     format is the contract: "irc-serve-" then a version, in 002 and 004.
 *
 * ---------------------------------------------------------------------------
 * THE HOST IS THE OBSERVED ADDRESS, NOT THE ONE USER ASSERTED
 * ---------------------------------------------------------------------------
 * USER carries a hostname, and the client is simply claiming it. This test
 * asserts that the node stores what accept() saw: the asserted hostname is
 * deliberately a different string from the loopback address, and 001 must come
 * back with the loopback one. A node that stored the assertion would have its
 * identity model controlled by the party being identified, and that is cheap to
 * get wrong now and expensive in Phase 5 when WHOIS reads c->host.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/server.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

/* Deadlines in seconds: generous for a loaded CI runner, and still failing fast
 * because every one of them waits for something that either arrives within
 * milliseconds or never arrives at all. */
#define T_READY_MS 15000
#define T_IO_MS 15000

/* The node's own name. This IS a wire contract -- it is the prefix on every
 * numeric and the <target>'s server half -- and it lives in node_main.c, so it
 * is stated here rather than imported. */
#define NODE_NAME "irc.test"

/* The loopback address the client connected from, which is what the node's
 * accept() recorded into c->host. */
#define OBSERVED_HOST "127.0.0.1"

/* A hostname the client could have put in USER's third parameter. RFC 2812
 * 3.1 names that slot <unused> -- USER has no hostname parameter at all -- but
 * older and some current clients fill it with one, which is where the idea that
 * USER carries a claimed host comes from. Different from the observed address
 * on purpose: if the two ever matched, this test could not tell "stored what
 * the client said" from "stored what the socket knows". */
#define ASSERTED_HOST "spoofed.example"

/* Register `c` as `nick`/`user` and wait for 001. */
static void register_as(test_client_t *c, int port, const char *nick,
                        const char *user)
{
    char line[512];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "tc_connect to port %d failed",
                 port);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "tc_send(NICK) failed");
    (void)snprintf(line, sizeof line, "USER %s 0 * :%s Example", user, user);
    TF_CHECK_MSG(tc_send(c, line) == 0, "tc_send(USER) failed");
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0,
                 "no 001 for nick=%s user=%s", nick, user);}

int main(void)
{
    nf_node_t node;
    test_client_t c;
    char want[4096];
    int n;

    tc_init(&c);

    TF_CHECK(nf_spawn_binary(&node) == 0);
    TF_CHECK_MSG(node.port > 0, "node reported no usable port");

    /* ---------------------------------------------------------------------
     * PASS: recorded, not authenticated.
     * ---------------------------------------------------------------------
     * Sent with a password the node has no way to check, and the registration
     * that follows must still succeed. That is the whole feature: a client
     * that sends PASS with any value is treated exactly like one that sent
     * none. The node's own line says so in as many words, and a real
     * authentication mechanism is SASL in Phase 8.
     *
     * A wrong password being accepted is asserted deliberately. A test that
     * only sent a CORRECT password would pass against a node that ignores
     * PASS entirely -- which is what this node does -- and would be testing
     * nothing.
     */
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");
    TF_CHECK_MSG(tc_send(&c, "PASS this-is-not-a-real-password") == 0,
                 "tc_send(PASS) failed");
    TF_CHECK_MSG(nf_expect(&node, "authenticated=0", T_IO_MS) == 0,
                 "the node did not report PASS as recorded-but-not-"
                 "authenticated; a PASS line that is silently ignored is not "
                 "the behaviour this phase documents");

    TF_CHECK_MSG(tc_send(&c, "NICK alice") == 0, "tc_send(NICK) failed");
    /* The third USER parameter is <unused> by the RFC; this client puts a
     * hostname there, and the node must not store it. */
    TF_CHECK_MSG(tc_send(&c, "USER alice 0 " ASSERTED_HOST
                               " :Alice Example") == 0,
                 "tc_send(USER) failed");

    /* ---------------------------------------------------------------------
     * 001, 002 and the head of 003 -- exact bytes.
     * --------------------------------------------------------------------- */
    n = snprintf(want, sizeof want,
                 ":%s 001 alice :Welcome to the irc-serve network "
                 "alice!alice@%s\r\n"
                 ":%s 002 alice :Your host is %s, running version %s\r\n"
                 ":%s 003 alice :This server was created ",
                 NODE_NAME, OBSERVED_HOST,
                 NODE_NAME, NODE_NAME, IRC_SERVE_VERSION,
                 NODE_NAME);
    TF_CHECK_MSG(n > 0 && (size_t)n < sizeof want, "expected string too large");
    TF_CHECK_MSG(tc_expect(&c, want, T_IO_MS) == 0,
                 "the first half of the welcome burst is not byte-exact. "
                 "001 must name the OBSERVED host (%s), not the one USER "
                 "asserted (%s)", OBSERVED_HOST, ASSERTED_HOST);

    /* The node records the assertion separately from the identity it stores,
     * which is what makes the choice visible rather than merely absent: the
     * claim is in the log, and the stored host is the observed address. The
     * byte-exact 001 above is the assertion that matters -- the assertion below
     * is that the claim never reached the wire. */
    TF_CHECK_MSG(nf_expect(&node, "host_source=observed", T_IO_MS) == 0,
                 "the node did not report that c->host is the observed peer "
                 "address");
    /* ------------------------------------------------------------------------
     * THE ASSERTED HOST IS MEASURED, NOT PRINTED (#121), and this is the assertion
     * that changed shape when it was.
     *
     * It used to be `nf_expect(&node, ASSERTED_HOST, ...)` -- the raw string, on
     * the ground that "the node did not even record the hostname the client
     * asserted" would make the observed/asserted difference diagnosable.
     *
     * That was true and it was a defect. `USER`'s third parameter is client
     * controlled, arrives before registration, and needs no credential, so
     * printing it put arbitrary bytes into an operator's terminal:
     * `USER alice 0 <ESC>[2J<BEL> :x` rendered the ESC and rang the bell (#121).
     * A field this node has no consumer for -- the host is OBSERVED, and nothing a
     * client asserts moves it -- is not worth an injection vector, so the value is
     * gone and what is left is the measurement.
     *
     * WHAT THIS STILL PROVES, and it is not a weaker claim:
     *
     *   - `asserted_host_len` is strlen(ASSERTED_HOST), so the node really did read
     *     the client's parameter rather than ignoring the argument. A node that
     *     dropped it entirely would report 0.
     *   - `asserted_host_wellformed=1` says `spoofed.example` is a name this node's
     *     own server-name grammar accepts. The FAILURE arm matters as much and is
     *     asserted by test_control_bytes.c, which sends a name carrying control
     *     bytes: a node that reported wellformed=1 for those would be claiming a
     *     grammar that irc_serve_server_name_valid() does not have.
     *   - The byte-exact 001 above is what proves the value never reached the WIRE,
     *     and the assertion just below proves it never reached the client's own
     *     socket. Neither of those moved, because neither of them was about the log.
     *
     * THE COST, restated because it is real: an operator can no longer read back
     * what a client claimed it was talking to. The length, the well-formedness
     * verdict and the bad-byte count survive. That is the trade #121 made on
     * purpose, and this assertion is where a future reader will notice if somebody
     * puts the string back.
     * ---------------------------------------------------------------------- */
    {
        char want_host[96];

        (void)snprintf(want_host, sizeof want_host,
                       "asserted_host_len=%zu asserted_host_wellformed=1 "
                       "asserted_host_bad_bytes=0",
                       strlen(ASSERTED_HOST));
        TF_CHECK_MSG(nf_expect(&node, want_host, T_IO_MS) == 0,
                     "the node did not report a measurement of the hostname the "
                     "client asserted (%s): expected \"%s\". The claim is measured "
                     "rather than printed since #121, so a mismatch between the "
                     "observed host and what a client said it was talking to is "
                     "diagnosable from the length and the verdict even though the "
                     "string itself is no longer in the log.",
                     ASSERTED_HOST, want_host);
    }
    TF_CHECK_MSG(strstr(tc_buffer(&c), ASSERTED_HOST) == NULL,
                 "the hostname USER asserted reached the wire. c->host is what "
                 "001 prints and what every later phase's access control will "
                 "read; a client that can set it is not being identified, it is "
                 "being believed.");

    /* ---------------------------------------------------------------------
     * The tail of 003, 004, 005 and the whole MOTD -- exact bytes.
     *
     * THE 005 NUMBERS BELOW ARE WRITTEN OUT AND NOT TAKEN FROM THE CONSTANTS
     * THEY DESCRIBE. That is the whole of the Phase 10.4 addition to this file
     * and it is deliberate in the direction that looks wrong: k_005[] derives
     * every one of them from the bound that ENFORCES it, so a value cannot drift
     * from its constant at run time -- and that is precisely why this test must
     * not derive from the constant too. A test built from IRC_MAX_TOPIC passes
     * the moment somebody raises CHAN_MAX_TOPIC, and the question Phase 10.4 has
     * to be able to answer is whether 005 was updated with it. Only a literal
     * here can fail that, so `TOPICLEN=255` and friends are literals.
     *
     * It also means raising any bound in src/ now breaks THIS line, which is the
     * intended cost: the person who raises CHAN_MAX_TOPIC has to look at 005 and
     * decide whether the new number is what clients should be told.
     * --------------------------------------------------------------------- */
    n = snprintf(want, sizeof want,
                 " (UTC)\r\n"
                 ":%s 004 alice %s %s i b,k,l,imnpst "
                 ":are supported by this server\r\n"
                 ":%s 005 alice NETWORK=irc-serve CHANTYPES=#& PREFIX=(ov)@+ "
                 "CASEMAPPING=ascii AWAYLEN=255 CHANNELLEN=63 KICKLEN=255 "
                 "LINELEN=8192 MAXTARGETS=1 NAMELEN=255 NICKLEN=63 TOPICLEN=255 "
                 ":are supported by this server\r\n"
                 ":%s 372 alice :- irc-serve: a federation-native IRC node.\r\n"
                   ":%s 372 alice :- registration, channels, messaging and peer "
                   "federation are implemented.\r\n"
                   ":%s 372 alice :- INFO lists what this node actually does; "
                   "try it.\r\n"
                 ":%s 375 alice :- Message of the day -\r\n"
                 ":%s 376 alice :End of /MOTD command.\r\n",
                 NODE_NAME, NODE_NAME, IRC_SERVE_VERSION,
                 NODE_NAME,
                 NODE_NAME, NODE_NAME, NODE_NAME, NODE_NAME, NODE_NAME);
    TF_CHECK_MSG(n > 0 && (size_t)n < sizeof want, "expected string too large");
    TF_CHECK_MSG(tc_expect(&c, want, T_IO_MS) == 0,
                 "004/005/MOTD are not byte-exact. 4.4 requires PREFIX=(ov)@+, "
                 "CHANTYPES=#& and NETWORK= in 005: many real clients misbehave "
                 "without them.");

    /* The three tokens 4.4 names are asserted individually as well, so a
     * failure says WHICH one went rather than dumping the whole burst. */
    TF_CHECK_MSG(tc_expect(&c, " PREFIX=(ov)@+ ", T_IO_MS) == 0,
                 "005 does not advertise PREFIX=(ov)@+");
    TF_CHECK_MSG(tc_expect(&c, " CHANTYPES=#& ", T_IO_MS) == 0,
                 "005 does not advertise CHANTYPES=#&");
    TF_CHECK_MSG(tc_expect(&c, " NETWORK=irc-serve ", T_IO_MS) == 0,
                 "005 does not advertise NETWORK=");

    /* ---------------------------------------------------------------------
     * EVERY DERIVED TOKEN, ONE BY ONE, so a drift names itself.
     * ---------------------------------------------------------------------
     * The byte-exact line above already fails on any change. These exist for the
     * OTHER failure: a token that keeps its value while the constant it is
     * derived from moves, which the byte-exact line catches too -- but it catches
     * it by printing the whole burst, and a failure that says "TOPICLEN=255 is
     * gone" is worth more than one that says "005 is not byte-exact". */
    {
        /* Each is <token>=<value>, spelled out with the leading and trailing SPACE
         * that bounds a middle parameter. The spaces are not decoration: without
         * them a test for "NAMELEN=" would be satisfied by a node advertising
         * `NAMELEN_MAX=255`, and `LINELEN=` would be satisfied by a
         * `CHANNELLEN=`-style neighbour that happens to share a prefix. A token
         * in a 005 is a whole space-delimited word or it is not a token. */
        static const char *const want_tokens[] = {
            " AWAYLEN=255 ",
            " CHANNELLEN=63 ",
            " KICKLEN=255 ",
            " LINELEN=8192 ",
            " MAXTARGETS=1 ",
            " NAMELEN=255 ",
            " NICKLEN=63 ",
            " TOPICLEN=255 ",
            " CASEMAPPING=ascii "
        };

        for (size_t i = 0; i < sizeof want_tokens / sizeof want_tokens[0]; i++) {
            TF_CHECK_MSG(strstr(tc_buffer(&c), want_tokens[i]) != NULL,
                         "005 does not carry \"%s\". Every one of these is derived "
                         "in k_005[] from the constant that ENFORCES the limit, so "
                         "a token that is missing here is either a number nobody "
                         "wrote out or a number that drifted from its constant.",
                         want_tokens[i]);
        }
    }

    /* ---------------------------------------------------------------------
     * AND NO OTHERS: the tokens this node does NOT advertise.
     * ---------------------------------------------------------------------
     * An ISUPPORT token is a promise, so the interesting half of "only what this
     * node honours" is the set of absences, and a list that only grows is exactly
     * how a node ends up claiming features it does not have. The reasons are at
     * k_005[] in commands.c; what is asserted here is only that the names are not
     * on the wire.
     *
     * KICKLEN WAS IN THIS LIST AND IS NOT ANY MORE, which is the point of keeping
     * the list beside the tokens. Phase 10.4 put it here because handle_kick() took
     * <reason> verbatim with no length test, so no number in this tree described the
     * largest reason this node accepts -- and because an over-long one then reached
     * message_format(), which refuses rather than reshapes, so a client COMMAND
     * could put a non-zero on n_reply_refused, the counter reply.c holds at zero
     * because a non-zero value is a bug report. Phase 10.9 added
     * CHAN_MAX_KICK_REASON, the 417 in handle_kick() and the token, and the token
     * is now asserted ABOVE against the literal 255 -- which is the whole shape of
     * the fix: a bound that exists and is enforced can be advertised, and one that
     * exists and is NOT (USERLEN, below) still cannot.
     *
     * So the absence of " KICKLEN=" is no longer asserted, and adding it back would
     * be a test that forbids the fix. What is asserted instead is the token's
     * presence with its literal, so a node that dropped the bound again fails the
     * positive assertion rather than quietly satisfying a negative one.
     *
     * BOT / EXTBAN / SAFELIST / MONITOR / WATCHNICK are the features; ACCEPT and
     * silence are the operator-model features, and this node has no operator
     * model at all (CHOPER answers 464 for everything). MSGREFTYPES needs a
     * message-reference parser, draft/CHATHISTORY needs a history store, MODES
     * needs a cap on one MODE command, and USERLEN is the one omission that has
     * a bound behind it and still cannot be advertised: USER's ident is
     * truncated rather than refused, so the number would promise a limit this
     * node does not apply. */
    {
        static const char *const absent[] = {
            " BOT=", " EXTBAN=", " SAFELIST", " MONITOR", " WATCHNICK",
            " MSGREFTYPES=", " ACCEPT", " silence", " CHATHISTORY",
            " MODES=", " USERLEN="
        };

        for (size_t i = 0; i < sizeof absent / sizeof absent[0]; i++) {
            TF_CHECK_MSG(strstr(tc_buffer(&c), absent[i]) == NULL,
                         "005 advertises \"%s\" and this node implements nothing "
                         "behind it. An advertised token a client acts on is worse "
                         "than an absent one, because absence is a client that "
                         "carries on.", absent[i]);
        }
    }

    /* Exactly one welcome burst. A second 001 for one registration would mean
     * the state machine re-fired, and a client that treats 001 as "I am
     * connected" would be pushed back into its connect path. */
    TF_CHECK_MSG(tf_count(tc_buffer(&c), " 001 ") == 1,
                 "001 arrived %zu times for one registration",
                 tf_count(tc_buffer(&c), " 001 "));

    /* MOTD on demand. Same 372-376 sequence, so a client that asks again gets
     * the same answer rather than an error or nothing. */
    {
        size_t before;

        before = tf_count(tc_buffer(&c), " 376 ");
        /* MOTD, then a PING whose reply is a UNIQUE marker. Waiting for the
         * MOTD's own text would not work: the second copy is byte-identical to
         * the first, so tc_expect would match what is already in the buffer and
         * return without the second one having arrived. The PING is the drain,
         * and the node processes the two lines in order, so by the time the PONG
         * is in hand the second MOTD is in hand too. */
        TF_CHECK_MSG(tc_send_raw(&c, "MOTD\r\nPING :after-motd\r\n",
                                 sizeof("MOTD\r\nPING :after-motd\r\n") - 1u)
                         == 0, "tc_send_raw failed");
        TF_CHECK_MSG(tc_expect(&c, ":irc.test PONG irc.test after-motd",
                               T_IO_MS) == 0,
                     "MOTD did not answer, or the PING behind it did not");
        TF_CHECK_MSG(tf_count(tc_buffer(&c), " 376 ") == before + 1,
                     "MOTD was expected to re-send 376 exactly once (%zu "
                     "before, %zu after)", before,
                     tf_count(tc_buffer(&c), " 376 "));
        TF_CHECK_MSG(tf_count(tc_buffer(&c), " 372 ") == 6,
                     "the second MOTD should have sent 3 more 372 lines, so 6 "
                     "in total; saw %zu",
                     tf_count(tc_buffer(&c), " 372 "));
    }
    tc_close(&c);

    /* ---------------------------------------------------------------------
     * USER BEFORE NICK.
     * ---------------------------------------------------------------------
     * The state enum is a projection of two facts (has a nick, has a user), so
     * the order the lines arrive in must not matter: a client that sends USER
     * first rests in CONN_REG_USER and still registers. A state that merely
     * counted progress would have nowhere to go back to, and would answer 001
     * only to the order irssi happens to use.
     * --------------------------------------------------------------------- */
    register_as(&c, node.port, "bob", "bob");
    TF_CHECK_MSG(tc_expect(&c, " 001 bob :Welcome", T_IO_MS) == 0,
                 "a client that sent USER before NICK did not get 001");
    TF_CHECK_MSG(tf_count(tc_buffer(&c), " 001 ") == 1,
                 "the second client got %zu welcome bursts, expected 1",
                 tf_count(tc_buffer(&c), " 001 "));
    tc_close(&c);

    /* ---------------------------------------------------------------------
     * PASS was recorded exactly once, and nothing was refused.
     * --------------------------------------------------------------------- */
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "pass_seen=", 1, T_IO_MS) == 0,
                 "pass_seen is not 1: the node must RECORD the PASS line even "
                 "though it does not authenticate it");
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0: the node refused to send a message "
                 "to one of its own clients, which for these flows means a "
                 "message it could not represent");
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", 2, T_IO_MS) == 0,
                 "accepted should be 2");
    TF_CHECK_MSG(nf_expect_u64(&node, "closed=", 2, T_IO_MS) == 0,
                 "closed should be 2: every connection must be closed exactly "
                 "once, by the reaper");

    nf_free(&node);
    tf_done("registration");
    return 0;
}
