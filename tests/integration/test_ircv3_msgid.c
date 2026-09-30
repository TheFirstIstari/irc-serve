/* test_ircv3_msgid.c -- the client-visible `msgid`, and the two properties that
 * make it worth having.
 *
 * Authority: docs/SERVER_DESIGN.md 7/Phase 8 ("Real tag escaping + roundtrip,
 * CAP negotiation (LS/REQ/ACK/NAK), real SASL PLAIN, message-ids") and 2.4 (the
 * (origin, epoch, id) triple this tag is rendered from).
 *
 * ---------------------------------------------------------------------------
 * WHAT "a msgid" IS HERE, AND WHY IT IS NOT A NEW COUNTER
 * ---------------------------------------------------------------------------
 * IRCv3's `draft/message-ids` asks a server to put a `msgid` tag on the messages
 * it delivers, and the tag exists for one reason: two clients on two different
 * nodes who were both sent ONE message must be able to tell it was one message.
 * Without it a client correlating two views of a conversation sees two events.
 *
 * The obvious implementation is a second monotonic counter incremented on every
 * outbound line, and it is the wrong one. Such a value means one thing to this
 * node and a DIFFERENT thing to a peer, so a relay has no way to carry it: it
 * cannot mint a value in the sender's number space, so every hop renumbers and
 * the tag's whole purpose is defeated by the first relay. This node instead
 * renders 2.4's OWN dedup key -- `(origin, epoch, id)` -- as
 * `<origin>_<epoch>_<id>`, which means:
 *
 *   - a client-visible value and a peer-internal key are the same three numbers,
 *     so a relay changes nothing and every hop shows the client the same value;
 *   - the server name is in the value, so uniqueness is a NETWORK property and
 *     this node needs no knowledge of the mesh to be unique;
 *   - there is no second counter to keep unique, and 2.4's argument against a
 *     per-CONNECTION counter (two connections on one server both emitting (a,1),
 *     and a peer silently dropping the second) applies for free.
 *
 * 2.4's `irc-serve-id` is a DIFFERENT tag and is not in this file's subject. It
 * is internal, stripped before a client sees anything, and its meaning is "this
 * node's dedup key for loop prevention". This tag's meaning is "the identity of
 * the message you were just sent". They are rendered from the same numbers on
 * purpose; they are not the same tag, and one counter serving both -- rather
 * than one counter serving neither -- is exactly what this file checks.
 *
 * ---------------------------------------------------------------------------
 * THE THREE CASES, AND WHAT EACH ONE CANNOT BE SATISFIED BY
 * ---------------------------------------------------------------------------
 *
 *   1. THE GATE. A client gets a `msgid` only when it asked for BOTH
 *      `message-tags` and `draft/message-ids`, and gets none otherwise -- not a
 *      msgid under one, not a bare tag block under the other. Each negative is
 *      beside a positive on the same node and the same message, because "no
 *      msgid" and "the test's client was not the one we think" look identical
 *      from outside otherwise.
 *
 *   2. THE SHAPE. The value on the wire is the server name, two separators and
 *      two numbers, read off a real socket. A node that invented a UUID here
 *      would still be "implementing message-ids" in the loosest sense and would
 *      fail this case, which is the point: the shape is what makes the value
 *      recoverable as a dedup key by a peer or a log reader.
 *
 *   3. THE HOP. Two nodes over real TCP, both clients negotiating, and the two
 *      client-visible values are the SAME STRING. This is the assertion the whole
 *      design turns on and it is the one with teeth: a node that minted a fresh
 *      id for the forward, or a relay that re-stamped what it received, delivers
 *      two different values to two clients and fails here while every other case
 *      still passes. See the file footer for the faults that were injected to
 *      prove it.
 *
 * ---------------------------------------------------------------------------
 * NO FIXED sleep() ANYWHERE (6.3)
 * ---------------------------------------------------------------------------
 * Every wait is tc_expect()'s deadline loop, and every negative closes its window
 * with a PING whose PONG is the drain token -- the technique test_messaging.c and
 * test_fed_relay.c use, and the reason a "no tag arrived" claim is a statement
 * about bytes rather than about when the parent last read the socket.
 */
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/cap.h"
#include "core/fanout.h"
#include "core/message.h"
#include "core/commands.h"
#include "core/server.h"
#include "federation/link.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

/* The shipped binary's own name when --name is not given; src/node_main.c's
 * NODE_NAME. Spelled out here because case 2 asserts the msgid's first field
 * against it, and a test that read the name off the node's own log would prove
 * nothing about what the client was sent. */
#define DEFAULT_NODE_NAME "irc.test"

#define NAME_A "irc.a"
#define NAME_B "irc.b"
#define CHAN   "#T"

#define SECRET "irc-serve-federation-secret-a"

/* A single word with no spaces, so counting it in a client's buffer is counting
 * DELIVERIES and not words -- the distinction test_fed_relay.c's times_seen()
 * exists for and the reason this test never asserts on a whole line's shape
 * where a token will do. */
#define TEXT  "msgidprobe"

/* ---------------------------------------------------------------------------
 * Buffer helpers
 * ------------------------------------------------------------------------ */

/* The start of the LINE containing `needle`, or NULL. Walks back to the byte
 * after the previous LF so a caller can look at the line's first byte -- which
 * is how "does this line carry a tag block" is asked. Counting '@' characters
 * would not do it: the source prefix on every one of these lines is
 * `nick!user@host`, so there is always at least one '@' on the wire. */
static const char *line_with(const char *buf, const char *needle)
{
    const char *at = strstr(buf, needle);

    if (at == NULL) {
        return NULL;
    }
    while (at > buf && at[-1] != '\n') {
        at--;
    }
    return at;
}

/* The value of the `msgid=` tag on the line beginning at `line`, into `out`.
 * Returns 0 when the line carries no msgid. Bounded by the caller's `cap` and
 * refuses rather than truncating, because a shortened id is a different id and
 * two of them can compare equal. */
static int msgid_on(const char *line, char *out, size_t cap)
{
    static const char key[] = "msgid=";
    const char *at;
    size_t n = 0;

    if (line == NULL) {
        return 0;
    }
    /* The key is looked for at a TAG position rather than anywhere: the value
     * this file checks must be the node's tag and not the letters "msgid="
     * appearing inside a channel topic somebody set. */
    if (line[0] != '@') {
        return 0;
    }
    at = line + 1;
    while (*at != '\0' && *at != ' ') {
        if (*at == ';') {
            at++;
            continue;
        }
        if (strncmp(at, key, sizeof key - 1u) == 0) {
            at += sizeof key - 1u;
            while (*at != '\0' && *at != ' ' && *at != ';' && *at != '\r') {
                if (n + 1u >= cap) {
                    out[0] = '\0';
                    return 0;
                }
                out[n++] = *at++;
            }
            out[n] = '\0';
            return (n != 0u) ? 1 : 0;
        }
        break;
    }
    return 0;
}

/* The msgid on the delivery of `needle` in `buf`, into `out`. The needle is a
 * parameter because this file sends more than one marker -- a short token for the
 * ordinary cases and an 8000-byte one for the boundary case -- and a helper that
 * hard-coded the short one would silently look for a message the boundary case's
 * client was never sent. That is not hypothetical: the first version of case 2b
 * did exactly this and reported "the largest message came back with NO msgid"
 * about a line that carried one. */
static int delivered_msgid(const char *buf, const char *needle, char *out,
                           size_t cap)
{
    const char *line = line_with(buf, needle);

    out[0] = '\0';
    if (line == NULL) {
        return 0;
    }
    return msgid_on(line, out, cap);
}

/* Drain: send a PING with a token and wait for its PONG, so the buffer holds
 * everything the node sent BEFORE the PING.
 *
 * THE TOKEN IS NOT THE NICK, and the first version of this file used the nick and
 * passed a NEGATIVE for the wrong reason: a registered client's welcome burst has
 * its nickname in every single line, so tc_expect() found the token in the 001
 * that had already been read, returned immediately, and every "no tag arrived"
 * assertion below it was a statement about the read schedule. The token here
 * contains no byte of anything else this file sends.
 *
 * It is not "PONG" either, for the reason the comment on register_caps() gives:
 * register_caps() has already drained this connection once. */
#define DRAIN_TOKEN "drainmsgidtoken"

static void drain(test_client_t *c)
{
    char line[128];

    (void)snprintf(line, sizeof line, "PING :" DRAIN_TOKEN);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING failed");
    TF_CHECK_MSG(tc_expect(c, DRAIN_TOKEN, T_IO_MS) == 0,
                 "no PONG for the drain token; the buffer is not yet drained and "
                 "every count below would be a statement about the read schedule");
}

/* ---------------------------------------------------------------------------
 * Registration
 * ------------------------------------------------------------------------ */

/* Connect, negotiate `caps` (a CAP REQ argument body, or NULL for no CAP at
 * all), and register as `nick`.
 *
 * CAP FIRST and CAP END before NICK/USER is not the order this writes -- it
 * negotiates, then names -- but the ORDER DOES NOT MATTER and the reason is
 * worth one line: cap.c's gate holds REGISTRATION, not the negotiation, so a REQ
 * after NICK/USER still takes effect and only the arrival of CAP END releases
 * the welcome burst. Sending REQ first is what a real client does and is what
 * makes this a test of the thing rather than of an ordering this test invented. */
static void register_caps(test_client_t *c, int port, const char *nick,
                          const char *caps)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    if (caps != NULL) {
        (void)snprintf(line, sizeof line, "CAP REQ :%s", caps);
        TF_CHECK_MSG(tc_send(c, line) == 0, "%s CAP REQ send failed", nick);
        /* An ACK naming the whole request, which is also the proof the node
         * KNOWS every capability named: a NAK would have been answered with a
         * NAK line and this wait would time out, so the case below cannot pass
         * against a node that only implements some of them. */
        (void)snprintf(line, sizeof line, " ACK :%s\r\n", caps);
        TF_CHECK_MSG(tc_expect(c, line, T_IO_MS) == 0,
                     "%s was not ACKed every capability in \"%s\", so the node "
                     "does not have all of them and the cases below would be "
                     "asserting a NEGATIVE for the wrong reason", nick, caps);
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

/* Join CHAN and wait for the 366 that terminates its names list. */
static void join(test_client_t *c, const char *nick)
{
    char line[128];

    (void)snprintf(line, sizeof line, "JOIN " CHAN);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s JOIN send failed", nick);
    TF_CHECK_MSG(tc_expect(c, " 366 ", T_IO_MS) == 0,
                 "%s never completed its JOIN", nick);
}

/* ---------------------------------------------------------------------------
 * CASE 1: the gate. Four clients on one node, one message each.
 * ------------------------------------------------------------------------ */

/* One client, one message, and what its own delivered copy carries.
 *
 * A client that sends a PRIVMSG to a channel it is on hears it back: RFC 1459
 * 3.3.1 has no echo-suppression for PRIVMSG (only NOTICE has it, and 3.1's
 * `exclude` argument says so), so the sender's own copy is the simplest possible
 * observable for "what does this node put on a delivered line to YOU". It also
 * means the case needs no second client and therefore cannot fail because the
 * fixture did not set a roster up. */
static void probe_and_expect(nf_node_t *node, const char *nick, const char *caps,
                             int want_tag)
{
    test_client_t c;
    char line[128];
    const char *at;

    tc_init(&c);
    register_caps(&c, node->port, nick, caps);
    join(&c, nick);

    (void)snprintf(line, sizeof line, "PRIVMSG " CHAN " :%s", TEXT);
    TF_CHECK_MSG(tc_send(&c, line) == 0, "%s PRIVMSG send failed", nick);
    drain(&c);

    at = line_with(tc_buffer(&c), TEXT);
    TF_CHECK_MSG(at != NULL,
                 "%s sent a PRIVMSG into a channel it is on and never heard its "
                 "own message back; there is nothing to assert about the tag on "
                 "a delivery that did not happen.\n  client saw: %s",
                 nick, tc_buffer(&c));
    /* THE NEGATIVE, as a shape rather than as an absence. A line with no tag
     * block starts with ':' (the source prefix) and one with a block starts with
     * '@'. Asserting "no '@' anywhere" would be wrong -- the hostmask has one. */
    TF_CHECK_MSG((at[0] == '@') != 0 || (at[0] == ':'),
                 "%s's delivered line starts with '%c', which is neither a tag "
                 "block marker nor a source prefix", nick, at[0]);
    if (want_tag == 0) {
        TF_CHECK_MSG(at[0] != '@',
                     "%s negotiated \"%s\" and its delivered PRIVMSG carries a tag "
                     "block anyway:\n  line: %s", nick,
                     (caps != NULL) ? caps : "(nothing)", at);
    } else {
        char id[IRC_MAX_MSGTAG + 1u];

        TF_CHECK_MSG(at[0] == '@',
                     "%s negotiated both capabilities and its delivered PRIVMSG "
                     "carries no tag block, so the msgid is not being written at "
                     "all.\n  line: %s", nick, at);
        TF_CHECK_MSG(delivered_msgid(tc_buffer(&c), TEXT, id, sizeof id) == 1,
                     "%s negotiated both capabilities and no msgid was found on "
                     "its delivered line.\n  client saw: %s", nick, tc_buffer(&c));
        TF_CHECK_MSG(id[0] != '\0', "%s's msgid is empty", nick);
    }
    tc_close(&c);
}

static void case_the_gate(void)
{
    nf_node_t node;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    /* ADVERTISED, because it is implemented. This is the check cap.h's rule is
     * written for: a name in `CAP LS` is a claim that the feature exists, so a
     * capability that appears here and produces no tag on the wire is a lie a
     * client acts on. */
    {
        test_client_t c;
        tc_init(&c);
        TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");
        TF_CHECK_MSG(tc_send(&c, "CAP LS") == 0, "CAP LS send failed");
        TF_CHECK_MSG(tc_expect(&c, " CAP * LS :", T_IO_MS) == 0,
                     "CAP LS was not answered");
        TF_CHECK_MSG(strstr(tc_buffer(&c), CAP_MESSAGE_IDS) != NULL,
                     "CAP LS does not advertise %s, which core/message.c renders "
                     "and core/fanout.c writes", CAP_MESSAGE_IDS);
        tc_close(&c);
    }

    /* Both capabilities: a tag block, with a msgid in it. */
    probe_and_expect(&node, "both", CAP_MESSAGE_TAGS " " CAP_MESSAGE_IDS, 1);

    /* msgids alone. A client that declined message-tags has said it will not
     * parse a tag block, and this node honours that: it is not a best-effort
     * answer, because a parser reads a block or it does not. */
    probe_and_expect(&node, "idsonly", CAP_MESSAGE_IDS, 0);

    /* message-tags alone. The client asked for tags and did not ask for
     * msgids, so it gets a tag block this node is able to write -- which is
     * nothing, because msgid is the only client tag this node produces. The
     * assertion is that there is no BLOCK, and that is a smaller claim than
     * "no msgid": a node that answered a message-tags request with an empty '@'
     * would be within the letter of this case and would break real clients. */
    probe_and_expect(&node, "tagsonly", CAP_MESSAGE_TAGS, 0);

    /* Nothing at all: the default connection, which is what every client in this
     * suite that does not negotiate anything is. Without this the three above
     * could all be passing for want of a tag block on any line. */
    probe_and_expect(&node, "plain", NULL, 0);

    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * CASE 2: the shape, read off a socket
 * ------------------------------------------------------------------------ */

/* `<origin>_<epoch>_<id>`, and the origin is THIS node's name.
 *
 * Checked from the wire rather than from a call into core/message.c, because the
 * thing being asserted is what a client is told. The epoch and the id are read
 * as "non-empty decimal" rather than against a constant: both are clock and
 * counter readings (s->epoch is server_now_ms() at init, the id is a counter),
 * so no fixed value can be written down -- the same constraint test_fed_wire.c
 * states for the same reason. What CAN be pinned is the shape and the origin,
 * and those are what make the value recoverable as a dedup key. */
static void case_the_shape(void)
{
    nf_node_t node;
    test_client_t c;
    char line[128];
    char id[IRC_MAX_MSGTAG + 1u];
    const char *p;
    int fields = 1;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");
    tc_init(&c);
    register_caps(&c, node.port, "shape", CAP_MESSAGE_TAGS " " CAP_MESSAGE_IDS);
    join(&c, "shape");

    (void)snprintf(line, sizeof line, "PRIVMSG " CHAN " :%s", TEXT);
    TF_CHECK_MSG(tc_send(&c, line) == 0, "PRIVMSG send failed");
    drain(&c);
    TF_CHECK_MSG(delivered_msgid(tc_buffer(&c), TEXT, id, sizeof id) == 1,
                 "no msgid on the delivered line.\n  client saw: %s",
                 tc_buffer(&c));

    /* The origin, verbatim: the server name this node advertises everywhere
     * else. */
    TF_CHECK_MSG(strncmp(id, DEFAULT_NODE_NAME "_",
                         strlen(DEFAULT_NODE_NAME) + 1u) == 0,
                 "the msgid is \"%s\" and does not begin with this node's server "
                 "name \"%s\" followed by a separator, so it is not 2.4's origin "
                 "field and carries nothing a peer can key on", id,
                 DEFAULT_NODE_NAME);

    /* Exactly two separators, and three non-empty fields. 2.4's origin grammar
     * excludes '_', which is what makes the split unambiguous, and a value with a
     * different number of separators is not this node's format. */
    for (p = id; *p != '\0'; p++) {
        if (*p != '_') {
            continue;
        }
        if (*(p - 1) == '_' || *(p + 1) == '_' || *(p + 1) == '\0') {
            TF_CHECK_MSG(0, "the msgid \"%s\" has an empty field or a doubled "
                         "separator", id);
        }
        fields++;
    }
    TF_CHECK_MSG(fields == 3,
                 "the msgid \"%s\" has %d fields, not 3: it is <origin>_<epoch>_<id>",
                 id, fields);

    /* Every byte is one the tag grammar allows unescaped, which is what lets the
     * value be emitted without an escape pass at all. A separator or a space here
     * would be a value that needed ircv3_tags.h's escaper. */
    for (p = id; *p != '\0'; p++) {
        const char ch = *p;
        const int alnum = (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') ||
                          (ch >= 'a' && ch <= 'z');

        TF_CHECK_MSG(alnum != 0 || ch == '_' || ch == '.',
                     "the msgid \"%s\" contains '%c', which the IRCv3 escape set "
                     "maps to something else; a value needing an escape pass is a "
                     "bug report, not a value", id, ch);
    }

    tc_close(&c);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* The client's OBSERVED hostmask, which is what msg_verbs.c charges the line
 * against. Built from the 001 line rather than written down, because
 * CONTRIBUTING.md forbids platform-specific assertions and what accept() reports
 * is not the same on every platform this suite runs on.
 *
 * `nick!user@host` off the "Welcome to the ... network " marker: 001 carries the
 * qualified name verbatim, so this reads the node's own rendering instead of
 * recomputing it from fields the test is not allowed to inspect. */
static int conn_hostmask_probe(const test_client_t *c, char *out, size_t cap)
{
    static const char mark[] = "Welcome to the irc-serve network ";
    const char *at = strstr(tc_buffer(c), mark);
    const char *end;
    size_t n;

    if (at == NULL) {
        return 0;
    }
    at += sizeof mark - 1u;
    end = strchr(at, '\r');
    if (end == NULL) {
        return 0;
    }
    n = (size_t)(end - at);
    if (n == 0u || n + 1u > cap) {
        return 0;
    }
    memcpy(out, at, n);
    out[n] = '\0';
    return 1;
}

/* Would the node deliver a PRIVMSG to CHAN with a body of `len` bytes to a client
 * whose prefix is `hostmask`? The node's own predicate, asked with the node's own
 * arguments -- so the boundary this case probes is the boundary the node enforces
 * rather than one this file re-derived and might get wrong. */
static int probe_body_fits(const char *hostmask, size_t len)
{
    char *body = (char *)malloc(len + 1u);
    int fits;

    if (body == NULL) {
        return 0;
    }
    memset(body, 'x', len);
    body[len] = '\0';
    fits = fanout_line_fits(hostmask, "PRIVMSG", CHAN, body);
    free(body);
    return fits;
}

/* ---------------------------------------------------------------------------
 * CASE 2b: the largest message this node will deliver STILL carries its msgid
 * ------------------------------------------------------------------------ */

/* A tag on a maximal line is a claim, and reply.c states the arithmetic that says
 * the claim is safe; this case is what checks it.
 *
 * The worry is real in shape: a `msgid` block costs bytes, a client's own message
 * is already capped at IRC_MAX_RELAY_LINE by msg_verbs.c, and a line that cannot
 * carry the tag it promised to carry is a lost message. So this sends the LARGEST
 * body the node's own rule accepts -- found with fanout_line_fits(), the function
 * that rule is, rather than a re-derivation of it -- and requires the msgid to be
 * there, on the wire, on that message.
 *
 * THAT IS ALSO WHY reply.c carries no "drop the tag, keep the message" retry: the
 * window does not exist, and code defending against a window that does not exist
 * is a claim this project does not make. If the headroom ever disappears this case
 * goes red and the arithmetic in reply.c is where the fix belongs.
 */
#define BIGTOKEN "bigprobemarker"

static void case_the_largest_line_still_carries_it(void)
{
    nf_node_t node;
    test_client_t c;
    char *body;
    char line[IRC_MAX_LINE + 16];
    char id[IRC_MAX_MSGTAG + 1u];
    size_t lo = 0;
    size_t hi = (size_t)IRC_MAX_LINE;
    size_t best;
    const char *at;
    char hostmask[CONN_HOSTMASK_MAX];

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");
    tc_init(&c);
    register_caps(&c, node.port, "bigbody", CAP_MESSAGE_TAGS " " CAP_MESSAGE_IDS);
    join(&c, "bigbody");
    TF_CHECK_MSG(conn_hostmask_probe(&c, hostmask, sizeof hostmask) == 1,
                 "could not build the client hostmask this case needs to ask "
                 "fanout_line_fits() the question the node asks");

    /* The boundary, found with the node's own predicate: the largest body it will
     * relay. Binary search because "the largest body the rule accepts" and "the
     * smallest it refuses" are the two cases worth having and guessing either puts
     * the probe a whole cap away from the thing being tested. */
    while (lo < hi) {
        size_t mid = lo + (hi - lo + 1u) / 2u;

        if (probe_body_fits(hostmask, mid) != 0) {
            lo = mid;
        } else {
            hi = mid - 1u;
        }
    }
    best = lo;
    TF_CHECK_MSG(best > 0u,
                 "fanout_line_fits() refuses every body length including an empty "
                 "one, so the cap this case is about does not exist");
    TF_CHECK_MSG(probe_body_fits(hostmask, best) != 0,
                 "the largest body the search found is itself refused by "
                 "fanout_line_fits()");

    body = (char *)malloc(best + 1u);
    TF_CHECK_MSG(body != NULL, "could not allocate the probe body");
    memcpy(body, BIGTOKEN, strlen(BIGTOKEN));
    memset(body + strlen(BIGTOKEN), 'x', best - strlen(BIGTOKEN));
    body[best] = '\0';

    (void)snprintf(line, sizeof line, "PRIVMSG " CHAN " :%s", body);
    TF_CHECK_MSG(tc_send(&c, line) == 0, "the long PRIVMSG could not be sent");
    /* It arrived, and it arrived WITH the tag: a maximal line whose tag did not
     * fit is the failure this case exists for, and a 417 or a missing delivery
     * would both be caught by this one wait. */
    TF_CHECK_MSG(tc_expect(&c, BIGTOKEN, T_IO_MS) == 0,
                 "the largest body this node will relay was not delivered to the "
                 "client.\n  client saw: %s", tc_buffer(&c));
    drain(&c);
    TF_CHECK_MSG(delivered_msgid(tc_buffer(&c), BIGTOKEN, id, sizeof id) == 1,
                 "the largest message this node will deliver came back with NO "
                 "msgid, so a client near the cap loses the identity the capability "
                 "promised it. Either the tag is dropped silently or the line was "
                 "refused; the former is the worse answer and this case exists to "
                 "say so.\n  client saw: %s", tc_buffer(&c));
    TF_CHECK_MSG(tf_count(tc_buffer(&c), BIGTOKEN) == 1u,
                 "the long message arrived %lu times",
                 (unsigned long)tf_count(tc_buffer(&c), BIGTOKEN));

    /* The boundary is the node's, on both sides, so the probe above really was
     * the largest message this node will relay rather than a large one it happens
     * to tolerate. */
    TF_CHECK_MSG(probe_body_fits(hostmask, best + 1u) == 0,
                 "fanout_line_fits() accepts one byte more than the body this case "
                 "sent, so the probe was not at the boundary and nothing above "
                 "proved anything about a maximal line");

    /* And the invariant reply.c documents, as a statement about BYTES: the line
     * as delivered has room for a WORST-CASE tag block and still be legal. This
     * is the load-bearing number in that comment -- 3.2's cap leaves 179 bytes
     * and the largest tag is 111 -- and asserting it here is what makes the
     * comment a claim rather than an assertion about a hypothetical.
     *
     * The +1 is the NUL message_format() reserves, which is why the comparison is
     * against IRC_MAX_LINE and not against IRC_MAX_LINE + 1. */
    at = line_with(tc_buffer(&c), BIGTOKEN);
    TF_CHECK_MSG(at != NULL, "no line carries the long message");
    TF_CHECK_MSG(at[0] == '@',
                 "the long delivered line does not carry a tag block at all:\n"
                 "  line: %.80s", at);
    {
        const char *eol = strstr(at, "\r\n");
        size_t rendered;

        TF_CHECK_MSG(eol != NULL, "the long delivered line is not CRLF-terminated");
        rendered = (size_t)(eol - at) + 2u;
        TF_CHECK_MSG(rendered + (size_t)IRC_MAX_MSGTAG + 1u <= (size_t)IRC_MAX_LINE,
                     "the largest message this node will relay renders to %zu bytes "
                     "with its tag, and a worst-case tag block is %u more: there is "
                     "not room for both. That is the case reply.c's comment says "
                     "cannot happen, and this is where it is checked.",
                     rendered, (unsigned)IRC_MAX_MSGTAG);
        TF_CHECK_MSG(rendered <= (size_t)IRC_MAX_LINE,
                     "the delivered line is %zu bytes, over IRC_MAX_LINE (%d)",
                     rendered, IRC_MAX_LINE);
    }

    free(body);
    tc_close(&c);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * CASE 3: the hop. Two nodes over real TCP.
 * ------------------------------------------------------------------------ */

/* Pre-fork state, exactly as test_fed_relay.c sets it up and for the same
 * reason: a child inherits the parent's memory as of fork(), so the port B
 * reported is published in a file-static and the child spawned NEXT reads it.
 * A port of zero means "configure no peer at all", which is how B is set up: B is
 * spawned first and accepts, because a node configured with BOTH ends of a pair
 * both dials, neither accepts, and the pair ends up with no link at all
 * (federation/link.h names that limitation and Phase 9 owns it). */
static const char *g_peer_name;
static int g_peer_port;

static void child_tick(server_t *s, uint64_t now_ms)
{
    fed_tick(s, now_ms);
}

static void child_setup(server_t *s)
{
    struct sockaddr_in sa;

    /* The client command surface installed BEFORE fed_open(), which is the whole
     * of the ordering hazard node_fixture.h names: fed_open() saves whatever
     * dispatch is there and replaces it, so a commands_dispatch installed after
     * it would become the node's whole dispatch and a peer line would never reach
     * the guard chain. */
    TF_CHECK_MSG(commands_dispatch != NULL,
                 "the client command surface is missing from the build");
    s->dispatch = commands_dispatch;
    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child; a node with an unopenable "
                 "federation module cannot reach any assertion in this test");
    s->on_tick = child_tick;
    /* Raised from the shipped 1000/2000 for the reason test_fed_relay.c gives:
     * on a loaded runner a poll tick slips far enough that a FEDERATE exchange
     * which completes in two ticks on an idle box misses its budget, and the
     * failure then reads as "federation is broken" rather than "the fixture was
     * too impatient". These bound the FAILURE case only. */
    fed_set_timeouts(5000, 5000, 30000, 90000);

    if (g_peer_port <= 0) {
        return;
    }
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)g_peer_port);
    TF_CHECK_MSG(fed_link_configure(s, g_peer_name, (const struct sockaddr *)&sa,
                                    (socklen_t)sizeof sa) != NULL,
                 "the child could not configure peer %s on port %d", g_peer_name,
                 g_peer_port);
}

static void case_survives_a_relay_hop(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t alice;
    test_client_t bob;
    const char *caps = CAP_MESSAGE_TAGS " " CAP_MESSAGE_IDS;
    char a_id[IRC_MAX_MSGTAG + 1u];
    char b_id[IRC_MAX_MSGTAG + 1u];
    char line[128];

    g_peer_name = NAME_A;
    g_peer_port = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node B");
    TF_CHECK_MSG(b.port > 0, "node B reported no port");
    g_peer_name = NAME_B;
    g_peer_port = b.port;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, NAME_A, child_setup) == 0,
                 "could not spawn node A");

    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_A, T_IO_MS) == 0,
                 "node B never established its link to node A");

    tc_init(&alice);
    tc_init(&bob);
    register_caps(&alice, a.port, "alice", caps);
    register_caps(&bob, b.port, "bob", caps);

    /* bob JOINs first, so A's SJOIN has somewhere to go and both nodes know the
     * channel; then alice JOINs on A, which is what makes A the OWNER. The
     * message below therefore travels A -> B exactly once, which is the hop the
     * case is about. */
    join(&bob, "bob");
    join(&alice, "alice");
    TF_CHECK_MSG(nf_expect(&a, "fed_sjoin: channel=" CHAN " member=bob", T_IO_MS) == 0,
                 "node A never learned about bob, so the message below would have "
                 "one member and no relay to compare against: %s", a.out);

    (void)snprintf(line, sizeof line, "PRIVMSG " CHAN " :%s", TEXT);
    TF_CHECK_MSG(tc_send(&alice, line) == 0, "alice's PRIVMSG send failed");

    /* WAIT FOR THE MESSAGE ON BOTH SIDES BEFORE DRAINING EITHER, and the order
     * is the whole of a race this file's first version lost. The drain is a PING
     * answered locally on whichever node received it, so on bob's connection the
     * PONG came back long before the SPRIVMSG crossed the link -- the buffer was
     * "drained" and then the message arrived behind it, and the case then read
     * as "the relay did not write a msgid" when it had not yet been written at
     * all. Waiting for the text FIRST makes the drain mean what it says: the
     * PONG is ordered behind the delivery on the same connection, so once it is
     * in the buffer the delivery is too. */
    TF_CHECK_MSG(tc_expect(&alice, TEXT, T_IO_MS) == 0,
                 "alice never heard her own PRIVMSG back on the originating node");
    TF_CHECK_MSG(tc_expect(&bob, TEXT, T_IO_MS) == 0,
                 "the message never reached bob on the far node, so there is no "
                 "relayed copy to compare.\n  node said: %s", b.out);
    drain(&bob);
    drain(&alice);

    TF_CHECK_MSG(delivered_msgid(tc_buffer(&bob), TEXT, b_id, sizeof b_id) == 1,
                 "bob, on the far node, received the message with no msgid on it.\n"
                 "  client saw: %s", tc_buffer(&bob));
    TF_CHECK_MSG(delivered_msgid(tc_buffer(&alice), TEXT, a_id, sizeof a_id) == 1,
                 "alice, on the originating node, received her own message with no "
                 "msgid on it.\n  client saw: %s", tc_buffer(&alice));

    /* THE ASSERTION. Equal strings, from two processes, over a real link.
     *
     * This is the case that has teeth. Two faults fail it and nothing else in
     * this file: a relay that re-mints what it received (the loop, and the reason
     * 2.4's identity exists) and an originator that mints SEPARATELY for the
     * local write and the forward (the same failure one hop later). Both produce
     * two different msgids for one message, which is precisely the state
     * `draft/message-ids` is defined to make impossible. */
    TF_CHECK_MSG(strcmp(a_id, b_id) == 0,
                 "the two clients were sent DIFFERENT msgids for one message.\n"
                 "  alice on " NAME_A " (the originator): %s\n"
                 "  bob   on " NAME_B " (the relay):       %s\n"
                 "A msgid has to survive the hop unchanged: a relay that re-mints "
                 "it, or an originator that stamps its local copy from a different "
                 "id than the one it forwarded, tells two clients two stories "
                 "about one message.", a_id, b_id);

    /* And the value is the ORIGINATOR's origin, not the relay's. Equal strings
     * would also be satisfied by a node that stamped every line with its own
     * name and the same numbers, so the first field is checked as well -- and it
     * is what makes the tag useful to a peer: it names the server whose dedup
     * key this is. */
    TF_CHECK_MSG(strncmp(b_id, NAME_A "_", strlen(NAME_A) + 1u) == 0,
                 "bob's msgid is \"%s\" and does not name the ORIGINATING server "
                 "(%s); a relay that stamped the message as its own would pass the "
                 "equality check above whenever both sides were wrong in the same "
                 "way", b_id, NAME_A);

    /* Exactly once each. A msgid that arrived twice would be two messages by the
     * definition this tag carries, and 2.4's dedup store is what should have
     * prevented it -- so the count is the assertion that the identity and the
     * loop guard are still the same fact. */
    TF_CHECK_MSG(tf_count(tc_buffer(&bob), TEXT) == 1u,
                 "bob received the message %lu times",
                 (unsigned long)tf_count(tc_buffer(&bob), TEXT));
    TF_CHECK_MSG(tf_count(tc_buffer(&alice), TEXT) == 1u,
                 "alice received the message %lu times",
                 (unsigned long)tf_count(tc_buffer(&alice), TEXT));

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    tc_close(&alice);
    tc_close(&bob);
    nf_free(&a);
    nf_free(&b);
}

/* ---------------------------------------------------------------------------
 * CASE 4: the renderer, at its bound, with no server involved
 * ------------------------------------------------------------------------ */

/* The bound the callers size their buffers from, checked against a stamp at the
 * bound. This is a string, not a struct field: irc_serve_msgid_tag() returns what
 * would go on the wire, which is the same kind of assertion tests/integration/
 * test_fed_tags.c makes about the 2.4 block.
 *
 * It is here rather than folded into case 2 because case 2 cannot reach it: no
 * client can make this node hold a 63-byte server name, and the derivation of
 * IRC_MAX_MSGTAG is only checkable by handing the renderer the largest stamp the
 * grammar admits. The cross-check on the OTHER side of the constant -- that the
 * worst case does NOT fit a buffer one byte smaller -- is what makes it a bound
 * rather than a lower bound. */
static void case_the_bound(void)
{
    irc_serve_tags_t t;
    char block[IRC_MAX_MSGTAG + 1u];
    char one_short[IRC_MAX_MSGTAG];
    size_t n;

    memset(&t, 0, sizeof t);
    memset(t.origin, 'a', sizeof t.origin - 1u); /* 63 bytes, 2.4's maximum */
    t.epoch = UINT64_MAX;                          /* 20 digits */
    t.id = UINT64_MAX;                             /* 20 digits */
    t.hops = 0u;

    TF_CHECK_MSG(irc_serve_tags_valid(&t) == 1,
                 "a stamp at the documented value bounds is not legal, so the "
                 "msgid derivation describes a stamp this node cannot put on the "
                 "wire");
    TF_CHECK_MSG(strlen(t.origin) == 63u,
                 "the test's origin is %zu bytes, not the 63 the derivation "
                 "assumes", strlen(t.origin));

    n = irc_serve_msgid_tag(&t, block, sizeof block);
    TF_CHECK_MSG(n != 0u,
                 "irc_serve_msgid_tag() refused a stamp it had just been told was "
                 "valid, at the bound its own constant is derived from");
    TF_CHECK_MSG(n == (size_t)IRC_MAX_MSGTAG,
                 "the largest legal msgid tag measured %zu bytes, expected %u: the "
                 "derivation in message.h no longer describes what this renderer "
                 "emits", n, (unsigned)IRC_MAX_MSGTAG);
    /* The value is the whole of the tag bar the six bytes of `msgid=`, which is
     * what makes the constant checkable at all -- a length cannot tell the key
     * from the value. */
    TF_CHECK_MSG(strncmp(block, "msgid=", 6u) == 0,
                 "the rendered tag does not begin with the key \"msgid=\"");
    TF_CHECK_MSG(strstr(block, "msgid=aaa") == block,
                 "the rendered tag's value does not begin with the origin");
    TF_CHECK_MSG(strcmp(block, "msgid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                               "aaaaaaaaaaaaaaa_18446744073709551615"
                               "_18446744073709551615") == 0,
                 "the largest legal msgid tag is not the derived literal.\n"
                 "  actual: %s", block);

    /* One byte smaller is REFUSED, so the constant is the bound and not a
     * lower bound. A constant that only had to be big enough would be satisfied
     * by any value in a wide range; one that also has to be no bigger catches a
     * derivation that stopped accounting for something. */
    TF_CHECK_MSG(irc_serve_msgid_tag(&t, one_short, sizeof one_short) == 0u,
                 "the largest legal msgid tag fitted a buffer one byte smaller "
                 "than IRC_MAX_MSGTAG, so that constant has slack in it and the "
                 "arithmetic in message.h is wrong");

    /* And an illegal stamp produces no tag rather than a partial one: the value
     * is a client-visible identity, and an identity derived from a stamp the 2.4
     * grammar refuses is one a peer cannot re-key. id == 0 is the reserved
     * "unset" value, so this is the cheapest way in. */
    t.id = 0u;
    TF_CHECK_MSG(irc_serve_msgid_tag(&t, block, sizeof block) == 0u,
                 "a stamp with the reserved id 0 rendered a client-visible msgid");
    TF_CHECK_MSG(irc_serve_msgid_tag(NULL, block, sizeof block) == 0u,
                 "a NULL stamp rendered a client-visible msgid");
}

/* ---------------------------------------------------------------------------
 * TEETH, AND WHERE THEY WERE INJECTED
 * ---------------------------------------------------------------------------
 * Every case above was watched go red with the behaviour broken, and the build
 * was checked before each run was believed -- an uncompilable fault leaves the
 * previous binary in place and reports a pass, which has happened in this repo
 * seven times.
 *
 *   the relay re-mints the msgid
 *       core/fanout.c, fanout_stamp()'s RELAYING arm: origin/epoch/id replaced
 *       with this node's name, its epoch and a fresh server_next_msg_id(). Fails
 *       case 3's string equality, and nothing else in the file.
 *
 *   the originator mints twice
 *       core/fanout.c, fanout_deliver(): the two fanout_forward_channel() calls
 *       handed `carry` (NULL for a client emission) instead of `&ident`, so the
 *       forward took its own id. Fails case 3's string equality too -- it is the
 *       same observable defect one hop later, and it is why the equality is
 *       asserted between two CLIENTS rather than between one client and a log
 *       line.
 *
 *   the tag is written to a client that declined it
 *       core/cap.c, cap_message_ids_enabled(): the message-tags half of the gate
 *       dropped. Fails case 1's `idsonly` negative and no other case, which is
 *       what makes the negative worth having.
 *
 *   the advertised capability is not the implemented one
 *       core/cap.c, k_caps[]: CAP_MESSAGE_IDS removed while the renderer stayed.
 *       Fails case 1's CAP LS assertion, so "advertised" and "implemented" are
 *       asserted together rather than one being taken on trust from the other.
 *
 *   the shape drifts
 *       core/message.c, MSGID_SEP changed from '_' to '-'. Fails case 2 and case
 *       4's literal, and case 3 still passes -- which is the correct division of
 *       labour: the hop test says the value is INVARIANT and the shape test says
 *       what it is.
 */

int main(void)
{
    case_the_gate();
    case_the_shape();
    case_the_largest_line_still_carries_it();
    case_the_bound();
    case_survives_a_relay_hop();
    tf_done("ircv3_msgid");
    return 0;
}
