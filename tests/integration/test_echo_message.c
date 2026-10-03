/* test_echo_message.c -- IRCv3's `echo-message`, on the wire, counted.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE IS MOSTLY ABOUT A NUMBER THAT DOES NOT CHANGE
 * ---------------------------------------------------------------------------
 * `echo-message` says a server MUST send `PRIVMSG` and `NOTICE` back to the client
 * that sent them. The obvious way to implement that is to send the message through
 * the normal path and then send an ACKNOWLEDGEMENT to the sender -- and that is the
 * bug this capability invites, because on this node the sender is **already in the
 * audience**. `fanout.c`'s `write_to_members()` writes to every live local member
 * INCLUDING the author, so a channel `PRIVMSG` has been echoed to its sender since
 * Phase 5. An implementation that adds an acknowledgement on top delivers every
 * message twice to every client that negotiated this.
 *
 * So the implementation here is ONE ARGUMENT -- whether the sender stays in the
 * audience of the delivery that is happening anyway -- and the test's job is to make
 * sure it stays one. Every assertion below is a COUNT over a marked region of the
 * wire, not a substring search: `" 417 "` being absent proves nothing about how many
 * copies of a message arrived.
 *
 * ---------------------------------------------------------------------------
 * THE FOUR COUNTS THAT MATTER
 * ---------------------------------------------------------------------------
 *   1. A negotiating sender's PRIVMSG to a channel: exactly ONE copy. This is the
 *      double-delivery defect, and it is the one this file exists for.
 *   2. A NON-negotiating sender's PRIVMSG to a channel: exactly ONE copy -- the same
 *      one -- because the normal path is unchanged for clients that did not ask.
 *      A node that made the capability change how a non-negotiating client is served
 *      is as wrong as one that double-delivers.
 *   3. A negotiating sender's NOTICE: exactly ONE copy, which the capability is
 *      responsible for and RFC 1459 2.4.2 is responsible for removing.
 *   4. A non-negotiating sender's NOTICE: ZERO. 2.4.2 says a NOTICE is never
 *      returned to the client that sent it, and that must stay true for a client
 *      that did not negotiate anything.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS *NOT* ASSERTED, AND WHY
 * ---------------------------------------------------------------------------
 * `TAGMSG` (the same rules apply when `message-tags` is on) and `batch` echoes are
 * out of scope for this node and out of scope for this file. `nick@server` targets
 * are out of scope too, and for a reason worth stating: 3.1's last row is
 * forward-only, so the target has no local destination and there is nobody on this
 * node to acknowledge to.
 *
 * NO FIXED sleep() ANYWHERE (6.3): every wait is tc_expect()'s deadline loop and
 * every window is closed by a PING whose PONG is the drain token -- numbered per
 * call, because tc_expect() searches the ACCUMULATED buffer and a reused token would
 * be satisfied by an earlier PONG with no read at all.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/cap.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define CHAN "#T"

/* The message text, unique to this file so a count over a region cannot pick up a
 * PRIVMSG from another case or from the node's own chatter.
 *
 * IT CONTAINS A SPACE, and that is load-bearing for the needles below. 3.2 colons a
 * trailing parameter only when the value needs it, so a single-word message arrives
 * as `PRIVMSG #T echo-probe` and a two-word one as `PRIVMSG #T :echo-probe here`.
 * Both are correct; only one of them is what these needles say, and rather than
 * encode "maybe a colon" they pick a text whose rendering is unambiguous. (test_
 * setname.c asserts BOTH shapes, because there the two confirmations in one case
 * differ and the difference is the point.) */
#define TEXT "echo-probe here"

static unsigned g_drain_seq;

static void drain(test_client_t *c)
{
    char token[64];
    char line[128];

    (void)snprintf(token, sizeof token, "eco%u", g_drain_seq++);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING failed");
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG for drain token %s, so the buffer is not yet drained and "
                 "every count below would be about the read schedule", token);
}

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
                     "capability and the counts below would be asserting a negative "
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
    TF_CHECK_MSG(tc_send(c, "JOIN " CHAN) == 0, "%s JOIN failed", nick);
    TF_CHECK_MSG(tc_expect(c, " 366 ", T_IO_MS) == 0,
                 "%s never completed its JOIN, so it is not in the audience these "
                 "cases are about", nick);
    drain(c);
}

/* How many times `needle` appears in the region of `c` from `mark` to now.
 *
 * `tc_buffer(c)` IS READ AT EVERY USE and not cached into a local pointer:
 * tc_buffer() returns c->buf, which the client's own reader REALLOCs as the
 * connection fills, so a cached pointer is a pointer into freed memory. The LENGTH
 * is the stable thing across a realloc -- it is an offset, not an address. */
static size_t copies_since(const test_client_t *c, size_t mark,
                           const char *needle)
{
    const char *hay = tc_buffer(c) + mark;
    size_t n = 0;
    size_t nlen = strlen(needle);

    if (nlen == 0u) {
        return 0u;
    }
    while (*hay != '\0') {
        if (strncmp(hay, needle, nlen) == 0) {
            n++;
            hay += nlen;
            continue;
        }
        hay++;
    }
    return n;
}

/* The needle for a delivered line: the verb and the unique text, WITHOUT a leading
 * boundary character.
 *
 * No leading space, and that is deliberate rather than lazy: a `PRIVMSG` the sender
 * receives as a member is prefixed `:<sender!user@host> PRIVMSG ` while a copy sent
 * as a separate acknowledgement would be `:irc.test PRIVMSG ` or a bare `PRIVMSG`.
 * Anchoring on a boundary would make the count sensitive to which of the two a node
 * chose, and the thing being counted is HOW MANY, not what the prefix says. The
 * companion assertion below pins the shape of the ONE copy that must be there. */
static void send_and_count(test_client_t *c, const char *who, const char *line,
                           const char *needle, size_t want, const char *why)
{
    const size_t mark = tc_received(c);
    size_t got;

    TF_CHECK_MSG(tc_send(c, line) == 0, "%s: the send failed", who);
    drain(c);
    got = copies_since(c, mark, needle);
    TF_CHECK_MSG(got == want, "%s: %zu copies of \"%s\" arrived, expected %zu. %s\n"
                              "  client saw: %s", who, got, needle, want, why,
                 tc_buffer(c) + mark);
}

/* The one case. Four senders' worth of behaviour on ONE channel, so the counts
 * cannot be explained by the channel being quiet. */
static void case_echo_message(void)
{
    nf_node_t node;
    test_client_t yes;   /* negotiated echo-message */
    test_client_t no;    /* no CAP exchange at all */
    char line[256];
    char needle[64];

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    /* ---- ADVERTISED, because it is implemented ---- */
    {
        test_client_t c;

        tc_init(&c);
        TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");
        TF_CHECK_MSG(tc_send(&c, "CAP LS") == 0, "CAP LS send failed");
        TF_CHECK_MSG(tc_expect(&c, " CAP * LS :", T_IO_MS) == 0,
                     "CAP LS was not answered");
        TF_CHECK_MSG(strstr(tc_buffer(&c), CAP_ECHO_MESSAGE) != NULL,
                     "CAP LS does not advertise %s, which this node now implements",
                     CAP_ECHO_MESSAGE);
        tc_close(&c);
    }

    tc_init(&yes);
    tc_init(&no);
    register_caps(&yes, node.port, "yes", CAP_ECHO_MESSAGE);
    register_caps(&no, node.port, "no", NULL);

    /* ---- 1. A NEGOTIATING SENDER'S PRIVMSG: EXACTLY ONE COPY ----
     * THE CLASSIC BUG. A node that sends the message through the normal path and
     * then acknowledges it delivers this twice, and the count is the only assertion
     * that can see it: both copies are byte-identical apart from the prefix, so a
     * substring search for either shape finds one of them and reports success. */
    (void)snprintf(line, sizeof line, "PRIVMSG " CHAN " :%s", TEXT);
    (void)snprintf(needle, sizeof needle, "PRIVMSG " CHAN " :%s", TEXT);
    send_and_count(&yes, "yes(PRIVMSG)", line, needle, 1u,
                   "The sender is ALREADY in the audience -- fanout writes to every "
                   "local member including the author -- so the copy echo-message "
                   "asks for is this one. A second emission would deliver every "
                   "message twice to every client that negotiated the capability.");

    /* ---- AND THE COPY THAT IS THERE IS THE RIGHT ONE ----
     * "Exactly one" is satisfied by one copy of the wrong thing, so the shape is
     * pinned: the sender's own hostmask as the source prefix, which is the
     * specification's example verbatim. The host is the OBSERVED one -- USER sent
     * `*spoofed` -- because §2.1 says c->host is what accept() saw. */
    {
        char want[256];

        (void)snprintf(want, sizeof want,
                       ":yes!yes@127.0.0.1 PRIVMSG " CHAN " :" TEXT "\r\n");
        TF_CHECK_MSG(strstr(tc_buffer(&yes), want) != NULL,
                     "the single copy of the sender's own PRIVMSG did not carry the "
                     "sender's hostmask as its source prefix.\n  client saw: %s",
                     tc_buffer(&yes));
    }

    /* ---- 2. A NON-NEGOTIATING SENDER'S PRIVMSG: EXACTLY ONE COPY, THE SAME ONE
     * The negative, and it is not a formality: the sender of a channel PRIVMSG was
     * echoed to before this capability existed and must still be, because the whole
     * point of the shape `fanout_form_for()` gives a destination is that a client
     * that did not ask is served exactly as it was. A node that made negotiating
     * change how a non-negotiating client is served is as wrong as one that
     * double-delivers. */
    {
        char other[256];
        char want[256];

        (void)snprintf(line, sizeof line, "PRIVMSG " CHAN " :%s-unnegotiated", TEXT);
        (void)snprintf(other, sizeof other, "PRIVMSG " CHAN " :%s-unnegotiated",
                       TEXT);
        send_and_count(&no, "no(PRIVMSG)", line, other, 1u,
                       "A client that did NOT negotiate the capability is served "
                       "exactly as it was before it existed. One copy, not zero: the "
                       "normal path has echoed a channel PRIVMSG to its sender since "
                       "Phase 5, and this capability did not create that.");
        (void)snprintf(want, sizeof want,
                       ":no!no@127.0.0.1 PRIVMSG " CHAN " :%s-unnegotiated\r\n", TEXT);
        TF_CHECK_MSG(strstr(tc_buffer(&no), want) != NULL,
                     "the non-negotiating sender's single copy is not the normal "
                     "delivery.\n  client saw: %s", tc_buffer(&no));
    }

    /* ---- 3. A NEGOTIATING SENDER'S NOTICE: EXACTLY ONE COPY ----
     * This is the part the capability is actually responsible for. RFC 1459 2.4.2
     * says a NOTICE is never returned to the client that sent it, so the normal path
     * excludes the sender -- and `echo-message`, for a client that asked, puts it
     * back. Exactly one, because it is the same delivery and not an extra one. */
    (void)snprintf(line, sizeof line, "NOTICE " CHAN " :%s-notice", TEXT);
    (void)snprintf(needle, sizeof needle, "NOTICE " CHAN " :%s-notice", TEXT);
    send_and_count(&yes, "yes(NOTICE)", line, needle, 1u,
                   "The sender of a NOTICE is excluded by 2.4.2 and put back by this "
                   "capability -- so the copy is the normal delivery with the sender "
                   "no longer excluded, not a second emission on top of it.");
    {
        char want[256];

        (void)snprintf(want, sizeof want,
                       ":yes!yes@127.0.0.1 NOTICE " CHAN " :%s-notice\r\n", TEXT);
        TF_CHECK_MSG(strstr(tc_buffer(&yes), want) != NULL,
                     "the echoing NOTICE did not carry the sender's hostmask as its "
                     "source prefix, which is the specification's shape.\n  client "
                     "saw: %s", tc_buffer(&yes));
    }

    /* ---- 4. A NON-NEGOTIATING SENDER'S NOTICE: ZERO ----
     * The negative that keeps case 3 honest. "One copy" in case 3 would also be
     * satisfied by a node that echoes every sender's NOTICE unconditionally, and the
     * difference is a client that never asked being sent back its own NOTICE -- which
     * is the exact thing 2.4.2 exists to prevent and the reason a bot's notice loop
     * cannot start. */
    (void)snprintf(line, sizeof line, "NOTICE " CHAN " :%s-silent", TEXT);
    (void)snprintf(needle, sizeof needle, "NOTICE " CHAN " :%s-silent", TEXT);
    send_and_count(&no, "no(NOTICE)", line, needle, 0u,
                   "RFC 1459 2.4.2: a NOTICE is never returned to the client that "
                   "sent it. This must stay true for a client that negotiated "
                   "nothing, or an unconditional echo would turn any bot that answers "
                   "NOTICEs into a loop.");

    /* ---- 5. A THIRD PARTY SEES ONE COPY EITHER WAY ----
     * The other member of the channel, who negotiated nothing, receives both of
     * `yes`'s messages exactly once. This is the control for cases 1 and 3: an
     * implementation that satisfied those by sending extra copies to the SENDER
     * would leave this count at one, so it is the count that catches a
     * whole-audience double-delivery rather than a sender-only one. */
    {
        size_t priv = copies_since(&no, 0u, "PRIVMSG " CHAN " :" TEXT "\r\n");
        size_t notice = copies_since(&no, 0u, "NOTICE " CHAN " :" TEXT "-notice\r\n");

        TF_CHECK_MSG(priv == 1u,
                     "the non-negotiating third party received %zu copies of a "
                     "PRIVMSG one client sent; every recipient gets one, whatever "
                     "the SENDER negotiated.", priv);
        TF_CHECK_MSG(notice == 1u,
                     "the non-negotiating third party received %zu copies of a "
                     "NOTICE one client sent; echo-message is about the SENDER's "
                     "audience and must not change anybody else's.", notice);
    }

    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
    tc_close(&yes);
    tc_close(&no);
}

/* ---------------------------------------------------------------------------
 * TEETH, AND WHERE THEY WERE INJECTED
 * ---------------------------------------------------------------------------
 * Each was watched go red with the behaviour broken, and the build was checked
 * before the run was believed -- an uncompilable fault leaves the previous binary
 * in place and reports a pass, which has happened in this repo seven times.
 *
 *   ECHO DELIVERED TWICE -- once by the capability and once by the normal path
 *       msg_verbs.c, send_message(): a SECOND fanout_deliver() aimed at the sender,
 *       added after the one that is already there. THIS IS THE CLASSIC BUG and it
 *       is the reason this file counts rather than searching: the two copies are
 *       byte-identical apart from the prefix, so a substring assertion passes. Fails
 *       case 1 on the count (2 != 1) and case 3 likewise, and PASSES cases 2, 4 and
 *       5 -- which is what makes it a fault about the sender's audience specifically.
 *
 *   echo-message applied to EVERY sender
 *       msg_verbs.c, send_message(): `exclude = NULL` unconditionally, so the sender
 *       is never removed from the audience and a NOTICE comes back to a client that
 *       negotiated NOTHING. Fails case 4 (1 copy, expected 0) and NOT case 3 --
 *       which is what makes case 4 load-bearing rather than a restatement of case 3.
 *
 *   echo-message IGNORED
 *       msg_verbs.c, send_message(): the capability test replaced with 1, so the
 *       sender is excluded from a NOTICE even when it asked not to be. Fails case 3
 *       (0 copies, expected 1) and NOT case 4.
 *
 *   the source prefix replaced by the server name
 *       msg_verbs.c, send_message(): `prefix` handed to fanout_deliver() as `s->name`.
 *       Fails the two SHAPE assertions and NOT a single count -- the number of copies
 *       is unchanged, only whose message it looks like. That is why the counts are
 *       paired with an exact `:<nick>!user@host VERB ...` assertion rather than left
 *       to stand alone. (A first attempt at this fault only rewrote the prefix when
 *       `exclude != NULL`, which never holds in the passing cases, so it was a no-op
 *       and the test went green; recorded because it is the same trap as the absent-
 *       numerics list in test_setname.c -- a negative that is only sometimes negative.)
 *
 *   advertised but not implemented
 *       cap.c, k_caps[]: CAP_ECHO_MESSAGE removed while the gate stayed. Fails the
 *       CAP LS assertion AND register_caps()'s ACK wait, so the two halves are
 *       asserted together rather than one being assumed from the other.
 */
int main(void)
{
    case_echo_message();
    tf_done("echo_message");
    return 0;
}
