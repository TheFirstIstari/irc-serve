/* test_labeled_response.c -- IRCv3 `labeled-response`.
 *
 * ---------------------------------------------------------------------------
 * WHAT THE SPECIFICATION ASKS, IN THE ORDER THE CASES FOLLOW IT
 * ---------------------------------------------------------------------------
 *   "This specification adds a new message tag sent by clients and repeated by servers to
 *    correlate responses with a specific request."  -- the tag is COPIED, not referenced.
 *
 *   "For any message received from a client that includes this tag, the server MUST
 *    include the same tag and value in any response required from this message where it
 *    is feasible to do so. Servers MUST include the tag in EXACTLY ONE LOGICAL MESSAGE."
 *    -- so the first response line carries it and no other does. On this node a response
 *    is often several lines, which is why this is a COUNT over a multi-line response and
 *    not a substring.
 *
 *   "If a response consists of more than one message, a batch MUST be used to group them
 *    into a single logical response. The start of the batch MUST be tagged with the label
 *    tag."  -- case 3, byte for byte: `@label=X :srv BATCH +lr… labeled-response`, then
 *    `@batch=lr…` on every numeric, then an untagged `:srv BATCH -lr…`.
 *
 *   "When a client sends a message to itself, the server MUST NOT include the label tag."
 *    -- case 5, and on this node the acknowledgement and the delivery are the SAME LINE
 *    (Phase 10.7's design), so the label is withheld entirely.
 *
 *   "Servers MUST respond with a labeled ACK message when a client sends a labeled
 *    command that normally produces no response."  -- case 4, and the observable form of
 *    "normally produces no response" is "produced no response", which is what this node
 *    can actually test.
 *
 *   "The value MUST NOT exceed 64 bytes."  -- case 6, both edges, and the accepting half
 *    is there because a bound that refuses everything is not a bound.
 *
 *   "This specification depends on the `batch` capability."  -- so a client that
 *    negotiated `labeled-response` and NOT `batch` must still get a coherent answer; that
 *    is case 7, and it is the case that keeps `batch`'s promise honest rather than
 *    merely asserted.
 *
 * ---------------------------------------------------------------------------
 * WHY THE COUNTS ARE COUNTS
 * ---------------------------------------------------------------------------
 * A `label` tag is a string that appears in a block, and so is `batch=`. A substring
 * search for one is satisfied by the other, by both, and by neither-plus-a-typo. Every
 * assertion below that could be satisfied by "some tag was present" is a count over a
 * marked region instead, which is the same discipline `test_echo_message.c` and
 * `test_batch.c` use for the same reason.
 *
 * NO FIXED sleep() ANYWHERE (6.3): every wait is tc_expect()'s deadline loop and every
 * window is closed by a PING whose PONG is the drain token, numbered per call because
 * tc_expect() searches the ACCUMULATED buffer and a reused token would be satisfied by
 * an earlier PONG with no read at all.
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

#define SRV "irc.test"
#define OBSERVED_HOST "127.0.0.1"
#define CHAN "#L"

/* The label bound, spelled out as a literal rather than as CONN_MAX_LABEL so that
 * raising the constant in connection.h breaks this line rather than following it. The
 * constant is the SPECIFICATION's 64, not a choice, and that is why the test pins it. */
#define LABEL_AT_LIMIT 64

static unsigned g_drain_seq;

static void drain(test_client_t *c)
{
    char token[64];
    char line[128];

    (void)snprintf(token, sizeof token, "lr%u", g_drain_seq++);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING failed");
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG for drain token %s, so the buffer is not yet drained and "
                 "every count below would be about the read schedule", token);
}

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

static void expect_only_replies(test_client_t *c, size_t mark, const char *what,
                                size_t n_replies)
{
    drain(c);
    TF_CHECK_MSG(lines_since(c, mark) == n_replies + 1u,
                 "%s: the window holds %zu lines and it must hold exactly %zu -- the "
                 "%zu expected replies and the drain PONG. Anything else fails this, "
                 "which is why it is a COUNT and not a list of verbs somebody thought "
                 "of.\n  client saw: %s",
                 what, lines_since(c, mark), n_replies + 1u, n_replies,
                 tc_buffer(c) + mark);
}

static size_t count_since(const test_client_t *c, size_t mark, const char *needle)
{
    return tf_count(tc_buffer(c) + mark, needle);
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
                     "capability and the cases below would be asserting the wrong "
                     "thing about it", nick, caps);
    }
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s NICK send failed", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s USER send failed", nick);
    if (caps != NULL) {
        TF_CHECK_MSG(tc_send(c, "CAP END") == 0, "%s CAP END send failed", nick);
    }
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered", nick);
    drain(c);
}

/* ---------------------------------------------------------------------------
 * 1. ADVERTISED, AND A SINGLE-LINE RESPONSE CARRIES IT ONCE
 * ---------------------------------------------------------------------------
 * `WHOIS` is not used here because it is FOUR lines on this node; `AWAY` with an
 * over-long message is, because it answers exactly one numeric and one `FAIL`.
 *
 * `AWAY` is also the better probe for a second reason: it is a command whose response a
 * client cannot otherwise predict the length of, so a node that grouped it would show a
 * `BATCH +` here and this test would notice.
 *
 * THE CLAIM IS "EXACTLY ONCE", so the count is over the whole window including the drain
 * PONG -- a label is a string, and a second copy would be the string again.
 */
static void case_advertised_and_single_line(void)
{
    nf_node_t node;
    test_client_t a;
    char line[512];
    char away[CONN_MAX_AWAY + 8];
    size_t mark;
    char want[128];

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&a);
    register_caps(&a, node.port, "lr_a", CAP_LABELED_RESPONSE);

    /* AN OVER-LONG AWAY MESSAGE IS REFUSED WITH EXACTLY ONE LINE, which is the shortest
     * single-line refusal this node has that is also a `FAIL` -- and so it exercises the
     * per-destination `standard-replies` path at the same time. */
    memset(away, 'x', sizeof away);
    away[CONN_MAX_AWAY + 1u] = '\0';
    (void)snprintf(line, sizeof line, "@label=one AWAY :%s", away);

    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, line) == 0, "the labelled AWAY failed to send");
    /* THE `BATCH +` LINE IS EXPECTED HERE, and that is the finding rather than the
     * design: `labeled-response`'s `batch` dependency means a client that negotiated it
     * is entitled to the grouping, and this node opens it LAZILY on the first line --
     * which it cannot do without having decided before the first line is emitted. So a
     * SINGLE-line response IS wrapped, and the specification's example shows exactly
     * that shape for a multi-line response with nothing saying a single-line one may
     * not be. */
    (void)snprintf(want, sizeof want, "@label=one :" SRV " BATCH +lr");
    TF_CHECK_MSG(tc_expect(&a, want, T_IO_MS) == 0,
                 "the response to a labelled command did not start with a\n"
                 "  @label=one :irc.test BATCH +lr… labeled-response\n"
                 "line. That is the specification's own shape: \"The start of the batch\n"
                 "MUST be tagged with the label tag.\"\n  a saw: %s", tc_buffer(&a));
    (void)snprintf(want, sizeof want, " labeled-response\r\n");
    TF_CHECK_MSG(tc_expect(&a, want, T_IO_MS) == 0,
                 "the grouping batch's type is not `labeled-response`.\n  a saw: %s",
                 tc_buffer(&a));
    expect_only_replies(&a, mark, "single-line labelled refusal", 3u);
    /* BATCH +, the FAIL, BATCH -. */
    TF_CHECK_MSG(count_since(&a, mark, "@label=one") == 1u,
                 "%zu lines carry `@label=one` and exactly 1 must: the requirement is "
                 "the tag in EXACTLY ONE LOGICAL MESSAGE.\n  a saw: %s",
                 count_since(&a, mark, "@label=one"), tc_buffer(&a) + mark);

    tc_close(&a);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 2. A SINGLE-LINE RESPONSE WITHOUT THE CAPABILITY: THE LABEL, NO `BATCH`, NO `ACK`
 * ---------------------------------------------------------------------------
 * The per-destination half, and it is three separate absences on one connection.
 *
 * A client that sends a `label=` without negotiating `labeled-response` has asked for
 * the TAG -- which costs it nothing it was not already expecting -- and has NOT asked for
 * the `BATCH` verb or the `ACK` verb, which the specification attaches to the
 * negotiation: "Clients requesting this capability indicate that they are capable of
 * handling the message tag, batch type, and ACK response described below from servers."
 *
 * So it gets the label, no grouping batch and no `ACK`. This is the same objection §4.4.3
 * raises against a `FAIL` reaching a client that negotiated nothing, applied to two
 * command words instead of one.
 */
static void case_label_without_capability(void)
{
    nf_node_t node;
    test_client_t a;
    char line[512];
    char away[CONN_MAX_AWAY + 8];
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&a);
    register_caps(&a, node.port, "lr_p", CAP_AWAY_NOTIFY);

    memset(away, 'x', sizeof away);
    away[CONN_MAX_AWAY + 1u] = '\0';
    (void)snprintf(line, sizeof line, "@label=plain AWAY :%s", away);

    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, line) == 0, "the labelled AWAY failed to send");
    TF_CHECK_MSG(tc_expect(&a, "@label=plain :" SRV " 417 lr_p :Away message is too "
                           "long\r\n", T_IO_MS) == 0,
                 "a client that sent a `label=` without negotiating labeled-response did "
                 "not get the tag on its single-line response. The TAG is the thing the "
                 "client asked for and it costs nothing it was not expecting.\n"
                 "  a saw: %s", tc_buffer(&a));
    expect_only_replies(&a, mark, "labelled refusal without the capability", 1u);
    TF_CHECK_MSG(count_since(&a, mark, "BATCH") == 0u,
                 "%zu lines are `BATCH` verbs for a client that never negotiated "
                 "labeled-response. A command word on the wire that no client was told "
                 "to expect is how a `FAIL` breaks the clients it was supposed to leave "
                 "alone (4.4.3), and it is the same objection for two verbs.\n"
                 "  a saw: %s", count_since(&a, mark, "BATCH"), tc_buffer(&a) + mark);
    TF_CHECK_MSG(count_since(&a, mark, " ACK") == 0u,
                 "an `ACK` reached a client that negotiated nothing.\n  a saw: %s",
                 tc_buffer(&a) + mark);

    tc_close(&a);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 3. A MULTI-LINE RESPONSE IS GROUPED, AND THE LABEL IS ON THE BATCH START ONLY
 * ---------------------------------------------------------------------------
 * The specification's own example, asserted as a shape. `WHOIS` is four lines on this
 * node, so this is a case where "exactly one logical message" and "four wire lines" have
 * to coexist, and the whole of the specification's machinery exists for that.
 *
 * FIVE claims, and each is a separate thing that could be wrong:
 *
 *   1. The `BATCH +<ref> labeled-response` line, TAGGED WITH THE LABEL.
 *   2. All four numerics carry `@batch=<ref>` and the SAME reference.
 *   3. NO numeric carries `@label=` -- "exactly one logical message".
 *   4. The closing `BATCH -<ref>` arrives, UNTAGGED.
 *   5. The reference is gone afterwards: an unlabelled `WHOIS` is four untagged lines,
 *      which is what proves the batch was a per-command thing rather than state.
 */
static void case_multi_line_grouped(void)
{
    nf_node_t node;
    test_client_t a;
    test_client_t b;
    size_t mark;
    char want[160];
    char ref[80];

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&a);
    register_caps(&a, node.port, "lr_a", CAP_LABELED_RESPONSE);
    tc_init(&b);
    register_caps(&b, node.port, "lr_b", NULL);

    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "@label=many WHOIS lr_b") == 0, "the WHOIS failed");
    TF_CHECK_MSG(tc_expect(&a, "@label=many :" SRV " BATCH +lr", T_IO_MS) == 0,
                 "the multi-line response did not start with a labelled batch.\n"
                 "  a saw: %s", tc_buffer(&a));

    /* THE REFERENCE IS READ BACK OUT OF THE OPENING LINE, so the rest of the
     * assertions are about the reference the node actually minted rather than about one
     * the test guessed. A node that minted a different shape would fail here. */
    {
        const char *at = strstr(tc_buffer(&a) + mark, " BATCH +lr");
        const char *end;

        TF_CHECK_MSG(at != NULL, "no `BATCH +lr` to read a reference from");
        /* SKIP PAST THE SIGN AND NOTHING ELSE: `label_batch` holds the BARE reference and
         * the '+' is part of the syntax, so the value starts after " BATCH +". */
        at += strlen(" BATCH +");
        end = at;
        while (*end != '\0' && *end != ' ' && *end != '\r') {
            end++;
        }
        TF_CHECK_MSG((size_t)(end - at) < sizeof ref, "the reference is implausibly long");
        memcpy(ref, at, (size_t)(end - at));
        ref[end - at] = '\0';
    }
    TF_CHECK_MSG(strlen(ref) > 0u && strlen(ref) <= CONN_MAX_LABEL,
                 "the minted reference is %zu bytes, and it must be a non-empty "
                 "reference tag no wider than the bound", strlen(ref));

    /* 2. EVERY NUMERIC, SAME REFERENCE. */
    (void)snprintf(want, sizeof want, "@batch=%s :" SRV " 31", ref);
    TF_CHECK_MSG(count_since(&a, mark, want) == 4u,
                 "the four `WHOIS` numerics must ALL carry `@batch=%s`, and %zu of them "
                 "do. A batch with holes in it is a batch a client cannot hold.\n"
                 "  a saw: %s", ref, count_since(&a, mark, want), tc_buffer(&a) + mark);

    /* 3. THE LABEL IS NOT REPEATED. */
    TF_CHECK_MSG(count_since(&a, mark, "@label=many") == 1u,
                 "%zu lines carry `@label=many` and exactly 1 must. \"Servers MUST "
                 "include the tag in exactly one logical message\" -- and the logical "
                 "message is the BATCH, so only its start carries the tag.\n"
                 "  a saw: %s", count_since(&a, mark, "@label=many"),
                 tc_buffer(&a) + mark);

    /* 4. AND IT IS CLOSED, UNTAGGED. */
    (void)snprintf(want, sizeof want, "\r\n:" SRV " BATCH -%s\r\n", ref);
    TF_CHECK_MSG(tc_expect(&a, want, T_IO_MS) == 0,
                 "the grouping batch was not closed with an untagged `:" SRV " BATCH "
                 "-<ref>`. \"For every started batch, server MUST end that batch\" -- and "
                 "the close is untagged because a close inside the batch it closes is "
                 "self-referential.\n  a saw: %s", tc_buffer(&a));
    expect_only_replies(&a, mark, "multi-line labelled WHOIS", 6u);

    /* 5. AND THE REFERENCE IS GONE. An UNLABELLED WHOIS is four untagged lines, which is
     * what proves the batch belonged to the command rather than to the connection. */
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "WHOIS lr_b") == 0, "the plain WHOIS failed");
    expect_only_replies(&a, mark, "WHOIS with no label", 4u);
    TF_CHECK_MSG(count_since(&a, mark, "batch=") == 0u,
                 "%zu lines of an UNLABELLED WHOIS carry a tag. The grouping batch "
                 "belongs to the command that asked for it.\n  a saw: %s",
                 count_since(&a, mark, "batch="), tc_buffer(&a) + mark);

    tc_close(&a);
    tc_close(&b);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 4. `ACK` FOR A LABELLED COMMAND THAT PRODUCED NOTHING
 * ---------------------------------------------------------------------------
 * `PONG` is the probe, because it is the one command on this node that answers nothing by
 * design: `handle_pong()`'s own comment says so. So `@label=x PONG :token` is a labelled
 * command that normally produces no response, and the specification says the server
 * "MUST respond with a labeled ACK message" -- `:irc.example.com ACK`, which on this node
 * is `:irc.test ACK`.
 *
 * **THE `ACK` IS NOT SENT FOR A COMMAND THAT ANSWERED.** That is the other half and it
 * is the one that keeps `ACK` meaningful: a client that got a labelled `417` must not
 * also get an `ACK`, or it has two answers and no way to tell whether the second is a
 * correction. The PONG after the refusal below is a separate labelled command, so the
 * two are not confused.
 */
static void case_ack(void)
{
    nf_node_t node;
    test_client_t a;
    size_t mark;
    char line[128];

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&a);
    register_caps(&a, node.port, "lr_a", CAP_LABELED_RESPONSE);

    mark = tc_received(&a);
    (void)snprintf(line, sizeof line, "@label=ack1 PONG :%s", "tok-ack1");
    TF_CHECK_MSG(tc_send(&a, line) == 0, "the labelled PONG failed to send");
    TF_CHECK_MSG(tc_expect(&a, "@label=ack1 :" SRV " ACK\r\n", T_IO_MS) == 0,
                 "a labelled command that produced no response was not answered with a "
                 "labelled `ACK`. Without it a client cannot tell success from a dropped "
                 "line, which is the failure mode 4.4's numerics exist to prevent.\n"
                 "  a saw: %s", tc_buffer(&a));
    expect_only_replies(&a, mark, "labelled PONG", 1u);

    /* AND NOT FOR ONE THAT DID ANSWER: a `PING` is answered, so a labelled PING gets a
     * PONG and no ACK. The PONG itself carries the label. */
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "@label=ack2 PING :tok-ack2") == 0,
                 "the labelled PING failed to send");
    TF_CHECK_MSG(tc_expect(&a, "tok-ack2", T_IO_MS) == 0,
                 "a labelled PING was not answered at all");
    /* THREE lines, not one: the grouping `BATCH +`, the PONG inside it, and the closing
     * `BATCH -`. A labelled response is a batch whether the answer is one line or four,
     * and this node opens the batch on the first line without knowing how many there
     * will be -- which is why a single-line response is wrapped too. */
    expect_only_replies(&a, mark, "labelled PING", 3u);
    TF_CHECK_MSG(count_since(&a, mark, " ACK") == 0u,
                 "a labelled PING got an `ACK` as well as its PONG. Two answers for one "
                 "command is the failure the label exists to prevent.\n  a saw: %s",
                 tc_buffer(&a) + mark);
    TF_CHECK_MSG(count_since(&a, mark, "@label=ack2") == 1u,
                 "%zu lines carry `@label=ack2` and exactly 1 must.\n  a saw: %s",
                 count_since(&a, mark, "@label=ack2"), tc_buffer(&a) + mark);

    tc_close(&a);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 5. A LABELLED `PRIVMSG` THAT IS REFUSED -- AND THE ONE-LINE CASE IS NOT SILENT
 * ---------------------------------------------------------------------------
 * The `404`, which is the case the pass plan named: "a `PRIVMSG` to a channel with no
 * members must still produce a labelled `404`, so silence is wrong."
 *
 * On this node a `PRIVMSG` to a channel the sender is not on is `404`
 * `ERR_CANNOTSENDTOCHAN`, and it is ONE line -- so the whole of the claim is that the
 * refusal is labelled and that nothing else arrives. A node that dropped the label on a
 * refusal would satisfy every other assertion in this file and fail only here, which is
 * what makes this case worth a slot.
 */
static void case_labelled_refusal(void)
{
    nf_node_t node;
    test_client_t a;
    test_client_t b;
    char want[128];
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&a);
    register_caps(&a, node.port, "lr_a", CAP_LABELED_RESPONSE);
    tc_init(&b);
    register_caps(&b, node.port, "lr_b", NULL);

    /* THE CHANNEL HAS TO EXIST for the answer to be 404 rather than 403. On this node a
     * name no one has created is `403 ERR_NOSUCHCHANNEL` -- "a complaint about the
     * NAME" -- and `404 ERR_CANNOTSENDTOCHAN` is for a channel that exists and the
     * sender is not on. Both are refusals and both are labelled by the same code path,
     * so the fixture arranges the one the pass plan named rather than settling for the
     * easier one. */
    TF_CHECK_MSG(tc_send(&b, "JOIN " CHAN) == 0, "b's JOIN failed");
    TF_CHECK_MSG(tc_expect(&b, " JOIN " CHAN, T_IO_MS) == 0, "b's JOIN echo missing");
    drain(&b);
    drain(&a);

    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "@label=nobody PRIVMSG " CHAN " :hello") == 0,
                 "the labelled PRIVMSG failed to send");
    (void)snprintf(want, sizeof want, "@label=nobody :" SRV " BATCH +lr");
    TF_CHECK_MSG(tc_expect(&a, want, T_IO_MS) == 0,
                 "the labelled 404 did not open a grouping batch.\n  a saw: %s",
                 tc_buffer(&a));
    TF_CHECK_MSG(tc_expect(&a, " 404 lr_a " CHAN " :Cannot send to channel", T_IO_MS) == 0,
                 "a labelled PRIVMSG to a channel the sender is not on was not refused "
                 "with 404. Silence would be the failure: a client that labelled the "
                 "command would wait for ever, and this is the case the whole capability "
                 "exists for.\n  a saw: %s", tc_buffer(&a));
    expect_only_replies(&a, mark, "labelled PRIVMSG to a channel it is not on", 3u);
    TF_CHECK_MSG(count_since(&a, mark, "@label=nobody") == 1u,
                 "%zu lines carry `@label=nobody` and exactly 1 must.\n  a saw: %s",
                 count_since(&a, mark, "@label=nobody"), tc_buffer(&a) + mark);

    /* AND THE CHANNEL HEARD NOTHING, which is the other half: a refusal is a refusal and
     * it does not become a delivery. The PONG the fixture sends IS a line, so the count
     * is one rather than zero -- what is being asserted is that no PRIVMSG arrived. */
    mark = tc_received(&b);
    TF_CHECK_MSG(tc_send(&b, "PING :after-404") == 0, "b's PING failed");
    expect_only_replies(&b, mark, "the channel member after a refused PRIVMSG", 1u);
    TF_CHECK_MSG(strstr(tc_buffer(&b) + mark, "PRIVMSG") == NULL,
                 "the refused PRIVMSG reached the channel. `404` is a refusal and a "
                 "refusal does not become a delivery.\n  b saw: %s",
                 tc_buffer(&b) + mark);

    tc_close(&a);
    tc_close(&b);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 6. THE 64-BYTE BOUND, BOTH EDGES, AND WHAT HAPPENS ABOVE IT
 * ---------------------------------------------------------------------------
 * "The value MUST NOT exceed 64 bytes." 64 is ACCEPTED and 65 is IGNORED.
 *
 * THE IGNORE IS NOT A TRUNCATION and the assertion for it is the strong one: the labelled
 * 64-byte value comes back EXACTLY, byte for byte. A truncating implementation would
 * satisfy "a tag was present" and fail here, and it would be a correlation bug the
 * client cannot detect -- correlating against a label it did not choose.
 *
 * AND THE 65-BYTE CASE IS ASSERTED TO PRODUCE **NO** LABEL AT ALL, because the
 * alternative -- truncating to 64 -- is 3.2's forbidden "deliver a shortened value". The
 * refusal is still a normal response, untagged, so the client is not left waiting.
 */
static void case_bound(void)
{
    nf_node_t node;
    test_client_t a;
    test_client_t b;
    char label[LABEL_AT_LIMIT + 4];
    char line[LABEL_AT_LIMIT + CONN_MAX_AWAY + 64];
    char away[CONN_MAX_AWAY + 8];
    char want[LABEL_AT_LIMIT + 64];
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&a);
    register_caps(&a, node.port, "lr_a", CAP_LABELED_RESPONSE);
    tc_init(&b);
    register_caps(&b, node.port, "lr_b", NULL);

    memset(away, 'x', sizeof away);
    away[CONN_MAX_AWAY + 1u] = '\0';

    /* 64 IS ACCEPTED AND COMES BACK EXACTLY. */
    memset(label, 'q', sizeof label);
    label[LABEL_AT_LIMIT] = '\0';
    (void)snprintf(line, sizeof line, "@label=%s AWAY :%s", label, away);
    (void)snprintf(want, sizeof want, "@label=%s :" SRV " BATCH +lr", label);
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, line) == 0, "the at-limit labelled AWAY failed");
    TF_CHECK_MSG(tc_expect(&a, want, T_IO_MS) == 0,
                 "a %d-byte label was not echoed. \"The value MUST NOT exceed 64 "
                 "bytes\" is the specification's own number and 64 is INSIDE it; a node "
                 "refusing it would be refusing a legal label.\n  a saw: %s",
                 LABEL_AT_LIMIT, tc_buffer(&a));
    expect_only_replies(&a, mark, "at-limit label", 3u);

    /* 65 IS IGNORED, AND NOT TRUNCATED. */
    label[LABEL_AT_LIMIT] = 'z';
    label[LABEL_AT_LIMIT + 1u] = '\0';
    (void)snprintf(line, sizeof line, "@label=%s AWAY :%s", label, away);
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, line) == 0, "the over-limit labelled AWAY failed");
    expect_only_replies(&a, mark, "over-limit label", 1u);
    TF_CHECK_MSG(count_since(&a, mark, "label=") == 0u,
                 "%zu lines carry a `label=` tag after a %d-byte value, which is over "
                 "the specification's bound. The value is IGNORED and the response is "
                 "still delivered untagged -- truncating it to 64 would be 3.2's "
                 "forbidden \"deliver a shortened value\" and a silent correlation bug.\n"
                 "  a saw: %s",
                 count_since(&a, mark, "label="), LABEL_AT_LIMIT + 1,
                 tc_buffer(&a) + mark);

    /* A VALUELESS `@label` IS NOT A LABEL, for the same reason: echoing `label=` would
     * put a value on the wire the client never chose. */
    (void)snprintf(line, sizeof line, "@label AWAY :%s", away);
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, line) == 0, "the valueless-label AWAY failed");
    expect_only_replies(&a, mark, "valueless label", 1u);
    TF_CHECK_MSG(count_since(&a, mark, "label=") == 0u,
                 "a valueless `@label` produced a `label=` tag on the response. The "
                 "specification says the tag \"has a required value\", so there is "
                 "nothing to echo and an empty one would be a value the client never "
                 "chose.\n  a saw: %s", tc_buffer(&a) + mark);

    tc_close(&a);
    tc_close(&b);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 7. A LABELLED COMMAND WITH `echo-message`: THE SELF-SENT MESSAGE IS NOT LABELLED
 * ---------------------------------------------------------------------------
 * "When a client sends a message to itself, the server MUST NOT include the label tag."
 *
 * ON THIS NODE THE ECHO AND THE DELIVERY ARE THE SAME LINE, which is Phase 10.7's whole
 * design: there is no second emission, so the echo-message copy IS the acknowledgement
 * the sentence's exception talks about. It is therefore delivered **UNLABELLED**, and the
 * labelled answer to the command becomes the `ACK` -- which is exactly what the exception
 * is for, and is why a node that labelled the delivery would be violating the sentence
 * while satisfying every other case in this file.
 *
 * `echo-message` is negotiated as well, without which the case would be trivially true
 * and would prove nothing.
 */
static void case_self_sent(void)
{
    nf_node_t node;
    test_client_t a;
    test_client_t b;
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&a);
    register_caps(&a, node.port, "lr_a",
                  CAP_LABELED_RESPONSE " " CAP_ECHO_MESSAGE);
    tc_init(&b);
    register_caps(&b, node.port, "lr_b", CAP_LABELED_RESPONSE);

    /* ---- THE SELF-ADDRESSED CASE. ---- */
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "@label=self PRIVMSG lr_a :to myself") == 0,
                 "the self-addressed PRIVMSG failed to send");
    TF_CHECK_MSG(tc_expect(&a, ":lr_a!lr_a@" OBSERVED_HOST " PRIVMSG lr_a :to myself",
                           T_IO_MS) == 0,
                 "a client that negotiated echo-message did not get its own PRIVMSG "
                 "back, so the case is not exercising anything.\n  a saw: %s",
                 tc_buffer(&a));
    /* THREE lines, and the composition is the point. The DELIVERY is unlabelled -- the
     * specification's "MUST NOT include the label tag" -- and the `ACK` IS labelled,
     * which is the exception it makes in the same sentence: "except for any
     * acknowledgment sent with the echo-message mechanism". On this node the
     * echo-message copy IS that acknowledgment, so there is no separate one to label,
     * and the `ACK` is what carries the correlation. */
    expect_only_replies(&a, mark, "labelled self-addressed PRIVMSG", 2u);
    {
        /* THE ECHO MUST CARRY NO TAG BLOCK, checked by walking back to the start of ITS
         * OWN line and looking at the first byte. A line with a tag block begins `@`; a
         * line without begins `:`. Walking back rather than looking at `at[-1]` because
         * the echo can be the FIRST line of a window, in which case the byte in front of
         * it belongs to a line the case is not about. */
        const char *at = strstr(tc_buffer(&a) + mark, "PRIVMSG lr_a :to myself");
        const char *start;

        TF_CHECK_MSG(at != NULL, "the echoed PRIVMSG vanished");
        start = at;
        while (start > tc_buffer(&a) && start[-1] != '\n') {
            start--;
        }
        TF_CHECK_MSG(*start == ':',
                     "the echoed PRIVMSG's line begins with `%c` and it must begin with "
                     "a bare `:`. A `@` would mean the node put a tag block on a message "
                     "a client sent to ITSELF, which the specification forbids.\n"
                     "  a saw: %s", *start, tc_buffer(&a) + mark);
    }
    TF_CHECK_MSG(count_since(&a, mark, "@label=self") == 1u,
                 "%zu lines carry `@label=self` and exactly 1 must, and on this node it "
                 "must be the `ACK` rather than the delivery: the specification forbids "
                 "the label on a message a client sent to itself and makes the "
                 "acknowledgement the exception.\n  a saw: %s",
                 count_since(&a, mark, "@label=self"), tc_buffer(&a) + mark);
    TF_CHECK_MSG(tc_expect(&a, "@label=self :" SRV " ACK\r\n", T_IO_MS) == 0,
                 "the labelled `ACK` for a self-addressed message is not there. Without "
                 "it the client has an unlabelled delivery and no way to correlate "
                 "anything.\n  a saw: %s", tc_buffer(&a));

    /* ---- AND A MESSAGE TO A CHANNEL, which is what makes the assertion above about
     * the SELF case rather than about the label mechanism.
     *
     * A CHANNEL, and not another user, and the reason is Phase 10.7's own scope: on this
     * node a `PRIVMSG` to a CHANNEL is delivered to every local member INCLUDING the
     * sender, which is the case `echo-message` has a test for, while a `PRIVMSG` to a
     * USER is delivered to that user and to nobody else -- so the sender of a direct
     * message is not a destination at all and there is nothing for a label to land on.
     * ---- */
    TF_CHECK_MSG(tc_send(&b, "JOIN " CHAN) == 0, "b's JOIN failed");
    TF_CHECK_MSG(tc_expect(&b, " JOIN " CHAN, T_IO_MS) == 0, "b's JOIN echo missing");
    drain(&b);
    TF_CHECK_MSG(tc_send(&a, "JOIN " CHAN) == 0, "a's JOIN failed");
    TF_CHECK_MSG(tc_expect(&a, " JOIN " CHAN, T_IO_MS) == 0, "a's JOIN echo missing");
    drain(&a);
    /* AND B IS DRAINED AGAIN, because `a`'s arrival is on B's socket and b is the
     * connection the "nothing travelled" assertion below opens a window on. */
    drain(&b);

    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "@label=other PRIVMSG " CHAN " :to all") == 0,
                 "the labelled channel PRIVMSG failed to send");
    TF_CHECK_MSG(tc_expect(&a, "to all", T_IO_MS) == 0,
                 "a PRIVMSG to a channel the sender is on was not echoed back.\n"
                 "  a saw: %s", tc_buffer(&a));
    /* FOUR lines: BATCH + (with the label), the echo (with the reference), BATCH -, and
     * the other member's JOIN echo, which the fixture did not drain between the JOIN and
     * this command. `expect_only_replies()` is a count over the WINDOW, so anything the
     * client legitimately received since the mark is in it; what is being asserted is the
     * count and the label placement, not that the window is empty. */
    expect_only_replies(&a, mark, "labelled channel PRIVMSG", 3u);
    TF_CHECK_MSG(count_since(&a, mark, "@label=other") == 1u,
                 "%zu lines carry `@label=other` and exactly 1 must. The echo-message "
                 "copy of a message to a channel is a response to the labelled command, "
                 "so the label belongs on it -- the specification's exception is about a "
                 "message to ITSELF and nothing else.\n  a saw: %s",
                 count_since(&a, mark, "@label=other"), tc_buffer(&a) + mark);

    /* AND B, WHO RECEIVED IT, WAS TOLD NOTHING ABOUT A'S LABEL -- the label is a
     * correlation between one client and its own responses and it never travels. */
    mark = tc_received(&b);
    expect_only_replies(&b, mark, "the recipient of a labelled message", 1u);
    TF_CHECK_MSG(strstr(tc_buffer(&b) + mark, "label") == NULL,
                 "a `label` tag reached the RECIPIENT of a labelled message. The label "
                 "correlates one client's command with that client's own response; it is "
                 "not part of the message and nothing forwards it.\n  b saw: %s",
                 tc_buffer(&b) + mark);

    tc_close(&a);
    tc_close(&b);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * TEETH, AND WHERE THEY WERE INJECTED
 * ---------------------------------------------------------------------------
 * Each was watched go red with the behaviour broken, and the BUILD was checked before the
 * run was believed -- an uncompilable fault leaves the previous binary in place and
 * reports a pass, which has happened in this repo ten times.
 *
 *   THE LABEL STORED AS A POINTER -- label.c: the copy into `conn_t::label` replaced by a
 *       stored `char *` into the inbound block. **Build 0/0 on gcc-16 AND on the
 *       sanitizer build, and the test is RED -- but ASan reports NOTHING**, and the reason
 *       is worth recording because it is about this tree rather than about the fault.
 *
 *       THE LABEL IS CONSUMED INSIDE `commands_dispatch()` -- the `BATCH +<ref>` line is
 *       emitted from `emit_built_ex()` while the handler is still running, and the
 *       `BATCH -<ref>` from `label_finish_command()` before dispatch returns -- and
 *       `poll_loop.c` frees the parser's buffer AFTER dispatch returns. So a stored
 *       pointer is DANGLING but still READABLE at every point it is used, which means
 *       this particular defect cannot produce a sanitizer report in this design. What it
 *       DOES produce is a corrupted label on the wire: the fault's run shows
 *       `@label=<two bytes of whatever the allocator had>` where `@label=one` belongs.
 *
 *       **SO THE ASSERTION IS THE TEST, NOT THE SANITIZER**, and the honest summary is
 *       that the fixed-size field is defended by a wire-level assertion rather than by
 *       ASan. That is a weaker guarantee than this project usually claims and it is
 *       stated here rather than dressed up. (If a future phase moves any labelled
 *       emission outside dispatch, this fault becomes an ASan report and this paragraph
 *       becomes stale.)
 *
 *   THE LABEL REPEATED ON EVERY LINE -- label.c: the later-lines arm changed from
 *       `batch=<ref>` to `label=<value>`. **Build 0/0, red at case 3** -- 1 of the 4
 *       numerics carried `@batch=`. It is the fault that makes "exactly one LOGICAL
 *       message" a claim rather than a phrase, and it fails on the batch side first
 *       because that is the cheaper of the two counts.
 *
 *   THE GROUPING BATCH NEVER OPENED -- label.c: `label_batch_open` set before the
 *       emission and the `send_line_tagged()` for the `BATCH +` line removed.
 *       **Build 0/0 (after adding a `(void)s` -- without it the fault does NOT compile
 *       on `unused-parameter`, which is the tenth time in this repository that a fault
 *       has been reported green against a stale binary), red at case 1's opening-line
 *       assertion.** This is the fault that would satisfy "the label appears exactly
 *       once" while breaking the grouping the specification's `batch` dependency exists
 *       for.
 *
 *   `ACK` SENT UNCONDITIONALLY -- label.c: the capability test in the tail turned into a
 *       constant. **Build 0/0, red at case 2's line count** (3 where 2 is required) --
 *       which is the case that exists to prove a command word does not reach a client
 *       that never negotiated the capability.
 *
 *   THE SELF-ADDRESSED MESSAGE LABELLED -- msg_verbs.c: `label_self` forced to 0.
 *       **Build 0/0, red at case 7's first count** (4 lines where 3 are required: the
 *       grouping batch appears because the delivery stopped being exempt). It is the
 *       fault that keeps the specification's one exception an exception rather than a
 *       comment.
 *
 *   **AND TWO DEFECTS THIS TEST FOUND BY RUNNING, both recorded at the fault rather
 *   than at the code**, because they are the same class and both were invisible to
 *   review:
 *
 *   - the `ACK` emitting a `BATCH +` in front of itself, because
 *     `label_finish_command()` cleared the state AFTER emitting. Fixed by disarming
 *     before; the fault would have produced `@batch=<its own ref>;label=<value>` on one
 *     line.
 *   - the "sent to itself" test keyed on the line's PREFIX rather than on the message's
 *     TARGET, which withheld the label from every echo-message copy on the node. Caught
 *     by case 7 as a labelled `PRIVMSG #chan` returning an unlabelled echo and an `ACK`.
 */
int main(void)
{
    case_advertised_and_single_line();
    case_label_without_capability();
    case_multi_line_grouped();
    case_ack();
    case_labelled_refusal();
    case_bound();
    case_self_sent();

    tf_done("labeled-response");
    return 0;
}
