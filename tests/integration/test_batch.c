/* test_batch.c -- IRCv3 `batch`, the client-facing half: the `BATCH` verb, and the
 * `@` / `+` reference tags.
 *
 * ---------------------------------------------------------------------------
 * SCOPE, AND IT IS NOT THE WHOLE SPECIFICATION
 * ---------------------------------------------------------------------------
 * `batch` has a server half this node does not implement: the SERVER opening a
 * `netsplit` or `netjoin` batch around its own emissions. That is not a hidden gap
 * and this file says why in one place:
 *
 *   - the specification says outright that "batch types are not advertised by servers
 *     nor explicitly requested by clients", and that a client "MAY ignore the type
 *     and process messages one by one". So advertising `batch` promises a client the
 *     FRAMING, not a netsplit suppressor.
 *   - the only batch TYPE this node emits is `labeled-response`, in
 *     `test_labeled_response.c`, because IRCv3's `labeled-response` specification
 *     requires one: a multi-line response must be grouped so the label appears in
 *     exactly one LOGICAL message.
 *
 * `draft/multiline` is the specification `client-tags/reference-tags` exists for, and
 * it is NOT implemented: it means interpreting `;draft/multiline-concat` values and
 * splitting one command into several. What IS here is the mechanism it needs -- a
 * client can open a batch, put tagged commands inside it, and read its own replies
 * back tagged -- so the gap is the *interpretation of the concat values*, not the
 * framing.
 *
 * ---------------------------------------------------------------------------
 * WHY THE ASSERTIONS ARE COUNTS
 * ---------------------------------------------------------------------------
 * The three claims that matter are all absences or repetitions:
 *
 *   - inside an open batch, every reply carries `batch=<ref>`; outside it, none does.
 *     A substring search for `batch=` cannot tell "no tags" from "one tag", and a
 *     node that tagged only its first reply would pass one.
 *   - `@<ref>` produces NO line at all. That is the whole meaning of `@` -- the
 *     response goes NOWHERE rather than being tagged and ignored -- so it is a line
 *     count of zero, not an absence of a needle.
 *   - a `BATCH -ref` that does not match leaves the batch OPEN, so a later reply is
 *     still tagged. This is the highest-value assertion in the file: it is the one a
 *     "close whatever is open" implementation fails, and the failure is invisible to
 *     a client that closed the right batch immediately afterwards.
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
#define CHAN "#B"

/* A 64-byte reference tag is the boundary, and it is spelled out as a literal rather
 * than as CONN_MAX_BATCH_REF so that raising the bound in connection.h breaks this
 * line -- the same argument test_registration.c makes about the 005 tokens. */
#define REF_AT_LIMIT 64

static unsigned g_drain_seq;

static void drain(test_client_t *c)
{
    char token[64];
    char line[128];

    (void)snprintf(token, sizeof token, "bt%u", g_drain_seq++);
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
 * 1. ADVERTISED, AND THE `BATCH` VERB EXISTS
 * ---------------------------------------------------------------------------
 * `cap.h`'s rule: `CAP LS` lists implementations. `batch` IS implemented on this node
 * -- the verb below answers it -- and the specification does not tie the name to any
 * particular batch TYPE, so advertising it claims the framing and nothing more.
 *
 * The verb's existence is a separate claim and a separate assertion: a client that
 * saw `batch` in `CAP LS` and then got `421` for `BATCH` would read "this server has
 * never heard of BATCH", which is a lie about a verb the dispatch table has a row for.
 */
static void case_advertised_and_verb_exists(void)
{
    nf_node_t node;
    test_client_t c;
    char ls[64];

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");
    TF_CHECK_MSG(tc_send(&c, "CAP LS") == 0, "CAP LS send failed");
    (void)snprintf(ls, sizeof ls, " CAP * LS :");
    TF_CHECK_MSG(tc_expect(&c, ls, T_IO_MS) == 0, "CAP LS was not answered");
    TF_CHECK_MSG(strstr(tc_buffer(&c), CAP_BATCH) != NULL,
                 "CAP LS does not advertise batch, which this node implements: the "
                 "BATCH verb is in the dispatch table and core/batch.c answers it");
    /* And the sanity check that makes the absence of a NEGOTIABLE one meaningful. */
    TF_CHECK_MSG(strstr(tc_buffer(&c), CAP_AWAY_NOTIFY) != NULL,
                 "CAP LS does not advertise away-notify, so the batch assertion above "
                 "could be satisfied by a CAP LS that stopped early.\n  saw: %s",
                 tc_buffer(&c));
    tc_close(&c);

    register_caps(&c, node.port, "btverb", CAP_BATCH);
    /* A MALFORMED `BATCH` -- neither sign -- is what proves the verb EXISTS, and it
     * is deliberately NOT 421: 421 would be the answer for a verb this build has
     * never heard of, which is the opposite of the truth. */
    TF_CHECK_MSG(tc_send(&c, "BATCH notaref") == 0, "BATCH send failed");
    TF_CHECK_MSG(tc_expect(&c, " 462 ", T_IO_MS) == 0,
                 "a BATCH with no '+'/'-' prefix was not refused with 462. It must "
                 "NOT be 421: the verb exists, and 421 would tell the client this "
                 "server has never heard of it.\n  saw: %s", tc_buffer(&c));
    drain(&c);

    tc_close(&c);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 2. AN OPEN BATCH TAGS EVERY REPLY, AND CLOSING IT STOPS
 * ---------------------------------------------------------------------------
 * The core claim, in both directions, by COUNT rather than by substring: three
 * numerics inside the batch, each carrying `batch=`, and then one outside it with no
 * tag at all.
 *
 * `WHOIS` is used because on this node it is FOUR lines (311/312/317/318), so the
 * "every line inside the batch" claim is about more than one line -- a node that
 * tagged only the first would pass a one-line case. The four replies are counted
 * separately from the PONG so a node that emitted three would fail on the count.
 */
static void case_open_batch_tags(void)
{
    nf_node_t node;
    test_client_t a;
    test_client_t b;
    size_t mark;
    char want[128];

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&a);
    register_caps(&a, node.port, "bt_a", CAP_BATCH);
    tc_init(&b);
    register_caps(&b, node.port, "bt_b", CAP_BATCH);

    /* OPEN. No reply is expected and none is a failure: `BATCH +ref <type>` is the
     * client's own bookkeeping, and the specification's framing means the ANSWER to
     * it is the appearance of `batch=` on what comes next. */
    TF_CHECK_MSG(tc_send(&a, "BATCH +who1 example.com/who") == 0,
                 "BATCH + failed to send");
    drain(&a);

    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "WHOIS bt_b") == 0, "WHOIS send failed");
    /* ONE line carrying the tag is required by byte, because the tag's POSITION in
     * the block and its exact spelling are what a client parses. */
    (void)snprintf(want, sizeof want, "@batch=who1 :" SRV " 311 bt_a bt_b bt_b "
                   OBSERVED_HOST " * :Real bt_b");
    TF_CHECK_MSG(tc_expect(&a, want, T_IO_MS) == 0,
                 "the first reply inside an open batch is not `@batch=who1 :...`. "
                 "The tag goes at the front of the block and the numeric is "
                 "unchanged behind it.\n  a saw: %s", tc_buffer(&a));
    /* EVERY line, not the first. A node that tagged only the first would satisfy the
     * assertion above.
     *
     * THE COUNT IS OVER THE NUMERICS AND NOT OVER EVERY LINE IN THE WINDOW, and the
     * distinction is not tidiness: the drain PONG this helper sends is ALSO inside the
     * batch, and it must be -- "every line this node sends to a connection with a
     * batch open is inside it" has no exception for the node's own liveness probe,
     * and a PONG that escaped the batch would leave a hole in it. Counting `@... :`
     * followed by a numeric therefore says "all four replies" without having to
     * subtract the PONG or reason about it. */
    expect_only_replies(&a, mark, "WHOIS inside an open batch", 4u);
    TF_CHECK_MSG(count_since(&a, mark, "@batch=who1 :" SRV " 31") == 4u,
                 "the WHOIS produced 4 numerics and %zu of them carried "
                 "`batch=who1`. Inside an open batch EVERY line this node sends is "
                 "inside it -- a batch with holes in it is a batch a client cannot "
                 "hold.\n  a saw: %s",
                 count_since(&a, mark, "@batch=who1 :" SRV " 31"), tc_buffer(&a) + mark);

    /* CLOSE, AND THE TAGS STOP. */
    TF_CHECK_MSG(tc_send(&a, "BATCH -who1") == 0, "BATCH - failed to send");
    drain(&a);
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "WHOIS bt_b") == 0, "second WHOIS send failed");
    expect_only_replies(&a, mark, "WHOIS after the batch closed", 4u);
    TF_CHECK_MSG(count_since(&a, mark, "batch=") == 0u,
                 "%zu lines after `BATCH -who1` still carry a `batch=` tag. Closing a "
                 "batch is the client's own bookkeeping and this node answers it by "
                 "the DISAPPEARANCE of the tag -- there is no numeric, because a "
                 "numeric would be a line inside the batch about the batch.\n"
                 "  a saw: %s",
                 count_since(&a, mark, "batch="), tc_buffer(&a) + mark);

    tc_close(&a);
    tc_close(&b);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 3. `BATCH -ref` THAT DOES NOT MATCH LEAVES THE BATCH OPEN
 * ---------------------------------------------------------------------------
 * This is the assertion that a "close whatever is open" implementation fails, and the
 * failure is invisible to a client that goes on to close the right reference -- which
 * is why it is a case of its own rather than an assertion inside case 2.
 *
 * IT IS ALSO THE CASE-SENSITIVITY CLAIM, and the two are the same test because the
 * specification says the reference tag "MUST be case-sensitive" and `strcmp()` rather
 * than `strcasecmp()` is how that is enforced. `+Who1` is opened and `-who1` is sent:
 * a case-folding implementation closes the batch here, and the very next reply is
 * untagged.
 *
 * THE REFUSAL IS ANSWERED, not dropped: nothing on this line carried an `@` tag and
 * so nothing is being suppressed, which makes the window exactly TWO lines -- the
 * `462` and the drain `PONG`. Worth being explicit about, because the alternative --
 * dropping a command's own refusal because some OTHER mechanism could suppress it --
 * is §4.4's failure mode, a client unable to tell a refusal from a dropped line.
 */
static void case_close_mismatch_keeps_open(void)
{
    nf_node_t node;
    test_client_t a;
    test_client_t b;
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&a);
    register_caps(&a, node.port, "bt_a", CAP_BATCH);
    tc_init(&b);
    register_caps(&b, node.port, "bt_b", CAP_BATCH);

    TF_CHECK_MSG(tc_send(&a, "BATCH +Who1 example.com/who") == 0,
                 "BATCH + failed to send");
    drain(&a);

    /* THE MIS-CASED CLOSE. Refused, with a numeric, and the batch STAYS OPEN. */
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "BATCH -who1") == 0, "BATCH - failed to send");
    TF_CHECK_MSG(tc_expect(&a, " 462 ", T_IO_MS) == 0,
                 "a mis-cased `BATCH -who1` against an open `+Who1` was not refused. "
                 "The reference tag MUST be case-sensitive, so this names no open "
                 "batch.\n  a saw: %s", tc_buffer(&a));
    /* FOUR lines: the 462 plus 311, 312 and 318. The refusal IS sent -- nothing here
     * carried an `@` tag, so nothing is suppressed -- which is why this window can
     * assert the numeric and the tag count together. */
    expect_only_replies(&a, mark, "mis-cased BATCH -", 1u);

    /* AND THE BATCH IS STILL OPEN, which is the claim. */
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "WHOIS bt_b") == 0, "WHOIS send failed");
    expect_only_replies(&a, mark, "WHOIS after a mis-cased close", 4u);
    TF_CHECK_MSG(count_since(&a, mark, "@batch=Who1 :" SRV " 31") == 4u,
                 "%zu of the 4 lines after a mis-cased `BATCH -who1` carry the batch "
                 "tag, and it must be 4. Closing whatever is open regardless of the "
                 "name would silently discard state the connection's remaining lines "
                 "depend on -- and would make the client's own reference accounting "
                 "wrong in the one case where it is already wrong.\n  a saw: %s",
                 count_since(&a, mark, "@batch=Who1 :" SRV " 31"), tc_buffer(&a) + mark);

    /* And the RIGHT close works, which is what makes the previous assertion about a
     * mismatch rather than about a broken handler. */
    TF_CHECK_MSG(tc_send(&a, "BATCH -Who1") == 0, "BATCH -Who1 failed to send");
    drain(&a);
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "WHOIS bt_b") == 0, "third WHOIS send failed");
    expect_only_replies(&a, mark, "WHOIS after the correct close", 4u);
    TF_CHECK_MSG(count_since(&a, mark, "batch=") == 0u,
                 "the batch is still tagging after `BATCH -Who1`, the correct close. "
                 "The mis-cased close must not have left it in a state the right one "
                 "cannot fix.\n  a saw: %s", tc_buffer(&a) + mark);

    tc_close(&a);
    tc_close(&b);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 4. `+<ref>` TAGS EXACTLY ONE REPLY, AND IS THEN CONSUMED
 * ---------------------------------------------------------------------------
 * The reference tag, in the only form the modern message-tag grammar preserves:
 * `+<ref>` is a CLIENT PREFIX INSIDE the key, so the wire form is `@+ref` and the
 * parser hands batch.c a block whose first key is `+ref`.
 *
 * **WHY THERE IS NO `@<ref>` CASE, and it is a finding rather than an omission.** The
 * retired `reference-tags` specification also defined `@<ref>` as "send the response
 * nowhere". `@` is the tag-BLOCK MARKER, and `message_parse_n()` consumes exactly one
 * of them:
 *
 *     "@ref WHOIS bob"      parses, and m->tags is "ref" -- a valueless tag
 *     "@@ref WHOIS bob"     the parser REFUSES the line outright
 *
 * Both were run, not reasoned about, and there is no third spelling: making the form
 * work would mean changing what the framing layer keeps, which 3.2 owns and which
 * every peer line depends on. So the drop form is not implemented and this file says
 * so instead of pretending a capability has two halves.
 *
 * EXACTLY ONE LINE of the four-line WHOIS carries the tag, which is what a reference
 * MEANS: it names one response, not a period of time. A node that tagged all four
 * would be conflating a reference with a batch, and the two are separate mechanisms --
 * `case_open_batch_tags` is the one that tags every line.
 */
static void case_reference_tags(void)
{
    nf_node_t node;
    test_client_t a;
    test_client_t b;
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&a);
    register_caps(&a, node.port, "bt_a", CAP_BATCH);
    tc_init(&b);
    register_caps(&b, node.port, "bt_b", CAP_BATCH);

    /* `+` -- EXACTLY ONE LINE. */
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "@+keep1 WHOIS bt_b") == 0, "+tagged WHOIS failed");
    expect_only_replies(&a, mark, "+keep1 WHOIS", 4u);
    TF_CHECK_MSG(count_since(&a, mark, "@batch=keep1 :" SRV " 31") == 1u,
                 "%zu of the 4 numerics carry `@batch=keep1` and exactly 1 must. A "
                 "reference tag names ONE response, so the one-shot is consumed by the "
                 "first line and the other three are untagged -- which is what makes "
                 "it usable by a client grouping a response it has not opened a batch "
                 "for.\n  a saw: %s",
                 count_since(&a, mark, "@batch=keep1 :" SRV " 31"),
                 tc_buffer(&a) + mark);

    /* AND IT IS CONSUMED, not sticky: the next WHOIS is entirely untagged. */
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "WHOIS bt_b") == 0, "WHOIS after + failed");
    expect_only_replies(&a, mark, "WHOIS after a one-shot +", 4u);
    TF_CHECK_MSG(count_since(&a, mark, "batch=") == 0u,
                 "%zu lines after a `+keep1` reference still carry a `batch=` tag. "
                 "The reference was a one-shot: it named the response to ONE command "
                 "and was consumed by it.\n  a saw: %s",
                 count_since(&a, mark, "batch="), tc_buffer(&a) + mark);

    /* AN ILLEGAL REFERENCE IS IGNORED AND THE RESPONSE STILL ARRIVES, which is the
     * cost `batch.c`'s own header names: no numeric, because no numeric means "your
     * tag was malformed", and a LOST response would be worse than a mis-tagged one. */
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "@+bad.ref WHOIS bt_b") == 0, "bad-ref WHOIS failed");
    expect_only_replies(&a, mark, "illegal-reference WHOIS", 4u);
    TF_CHECK_MSG(count_since(&a, mark, "batch=") == 0u,
                 "%zu lines carry a `batch=` tag after a reference containing '.', "
                 "which is not in IRCv3's class. The reference is IGNORED rather than "
                 "applied, and the response is still delivered.\n  a saw: %s",
                 count_since(&a, mark, "batch="), tc_buffer(&a) + mark);

    /* AND IT DID NOT BECOME A STORED ONE, which is the half that matters: a rejected
     * reference that was nevertheless remembered would tag the NEXT command's response
     * with a batch nobody opened. */
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "WHOIS bt_b") == 0, "WHOIS after bad ref failed");
    expect_only_replies(&a, mark, "WHOIS after an illegal reference", 4u);
    TF_CHECK_MSG(count_since(&a, mark, "batch=") == 0u,
                 "%zu lines carry a `batch=` tag on the command AFTER one whose "
                 "reference was rejected, so the rejected reference was stored anyway. "
                 "An invalid reference must not become a stored one.\n  a saw: %s",
                 count_since(&a, mark, "batch="), tc_buffer(&a) + mark);

    tc_close(&a);
    tc_close(&b);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 5. THE REFUSALS, AND THE BOUNDARY
 * ---------------------------------------------------------------------------
 * `BATCH` has five refusals and they are all here, because a refusal nobody wrote a
 * case for is a refusal nobody checks:
 *
 *   two batches at once   462. The specification's client model is a flat one -- open,
 *                         send, close -- and `draft/multiline` opens ONE batch per
 *                         message group. A client wanting two concurrent groups is out
 *                         of scope and is TOLD SO rather than silently given a re-open.
 *   an illegal character  462. The class is IRCv3's -- ASCII letters, digits and '-' --
 *                         and it is checked rather than assumed.
 *   an over-long ref      417. Refused, NOT truncated: a shortened reference tag names
 *                         a batch nobody opened, and 3.2 forbids delivering a
 *                         shortened value.
 *   no type               461. A batch with no type is a batch the client cannot
 *                         interpret, and the specification lets a client IGNORE an
 *                         unknown type but not GUESS an absent one.
 *   no reference at all   461. Arity is checked before anything else, because a
 *                         `BATCH` with no reference tag is not a batch at all.
 *
 * THE BOUNDARY IS 64/65, and 64 is spelled out as a literal at the top of this file so
 * that raising CONN_MAX_BATCH_REF in connection.h breaks this line rather than
 * following it.
 */
static void case_refusals_and_bounds(void)
{
    nf_node_t node;
    test_client_t c;
    test_client_t d;
    char line[256];
    char ref[REF_AT_LIMIT + 2];
    char close[256];
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    /* A SECOND CLIENT, because a `WHOIS` of ONESELF is three lines on this node
     * (311/312/318, with no 317) and a count of four would then be a claim about the
     * wrong thing. */
    tc_init(&d);
    register_caps(&d, node.port, "bt_d", NULL);

    tc_init(&c);
    /* `standard-replies` AS WELL, and that is the point of this connection: the
     * INVALID_REFTAG refusal below is `client-batch`'s own `FAIL` code, and it reaches
     * this client BECAUSE it negotiated. A second connection further down negotiates
     * nothing and must get the legacy numeric for the same refusal. */
    register_caps(&c, node.port, "bt_r", CAP_BATCH " " CAP_STANDARD_REPLIES);

    TF_CHECK_MSG(tc_send(&c, "BATCH +one example.com/one") == 0, "BATCH + failed");
    drain(&c);

    /* TWO AT ONCE. */
    mark = tc_received(&c);
    TF_CHECK_MSG(tc_send(&c, "BATCH +two example.com/two") == 0, "second BATCH +");
    TF_CHECK_MSG(tc_expect(&c, " 462 ", T_IO_MS) == 0,
                 "a second `BATCH +` while one is open was not refused with 462. One "
                 "batch at a time is the model this node implements, and the client is "
                 "told rather than silently given a re-open.\n  c saw: %s",
                 tc_buffer(&c));
    expect_only_replies(&c, mark, "second BATCH +", 1u);

    /* AND THE FIRST BATCH SURVIVED IT -- a re-open is not a transaction this node
     * performs behind the client's back. */
    mark = tc_received(&c);
    TF_CHECK_MSG(tc_send(&c, "WHOIS bt_d") == 0, "WHOIS send failed");
    expect_only_replies(&c, mark, "WHOIS after a refused re-open", 4u);
    TF_CHECK_MSG(count_since(&c, mark, "@batch=one :" SRV " 31") == 4u,
                 "%zu lines carry `@batch=one` after a refused second `BATCH +`, and "
                 "it must be 4: the refused re-open must not have closed the batch "
                 "that was already open.\n  c saw: %s",
                 count_since(&c, mark, "@batch=one :" SRV " 31"), tc_buffer(&c) + mark);
    TF_CHECK_MSG(tc_send(&c, "BATCH -one") == 0, "BATCH -one failed");
    drain(&c);

    /* AN ILLEGAL CHARACTER, AND IT IS `client-batch`'s OWN CODE. `.` is not in
     * IRCv3's class, so this is `INVALID_REFTAG`, and the assertion is on the `FAIL`
     * because this connection negotiated `standard-replies` -- which is the per-
     * destination half of the decision, and the half a `FAIL`-everywhere
     * implementation would fail. */
    mark = tc_received(&c);
    TF_CHECK_MSG(tc_send(&c, "BATCH +bad.ref example.com/x") == 0,
                 "illegal-reference BATCH + failed");
    TF_CHECK_MSG(tc_expect(&c, "FAIL bt_r BATCH INVALID_REFTAG :Reference tag is "
                           "not acceptable\r\n", T_IO_MS) == 0,
                 "a reference tag containing '.' was not refused with "
                 "`FAIL BATCH INVALID_REFTAG`. That is `client-batch`'s own code, and "
                 "this connection negotiated standard-replies, so it must get the FAIL "
                 "rather than the legacy 417.\n  c saw: %s", tc_buffer(&c));
    expect_only_replies(&c, mark, "illegal reference", 1u);

    /* AND THE LEGACY NUMERIC FOR A CLIENT THAT NEGOTIATED NOTHING, on the same
     * refusal -- which is what makes the per-destination claim a claim rather than a
     * single observation. */
    tc_close(&c);
    tc_init(&c);
    register_caps(&c, node.port, "bt_plain", NULL);
    mark = tc_received(&c);
    TF_CHECK_MSG(tc_send(&c, "BATCH +bad.ref example.com/x") == 0,
                 "illegal-reference BATCH + failed on the plain connection");
    TF_CHECK_MSG(tc_expect(&c, " 417 ", T_IO_MS) == 0,
                 "a client that negotiated nothing did not get the legacy 417 for an "
                 "invalid reference tag. `FAIL` is a command word no such client was "
                 "ever told to expect.\n  c saw: %s", tc_buffer(&c));
    TF_CHECK_MSG(strstr(tc_buffer(&c) + mark, "FAIL") == NULL,
                 "a FAIL reached a client that negotiated nothing.\n  c saw: %s",
                 tc_buffer(&c) + mark);
    expect_only_replies(&c, mark, "illegal reference, legacy", 1u);
    tc_close(&c);
    tc_init(&c);
    register_caps(&c, node.port, "bt_r2", CAP_BATCH " " CAP_STANDARD_REPLIES);

    /* 64 IS ACCEPTED. The accepting half is here because a bound that refuses
     * everything is not a bound. */
    memset(ref, 'a', sizeof ref);
    ref[REF_AT_LIMIT] = '\0';
    (void)snprintf(line, sizeof line, "BATCH +%s example.com/len", ref);
    TF_CHECK_MSG(tc_send(&c, line) == 0, "the at-limit BATCH + failed to send");
    drain(&c);
    mark = tc_received(&c);
    TF_CHECK_MSG(tc_send(&c, "WHOIS bt_d") == 0, "WHOIS send failed");
    expect_only_replies(&c, mark, "WHOIS inside a 64-byte reference", 4u);
    TF_CHECK_MSG(count_since(&c, mark, "@batch=") == 5u,
                 "a %d-byte reference tag was refused: %zu tagged lines arrived where "
                 "4 numerics plus the drain PONG is 5. CONN_MAX_BATCH_REF is %d and it "
                 "is a CAP: a client cannot grow it.\n  c saw: %s",
                 REF_AT_LIMIT, count_since(&c, mark, "@batch="), CONN_MAX_BATCH_REF,
                 tc_buffer(&c) + mark);
    (void)snprintf(close, sizeof close, "BATCH -%s", ref);
    TF_CHECK_MSG(tc_send(&c, close) == 0, "the closing BATCH failed to send");
    drain(&c);

    /* AND 65 IS REFUSED. */
    ref[REF_AT_LIMIT] = 'b';
    ref[REF_AT_LIMIT + 1u] = '\0';
    (void)snprintf(line, sizeof line, "BATCH +%s example.com/len", ref);
    mark = tc_received(&c);
    TF_CHECK_MSG(tc_send(&c, line) == 0, "the over-long BATCH + failed to send");
    /* 65 IS REFUSED, and it is the SAME refusal as an illegal character rather than a
     * fourth kind: `batch_ref_valid()` answers 0 for both, so both are
     * `INVALID_REFTAG`, and a client that gets `417` here and `FAIL ... INVALID_REFTAG`
     * there for the same predicate would be reading one condition out of two answers.
     *
     * IT IS A REFUSAL AND NOT A TRUNCATION, and the difference is the whole point: a
     * shortened reference tag names a batch nobody opened, and 3.2 forbids delivering a
     * shortened value. That is also the assertion the FIRST version of `reply.c` could
     * not have passed -- it sized its tag buffer at `CONN_MAX_BATCH_REF + 1` and
     * silently dropped the tag for the 64-byte case, which this file's boundary case
     * is here to catch. */
    TF_CHECK_MSG(tc_expect(&c, "FAIL bt_r2 BATCH INVALID_REFTAG :Reference tag is not "
                           "acceptable\r\n", T_IO_MS) == 0,
                 "a %d-byte reference tag was ACCEPTED. It must be refused: a "
                 "shortened reference tag names a batch nobody opened, and 3.2 forbids "
                 "delivering a shortened value.\n  c saw: %s",
                 REF_AT_LIMIT + 1, tc_buffer(&c));
    expect_only_replies(&c, mark, "over-long reference", 1u);

    /* NO TYPE. */
    mark = tc_received(&c);
    TF_CHECK_MSG(tc_send(&c, "BATCH +notype") == 0, "typeless BATCH + failed");
    TF_CHECK_MSG(tc_expect(&c, "FAIL bt_r2 BATCH NEED_MORE_PARAMS :Not enough "
                           "parameters\r\n", T_IO_MS) == 0,
                 "a `BATCH +ref` with no type was not refused with NEED_MORE_PARAMS. "
                 "The grammar is `BATCH +reference-tag type`, and a client may ignore "
                 "an UNKNOWN type but not guess an absent one -- which is exactly why "
                 "this is 461 and not UNKNOWN_TYPE.\n  c saw: %s", tc_buffer(&c));
    expect_only_replies(&c, mark, "typeless BATCH +", 1u);

    /* AND ARITY: no reference at all. */
    mark = tc_received(&c);
    TF_CHECK_MSG(tc_send(&c, "BATCH") == 0, "argument-less BATCH failed");
    TF_CHECK_MSG(tc_expect(&c, "FAIL bt_r2 BATCH NEED_MORE_PARAMS :Not enough "
                           "parameters\r\n", T_IO_MS) == 0,
                 "a bare `BATCH` was not refused with NEED_MORE_PARAMS.\n  c saw: %s",
                 tc_buffer(&c));
    expect_only_replies(&c, mark, "bare BATCH", 1u);

    tc_close(&c);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 6. THE STATE IS PER CONNECTION, AND IT OUTLIVES THE MESSAGE
 * ---------------------------------------------------------------------------
 * The obvious way to get a per-connection feature wrong is to make it per NODE, and
 * the symptom -- one client seeing another client's batch tag -- is the kind of thing a
 * single-connection test cannot produce at all. Two connections, one batch open on one
 * of them, and a claim about the other.
 *
 * It is also where the LIFETIME claim lives for this module, in the only form a wire
 * test can make: the reference is stored on the connection and read back out across a
 * `WHOIS` four lines later. `m->params[0]` points into the `message_t`'s own heap and
 * the connection outlives the message by an enormous margin -- a client can hold a
 * batch open for hours -- so a stored POINTER is a use-after-free. The fixed-size
 * `conn_t::batch_ref` is what prevents it, and the tag still being correct three
 * commands later is the observable half. The other half is the ASan run, and that is
 * recorded at the TEETH block as a claim about the sanitizer rather than as a test.
 */
static void case_state_is_per_connection(void)
{
    nf_node_t node;
    test_client_t a;
    test_client_t b;
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&a);
    register_caps(&a, node.port, "bt_a", CAP_BATCH);
    tc_init(&b);
    register_caps(&b, node.port, "bt_b", CAP_BATCH);

    TF_CHECK_MSG(tc_send(&a, "BATCH +mine example.com/mine") == 0, "BATCH + failed");
    drain(&a);

    /* B HAS NOTHING OPEN. */
    mark = tc_received(&b);
    TF_CHECK_MSG(tc_send(&b, "WHOIS bt_a") == 0, "b WHOIS send failed");
    expect_only_replies(&b, mark, "b's WHOIS while a has a batch open", 4u);
    TF_CHECK_MSG(count_since(&b, mark, "batch=") == 0u,
                 "%zu of b's lines carry a `batch=` tag while only a has a batch "
                 "open. The batch state is on the CONNECTION -- four fixed-size "
                 "fields in conn_t, zeroed by conn_new() and freed with the struct -- "
                 "so no connection can see another's.\n  b saw: %s",
                 count_since(&b, mark, "batch="), tc_buffer(&b) + mark);

    /* A STILL DOES, several commands later. */
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "WHOIS bt_b") == 0, "a WHOIS send failed");
    expect_only_replies(&a, mark, "a's WHOIS with its batch open", 4u);
    TF_CHECK_MSG(count_since(&a, mark, "@batch=mine :" SRV " 31") == 4u,
                 "%zu of a's lines carry `@batch=mine` and it must be 4. The open "
                 "batch survived another client's traffic, which is what per-"
                 "connection state means.\n  a saw: %s",
                 count_since(&a, mark, "@batch=mine :" SRV " 31"), tc_buffer(&a) + mark);

    tc_close(&a);
    tc_close(&b);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 7. NO NESTING
 * ---------------------------------------------------------------------------
 * `client-batch`: "clients may not send BATCH commands with a batch tag." That is the
 * whole of its no-nesting rule, and it is enforced here rather than ignored, because
 * every piece of per-connection batch state on this node is a FLAT single open batch: a
 * nested `BATCH +` would overwrite `conn_t::batch_ref` and every subsequent line would be
 * tagged with the INNER reference while the client still believed the OUTER one was open.
 *
 * **THE CASE IS SPLIT IN TWO, AND THE FIRST HALF IS THE ONE WITH TEETH.** The obvious
 * shape -- open a batch, then try to nest inside it -- does not discriminate: a
 * nested `BATCH +` is refused anyway by the one-batch-at-a-time rule, so a node with the
 * nesting check DELETED produces the same `462` and the same line count, and the test
 * went green on the fault the first time it was run. (Build checked at 0/0 first, and
 * the fault is recorded at the TEETH block rather than quietly replaced.)
 *
 * So the discriminating case is a `BATCH` carrying a `batch=` tag on a connection with
 * **nothing open**: there the one-batch rule cannot fire, so the only thing that can
 * refuse it is the nesting check, and the observable is that **no batch is opened**.
 */
static void case_no_nesting(void)
{
    nf_node_t node;
    test_client_t a;
    test_client_t d;
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&a);
    register_caps(&a, node.port, "bt_a", CAP_BATCH);
    tc_init(&d);
    register_caps(&d, node.port, "bt_d", NULL);

    /* ---- HALF ONE: nothing open, so only the nesting check can refuse this. ---- */
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "@batch=ghost BATCH +inner example.com/inner") == 0,
                 "the tagged BATCH + failed to send");
    TF_CHECK_MSG(tc_expect(&a, " 462 ", T_IO_MS) == 0,
                 "a `BATCH` command carrying a `batch=` tag was not refused on a "
                 "connection with no batch open. There is nothing else that could "
                 "have refused it -- the one-batch-at-a-time rule cannot fire -- so this "
                 "is the no-nesting rule and nothing else.\n  a saw: %s",
                 tc_buffer(&a));
    expect_only_replies(&a, mark, "BATCH + with a batch= tag and nothing open", 1u);

    /* AND NO BATCH WAS OPENED. This is the half that cannot be satisfied by a refusal
     * for some other reason: a node that answered 462 and opened the batch anyway
     * would produce the same numeric and a client would see its lines tagged with a
     * batch it was told did not exist. */
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "WHOIS bt_d") == 0, "WHOIS send failed");
    expect_only_replies(&a, mark, "WHOIS after a refused tagged BATCH +", 4u);
    TF_CHECK_MSG(count_since(&a, mark, "batch=") == 0u,
                 "%zu lines carry a `batch=` tag after a refused `BATCH` carrying one, "
                 "so the batch was opened anyway. The refusal has to leave the state "
                 "exactly as it was -- `test_close_mismatch_keeps_open` asserts the same "
                 "property for a mismatched close, and it is the same property.\n"
                 "  a saw: %s", count_since(&a, mark, "batch="), tc_buffer(&a) + mark);

    /* ---- HALF TWO: with a batch open, the OUTER one must survive. ---- */
    TF_CHECK_MSG(tc_send(&a, "BATCH +outer example.com/outer") == 0,
                 "the outer BATCH + failed to send");
    drain(&a);
    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "@batch=outer BATCH +inner example.com/inner") == 0,
                 "the nested BATCH + failed to send");
    TF_CHECK_MSG(tc_expect(&a, " 462 ", T_IO_MS) == 0,
                 "the nested `BATCH +` was not refused.\n  a saw: %s", tc_buffer(&a));
    expect_only_replies(&a, mark, "nested BATCH +", 1u);

    mark = tc_received(&a);
    TF_CHECK_MSG(tc_send(&a, "WHOIS bt_d") == 0, "WHOIS send failed");
    expect_only_replies(&a, mark, "WHOIS after a refused nested open", 4u);
    TF_CHECK_MSG(count_since(&a, mark, "@batch=outer :" SRV " 31") == 4u,
                 "%zu of 4 numerics carry `@batch=outer` after a refused nested open, "
                 "and it must be 4: the refusal must not have disturbed the batch that "
                 "was already open.\n  a saw: %s",
                 count_since(&a, mark, "@batch=outer :" SRV " 31"),
                 tc_buffer(&a) + mark);
    TF_CHECK_MSG(count_since(&a, mark, "@batch=inner") == 0u,
                 "a line carries `@batch=inner`, so the nested reference was stored "
                 "anywhere. It must not be: the inner batch was refused.\n  a saw: %s",
                 tc_buffer(&a) + mark);

    tc_close(&a);
    tc_close(&d);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * TEETH, AND WHERE THEY WERE INJECTED
 * ---------------------------------------------------------------------------
 * Each was watched go red with the behaviour broken, and the BUILD was checked
 * before the run was believed -- an uncompilable fault leaves the previous binary in
 * place and reports a pass, which has happened in this repo ten times.
 *
 *   `BATCH -ref` CLOSES WHATEVER IS OPEN -- batch.c: the mismatched-close branch's
 *       condition replaced by a constant false. **Build 0/0, red at case 3's `462`
 *       assertion** -- the mis-cased close is now answered rather than acted on, which
 *       is the first of case 3's two claims. This is the highest-value fault in the
 *       file because a lenient close is exactly what a client cannot detect until a
 *       later line arrives untagged.
 *
 *   THE TAG BUFFER UNDER-SIZED AT THE BOUNDARY -- reply.c: `bref` from
 *       `BATCH_TAG_MAX` back to `CONN_MAX_BATCH_REF + 1`. **Build 0/0, red at case 5's
 *       64-byte case** (0 tagged lines where 5 are required). This fault is the SECOND
 *       version of a defect the code actually shipped in its first form, and it is
 *       recorded here as the reason `BATCH_TAG_MAX` exists rather than as a
 *       hypothetical.
 *
 *   NESTING NOT REFUSED -- batch.c: `batch_line_tagged_inbound()`'s condition replaced
 *       by a constant false. **Build 0/0, and the FIRST version of this fault was
 *       GREEN**, which is the interesting part: the obvious shape of the case -- open a
 *       batch, then nest inside it -- cannot see it, because a nested `BATCH +` is
 *       refused by the one-batch-at-a-time rule anyway and the numeric and the line
 *       count come out identical. The case was rewritten to send the tagged `BATCH` on a
 *       connection with NOTHING open, where nothing else can refuse it and the
 *       observable is that no batch was opened; re-run, **red at case 7's `462`**. A
 *       fault that builds, changes something, and is still invisible is the harder of
 *       the two traps and both are written down.
 *
 *   AN INVALID REFERENCE STORED ANYWAY -- batch.c: the `return` after the
 *       `batch_ref_refused:` log line deleted. **Build 0/0, red at case 4** (1 tagged
 *       line where 0 are required). It is the fault that proves "ignored" means ignored
 *       rather than "logged and used".
 *
 *   THE REFERENCE STORED AS A POINTER -- batch.c: the two `memcpy`s in `handle_batch()`
 *       replaced by a `strdup` freed on close, which is the obvious "optimisation" of a
 *       fixed field. **INVISIBLE WITHOUT ASan**: the test still passes, because the
 *       freed bytes still hold the right string. That is the whole reason the field is a
 *       fixed array rather than a pointer, and it is recorded here as a claim about the
 *       sanitizer run rather than as a passing test.
 */
int main(void)
{
    case_advertised_and_verb_exists();
    case_open_batch_tags();
    case_close_mismatch_keeps_open();
    case_reference_tags();
    case_refusals_and_bounds();
    case_state_is_per_connection();
    case_no_nesting();

    tf_done("batch");
    return 0;
}
