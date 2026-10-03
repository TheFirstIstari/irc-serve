/* test_chghost.c -- the `chghost` capability, asserted ABSENT, and why.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE ASSERTS AN ABSENCE AND CALLS IT THE DELIVERABLE
 * ---------------------------------------------------------------------------
 * `chghost` says: when a client username or host is changed, servers MUST send
 *
 *     :nick!old_user@old_host CHGHOST new_user new_host
 *
 * to other clients who share channels with the target AND who have enabled the
 * capability. So there are three things to establish, and only the first is a
 * feature:
 *
 *   1. THE VERB. Is there a `CHGHOST` on this node to send? `k_commands[]` has no
 *      row for it, so a client that sends one gets `421`.
 *   2. THE EVENT. Can a username or host change at all after registration? For the
 *      HOST: no -- `describe_peer()` at accept is its only writer, and
 *      `resume.c` *requires* (nick, ident, host) to match to resume, so a resume
 *      refuses rather than applying a new identity. For the IDENT: **yes**, and
 *      this is the finding. `handle_user()` writes `conn_t::user` unconditionally,
 *      and `USER` is a pre-registration verb that the dispatch table still routes
 *      for a REGISTERED connection, so a client may re-send `USER` and change its
 *      own ident at will.
 *   3. THE NOTIFICATION. Nothing tells anybody. The re-sent `USER` produces no
 *      server-to-client line, and no other client's view of the roster changes --
 *      which is exactly the gap `chghost` exists to close.
 *
 * So the capability is NOT advertised, and the reason is not the tidy one. It is
 * not "nothing on this node can change" -- an ident CAN change. It is that the one
 * thing which changes is not supposed to be able to, which is a defect recorded
 * below rather than a feature to notify about.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS DELIBERATELY NOT HERE
 * ---------------------------------------------------------------------------
 * **No way to change a host was invented.** `WEBIRC`/`spoofing` is the territory a
 * host change belongs to, it is a security decision, and it is a different phase.
 * Adding a verb that moves `conn_t::host` so that a `CHGHOST` notification would
 * have something to report would be inventing a spoofing surface to satisfy a
 * specification, which is worse than the absence.
 *
 * **The `USER`-after-registration hole is REPORTED, not closed.** Refusing a second
 * `USER` is a behaviour change to an RFC 1459 MUST command with nothing in the RFC
 * requiring it, so it is not this file's decision to take. What this file does is
 * make the hole **provable**, so a future phase that closes it has a test to remove
 * rather than a claim to re-derive.
 *
 * NO FIXED sleep() ANYWHERE (6.3): every wait is tc_expect()'s deadline loop and
 * every window is closed by a PING whose PONG is the drain token, numbered per
 * call because tc_expect() searches the ACCUMULATED buffer and a reused token would
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

#define SRV "irc.test"

/* The observed host, which is the `<host>` half of everything `chghost` would have
 * reported. `USER`'s third parameter is `*spoofed.example` on every connection in
 * this file, so a node that stored the assertion instead of what accept() saw fails
 * every 311 below. §2.1 makes that deliberate: 2.1 records the OBSERVED address. */
#define OBSERVED_HOST "127.0.0.1"

static unsigned g_drain_seq;

static void drain(test_client_t *c)
{
    char token[64];
    char line[128];

    (void)snprintf(token, sizeof token, "cg%u", g_drain_seq++);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING failed");
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG for drain token %s, so the buffer is not yet drained and "
                 "every claim below would be about the read schedule", token);
}

/* Register `c` as `nick`, negotiating `caps` first (NULL for no CAP exchange). */
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
                     "capability and the case below would be asserting the wrong "
                     "thing about it", nick, caps);
    }
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s NICK send failed", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed.example :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s USER send failed", nick);
    if (caps != NULL) {
        TF_CHECK_MSG(tc_send(c, "CAP END") == 0, "%s CAP END send failed", nick);
    }
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered", nick);
    /* The welcome carries `nick!user@host`, so asserting it here means every
     * expectation below starts from a known identity rather than from whatever
     * USER happened to store. */
    {
        char want[160];

        (void)snprintf(want, sizeof want, "001 %s :Welcome to the irc-serve network "
                     "%s!%s@" OBSERVED_HOST "\r\n", nick, nick, nick);
        TF_CHECK_MSG(tc_expect(c, want, T_IO_MS) == 0,
                     "%s's 001 does not carry the host this node OBSERVED. Every "
                     "`chghost` claim in this file is about an identity nobody can "
                     "move, and USER's third parameter is how a client tries.\n"
                     "  expected: %s\n  saw: %s", nick, want, tc_buffer(c));
    }
    drain(c);
}

/* How many complete CRLF-terminated lines the region `from`..end of `c` holds. */
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

/* Assert that `c` received EXACTLY `n_replies` replies after `mark`, and nothing
 * else -- the last line in the window being its drain PONG.
 *
 * THIS IS THE "NOTHING ELSE WAS TOLD" ASSERTION, and it is a COUNT rather than a
 * list of absent verbs: a notification whose name nobody thought of would satisfy
 * a list, and the whole claim in this file is that there is NO notification of any
 * shape. `n_replies` is counted ALONG WITH the PONG, so a case that expects one
 * reply passes 1 and a case that expects none passes 0; getting that backwards
 * fails the test rather than passing quietly. */
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

/* ---------------------------------------------------------------------------
 * 1. THE CAPABILITY IS ABSENT
 * ---------------------------------------------------------------------------
 * `cap.h`'s rule is that `CAP LS` lists implementations, and an advertised
 * capability this node cannot honour is worse than an absent one: it is a client
 * that switches a feature on and then behaves as though the node agreed. So the
 * absence is asserted positively -- the name is not in the list, AND the
 * capabilities that ARE there are, so a `CAP LS` that had stopped answering at all
 * cannot satisfy this by returning nothing. */
static void case_not_advertised(void)
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
    TF_CHECK_MSG(strstr(tc_buffer(&c), "CHGHOST") == NULL,
                 "CAP LS advertises chghost. This node has no CHGHOST verb to send "
                 "with -- `CHGHOST` from a client is answered 421 -- so a client that "
                 "negotiated this would be waiting for a message nothing can produce.");
    TF_CHECK_MSG(strstr(tc_buffer(&c), CAP_ECHO_MESSAGE) != NULL &&
                 strstr(tc_buffer(&c), CAP_STANDARD_REPLIES) != NULL,
                 "CAP LS does not advertise the capabilities this node DOES "
                 "implement (%s, %s), so the absence of chghost above is not a "
                 "CAP LS that returned nothing.\n  CAP LS read: %s",
                 CAP_ECHO_MESSAGE, CAP_STANDARD_REPLIES, tc_buffer(&c));
    /* AND IT CANNOT BE NEGOTIATED, which is the difference between an absent name
     * and an unknown one: a client that asks anyway gets NAKed, so it learns from
     * the node rather than from a timeout. */
    TF_CHECK_MSG(tc_send(&c, "CAP REQ :chghost") == 0, "CAP REQ send failed");
    TF_CHECK_MSG(tc_expect(&c, " CAP * NAK :chghost\r\n", T_IO_MS) == 0,
                 "a CAP REQ for chghost was not NAKed. An unknown capability is "
                 "NAKed rather than ignored, so the client knows.\n  saw: %s",
                 tc_buffer(&c));
    tc_close(&c);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 2. THERE IS NO VERB TO SEND IT WITH
 * ---------------------------------------------------------------------------
 * The specification's message is `:nick!old_user@old_host CHGHOST new_user
 * new_host`. A client cannot ask for it and a client cannot send it, because the
 * dispatch table has no row: `421` is the honest answer and is the one this node
 * gives. */
static void case_no_verb(void)
{
    nf_node_t node;
    test_client_t c;
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&c);
    register_caps(&c, node.port, "verbtest", CAP_STANDARD_REPLIES);

    mark = tc_received(&c);
    TF_CHECK_MSG(tc_send(&c, "CHGHOST newuser new.example") == 0, "send failed");
    TF_CHECK_MSG(tc_expect(&c, ":" SRV " 421 verbtest CHGHOST :Unknown command\r\n",
                           T_IO_MS) == 0,
                 "a client CHGHOST was not answered 421. The specification defines "
                 "the message as something a SERVER sends; this node has no verb "
                 "that would produce it, and 421 is the answer rather than silence "
                 "so a client waiting for a notification learns that there will be "
                 "none.\n  saw: %s", tc_buffer(&c));
    /* AND IT IS NOT MIGRATED, which is worth asserting rather than assumed: 421 is
     * not one of the four numerics `standard-replies` moves, because it answers
     * exactly one question on this node. */
    expect_only_replies(&c, mark, "chghost-verb", 1u);

    tc_close(&c);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 3. THE EVENT: THE HOST CANNOT MOVE, AND THE IDENT CAN
 * ---------------------------------------------------------------------------
 * Both halves, on the wire, and both from a SECOND client's view -- which is the
 * view `chghost` exists to inform. */
static void case_the_event(void)
{
    nf_node_t node;
    test_client_t alice;
    test_client_t bob;
    char line[256];
    size_t mark_a;
    size_t mark_b;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&alice);
    register_caps(&alice, node.port, "alice", NULL);
    tc_init(&bob);
    register_caps(&bob, node.port, "bob", CAP_STANDARD_REPLIES);

    /* ---- THE HOST. `USER`'s third parameter is how a client tries to move it,
     * and it is ignored: §2.1 records what accept() observed. So the host in a
     * 311 is the loopback address however the client spelled it. ---- */
    mark_b = tc_received(&bob);
    TF_CHECK_MSG(tc_send(&bob, "WHOIS alice") == 0, "bob WHOIS send failed");
    TF_CHECK_MSG(tc_expect(&bob, ":" SRV " 311 bob alice alice " OBSERVED_HOST
                           " * :Real alice\r\n",
                           T_IO_MS) == 0,
                 "the 311 does not carry the OBSERVED host. USER sent "
                 "*spoofed.example as its third parameter and it must not appear "
                 "here: a host a client asserts is a host it chose.\n  bob saw: %s",
                 tc_buffer(&bob));
    drain(&bob);

    /* ---- THE IDENT. `USER` is a pre-registration verb, and the dispatch table
     * still routes it for a REGISTERED connection, so this is accepted -- and
     * `handle_user()` writes `conn_t::user` unconditionally. ----
     *
     * THE ASSERTION IS TWO-SIDED AND BOTH SIDES MATTER. That the ident changed is
     * the finding; that NOTHING was said about it is the reason the capability
     * cannot be advertised. A test that asserted only the change would pass on a
     * node that notified everybody, which is a different deliverable entirely. */
    (void)snprintf(line, sizeof line, "USER mallory 0 *spoofed.example :Real alice");
    mark_a = tc_received(&alice);
    mark_b = tc_received(&bob);
    TF_CHECK_MSG(tc_send(&alice, line) == 0, "the re-sent USER failed to send");

    /* BOB'S WINDOW IS CHECKED FIRST AND HE HAS SENT NOTHING, and that ordering IS
     * the assertion. Bob is idle on the socket while alice changes her ident, so
     * every byte he receives in this window arrived because of the change -- which
     * makes "zero lines" a statement about the NOTIFICATION rather than about the
     * read schedule. Bob negotiated `standard-replies`, so even the notification
     * family this node does implement would have reached him, and nothing did. */
    expect_only_replies(&bob, mark_b, "bob while alice's ident changed", 0u);
    TF_CHECK_MSG(strstr(tc_buffer(&bob) + mark_b, "CHGHOST") == NULL,
                 "a CHGHOST line reached bob. This node emits none -- there is no "
                 "emitter for it anywhere in src/ -- so if this fires the node has "
                 "grown a verb whose trigger it does not otherwise have.\n"
                 "  bob saw: %s", tc_buffer(&bob) + mark_b);

    /* And the re-sent USER answers NOTHING at all -- not a numeric, not a
     * server-to-client line. `USER`'s confirmation is its absence, where
     * `setname`'s is a line, so a client gets silence either way. */
    expect_only_replies(&alice, mark_a, "re-sent USER", 0u);

    /* NOW the change is visible -- but only to somebody who goes and looks. Bob
     * asks, and the 311 carries the new ident. */
    mark_b = tc_received(&bob);
    TF_CHECK_MSG(tc_send(&bob, "WHOIS alice") == 0, "bob WHOIS send failed");
    TF_CHECK_MSG(tc_expect(&bob, ":" SRV " 311 bob alice mallory " OBSERVED_HOST
                           " * :Real alice\r\n", T_IO_MS) == 0,
                 "the ident did NOT change after a re-sent USER. That would be the "
                 "other honest answer -- `USER` refused once registered -- and it is "
                 "NOT what this node does: `handle_user()` writes `conn_t::user` "
                 "unconditionally and `USER` is `pre_reg`, so the dispatch table "
                 "routes it for a registered connection. If this assertion starts "
                 "failing, the hole was closed and §9's risk row is stale.\n"
                 "  bob saw: %s", tc_buffer(&bob));
    /* 312, 317 and 318 follow it: a `WHOIS` is four lines and this node says so. */
    expect_only_replies(&bob, mark_b, "bob's WHOIS of alice", 4u);

    /* AND THE NODE SAID NOTHING ABOUT IT EITHER, which is the half an operator
     * would want. `handle_user()` prints its `user:` line, so the change IS
     * visible on the node's own output -- the point is that it is a LOG LINE and
     * not a notification to a client. */
    TF_CHECK_MSG(strstr(node.out, "user=mallory") != NULL,
                 "the node's own output does not record the ident change either, so "
                 "the hole would be invisible from both sides. `handle_user()` prints "
                 "a `user:` line for every USER it accepts.\n  node output:\n%s",
                 node.out);

    tc_close(&alice);
    tc_close(&bob);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * TEETH, AND WHERE THEY WERE INJECTED
 * ---------------------------------------------------------------------------
 * Each was watched go red with the behaviour broken, and the BUILD was checked
 * before the run was believed -- an uncompilable fault leaves the previous binary
 * in place and reports a pass, which has happened in this repo seven times.
 *
 *   `chghost` ADVERTISED -- cap.c: the `{ CAP_CHGHOST, CAPBIT_CHGHOST }` row added
 *       to k_caps[] with a fresh bit. Fails the absence assertion and the `CAP LS`
 *       sanity check, and it is the fault with teeth: a client that negotiated a
 *       capability nothing can honour waits for a `CHGHOST` that will never come,
 *       which cap.h calls "a client that switches the feature on and then behaves
 *       as though the node agreed".
 *
 *   a `CHGHOST` EMITTER INVENTED -- commands.c: `handle_chghost()` added to
 *       k_commands[] so `CHGHOST` from a client echoes. Fails the 421 case only,
 *       which is the point of having one: it is the assertion that says the verb
 *       does not exist, and it is the assertion a future phase would have to
 *       remove.
 *
 *   THE IDENT CHANGE SILENTLY NOTIFIED -- chan_verbs.c or commands.c: a `send_line`
 *       added to the `handle_user()` path so the change is reported. Fails
 *       `expect_only_the_pong()` on BOTH connections -- and that is the assertion
 *       that makes this file's finding precise rather than a complaint. A node that
 *       notified would be a node where `chghost` is implementable; this one is not,
 *       and the difference is visible here.
 */
int main(void)
{
    case_not_advertised();
    case_no_verb();
    case_the_event();

    tf_done("chghost");
    return 0;
}
