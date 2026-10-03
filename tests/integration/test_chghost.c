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
 *      refuses rather than applying a new identity. For the IDENT: **no either**,
 *      and getting there is what Phase 10.10 did. `handle_user()` used to write
 *      `conn_t::user` unconditionally, and `USER` is a pre-registration verb that
 *      the dispatch table still routed for a REGISTERED connection, so a client
 *      could re-send `USER` and change its own ident at will with no line to
 *      anyone. That hole is CLOSED: a second `USER` is `462` and the write does
 *      not happen.
 *   3. THE NOTIFICATION. Nothing tells anybody, because nothing happens. The
 *      re-sent `USER` produces no state change, so there is nothing for a
 *      `CHGHOST` to report.
 *
 * So the capability is NOT advertised, and after Phase 10.10 the reason is the
 * tidy one Phase 10.8 could not reach: **nothing this node shows a third party
 * about a user can change.** A host is fixed at accept(); an ident is fixed at
 * registration and a second `USER` is `462`; a realname moves only through
 * `SETNAME`, which is Phase 10.6's own notification.
 *
 * ---------------------------------------------------------------------------
 * WHAT CHANGED IN PHASE 10.10, AND WHY INVERTING THE CASE WAS RIGHT
 * ---------------------------------------------------------------------------
 * Case 3 below USED TO assert the hole: that the ident changed, and that a
 * **zero line count** on a second connection's socket while it did. That was a
 * change-detection test for an open defect, written so a future phase would have
 * something to remove rather than a claim to re-derive -- and Phase 10.10 is
 * that future phase. It was **inverted, not deleted**: the case still runs the
 * same sequence, still asserts the same zero-line count for the same reason, and
 * now requires the ident to be UNCHANGED, the sender to be refused `462`, and the
 * node's own output to record a refusal rather than a write.
 *
 * Two of those three new assertions are the load-bearing ones, and neither
 * existed before:
 *
 *   - the 462 has to be the RFC's OWN numeric. RFC 2812 3.1.3 lists
 *     `ERR_ALREADYREGISTRED` among `USER`'s replies and RFC 2812 9 names the
 *     case ("user details from second USER message"), so a node answering
 *     something else would be answering a question the RFC already answered.
 *   - the refusal must be **per destination**: a client that negotiated
 *     `standard-replies` must still receive the byte-identical `462`, because
 *     4.4.3's rule migrates a numeric only where it answers more than one
 *     question on this node and 462 answers exactly one. A node that migrated it
 *     would have taken away the number a client already handles for no gain.
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
 * **The pre-registration double `USER` still works**, and that is not an
 * oversight: the gate is `commands_registered()`, so a client that sends `USER`
 * twice before it has been answered `001` is registering, and last-one-wins is
 * what every client library expects. Case 4 asserts it, because "the second USER
 * is refused" and "the second USER is honoured" are both true on this node and
 * only the boundary between them is the fix.
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
 * 3. THE EVENT: NEITHER THE HOST NOR THE IDENT CAN MOVE
 * ---------------------------------------------------------------------------
 * Both halves, on the wire, and both from a SECOND client's view -- which is the
 * view `chghost` exists to inform. This case is the INVERTION of Phase 10.8's:
 * it runs the identical sequence and asserts that the ident did NOT move, that
 * the sender was told, and that nothing at all was said to anybody else.
 */
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
     * routes it for a REGISTERED connection too -- which is the whole of how the
     * hole was reachable. It is now refused, and refused with the RFC's own
     * numeric. ----
     *
     * THE ASSERTION IS TWO-SIDED AND BOTH SIDES MATTER. That the ident is
     * UNCHANGED is the fix; that the client is TOLD is what makes it a refusal
     * rather than a drop. A test that asserted only the silence would pass on a
     * node that simply ignored the command, and a node that ignored it is a
     * different defect: RFC 2812 3.1.3 names 462 as one of `USER`'s two numeric
     * replies, so silence would be a node declining to answer a question the RFC
     * answers. */
    (void)snprintf(line, sizeof line, "USER mallory 0 *spoofed.example :Real alice");
    mark_a = tc_received(&alice);
    mark_b = tc_received(&bob);
    TF_CHECK_MSG(tc_send(&alice, line) == 0, "the re-sent USER failed to send");

    /* BOB'S WINDOW IS CHECKED FIRST AND HE HAS SENT NOTHING, and that ordering IS
     * the assertion. Bob is idle on the socket while alice sends a second USER, so
     * every byte he receives in this window arrived because of the command -- which
     * makes "zero lines" a statement about the NOTIFICATION rather than about the
     * read schedule. Bob negotiated `standard-replies`, so even the notification
     * family this node does implement would have reached him, and nothing did. */
    expect_only_replies(&bob, mark_b, "bob while alice's second USER was refused", 0u);
    TF_CHECK_MSG(strstr(tc_buffer(&bob) + mark_b, "CHGHOST") == NULL,
                 "a CHGHOST line reached bob. This node emits none -- there is no "
                 "emitter for it anywhere in src/ -- so if this fires the node has "
                 "grown a verb whose trigger it does not otherwise have.\n"
                 "  bob saw: %s", tc_buffer(&bob) + mark_b);

    /* AND THE SENDER IS TOLD, exactly once, with 462 and not with a `FAIL` --
     * because alice negotiated nothing, so 4.4.3's one question puts her on the
     * legacy branch. The COUNT is what makes this a refusal and not a flood. */
    TF_CHECK_MSG(tc_expect(&alice, ":" SRV " 462 alice :Unauthorized command "
                           "(already registered)\r\n", T_IO_MS) == 0,
                 "the second USER was not refused with 462. RFC 2812 3.1.3 lists "
                 "ERR_ALREADYREGISTRED among USER's numeric replies and RFC 2812 9 "
                 "names the case -- \"user details from second USER message\" -- so "
                 "this node's answer should be the RFC's own numeric and not silence "
                 "and not a number of its own.\n  alice saw: %s", tc_buffer(&alice));
    expect_only_replies(&alice, mark_a, "second USER", 1u);
    TF_CHECK_MSG(strstr(tc_buffer(&alice) + mark_a, "FAIL") == NULL,
                 "a FAIL reached a client that negotiated nothing. 462 answers "
                 "exactly one question on this node -- \"you are already "
                 "registered\" -- so 4.4.3's migration rule keeps it legacy, and "
                 "FAIL is a command word no such client was ever told to expect.\n"
                 "  alice saw: %s", tc_buffer(&alice) + mark_a);

    /* NOW ask again -- and the ident is STILL the one the client sent at
     * registration. This is the assertion that is the inverse of the old one: it
     * used to read `mallory` here and carried a comment saying that if it ever
     * started failing, the hole had been closed. It has been closed, so the
     * expectation is `alice` and the comment above is what a reader needs. */
    mark_b = tc_received(&bob);
    TF_CHECK_MSG(tc_send(&bob, "WHOIS alice") == 0, "bob WHOIS send failed");
    TF_CHECK_MSG(tc_expect(&bob, ":" SRV " 311 bob alice alice " OBSERVED_HOST
                           " * :Real alice\r\n", T_IO_MS) == 0,
                  "the ident CHANGED after a second USER. `handle_user()` refuses a "
                  "second USER once `commands_registered(c)` and returns before the "
                  "write to `conn_t::user`, so the ident a client shows every roster "
                  "on this node is the one it sent at registration and cannot be "
                  "moved afterwards.\n  bob saw: %s", tc_buffer(&bob));
    /* 312, 317 and 318 follow it: a `WHOIS` is four lines and this node says so. */
    expect_only_replies(&bob, mark_b, "bob's WHOIS of alice", 4u);

    /* AND THE NODE'S OWN OUTPUT RECORDS A REFUSAL, NOT A WRITE. The old case
     * asserted `user=mallory` was present -- that was the hole being provable from
     * the operator's side. The inversion is that the refusal is there and the
     * write is NOT, because a node that logged `user=mallory` while refusing would
     * be telling an operator something that did not happen. */
    TF_CHECK_MSG(strstr(node.out, "reason=ALREADY_REGISTERED") != NULL,
                 "the node's own output does not record the refusal. "
                 "`handle_user()` prints a `user_refused:` line with "
                 "reason=ALREADY_REGISTERED, so a log reader can see that a client "
                 "tried and was stopped.\n  node output:\n%s", node.out);
    TF_CHECK_MSG(strstr(node.out, "user=mallory") == NULL,
                 "the node logged `user=mallory`, so the ident was WRITTEN as well as "
                 "refused. The gate returns before `copy_field()`, so a node that "
                 "both refuses and writes is a node whose log lies to the operator "
                 "reading it.\n  node output:\n%s", node.out);

    tc_close(&alice);
    tc_close(&bob);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 4. THE SAME REFUSAL FOR A CLIENT THAT NEGOTIATED `standard-replies`
 * ---------------------------------------------------------------------------
 * This case exists because the refusal is per DESTINATION, and the per-destination
 * half is where a migration decision shows up on the wire.
 *
 * 4.4.3's rule: a legacy numeric migrates where it answers MORE THAN ONE question
 * on this node, so the number alone cannot tell a client which refusal happened.
 * `462` answers exactly one -- "you are already registered" -- so it does NOT
 * migrate, and a client that negotiated the capability gets the byte-identical
 * legacy numeric rather than a `FAIL USER ...`. That is a deliberate choice and
 * the cost is named: a client matching on 462 keeps working, and a client that
 * would have preferred a code has not been given one it needed.
 *
 * The negative half matters as much as the positive: a `FAIL` reaching carol would
 * be a command word she was never told to expect, and RFC 1459 2.3 parses it as an
 * unknown command -- which is exactly the breakage 4.4.3's per-destination branch
 * exists to avoid. */
static void case_462_is_per_destination(void)
{
    nf_node_t node;
    test_client_t carol;
    size_t mark;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&carol);
    register_caps(&carol, node.port, "carol", CAP_STANDARD_REPLIES);

    mark = tc_received(&carol);
    TF_CHECK_MSG(tc_send(&carol, "USER mallory 0 *spoofed.example :Real carol") == 0,
                 "carol's second USER failed to send");
    TF_CHECK_MSG(tc_expect(&carol, ":" SRV " 462 carol :Unauthorized command "
                           "(already registered)\r\n", T_IO_MS) == 0,
                 "carol -- who DID negotiate standard-replies -- did not get the "
                 "legacy 462. 462 answers exactly one question on this node, so "
                 "4.4.3's rule leaves it unmigrated and she must receive it "
                 "byte-identically.\n  carol saw: %s", tc_buffer(&carol));
    expect_only_replies(&carol, mark, "second USER by a standard-replies client", 1u);
    TF_CHECK_MSG(strstr(tc_buffer(&carol) + mark, "FAIL") == NULL,
                 "a FAIL USER reached a client that negotiated standard-replies, so "
                 "462 has been migrated. That is a change to the numeric a client "
                 "already handles, taken for no gain: the number was unambiguous.\n"
                 "  carol saw: %s", tc_buffer(&carol) + mark);

    tc_close(&carol);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
}

/* ---------------------------------------------------------------------------
 * 5. THE BOUNDARY: A SECOND `USER` BEFORE REGISTRATION IS STILL HONOURED
 * ---------------------------------------------------------------------------
 * The fix is the gate `commands_registered(c)`, not "has this connection ever seen
 * a `USER`". This case pins the other side of that gate, and it is the compatibility
 * half of the change: a client that sends `USER` twice while still registering
 * (holding a CAP negotiation open, or simply correcting a typo in its own ident)
 * must still work, last-one-wins.
 *
 * IT IS ALSO THE CASE THAT MAKES THE GATE'S SHAPE DEFENSIBLE rather than merely
 * strict. A node that refused every second `USER` would strand the half-registered
 * client §4.2.1's realname argument is about -- the one that cannot recover except
 * by reconnecting -- over a value it could have simply corrected. Refusing only
 * after `001` costs nothing and strands nobody.
 *
 * `CAP REQ` with no capability is a NAK, which keeps the negotiation OPEN (this
 * node's CAP END gate holds registration until END), so the two USERs really do
 * arrive while `commands_registered(c)` is false. The `001` is then read for its
 * hostmask, which is the only place the surviving ident is visible on the wire. */
static void case_second_user_before_registration(void)
{
    nf_node_t node;
    test_client_t c;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");

    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");
    /* A NAK keeps CAP negotiation open, so registration is still HELD here --
     * commands.c's reg_held path -- which is the state this case needs.
     *
     * `account-tag` is the capability asked for because it is the one this node
     * NAKs on a DEFAULT configuration: cap.c's account_possible() withholds it
     * when no account registry was loaded, and nf_spawn_binary() loads none. An
     * ACK would also have held registration open (the gate is `cap_negotiating`,
     * not the verdict), so this is about the refusal being the one a default node
     * gives rather than about the mechanism. */
    TF_CHECK_MSG(tc_send(&c, "CAP REQ :" CAP_ACCOUNT_TAG) == 0,
                 "CAP REQ send failed");
    TF_CHECK_MSG(tc_expect(&c, " CAP * NAK :" CAP_ACCOUNT_TAG "\r\n", T_IO_MS) == 0,
                 "CAP REQ was not NAKed, so this case would be asserting about a "
                 "node whose negotiation state it did not arrange.\n  saw: %s",
                 tc_buffer(&c));
    TF_CHECK_MSG(tc_send(&c, "USER first 0 *spoofed.example :First") == 0,
                 "first USER failed to send");
    TF_CHECK_MSG(tc_send(&c, "USER second 0 *spoofed.example :Second") == 0,
                 "second USER failed to send");
    TF_CHECK_MSG(tc_send(&c, "NICK preuser") == 0, "NICK send failed");
    /* Registration is still held, so there is no 001 yet and NO 462 -- which is
     * itself the assertion: the refusal must not fire for a connection this node
     * has not registered. */
    TF_CHECK_MSG(tc_send(&c, "CAP END") == 0, "CAP END send failed");
    TF_CHECK_MSG(tc_expect(&c, "001 preuser :Welcome to the irc-serve network "
                           "preuser!second@" OBSERVED_HOST "\r\n", T_IO_MS) == 0,
                 "a client that sent USER twice while still negotiating CAP did not "
                 "register with the SECOND ident. The gate is "
                 "`commands_registered(c)`, which is false while CAP END is "
                 "outstanding, so both USERs are registration and last-one-wins is "
                 "what a client library expects.\n  saw: %s", tc_buffer(&c));
    drain(&c);
    /* And no 462 anywhere in what it received: a refusal here would be the strict
     * version of the gate, and the strict version strands a half-registered
     * client over a value it should be able to correct. */
    TF_CHECK_MSG(strstr(tc_buffer(&c), " 462 ") == NULL,
                 "a 462 reached a client whose second USER arrived BEFORE "
                 "registration completed. The gate is on the connection's "
                 "registration state and not on whether a USER was seen before.\n"
                 "  saw: %s", tc_buffer(&c));

    tc_close(&c);
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
 *   THE GATE REMOVED -- commands.c: the `commands_registered(c)` branch at the top
 *       of `handle_user()` replaced by `if (0) { }`. **This is the Phase 10.8
 *       fault run BACKWARDS**, and running it backwards is the point: the fault
 *       that used to expose the hole now restores it, and the case fails.
 *       Build checked first: 0 errors, 0 warnings, and the run went red at
 *       `test_chghost.c:346` -- the `462` assertion in case 3, the FIRST of the
 *       four. `TF_CHECK_MSG` exits on the first failure, so the other three (the
 *       `311` reading `mallory`, alice's line count of 0, and the operator's
 *       `user=mallory` log line) are NOT reached in that run. They are recorded
 *       as a property of the assertions rather than as observed failures, and
 *       that is the honest way to say it.
 *
 *   THE GATE MOVED BELOW THE ARITY TEST -- commands.c: the registration branch
 *       moved under `if (m->nparams < 4)`. Fails NOTHING today and that is stated
 *       rather than hidden: every case in this file sends a well-formed four-
 *       parameter USER. It is recorded because the order is a decision this file
 *       documents, and a fault that changes nothing today is exactly the kind that
 *       is unnoticed when it starts mattering. (A conforming fault would be a
 *       third-parameter-less USER from a REGISTERED client, which is case 3's
 *       `line` with three parameters -- the honest version of this fault is
 *       asserted positively instead, by the case-3 count requiring 1 line and
 *       not 0.)
 */
int main(void)
{
    case_not_advertised();
    case_no_verb();
    case_the_event();
    case_462_is_per_destination();
    case_second_user_before_registration();

    tf_done("chghost");
    return 0;
}
