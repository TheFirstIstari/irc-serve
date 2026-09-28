/* test_reply_guard.c -- the federation invariant: a numeric NEVER reaches a
 * peer link.
 *
 * docs/SERVER_DESIGN.md 3, the reply path:
 *
 *   "Numerics are NEVER written to a peer link and never relayed. Enforced in
 *    exactly one reply() function, never ad hoc per handler."
 *   "src may be NULL for server-originated messages -- SQUIT, a peer KILL, a
 *    resync burst. reply() documents what NULL means per numeric."
 *
 * WHY THIS MATTERS ENOUGH TO TEST DIRECTLY
 * ----------------------------------------
 * A handler that writes a numeric to a CONN_SERVER socket sends
 * ":server 433 nick x" at a peer. The peer's framing layer then reads "433" as a
 * COMMAND WORD and asks the peer what it meant, or worse, treats it as a
 * message with an unknown verb and drops the connection. Nothing on either side
 * reports an error. Phase 6 inherits whatever this phase gets right, and it
 * gets it for free only if the rule is enforced in one place and that place is
 * tested.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS TEST ACTUALLY COVERS, STATED PLAINLY
 * ---------------------------------------------------------------------------
 * Phase 6 has no peer sockets. There is no federated link in this build, no
 * handshake has ever run, and nothing in src/ can create a CONN_SERVER
 * connection except the dial state machine, which no caller drives.
 *
 * So this test does NOT claim to prove "no numeric ever reaches a peer" end to
 * end -- there is no peer to reach. What it proves is the enforcement point
 * itself, which is the part that can be tested honestly today:
 *
 *   1. a conn_t marked CONN_SERVER is REFUSED by reply(), and
 *   2. not one byte reaches the socket behind it.
 *
 * The socket behind it is a socketpair(2) end. That is a pipe with a real
 * descriptor, not a stub, and it is what makes claim 2 a real observation: the
 * positive control below writes the identical message to a CONN_CLIENT conn on
 * an identical socketpair and the bytes DO arrive at the far end, so a passing
 * negative here cannot be explained by the socketpair being unable to carry
 * them.
 *
 * What this does NOT cover, and what Phase 6 must add: a real CONN_SERVER conn
 * created by the dial FSM, across a real link, with the peer asserting it saw
 * nothing numeric. That test cannot be written before there is a peer, and a
 * test written now that implied it would be a fabricated one.
 *
 * The second half of this file is the same property checked by inspection,
 * because the failure mode is a handler that stops using reply() and starts
 * writing to a socket itself. Every runtime invariant above would still hold
 * with such a handler in place -- it would just be wrong.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/connection.h"
#include "core/message.h"
#include "core/reply.h"
#include "core/server.h"
#include "harness/test_util.h"

#define T_POLL_MS 2000

/* Is there anything readable on `fd` within a short deadline? Used to turn "no
 * bytes were written" into an observation rather than an assumption. A select()
 * deadline, never a sleep: 6.3 forbids the fixed wait, and this is the same
 * shape as every other wait in the suite.
 *
 * The deadline is built as a SECONDS/ MICROSECONDS pair rather than by scaling
 * one integer, because tv_usec must stay below 1000000 and a value above it
 * makes select() fail with EINVAL -- which looks exactly like "nothing
 * arrived", silently turning every negative assertion here into a vacuous one. */
static int has_bytes(int fd)
{
    fd_set rfds;
    struct timeval tv;
    int rc;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    tv.tv_sec = T_POLL_MS / 1000;
    tv.tv_usec = (T_POLL_MS % 1000) * 1000;
    rc = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (rc <= 0) {
        return 0; /* timed out with nothing, or an error: either way, no bytes */
    }
    return 1;
}

int main(void)
{
    server_t s;
    int sv[2];
    conn_t *peer;
    char got[512];
    ssize_t n;

    TF_CHECK_MSG(server_init(&s, "irc.test") == 0, "server_init failed");

    /* A socketpair gives both sides a real descriptor. The node side becomes a
     * conn_t; the far end is read directly. */
    TF_CHECK_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
                 "socketpair failed");
    peer = conn_new(sv[0], CONN_SERVER);
    TF_CHECK_MSG(peer != NULL, "conn_new failed");

    /* ------------------------------------------------------------------------
     * The invariant: a numeric aimed at a peer is refused and writes nothing.
     * ------------------------------------------------------------------------ */
    TF_CHECK_MSG(reply(&s, peer, "433", NULL, 0, "Nickname is already in use")
                     == REPLY_REFUSED,
                 "reply() ACCEPTED a numeric aimed at a CONN_SERVER conn. That "
                 "is the failure this whole test exists for: the peer's framing "
                 "layer reads \"433\" as a command word.");
    TF_CHECK_MSG(conn_write_pending(peer) == 0,
                 "reply() queued %zu bytes for a peer conn: the refusal must "
                 "happen BEFORE anything is buffered, not after",
                 conn_write_pending(peer));
    TF_CHECK_MSG(s.n_reply_refused == 1,
                 "n_reply_refused is %llu, expected 1: the refusal must be "
                 "counted, or a node that refused a peer numeric for a week "
                 "would look identical to one that never had the chance",
                 (unsigned long long)s.n_reply_refused);
    TF_CHECK_MSG(!has_bytes(sv[1]),
                 "bytes arrived at the far end of the socket behind a "
                 "CONN_SERVER conn. The refusal is supposed to mean no byte is "
                 "written, not that the bytes are ignored afterwards.");

    /* The same refusal for a PONG, which is a COMMAND rather than a numeric
     * and could easily have been left out of the guard by accident. */
    TF_CHECK_MSG(send_pong(&s, peer, "token") == REPLY_REFUSED,
                 "send_pong() accepted a peer conn: a PONG reaching a peer is "
                 "wrong in exactly the same way a numeric is, and it travels "
                 "through a different function");
    TF_CHECK_MSG(!has_bytes(sv[1]),
                 "send_pong() wrote to a peer socket");
    TF_CHECK_MSG(s.n_reply_refused == 2,
                 "n_reply_refused is %llu, expected 2 after the PONG",
                 (unsigned long long)s.n_reply_refused);

    /* ------------------------------------------------------------------------
     * The POSITIVE CONTROL, and it is the load-bearing half of this file.
     *
     * The identical message, to a CONN_CLIENT conn on an identical
     * socketpair. It must be rendered, queued, and read at the far end --
     * byte for byte, because the exact form is also what this test is checking
     * when it checks that the negative case wrote nothing.
     *
     * Without this, "no bytes arrived" would be satisfied by a reply() that
     * writes nothing at all, and the whole test would pass against a node whose
     * numerics were broken. A negative assertion is only worth what its positive
     * control is.
     * ------------------------------------------------------------------------ */
    {
        conn_t *ok = conn_new(sv[1], CONN_CLIENT);
        const char *mid[1];
        const char *want;

        TF_CHECK_MSG(ok != NULL, "conn_new failed");
        memcpy(ok->nick, "alice", sizeof "alice");
        mid[0] = "shared";
        TF_CHECK_MSG(reply(&s, ok, "433", mid, 1,
                           "Nickname is already in use") == REPLY_OK,
                     "reply() refused a legal client numeric: the negative case "
                     "above would then pass for the wrong reason");
        TF_CHECK_MSG(conn_write_pending(ok) > 0, "nothing was queued");
        TF_CHECK_MSG(conn_pump(ok) == 0, "conn_pump failed");

        want = ":irc.test 433 alice shared :Nickname is already in use\r\n";
        TF_CHECK_MSG(has_bytes(sv[0]),
                     "nothing arrived at the far end of the control "
                     "socketpair: the positive control did not run, so the "
                     "negative assertions above prove nothing");
        n = recv(sv[0], got, sizeof got - 1u, 0);
        TF_CHECK_MSG(n > 0, "recv on the control socketpair returned %d", (int)n);
        if (n <= 0) {
            n = 0; /* keep the comparison below well-defined */
        }
        got[n] = '\0';
        TF_CHECK_MSG(strcmp(got, want) == 0,
                     "the numeric on the wire is \"%s\", expected \"%s\"", got,
                     want);
        conn_free(ok);
    }

    /* And s->name really is the prefix, asserted rather than assumed: a node
     * whose prefix were wrong would still satisfy every other check here. */
    TF_CHECK_MSG(strstr(got, ":irc.test 433 ") == got,
                 "the numeric does not begin with the node's own name");
    TF_CHECK_MSG(s.n_reply_refused == 2,
                 "n_reply_refused moved to %llu: a message that WAS sent was "
                 "counted as a refusal, or a refusal was not counted",
                 (unsigned long long)s.n_reply_refused);

    /* ------------------------------------------------------------------------
     * A NULL src: no client to answer, so nothing is emitted -- and that is a
     * refusal, not a broadcast. 3 names the server-originated cases (SQUIT, a
     * peer KILL, the Phase 6 resync burst) and NONE of them is a numeric: they
     * are protocol messages that go out through the relay path to their target.
     * A numeric addressed to nobody is a caller that reached for reply() when it
     * wanted a fan-out, and the honest answer is to say so loudly.
     * ------------------------------------------------------------------------ */
    TF_CHECK_MSG(reply(&s, NULL, "401", NULL, 0, "No such nick/channel") ==
                     REPLY_REFUSED,
                 "reply() accepted a NULL src. 3 allows src to be NULL for a "
                 "server-originated MESSAGE; it does not allow it to invent an "
                 "addressee for a numeric.");
    TF_CHECK_MSG(!has_bytes(sv[1]),
                 "a numeric with no addressee was written somewhere");

    /* ------------------------------------------------------------------------
     * A CLOSING client: the loop has already dropped it from the poll set, so
     * anything queued would sit in a write queue that is never pumped. This is
     * reachable from a real client, not just here: a QUIT and a PING in one
     * segment reach the dispatcher with the conn already CLOSING, which
     * test_quit.c exercises end to end through the binary.
     * ------------------------------------------------------------------------ */
    {
        conn_t *closing = conn_new(sv[0], CONN_CLIENT);

        TF_CHECK_MSG(closing != NULL, "conn_new failed");
        conn_mark_closing(closing);
        TF_CHECK_MSG(reply(&s, closing, "001", NULL, 0, "Welcome") ==
                         REPLY_REFUSED,
                     "reply() queued a message for a connection that is already "
                     "CLOSING");
        TF_CHECK_MSG(!has_bytes(sv[1]),
                     "reply() wrote to a CLOSING connection");
        conn_free(closing);
    }

    /* ------------------------------------------------------------------------
     * 2.3: a peer link is EXEMPT from the client registration state machine.
     * ------------------------------------------------------------------------
     * Even with reply() refusing every numeric, a peer must not be able to
     * REGISTER, because registration mutates the nick registry -- and a nick
     * claimed by a peer socket would be a nick the node advertises to its users
     * that no user can log in as.
     *
     * This is the one part of the peer story that can be tested without a peer,
     * because the rule is about the KIND of connection, not about a link.
     */
    {
        message_t m;

        peer->state = CONN_REG_PASS;
        peer->nick[0] = '\0';
        TF_CHECK_MSG(message_parse("NICK intruder", &m) == 0, "parse failed");
        commands_dispatch(&s, peer, &m);
        message_free(&m);
        TF_CHECK_MSG(peer->nick[0] == '\0',
                     "a CONN_SERVER conn REGISTERED a nickname (\"%s\"): 2.3 "
                     "exempts a peer link from the client state machine "
                     "entirely", peer->nick);
        TF_CHECK_MSG(peer->state == CONN_REG_PASS,
                     "a CONN_SERVER conn advanced its registration state to %d",
                     peer->state);
        TF_CHECK_MSG(server_nick_lookup(&s, "intruder") == NULL,
                     "a peer conn put a nickname into the user registry");
        TF_CHECK_MSG(!has_bytes(sv[1]), "a peer conn was answered");

        TF_CHECK_MSG(message_parse("USER intruder 0 * :Intruder", &m) == 0,
                     "parse failed");
        commands_dispatch(&s, peer, &m);
        message_free(&m);
        TF_CHECK_MSG(peer->user[0] == '\0',
                     "a CONN_SERVER conn captured a USER line (\"%s\")",
                     peer->user);
    }

    /* ------------------------------------------------------------------------
     * The same property, by inspection.
     *
     * The failure mode a runtime test cannot see is a handler that stops using
     * reply() and starts writing to a socket itself. Every runtime invariant in
     * this file would still hold with such a handler in place -- it would just
     * be wrong, and it would be wrong in the one direction this phase exists to
     * prevent.
     *
     * The scope is deliberately narrow: commands.c must not reach a socket at
     * all. reply.c obviously does queue, so what is checked there is that the
     * queueing is inside emit_to_client(), after the peer check. Phase 6's
     * fan-out will legitimately write to CLIENT conns from its own file, and
     * this assertion is written so that it does not forbid that -- it forbids a
     * HANDLER reaching around the reply path, which is the thing 3 says must
     * never happen.
     * ------------------------------------------------------------------------ */
    {
        char *cmds = tf_read_code("src/core/commands.c", NULL);
        char *rep = tf_read_code("src/core/reply.c", NULL);
        const char *at;
        const char *queue_at;

        TF_CHECK_MSG(cmds != NULL && rep != NULL,
                     "could not read the sources (is IRCSERVE_SRC_DIR set?)");

        TF_CHECK_MSG(!tf_calls(cmds, "server_queue"),
                     "commands.c calls server_queue(): a handler has reached "
                     "around reply() and can therefore write to a peer link, "
                     "which is exactly what 3 forbids");
        TF_CHECK_MSG(!tf_calls(cmds, "conn_pump"),
                     "commands.c calls conn_pump(): a handler has reached around "
                     "reply() into the socket itself");
        /* QUIT must go through conn_mark_closing() so the reaper stays the only
         * close site (3.4). It is asserted here rather than left to
         * test_close_sites.c, which proves the same rule from the other side:
         * that no file but server.c calls close(). */
        TF_CHECK_MSG(tf_calls(cmds, "conn_mark_closing"),
                     "commands.c no longer calls conn_mark_closing(): QUIT must "
                     "MARK the connection closing and let the reaper close the "
                     "descriptor (3.4), or it has found a second close site");
        TF_CHECK_MSG(strstr(cmds, "server_nick_claim") != NULL,
                     "commands.c no longer claims nicknames: valid_nick() would "
                     "have lost its only production caller, which is the whole "
                     "reason this phase exists");

        /* reply.c queues -- and does so from inside the function that holds the
         * peer check, not from reply() or send_pong() directly. */
        queue_at = strstr(rep, "server_queue");
        TF_CHECK_MSG(queue_at != NULL,
                     "reply.c no longer calls server_queue() at all: the "
                     "positive control above would have caught that, so this is "
                     "belt to that braces");
        at = strstr(rep, "emit_to_client");
        TF_CHECK_MSG(at != NULL, "reply.c has no emit_to_client()");
        {
            /* The refusal must be textually BEFORE the queueing site, so the
             * guard cannot be reordered past it. The search is for CODE, not
             * for the reason string: tf_read_code() strips string literals, so
             * looking for "peer_target" here would search for something the
             * stripper deliberately removed. */
            const char *guard = strstr(rep, "CONN_SERVER");

            TF_CHECK_MSG(guard != NULL,
                         "reply.c no longer tests c->kind against CONN_SERVER: "
                         "the peer-link refusal is gone");
            TF_CHECK_MSG(guard < queue_at,
                         "the peer-link refusal is no longer before the "
                         "queueing site in reply.c, so it can be reordered past "
                         "it and still compile");
        }
        free(cmds);
        free(rep);
    }

    /* The refusals above all happened; the positive control did not. */
    TF_CHECK_MSG(s.n_reply_refused == 4,
                 "n_reply_refused is %llu, expected 4: two peer numerics, one "
                 "peer PONG, one NULL src and one CLOSING target. A different "
                 "number means a refusal path stopped refusing, or a message "
                 "that should have been sent was dropped.",
                 (unsigned long long)s.n_reply_refused);
    TF_CHECK_MSG(conn_write_pending(peer) == 0, "the peer conn has queued bytes");

    conn_free(peer);
    close(sv[0]);
    close(sv[1]);
    server_shutdown(&s);

    tf_done("reply_guard");
    return 0;
}
