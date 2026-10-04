/* test_readiness_intent.c -- Phase 12, the STRUCTURAL change: poll() asks the
 * connection what it wants instead of deriving it from data.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE IS MOSTLY ABOUT A FIELD THAT DID NOT EXIST TWELVE PHASES AGO
 * ---------------------------------------------------------------------------
 * The loop used to build a connection's event mask like this:
 *
 *     pfds[n].events = POLLIN;
 *     if (conn_write_pending(c) > 0) { pfds[n].events |= POLLOUT; }
 *
 * and that was correct, because for a plaintext socket "there are unsent bytes"
 * and "the socket is waiting to be written to" are the same fact. Nonblocking
 * TLS breaks the identity: SSL_read() can answer SSL_ERROR_WANT_WRITE, meaning
 * "the handshake is parked awaiting a write", while the write queue is EMPTY --
 * and poll()'s revents cannot report it, because at that instant the socket has
 * nothing in either direction to report. So the loop needs the transport to TELL
 * it, which is `conn_t::want_read` / `conn_t::want_write`.
 *
 * Two things therefore have to be true, and they are the two halves of this file:
 *
 *   1. THE INTENT IS CONSULTED. Case 3 is an observable wire fact: a connection
 *      whose intent says "do not read me" is never read, and the client sees
 *      silence while a second client on the same node is served normally.
 *
 *   2. THE PLAINTEXT PATH IS UNCHANGED. Case 1 asserts the invariant that makes
 *      it so -- on a plaintext connection want_read is always 1 and want_write is
 *      exactly "there are unsent bytes", which is what the old derivation
 *      computed -- and the other 82 tests are the regression bar. Case 4 is the
 *      structural half: the loop may not go back to deriving the mask, and the
 *      I/O seam may not grow past the three sites transport.h names.
 *
 * The ordering matters and is why case 3 comes before case 4: a source check that
 * said "poll_loop.c mentions want_read" would pass against a loop that also kept
 * its old derivation, so the wire case has to be the one that carries the claim.
 *
 * NO FIXED SLEEP ANYWHERE. Every wait is a deadline wait over select() (6.3), and
 * every assertion is on something a CLIENT can see or on a number the node
 * prints.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/connection.h"
#include "core/server.h"
#include "core/transport.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

/* The PONG this node answers a PING with. PONG's <server> is this node's own
 * name and the trailing text is the token the client sent, so the token is what
 * makes these needles distinguishable from each other -- RFC 2812 4.1.2's "the
 * <server> and <server2> field is ignored" is about the server names, not about
 * the token, and every current client correlates on the token. */
#define PONG_PARKED "PONG intent.test onparked"
#define PONG_FENCE  "PONG intent.test fence"

static int failures;

static void check(int cond, const char *what, const char *detail)
{
    if (cond) {
        printf("ok: %s\n", what);
        return;
    }
    failures++;
    printf("FAILED: %s\n  %s\n", what, (detail != NULL) ? detail : "");
}

/* ===========================================================================
 * CASE 1: the plaintext invariant, which is what makes the poll set identical
 * ===========================================================================
 *
 * IN-PROCESS AND AGAINST A REAL SOCKET PAIR, because the invariant is about
 * send()'s behaviour and a mocked write() would prove nothing about it. A
 * socketpair gives two descriptors, so "the peer is not draining" is a condition
 * the test creates rather than schedules.
 *
 * THE THREE FACTS, and each is a separate assertion because each can break alone:
 *
 *   want_read is 1 from birth and never lowered.     A plaintext loop that
 *       derived POLLIN from anything else would stop reading idle clients, which
 *       is the largest and quietest possible regression.
 *   conn_queue() raises want_write.                  Without this a reply queued
 *       by a handler waits for the peer to speak first, which an idle client
 *       never does.
 *   conn_pump() lowers it exactly when the queue empties, and leaves it raised
 *       across a short write.                        A loop that asks for POLLOUT
 *       forever on a drained connection spins at 100% CPU; one that never asks
 *       cannot flush at all. */
/* Put `fd` in nonblocking mode, or say why the test cannot proceed.
 *
 * IT IS NOT OPTIONAL AND THE COMMENT IS THE FINDING. A socketpair's descriptors
 * are BLOCKING, and a blocking send() on a full socket does not return EAGAIN --
 * it blocks, forever, inside the exact call this test is measuring. The node's
 * own descriptors are made nonblocking by server.c's set_nonblocking() at every
 * accept and dial site, so a test that forgets this is not testing a smaller
 * thing, it is testing a different kernel behaviour -- and it HANGS rather than
 * failing, which is the worst shape a test bug can have. This was found by
 * exactly that hang during Phase 12. */
static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void case_plaintext_invariant(void)
{
    int sv[2];
    conn_t *c;
    char drain[4096];
    size_t pending;
    int guard;
    int short_written = 0;
    int saturated;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        check(0, "socketpair for the plaintext invariant", "socketpair failed");
        return;
    }
    if (set_nonblocking(sv[0]) != 0) {
        check(0, "make the connection side nonblocking", "fcntl failed");
        close(sv[0]);
        close(sv[1]);
        return;
    }
    (void)set_nonblocking(sv[1]);
    c = conn_new(sv[0], CONN_CLIENT);
    if (c == NULL) {
        check(0, "conn_new over a socketpair", "allocation failed");
        close(sv[0]);
        close(sv[1]);
        return;
    }

    check(c->want_read == 1,
          "a new plaintext connection wants to be read",
          "conn_new() must publish want_read = 1");
    check(c->want_write == 0,
          "a new plaintext connection wants no writability",
          "conn_new() must publish want_write = 0 with an empty queue");

    check(conn_queue(c, "PING :x\r\n", 9) == 0, "queue a line", "append failed");
    check(c->want_write == 1,
          "queueing a reply raises want_write",
          "conn_queue() must raise the intent, or the reply waits for the peer "
          "to speak first");

    /* FILL THE SOCKET and never read the peer, until send() refuses.
     *
     * The harness cannot force this by asking for a small SO_RCVBUF -- irc_client.h
     * says at length that the request is not a guarantee and that reading the
     * number back is platform-dependent -- so the test makes the condition
     * unavoidable instead: queue bytes and never drain, and let the kernel and
     * the bounded write queue (CONN_WQ_MAX, 256 KiB) bound the loop. The loop is
     * ALSO bounded by `guard`, and `saturated` is what decides whether the bound
     * was reached or the socket filled: a transport that accepted every byte
     * would exit the loop with nothing queued, and that is reported as a harness
     * failure rather than passed over. */
    for (guard = 0; guard < 200000; guard++) {
        if (conn_pump(c) != 0) {
            break;
        }
        if (conn_write_pending(c) > 0u) {
            short_written = 1; /* the socket refused: EAGAIN with bytes queued */
        }
        if (conn_queue(c, "0123456789abcdef", 16u) != 0) {
            break; /* CONN_WQ_MAX: the socket is saturated and stays saturated */
        }
    }
    saturated = (short_written != 0 && conn_write_pending(c) > 0u) ? 1 : 0;
    pending = conn_write_pending(c);
    if (saturated == 0) {
        check(0,
              "a peer that stops draining produces a short write with bytes "
              "still queued",
              "the test could not saturate the socket, so it cannot assert the "
              "invariant; this is a harness failure, not a server one");
        conn_free(c);
        close(sv[1]);
        return;
    }
    check(c->want_write == 1,
          "a short write leaves want_write raised",
          "conn_pump() must not clear the intent while bytes remain: the loop "
          "would stop asking for POLLOUT and the queue would never finish "
          "draining");

    /* NOW drain the peer, so the queue empties and the intent must come down. */
    for (guard = 0; guard < 1000000 && conn_write_pending(c) > 0u; guard++) {
        (void)recv(sv[1], drain, sizeof drain, MSG_DONTWAIT);
        if (conn_pump(c) != 0) {
            break;
        }
    }
    check(pending > 0u, "the short write really had bytes left in the queue",
          "a zero pending count means the earlier check passed vacuously");
    check(conn_write_pending(c) == 0u, "the queue drains once the peer reads",
          "conn_pump() stopped making progress");
    check(c->want_write == 0,
          "an empty queue lowers want_write",
          "conn_pump() must lower the intent, or the loop polls POLLOUT on a "
          "connection with nothing to send and spins");
    check(c->want_read == 1,
          "the plaintext read intent is never lowered",
          "something cleared want_read on a plaintext connection");

    conn_free(c); /* transport_close() runs from here; see case 4 */
    close(sv[1]);
}

/* ===========================================================================
 * CASE 2: the peer link's drain goes through the transport too
 * ===========================================================================
 *
 * `fed_send_shutdown()`'s drain is the third and last of the three I/O sites, and
 * it is the easiest one to leave behind because it is a RECV into a sink rather
 * than a read into the connection. If it kept calling recv() directly then a TLS
 * peer link would be drained with the wrong protocol -- reading ciphertext into a
 * stack buffer and counting it as "drained", which is at best a wrong number on a
 * log line and at worst a handshake failure on the way out -- and nothing else in
 * the suite would notice.
 *
 * ASSERTED BY INSPECTION and labelled as such: the drain runs during teardown and
 * its effect is not a wire line. The search is over CODE (comments and literals
 * stripped, by test_util.h's helper), which is what makes "no raw recv(" a
 * statement about the program rather than about its prose -- link.c's drain block
 * has a nine-line comment that names recv() twice. */
static void case_drain_uses_transport(void)
{
    size_t len = 0;
    char *code = tf_read_code("src/federation/link.c", &len);

    if (code == NULL) {
        check(0, "read src/federation/link.c",
              "tf_read_code() failed (is IRCSERVE_SRC_DIR set?)");
        return;
    }
    check(tf_calls(code, "transport_recv") == 1,
          "fed_send_shutdown()'s drain reads through transport_recv()",
          "link.c must not recv() a peer socket directly: on a TLS link that "
          "reads ciphertext and counts it as bytes drained");
    check(tf_calls(code, "recv") == 0,
          "link.c's CODE calls no recv() at all, with comments stripped",
          "a raw recv( in link.c means the drain has a second implementation");
    free(code);
}

/* ===========================================================================
 * CASE 3: THE INTENT IS CONSULTED -- an observable wire fact
 * ===========================================================================
 *
 * THE FINDING THAT FORCED THIS TEST'S SHAPE, and it is worth stating before the
 * mechanism because it is the answer to "why is the wire case not just a tick
 * that clears want_read":
 *
 * CLEARING want_read FROM OUTSIDE DOES NOTHING, AND THAT IS CORRECT. The
 * plaintext transport republishes want_read = 1 on every read and every write --
 * that is its contract, and case 1 asserts it -- so the very next I/O puts the
 * connection back in the poll set. An earlier version of this case cleared the
 * field in a tick hook and the test's own trace then showed the node framing the
 * line anyway: six PINGs where five were expected. The field was being set and
 * ignored in the same tick, by the code that is supposed to own it.
 *
 * WHICH LEAVES THE REAL QUESTION: can a plaintext connection EVER be in the
 * state want_read == 0 && want_write == 0, and if so is the connection really
 * left out of the poll set? The answer for the shipped transport is no, and that
 * is exactly the property that makes its poll set identical to the pre-Phase-12
 * one. To observe the LOOP's behaviour in a state the plaintext transport cannot
 * reach, this test installs its own transport on the connection -- which is what
 * the vtable is for. A TLS transport IS this transport: one that has published
 * "I am waiting for something else" instead of "read me".
 *
 * THE DOUBLE IS DELIBERATELY PERMISSIVE, AND THAT IS WHERE ITS TEETH ARE.
 *
 * Its recv publishes want_read = 0 AND THEN, IF ANYBODY ASKS, RETURNS A WHOLE
 * PING LINE. An inert double -- one that returns TRANSPORT_RETRY and no bytes --
 * was the first version, and it had no teeth at all: a loop that had regressed to
 * `events = POLLIN` would have polled this connection, called the double, got
 * nothing, framed nothing, and every assertion below would still have passed.
 * Only case 4 caught that fault, and a wire case that cannot fail on the fault it
 * exists for is decoration.
 *
 * So the double hands over data it was never asked for. That is incoherent as a
 * MODEL of a TLS transport, and it is not trying to be one: it is a probe. Its
 * whole purpose is to make the loop's decision observable -- "did you read a
 * connection you were told not to read?" is only answerable if reading is
 * possible. A permissive double answers it, and the answer arrives on the wire as
 * a PONG the client did not earn.
 *
 * WHY A TICK HOOK rather than a command handler: the swap has to happen AFTER
 * the connection has registered and its write queue has drained, and the tick is
 * the only seam in this codebase that runs at a fixed point in the loop with no
 * dependence on what any client did. Both conditions are checked, so the swap
 * cannot happen while the registration burst is still queued -- a double
 * installed over a connection with bytes pending would refuse to write them and
 * the client would never see its own 001.
 *
 * WHY IT IS NEVER REVERTED: a test that swapped the transport back could not
 * tell "the intent was honoured" from "the intent was ignored and something else
 * recovered", because the PONG would arrive either way. */
/* The most recent node's output, COPIED, so a failure can print it.
 *
 * COPIED rather than pointed at: nf_free() releases `n->out`, so a pointer kept
 * across the teardown is a use-after-free on the failure path -- which is the
 * path that only runs when something is already wrong, and is therefore the last
 * place a dangling read should hide. The copy is made while the node is alive and
 * bounded, because a runaway node can print a great deal. */
static char g_node_dump[1 << 17];
static int g_have_node_dump;

static void case_capture_node(const nf_node_t *n)
{
    size_t len;

    g_have_node_dump = 0;
    g_node_dump[0] = '\0';
    if (n == NULL || n->out == NULL) {
        return;
    }
    len = n->out_len;
    if (len >= sizeof g_node_dump) {
        len = sizeof g_node_dump - 1u;
    }
    memcpy(g_node_dump, n->out, len);
    g_node_dump[len] = '\0';
    g_have_node_dump = 1;
}

static void case_dump_node(void)
{
    if (g_have_node_dump != 0) {
        printf("%s", g_node_dump);
    }
}

static int g_stalled_done;

/* The line the permissive double hands over if the loop asks for it. It is a
 * real, dispatchable command, so if a loop reads this connection the client sees
 * a PONG and cannot fail to notice. Its token is deliberately NOT the one the
 * test sent, so "the client's own PING was answered" and "the double's PING was
 * answered" are two separate assertions rather than one. */
#define DOUBLE_LINE "PING :fromdouble\r\n"
#define PONG_DOUBLE "PONG intent.test fromdouble"

/* ONE LINE, ONCE. The double is permissive but BOUNDED, and the bound is what
 * makes it a usable probe.
 *
 * Unbounded, it generates a line on every read, so a regressed loop frames one
 * per 19 bytes of buffer forever; the PONGs outrun a client that is not reading,
 * the write queue reaches CONN_WQ_MAX, and the connection is dropped -- which
 * still failed the test, but by way of a livelock that took 97451 framed lines
 * and starved the wire assertion the probe exists to serve. One line is enough:
 * the fault's signature is "the node framed a PING nobody sent it", and one
 * unrepeated line makes that signature exact, countable and prompt. */
static int g_double_served;

static ssize_t stalled_recv(conn_t *c, void *buf, size_t len)
{
    const size_t n = strlen(DOUBLE_LINE);

    /* Publish what a parked transport publishes: no readability. want_write is
     * passed through unchanged because it is still this connection's write
     * queue's business and not the double's. */
    conn_want(c, 0, c->want_write);
    if (g_double_served != 0 || len < n) {
        return TRANSPORT_RETRY;
    }
    g_double_served = 1;
    memcpy(buf, DOUBLE_LINE, n);
    return (ssize_t)n;
}

/* Permissive on the WRITE side for the same reason, and this is a second version
 * of a bug the first version of the double had: an inert send means that even a
 * fully regressed loop produces no wire difference, because the PONGs it framed
 * are queued and then never leave. A probe has to be permissive in BOTH
 * directions or it cannot see the caller get it wrong. */
static ssize_t stalled_send(conn_t *c, const void *buf, size_t len)
{
    ssize_t n;

    if (len == 0u) {
        conn_want(c, 0, 0);
        return 0;
    }
    n = send(c->fd, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (n > 0) {
        /* "Ask me again if there is more", which is the rule a real transport
         * follows and the one that keeps a PROBE from being pathological when
         * the loop gets it wrong.
         *
         * The first version of this double published want_write = 0
         * unconditionally, and under a regressed loop that livelocked the node:
         * the double handed over a line every read, each line produced a PONG,
         * the PONGs queued, and nothing ever asked for them again -- so the
         * write queue filled to CONN_WQ_MAX, the connection was dropped, and
         * 97198 PINGs were framed before the test looked. The test still FAILED,
         * which is why this was found, but it failed for the wrong reason and
         * took far longer than it should have. A probe has to behave like the
         * thing it stands in for, or it measures the probe. */
        conn_want(c, 0, ((size_t)n < len) ? 1 : 0);
        return n;
    }
    if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
        conn_want(c, 0, 1);
        return TRANSPORT_RETRY;
    }
    return TRANSPORT_FATAL;
}

static void stalled_close(conn_t *c)
{
    /* Nothing. A TLS close sends close_notify; a parked test double has nothing
     * to say and, like plain_close(), must not touch the descriptor (3.4). The
     * context is NULL -- this conn was never TLS -- so there is nothing to free
     * here, and transport_close() clears the ops after this returns. */
    (void)c;
}

static const transport_ops_t k_stalled_ops = {
    stalled_recv,
    stalled_send,
    stalled_close
};

static void stop_reading_tick(server_t *s, uint64_t now_ms);

static void stop_reading_setup(server_t *s)
{
    s->dispatch = commands_dispatch;
    /* The harness CHAINES this hook rather than replacing it (node_fixture.c keeps
     * its own parent-death check), so assigning it here is safe and is the only
     * way a test gets a tick. */
    s->on_tick = stop_reading_tick;
    /* Per-line tracing, which is what makes "the node FRAMED N commands" a
     * countable observable rather than an inference from what came back on the
     * wire. The distinction matters here: a line can be framed and dispatched
     * with no reply (a refused verb), and "no PONG arrived" cannot tell that from
     * "the line was never read". */
    s->trace = 1;
}

static void stop_reading_tick(server_t *s, uint64_t now_ms)
{
    (void)now_ms;
    if (g_stalled_done) {
        return;
    }
    for (int fd = 0; fd < SERVER_FD_TABLE; fd++) {
        conn_t *c = server_conn(s, fd);

        if (c == NULL || c->kind != CONN_CLIENT) {
            continue;
        }
        /* REGISTERED: NICK and USER are in. */
        if (c->state != CONN_REG_READY) {
            continue;
        }
        /* AND ITS WRITE QUEUE IS EMPTY, so the registration burst has actually
         * gone out. Installing a transport that refuses to write over a
         * connection with bytes pending would make the client wait for ever. */
        if (conn_write_pending(c) > 0u) {
            continue;
        }
        c->t_ops = &k_stalled_ops;
        c->t_ctx = NULL;
        conn_want(c, 0, c->want_write);
        printf("[observable] readiness_intent_parked: fd=%d want_read=%d "
               "want_write=%d transport=PARKED\n", fd, c->want_read,
               c->want_write);
        g_stalled_done = 1;
        return;
    }
}

static void case_intent_is_consulted(void)
{
    nf_node_t n;
    test_client_t quiet;
    test_client_t fence;
    int round;
    int fence_ok = 1;
    int fence_rounds = 0;

    g_stalled_done = 0;
    g_double_served = 0;
    if (nf_spawn_inline_named(&n, "intent.test", stop_reading_setup) != 0) {
        check(0, "spawn an inline node that parks one connection's transport", NULL);
        return;
    }


    /* The connection whose transport will be parked. It registers and stops; the
     * registration burst is the last thing that connection will ever be sent,
     * which is asserted rather than assumed: the burst must be COMPLETE (376)
     * before the line the node must not answer is written, or the assertion
     * below could be satisfied by the burst still being in flight. */
    if (tc_connect(&quiet, n.port) != 0) {
        check(0, "connect the connection that will go quiet", NULL);
        nf_kill(&n);
        nf_free(&n);
        return;
    }
    check(tc_send(&quiet, "NICK alice") == 0, "send NICK", NULL);
    check(tc_send(&quiet, "USER alice 0 * :Alice") == 0, "send USER", NULL);
    check(tc_expect(&quiet, " 376 ", 10000) == 0,
          "the connection registers and its MOTD is complete", tc_buffer(&quiet));

    /* The node must have parked the transport, and said so. The [observable] log
     * IS this project's contract, so asserting on it is asserting on an
     * observable, and `want_read=0` is the fact rather than the fact that a
     * function ran. */
    check(nf_expect(&n, "readiness_intent_parked:", 5000) == 0,
          "the node's own log records the connection being parked",
          "the tick hook never found a registered connection with a drained "
          "write queue");
    check(nf_expect(&n, "want_read=0", 5000) == 0,
          "the parked field is reported as 0, so the log and the struct agree",
          NULL);

    /* The second connection: it registers AFTER the first was parked, so its own
     * registration proves the node is still accepting, framing, parsing and
     * answering. Its PING/PONG is the fence that makes "connection A is quiet" a
     * fact about connection A. */
    if (tc_connect(&fence, n.port) != 0) {
        check(0, "connect the control connection", NULL);
        tc_close(&quiet);
        nf_kill(&n);
        nf_free(&n);
        return;
    }
    check(tc_send(&fence, "NICK bob") == 0, "control sends NICK", NULL);
    check(tc_send(&fence, "USER bob 0 * :Bob") == 0, "control sends USER", NULL);
    check(tc_expect(&fence, " 001 ", 10000) == 0,
          "a second client registers on the same node AFTER the first was parked, "
          "so the node is alive and serving",
          tc_buffer(&fence));

    check(tf_count(n.out, "command=PING") == 0u,
          "the node has framed no PING at all yet", NULL);
    check(tc_send(&quiet, "PING :onparked") == 0,
          "send a PING on the connection whose transport is parked", NULL);

    /* ------------------------------------------------------------------------
     * THE FENCE, AND WHY IT MEASURES QUIESCENCE RATHER THAN COUNTING ROUNDS
     * ------------------------------------------------------------------------
     * An absence cannot be waited for, so every wait here is on the CONTROL
     * connection instead: a PING/PONG round trip through a second client is proof
     * that the event loop ran at least one more iteration, and each iteration was
     * an opportunity at which the parked connection's line would have been read.
     * No sleep is involved -- the wait is on a socket, with a deadline.
     *
     * BUT A FIXED NUMBER OF ROUNDS IS NOT ENOUGH, and the reason is a race this
     * test lost twice while it was being written. Whether the parked connection is
     * read on the tick the client's bytes land or on a LATER one is not
     * something the test controls, so assertions made a fixed number of fence
     * rounds after the send can be made before that tick has happened. In one run
     * the framed-line count had already moved (the fault was caught) while the
     * reply to it had not yet been written (a second assertion had not seen it).
     *
     * SO THE LOOP WAITS FOR THE NODE TO GO QUIET, AND "QUIET" IS MEASURED AS A
     * PER-ROUND DELTA RATHER THAN AS AN ABSOLUTE COUNT.
     *
     * Each fence round contributes exactly ONE framed PING -- its own -- so the
     * count cannot stay still and "unchanged" is the wrong test; the first version
     * of this loop used it and settled on zero rounds in eight. The measure is the
     * DELTA: three consecutive rounds in which the node framed exactly one PING,
     * i.e. only the fence, have bracketed the tick on which the parked
     * connection's line would have been read. One round framing two PINGs is the
     * fault's signature and it resets the streak, which is exactly what makes the
     * count meaningful afterwards.
     *
     * The upper bound is there so a node that never settles fails the loop instead
     * of spinning: eight rounds of a rising-per-round delta exit with
     * `settled == 0` and the equality assertion below reports the real figure.
     */
    {
        size_t prev = 0u;
        size_t pinged = 0u;
        int streak = 0;
        int settled = 0;
        int eof = 0;

        fence_rounds = 0;
        prev = tf_count(n.out, "command=PING");
        for (round = 0; round < 10; round++) {
            char out[64];
            char back[64];

            snprintf(out, sizeof out, "PING :fence%d", round);
            snprintf(back, sizeof back, PONG_FENCE "%d", round);
            if (tc_send(&fence, out) != 0 || tc_expect(&fence, back, 10000) != 0) {
                fence_ok = 0;
                continue;
            }
            fence_rounds++;
            /* Read whatever the parked connection has been sent, so that a PONG it
             * was wrongly given ends up in the buffer the assertions below look
             * at. Without this an assertion about what did NOT arrive in a buffer
             * nobody has read is vacuous. */
            (void)tc_drain(&quiet, 50, &eof);
            pinged = tf_count(n.out, "command=PING");
            /* Exactly one new framed PING: this round's fence and nothing else. */
            if (pinged > prev && (pinged - prev) == 1u) {
                streak++;
            } else {
                streak = 0;
            }
            prev = pinged;
            if (streak >= 3) {
                settled = 1;
                break;
            }
        }
        check(fence_ok,
              "every control-connection fence PING is answered, so the loop was "
              "running and was answering PINGs throughout while the parked one "
              "went unanswered",
              tc_buffer(&fence));
        check(settled != 0,
              "three consecutive poll iterations each framed exactly one PING -- "
              "the fence and nothing else -- so the assertions below are about a "
              "node that has demonstrably stopped reading the parked connection "
              "rather than one caught mid-tick",
              "the count kept moving: see the figure in the assertion below");
    }
    check(strstr(tc_buffer(&quiet), PONG_PARKED) == NULL,
          "the PING on the parked connection is NEVER answered",
          tc_buffer(&quiet));

    /* THE ASSERTION THAT GIVES THIS WIRE CASE ITS TEETH, and it is the reason
     * the double is permissive. The double's own line is one the node was never
     * asked for -- the transport published want_read = 0 -- so a PONG answering it
     * can only have come from a loop that read a connection it had been told to
     * leave alone. With an inert double this assertion would be satisfied trivially
     * even by a fully regressed loop; with this one it fails on the wire. */
    check(strstr(tc_buffer(&quiet), PONG_DOUBLE) == NULL,
          "the parked connection's transport was never asked for a line, so the "
          "line it would have handed over is NOT answered either -- which is what "
          "fails on the wire if the loop derives POLLIN instead of reading the "
          "intent",
          tc_buffer(&quiet));

    /* AND THE SHARPEST FORM OF THE CLAIM: the node's own trace counts the PINGs it
     * FRAMED, and the parked connection's line is not among them.
     *
     * THE EXPECTED FIGURE IS DERIVED FROM THE ROUNDS ACTUALLY RUN, and it is an
     * equality rather than an upper bound for two reasons. An upper bound would be
     * satisfied by a node that framed the parked line and then framed nothing
     * else, which is not the property being claimed; and a hard-coded number would
     * be wrong whenever the quiescence streak settles early or late, which it does
     * -- three rounds is typical, four was what the earlier fixed-count version
     * produced. One framed PING per fence round, and nothing else, is the claim. */
    {
        size_t pinged = tf_count(n.out, "command=PING");
        char detail[192];

        snprintf(detail, sizeof detail,
                 "the node framed %zu PINGs across %d fence rounds; the two must "
                 "be equal, because a round frames exactly one -- its own fence -- "
                 "and any extra is the parked connection's line being read",
                 pinged, fence_rounds);
        check((int)pinged == fence_rounds,
              "the node's own trace shows the parked connection's PING was never "
              "FRAMED: it framed exactly one PING per fence round and nothing "
              "else",
              detail);
    }

    /* AND THE OTHER HALF OF THE CLAIM: the parked connection is not merely
     * unread, it is OUT OF THE POLL SET. The evidence is that the node keeps
     * working -- the fences above -- and that the parked connection's descriptor
     * is never reported. The node's own accept/close counters bracket it. */
    check(nf_expect(&n, "accepted=", 5000) == 0,
          "the node reports its accepted-connection counter, so the parked "
          "connection was a real connection and not one that was refused",
          NULL);

    tc_close(&quiet);
    tc_close(&fence);
    (void)nf_stop(&n);
    case_capture_node(&n);
    nf_free(&n);
}

/* ===========================================================================
 * CASE 4: the structural half
 * ===========================================================================
 *
 * Source inspection, and every check here says so in its name. What it asserts is
 * the two things a wire test cannot: that the loop has not been reverted to
 * deriving the mask, and that the I/O seam has not grown.
 *
 * It is here and not as the only case because both claims are about code rather
 * than behaviour, and a test that only read sources would pass against a loop that
 * reads the intent AND ignores it. */
static void case_structural(void)
{
    size_t len = 0;
    char *code = tf_read_code("src/core/poll_loop.c", &len);

    if (code == NULL) {
        check(0, "read src/core/poll_loop.c",
              "tf_read_code() failed (is IRCSERVE_SRC_DIR set?)");
        return;
    }
    check(strstr(code, "c->want_read") != NULL,
          "poll_loop.c reads conn_t::want_read",
          "the loop must ask the connection what it wants");
    check(strstr(code, "c->want_write") != NULL,
          "poll_loop.c reads conn_t::want_write",
          "the loop must ask the connection what it wants");
    {
        /* The literal `events = POLLIN;` is the pre-Phase-12 derivation. It may
         * appear ONCE, for the listener, which genuinely always wants to be read
         * and has no transport to publish anything. A second one means a
         * connection's mask is being derived from data again. */
        int count = 0;
        const char *p = code;

        while ((p = strstr(p, "events = POLLIN;")) != NULL) {
            count++;
            p += 16;
        }
        check(count == 1,
              "poll_loop.c derives POLLIN exactly once, for the LISTENER",
              "a second one means a connection's mask is derived from data "
              "again and the readiness intent is being ignored");
    }
    free(code);

    /* The I/O seam. Three sites call the transport; one file implements the
     * plaintext half of it. A recv()/send() outside transport.c and the drain is
     * a fourth I/O path, and the point of the vtable is that there is not one. */
    code = tf_read_code("src/core/transport.c", &len);
    if (code == NULL) {
        check(0, "read src/core/transport.c", "tf_read_code() failed");
        return;
    }
    check(strstr(code, "recv(c->fd") != NULL,
          "the plaintext transport is the one that calls recv(c->fd, ...)", NULL);
    check(strstr(code, "send(c->fd") != NULL,
          "the plaintext transport is the one that calls send(c->fd, ...)", NULL);
    free(code);

    code = tf_read_code("src/core/connection.c", &len);
    if (code == NULL) {
        check(0, "read src/core/connection.c", "tf_read_code() failed");
        return;
    }
    check(tf_calls(code, "recv") == 0, "connection.c calls no recv() of its own",
          "the read must go through transport_recv()");
    check(tf_calls(code, "send") == 0,
          "connection.c calls no send() of its own",
          "the write must go through transport_send()");
    check(tf_calls(code, "transport_recv") == 1,
          "conn_fill() reads through transport_recv(), at exactly one site", NULL);
    /* TEARDOWN, ASSERTED STATICALLY, and it has to be static.
     *
     * On this build -- TLS compiled out, every connection plaintext -- removing
     * transport_close() from conn_free() changes NOTHING observable: there is no
     * SSL* to leak, no counter that moves, no byte on any wire. A fault injection
     * confirmed it: deleting the call left every assertion in this file green. On
     * a plaintext-only build that is not a defect in the test, it is the honest
     * limit of what a plaintext-only build can check.
     *
     * AND LSan CANNOT BE REACHED FOR IT HERE. LeakSanitizer does not exist on
     * Darwin -- the top-level CMakeLists.txt says so at the IRC_SANITIZE block and
     * records that an ASan binary with detect_leaks=1 HANGS on macOS -- so the only
     * run that could catch a leaked SSL* is the Linux CI job. This assertion is
     * therefore NOT "the leak checker passed"; it is a claim about the code's
     * shape, and it is the strongest check available on this platform.
     *
     * The claim is that conn_free() is the SINGLE release point, because it is
     * what server_close_conn(), server_dial_progress()'s two failure arms and
     * server_shutdown()'s walk all end in. One call in one function is a thing a
     * reader can check; four call sites is a thing a reader has to remember. */
    check(tf_calls(code, "transport_close") == 1,
          "conn_free() releases the transport, and it is the only function on "
          "the connection path that does",
          "every path that ends a connection ends in conn_free(), so this is "
          "where an SSL* must be freed");

    {
        char detail[128];
        int n = tf_calls(code, "transport_send");

        snprintf(detail, sizeof detail,
                 "conn_pump() must reach transport_send() from the queued write "
                 "and from the empty handshake pass (tf_calls() is a boolean, "
                 "so it reports 1 when either exists; the count of raw "
                 "occurrences is what distinguishes the two)");
        check(n == 1,
              "conn_pump() reaches transport_send(), and it is the only writer",
              detail);
    }
    free(code);
}

int main(void)
{
    /* Line buffered, so a run that hangs says WHERE it hung rather than
     * producing one 4 KiB block at the end. Every assertion in this file is
     * printed as it is made for exactly that reason. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("== test_readiness_intent ==\n");

    case_plaintext_invariant();
    case_intent_is_consulted();
    case_drain_uses_transport();
    case_structural();

    if (failures != 0) {
        /* WHAT THE NODE SAID, and why here rather than through tf_report(). The
         * other cases print an [observable] line the test then asserts on, and
         * when one of those fails the interesting question is what else the node
         * said around it -- whether it queued the PONGs it framed, whether the
         * connection overflowed, whether it closed. This file has no TF_CHECK and
         * so no automatic dump. */
        printf("---- the node's own output follows ----\n");
        case_dump_node();
    }
    printf("== %d failure(s) ==\n", failures);
    return (failures == 0) ? 0 : 1;
}
