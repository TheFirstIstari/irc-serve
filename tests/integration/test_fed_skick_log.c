/* test_fed_skick_log.c -- the `fed_skick:` line has to be READABLE, and a withheld
 * value with no measurement beside it is not.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS BROKEN, AND WHAT IS NOT, BECAUSE THE TWO ARE EASY TO CONFUSE
 * ---------------------------------------------------------------------------
 * `fed_in_skick()` printed the peer's `<member>` and `<target>` fields as bare `%s`
 * arguments, two lines after `fed_in_smodes()` had been given the same treatment --
 * and the first reading of that is an injection: a peer sends
 * `SKICK <ESC>[2J ...` and a CSI sequence lands in an operator's terminal.
 *
 * IT WAS NOT AN INJECTION, and the reason matters for what this test asserts.
 * `fed_obs()` -- which the line already called -- renders every `%s` argument
 * through `conn_text_logsafe()`, which withholds any value holding a byte outside
 * printable ASCII as `-`. So the ESC never reached the terminal. What the line could
 * not do was be READ:
 *
 *     [observable] fed_skick: channel=#K by=- target=-
 *
 * reads identically whether the peer sent nothing in those fields or sent something
 * this node declined to print. `conn_text_logsafe()`'s own header calls the `-`
 * three things -- absent, unsafe, or too long for the field -- and says the `len=`
 * a caller prints beside it is what tells the last two apart. This line printed
 * neither. `fed_modes:` prints `by_len=` and `by_bad_bytes=`; `fed_skick:` did not.
 *
 * SO WHAT IS ASSERTED HERE IS THE MEASUREMENT, on the observable line itself:
 *
 *   by_len= / by_bad_bytes=          present, and naming the bytes the peer sent
 *   target_len= / target_bad_bytes=  present for the same reason
 *   by=-                             the ESC was WITHHELD, not printed
 *
 * The first pair is the teeth and the third is the safety property they make
 * checkable: a line that printed the byte would read `by_len=6 by_bad_bytes=0` and
 * `by=<ESC>[2J`, and a line that measured but stopped filtering would read
 * `by_bad_bytes=0`. The two are separate claims and both are asserted.
 *
 * ---------------------------------------------------------------------------
 * WHY A NEW FILE AND NOT A ROW IN test_peer_terminal_sweep.c
 * ---------------------------------------------------------------------------
 * The sweep is the right instrument for "did a byte reach a surface", and its SKICK
 * row puts its marker in the `<reason>` -- parameter 3, which `fed_relay_clean()`
 * filters on the outbound path. Moving a marker into `<member>` to witness the
 * measurement would put that byte on the PEER SOCKET instead, because `SKICK`'s
 * member and target fields are not among the parameters that filter covers. This
 * file therefore asserts one thing -- the node's own line -- and says so, rather than
 * borrowing an instrument whose second surface asks a different question.
 *
 * ---------------------------------------------------------------------------
 * THE FIXTURE, AND WHY IT IS AN INLINE CHILD
 * ---------------------------------------------------------------------------
 * One end of a federation link, owned by this test: it listens, the node dials it,
 * it answers with a genuine FEDERATE carrying the configured secret and this node's
 * version word, and from that moment the node believes it is talking to `irc.b` and
 * the test can put any line on that socket. The handshake is REAL and the link goes
 * through the real FSM; what is not real is the node on the far side, and that is
 * stated rather than papered over.
 *
 * An INLINE child rather than the shipped binary, for the reason the other peer tests
 * give: `fed_link_configure()` is a library call, and a command line cannot express
 * "dial the socket this test just opened" without racing the spawn.
 *
 * NO FIXED sleep() ANYWHERE (6.3): every wait is a deadline, and every wait is for an
 * OBSERVABLE LINE.
 */
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/server.h"
#include "federation/link.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/peer_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define SECRET "irc-serve-federation-secret-k"
#define NAME_A "irc.a"
#define PEER  "irc.b"
#define CHAN  "#K"

/* THE BYTE, written as an escape rather than as a literal. A C source file carrying a
 * raw 0x1B is unreadable in a diff, and this project has been bitten by invisible
 * bytes in source before: `conn_text_bad_count()` exists because a realname could
 * carry one. */
#define MARK "\033"  /* ESC: the first half of an ESC [ CSI sequence */

/* A TARGET WHO IS NOT A MEMBER, and the reason is structural rather than cosmetic.
 * `chan_remote_remove()` is called with `<target>` BEFORE the line is printed, so a
 * SKICK naming the channel's only member empties it and `chan_dispose_if_empty()`
 * takes the channel away -- and the next probe would be refused as a malformed
 * channel name, printing `fed_malformed:` instead of `fed_skick:` and satisfying its
 * wait for a reason that has nothing to do with the measurement. `dave` was never in
 * the roster, so nothing is removed, the channel survives all three probes, and the
 * claim stays the one this file makes: what the node PRINTS about a peer-chosen
 * field. */
#define TARGET "dave"

/* THE POLL INTERVAL for the waits below. A poll interval, not a sleep. */
#define WAIT_POLL_MS 20

static void child_tick(server_t *s, uint64_t now_ms)
{
    fed_tick(s, now_ms);
}

static int g_peer_port;

static void child_setup(server_t *s)
{
    struct sockaddr_in sa;

    /* The client surface BEFORE fed_open(): fed_open() saves whatever dispatch is
     * there and replaces it, so a commands_dispatch installed afterwards becomes the
     * node's whole dispatch and no peer line would ever reach the guard chain. The
     * symptom is silent and total -- a client that connects, registers nothing and
     * receives no numerics -- and node_fixture.h says so at length. */
    s->dispatch = commands_dispatch;
    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child; a node with an unopenable "
                 "federation module cannot reach any assertion in this test");
    s->on_tick = child_tick;
    /* THE SHIPPED TIMERS. Raised, like every peer test's, so that a link this test
     * breaks is noticed rather than being carried into the next probe -- and this
     * test's three probes are milliseconds apart, so a tighter value would only
     * make the module's own traffic land between them. */
    fed_set_timeouts(5000, 5000, 30000, 90000);

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)g_peer_port);
    TF_CHECK_MSG(fed_link_configure(s, PEER, (const struct sockaddr *)&sa,
                                    (socklen_t)sizeof sa) != NULL,
                 "the child could not configure peer %s on port %d", PEER,
                 g_peer_port);
}

/* The 2.4 stamp, rendered by the test rather than read from the node, because the
 * point of the case is what the node does with a stamp it did not mint. The epoch is
 * this test's own number and is compared against nothing; the id differs per line, so
 * two SKICKs are two messages to the dedup store rather than one being dropped as a
 * duplicate of the other -- which would be a third way for the probes below to pass
 * for the wrong reason. */
static void stamp(char *out, size_t cap, unsigned long id)
{
    (void)snprintf(out, cap,
                   "@irc-serve-origin=%s;irc-serve-epoch=1700000000;"
                   "irc-serve-id=%lu;irc-serve-hops=1 ", PEER, id);
}

/* A bounded substring search.
 *
 * `memmem()` IS THE OBVIOUS ANSWER AND IT IS NOT USABLE HERE: it is a GNU
 * extension, and test_peer_terminal_sweep.c records what that cost this project --
 * "it compiled on all thirteen local gate cells and failed on Linux's glibc", as one
 * implicit declaration and four pointer-versus-integer comparisons. `strstr()` is not
 * usable either, because every view below is bounded and the node's output buffer is
 * not NUL-terminated where it ends. */
static const char *find_bytes(const char *hay, size_t hlen, const char *needle,
                              size_t nlen)
{
    size_t i;

    if (nlen == 0u || hlen < nlen) {
        return NULL;
    }
    for (i = 0; i + nlen <= hlen; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) {
            return hay + i;
        }
    }
    return NULL;
}

static int view_has(const char *hay, size_t len, const char *needle)
{
    return find_bytes(hay, len, needle, strlen(needle)) != NULL;
}

/* THE NODE'S OWN STDOUT IS A PIPE, AND A FULL ONE STOPS THE NODE.
 *
 * The harness reads that pipe only when a caller waits on it, so every wait here has
 * to pump before it checks and after it checks. Pumping only after would hide a
 * deadlock: a node blocked inside write(2) needs the pump to make progress, and the
 * check is what decides whether to keep pumping. This pair is test_peer_terminal_
 * sweep.c's `drain_node_pipe()`, duplicated rather than shared for the reason that
 * file gives -- the nine lines would have to export the node type and the pump hook
 * into the marker-instrument header, which owns neither. */
static void drain_node_pipe(const nf_node_t *node)
{
    int pending = 0;

    if (nf_pending_bytes(node, &pending) != 0) {
        return; /* the descriptor cannot be asked; the buffer is what we have */
    }
    if (pending == 0) {
        return;
    }
    tc_pump();
}

/* wait_new(): WAIT FOR A LINE IN THE OUTPUT THE NODE HAS PRODUCED SINCE `from`.
 *
 * `nf_expect()` searches the node's ACCUMULATED output, so after the first probe
 * every needle in this file is already in the buffer and a wait returns instantly on
 * an earlier probe's line -- never pumping the pipe, so the probe in hand is then
 * judged on its neighbour's evidence. That is generator mistake 1 in
 * test_peer_terminal_sweep.c and the first version of this file made it too: probe 2
 * reported probe 1's line, the pump never ran, and every measurement assertion below
 * passed against a line the node had printed before the hostile byte was sent.
 *
 * Scoping to what is NEW is the fix, and the offset is unique by construction, so no
 * per-probe needle has to be invented -- which is what keeps the probes' `<member>`
 * and `<target>` values free to be the hostile ones.
 *
 * Returns 0 on success, -1 on the deadline. The deadline is a deadline and not a
 * sleep: the loop waits for READABILITY on the node's own pipe, capped at the poll
 * interval. */
static int wait_new(nf_node_t *node, size_t from, const char *needle, int timeout_ms)
{
    const unsigned long long deadline =
        pf_now_ms() + (unsigned long long)timeout_ms;
    const size_t nlen = strlen(needle);

    for (;;) {
        drain_node_pipe(node);
        if (from < node->out_len &&
            find_bytes(node->out + from, node->out_len - from, needle, nlen) != NULL) {
            return 0;
        }
        if (pf_now_ms() >= deadline) {
            return -1;
        }
        {
            struct timeval tv;
            fd_set rfds;

            FD_ZERO(&rfds);
            FD_SET(node->out_fd, &rfds);
            tv.tv_sec = 0;
            tv.tv_usec = (suseconds_t)(WAIT_POLL_MS * 1000);
            (void)select(node->out_fd + 1, &rfds, NULL, NULL, &tv);
        }
    }
}

/* The LAST `fed_skick:` line the node printed between `from` and now, as a bounded
 * view. "Last" rather than "first" because the wait above returns as soon as the
 * needle appears and the line may still be arriving; the needle is matched ANYWHERE
 * IN THE LINE because the line begins `[observable] `. */
static size_t last_skick_line(const nf_node_t *node, size_t from, const char **line)
{
    static const char needle[] = "fed_skick:";
    const size_t nlen = sizeof needle - 1u;
    size_t at = from;
    size_t found = from;
    int have = 0;

    while (at < node->out_len) {
        const char *nl = (const char *)memchr(node->out + at, '\n',
                                              node->out_len - at);
        const size_t n = (nl != NULL) ? (size_t)(nl - (node->out + at))
                                       : (node->out_len - at);

        if (find_bytes(node->out + at, n, needle, nlen) != NULL) {
            found = at;
            have = 1;
        }
        at += n + 1u;
    }
    *line = (have != 0) ? (node->out + found) : NULL;
    return (have != 0)
               ? strcspn(node->out + found, "\n")
               : 0u;
}

/* One probe: send `line`, wait for THIS node's `fed_skick:` line, and hand the caller
 * a bounded view of it.
 *
 * The `mark` is taken BEFORE the send, so "the line this probe produced" is decided by
 * when the bytes left rather than by which needle was chosen -- which is the whole
 * difference between a per-probe assertion and three probes sharing one. */
static void probe(nf_node_t *node, pf_peer_t *peer, const char *desc,
                  const char *line, unsigned long id, const char **view,
                  size_t *view_len)
{
    char block[256];
    size_t mark = node->out_len;

    stamp(block, sizeof block, id);
    {
        char stamped[512];
        int n = snprintf(stamped, sizeof stamped, "%s%s\r\n", block, line);

        TF_CHECK_MSG(n > 0 && (size_t)n < sizeof stamped,
                     "the %s probe line could not be built", desc);
        TF_CHECK_MSG(pf_send_line(peer->fd, stamped) == 0, "the %s send failed",
                     desc);
    }
    TF_CHECK_MSG(wait_new(node, mark, "fed_skick:", T_IO_MS) == 0,
                 "the node printed no `fed_skick:` line for the %s probe, so every "
                 "assertion about it would be about a line that does not exist. "
                 "Check that the probe's channel exists and its stamp is a NEW 2.4 "
                 "id: an id the dedup store has already seen is dropped silently.\n"
                 "  node said: %s", desc, node->out);
    *view_len = last_skick_line(node, mark, view);
}

int main(void)
{
    nf_node_t node;
    test_client_t client;
    pf_peer_t peer;
    int listen_fd;
    const char *view;
    size_t view_len;
    const char *const claim[] = {
        ":" NAME_A " FEDERATE " NAME_A " ",
        " " SECRET " " IRC_SERVE_VERSION "\r\n"
    };

    pf_peer_init(&peer);
    tc_init(&client);
    listen_fd = pf_listen_loopback(&peer.port);
    TF_CHECK_MSG(listen_fd >= 0, "the test could not open a listening socket");
    g_peer_port = peer.port;
    TF_CHECK_MSG(nf_spawn_inline_named(&node, NAME_A, child_setup) == 0,
                 "could not spawn the node under test");

    peer.fd = pf_accept_deadline(listen_fd, T_IO_MS);
    /* Closed as soon as it has served its purpose: a second listener would let a
     * second dial be accepted by accident, and every "there is one link" claim here
     * rests on there being exactly one. */
    (void)close(listen_fd);
    TF_CHECK_MSG(peer.fd >= 0, "the node never dialled the socket this test owns");

    /* READ THE CLAIM BEFORE ANSWERING IT. Without this, "the link is up" is satisfied
     * by a node that never said hello -- the vacuous-sweep failure peer_fixture.h's
     * header is about, and the reason that helper reads before it answers. */
    TF_CHECK_MSG(pf_read_until(peer.fd, claim, sizeof claim / sizeof claim[0],
                               T_IO_MS) == 0,
                 "the node never sent a FEDERATE naming itself with the configured "
                 "secret, so nothing below could mean anything.\n  node said: %s",
                 node.out);
    TF_CHECK_MSG(pf_send_line(peer.fd, ":" PEER " FEDERATE " PEER
                             " 1700000000 " SECRET " " IRC_SERVE_VERSION) == 0,
                 "the test could not answer with a FEDERATE");
    TF_CHECK_MSG(nf_expect(&node, "link_established: peer=" PEER, T_IO_MS) == 0,
                 "the link never came up, so every assertion below would be a pre-auth "
                 "drop wearing the right name.\n  node said: %s", node.out);

    /* THE CHANNEL HAS TO EXIST, and it has to exist on THIS node: `fed_in_skick()` is
     * reached through `fed_dispatch()`'s channel lookup, which returns NULL -- and
     * prints `fed_malformed:` rather than `fed_skick:` -- for a channel this node has
     * never heard of. It is the CLIENT's join rather than the peer's SJOIN because a
     * peer's SJOIN would make the PEER the origin, which is a different fixture with a
     * different set of ownership rules.
     *
     * AND THE CLIENT IS ALSO THE LIVENESS FENCE at the end: one event loop serves
     * both surfaces, so a node that answers a client PING is a node that is reading
     * its sockets and not wedged inside write(2). */
    TF_CHECK_MSG(tc_connect(&client, node.port) == 0,
                 "the client could not connect");
    TF_CHECK_MSG(tc_send(&client, "NICK carol") == 0, "NICK send failed");
    TF_CHECK_MSG(tc_send(&client, "USER carol 0 *spoofed :Real Carol") == 0,
                 "USER send failed");
    TF_CHECK_MSG(tc_expect(&client, " 001 ", T_IO_MS) == 0,
                 "the client never registered");
    TF_CHECK_MSG(tc_send(&client, "JOIN " CHAN) == 0, "the JOIN send failed");
    TF_CHECK_MSG(tc_expect(&client, " 366 ", T_IO_MS) == 0,
                 "the JOIN never completed, so the channel does not exist and every "
                 "SKICK below would be refused as a malformed channel name");

    /* ---------------------------------------------------------------------
     * PROBE 1: A CLEAN SKICK, WHICH IS WHAT MAKES PROBE 2 MEANINGFUL.
     *
     * Both fields are ordinary printable ASCII, so both are printed verbatim and both
     * measurements are zero. This is the case where the values are VISIBLE, and it is
     * asserted first so that a node which printed `-` for everything -- a node whose
     * filter had swallowed the whole field -- cannot pass the withheld case below by
     * accident. That is the same disguised-field trap test_peer_terminal_sweep.c
     * documents at ps_expect_withheld(), and it is why the two halves are separate
     * assertions rather than one "the field was handled" check.
     * --------------------------------------------------------------------- */
    {
        char line[256];

        (void)snprintf(line, sizeof line,
                       ":" PEER " SKICK " NAME_A " " CHAN " " TARGET " :out you");
        probe(&node, &peer, "clean", line, 700UL, &view, &view_len);
    }
    TF_CHECK_MSG(view != NULL && view_has(view, view_len, "by=" NAME_A),
                 "a peer-supplied `<member>` field of ordinary ASCII is printed "
                 "verbatim, so an operator can read what the peer said: %.*s",
                 (int)view_len, (view != NULL) ? view : "");
    TF_CHECK_MSG(view != NULL && view_has(view, view_len, "by_bad_bytes=0"),
                 "and the line says the field held no byte in the strip set, which is "
                 "what tells a withheld `by=-` apart from an empty one in the probe "
                 "below: %.*s", (int)view_len, (view != NULL) ? view : "");
    TF_CHECK_MSG(view != NULL && view_has(view, view_len, "target=" TARGET) &&
                     view_has(view, view_len, "target_bad_bytes=0"),
                 "and the same for `<target>`, because a line that measured one field "
                 "and not the other is the shape this pass is about: %.*s",
                 (int)view_len, (view != NULL) ? view : "");

    /* ---------------------------------------------------------------------
     * PROBE 2: A HOSTILE `<member>`, AND THE CLAIM IS THE MEASUREMENT.
     * --------------------------------------------------------------------- */
    {
        char line[256];

        (void)snprintf(line, sizeof line,
                       ":" PEER " SKICK " MARK "[2J " CHAN " " TARGET " :no");
        probe(&node, &peer, "hostile <member>", line, 701UL, &view, &view_len);
    }
    /* THE WITHHOLDING, which is fed_obs()'s job, asserted here so the measurement
     * below cannot be satisfied by a line that printed the byte AND counted it. */
    TF_CHECK_MSG(view != NULL && view_has(view, view_len, "by=-"),
                 "the ESC in the peer's `<member>` field is WITHHELD and printed as "
                 "`-`, so a CSI sequence is in nobody's terminal: %.*s",
                 (int)view_len, (view != NULL) ? view : "");
    TF_CHECK_MSG(view != NULL && view_has(view, view_len, MARK "[2J") == 0,
                 "and no part of the sequence it introduced appears anywhere on the "
                 "line, so the withholding is of the whole value rather than of the one "
                 "byte a counter can see: %.*s", (int)view_len,
                 (view != NULL) ? view : "");
    /* THE MEASUREMENT, and this is the assertion this file exists for. `by=-` on its
     * own says "absent, unsafe, or too long"; `by_len=` beside it says which. */
    TF_CHECK_MSG(view != NULL && view_has(view, view_len, "by_len="),
                 "the line does not carry `by_len=`, so a reader cannot tell a "
                 "withheld value from an empty field -- which is the whole defect: "
                 "`fed_obs()` withholds and this line did not MEASURE, so an operator "
                 "cannot see that a peer sent bytes it should not have sent: %.*s",
                 (int)view_len, (view != NULL) ? view : "");
    TF_CHECK_MSG(view != NULL && view_has(view, view_len, "by_bad_bytes="),
                 "the line does not carry `by_bad_bytes=`, so the same `by=-` reads "
                 "identically whichever of the two happened: %.*s", (int)view_len,
                 (view != NULL) ? view : "");
    /* AND `<target>`, which is the other peer-chosen field on the line. A fix that
     * measured `by=` and left `target=` bare would pass every assertion above. */
    TF_CHECK_MSG(view != NULL && view_has(view, view_len, "target=" TARGET) &&
                     view_has(view, view_len, "target_len=") &&
                     view_has(view, view_len, "target_bad_bytes=0"),
                 "`<target>` is measured the same way, because a line that measures one "
                 "peer-supplied field and prints the other bare is the shape this pass "
                 "is about: %.*s", (int)view_len, (view != NULL) ? view : "");

    /* ---------------------------------------------------------------------
     * PROBE 3: A HOSTILE `<target>`, so the OTHER field's withholding is witnessed
     * rather than assumed. The `<member>` is clean here, which is what makes this
     * probe's `target=-` attributable to the target rather than to a filter that had
     * already fired on the previous line.
     * --------------------------------------------------------------------- */
    {
        char line[256];

        (void)snprintf(line, sizeof line,
                       ":" PEER " SKICK " NAME_A " " CHAN " " MARK "[2J :no");
        probe(&node, &peer, "hostile <target>", line, 702UL, &view, &view_len);
    }
    TF_CHECK_MSG(view != NULL && view_has(view, view_len, "target=-") &&
                     view_has(view, view_len, "target_bad_bytes=") &&
                     view_has(view, view_len, "by=" NAME_A),
                 "the byte in `<target>` is withheld and MEASURED, and the clean "
                 "`<member>` beside it is still printed verbatim -- so the two halves are "
                 "distinguishable on one line, which is what a measurement is for: %.*s",
                 (int)view_len, (view != NULL) ? view : "");

    /* THE LIVENESS FENCE, last, so that every assertion above is a statement about a "
     "node that is still serving. */
    TF_CHECK_MSG(tc_send(&client, "PING :fence") == 0, "the fence PING failed");
    TF_CHECK_MSG(tc_expect(&client, "PONG", T_IO_MS) == 0,
                 "the node stopped answering, so the probe results above would be "
                 "about a node that had stopped reading its sockets");

    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    tc_close(&client);
    nf_free(&node);
    if (peer.fd >= 0) {
        (void)close(peer.fd);
    }
    return 0;
}
