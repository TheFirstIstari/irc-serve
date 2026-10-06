/* test_burst_malformed_log.c -- #135: a peer's <nick> on the branch that REFUSED it.
 *
 * ===========================================================================
 * WHY THIS EXISTS WHEN THERE IS ALREADY A PEER SWEEP
 * ===========================================================================
 * `test_peer_terminal_sweep.c` drives every shape a peer sends that this node
 * RENDERS, STORES or FORWARDS, and it does it with a real handshake on a real
 * socket. It has one structural gap, and it is the gap #135 was filed through:
 *
 *   Every shape in that sweep's table is a shape this node ACTS ON. The four sites
 *   this file covers are the shapes it REFUSES -- `SBURSTN` with the wrong arity,
 *   `SBURSTC` with the wrong arity, `SBURSTM` with the wrong arity -- and on a
 *   refusal the node prints the field it refused. `apply_nick()` logs
 *   `m->params[0]` precisely when `valid_nick()` has NOT run on it, because the
 *   shape check is the thing that failed. A sweep table entry for those shapes
 *   would assert a refusal, which is what its own header says it refuses to do:
 *   "a probe that can only ever produce 'refused' tests the refusal rather than
 *   the filter".
 *
 * So the sweep CANNOT reach them by construction, and the sweep's absence is not
 * evidence about them. This file is the missing half: it drives the REFUSAL shapes
 * and asserts on what the node printed about them.
 *
 * ===========================================================================
 * WHY THE BURST FAMILY AND NOT ANOTHER REFUSAL
 * ===========================================================================
 * Because the burst family is the one place on the peer path where a handler
 * prints a field from the line it is refusing, at three separate sites with three
 * separate `(m->nparams > N) ? m->params[N] : "?"` guards. Three instances of one
 * shape is what makes it a sweep's worth of work rather than a fix of whichever one
 * a reader happened to look at -- and a check that names `m->params[` in a `%s`
 * argument is what keeps the fourth from appearing.
 *
 * The peer here has to complete the real 2.3 handshake AND open a real burst
 * transaction, because `fed_burst_apply()` refuses a record line when
 * `g_shadow.open == 0`: "a record that arrives with nothing open is a peer out of
 * order with itself, and the alternative -- creating a shadow on a stray SBURSTN
 * -- would let a peer build this node's state without ever sending a BEGIN". A
 * test that skipped the BEGIN would be measuring the NO_TRANSACTION refusal, which
 * is a different line with a different shape, and that is the trap this file's
 * first draft fell into.
 *
 * ===========================================================================
 * WHAT IS ASSERTED, AND WHY IT IS ASSERTED TWICE
 * ===========================================================================
 * For each of the three shapes:
 *   1. the node REPORTED the malformed record -- so the probe was not silently
 *      ignored, which is the failure mode that makes a sweep vacuous;
 *   2. the node's own stdout contains NO marker byte -- which is the claim, and
 *      which is asserted over the WHOLE buffer rather than over the needle, so a
 *      withheld field and a leaked one cannot both be true.
 *
 * (1) without (2) would pass against a node that reported the refusal and then did
 * the thing anyway. (2) without (1) would pass against a node that ignored the line.
 * Both together are the pair test_fed_guards.c's header calls "the half with
 * teeth", and neither is a substitute for the other.
 *
 * ===========================================================================
 * NO FIXED sleep() ANYWHERE (6.3), NO SKIP, AND NO BUILD-CONFIGURATION DEPENDENCE
 * ===========================================================================
 * Every wait is a deadline over `nf_expect()`. The file runs identically with and
 * without TLS: it drives a PLAINTEXT peer link, which a node with `WITH_TLS=ON`
 * accepts as well as one without, and nothing here needs a crypto library.
 */
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#define SECRET "irc-serve-federation-secret-c"
#define NAME_A "irc.a"
/* A legal 2.4 tag value that is NOT this node's own name, because a claim of the
 * node's own name is SELF_NAME and this file is about the guards after the
 * handshake. */
#define PEER  "irc.b"
#define CHAN  "#T"

/* The one marker byte, and it is ESC because that is what a hostile peer would
 * send: 0x1b introduces a CSI sequence, so a log reader's terminal moves its
 * cursor, clears the screen or recolours. Octal so the C grammar cannot extend
 * the escape into what follows -- "\x1b[" would be one hex escape reading as
 * U+1B3 and the case would send something else entirely. */
#define MARK "\033"

/* The child, dialling THIS test's listener. */
static int g_peer_port;

static void child_tick(server_t *s, uint64_t now_ms)
{
    fed_tick(s, now_ms);
}

static void child_setup(server_t *s)
{
    struct sockaddr_in sa;

    s->dispatch = commands_dispatch;
    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child; a node with an unopenable "
                 "federation module cannot reach any assertion in this test");
    s->on_tick = child_tick;
    fed_set_timeouts(1000, 5000, 30000, 90000);

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons((unsigned short)g_peer_port);
    TF_CHECK_MSG(fed_link_configure(s, PEER, (const struct sockaddr *)&sa,
                                    (socklen_t)sizeof sa) != NULL,
                 "the child could not configure peer %s on port %d", PEER,
                 g_peer_port);
}

/* The 2.4 stamp, rendered here rather than read from the node: the point of the
 * case is what the node does with a stamp the node did not mint. `epoch` is this
 * test's own number and is never compared against anything; `id` differs per line
 * so two lines are two distinct messages to the dedup store rather than one being
 * dropped as a duplicate of the other. */
static void stamp(char *out, size_t cap, const char *origin, unsigned long id)
{
    (void)snprintf(out, cap,
                   "@irc-serve-origin=%s;irc-serve-epoch=1700000000;"
                   "irc-serve-id=%lu;irc-serve-hops=0 ", origin, id);
}

/* Does the node's output contain a byte from the log-injection set?
 *
 * CR and LF are skipped because the node's own log lines END with them; every
 * other byte in 0x00-0x1f, DEL and 0x80-0xff is a finding. Returns the first
 * offending byte or 0, and prints what it found at the call site so a failure
 * names the byte rather than just asserting "some byte".
 *
 * THE WHOLE BUFFER, NOT A WINDOW, and that is the point of the assertion: a
 * withheld field and a leaked one are distinguished by whether a byte is there at
 * all, so narrowing the search would defeat it.
 */
static unsigned char find_marker(const char *hay, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        const unsigned char c = (unsigned char)hay[i];

        if (c == '\r' || c == '\n') {
            continue;
        }
        if (c < 0x20u || c >= 0x7fu) {
            return c;
        }
    }
    return 0u;
}

/* OPEN THE BURST TRANSACTION, and this is called before EVERY probe rather than
 * once at the top -- which is the second thing a first draft of this file got
 * wrong, and the more interesting of the two.
 *
 * `shadow_discard()` CLOSES the transaction, and every refusal path in the burst
 * family calls it: "a record that arrives with nothing open is a peer out of order
 * with itself, and the alternative -- creating a shadow on a stray SBURSTN -- would
 * let a peer build this node's state without ever sending a BEGIN". So after probe
 * 1 is refused, the shadow is gone and probes 2 and 3 would each be answered
 * NO_TRANSACTION, which prints NOTHING of the record. All three probes would then
 * have asserted a line the node never prints, and the first one would have failed
 * while saying nothing about why.
 *
 * The BEGIN also carries a FRESH id every time, for the reason `stamp()`'s comment
 * gives: a shared (origin, epoch, id) is a duplicate, and G7 records on SIGHT and
 * drops before `fed_burst_apply()` runs. */
static void open_burst(nf_node_t *node, int peer_fd, unsigned long id)
{
    char block[256];
    char line[512];
    char needle[128];

    stamp(block, sizeof block, PEER, id);
    (void)snprintf(line, sizeof line, "%s:" PEER " SBURST 1700000000 0\r\n", block);
    (void)snprintf(needle, sizeof needle, "fed_burst_sent: peer=" PEER);
    TF_CHECK_MSG(pf_send_line(peer_fd, line) == 0,
                 "the SBURST begin (id=%lu) send failed", id);
    TF_CHECK_MSG(nf_expect(node, needle, T_IO_MS) == 0,
                 "the node never opened the burst transaction for id=%lu, so the "
                 "record line after it would be answered NO_TRANSACTION and nothing "
                 "of the record would be printed -- a different branch with a "
                 "different shape.\n  node said: %s", id, node->out);
}

/* One refusal probe: send `line`, require the node to report `needle`, and
 * require no marker byte to have reached its output.
 *
 * `from` is the length of the node's output BEFORE the line is sent, so the
 * marker scan can be over the WHOLE buffer (as it must be, per find_marker) while
 * the "the node still prints nothing unexpected" claim stays attributable to this
 * probe.
 */
static void probe(nf_node_t *node, int peer_fd, const char *what, const char *needle,
                  const char *line)
{
    unsigned char bad;

    TF_CHECK_MSG(pf_send_line(peer_fd, line) == 0, "%s: could not send", what);
    TF_CHECK_MSG(nf_expect(node, needle, T_IO_MS) == 0,
                 "%s: the node did not report the refusal, so the probe was "
                 "silently ignored and the marker scan below would be a clean "
                 "result for the wrong reason.\n  node said: %s", what, node->out);
    bad = find_marker(node->out, node->out_len);
    TF_CHECK_MSG(bad == 0u,
                 "%s: a byte from the log-injection set (0x%02x) reached the node's "
                 "own stdout from a field the node had just REFUSED to store. The "
                 "refusal's own log line is where a peer's raw nickname reaches the "
                 "operator.\n  node said: %s", what, bad, node->out);
}

int main(void)
{
    nf_node_t node;
    test_client_t client;
    char reply[512];
    char line[512];
    char block[256];
    const char *claim[2];
    int listen_fd;
    int peer_fd;

    listen_fd = pf_listen_loopback(&g_peer_port);
    TF_CHECK_MSG(listen_fd >= 0, "the test could not open a listening socket");
    TF_CHECK_MSG(nf_spawn_inline_named(&node, NAME_A, child_setup) == 0,
                 "could not spawn node A");

    peer_fd = pf_accept_deadline(listen_fd, T_IO_MS);
    /* The listener is the test's own and there is only ever one peer on it, so it
     * is closed here rather than at the end: leaving it open would mean a second
     * dial could be accepted by accident. */
    close(listen_fd);
    TF_CHECK_MSG(peer_fd >= 0, "node A never dialled the socket this test owns");

    /* A real handshake, read before it is answered, so "A established a link"
     * cannot be satisfied by a node that never spoke. */
    claim[0] = ":" NAME_A " FEDERATE " NAME_A " ";
    claim[1] = " " SECRET " " IRC_SERVE_VERSION "\r\n";
    TF_CHECK_MSG(pf_read_until(peer_fd, claim, 2, T_IO_MS) == 0,
                 "node A never sent a FEDERATE naming itself with the configured "
                 "secret, so nothing after this could mean anything.\n  node said: %s",
                 node.out);
    (void)snprintf(reply, sizeof reply,
                   ":" PEER " FEDERATE " PEER " 1700000000 %s %s\r\n", SECRET,
                   IRC_SERVE_VERSION);
    TF_CHECK_MSG(pf_send_line(peer_fd, reply) == 0,
                 "the test could not answer with a FEDERATE");
    TF_CHECK_MSG(nf_expect(&node, "link_established: peer=" PEER, T_IO_MS) == 0,
                 "node A never established its link, so every refusal below would be "
                 "a pre-auth drop wearing the wrong name.\n  node said: %s", node.out);

    /* A client on the node. Not a member of anything -- nothing here is delivered
     * to anybody -- but a node with no client at all has no place for a test to
     * observe from, and this file's subject is the node's OUTPUT rather than a
     * client's. It is here so a reader can see the sweep is not testing delivery,
     * which is what the other peer sweep is for. */
    TF_CHECK_MSG(tc_connect(&client, node.port) == 0, "the client could not connect");
    TF_CHECK_MSG(tc_send(&client, "NICK dave") == 0, "NICK send failed");
    TF_CHECK_MSG(tc_send(&client, "USER dave 0 *spoofed :Real dave") == 0,
                 "USER send failed");
    TF_CHECK_MSG(tc_expect(&client, " 001 ", T_IO_MS) == 0,
                 "the client never registered");

    /* OPEN THE BURST TRANSACTION ONCE, to prove the shape works and to keep the
     * reason visible where a reader will meet it; `open_burst()` is called again
     * before probes 2 and 3, because each refusal closes the shadow. */
    stamp(block, sizeof block, PEER, 1UL);
    (void)snprintf(line, sizeof line, "%s:" PEER " SBURST 1700000000 0\r\n", block);
    TF_CHECK_MSG(pf_send_line(peer_fd, line) == 0, "the SBURST begin send failed");
    TF_CHECK_MSG(nf_expect(&node, "fed_burst_sent: peer=" PEER, T_IO_MS) == 0,
                 "the node never opened the burst transaction, so every record line "
                 "below would be answered NO_TRANSACTION and nothing of the record "
                 "would be printed -- which is a different branch with a different "
                 "shape.\n  node said: %s", node.out);

    /* The stamp's origin MUST be the link's own name: apply_begin() refuses a
     * RELAYED_BURST, i.e. a burst whose tag block names a third server, because "a
     * burst is the full state of one origin, sent to the node that needs it, and a
     * node relaying it would be claiming to be the origin". The BEGIN above uses "
     PEER " for that reason and every probe below does too. */

    /* ------------------------------------------------------------------------
     * PROBE 1: SBURSTN WITH ONE PARAMETER, AND A MARKER IN IT.
     *
     * The nickname is the FIRST parameter and `apply_nick()` requires SIX, so
     * `valid_nick()` never runs and the log line's `nick=` is the peer's bytes. One
     * parameter is the minimum that reaches the print at all, which is why the
     * probe is this shape rather than a six-parameter line with a bad nickname: the
     * six-parameter line would be refused by `valid_nick()` and the refusal line
     * would carry a nickname the node had already checked.
     *
     * THE NEEDLE DOES NOT PIN `fd=`. The descriptor is an allocation, not a
     * property, and a needle that named it would be a needle that went stale the
     * next time a test in this binary opened something first. It starts at
     * `command=` and that is enough to be specific: there is exactly one line per
     * malformed record and this names which record.
     * ---------------------------------------------------------------------- */
    stamp(block, sizeof block, PEER, 2UL);
    (void)snprintf(line, sizeof line, "%s:" PEER "!u@h SBURSTN %sevil\r\n", block,
                   MARK);
    probe(&node, peer_fd, "SBURSTN with a marker in its nickname",
          "command=SBURSTN nick=- nick_len=5 nick_bad_bytes=1", line);

    /* PROBE 2: SBURSTC WITH ONE PARAMETER. The channel name is the first parameter
     * and `apply_chan()` requires SIX, so `chan_name_valid()` has not run and the
     * log line's `channel=` is the peer's bytes. The transaction is REOPENED first,
     * because probe 1's refusal discarded the shadow. */
    open_burst(&node, peer_fd, 3UL);
    stamp(block, sizeof block, PEER, 4UL);
    (void)snprintf(line, sizeof line, "%s:" PEER "!u@h SBURSTC %s#evil\r\n", block,
                   MARK);
    probe(&node, peer_fd, "SBURSTC with a marker in its channel name",
          "command=SBURSTC channel=- channel_len=6 channel_bad_bytes=1", line);

    /* PROBE 3: SBURSTM WITH THREE PARAMETERS. The member is the THIRD parameter and
     * `apply_member()` requires FIVE, so the guard is `(m->nparams > 2)`: with two
     * parameters the guard fails and the `?` placeholder is printed instead, and
     * with three the guard passes and the PEER'S STRING is printed. Three is the
     * shape that exercises the log line, and it is sent for exactly that reason --
     * the boundary is named here rather than left for a reader to work out. */
    open_burst(&node, peer_fd, 5UL);
    stamp(block, sizeof block, PEER, 6UL);
    /* THREE parameters, so the nickname really is params[2]: <chan> <server>
     * <nick>. Two would print `member=?` -- which the node did, and which is the
     * guard working rather than the filter. */
    (void)snprintf(line, sizeof line,
                   "%s:" PEER "!u@h SBURSTM " CHAN " " PEER " %seve\r\n", block,
                   MARK);
    probe(&node, peer_fd, "SBURSTM with a marker in its member name",
          "command=SBURSTM member=- member_len=4 member_bad_bytes=1", line);

    /* AND THE FOURTH SITE IS NOT REACHABLE FROM HERE, which is stated rather than
     * left to a reader: `fed_burst_unhandled:` prints `m->command`, and
     * `fed_burst_verb()` tests that same string against the table before this
     * function is reached, so a peer sending a verb that is in no row never gets
     * here. It is filtered anyway, at the cost of one pass on a path that does not
     * execute, because #134 established that a branch nobody can reach is a branch
     * nobody maintains -- and this file does not claim to have reached it.
     *
     * WHAT THIS FILE THEREFORE DOES NOT PROVE: that `m->command` can reach that
     * printf. It cannot, today. What it proves is that the three shapes a peer CAN
     * send and this node DOES report no longer put a peer byte on stdout, and
     * `scripts/check-peer-log-sites.py` is what keeps the fourth filtered without
     * this file having to reach it. */

    TF_CHECK_MSG(nf_stop(&node) == 0, "node A did not exit cleanly");
    tc_close(&client);
    nf_free(&node);
    if (peer_fd >= 0) {
        close(peer_fd);
    }

    tf_done("burst_malformed_log");
    return 0;
}
