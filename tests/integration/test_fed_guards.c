/* test_fed_guards.c -- every guard in fed_dispatch()'s chain, driven by a peer
 * that is trying to get past them.
 *
 * docs/SERVER_DESIGN.md 2.4 (the loop-prevention rules) and 7/Phase 6 (the
 * inbound S-verb path is where they are enforced).
 *
 * ---------------------------------------------------------------------------
 * WHY THE PEER IS A RAW SOCKET AND NOT A SECOND NODE
 * ---------------------------------------------------------------------------
 * Every guard in the chain is a REFUSAL of a line a well-behaved node would
 * never send: hops at the ceiling, an origin that names the receiver, the same
 * id twice, no tag block at all, a verb that is not in 4.3. A second node built
 * from this code cannot produce any of them, so a two-node fixture can only
 * prove the guards are not reached -- which is a real property, and it is what
 * test_fed_loop.c and test_fed_roster.c assert, but it is not the same property
 * as "the guard works".
 *
 * So this test owns ONE END of a link. It listens, node A dials it, it answers
 * A's FEDERATE with a correct claim, and from that moment A believes it is
 * talking to a peer named irc.b -- and the test can then put any line it likes on
 * that socket, tagged however it likes. That is the only way to reach a guard,
 * and reaching a guard is the whole of what this file is for.
 *
 * The handshake is still real: the answer is a genuine FEDERATE with the right
 * name, the right shared secret and the right version word, and A's link goes
 * through the real FSM. What is not real is the node on the far side, and the
 * test says so rather than pretending otherwise.
 *
 * ---------------------------------------------------------------------------
 * EVERY CASE ASSERTS THE REFUSAL *AND* THE ABSENCE OF THE EFFECT
 * ---------------------------------------------------------------------------
 * The observable line a guard prints is the guard talking about itself, and a
 * guard that prints a line and then does the thing anyway would pass a test that
 * only looked for the line. So every case here asserts two things: the node
 * reported the refusal with its own reason, AND the client on the node did not
 * receive the thing that was refused. The second half is the half that has
 * teeth, and it is a client-side byte check -- observable, not a struct read.
 *
 * NO FIXED sleep() ANYWHERE (6.3). Every wait is a deadline over nf_expect() or
 * tc_expect(), and the local socket helpers are select() loops.
 */
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/server.h"
#include "federation/link.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define SECRET "irc-serve-federation-secret-a"
#define NAME_A "irc.a"
/* The name this test's socket claims. It is a legal 2.4 tag value and it is not
 * the node's own name, because a claim of the node's own name is SELF_NAME and
 * this file is about the guards that come after the handshake. */
#define PEER   "irc.b"
#define CHAN   "#T"
#define NICK_C "carol"

/* ---------------------------------------------------------------------------
 * The child
 * ---------------------------------------------------------------------------
 * One node, dialling THIS TEST. No peer is configured and there is no port to
 * hand it: the address is the socket this test already owns, which is why the
 * node is spawned after the listener and not before.
 */
static int g_peer_port;
static int g_trace;

static void child_tick(server_t *s, uint64_t now_ms)
{
    fed_tick(s, now_ms);
}

static void child_setup(server_t *s)
{
    struct sockaddr_in sa;

    /* The client command surface, installed BEFORE fed_open(): fed_open() saves
     * whatever dispatch is there and replaces it with its own, so a
     * commands_dispatch installed afterwards would become the node's whole
     * dispatch and the peer path would never be reached. The fixture brings up a
     * server_t and a listener and nothing else, and s->dispatch is NULL on a
     * fresh node. */
    s->dispatch = commands_dispatch;

    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child; a node with an unopenable "
                 "federation module cannot reach any assertion in this test");
    s->trace = g_trace;
    s->on_tick = child_tick;
    /* The shipped keepalive and dead thresholds, deliberately: this test sends a
     * handful of lines over a few seconds, and shortening the keepalive would
     * put PINGs on the peer link that the test's own sends would have to be
     * distinguished from. */
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

/* ---------------------------------------------------------------------------
 * Local socket helpers
 * ---------------------------------------------------------------------------
 * Two, and both because this test is the SERVER half of a peer connection and
 * harness/irc_client.h is the client half. They are deadline waits over select()
 * for the same reason everything else here is.
 */
static uint64_t now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000L);
}

static int listen_loopback(int *port_out)
{
    struct sockaddr_in sa;
    socklen_t len = sizeof sa;
    int one = 1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        return -1;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0 ||
        listen(fd, 8) != 0 ||
        getsockname(fd, (struct sockaddr *)&sa, &len) != 0) {
        close(fd);
        return -1;
    }
    *port_out = (int)ntohs(sa.sin_port);
    return fd;
}

static int accept_deadline(int listen_fd, int timeout_ms)
{
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    fd_set rfds;
    int rc;

    for (;;) {
        struct timeval tv;
        uint64_t left = (deadline > now_ms()) ? deadline - now_ms() : 0;

        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);
        tv.tv_sec = (time_t)(left / 1000u);
        tv.tv_usec = (suseconds_t)((left % 1000u) * 1000u);
        rc = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (rc == 0) {
            return -1;
        }
        return accept(listen_fd, NULL, NULL);
    }
}

/* Read until `needle` has appeared in what has arrived, or the deadline passes.
 * All the needles in ONE call rather than one call each: the buffer is local, so
 * a second call starts from nothing and can never see the bytes the first
 * consumed. */
static int read_until(int fd, const char *const *needles, size_t nneedles,
                      int timeout_ms)
{
    char buf[4096];
    char seen[8192];
    size_t used = 0;
    size_t got_all = 0;
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;

    for (;;) {
        struct timeval tv;
        uint64_t left = (deadline > now_ms()) ? deadline - now_ms() : 0;
        fd_set rfds;
        ssize_t got;
        int rc;

        if (got_all == nneedles) {
            return 0;
        }
        if (used >= sizeof seen - 1u) {
            break;
        }
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        tv.tv_sec = (time_t)(left / 1000u);
        tv.tv_usec = (suseconds_t)((left % 1000u) * 1000u);
        rc = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (rc <= 0) {
            break;
        }
        got = read(fd, buf, sizeof buf);
        if (got <= 0) {
            break;
        }
        if ((size_t)got >= sizeof seen - 1u - used) {
            got = (ssize_t)(sizeof seen - 1u - used);
        }
        memcpy(seen + used, buf, (size_t)got);
        used += (size_t)got;
        seen[used] = '\0';
        got_all = 0;
        for (size_t i = 0; i < nneedles; i++) {
            if (strstr(seen, needles[i]) != NULL) {
                got_all++;
            }
        }
    }
    return (got_all == nneedles) ? 0 : -1;
}

static int send_line(int fd, const char *line)
{
    size_t n = strlen(line);
    size_t off = 0;

    while (off < n) {
        ssize_t got = write(fd, line + off, n - off);

        if (got <= 0) {
            return -1;
        }
        off += (size_t)got;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * G1 AND G3: A LINE THAT ARRIVES BEFORE THE HANDSHAKE
 * ---------------------------------------------------------------------------
 * The first guard, and the one with a cost: the line is dropped and counted, and
 * THE LINK IS NOT TORN DOWN.
 *
 * IT IS REACHED FROM THE DIALING SIDE, and that is not incidental. A connection
 * only becomes CONN_SERVER when fed_link_established() runs, so a line that
 * arrives on a link still in HANDSHAKE_SENT is a line a peer sent BEFORE it said
 * hello -- and on this side of the handshake that is the only shape the case has.
 * A client connection is not it at all: commands_dispatch() answers a client line
 * from the client table and never calls the guard chain, which is 3's "one path
 * for local and remote input" doing its job.
 *
 * "NOT TORN DOWN" IS ASSERTED BY WHAT HAPPENS NEXT, which is the honest way to
 * assert it: the very next line this test sends is the FEDERATE, and the link
 * reaches ESTABLISHED. A guard that closed the connection would make a peer that
 * speaks before it says hello permanently unconnectable, and the handshake FSM has
 * no way to recover from that -- so the sequence below is the assertion, and a
 * separate observable would only be a report of it. */
static void case_preauth_drop(nf_node_t *node, int *peer_fd)
{
    char line[512];
    size_t before = tf_count(node->out, "fed_preauth_drop:");

    /* No tag block, a server prefix, and a verb that would otherwise be acted on
     * -- everything a real pre-auth line looks like. The channel does not exist
     * on this node, so an accepted line would be a malformed-target drop rather
     * than a delivery, and the pre-auth counter is the property under test
     * anyway. */
    (void)snprintf(line, sizeof line, ":" PEER " SPRIVMSG " CHAN " :toosoon\r\n");
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0,
                 "the test could not send the pre-auth line");
    TF_CHECK_MSG(nf_expect(node, "fed_preauth_drop: ", T_IO_MS) == 0,
                 "a line that arrived before the handshake was not dropped and "
                 "counted. A pre-auth line is a stranger talking, and the answer "
                 "to a stranger is the handshake rather than a closed socket: %s",
                 node->out);
    TF_CHECK_MSG(tf_count(node->out, "fed_preauth_drop:") > before,
                 "the pre-auth drop was reported but not counted, so an operator "
                 "reading the counters cannot see a stranger talking to the node: "
                 "%s",
                 node->out);
    /* The line named no one, so nothing was applied and nothing was forwarded:
     * the drop has to be a drop and not a deferral. */
    TF_CHECK_MSG(strstr(node->out, "toosoon") == NULL,
                 "the pre-auth line was acted on rather than dropped: %s",
                 node->out);
}

/* ---------------------------------------------------------------------------
 * The peer, established
 * ---------------------------------------------------------------------------
 * `line` is the FIRST thing this test puts on the link, and every case after it
 * is a line the node is meant to refuse. */
typedef struct {
    int fd;
    int port;
} hostile_peer_t;

/* `preauth` is a callback invoked on the accepted socket AFTER node A's claim
 * has been read and BEFORE this test answers it. It exists so the pre-auth guard
 * can be exercised on a link that is still in HANDSHAKE_SENT, and it is a
 * callback rather than an inline block so the same handshake carries the
 * unsolicited line and the answer -- the case that proves the guard drops the
 * line WITHOUT tearing the link down is a sequence, not a property. */
typedef void (*peer_mid_fn)(nf_node_t *node, int *peer_fd);

static void peer_open(hostile_peer_t *p, nf_node_t *node, test_client_t *client,
                      peer_mid_fn mid)
{
    char reply[512];
    char line[256];
    int listen_fd;
    const char *const needles[] = {
        ":" NAME_A " FEDERATE " NAME_A " ",
        " " SECRET " " IRC_SERVE_VERSION "\r\n"
    };

    listen_fd = listen_loopback(&p->port);
    TF_CHECK_MSG(listen_fd >= 0, "the test could not open a listening socket");
    g_peer_port = p->port;
    g_trace = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(node, NAME_A, child_setup) == 0,
                 "could not spawn node A");

    p->fd = accept_deadline(listen_fd, T_IO_MS);
    /* The listener is the test's own and there is only ever one peer, so it is
     * closed here rather than at the end: leaving it open would mean a second
     * dial could be accepted by accident and the "one link" the cases below rest
     * on would be two. */
    close(listen_fd);
    TF_CHECK_MSG(p->fd >= 0, "node A never dialled the socket this test owns");

    /* Read A's claim first, for the reason test_fed_handshake.c gives: without
     * it, "A established a link" would be satisfied by a node that never sent a
     * handshake. Pinned on both sides of the epoch, which is a clock reading. */
    TF_CHECK_MSG(read_until(p->fd, needles, sizeof needles / sizeof needles[0],
                            T_IO_MS) == 0,
                 "node A never sent a FEDERATE naming itself with the configured "
                 "secret, so nothing after this could mean anything");

    if (mid != NULL) {
        mid(node, &p->fd);
    }

    /* The claim. Correct in every field, so the handshake SUCCEEDS and the
     * guards below are reachable -- a test that stopped at the handshake would
     * pass against a node that refuses every line from every peer, which is not
     * a property anything wants. */
    (void)snprintf(reply, sizeof reply, ":" PEER " FEDERATE " PEER " 1700000000 %s %s\r\n",
                   SECRET, IRC_SERVE_VERSION);
    TF_CHECK_MSG(send_line(p->fd, reply) == 0,
                 "the test could not answer with a FEDERATE");
    TF_CHECK_MSG(nf_expect(node, "link_established: peer=" PEER, T_IO_MS) == 0,
                 "node A never established its link, so the guards below are "
                 "unreachable and every assertion in this file would be vacuous: "
                 "%s",
                 node->out);

    /* A client on the node, in the channel, so that a refusal is a statement
     * about bytes the client did not receive rather than about a line the node
     * never had anyone to give it to. */
    TF_CHECK_MSG(tc_connect(client, node->port) == 0, "the client could not connect");
    (void)snprintf(line, sizeof line, "NICK %s", NICK_C);
    TF_CHECK_MSG(tc_send(client, line) == 0, "NICK send failed");
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", NICK_C, NICK_C);
    TF_CHECK_MSG(tc_send(client, line) == 0, "USER send failed");
    TF_CHECK_MSG(tc_expect(client, " 001 ", T_IO_MS) == 0,
                 "the client never registered");
    (void)snprintf(line, sizeof line, "JOIN " CHAN);
    TF_CHECK_MSG(tc_send(client, line) == 0, "JOIN send failed");
    TF_CHECK_MSG(tc_expect(client, " 366 ", T_IO_MS) == 0,
                 "the client's JOIN never completed, so it is not a member and a "
                 "refused delivery to it would prove nothing");
}

static void peer_close(hostile_peer_t *p, nf_node_t *node, test_client_t *client)
{
    TF_CHECK_MSG(nf_stop(node) == 0, "node A did not exit cleanly");
    tc_close(client);
    nf_free(node);
    if (p->fd >= 0) {
        close(p->fd);
        p->fd = -1;
    }
}

/* How many times `needle` appears in everything the client has received. The
 * needle is a single word with no spaces, so the count is a count of DELIVERIES
 * and not of words. */
static size_t times_seen(const test_client_t *c, const char *needle)
{
    const char *p = tc_buffer(c);
    size_t n = 0;
    size_t len = strlen(needle);

    while ((p = strstr(p, needle)) != NULL) {
        n++;
        p += len;
    }
    return n;
}

/* The 2.4 stamp, rendered by the test rather than read from the node, because
 * the point of every case below is what the node does with a stamp the node did
 * not mint. */
static void stamp(char *out, size_t cap, const char *origin, unsigned long epoch,
                  unsigned long id, unsigned long hops)
{
    (void)snprintf(out, cap,
                   "@irc-serve-origin=%s;irc-serve-epoch=%lu;irc-serve-id=%lu"
                   ";irc-serve-hops=%lu ",
                   origin, epoch, id, hops);
}

/* ---------------------------------------------------------------------------
 * G5: THE HOP CEILING
 * ---------------------------------------------------------------------------
 * hops=10 is exactly IRC_MAX_HOPS, and 2.4 says the message is dropped AT 10 --
 * so `>=`, not `>`. A ceiling written as `>` would pass every message one hop
 * further than the design allows and the only way to notice is a peer that puts
 * hops=10 on the wire, which is what this line is.
 *
 * The stamp names a THIRD origin, so nothing else in the chain can refuse it:
 * it is not this node's own origin (G6), and the id is fresh (G7). The message
 * would otherwise have been delivered to the client, which is what makes the
 * client-side assertion below the half with teeth. */
static void case_hop_ceiling(nf_node_t *node, test_client_t *client, int *peer_fd)
{
    char line[512];
    char block[256];
    size_t mark = tc_received(client);

    stamp(block, sizeof block, "irc.z", 1700000001UL, 500UL, 10UL);
    (void)snprintf(line, sizeof line, "%s:" NICK_C "!u@1.2.3.4 SPRIVMSG " CHAN
                                    " :atthelimit\r\n",
                   block);
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0, "the test could not send the line");

    TF_CHECK_MSG(nf_expect(node, "fed_hop_drop: ", T_IO_MS) == 0,
                 "a message with hops=10 was not reported as past the hop "
                 "ceiling. 2.4 drops the message AT %d and the check has to be "
                 "`>=`, not `>`, so this is the line that separates the two.",
                 10);
    TF_CHECK_MSG(strstr(tc_buffer(client) + mark, "atthelimit") == NULL,
                 "a message at the hop ceiling was DELIVERED to a local member. "
                 "The node reported a hop drop and did the thing anyway, which is "
                 "a worse failure than either alone: %s",
                 tc_buffer(client));
}

/* ---------------------------------------------------------------------------
 * G6: NEVER ACT ON OUR OWN ORIGIN
 * ---------------------------------------------------------------------------
 * The inbound half of 2.4's second rule, and the half a two-node test cannot
 * reach, because in a two-node mesh the message that comes back is the one the
 * node just sent and the node's own `fanout_forward_link()` would have refused it
 * at forward time before it was ever written. Here the stamp claims this node's
 * origin from the OUTSIDE, which is the only way to make the RECEIPT-side check
 * the thing under test.
 *
 * The drop is what stops the two-node cycle. Without it the node would deliver
 * the message to its own member, forward it onward, and the mesh would circulate
 * it -- and the hop ceiling would be the only thing left, which bounds it at ten
 * passes rather than stopping it. */
static void case_own_origin(nf_node_t *node, test_client_t *client, int *peer_fd)
{
    char line[512];
    char block[256];
    size_t mark = tc_received(client);

    stamp(block, sizeof block, NAME_A, 1700000002UL, 501UL, 1UL);
    (void)snprintf(line, sizeof line, "%s:" NICK_C "!u@1.2.3.4 SPRIVMSG " CHAN
                                    " :ownorigin\r\n",
                   block);
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0, "the test could not send the line");

    TF_CHECK_MSG(nf_expect(node, "fed_own_origin_drop: ", T_IO_MS) == 0,
                 "a message whose origin is THIS node was not dropped. The stamp "
                 "above names %s and the node is %s, and a stamp that did not "
                 "match would leave the two-node cycle unbounded except by the "
                 "hop ceiling.",
                 NAME_A, NAME_A);
    TF_CHECK_MSG(strstr(tc_buffer(client) + mark, "ownorigin") == NULL,
                 "a message of this node's own origin was DELIVERED to a local "
                 "member: %s",
                 tc_buffer(client));
}

/* ---------------------------------------------------------------------------
 * G7: THE DEDUP STORE
 * ---------------------------------------------------------------------------
 * One line, sent TWICE, and the two facts that matter are that the first was
 * acted on and the second was not -- and that the record is made AT THE GUARD,
 * so it exists whether or not the handler ran. The pair is asserted on a
 * non-delivering verb as well as on a delivering one, because "recorded after
 * apply" is the shape that lets a peer retry a malformed line under a new id
 * and be believed.
 *
 * The count is over the client's whole conversation, so a second delivery
 * anywhere in it is caught rather than only a second delivery here. */
static void case_duplicate_dropped(nf_node_t *node, test_client_t *client,
                                   int *peer_fd)
{
    char line[512];
    char block[256];

    stamp(block, sizeof block, "irc.z", 1700000003UL, 777UL, 1UL);
    (void)snprintf(line, sizeof line, "%s:" NICK_C "!u@1.2.3.4 SPRIVMSG " CHAN
                                    " :onlyonce\r\n",
                   block);
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0, "the test could not send the line");
    /* The first one is acted on. Waiting for it is what makes the count below a
     * statement about the SECOND copy rather than about a node that delivered
     * neither. */
    TF_CHECK_MSG(tc_expect(client, " PRIVMSG " CHAN " onlyonce\r\n", T_IO_MS) == 0,
                 "the first copy of a message with a fresh id was not delivered, "
                 "so the duplicate case below would be satisfied by a node that "
                 "delivers nothing: %s",
                 tc_buffer(client));
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0,
                 "the test could not send the second copy");

    TF_CHECK_MSG(nf_expect(node, "fed_duplicate: ", T_IO_MS) == 0,
                 "the same (origin, epoch, id) was accepted twice. 2.4's key is "
                 "that triple and a second copy of it is a message this node has "
                 "already been sent.");
    TF_CHECK_MSG(times_seen(client, "onlyonce") == 1,
                 "the client's client saw a duplicated message %lu times; 2.4's "
                 "whole point is that a second copy is dropped, not re-delivered",
                 (unsigned long)times_seen(client, "onlyonce"));
    /* The two counters are the same event at two levels, and a difference
     * between them would be a bug in the chain rather than a number nobody
     * looked at. */
    TF_CHECK_MSG(nf_expect_u64(node, "fed_dup_drop=", 1, T_IO_MS) == 0,
                 "node A never published fed_dup_drop=1, so the guard's own count "
                 "of the drop is missing even though it reported one: %s",
                 node->out);
    TF_CHECK_MSG(nf_expect_u64(node, "fed_dedup_dup=", 1, T_IO_MS) == 0,
                 "the store's count of the duplicate is not 1. The two counters "
                 "are the same event read at two levels -- the guard's drop and "
                 "the store's duplicate -- and a difference between them is a bug "
                 "in the chain rather than a number nobody looked at: %s",
                 node->out);
}

/* ---------------------------------------------------------------------------
 * G4 CASE B: AN UNTAGGED RELAY FROM A PEER
 * ---------------------------------------------------------------------------
 * The trust boundary, and the case that makes it a boundary rather than a check.
 * A peer relaying a message it received FOR A CHANNEL IT HAS A MEMBER IN sends
 * SPRIVMSG with a REMOTE prefix -- the relayed user's hostmask, not its own
 * server name -- and a node that cannot tell that apart from its own peer
 * injecting a fresh message has no loop prevention: there is no origin to check
 * against our own name, no hop count to apply the ceiling to, and no
 * (origin, epoch, id) to record, so every 2.4 rule is unavailable on the line at
 * exactly the moment it is most needed.
 *
 * The discriminator is therefore THE PREFIX and never the verb, and this case is
 * the one that says so: the verb is the most ordinary verb in 4.3 and the line is
 * still refused, because the prefix names a server other than the link's.
 *
 * The link is NOT torn down, and the next case depends on that: the same socket
 * carries a line this node does accept. */
static void case_untagged_relay_refused(nf_node_t *node, test_client_t *client,
                                        int *peer_fd)
{
    char line[512];
    size_t mark = tc_received(client);

    /* A remote user, on a remote server, relaying with no block. There is no
     * tag at all here -- that is the whole of the case. */
    (void)snprintf(line, sizeof line,
                   ":mallory!u@example.org SPRIVMSG " CHAN " :relayeduntagged\r\n");
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0, "the test could not send the line");

    TF_CHECK_MSG(nf_expect(node, "fed_untagged: fd=", T_IO_MS) == 0,
                 "an untagged line whose prefix names another server was not "
                 "reported. Every 2.4 guard is unavailable on such a line, and a "
                 "node that accepts them has no loop prevention at all: %s",
                 node->out);
    TF_CHECK_MSG(strstr(node->out, "reason=RELAY_UNTAGGED") != NULL,
                 "the refusal did not name RELAY_UNTAGGED, so an operator reading "
                 "it cannot tell a relay from a malformed prefix: %s",
                 node->out);
    TF_CHECK_MSG(strstr(tc_buffer(client) + mark, "relayeduntagged") == NULL,
                 "an untagged relay was DELIVERED to a local member: %s",
                 tc_buffer(client));
    /* The link survives. A peer that sent one untagged line is a peer with a
     * version mismatch, not an attacker, and dropping the link turns a
     * configuration problem into an outage. */
    TF_CHECK_MSG(strstr(node->out, "link_rejected:") == NULL,
                 "the node rejected the LINK over one untagged relay, so the next "
                 "case -- which needs the same socket -- cannot run: %s",
                 node->out);
}

/* ---------------------------------------------------------------------------
 * G4 CASE A: AN UNTAGGED LINE FROM THE PEER'S OWN SERVER
 * ---------------------------------------------------------------------------
 * The other half, and the one that says the guard discriminates on the PREFIX
 * rather than on the presence of tags. This line has the same missing block as
 * the case above and is ACCEPTED, because its prefix names the link's own server
 * -- so the peer ORIGINATED it rather than relaying it.
 *
 * The identity is then SUPPLIED rather than read, and the observable says which
 * values: the origin is the peer, the epoch is the PEER's, the id is minted here
 * and the hop count starts at zero. Two nodes minting for the same peer both pair
 * their own counter with the peer's boot, so two relays of one untagged line
 * collapse onto one key instead of appearing as two messages. */
static void case_untagged_origin_accepted(nf_node_t *node, test_client_t *client,
                                          int *peer_fd)
{
    char line[512];

    (void)snprintf(line, sizeof line, ":" PEER " SPRIVMSG " CHAN " :originated\r\n");
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0, "the test could not send the line");
    TF_CHECK_MSG(tc_expect(client, " PRIVMSG " CHAN " originated\r\n", T_IO_MS) == 0,
                 "an untagged line whose prefix names the link's OWN server was "
                 "not delivered. The node cannot tell a peer originating a line "
                 "from a peer relaying one by anything except the prefix, and "
                 "refusing both would be refusing the peer's own traffic: %s",
                 tc_buffer(client));
    TF_CHECK_MSG(nf_expect(node, "reason=ORIGINATED_UNTAGGED", T_IO_MS) == 0,
                 "the node did not say that it SUPPLIED the identity for the "
                 "untagged originated line, so there is no record of which epoch "
                 "and which id it invented: %s",
                 node->out);
}

/* ---------------------------------------------------------------------------
 * G8 AND G9: THE VERB TABLE AND THE FIELD CHECKS
 * --------------------------------------------------------------------------- */
static void case_verb_and_field_checks(nf_node_t *node, int *peer_fd)
{
    char line[512];
    char block[256];
    int before;

    /* A 4.3 verb this build has not implemented. It is a DEFERRED verb and not
     * an unknown one, and the two are different facts for an operator: the first
     * means "a peer is running a build I do not have", the second means "a peer
     * is talking nonsense". Reporting the first as the second makes the counter
     * mean two incompatible things. */
    before = (int)tf_count(node->out, "fed_unknown_verb:");
    stamp(block, sizeof block, "irc.z", 1700000004UL, 601UL, 1UL);
    (void)snprintf(line, sizeof line, "%s:" PEER " SNAMES " CHAN "\r\n", block);
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0, "the test could not send the line");
    TF_CHECK_MSG(nf_expect(node, "fed_verb_deferred: ", T_IO_MS) == 0,
                 "a 4.3 verb this build does not implement was not reported as "
                 "deferred: %s",
                 node->out);

    /* A word that is not in 4.3 at all. */
    stamp(block, sizeof block, "irc.z", 1700000005UL, 602UL, 1UL);
    (void)snprintf(line, sizeof line, "%s:" PEER " NOSUCHVERB " CHAN "\r\n", block);
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0, "the test could not send the line");
    TF_CHECK_MSG(nf_expect(node, "fed_unknown_verb: ", T_IO_MS) == 0,
                 "a verb that is not in 4.3's list was not reported as unknown: %s",
                 node->out);
    TF_CHECK_MSG((int)tf_count(node->out, "fed_unknown_verb:") == before + 1,
                 "the deferred verb above was counted as an UNKNOWN verb, so the "
                 "counter means both 'a peer is wrong' and 'a peer is newer than "
                 "me' and is evidence of neither: %s",
                 node->out);

    /* An SJOIN with the wrong arity. 4.3's frozen shape is exactly FOUR
     * parameters -- `<channel> <member> <flags> <account>` since Phase 10.3 -- and a
     * two-parameter one is a peer running a different format: reading params[2] of
     * it would be a read of a field that does not exist. A THREE-parameter line is
     * now the shape of a build that predates the account field, and it is refused
     * for the same reason and by the same check; the case below is the short one
     * because it is the one that was already here. */
    stamp(block, sizeof block, "irc.z", 1700000006UL, 603UL, 1UL);
    (void)snprintf(line, sizeof line, "%s:" PEER " SJOIN " CHAN " mallory\r\n", block);
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0, "the test could not send the line");
    TF_CHECK_MSG(nf_expect(node, "fed_malformed: ", T_IO_MS) == 0,
                 "an SJOIN with two parameters was accepted. The frozen shape is "
                 "three, and a node that reads the third out of a two-parameter "
                 "line is reading a field that does not exist: %s",
                 node->out);
    TF_CHECK_MSG(strstr(node->out, "field=arity") != NULL,
                 "the malformed report did not name the ARITY as the field, so an "
                 "operator cannot tell a short line from a bad nickname: %s",
                 node->out);

    /* And the nickname rule, on a well-shaped SJOIN whose member is not a legal
     * nickname. 2.1's charset exists because later phases build on it, and this
     * is the first point in the tree where a nickname arrives from a network. */
    stamp(block, sizeof block, "irc.z", 1700000007UL, 604UL, 1UL);
    (void)snprintf(line, sizeof line,
                   "%s:" PEER " SJOIN " CHAN " bad@nick - *\r\n", block);
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0, "the test could not send the line");
    TF_CHECK_MSG(nf_expect(node, "fed_sjoin_reject: ", T_IO_MS) == 0,
                 "an SJOIN whose member is not a legal nickname was recorded in "
                 "the roster. 2.1's charset rule is what makes nick@server "
                 "unambiguous, and a roster entry that skipped it is a name the "
                 "node could not qualify or render: %s",
                 node->out);
    /* The positive control beside it: the same shape with a legal nickname IS
     * recorded, so the refusal above is a charset check and not a node that
     * refuses every SJOIN. */
    stamp(block, sizeof block, "irc.z", 1700000008UL, 605UL, 1UL);
    (void)snprintf(line, sizeof line, "%s:" PEER " SJOIN " CHAN " mallory - *\r\n",
                   block);
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0, "the test could not send the line");
    TF_CHECK_MSG(nf_expect(node, "fed_sjoin: channel=" CHAN " member=mallory", T_IO_MS) ==
                     0,
                 "an SJOIN with a legal nickname was not recorded either, so the "
                 "refusal above proves nothing about the charset: %s",
                 node->out);
    /* And it is in the ROSTER, on the wire, which is the property the charset
     * exists to protect. */
    TF_CHECK_MSG(nf_expect(node, "fed_sjoin: channel=" CHAN " member=mallory", T_IO_MS) ==
                     0,
                 "mallory is not in the node's account of the channel at all: %s",
                 node->out);
}

int main(void)
{
    nf_node_t node;
    test_client_t client;
    hostile_peer_t peer;

    /* The cases run in the order of the chain they exercise, so a failure names
     * a guard rather than a symptom: the ceiling, the own-origin rule, the dedup
     * store, the untagged boundary in both its cases, the verb and field checks,
     * and the pre-auth drop. */
    memset(&peer, 0, sizeof peer);
    peer.fd = -1;
    peer_open(&peer, &node, &client, case_preauth_drop);
    case_hop_ceiling(&node, &client, &peer.fd);
    case_own_origin(&node, &client, &peer.fd);
    case_duplicate_dropped(&node, &client, &peer.fd);
    case_untagged_relay_refused(&node, &client, &peer.fd);
    case_untagged_origin_accepted(&node, &client, &peer.fd);
    case_verb_and_field_checks(&node, &peer.fd);
    peer_close(&peer, &node, &client);
    tf_done("fed_guards");
    return 0;
}
