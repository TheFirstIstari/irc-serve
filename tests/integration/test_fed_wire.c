/* test_fed_wire.c -- the S-verb wire, compared byte for byte.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS FILE IS FOR
 * ---------------------------------------------------------------------------
 * 4.3 names the internal verbs and 2.4 fixes the tag block that goes on every
 * one of them. Between them that is a WIRE FORMAT, and the argument in 4.3 for
 * making them distinct words rather than reusing JOIN/PRIVMSG is precisely that
 * a wire format cannot be invented later. So this file pins the bytes.
 *
 * For every client verb with an S-verb, the bytes the node writes toward a peer
 * are compared against a written-out literal: the tag block's four names, in the
 * frozen order, with hops=0, followed by the S-verb, the target and the text.
 * Nothing about that line is reconstructed from the node's own state except the
 * epoch, which is a clock reading (see THE EPOCH below).
 *
 * ---------------------------------------------------------------------------
 * WHY THE NODE RUNS IN THIS PROCESS, AND WHY THAT IS NOT A WEAKENING
 * ---------------------------------------------------------------------------
 * The bytes have to come off a real socket, and the far end of that socket has
 * to belong to the test. Neither is possible against the shipped binary in this
 * commit: node_main.c takes a port and nothing else, it has no peer list to dial
 * and no way to be handed a link, and the two files that would give it one
 * (link.c, and the accept path for a peer) are later commits. So the test
 * brings up a server_t itself, installs the one link the forwarding path needs,
 * and drives the REAL loop one iteration at a time with poll_loop_step().
 *
 * That is a real node, not a mock of one. server_init, server_listen, the
 * accept, the framing, message_parse_n, commands_dispatch, the fan-out table,
 * the write queue and the pump are all the shipped code; the only thing the test
 * supplies is the existence of a peer, which is the thing the phase under test
 * is about. poll_loop_step() is public precisely for a caller that wants to
 * drive the loop itself, and it runs the same eight steps in the same order as
 * poll_loop_run() does.
 *
 * ---------------------------------------------------------------------------
 * NO FIXED SLEEP, AND WHY THE NEGATIVES ARE SOUND
 * ---------------------------------------------------------------------------
 * There is no sleep and no timing assumption anywhere. Waiting is
 * drive_until(): step the loop, drain both sockets, check for a needle, repeat
 * until a deadline. The short poll timeout inside a step is the node's own
 * POLL_TICK_MS, so a step returns as soon as there is work and never later.
 *
 * The "nothing arrived on the peer link" assertions are the ones that need
 * justifying, and they use the window idiom this suite already uses: a PING is
 * sent after the command under test and the wait is for its PONG. The loop's
 * order makes that a fact rather than an assumption -- the write pump for a
 * connection runs in the step AFTER the one that dispatched the command, and
 * the PONG is written two steps after the command, so by the time the PONG is
 * readable the peer link has already been pumped twice. A numeric that the node
 * had queued for the peer would therefore have arrived, and its absence is a
 * statement about the bytes rather than about when the test looked.
 *
 * One more step and one more drain are run after each window closes anyway. The
 * argument above is sufficient; the extra round costs nothing and removes the
 * need for a reader to have made the argument at all.
 *
 * ---------------------------------------------------------------------------
 * THE EPOCH IS THE ONE VALUE THE TEST CANNOT WRITE DOWN
 * ---------------------------------------------------------------------------
 * The stamp carries the node's per-boot epoch, which is server_now_ms() at
 * server_init() and therefore a clock reading that changes every run -- and, on
 * this platform, an uptime in milliseconds rather than a calendar time, so its
 * digit count is a property of the machine. It is READ here and formatted into
 * the expected string, and that is the single place this file builds any part of
 * an expectation rather than writing it out.
 *
 * Two things keep that from being circular. The message id is NOT read: the
 * fixture sets the per-SERVER counter to a fixed value immediately before each
 * command under test, so `id=41` and `id=60` are literals, and a counter that
 * did not advance, or that advanced by the wrong amount, would fail here. And
 * the epoch is checked against 2.4's own value GRAMMAR -- 1..20 digits, no
 * leading zero -- so a stamp that rendered it padded, truncated or in another
 * base would fail on the shape as well as on the value.
 *
 * ---------------------------------------------------------------------------
 * THE PREFIX, AND THE GAP THIS COMMIT CLOSED
 * ---------------------------------------------------------------------------
 * C1 emitted this node's own name -- `irc.a` -- as the source prefix of all
 * seven S-verbs, and this file documented that as a known gap: the forwarding
 * function had no prefix parameter, so the caller had nothing to pass. That is
 * correct for five of the seven, whose subject IS the server, and WRONG for
 * SPRIVMSG and SNOTICE, whose subject is a user. A peer handed
 * `:irc.b SPRIVMSG #T :hi` cannot build a hostmask for the message it delivers
 * to its own members, because 2.1's `nick!user@host` is the only thing a client
 * can be shown as an author and a server name is not one.
 *
 * fanout_forward_link() now takes a prefix, and the expected lines below are
 * THE FIXED ONES: SPRIVMSG and SNOTICE carry the sending client's hostmask, and
 * the five state verbs carry the client's hostmask too -- because 4.3's frozen
 * shapes name the SUBJECT in a parameter (`SJOIN #T alice +o`) and take it from
 * the prefix, so a state verb's prefix and its subject are the same bytes. The
 * state verbs' prefix is therefore the hostmask as well, and the difference from
 * the five S-verbs' subject is that the subject appears TWICE.
 *
 * The positive control above is what makes those expectations meaningful: the
 * node never echoes a client's CLAIMED hostname, so the hostmask in the expected
 * lines can only have come from the observed one.
 */
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/channel.h"
#include "core/commands.h"
#include "core/connection.h"
#include "core/fanout.h"
#include "core/message.h"
#include "core/poll_loop.h"
#include "core/server.h"
#include "federation/verbs.h"
#include "harness/test_util.h"

/* This node's name. It must satisfy 2.4's tag grammar, because it is stamped
 * on every outbound origin tag, and it is a literal in every expected line
 * below -- exactly as test_messaging.c hard-codes `irc.test` for the shipped
 * node. */
#define NODE_NAME "irc.a"

/* The peer's name, the one the link is installed under. 2.2's ownership rules
 * want it to look like another node's name and not like ours, which it does. */
#define PEER_NAME "irc.b"

/* The channel the S-verbs address. Uppercase, because 2.2 canonicalises channel
 * names and an expected line that said `#t` would never match a line the node
 * built from a chan_t. */
#define CHAN "#T"

/* The text every forwarded line carries. Two words, so a formatter that dropped
 * the trailing colon and re-split on the space would produce two parameters and
 * fail the comparison rather than pass it. */
#define TEXT "hello there"

/* The client. */
#define CLIENT_NICK "alice"
#define CLIENT_HOST "127.0.0.1"

/* Deadlines. Generous, because these are for a loop running in this process
 * alongside a test that is also stepping it, and failing fast when the thing
 * being waited for never happens. */
#define T_IO_MS 10000

/* ---------------------------------------------------------------------------
 * A socket this test owns
 * ---------------------------------------------------------------------------
 * A deliberate near-duplicate of harness/irc_client.h's test_client_t, and the
 * reason is that irc_client's reads are BLOCKING deadline waits: tc_expect()
 * cannot be used to poll while this test is stepping the node, because between
 * the two the test must own the loop. So this is the same idea with a
 * non-blocking drain, small enough to be obviously correct and used the same way
 * every other fixture in tests/integration/ is -- see test_messaging.c,
 * test_queries.c and test_channels.c, each of which carries its own.
 */
typedef struct {
    int    fd;
    char  *buf;
    size_t len;
    size_t cap;
} wire_t;

static void wire_init(wire_t *w)
{
    w->fd = -1;
    w->buf = NULL;
    w->len = 0;
    w->cap = 0;
}

static int wire_listen(int *port_out)
{
    struct sockaddr_in addr;
    socklen_t alen = sizeof addr;
    int one = 1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        return -1;
    }
    /* SO_REUSEADDR for the same reason server_listen() sets it: a test that
     * leaves a port in TIME_WAIT should not stop the next run binding it. */
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, (socklen_t)sizeof one);
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; /* the kernel picks; read back below */
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0 ||
        listen(fd, 4) != 0 ||
        getsockname(fd, (struct sockaddr *)&addr, &alen) != 0) {
        close(fd);
        return -1;
    }
    *port_out = (int)ntohs(addr.sin_port);
    return fd;
}

static int wire_connect(wire_t *w, int port)
{
    struct sockaddr_in addr;

    w->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (w->fd < 0) {
        return -1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    /* Blocking, and safe to block: the peer is a loopback listener that is
     * already listening, so the kernel completes the handshake whether or not
     * the application ever calls accept(). The accept below therefore cannot
     * wait, which is why this file needs no sleep anywhere. */
    if (connect(w->fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(w->fd);
        w->fd = -1;
        return -1;
    }
    return 0;
}

/* Read whatever has arrived, without waiting. Returns 1 if anything was
 * appended. A NUL is written after the data so the buffer can be searched with
 * strstr(); nothing in this file searches for a NUL and the lengths are kept
 * separately for the byte-for-byte comparisons. */
static int wire_drain(wire_t *w)
{
    char chunk[8192];
    struct timeval tv;
    fd_set rfds;
    ssize_t got;
    int got_any = 0;

    if (w->fd < 0) {
        return 0;
    }
    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(w->fd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        if (select(w->fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
            break;
        }
        got = recv(w->fd, chunk, sizeof chunk, 0);
        if (got <= 0) {
            break;
        }
        if (w->len + (size_t)got + 1u > w->cap) {
            size_t want = (w->cap == 0) ? 8192u : w->cap;
            char *grown;

            while (want < w->len + (size_t)got + 1u) {
                want *= 2u;
            }
            grown = (char *)realloc(w->buf, want);
            if (grown == NULL) {
                break;
            }
            w->buf = grown;
            w->cap = want;
        }
        memcpy(w->buf + w->len, chunk, (size_t)got);
        w->len += (size_t)got;
        w->buf[w->len] = '\0';
        got_any = 1;
    }
    return got_any;
}

static int wire_send(wire_t *w, const char *line)
{
    char out[1024];
    size_t want = strlen(line);
    size_t n = 0;

    if (want + 2u > sizeof out) {
        return -1;
    }
    memcpy(out, line, want);
    out[want] = '\r';
    out[want + 1u] = '\n';
    want += 2u;
    while (n < want) {
        ssize_t wrote = send(w->fd, out + n, want - n, 0);

        if (wrote <= 0) {
            if (wrote < 0 && errno == EINTR) {
                continue;
            }
            return -1;
        }
        n += (size_t)wrote;
    }
    return 0;
}

static const char *wire_text(const wire_t *w)
{
    return (w->buf != NULL) ? w->buf : "";
}

static void wire_close(wire_t *w)
{
    if (w->fd >= 0) {
        close(w->fd);
        w->fd = -1;
    }
    free(w->buf);
    w->buf = NULL;
    w->len = 0;
    w->cap = 0;
}

/* ---------------------------------------------------------------------------
 * Driving the node
 * ---------------------------------------------------------------------------
 * One iteration of the real loop, then a drain of both sockets. A step is
 * bounded by the node's own POLL_TICK_MS and returns sooner when there is work,
 * so a loop of these makes progress as fast as the node can do it and costs
 * nothing when there is nothing to do.
 */
static void step_and_drain(server_t *s, wire_t *cli, wire_t *peer)
{
    (void)poll_loop_step(s, POLL_TICK_MS);
    (void)wire_drain(cli);
    (void)wire_drain(peer);
}

/* Step until `needle` is in `from`'s buffer, or the deadline passes. Returns 0
 * when it was found. `from` is named rather than assumed to be the client,
 * because roughly half the assertions in this file are about the PEER link and
 * searching the wrong buffer would time out on a line that had in fact arrived.
 *
 * The needle is a substring of the ACCUMULATED buffer, so a line split across
 * two reads is still found. */
static int drive_until(server_t *s, wire_t *cli, wire_t *peer, wire_t *from,
                       const char *needle, int ms)
{
    uint64_t deadline = server_now_ms() + (uint64_t)ms;

    for (;;) {
        step_and_drain(s, cli, peer);
        if (strstr(wire_text(from), needle) != NULL) {
            return 0;
        }
        if (server_now_ms() >= deadline) {
            fprintf(stderr, "drive_until: TIMEOUT after %d ms waiting for \"%s\"\n"
                            "  client: %s\n  peer:   %s\n",
                    ms, needle, wire_text(cli), wire_text(peer));
            return -1;
        }
    }
}

/* Close a window on `w` and give the loop one more iteration, so a negative
 * assertion is a statement about the bytes rather than about when the test last
 * looked. The extra round is belt and braces on top of the PONG argument in the
 * file header; it costs one tick. */
static void settle(server_t *s, wire_t *cli, wire_t *peer)
{
    step_and_drain(s, cli, peer);
    step_and_drain(s, cli, peer);
}

/* ---------------------------------------------------------------------------
 * The peer link
 * ---------------------------------------------------------------------------
 * A real TCP connection whose FAR end this test owns: `far` is connected to a
 * listener this test created, and the accepted descriptor becomes the node's
 * peer socket. Real loopback, real framing, real kernel buffers -- and the test
 * reading the far end is what makes "the bytes the node writes toward a
 * listener the test itself owns" literally true rather than a description of a
 * socketpair.
 *
 * The link is ESTABLISHED, because 2.3 refuses a peer before ESTABLISHED and
 * server_find_peer() answers NULL for anything else -- which is the whole point
 * of the narrowing this commit makes, so a link that is not established is a
 * second fixture used in test_fed_dedup.c.
 */
static void peer_link_up(server_t *s, wire_t *far, int listen_fd, int port)
{
    conn_t *pc;
    server_link_t *l;
    struct sockaddr_storage peer_addr;
    socklen_t peer_alen = (socklen_t)sizeof peer_addr;
    int node_fd;

    TF_CHECK_MSG(wire_connect(far, port) == 0,
                 "the test could not connect to its own listener");
    node_fd = accept(listen_fd, (struct sockaddr *)&peer_addr, &peer_alen);
    TF_CHECK_MSG(node_fd >= 0, "accept() on the test's own listener failed");

    pc = conn_new(node_fd, CONN_SERVER);
    TF_CHECK_MSG(pc != NULL, "conn_new() failed for the peer connection");
    pc->peer_name = (char *)malloc(strlen(PEER_NAME) + 1u);
    TF_CHECK_MSG(pc->peer_name != NULL, "could not set the peer's display name");
    memcpy(pc->peer_name, PEER_NAME, strlen(PEER_NAME) + 1u);
    TF_CHECK_MSG(server_add_conn(s, pc) == 0,
                 "the peer connection could not be registered in by_fd");

    /* The vector, allocated at the capacity a link-adding path would use, so
     * the shape this fixture builds is the shape server_t::links is specified to
     * have rather than a one-off. */
    s->links = (server_link_t *)calloc(IRC_FED_MAX_PEERS, sizeof *s->links);
    TF_CHECK_MSG(s->links != NULL, "could not allocate the link vector");
    s->links_cap = (size_t)IRC_FED_MAX_PEERS;
    s->nlinks = 1;
    l = &s->links[0];
    memcpy(l->name, PEER_NAME, strlen(PEER_NAME) + 1u);
    l->fd = node_fd;
    l->initiator = 1;
    l->created_ms = server_now_ms();
    /* 3.4's pre-resolved-address requirement, honoured in the fixture: the
     * address the test connected to was already a resolved struct sockaddr, and
     * it is stored on the link rather than looked up again from a name. */
    memcpy(&l->addr, &peer_addr, sizeof peer_addr);
    l->addrlen = peer_alen;
    /* hs is the FSM context and `state` mirrors it -- written here the way
     * fed_link_set_state() will, through hs first, so the mirror cannot be set
     * without the context. */
    handshake_init(&l->hs);
    l->hs.state = ESTABLISHED;
    l->state = (int)l->hs.state;
    /* The peer's epoch is 0: this fixture has no handshake, so the peer has not
     * said. Nothing in the forwarding path reads it in this commit, and a link
     * that is ESTABLISHED with epoch 0 is exactly the "not yet told" case
     * server_link_t documents. */
    l->epoch = 0;
    l->burst_done = 0;
}

/* ---------------------------------------------------------------------------
 * The expected line
 * ---------------------------------------------------------------------------
 * Written as one format with the stamp as an argument, so that the FOUR TAG
 * NAMES AND THEIR ORDER are literal text in the source and cannot drift. The
 * two substituted values are the epoch (a clock reading; see the file header)
 * and the id, which the fixture pins before each command so the id is a
 * literal in every call site.
 */
/* `prefix` is the source prefix the line is expected to carry, WITHOUT the
 * leading ':' -- the same convention core/fanout.h uses -- and `tail` is
 * EVERYTHING after the verb, the channel included and in whatever position
 * 4.3's frozen shape puts it.
 *
 * THE CHANNEL IS INSIDE `tail` AND NOT IN THE FORMAT, and that is the whole
 * point of this file's per-verb table. C1 emitted `<target> :<text>` for all
 * seven verbs; 4.3 freezes the channel's POSITION per verb -- first for SJOIN
 * and SMODES, second for SPART, STOPIC and SKICK, first for the two message
 * verbs too -- and a format that assumed one position would assert a shape the
 * design does not have. The shapes are frozen in federation/verbs.h; this is
 * the other copy of them, and a copy in a test on purpose: an expectation
 * derived from the encoder's own table would pass whatever that table said,
 * which is the failure 4.3's "a wire format cannot be invented later" is about.
 */
static void want_line(char *out, size_t cap, const char *prefix, uint64_t epoch,
                      uint64_t id, uint32_t hops, const char *sverb,
                      const char *tail)
{
    (void)snprintf(out, cap,
                   "@irc-serve-origin=" NODE_NAME
                   ";irc-serve-epoch=%llu;irc-serve-id=%llu;irc-serve-hops=%lu"
                   " :%s %s %s\r\n",
                   (unsigned long long)epoch, (unsigned long long)id,
                   (unsigned long)hops, prefix, sverb, tail);
}

/* The 7 client verbs and their S-verbs, in the order 4.3 lists them, and with
 * SMODES checked against the design's SSMODE here as well as in the header: a
 * rename that is only documented in one place is a rename the next reader
 * re-litigates. */
static const struct {
    const char *client;
    const char *sverb;
    /* Everything after the verb, per 4.3's frozen shapes, and how many CLIENT
     * parameters went in. See want_line() for why the shapes are written out
     * here rather than derived from the encoder's own table. */
    const char *tail;
    /* The CLIENT parameters after the target, one entry each, and how many of
     * them there are. A client KICK is `KICK #chan <target> [:reason]`, so it is
     * the one row with two, and a client JOIN is `JOIN #chan`, so it is the one
     * row with none -- and the row that proves the frozen shape is not
     * "<target> :<text>" for all seven. */
    const char *c0;
    const char *c1;
    int         nclient;
} VERBS[] = {
    { "PRIVMSG", "SPRIVMSG", CHAN " :" TEXT,            TEXT, NULL, 1 },
    { "NOTICE",  "SNOTICE",  CHAN " :" TEXT,            TEXT, NULL, 1 },
    /* The member is the nick of the source prefix, the flag token is `-` because
     * this fixture has no channel and therefore no flags to report, and the fourth
     * parameter is the ACCOUNT -- which Phase 10.3 added to 4.3's SJOIN and which
     * is `*` here because this fixture's client never authenticated. `*` is the
     * protocol's spelling of "not logged in to an account", and putting it in the
     * expected wire line rather than leaving the row three-wide is what makes the
     * format change visible in this test instead of only in the acceptance. */
    { "JOIN",    "SJOIN",    CHAN " " CLIENT_NICK " - *", NULL, NULL, 0 },
    { "PART",    "SPART",    CLIENT_NICK " " CHAN " :" TEXT, TEXT, NULL, 1 },
    { "TOPIC",   "STOPIC",   CLIENT_NICK " " CHAN " :" TEXT, TEXT, NULL, 1 },
    /* SMODES' subject is the SERVER that evaluated the change, per 2.2, and it
     * comes BEFORE the channel. */
    { "MODE",    "SMODES",   NODE_NAME " " CHAN " :" TEXT, TEXT, NULL, 1 },
    { "KICK",    "SKICK",
      CLIENT_NICK " " CHAN " " CLIENT_NICK " :" TEXT, CLIENT_NICK, TEXT, 2 }
};

/* The whole peer stream, built up as the expected lines are confirmed. The final
 * assertion is that this equals the peer's entire buffer, which is a stronger
 * statement than "each line was present": it also says no line is present that
 * was not asked for. */
static char expected_stream[8192];
static size_t expected_len;

static void expect_stream_line(const char *line, const char *what)
{
    size_t n = strlen(line);

    TF_CHECK_MSG(expected_len + n < sizeof expected_stream,
                 "the expected peer stream overflowed its buffer at \"%s\"",
                 what);
    memcpy(expected_stream + expected_len, line, n);
    expected_len += n;
    expected_stream[expected_len] = '\0';
}

/* Count lines on the peer link that look like a NUMERIC: `:irc.a 3dd `. 3 is the
 * first digit of every numeric 4.4 lists, and this is the shape
 * reply.c's emit_to_client() produces. Returns the number found, and the
 * assertion is that it is zero. */
static size_t count_numerics_on_peer(const wire_t *peer)
{
    const char *p = wire_text(peer);
    size_t n = 0;

    for (; (p = strstr(p, ":" NODE_NAME " 3")) != NULL; p += strlen(NODE_NAME) + 2u) {
        n++;
    }
    return n;
}

int main(void)
{
    server_t s;
    wire_t cli;
    wire_t peer;
    int node_port = 0;
    int listen_fd;
    int listen_port = 0;
    uint64_t epoch;
    char want[512];
    char line[256];
    size_t i;

    wire_init(&cli);
    wire_init(&peer);
    expected_stream[0] = '\0';
    expected_len = 0;

    /* The node. Same construction node_main.c performs, with the same dispatch,
     * so the command surface under test is the shipped one. */
    TF_CHECK_MSG(server_init(&s, NODE_NAME) == 0, "server_init failed");
    TF_CHECK_MSG(s.trace == 0, "the fixture left tracing on, which would put a "
                                "line per event into this test's stdout");
    s.dispatch = commands_dispatch;
    TF_CHECK_MSG(server_listen(&s, 0) == 0, "server_listen failed");
    node_port = server_port(&s);
    TF_CHECK_MSG(node_port > 0, "the node did not report a bound port");
    /* The one value in every expected line that this file cannot write down.
     * See the file header. */
    epoch = s.epoch;
    /* What IS checkable about it is the 2.4 value GRAMMAR: 1..20 decimal digits,
     * no leading zero. Not the magnitude -- server_now_ms() is CLOCK_MONOTONIC
     * on this platform, so the epoch is an uptime in milliseconds and its digit
     * count is a property of how long the machine has been up, not of the node.
     * A test that assumed a 13-digit value would pass on a machine that had
     * been up a decade and fail on a fresh one. */
    (void)snprintf(line, sizeof line, "%llu", (unsigned long long)epoch);
    TF_CHECK_MSG(strlen(line) >= 1u && strlen(line) <= 20u &&
                     line[0] != '0',
                 "the node's epoch rendered as \"%s\", which is outside 2.4's "
                 "epoch grammar (1..20 digits, no leading zero)",
                 line);

    listen_fd = wire_listen(&listen_port);
    TF_CHECK_MSG(listen_fd >= 0, "the test could not open its own listener");
    peer_link_up(&s, &peer, listen_fd, listen_port);

    /* =======================================================================
     * 1. THE PEER IS A ROUTE, AND THE CLIENT IS A CLIENT
     * ==================================================================== */
    /* The positive control for the whole file, and it comes first: a fixture in
     * which server_find_peer() answers NULL would make every expected line
     * "absent", which is what a broken link also looks like. So this asserts the
     * link is routable before anything asserts what travels over it.
     *
     * A case-different spelling is used, because 2.3's lookup is ASCII
     * case-insensitive and a forward that named the peer "IRC.B" must still
     * resolve: server names are case-insensitive in IRC (2.1, RFC 1459 2.3.2) and
     * 2.2's servers[] set stores them verbatim. */
    TF_CHECK_MSG(server_link_count(&s) == 1u,
                 "the fixture installed %zu links, expected 1",
                 server_link_count(&s));
    TF_CHECK_MSG(server_find_link(&s, PEER_NAME) != NULL,
                 "the link is not findable by its own name");
    TF_CHECK_MSG(server_find_link(&s, "IRC.B") != NULL,
                 "the link is not findable by a differently-cased spelling of "
                 "its name; 2.3's lookup is ASCII case-insensitive");
    TF_CHECK_MSG(server_link_conn(&s, server_find_link(&s, PEER_NAME)) != NULL,
                 "the link names a descriptor but no connection");
    TF_CHECK_MSG(server_find_peer(&s, PEER_NAME) != NULL,
                 "an ESTABLISHED link is not a route, so nothing could ever be "
                 "forwarded and every assertion below would be vacuous");

    TF_CHECK_MSG(wire_connect(&cli, node_port) == 0,
                 "the test client could not connect to the node");
    TF_CHECK_MSG(wire_send(&cli, "NICK " CLIENT_NICK) == 0, "NICK send failed");
    (void)snprintf(line, sizeof line,
                   "USER %s 0 *spoofed.example :Real %s", CLIENT_NICK,
                   CLIENT_NICK);
    TF_CHECK_MSG(wire_send(&cli, line) == 0, "USER send failed");
    TF_CHECK_MSG(drive_until(&s, &cli, &peer, &cli, ":" NODE_NAME " 001 ", T_IO_MS) == 0,
                 "the client never registered");
    /* The client claims a hostname in USER's <unused> slot, and every forwarded
     * line below is checked to NOT carry it. That is a negative control on the
     * one part of the line the node could have got wrong by copying a claim
     * rather than observing, and it is the reason the claim is here at all. */
    TF_CHECK_MSG(strstr(wire_text(&cli), "spoofed.example") == NULL,
                 "the node echoed a client's CLAIMED hostname, so nothing in this "
                 "file's prefix assertions could be trusted");

    /* =======================================================================
     * 2. THE VERB MAP, BYTE FOR BYTE, THROUGH THE DOCUMENTED SEAM
     * ==================================================================== */
    /* fanout_forward_link() is called directly here rather than through a client
     * command, and the reason is which 3.1 row each verb can reach DIRECTLY. A
     * client JOIN is now routed through fanout_deliver() by core/chan_verbs.c,
     * so the state-change arm has a caller on the wire and section 3 below
     * asserts that end to end -- but the other four state verbs are only
     * reachable from a handler that has already applied its local change, and
     * driving them here keeps the byte comparison for all seven in one place
     * with one fixture.
     *
     * So the map is exercised at the seam, which is what fanout.h says the seam
     * is exposed FOR, and the two rows that ARE on the wire are exercised end to
     * end as well. A test that asserted all seven through the command surface
     * would need a channel with a non-op client for KICK, a non-op for MODE and
     * a second nick for the KICK target -- and would then be asserting
     * core/chan_verbs.c's refusals rather than the wire format.
     *
     * The message id is PINNED rather than read, so `id=41` and `id=60` are
     * literals in the expected strings and a per-SERVER counter that did not
     * advance, or advanced by a different amount, fails the comparison. */
    {
        fanout_target_t tgt;
        uint64_t id = 41;
        const char *sp[2];
        char hostmask[CONN_HOSTMASK_MAX];

        memset(&tgt, 0, sizeof tgt);
        tgt.kind = FANOUT_NONE;
        tgt.vclass = FANOUT_STATE_CHANGE;
        memcpy(tgt.name, CHAN, sizeof CHAN);
        /* The OBSERVED hostmask, built the same way the node builds it, and the
         * file's positive control above is what makes it trustworthy: the client
         * claimed "spoofed.example" in USER's <unused> slot and the node echoed
         * none of it, so a prefix carrying this string can only have come from
         * accept()'s observation. */
        (void)snprintf(hostmask, sizeof hostmask, "%s!%s@%s", CLIENT_NICK,
                       CLIENT_NICK, CLIENT_HOST);

        for (i = 0; i < sizeof VERBS / sizeof VERBS[0]; i++) {
            int rc;

            s.msg_id = id;
            /* Both client parameter slots are WRITTEN on every iteration, not
             * only the used ones: an array read past what was written is a
             * dangling read, and a test that segfaults on the KICK row proves
             * nothing about the KICK row. */
            sp[0] = VERBS[i].c0;
            sp[1] = VERBS[i].c1;
            rc = fanout_forward_link(&s, PEER_NAME, &tgt, VERBS[i].client, sp,
                                     VERBS[i].nclient, hostmask, NULL);
            TF_CHECK_MSG(rc == 1,
                         "forwarding %s returned %d; the link is established and "
                         "the line fits, so this should be a delivery",
                         VERBS[i].client, rc);
            want_line(want, sizeof want, hostmask, epoch, id, 0u, VERBS[i].sverb,
                      VERBS[i].tail);
            TF_CHECK_MSG(drive_until(&s, &cli, &peer, &peer, want, T_IO_MS) == 0,
                         "the peer link did not receive the %s line\n"
                         "  expected: %s\n  peer saw: %s",
                         VERBS[i].sverb, want, wire_text(&peer));
            expect_stream_line(want, VERBS[i].sverb);
            id++;
        }
        TF_CHECK_MSG(s.msg_id == id,
                     "the per-SERVER id counter is %llu after seven forwards, "
                     "expected %llu: 2.4's counter is the thing that makes ids "
                     "unique across a node, and it has to advance per message",
                     (unsigned long long)s.msg_id, (unsigned long long)id);
    }

    /* The map itself, independent of the wire: a verb with no S-verb has to be
     * REFUSED rather than forwarded under the client verb's own name, because a
     * peer receiving `PRIVMSG` where it expects `SPRIVMSG` has no way to tell
     * the difference between a relayed message and a client command. */
    TF_CHECK_MSG(fed_sverb_for("PRIVMSG") != NULL &&
                     strcmp(fed_sverb_for("PRIVMSG"), "SPRIVMSG") == 0,
                 "fed_sverb_for(\"PRIVMSG\") is not SPRIVMSG");
    TF_CHECK_MSG(strcmp(fed_sverb_for("MODE"), "SMODES") == 0,
                 "fed_sverb_for(\"MODE\") is not SMODES; 4.3 spells it SSMODE and "
                 "verbs.h records the rename -- if that rename is being reverted, "
                 "revert the comment too");
    TF_CHECK_MSG(fed_sverb_for("WHO") == NULL && fed_sverb_for("PING") == NULL,
                 "a node-local verb was given an S-verb: 4.3's list is the "
                 "forwarded vocabulary, and adding to it is a wire-format change");
    TF_CHECK_MSG(fed_sverb_for("NOSUCHVERB") == NULL && fed_sverb_for(NULL) == NULL,
                 "an unknown verb was mapped to an S-verb instead of refused");

    /* =======================================================================
     * 3. THE SAME LINE, END TO END, THROUGH THE REAL COMMAND SURFACE
     * ==================================================================== */
    /* The client joins #T, which this node creates and therefore owns; then the
     * channel is re-keyed to the peer's name through 2.2's own creation-race
     * path, exactly as tests/integration/test_channels.c does. That is the only
     * way to produce a channel this node does not own without a peer link
     * having reported one, and it is a real code path rather than a field write:
     * chan_re_key consults the same (creation_epoch, server_name) rule 2.2
     * specifies, and the candidate wins here by having the later epoch.
     *
     * With the channel owned elsewhere, 3.1's non-owned `message` row is the one
     * that applies: write to the local members AND forward to the owner. Both
     * halves are asserted, because a node that forwarded without writing locally
     * would lose its own member's copy and a node that wrote without forwarding
     * would silently drop the message for the rest of the mesh. */
    TF_CHECK_MSG(wire_send(&cli, "JOIN " CHAN) == 0, "JOIN send failed");
    TF_CHECK_MSG(drive_until(&s, &cli, &peer, &cli, ":" NODE_NAME " 366 ", T_IO_MS) == 0,
                 "the client never completed its JOIN");
    {
        chan_t *ch = server_chan_get(&s, CHAN);

        TF_CHECK_MSG(ch != NULL, "the node does not hold the channel it was "
                                 "just asked to join");
        TF_CHECK_MSG(chan_rekey(ch, PEER_NAME, s.epoch + 1u) == 1,
                     "the creation-race re-key did not move %s's ownership to %s",
                     CHAN, PEER_NAME);
    }
    /* THE JOIN'S OWN FORWARD, and it is the line C3 adds to this stream. Before
     * it, core/chan_verbs.c broadcast a JOIN to the members through its own
     * helper and 3.1's state-change arm had no caller at all, so a JOIN reached
     * every local member and no peer. The comment above used to say exactly that
     * and it is now false.
     *
     * The flags are `+o` rather than the `-` of section 2's direct call, and the
     * difference is the whole of why the SJOIN carries flags: this client created
     * the channel, so RFC 1459 2.3.1 made it an operator, and the frozen shape
     * reports that. The id is 48 because the loop above pinned the counter there
     * and seven forwards consumed 41 through 47. */
    {
        char hostmask[CONN_HOSTMASK_MAX];

        (void)snprintf(hostmask, sizeof hostmask, "%s!%s@%s", CLIENT_NICK,
                       CLIENT_NICK, CLIENT_HOST);
        want_line(want, sizeof want, hostmask, epoch, 48u, 0u, "SJOIN",
                  CHAN " " CLIENT_NICK " +o *");
    }
    TF_CHECK_MSG(drive_until(&s, &cli, &peer, &peer, want, T_IO_MS) == 0,
                 "a JOIN did not reach the owning server, so 3.1's state-change "
                 "row still has no caller on the wire.\n"
                 "  expected: %s\n  peer saw: %s",
                 want, wire_text(&peer));
    expect_stream_line(want, "the end-to-end SJOIN");

    s.msg_id = 60;
    TF_CHECK_MSG(wire_send(&cli, "PRIVMSG " CHAN " :" TEXT) == 0,
                 "PRIVMSG send failed");
    /* The local half: 3.1's row, and it is a PLAIN PRIVMSG because a client
     * cannot be sent an S-verb -- the S-verbs are internal (4.3) and a client
     * that received one would have no idea what it was. */
    TF_CHECK_MSG(drive_until(&s, &cli, &peer, &cli,
                             ":" CLIENT_NICK "!" CLIENT_NICK "@" CLIENT_HOST
                             " PRIVMSG " CHAN " :" TEXT "\r\n",
                             T_IO_MS) == 0,
                 "the local member did not receive its own message.\n"
                 "  client: %s",
                 wire_text(&cli));
    /* The remote half, byte for byte, from the same command. */
    {
        char hostmask[CONN_HOSTMASK_MAX];

        (void)snprintf(hostmask, sizeof hostmask, "%s!%s@%s", CLIENT_NICK,
                       CLIENT_NICK, CLIENT_HOST);
        want_line(want, sizeof want, hostmask, epoch, 60u, 0u, "SPRIVMSG",
                  CHAN " :" TEXT);
    }
    TF_CHECK_MSG(drive_until(&s, &cli, &peer, &peer, want, T_IO_MS) == 0,
                 "a PRIVMSG to a channel this node does not own did not reach the "
                 "owning server.\n  expected: %s\n  peer saw: %s",
                 want, wire_text(&peer));
    expect_stream_line(want, "the end-to-end SPRIVMSG");

    /* =======================================================================
     * 4. NO NUMERIC EVER APPEARS ON A PEER LINK
     * ==================================================================== */
    /* The end-to-end half of tests/integration/test_reply_guard.c, which
     * asserts the property by reading reply.c's source. Source inspection proves
     * the guard is in emit_to_client(); it cannot prove the guard is REACHED, or
     * that a second door onto the socket was not opened somewhere else. So this
     * drives real numerics through a real peer link and looks at the bytes.
     *
     * Each case is a numeric the node really does emit, and each is checked to
     * ARRIVE at the client first. Without that positive control a peer link that
     * never worked at all would satisfy every one of these.
     *
     * The window is a PING sent after the command, and the PONG is the fact
     * that the node has finished with the command; see the file header. */
    {
        static const struct {
            const char *command;
            const char *numeric;
        } NUMERICS[] = {
            { "PRIVMSG nosuchnick :x", ":" NODE_NAME " 401 " },
            { "PRIVMSG #nosuchchan :x", ":" NODE_NAME " 403 " },
            { "WHOX",                  ":" NODE_NAME " 421 " }
        };

        for (i = 0; i < sizeof NUMERICS / sizeof NUMERICS[0]; i++) {
            size_t before = peer.len;

            TF_CHECK_MSG(wire_send(&cli, NUMERICS[i].command) == 0,
                         "could not send the numeric probe \"%s\"",
                         NUMERICS[i].command);
            /* The positive control: the numeric the command produces. */
            TF_CHECK_MSG(drive_until(&s, &cli, &peer, &cli, NUMERICS[i].numeric,
                                     T_IO_MS) == 0,
                         "the command \"%s\" produced no numeric, so refusing to "
                         "prove the peer link is empty proves nothing",
                         NUMERICS[i].command);
            /* The drain token. RFC 1459 2.4.2: a PING with an argument is
             * answered `PONG <server> <token>`, and this node renders the token
             * as an ordinary middle parameter -- NOT colonned, because 3.2
             * colons a trailing parameter only when the wire requires it and
             * `num0` requires nothing. test_messaging.c asserts the same shape
             * for the same reason. */
            (void)snprintf(line, sizeof line, "PING :num%zu", i);
            TF_CHECK_MSG(wire_send(&cli, line) == 0, "drain PING send failed");
            (void)snprintf(line, sizeof line, "PONG " NODE_NAME " num%zu\r\n", i);
            TF_CHECK_MSG(drive_until(&s, &cli, &peer, &cli, line, T_IO_MS) == 0,
                         "no PONG for the drain token after \"%s\"",
                         NUMERICS[i].command);
            settle(&s, &cli, &peer);
            TF_CHECK_MSG(peer.len == before,
                         "the peer link grew by %zu byte(s) while the node was "
                         "answering a client with numerics: a numeric reached a "
                         "peer link, which 3 forbids outright",
                         peer.len - before);
        }
        TF_CHECK_MSG(count_numerics_on_peer(&peer) == 0u,
                     "the peer link carries at least one line shaped like a "
                     "numeric: %s",
                     wire_text(&peer));
    }

    /* =======================================================================
     * 5. THE PEER LINK'S ENTIRE CONTENTS
     * ==================================================================== */
    /* The strongest form of the assertion, and the one that catches everything
     * the per-line checks above would let through individually: the peer
     * link's whole buffer equals the concatenation of the expected lines, byte
     * for byte and in order. Ten S-verbs, ten lines, and nothing else --
     * no 353, no 001, no PONG, no stray CRLF, no tag on a line that should not
     * have one. */
    TF_CHECK_MSG(strcmp(wire_text(&peer), expected_stream) == 0,
                 "the peer link's contents are not exactly the expected S-verbs.\n"
                 "  expected (%zu bytes):\n%s  actual (%zu bytes):\n%s",
                 expected_len, expected_stream, peer.len, wire_text(&peer));
    TF_CHECK_MSG(peer.len == expected_len,
                 "the peer link carries %zu bytes where %zu were expected",
                 peer.len, expected_len);
    /* And every expected line was a complete, terminated line: a line that
     * arrived without its CRLF would still have been found by drive_until(),
     * because it searched for a substring. Comparing the stream above is what
     * rules that out, and this is the belt-and-braces statement of it. */
    TF_CHECK_MSG(peer.len > 0u && wire_text(&peer)[peer.len - 1u] == '\n' &&
                     wire_text(&peer)[peer.len - 2u] == '\r',
                 "the peer link's last line is not CRLF-terminated: %s",
                 wire_text(&peer));

    /* =======================================================================
     * Teardown
     * ==================================================================== */
    /* server_shutdown() closes the peer connection (it is registered in by_fd)
     * and releases the link vector and the dedup table. The test's own listener
     * and its far end are not the node's, so they are closed here. */
    server_shutdown(&s);
    close(listen_fd);
    wire_close(&cli);
    wire_close(&peer);
    tf_done("fed_wire");
    return 0;
}
