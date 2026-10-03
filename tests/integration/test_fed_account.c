/* test_fed_account.c -- the <account> field of 4.3's SJOIN and SBURSTM, and the
 * bound that field needs.
 *
 * docs/SERVER_DESIGN.md 2.5.7 ("AN ACCOUNT NAME MUST NOW BE WRITABLE AS A
 * PARAMETER, AND THAT IS A RULE") and 4.3.1 (the frozen SBURSTM shape).
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS FILE PROVES
 * ---------------------------------------------------------------------------
 * That an account name this node cannot publish is REFUSED at the receiver,
 * on both of the two records that carry one.
 *
 * 2.5.7 names `account_name_wire_safe()` as the rule and states the cost of it
 * as a restriction rather than as a promise: "an operator cannot create an
 * account whose name holds a space, and a registry record holding one is REFUSED
 * rather than loaded with a name this node could not publish to anybody. A
 * restriction, enforced at the one writer of the field rather than discovered at
 * a renderer." account_store.h says the same thing about the KEY SPACE, and
 * ACCOUNT_MAX_NAME is defined as "conn_t::account's bound minus one".
 *
 * So a name longer than conn_t::account cannot be an account on this node, and a
 * peer that reports one is reporting something the receiver has no field for.
 * The rule 2.5.7 states is that it is refused. The rule the code implements is
 * `account_name_wire_safe()`, which checks every BYTE but no LENGTH -- and both
 * receiver paths then hand the value to a 64-byte field with the copy's failure
 * discarded:
 *
 *   chan_remote_add()  copy_bounded() TRUNCATES and returns 0, which is cast to
 *                      (void) -- so the roster holds a DIFFERENT NAME than the
 *                      peer reported, under a name the peer will never be asked
 *                      about again.
 *   burst.c's apply_member()  burst_copy() REFUSES and writes NOTHING, into a
 *                      slot that apply_member() never zeroes -- so what lands on
 *                      the roster is whatever the allocator left there. Its two
 *                      siblings in the same file (apply_nick(), apply_chan()) DO
 *                      memset the slot they are about to write, which is why the
 *                      third one is a defect and not a house style.
 *
 * 3.2's rule is "never deliver a silently shortened parameter", and the second
 * of the two is worse than a shortened value: it is a value this node never
 * received.
 *
 * ---------------------------------------------------------------------------
 * WHY THE PEER IS A RAW SOCKET AND NOT A SECOND NODE
 * ---------------------------------------------------------------------------
 * The same reason test_fed_guards.c gives, and it is the whole reason this test
 * exists at all: a second node built from this code CANNOT produce either line.
 * Its accounts come from its own --account-store, and account_store_add() will
 * not store a name longer than ACCOUNT_MAX_NAME. So a two-node fixture could only
 * prove the guards are not reached, which is a real property and not this one.
 *
 * So this test owns ONE END of a link. The handshake is real -- a genuine
 * FEDERATE with the right name, the right shared secret and the right version
 * word -- and from that moment the node believes it is talking to a peer named
 * irc.b, and this test can put any line it likes on that socket.
 *
 * ---------------------------------------------------------------------------
 * EVERY CASE ASSERTS THE REFUSAL AND THE POSITIVE CONTROL BESIDE IT
 * ---------------------------------------------------------------------------
 * A node that refuses every account would pass a test that only looked for the
 * refusal, so each case sends the same shape with a legal length immediately
 * afterwards and requires it to be ACCEPTED. The bound is tested from both sides
 * because a bound tested only below its own edge passes.
 *
 * NO FIXED sleep() ANYWHERE (6.3). Every wait is a deadline over nf_expect().
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
#define PEER   "irc.b"
#define CHAN   "#T"

/* THE LONGEST NAME THE NODE CAN HOLD, and the first name it cannot. The field is
 * conn_t::account / chan_remote_t::account / burst_member_t::account, all three
 * CONN_MAX_ACCOUNT + 1, so one past the bound is one byte too many for all of
 * them at once -- which is the point of writing the numbers here rather than
 * reading them out of a header the test is supposed to be checking. */
#define ACCT_AT_BOUND   63
#define ACCT_OVER_BOUND 200

/* ---------------------------------------------------------------------------
 * The child
 * ---------------------------------------------------------------------------
 * One node, dialling THIS TEST. The client dispatch is installed BEFORE
 * fed_open(), which saves and replaces it -- the fixture arrangement
 * test_fed_guards.c uses for the same reason.
 */
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

/* ---------------------------------------------------------------------------
 * Local socket helpers. Deadlines over select(), never a fixed wait.
 * --------------------------------------------------------------------------- */
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

/* The 2.4 stamp, rendered by the test. `origin` is the PEER for a burst, because
 * 4.3.1 refuses a transaction whose tag block names a third server
 * (RELAYED_BURST) -- a burst is the state of one origin, sent to the node that
 * needs it. */
static void stamp(char *out, size_t cap, unsigned long id, unsigned long hops)
{
    (void)snprintf(out, cap,
                   "@irc-serve-origin=%s;irc-serve-epoch=1700000009"
                   ";irc-serve-id=%lu;irc-serve-hops=%lu ",
                   PEER, id, hops);
}

/* A run of `n` 'A's. No space, no colon, no control byte: every one of them is
 * a byte account_name_wire_safe() ACCEPTS, so the only thing wrong with the
 * value is its length -- which is the point. */
static void fill(char *out, size_t cap, int n)
{
    for (int i = 0; i < n && (size_t)i + 1u < cap; i++) {
        out[i] = 'A';
    }
    out[n < (int)cap ? n : (int)cap - 1] = '\0';
}

/* ---------------------------------------------------------------------------
 * The peer, established
 * --------------------------------------------------------------------------- */
typedef struct {
    int fd;
    int port;
} hostile_peer_t;

static void peer_open(hostile_peer_t *p, nf_node_t *node, test_client_t *client)
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
    TF_CHECK_MSG(nf_spawn_inline_named(node, NAME_A, child_setup) == 0,
                 "could not spawn node A");

    p->fd = accept_deadline(listen_fd, T_IO_MS);
    close(listen_fd);
    TF_CHECK_MSG(p->fd >= 0, "node A never dialled the socket this test owns");

    TF_CHECK_MSG(read_until(p->fd, needles, sizeof needles / sizeof needles[0],
                            T_IO_MS) == 0,
                 "node A never sent a FEDERATE naming itself with the configured "
                 "secret, so nothing after this could mean anything");

    (void)snprintf(reply, sizeof reply, ":" PEER " FEDERATE " PEER " 1700000000 %s %s\r\n",
                   SECRET, IRC_SERVE_VERSION);
    TF_CHECK_MSG(send_line(p->fd, reply) == 0,
                 "the test could not answer with a FEDERATE");
    TF_CHECK_MSG(nf_expect(node, "link_established: peer=" PEER, T_IO_MS) == 0,
                 "node A never established its link, so nothing below is reachable "
                 "and every assertion in this file would be vacuous: %s",
                 node->out);

    /* A client on the node, in the channel, so a refusal is a statement about
     * state the client could otherwise have been shown. */
    TF_CHECK_MSG(tc_connect(client, node->port) == 0, "the client could not connect");
    (void)snprintf(line, sizeof line, "NICK carol");
    TF_CHECK_MSG(tc_send(client, line) == 0, "NICK send failed");
    (void)snprintf(line, sizeof line, "USER carol 0 *spoofed :Real carol");
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

/* ---------------------------------------------------------------------------
 * CASE 1: SJOIN, THE LIVE PATH
 * ---------------------------------------------------------------------------
 * 4.3's frozen shape is `<channel> <member> <flags> <account>`, and
 * chan_remote_add() is where the fourth one lands. Its own comment states the
 * rule: "An account that cannot be rendered as a PARAMETER is refused rather
 * than stored ... and because the alternative is a value that arrives intact and
 * then cannot be emitted."
 *
 * So a name longer than the field is one that cannot be emitted, and the answer
 * is the refusal -- `fed_sjoin_reject:` is the node's own observable for exactly
 * this, and it is the observable the illegal-nickname case above it already
 * uses. The nickname `zaphod` is used ONLY here so the assertion "zaphod was
 * never recorded" cannot be satisfied by another member's line.
 */
static void case_sjoin_account_bound(nf_node_t *node, int *peer_fd)
{
    char block[256];
    char acct[ACCT_OVER_BOUND + 1u];
    char line[1024];

    fill(acct, sizeof acct, ACCT_OVER_BOUND);
    stamp(block, sizeof block, 700UL, 1UL);
    (void)snprintf(line, sizeof line, "%s:" PEER " SJOIN " CHAN " zaphod - %s\r\n",
                   block, acct);
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0, "the test could not send the line");

    TF_CHECK_MSG(nf_expect(node, "fed_sjoin_reject: ", T_IO_MS) == 0,
                 "an SJOIN carrying a %d-byte account was recorded in the roster. "
                 "chan_remote_add() states the rule this breaks -- an account that "
                 "cannot be rendered as a parameter is REFUSED rather than stored "
                 "-- and the account field is %d bytes, so a longer name is one "
                 "this node cannot publish to anybody. What lands instead is a "
                 "TRUNCATED prefix: a name the peer never reported, in a roster "
                 "3.2's 'never deliver a silently shortened parameter' exists to "
                 "prevent: %s",
                 ACCT_OVER_BOUND, ACCT_AT_BOUND, node->out);
    /* THE ABSENCE IS ASSERTED ON THE ACCEPT LINE AND NOT ON THE NICK, because the
     * refusal above NAMES the member too -- `fed_sjoin_reject: channel=#T
     * member=zaphod` -- so a needle of "zaphod" would be satisfied by the refusal
     * itself and the assertion would pass against a node that recorded it anyway.
     * `fed_sjoin:` is the line apply only for an installed member. */
    TF_CHECK_MSG(strstr(node->out, "fed_sjoin: channel=" CHAN " member=zaphod") == NULL,
                 "zaphod was recorded in the channel's roster: the node reported the "
                 "refusal above and then installed the member anyway, which is one "
                 "event reported twice: %s",
                 node->out);

    /* THE POSITIVE CONTROL, and it is at the bound rather than comfortably
     * inside it: the same shape with a %d-byte account IS recorded. Without this
     * a node that refused every account would pass the case above. */
    fill(acct, sizeof acct, ACCT_AT_BOUND);
    stamp(block, sizeof block, 701UL, 1UL);
    (void)snprintf(line, sizeof line, "%s:" PEER " SJOIN " CHAN " mallory - %s\r\n",
                   block, acct);
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0, "the test could not send the line");
    TF_CHECK_MSG(nf_expect(node, "fed_sjoin: channel=" CHAN " member=mallory",
                           T_IO_MS) == 0,
                 "an SJOIN carrying a %d-byte account -- exactly the field's bound "
                 "-- was refused too, so the refusal above is a node that refuses "
                 "every account rather than a bound: %s",
                 ACCT_AT_BOUND, node->out);
}

/* ---------------------------------------------------------------------------
 * CASE 2: SBURSTM, THE RESYNC PATH
 * ---------------------------------------------------------------------------
 * The same field on the record 4.3.1 puts it on, and the one with the worse
 * failure mode. burst.c's apply_member() fills a slot of a realloc'd array, and
 * unlike its two siblings in the same file it never zeroes that slot -- so when
 * the copy refuses (which is what it does for a value wider than the field,
 * unlike copy_bounded(), which truncates) what is left behind is whatever the
 * allocator handed back.
 *
 * The assertion is the node's own: `fed_malformed: ... command=SBURSTM` is what
 * apply_member() prints when it refuses a member record, and a record it cannot
 * describe is one it must refuse rather than half-install.
 */
static void case_sburstm_account_bound(nf_node_t *node, int *peer_fd)
{
    char block[256];
    char acct[ACCT_OVER_BOUND + 1u];
    char line[1024];

    fill(acct, sizeof acct, ACCT_OVER_BOUND);

    stamp(block, sizeof block, 710UL, 0UL);
    (void)snprintf(line, sizeof line, "%s:" PEER " SBURST 1700000009 0\r\n", block);
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0, "the test could not send SBURST");

    stamp(block, sizeof block, 711UL, 0UL);
    (void)snprintf(line, sizeof line,
                   "%s:" PEER " SBURSTC " CHAN " " PEER " - 1700000000 - :\r\n", block);
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0, "the test could not send SBURSTC");

    /* THE TRANSACTION IS OPEN, asserted before the record under test rather than
     * after it, and it is what makes the needle below unambiguous: fed_burst_apply()
     * prints `command=SBURSTM` for a record it REFUSED and
     * `command=SBURSTM reason=NO_TRANSACTION` for one that arrived with nothing
     * open, so a case that only looked for the verb would pass against a node
     * whose BEGIN never worked. The needle is the refusal arm's -- it names the
     * member, and the NO_TRANSACTION arm does not. */
    TF_CHECK_MSG(strstr(node->out, "reason=NO_TRANSACTION") == NULL,
                 "the transaction never opened, so the member record below is "
                 "unreachable and the case would be asserting nothing: %s",
                 node->out);

    stamp(block, sizeof block, 712UL, 0UL);
    (void)snprintf(line, sizeof line,
                   "%s:" PEER " SBURSTM " CHAN " " PEER " zaphod - %s\r\n", block,
                   acct);
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0,
                 "the test could not send SBURSTM");

    TF_CHECK_MSG(nf_expect(node, "command=SBURSTM member=zaphod", T_IO_MS) == 0,
                 "an SBURSTM carrying a %d-byte account was accepted into the "
                 "resync shadow. That field is %d bytes and the copy into it "
                 "REFUSES rather than truncating, so what the transaction goes on "
                 "to install is whatever the allocator left in a slot nothing "
                 "zeroed -- an uninitialised value this node then publishes as "
                 "somebody's account name. apply_nick() and apply_chan() memset the "
                 "slot they are about to write; this is the third one: %s",
                 ACCT_OVER_BOUND, ACCT_AT_BOUND, node->out);
    TF_CHECK_MSG(strstr(node->out, "fed_burst_applied:") == NULL,
                 "a transaction carrying a member record this node could not "
                 "describe was COMMITTED. The record was refused and the "
                 "terminator still went through, so the count assertion did not "
                 "catch it and the node's roster now holds a name nobody "
                 "reported: %s",
                 node->out);
}

/* THE POSITIVE CONTROL for case 2, in its own transaction: the same shape with
 * an account at the bound commits, and installs the member. Without it, a node
 * that refused every resync would pass the case above. */
static void case_burst_at_bound(nf_node_t *node, int *peer_fd)
{
    char block[256];
    char acct[ACCT_AT_BOUND + 1u];
    char line[1024];

    fill(acct, sizeof acct, ACCT_AT_BOUND);

    stamp(block, sizeof block, 720UL, 0UL);
    (void)snprintf(line, sizeof line, "%s:" PEER " SBURST 1700000010 0\r\n", block);
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0, "the test could not send SBURST");

    stamp(block, sizeof block, 721UL, 0UL);
    (void)snprintf(line, sizeof line,
                   "%s:" PEER " SBURSTC " CHAN " " PEER " - 1700000000 - :\r\n", block);
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0, "the test could not send SBURSTC");

    stamp(block, sizeof block, 722UL, 0UL);
    (void)snprintf(line, sizeof line,
                   "%s:" PEER " SBURSTM " CHAN " " PEER " trillian - %s\r\n", block,
                   acct);
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0,
                 "the test could not send SBURSTM");

    stamp(block, sizeof block, 723UL, 0UL);
    (void)snprintf(line, sizeof line,
                   "%s:" PEER " SBURSTE 1700000010 0 1 1\r\n", block);
    TF_CHECK_MSG(send_line(*peer_fd, line) == 0, "the test could not send SBURSTE");

    TF_CHECK_MSG(nf_expect(node, "fed_burst_applied: ", T_IO_MS) == 0,
                 "a resync carrying an account of exactly the field's bound did not "
                 "commit, so the refusal in the case above is a node that refuses "
                 "every resync member rather than a length bound: %s",
                 node->out);
    TF_CHECK_MSG(strstr(node->out, "installed=1") != NULL,
                 "the resync committed but installed nothing, so the member record "
                 "at the bound was dropped by something other than the bound: %s",
                 node->out);
}

/* ---------------------------------------------------------------------------
 * THE SLOT IS ZEROED, ASSERTED BY LOOKING AT THE CODE
 * ---------------------------------------------------------------------------
 * WITH THE BOUND IN PLACE THIS LAST HALF HAS NO RUNTIME TEETH, and it is worth
 * saying why rather than quietly leaving an assertion that passes either way.
 *
 * `burst_copy()` REFUSES rather than truncating, and all three of its calls in
 * apply_member() discard the result. With account_name_wire_safe() refusing an
 * over-long name, none of the three can refuse -- <nick> is bounded by
 * valid_nick(), <server> by irc_serve_server_name_valid(), <account> by the rule.
 * So the pattern is unreachable TODAY and a fault injected here (drop the memset,
 * re-inject A or B, and the runtime half above catches both) is caught anyway.
 *
 * What is NOT caught is the pattern itself: a slot of a realloc'd array that
 * nothing zeroes is one realloc away from carrying the previous member's field
 * into a field no writer touched, and the two sibling record functions in the
 * same file both memset for exactly that reason. `channel.c` says the same shape
 * out loud -- "a RECYCLED element carrying the previous member's host ... is a
 * member impersonation bug wearing a memory bug's clothes" -- and names
 * `member_server` and `account` as the fields that grew into it.
 *
 * So the memset is asserted the only other way available: by looking at the
 * source, with test_util.h's tf_read_code()/strstr(), for the same reason
 * test_close_sites.c and test_account.c's expect_shutdown_frees_the_account_store()
 * do it -- no runtime test can check a missing call whose absence leaves every
 * runtime invariant intact.
 *
 * WHAT THIS DOES AND DOES NOT ESTABLISH. It establishes that apply_member() zeroes
 * the slot it is about to write. It does NOT establish that every field of that
 * slot is written on every path -- it establishes the opposite direction, that
 * nothing in the slot is left holding the previous member's bytes. Both halves
 * are stated rather than one being read as the other.
 */
static void case_slot_is_zeroed(void)
{
    char *code = tf_read_code("src/federation/burst.c", NULL);
    const char *at;

    TF_CHECK_MSG(code != NULL,
                 "could not read src/federation/burst.c (is IRCSERVE_SRC_DIR set?)");
    if (code == NULL) {
        return;
    }
    /* Scoped to apply_member() rather than counted over the whole file, because
     * the file DOES memset elsewhere -- apply_nick() and apply_chan() both do --
     * and a whole-file count would be satisfied by either of those. */
    at = strstr(code, "static int apply_member(");
    TF_CHECK_MSG(at != NULL, "could not find apply_member() in src/federation/burst.c");
    if (at != NULL) {
        const char *end = strstr(at, "\nstatic int apply_end(");
        TF_CHECK_MSG(end != NULL,
                     "could not find the end of apply_member() in "
                     "src/federation/burst.c");
        if (end != NULL) {
            const size_t len = (size_t)(end - at);
            char *body = (char *)malloc(len + 1u);

            TF_CHECK_MSG(body != NULL, "could not allocate the apply_member() body");
            if (body != NULL) {
                memcpy(body, at, len);
                body[len] = '\0';
                TF_CHECK_MSG(strstr(body, "memset(slot, 0, sizeof *slot)") != NULL,
                             "apply_member() writes a slot of a realloc'd array and "
                             "never zeroes it. Its two siblings in the same file both "
                             "do -- apply_nick() memsets and apply_chan() zeroes the "
                             "region it grows into -- and all three of its burst_copy() "
                             "calls discard the result, so a copy that refused would "
                             "leave the previous member's bytes in a field this "
                             "function then publishes: %s",
                             body);
                free(body);
            }
        }
    }
    free(code);
}

/* ---------------------------------------------------------------------------
 * THE ROSTER, ON THE WIRE, FOR BOTH MEMBERS AT ONCE
 * ---------------------------------------------------------------------------
 * The two cases above are both about what the node says about ITSELF -- a reject
 * line, a malformed line, a commit line. This one is about what a CLIENT is shown,
 * because that is the surface the truncation would have reached: a member of the
 * channel this node holds, named with an account that is not the account any peer
 * reported.
 *
 * `trillian` came in at the bound and is installed. `zaphod` came in one byte too
 * long and its transaction was thrown away, so the member must not be on the
 * roster at all -- a name a client can see in a 353 for a member record the node
 * refused is a roster entry the node cannot explain, which is what 4.3.1's
 * replace-never-merge is about.
 *
 * BOTH IN ONE NAMES ANSWER rather than in two, because "zaphod is absent" is only
 * evidence if the same buffer also shows that names ARE being drawn -- an empty
 * roster would satisfy it.
 *
 * AND THE TRANSACTION IS GATED ON FIRST, which is a race and not a formality: the
 * resync arrives on the PEER's socket and the NAMES on the CLIENT's, so the loop
 * has no reason to have read the peer's terminator before it reads the client's
 * question. Without this gate a correct node answers NAMES from the roster it had
 * a moment earlier and the case fails on the fix rather than on the defect -- which
 * is the shape of a flaky test this project would rather not add.
 *
 * AND THE CLIENT IS DRAINED BEFORE THE NAMES, which is the harness's own rule
 * rather than a precaution: tc_expect() searches the WHOLE buffer, this client
 * already has a 353 and a 366 from its JOIN, and tc_drain() is documented as the
 * thing that consumes what is already buffered "so the next strstr() [does not]
 * match something from an earlier exchange". So the drain is what makes the delta
 * below the NAMES answer and not the JOIN's.
 */
static void case_roster_on_the_wire(nf_node_t *node, test_client_t *client)
{
    size_t mark;
    int eof = 0;

    TF_CHECK_MSG(nf_expect(node, "fed_burst_applied: ", T_IO_MS) == 0,
                 "the resync never committed, so the roster this case reads is the "
                 "one from before it and both assertions below would be about "
                 "nothing: %s",
                 node->out);
    (void)tc_drain(client, 200, &eof);
    mark = tc_received(client);
    TF_CHECK_MSG(tc_send(client, "NAMES " CHAN) == 0, "NAMES send failed");
    TF_CHECK_MSG(tc_expect(client, " 366 ", T_IO_MS) == 0,
                 "the NAMES answer never terminated, so the two assertions below "
                 "would be reading a partial roster: %s",
                 tc_buffer(client) + mark);
    TF_CHECK_MSG(strstr(tc_buffer(client) + mark, "trillian") != NULL,
                 "the member whose account was exactly the field's bound is not in "
                 "the roster a client is shown, so the commit above installed "
                 "nothing: %s",
                 tc_buffer(client) + mark);
    TF_CHECK_MSG(strstr(tc_buffer(client) + mark, "zaphod") == NULL,
                 "a member whose account this node could not hold is on the roster "
                 "a client is shown. Its record was refused, so the roster now "
                 "names a member no peer reported: %s",
                 tc_buffer(client) + mark);
}

int main(void)
{
    nf_node_t node;
    test_client_t client;
    hostile_peer_t peer;

    memset(&peer, 0, sizeof peer);
    peer.fd = -1;
    tc_init(&client);
    peer_open(&peer, &node, &client);
    case_sjoin_account_bound(&node, &peer.fd);
    case_sburstm_account_bound(&node, &peer.fd);
    case_burst_at_bound(&node, &peer.fd);
    case_roster_on_the_wire(&node, &client);
    case_slot_is_zeroed();
    peer_close(&peer, &node, &client);
    tf_done("fed_account");
    return 0;
}
