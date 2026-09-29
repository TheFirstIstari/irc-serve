/* test_fed_handshake.c -- the FEDERATE exchange, on the wire, over real TCP.
 *
 * docs/SERVER_DESIGN.md 2.3: "Peer auth is not user SASL. A peer connection is
 * exempt from the client registration state machine entirely: no PASS/NICK/
 * USER, no 001-005, no MOTD. It authenticates with the FEDERATE handshake
 * secret and is REJECTED BEFORE ESTABLISHED. Server-name uniqueness is enforced
 * at the same point -- two nodes both named irc.a is catastrophic and
 * undetectable later."  8: "Two nodes cannot both be named irc.a -- rejected at
 * handshake."
 *
 * ---------------------------------------------------------------------------
 * WHAT IS ASSERTED, AND ON WHAT
 * ---------------------------------------------------------------------------
 * Every assertion here is on OBSERVABLE OUTPUT -- the child's own [observable]
 * lines and, in four cases, the bytes this test sends and receives. No case
 * reads a struct field, and none of them would notice a reorder of server_t.
 * The nine cases, in the order they run:
 *
 *   1. same name, both directions    SELF_NAME, and NOBODY reaches ESTABLISHED
 *   2. wrong secret                  BAD_SECRET, and the exchange still failed
 *   3. NO secret configured          NO_SECRET, and NOT BAD_SECRET
 *   3b. answer names another server  NAME_MISMATCH, and NOT a duplicate
 *   4. name already ESTABLISHED      DUPLICATE_LINK, and fed_duplicate=1
 *   5. handshake never answered      link_timeout / state=TIMED_OUT
 *   6. liveness, the positive case   keepalives flow and lines= climbs
 *   7. peer goes silent              link_dead, after the keepalives stop
 *   8. happy path, the SHIPPED BINARY  link_established on both nodes
 *
 * Case 8 is the one that runs the real executable, so the command line and
 * node_main.c's getaddrinfo are covered by something that can fail: a broken
 * --peer parse or a resolution that returns the wrong address shows up as case
 * 8 failing, not as a code path nothing reaches.
 *
 * Cases 2 and 3 are ONE experiment run twice and the PAIRING is the assertion:
 * the same offered secret, refused with two different reasons, differing only in
 * whether the node was given a secret at all. An operator reading `reason=` has
 * to be able to tell a wrong guess from a node that is not configured to
 * federate, so a test that only proved "somebody was refused" would not be
 * asserting the part that is new.
 *
 * ---------------------------------------------------------------------------
 * THE TWO SECRETS DIFFER IN EXACTLY ONE BYTE, AND THAT IS THE POINT
 * ---------------------------------------------------------------------------
 * SECRET_OK and SECRET_BAD are identical except for their LAST character. A
 * comparison that looked at the first byte, or at a prefix, or that stopped
 * early on a match, would accept SECRET_BAD and link the pair -- which is what
 * makes this case a test of the compare rather than of the fact that two
 * different strings exist. Two secrets chosen to differ in their first byte
 * would also pass a broken compare, so they are not chosen that way.
 *
 * ---------------------------------------------------------------------------
 * WHY THE TIMEOUTS ARE SET PER PROCESS AND NOT PER TEST FILE
 * ---------------------------------------------------------------------------
 * Every case here lives in ONE executable, so a compile-time constant would
 * make "5 seconds" a property of the binary and force the handshake-timeout and
 * liveness cases to either wait the shipped interval or skip. Instead the child
 * calls fed_set_timeouts() in its setup hook, which runs after fork() -- so the
 * value applies in the CHILD'S OWN PROCESS and the parent is unaffected. That
 * is the whole reason the override is a function and not an #ifdef: the
 * alternative makes a per-case requirement into a per-build one.
 *
 * ---------------------------------------------------------------------------
 * WHY lines= IS ASSERTED WITH A LOWER BOUND AND NEVER WITH EQUALITY
 * ---------------------------------------------------------------------------
 * T3 queues a keepalive on every ESTABLISHED link every IRC_FED_KEEPALIVE_MS,
 * and a received line is framed and counted in n_lines. So on a LINKED node the
 * peer keeps lines= climbing with no client involved, and an equality
 * assertion is a race against a timer. The lower bound below is deliberately
 * loose for the same reason it is not exact: what is being claimed is "the
 * link is carrying traffic", not "the link carried exactly N lines".
 *
 * ---------------------------------------------------------------------------
 * WHY EVERY ASSERTION HERE WAITS AND NONE OF THEM GREPS A HALF-DRAINED BUFFER
 * ---------------------------------------------------------------------------
 * `strstr(n->out, ...)` reads whatever the parent has happened to read off the
 * child's pipe so far, and nf_expect() stops pumping the instant its needle
 * appears. So a strstr() for a line printed AFTER the one the preceding
 * nf_expect() waited for is a race: it passes on a machine where both lines
 * arrived in one read() and fails on one where the pump stopped between them.
 * This file hit that on Apple clang and passed on GCC and upstream clang, which
 * is what a race looks like.
 *
 * So: a POSITIVE assertion is always nf_expect(), which pumps until the line is
 * there; and a NEGATIVE assertion -- "this must never be printed" -- is made
 * AFTER nf_stop(), when the child is gone, nf_stop() has drained what it wrote,
 * and the buffer therefore contains everything the child will ever say. A
 * negative read against a live child would be satisfied by output that simply
 * had not arrived yet, which is the failure mode a test most needs to avoid.
 * ---------------------------------------------------------------------------
 * NO FIXED SLEEP ANYWHERE (6.3)
 * ---------------------------------------------------------------------------
 * Every wait is a deadline: nf_expect() over the child's stdout, tc_expect()
 * over a socket, or a select()-driven loop in the two local helpers at the
 * bottom. The one place a wait is not enough on its own -- "B has finished
 * dialling before I read its port" -- is handled by the fixture's own readiness
 * handshake (6.2) rather than by a delay.
 */
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "core/server.h"
#include "federation/link.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

/* Deadlines. Generous, because these are deadlines for forked children on a
 * possibly loaded CI machine and not estimates of how long anything should
 * take; they fail fast enough when the thing being waited for never happens. */
#define T_IO_MS 15000

/* See the header: identical but for the last byte, on purpose. */
#define SECRET_OK "irc-serve-federation-secret-a"
#define SECRET_BAD "irc-serve-federation-secret-b"

/* What the no-secret case OFFERS: two double-quote characters, and not an empty
 * parameter, because this node's parser cannot carry one in a non-final
 * position. Case 3's comment has the three wire shapes and what each of them
 * actually parses to, all three checked against the shipped binary; this is the
 * line that follows from them. */
#define OFFERED_SECRET "\"\""

/* The node name the same-name cases use. It has to be one this node's own
 * default would also be legal under, which is the 2.4 tag grammar, and the
 * harness's default ("irc.fixture") is already exactly that. */
#define SELF_NAME_NODE "irc.fixture"

/* ---------------------------------------------------------------------------
 * The child's configuration
 * ---------------------------------------------------------------------------
 * Read by the child AFTER the fork, so the parent fills it in before spawning
 * and the child inherits it. It is a file-static rather than a setup-function
 * parameter because nf_setup_fn is `void (*)(server_t *)` and changing that
 * signature for one test's convenience would touch every existing caller.
 *
 * The alternative -- a global per test binary -- is exactly what this is; the
 * difference is that it is declared here, in the one file that uses it, with
 * the reason written down. Tests run in separate processes, so two tests cannot
 * see each other's values, and within this file the value is always set
 * immediately before the spawn that reads it. */
typedef struct {
    const char *peer_name;   /* NULL: no peer configured */
    int         peer_port;   /* 0: no peer configured */
    const char *secret;
    uint64_t    dial_ms;
    uint64_t    hs_ms;
    uint64_t    keepalive_ms;
    uint64_t    dead_ms;
    int         trace;       /* set s->trace, for the per-line observable */
    uint64_t    line_probe;  /* 0: off; else report framed= once past it */
} child_cfg_t;

static child_cfg_t g_cfg;

/* The tick this test installs in its children, which is fed_tick plus a probe.
 *
 * The probe exists because n_lines is not one of the counters the harness
 * republishes, and the liveness case has to read a line count that is still
 * GROWING -- a test that stops the child and then reads the final total cannot
 * tell "the keepalives flowed" from "the keepalives had not started yet".
 *
 * So the child's own tick reports it, once past a threshold the test chose and
 * again whenever it moves. It is a test-owned hook chained in front of the
 * harness's, in the same way the harness chains its own in front of this one:
 * every layer calls the next, and no layer replaces another.
 *
 * The key is `framed=` rather than `lines=` on purpose. nf_find_u64() takes the
 * LAST occurrence of a key, and the fixture's own stats line also carries
 * lines=, so reusing the spelling would make this probe and the harness's
 * report race for the same key. */
static uint64_t g_probe_target = 0;
static uint64_t g_probe_reported = (uint64_t)-1;

static void child_tick(server_t *s, uint64_t now_ms)
{
    fed_tick(s, now_ms);
    if (g_probe_target != 0u && s->n_lines >= g_probe_target &&
        s->n_lines != g_probe_reported) {
        g_probe_reported = s->n_lines;
        printf("[test] framed=%llu\n", (unsigned long long)s->n_lines);
        fflush(stdout);
    }
}

static void child_setup(server_t *s)
{
    struct sockaddr_in sa;

    TF_CHECK_MSG(fed_open(s, g_cfg.secret) == 0,
                 "fed_open() failed in the child; a node with an unopenable "
                 "federation module cannot reach any assertion in this test");
    /* The trace is the node's own per-line output, and the tick is the node's
     * own time seam: both are assigned HERE, in the test's setup hook, for the
     * same reason node_main.c assigns them there rather than delegating to
     * fed_open(). A reader of this test should be able to see that the
     * federation tick is installed, not infer it. */
    s->on_tick = child_tick;
    s->trace = g_cfg.trace;
    g_probe_target = g_cfg.line_probe;
    g_probe_reported = (uint64_t)-1;
    /* Applied BEFORE the loop is armed, and therefore before the first tick:
     * a dial started in the first tick must already be timed against this
     * process's dial timeout rather than the shipped one. */
    fed_set_timeouts(g_cfg.dial_ms, g_cfg.hs_ms, g_cfg.keepalive_ms,
                     g_cfg.dead_ms);

    if (g_cfg.peer_name != NULL && g_cfg.peer_port > 0) {
        /* 127.0.0.1 built by hand rather than resolved, which is the honest
         * thing for a fixture to do: node_main.c's getaddrinfo is exercised by
         * case 8 (the shipped binary), and a second copy of a resolver in a
         * test would be a second thing to keep right. The production rule this
         * respects is the ADDRESS SHAPE -- a struct sockaddr handed to
         * fed_link_configure() -- not the lookup. */
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = htons((unsigned short)g_cfg.peer_port);
        TF_CHECK_MSG(fed_link_configure(s, g_cfg.peer_name,
                                        (const struct sockaddr *)&sa,
                                        (socklen_t)sizeof sa) != NULL,
                     "the child could not configure peer %s on port %d",
                     g_cfg.peer_name, g_cfg.peer_port);
    }
}

/* Fill g_cfg with everything except the peer, which the caller sets after it
 * knows the port. Zeroing matters: a previous case's peer_port left in place
 * would make a case that means to have no peer dial the last one it saw. */
static void cfg_no_peer(const char *secret, uint64_t hs_ms, int trace)
{
    memset(&g_cfg, 0, sizeof g_cfg);
    g_cfg.peer_name = NULL;
    g_cfg.peer_port = 0;
    g_cfg.secret = secret;
    g_cfg.hs_ms = hs_ms;
    g_cfg.trace = trace;
}

static void cfg_dials(const char *peer_name, int peer_port, const char *secret,
                      uint64_t hs_ms, int trace)
{
    cfg_no_peer(secret, hs_ms, trace);
    g_cfg.peer_name = peer_name;
    g_cfg.peer_port = peer_port;
}

/* ---------------------------------------------------------------------------
 * Local socket helpers
 * ---------------------------------------------------------------------------
 * Two, and both because this test is the SERVER half of a connection in one
 * case and irc_client.h is the client half. They are deadline waits over
 * select() for the same reason everything else here is.
 */
static uint64_t now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000L);
}

/* A listening socket on the loopback, ephemeral port, reported through
 * *port_out. The port is needed BEFORE the child spawns (a child's peer
 * configuration is fixed at fork), which is why this exists rather than a
 * tc_connect() against a node that is going to dial US. */
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

/* Accept one connection, or -1 by the deadline. */
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

/* Read from `fd` until EVERY needle in `needles` has appeared in what has
 * arrived, or the deadline passes. The positive control for case 5: the test
 * has to see the node's FEDERATE go out, or "the node timed out" would be
 * satisfied by a node that never sent anything at all.
 *
 * All the needles in ONE call rather than one call each, and the reason is
 * mechanical but worth stating: the buffer here is local, so a second call
 * starts from nothing and can never see the bytes the first call consumed. A
 * helper that grew the state and the needles together would make that mistake
 * impossible; this one makes it a wrong argument list instead. */
static int read_until(int fd, const char *const *needles, size_t nneedles,
                      int timeout_ms)
{
    char buf[4096];
    char seen[8192];
    size_t used = 0;
    size_t got_all = 0;
    size_t i;
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
            break; /* more than we are willing to accumulate */
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
        for (i = 0; i < nneedles; i++) {
            if (strstr(seen, needles[i]) != NULL) {
                got_all++;
            }
        }
    }
    for (i = 0; i < nneedles; i++) {
        if (strstr(seen, needles[i]) == NULL) {
            fprintf(stderr, "read_until: TIMEOUT after %d ms; never saw "
                    "\"%s\"\nread %lu bytes: %s\n",
                    timeout_ms, needles[i], (unsigned long)used,
                    (used > 0u) ? seen : "(nothing)");
        }
    }
    return -1;
}

/* ---------------------------------------------------------------------------
 * Case 1: two nodes with one name
 * ---------------------------------------------------------------------------
 * 2.3 calls this "catastrophic and undetectable later", and 8 makes it a
 * definition-of-done item. It cannot be reached with two DIFFERENTLY named
 * nodes, which is why nf_spawn_inline_named() exists: the harness's own default
 * name is the only name a child had before, and a test that needs two children
 * to claim the same one has to be able to say what it is.
 *
 * The chain is A <- B <- C <- D, each dialling the previous one, all four named
 * `irc.fixture`:
 *
 *   - A, B and C each RECEIVE a claim for their own name and must answer
 *     SELF_NAME. That is three of the four possible receiving sides, reached
 *     without any of them having to know a port before it existed.
 *   - B, C and D each also run a link of their own, and none of those links may
 *     reach ESTABLISHED. A link that did would be the catastrophic case, so
 *     the negative assertion is the load-bearing half of this case and it is
 *     asserted on the wire: no node may print link_established, and the three
 *     dialling links must instead end in T2.
 *
 * The 500 ms handshake timeout is set per child so the T2 side of the assertion
 * arrives promptly instead of after the shipped five seconds. It is not 0 --
 * fed_set_timeouts() treats 0 as "keep the built-in" -- and it is 500 rather
 * than 100 because the T2 deadline is measured from the moment the link was
 * dialled, on loopback, and a number that tight would be asserting the
 * scheduler's mood. */
static void case_self_name(void)
{
    nf_node_t a;
    nf_node_t b;
    nf_node_t c;
    nf_node_t d;

    cfg_no_peer(SECRET_OK, 500, 0);
    TF_CHECK_MSG(nf_spawn_inline_named(&a, SELF_NAME_NODE, child_setup) == 0,
                 "could not spawn node A");

    cfg_dials(SELF_NAME_NODE, a.port, SECRET_OK, 500, 0);
    TF_CHECK_MSG(nf_spawn_inline_named(&b, SELF_NAME_NODE, child_setup) == 0,
                 "could not spawn node B");

    cfg_dials(SELF_NAME_NODE, b.port, SECRET_OK, 500, 0);
    TF_CHECK_MSG(nf_spawn_inline_named(&c, SELF_NAME_NODE, child_setup) == 0,
                 "could not spawn node C");

    cfg_dials(SELF_NAME_NODE, c.port, SECRET_OK, 500, 0);
    TF_CHECK_MSG(nf_spawn_inline_named(&d, SELF_NAME_NODE, child_setup) == 0,
                 "could not spawn node D");

    /* The receiving side refuses, with the name in the line so an operator
     * reading the log knows which claim was rejected rather than only that one
     * was. */
    TF_CHECK_MSG(nf_expect(&a, "link_rejected: peer=" SELF_NAME_NODE
                                " reason=SELF_NAME", T_IO_MS) == 0,
                 "node A accepted a FEDERATE claiming its own name; 2.3 makes "
                 "that a rejection and 8 makes it a definition-of-done item");
    TF_CHECK_MSG(nf_expect(&b, "link_rejected: peer=" SELF_NAME_NODE
                                " reason=SELF_NAME", T_IO_MS) == 0,
                 "node B accepted a FEDERATE claiming its own name");
    TF_CHECK_MSG(nf_expect(&c, "link_rejected: peer=" SELF_NAME_NODE
                                " reason=SELF_NAME", T_IO_MS) == 0,
                 "node C accepted a FEDERATE claiming its own name");

    /* And the counter agrees with the line, from the child's own stats line
     * rather than from the struct -- the count is republished on change, so
     * nf_expect_u64() waiting for it is a deadline wait and not a read. */
    TF_CHECK_MSG(nf_expect_u64(&a, "fed_rejected=", 1, T_IO_MS) == 0,
                 "node A should have counted exactly one rejection");

    /* The dialling links end in T2, never in ESTABLISHED. T2 rather than
     * nothing because the peer closed the connection on rejection, and a link
     * whose connection is gone still owes the FSM a terminal state -- if it did
     * not get one it would sit in HANDSHAKE_SENT forever with a dead
     * descriptor, which is the thing T2 exists to prevent. */
    TF_CHECK_MSG(nf_expect_u64(&b, "fed_hs_timeout=", 1, T_IO_MS) == 0,
                 "node B's link to a same-named peer should have timed out");
    TF_CHECK_MSG(nf_expect_u64(&c, "fed_hs_timeout=", 1, T_IO_MS) == 0,
                 "node C's link to a same-named peer should have timed out");
    TF_CHECK_MSG(nf_expect_u64(&d, "fed_hs_timeout=", 1, T_IO_MS) == 0,
                 "node D's link to a same-named peer should have timed out");

    /* The negative that matters, and it is read only after the four children
     * have stopped: while one is alive its buffer is whatever the parent has
     * pumped so far, and "link_established has not appeared" is then a statement
     * about the pipe rather than about the node. After a stop the buffer holds
     * everything the child ever printed, so this is a statement about the
     * node. */
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&c) == 0, "node C did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&d) == 0, "node D did not exit cleanly");
    TF_CHECK_MSG(strstr(a.out, "link_established") == NULL,
                 "node A reported a link as ESTABLISHED after refusing the "
                 "only claim it was ever sent: %s", a.out);
    TF_CHECK_MSG(strstr(b.out, "link_established") == NULL,
                 "node B reported a link as ESTABLISHED: %s", b.out);
    TF_CHECK_MSG(strstr(c.out, "link_established") == NULL,
                 "node C reported a link as ESTABLISHED: %s", c.out);
    TF_CHECK_MSG(strstr(d.out, "link_established") == NULL,
                 "node D reported a link as ESTABLISHED: %s", d.out);

    nf_free(&a);
    nf_free(&b);
    nf_free(&c);
    nf_free(&d);
}

/* ---------------------------------------------------------------------------
 * Case 2: a peer that presents the wrong secret
 * ---------------------------------------------------------------------------
 * B presents SECRET_BAD and A holds SECRET_OK, so the two differ in one byte at
 * the end (see the header). A must refuse, and the reason must be the SECRET
 * and not the name: 2.3 puts the secret check before the identity checks so
 * that a node which is not allowed to be here learns nothing about who is, and
 * a wrong-secret rejection reported as NAME_IN_USE would tell a stranger that
 * this node has a link to that name.
 *
 * A's rejection is the assertion. B's own link is left HANDSHAKE_SENT and
 * times out, and that is NOT asserted here: it is a consequence of A refusing
 * to answer rather than a claim about the secret, and case 1 already asserts
 * the T2 path. Asserting it twice would only make this case slower. */
static void case_bad_secret(void)
{
    nf_node_t a;
    nf_node_t b;

    cfg_no_peer(SECRET_OK, 500, 0);
    TF_CHECK_MSG(nf_spawn_inline_named(&a, "irc.a", child_setup) == 0,
                 "could not spawn node A");

    cfg_dials("irc.a", a.port, SECRET_BAD, 500, 0);
    TF_CHECK_MSG(nf_spawn_inline_named(&b, "irc.b", child_setup) == 0,
                 "could not spawn node B");

    TF_CHECK_MSG(nf_expect(&a, "link_rejected: peer=irc.b reason=BAD_SECRET",
                           T_IO_MS) == 0,
                 "node A accepted a FEDERATE with the wrong secret. If the "
                 "compare is looking at a prefix rather than at the whole "
                 "value, this is where it shows: the two secrets used here "
                 "differ only in their LAST byte.");
    TF_CHECK_MSG(nf_expect_u64(&a, "fed_rejected=", 1, T_IO_MS) == 0,
                 "node A should have counted exactly one rejection");
    /* And it was not also counted as a duplicate or a name clash, which is the
     * ORDER of the checks rather than the verdicts: the reason breakdown in the
     * dump is the assertion, and a reason reported as BAD_SECRET that also
     * incremented rej_dup would mean the uniqueness check ran first. */
    TF_CHECK_MSG(nf_expect(&a, "rej_secret=1", T_IO_MS) == 0,
                 "node A's dump does not report one bad-secret rejection");
    TF_CHECK_MSG(nf_expect(&a, "rej_dup=0", T_IO_MS) == 0,
                 "node A counted a duplicate link for a wrong secret, which "
                 "means the secret check ran after the uniqueness check");

    /* The negative, read after the stop. See the file header: a strstr() for a
     * line that must never appear is only meaningful once the child is gone and
     * its whole output has been drained. */
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    TF_CHECK_MSG(strstr(a.out, "link_established") == NULL,
                 "node A reported a link as ESTABLISHED after refusing the "
                 "secret: %s", a.out);
    nf_free(&a);
    nf_free(&b);
}

/* ---------------------------------------------------------------------------
 * Case 3: a node with NO secret configured refuses every inbound claim
 * ---------------------------------------------------------------------------
 * The policy: federation is OPT-IN. A node federates because it was given a
 * --secret, so a node with no secret is a node that federates with nobody, and
 * it says so with a verdict of its own -- FED_NO_SECRET, reported as
 * `reason=NO_SECRET` -- rather than folding the case into BAD_SECRET.
 *
 * The pairing with case 2 IS the test. One line, byte for byte identical, goes
 * to two nodes that differ in exactly one thing: whether fed_open() was given a
 * secret. The unconfigured node answers NO_SECRET and the configured node
 * answers BAD_SECRET. Either assertion alone would be satisfiable by a node
 * that refuses everything, and the difference between the two reasons is the
 * whole reason the verdict is not folded in: an operator reading `reason=` has
 * to be able to tell a credential under attack from a missing --secret, because
 * the fixes are opposites and one of them is "stop rotating the credential".
 *
 * WHAT THE OFFERED SECRET IS, AND WHY IT IS TWO QUOTE CHARACTERS
 * -------------------------------------------------------------
 * `""` -- two double-quote characters -- and NOT an empty parameter, because an
 * empty parameter cannot be put on the wire in a non-final position by this
 * node's parser. core/message.c skips an empty token rather than counting it, and
 * a `:` parameter consumes the rest of the line, so both of the shapes that
 * look like an empty secret arrive as something else:
 *
 *     :x FEDERATE n 1700000000 "" irc-serve-0.1.0   -> 4 params, secret = ""
 *     :x FEDERATE n 1700000000 : irc-serve-0.1.0    -> 3 params -> BAD_ARITY
 *     :x FEDERATE n 1700000000  irc-serve-0.1.0     -> 3 params -> BAD_ARITY
 *
 * All three were checked against the shipped binary before this comment was
 * written, and the consequences are worth being exact about, because they are
 * the difference between a hole and a latent one:
 *
 *   - BEFORE the guard, a default-configured node answered the first of those
 *     three lines with BAD_SECRET, not with an acceptance. The empty-vs-empty
 *     accept that the guard closes is NOT reachable from a line today, because
 *     a parser in ANOTHER module refuses to produce an empty parameter.
 *   - So the link path itself had no defence of its own: whether a
 *     default-configured node admitted a stranger depended on core/message.c's
 *     parameter grammar rather than on anything in the link module. One change
 *     to a parameter rule, in a file that knows nothing about peers, would have
 *     opened it.
 *
 * What is asserted below, then, is the POLICY rather than a parser accident: a
 * node with no secret accepts no inbound claim, whatever the offered value is
 * and however the wire happens to spell it. That is the property worth having,
 * and it is the one that makes NO_SECRET worth printing.
 */
static void case_no_secret_refused(void)
{
    nf_node_t bare;   /* fed_open() with "" -- no secret configured */
    nf_node_t armed;  /* fed_open() with SECRET_OK                  */
    test_client_t to_bare;
    test_client_t to_armed;
    char line[512];

    /* "" rather than NULL, because that is what the CLI's default is and the
     * point of the case is the default: node_main.c's NODE_DEFAULT_SECRET is
     * "" and fed_open() cannot tell the two apart, so neither can this test. */
    cfg_no_peer("", 1000, 0);
    TF_CHECK_MSG(nf_spawn_inline_named(&bare, "irc.bare", child_setup) == 0,
                 "could not spawn the node with no secret");
    cfg_no_peer(SECRET_OK, 1000, 0);
    TF_CHECK_MSG(nf_spawn_inline_named(&armed, "irc.armed", child_setup) == 0,
                 "could not spawn the node with a secret");

    /* One line, both nodes, same bytes. The version is IRC_SERVE_VERSION rather
     * than a literal so this cannot quietly stop being a well-formed FEDERATE,
     * and the epoch is any legal 2.4 epoch for the reason case 4 gives. The
     * prefix is a third name, again because the prefix is not the authority.
     * The claim is a name neither node has, because a claim that matched one of
     * them would be refused as SELF_NAME first and the secret step would never
     * be reached. */
    (void)snprintf(line, sizeof line, ":irc.thief FEDERATE irc.peer 1700000000 %s %s",
                   OFFERED_SECRET, IRC_SERVE_VERSION);

    tc_init(&to_bare);
    TF_CHECK_MSG(tc_connect(&to_bare, bare.port) == 0,
                 "the test could not open a connection to the node with no "
                 "secret");
    TF_CHECK_MSG(tc_send(&to_bare, line) == 0,
                 "the test could not send FEDERATE to the node with no secret");
    TF_CHECK_MSG(nf_expect(&bare, "link_rejected: peer=irc.peer reason=NO_SECRET",
                           T_IO_MS) == 0,
                 "a node started with no secret accepted a FEDERATE, or refused "
                 "it for a reason that does not name the configuration. The "
                 "policy is that a node with no --secret federates with NOBODY, "
                 "and it has to say so as NO_SECRET so an operator can tell a "
                 "missing --secret from a guessed credential.");
    /* The counter is its own, which is the other half of "distinguishable": a
     * reason that shares a counter with another reason is a reason a reader of
     * the dump cannot separate, whatever the rejection line says. */
    TF_CHECK_MSG(nf_expect(&bare, "rej_nosecret=1", T_IO_MS) == 0,
                 "the no-secret rejection is not counted as rej_nosecret=1: %s",
                 bare.out);
    TF_CHECK_MSG(nf_expect(&bare, "rej_secret=0", T_IO_MS) == 0,
                 "the node counted a no-secret rejection as a bad secret, which "
                 "reports a misconfiguration as an attack");
    TF_CHECK_MSG(nf_expect_u64(&bare, "fed_rejected=", 1, T_IO_MS) == 0,
                 "the node should have counted exactly one rejection");
    /* And the claimer was closed, which is the wire-observable half of the
     * refusal: 3.4 puts the close at the reaper, and a rejected handshake left
     * open is a descriptor this node is still reading from. */
    TF_CHECK_MSG(tc_expect_eof(&to_bare, T_IO_MS) == 0,
                 "the node with no secret did not close the refused connection");
    tc_close(&to_bare);

    /* The same line to the node that DOES have a secret: the identical offer is
     * now a wrong guess rather than a disabled feature, and it must be reported
     * as the other reason. This is the half that would be lost by folding the
     * two cases into one verdict. */
    tc_init(&to_armed);
    TF_CHECK_MSG(tc_connect(&to_armed, armed.port) == 0,
                 "the test could not open a connection to the node with a secret");
    TF_CHECK_MSG(tc_send(&to_armed, line) == 0,
                 "the test could not send FEDERATE to the node with a secret");
    TF_CHECK_MSG(nf_expect(&armed, "link_rejected: peer=irc.peer reason=BAD_SECRET",
                           T_IO_MS) == 0,
                 "a node WITH a secret must still refuse an offer that is not it; "
                 "the new guard is about the node's own configuration and must "
                 "not have weakened the compare that case 2 covers");
    TF_CHECK_MSG(nf_expect_u64(&armed, "fed_rejected=", 1, T_IO_MS) == 0,
                 "the armed node should have counted exactly one rejection");

    TF_CHECK_MSG(nf_stop(&bare) == 0, "the bare node did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&armed) == 0, "the armed node did not exit cleanly");
    /* Neither created a link, and neither was fooled into treating the claim as
     * a duplicate of something: the new verdict has its own counter precisely so
     * that a name disagreement is not reported as a split brain, and neither
     * applies here. Read after the stops, so the buffer holds everything. */
    TF_CHECK_MSG(strstr(bare.out, "link_established") == NULL,
                 "the node with no secret reported a link as ESTABLISHED: %s",
                 bare.out);
    TF_CHECK_MSG(strstr(armed.out, "link_established") == NULL,
                 "the armed node reported a link as ESTABLISHED: %s", armed.out);
    TF_CHECK_MSG(strstr(bare.out, "reason=NAME_MISMATCH") == NULL &&
                 strstr(armed.out, "reason=NAME_MISMATCH") == NULL,
                 "a claim on a fresh connection was reported as a name mismatch; "
                 "that verdict is for a claim arriving on a link that already "
                 "has a different name, and these claims arrived on the listener");
    tc_close(&to_armed);
    nf_free(&bare);
    nf_free(&armed);
}

/* ---------------------------------------------------------------------------
 * Case 3b: a sink that answers with a DIFFERENT claim
 * ---------------------------------------------------------------------------
 * FED_NAME_MISMATCH is the one verdict 2.3 lists that no case reached, and it is
 * the one that is WIRE-CONFIRMED BUT UNTESTED: fed_check_federate() produces it
 * on the fourth step, and nothing in the suite drove the path.
 *
 * The situation is a misconfiguration with a specific signature. Node A is told
 * to DIAL a peer it calls `irc.b`, so A creates a link NAMED irc.b and sends
 * `:irc.a FEDERATE irc.a <epoch> <secret> <version>` down it. The far end here
 * is a socket this test owns, and it answers with a claim for a DIFFERENT name --
 * `irc.wrong`. The name on the wire therefore disagrees with the name on the
 * link it arrived on, which is the only way to reach that verdict, and the node
 * has to say so rather than adopting the stranger's name or treating it as a
 * duplicate of something.
 *
 * WHY A RAW SOCKET AND NOT A SECOND NODE. A second node would have to be told to
 * answer with the wrong name, which means configuring it wrong on purpose, and
 * the failure would then be visible in the second node's own log as well as the
 * first's -- so a test would pass if EITHER node noticed. Here the far end is
 * four lines of answer, and the only node with a verdict is the one under test.
 *
 * THE TWO ASSERTIONS THAT ARE NOT THE REASON, and they matter more than the
 * reason does:
 *
 *   - `fed_duplicate=0`. A name disagreement is a MISCONFIGURATION and not a
 *     second route to a peer, so reporting it under the duplicate verdict would
 *     tell an operator reading the dump that the mesh has split. The verdict has
 *     its own counter for exactly this, and this case is what proves it.
 *   - NO link_established. A node that adopted the stranger's name would have a
 *     link to irc.wrong that its configuration does not mention, which is how a
 *     mesh ends up with a route nobody configured.
 */
static void case_name_mismatch(void)
{
    nf_node_t a;
    int listen_fd;
    int port = 0;
    int peer_fd;
    char reply[512];

    listen_fd = listen_loopback(&port);
    TF_CHECK_MSG(listen_fd >= 0, "the test could not open a listening socket");

    /* The link is named irc.b, so the claim that comes back as irc.wrong is a
     * mismatch and not a fresh claim on the listener. */
    cfg_dials("irc.b", port, SECRET_OK, 1000, 0);
    TF_CHECK_MSG(nf_spawn_inline_named(&a, "irc.a", child_setup) == 0,
                 "could not spawn node A");

    peer_fd = accept_deadline(listen_fd, T_IO_MS);
    TF_CHECK_MSG(peer_fd >= 0, "node A never dialled the socket this test owns");

    /* Read A's claim first, for the reason case 5 gives: without it, "the node
     * rejected the exchange" would be satisfied by a node that never sent
     * anything. Pinned on both sides of the epoch, which is a clock reading. */
    {
        const char *const needles[] = {
            ":irc.a FEDERATE irc.a ",
            " " SECRET_OK " " IRC_SERVE_VERSION "\r\n"
        };

        TF_CHECK_MSG(read_until(peer_fd, needles,
                                sizeof needles / sizeof needles[0], T_IO_MS) == 0,
                     "node A never sent a FEDERATE, so the mismatch below would "
                     "be asserting nothing");
    }

    /* The wrong answer. Everything about it is legal -- four parameters, a legal
     * name, a legal epoch, the RIGHT SECRET and the right version -- and the
     * only thing wrong with it is that it names a server this link is not
     * configured for. That is what makes it a test of the mismatch step rather
     * than of any of the other three, all of which it deliberately passes. */
    (void)snprintf(reply, sizeof reply,
                   ":irc.wrong FEDERATE irc.wrong 1700000000 %s %s\r\n",
                   SECRET_OK, IRC_SERVE_VERSION);
    TF_CHECK_MSG(write(peer_fd, reply, strlen(reply)) > 0,
                 "the test could not answer with the mismatched claim");

    TF_CHECK_MSG(nf_expect(&a, "link_rejected: peer=irc.b reason=NAME_MISMATCH",
                           T_IO_MS) == 0,
                 "a claim naming a different server than the link it arrived on "
                 "was not reported as NAME_MISMATCH. Everything else about that "
                 "claim was correct, so the only check it could have failed is "
                 "the one this case is about.");

    /* The sink closed its half, which the node observes: 3.4 makes the close the
     * reaper's, so a rejected exchange left open is a descriptor the node is
     * still reading from. */
    {
        fd_set rfds;
        struct timeval tv;
        char scratch[256];
        int rc;

        FD_ZERO(&rfds);
        FD_SET(peer_fd, &rfds);
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        rc = select(peer_fd + 1, &rfds, NULL, NULL, &tv);
        TF_CHECK_MSG(rc == 1, "node A did not close the mismatched handshake");
        if (rc == 1) {
            ssize_t got = read(peer_fd, scratch, sizeof scratch);

            TF_CHECK_MSG(got == 0, "the connection was reset rather than closed "
                                    "cleanly (read returned %ld)",
                         (long)got);
        }
    }

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    /* Read after the stop, so the buffer holds everything the node will ever
     * say. The duplicate verdict is the one that must NOT be here: a name
     * disagreement is a misconfiguration and reporting it as a split brain is
     * the specific confusion this verdict was separated to prevent. */
    TF_CHECK_MSG(nf_find_u64(&a, "fed_duplicate", NULL) == -1,
                 "a name mismatch was counted as a duplicate link, so an "
                 "operator reading the dump would be told the mesh had split: %s",
                 a.out);
    TF_CHECK_MSG(strstr(a.out, "link_established") == NULL,
                 "the node adopted the stranger's name and reported a link as "
                 "ESTABLISHED: %s",
                 a.out);
    nf_free(&a);
    close(peer_fd);
    close(listen_fd);
}

/* ---------------------------------------------------------------------------
 * Case 4: a second claim on a name that is already ESTABLISHED
 * ---------------------------------------------------------------------------
 * A and B link normally, and then THIS TEST opens a third connection to A and
 * presents a well-formed FEDERATE claiming B's name with the CORRECT secret.
 * Everything about the line is right; the only thing wrong with it is that the
 * name is taken, and the node has to say so rather than admitting a second
 * route to a peer it can already reach.
 *
 * The claiming connection is a real socket speaking the real wire, not a call
 * into fed_check_federate(), because the thing being tested is what a NODE
 * does -- the accept path, the framing, the dispatch seam and the handshake
 * together. A unit call would pass whether or not any of those were wired up.
 *
 * The prefix of the claim is deliberately a THIRD name: 2.3's own note is that
 * the prefix is not the authority, and a line whose prefix agreed with the
 * claim would not exercise that. */
static void case_duplicate_link(void)
{
    nf_node_t a;
    nf_node_t b;
    test_client_t thief;
    char line[512];

    cfg_no_peer(SECRET_OK, 1000, 0);
    TF_CHECK_MSG(nf_spawn_inline_named(&a, "irc.a", child_setup) == 0,
                 "could not spawn node A");

    cfg_dials("irc.a", a.port, SECRET_OK, 1000, 0);
    TF_CHECK_MSG(nf_spawn_inline_named(&b, "irc.b", child_setup) == 0,
                 "could not spawn node B");

    /* The precondition, asserted before the case is worth anything: if the link
     * is not up, a DUPLICATE_LINK assertion below would be satisfied by a node
     * that rejects everything. */
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=irc.b", T_IO_MS) == 0,
                 "node A never established its link to node B");
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=irc.a", T_IO_MS) == 0,
                 "node B never established its link to node A");

    tc_init(&thief);
    TF_CHECK_MSG(tc_connect(&thief, a.port) == 0,
                 "the test could not open a third connection to node A");
    /* The version is IRC_SERVE_VERSION rather than a literal, so this line
     * cannot quietly stop being a valid FEDERATE if the version string moves.
     * The epoch is any legal 2.4 epoch; the node does not and cannot check it
     * against anything yet, because it learns the real one from a real peer. */
    (void)snprintf(line, sizeof line, ":irc.thief FEDERATE irc.b 1700000000 %s %s",
                   SECRET_OK, IRC_SERVE_VERSION);
    TF_CHECK_MSG(tc_send(&thief, line) == 0, "the test could not send FEDERATE");

    TF_CHECK_MSG(nf_expect(&a, "link_rejected: peer=irc.b reason=DUPLICATE_LINK",
                           T_IO_MS) == 0,
                 "node A admitted a second claim on a name it was already "
                 "ESTABLISHED to; the split-brain case 2.3 calls catastrophic");
    TF_CHECK_MSG(nf_expect_u64(&a, "fed_duplicate=", 1, T_IO_MS) == 0,
                 "the duplicate rejection should be counted separately from "
                 "the other rejection reasons");
    /* The node that answered must not still be routing to a second socket for
     * the same name, and the observable for that is the ESTABLISHED count in
     * the dump the rejection printed: 1, not 2. */
    TF_CHECK_MSG(nf_expect(&a, "established=1", T_IO_MS) == 0,
                 "node A does not report exactly one established link after a "
                 "duplicate claim: %s", a.out);
    /* And the claimer was closed rather than left hanging: 3.4 makes the close
     * the reaper's, and a rejected handshake that is not closed is a
     * descriptor this node is still reading from. */
    TF_CHECK_MSG(tc_expect_eof(&thief, T_IO_MS) == 0,
                 "node A did not close the rejected duplicate connection");
    tc_close(&thief);

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    /* The first link is still the only one, after everything. Read after the
     * stop so the buffer holds the whole story. */
    TF_CHECK_MSG(tf_count(a.out, "link_established: peer=irc.b") == 1,
                 "node A reported %lu establishments for irc.b, expected 1: a "
                 "duplicate claim must not create a second one",
                 (unsigned long)tf_count(a.out, "link_established: peer=irc.b"));
    nf_free(&a);
    nf_free(&b);
}

/* ---------------------------------------------------------------------------
 * Case 5: a handshake that is never answered
 * ---------------------------------------------------------------------------
 * A dials a listening socket THIS TEST owns and the test then says nothing. The
 * link is in HANDSHAKE_SENT, and T2 has to notice.
 *
 * The two things that make this a real test rather than a wait:
 *   - the timeout is 300 ms IN THE CHILD'S OWN PROCESS (see the header), so the
 *     case does not spend the shipped five seconds proving that five seconds
 *     pass;
 *   - the test READS the node's FEDERATE off the accepted socket first. Without
 *     that, "the node reported a handshake timeout" is satisfied by a node that
 *     never sent a handshake at all, which is a different bug with the same
 *     symptom.
 *
 * The peer here is a raw socket rather than a second node because the second
 * node would answer, and a peer that answers is the happy path (case 8). */
static void case_handshake_timeout(void)
{
    nf_node_t a;
    int listen_fd;
    int port = 0;
    int peer_fd;

    listen_fd = listen_loopback(&port);
    TF_CHECK_MSG(listen_fd >= 0, "the test could not open a listening socket");

    cfg_dials("irc.silent", port, SECRET_OK, 300, 0);
    TF_CHECK_MSG(nf_spawn_inline_named(&a, "irc.a", child_setup) == 0,
                 "could not spawn node A");

    peer_fd = accept_deadline(listen_fd, T_IO_MS);
    TF_CHECK_MSG(peer_fd >= 0, "node A never dialled the socket this test owns");

    /* The positive control, and a check of the wire FORMAT rather than of the
     * verb. Two needles, because the epoch sits between the fields this test can
     * name: it is whatever server_init() stamped this boot with, and a test
     * that asserted a literal epoch would be asserting a number no
     * implementation can predict. So the line is pinned on both sides of it --
     * the source prefix, the verb, and our own name before it; the shared
     * secret and this node's own version after it, with the RFC 1459 2.3
     * terminator on the end. */
    {
        const char *const needles[] = {
            ":irc.a FEDERATE irc.a ",
            " " SECRET_OK " " IRC_SERVE_VERSION "\r\n"
        };

        TF_CHECK_MSG(read_until(peer_fd, needles,
                                sizeof needles / sizeof needles[0], T_IO_MS) == 0,
                     "node A did not send a FEDERATE naming itself with the "
                     "configured secret and the current version string, so the "
                     "handshake this case times out never happened");
    }

    /* Silence from here: no reply, no close, nothing. The node has to decide on
     * its own that the exchange is dead. */
    TF_CHECK_MSG(nf_expect(&a, "link_timeout: peer=irc.silent state=TIMED_OUT",
                           T_IO_MS) == 0,
                 "node A did not time out a handshake that was never answered");
    TF_CHECK_MSG(nf_expect_u64(&a, "fed_hs_timeout=", 1, T_IO_MS) == 0,
                 "the handshake timeout should have been counted once");
    /* And it closed its half, which the peer observes. That is the reaper
     * doing its job after conn_mark_closing() and not the link module closing
     * anything itself -- the assertion is on the wire precisely so that it
     * cannot tell those two apart, because 3.4 says only one of them is
     * allowed and the test is not the place that decides which. */
    {
        fd_set rfds;
        struct timeval tv;
        char scratch[256];
        int rc;

        FD_ZERO(&rfds);
        FD_SET(peer_fd, &rfds);
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        rc = select(peer_fd + 1, &rfds, NULL, NULL, &tv);
        TF_CHECK_MSG(rc == 1, "node A did not close a timed-out handshake");
        if (rc == 1) {
            ssize_t got = read(peer_fd, scratch, sizeof scratch);

            TF_CHECK_MSG(got == 0, "the connection was reset rather than closed "
                                    "cleanly (read returned %ld)",
                         (long)got);
        }
    }
    /* The link's terminal state is in the dump, and it is TIMED_OUT rather than
     * INIT: a handshake that never completed is not reset, because resetting it
     * would make it indistinguishable from a link that has never been dialled
     * and would make the no-auto-redial latch invisible. */
    TF_CHECK_MSG(strstr(a.out, "state=TIMED_OUT") != NULL,
                 "node A's dump does not show the timed-out link: %s", a.out);

    close(peer_fd);
    close(listen_fd);
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    nf_free(&a);
}

/* ---------------------------------------------------------------------------
 * Case 6: the liveness SIGNAL, the positive half
 * ---------------------------------------------------------------------------
 * Two nodes, linked, with a 200 ms keepalive and a 600 ms dead threshold -- the
 * same three-to-one relationship IRC_FED_DEAD_MS spells, written out so the
 * test's numbers and the constant cannot drift apart silently. Both children run
 * with the trace ON, so every keepalive that arrives is an observable per-line
 * report and the assertion is on the node saying it RECEIVED a PING.
 *
 * This case exists because case 7 would otherwise also pass on a node whose
 * tick never sends anything: a node that never probes anything is a node that
 * eventually calls its peer dead, and asserting only the dead half would be
 * asserting a broken node works. */
static void case_keepalive_flows(void)
{
    nf_node_t a;
    nf_node_t b;

    /* A keepalive every 200 ms, so a bound of 3 framed lines is reached in
     * about 400 ms of an established link -- fast enough that the case is not
     * dominated by waiting, and the bound is set by the test rather than by the
     * shipped IRC_FED_KEEPALIVE_MS, which is 30 s. */
    cfg_no_peer(SECRET_OK, 1000, 1);
    g_cfg.keepalive_ms = 200;
    g_cfg.dead_ms = 600; /* 3 * keepalive: the relationship IRC_FED_DEAD_MS is */
    g_cfg.line_probe = 3;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, "irc.a", child_setup) == 0,
                 "could not spawn node A");

    cfg_dials("irc.a", a.port, SECRET_OK, 1000, 1);
    g_cfg.keepalive_ms = 200;
    g_cfg.dead_ms = 600;
    g_cfg.line_probe = 3;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, "irc.b", child_setup) == 0,
                 "could not spawn node B");

    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=irc.b", T_IO_MS) == 0,
                 "the two nodes did not establish a link");
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=irc.a", T_IO_MS) == 0,
                 "the dialling node did not establish its link");

    /* The keepalive actually goes out and actually arrives. Both directions
     * matter: A receiving B's PING is what keeps A's link alive, and B
     * receiving A's PING is what keeps B's, so a one-sided T3 would show up as
     * one of these two assertions failing. */
    TF_CHECK_MSG(nf_expect(&a, "command=PING", T_IO_MS) == 0,
                 "node A never received a keepalive from its peer, so the "
                 "liveness signal case 7 depends on is not flowing");
    TF_CHECK_MSG(nf_expect(&b, "command=PING", T_IO_MS) == 0,
                 "node B never received a keepalive from its peer");
    /* The line count has to KEEP CLIMBING, which is the part case 7 removes.
     * Read while the node is still running, off the child's own tick, because a
     * count that only appears at shutdown cannot distinguish "the keepalives
     * flowed" from "the keepalives had not started yet". */
    TF_CHECK_MSG(nf_expect_u64_ge(&a, "framed=", 3, T_IO_MS) == 0,
                 "node A framed fewer than three lines, so its peer's "
                 "keepalives are not arriving over the link");
    TF_CHECK_MSG(nf_expect_u64_ge(&b, "framed=", 3, T_IO_MS) == 0,
                 "node B framed fewer than three lines");
    /* And neither called the other dead, which is the pair's real state: a link
     * with keepalives flowing is a link that stays up. */
    TF_CHECK_MSG(nf_expect_u64(&a, "fed_dead=", 0, 1000) == 0,
                 "node A declared a link dead while its peer was sending "
                 "keepalives every 200 ms");
    TF_CHECK_MSG(nf_expect_u64(&b, "fed_dead=", 0, 1000) == 0,
                 "node B declared a link dead while its peer was sending "
                 "keepalives every 200 ms");

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    /* lines= is a LOWER BOUND and never an equality: the peer's keepalives are
     * inbound lines and the number climbs on its own. See the header. This is
     * the shipped key, read from the final stats line. */
    TF_CHECK_MSG(nf_expect_u64_ge(&a, "lines=", 3, T_IO_MS) == 0,
                 "node A's final line count should be at least its own FEDERATE "
                 "plus two keepalives from its peer, and the assertion is a "
                 "lower bound because a linked node's count climbs by itself");
    /* The link was still up when the node stopped, which is the state the dump
     * reports at shutdown and which the case above depends on. */
    TF_CHECK_MSG(nf_expect(&a, "peer=irc.b state=ESTABLISHED", T_IO_MS) == 0,
                 "node A's shutdown dump does not show an ESTABLISHED link to "
                 "its peer: %s", a.out);

    nf_free(&a);
    nf_free(&b);
}

/* ---------------------------------------------------------------------------
 * Case 7: a link that goes SILENT, the negative half
 * ---------------------------------------------------------------------------
 * The same pair, and then the ACCEPTING node is frozen. Two things about that
 * choice, and the first is the reason for the second:
 *
 *   - SIGSTOP rather than a kill. A killed peer sends a FIN, the survivor sees
 *     the EOF, closes through the reaper, and reports a CLOSED CONNECTION --
 *     a different event, which would satisfy no assertion here. SIGSTOP leaves
 *     the socket open and unanswered, and an open-and-silent socket is the only
 *     way this test can produce a link that is ESTABLISHED and silent, which is
 *     the only condition T4 exists to notice.
 *   - It has to be the ACCEPTOR that is frozen, because the node left running
 *     has to be the one whose link returns to INIT, and only a link this node
 *     DIalled is one T7 would redial. Watching the acceptor instead would prove
 *     nothing about re-dialing, because a link it accepted has no address and
 *     was never a candidate for a dial.
 *
 * 3.4's "a saturated link is dropped, not buffered" is what makes the freeze
 * survivable: the survivor keeps queueing 200 ms keepalives into a peer that has
 * stopped reading, and the kernel socket buffer holds them without the writer
 * ever blocking.
 */
static void case_dead_link(void)
{
    nf_node_t a;
    nf_node_t b;

    cfg_no_peer(SECRET_OK, 1000, 1);
    g_cfg.keepalive_ms = 200;
    g_cfg.dead_ms = 600;
    g_cfg.line_probe = 2;
    TF_CHECK_MSG(nf_spawn_inline_named(&a, "irc.a", child_setup) == 0,
                 "could not spawn node A");

    cfg_dials("irc.a", a.port, SECRET_OK, 1000, 1);
    g_cfg.keepalive_ms = 200;
    g_cfg.dead_ms = 600;
    g_cfg.line_probe = 2;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, "irc.b", child_setup) == 0,
                 "could not spawn node B");

    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=irc.b", T_IO_MS) == 0,
                 "the two nodes did not establish a link");
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=irc.a", T_IO_MS) == 0,
                 "the dialling node did not establish its link");
    /* Positive control, the same one case 6 asserts: the link was ALIVE before
     * it was killed, so a link_dead afterwards is about the freeze and not
     * about a link that never came up. */
    TF_CHECK_MSG(nf_expect(&b, "command=PING", T_IO_MS) == 0,
                 "the dialling node never received a keepalive from its peer, "
                 "so the link was not demonstrably alive before the freeze");
    TF_CHECK_MSG(nf_expect_u64(&b, "fed_dead=", 0, 1000) == 0,
                 "the dialling node declared the link dead before the freeze");

    TF_CHECK_MSG(kill(a.pid, SIGSTOP) == 0, "could not freeze node A");
    /* From here node A does nothing at all -- it does not read, does not write
     * and does not answer -- which is the condition T4 has to notice. The wait
     * is a deadline on B's own output and not a sleep: 600 ms of silence is
     * twelve 50 ms ticks, and the parent waits for the line rather than
     * assuming a duration. */
    TF_CHECK_MSG(nf_expect(&b, "link_dead: peer=irc.a silent_ms=", T_IO_MS) == 0,
                 "the dialling node did not notice that its peer had gone "
                 "silent, so a link whose peer is frozen stays up forever");
    TF_CHECK_MSG(nf_expect_u64(&b, "fed_dead=", 1, T_IO_MS) == 0,
                 "the dead link should have been counted once");
    /* The link went back to INIT rather than to FAILED, because it was an
     * ESTABLISHED link that died and a node has to stop believing in it. The
     * observable is the dump the dead path prints, and INIT is the state a
     * later reconnect would start from. */
    TF_CHECK_MSG(nf_expect(&b, "why=link_down", T_IO_MS) == 0,
                 "the dialling node did not report taking the dead link down: "
                 "%s", b.out);
    /* And it did NOT redial. C2 deliberately never dials a link twice (2.3's
     * reconnect handling is Phase 9's, and the latch is fed_link_reset's to
     * clear), so the whole life of this node is one dial. This is the assertion
     * that catches a T7 which re-dials on every tick against a frozen peer: the
     * link is in INIT with an address, which is exactly the state that would
     * attract one. */
    TF_CHECK_MSG(tf_count(b.out, "link_dial: peer=irc.a") == 1,
                 "the dialling node dialled its peer %lu times; C2 must dial a "
                 "link exactly once and auto-redial is Phase 9's",
                 (unsigned long)tf_count(b.out, "link_dial: peer=irc.a"));
    /* The link's own state after the dead path, read from the dump: INIT with
     * the address still attached and the initiator flag kept, which is what a
     * Phase 9 reconnect would start from. Waited for rather than grepped,
     * because the dump is printed after the link_dead line this test waited
     * for and the pump stops at the needle. */
    TF_CHECK_MSG(nf_expect(&b, "peer=irc.a state=INIT fd=-1 initiator=1", T_IO_MS)
                     == 0,
                 "the dead link is not back in INIT with no descriptor and its "
                 "initiator flag kept: %s", b.out);

    (void)kill(a.pid, SIGCONT);
    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    nf_free(&a);
    nf_free(&b);
}

/* ---------------------------------------------------------------------------
 * Case 8: the happy path, on the SHIPPED BINARY
 * ---------------------------------------------------------------------------
 * Two `irc-serve` processes, configured entirely on the COMMAND LINE, with node
 * B dialling node A. This is the only case that runs the real executable, and
 * that is what it is for: it is the only thing that can fail if node_main.c's
 * --name/--secret/--peer parsing breaks, if the --peer address is assembled
 * wrongly, or if the getaddrinfo in main() returns something other than the
 * address the operator named. An inline child configures its own link from a
 * struct sockaddr it built by hand, so it exercises none of that.
 *
 * 3.4's rule is asserted here by construction rather than by inspection: the
 * node is handed "irc.a,127.0.0.1,<port>" on the command line, so the address
 * was resolved before the loop was armed or the test could not run at all.
 *
 * Node A is started FIRST and with no --peer, so B's --peer can name A's port.
 * That ordering is also the one the design asks for: configure each pair in ONE
 * direction (see link.h's limitation note), which is why A is not given B as a
 * peer and B is. */
static void case_happy_path_binary(void)
{
    nf_node_t a;
    nf_node_t b;
    char peer_arg[64];

    {
        char *const argv[] = { (char *)"irc-serve", (char *)"--name",
                               (char *)"irc.a",   (char *)"--secret",
                               SECRET_OK,         (char *)"0",
                               NULL };

        TF_CHECK_MSG(nf_spawn_binary_argv(&a, argv) == 0,
                     "could not start node A from the shipped binary");
    }
    /* --name took effect. Asserted separately from the link because a node with
     * the wrong name would produce a different SELF_NAME story rather than a
     * missing link, and reading it here says which it is. */
    TF_CHECK_MSG(nf_expect(&a, "server initialized: name=irc.a", T_IO_MS) == 0,
                 "node A did not report the name it was given: %s", a.out);
    TF_CHECK_MSG(nf_expect(&a, "peers=0 secret=set", T_IO_MS) == 0,
                 "node A should have started with no peers and a configured "
                 "secret");

    (void)snprintf(peer_arg, sizeof peer_arg, "irc.a,127.0.0.1,%d", a.port);
    {
        char *const argv[] = { (char *)"irc-serve", (char *)"--name",
                               (char *)"irc.b",   (char *)"--secret",
                               SECRET_OK,         (char *)"--peer",
                               peer_arg,          (char *)"0",
                               NULL };

        TF_CHECK_MSG(nf_spawn_binary_argv(&b, argv) == 0,
                     "could not start node B from the shipped binary with a "
                     "--peer of %s", peer_arg);
    }
    TF_CHECK_MSG(nf_expect(&b, "peers=1 secret=set", T_IO_MS) == 0,
                 "node B did not report the peer it was configured with: %s",
                 b.out);

    /* The exchange, from both ends. Neither of these can be satisfied by a
     * node that merely accepted the connection: link_established is printed
     * only after the FSM has reached ESTABLISHED, which on each side means the
     * other's claim was checked and accepted. */
    TF_CHECK_MSG(nf_expect(&a, "link_established: peer=irc.b", T_IO_MS) == 0,
                 "the accepting node never reported an established link: %s",
                 a.out);
    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=irc.a", T_IO_MS) == 0,
                 "the dialling node never reported an established link: %s",
                 b.out);
    /* Neither rejected anything: a rejection and an establishment cannot both
     * have happened, and this is what rules out the second having been faked.
     * Asserted on the ABSENCE of the line rather than on the counter, because
     * the shipped binary publishes its counters once -- in loop_stats, at
     * shutdown -- and a counter this node has not printed yet cannot be read.
     * And it is read after the stops below, where the buffer is whole. The
     * counters themselves are asserted there too. */
    /* Each node dialled exactly the links it was told to, and no more. */
    TF_CHECK_MSG(nf_expect(&b, "link_dial: peer=irc.a", T_IO_MS) == 0,
                 "the dialling node never reported dialling its peer: %s", b.out);
    /* Each node knows the PEER's epoch, which is not its own and is not
     * derivable from it: 4.3's burst carries the origin's epoch, so a link
     * that reached ESTABLISHED without one could not be burst. */
    TF_CHECK_MSG(nf_expect(&a, "link: peer=irc.b state=ESTABLISHED", T_IO_MS) == 0,
                 "node A's dump does not show the link as ESTABLISHED: %s",
                 a.out);

    TF_CHECK_MSG(nf_stop(&a) == 0, "node A did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node B did not exit cleanly");
    /* Now the counters exist, in the shutdown stats line, and the buffers are
     * whole. */
    TF_CHECK_MSG(nf_expect_u64(&a, "fed_rejected=", 0, 1000) == 0,
                 "the accepting node counted a rejection");
    TF_CHECK_MSG(nf_expect_u64(&b, "fed_rejected=", 0, 1000) == 0,
                 "the dialling node counted a rejection");
    TF_CHECK_MSG(strstr(a.out, "link_rejected:") == NULL,
                 "the accepting node reported a rejection and an establishment "
                 "for the same exchange: %s", a.out);
    TF_CHECK_MSG(strstr(b.out, "link_rejected:") == NULL,
                 "the dialling node reported a rejection and an establishment "
                 "for the same exchange: %s", b.out);
    TF_CHECK_MSG(tf_count(b.out, "link_dial: peer=irc.a") == 1,
                 "node B should have dialled its one configured peer exactly "
                 "once, and dialled it %lu times",
                 (unsigned long)tf_count(b.out, "link_dial: peer=irc.a"));
    TF_CHECK_MSG(tf_count(a.out, "link_dial:") == 0,
                 "node A was configured with no peers and must not have dialled "
                 "anything: %s", a.out);
    nf_free(&a);
    nf_free(&b);
}

/* ---------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------------
 * The cases run in the order they are listed in the header, and the ordering is
 * not arbitrary: the cheap rejections come first so that a failure in the
 * handshake's VERDICTS is reported before a failure in the timing, which is
 * the harder half to read. The last case is the shipped binary, because it is
 * the one that proves the wiring above it is real.
 */
int main(void)
{
    case_self_name();
    case_bad_secret();
    case_no_secret_refused();
    case_name_mismatch();
    case_duplicate_link();
    case_handshake_timeout();
    case_keepalive_flows();
    case_dead_link();
    case_happy_path_binary();
    tf_done("fed_handshake");
    return 0;
}

