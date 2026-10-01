/* test_autoscale.c -- 2.3's auto-scale, as far as an IRC NODE can honestly go.
 *
 * docs/SERVER_DESIGN.md 2.3 ("Peer discovery and auto-scale stay Phase 9"), 8 and
 * the Phase 9 item this test is the acceptance for. It replaces a ten-line
 * placeholder in tests/loadbal/ that returned 77 and said "auto-scaling
 * (spawn/shutdown/propagation) is not implemented". The CTest name is unchanged
 * (`AutoScale`) -- see irc_ctest_name() in tests/integration/CMakeLists.txt for why
 * a moved test must not be renamed, and tests/known_skips.txt for the ratchet that
 * enforces it.
 *
 * ---------------------------------------------------------------------------
 * WHAT "AUTO-SCALE" MEANS HERE, AND WHY IT IS NOT NODE LIFECYCLE
 * ---------------------------------------------------------------------------
 * 2.3 names "peer discovery and auto-scale" in one sentence and the name covers two
 * unrelated things. THIS FILE TAKES THE ONE THAT IS THIS CODEBASE'S BUSINESS, and
 * says plainly which one it is not, because the placeholder's reason for existing
 * ("honest CTest skip rather than fabricated node lifecycle / 'RSS' claims") is a
 * statement about a boundary rather than about missing work:
 *
 *   A NODE DOES NOT SPAWN OR STOP NODES. That is a supervisor's job -- systemd, an
 *   orchestrator, a k8s replica controller -- and it is outside what this program
 *   is: a node that cannot measure its own load (`load_pct` is an OPERATOR KNOB, not
 *   a metric; see server.h) has nothing honest to decide a spawn on. A node that
 *   spawned another node on a fabricated "RSS" number would be a node inventing the
 *   input to its own decision, and the cost of getting that wrong is a fork bomb on
 *   a mesh. So there is no node_spawned(), no get_connection_load(), and no
 *   node_shutdown() here, and this test asserts nothing about any of them.
 *
 *   WHAT IS THIS NODE'S BUSINESS, AND IS BOTH HALVES OF IT:
 *     1. GRACEFUL LEAVE. A node that is going away SAYS SO on the wire before it
 *        goes, and its peers treat the departure as terminal rather than as a
 *        failure: no retry budget, no redials, and the roster purged. This half was
 *        implemented in bee5ca5 and was REACHABLE ONLY FROM A TEST, because
 *        fed_send_shutdown() had no caller in src/ at all. It has one now, in
 *        server_shutdown(), and case 1 below is what makes that true rather than
 *        claimed.
 *
 *        Making it reachable turned up TWO DEFECTS that had to be fixed for the
 *        goodbye to survive its own journey, both in core/poll_loop.c and both
 *        documented at the site: a node that writes its last line and closes in the
 *        same breath had that line DISCARDED, because conn_fill() reports the end of
 *        the stream while its buffer is non-empty and the EOF arm returned without
 *        framing what it had already read. "Send the line, then go" IS the graceful
 *        leave, so the loop was eating the one sequence this feature exists for. A
 *        departing node also had to start DRAINING each peer socket before closing,
 *        because a close() with unread data in the receive queue makes the kernel send
 *        RST instead of FIN, and an RST discards the goodbye that was in flight --
 *        measured at roughly one departure in twenty-five. Neither was visible from
 *        the feature's own code, and case 3 below exists because case 1 is robust to
 *        both by construction.
 *     2. PROPAGATION. A peer publishes how loaded it is, and this node OBSERVES the
 *        figure and reports a peer that crosses a threshold the operator set. It
 *        does not move anything, and the test asserts that it does not.
 *
 * The line a test could not previously draw -- "a node announces its own departure,
 * and a real node's departure is handled" -- is the line this file draws. Every node
 * in it is a real forked server_t running the real poll loop; none of the payloads
 * are written by this test, because unlike PeerDiscovery (which had to hand-write a
 * SHUTDOWN because no node could originate one) every line under test here is
 * produced by fed_send_shutdown() and fed_send_advertise() in the departing node.
 *
 * ---------------------------------------------------------------------------
 * FOUR CLAIMS, AND WHERE EACH IS ASSERTED
 * ---------------------------------------------------------------------------
 *   1. A REAL NODE'S GRACEFUL LEAVE IS ORIGINATED AND RECEIVED (case 1). The wire
 *      half: ` SHUTDOWN\r\n` read off the departing node's own socket by the peer it
 *      dialled, which is the only place a "the node said it" claim can be checked
 *      without asking the node whether it said it. The receipt half: the surviving
 *      node's own `link_clean_leave:` and
 *      `fed_shutdown: ... clean_leave=1 retried=0`, and the relay a node TWO HOPS away
 *      sees.
 *   2. A CLEAN LEAVE ARMS NO RETRY, AND THIS IS THE HALF WITH TEETH (case 1).
 *      Asserted on COUNTS OF SOCKETS AND SCHEDULES, never on the log's own claim:
 *      exactly one `link_dial:` to the departed peer for the life of the node, and
 *      exactly one `link_retry:` -- the second is the more interesting half, because
 *      "one arm" is what makes the zero redials a DECISION rather than an inert link.
 *   3. THE LOAD FIGURE PROPAGATES, AND CROSSING A THRESHOLD IS REPORTED WITHOUT
 *      ANYTHING BEING MOVED (cases 1, 2 and 3's node).
 *      `fed_advertise: peer=... load=N%` on the receiver is the inbound half and
 *      ` ADVERTISE 42` read off a socket is the outbound one; `fed_shed: ...
 *      action=REPORT_ONLY` is the reaction, asserted ONCE where the latch says once
 *      and NEVER on a node with no threshold, which is the shipped configuration; and
 *      the absence assertions at the end of case 2 are the "and nothing else
 *      happened" half, which is what makes this a propagation feature rather than a
 *      rebalancing one.
 *   4. A PEER'S LAST LINE SURVIVES ITS OWN DEPARTURE (case 3). A complete line sent
 *      immediately before closing, with nothing read in between, must still be
 *      FRAMED and applied. This is a claim about the loop rather than about a
 *      graceful leave, and it has its own case because case 1 cannot reach it: the
 *      shipped departure path DRAINS each peer socket before closing (so the close is
 *      a FIN, not an RST), which means case 1 is robust to the very defect case 3 is
 *      about. The teeth run is what established that -- with case 3 absent, removing
 *      the framing fix from the loop left every assertion in this file passing.
 *
 * ---------------------------------------------------------------------------
 * NO FIXED sleep() ANYWHERE (6.3)
 * ---------------------------------------------------------------------------
 * Every wait is a deadline: nf_expect()/nf_expect_u64_ge() over a child's output,
 * or poll() with a deadline over this test's own socket. That is not only the style
 * rule here -- claim 2 is an ABSENCE, and an absence needs a window measured on the
 * node's own clock rather than on how fast this test can issue commands. The
 * arithmetic for both windows is stated where the numbers are set.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS SHORTENED, AND WHY THE SHORTENED TEST IS STILL A REAL TEST
 * ---------------------------------------------------------------------------
 * Three numbers, all per-process overrides that exist for exactly this purpose
 * (fed_set_timeouts(), fed_set_retry(), fed_set_advertise_interval(), each of which
 * is a function rather than a rule edit), and nothing else:
 *
 *   DEAD_MS / RETRY_BASE_MS / RETRY_MAX_MS  the shipped ladder starts at
 *       IRC_FED_DEAD_MS (90 s), so a case that waited out even the first rung would
 *       take minutes. What the test preserves is the ladder's SHAPE -- base x 2 per
 *       attempt, capped, bounded by a budget of 3 -- and the single T7 condition
 *       that refuses a diallable link. That condition is the claim; the scale is
 *       not. Stated as a cost, because a test that sets a 60 ms base proves the
 *       policy's shape and says nothing about how 90 s behaves in a field.
 *   ADVERTISE_MS  the shipped advertisement interval is derived equal to the
 *       keepalive (30 s), and the test needs a second advertisement inside its own
 *       deadline so it can watch a figure CHANGE and see the edge latch work. The
 *       interval is a knob for that reason (link.h says so), and the refresh being
 *       on a clock at all is what the test checks.
 *   KEEPALIVE_MS on the two nodes that are only there to be clocks, so the absence
 *       windows are hundreds of milliseconds rather than tens of seconds.
 *
 * NOT SHORTENED, and these are the claims: the ORDER of the guard chain, the shape
 * of the ADVERTISE verb, the latch semantics of the shed report (once per crossing,
 * not once per tick), the single T7 condition, and the requirement that the leave
 * reaches the wire BEFORE the socket closes.
 */
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/message.h"
#include "core/server.h"
#include "federation/link.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define SECRET "irc-serve-autoscale-secret"
#define NAME_LEAVE "irc.depart" /* announces its own departure, on SIGTERM     */
#define NAME_STAY  "irc.stay"   /* its peer: receives it, and must not redial   */
#define NAME_THIRD "irc.third"  /* dials " NAME_STAY ": receives the departure, and
                                 * must not redial                              */
/* The node TWO HOPS from the departure. " NAME_THIRD " relays the departure onward
 * to it, which is what makes the departure a mesh event rather than a local one, and
 * it exists only for that: nothing is asserted about it except that the SQUIT
 * arrived. */
#define NAME_FOURTH "irc.fourth"
/* The name this TEST's socket claims. It is a peer of the departing node and
 * nothing else: it is the one end of a link whose bytes can be read directly,
 * which is what makes the goodbye a WIRE claim rather than a log one. */
#define NAME_PROBE "irc.probe"

/* The figures. INBOUND is what the surviving node is told and is the real claim: a
 * peer publishes a percentage and this node reports it back on its own
 * `fed_advertise:` line. OUTBOUND is what the departing node publishes about
 * itself, read off this test's own socket, which is why fed_set_load() being DEFINED
 * matters here: the departing node is configured with a figure in its own
 * child_setup, so the number on the wire is one an operator chose rather than the
 * zero server_init() left behind. (test_peer_discovery.c had to assert 0% for the
 * outbound direction for exactly the opposite reason and says so there; that file's
 * comment is now stale on this point and is not this pass's file to edit.) */
#define LOAD_PUB_TEXT "42"
#define LOAD_PUB_PCT  42u
/* THE FIGURE IN TWO SPELLINGS, and the pair exists because this file uses the same
 * number in two different ROLES and confusing them produces a test that times out
 * against a node that is behaving perfectly.
 *
 *   LOAD_PUB_FMT  "42%"   a NEEDLE. What the node PRINTS: a single percent sign.
 *   LOAD_PUB_ESC  "42%%"  a printf FORMAT argument. Two, because a lone `%` in a
 *                        format string is a conversion specifier and `% t` is not one
 *                        -- so `nf_expect(watcher, "load=42% threshold=30% ...")`
 *                        compiles, runs, and waits for ever for a string that no
 *                        output line can ever equal.
 *
 * It cost this file one 15-second timeout and one "did not report it as shedding"
 * message against a node whose log had the exact right line in it three times over.
 * The bug is invisible in the source because the needle LOOKS right -- it is what the
 * node prints, character for character -- and it is only wrong because of which
 * argument of TF_CHECK_MSG it landed in. Hence two names, and the doubled spelling
 * spelled out rather than left to be inferred. */
#define LOAD_PUB_FMT  "42%"
#define LOAD_PUB_ESC  "42%%"

/* THE SHED THRESHOLD, and it is set BELOW LOAD_PUB_PCT so the crossing is reachable
 * with the figure this test publishes. 30 rather than 50 or 80 because the value
 * carries no meaning: it is an operator's threshold and the test is an operator. The
 * shipped value is 0 (no opinion) -- see link.h's fed_set_shed_pct(). */
#define SHED_PCT     30u
#define SHED_PCT_FMT "30%"  /* the NEEDLE spelling; see LOAD_PUB_FMT above */
#define SHED_PCT_ESC "30%%" /* the printf-FORMAT spelling; see LOAD_PUB_ESC above */

/* The clean-leave case's ladder, and the four numbers are ONE calculation rather
 * than four choices. The shipped base is IRC_FED_DEAD_MS (90 s); 60 ms with a 240 ms
 * ceiling keeps the ladder's SHAPE (base x 2^attempt, capped, budget 3) and changes
 * only its scale.
 *
 * WITH the dead threshold at DEAD_MS, an UNSUPPRESSED clean leave would be re-dialled
 * at
 *
 *      150 +  60 = 210 ms     first rung
 *      210 + 120 = 330 ms     second
 *      330 + 240 = 570 ms     third, at the ceiling
 *
 * and the observation window is " WINDOW_LINES " inbound lines at KEEPALIVE_MS, which is
 * " WINDOW_MS ". That is past EVERY rung above by a wide margin, so an unsuppressed
 * leave would have dialled three times inside a window in which the assertion requires
 * none. The margin is not decoration: a window that closes before the fault's first
 * dial is a window that cannot catch it, and that is exactly the failure mode an
 * earlier set of these numbers had.
 *
 * The boundary is INBOUND LINES ON THE NODE UNDER TEST -- the fourth node's keepalive
 * PINGs, which arrive as inbound lines and move `lines=` on a real timer. Two things
 * about that choice, both of them learned elsewhere in this phase:
 *
 *   it is the fourth node's clock rather than this test's, so the window measures the
 *   node running with a departed peer in the state under test rather than how fast
 *   this test can issue commands;
 *   and it is NOT measured on `link_dial:` or on `accepted=`, which are the very
 *   things under assertion -- a boundary satisfied BY the fault stops before the
 *   fault fires. That is the trap the SSRF case in test_peer_discovery.c records
 *   having caught its injected fault in 4 runs out of 8 before its boundary was moved
 *   onto inbound traffic, where it caught it in 8 out of 8. */
#define RETRY_BASE_MS 60
#define RETRY_MAX_MS  240
#define DEAD_MS 150
#define KEEPALIVE_MS 60
#define WINDOW_LINES 16
#define WINDOW_MS (WINDOW_LINES * KEEPALIVE_MS)

/* HOW OFTEN THE DEPARTING NODE SPEAKS, and the reason this is a separate number from
 * KEEPALIVE_MS is that the two roles are opposite and confusing them breaks the
 * fixture in a way that looks like a product bug.
 *
 *   KEEPALIVE_MS  the CLOCK nodes (" NAME_THIRD " and " NAME_FOURTH "). Their PINGs are
 *                 what open the observation window, and nothing depends on them being
 *                 answered -- a peer link does not answer PINGs at all in this build,
 *                 which is why n_fed_unknown_verb counts them on the far side.
 *   SPEAK_MS      the DEPARTING node's own cadence, and it is a FIXTURE CONSTRAINT
 *                 rather than a choice: the node that receives the departure has a
 *                 150 ms dead threshold (scaled so T4 arms the ladder, which is what
 *                 makes "no retry" a decision rather than an accident), so the peer it
 *                 is watching has to speak well inside 150 ms or the receiver declares
 *                 it dead before the case ever sends SIGTERM. 50 against 150 is the
 *                 same three-to-one shape the shipped 30 s keepalive has to the
 *                 shipped 90 s dead threshold. */
#define SPEAK_MS 50

/* THE SHED LATCH'S WINDOW: how many advertisements must reach the observer before the
 * report count is read.
 *
 * It is a COUNT OF INBOUND LINES rather than a wait, for the reason this file states
 * everywhere else: a fixed sleep would be measuring this test's clock, and a count of
 * lines the OBSERVER received is measuring the observer's. Three rather than two
 * because two is the number the first assertion has already satisfied.
 *
 * The teeth run is what found this number necessary. With no window at all the count
 * was taken inside the same tick that printed the first report, so an implementation
 * that reported on EVERY tick passed -- the assertion had no window in which the
 * difference between "once per crossing" and "once per tick" could exist. */
#define EDGE_LINES 3
#define ADVERTISE_COUNT_STR "3"

/* The advertisement interval, so a figure can be seen to CHANGE inside the test's
 * own deadline. The shipped value is 30 s (derived equal to the keepalive), and the
 * refresh being on a clock at all is the property under test. */
#define ADVERTISE_MS 150

/* ---------------------------------------------------------------------------
 * The child
 * ---------------------------------------------------------------------------
 * One setup for every node in the file, driven by a global the parent fills in
 * before each spawn.
 */
typedef struct {
    const char *name; /* NULL: no peer at this slot */
    int         port;
} peer_cfg_t;

typedef struct {
    peer_cfg_t peers[2];
    uint64_t   dial_ms;
    uint64_t   hs_ms;
    uint64_t   keepalive_ms;
    uint64_t   dead_ms;
    uint64_t   retry_base_ms;
    uint64_t   retry_max_ms;
    unsigned   retry_budget;
    /* The two knobs the claims are about, and both are set HERE rather than poked
     * from the parent because neither has a wire equivalent: this test cannot reach
     * into a child process's server_t, and the alternative -- asserting on a figure
     * the child chose for itself -- would be asserting on the fixture. */
    int      publish_load; /* fed_set_load(s, LOAD_PUB_PCT) */
    int      shed_pct;     /* fed_set_shed_pct(s, ...) */
} child_cfg_t;

static child_cfg_t g_cfg;

static void child_setup(server_t *s)
{
    /* The client command surface, installed BEFORE fed_open(): fed_open() saves
     * whatever dispatch is there and installs its own over it, so a
     * commands_dispatch installed afterwards would become the node's whole dispatch
     * and the peer path would never be reached. */
    s->dispatch = commands_dispatch;

    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child; a node with an unopenable "
                 "federation module cannot reach any assertion in this test");
    s->on_tick = fed_tick;

    /* A 0 argument keeps the built-in, so this is safe to call unconditionally. */
    fed_set_timeouts(g_cfg.dial_ms, g_cfg.hs_ms, g_cfg.keepalive_ms, g_cfg.dead_ms);
    if (g_cfg.retry_base_ms != 0u) {
        fed_set_retry(g_cfg.retry_base_ms, g_cfg.retry_max_ms, g_cfg.retry_budget);
    }
    /* THIS NODE'S OWN LOAD FIGURE, and it is a KNOB rather than a measurement --
     * see fed_set_load()'s comment, which is the reason this whole feature cannot
     * be a load balancer. What the test does with it is put a chosen figure on the
     * wire and read it back off a real socket. */
    if (g_cfg.publish_load != 0) {
        fed_set_load(s, LOAD_PUB_PCT);
    }
    /* ...AND THE THRESHOLD AT WHICH A PEER IS REPORTED AS SHEDDING. Set on the
     * SURVIVING node only, and that asymmetry is the point of the fixture: the node
     * that publishes a busy figure is not the node that reacts to one. */
    if (g_cfg.shed_pct != 0) {
        fed_set_shed_pct(s, (unsigned)g_cfg.shed_pct);
    }
    /* Set in EVERY child, not just the publishing one, so the second advertisement
     * (the one that CHANGES the figure and exercises the edge latch) is inside this
     * test's deadline. See the file header's "what is shortened". */
    fed_set_advertise_interval(ADVERTISE_MS);
    for (size_t i = 0; i < sizeof g_cfg.peers / sizeof g_cfg.peers[0]; i++) {
        struct sockaddr_in sa;

        if (g_cfg.peers[i].name == NULL) {
            continue;
        }
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = htons((unsigned short)g_cfg.peers[i].port);
        TF_CHECK_MSG(fed_link_configure(s, g_cfg.peers[i].name,
                                        (const struct sockaddr *)&sa,
                                        (socklen_t)sizeof sa) != NULL,
                     "the child could not configure peer %s on port %d",
                     g_cfg.peers[i].name, g_cfg.peers[i].port);
    }
}

/* ---------------------------------------------------------------------------
 * This test's end of a peer link
 * ---------------------------------------------------------------------------
 * A buffer that PERSISTS across calls: one call consumes the bytes it read and the
 * next has to see the ones after them without seeing the ones before.
 */
typedef struct {
    int    fd;
    char   seen[16384];
    size_t used;
} peer_t;

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

    for (;;) {
        struct pollfd pfd;
        uint64_t left = (deadline > now_ms()) ? deadline - now_ms() : 0;
        int rc;

        pfd.fd = listen_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        rc = poll(&pfd, 1, (int)left);
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

static int send_line(int fd, const char *line)
{
    size_t n = strlen(line);
    size_t off = 0;

    while (off < n) {
        ssize_t got = write(fd, line + off, n - off);

        if (got <= 0) {
            if (got < 0 && errno == EINTR) {
                continue;
            }
            return -1;
        }
        off += (size_t)got;
    }
    return 0;
}

/* Read whatever has arrived, up to the deadline. Returns 0 if it read anything, -1
 * on a closed socket, and 1 if the deadline passed with nothing new. */
static int peer_fill(peer_t *p, int timeout_ms)
{
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;

    for (;;) {
        struct pollfd pfd;
        uint64_t left = (deadline > now_ms()) ? deadline - now_ms() : 0;
        ssize_t got;
        size_t room;
        int rc;

        pfd.fd = p->fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        rc = poll(&pfd, 1, (int)left);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (rc == 0) {
            return 1;
        }
        room = sizeof p->seen - 1u - p->used;
        if (room == 0u) {
            return 1;
        }
        got = read(p->fd, p->seen + p->used, room);
        if (got == 0) {
            return -1;
        }
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        p->used += (size_t)got;
        p->seen[p->used] = '\0';
        return 0;
    }
}

/* How many times `needle` has arrived, counted non-overlapping. */
static size_t peer_count(const peer_t *p, const char *needle)
{
    size_t nlen = strlen(needle);
    size_t seen = 0u;

    for (const char *at = p->seen; (at = strstr(at, needle)) != NULL; at += nlen) {
        seen++;
    }
    return seen;
}

/* Read until `needle` has arrived at least `want` TIMES, or the deadline passes.
 *
 * THE COUNT IS THE CLAIM, and this file needs it for the liveness witness below
 * rather than for an absence: the departing node publishes its figure once on
 * ESTABLISHMENT and then on the advertisement interval, so a SECOND one is proof
 * that the node is treating this link as a live route and is driving traffic on it
 * over time. A single advertisement would be satisfied by a link that went dead the
 * instant it was established. */
static int peer_expect_n(peer_t *p, const char *needle, size_t want, int timeout_ms)
{
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;

    for (;;) {
        int rc;

        if (peer_count(p, needle) >= want) {
            return 0;
        }
        rc = peer_fill(p, timeout_ms);
        if (rc < 0) {
            return (peer_count(p, needle) >= want) ? 0 : -1;
        }
        if (now_ms() >= deadline) {
            return -1;
        }
        timeout_ms = 1;
    }
}

/* Read until `needle` has arrived, or the deadline passes.
 *
 * THE BUFFER IS SEARCHED BEFORE THE SOCKET IS READ, and that ordering is load-bearing
 * for THIS FILE specifically. A departing node says goodbye and then closes, so the
 * last line it ever sends is exactly the one a fill-first loop would miss: the peer
 * reports POLLIN|POLLHUP, read() answers 0, and a fill-first loop returns "closed"
 * without looking at the bytes already in hand. The same argument is why
 * harness/node_fixture.h's nf_expect() searches the accumulated buffer: what has
 * arrived is a fact and a later event does not un-arrive it. */
static int peer_expect(peer_t *p, const char *needle, int timeout_ms)
{
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;

    for (;;) {
        int rc;

        if (strstr(p->seen, needle) != NULL) {
            return 0;
        }
        rc = peer_fill(p, timeout_ms);
        if (rc < 0) {
            return (strstr(p->seen, needle) != NULL) ? 0 : -1;
        }
        if (now_ms() >= deadline) {
            return -1;
        }
        timeout_ms = 1;
    }
}

/* The departing node's claim, read before this test answers it. "A established a
 * link" would otherwise be satisfied by a node that never said hello. */
/* `name` is the peer whose claim is being read. It is a PARAMETER rather than a
 * constant because this file puts two different nodes behind this test's end of a link
 * -- case 1's is a departing node and case 3's is a node told a third server is gone
 * -- and a needle naming the wrong one turns a handshake that legitimately differs into
 * a failure that points at the verbs under test. It used to be hardcoded, and case 3
 * failed on its first run for exactly that reason. */
static void peer_expect_claim_as(peer_t *p, const char *name)
{
    const char *const needles[] = {
        ":",
        " " SECRET " " IRC_SERVE_VERSION "\r\n"
    };
    char claim[128];

    /* NO SPACE after the colon, and that is not a typo. The node's own serialiser
     * writes `:<name> FEDERATE ...` with the colon abutting the name, and a needle
     * written the way one would naturally write it -- ": name FEDERATE" -- does not
     * match, which cost this file one debug cycle. The needle is built rather than
     * spelled out so the name is the only variable in it, and the separator is taken
     * from what the node actually emits. */
    (void)snprintf(claim, sizeof claim, ":%s FEDERATE %s ", name, name);
    TF_CHECK_MSG(peer_expect(p, claim, T_IO_MS) == 0,
                 "%s never named itself in a FEDERATE, so nothing after this could "
                 "mean anything. What arrived on this socket: %s",
                 name, p->seen);
    TF_CHECK_MSG(peer_expect(p, needles[1], T_IO_MS) == 0,
                 "%s's claim did not carry the configured secret and the version "
                 "word, so the handshake below would be refused for a reason that has "
                 "nothing to do with the verbs under test. What arrived on this "
                 "socket: %s",
                 name, p->seen);
}

/* Case 1's node. Thin wrapper rather than a second copy of the body. */
static void peer_expect_claim(peer_t *p)
{
    peer_expect_claim_as(p, NAME_STAY);
}

/* The answer. A genuine claim in every field, so the handshake SUCCEEDS and the
 * link is ESTABLISHED -- which is the precondition for anything below, since both
 * the goodbye and the advertisement require an established link to travel on. */
static void peer_answer_claim(peer_t *p)
{
    char line[512];

    (void)snprintf(line, sizeof line, ":" NAME_PROBE " FEDERATE " NAME_PROBE
                                            " 1700000000 " SECRET " "
                                            IRC_SERVE_VERSION "\r\n");
    TF_CHECK_MSG(send_line(p->fd, line) == 0,
                 "the test could not answer " NAME_STAY " with a FEDERATE");
}

/* ---------------------------------------------------------------------------
 * CASE 1 -- CLAIMS 1, 2 AND 3: A REAL NODE'S GRACEFUL LEAVE
 * ---------------------------------------------------------------------------
 * THE FIXTURE IS TWO NODES PLUS THIS TEST'S OWN SOCKET, AND EACH IS LOAD-BEARING:
 *
 *   " NAME_STAY "   the node that is told to leave. A real forked server_t running
 *           the real loop, stopped with nf_stop() -- which sends SIGTERM, exactly the
 *           signal an operator or a supervisor sends. NOTHING HERE WRITES A
 *           SHUTDOWN: the line under test is produced by fed_send_shutdown() called
 *           from server_shutdown(), which is the claim.
 *
 *   this test     the ONE END of a link " NAME_STAY " dialled, as " NAME_PROBE ", so
 *           the goodbye can be read off the WIRE rather than off the departing
 *           node's own log. A node asked whether it sent something will say yes; a
 *           socket asked whether bytes arrived cannot.
 *
 *   " NAME_THIRD "  the node that DIALS " NAME_STAY ", and it is where claim 2 lives.
 *           THE DIRECTION IS THE WHOLE OF CLAIM 2 AND IT IS THE OPPOSITE OF WHAT IT
 *           LOOKS LIKE: T7's dial arm is guarded by `initiator != 0 && addrlen != 0`
 *           because an ACCEPTED link has no address and could never be dialled, so a
 *           clean-leave SUPPRESSION is untestable from the accepting side -- a node
 *           that let the ladder reach T7 there would look identical to one that
 *           suppressed it, and the test would pass against a node with no suppression
 *           at all. So the node that must NOT redial is the one that DID dial.
 *
 *           It is also the CLOCK the absence window is measured on -- its 60 ms
 *           keepalive produces the inbound lines that open the window.
 *
 *   " NAME_FOURTH "  the node the departure is relayed ONWARD to, two hops from the
 *           event. It earns its place because A RELAY NEEDS A THIRD NODE and no test
 *           can get around that: fed_in_shutdown() forwards the departure as a SQUIT
 *           to every ESTABLISHED peer EXCEPT the one it arrived on, so a node with
 *           one peer has nowhere to forward to and reports relayed=0. That is correct
 *           behaviour and it is untestable, which is the same reason
 *           tests/integration/test_fed_resync.c needs four nodes and
 *           test_peer_discovery.c needs a third.
 *
 *           It DIALS " NAME_THIRD " rather than the other way round, and the direction
 *           matters for the fixture rather than for the claim: the relay must travel
 *           over a link " NAME_THIRD " believes in, and an ACCEPTED link is as much
 *           of that as a dialled one -- fed_send_squit_named() walks ESTABLISHED
 *           links and does not care which end dialled. Dialing inward is chosen
 *           because it is the direction that needs no port this test does not already
 *           have: " NAME_THIRD "'s port is known before " NAME_FOURTH " is spawned.
 */static void case_a_real_node_announces_its_own_departure(void)
{
    nf_node_t stay;
    nf_node_t third;
    nf_node_t fourth;
    peer_t p;
    int listen_fd;
    int probe_port = 0;
    uint64_t base = 0;
    uint64_t dials;
    uint64_t arms;
    uint64_t shed_lines;

    /* THE TEST'S OWN LISTENER IS OPENED FIRST, because it is " NAME_STAY "'s only
     * peer and " NAME_STAY " is spawned against its port. */
    listen_fd = listen_loopback(&probe_port);
    TF_CHECK_MSG(listen_fd >= 0, "the test could not open a listening socket");

    /* --- " NAME_STAY ": it will be told to leave, and it will announce it ------ */
    memset(&g_cfg, 0, sizeof g_cfg);
    /* " NAME_PROBE " is the name this test's socket claims, and it is the name
     * " NAME_STAY " DIALS. One direction per pair, or both ends dial and neither
     * accepts (federation/link.h names the limitation). */
    g_cfg.peers[0].name = NAME_PROBE;
    g_cfg.peers[0].port = probe_port;
    g_cfg.dial_ms = 1000;
    g_cfg.hs_ms = 5000;
    /* THE KEEPALIVE IS THE ONE INTERVAL SHORTENED HERE, and it is not an
     * optimisation -- it is what keeps the fixture honest.
     *
     * The node that receives the departure has a SHORT dead threshold (DEAD_MS,
     * scaled with the ladder, and the reason why is at that spawn). A dead threshold
     * of 150 ms with this node's keepalive at the shipped 30 s means the receiver
     * declares this peer DEAD 150 ms after the last thing it heard -- which is long
     * before the case gets to send SIGTERM. T4 would then tear the link down,
     * announce this node's own departure, arm the ladder and redial, and the
     * assertions below would be measuring a link that had already failed for an
     * unrelated reason. The first run of this file did exactly that and failed with
     * a self-SQUIT naming the wrong server.
     *
     * So the two numbers have to agree, and the way they agree is that this node
     * speaks well inside the receiver's dead threshold. 50 ms against 150 ms is the
     * same three-to-one relationship the shipped 30 s keepalive has to the shipped
     * 90 s dead threshold, so the SHAPE of the shipped pairing is preserved and only
     * its scale changes -- which is the whole trade every one of these knobs exists
     * to make.
     *
     * The cost is traffic this node would not otherwise send, and it is worth
     * stating: at 50 ms it emits about twenty PINGs a second on each of its two
     * links for the life of the case. It goes onto the probe socket this test owns,
     * which does not answer them, so nothing here depends on a PONG.
     *
     * Its DEAD threshold is NOT shortened, and it has to be not: the probe socket
     * never answers this node, so any threshold shorter than the case would declare
     * that link dead and take the very link the wire claim is about. */
    g_cfg.keepalive_ms = SPEAK_MS;
    g_cfg.dead_ms = 0;
    /* THE FIGURE THIS NODE PUBLISHES ABOUT ITSELF, which the outbound-half
     * assertion below reads off the wire. */
    g_cfg.publish_load = 1;
    TF_CHECK_MSG(nf_spawn_inline_named(&stay, NAME_STAY, child_setup) == 0,
                 "could not spawn node " NAME_STAY);

    /* --- " NAME_THIRD ": it dials " NAME_STAY " and is the clock --------------- */
    memset(&g_cfg, 0, sizeof g_cfg);
    g_cfg.peers[0].name = NAME_STAY;
    g_cfg.peers[0].port = stay.port;
    g_cfg.dial_ms = 1000;
    g_cfg.hs_ms = 5000;
    /* THE CLOCK. Each PING is an INBOUND line on " NAME_STAY ", so `lines=` there
     * climbs on a real timer and the absence window below is a deadline over that
     * timer rather than a sleep. See the file header on why the boundary must be
     * inbound traffic and not something the fault under test produces. */
    g_cfg.keepalive_ms = KEEPALIVE_MS;
    /* THE LADDER, AND THIS IS THE MOST LOAD-BEARING SHORTENING IN THE FILE. The
     * dead threshold and the retry base are both scaled down so that T4 FIRES inside
     * this case and therefore ARMS the retry schedule.
     *
     * WHY IT MATTERS SO MUCH: claim 2 is that a clean leave arms no retry. Asserted
     * alone, that claim is VACUOUS -- with the shipped 90 s dead threshold the ladder
     * is never armed at all, so a node with no clean-leave suppression whatsoever
     * would also dial zero times and pass. The only thing that makes the zero redials
     * a DECISION is that the schedule is live and expiring, and T7's
     * `clean_leave == 0` is the single thing standing between it and a socket. So
     * this is why the assertion below is a PAIR: one `link_retry:` (the schedule was
     * armed) and one `link_dial:` (no socket came of it).
     *
     * What the scaling preserves is the ladder's SHAPE -- base x 2 per attempt,
     * capped, bounded by a budget of three -- and what it costs is stated in the
     * header: a 60 ms base proves the policy's shape and termination, and says
     * nothing about how 90 s behaves in a field.
     *
     * Its KEEPALIVE is the shipped 30 s, deliberately: nothing here needs this node's
     * OUTBOUND cadence, and a node under test for its retry policy is a poor choice
     * to also flood. What it needs from its own keepalive is only that it stays
     * quiet. */
    g_cfg.dead_ms = DEAD_MS;
    g_cfg.retry_base_ms = RETRY_BASE_MS;
    g_cfg.retry_max_ms = RETRY_MAX_MS;
    g_cfg.retry_budget = 3;
    /* A SHED THRESHOLD, and this node is the only place in case 1 that has one. It is
     * here for the unset-figure branch, which is otherwise UNREACHABLE while a link
     * is up -- every ESTABLISHED link advertises itself the moment it is established
     * (link.c's fed_link_established arm), so there is no window in which a live link
     * has no figure.
     *
     * A LINK THAT HAS GONE DOWN is where it is reachable: fed_link_down() clears the
     * figure and its "have we heard from this peer" flag, precisely because a link
     * that is down has learned nothing about the peer's CURRENT load. So after " NAME_STAY "
     * departs, this node's link to it is INIT with NO figure -- and an arm that reads
     * an unset figure as 0% would report a node that is GONE as a node that is IDLE.
     *
     * That is the fabricated-metric failure this feature is scoped to avoid, in its
     * sharpest form: a number this node does not have, about a server that has left,
     * printed as an observation. The teeth run is what proved the branch needed a
     * subject -- a fault that drops the unset check from T8's condition passed while
     * this case had no threshold anywhere and case 2's receiver always had a figure.
     */
    g_cfg.shed_pct = (int)SHED_PCT;
    TF_CHECK_MSG(nf_spawn_inline_named(&third, NAME_THIRD, child_setup) == 0,
                 "could not spawn node " NAME_THIRD);

    /* --- " NAME_FOURTH ": the relay's far end ------------------------------- */
    /* It has no configured peers of its own and exists purely as an accepted link on
     * " NAME_THIRD ", and it is ALSO THE CLOCK -- which is the second thing it is for
     * and the reason its KEEPALIVE is the only interval shortened here.
     *
     * After the departure, " NAME_THIRD "'s links are the socket this test holds
     * (which does not answer its PINGs) and this node. So this node's keepalive is
     * the only remaining source of inbound lines on the node the absence is asserted
     * on, and at the shipped 30 s the observation window could not open inside any
     * deadline this test has. At 60 ms it opens in under a second.
     *
     * Its DEAD threshold is deliberately NOT shortened. " NAME_THIRD " dials it and
     * is answered, so its one link is established and healthy, and a short threshold
     * here would be a way to fail the case for a reason that has nothing to do with a
     * graceful leave. It is the one node in this file with no policy under test at
     * all, and it is kept that way on purpose: a fixture node with a shortened
     * interval is a fixture node that can fail the case for its own reasons. */
    memset(&g_cfg, 0, sizeof g_cfg);
    g_cfg.peers[0].name = NAME_THIRD;
    g_cfg.peers[0].port = third.port;
    g_cfg.dial_ms = 1000;
    g_cfg.hs_ms = 5000;
    g_cfg.keepalive_ms = KEEPALIVE_MS;
    g_cfg.dead_ms = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&fourth, NAME_FOURTH, child_setup) == 0,
                 "could not spawn node " NAME_FOURTH);

    /* --- the departing node's link to this test ---------------------------- */
    p.fd = accept_deadline(listen_fd, T_IO_MS);
    /* Closed here and not at the end: this listener is the departing node's only
     * peer to this test and a second accept would be a second link. */
    close(listen_fd);
    TF_CHECK_MSG(p.fd >= 0, NAME_STAY " never dialled the socket this test owns");
    p.used = 0u;
    p.seen[0] = '\0';

    peer_expect_claim(&p);
    peer_answer_claim(&p);

    /* --- CLAIM 3, THE OUTBOUND HALF, ON THE WIRE ---------------------------- */
    /* The figure this node publishes about ITSELF, read off a real socket. It is
     * " LOAD_PUB_TEXT " because the departing node's child_setup called
     * fed_set_load(), which is DEFINED -- so unlike test_peer_discovery.c this
     * direction asserts a chosen figure rather than the zero a node with no knob
     * can honestly produce.
     *
     * It is sent ONCE on establishment (link.c's fed_link_established arm), so this
     * single wait covers the whole claim: the figure is on the wire before anything
     * below happens, and a node that advertised nothing at all would time out here
     * rather than pass vacuously further down. */
    TF_CHECK_MSG(peer_expect(&p, " ADVERTISE " LOAD_PUB_TEXT, T_IO_MS) == 0,
                 NAME_STAY " never advertised its own load figure on this link. The "
                 "figure is the only payload a node publishes about itself and it is "
                 "sent once on establishment, so this wait covers the whole claim. "
                 "What arrived on this socket: %s",
                 p.seen);

    /* BOTH LINKS UP, and each is a precondition for something below rather than a
     * formality: the second link is what gives the departure somewhere to be told
     * onward to, so without it the mesh half of this case does not exist. */
    TF_CHECK_MSG(nf_expect(&stay, "link_established: peer=" NAME_PROBE, T_IO_MS) == 0,
                 NAME_STAY " never established its link to the socket this test owns, "
                 "so the goodbye below would have nowhere to go: %s",
                 stay.out);
    TF_CHECK_MSG(nf_expect(&stay, "link_established: peer=" NAME_THIRD, T_IO_MS) == 0,
                 NAME_STAY " never established its link to " NAME_THIRD
                 ", so its departure would have nowhere to be told onward to: %s",
                 stay.out);
    TF_CHECK_MSG(nf_expect(&third, "link_established: peer=" NAME_STAY, T_IO_MS) == 0,
                 NAME_THIRD " never established its link to " NAME_STAY ": %s",
                 third.out);
    /* AND THE RELAY'S LINK IS UP ON BOTH SIDES, which is a PRECONDITION and not a
     * formality, and its absence was the first version of this case's real defect.
     *
     * fed_in_shutdown() forwards the departure as a SQUIT to every ESTABLISHED peer
     * EXCEPT the one it arrived on. With " NAME_FOURTH "'s link not yet established
     * when the SHUTDOWN is processed there is nowhere to forward to, the node
     * correctly reports relayed=0, and the mesh half of the claim is simply not
     * exercised -- while every other assertion in this case still passes. The first
     * run of this file did exactly that and failed only on the far end.
     *
     * Asserted on BOTH nodes because a half-established link is the interesting
     * middle: the dialling side prints `link_dialled:` long before the accepting side
     * answers, so waiting on " NAME_FOURTH " alone would pass while " NAME_THIRD " still
     * had the peer in HANDSHAKE_SENT.
     *
     * The wait is here rather than at the spawn for the same reason the rest of this
     * file's waits are: a readiness line proves the loop is armed, not that a
     * particular link came up, and the departure must not be timed against a link
     * that has not finished handshaking. */
    TF_CHECK_MSG(nf_expect(&third, "link_established: peer=" NAME_FOURTH, T_IO_MS) == 0,
                 NAME_THIRD " never established its link to " NAME_FOURTH
                 ", so it has no peer to relay " NAME_STAY "'s departure to and the "
                 "mesh half of this case would be vacuous: %s",
                 third.out);
    TF_CHECK_MSG(nf_expect(&fourth, "link_established: peer=" NAME_THIRD, T_IO_MS) == 0,
                 NAME_FOURTH " never established its link to " NAME_THIRD
                 ", so a relayed SQUIT would arrive on a connection the far end does "
                 "not believe in: %s",
                 fourth.out);
    /* THE LIVENESS WITNESS, and it is deliberately a SECOND advertisement rather
     * than a keepalive PING. This node's keepalive is the shipped 30 s (its timers
     * are not shortened -- see the spawn above), so waiting for a PING here would be
     * waiting out half a minute for no additional information.
     *
     * The advertisement refresh is the better witness for three reasons. It is
     * driven by the same "is this link ESTABLISHED and live" clock the goodbye will
     * travel on. It arrives inside the test's own deadline because the advertisement
     * interval IS shortened (see the header's "what is shortened"). And the COUNT
     * matters: ONE advertisement is what a link sends the instant it is established,
     * so a single one is satisfied by a link that died immediately afterwards, while
     * two prove the node went on believing this link and drove traffic over it.
     *
     * It is read off the socket rather than from the node's `fed_advertise_sent:`
     * line, which is the same reason the goodbye is: that line is the sender
     * reporting on itself, and a node asked whether it sent something will say yes.
     */
    TF_CHECK_MSG(peer_expect_n(&p, " ADVERTISE " LOAD_PUB_TEXT, 2u, T_IO_MS) == 0,
                 NAME_STAY " advertised its figure once and then stopped, so it is "
                 "not treating this link as a live peer route -- and a goodbye from a "
                 "node that does not believe its link is a goodbye it had no reason "
                 "to send. It is also possible the interval was not applied and the "
                 "second advertisement is simply late; either way the wire claim "
                 "below is not yet anchored. What arrived on this socket: %s",
                 p.seen);

    /* --- THE DEPARTURE ---------------------------------------------------- */
    /* nf_stop() sends SIGTERM and waits for a clean exit. That is the whole
     * mechanism, and it is the shipped one: poll_loop_run() returns, and
     * server_shutdown() calls fed_send_shutdown() BEFORE it closes a single socket.
     * A node without that call would exit 0 here having said nothing, and every
     * assertion below would be measuring a node's silence.
     *
     * NOTE WHAT IS NOT DONE: this test does not write a SHUTDOWN, and it does not
     * ask the departing node whether it sent one. Both are available and both are
     * worthless -- the first tests the test, the second asks the guilty party.
     * `fed_shutdown_sent:` exists on the departing node's log and is deliberately
     * NOT asserted here, for exactly that reason: a node asked whether it sent
     * something will say yes. */
    TF_CHECK_MSG(nf_stop(&stay) == 0,
                 NAME_STAY " did not exit cleanly on SIGTERM, so the departure under "
                 "test did not happen through the shipped path");

    /* CLAIM 1, THE WIRE HALF. Read off the departing node's own socket, AFTER the
     * node has exited -- which is what makes it a wire claim rather than a log one:
     * the bytes are in this process's buffer and the sender is a process that no
     * longer exists to be asked.
     *
     * It is searched before any read for the reason peer_expect() says: the node
     * said goodbye and then closed, so this is the LAST line it ever sent and a
     * fill-first loop would report the close and miss it. That is not
     * hypothetical -- core/connection.c's conn_fill() loops until recv() answers
     * EAGAIN or 0, so "say it and go" arrives as one read followed by an EOF, and
     * this assertion is the reason the order of those two events is load-bearing. */
    TF_CHECK_MSG(peer_expect(&p, " SHUTDOWN\r\n", T_IO_MS) == 0,
                 NAME_STAY " exited without putting a SHUTDOWN on the wire. Its exit "
                 "path runs server_shutdown(), which is the only caller of "
                 "fed_send_shutdown() in this tree; with that call gone, a planned "
                 "restart is indistinguishable from a crash on every peer. What "
                 "arrived on this socket: %s",
                 p.seen);
    /* AND IT IS THE COMPLETE VERB AND NOT A PREFIX OF SOMETHING LONGER. 4.3 has no
     * SHUTDOWN, so this phase chose its shape, and the shape chosen is the whole
     * verb with no parameters (link.h gives the reason: a field a second
     * implementation would have to guess at is a compatibility break bought for
     * nothing). This is the half that would catch a shape change: `SHUTDOWN` on its
     * own is a complete line, whereas `SHUTDOWN something` is not the verb this
     * phase specified, and the needle above would be satisfied by both because a
     * substring match cannot see where a parameter list starts.
     *
     * It is asserted as a SECOND needle rather than by replacing the first because
     * the first is the one that fails if nothing arrives at all, and a diagnostic
     * that only runs after another has passed tells you less when the line is
     * missing entirely. */
    TF_CHECK_MSG(peer_expect(&p, ":irc.stay SHUTDOWN\r\n", T_IO_MS) == 0,
                 NAME_STAY " put a SHUTDOWN on the wire but not as the bare verb this "
                 "phase specified -- it carried a parameter list, so a second "
                 "implementation's parser would have to guess what the parameters "
                 "mean: %s",
                 p.seen);

    /* CLAIM 1, THE ONWARD HALF. The departure reached a node two hops from the
     * event, as a SQUIT -- the verb the receiving side already knows how to act on,
     * since 4.3 has no SHUTDOWN. What is asserted is the OBSERVABLE, and it is the
     * one a peer of an older build would also produce, which is why this is the
     * relay half and not a second copy of the claim above: the socket cannot show
     * relay, because it is the departing node's own link. */
    TF_CHECK_MSG(nf_expect(&fourth, "fed_squit: server=" NAME_STAY, T_IO_MS) == 0,
                 "the departure of " NAME_STAY " never reached " NAME_FOURTH
                 ", so a node two hops away is still holding a roster for a server "
                 "that is gone: %s",
                 fourth.out);

    /* --- CLAIM 2: NO RETRY, AND NO DIALS ----------------------------------- */
    /* The decision first, because the implementation prints it first: a log reader
     * has to see the decision before the consequences of it. This is the WEAKER of
     * the two claims -- a node can print a flag it did not honour -- and the counts
     * below are the stronger one. It is asserted anyway because it names the cause,
     * and because it is what distinguishes "this node decided" from "this node
     * never noticed". */
    TF_CHECK_MSG(nf_expect(&third, "link_clean_leave: peer=" NAME_STAY
                                   " reason=PEER_SHUTDOWN",
                           T_IO_MS) == 0,
                 NAME_THIRD " treated the departure of " NAME_STAY " as a plain "
                 "link-down rather than as a clean departure, so nothing downstream "
                 "could tell a planned stop from a crash: %s",
                 third.out);
    /* THE ACCOUNT. `relayed=1` is the part with teeth and it is the local half of
     * the mesh claim above: it says the node forwarded the departure rather than
     * swallowing it, and it is a COUNT of peers told rather than a claim about
     * whether the node tried.
     *
     * `retried=0` is the WEAKEST token on the line and is not relied on: a node can
     * print it and then dial, which is why the counts below are the claim.
     *
     * `reason=-` IS ASSERTED RATHER THAN SKIPPED, and it is a real consequence of the
     * wire format rather than a placeholder: fed_send_shutdown() sends the bare verb
     * with no parameters, so the receiver has nothing to print and renders "-". A
     * needle written without it would pass against a node that invented a reason, and
     * a future change that started sending one would silently pass an assertion
     * written here -- so the absence of a reason is part of what this case pins. */
    TF_CHECK_MSG(nf_expect(&third, "fed_shutdown: peer=" NAME_STAY
                                   " reason=- chans=0 purged=0 relayed=1 clean_leave=1"
                                   " retried=0",
                           T_IO_MS) == 0,
                 "the SHUTDOWN was not accounted for as a clean, unretried, forwarded "
                 "departure, or it was not forwarded at all -- " NAME_FOURTH
                 " was ESTABLISHED and is the peer it had to go to: %s",
                 third.out);

    /* THE WINDOW'S LOWER BOUND, AND WHEN IT IS TAKEN IS THE WHOLE OF IT.
     *
     * It is read HERE -- after the departure has been fully processed and observed --
     * and not before it, and that ordering was the first version of this case's real
     * bug. The window is "did any dial happen during the period after the
     * departure", and the bound has to be a reading of the counter taken at the START
     * of that period. Taken before the departure it is not: the departing node is
     * still sending (its own keepalive is " SPEAK_MS " and it is sending to two links),
     * so a base read before SIGTERM is a reading of a moment that the departure's own
     * traffic then advances past -- and the more the base is behind, the shorter the
     * window, down to zero.
     *
     * The failure it produced was the worst kind this project keeps meeting: the test
     * FAILED for the right reason and reported the wrong one. With the window closed
     * early, T4 had not yet fired inside it, so `link_retry:` was legitimately 0, and
     * the assertion that exists to prove the ladder WAS armed and then was REFUSED
     * fired with "armed the ladder 0 times". The message pointed at the product. The
     * window had closed before the product had done anything.
     *
     * Reading it here also means everything already in the buffer is accounted for by
     * construction: the departure's own lines, the burst of anything the departure
     * provoked, and the republications that happened while the assertions above were
     * running. Whatever the counter reads now is the floor, and only lines that arrive
     * AFTER it can open the window.
     *
     * The node is " NAME_THIRD " and not " NAME_STAY " because that is the node the
     * absence is asserted on. */
    TF_CHECK_MSG(nf_find_u64(&third, "lines=", &base) == 0,
                 NAME_THIRD " never published its inbound line count, so the "
                 "observation window below has no lower bound to grow from: %s",
                 third.out);

    /* THE WINDOW, and its arithmetic is at WINDOW_LINES: " WINDOW_LINES " inbound lines
     * at the fourth node's " KEEPALIVE_MS " keepalive is " WINDOW_MS ", past every rung of
     * the " RETRY_BASE_MS " ladder and past the budget's last. The boundary is INBOUND
     * traffic, which no dial produces -- a boundary on `link_dial:` or `accepted=`
     * would be satisfied BY the fault under test and would stop before the fault
     * fired. */
    TF_CHECK_MSG(nf_expect_u64_ge(&third, "lines=", base + (uint64_t)WINDOW_LINES,
                                  T_IO_MS) == 0,
                 NAME_THIRD " received too few inbound lines and the observation "
                 "window never opened, so the absence asserted below would be "
                 "vacuous: %s",
                 third.out);

    /* THE ASSERTION WITH TEETH. Exactly one dial to " NAME_STAY " in the surviving
     * node's whole life. A retrying goodbye prints a second link_dial: line inside
     * this window and fails this, which is the failure the case exists to catch: a
     * planned restart spent as three dials, three rungs of backoff, and a link in a
     * dump that looks retryable.
     *
     * This is a COUNT OF SOCKETS THE NODE ACTUALLY OPENED, which is the whole reason
     * it is here rather than the `retried=0` field above. A node can print
     * `retried=0` and then dial; a node cannot print a second `link_dial:` without
     * having dialled. */
    dials = tf_count(third.out, "link_dial: peer=" NAME_STAY);
    TF_CHECK_MSG(dials == 1u,
                 NAME_THIRD " dialled peer " NAME_STAY " %llu times. It dialled it "
                 "once to open this link, and a peer that said SHUTDOWN must never be "
                 "dialled again without an operator resetting it: %s",
                 (unsigned long long)dials, third.out);

    /* AND THE LADDER WAS STILL ARMED, exactly once. This is what makes the count
     * above an assertion about the clean-leave guard rather than about a link that
     * had nothing to retry: T4 armed the schedule on the closure, the schedule was
     * live and expiring, and T7's `clean_leave == 0` is the only thing standing
     * between it and a socket. A node that never armed the ladder at all would pass
     * the line above for the wrong reason, which is why this one is here and not
     * optional. */
    arms = tf_count(third.out, "link_retry: peer=" NAME_STAY);
    TF_CHECK_MSG(arms == 1u,
                 NAME_THIRD " armed the retry ladder %llu times for a link that had "
                 "cleanly departed, expected the single arm T4 makes when the socket "
                 "closed: %s",
                 (unsigned long long)arms, third.out);
    /* AND THE BUDGET WAS NOT SPENT, which is the cost clean_leave exists to avoid:
     * three dials and a two-minute ceiling rediscovering a message that already
     * arrived. */
    TF_CHECK_MSG(strstr(third.out, "link_retry_exhausted: peer=" NAME_STAY) == NULL,
                 NAME_THIRD " spent a whole retry budget on a peer that said it was "
                 "leaving, which is exactly the failure the suppression is for: %s",
                 third.out);

    /* EXACTLY ONE SHED REPORT ABOUT THE DEPARTED PEER, AND THE COUNT IS THE CLAIM.
     *
     * " NAME_THIRD " saw " NAME_STAY " advertise " LOAD_PUB_FMT " over a live link, with
     * a threshold of " SHED_PCT_FMT " set, so ONE report was correct -- a crossing, reported once.
     * Two things would make the count wrong, and they are the two ways a mesh-load
     * feature becomes a stale roster, which is the failure 2.2's purge discipline is
     * entirely about:
     *
     *   ZERO    the arm does not run. The propagation half is missing, which is the
     *           first thing a reader wants to know about a node that has the threshold
     *           set and has not reported anything.
     *   TWO     the figure was NOT cleared when the link went down, and the latch was
     *           cleared with it. The node then re-reports " NAME_STAY " as busy on a
     *           link that no longer exists -- a measurement of a server that has left,
     *           published by a node that should have thrown the number away. An
     *           operator reading "who is busy" on this mesh finds a departed server on
     *           the list, permanently, because nothing ever revisits a link whose peer
     *           is gone.
     *
     * So the count is asserted as exactly one rather than as an absence. An absence
     * would pass against an arm that never ran, which is the same vacuity the teeth
     * run found in this file's other negative half, and it is worth saying that the
     * teeth are what turned this from "assert nothing happens" into "assert exactly
     * one thing happens".
     *
     * A count rather than a window, and deliberately: the second report is not
     * something that might arrive later, it is something that either happened on the
     * tick that took the link down or did not happen at all. The link is down and the
     * node has been running since, so there is nothing further to wait for.
     */
    shed_lines = tf_count(third.out, "fed_shed: peer=" NAME_STAY);
    TF_CHECK_MSG(shed_lines == 1u,
                 NAME_THIRD " printed %llu shed reports about " NAME_STAY ". One is "
                 "right -- it advertised " LOAD_PUB_ESC " while the link was up and the "
                 "threshold is " SHED_PCT_ESC ", so that was a crossing. Any further one "
                 "is it reporting the DEPARTED peer from a link that has gone down: the "
                 "figure was cleared on purpose, because a link that is down has learned "
                 "nothing about the peer's current load, and reading the cleared figure "
                 "as 0%% prints a server that has left as one that is idle: %s",
                 (unsigned long long)shed_lines, third.out);

    /* CLAIM 3, THE INBOUND HALF. The surviving node observed the figure the
     * departing node published, which is part of what a graceful leave is: a node
     * leaving while loaded is the case an operator needs the mesh to have seen.
     *
     * It is asserted on the receiver's own report -- the observable for "a figure a
     * peer published was observed" -- and on the FIGURE, not merely on the line
     * arriving: a node with no figure set publishes 0%, so a bare `fed_advertise:`
     * would be satisfied by a build that propagated nothing but its own default. */
    TF_CHECK_MSG(nf_expect(&third, "fed_advertise: peer=" NAME_STAY, T_IO_MS) == 0,
                 NAME_THIRD " never observed an advertisement from " NAME_STAY
                 ", so the load figure a peer publishes did not propagate to a node "
                 "other than the one this test is holding a socket to: %s",
                 third.out);
    TF_CHECK_MSG(nf_expect(&third, "load=" LOAD_PUB_FMT, T_IO_MS) == 0,
                 NAME_THIRD " observed advertisements but never the figure "
                 NAME_STAY " was configured to publish (" LOAD_PUB_ESC
                 "), so the number that propagated is not the number that was sent: "
                 "%s",
                 third.out);

    TF_CHECK_MSG(nf_stop(&fourth) == 0, "node " NAME_FOURTH " did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&third) == 0, "node " NAME_THIRD " did not exit cleanly");
    close(p.fd);
    nf_free(&stay);
    nf_free(&third);
    nf_free(&fourth);
}

/* ---------------------------------------------------------------------------
 * CASE 2 -- CLAIM 3'S REACTION: A CROSSING IS REPORTED ONCE, AND NOTHING MOVES
 * ---------------------------------------------------------------------------
 * THIS CASE NEEDS NO DEPARTURE, because the reaction is to a peer advertising itself
 * as BUSY, which is a different event from a peer announcing it is LEAVING and is
 * worth testing on its own: a mesh where somebody is loaded is the ordinary case, and
 * a departure is the rare one.
 *
 * THE FIXTURE IS TWO NODES, AND THE ASYMMETRY IS THE POINT:
 *
 *   " NAME_LEAVE "  republishes itself as a peer that PUBLISHES A BUSY FIGURE. It
 *           keeps a fast advertisement interval so the figure reaches the other node
 *           repeatedly, which is what makes the edge latch testable rather than
 *           decorative.
 *   " NAME_THIRD "  observes it and HAS A THRESHOLD SET (fed_set_shed_pct). It is
 *           the only node in the file with one, and that is what makes the crossing
 *           reachable: on a node with no threshold -- the shipped state -- the arm
 *           compares and finds nothing to report.
 *
 * WHY A NODE WITH NO THRESHOLD IS ALSO ASSERTED, in the negative half below: a
 * feature that only works when configured is not a feature that works, and the shipped
 * configuration is no threshold. So the claim has two halves and they are tested on
 * two nodes.
 *
 * AND THE PUBLISHING NODE'S OWN THRESHOLD IS ZERO, deliberately. A node reporting
 * itself as shedding would be a node judging its own load against its own threshold,
 * which is the thing fed_set_load()'s comment exists to prevent: the percentage is
 * not a measurement, so this node has no standing to say whether its own figure is
 * too high. The reaction belongs to the node that has the information -- the peers.
 */
static void case_b_a_busy_peer_is_reported_once_and_nothing_moves(void)
{
    nf_node_t busy;
    nf_node_t watcher;
    nf_node_t fourth;
    uint64_t reports;
    uint64_t dials;

    /* " NAME_LEAVE ": it publishes a busy figure, and it HAS A PEER of its own --
     * which the teeth run showed is the whole of what makes the negative half below
     * an assertion. With no peers this node could not report a shed no matter what
     * the arm did, so an arm that fired unconditionally passed, and the assertion
     * that was supposed to catch it was vacuous. A node needs something to be busy
     * ABOUT before "no threshold, so no opinion" can be observed.
     *
     * Its peer is " NAME_FOURTH ", which publishes a figure of its own -- and that is
     * what " NAME_LEAVE " would wrongly report if the arm ignored the threshold. */
    memset(&g_cfg, 0, sizeof g_cfg);
    g_cfg.peers[0].name = NAME_FOURTH;
    g_cfg.keepalive_ms = KEEPALIVE_MS;
    g_cfg.dead_ms = 0;
    g_cfg.publish_load = 1;
    /* NO shed_pct, and that is the node's entire difference from " NAME_THIRD ": it
     * has something above the threshold to look at and no threshold to look at it
     * with. */
    TF_CHECK_MSG(nf_spawn_inline_named(&busy, NAME_LEAVE, child_setup) == 0,
                 "could not spawn node " NAME_LEAVE);

    memset(&g_cfg, 0, sizeof g_cfg);
    g_cfg.peers[0].name = NAME_LEAVE;
    g_cfg.peers[0].port = busy.port;
    g_cfg.dial_ms = 1000;
    g_cfg.hs_ms = 5000;
    g_cfg.keepalive_ms = KEEPALIVE_MS;
    g_cfg.dead_ms = 0;
    /* THE THRESHOLD, and it is the only difference between this node and a shipped
     * one. Set below LOAD_PUB_PCT so the crossing is reachable with the figure the
     * other node publishes. */
    g_cfg.shed_pct = (int)SHED_PCT;
    TF_CHECK_MSG(nf_spawn_inline_named(&watcher, NAME_THIRD, child_setup) == 0,
                 "could not spawn node " NAME_THIRD);

    /* " NAME_FOURTH ": it dials " NAME_LEAVE ", so " NAME_LEAVE " has a peer whose
     * advertised figure is its own to (wrongly) report on. It is the same shape as
     * the relay's far end in case 1 -- a node with nothing to do but be the other
     * side of something -- and it earns its place by making the negative half real. */
    memset(&g_cfg, 0, sizeof g_cfg);
    g_cfg.peers[0].name = NAME_LEAVE;
    g_cfg.peers[0].port = busy.port;
    g_cfg.dial_ms = 1000;
    g_cfg.hs_ms = 5000;
    g_cfg.keepalive_ms = KEEPALIVE_MS;
    g_cfg.dead_ms = 0;
    /* IT PUBLISHES A FIGURE TOO, and above zero, because " NAME_LEAVE " can only be
     * observed staying silent about a figure it has actually been told. A peer that
     * advertised nothing would leave the negative half testing the unset-figure
     * guard rather than the threshold, and those are two different rules. */
    g_cfg.publish_load = 1;
    TF_CHECK_MSG(nf_spawn_inline_named(&fourth, NAME_FOURTH, child_setup) == 0,
                 "could not spawn node " NAME_FOURTH);

    /* ALL THREE LINKS UP. Asserted before the crossing rather than after, because
     * the negative half below is about " NAME_LEAVE "'s behaviour and it can only be
     * about that once " NAME_LEAVE " has a peer whose figure it has observed. */
    TF_CHECK_MSG(nf_expect(&watcher, "link_established: peer=" NAME_LEAVE, T_IO_MS) == 0,
                 NAME_THIRD " never established its link to " NAME_LEAVE
                 ", so the figure below could not have propagated: %s",
                 watcher.out);
    TF_CHECK_MSG(nf_expect(&busy, "link_established: peer=" NAME_FOURTH, T_IO_MS) == 0,
                 NAME_LEAVE " never established its link to " NAME_FOURTH
                 ", so it has nothing to be wrongly silent about: %s",
                 busy.out);
    TF_CHECK_MSG(nf_expect(&fourth, "link_established: peer=" NAME_LEAVE, T_IO_MS) == 0,
                 NAME_FOURTH " never established its link to " NAME_LEAVE ": %s",
                 fourth.out);
    /* AND IT HAS ACTUALLY OBSERVED A FIGURE, which is the precondition the negative
     * half depends on and the one a reader cannot check from the link being up: a
     * node with a live link and no advertisement in its store has nothing to report
     * whatever the arm does. */
    TF_CHECK_MSG(nf_expect(&busy, "fed_advertise: peer=" NAME_FOURTH, T_IO_MS) == 0,
                 NAME_LEAVE " never observed an advertisement from " NAME_FOURTH
                 ", so its staying silent below would prove nothing -- it has nothing "
                 "to report in the first place: %s",
                 busy.out);

    /* CLAIM 3, THE CROSSING. Reported once, with the figure, the threshold, and --
     * the part that carries the design -- action=REPORT_ONLY and rebalance=NO with
     * the reason. A reader grepping a mesh for "who is busy" gets an unambiguous
     * answer to "and then what?", and the answer being "nothing, and here is why"
     * is the honest one rather than a gap in a comment.
     *
     * The full literal rather than a prefix is asserted so a future edit cannot
     * quietly drop `action=REPORT_ONLY` and leave a line that reads like a routing
     * change. */
    TF_CHECK_MSG(nf_expect(&watcher,
                           "fed_shed: peer=" NAME_LEAVE " load=" LOAD_PUB_FMT
                           " threshold=" SHED_PCT_FMT " action=REPORT_ONLY "
                           "rebalance=NO reason=NO_MOVE_MECHANISM",
                           T_IO_MS) == 0,
                 NAME_THIRD " observed a peer advertising " LOAD_PUB_ESC
                 " with a " SHED_PCT_ESC " threshold set and did not report it as "
                 "shedding. The propagation half of this feature is that a peer which "
                 "says it is busy is TOLD to somebody who can act on it, and this "
                 "line is the whole of it: %s",
                 watcher.out);

    /* A WINDOW BEFORE THE COUNT, and without it the count is VACUOUS -- which the
     * teeth run proved rather than argued. The crossing assertion above returns the
     * instant the first `fed_shed:` line appears, which is inside the SAME tick that
     * printed it, so `tf_count` at that moment can only ever see one line. An
     * implementation that reported on every tick would pass, because the test had
     * not yet given the ticks time to happen.
     *
     * So the window opens FIRST and the count is read SECOND. What the window waits
     * for is the publishing node's SECOND advertisement, which is an inbound line on
     * the watcher and therefore a thing that arrives on the watcher's own clock: the
     * watcher has by definition processed it, re-run the arm, and had its chance to
     * print a second time. Counting after that is counting over a period in which a
     * per-tick implementation had " EDGE_LINES " opportunities and a per-crossing one
     * had none.
     *
     * " EDGE_LINES " rather than one, because one is the number the assertion above
     * has already satisfied and would add nothing. */
    TF_CHECK_MSG(nf_expect_nth(&watcher, "fed_advertise: peer=" NAME_LEAVE,
                               (size_t)EDGE_LINES, T_IO_MS) == 0,
                 NAME_THIRD " received fewer than " ADVERTISE_COUNT_STR " advertisements "
                 "from " NAME_LEAVE ", so the count below was taken over a period in "
                 "which the arm could not have reported again even if it reports on "
                 "every tick. The latch is the claim and the window has to be able to "
                 "catch its absence: %s",
                 watcher.out);

    /* THE EDGE, NOT THE STATE. A peer sitting at 42% would, without the latch, print
     * a line every POLL_TICK_MS for the life of the link -- twenty lines a second,
     * per busy peer, on a mesh where somebody is busy. That is the opposite of
     * reporting, and it is the failure the latch exists to prevent.
     *
     * The count is over the watcher's whole output, so it catches a latch that never
     * engaged (many lines) as well as one that is missing (zero, which the assertion
     * above already failed on). The upper bound is what makes this an assertion
     * about a CROSSING rather than about the first line having appeared. */
    reports = tf_count(watcher.out, "fed_shed: peer=" NAME_LEAVE);
    TF_CHECK_MSG(reports == 1u,
                 NAME_THIRD " reported the same busy peer %llu times. It should report "
                 "a CROSSING once and then stay quiet until the figure comes back "
                 "down: %s",
                 (unsigned long long)reports, watcher.out);

    /* THE NEGATIVE HALF, and it is the half that pins the SHIPPED CONFIGURATION.
     * " NAME_LEAVE " has a peer advertising " LOAD_PUB_FMT " and NO threshold set, and
     * it printed nothing.
     *
     * Without it the feature passes against an arm that reports unconditionally, and
     * a node with no threshold -- which is every node in every deployment, because
     * 0 is the shipped value -- would print a verdict about load that this codebase
     * has no standing to reach. That is the fabricated-metric failure the whole
     * feature is scoped to avoid, arriving through the arm rather than through a
     * comment.
     *
     * It was VACUOUS until the teeth run, and the reason is worth recording: at first
     * " NAME_LEAVE " had no peers of its own, so it could not have reported a shed
     * however the arm behaved, and the assertion passed against an arm that fires on
     * every non-zero figure regardless of any threshold. It now has a peer, it has
     * observed that peer's figure (asserted above), and it has something it could
     * wrongly report. An assertion whose subject has nothing to say is not a test of
     * the arm. */
    TF_CHECK_MSG(strstr(busy.out, "fed_shed:") == NULL,
                 NAME_LEAVE " reported a peer as shedding with NO threshold set, having "
                 "observed that peer's " LOAD_PUB_ESC " figure. The shipped state is "
                 "no opinion (fed_set_shed_pct()'s default is 0), and a node that "
                 "judges load it cannot measure is the fabricated-metric failure this "
                 "whole feature is scoped to avoid: %s",
                 busy.out);

    /* AND NOTHING WAS MOVED, which is the claim that makes this a propagation
     * feature rather than a rebalancing one. THREE ABSENCES, each a different way the
     * scope could have been exceeded without the two lines above changing at all:
     *
     *   no NEW dial  the busy figure did not become a dial target. This is the
     *      SSRF-shaped half and the one worth being careful about in the WORDING,
     *      because the obvious way to write it is wrong: this test's watcher DOES
     *      dial, because that is how the two nodes were configured -- the
     *      operator gave it one peer and it dialled it. So the assertion is not
     *      "no dial" but "no dial it did not already have in its configured peer
     *      set", which is EXACTLY ONE, and it happened before the figure had been
     *      seen. A learned address reaching the dial path would be a second dial of
     *      a name this node was never configured with, and the count catches it.
     *   no client   nobody was transferred anywhere. There is no session-transfer
     *      verb in 4.3 and no client-visible redirect, so this is asserted as a
     *      count of connections the node took rather than as an absence, because
     *      "zero connections" is also what a node that accepted nothing all day
     *      looks like.
     *   no 437      no channel was re-homed. 437 is 2.2's fail-closed answer when
     *      an origin is unreachable, and re-homing a channel IS origin
     *      re-election, which 9's risk table records as not to be begun without
     *      re-opening 2.4.
     *
     * The window for all three is the crossing assertion above plus the fast
     * advertisement interval: the publishing node has refreshed its figure several
     * times since, and every refresh re-ran the arm that could have acted on it. */
    dials = tf_count(watcher.out, "link_dial: peer=");
    TF_CHECK_MSG(dials == 1u,
                 NAME_THIRD " started %llu dials. Its operator configured it with "
                 "exactly one peer and it dialled that one; a load figure that became "
                 "a dial target would be a second socket to a name this node was "
                 "never configured with, and that is the SSRF primitive server.h "
                 "spends a page ruling out: %s",
                 (unsigned long long)dials, watcher.out);
    TF_CHECK_MSG(tf_count(watcher.out, "client_connect:") == 0u,
                 NAME_THIRD " accepted %zu connections. Nobody should have been moved: "
                 "4.3 has no session-transfer verb and no client-visible redirect, so "
                 "there is no mechanism by which this node could have moved a client "
                 "off the socket it owns: %s",
                 tf_count(watcher.out, "client_connect:"), watcher.out);
    TF_CHECK_MSG(strstr(watcher.out, " 437 ") == NULL,
                 NAME_THIRD " refused an action naming an origin after observing a busy "
                 "peer. That numeric is the fail-closed answer when an origin is "
                 "unreachable, and 2.2's origin is immutable -- re-homing a channel "
                 "IS origin re-election, which 9's risk table records as not to be "
                 "begun without re-opening 2.4: %s",
                 watcher.out);

    TF_CHECK_MSG(nf_stop(&fourth) == 0, "node " NAME_FOURTH " did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&busy) == 0, "node " NAME_LEAVE " did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&watcher) == 0, "node " NAME_THIRD " did not exit cleanly");
    nf_free(&busy);
    nf_free(&watcher);
    nf_free(&fourth);
}

/* ---------------------------------------------------------------------------
 * CASE 3 -- THE GOODBYE MUST BE FRAMED, AND THIS CASE MAKES THAT HAPPEN EVERY TIME
 * ---------------------------------------------------------------------------
 * WHY A THIRD CASE, AND WHY IT EXISTS BECAUSE THE TEETH RUN FOUND A GAP
 *
 * Cases 1 and 2 assert that a departing node's SHUTDOWN is announced and handled. They
 * do so through the SHIPPED binary's own exit path, and that path -- correctly -- is
 * robust: the departing node drains each peer socket before closing it (so the close
 * is a FIN and not an RST), and the receiving node frames whatever is buffered before
 * honouring the end of the stream. TWO independent defences, either of which is
 * normally enough.
 *
 * WHICH MEANS NEITHER OF THEM IS TESTABLE THROUGH CASE 1. Removing either one leaves
 * the other in place, so the case keeps passing -- and that was measured rather than
 * assumed: with BOTH reverted, this file failed 1 run in 20, which is a real signal
 * and nowhere near a real test. A defect that reproduces one time in twenty under a
 * loaded runner is a defect that will be reported as a flake and then ignored.
 *
 * So the race is REMOVED rather than gambled on: this case makes the peer close
 * WITHOUT draining, and sends its last line immediately before doing so. That is the
 * exact sequence a graceful leave is ("send the line, then go"), it is deterministic
 * rather than probabilistic, and it puts the receiving node on the path where
 * conn_fill() has buffered a line AND seen the stream end in one call -- which is the
 * only way to reach the framing code at all.
 *
 * WHAT IT DOES NOT DO: it does not bypass the shipped exit path, and it is not a
 * second copy of case 1's claim. Case 1 asks "does a node announce its departure, and
 * do its peers handle it cleanly". This case asks a different and narrower question:
 * "when a peer's last words and the end of its stream arrive together, are those
 * words read". The second is a property of the LOOP, not of a graceful leave, and it
 * is the property case 1's robustness hides.
 *
 * THE PAYLOAD IS A SQUIT AND NOT A SHUTDOWN, deliberately. A SHUTDOWN would be read as
 * a second copy of case 1's wire claim, and its handler has its own observable
 * (link_clean_leave:) that could be satisfied by the departure case already passing.
 * A SQUIT names a THIRD server, so it exercises the same framing path and produces an
 * observable -- `fed_squit: server=<name>` -- that nothing else in this file produces,
 * and that this node had no other way to learn. It is the cheapest payload that makes
 * "the line was framed" distinguishable from "the connection closed".
 */
/* The name this test's socket claims in CASE 3. It is a different name from case 1's
 * on purpose: the two cases put two DIFFERENT nodes behind this test's end of a link
 * -- case 1's is a departing node, this one's is a node told a third server has gone
 * -- and a node refuses a second claim on a name it already holds, so reusing case 1's
 * name would have this case's handshake refused for a reason that has nothing to do
 * with framing. One name per case, and the reason is here rather than in a comment on
 * the line that would have failed. */
#define NAME_PROBE3 "irc.probe3"

/* The server this case tells the node has gone. A name no node in this file uses, so
 * the only way the node can learn about it is by reading the line this test sends. */
#define GONE_NAME "irc.gone"

static void case_c_a_last_line_arriving_with_the_eof_is_still_framed(void)
{
    nf_node_t node;
    peer_t p;
    int listen_fd;
    int port = 0;
    irc_serve_tags_t t;
    char block[IRC_MAX_TAG_OVERHEAD];
    /* Sized to the line, not to the name: the buffer renders the WHOLE outgoing SQUIT,
     * and GCC's -Wformat-truncation is right that a 64-byte name buffer cannot hold
     * it. Sized from the pieces so the arithmetic is visible rather than guessed:
     * the block, the prefix, the name, the CRLF and a NUL. */
    char gone[IRC_MAX_LINE];

    /* A THIRD SERVER NAME, and it is not a node in this file: this is a server the
     * node under test is told has gone, which is a state this file has not otherwise
     * put it in.
     *
     * IT IS A MACRO AND NOT A LOCAL, and that is a mechanical necessity rather than a
     * style preference: the name has to appear inside a string LITERAL (the needles
     * below are literals, because a needle built at runtime would make a typo in it a
     * silently unmatchable assertion rather than a compile error), and a local buffer
     * cannot be concatenated into a literal. The buffer exists only to render the
     * outgoing SQUIT. */

    listen_fd = listen_loopback(&port);
    TF_CHECK_MSG(listen_fd >= 0, "the test could not open a listening socket");

    /* The node is configured to DIAL this test's socket, so it is the initiator and
     * the handshake below is it presenting itself. It has no shed threshold: this case
     * is about framing and nothing else, and a threshold here would be one more thing
     * that could fail it for an unrelated reason. */
    memset(&g_cfg, 0, sizeof g_cfg);
    g_cfg.peers[0].name = NAME_PROBE3;
    g_cfg.peers[0].port = port;
    g_cfg.dial_ms = 1000;
    g_cfg.hs_ms = 5000;
    g_cfg.keepalive_ms = 0;
    g_cfg.dead_ms = 0;
    TF_CHECK_MSG(nf_spawn_inline_named(&node, NAME_FOURTH, child_setup) == 0,
                 "could not spawn node " NAME_FOURTH);

    p.fd = accept_deadline(listen_fd, T_IO_MS);
    close(listen_fd);
    TF_CHECK_MSG(p.fd >= 0, NAME_FOURTH " never dialled the socket this test owns");
    p.used = 0u;
    p.seen[0] = '\0';

    /* THE HANDSHAKE, so the link is ESTABLISHED and the SQUIT will be dispatched
     * rather than refused by the pre-handshake guard chain. The claim is checked
     * against the name the NODE dialled (" NAME_FOURTH ") and answered with the name
     * this socket was configured under (" NAME_PROBE3 "). */
    peer_expect_claim_as(&p, NAME_FOURTH);
    {
        char claim[512];

        (void)snprintf(claim, sizeof claim, ":" NAME_PROBE3 " FEDERATE " NAME_PROBE3
                                                  " 1700000000 " SECRET " "
                                                  IRC_SERVE_VERSION "\r\n");
        TF_CHECK_MSG(send_line(p.fd, claim) == 0,
                     "the test could not answer " NAME_FOURTH " with a FEDERATE");
    }
    TF_CHECK_MSG(nf_expect(&node, "link_established: peer=" NAME_PROBE3, T_IO_MS) == 0,
                 NAME_FOURTH " never established its link to the socket this test "
                 "owns, so the SQUIT below would be refused before it could be "
                 "framed: %s",
                 node.out);

    /* THE LINE AND THE CLOSE, IN THAT ORDER AND WITH NOTHING BETWEEN THEM.
     *
     * This is the whole case, and each half is load-bearing:
     *   the write() and the close() are adjacent, with no intervening read and no
     *   intervening delay, so the receiving node's poll() almost certainly reports
     *   readability once with BOTH the bytes and the end of the stream pending. That
     *   is the state conn_fill() reports as CONN_FILL_EOF while c->rlen is non-zero,
     *   and it is the only way to reach the framing code.
     *   the payload is a COMPLETE line -- a 2.4 block from the node's own serialiser,
     *     a legal SQUIT, a CRLF -- because a partial line is not a line and this case
     *     must not be about that.
     *
     * WHY A 2.4 BLOCK FROM THE NODE'S OWN SERIALISER, which test_fed_tags.c would
     * spell out literally: this file asserts what the guard chain DOES with a
     * well-formed line, so it wants the line a peer of this build would send. The
     * serialiser is the right source and the wrong one there; the distinction is that
     * test's, and this file says so rather than leaving a reader to wonder whether the
     * block was verified. */
    memset(&t, 0, sizeof t);
    /* The tag's origin is the SENDER -- this test's socket, under the name it claimed
     * in the handshake above. It is not the node's name: the node is the receiver, and
     * 2.4's own-origin rule means a line stamped with the receiving node's name is the
     * one thing a peer must never send it. */
    memcpy(t.origin, NAME_PROBE3, strlen(NAME_PROBE3) + 1u);
    t.epoch = 1700000000u;
    t.id = 900u;
    t.hops = 1;
    TF_CHECK_MSG(irc_serve_tags_format(&t, block, sizeof block) != 0u,
                 "the test could not serialise a 2.4 stamp, so the SQUIT it sends "
                 "would be refused before the framing under test was ever reached");
    /* THE PREFIX IS THE LINK'S NAME AND NOT THE NODE'S, which is the one detail here
     * that is easy to get backwards: the node's link to this socket is named
     * " NAME_PROBE3 ", so an inbound line has to be prefixed with that. Prefix it with
     * the node's own name instead and the guard chain refuses it at the prefix rule,
     * long before the framing under test is reached -- which is what the first
     * version of this case did, and it failed with a message pointing at framing for
     * a reason that was entirely in the test. */
    (void)snprintf(gone, sizeof gone, "@%s :" NAME_PROBE3 " SQUIT %s\r\n", block,
                   GONE_NAME);
    TF_CHECK_MSG(send_line(p.fd, gone) == 0,
                 "the test could not send the SQUIT this case is about");
    /* THE CLOSE, IMMEDIATELY, and this is the line that makes the case deterministic.
     * The node is told a server is gone and then told nothing else, in one breath,
     * which is what "send the line, then go" means and what a departing peer does. */
    close(p.fd);
    p.fd = -1;

    /* THE ASSERTION. The node applied a SQUIT naming a server it has no other way of
     * having heard about, which it could only have learned by FRAMING the bytes it had
     * already buffered when the stream ended.
     *
     * The alternative failure is specific and worth naming: if the framing is skipped,
     * the node prints `conn_close: reason=eof`, the SQUIT is never dispatched, and the
     * node's own counters say so exactly -- n_lines does not move and frame_error stays
     * 0, because the bytes were never turned into a line at all. So this is not an
     * assertion about a line being handled correctly; it is an assertion about a line
     * existing. */
    TF_CHECK_MSG(nf_expect(&node, "fed_squit: server=" GONE_NAME, T_IO_MS) == 0,
                 NAME_FOURTH " never applied the SQUIT this test sent immediately "
                 "before closing. The bytes and the end of the stream arrived together "
                 "and the node discarded them: conn_fill() reports EOF while its buffer "
                 "is non-empty, so an arm that returns on EOF without framing what it "
                 "has already read throws the peer's last line away. That is the whole "
                 "of a graceful leave -- send the line, then go -- so it is the one "
                 "sequence this cannot lose: %s",
                 node.out);
    /* AND IT WAS COUNTED, which distinguishes "framed and applied" from "found in the
     * log by accident". `fed_squit_self=` is this node's own counter for a SQUIT it
     * refused, and it must be 0: the line names a third server, so applying it is the
     * correct outcome and refusing it would be the node claiming it had gone too. */
    TF_CHECK_MSG(nf_expect_u64(&node, "fed_squit_self=", 0u, T_IO_MS) == 0,
                 NAME_FOURTH " counted a refusal of the SQUIT naming " GONE_NAME
                 ", so it treated a third server's departure as its own: %s",
                 node.out);

    TF_CHECK_MSG(nf_stop(&node) == 0, "node " NAME_FOURTH " did not exit cleanly");
    nf_free(&node);
}

int main(void)
{
    case_a_real_node_announces_its_own_departure();
    case_b_a_busy_peer_is_reported_once_and_nothing_moves();
    case_c_a_last_line_arriving_with_the_eof_is_still_framed();
    tf_done("autoscale");
    return 0;
}
