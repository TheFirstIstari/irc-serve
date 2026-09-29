/* node_fixture.h -- spawn a real node in a child process and talk to it.
 *
 * Authority: docs/SERVER_DESIGN.md 6.1 (servers bind port 0 and report the
 * chosen port) and 6.2 (the two-node harness: two CHILD PROCESSES over real
 * TCP, with a deterministic readiness handshake).
 *
 * ---------------------------------------------------------------------------
 * HOW THE EPHEMERAL PORT REACHES THE TEST
 * ---------------------------------------------------------------------------
 * Over the child's stdout, as one line. The child prints the port the kernel
 * chose and then, separately, a readiness line -- and the parent waits for the
 * READINESS line, not the port line.
 *
 * The distinction is the whole point of 6.2's "deterministic readiness
 * handshake". A port line alone only proves bind() returned; it says nothing
 * about whether the loop is armed and able to serve. So the sequence the parent
 * requires is:
 *
 *   [fixture] port=NNNNN          (inline children)  or
 *   [observable] tcp_bind: port=N (the shipped binary)
 *   ... then ...
 *   [fixture] ready               (inline children)  or
 *   [observable] loop_running:    (the shipped binary)
 *
 * and only the second line means "connect to me now". Every wait in this file
 * is a deadline wait over select(): no fixed sleep anywhere (6.3).
 *
 * ---------------------------------------------------------------------------
 * DOES THIS SUPPORT THE PHASE 6 TWO-NODE FIXTURE?
 * ---------------------------------------------------------------------------
 * Yes, and that is why it is factored this way rather than as a bespoke
 * per-test helper. 6.2 wants node A and node B as two child processes over real
 * TCP, each announcing readiness, and then asserting convergence. Everything
 * needed for that is already here: two independent children, port 0 with a
 * readback, a readiness line, and a way to inject a test-provided dispatch and
 * tick hook into a child so the parent can drive the scenario.
 *
 * What is NOT here, and would be added rather than replaced:
 *   - a second node dialing the first. That needs the pre-resolved-address
 *     entry point (6.1's peer list) to be configurable, and the dial FSM is
 *     already in place and tested.
 *   - asserting convergence, which is Phase 6 behaviour to assert.
 *   - a readiness signal on a channel OTHER than stdout, in case two children's
 *     output would be ambiguous. 6.2 explicitly allows "one line to stdout (or
 *     to fd 3)", and the read is already per-child, so interleaved output from
 *     two children is not actually a problem.
 *
 * ---------------------------------------------------------------------------
 * ONE THING A TEST WITH CLIENTS HAS TO DO ITSELF, AND IT IS WORTH NAMING
 * ---------------------------------------------------------------------------
 * The child installs NO command dispatch. s->dispatch is NULL on a fresh
 * server_t, which is the honest Phase 2 state and is exactly right for a
 * peer-only test: the federation handshake is answered by the link module's own
 * wrapper, which fed_open() installs over whatever was there.
 *
 * A test that attaches a CLIENT has to install core/commands.c's
 * commands_dispatch itself, and it has to do so BEFORE fed_open() -- fed_open()
 * saves the dispatch that is already there and replaces it, so a
 * commands_dispatch installed afterwards would become the node's whole dispatch
 * and a peer line would never reach the guard chain at all. The symptom is
 * silent and total: the client connects, registers nothing and receives no
 * numerics, and no [observable] line says why. test_fed_roster.c's child_setup
 * is the worked example.
 *
 * THAT IS ALSO THE ORDERING 3's "one dispatch" claim needs. The node's dispatch
 * is the federation wrapper, its inner is commands_dispatch, and a peer line
 * reaches fed_dispatch() THROUGH the client dispatch on the strength of
 * src->kind. If they were two dispatch functions, nothing in a test would notice
 * -- which is why the claim is made where both live.
 */
#ifndef TEST_HARNESS_NODE_FIXTURE_H
#define TEST_HARNESS_NODE_FIXTURE_H

#include <stdint.h>
#include <sys/types.h>

#include "core/server.h"

typedef enum {
    NF_BINARY, /* fork + exec the real irc-serve binary  */
    NF_INLINE  /* fork and run server_t + poll_loop_run() in the child */
} nf_mode_t;

typedef struct {
    pid_t     pid;
    int       port;      /* the ephemeral port the child reported */
    int       out_fd;    /* the child's stdout, read for [observable] lines */
    char     *out;       /* everything read from it so far */
    size_t    out_len;
    size_t    out_cap;
    nf_mode_t mode;
    int       reaped;
} nf_node_t;

/* Called in the CHILD, after server_init() and server_listen() and before the
 * loop is armed. This is where a test installs its dispatch, its tick hook, or
 * fills the descriptor table -- i.e. everything that must be true of the node
 * before anyone may connect to it. */
typedef void (*nf_setup_fn)(server_t *s);

/* Fork a child running the real irc-serve binary on port 0. Blocks until the
 * child reports readiness. Returns 0 on success, -1 on failure. */
int nf_spawn_binary(nf_node_t *n);

/* As nf_spawn_binary(), but with the binary's OWN argument vector, for a test
 * that needs to drive the shipped command line (--name, --secret, --peer).
 *
 * `argv` is the FULL vector INCLUDING argv[0] and MUST be NULL-terminated;
 * passing NULL is an error rather than a default, because a caller that
 * reached for this and passed NULL wanted arguments and would silently get the
 * bare one. The strings are only read in the child, before execv(), so the
 * caller may free them as soon as the spawn returns.
 *
 * The readiness and port lines are read exactly as they are for
 * nf_spawn_binary() (6.1: servers bind port 0 and report the chosen port), so
 * a test can mix the two forms in one run. */
int nf_spawn_binary_argv(nf_node_t *n, char *const argv[]);

/* Fork a child that builds its own server_t, binds port 0, calls `setup` (may
 * be NULL), then runs the real loop until it is signalled to stop. Blocks
 * until the child reports readiness. Returns 0 on success, -1 on failure.
 *
 * The child runs the SAME core loop the binary does, so a test that needs
 * control over the command surface tests the real loop rather than a copy of
 * it. What it does not do is exercise the shipped executable -- use
 * nf_spawn_binary() for that. */
int nf_spawn_inline(nf_node_t *n, nf_setup_fn setup);

/* As nf_spawn_inline(), with the child naming ITSELF `name` rather than the
 * harness default.
 *
 * This exists because 2.3's name uniqueness is a property of the NODE's name
 * and cannot be exercised any other way: a test that wants two nodes which
 * both claim to be `irc.a` has to be able to name them, and the harness's own
 * default name is exactly what it could not override before. The same-named
 * handshake case in test_fed_handshake.c is the caller that needed it.
 *
 * `name` must satisfy 2.4's tag grammar (server_init() refuses anything else
 * and the child exits), must be non-NULL and non-empty, and is copied by the
 * fork rather than retained: the child is a separate process, so nothing the
 * caller does to the string afterwards can be seen. */
int nf_spawn_inline_named(nf_node_t *n, const char *name, nf_setup_fn setup);

/* Wait until `needle` appears in the child's output, or the deadline passes.
 * Returns 0 on success, -1 on timeout, and prints what the child did say. */
int nf_expect(nf_node_t *n, const char *needle, int timeout_ms);

/* As nf_expect(), but re-sends `sig` to the child on every polling iteration
 * until the needle appears. This is how the EINTR test reaches a signal that
 * reliably lands INSIDE poll() without a fixed sleep: the child spends
 * milliseconds blocked in poll() and microseconds between iterations, so a
 * retried signal lands in the wait almost immediately, and the retry is driven
 * by the same select() loop the wait already uses. */
int nf_expect_retry_signal(nf_node_t *n, const char *needle, int sig,
                           int timeout_ms);


/* Find `key` (for example "accepted=") in the child's output and parse the
 * unsigned integer that follows the LAST occurrence of it. Returns 0 on
 * success, -1 if the key is not present or the value does not parse.
 *
 * Last, not first: the node's counters are monotonic and republished as they
 * change, so the most recent report is the current state. */
int nf_find_u64(nf_node_t *n, const char *key, uint64_t *out);

/* Wait until the node's latest value for `key` equals `expected`, or the
 * deadline passes. Returns 0 on success, -1 on timeout. Use this rather than
 * nf_find_u64() when the event being waited for is observable on the wire as
 * well: seeing an EOF does not mean the child has published the counter yet,
 * and a read-once check is a race that passes or fails on the scheduler. */
int nf_expect_u64(nf_node_t *n, const char *key, uint64_t expected,
                  int timeout_ms);

/* As nf_expect_u64(), for a lower bound. */
int nf_expect_u64_ge(nf_node_t *n, const char *key, uint64_t minimum,
                     int timeout_ms);

/* Signal the child to stop (SIGTERM), wait for it to exit, and return its exit
 * status -- or -1 if it had to be killed, -2 on a wait failure. A clean stop
 * must be status 0; anything else is a finding. */
int nf_stop(nf_node_t *n);

/* Kill the child immediately and reap it. Safe to call after nf_stop(), and
 * safe to call from a test's failure path so a failed test does not leave a
 * server holding a port. */
void nf_kill(nf_node_t *n);

/* Close descriptors and free buffers. Does NOT kill; call nf_kill() or
 * nf_stop() first. */
void nf_free(nf_node_t *n);

/* Raise RLIMIT_NOFILE's soft limit to the hard limit. Returns 0 on success, -1
 * if it could not be raised. Needed by the FD_SETSIZE test, which has to hold
 * more than FD_SETSIZE descriptors open at once; on a machine whose hard limit
 * is below that the test must say so rather than quietly pass. */
int nf_raise_fd_limit(void);

/* Open /dev/null until every descriptor below `target` is occupied, so the
 * next accept() is forced to return one at or above it. Returns 0 on success,
 * -1 if the process ran out of descriptors first (which the caller must treat
 * as a real failure, not a skip). */
int nf_fill_descriptors_below(int target);

#endif /* TEST_HARNESS_NODE_FIXTURE_H */
