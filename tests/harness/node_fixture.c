/* node_fixture.c -- see node_fixture.h. */
#include "harness/node_fixture.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "harness/test_util.h"

#include "core/connection.h"
#include "core/message.h"
#include "core/poll_loop.h"

/* The child used by nf_spawn_inline(). Its name must satisfy the 2.4 tag
 * grammar, exactly as the shipped node's does. */
#define NF_NODE_NAME "irc.fixture"

/* How often a deadline loop checks. Short, so a response is noticed promptly;
 * a polling interval, never an assumption about the other side. */
#define NF_POLL_MS 20

/* Generous, because these are deadlines for a forked child on a possibly
 * loaded CI machine, not estimates of how long anything should take. */
#define NF_READY_TIMEOUT_MS 15000
#define NF_STOP_TIMEOUT_MS 15000

#ifndef NF_SERVER_BIN
/* Set by CMake from $<TARGET_FILE:irc-serve> (see tests/integration). A build
 * that did not define it cannot run the tests that need the shipped binary. A
 * compile error rather than a runtime check, because an empty fallback would
 * make the check that follows provably dead -- and a dead "the build is
 * misconfigured" branch is exactly the kind that stops being noticed. */
#error "NF_SERVER_BIN must name the irc-serve executable"
#endif

static uint64_t nf_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000L);
}

/* Wait up to `ms` for the child to be reapable, polling with WNOHANG. This is a
 * wait-for-exit with a deadline, not a fixed sleep: it returns the instant the
 * child is gone. select() with no descriptors is the portable way to yield
 * between polls without naming a sleep. */
static int wait_child(pid_t pid, int ms, int *status)
{
    uint64_t deadline = nf_now_ms() + (uint64_t)ms;

    for (;;) {
        pid_t r = waitpid(pid, status, WNOHANG);
        struct timeval tv;

        if (r == pid) {
            return 0;
        }
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (nf_now_ms() >= deadline) {
            return 1; /* still running */
        }
        tv.tv_sec = 0;
        tv.tv_usec = NF_POLL_MS * 1000;
        (void)select(0, NULL, NULL, NULL, &tv);
    }
}

/* ---------------------------------------------------------------------------
 * Reading the child's output
 * ---------------------------------------------------------------------------
 * Everything the child prints is kept, and needles are matched against the
 * accumulated text, so a line that arrives in pieces still matches. The
 * accumulate-everything design is also what makes a failure diagnosable: a
 * timeout prints what the child actually said.
 */

static int out_append(nf_node_t *n, const char *bytes, size_t len)
{
    if (n->out_len + len + 1u > n->out_cap) {
        size_t want = (n->out_cap == 0) ? 8192u : n->out_cap;
        char *grown;

        while (want < n->out_len + len + 1u) {
            want *= 2u;
        }
        grown = (char *)realloc(n->out, want);
        if (grown == NULL) {
            return -1;
        }
        n->out = grown;
        n->out_cap = want;
    }
    memcpy(n->out + n->out_len, bytes, len);
    n->out_len += len;
    n->out[n->out_len] = '\0';
    return 0;
}

/* Read whatever the child has written. Returns 1 if bytes were appended, 0 if
 * nothing was available before the deadline, -1 on a hard read error. */
static int out_pump(nf_node_t *n, uint64_t deadline)
{
    char chunk[4096];
    struct timeval tv;
    fd_set rfds;
    uint64_t left = (deadline > nf_now_ms()) ? (deadline - nf_now_ms()) : 0;
    ssize_t got;
    int rc;

    if (left == 0) {
        return 0;
    }
    FD_ZERO(&rfds);
    FD_SET(n->out_fd, &rfds);
    tv.tv_sec = (time_t)(left / 1000u);
    tv.tv_usec = (suseconds_t)((left % 1000u) * 1000u);

    rc = select(n->out_fd + 1, &rfds, NULL, NULL, &tv);
    if (rc < 0) {
        return (errno == EINTR) ? 0 : -1;
    }
    if (rc == 0) {
        return 0;
    }
    got = read(n->out_fd, chunk, sizeof chunk);
    if (got <= 0) {
        return 0; /* child closed stdout, or nothing yet */
    }
    return (out_append(n, chunk, (size_t)got) == 0) ? 1 : -1;
}

/* The single wait implementation; nf_expect() is the header-declared entry
 * point. Split only so the timeout is a parameter rather than a constant buried
 * in the body. */
static int nf_expect_with_timeout(nf_node_t *n, const char *needle,
                                  int timeout_ms)
{
    uint64_t deadline;

    if (n == NULL || needle == NULL) {
        return -1;
    }
    deadline = nf_now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        if (n->out != NULL && strstr(n->out, needle) != NULL) {
            return 0;
        }
        if (out_pump(n, deadline) < 0) {
            break;
        }
        if (nf_now_ms() >= deadline) {
            break;
        }
    }
    fprintf(stderr, "nf_expect: TIMEOUT after %d ms waiting for \"%s\"\n",
            timeout_ms, needle);
    fprintf(stderr, "nf_expect: child output was:\n%s\n",
            (n->out != NULL) ? n->out : "(nothing)");
    return -1;
}

int nf_expect(nf_node_t *n, const char *needle, int timeout_ms)
{
    return nf_expect_with_timeout(n, needle, timeout_ms);
}

int nf_expect_retry_signal(nf_node_t *n, const char *needle, int sig,
                           int timeout_ms)
{
    uint64_t deadline;

    if (n == NULL || needle == NULL) {
        return -1;
    }
    deadline = nf_now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        if (n->out != NULL && strstr(n->out, needle) != NULL) {
            return 0;
        }
        /* Re-send before each wait. The child is either blocked in poll() --
         * in which case this interrupts it -- or between iterations, in which
         * case the next one lands there. Either way the loop makes progress and
         * no fixed timing is assumed. */
        if (kill(n->pid, sig) != 0 && errno != ESRCH) {
            break;
        }
        if (out_pump(n, nf_now_ms() + NF_POLL_MS) < 0) {
            break;
        }
        if (nf_now_ms() >= deadline) {
            break;
        }
    }
    fprintf(stderr, "nf_expect_retry_signal: TIMEOUT after %d ms waiting for "
            "\"%s\" (signal %d)\n", timeout_ms, needle, sig);
    fprintf(stderr, "nf_expect_retry_signal: child output was:\n%s\n",
            (n->out != NULL) ? n->out : "(nothing)");
    return -1;
}

/* Find the value of the LAST occurrence of `key` in the child's output.
 *
 * LAST, not first, and deliberately: the node's counters are monotonic and the
 * child republishes them as they change, so the most recent report IS the
 * current state. Reading the first occurrence would find the report from before
 * the event being waited for, which turns every counter assertion into a race.
 * Returns 0 on success, -1 if the key is not present or the value does not
 * parse. */
int nf_find_u64(nf_node_t *n, const char *key, uint64_t *out)
{
    const char *at = NULL;
    const char *scan;
    size_t klen;
    uint64_t value = 0;

    if (n == NULL || key == NULL || out == NULL || n->out == NULL) {
        return -1;
    }
    klen = strlen(key);
    for (scan = n->out; (scan = strstr(scan, key)) != NULL; scan += klen) {
        const char *digits = scan + klen;
        int ndigits = 0;
        uint64_t v = 0;

        while (*digits >= '0' && *digits <= '9') {
            v = v * 10u + (uint64_t)(*digits - '0');
            digits++;
            ndigits++;
        }
        if (ndigits == 0) {
            continue; /* the key matched somewhere with no number after it */
        }
        at = scan + klen;
        value = v;
    }
    if (at == NULL) {
        return -1;
    }
    *out = value;
    return 0;
}

/* Wait until the node's latest value for `key` is exactly `expected`, or the
 * deadline passes. A deadline wait, not a read-and-hope: a test that checks a
 * counter once after seeing an EOF on the wire is racing the child that
 * published it, and that race passes or fails depending on the scheduler.
 * Returns 0 on success, -1 on timeout (printing the last value seen). */
int nf_expect_u64(nf_node_t *n, const char *key, uint64_t expected,
                  int timeout_ms)
{
    uint64_t deadline = nf_now_ms() + (uint64_t)timeout_ms;
    uint64_t seen = 0;

    for (;;) {
        if (nf_find_u64(n, key, &seen) == 0 && seen == expected) {
            return 0;
        }
        if (out_pump(n, nf_now_ms() + NF_POLL_MS) < 0) {
            break;
        }
        if (nf_now_ms() >= deadline) {
            break;
        }
    }
    fprintf(stderr, "nf_expect_u64: TIMEOUT after %d ms waiting for %s%llu; "
            "last seen was %llu\n", timeout_ms, key,
            (unsigned long long)expected, (unsigned long long)seen);
    fprintf(stderr, "nf_expect_u64: child output was:\n%s\n",
            (n->out != NULL) ? n->out : "(nothing)");
    return -1;
}

/* As nf_expect_u64(), but for a lower bound rather than an exact value. */
int nf_expect_u64_ge(nf_node_t *n, const char *key, uint64_t minimum,
                     int timeout_ms)
{
    uint64_t deadline = nf_now_ms() + (uint64_t)timeout_ms;
    uint64_t seen = 0;

    for (;;) {
        if (nf_find_u64(n, key, &seen) == 0 && seen >= minimum) {
            return 0;
        }
        if (out_pump(n, nf_now_ms() + NF_POLL_MS) < 0) {
            break;
        }
        if (nf_now_ms() >= deadline) {
            break;
        }
    }
    fprintf(stderr, "nf_expect_u64_ge: TIMEOUT after %d ms waiting for %s>=%llu; "
            "last seen was %llu\n", timeout_ms, key,
            (unsigned long long)minimum, (unsigned long long)seen);
    fprintf(stderr, "nf_expect_u64_ge: child output was:\n%s\n",
            (n->out != NULL) ? n->out : "(nothing)");
    return -1;
}

/* ---------------------------------------------------------------------------
 * The inline child
 * ---------------------------------------------------------------------------
 * It runs the real core loop. The tick hook chains the test's hook and watches
 * for the parent going away, so a test that fails partway through does not
 * leave a child holding a port for the rest of the run.
 */

static pid_t g_child_ppid = 0;
static server_tick_fn g_test_tick = NULL;

static void nf_child_print_stats(const server_t *s);

/* Last counters republished by the tick, so the republication is change-driven
 * rather than per-tick. */
static size_t g_last_nconns = (size_t)-1;
static uint64_t g_last_closed = 0;
static uint64_t g_last_accepted = 0;

static void nf_on_stop(int sig)
{
    (void)sig;
    poll_loop_request_stop();
}

static void nf_on_usr1(int sig)
{
    /* Empty on purpose: the signal exists to interrupt poll() and nothing
     * else. A handler that requested a stop would defeat the point. */
    (void)sig;
}

static void nf_child_tick(server_t *s, uint64_t now_ms)
{
    /* Chain to whatever the test installed, then check for parent death. */
    if (g_test_tick != NULL) {
        g_test_tick(s, now_ms);
    }
    if (getppid() != g_child_ppid) {
        /* The test process is gone: a failed test must not leave this node
         * running. Exit without touching the parent's state. */
        _exit(0);
    }

    /* Republish the counters whenever they change, so a test can assert on a
     * mid-run state ("the flooder is gone and the survivor is not") instead of
     * only on the totals at exit. Driven off a change, not off every tick: a
     * line per 50 ms tick would fill the pipe the parent reads and deadlock it
     * against a child that is waiting to write. */
    if (s->nconns != g_last_nconns || s->n_closed != g_last_closed ||
        s->n_accepted != g_last_accepted) {
        g_last_nconns = s->nconns;
        g_last_closed = s->n_closed;
        g_last_accepted = s->n_accepted;
        nf_child_print_stats(s);
    }
}

static void nf_child_print_stats(const server_t *s)
{
    /* The same key names as the shipped binary's loop_stats line, so a test can
     * read a counter with one helper whichever way the node was hosted. */
    printf("[fixture] stats accepted=%llu closed=%llu lines=%llu "
           "parse_reject=%llu frame_error=%llu writeq_overflow=%llu "
           "write_error=%llu partial_writes=%llu eintr=%llu rejected_fd=%llu "
           "nconns=%llu dial_connected=%llu dial_failed=%llu\n",
           (unsigned long long)s->n_accepted, (unsigned long long)s->n_closed,
           (unsigned long long)s->n_lines,
           (unsigned long long)s->n_parse_reject,
           (unsigned long long)s->n_frame_error,
           (unsigned long long)s->n_writeq_overflow,
           (unsigned long long)s->n_write_error,
           (unsigned long long)s->n_partial_writes,
           (unsigned long long)s->n_eintr,
           (unsigned long long)s->n_rejected_fd,
           (unsigned long long)s->nconns,
           (unsigned long long)s->n_dial_connected,
           (unsigned long long)s->n_dial_failed);
    fflush(stdout);
}

static int nf_child_run(nf_setup_fn setup)
{
    server_t *s;
    int rc;

    /* Line buffering BEFORE anything is printed, or a parent reading this
     * child's output waits for the process to exit. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    (void)signal(SIGPIPE, SIG_IGN);
    (void)signal(SIGTERM, nf_on_stop);
    (void)signal(SIGINT, nf_on_stop);
    (void)signal(SIGUSR1, nf_on_usr1);
    g_child_ppid = getppid();

    s = (server_t *)calloc(1, sizeof *s);
    if (s == NULL) {
        return 1;
    }
    if (server_init(s, NF_NODE_NAME) != 0) {
        fprintf(stderr, "fixture: server_init failed\n");
        return 1;
    }
    if (server_listen(s, 0) != 0) {
        fprintf(stderr, "fixture: server_listen failed: %s\n", strerror(errno));
        return 1;
    }

    /* The test's hook runs here: after the listener exists (so it owns a small
     * descriptor) and before anything may connect (so the node is in its final
     * shape when the parent is told it is ready). */
    if (setup != NULL) {
        setup(s);
    }
    /* The test's tick hook is chained, not replaced: the fixture's own check
     * for parent death has to run whether or not the test wanted a tick. */
    g_test_tick = s->on_tick;
    s->on_tick = nf_child_tick;

    printf("[fixture] port=%d\n", server_port(s));
    printf("[fixture] ready\n");
    fflush(stdout);

    rc = poll_loop_run(s);

    /* Shutdown FIRST, then report. server_shutdown() closes whatever is still
     * registered, so printing before it would report a node that is on its way
     * out with connections still open -- and a test asserting "every accepted
     * connection was closed" would be asserting something untrue about a
     * snapshot taken mid-teardown. */
    server_shutdown(s);
    nf_child_print_stats(s);
    free(s);
    return rc;
}

/* ---------------------------------------------------------------------------
 * Spawning
 * ---------------------------------------------------------------------------
 */

static int nf_finish_spawn(nf_node_t *n, int expect_port_line)
{
    uint64_t deadline = nf_now_ms() + (uint64_t)NF_READY_TIMEOUT_MS;
    static const char *const ready_needles[] = {
        "[observable] loop_running:", /* the shipped binary */
        "[fixture] ready"            /* an inline child */
    };
    uint64_t value = 0;
    size_t i;

    for (;;) {
        int ready = 0;

        for (i = 0; i < sizeof ready_needles / sizeof ready_needles[0]; i++) {
            if (n->out != NULL && strstr(n->out, ready_needles[i]) != NULL) {
                ready = 1;
            }
        }
        if (ready) {
            break;
        }
        if (out_pump(n, deadline) < 0) {
            break;
        }
        if (nf_now_ms() >= deadline) {
            fprintf(stderr, "nf_spawn: TIMEOUT waiting for node readiness\n");
            fprintf(stderr, "nf_spawn: child output was:\n%s\n",
                    (n->out != NULL) ? n->out : "(nothing)");
            return -1;
        }
    }

    /* Readiness first, port second: the port line only proves bind() returned,
     * and the port is useless until the loop is armed. The binary reports the
     * port it actually bound (which is not the argument when it was 0). */
    if (expect_port_line) {
        if (nf_find_u64(n, "tcp_bind: port=", &value) != 0) {
            fprintf(stderr, "nf_spawn: no tcp_bind port line in:\n%s\n",
                    (n->out != NULL) ? n->out : "(nothing)");
            return -1;
        }
    } else if (nf_find_u64(n, "[fixture] port=", &value) != 0) {
        fprintf(stderr, "nf_spawn: no fixture port line in:\n%s\n",
                (n->out != NULL) ? n->out : "(nothing)");
        return -1;
    }
    if (value == 0 || value > 65535) {
        fprintf(stderr, "nf_spawn: implausible port %llu\n",
                (unsigned long long)value);
        return -1;
    }
    n->port = (int)value;
    return 0;
}

static int nf_spawn_common(nf_node_t *n, nf_mode_t mode, nf_setup_fn setup)
{
    int pipefd[2];
    pid_t pid;

    memset(n, 0, sizeof *n);
    n->out_fd = -1;
    n->port = -1;

    /* A pipe, so the child gets a stdout the parent can read. The child's real
     * stderr is left alone so its diagnostics still reach the CTest log. */
    if (pipe(pipefd) != 0) {
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) {
            _exit(126);
        }
        close(pipefd[1]);
        if (mode == NF_BINARY) {
            char *argv[3];

            argv[0] = (char *)"irc-serve";
            argv[1] = (char *)"0";
            argv[2] = NULL;
            execv(NF_SERVER_BIN, argv);
            _exit(127);
        }
        _exit(nf_child_run(setup));
    }

    close(pipefd[1]);
    n->pid = pid;
    n->out_fd = pipefd[0];
    n->mode = mode;

    if (nf_finish_spawn(n, (mode == NF_BINARY) ? 1 : 0) != 0) {
        nf_kill(n);
        return -1;
    }
    /* Registered so a failing TF_CHECK can kill this node instead of leaving
     * it running for the rest of the suite. */
    tf_register(n);
    return 0;
}

int nf_spawn_binary(nf_node_t *n)
{
    return nf_spawn_common(n, NF_BINARY, NULL);
}

int nf_spawn_inline(nf_node_t *n, nf_setup_fn setup)
{
    return nf_spawn_common(n, NF_INLINE, setup);
}

int nf_stop(nf_node_t *n)
{
    int status = 0;
    int rc;

    if (n == NULL || n->pid <= 0) {
        return -1;
    }
    (void)kill(n->pid, SIGTERM);
    rc = wait_child(n->pid, NF_STOP_TIMEOUT_MS, &status);
    if (rc == 1) {
        fprintf(stderr, "nf_stop: child did not exit within %d ms; killing\n",
                NF_STOP_TIMEOUT_MS);
        nf_kill(n);
        return -1;
    }
    if (rc < 0) {
        return -2;
    }
    n->reaped = 1;
    tf_unregister(n);

    /* Drain whatever the child printed on its way out, so a test can read the
     * final counters. Best effort: the child may already be gone. */
    if (n->out_fd >= 0) {
        uint64_t deadline = nf_now_ms() + 200u;

        while (out_pump(n, deadline) > 0) {
            deadline = nf_now_ms() + 50u;
        }
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "nf_stop: child killed by signal %d\n", WTERMSIG(status));
        return -1;
    }
    return -1;
}

void nf_kill(nf_node_t *n)
{
    int status = 0;

    if (n == NULL || n->pid <= 0) {
        return;
    }
    if (!n->reaped) {
        (void)kill(n->pid, SIGKILL);
        (void)wait_child(n->pid, 2000, &status);
        n->reaped = 1;
    }
    n->pid = 0;
}

void nf_free(nf_node_t *n)
{
    if (n == NULL) {
        return;
    }
    if (n->out_fd >= 0) {
        close(n->out_fd);
        n->out_fd = -1;
    }
    free(n->out);
    n->out = NULL;
    n->out_len = 0;
    n->out_cap = 0;
}

int nf_raise_fd_limit(void)
{
    struct rlimit rl;

    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        return -1;
    }
    if (rl.rlim_cur >= rl.rlim_max) {
        return 0;
    }
    rl.rlim_cur = rl.rlim_max;
    return setrlimit(RLIMIT_NOFILE, &rl);
}

int nf_fill_descriptors_below(int target)
{
    for (;;) {
        int fd = open("/dev/null", O_RDONLY);

        if (fd < 0) {
            return -1; /* out of descriptors: a real failure, not a skip */
        }
        if (fd >= target) {
            /* Everything below `target` is now occupied, so the next accept()
             * must be handed a descriptor at or above it. This one is not
             * needed. */
            close(fd);
            return 0;
        }
    }
}
