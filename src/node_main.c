/* node_main.c -- the node binary: bring the listener up and drive the loop.
 *
 * Phase 2 is the first phase in which this executable does something real.
 * Before it opened a socket, accepted one connection, printed the peer address
 * and closed it immediately; that is gone. The loop in core/poll_loop.c now
 * owns the node's lifetime: it accepts, frames, parses, drains write queues and
 * reaps.
 *
 * ---------------------------------------------------------------------------
 * THE PORT IS AN ARGUMENT, AND 0 IS MEANINGFUL
 * ---------------------------------------------------------------------------
 *   irc-serve [port]
 *
 * The port used to be the literal 6667 compiled into main(). It is an argument
 * now, and `port 0` is explicitly supported: the kernel picks an unused
 * ephemeral port, and this executable reports which one via server_port() so a
 * caller can connect to it. That is what lets the integration tests run in
 * parallel without a port table and without a retry loop.
 *
 * ---------------------------------------------------------------------------
 * [observable] OUTPUT IS PART OF THE CONTRACT
 * ---------------------------------------------------------------------------
 * The lines below are how the node reports what it did, and the integration
 * tests parse them. Two properties matter and both are deliberate:
 *
 *   - stdout is set LINE BUFFERED before anything is printed. The default is
 *     full buffering when stdout is a pipe, which would leave a parent reading
 *     this output blocked until the process exits -- and this process is
 *     supposed to keep running.
 *   - the readiness line is emitted only once poll() is about to be armed, so a
 *     caller that waits for it is waiting for a node that is actually serving.
 *     6.2 requires the same handshake for the two-node fixture, where each
 *     child writes one line once its loop is armed; this is that line.
 *
 * There is NO command surface here yet. Registration, numerics, PING/PONG and
 * everything else are Phase 3, and a reply invented now would be a fabricated
 * behaviour wearing a protocol's clothes.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/poll_loop.h"
#include "core/server.h"

/* The node's own name. It must satisfy the 2.4 tag grammar, because it is
 * stamped on every outbound irc-serve-origin tag, and a name that cannot be
 * stamped would break the never-forward-own-origin rule at the first relay.
 * Phase 6 makes this configurable. */
#define NODE_NAME "irc.test"

#define NODE_DEFAULT_PORT 6667

/* SIGTERM and SIGINT stop the loop; SIGUSR1 exists so the EINTR path is
 * reachable from outside. Neither sets SA_RESTART: the handlers must interrupt
 * poll() rather than have it silently restarted, because an EINTR that the
 * loop does not observe is an EINTR path that is never tested. */
static void on_stop_signal(int sig)
{
    (void)sig;
    poll_loop_request_stop();
}

static void on_usr1_signal(int sig)
{
    (void)sig;
    /* Deliberately empty. The point is that the signal interrupts poll() and
     * the loop survives it; the handler must not request a stop. */
}

static int install_handler(int sig, void (*handler)(int))
{
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    /* sigemptyset() cannot fail: POSIX specifies it as always returning 0, and
     * the whole mask is already zero from the memset above. Its return value is
     * deliberately not checked, because a branch on it would be dead code. */
    (void)sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* no SA_RESTART: poll() must return EINTR */
    return sigaction(sig, &sa, NULL);
}

static void usage(const char *argv0)
{
    fprintf(stderr, "usage: %s [port]\n", argv0);
    fprintf(stderr, "  port   TCP port to listen on, 0-%d; 0 asks the kernel for\n"
                    "         an ephemeral port and reports which one it chose\n",
            65535);
}

/* Parse the port argument. Returns 0 on success, -1 if it is not a number in
 * range, and 1 if no argument was given (which is not an error: the default
 * port applies). */
static int parse_port(const char *arg, int *port)
{
    char *end = NULL;
    long value;

    if (arg == NULL || arg[0] == '\0') {
        return 1;
    }
    errno = 0;
    value = strtol(arg, &end, 10);
    if (errno != 0 || end == arg || *end != '\0' || value < 0 || value > 65535) {
        return -1;
    }
    *port = (int)value;
    return 0;
}

int main(int argc, char **argv)
{
    server_t srv;
    int port = NODE_DEFAULT_PORT;
    int bound;
    int rc;

    /* Before any output: see the note on line buffering above. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    rc = parse_port((argc > 1) ? argv[1] : NULL, &port);
    if (rc < 0) {
        fprintf(stderr, "irc-serve: bad port argument: %s\n",
                (argc > 1) ? argv[1] : "");
        usage(argv[0]);
        return 2;
    }
    if (argc > 2) {
        usage(argv[0]);
        return 2;
    }

    printf("IRC-Serve Federated Node v0.1.0 initializing...\n");

    if (install_handler(SIGTERM, on_stop_signal) != 0 ||
        install_handler(SIGINT, on_stop_signal) != 0 ||
        install_handler(SIGUSR1, on_usr1_signal) != 0) {
        perror("sigaction");
        return 1;
    }
    /* A write to a peer that has already gone must surface as EPIPE from
     * send(), which is what MSG_NOSIGNAL in connection.c relies on. */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    if (server_init(&srv, NODE_NAME) != 0) {
        printf("[observable] server init failed: name=%s reason=invalid_name\n",
               NODE_NAME);
        return 1;
    }
    /* Observable per-line framing/parse output. The node's own [observable]
     * lines are the contract described at the top of this file, so the trace
     * flag is on for the shipped binary. */
    srv.trace = 1;

    if (server_listen(&srv, port) != 0) {
        printf("[observable] server startup failed: port=%d reason=%s\n",
               port, strerror(errno));
        server_shutdown(&srv);
        return 1;
    }

    /* Read the port back rather than echoing the argument: with port 0 the
     * argument is not the port, and a caller that cannot learn the real one
     * cannot connect. */
    bound = server_port(&srv);
    if (bound < 0) {
        printf("[observable] server startup failed: reason=getsockname\n");
        server_shutdown(&srv);
        return 1;
    }
    printf("[observable] tcp_bind: port=%d fd=%d state=LISTENING\n",
           bound, srv.listen_fd);
    printf("[observable] server initialized: name=%s epoch=%llu\n",
           NODE_NAME, (unsigned long long)srv.epoch);

    /* Readiness: emitted after the listener is up and immediately before the
     * loop is armed, so anything waiting on this line is talking to a serving
     * node. */
    printf("[observable] loop_running: listener_fd=%d tick_ms=%d state=ARMED\n",
           srv.listen_fd, POLL_TICK_MS);
    fflush(stdout);

    rc = poll_loop_run(&srv);
    if (rc != 0) {
        printf("[observable] loop_error: state=FAILED\n");
    }

    /* Shutdown BEFORE reporting. server_shutdown() closes every connection
     * still registered, so the numbers printed here describe the node as it
     * actually finished, not a snapshot taken mid-teardown with connections
     * still open. */
    server_shutdown(&srv);

    printf("[observable] loop_stats: ticks=%llu eintr=%llu accepted=%llu "
           "closed=%llu lines=%llu parse_reject=%llu frame_error=%llu "
           "writeq_overflow=%llu write_error=%llu partial_writes=%llu "
           "rejected_fd=%llu\n",
           (unsigned long long)srv.n_ticks, (unsigned long long)srv.n_eintr,
           (unsigned long long)srv.n_accepted, (unsigned long long)srv.n_closed,
           (unsigned long long)srv.n_lines,
           (unsigned long long)srv.n_parse_reject,
           (unsigned long long)srv.n_frame_error,
           (unsigned long long)srv.n_writeq_overflow,
           (unsigned long long)srv.n_write_error,
           (unsigned long long)srv.n_partial_writes,
           (unsigned long long)srv.n_rejected_fd);

    /* exit 0 even after a loop error: a clean shutdown is what a test asserts,
     * and a failed loop has already said so on stdout. */
    printf("[observable] server_shutdown: state=STOPPED\n");
    return (rc == 0) ? 0 : 1;
}
