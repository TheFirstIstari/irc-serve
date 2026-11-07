/* test_active_fd.c -- the active-fd list is the poll set (#176).
 *
 * server_t holds connections twice: by_fd[] is the O(1) lookup by descriptor,
 * and active_fds[] is the dense enumeration. poll_loop_step() builds its poll
 * set from the list rather than scanning FD_SETSIZE slots per tick, and the
 * list is maintained alongside by_fd[] -- appended by server_add_conn(),
 * swap-removed by server_close_conn().
 *
 * This drives the loop directly over socketpairs rather than through a spawned
 * node, and the reason is counting. Over the wire the poll set is invisible --
 * a client cannot tell whether its fd was polled or found by a scan -- so the
 * two claims here are asserted where they are visible: the list's own length
 * against the number of registered connections, and the loop's servicing of
 * every fd (one line in per client, N lines framed) against a step. The
 * close-all half then asserts the list drains to empty through the same reaper
 * the loop uses, rather than through a second teardown path.
 *
 * N is 16 rather than 1 for one reason: a list of one cannot distinguish "the
 * loop walked the list" from "the loop looked at slot 0". Sixteen needs the
 * list to actually enumerate.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/connection.h"
#include "core/poll_loop.h"
#include "core/server.h"
#include "harness/test_util.h"

/* Sixteen clients. See the file header for why it is not one. */
#define NCLI 16

static int client_fds[NCLI];
static int feed_fds[NCLI];

static void make_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    TF_CHECK(flags >= 0);
    TF_CHECK_MSG(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
                 "could not make socketpair end nonblocking");
}

/* One line per client, then exactly one step must frame all of them. If the
 * poll set missed an fd, that client's bytes sit unread and the count falls
 * short -- so the count is the assertion that the set held N + listeners. */
static void feed_all(void)
{
    static const char line[] = "PING test\r\n";
    int i;

    for (i = 0; i < NCLI; i++) {
        ssize_t w = write(feed_fds[i], line, sizeof line - 1u);

        TF_CHECK_MSG(w == (ssize_t)(sizeof line - 1u),
                     "short write to client %d", i);
    }
}

int main(void)
{
    server_t s;
    int i;

    TF_CHECK_MSG(server_init(&s, "irc.test") == 0, "server_init failed");
    /* One listener, so the poll set under test is N clients plus listeners. */
    TF_CHECK_MSG(server_listen(&s, 0) == 0, "server_listen failed");

    for (i = 0; i < NCLI; i++) {
        int pair[2];
        conn_t *c;

        TF_CHECK_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0,
                     "socketpair %d failed", i);
        make_nonblocking(pair[0]);
        make_nonblocking(pair[1]);
        c = conn_new(pair[0], CONN_CLIENT);
        TF_CHECK_MSG(c != NULL, "conn_new %d failed", i);
        TF_CHECK_MSG(server_add_conn(&s, c) == 0,
                     "server_add_conn %d failed", i);
        client_fds[i] = pair[0];
        feed_fds[i] = pair[1];
    }

    /* --- the list tracks registration --- */
    TF_CHECK_MSG(s.nactive == (size_t)NCLI, "nactive=%zu, want %d",
                 s.nactive, NCLI);
    TF_CHECK_MSG(s.nconns == (size_t)NCLI, "nconns=%zu, want %d",
                 s.nconns, NCLI);

    /* --- one step services every fd in the set --- */
    feed_all();
    TF_CHECK_MSG(poll_loop_step(&s, 0) == 0, "poll_loop_step failed");
    TF_CHECK_MSG(s.n_lines == (uint64_t)NCLI, "n_lines=%llu, want %d",
                 (unsigned long long)s.n_lines, NCLI);
    TF_CHECK_MSG(s.nactive == (size_t)NCLI, "step moved nactive to %zu",
                 s.nactive);

    /* --- close-all empties the list --- */
    for (i = 0; i < NCLI; i++) {
        conn_t *c = server_conn(&s, client_fds[i]);

        TF_CHECK_MSG(c != NULL, "client %d vanished before close", i);
        conn_mark_closing(c);
    }
    TF_CHECK_MSG(server_reap(&s) == NCLI, "reap did not close all");
    TF_CHECK_MSG(s.nactive == 0, "nactive=%zu after close-all", s.nactive);
    TF_CHECK_MSG(s.nconns == 0, "nconns=%zu after close-all", s.nconns);
    for (i = 0; i < NCLI; i++) {
        TF_CHECK_MSG(server_conn(&s, client_fds[i]) == NULL,
                     "client %d still registered after close-all", i);
    }

    /* --- the loop still steps with only the listener left --- */
    TF_CHECK_MSG(poll_loop_step(&s, 0) == 0, "step on empty set failed");

    for (i = 0; i < NCLI; i++) {
        close(feed_fds[i]);
    }
    server_shutdown(&s);
    tf_done("ActiveFd");
    return 0;
}
