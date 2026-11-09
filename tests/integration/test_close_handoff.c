/* test_close_handoff.c -- MT 2.3 (#242): the reaper never frees a conn under a writer.
 *
 * At N > 0 the writers own conn_pump() under each conn's wq_lock, and the
 * reaper's close()+free() must not run while a writer holds that lock
 * mid-drain. The guarantee is structural, not timing-only: server_reap()
 * takes wq_lock with trylock, and a held lock skips the conn this tick
 * WITHOUT touching the 2 s wq_close_at deadline (a draining writer is
 * progress, not stalling). The deadline still bounds the deferral for a peer
 * that never reads.
 *
 * In-process and deterministic: no writers are started (writer_threads > 0 is
 * what arms the reaper path; the kick is a no-op with no pool). The test holds
 * wq_lock itself to stand in for a writer inside conn_pump(), so the trylock
 * half is exercised without a race, and the deadline half by forcing the
 * stored timestamp into the past.
 */
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/connection.h"
#include "core/server.h"
#include "harness/test_util.h"

int main(void)
{
    server_t s;
    int pair[2];
    conn_t *c;
    int fd;
    static const char line[] = ":irc.fixture NOTICE you :HELD\r\n";

    TF_CHECK_MSG(server_init(&s, "irc.test") == 0, "server_init failed");
    /* Arms the N > 0 reaper path. No server_writers_start(): the test holds
     * wq_lock directly, so no thread is needed and the reap calls below are
     * race-free by construction. */
    server_set_writer_threads(&s, 4);

    TF_CHECK_MSG(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0,
                 "socketpair failed");
    {
        int flags = fcntl(pair[0], F_GETFL, 0);

        TF_CHECK(flags >= 0);
        TF_CHECK_MSG(fcntl(pair[0], F_SETFL, flags | O_NONBLOCK) == 0,
                     "could not make server end nonblocking");
    }
    c = conn_new(pair[0], CONN_CLIENT);
    TF_CHECK_MSG(c != NULL, "conn_new failed");
    TF_CHECK_MSG(server_add_conn(&s, c) == 0, "server_add_conn failed");
    fd = pair[0];

    TF_CHECK_MSG(server_queue(&s, c, line, sizeof line - 1u) == 0,
                 "server_queue failed");
    conn_mark_closing(c);

    /* --- a writer mid-drain: the reaper must not touch the conn --- */
    TF_CHECK_MSG(pthread_mutex_lock(&c->wq_lock) == 0, "lock failed");
    TF_CHECK_MSG(server_reap(&s) == 0,
                 "reaper closed a conn while wq_lock was held by a writer");
    TF_CHECK_MSG(server_conn(&s, fd) == c,
                 "reaper detached a conn while wq_lock was held");
    /* The deadline must not have moved: a held lock is progress, and the
     * skip above must leave wq_close_at alone so a slow drain keeps its
     * full bound. Zero means the trylock skip fired before any deadline
     * write, which is the ordering the handoff requires. */
    TF_CHECK_MSG(s.wq_close_at[fd] == 0,
                 "trylock skip touched the deadline (wq_close_at=%llu)",
                 (unsigned long long)s.wq_close_at[fd]);
    TF_CHECK_MSG(pthread_mutex_unlock(&c->wq_lock) == 0, "unlock failed");

    /* --- lock free but bytes still queued: deadline deferral, still alive --- */
    TF_CHECK_MSG(server_reap(&s) == 0,
                 "reaper closed a CLOSING conn with pending bytes inside "
                 "its deadline");
    TF_CHECK_MSG(server_conn(&s, fd) == c,
                 "reaper detached a conn with pending bytes inside its deadline");
    TF_CHECK_MSG(s.wq_close_at[fd] != 0,
                 "pending deferral left no deadline behind");

    /* --- deadline expired: the bound holds, the conn finally closes --- */
    s.wq_close_at[fd] = 1;
    TF_CHECK_MSG(server_reap(&s) == 1,
                 "reaper did not close past the deadline");
    TF_CHECK_MSG(server_conn(&s, fd) == NULL,
                 "closed conn still registered");
    TF_CHECK_MSG(s.nactive == 0, "nactive=%zu after close", s.nactive);

    close(pair[1]);
    server_shutdown(&s);
    tf_done("close_handoff");
    return 0;
}
