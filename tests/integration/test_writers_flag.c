/* test_writers_flag.c -- MT 2.1 (#240): --writers N + seam default.
 *
 * Default 0 (single-threaded drain); the seam stores what it is given and
 * clamps negatives to 0. --writers 0 starts a node that serves exactly as
 * before; --help names the flag; a negative value is refused. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "core/server.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

static int run_and_capture(char *const argv[], char *msg, size_t msgcap)
{
    int fds[2];
    pid_t pid = -1;
    int status = 0;
    size_t n = 0;

    msg[0] = '\0';
    if (pipe(fds) != 0) {
        return -1;
    }
    pid = fork();
    if (pid == 0) {
        (void)close(fds[0]);
        (void)dup2(fds[1], STDOUT_FILENO);
        (void)dup2(fds[1], STDERR_FILENO);
        execv(NF_SERVER_BIN, argv);
        _exit(127);
    }
    if (pid < 0) {
        (void)close(fds[0]);
        (void)close(fds[1]);
        return -1;
    }
    (void)close(fds[1]);
    for (;;) {
        fd_set rd;
        struct timeval tv;
        int r;

        FD_ZERO(&rd);
        FD_SET(fds[0], &rd);
        tv.tv_sec = 0;
        tv.tv_usec = 20000;
        r = select(fds[0] + 1, &rd, NULL, NULL, &tv);
        if (r > 0) {
            ssize_t got = read(fds[0], msg + n, msgcap - n - 1u);

            if (got > 0) {
                n += (size_t)got;
                msg[n] = '\0';
                continue;
            }
        }
        if (waitpid(pid, &status, WNOHANG) == pid) {
            break;
        }
    }
    (void)close(fds[0]);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int main(void)
{
    /* Seam default is 0; stores values; clamps negatives. */
    {
        server_t s;

        TF_CHECK_MSG(server_init(&s, "irc.test") == 0, "server_init failed");
        TF_CHECK_MSG(s.writer_threads == 0, "seam default is not 0: %d",
                     s.writer_threads);
        server_set_writer_threads(&s, 4);
        TF_CHECK_MSG(s.writer_threads == 4, "seam did not store 4: %d",
                     s.writer_threads);
        server_set_writer_threads(&s, -1);
        TF_CHECK_MSG(s.writer_threads == 0, "seam did not clamp -1: %d",
                     s.writer_threads);
        server_set_writer_threads(NULL, 4); /* no-op, must not crash */
        server_shutdown(&s);
    }

    /* --help names --writers. */
    {
        static char a0[] = "irc-serve";
        static char a1[] = "--help";
        char *v[3];
        char msg[8192];
        int rc;

        v[0] = a0; v[1] = a1; v[2] = NULL;
        rc = run_and_capture(v, msg, sizeof msg);
        TF_CHECK_MSG(rc == 0, "--help exited %d: %s", rc, msg);
        TF_CHECK_MSG(strstr(msg, "--writers") != NULL,
                     "--help does not name --writers: %s", msg);
    }

    /* --writers 0 serves exactly as before. */
    {
        nf_node_t n;
        static char a0[] = "irc-serve";
        static char a1[] = "0";
        static char a2[] = "--writers";
        static char a3[] = "0";
        char *w[5];

        w[0] = a0; w[1] = a1; w[2] = a2; w[3] = a3; w[4] = NULL;
        TF_CHECK_MSG(nf_spawn_binary_argv(&n, w) == 0,
                     "a node with --writers 0 did not start");
        TF_CHECK_MSG(strstr(n.out, "startup: version=") != NULL,
                     "no startup line: %s", n.out);
        TF_CHECK_MSG(nf_stop(&n) == 0, "the node did not stop cleanly");
        nf_free(&n);
    }

    /* Negative --writers is refused. */
    {
        static char a0[] = "irc-serve";
        static char a1[] = "0";
        static char a2[] = "--writers";
        static char a3[] = "-1";
        char *v[5];
        char msg[8192];
        int rc;

        v[0] = a0; v[1] = a1; v[2] = a2; v[3] = a3; v[4] = NULL;
        rc = run_and_capture(v, msg, sizeof msg);
        TF_CHECK_MSG(rc != 0, "--writers -1 was accepted: %s", msg);
    }

    printf("PASS test_writers_flag\n");
    return 0;
}
