/* test_priv_drop.c -- --user, the post-bind privilege drop, and the banner.
 *
 * Issue #182: after both listeners are bound the node sheds privilege with
 * setgid()/setuid() to --user (default `nobody`), with no daemonize and no
 * chroot. Root without an explicit --user refuses; anything else runs. The
 * startup banner reports version, name, port and secret none|set, never the
 * secret itself.
 *
 * The drop cannot be watched from outside -- a uid change is invisible to the
 * parent -- so every outcome is asserted off the node's own [observable] lines:
 *   --help names --user;
 *   an unprivileged start serves exactly as before (SKIPPED_NOT_ROOT + banner);
 *   root with --user drops (DROPPED), root without refuses (root_without_user,
 *   nonzero exit).
 *
 * The two root cases only run as root: anything else would be asserting about a
 * branch the process cannot reach. Off root they print a note and pass, the
 * same way a port the kernel did not grant would be a fact about the machine
 * rather than about the node.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "harness/node_fixture.h"
#include "harness/test_util.h"

/* Run the shipped binary with `argv` (NULL-terminated, argv[0] included),
 * capture stdout+stderr into `msg`, and return the child's exit status (or -1
 * if it could not be reaped). The read is bounded by the child's exit rather
 * than by a sleep: a node that started listening instead of exiting is reaped
 * by the wait, not waited out. */
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
    /* ---- --help names --user ---- */
    {
        static char a0[] = "irc-serve";
        static char a1[] = "--help";
        char *v[3];
        char msg[8192];
        int rc;

        v[0] = a0; v[1] = a1; v[2] = NULL;
        rc = run_and_capture(v, msg, sizeof msg);
        TF_CHECK_MSG(rc == 0, "--help exited %d, expected 0: %s", rc, msg);
        TF_CHECK_MSG(strstr(msg, "--user") != NULL,
                     "--help does not name --user: %s", msg);
    }

    /* ---- an unprivileged start serves exactly as before ---- */
    {
        nf_node_t n;
        static char a0[] = "irc-serve";
        static char a1[] = "0";
        static char a2[] = "--user";

        /* --user is given AND ignored off root: the point is that the flag
         * changes nothing for a caller with nothing to shed. "nobody" is the
         * default, so this is also the shape a root caller types. */
        static char a3[] = "nobody";
        char *w[5];

        w[0] = a0; w[1] = a1; w[2] = a2; w[3] = a3; w[4] = NULL;
        TF_CHECK_MSG(nf_spawn_binary_argv(&n, w) == 0,
                     "an unprivileged node with --user did not start");
        TF_CHECK_MSG(strstr(n.out, "startup: version=") != NULL &&
                     strstr(n.out, "secret=none") != NULL,
                     "the banner (version + secret state) is missing: %s", n.out);
        if (geteuid() != 0) {
            TF_CHECK_MSG(strstr(n.out, "priv_drop: state=SKIPPED_NOT_ROOT") !=
                         NULL,
                         "an unprivileged start did not skip the drop: %s", n.out);
        } else {
            TF_CHECK_MSG(strstr(n.out, "priv_drop: state=DROPPED "
                                       "user=nobody") != NULL,
                         "a root start with --user nobody did not drop: %s",
                         n.out);
        }
        TF_CHECK_MSG(nf_stop(&n) == 0, "the node did not stop cleanly");
        nf_free(&n);
    }

    /* ---- the banner never carries the secret ---- */
    {
        nf_node_t n;
        static char a0[] = "irc-serve";
        static char a1[] = "0";
        static char a2[] = "--secret";
        static char a3[] = "s3cr3t-priv-drop-pw";
        char *w[5];

        w[0] = a0; w[1] = a1; w[2] = a2; w[3] = a3; w[4] = NULL;
        TF_CHECK_MSG(nf_spawn_binary_argv(&n, w) == 0,
                     "a node with --secret did not start");
        TF_CHECK_MSG(strstr(n.out, "startup:") != NULL &&
                     strstr(n.out, "secret=set") != NULL,
                     "the banner does not report a set secret: %s", n.out);
        TF_CHECK_MSG(strstr(n.out, a3) == NULL,
                     "the secret itself appears in the node's output: %s", n.out);
        TF_CHECK_MSG(nf_stop(&n) == 0, "the node did not stop cleanly");
        nf_free(&n);
    }

    /* ---- root without --user refuses ---- */
    if (geteuid() == 0) {
        static char a0[] = "irc-serve";
        static char a1[] = "0";
        char *v[3];
        char msg[8192];
        int rc;

        v[0] = a0; v[1] = a1; v[2] = NULL;
        rc = run_and_capture(v, msg, sizeof msg);
        TF_CHECK_MSG(rc != 0, "root without --user started (rc=0): the node "
                     "kept root after bind: %s", msg);
        TF_CHECK_MSG(strstr(msg, "root_without_user") != NULL,
                     "the refusal does not say why: %s", msg);
    } else {
        printf("note: not root, so the root-without---user refusal is not "
               "reachable here\n");
    }

    /* ---- root with an unknown --user refuses ---- */
    if (geteuid() == 0) {
        static char a0[] = "irc-serve";
        static char a1[] = "0";
        static char a2[] = "--user";
        static char a3[] = "irc-serve-no-such-user";
        char *v[5];
        char msg[8192];
        int rc;

        v[0] = a0; v[1] = a1; v[2] = a2; v[3] = a3; v[4] = NULL;
        rc = run_and_capture(v, msg, sizeof msg);
        TF_CHECK_MSG(rc != 0, "--user %s started (rc=0): %s", a3, msg);
        TF_CHECK_MSG(strstr(msg, "unknown_user") != NULL,
                     "the refusal does not say why: %s", msg);
    } else {
        printf("note: not root, so the unknown---user refusal is not "
               "reachable here\n");
    }

    return 0;
}
