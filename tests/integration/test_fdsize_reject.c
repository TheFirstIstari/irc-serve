/* test_fdsize_reject.c -- an accepted descriptor at or above FD_SETSIZE is
 * rejected explicitly.
 *
 * docs/SERVER_DESIGN.md 3.4: "Explicit if (fd >= FD_SETSIZE) reject at every
 * accept/dial site."
 *
 * The check is not defensive decoration. poll() silently ignores a descriptor
 * outside its set, and FD_SET on one is undefined behaviour that writes past the
 * end of the fd_set on some paths -- so "just don't register it" leaves a
 * connection that was accepted and then vanishes, with a stack scribble on the
 * way out. 3.4 requires the check to be explicit and immediate, and this test
 * exists so that removing it fails the suite rather than the network.
 *
 * HOW THE SCENARIO IS FORCED
 * ---------------------------
 * FD_SETSIZE is 1024 on both macOS and Linux, and a freshly started process has
 * descriptors 0..3 or so in use, so accept() will never naturally hand back a
 * number that large. The node's setup hook therefore fills the descriptor table
 * first: it opens /dev/null until every descriptor below FD_SETSIZE is
 * occupied, which forces the kernel to hand the next accept() a descriptor at
 * or above the limit. That is a real accept() on a real listener -- nothing is
 * stubbed -- and it is why this test needs RLIMIT_NOFILE raised first.
 *
 * If the machine's hard descriptor limit is too low to fill the table, the test
 * FAILS and says so. It does not skip: a skip here would be indistinguishable
 * from the check being absent, which is the exact blind spot 6.4 is about.
 *
 * What is asserted:
 *   - the node reports the rejection, by name, with the limit
 *   - the client is not left hanging: the descriptor was closed
 *   - the node counted exactly one rejection
 *   - the node is still running afterwards
 */
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "core/server.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

static void setup(server_t *s)
{
    int rc = nf_fill_descriptors_below(FD_SETSIZE);

    if (rc != 0) {
        fprintf(stderr, "fixture: could not fill descriptors below %d: %s\n"
                "(raise RLIMIT_NOFILE; this must fail, not skip)\n",
                FD_SETSIZE, strerror(errno));
        _exit(1);
    }
    printf("[fixture] filled descriptors below %d\n", FD_SETSIZE);
    fflush(stdout);
    (void)s;
}

int main(void)
{
    nf_node_t node;
    test_client_t c;
    struct rlimit rl;

    TF_CHECK_MSG(FD_SETSIZE > 8, "FD_SETSIZE is implausibly small: %d",
                 FD_SETSIZE);

    /* The child inherits this, and the whole scenario depends on the process
     * being able to hold more than FD_SETSIZE descriptors. */
    TF_CHECK_MSG(nf_raise_fd_limit() == 0, "could not raise RLIMIT_NOFILE");
    TF_CHECK_MSG(getrlimit(RLIMIT_NOFILE, &rl) == 0, "getrlimit failed");
    TF_CHECK_MSG((long long)rl.rlim_cur > (long long)FD_SETSIZE,
                 "RLIMIT_NOFILE soft limit is %llu, which is not above "
                 "FD_SETSIZE=%d: this test cannot force the condition it "
                 "tests and must not pass silently",
                 (unsigned long long)rl.rlim_cur, FD_SETSIZE);

    TF_CHECK(nf_spawn_inline(&node, setup) == 0);
    TF_CHECK_MSG(nf_expect(&node, "[fixture] filled descriptors", T_IO_MS) == 0,
                 "the node never reported filling its descriptor table");

    /* The listener still has room in its backlog, so connect() succeeds even
     * though the descriptor the node is about to get is unusable. */
    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0,
                 "connect failed; the listener was not accepting");

    /* The explicit check, by name. Without it this line never appears. */
    TF_CHECK_MSG(nf_expect(&node, "accept_rejected:", T_IO_MS) == 0,
                 "the node never reported rejecting an out-of-range "
                 "descriptor: the fd >= FD_SETSIZE check did not run");
    TF_CHECK_MSG(nf_expect(&node, "reason=fd_ge_fdsize", T_IO_MS) == 0,
                 "the rejection was not attributed to the FD_SETSIZE check");

    /* The rejected descriptor is closed rather than left open, so the client is
     * not left hanging on a socket nobody owns. FIN versus RST is not asserted
     * here on purpose: closing immediately with no data ever sent is a FIN on
     * every platform, but the meaningful claim is "not left hanging", and
     * counting the rejection is what proves the explicit path was taken. */
    {
        int rc = tc_expect_eof(&c, T_IO_MS);

        TF_CHECK_MSG(rc == 0 || rc == -3,
                     "the rejected connection was left hanging: rc=%d", rc);
    }

    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "rejected_fd=", 1, T_IO_MS) == 0,
                 "rejected_fd should be 1: exactly one accept should have been "
                 "refused");
    /* The refused connection never became a conn, so it must not appear in the
     * connection accounting either. */
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", 0, T_IO_MS) == 0,
                 "accepted should be 0: an out-of-range descriptor must not "
                 "become a connection");
    TF_CHECK_MSG(nf_expect_u64(&node, "closed=", 0, T_IO_MS) == 0,
                 "closed should be 0");

    tc_close(&c);
    nf_free(&node);
    tf_done("fdsize_reject");
    return 0;
}
