/* test_close_sites.c -- no code path closes a connection except the reaper.
 *
 * docs/SERVER_DESIGN.md 3.4: "The send path never closes a connection. It
 * marks CLOSING; a reaper runs at a fixed point in the loop."
 *
 * test_reaper_close.c checks that the rule HOLDS at runtime -- nothing survives
 * a reap, a reissued descriptor is clean, and the close count matches the
 * accept count. It cannot check that the rule is obeyed BY CONSTRUCTION: a
 * second close() syscall on an already-closed descriptor is swallowed by any
 * error path that looks right, and a close() issued from the wrong place would
 * leave every runtime invariant intact.
 *
 * So this test reads the sources. That is a source-inspection test and it is
 * labelled as one: the property being checked is a property of the code's
 * shape, and looking is the only way to check it. A close() appearing anywhere
 * new fails the build, which is the point -- retrofitting a stray close into the
 * send path is precisely the change that would otherwise stay invisible until a
 * federation link double-closed under load.
 *
 * ALLOWED SITES, and why each is not a connection close:
 *
 *   src/core/connection.c   NONE. A conn_t does not know whether it is
 *                          registered, so it cannot own its descriptor. This
 *                          is the file where a close would be most tempting and
 *                          most wrong.
 *   src/core/poll_loop.c    NONE, and additionally it must not call
 *                          server_close_conn() or conn_free() either. "Close"
 *                          here means anything that destroys a connection, not
 *                          just the close() call: a loop that calls
 *                          server_close_conn() from the send path is the exact
 *                          failure 3.4 forbids, and it looks correct in review
 *                          because the close is in the right file. The loop's
 *                          only permitted move is conn_mark_closing().
 *   src/core/reply.c        NONE. It builds outbound lines and queues them; it
 *                          has no business deciding that a descriptor dies.
 *   src/core/commands.c     NONE, same reason: a handler states what it wants
 *                          to say, never what happens to the socket.
 *   src/core/server.c       The registry close in server_close_conn() -- the one
 *                          place a conn_t's descriptor is closed. Plus: the
 *                          accept whose descriptor was >= FD_SETSIZE and so
 *                          could never become a conn_t (by_fd is indexed BY
 *                          descriptor, so the reaper cannot own it); a
 *                          bind/listen failure before the listener is reachable;
 *                          the listener at shutdown; and dials that never became
 *                          connections.
 *   everything else         NONE.
 *
 * Comments and string/char literals are stripped before the search, so prose
 * about closing a descriptor is not mistaken for a call. A trailing comment
 * containing the literal text `close(` would be a false positive; that is the
 * cost of checking by inspection, and it is cheaper than the bug it prevents.
 *
 * The stripper and the call matcher live in the harness now (test_util.h,
 * tf_read_code() and tf_calls()) rather than here, because the second
 * source-inspection test -- test_reply_guard.c -- needs the same two and a
 * second copy of a hand-written C lexer is a liability rather than a
 * convenience. Every assertion below is unchanged.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/test_util.h"

static char *load(const char *rel)
{
    size_t len = 0;
    char *code = tf_read_code(rel, &len);

    TF_CHECK_MSG(code != NULL, "could not read %s (is IRCSERVE_SRC_DIR set?)",
                 rel);
    return code;
}

/* Does the byte range [from, to) call `name`? */
static int calls_between(const char *name, const char *from, const char *to)
{
    char body[16384];
    size_t n;

    if (from == NULL || to == NULL || to <= from) {
        return 0;
    }
    n = (size_t)(to - from);
    if (n >= sizeof body) {
        return -1; /* implausibly large; treat as "cannot tell" */
    }
    memcpy(body, from, n);
    body[n] = '\0';
    return tf_calls(body, name);
}

int main(void)
{
    /* Files that must never close a descriptor. poll_loop.c is the load-bearing
     * one: 3.4 says it only marks CLOSING. connection.c is the tempting one. */
    static const char *const never[] = {
        "src/core/connection.c",
        "src/core/poll_loop.c",
        "src/core/message.c",
        "src/core/reply.c",
        "src/core/commands.c",
        "src/node_main.c",
        "src/protocol_parse.c",
        "src/ircv3_tags.c",
        "src/federation_handshake.c",
        "src/sasl_framework.c",
        "src/message_id.c"
    };
    char *code;
    const char *fn;
    const char *end;
    size_t i;
    int rc;

    /* Two lists, because the rule is not the same for both. `never` is every
     * file that must not touch the close() syscall. `no_destroy` is every file
     * that must not DESTROY a connection, which is the stronger property: not
     * the registry that owns it, and not the destructor. connection.c and
     * server.c are absent from the second list because each is one of the two
     * places where destruction legitimately happens. */
    static const char *const no_destroy[] = {
        "src/core/poll_loop.c", "src/core/message.c", "src/core/reply.c",
        "src/core/commands.c", "src/node_main.c",
        "src/protocol_parse.c", "src/ircv3_tags.c",
        "src/federation_handshake.c", "src/sasl_framework.c",
        "src/message_id.c"
    };

    for (i = 0; i < sizeof never / sizeof never[0]; i++) {
        code = load(never[i]);
        TF_CHECK_MSG(!tf_calls(code, "close"),
                     "%s calls close(). Only the reaper in server.c may close "
                     "a connection descriptor; everything else marks CLOSING "
                     "and lets the reaper do it.", never[i]);
        free(code);
    }

    for (i = 0; i < sizeof no_destroy / sizeof no_destroy[0]; i++) {
        code = load(no_destroy[i]);
        TF_CHECK_MSG(!tf_calls(code, "conn_free"),
                     "%s calls conn_free(): a registered conn_t is owned by "
                     "the registry and released by the reaper, so a free() "
                     "from anywhere else is a use-after-free waiting for the "
                     "next lookup on that descriptor", no_destroy[i]);
        TF_CHECK_MSG(!tf_calls(code, "server_close_conn"),
                     "%s calls server_close_conn(): only the reaper destroys a "
                     "registered connection, so that every close happens at one "
                     "fixed point in the iteration", no_destroy[i]);
        free(code);
    }

    /* connection.c: the module that owns conn_t. It may not close anything (a
     * conn_t does not know whether it is registered) and may not reach the
     * registry, but it must still define the destructor. */
    {
        char *conn_code = load("src/core/connection.c");

        TF_CHECK_MSG(!tf_calls(conn_code, "server_close_conn"),
                     "connection.c calls server_close_conn(): a conn_t does not "
                     "know whether it is registered, so it must never decide "
                     "that a descriptor is closed");
        TF_CHECK_MSG(tf_calls(conn_code, "conn_free"),
                     "connection.c no longer defines conn_free(): something "
                     "has to be able to release a conn_t's buffers");
        free(conn_code);
    }

    code = load("src/core/server.c");

    /* The reaper's close must be there. Without this, "no stray close" could be
     * satisfied by deleting the legitimate one and leaving every connection
     * leaking, which the runtime test would then catch only as a hung test. */
    TF_CHECK_MSG(tf_calls(code, "close"),
                 "server.c no longer calls close() at all: the reaper must be "
                 "the place a connection descriptor is closed");

    /* And it must be inside server_close_conn(), not merely somewhere in the
     * file. This is the assertion that names the single close site. */
    fn = strstr(code, "server_close_conn(server_t");
    TF_CHECK_MSG(fn != NULL, "could not find server_close_conn() in server.c");
    end = strstr(fn, "\n}\n");
    TF_CHECK_MSG(end != NULL, "could not find the end of server_close_conn()");
    rc = calls_between("close", fn, end);
    TF_CHECK_MSG(rc == 1,
                 "server_close_conn() does not contain exactly one close() "
                 "(found %d): the registry close is the single place a "
                 "connection descriptor is closed", rc);

    /* The out-of-range accept is the one place that closes an accepted
     * descriptor outside the reaper, and it has to stay that way deliberately:
     * by_fd is indexed BY descriptor, so an fd >= FD_SETSIZE cannot be
     * registered and the reaper has no conn_t to own. If the check ever
     * disappears, this is the assertion that says so by name. */
    fn = strstr(code, "if (fd >= FD_SETSIZE)");
    TF_CHECK_MSG(fn != NULL,
                 "the explicit fd >= FD_SETSIZE check is gone from "
                 "server.c: 3.4 requires it explicitly at every accept/dial "
                 "site, and its absence is silent corruption rather than a "
                 "graceful degradation");
    end = strstr(fn, "n_rejected_fd");
    TF_CHECK_MSG(end != NULL,
                 "the FD_SETSIZE rejection no longer records itself");
    rc = calls_between("close", fn, end);
    TF_CHECK_MSG(rc == 1,
                 "the FD_SETSIZE rejection does not close the out-of-range "
                 "descriptor (found %d close() calls): it would leak one "
                 "descriptor per refused connection", rc);

    free(code);
    tf_done("close_sites");
    return 0;
}
