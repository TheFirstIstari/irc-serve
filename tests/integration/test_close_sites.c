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
 * ---------------------------------------------------------------------------
 * src/federation/link.c IS THE EXCEPTION, AND IT IS A NARROW ONE
 * ---------------------------------------------------------------------------
 * It closes exactly one thing: the descriptor of a DIAL_CONNECTING entry that
 * fed_tick()'s T1 has decided will never complete. That is a DIAL and not a
 * connection -- the descriptor is not in by_fd, it has no conn_t, and the reaper
 * has nothing to reap -- and server.c already closes precisely these on
 * precisely this ground, in server_dial_progress()'s DIAL_FAILED arms and in
 * the shutdown walk. Without it a connect() to a black-holed host would leak a
 * descriptor on every timeout.
 *
 * So link.c is NOT in the `never` list above: putting it there would mean
 * asserting a falsehood, and a test that asserts a falsehood is a test that
 * has stopped checking anything. What it gets instead is in the `no_destroy`
 * list, plus the two targeted assertions at the bottom of this file: that it
 * has exactly ONE close(), and that the one it has is the dial timeout's. That
 * is a stronger statement than membership in `never` would have been, because
 * `never` says "this file never closes" and these say "this file closes one
 * thing and it is a dial".
 *
 * The consequence of the exception is stated rather than glossed: the "no stray
 * close in a federation file" property is no longer covered by list
 * membership for link.c. It is covered by the two assertions instead, and that
 * is why they are there.
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
    /* 64 KiB, and the number is measured rather than guessed. This was 16 KiB
     * until src/federation/link.c needed a WHOLE-FILE range for its own
     * assertion, and link.c with its comments stripped by tf_read_code() is
     * 20511 bytes -- over 16 KiB, so at the old size the whole-file count came
     * back -1 and `n == rc` failed. Both facts were checked by building this
     * test at 16 KiB and watching it go red, rather than by reading the file
     * size off a comment.
     *
     * The largest file this test measures is src/core/server.c at 24204
     * stripped, so 64 KiB is about 2.7x the biggest thing in the tree today. The
     * cap is a backstop against a pointer mistake in a caller's `to`, not a
     * bound on a source file.
     *
     * AND -1 IS A LOUD ANSWER, WHICH IS THE PART THAT MAKES THE CAP HONEST.
     * Every call site compares against a positive expected count (`rc == 1`) or
     * against that same rc, so a range too large to measure FAILS the test rather
     * than passing it quietly: verified by building this at 1 KiB, where
     * test_close_sites reports `n == rc` with n = -1. An earlier version of this
     * comment called that "silently stops checking", which was wrong and is
     * retracted here. The alternative to the cap -- malloc the range and copy it
     * with no upper bound -- would trade a loud failure for a read past the end
     * of a heap buffer, which is the worse of the two. */
    char body[65536];
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
     * one: 3.4 says it only marks CLOSING. connection.c is the tempting one.
     *
     * src/message_id.c was on both lists below and is not any more: it was an
     * orphan that no CMakeLists.txt ever compiled, and #86 deleted it. The entry
     * had to go with it, because load() treats an unreadable file as a failure
     * and this list is a list of files that exist. No assertion is weakened --
     * every file still in either list is checked exactly as before. */
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
        "src/sasl_framework.c"
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
        /* The link module. It is in the second list and NOT the first, which is
         * the whole of the exception documented in the header: it closes a
         * DIAL that never became a connection, and it must never destroy a
         * connection. The two assertions below pin the close itself. */
        "src/federation/link.c"
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

    /* federation/link.c: the one file outside server.c that may call close(),
     * and it may call it for exactly one reason. Two assertions, and both are
     * needed: the first says there is only the one, the second says which one
     * it is. Together they are stronger than membership in `never` would have
     * been, because `never` would have said "this file never closes" -- which
     * is false -- and a list entry that is false takes the file's real
     * protection with it. */
    {
        char *link_code = load("src/federation/link.c");
        int n;

        TF_CHECK_MSG(tf_calls(link_code, "close"),
                     "src/federation/link.c no longer calls close() at all: "
                     "T1 has to close the descriptor of a dial that will never "
                     "complete, because a connect() to a black-holed host is "
                     "not in by_fd and the reaper cannot own it. If the "
                     "timeout was removed instead, remove the comment in the "
                     "header with it.");
        /* And the one it has is the dial timeout's -- which is a stronger claim
         * than "there is one somewhere in the file", and is checked the same way
         * server_close_conn() above is: by finding the function and counting the
         * close() calls inside it. tf_read_code() strips string literals, so
         * this cannot search for the observable line the function prints; it
         * searches for the function, which is the better target anyway, because
         * a close moved into a DIFFERENT function would then fail rather than
         * pass. */
        fn = strstr(link_code, "fed_dial_expired(server_t");
        TF_CHECK_MSG(fn != NULL,
                     "could not find fed_dial_expired() in link.c; the function "
                     "that owns the one close() this file is allowed has been "
                     "renamed, and the comment above it with it");
        end = strstr(fn, "\n}\n");
        TF_CHECK_MSG(end != NULL,
                     "could not find the end of fed_dial_expired() in link.c");
        rc = calls_between("close", fn, end);
        TF_CHECK_MSG(rc == 1,
                     "fed_dial_expired() does not contain exactly one close() "
                     "(found %d): that is the dial-timeout close, and it is the "
                     "only close a peer-link file may have", rc);
        /* And nothing else in link.c does. The whole-file count plus the
         * in-function count is the pair that says both things; either alone
         * would leave room for a second close elsewhere. */
        n = calls_between("close", link_code, link_code + strlen(link_code));
        TF_CHECK_MSG(n == rc,
                     "src/federation/link.c has %d close() calls in total but %d "
                     "inside fed_dial_expired(): a peer link is the one place "
                     "outside the registry that touches a descriptor, so a "
                     "close anywhere else is a close path 3.4 does not have", n,
                     rc);
        free(link_code);
    }

    free(code);
    tf_done("close_sites");
    return 0;
}
