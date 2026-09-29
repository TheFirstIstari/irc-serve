/* test_disconnect_nick.c -- a client that goes away WITHOUT QUIT leaves nothing
 * behind in the nick index.
 *
 * The ordinary end of a connection. Not the QUIT path: a closed laptop lid, a
 * dropped TCP session, a client that was SIGKILLed. Every node sees several of
 * those an hour, and all the server did was notice recv() returning 0, mark the
 * conn CLOSING, and let the reaper close it. Nothing in that path sends a line,
 * which is exactly why it is where a mistake survives review: QUIT has a handler
 * to read and a test named after it, and the read-EOF path has neither.
 *
 * ---------------------------------------------------------------------------
 * WHAT WAS WRONG (issue #102)
 * ---------------------------------------------------------------------------
 * The reaper's close removed the nickname from the TABLE and then freed the
 * conn_t, while the ENUMERATION -- the ordered vector of connections that WHO
 * walks -- kept the pointer. So a freed conn_t stayed reachable from
 * server_nick_at(), the next bare WHO (which is what irssi and weechat send on
 * connect) dereferenced it, and server_nick_count() stayed one too high for the
 * rest of the process's life.
 *
 * Two halves of one index, and the close path did half of it. The test below is
 * written so that BOTH halves are observable without a sanitizer, because the
 * COUNT is observable and the dangling read is not:
 *
 *   1. the node's own `[observable] conn_reaped: ... nicks=N` line, printed at
 *      the teardown, is the enumeration size once the connection is gone. A conn
 *      left in the vector is exactly this number being one too high. (The loop's
 *      `conn_close: ... reason=eof` lines are the other half of this: they say a
 *      connection is on its way out and why, and they are printed by poll_loop.c
 *      before anything is freed. This test needs the number that only exists
 *      after the teardown, which is why it is a separate word and a separate
 *      line.)
 *   2. `[observable] who: ... nicks=N` is the same number at query time, reached
 *      by the walk that reads the stale entry.
 *   3. WHO's 352 lines and its 315 terminator, asserted as whole lines, so "the
 *      count is right" cannot be satisfied by a WHO that answers nothing.
 *
 * And under -DIRC_SANITIZE=ON the second group is what turns the dangling read
 * into a FAILURE rather than an observation: that WHO reads conn_t::nick and
 * conn_t::state out of a freed allocation, and AddressSanitizer reports it in the
 * node process. The node here is the SHIPPED binary ($<TARGET_FILE:irc-serve>),
 * which in a sanitized build is the instrumented one; an inline child would
 * exercise the same code but would not be the artefact under test. That is the
 * whole reason the sanitizer job exists -- nothing in the unsanitized suite can
 * see a read of freed memory that happens to return bytes the node never uses.
 *
 * ---------------------------------------------------------------------------
 * WHY THE WAIT IS A WAIT AND NOT A SLEEP
 * ---------------------------------------------------------------------------
 * The reap is asynchronous: the node closes the dropped client on its own
 * schedule, so a WHO sent immediately after the FIN could be processed BEFORE
 * the node notices the FIN, and nicks=2 would then be correct and the assertion
 * a coin flip. The synchronisation point is the node's own close line, waited
 * for with nf_expect()'s deadline. No sleep anywhere (6.3), and what follows is
 * a statement about the node rather than about how fast it is.
 *
 * The last group is a source-inspection check and is labelled as one: "QUIT and
 * a bare disconnect go through ONE function" is a property of the code's shape,
 * and no runtime observation can tell which function a call went through. It is
 * the assertion that stops the two paths drifting apart again, which is exactly
 * how #102 happened: one call that removed half of an index.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define BIN_NAME "irc.test"
#define OBSERVED_HOST "127.0.0.1"

/* The nickname whose connection disappears without QUIT, and the one a third
 * client claims afterwards to show the name is free again. Same string on
 * purpose: it is the release that is under test, not the spelling. */
#define NICK_GONE "ghost"
/* Stays connected and asks every question. */
#define NICK_HELD "probe"

static unsigned g_drain_seq;

/* Is there a line in `hay` containing `head` that also contains `needle`? This
 * reads one [observable] line as a unit, so "the close line reported one entry"
 * cannot be satisfied by a close line reporting two plus some unrelated line
 * mentioning one. Returns 1 if such a line exists, 0 if not.
 *
 * It is a check on what has ALREADY been read, not a wait: the parent's copy of
 * the node's stream only grows when an nf_* call pumps it, so every wait for a
 * node line is nf_expect() and this only narrows what nf_expect() found. */
static int line_with(const char *hay, const char *head, const char *needle)
{
    const char *at = hay;

    if (hay == NULL || head == NULL || needle == NULL) {
        return 0;
    }
    while ((at = strstr(at, head)) != NULL) {
        const char *nl = strchr(at, '\n');
        size_t n = (nl != NULL) ? (size_t)(nl - at) : strlen(at);
        char line[512];

        if (n >= sizeof line) {
            n = sizeof line - 1u;
        }
        memcpy(line, at, n);
        line[n] = '\0';
        if (strstr(line, needle) != NULL) {
            return 1;
        }
        at = (nl != NULL) ? nl + 1 : at + n;
    }
    return 0;
}

/* A PING round trip. The PONG's position proves every answer the node wrote
 * before it has already arrived, so a window closed by a drain is a statement
 * about the node rather than about timing. */
static size_t drain(test_client_t *c)
{
    char line[64];
    char needle[96];
    const char *at;

    g_drain_seq++;
    (void)snprintf(line, sizeof line, "PING :d%u", g_drain_seq);
    (void)snprintf(needle, sizeof needle, "PONG %s d%u\r\n", BIN_NAME,
                   g_drain_seq);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(c, needle, T_IO_MS) == 0, "no PONG for %s", line);
    at = strstr(tc_buffer(c), needle);
    TF_CHECK_MSG(at != NULL, "the drain PONG vanished from the buffer");
    return (at != NULL) ? (size_t)(at - tc_buffer(c)) : 0u;
}

static void connect_and_register(test_client_t *c, nf_node_t *node,
                                 const char *nick, const char *realname)
{
    char line[160];
    char needle[192];

    TF_CHECK_MSG(tc_connect(c, node->port) == 0, "tc_connect(%s) failed", nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "NICK %s send failed", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 * :%s", nick, realname);
    TF_CHECK_MSG(tc_send(c, line) == 0, "USER %s send failed", nick);
    (void)snprintf(needle, sizeof needle, " 001 %s :Welcome", nick);
    TF_CHECK_MSG(tc_expect(c, needle, T_IO_MS) == 0, "%s did not register", nick);
    (void)drain(c);
}

/* The 352 this node writes for `who` on a bare WHO: <channel> is the RFC's own
 * '*' placeholder, <flags> is 'H' for a user who is here, and the trailing text
 * is the hopcount (always 0 here: a user this node holds the socket for has been
 * forwarded nowhere) and the realname. Asserted as the WHOLE line including the
 * CRLF, because a needle of " 352 " would match the start of a line and say
 * nothing at all about what followed it. */
static void expect_352_for(test_client_t *c, size_t from, size_t end,
                           const char *who, const char *realname)
{
    char want[320];
    const char *at;

    (void)snprintf(want, sizeof want,
                   ":%s 352 " NICK_HELD " * %s " OBSERVED_HOST " %s %s H :0 %s"
                   "\r\n",
                   BIN_NAME, who, BIN_NAME, who, realname);
    at = strstr(tc_buffer(c) + from, want);
    TF_CHECK_MSG(at != NULL, "expected exactly this 352 in the window: \"%s\"",
                 want);
    TF_CHECK_MSG(at < tc_buffer(c) + end,
                 "\"352 ... %s ...\" appears only AFTER the window closed, so it "
                 "was not an answer to the WHO under test", who);
}

/* How many 352 lines are in [from, end)? A count rather than a "not present"
 * check on the dead nickname, because a WHO that listed the departed client
 * TWICE and the survivor once would pass a naive "is ghost absent" assertion. */
static size_t count_352(test_client_t *c, size_t from, size_t end)
{
    const char *p = tc_buffer(c) + from;
    size_t n = 0;

    while (p < tc_buffer(c) + end) {
        const char *hit = strstr(p, " 352 ");

        if (hit == NULL || hit >= tc_buffer(c) + end) {
            break;
        }
        n++;
        p = hit + 5;
    }
    return n;
}

/* `nick` must not appear anywhere in [from, end), and the window must have been
 * closed -- an unclosed window would make "did not appear" a statement about a
 * buffer the node may not have finished writing to, which is the race that lets
 * "assert nothing arrived" tests pass without asserting anything. */
static void expect_absent_in_window(test_client_t *c, size_t from, size_t end,
                                    const char *what, const char *needle)
{
    const char *base = tc_buffer(c);
    size_t count = 0;

    TF_CHECK_MSG(end > from,
                 "%s: the window was never closed (from=%zu end=%zu), so \"did "
                 "not appear\" would prove nothing", what, from, end);
    for (const char *p = base + from; p < base + end;) {
        const char *hit = strstr(p, needle);

        if (hit == NULL || hit >= base + end) {
            break;
        }
        count++;
        p = hit + strlen(needle);
    }
    TF_CHECK_MSG(count == 0,
                 "%s: \"%s\" appeared %zu time(s) in the window and must not "
                 "have appeared at all", what, needle, count);
}

/* One bare WHO, answered between two drains. Leaves the window in `from`/`end`
 * and asserts the list is terminated, which is what makes the window a complete
 * answer rather than a prefix of one. */
static void who_window(test_client_t *c, size_t *from, size_t *end)
{
    *from = drain(c);
    TF_CHECK_MSG(tc_send(c, "WHO") == 0, "WHO send failed");
    TF_CHECK_MSG(tc_expect(c, ":" BIN_NAME " 315 " NICK_HELD
                                " * :End of WHO list\r\n",
                           T_IO_MS) == 0,
                 "WHO was not terminated by 315, so the window below would not "
                 "be the whole answer");
    *end = drain(c);
    TF_CHECK_MSG(*end > *from, "the WHO window was never closed");
}

int main(void)
{
    nf_node_t node;
    test_client_t gone;
    test_client_t held;
    test_client_t taken;
    size_t from;
    size_t end;
    size_t n;

    memset(&gone, 0, sizeof gone);
    memset(&held, 0, sizeof held);
    memset(&taken, 0, sizeof taken);
    TF_CHECK(nf_spawn_binary(&node) == 0);
    TF_CHECK_MSG(node.port > 0, "the node reported no usable port");

    /* Two registered clients, so a bare WHO has something correct to say before
     * the disconnect and something smaller to say after it. */
    connect_and_register(&gone, &node, NICK_GONE, "Gone Without Quit");
    connect_and_register(&held, &node, NICK_HELD, "Held On Purpose");

    /* --- baseline: both connections are enumerated --- */
    TF_CHECK_MSG(strstr(node.out, "[observable] conn_reaped:") == NULL,
                 "a connection was reaped before this test closed one, so the "
                 "reap line checked later is not the one it means");
    who_window(&held, &from, &end);
    expect_352_for(&held, from, end, NICK_HELD, "Held On Purpose");
    expect_352_for(&held, from, end, NICK_GONE, "Gone Without Quit");
    TF_CHECK_MSG(count_352(&held, from, end) == 2,
                 "the baseline WHO listed %zu clients, expected 2",
                 count_352(&held, from, end));
    TF_CHECK_MSG(nf_expect(&node, "[observable] who: nick=" NICK_HELD
                                  " mask=* nicks=2",
                           T_IO_MS) == 0,
                 "the node reported the wrong enumeration size with two "
                 "registered clients: expected nicks=2 on the mask=* line");

    /* --- the disconnect under test: a FIN, with no QUIT in it --- */
    /* Not a half-close and not a QUIT: a client that simply goes away, which is
     * what a dropped TCP connection is from the node's side. recv() returns 0,
     * the conn is marked CLOSING, the reaper closes it, and nothing on the wire
     * says why. */
    tc_close(&gone);
    TF_CHECK_MSG(nf_expect(&node, "[observable] conn_reaped:", T_IO_MS) == 0,
                 "the node never reported reaping the connection that "
                 "disconnected without QUIT");

    /* 2. THE COUNT, as WHO sees it -- and the walk that reads the stale entry on
     * the way past. Under -DIRC_SANITIZE=ON this is the statement that reads
     * freed memory on unfixed code, which is why it comes BEFORE the count check
     * below: on unfixed code the query is the thing that faults, and a test that
     * asserted the count first would report the arithmetic and never reach the
     * memory error. Without a sanitizer it is the count above restated at the
     * query rather than at the close. */
    who_window(&held, &from, &end);
    expect_352_for(&held, from, end, NICK_HELD, "Held On Purpose");
    n = count_352(&held, from, end);
    TF_CHECK_MSG(n == 1,
                 "WHO after a client disconnected without QUIT produced %zu 352 "
                 "lines, expected exactly 1: the departed connection is still "
                 "in the nick enumeration", n);
    expect_absent_in_window(&held, from, end, "the WHO after the disconnect",
                            NICK_GONE);
    TF_CHECK_MSG(nf_expect(&node, "[observable] who: nick=" NICK_HELD
                                  " mask=* nicks=1",
                           T_IO_MS) == 0,
                 "WHO reported the wrong enumeration size after the disconnect: "
                 "expected nicks=1 on the mask=* line, because the connection "
                 "that went away is not one of this node's users any more");

    /* 1. THE COUNT, at the moment the connection was torn down. A connection
     * still in the enumeration is exactly this number being one too high. Read
     * after the WHO above, but it is the same fact at the earlier of the two
     * moments, and reading it there pins down WHICH close left it behind. */
    TF_CHECK_MSG(line_with(node.out, "[observable] conn_reaped:", "nicks=1"),
                 "the reap of the client that disconnected without QUIT left "
                 "its conn_t in the nick enumeration: the teardown line did not "
                 "report nicks=1");

    /* 3. THE TABLE, which is the other half of the index and the one a message
     * addressed to the dead nickname resolves through. 401 is the answer for a
     * name this node no longer holds, and 318 ends the list, as RFC 2812 3.3.4
     * pairs them. */
    from = drain(&held);
    TF_CHECK_MSG(tc_send(&held, "WHOIS " NICK_GONE) == 0, "WHOIS send failed");
    TF_CHECK_MSG(tc_expect(&held, ":" BIN_NAME " 401 " NICK_HELD " " NICK_GONE
                                " :No such nick/channel\r\n",
                           T_IO_MS) == 0,
                 "WHOIS for a nickname whose connection went away without QUIT "
                 "did not answer 401: the name is still in the table, and a "
                 "PRIVMSG to it would be a message to a freed connection");
    TF_CHECK_MSG(tc_expect(&held, ":" BIN_NAME " 318 " NICK_HELD " " NICK_GONE
                                " :End of /WHOIS list\r\n",
                           T_IO_MS) == 0,
                 "the 401 was not followed by the 318 that ends the list");
    end = drain(&held);
    expect_absent_in_window(&held, from, end, "the WHOIS", " 311 ");

    /* And the name is claimable again, which is the same fact from the other
     * side: a name left in the table by a connection that is gone is a name
     * nobody can ever use again. */
    connect_and_register(&taken, &node, NICK_GONE, "Took The Name Back");
    who_window(&held, &from, &end);
    n = count_352(&held, from, end);
    TF_CHECK_MSG(n == 2,
                 "WHO after the released name was re-claimed produced %zu 352 "
                 "lines, expected 2: the index did not come back", n);
    expect_352_for(&held, from, end, NICK_HELD, "Held On Purpose");
    expect_352_for(&held, from, end, NICK_GONE, "Took The Name Back");
    TF_CHECK_MSG(nf_expect(&node, "[observable] who: nick=" NICK_HELD
                                  " mask=* nicks=2",
                           T_IO_MS) == 0,
                 "the enumeration did not come back to two after the departed "
                 "connection's name was claimed by somebody else");

    /* --- the shape of the fix, asserted by inspection --- */
    {
        size_t len = 0;
        char *code = tf_read_code("src/core/server.c", &len);
        char *cmds = tf_read_code("src/core/commands.c", &len);
        const char *fn;
        const char *fn_end;
        char body[8192];
        size_t body_len;

        TF_CHECK_MSG(code != NULL,
                     "could not read src/core/server.c (is IRCSERVE_SRC_DIR "
                     "set?)");
        TF_CHECK_MSG(cmds != NULL,
                     "could not read src/core/commands.c (is IRCSERVE_SRC_DIR "
                     "set?)");

        /* The close path. One call, and it is a call that owns BOTH halves of
         * the index. The two negative checks are the assertion that matters: a
         * teardown that touches either half by hand is the shape #102 had, and
         * what made it a bug is that the two halves were separate calls. */
        fn = strstr(code, "server_close_conn(server_t");
        TF_CHECK_MSG(fn != NULL,
                     "could not find server_close_conn() in server.c");
        fn_end = strstr(fn, "\n}\n");
        TF_CHECK_MSG(fn_end != NULL,
                     "could not find the end of server_close_conn()");
        body_len = (size_t)(fn_end - fn);
        TF_CHECK_MSG(body_len < sizeof body,
                     "server_close_conn() is implausibly large to inspect");
        memcpy(body, fn, body_len);
        body[body_len] = '\0';
        TF_CHECK_MSG(strstr(body, "server_nick_unclaim(") != NULL,
                     "server_close_conn() no longer retires the connection "
                     "through server_nick_unclaim(): a close that removes one "
                     "half of the nick index by hand is issue #102");
        TF_CHECK_MSG(strstr(body, "strtab_del(") == NULL,
                     "server_close_conn() calls strtab_del() itself: the table "
                     "and the enumeration are one index, and a close that "
                     "removes only the table half leaves WHO walking freed "
                     "memory");
        TF_CHECK_MSG(strstr(body, "nick_objs_") == NULL,
                     "server_close_conn() reaches into the enumeration "
                     "directly: the vector is changed by the same operation that "
                     "removes the table entry, or the two halves drift apart "
                     "again");

        /* The QUIT path. The same function, and specifically NOT the name-scoped
         * release: a QUIT is a teardown, and the name-scoped operation is for
         * giving up one name while staying connected. */
        fn = strstr(cmds, "handle_quit(server_t");
        TF_CHECK_MSG(fn != NULL, "could not find handle_quit() in commands.c");
        fn_end = strstr(fn, "\n}\n");
        TF_CHECK_MSG(fn_end != NULL,
                     "could not find the end of handle_quit()");
        body_len = (size_t)(fn_end - fn);
        TF_CHECK_MSG(body_len < sizeof body,
                     "handle_quit() is implausibly large to inspect");
        memcpy(body, fn, body_len);
        body[body_len] = '\0';
        TF_CHECK_MSG(strstr(body, "server_nick_unclaim(") != NULL,
                     "handle_quit() does not retire the connection through "
                     "server_nick_unclaim(): a QUIT and a bare disconnect must "
                     "go through ONE function, because those are the two paths "
                     "that disagreed in issue #102");
        TF_CHECK_MSG(strstr(body, "server_nick_release(") == NULL,
                     "handle_quit() still calls the name-scoped "
                     "server_nick_release(): that is the release for a "
                     "connection that is staying alive, and using it on the "
                     "teardown path is how the two paths came to differ");

        free(code);
        free(cmds);
    }

    /* --- the node's own accounting, read after it exits --- */
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", 3, T_IO_MS) == 0,
                 "accepted should be 3: the two clients plus the one that took "
                 "the released name");
    TF_CHECK_MSG(nf_expect_u64(&node, "closed=", 3, T_IO_MS) == 0,
                 "closed should be 3: a disconnect without QUIT is still closed "
                 "exactly once, by the reaper, like every other close");
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0: a numeric was addressed to a "
                 "connection that had gone away without QUIT");

    tc_close(&taken);
    tc_close(&held);
    nf_free(&node);
    tf_done("disconnect_nick");
    return 0;
}
