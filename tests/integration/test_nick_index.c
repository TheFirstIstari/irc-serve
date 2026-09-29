/* test_nick_index.c -- the nick index's invariants, asserted against server_t.
 *
 * The two failures this file exists for are both properties of the INDEX rather
 * than of any one command, and neither is reachable from the wire:
 *
 *   issue #102  the reaper removed a connection's name from the registry's
 *               TABLE and freed the conn_t, and left the conn_t in the
 *               ENUMERATION. WHO walks the enumeration, so the next bare WHO
 *               dereferenced freed memory. test_disconnect_nick.c is where that
 *               is observed from outside, under AddressSanitizer; this file is
 *               where the two halves are checked directly.
 *   issue #103  a claim appended to the enumeration unconditionally, so a
 *               connection holding two names appeared in it twice while the
 *               table had one entry per name. The two halves counted different
 *               things. Nothing on the wire produces that state -- handle_nick
 *               claims before it releases, so a rename nets one entry -- which is
 *               exactly why it is asserted here against the API instead of
 *               against a command.
 *
 * WHY A RENAME IS NOT "A CONNECTION HOLDING TWO NAMES"
 * ---------------------------------------------------
 * The two names a connection briefly holds during a rename are a different event
 * from a connection holding two names afterwards, and treating them as one thing
 * would force a choice nobody needs to make:
 *
 *   server_nick_claim() REFUSES a name somebody else holds and ACCEPTS a name
 *   the calling connection already holds another of. It has to accept it. The
 *   rename claims the new name BEFORE releasing the old one, deliberately:
 *   releasing first opens a window in which the old name is unowned and another
 *   client can take it. A claim that refused a connection's own second name
 *   would force that order and introduce the window -- and would make the
 *   registry's contract depend on an ordering argument in a different file,
 *   which is the accident #103 already was.
 *
 * So the invariant is enforced where it holds without an ordering constraint:
 * the ENUMERATION is a set of connections, so a second name adds no second
 * entry, and a teardown retires every name the connection holds rather than the
 * one its display field happens to contain. Both hold whatever the caller does
 * and in whatever order, which is the difference between an invariant and
 * accidental correctness.
 *
 * ONE NAME PER CONNECTION IS STILL THE RULE ON THE WIRE: RFC 2812 2.3.1 has no
 * notion of a user holding two nicknames, WHO's 352 is one line per user, and
 * this node behaves that way. But it is enforced by the enumeration being a set
 * and by one 352 per connection -- not by refusing a claim the rename depends
 * on. test_registries.c also reaches the two-names state directly, by claiming a
 * second name for a connection that already holds one, and requires the claim to
 * SUCCEED, so refusing it would change an existing contract rather than tighten
 * this one.
 *
 * The conns here are made by conn_new() and never registered in by_fd, so
 * server_shutdown() does not own them and each is freed by hand -- the same
 * discipline test_registries.c uses for the conns it never registers.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"
#include "harness/test_util.h"

/* A connection with a display nickname, which is a different thing from the
 * names it holds in the registry. The two are deliberately allowed to disagree
 * below, because that disagreement is what the guard cases are about. */
static conn_t *make_conn(int fd, const char *nick)
{
    conn_t *c = conn_new(fd, CONN_CLIENT);

    TF_CHECK(c != NULL);
    if (nick != NULL) {
        memcpy(c->nick, nick, strlen(nick) + 1u);
    }
    return c;
}

/* How many times `c` appears in the enumeration? Zero is the answer a teardown
 * depends on and two is the answer #103 produced. */
static size_t times_enumerated(const server_t *s, const conn_t *c)
{
    size_t i;
    size_t n = 0;

    for (i = 0; i < server_nick_count(s); i++) {
        if (server_nick_at(s, i) == c) {
            n++;
        }
    }
    return n;
}

int main(void)
{
    server_t s;
    conn_t *a;
    conn_t *b;
    conn_t *stale;
    conn_t *denied;
    conn_t *never;

    TF_CHECK_MSG(server_init(&s, "irc.test") == 0, "server_init failed");
    a = make_conn(10, "carol");
    b = make_conn(11, "erin");

    /* --- one connection, one entry, however many names it claims --- */
    TF_CHECK_MSG(server_nick_claim(&s, "carol", a) == 0,
                 "the first claim failed");
    TF_CHECK_MSG(server_nick_count(&s) == 1,
                 "a claim did not add exactly one entry: %zu enumerated",
                 server_nick_count(&s));
    /* A second name for the SAME connection. The table takes it -- this is the
     * rename's overlap, and refusing it would force the release-first ordering
     * handle_nick() is written to avoid -- but the enumeration must not grow,
     * because it counts USERS and WHO's 352 is one line per user. */
    TF_CHECK_MSG(server_nick_claim(&s, "dave", a) == 0,
                 "a connection holding one name was refused a second: the "
                 "rename claims the new name before releasing the old one, so "
                 "refusing it would open a window in which the old name is "
                 "unowned and another client can take it");
    TF_CHECK_MSG(server_nick_count(&s) == 1,
                 "one connection holding two names was enumerated %zu times: "
                 "the vector counts names where it must count connections, so "
                 "WHO lists the same user twice", server_nick_count(&s));
    TF_CHECK_MSG(times_enumerated(&s, a) == 1,
                 "the connection appears %zu times in the enumeration, "
                 "expected exactly 1", times_enumerated(&s, a));
    /* Both names really are in the table. The point above is that the
     * ENUMERATION is a set, not that a second claim is thrown away. */
    TF_CHECK_MSG(server_nick_lookup(&s, "carol") == a &&
                     server_nick_lookup(&s, "DAVE") == a,
                 "the two names a connection holds are not both in the table");

    /* A different connection is a different user, and does add an entry. */
    TF_CHECK_MSG(server_nick_claim(&s, "erin", b) == 0,
                 "an unrelated claim was refused");
    TF_CHECK_MSG(server_nick_count(&s) == 2,
                 "two users are enumerated %zu times, expected 2",
                 server_nick_count(&s));
    TF_CHECK_MSG(times_enumerated(&s, a) == 1 && times_enumerated(&s, b) == 1,
                 "the two users are not enumerated exactly once each");

    /* --- the rename: claim, release, and the connection stays put --- */
    /* Exactly what handle_nick() does, in the order it does it. This is the case
     * a "a release removes the holder from the enumeration" rule would break: at
     * the release this connection still holds the NEW name, so it must not leave
     * the walk. */
    TF_CHECK_MSG(server_nick_claim(&s, "hank", a) == 0,
                 "the rename's claim failed");
    server_nick_release(&s, "dave");
    TF_CHECK_MSG(server_nick_lookup(&s, "dave") == NULL,
                 "the released name is still in the table");
    TF_CHECK_MSG(server_nick_lookup(&s, "hank") == a,
                 "the new name is not in the table after a rename");
    TF_CHECK_MSG(server_nick_count(&s) == 2,
                 "a rename left %zu entries enumerated, expected 2: the "
                 "connection gave up a name and took another, so it is still "
                 "one user", server_nick_count(&s));
    TF_CHECK_MSG(times_enumerated(&s, a) == 1,
                 "the renamed connection appears %zu times, expected 1",
                 times_enumerated(&s, a));

    /* --- the teardown retires EVERY name the connection holds --- */
    /* a holds "carol" and "hank" here. This is the memory-safety half of #102:
     * the old close path removed the name in conn_t::nick and nothing else, so a
     * second name stayed in the table pointing at a conn_t about to be freed --
     * and a PRIVMSG to that name resolves straight to freed memory. */
    server_nick_unclaim(&s, a);
    TF_CHECK_MSG(server_nick_lookup(&s, "carol") == NULL &&
                     server_nick_lookup(&s, "hank") == NULL,
                 "retiring a connection left one of its names in the table: a "
                 "message to that nickname resolves to a freed connection");
    TF_CHECK_MSG(times_enumerated(&s, a) == 0 && server_nick_count(&s) == 1,
                 "retiring a connection left it in the enumeration: %zu entries, "
                 "expected 1", server_nick_count(&s));
    /* And the name is genuinely free, for whoever asks next. */
    TF_CHECK_MSG(server_nick_claim(&s, "carol", b) == 0,
                 "a retired connection's name could not be claimed: the table "
                 "still holds a name nobody can use");

    /* --- a connection that was DENIED a name must not evict the holder --- */
    /* b now holds "erin" and "carol" and its display field says "erin".
     *
     * Two shapes of "not the holder" are checked, and the second one is the
     * interesting one. `denied` is the obvious case: a client that asked for an
     * occupied nickname was refused, so its display field is still empty and
     * there is nothing to match. `stale` is the reachable one -- a connection
     * that HELD "erin", gave it up, and still has the old spelling in its
     * display field, which is exactly what conn_t::nick is after a rename away
     * because only a successful claim ever writes it. Its display field now
     * matches the REAL holder's, and the removal this replaces matched on that
     * field: retiring `stale` took the entry belonging to `b` out of the
     * enumeration, so WHO stopped listing a user who is still connected and
     * still holds the name. Nothing about the registry had noticed: the table
     * was right and the count was wrong. */
    denied = make_conn(13, NULL);
    server_nick_unclaim(&s, denied);
    TF_CHECK_MSG(server_nick_lookup(&s, "carol") == b &&
                     server_nick_lookup(&s, "erin") == b,
                 "retiring a connection that was refused a nickname evicted a "
                 "name from the table that somebody else holds");
    TF_CHECK_MSG(server_nick_count(&s) == 1 && times_enumerated(&s, b) == 1,
                 "retiring a connection that was refused a nickname disturbed "
                 "the enumeration: %zu entries, expected 1",
                 server_nick_count(&s));
    conn_free(denied);

    stale = make_conn(12, "erin"); /* held "erin" once; gave it up */
    server_nick_unclaim(&s, stale);
    TF_CHECK_MSG(server_nick_lookup(&s, "erin") == b,
                 "retiring a connection that had already given up a nickname "
                 "evicted the name from the table: the entry belonged to "
                 "somebody else");
    TF_CHECK_MSG(server_nick_count(&s) == 1 && times_enumerated(&s, b) == 1,
                 "the real holder lost its enumeration entry when an unrelated "
                 "connection was retired: %zu entries, expected 1, and the "
                 "holder appears %zu times",
                 server_nick_count(&s), times_enumerated(&s, b));

    /* --- the reaper after a QUIT: the same teardown, run again --- */
    /* The ordering handle_quit() produces, and the same trap one step later. The
     * handler retires the connection, ANOTHER client takes the name it gave up,
     * and the reaper then retires the original conn a second time at its fixed
     * point. That second call must find no name mapping to this conn and do
     * nothing -- in particular it must not evict the successor, whose display
     * field is the very string the dead connection still carries. */
    server_nick_unclaim(&s, b);
    TF_CHECK_MSG(server_nick_count(&s) == 0 &&
                     server_nick_lookup(&s, "carol") == NULL &&
                     server_nick_lookup(&s, "erin") == NULL,
                 "retiring the last holder did not empty the index: %zu entries "
                 "remain", server_nick_count(&s));
    TF_CHECK_MSG(server_nick_claim(&s, "erin", stale) == 0,
                 "a retired connection's name could not be claimed");
    server_nick_unclaim(&s, b); /* the reaper, after the handler already ran */
    server_nick_unclaim(&s, b);
    TF_CHECK_MSG(server_nick_lookup(&s, "erin") == stale,
                 "the reaper's second teardown of a QUIT-ing connection evicted "
                 "the name its SUCCESSOR had taken");
    TF_CHECK_MSG(server_nick_count(&s) == 1 && times_enumerated(&s, stale) == 1,
                 "the successor is not enumerated exactly once: %zu entries, and "
                 "it appears %zu times", server_nick_count(&s),
                 times_enumerated(&s, stale));

    /* --- a connection that never claimed a name --- */
    /* The majority of closes: a client dropped during registration. Retiring it
     * must be a no-op rather than a crash or an index edit. */
    never = make_conn(14, NULL);
    server_nick_unclaim(&s, never);
    TF_CHECK_MSG(server_nick_count(&s) == 1 && server_nick_lookup(&s, "erin") == stale,
                 "retiring a connection that never held a nickname changed the "
                 "index: %zu entries", server_nick_count(&s));
    conn_free(never);

    /* --- everything retired --- */
    server_nick_unclaim(&s, stale);
    TF_CHECK_MSG(server_nick_count(&s) == 0,
                 "the enumeration is not empty after every connection is "
                 "retired: %zu entries remain", server_nick_count(&s));
    /* Every name is claimable again, by anyone: an index that has been through a
     * teardown is in the same state as a fresh one. */
    TF_CHECK_MSG(server_nick_claim(&s, "carol", a) == 0 &&
                     server_nick_claim(&s, "erin", b) == 0,
                 "names were not claimable after every connection was retired: "
                 "the teardown left the index in a state a new node is not in");

    conn_free(a);
    conn_free(b);
    conn_free(stale);
    server_shutdown(&s);
    tf_done("nick_index");
    return 0;
}
