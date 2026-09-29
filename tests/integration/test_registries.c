/* test_registries.c -- the nick registry, the channel registry, and the
 * per-SERVER message id.
 *
 * docs/SERVER_DESIGN.md 2.1 (nick uniqueness is per SERVER, so bob@a and bob@b
 * are distinct keys and there is no global collision to resolve), 2.2 (the
 * channel key space), 2.4 (ids come from a per-SERVER monotonic counter, and
 * epoch is per-boot).
 *
 * These are registry contracts rather than protocol behaviour, so they are
 * tested in process against server_t. The connection registry itself -- the
 * fd-indexed one, its O(1) lookup and its zero-on-close behaviour -- is tested
 * over a real socket in test_reaper_close.c, because that is where a mistake in
 * it shows up as a leaked or cross-wired connection.
 *
 * The id counter is the one with a Phase 6 trap in it, and the trap is worth
 * stating: a per-CONNECTION counter makes two connections on one server both
 * emit (server, 1), and a peer then silently drops the second message as a
 * duplicate. So the assertions here are that two "connections" drawing from one
 * server get DIFFERENT ids, that the sequence is monotonic, and that 0 is never
 * handed out because 0 means "tag absent" rather than "first message".
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/connection.h"
#include "core/message.h"
#include "core/server.h"
#include "harness/test_util.h"

static conn_t *fake_conn(int fd, const char *nick)
{
    conn_t *c = conn_new(fd, CONN_CLIENT);

    TF_CHECK(c != NULL);
    if (nick != NULL) {
        memcpy(c->nick, nick, strlen(nick) + 1u);
    }
    return c;
}

int main(void)
{
    server_t s;
    conn_t *a;
    conn_t *b;
    uint64_t id1;
    uint64_t id2;
    uint64_t id3;

    TF_CHECK_MSG(server_init(&s, "irc.test") == 0, "server_init failed");

    /* --- a node name must be able to carry the 2.4 origin tag --- */
    {
        server_t bad;

        TF_CHECK_MSG(server_init(&bad, "has space") != 0,
                     "a server name with a space was accepted: it could not "
                     "be stamped on an irc-serve-origin tag, which would "
                     "break the never-forward-own-origin rule at the first "
                     "relay");
        TF_CHECK_MSG(server_init(&bad, "") != 0, "an empty name was accepted");
    }

    /* --- nick registry: uniqueness is per server, not global --- */
    a = fake_conn(10, "bob");
    b = fake_conn(11, "alice");
    TF_CHECK_MSG(server_nick_claim(&s, "bob", a) == 0, "the first claim on "
                 "'bob' failed");
    TF_CHECK_MSG(server_nick_lookup(&s, "bob") == a,
                 "lookup did not return the claiming connection");
    /* The duplicate is refused. Phase 3 turns this into 433; it is not a
     * rename here, because rename-the-loser needs a broadcast that does not
     * exist until Phase 9. */
    TF_CHECK_MSG(server_nick_claim(&s, "bob", b) != 0,
                 "a duplicate nick was allowed: two connections would both be "
                 "'bob' to a user");
    /* bob@a and bob@b are different registry keys in Phase 2's single-server
     * world, which is exactly right: there is no collision to resolve here, and
     * inventing one would break a lone server. */
    TF_CHECK_MSG(server_nick_claim(&s, "alice", b) == 0,
                 "an unrelated nick was refused");

    /* A nick that cannot be qualified must not enter the registry at all: 2.1's
     * nick@server split is unsound if '@' or a channel sigil can appear. */
    TF_CHECK_MSG(server_nick_claim(&s, "a@evil", b) != 0,
                 "'a@evil' was accepted as a nick");
    TF_CHECK_MSG(server_nick_claim(&s, "a#b", b) != 0, "'a#b' was accepted");
    TF_CHECK_MSG(server_nick_claim(&s, "1bob", b) != 0,
                 "a nick starting with a digit was accepted");
    TF_CHECK_MSG(server_nick_claim(&s, "", b) != 0, "an empty nick was "
                 "accepted");
    TF_CHECK_MSG(server_nick_lookup(&s, "a@evil") == NULL,
                 "a rejected nick is in the registry anyway");

    /* Releasing frees the name for someone else, and releasing a name that is
     * not there is harmless. */
    server_nick_release(&s, "bob");
    TF_CHECK_MSG(server_nick_lookup(&s, "bob") == NULL,
                 "the name was not released");
    TF_CHECK_MSG(server_nick_claim(&s, "bob", b) == 0,
                 "the released name could not be claimed again");
    server_nick_release(&s, "nobody");
    server_nick_release(&s, "nobody");

    /* --- the same registry, folded (2.1 / RFC 2812 2.3.1) ---
     * A fresh conn rather than a or b, because those two were deliberately given
     * nicknames that do not match the names they were made to hold -- "bob" is
     * held by a conn whose conn_t::nick is "bob", but "alice" is held by a conn
     * whose conn_t::nick is also "bob" -- and this block is about the ENUMERATION
     * agreeing with the table, which a fixture like that cannot answer for.
     *
     * Every count is a DELTA rather than an absolute, for the same reason: what
     * this block must show is that a folded claim and a folded release move the
     * enumeration by exactly one, not what the enumeration happens to hold.
     * test_nick_case.c is the wire-level statement of the same rule. */
    {
        conn_t *d = fake_conn(12, "carol");
        size_t before = server_nick_count(&s);

        TF_CHECK_MSG(server_nick_claim(&s, "carol", d) == 0,
                     "a free nickname was refused");
        TF_CHECK_MSG(server_nick_count(&s) == before + 1,
                     "a claim did not add exactly one entry to the enumeration: "
                     "%zu held, expected %zu",
                     server_nick_count(&s), before + 1u);
        TF_CHECK_MSG(server_nick_lookup(&s, "CAROL") == d,
                     "a differently-cased spelling did not find a held nickname: "
                     "2.1 and RFC 2812 2.3.1 both make a nickname "
                     "case-insensitive");
        TF_CHECK_MSG(server_nick_claim(&s, "CaRoL", a) != 0,
                     "'CaRoL' was claimable while 'carol' was held: they are one "
                     "name, so this node would be running two users whose "
                     "nicknames differ only in case");
        TF_CHECK_MSG(server_nick_count(&s) == before + 1,
                     "a REFUSED claim still added to the enumeration (%zu held, "
                     "expected %zu): a name nobody holds would be listed by WHO",
                     server_nick_count(&s), before + 1u);
        /* Releasing by the OTHER spelling must reach both halves of the index.
         * The count is the half that goes wrong quietly: a release that removed
         * the table entry and left the vector holding the connection would leave
         * WHO <mask> listing somebody this node no longer holds a nickname for,
         * with nothing to reconcile the two. */
        server_nick_release(&s, "cAROL");
        TF_CHECK_MSG(server_nick_lookup(&s, "carol") == NULL,
                     "a release by a differently-cased spelling did not remove "
                     "the name");
        TF_CHECK_MSG(server_nick_count(&s) == before,
                     "the release removed the table entry but not the "
                     "enumeration: %zu enumerated, expected %zu",
                     server_nick_count(&s), before);
        TF_CHECK_MSG(server_nick_claim(&s, "CarOl", d) == 0,
                     "the name was not claimable in any case after a folded "
                     "release");
        server_nick_release(&s, "CAROL");
        conn_free(d); /* never registered in by_fd, so shutdown will not own it */
    }

    /* --- channel registry: names in Phase 2, values in Phase 4 --- */
    TF_CHECK_MSG(server_chan_add(&s, "#Chan") == 0, "adding a channel failed");
    TF_CHECK_MSG(server_chan_add(&s, "#Chan") != 0,
                 "a channel was added twice");
    TF_CHECK_MSG(server_chan_lookup(&s, "#chan") == NULL,
                 "channel lookup is case-insensitive: 2.2 says the name is "
                 "always uppercase-normalised, and that normalisation is "
                 "Phase 4's, not a silent case-fold here");
    TF_CHECK_MSG(server_chan_add(&s, "") != 0, "an empty channel name was "
                 "accepted");
    server_chan_remove(&s, "#Chan");
    TF_CHECK_MSG(server_chan_lookup(&s, "#Chan") == NULL,
                 "the channel was not removed");
    server_chan_remove(&s, "#Chan"); /* removing twice is harmless */

    /* --- 2.4: ids come from the server, not the connection --- */
    TF_CHECK_MSG(s.msg_id == 1, "the id counter does not start at 1");
    TF_CHECK_MSG(s.epoch != 0, "the per-boot epoch is zero, which is the "
                 "value that means 'unset'");
    id1 = server_next_msg_id(&s);
    id2 = server_next_msg_id(&s);
    id3 = server_next_msg_id(&s);
    TF_CHECK_MSG(id1 == 1 && id2 == 2 && id3 == 3,
                 "ids are %llu %llu %llu, expected 1 2 3 from a monotonic "
                 "counter",
                 (unsigned long long)id1, (unsigned long long)id2,
                 (unsigned long long)id3);
    TF_CHECK_MSG(id1 != 0 && id2 != 0 && id3 != 0,
                 "0 was handed out as a message id: 0 means the tag was "
                 "absent, so a peer must never read it as a real id");

    /* Two connections on one server drawing ids must not collide. This is the
     * 2.4 bug the per-SERVER counter exists to prevent, so it is asserted in
     * the shape the bug would take: a per-connection counter would give both
     * of these the same first id. */
    {
        uint64_t from_a[3];
        uint64_t from_b[3];
        int i;

        for (i = 0; i < 3; i++) {
            from_a[i] = server_next_msg_id(&s);
            from_b[i] = server_next_msg_id(&s);
        }
        for (i = 0; i < 3; i++) {
            TF_CHECK_MSG(from_a[i] != from_b[i],
                         "two draws produced the same id %llu: a peer would "
                         "silently drop the second as a duplicate",
                         (unsigned long long)from_a[i]);
            TF_CHECK_MSG(from_b[i] > from_a[i],
                         "the id sequence is not monotonic (%llu then %llu)",
                         (unsigned long long)from_a[i],
                         (unsigned long long)from_b[i]);
        }
    }

    /* --- the fd-indexed connection registry: O(1) by descriptor --- */
    {
        conn_t *too_big;
        conn_t *negative;
        int i;

        for (i = 0; i < 200; i++) {
            TF_CHECK_MSG(server_conn(&s, i) == NULL,
                         "descriptor %d resolved to a connection before any "
                         "was added", i);
        }
        TF_CHECK_MSG(server_add_conn(&s, a) == 0, "adding a failed");
        TF_CHECK_MSG(server_conn(&s, 10) == a, "lookup by descriptor missed");
        TF_CHECK_MSG(server_conn(&s, 11) == NULL,
                     "the wrong descriptor resolved to a connection");
        TF_CHECK_MSG(s.nconns == 1, "nconns=%zu after one add",
                     s.nconns);
        /* A second connection on an occupied descriptor is refused, not
         * silently displacing the first: a displaced conn would leak and its
         * descriptor would never be closed. */
        TF_CHECK_MSG(server_add_conn(&s, b) == 0, "adding b failed");
        TF_CHECK_MSG(server_add_conn(&s, b) != 0,
                     "the same connection was registered twice on one "
                     "descriptor");
        /* An out-of-range descriptor cannot be registered: by_fd is indexed by
         * descriptor, so this is the same bound the accept site enforces. */
        too_big = fake_conn(FD_SETSIZE, NULL);
        negative = fake_conn(-1, NULL);
        TF_CHECK_MSG(server_add_conn(&s, too_big) != 0,
                     "a descriptor at FD_SETSIZE was registered: it could not "
                     "be put in the poll set, so it would never be served");
        TF_CHECK_MSG(server_add_conn(&s, negative) != 0,
                     "a negative descriptor was registered");
        /* Rejected, so the server never took ownership: freed here rather than
         * by server_shutdown(). */
        conn_free(too_big);
        conn_free(negative);
        /* Closing clears the slot completely, and closing an unregistered
         * descriptor is a no-op rather than a double close. */
        TF_CHECK_MSG(server_conn(&s, 10) != NULL, "a vanished before close");
        server_close_conn(&s, 10);
        TF_CHECK_MSG(server_conn(&s, 10) == NULL,
                     "the slot was not cleared on close");
        TF_CHECK_MSG(s.n_closed == 1, "n_closed=%llu after one close",
                     (unsigned long long)s.n_closed);
        server_close_conn(&s, 10);
        TF_CHECK_MSG(s.n_closed == 1,
                     "closing an already-closed descriptor was counted: the "
                     "reaper must be idempotent");
    }

    /* server_shutdown closes what is left, so a node cannot exit holding
     * descriptors. Both a and b were freed by the close above and by this
     * shutdown -- a registered conn_t is owned by the registry, which is why
     * nothing is freed by hand at the end. */
    TF_CHECK(s.nconns == 1);
    server_shutdown(&s);
    TF_CHECK_MSG(s.n_closed == 2, "n_closed=%llu after shutdown, expected the "
                 "one remaining connection to be closed too",
                 (unsigned long long)s.n_closed);
    TF_CHECK_MSG(s.by_fd == NULL, "the registry survived shutdown");

    tf_done("registries");
    return 0;
}
