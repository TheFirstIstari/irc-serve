/* channel.c -- see channel.h. The chan_t model, the ownership rules of 2.2, and
 * the two federation invariants that are single-node testable.
 *
 * Authority: docs/SERVER_DESIGN.md 2.2 in the body, and 7/Phase 4's requirement
 * that the struct shapes land final here rather than being revised in Phase 6.
 *
 * The split with server.c is by question, not by convenience. THIS file answers
 * "what is true of a channel"; server.c answers "what does this node hold",
 * because the hash table it needs is file-private to server.c and a registry is
 * the registry's owner's business. The node-side accessors declared in
 * channel.h are therefore implemented in server.c, next to the strtab.
 */
#include "core/channel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Phase 9: the session window, asked by chan_dispose_if_empty() whether a
 * channel is still HELD by a client that is coming back to it. See the guard there
 * for why the hold is short: 2.2's disposal rule is delayed, not exempted. */
#include "account_store.h"
#include "core/resume.h"
#include "core/reply.h"

/* ---------------------------------------------------------------------------
 * Small helpers
 * ------------------------------------------------------------------------- */

/* Copy at most `cap - 1` bytes and NUL-terminate. Returns 1 if the whole value
 * fitted, 0 if it was truncated -- so a caller storing into a fixed field can
 * REPORT the truncation instead of silently keeping a prefix, which is 3.2's
 * rule about not delivering a shortened value. */
static int copy_bounded(char *dst, size_t cap, const char *src)
{
    size_t n;

    if (dst == NULL || src == NULL || cap == 0) {
        return 0;
    }
    n = strlen(src);
    if (n >= cap) {
        n = cap - 1u;
        memcpy(dst, src, n);
        dst[n] = '\0';
        return 0;
    }
    memcpy(dst, src, n + 1u);
    return 1;
}

/* ASCII upper-case. Deliberately not tolower()/toupper() in a locale: 005
 * advertises CASEMAPPING=ascii, message.c's up() is ASCII-only, and a
 * locale-dependent fold here would make the registry key depend on the
 * environment the node happens to run in. */
static char up_ascii(char c)
{
    if (c >= 'a' && c <= 'z') {
        return (char)(c - ('a' - 'A'));
    }
    return c;
}

/* Case-insensitive equality, ASCII-folded, for server names. 2.1 and 2.4 both
 * say a server-name comparison must be case-insensitive, and this is the one
 * place the rule is implemented for channel state. */
static int same_name(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    while (*a != '\0' && *b != '\0') {
        if (up_ascii(*a) != up_ascii(*b)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

/* ---------------------------------------------------------------------------
 * Names
 * ------------------------------------------------------------------------- */

int chan_name_valid(const char *name)
{
    size_t n;

    if (name == NULL) {
        return 0;
    }
    n = strlen(name);
    /* CHANTYPES=#&, so a channel name begins with one of the two sigils. A bare
     * sigil is not a name: there is nothing after it to distinguish. The two
     * bytes are CHAN_TYPE1 and CHAN_TYPE2 rather than literals, because 005
     * advertises CHAN_TYPES and a third spelling of the same pair is how the
     * advertised token and the validator come to disagree. */
    if (n < 2u || n > (size_t)CHAN_MAX_NAME) {
        return 0;
    }
    if (name[0] != CHAN_TYPE1 && name[0] != CHAN_TYPE2) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)name[i];

        /* Space, comma, colon, and every control character are refused. Comma
         * because it is JOIN's argument separator and an unescaped one would
         * make "JOIN #a,#b" ambiguous with a channel actually named "#a,#b";
         * colon because the wire colons the trailing parameter; control
         * characters because message_format() refuses CR and LF in any field
         * and a channel name is rendered as a middle parameter in most of them. */
        if (ch <= 0x20u || ch == 0x7Fu) {
            return 0;
        }
        if (ch == ',' || ch == ':' || ch == '@') {
            return 0;
        }
    }
    return 1;
}

void chan_name_upper(char *out, size_t cap, const char *name)
{
    size_t i;

    if (out == NULL || cap == 0) {
        return;
    }
    if (name == NULL) {
        out[0] = '\0';
        return;
    }
    for (i = 0; name[i] != '\0' && i + 1u < cap; i++) {
        out[i] = up_ascii(name[i]);
    }
    out[i] = '\0';
}

/* ---------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

chan_t *chan_new(const char *name, const char *origin, uint64_t origin_epoch)
{
    chan_t *ch;
    char canonical[CHAN_MAX_NAME + 1];

    if (!chan_name_valid(name) || origin == NULL || origin[0] == '\0' ||
        strlen(origin) > (size_t)CHAN_MAX_SERVER) {
        return NULL;
    }
    ch = (chan_t *)calloc(1, sizeof *ch);
    if (ch == NULL) {
        return NULL;
    }
    (void)chan_name_upper(canonical, sizeof canonical, name);
    memcpy(ch->name, canonical, strlen(canonical) + 1u);
    if (!copy_bounded(ch->origin, sizeof ch->origin, origin)) {
        free(ch);
        return NULL;
    }
    ch->origin_epoch = origin_epoch;
    /* 329 RPL_CREATIONTIME is a creation timestamp, so the value is a wall
     * clock read here for the same reason chan_set_topic() reads one. Written
     * once and never rewritten. */
    ch->created_at = time(NULL);
    return ch;
}

void chan_free(chan_t *ch)
{
    if (ch == NULL) {
        return;
    }
    free(ch->members);
    free(ch->servers);
    free(ch->bans);
    free(ch->remotes);
    free(ch);
}

/* ---------------------------------------------------------------------------
 * Members
 * ------------------------------------------------------------------------- */

struct member *chan_find_member(const chan_t *ch, const conn_t *c)
{
    if (ch == NULL || c == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < ch->nmembers; i++) {
        if (ch->members[i].c == c) {
            return &ch->members[i];
        }
    }
    return NULL;
}

int chan_member_is(const struct member *m, unsigned flag)
{
    return (m != NULL && (m->flags & flag) != 0u) ? 1 : 0;
}

int chan_member_live(const struct member *m)
{
    return (m != NULL && m->c != NULL && m->c->state != CONN_CLOSING) ? 1 : 0;
}

int chan_add_member(chan_t *ch, conn_t *c, unsigned flags)
{
    if (ch == NULL || c == NULL) {
        return -1;
    }
    /* A repeat JOIN is not an error here. The caller decides how to say so (482
     * for JOIN, per RFC 2812 3.3.1), so this function's job is only to not
     * produce a second member record for one conn -- which would double every
     * broadcast the conn receives. */
    if (chan_find_member(ch, c) != NULL) {
        return 0;
    }
    if (ch->nmembers == ch->cap) {
        size_t want = (ch->cap == 0) ? 4u : ch->cap * 2u;
        struct member *grown =
            (struct member *)realloc(ch->members, want * sizeof *grown);

        if (grown == NULL) {
            return -1;
        }
        ch->members = grown;
        ch->cap = want;
    }
    ch->members[ch->nmembers].c = c;
    ch->members[ch->nmembers].flags = flags;
    ch->nmembers++;
    return 0;
}

/* Remove `who`'s member record, keeping the remaining members in join order.
 * memmove rather than swap-with-last because the order is load-bearing: 353
 * renders members in join order, and a channel whose roster order changed
 * because somebody left would make LIST and 353 output depend on history. */
static void member_drop(chan_t *ch, conn_t *who)
{
    for (size_t i = 0; i < ch->nmembers; i++) {
        if (ch->members[i].c == who) {
            (void)memmove(&ch->members[i], &ch->members[i + 1u],
                          (ch->nmembers - i - 1u) * sizeof ch->members[0]);
            ch->nmembers--;
            return;
        }
    }
}

int chan_set_member_flags(chan_t *ch, conn_t *c, int on, unsigned flag)
{
    struct member *m = chan_find_member(ch, c);
    int was;

    if (m == NULL) {
        return -1;
    }
    was = (m->flags & flag) != 0u;
    if (on) {
        m->flags |= flag;
    } else {
        m->flags &= ~flag;
    }
    return (was != (on ? 1 : 0)) ? 1 : 0;
}

void chan_member_leave(server_t *s, chan_t *ch, conn_t *who, int echo_to_who,
                       const char *reason)
{
    char hostmask[CONN_HOSTMASK_MAX];
    const char *params[2];
    int n = 0;

    if (ch == NULL || who == NULL) {
        return;
    }
    if (echo_to_who == 0) {
        /* Remove first, then address what is left. On the teardown path the
         * departing conn is going away, and emitting to it would be a
         * reply() refusal -- which lands on n_reply_refused, the counter the
         * whole reply module keeps at zero because a non-zero value is a bug
         * report rather than a metric. */
        member_drop(ch, who);
    }
    if (conn_hostmask(who, hostmask, sizeof hostmask) == 0) {
        hostmask[0] = '\0';
    }
    /* params[0] is the CHANNEL. The prefix goes to send_line() as its own
     * argument and is not a parameter: it is not a parameter on the wire either,
     * and putting it in the array would render it as one. */
    params[n++] = ch->name;
    if (reason != NULL && reason[0] != '\0') {
        /* RFC 1459 2.3.1's optional trailing reason. The formatter colons it, so
         * a reason containing a space is representable here and nowhere else in
         * this protocol. */
        params[n++] = reason;
    }
    for (size_t i = 0; i < ch->nmembers; i++) {
        /* Skip a member the loop has already retired -- see chan_member_live().
         * `who` itself is in this list on the echo_to_who == 1 path, and on the
         * teardown path it has already been dropped; the third case is another
         * member whose conn hit EOF in the same read step. */
        if (chan_member_live(&ch->members[i]) == 0) {
            continue;
        }
        (void)send_line(s, ch->members[i].c, hostmask, "PART", params, n);
    }
    if (echo_to_who != 0) {
        member_drop(ch, who);
    }
    printf("[observable] chan_part: channel=%s nick=%s members=%zu servers=%zu\n",
           ch->name, who->nick, ch->nmembers, ch->nservers);
}

int chan_has_flag(const chan_t *ch, const conn_t *c, unsigned flag)
{
    return chan_member_is(chan_find_member(ch, c), flag);
}

int chan_same_name(const char *a, const char *b)
{
    return same_name(a, b);
}

struct member *chan_find_nick(const chan_t *ch, const char *nick)
{
    if (ch == NULL || nick == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < ch->nmembers; i++) {
        if (ch->members[i].c != NULL && same_name(ch->members[i].c->nick, nick)) {
            return &ch->members[i];
        }
    }
    return NULL;
}

int chan_remove_member(chan_t *ch, conn_t *c)
{
    size_t before;

    if (ch == NULL || c == NULL) {
        return 0;
    }
    before = ch->nmembers;
    member_drop(ch, c);
    return (ch->nmembers != before) ? 1 : 0;
}

/* ---------------------------------------------------------------------------
 * conn_t::chans
 * ---------------------------------------------------------------------------
 * The connection's own list of channels. It is NOT derivable from the other
 * direction -- iterating every channel to find the ones a connection is in is
 * O(channels) and, more to the point, a channel that has outlived its last
 * local member is in no connection's list at all -- so both indexes are real and
 * both are maintained together. chan_attach_conn()/chan_detach_conn() are the
 * only writers.
 *
 * conn_t::chans' layout is final as of Phase 2 and is not touched here: this
 * file stores chan_t pointers in the array it declared.
 */
int chan_attach_conn(conn_t *c, chan_t *ch)
{
    if (c == NULL || ch == NULL) {
        return -1;
    }
    for (size_t i = 0; i < c->nchans; i++) {
        if (c->chans[i] == ch) {
            return 0; /* already listed */
        }
    }
    if (c->nchans == c->cap) {
        size_t want = (c->cap == 0) ? 4u : c->cap * 2u;
        struct chan **grown =
            (struct chan **)realloc(c->chans, want * sizeof *grown);

        if (grown == NULL) {
            return -1;
        }
        c->chans = grown;
        c->cap = want;
    }
    c->chans[c->nchans++] = ch;
    return 0;
}

int chan_detach_conn(conn_t *c, chan_t *ch)
{
    if (c == NULL || ch == NULL) {
        return -1;
    }
    for (size_t i = 0; i < c->nchans; i++) {
        if (c->chans[i] == ch) {
            (void)memmove(&c->chans[i], &c->chans[i + 1u],
                          (c->nchans - i - 1u) * sizeof c->chans[0]);
            c->nchans--;
            return 0;
        }
    }
    return 0; /* not listed; a double detach is harmless */
}

/* ---------------------------------------------------------------------------
 * Topic
 * ------------------------------------------------------------------------- */

int chan_set_topic(chan_t *ch, const char *topic, const char *who)
{
    if (ch == NULL || topic == NULL) {
        return -1;
    }
    /* Refused, not truncated. 3.2's rule about never delivering a silently
     * shortened parameter, applied to a value that is protocol-visible on the
     * very next 331/332/333. A topic cut mid-word is a different topic, and a
     * client would have no way to tell. */
    if (strlen(topic) > (size_t)CHAN_MAX_TOPIC) {
        return -1;
    }
    (void)copy_bounded(ch->topic, sizeof ch->topic, topic);
    if (topic[0] == '\0') {
        /* A cleared topic has no setter and no time: 331 says "no topic is
         * set", and leaving a stale 333 behind would claim a topic that is not
         * there. */
        ch->topic_who[0] = '\0';
        ch->topic_when = 0;
        return 0;
    }
    if (!copy_bounded(ch->topic_who, sizeof ch->topic_who,
                      (who != NULL) ? who : "")) {
        return -1;
    }
    /* The wall-clock read, and a deliberate one. 333's third field is a Unix
     * timestamp: a value the client can compare against its own clock. 3.4's
     * tick is CLOCK_MONOTONIC milliseconds since an arbitrary epoch, which is
     * monotonic but carries no calendar meaning, so there is nothing it could
     * stand in for. The same reasoning as 003's boot stamp in commands.c, and
     * read once per topic change rather than once per tick. */
    ch->topic_when = time(NULL);
    return 0;
}

time_t chan_created_at(const chan_t *ch)
{
    return (ch == NULL) ? (time_t)0 : ch->created_at;
}


/* ---------------------------------------------------------------------------
 * The remote server cache
 * ------------------------------------------------------------------------- */

int chan_server_add(chan_t *ch, const char *name)
{
    if (ch == NULL || name == NULL || name[0] == '\0' ||
        strlen(name) > (size_t)CHAN_MAX_SERVER) {
        return -1;
    }
    /* Idempotent. Two members behind the same server must not create two
     * entries: the set is a refcount, and the count lives in the origin's
     * records, so presence is the whole state. */
    if (chan_server_has(ch, name)) {
        return 0;
    }
    if (ch->nservers == ch->scap) {
        size_t want = (ch->scap == 0) ? 4u : ch->scap * 2u;
        struct chan_server *grown =
            (struct chan_server *)realloc(ch->servers, want * sizeof *grown);

        if (grown == NULL) {
            return -1;
        }
        ch->servers = grown;
        ch->scap = want;
    }
    if (!copy_bounded(ch->servers[ch->nservers].name,
                      sizeof ch->servers[0].name, name)) {
        return -1;
    }
    ch->nservers++;
    return 0;
}

int chan_server_remove(chan_t *ch, const char *name)
{
    if (ch == NULL || name == NULL) {
        return 0;
    }
    for (size_t i = 0; i < ch->nservers; i++) {
        if (same_name(ch->servers[i].name, name)) {
            (void)memmove(&ch->servers[i], &ch->servers[i + 1u],
                          (ch->nservers - i - 1u) * sizeof ch->servers[0]);
            ch->nservers--;
            return 1;
        }
    }
    return 0;
}

int chan_server_has(const chan_t *ch, const char *name)
{
    if (ch == NULL || name == NULL) {
        return 0;
    }
    for (size_t i = 0; i < ch->nservers; i++) {
        if (same_name(ch->servers[i].name, name)) {
            return 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * The remote roster
 * ------------------------------------------------------------------------- */

chan_remote_t *chan_remote_find(const chan_t *ch, const char *server,
                                const char *nick)
{
    if (ch == NULL || server == NULL || nick == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < ch->nremotes; i++) {
        if (same_name(ch->remotes[i].server, server) &&
            same_name(ch->remotes[i].nick, nick)) {
            return &ch->remotes[i];
        }
    }
    return NULL;
}

int chan_remote_add(chan_t *ch, const char *server, const char *member_server,
                    const char *nick, const char *account, unsigned flags)
{
    chan_remote_t *seen;

    if (ch == NULL || server == NULL || nick == NULL) {
        return -1;
    }
    /* THE ACCOUNT IS VALIDATED WHEN IT IS GIVEN AND TREATED AS ABSENT WHEN IT IS
     * NOT, on exactly the terms channel.h gives for `member_server`: "" and NULL
     * both mean "this node has not been told", which is the ordinary state of an
     * entry learned from a peer that does not carry the field. An account that
     * cannot be rendered as a PARAMETER is refused rather than stored, because a
     * roster entry carrying a string this node could not put on the wire is a
     * member it could not describe to a client -- and because the alternative is a
     * value that arrives intact and then cannot be emitted.
     *
     * AND "CANNOT BE STORED" IS PART OF THAT, because the field below is
     * CONN_MAX_NAME wide and a longer value used to be TRUNCATED by the
     * copy_bounded() whose result both call sites discard: a peer that reported a
     * 200-byte account got a 63-byte one, under a name it will never be asked
     * about again, and 3.2's rule against delivering a silently shortened value
     * exists for exactly that. account_name_wire_safe() refuses an over-long name
     * for the same reason it refuses a space -- and it is where the bound lives,
     * rather than here, so that the local writer and the two peer receivers
     * cannot come to disagree about where the edge is.
     *
     * `*` IS THE PROTOCOL'S SPELLING OF THE ABSENCE and is translated to "" here,
     * so that the roster holds "no account" rather than an account named "*". And
     * an EMPTY account is the not-told state and is not checked at all -- which is
     * why the guard tests for empty BEFORE it tests for safety rather than letting
     * account_name_wire_safe() refuse it. It did refuse it, and the symptom was a
     * resync that dropped every member it had been told nothing about. */
    if (account != NULL && account[0] != '\0' && account[0] != '*' &&
        account_name_wire_safe(account) == 0) {
        return -1;
    }
    /* Validated HERE, and not left to the caller, because the caller is a peer
     * protocol handler and the three rules it would have to remember are 2.1's
     * nickname charset and 2.4's server-name grammar (twice, because the entry
     * now names two different servers). All of them exist because later phases
     * build on them -- 2.1's split at the last '@' is unsound without the
     * charset -- and a roster entry that skipped any of them would be a name the
     * node could not qualify, compare or render. This is the first place in the
     * tree a nickname arrives from a network rather than from a client.
     *
     * member_server is validated when it is GIVEN and accepted as absent when it
     * is not: "" and NULL both mean "this node has not been told", which is the
     * ordinary state of an entry learned from a live SJOIN rather than a
     * corruption. Refusing an empty one would mean a live SJOIN could not record
     * a member at all.
     *
     * THE VALIDATION ALSO BOUNDS THE LENGTH, which is why the copy further down
     * cannot fail: irc_serve_server_name_valid() refuses a name longer than
     * IRC_MAX_SERVER_NAME, and CHAN_MAX_SERVER is that same bound, so a name
     * that passed is a name that fits. The copy's result is still checked for the
     * KEY, which is what the existing code did, and deliberately not for the
     * holder -- a refusal there would drop a whole member over a field the
     * member itself is fine without. */
    if (!irc_serve_server_name_valid(server) || !valid_nick(nick)) {
        return -1;
    }
    if (member_server != NULL && member_server[0] != '\0' &&
        !irc_serve_server_name_valid(member_server)) {
        return -1;
    }
    seen = chan_remote_find(ch, server, nick);
    if (seen != NULL) {
        /* A repeated SJOIN is a re-assertion, not a second member. The flags
         * are overwritten rather than OR'd because a peer that says `alice` is
         * no longer an op has told us something, and a roster where nobody can
         * ever lose +o is a roster that converges on the wrong answer.
         *
         * The holder is overwritten on a repeat even when the repeat is a live
         * SJOIN carrying no server, because a caller that knows nothing says so
         * and must not silently clear what a burst established -- a stale holder
         * is a fact this node can still act on, a cleared one is not. */
        seen->flags = flags;
        if (member_server != NULL && member_server[0] != '\0') {
            (void)copy_bounded(seen->member_server, sizeof seen->member_server,
                               member_server);
        }
        /* THE ACCOUNT IS OVERWRITTEN ON A REPEAT WHEN IT IS GIVEN, and NOT
         * CLEARED when it is not, which is `member_server`'s rule rather than
         * `host`'s. A peer's re-assertion is allowed to correct a stale account --
         * a user who changed accounts is now a fact this node should hold -- while
         * a peer that says nothing must not clear what a burst established, since a
         * cleared account is a member this node can no longer describe. */
        if (account != NULL && account[0] != '\0') {
            (void)copy_bounded(seen->account, sizeof seen->account,
                               (account[0] == '*') ? "" : account);
        }
        return 0;
    }
    if (ch->nremotes == ch->rcap) {
        size_t want = (ch->rcap == 0) ? 4u : ch->rcap * 2u;
        chan_remote_t *grown;

        if (ch->nremotes >= (size_t)CHAN_MAX_REMOTE_MEMBERS) {
            return -1;
        }
        grown = (chan_remote_t *)realloc(ch->remotes, want * sizeof *grown);
        if (grown == NULL) {
            return -1;
        }
        ch->remotes = grown;
        ch->rcap = want;
    }
    if (!copy_bounded(ch->remotes[ch->nremotes].nick,
                      sizeof ch->remotes[0].nick, nick) ||
        !copy_bounded(ch->remotes[ch->nremotes].server,
                      sizeof ch->remotes[0].server, server)) {
        return -1;
    }
    /* A new entry has no host: 4.3's SJOIN does not carry one, and a burst is
     * the only thing that can supply it. Written explicitly rather than left to
     * the allocator, because realloc does NOT zero the slot it hands back -- this
     * struct grew the field in C4, so an initialiser that existed only in
     * chan_new()'s memset would leave a RECYCLED element carrying the previous
     * member's host, which is a member impersonation bug wearing a memory bug's
     * clothes. `member_server` is written the same way and for the same reason:
     * it grew in C5, and a recycled element must not inherit the previous
     * member's server either -- that is the same impersonation with a
     * different field. */
    ch->remotes[ch->nremotes].host[0] = '\0';
    ch->remotes[ch->nremotes].member_server[0] = '\0';
    /* ...and `account` the same way, for the same reason, because it grew in
     * Phase 10.3 and a recycled element inheriting the previous member's account
     * would be that same impersonation with a third field. */
    ch->remotes[ch->nremotes].account[0] = '\0';
    if (account != NULL && account[0] != '\0') {
        (void)copy_bounded(ch->remotes[ch->nremotes].account,
                           sizeof ch->remotes[0].account,
                           (account[0] == '*') ? "" : account);
    }
    if (member_server != NULL) {
        (void)copy_bounded(ch->remotes[ch->nremotes].member_server,
                           sizeof ch->remotes[0].member_server, member_server);
    }
    ch->remotes[ch->nremotes].flags = flags;
    ch->nremotes++;
    return 0;
}

size_t chan_remote_purge(chan_t *ch, const char *server)
{
    size_t i = 0;
    size_t gone = 0;

    if (ch == NULL || server == NULL) {
        return 0;
    }
    /* Walking FORWARD under a shrinking array rather than backward from the end
     * under a growing one: the only other shape is an index that has to be
     * decremented on every removal, and the off-by-one that produces is silent
     * -- it skips a member rather than crashing. Entries are ordered, and 7/Phase
     * 4 fixes 353's rendering order across this array, so a forward walk is
     * also the one that does not reorder what is kept. */
    while (i < ch->nremotes) {
        if (same_name(ch->remotes[i].server, server)) {
            (void)memmove(&ch->remotes[i], &ch->remotes[i + 1u],
                          (ch->nremotes - i - 1u) * sizeof ch->remotes[0]);
            ch->nremotes--;
            gone++;
            continue; /* the element now at i is unexamined; look at it again */
        }
        i++;
    }
    return gone;
}

int chan_remote_set_host(chan_t *ch, const char *server, const char *nick,
                         const char *host)
{
    chan_remote_t *seen;

    if (ch == NULL || server == NULL || nick == NULL || host == NULL) {
        return -1;
    }
    /* An EMPTY host is a real answer, not a bad argument: it is what a burst
     * that carried none leaves behind, and refusing it would mean a peer could
     * not say "this member has no host" once a host had been learned. */
    seen = chan_remote_find(ch, server, nick);
    if (seen == NULL) {
        return -1;
    }
    return copy_bounded(seen->host, sizeof seen->host, host) ? 0 : -1;
}

/* The ident setter, and the same three refusals in the same order as
 * chan_remote_set_host()'s: bad argument, no such entry, or a value that does not
 * fit. The comment on the declaration has the argument for why the copy is
 * REFUSED rather than truncated; repeating it here would be worse than saying
 * nothing, so this points there. */
int chan_remote_set_user(chan_t *ch, const char *server, const char *nick,
                         const char *user)
{
    chan_remote_t *seen;

    if (ch == NULL || server == NULL || nick == NULL || user == NULL) {
        return -1;
    }
    /* An EMPTY ident is a real answer, not a bad argument, and it is what a live
     * SJOIN leaves behind -- 4.3's SJOIN carries no ident at all, so this is the
     * NORMAL state for a member learned from one rather than from a burst. That is
     * the same asymmetry `host` has and for the same reason, and the renderer has
     * to handle it rather than printing a half-built hostmask. */
    seen = chan_remote_find(ch, server, nick);
    if (seen == NULL) {
        return -1;
    }
    return copy_bounded(seen->user, sizeof seen->user, user) ? 0 : -1;
}

int chan_remote_remove(chan_t *ch, const char *server, const char *nick)
{
    if (ch == NULL || server == NULL || nick == NULL) {
        return 0;
    }
    for (size_t i = 0; i < ch->nremotes; i++) {
        if (same_name(ch->remotes[i].server, server) &&
            same_name(ch->remotes[i].nick, nick)) {
            (void)memmove(&ch->remotes[i], &ch->remotes[i + 1u],
                          (ch->nremotes - i - 1u) * sizeof ch->remotes[0]);
            ch->nremotes--;
            return 1;
        }
    }
    return 0;
}

int chan_remote_rename(chan_t *ch, const char *server, const char *old_nick,
                       const char *new_nick)
{
    if (ch == NULL || server == NULL || old_nick == NULL || new_nick == NULL) {
        return 0;
    }
    /* THE LEGALITY OF `new_nick` IS CHANNELS.C'S BUSINESS, not this function's,
     * and it is checked against the same rule SJOIN's entry path uses. A rename
     * that put an unusable name in a roster would make the member unrendereable
     * and -- because the roster is keyed on the name -- unremovable, so SPART
     * could never clean it up and a channel would keep a member for ever. That is
     * the failure this check exists to prevent, and it is why the refusal is here
     * rather than left to the registry. */
    if (!valid_nick(new_nick)) {
        return -1;
    }
    /* A RENAME TO A NAME THE SAME HOLDER ALREADY USES is refused, and the scan
     * runs BEFORE the find so a rename from `bob` to `bob_` on a roster holding
     * both cannot overwrite the other member. Chan_remote_t has no uniqueness
     * invariant the rest of this module maintains, so this check is what keeps
     * "one row per (server, nick)" true. */
    for (size_t i = 0; i < ch->nremotes; i++) {
        if (same_name(ch->remotes[i].server, server) &&
            same_name(ch->remotes[i].nick, new_nick)) {
            return -1;
        }
    }
    for (size_t i = 0; i < ch->nremotes; i++) {
        if (!same_name(ch->remotes[i].server, server) ||
            !same_name(ch->remotes[i].nick, old_nick)) {
            continue;
        }
        /* IN PLACE, and the reason is the row's other fields. A remove-then-add
         * would have to pass `flags` and `host` through two calls, and either
         * omitting them or letting the caller re-supply them is how a rename would
         * silently demote a channel operator. The copy goes through the same
         * bounded helper chan_remote_add() uses, so a name that would have been
         * refused at join time is refused here too -- and it cannot be, because
         * valid_nick() bounds it above, which is why the return value is dropped
         * rather than propagated. */
        (void)snprintf(ch->remotes[i].nick, sizeof ch->remotes[i].nick, "%s", new_nick);
        return 1;
    }
    return 0;
}

size_t chan_remote_count(const chan_t *ch)
{
    return (ch != NULL) ? ch->nremotes : 0u;
}

chan_remote_t *chan_remote_at(const chan_t *ch, size_t i)
{
    if (ch == NULL || i >= ch->nremotes) {
        return NULL;
    }
    return &ch->remotes[i];
}

/* ---------------------------------------------------------------------------
 * Modes
 * ------------------------------------------------------------------------- */

int chan_mode_is_origin_only(char m)
{
    switch (m) {
    /* 2.2 names exactly these three as the modes only the origin evaluates.
     * +e is a ban exception and +I an invite exception, so both are masks over
     * a channel's membership and both are decisions about who may join -- which
     * is why they sit with +b rather than with the prefix modes. */
    case 'b':
    case 'e':
    case 'I':
        return 1;
    default:
        return 0;
    }
}

int chan_mode_has(const chan_t *ch, char m)
{
    if (ch == NULL) {
        return 0;
    }
    for (size_t i = 0; ch->modes[i] != '\0'; i++) {
        if (ch->modes[i] == m) {
            return 1;
        }
    }
    return 0;
}

int chan_mode_set(chan_t *ch, char m, int on)
{
    char *at;
    size_t n;

    if (ch == NULL || m == '\0') {
        return -1;
    }
    n = strlen(ch->modes);
    at = strchr(ch->modes, m);
    if (on != 0) {
        if (at != NULL) {
            return 0; /* already set */
        }
        if (n >= (size_t)CHAN_MAX_MODES) {
            return -1; /* modes[] is full; the caller reports it */
        }
        ch->modes[n] = m;
        ch->modes[n + 1u] = '\0';
        return 1;
    }
    if (at == NULL) {
        return 0;
    }
    (void)memmove(at, at + 1, strlen(at + 1) + 1u);
    return 1;
}

int chan_ban_add(chan_t *ch, const char *mask)
{
    if (ch == NULL || mask == NULL || mask[0] == '\0' ||
        strlen(mask) > (size_t)CHAN_MAX_BAN) {
        return -1;
    }
    /* THE CAP, AND IT WAS NOT HERE. Phase 11's RFC 2812 sweep found this while
     * checking whether the ban-list-full refusal was reachable at all, and it was
     * not: `bcap` was doubled on demand with nothing comparing `nbans` against
     * CHAN_MAX_BANS, so the list grew without bound and the caller's `-1` branch
     * -- which is where 478 ERR_BANLISTFULL lives -- could never be taken.
     *
     * That made two documented claims false. channel.h says of this function that
     * it returns "-1 on ... a full list (CHAN_MAX_BANS)", and channel.h says of
     * the constant that "Bans ARE client-driven (MODE #c +b mask), so this bound
     * is reached by ordinary input and CHAN_MAX_BANS is a real limit rather than a
     * formality". Neither was true. The same mistake is documented one page above
     * for SERVER_TOPIC_MAX, and there the bound IS enforced and a loss is counted
     * -- which is what made the contrast checkable rather than a matter of taste.
     *
     * CHECKED HERE AND NOT BY THE CALLER, for the reason the growth is here and not
     * in the caller: this is the only writer of `ch->bans`, so a bound checked at
     * the call site would be one call site out of however many exist later, and the
     * next one would not have it. It also has to be checked before the growth, not
     * after, or the refusal has already allocated.
     *
     * THE COST IS ONE COMPARISON on a path a client reaches by asking for a ban,
     * and the cost of NOT having it is a per-channel array that a single `MODE #c
     * +b` loop grows without limit on an operator-controlled channel. */
    if (ch->nbans >= (size_t)CHAN_MAX_BANS) {
        return -1;
    }
    if (ch->nbans == ch->bcap) {
        size_t want = (ch->bcap == 0) ? 4u : ch->bcap * 2u;
        struct chan_ban *grown =
            (struct chan_ban *)realloc(ch->bans, want * sizeof *grown);

        if (grown == NULL) {
            return -1;
        }
        ch->bans = grown;
        ch->bcap = want;
    }
    if (!copy_bounded(ch->bans[ch->nbans].mask, sizeof ch->bans[0].mask, mask)) {
        return -1;
    }
    ch->nbans++;
    return 0;
}

int chan_ban_remove(chan_t *ch, const char *mask)
{
    if (ch == NULL || mask == NULL) {
        return 0;
    }
    for (size_t i = 0; i < ch->nbans; i++) {
        if (same_name(ch->bans[i].mask, mask)) {
            (void)memmove(&ch->bans[i], &ch->bans[i + 1u],
                          (ch->nbans - i - 1u) * sizeof ch->bans[0]);
            ch->nbans--;
            return 1;
        }
    }
    return 0;
}

int chan_mask_match(const char *mask, const char *value)
{
    const char *m;
    const char *v;
    const char *star;
    const char *retry;

    if (mask == NULL || value == NULL) {
        return 0;
    }
    /* Iterative backtracking glob, so a hostile mask cannot make this
     * exponential: one pointer to the last '*' and one to the character that
     * failed after it, advanced rather than recursed. */
    m = mask;
    v = value;
    star = NULL;
    retry = NULL;
    while (*v != '\0') {
        if (*m == '*') {
            star = m++;
            retry = v;
        } else if (*m == '?' ||
                   (up_ascii(*m) != '\0' && up_ascii(*m) == up_ascii(*v))) {
            m++;
            v++;
        } else if (star != NULL) {
            m = star + 1;
            v = ++retry;
        } else {
            return 0;
        }
    }
    while (*m == '*') {
        m++;
    }
    return (*m == '\0') ? 1 : 0;
}

int chan_banned(const chan_t *ch, const char *nick, const char *user,
                const char *host)
{
    /* The identity a mask is matched against, in the order that makes the
     * common masks work.
     *
     * The FULL "nick!user@host" is the one that matters and it has to be here:
     * a mask of the shape "*!*@10.0.0.1" contains the "!" and the "@", so it
     * cannot match a bare nickname and cannot match a bare host, and an
     * implementation that only ever compared against those two fields would
     * silently fail to enforce the single most common ban an operator writes.
     * "*@*" is the same case. The separate fields are kept because an operator
     * also writes a bare nickname, and because a bare host is a legitimate
     * (if blunt) mask. */
    char full[CONN_HOSTMASK_MAX];
    int have_full = 0;

    if (ch == NULL) {
        return 0;
    }
    if (nick != NULL && user != NULL && host != NULL) {
        int n = snprintf(full, sizeof full, "%s!%s@%s", nick, user, host);

        have_full = (n > 0 && (size_t)n < sizeof full);
    }
    for (size_t i = 0; i < ch->nbans; i++) {
        if (nick != NULL && chan_mask_match(ch->bans[i].mask, nick)) {
            return 1;
        }
        if (host != NULL && chan_mask_match(ch->bans[i].mask, host)) {
            return 1;
        }
        if (have_full && chan_mask_match(ch->bans[i].mask, full)) {
            return 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * Ownership -- the three rules of 2.2
 * ------------------------------------------------------------------------- */

chan_origin_state_t chan_origin_state(const server_t *s, const chan_t *ch)
{
    if (s == NULL || ch == NULL || ch->origin[0] == '\0') {
        return CHAN_ORIGIN_UNREACHABLE;
    }
    /* origin == self FIRST, and unconditionally. On a single node every channel
     * this node created takes this branch, so the single-writer refusal costs
     * no lookup at all in the case that is the only case a single node has. */
    if (same_name(ch->origin, s->name)) {
        return CHAN_ORIGIN_SELF;
    }
    /* A peer connection bearing that name exists, so 3.1's FORWARD path is
     * available in principle. Phase 6 narrows this to the handshake FSM's
     * ESTABLISHED state; today no FSM is driving any link, so a CONN_SERVER
     * conn is as established as one can be. */
    if (server_find_peer(s, ch->origin) != NULL) {
        return CHAN_ORIGIN_LINKED;
    }
    return CHAN_ORIGIN_UNREACHABLE;
}

int chan_origin_is_self(const server_t *s, const chan_t *ch)
{
    return (chan_origin_state(s, ch) == CHAN_ORIGIN_SELF) ? 1 : 0;
}

int chan_origin_wins(uint64_t a_epoch, const char *a_name,
                     uint64_t b_epoch, const char *b_name)
{
    if (a_name == NULL || b_name == NULL) {
        return 0;
    }
    /* Lexicographic, and the two halves are genuinely different comparisons.
     * Testing only "higher epoch wins" would leave the name half unexercised,
     * and testing only "higher name wins" would not be the rule at all. */
    if (a_epoch != b_epoch) {
        return (a_epoch > b_epoch) ? 1 : 0;
    }
    return (strcasecmp(a_name, b_name) > 0) ? 1 : 0;
}

int chan_rekey(chan_t *ch, const char *origin, uint64_t origin_epoch)
{
    if (ch == NULL || origin == NULL || origin[0] == '\0' ||
        strlen(origin) > (size_t)CHAN_MAX_SERVER) {
        return -1;
    }
    /* The loser of the race re-keys to the winner. A candidate that does not
     * win is refused, which also means re-keying to the incumbent's own origin
     * is a refusal rather than a no-op success: chan_origin_wins() returns 0 for
     * identical pairs, and "this channel already has that origin" is not a
     * reason to rewrite it. */
    if (!chan_origin_wins(origin_epoch, origin, ch->origin_epoch, ch->origin)) {
        return 0;
    }
    (void)copy_bounded(ch->origin, sizeof ch->origin, origin);
    ch->origin_epoch = origin_epoch;
    printf("[observable] chan_rekey: channel=%s origin=%s epoch=%llu\n", ch->name,
           ch->origin, (unsigned long long)ch->origin_epoch);
    return 1;
}

/* ---------------------------------------------------------------------------
 * Teardown
 * ------------------------------------------------------------------------- */

void chan_conn_gone(server_t *s, conn_t *c)
{
    size_t i;

    if (c == NULL || c->nchans == 0) {
        return;
    }
    /* Walk the connection's OWN list rather than every channel on the node, so
     * this is O(channels this connection was in) and not O(all channels). It
     * also keeps the two indexes from disagreeing: conn_t::chans is what
     * conn_free() is about to release, and a member record left pointing at a
     * freed conn_t is the failure this function exists to prevent. */
    for (i = 0; i < c->nchans; i++) {
        chan_t *ch = c->chans[i];

        if (ch == NULL) {
            continue;
        }
        /* Silent to the departing conn: it is going away, and the reply module
         * would refuse the emission and count a refusal. No reason either: a
         * QUIT reason is not stored (there is no quit cache until Phase 9) and
         * a hangup has none, so there is nothing to pass and inventing one
         * would put a word on the wire the client never wrote. */
        chan_member_leave(s, ch, c, 0, NULL);
        (void)chan_dispose_if_empty(s, ch);
    }
    c->nchans = 0; /* conn_free() releases the array; the count goes with it */
}

int chan_dispose_if_empty(server_t *s, chan_t *ch)
{
    if (s == NULL || ch == NULL) {
        return 0;
    }
    /* Two conditions, and the second is the one that matters.
     *
     * nservers == 0 means no peer has reported a member for this channel, so
     * there is nothing to remember it for. nservers > 0 with nmembers == 0 is
     * the case 3.1 still has to route: a node with zero local members in a
     * channel must still be able to forward that channel's messages to the
     * owner, so the channel SURVIVES. Freeing it here is the specific bug that
     * would make servers[] a declared-but-unused field. */
    if (ch->nmembers != 0 || ch->nservers != 0) {
        return 0;
    }
    /* PHASE 9: A SESSION WINDOW STILL HOLDS THIS CHANNEL, so it is NOT disposed --
     * and this is the third reason to exist, after local members and remote ones,
     * and the only one that is TIMED rather than permanent.
     *
     * WITHOUT IT THE FEATURE IS WORTHLESS ON THE COMMON CASE, which is worth
     * spelling out because it is not obvious from the code: a client that drops is
     * parted out of every channel it was in (chan_conn_gone, called from the
     * reaper), so a client who was the only member of every channel it was in
     * leaves every one of them with nothing to remember it for. The window that
     * was recorded one line earlier names channels that no longer exist, and the
     * restore finds nothing to put the client back into -- on a single-client
     * node, silently, which is the worst combination of the two.
     *
     * THE HOLD IS SHORT AND DERIVED (core/resume.h), and the shortness is the
     * point rather than a compromise: 2.2's disposal rule above is DELAYED, not
     * exempted. A hold as long as the window would keep a channel alive for two
     * minutes after its last member left, and tests/integration/
     * test_topic_persist.c -- which empties a channel by dropping one client and
     * QUITting the other, which is exactly the pair of events that records a
     * window, and then waits fifteen seconds for `chan_destroy` -- would fail.
     * A hold of a few seconds covers the population this feature serves
     * completely, because a client whose session was lost is already reconnecting
     * by then.
     *
     * AND IT IS A GUARD IN THE EXISTING RULE, NOT A NEW ONE. Putting it here
     * rather than in the four callers that offer a channel for disposal means one
     * check covers all of them, and a path that forgot it would dispose a channel
     * a returning client is about to be restored into. */
    if (resume_holds(s, ch->name)) {
        return 0;
    }
    printf("[observable] chan_destroy: channel=%s reason=empty\n", ch->name);
    /* The TOPIC goes out to the cache on the way down, and this is the only
     * place it happens, which is what makes the cache's lifetime equal to the
     * channel's: there is no other teardown path for a chan_t, so there is no
     * other place a topic could be dropped. A loss here -- a full cache -- leaves
     * the topic lost exactly as it would have been without the cache, and is
     * counted on s->n_topic_cache_full; the return value is deliberately not
     * examined, because refusing to dispose a channel over a cache miss would
     * trade a lost topic for an unbounded store. */
    (void)server_topic_remember(s, ch);
    server_chan_detach(s, ch->name);
    chan_free(ch);
    return 1;
}

/* ---------------------------------------------------------------------------
 * The topic cache
 * ---------------------------------------------------------------------------
 * The reasoning for the cache's existence, its bounds and what it deliberately
 * does NOT carry is in channel.h. What follows is the code, and it is four
 * functions and one static helper because the whole of the thing is a keyed
 * array with one writer and one reader.
 */

/* The entry for `name`, or NULL.
 *
 * It folds, and THE FOLD IS CURRENTLY UNREACHABLE, which is worth saying rather
 * than leaving to be discovered: both callers pass a `chan_t::name`, and 2.2
 * stores those canonicalised, so the two spellings this comparison is there to
 * tell apart cannot both arrive. A fault injection that replaced chan_same_name()
 * here with strcmp() therefore passes the whole suite -- it was tried, and the
 * only reason it does is that nothing on the wire reaches it.
 *
 * It is kept anyway, for the same reason server_link_t::name is a copy rather
 * than a pointer: "is this the same name" must have ONE answer in this tree, and
 * a comparison that folds differently from every other one is a comparison that
 * will differ the day a caller passes something else. The cost is a fold per
 * entry in a table bounded at SERVER_TOPIC_MAX, on a path that runs once per
 * channel creation. */
static chan_topic_t *topic_find(const server_t *s, const char *name)
{
    for (size_t i = 0; i < s->ntopics; i++) {
        if (chan_same_name(s->topics[i].name, name) != 0) {
            return &s->topics[i];
        }
    }
    return NULL;
}

/* Drop the entry at `idx`, order-preserving. The order is not used by anything
 * (there is no LIST over the cache) but preserving it keeps the vector honest for
 * whoever walks it next, and an order-preserving removal is the same choice
 * chan_detach_conn() already makes for 2.2's member lists. */
static void topic_remove_at(server_t *s, size_t idx)
{
    for (size_t i = idx; i + 1u < s->ntopics; i++) {
        s->topics[i] = s->topics[i + 1u];
    }
    s->ntopics--;
}

int server_topic_remember(server_t *s, const chan_t *ch)
{
    chan_topic_t *e;

    if (s == NULL || ch == NULL) {
        return 0;
    }
    e = topic_find(s, ch->name);
    if (ch->topic[0] == '\0') {
        /* A CLEARED topic removes the entry rather than remembering an empty
         * one. See channel.h: absence is how "never remembered" is spelled, and
         * an entry holding "" would be a second way to spell it. */
        if (e == NULL) {
            return 0; /* nothing to remember and nothing to forget */
        }
        topic_remove_at(s, (size_t)(e - s->topics));
        printf("[observable] topic_persist: channel=%s state=forgotten entries=%zu\n",
               ch->name, s->ntopics);
        return 0;
    }
    if (e != NULL) {
        /* Already known: overwrite in place. The three fields move together, so
         * an entry is never half old and half new -- the same "every field
         * changes or none does" rule chan_set_topic() applies to a channel. */
        (void)copy_bounded(e->topic, sizeof e->topic, ch->topic);
        (void)copy_bounded(e->who, sizeof e->who, ch->topic_who);
        e->when = ch->topic_when;
        printf("[observable] topic_persist: channel=%s state=remembered "
               "topic_len=%zu entries=%zu updated=1\n",
               ch->name, strlen(ch->topic), s->ntopics);
        return 1;
    }
    if (s->ntopics >= (size_t)SERVER_TOPIC_MAX) {
        /* The bound, and the loss is COUNTED rather than hidden. A node whose
         * counter climbs is a node that has seen more distinct channel names
         * than it can remember topics for, and that is the number an operator
         * needs; the topic is then lost exactly as it would have been without
         * this cache. */
        s->n_topic_cache_full++;
        printf("[observable] topic_persist: channel=%s state=REFUSED "
               "reason=CACHE_FULL entries=%zu\n",
               ch->name, s->ntopics);
        return -1;
    }
    /* Geometric growth, doubling from the first entry, so a node that remembers
     * 64 topics has done six reallocs rather than 64. The bound above is what
     * makes this safe: the loop is not asked to grow without a ceiling, and
     * `want` is clamped to it so a request past the bound cannot allocate a
     * bigger array and then fail to use it. */
    if (s->ntopics == s->topics_cap) {
        size_t want = (s->topics_cap == 0u) ? 8u : s->topics_cap * 2u;
        chan_topic_t *grown;

        if (want > (size_t)SERVER_TOPIC_MAX) {
            want = (size_t)SERVER_TOPIC_MAX;
        }
        grown = (chan_topic_t *)realloc(s->topics, want * sizeof *s->topics);
        if (grown == NULL) {
            s->n_topic_cache_full++;
            printf("[observable] topic_persist: channel=%s state=REFUSED "
                   "reason=NO_MEMORY entries=%zu\n",
                   ch->name, s->ntopics);
            return -1;
        }
        s->topics = grown;
        s->topics_cap = want;
    }
    e = &s->topics[s->ntopics];
    (void)copy_bounded(e->name, sizeof e->name, ch->name);
    (void)copy_bounded(e->topic, sizeof e->topic, ch->topic);
    (void)copy_bounded(e->who, sizeof e->who, ch->topic_who);
    e->when = ch->topic_when;
    s->ntopics++;
    printf("[observable] topic_persist: channel=%s state=remembered "
           "topic_len=%zu entries=%zu updated=0\n",
           ch->name, strlen(ch->topic), s->ntopics);
    return 1;
}

int server_topic_restore(server_t *s, chan_t *ch)
{
    const chan_topic_t *e;

    if (s == NULL || ch == NULL) {
        return 0;
    }
    e = topic_find(s, ch->name);
    if (e == NULL) {
        return 0;
    }
    /* The three fields are written by hand rather than through
     * chan_set_topic(), and the reason is the time. chan_set_topic() STAMPS
     * topic_when with the current clock, which is right for a topic a client is
     * setting now and wrong here: 333 would then say the topic was set at the
     * moment of the rejoin, by the user who rejoined, which is a lie about both
     * facts and is exactly the failure 333's existence is meant to prevent.
     *
     * A refused copy leaves the channel's topic empty, which is the state it was
     * in anyway, so there is no half-restored state to clean up. A value that
     * fitted once cannot fail to fit a second time -- both are the same
     * CHAN_MAX_* fields the channel was filled from -- which is why the result is
     * reported rather than handled. */
    (void)copy_bounded(ch->topic, sizeof ch->topic, e->topic);
    (void)copy_bounded(ch->topic_who, sizeof ch->topic_who, e->who);
    ch->topic_when = e->when;
    printf("[observable] topic_persist: channel=%s state=restored topic_len=%zu "
           "entries=%zu\n",
           ch->name, strlen(ch->topic), s->ntopics);
    return 1;
}

size_t server_topic_count(const server_t *s)
{
    return (s != NULL) ? s->ntopics : 0u;
}

const chan_topic_t *server_topic_at(const server_t *s, size_t i)
{
    if (s == NULL || i >= s->ntopics) {
        return NULL;
    }
    return &s->topics[i];
}
