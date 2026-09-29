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
     * sigil is not a name: there is nothing after it to distinguish. */
    if (n < 2u || n > (size_t)CHAN_MAX_NAME) {
        return 0;
    }
    if (name[0] != '#' && name[0] != '&') {
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

int chan_remote_add(chan_t *ch, const char *server, const char *nick,
                    unsigned flags)
{
    chan_remote_t *seen;

    if (ch == NULL || server == NULL || nick == NULL) {
        return -1;
    }
    /* Validated HERE, and not left to the caller, because the caller is a peer
     * protocol handler and the two rules it would have to remember are 2.1's
     * nickname charset and 2.4's server-name grammar. Both exist because later
     * phases build on them -- 2.1's split at the last '@' is unsound without
     * the charset -- and a roster entry that skipped either would be a name the
     * node could not qualify, compare or render. This is the first place in the
     * tree a nickname arrives from a network rather than from a client. */
    if (!irc_serve_server_name_valid(server) || !valid_nick(nick)) {
        return -1;
    }
    seen = chan_remote_find(ch, server, nick);
    if (seen != NULL) {
        /* A repeated SJOIN is a re-assertion, not a second member. The flags
         * are overwritten rather than OR'd because a peer that says `alice` is
         * no longer an op has told us something, and a roster where nobody can
         * ever lose +o is a roster that converges on the wrong answer. */
        seen->flags = flags;
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
     * clothes. */
    ch->remotes[ch->nremotes].host[0] = '\0';
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
    printf("[observable] chan_destroy: channel=%s reason=empty\n", ch->name);
    server_chan_detach(s, ch->name);
    chan_free(ch);
    return 1;
}
