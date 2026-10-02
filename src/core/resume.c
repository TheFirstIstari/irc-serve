/* resume.c -- the session window. See resume.h for the design, and in particular
 * for why this is plain reconnect-and-rejoin and NOT IRCv3 `RESUME`.
 *
 * The shape of this file is deliberate and worth stating before any of it:
 *
 *   - ONE table, on server_t, lazily allocated, a flat array of fixed-size
 *     records. No per-entry allocation, so the whole store is one calloc and one
 *     free and the leak question has exactly two answers. Every other registry
 *     in this node is the same shape (the nick index, the dedup table, the
 *     federation resync shadow) and resume.h gives the reasoning.
 *   - FOUR RELEASE PATHS and no fifth: on use (resume_take), on expiry
 *     (resume_sweep), on eviction (resume_note, at the bound), and on shutdown
 *     (resume_close). Each is stated at its function and the header states the
 *     list, because "where is this freed" is the question a reviewer asks first
 *     about any bounded store.
 *   - THE FLAGS ARE RECORDED AND RE-DERIVED, never copied. That is the whole
 *     security argument for the feature and it is implemented in
 *     resume_apply(); the short version is that a window cannot re-grant
 *     authority the channel no longer recognises.
 */
#include "core/resume.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/chan_verbs.h"
#include "core/channel.h"
#include "core/reply.h"
#include "core/server.h"

/* ---------------------------------------------------------------------------
 * The record
 * ---------------------------------------------------------------------------
 *
 * A FLAT, FIXED-SIZE record in a flat array, and both of those are load-bearing
 * rather than lazy:
 *
 *   FIXED-SIZE  so IRC_RESUME_MAX bounds the table's memory on its own. A
 *               variable-size record per user would make the table's size a
 *               function of how many channels users are in, which is a number a
 *               client controls, and a bounded store whose bound a client can
 *               move is not a bounded store.
 *   FLAT        so eviction and expiry are index walks rather than list
 *               surgery, and so the sweep's cost is O(windows) with no
 *               allocation and no failure mode. The cost of flat is that
 *               removing an entry shifts the tail, which is O(windows) too --
 *               paid on a resume and on a sweep, both of which are rare and both
 *               of which are already O(n).
 *
 * THE SIZE, and it is worth being explicit because it is a cost on every node
 * with a client that drops: nick + ident + host + 16 channels of (64 + 8) is
 * about 1.3 KiB per window, so IRC_RESUME_MAX windows is about 85 KiB -- the
 * same order as the federation resync shadow's budget and allocated only on the
 * first resume. */
struct resume_window {
    char     nick[IRC_MAX_NICK + 1];
    char     ident[CONN_USER_MAX + 1];
    char     host[CONN_HOST_MAX + 1];
    uint64_t dropped_ms;
    /* 0 while the window is RESUMABLE, and the stamp at which it stopped being
     * so once it is not. The window's whole life has two stages and this is the
     * boundary between them; see resume.h on why the second stage exists at all,
     * which is a requirement about the WIRE rather than about memory. */
    uint64_t retired_ms;
    /* Set once the HOLD on this window's channels has run out, and it is a flag
     * rather than a stamp because the hold is a fixed fraction of the window: the
     * sweep needs to know only WHETHER it has already offered the channels back,
     * and a stamp would be a second thing to keep in step with resume_hold_ms().
     * Once set it never clears, so the channels are offered back exactly once. */
    int hold_released;
    struct resume_chan chans[IRC_RESUME_MAX_CHANS];
    size_t   nchans;
    size_t   dropped_chans; /* beyond IRC_RESUME_MAX_CHANS; counted, not silent */
};

/* The per-process window length. Static because it is a property of the
 * PROCESS and not of a server_t: a test that forks a child sets it in the child
 * before the child has a server, and two server_t in one process (which is what
 * the inline fixture makes) would otherwise disagree about the same constant.
 *
 * THE INITIALISER AND NOT A ZERO CHECK, and that is the point: a zero here would
 * mean "every window is already expired", which is a configuration a caller
 * cannot ask for and does not mean. A caller who wants no feature at all sets
 * the length to 0 through resume_set_window(), which refuses it. */
static uint64_t g_window_ms = IRC_RESUME_WINDOW_MS;

/* The sweep throttle, as a divisor of the window. Same shape as
 * fed_dedup_sweep()'s and for the same reason: expiry is O(windows) and there is
 * no event in it that needs millisecond resolution. Sixteen is a divisor that
 * keeps a sweep to one per window/16 -- about every seven seconds at the shipped
 * two minutes -- while still expiring a window within a sixteenth of its
 * lifetime of its real expiry. */
#define RESUME_SWEEP_DIVISOR ((uint64_t)16u)

/* ---------------------------------------------------------------------------
 * Folds
 * ---------------------------------------------------------------------------
 *
 * THE NODE HAS THREE OF THESE and this is the third, added here for the reason
 * server.c records when it deleted its third copy: each module owns the fold for
 * the field it owns, because a shared "ascii fold" helper is a function whose
 * contract would have to be "fold anything, and the answer is right for
 * nicknames and server names and not for something else", and a contract like
 * that is a contract nobody can check.
 *
 * 2.1's nickname charset folds case; `Bob` and `bob` are one nickname. RFC 1459
 * 2.2's casemapping is `ascii`, and `005` advertises CASEMAPPING=ascii, so this
 * fold is the advertised one and not a guess. The same fold serves the ident
 * because USER has no charset rule of its own and a session that missed on case
 * would be a session a client could not get back by reconnecting correctly. */
static char resume_fold(char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return (char)(ch - 'A' + 'a');
    }
    return ch;
}

static int same_folded(const char *a, const char *b)
{
    size_t i;

    if (a == NULL || b == NULL) {
        return 0;
    }
    for (i = 0;; i++) {
        char ca = resume_fold(a[i]);
        char cb = resume_fold(b[i]);

        if (ca != cb) {
            return 0;
        }
        if (ca == '\0') {
            return 1;
        }
    }
}

/* A bounded copy that reports whether it fitted, because the three callers all
 * need to know: a nick or a channel name that does not fit is a name this node
 * would have refused, and storing a truncated one would produce a window whose
 * key matches nothing. Returns 0 when the value was refused and `dst` is then
 * empty, so a caller that ignores the return still cannot produce a half-built
 * name. */
static int resume_copy(char *dst, size_t cap, const char *src)
{
    size_t n;

    if (dst == NULL || cap == 0u) {
        return 0;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return 1;
    }
    n = strlen(src);
    if (n >= cap) {
        dst[0] = '\0';
        return 0;
    }
    memcpy(dst, src, n + 1u);
    return 1;
}

/* ---------------------------------------------------------------------------
 * Table access
 * ---------------------------------------------------------------------------
 *
 * s->resume_windows is a `struct resume_window *` and s->nresume_used counts the
 * LIVE windows in it. The table is allocated at its FULL bound on first use
 * rather than grown: the bound is 85 KiB, a growable vector would be a second
 * thing to keep in step with the count, and a partially filled array is the
 * simplest possible thing to sweep and to index.
 *
 * The alternative -- a per-node FIXED array inside server_t -- was rejected
 * because it would put 85 KiB in every server_t including the ones that never
 * resume anything, and this node's other optional stores are all lazily
 * allocated for that reason. */
static struct resume_window *resume_table(server_t *s)
{
    if (s->resume_windows == NULL) {
        s->resume_windows = (struct resume_window *)calloc(IRC_RESUME_MAX,
                                                           sizeof *s->resume_windows);
        if (s->resume_windows == NULL) {
            /* A node that cannot allocate cannot remember, and saying so is
             * better than a store that silently did not record: a client that
             * dropped and came back would get a plain registration, and the
             * operator reading the log would have no way to know the feature was
             * off. Counting it is what makes that visible. */
            s->n_resume_alloc_failed++;
            return NULL;
        }
    }
    return s->resume_windows;
}

/* Remove the window at `idx`, shifting the tail down. The slot is CLEARED after
 * the shift rather than before it, so the memset cannot wipe a window that moved
 * into this index -- the same ordering bug fed_dedup_sweep() records about, and
 * the same reason the clear is last. */
static void resume_drop_at(server_t *s, size_t idx)
{
    size_t j;

    if (idx >= s->nresume_used) {
        return;
    }
    for (j = idx + 1u; j < s->nresume_used; j++) {
        s->resume_windows[j - 1u] = s->resume_windows[j];
    }
    s->nresume_used--;
    memset(&s->resume_windows[s->nresume_used], 0, sizeof s->resume_windows[0]);
}

/* The window matching `c`, or NULL. EXPIRY IS DECIDED HERE and not in the
 * caller, for the reason fed_nickreg_sweep()'s throttle gives: "is this window
 * still a window" is a question about the store's contents rather than about the
 * caller, and answering it in one place is what keeps resume_take() and
 * resume_window_for() from disagreeing about the same entry.
 *
 * AN EXPIRED MATCH IS NOT CONSUMED HERE, and the caller is expected to sweep.
 * The alternative -- dropping it inside the lookup -- would make a predicate
 * free the thing it was asked about, and a caller that asked "is there a window?"
 * would find out by destroying it. resume_apply() calls resume_sweep() right
 * after its lookup for exactly this reason. */
/* The const half of resume_find(), and the reason it is a function rather than a
 * parameter: resume_window_for() is a predicate, and a predicate that could write
 * is not a predicate. Everything it does is the same comparison, and the only
 * difference is the two consts. */
static const struct resume_window *resume_find_const(const server_t *s,
                                                    const conn_t *c,
                                                    uint64_t now_ms)
{
    size_t i;

    if (s == NULL || s->resume_windows == NULL || c == NULL) {
        return NULL;
    }
    for (i = 0; i < s->nresume_used; i++) {
        const struct resume_window *w = &s->resume_windows[i];

        if (!same_folded(w->nick, c->nick) || !same_folded(w->ident, c->user) ||
            !same_folded(w->host, c->host)) {
            continue;
        }
        if (now_ms < w->dropped_ms || (now_ms - w->dropped_ms) >= g_window_ms) {
            return NULL;
        }
        if (w->retired_ms != 0u) {
            return NULL; /* retired: present, not resumable */
        }
        return w;
    }
    return NULL;
}

static struct resume_window *resume_find(server_t *s, const conn_t *c,
                                         uint64_t now_ms)
{
    (void)now_ms; /* the key is the whole of it; the state is the caller's */
    size_t i;

    if (s == NULL || s->resume_windows == NULL || c == NULL) {
        return NULL;
    }
    for (i = 0; i < s->nresume_used; i++) {
        struct resume_window *w = &s->resume_windows[i];

        if (!same_folded(w->nick, c->nick) || !same_folded(w->ident, c->user) ||
            !same_folded(w->host, c->host)) {
            continue;
        }
        /* THE KEY AND NOTHING ELSE, and that is the difference from
         * resume_find_const() below, which applies the state rules on top of the
         * same comparison. A caller that is going to TELL the client something
         * needs the entry whatever state it is in, and a caller that is only
         * asking "is there something to resume" needs the state applied. Two
         * predicates over one comparison rather than one predicate with a flag,
         * because a flag would be a boolean that says which question is being
         * asked and the two callers ask them at very different moments: one
         * during registration, the other from a log reader. */
        return w;
    }
    return NULL;
}

/* ---------------------------------------------------------------------------
 * resume_note() -- recording the window, which is the moment the session is lost
 * ---------------------------------------------------------------------------
 *
 * CALLED FROM server_close_conn() BEFORE chan_conn_gone(), and the ordering is
 * the whole of what makes this work: chan_conn_gone() walks c->chans, parts the
 * client out of every channel and disposes of any that has run out of reasons to
 * exist. A window noted after it would find an empty channel list and restore
 * nothing, and it would restore nothing SILENTLY -- which is the failure mode
 * this whole file is arranged to avoid.
 *
 * THE EXPLICIT-QUIT EXCLUSION is here rather than in the caller, because the
 * caller cannot tell the two cases apart: by the time server_close_conn() runs,
 * a QUIT and a dropped socket are both a CLOSING conn, and the only difference
 * is that the QUIT handler has already unclaimed the nickname. So the test is
 * "does this connection still hold a name", which is a fact the node already
 * maintains and which is TRUE for a lost session and FALSE for one that said
 * goodbye.
 *
 * That test is also what makes the exclusion robust rather than dependent on a
 * flag somebody might forget to set: a client that sends QUIT and then has its
 * socket close anyway is a QUIT, because handle_quit() ran. */
void resume_note(server_t *s, const conn_t *c, uint64_t now_ms)
{
    struct resume_window *w;
    size_t i;

    if (s == NULL || c == NULL) {
        return;
    }
    /* A PEER LINK IS NOT A SESSION. A CONN_SERVER connection is the federation
     * FSM's own bookkeeping and its "channel set" is a mirror of somebody else's
     * state, so a window built from one would restore a mesh rather than a
     * user. */
    if (c->kind != CONN_CLIENT) {
        return;
    }
    /* THE STATE IS NOT TESTED AND THAT IS A FINDING RATHER THAN AN OMISSION.
     * The obvious guard here is `c->state == CONN_REG_READY`, and it is wrong:
     * the poll loop marks a connection CONN_CLOSING the moment it sees the EOF,
     * and the reaper -- which is what called this function -- runs at the end of
     * a LATER iteration. So by the time any teardown code runs, a dropped
     * session's state is CONN_CLOSING and a QUIT's is CONN_CLOSING, and the
     * state field cannot tell a registered client from a half-registered one.
     *
     * What DOES tell them apart, and is used below instead, is the nickname: a
     * connection that reached registration holds a name in the table, and one
     * that sent NICK and stopped has a name in a DISPLAY FIELD and nothing in
     * the table. The nchans guard closes the remaining gap on its own -- a
     * connection that never completed registration cannot have joined anything,
     * so a half-registered client has an empty channel set and is refused by
     * that test rather than by this one. */
    if (c->nick[0] == '\0') {
        return;
    }
    /* AN EXPLICIT QUIT IS NOT A LOST SESSION, and the test is the nickname: the
     * QUIT handler calls server_nick_unclaim() before marking the connection
     * CLOSING, so by the time the reaper gets here a QUIT's connection holds no
     * name and a dropped socket's does. See the header for why the feature is
     * for a session that was LOST. */
    if (c->nick[0] == '\0' || server_nick_lookup(s, c->nick) != c) {
        return;
    }
    /* NOTHING TO RESTORE, and an entry with an empty channel list is a window
     * that would restore nothing while occupying a slot. A client that
     * registered and joined nothing is a client whose session was not lost --
     * there was nothing in it. */
    if (c->nchans == 0u) {
        return;
    }
    w = resume_table(s);
    if (w == NULL) {
        return;
    }
    if (s->nresume_used >= IRC_RESUME_MAX) {
        /* THE OLDEST GOES, and the oldest rather than the newest because the
         * newest is the one somebody is about to come back for. The alternative
         * -- refusing the new window -- would mean a node under a scripted
         * connect/disconnect loop stops resuming for EVERYBODY, which is the
         * failure mode 2.2's topic-cache rule is written against: a store that
         * can refuse is a store that can break a client command. So the pressure
         * is answered by forgetting, and the forgetting is counted so an
         * operator can see that the window is too small for this node. */
        s->n_resume_evicted++;
        printf("[observable] session_resume_evict: bound=%zu\n", IRC_RESUME_MAX);
        resume_drop_at(s, 0);
    }
    /* The slot is at nresume_used after any eviction, and it is CLEARED before
     * the copies rather than overwritten field by field: an eviction shifts a
     * live window into an arbitrary index, and a slot that kept a stale channel
     * array from its previous occupant would restore channels the previous
     * occupant was in. */
    w = &s->resume_windows[s->nresume_used];
    memset(w, 0, sizeof *w);
    w->nchans = 0u;
    w->dropped_ms = now_ms;
    if (!resume_copy(w->nick, sizeof w->nick, c->nick) ||
        !resume_copy(w->ident, sizeof w->ident, c->user) ||
        !resume_copy(w->host, sizeof w->host, c->host)) {
        /* Unreachable: every field was accepted by the struct it is being
         * copied into, which is the same width. Handled rather than asserted
         * because a window whose key is half-built matches a connection whose
         * key is half-built, and two half-built keys matching is a session
         * handed to the wrong client. */
        memset(w, 0, sizeof *w);
        s->n_resume_rejected++;
        return;
    }
    for (i = 0; i < c->nchans; i++) {
        chan_t *ch = c->chans[i];
        struct member *m;
        struct resume_chan *rc;

        if (ch == NULL) {
            continue;
        }
        if (w->nchans >= IRC_RESUME_MAX_CHANS) {
            /* COUNTED, NOT SILENT, and the count is on the window so it can be
             * reported at restore time -- a user in twenty channels is told their
             * session came back with sixteen of them, which is a fact they can
             * act on, where silence would look like a bug. */
            w->dropped_chans++;
            continue;
        }
        /* THE FLAGS ARE READ HERE AND NOT RESTORED HERE. This is the whole
         * security argument: what is recorded is what the client HELD, and what
         * is restored is what the channel will GRANT, and those are two
         * different questions whose answers can differ because an operator
         * deopped the client, or the origin changed the prefix, or this node
         * does not own the channel at all. resume_apply() asks the second
         * question. */
        m = chan_find_member(ch, c);
        rc = &w->chans[w->nchans];
        memset(rc, 0, sizeof *rc);
        if (!resume_copy(rc->name, sizeof rc->name, ch->name)) {
            continue;
        }
        rc->flags = (m != NULL) ? m->flags : 0u;
        w->nchans++;
    }
    if (w->nchans == 0u) {
        /* Every channel was refused, so there is nothing to restore and the slot
         * is given back rather than occupied by a window that would restore
         * nothing. Same reasoning as the nchans == 0 case above. */
        memset(w, 0, sizeof *w);
        s->n_resume_rejected++;
        return;
    }
    s->nresume_used++;
    s->n_resume_noted++;
    printf("[observable] session_resume_note: nick=%s ident=%s chans=%zu%s\n",
           w->nick, w->ident, w->nchans,
           (w->dropped_chans > 0u) ? " detail=CHANS_DROPPED" : "");
}

/* ---------------------------------------------------------------------------
 * resume_window_for() -- the predicate, and it does NOT consume
 * ---------------------------------------------------------------------------
 */
const struct resume_chan *resume_window_for(const server_t *s, const conn_t *c,
                                            uint64_t now_ms, size_t *count_out)
{
    /* resume_find() TAKES A NON-CONST server_t and this predicate is const, which
     * is a real mismatch rather than a formality: find() does not write, but its
     * signature is shared with resume_apply() which does, and casting the const
     * away to share it would be a lie the type system is right to refuse.
     *
     * THE FIX IS A CONST FINDER, and it is a separate small function rather than
     * a flag on the shared one: a `mutable` parameter is a boolean that says
     * "trust me", and this function's whole contract is that asking whether a
     * window exists changes nothing. The duplication is the loop, which is five
     * lines, and the alternative -- making the predicate take a non-const server
     * and trusting every caller not to write -- is a worse contract for a
     * question every caller asks. */
    const struct resume_window *w = resume_find_const(s, c, now_ms);

    if (count_out != NULL) {
        *count_out = 0u;
    }
    if (w == NULL) {
        return NULL;
    }
    if (count_out != NULL) {
        *count_out = w->nchans;
    }
    return w->chans;
}

/* ---------------------------------------------------------------------------
 * resume_apply() -- the restore, and the two thirds of it that are not obvious
 * ---------------------------------------------------------------------------
 *
 * THE ORDER OF THE THREE THINGS IT DOES, and every one of them is load-bearing:
 *
 *   1. TAKE THE WINDOW. Removed before any restore work, so a restore that fails
 *      halfway has still consumed it and cannot be replayed.
 *   2. RE-JOIN EACH CHANNEL through chan_admit(), which is the SAME function a
 *      client's own JOIN goes through. That is what makes the restore inherit
 *      the ban check, the channel lookup, the topic cache and 3.1's forward
 *      rule without this file restating any of them, and it is why a restored
 *      client is on a mesh exactly as a joining one is.
 *   3. ASK THE CHANNEL FOR ITS FLAGS, and install only what it grants.
 */

/* What the channel is willing to re-grant to a returning client, and the whole
 * of the feature's privilege argument is the difference between this and the
 * window's recorded field.
 *
 * THE RULE, and it is one rule with two halves:
 *
 *   A. NOT ON A CHANNEL THIS NODE DOES NOT OWN. 2.2's single-writer rule is
 *      enough on its own: the ORIGIN decides a channel's prefixes, so a
 *      non-owner's member list is a cache, and handing a returning client
 *      operator status out of a cache would be this node asserting authority it
 *      does not have. The origin would disagree, and 2.2 names a divergence as
 *      the failure the rule exists to prevent. The membership is still restored
 *      there -- a JOIN is a local membership fact and 3.1's non-owned row
 *      forwards it without asking the origin to decide it -- so a client on a
 *      mesh comes back to its channels and only loses the prefixes.
 *
 *   B. NEVER MORE THAN THE WINDOW RECORDED, on a channel this node does own.
 *      This is what makes a restore MONOTONE-SUBORDINATE to the window: the
 *      restore can lose authority relative to what the client had and can never
 *      gain any. A window that recorded a plain member restores a plain member;
 *      a window that recorded an operator restores an operator; there is no
 *      input that makes a restore more privileged than the drop was. That is the
 *      property worth having, because it means a bug in the note path produces a
 *      client with too FEW channels and not one with too many.
 *
 * SO THE ANSWER IS A MASK AGAINST THE RECORD, and the mask is applied by the
 * caller. The reason this function is a function at all rather than a line in
 * resume_apply() is that rule A is a judgement about 2.2 and belongs beside the
 * other places that make it, and the reason it takes the RECORD is that the
 * comparison has to be somewhere a reader can find the two halves in one place.
 *
 * THE LIMIT, STATED BECAUSE IT IS NOT FIXED HERE: a de-op that happened while
 * the client was away is NOT observable on a single node, and saying so is more
 * useful than implying the design handles it. `MODE -o` against a nickname that
 * is not on the channel is 441 (chan_verbs.c's own comment), and a client that
 * has dropped is not on any channel, so nothing on this node can revoke a
 * departed member's prefix. A window's recorded operator status is therefore
 * still the truth on a single node, and the two guards above are what keep that
 * from being a claim about authority rather than about membership. On a mesh the
 * origin CAN have changed it, and that is exactly the case rule A covers by
 * dropping the prefix entirely. */
static unsigned resume_flags_for(const server_t *s, const chan_t *ch,
                                 unsigned recorded)
{
    if (!chan_origin_is_self(s, ch)) {
        return 0u; /* rule A: this node is not the authority for this channel */
    }
    return recorded; /* rule B: never more than the window recorded */
}

int resume_apply(server_t *s, conn_t *c, uint64_t now_ms)
{
    char nick[IRC_MAX_NICK + 1];
    char ident[CONN_USER_MAX + 1];
    struct resume_chan chans[IRC_RESUME_MAX_CHANS];
    size_t nchans = 0u;
    size_t dropped = 0u;
    size_t joined = 0u;
    size_t idx = 0u;
    struct resume_window *w;
    size_t i;

    if (s == NULL || c == NULL) {
        return -1;
    }
    /* The three key fields are COPIED before the window is taken, because taking
     * it shifts the array and the connection's own fields are the only other
     * place they exist. */
    (void)resume_copy(nick, sizeof nick, c->nick);
    (void)resume_copy(ident, sizeof ident, c->user);

    /* THE FINDER, NOT A SECOND COPY OF ITS COMPARISON. resume_apply() needs the
     * INDEX as well as the entry -- it has to take the window and it has to
     * re-read the retired stamp before it does -- and the index is a pointer
     * subtraction because the table is a flat array, which is the same shape
     * nickreg_learn() uses for the same reason. A caller that wrote the
     * comparison out again would have a second place where the key is decided,
     * and the key is the whole security argument. */
    w = resume_find(s, c, now_ms);
    if (w == NULL) {
        return 0; /* no window: the ordinary case, and not an error */
    }
    idx = (size_t)(w - s->resume_windows);
    /* THREE OUTCOMES FOR ONE MATCH, and the third is the one this whole
     * two-stage expiry exists to reach:
     *
     *   RETIRED        the window aged out and the tombstone is still here. The
     *                  client is told, in a NOTICE it can render, and nothing is
     *                  restored.
     *   AGED OUT BUT NOT YET SWEPT
     *                  the window is past its bound and the sweep has not got
     *                  to it. This is the SAME answer as RETIRED, and treating it
     *                  differently is the bug: a client would be told "your
     *                  session could not be resumed" on one tick and told nothing
     *                  on the next, depending on whether the sweep had run. The
     *                  window is marked retired here so that the sweep's own
     *                  decision and this one cannot disagree about when it
     *                  expired.
     *   LIVE           the restore below. */
    if (s->resume_windows[idx].retired_ms != 0u ||
        (now_ms >= s->resume_windows[idx].dropped_ms &&
         (now_ms - s->resume_windows[idx].dropped_ms) >= g_window_ms)) {
        if (s->resume_windows[idx].retired_ms == 0u) {
            s->resume_windows[idx].retired_ms = now_ms;
        }
        s->n_resume_expired++;
        printf("[observable] session_resume_miss: nick=%s ident=%s reason=EXPIRED\n",
               c->nick, c->user);
        /* THE TOMBSTONE IS TAKEN HERE, so a client that comes back twice is told
         * once and the second is an ordinary registration. That asymmetry is
         * deliberate: the first arrival is a client that lost a session and
         * deserves an answer, and the second is a client that has just been told
         * the answer. */
        resume_drop_at(s, idx);
        (void)send_line(s, c, s->name, "NOTICE",
                        (const char *const[]){ c->nick,
                                               "Session resume unavailable: the "
                                               "window closed. Re-join to "
                                               "restore your channels." },
                        2);
        return 0;
    }
    if ((now_ms - s->resume_windows[idx].dropped_ms) >= g_window_ms) {
        /* Unreachable given the arm above, and kept as the belt to it: the first
         * arm reads the age and this one reads the bound, and a change to one
         * that missed the other would be a window that is neither restored nor
         * reported. */
        s->resume_windows[idx].retired_ms = now_ms;
        s->n_resume_expired++;
        printf("[observable] session_resume_miss: nick=%s ident=%s reason=EXPIRED\n",
               c->nick, c->user);
        resume_drop_at(s, idx);
        (void)send_line(s, c, s->name, "NOTICE",
                        (const char *const[]){ c->nick,
                                               "Session resume unavailable: the "
                                               "window closed. Re-join to "
                                               "restore your channels." },
                        2);
        return 0;
    }
    /* COPIED OUT before the take, for the same reason the key was: the array
     * shifts underneath the pointer. The copy is onto the STACK at the bound
     * rather than a heap allocation, which is what lets this function have no
     * failure mode of its own. */
    nchans = s->resume_windows[idx].nchans;
    dropped = s->resume_windows[idx].dropped_chans;
    for (i = 0; i < nchans; i++) {
        chans[i] = s->resume_windows[idx].chans[i];
    }
    /* TAKEN, BEFORE THE RESTORE. A window is one-shot, and taking it first is
     * what makes a partial restore unreplayable: a second connection presenting
     * the same nick, ident and host finds nothing and gets an ordinary
     * registration. */
    resume_drop_at(s, idx);
    s->n_resume_applied++;

    for (i = 0; i < nchans; i++) {
        chan_t *ch = server_chan_get(s, chans[i].name);
        unsigned flags;

        if (ch == NULL) {
            /* THE CHANNEL IS GONE. It was disposed while the client was away --
             * every member left, or the node dropped it -- and the client is
             * told, because a session that came back with fewer channels than it
             * had and no explanation is indistinguishable from one that lost
             * them. */
            s->n_resume_chan_gone++;
            printf("[observable] session_resume_skip: channel=%s reason=NO_CHANNEL\n",
                   chans[i].name);
            continue;
        }
        if (chan_find_nick(ch, c->nick) != NULL) {
            /* SOMEBODY ELSE HOLDS THIS NICK ON THIS CHANNEL, which is possible
             * because the window outlived the connection that had the nickname:
             * another client claimed the nick, joined the channel, and this
             * connection has just claimed the nick back. Two members with one
             * nickname in one roster is a roster 353 would draw twice and MODE
             * would resolve ambiguously, so the restore is refused for this
             * channel and the client is told. */
            s->n_resume_chan_taken++;
            printf("[observable] session_resume_skip: channel=%s reason=NICK_TAKEN\n",
                   chans[i].name);
            continue;
        }
        flags = resume_flags_for(s, ch, chans[i].flags);
        if (chans[i].flags != 0u && flags != chans[i].flags) {
            /* THE ONE LINE THAT MAKES THE FEATURE HONEST about privilege: it
             * names a channel where the client held a prefix the channel did not
             * re-grant, and a 353 will show the difference. Without it the
             * change from "@nick" to "nick" would be a mystery, and the whole
             * design's claim is that the change is deliberate. */
            printf("[observable] session_resume_flag: channel=%s nick=%s had=%c now=- "
                   "reason=NOT_REGRANTED\n",
                   chans[i].name, c->nick,
                   (chans[i].flags & CHAN_MEMBER_OP) != 0u ? '@' : '+');
        }
        if (chan_admit(s, c, ch, flags) == 0) {
            joined++;
        }
    }
    printf("[observable] session_resume: nick=%s ident=%s chans=%zu joined=%zu\n",
           nick, ident, nchans, joined);
    if (dropped > 0u || joined < nchans) {
        /* ONE NOTICE FOR ANY INCOMPLETE RESTORE, and it is a NOTICE rather than
         * a numeric for the reason the expired case gives: there is no 4.4 code
         * for "your session came back with fewer channels than it had", and a
         * client that cannot act on a number is not being told anything. The
         * count is the useful half: how many of the recorded channels did not
         * come back. */
        char text[160];

        (void)snprintf(text, sizeof text,
                       "Session resumed with %zu of %zu channels; re-join the "
                       "rest.",
                       joined, nchans);
        (void)send_line(s, c, s->name, "NOTICE",
                        (const char *const[]){ c->nick, text }, 2);
    }
    return 1;
}

/* ---------------------------------------------------------------------------
 * The clock, the sweep, and the teardown
 * ---------------------------------------------------------------------------
 */

void resume_set_window(uint64_t window_ms)
{
    /* ZERO IS REFUSED rather than clamped, and the reason is that "no window"
     * and "a window that expires immediately" are different configurations.
     * A caller who wants the feature off gets a resume_find() that never
     * matches, because the recorded window is older than any subsequent
     * lookup -- which is what resume_set_window(1) buys, and it is why this
     * function returns without setting anything rather than setting 0 and
     * making every window match and immediately expire. */
    if (window_ms == 0u) {
        return;
    }
    g_window_ms = window_ms;
}

uint64_t resume_window_ms(void)
{
    return g_window_ms;
}

/* The grace, and it is CLAMPED AT ONE TICK'S WORTH so a window shorter than the
 * divisor still gets a tombstone that outlives a sweep. Without the clamp a
 * window of 30 ms would retire and be freed inside the same sweep call, and the
 * window the client is told about would be gone before it could be told -- which
 * is the failure the two-stage expiry exists to prevent, reintroduced through
 * the other end. */
uint64_t resume_hold_ms(void)
{
    /* WINDOW/2, CLAMPED into [1000, 5000]. resume.h argues both clamps: the floor
     * is above the sweep interval at every window length this build can be given
     * (window/16 is 75 ms even at the floor's 1000 ms window... which is BELOW
     * the floor, so the floor is what guarantees the hold is re-checked at least
     * once while in force, and the ceiling is what keeps a two-minute window from
     * delaying a channel's disposal for two minutes). */
    uint64_t hold = g_window_ms / 2u;

    if (hold < 1000u) {
        hold = 1000u;
    }
    if (hold > 5000u) {
        hold = 5000u;
    }
    return hold;
}

static uint64_t resume_grace_ms(void)
{
    uint64_t grace = g_window_ms / IRC_RESUME_GRACE_DIVISOR;

    return (grace == 0u) ? 1u : grace;
}

int resume_holds(const server_t *s, const char *chan)
{
    size_t i;
    size_t k;

    if (s == NULL || s->resume_windows == NULL || chan == NULL) {
        return 0;
    }
    /* THE NAME COMPARISON FOLDS, because the channel registry's own key does
     * (server_chan_get() canonicalises through the same ascii fold) and a
     * retention test that compared bytes would miss `#chan` for a window that
     * recorded `#CHAN` -- and the consequence of a miss is the feature quietly
     * not working on a node where a client happened to type a capital. */
    for (i = 0; i < s->nresume_used; i++) {
        const struct resume_window *w = &s->resume_windows[i];

        /* A WINDOW PAST ITS HOLD IS NOT HOLDING, and that is the whole of what
         * keeps 2.2's disposal rule true: a channel is delayed, not exempted. The
         * flag is consulted here rather than by deleting the window, because the
         * window itself is still resumable -- the client may come back and be
         * told which of its channels did not survive, which is a fact it can act
         * on and a silent omission is not. */
        if (w->hold_released != 0) {
            continue;
        }
        for (k = 0; k < w->nchans; k++) {
            if (same_folded(w->chans[k].name, chan)) {
                return 1;
            }
        }
    }
    return 0;
}

/* Offer every channel a dying window was holding back to the disposal rule.
 *
 * IT IS CALLED PER WINDOW AND NOT ONCE AT THE END, and the reason is that
 * chan_dispose_if_empty() now ASKS whether another window still holds the
 * channel. A window that went at index 0 releases its channels only if no
 * LATER window also names them, and doing them in a batch at the end would have
 * each window's channels released by the wrong one -- which for two windows
 * sharing a channel means the first to die keeps the channel alive for the
 * second and the second disposes a channel the first still claims. */
static void resume_reclaim(server_t *s, const struct resume_window *w)
{
    size_t k;

    /* SAFE TO CALL MORE THAN ONCE, and it is called from two places: the hold
     * release and the free. The second call is a no-op because the channels are
     * either gone or already offered back and disposed -- and being idempotent is
     * what lets the two bounds be independent instead of one having to know
     * whether the other has run. */
    for (k = 0; k < w->nchans; k++) {
        chan_t *ch = server_chan_get(s, w->chans[k].name);

        if (ch == NULL) {
            continue; /* already gone: nothing to offer back */
        }
        /* chan_dispose_if_empty() is the WHOLE of the disposal rule and this is
         * a call to it rather than a second opinion: it knows the "no local
         * members AND no remote ones" condition, and it asks resume_holds() about
         * the remaining windows itself. A caller that checked the counts here and
         * then freed would be a second copy of the rule, and would be a copy that
         * did not learn about the retention when the retention was added. */
        (void)chan_dispose_if_empty(s, ch);
    }
}

size_t resume_sweep(server_t *s, uint64_t now_ms)
{
    size_t i = 0u;
    size_t dropped = 0u;
    size_t retired = 0u;

    if (s == NULL || s->resume_windows == NULL) {
        return 0u;
    }
    /* NO THROTTLE HERE, and the reason is that the caller throttles: the sweep
     * is driven from server_tick(), which runs every POLL_TICK_MS, and doing
     * the walk every 50 ms to discover that nothing is old is the kind of cost a
     * store on the tick path should not pay. server_tick() asks resume_sweep()
     * at the throttle below instead, so the walk happens about once per
     * window/16 and the return value here is always the full count. */
    while (i < s->nresume_used) {
        /* NOT const, and the reason is the two-stage expiry: the live arm WRITES
         * retired_ms, so a window is mutated by the sweep that retires it rather
         * than by resume_apply() alone. That is deliberate -- it is what makes the
         * retire stamp the same value whoever got there first -- and it is why
         * the const on this pointer is a compile error rather than a cast away. */
        struct resume_window *w = &s->resume_windows[i];

        /* The comparison is SUBTRACTION and the guard is the `now < dropped`
         * test, which is the same shape fed_nickreg_sweep() uses and for the
         * same reason: 3.4's clock is monotonic and a subtraction is the shape
         * that stays correct if it ever is not. A window stamped in the future
         * -- which a clock that went backwards would produce -- is not
         * expired, and dropping it would lose a session over a clock glitch. */
        /* THE HOLD COMES FIRST, and the order is the whole of what makes the two
         * bounds independent: a window's channels are offered back at
         * resume_hold_ms(), which is well inside the window, so a channel whose
         * only member dropped is disposed while the window is still resumable. If
         * the retire arm came first, a client that came back after the hold would
         * find its window already a tombstone and would be told the session could
         * not be resumed -- when in fact the session could have been and it was the
         * channel that had gone. */
        if (w->hold_released == 0 && now_ms >= w->dropped_ms &&
            (now_ms - w->dropped_ms) >= resume_hold_ms()) {
            w->hold_released = 1;
            printf("[observable] session_resume_hold: nick=%s ident=%s released=1\n",
                   w->nick, w->ident);
            /* THE CHANNELS ARE OFFERED BACK HERE and not at the free, because
             * chan_dispose_if_empty() is the disposal rule and this flag is what
             * makes it agree that the hold is over. A sweep that only reclaimed
             * at the free would leave every channel alive for the whole window
             * plus the grace -- and that is the 2.2 hole this design exists to
             * avoid, arriving by a different road. */
            resume_reclaim(s, w);
            continue; /* re-examine: nothing else about this window changed, but
                       * the index walk must not skip a retirement decided later
                       * in the same pass */
        }
        if (w->retired_ms == 0u) {
            if (now_ms >= w->dropped_ms && (now_ms - w->dropped_ms) >= g_window_ms) {
                /* RETIRE, DO NOT FREE. This is the stage that makes expiry
                 * visible on the wire: a freed window is a client that comes back
                 * too late and is told NOTHING, and the sweep runs on a tick, so
                 * "too late" almost always means "already freed". The entry stays
                 * as a tombstone so resume_apply() can find it and refuse it
                 * out loud. */
                w->retired_ms = now_ms;
                s->n_resume_expired++;
                retired++;
                /* ONE LINE PER WINDOW, with the nick in it, and the reason is a
                 * test that cannot be satisfied by the wrong one. A summary line
                 * saying "retired=1" is matched by the retirement of ANY window,
                 * and a test waiting for a particular client's window to expire
                 * would be satisfied by an unrelated one -- which is exactly what
                 * a first version of this did, and it is the reason the expiry
                 * case was reported as unreachable. Retirement is rare, so the
                 * lines are rare too, and a log that names what it retired is
                 * worth more than one that counts it. */
                printf("[observable] session_resume_retire: nick=%s ident=%s\n",
                       w->nick, w->ident);
                continue;
            }
            i++;
            continue;
        }
        if (now_ms < w->retired_ms ||
            (now_ms - w->retired_ms) < resume_grace_ms()) {
            /* STILL INSIDE THE GRACE, and the guard is the same `now <` test the
             * live arm uses: a stamp in the future is not due, and dropping a
             * tombstone over a clock glitch would be the wrong way to lose it. */
            i++;
            continue;
        }
        /* THE GRACE RAN OUT AND NOBODY CLAIMED IT, so it is freed -- and the
         * channels it was holding are offered back first, because
         * resume_holds() counts LIVE and RETIRED windows alike (a tombstone still
         * claims its channels: the client may yet arrive and be told, and until
         * it has been told the channel it is coming back to must still exist) and
         * so the reclaim has to come after the removal it is reacting to. */
        dropped++;
        printf("[observable] session_resume_free: nick=%s ident=%s\n", w->nick,
               w->ident);
        resume_reclaim(s, w);
        resume_drop_at(s, i);
        continue; /* the tail shifted into i, so examine it again */
    }
    if (retired > 0u || dropped > 0u) {
        printf("[observable] session_resume_sweep: retired=%zu dropped=%zu "
               "held=%zu\n",
               retired, dropped, s->nresume_used);
    }
    if (dropped > 0u) {
        s->n_resume_swept += dropped;
    }
    return dropped;
}

void resume_close(server_t *s)
{
    if (s == NULL) {
        return;
    }
    /* THE ARM, and it PRINTS WHETHER THE TABLE WAS OPEN so it can be asserted
     * on a platform whose LeakSanitizer does not run -- the argument
     * server_shutdown() makes about the burst shadow, and the reason a test can
     * prove this ran without a leak checker while Linux CI reads the same line
     * next to its LSan run. */
    printf("[observable] session_resume_close: table=%s held=%zu\n",
           (s->resume_windows != NULL) ? "OPEN" : "NONE", s->nresume_used);
    free(s->resume_windows);
    s->resume_windows = NULL;
    s->nresume_used = 0u;
}

size_t resume_count(const server_t *s)
{
    return (s != NULL) ? s->nresume_used : 0u;
}
