/* burst.c -- see burst.h. The 4.3 resync: the wire format, the staged send, and
 * the transaction that replaces rather than merges. */
#include "federation/burst.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/channel.h"
#include "core/connection.h"
#include "federation/link.h"
#include "federation/verbs.h"

/* ---------------------------------------------------------------------------
 * THE FIVE WORDS
 * ---------------------------------------------------------------------------
 * A table rather than a switch, for the reason fed_sverb_for() gives: a switch
 * over strings duplicates every name in the source, so a typo in one arm
 * compiles cleanly and answers wrongly at run time -- and here the wrong answer
 * is "this node does not implement 4.3's resync", which is a version fact an
 * operator would act on. A typo in a table entry is a word that never matches,
 * which is visibly wrong on the wire. */
static const char *const BURST_VERBS[] = { "SBURST", "SBURSTN", "SBURSTC",
                                            "SBURSTM", "SBURSTE" };

int fed_burst_verb(const char *verb)
{
    if (verb == NULL) {
        return 0;
    }
    for (size_t i = 0; i < sizeof BURST_VERBS / sizeof BURST_VERBS[0]; i++) {
        if (strcmp(BURST_VERBS[i], verb) == 0) {
            return 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * THE SHADOW -- the transaction being assembled
 * ---------------------------------------------------------------------------
 * There is ONE, and it is a module global for the reason the shared secret and
 * the dispatch hook in federation/link.c are: this node is one process
 * (fed_open() refuses a second node) and the loop is single-threaded (3.4). A
 * per-link shadow would be a second thing to index for no property -- a node has
 * one transaction in flight per link, and a link's transaction is over the
 * instant a second SBURST arrives on it, because a BEGIN discards whatever was
 * open.
 *
 * WHAT A NICK RECORD KEEPS, and what it does not, is the interesting part of
 * this struct. SBURSTN carries nick, user, host, modes, signon and away, and
 * the shadow stores ONE of those six: the host. That is not a shortcut, it is the
 * whole of what there is somewhere to put. The one persistent consumer of a
 * burst's nick records in this phase is chan_remote_t::host, and 2.1's "which
 * server holds the user called X" registry -- the thing the other five fields
 * exist for -- is Phase 9's work and has no home on server_t yet. The other five
 * are ON THE WIRE anyway: 4.3 names them, and a format that omitted them would
 * have to be extended the moment that registry arrives, which is exactly what
 * 4.3's "a wire format cannot be invented later" is about. The count of accepted
 * nick records is what SBURSTE's first count is compared against, and a counter
 * does not need the records themselves to do that. */
typedef struct {
    char nick[IRC_MAX_NICK + 1];
    char host[CHAN_MAX_REMOTE_HOST + 1];
} burst_nick_t;

/* One member line. The flags word is the wire's: '-', "o", "v" or "ov". It is
 * NOT the SJOIN token, which carries a leading '+' -- see the header on why the
 * two differ. */
typedef struct {
    char     nick[IRC_MAX_NICK + 1];
    unsigned flags;
} burst_member_t;

typedef struct {
    char            name[CHAN_MAX_NAME + 1];
    char            origin[CHAN_MAX_SERVER + 1];
    char            topic[CHAN_MAX_TOPIC + 1];
    char            topic_who[CHAN_MAX_TOPIC_WHO + 1];
    uint64_t        topic_when; /* the ORIGIN's clock, which is what 333 wants */
    char            modes[CHAN_MAX_MODES + 1];
    burst_member_t *members;
    size_t          nmembers;
    size_t          mcap;
} burst_chan_t;

typedef struct {
    int             open;  /* a BEGIN has arrived and no COMMIT has           */
    char            origin[IRC_MAX_SERVER_NAME + 1];
    uint64_t        epoch; /* what the BEGIN claimed                          */
    uint64_t        expect_nnicks;
    size_t          nnicks;
    size_t          nchans;
    size_t          nmembers;
    size_t          bytes; /* volume charged against IRC_BURST_MAX_BYTES       */
    burst_nick_t   *nicks;
    size_t          nnick_cap;
    burst_chan_t   *chans;
    size_t          nchan_cap;
    size_t          nchan_used;
    burst_chan_t   *cur; /* the SBURSTC the SBURSTM lines attach to           */
} burst_shadow_t;

static burst_shadow_t g_shadow;
static size_t          g_max_bytes = IRC_BURST_MAX_BYTES;

void fed_burst_set_max_bytes(size_t max_bytes)
{
    /* 0 KEEPS THE BUILT-IN rather than meaning "no bytes": a zero budget is not
     * a configuration anybody wants, and the alternative is a second sentinel for
     * the same question. fed_set_timeouts() answers it the same way. */
    if (max_bytes > 0u) {
        g_max_bytes = max_bytes;
    }
}

/* A bounded copy. The same rule as channel.c's copy_bounded() -- refuse, never
 * truncate -- for the reason 3.2 gives: a truncated host is a hostmask that is
 * not the one the peer reported. It is a copy rather than an export because
 * channel.c's is static, and a shared helper for two strings is a header
 * dependency this file does not otherwise have. */
static int burst_copy(char *dst, size_t cap, const char *src)
{
    size_t n;

    if (dst == NULL || cap == 0u || src == NULL) {
        return 0;
    }
    n = strlen(src);
    if (n >= cap) {
        return 0;
    }
    memcpy(dst, src, n + 1u);
    return 1;
}

/* An unsigned decimal in 2.4's grammar: 1..20 digits, no leading zero unless
 * the value is exactly "0", no sign. The same rule the epoch and id tags use, for
 * the same reason -- a grammar stated once in this tree and used twice cannot
 * disagree with itself. 0 legal, -1 not. */
static int burst_parse_u64(const char *v, uint64_t *out)
{
    uint64_t acc = 0;
    size_t i;

    if (v == NULL || out == NULL || v[0] == '\0') {
        return -1;
    }
    for (i = 0; v[i] != '\0'; i++) {
        if (v[i] < '0' || v[i] > '9') {
            return -1;
        }
        /* Overflow rather than wrap: a topic_when that wrapped to a small number
         * is a plausible timestamp for the wrong year, and a plausible wrong
         * value is worse than a refusal. */
        if (acc > (UINT64_MAX - (uint64_t)(v[i] - '0')) / 10u) {
            return -1;
        }
        acc = acc * 10u + (uint64_t)(v[i] - '0');
    }
    if (i > 20u || (i > 1u && v[0] == '0')) {
        return -1;
    }
    *out = acc;
    return 0;
}

static void burst_render_u64(char *out, size_t cap, uint64_t v)
{
    /* 24 is 20 digits plus room for a sign this path never emits, and the
     * buffer is a fixed local at every call site -- so the truncation snprintf
     * would report cannot happen, and the value is a number rather than a
     * string a peer could have made longer. */
    (void)snprintf(out, cap, "%llu", (unsigned long long)v);
}

/* ---------------------------------------------------------------------------
 * THE STAGING BUFFER -- all-or-nothing, and why it is not the queue
 * ---------------------------------------------------------------------------
 * 3.4 drops a saturated link rather than buffering it, so a burst that does not
 * fit cannot be discovered one line at a time: by the time the queue refuses the
 * 900th line, the first 899 are on the wire and the peer holds a transaction
 * with no terminator. Rendering first and flushing second is what makes "refuse
 * the burst in full" a thing this node can actually do, and the offsets are what
 * make the flush a second pass over ONE render rather than a second render with
 * its own chance of disagreeing with the first. */
typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
    size_t *at; /* each line's offset into buf, CRLF included */
    size_t *sz; /* each line's length, CRLF included     */
    size_t n;
    size_t acap;
} burst_stage_t;

static void stage_free(burst_stage_t *st)
{
    free(st->buf);
    free(st->at);
    free(st->sz);
    memset(st, 0, sizeof *st);
}

static int stage_grow(burst_stage_t *st, size_t want)
{
    size_t ncap = (st->cap == 0u) ? 1024u : st->cap;
    char *grown;

    while (ncap < want) {
        ncap *= 2u;
    }
    grown = (char *)realloc(st->buf, ncap);
    if (grown == NULL) {
        return -1;
    }
    st->buf = grown;
    st->cap = ncap;
    return 0;
}

static int stage_note(burst_stage_t *st, size_t off, size_t len)
{
    if (st->n == st->acap) {
        size_t want = (st->acap == 0u) ? 16u : st->acap * 2u;
        size_t *gat = (size_t *)realloc(st->at, want * sizeof *st->at);
        size_t *gsz;

        if (gat == NULL) {
            return -1;
        }
        st->at = gat;
        gsz = (size_t *)realloc(st->sz, want * sizeof *st->sz);
        if (gsz == NULL) {
            return -1;
        }
        st->sz = gsz;
        st->acap = want;
    }
    st->at[st->n] = off;
    st->sz[st->n] = len;
    st->n++;
    return 0;
}

/* Render one line into the staging buffer. 0 on success, -1 on any refusal.
 *
 * THE STAMP IS MINTED HERE, once per line, and that is the whole of 2.4's
 * treatment of a burst. A burst is O(n) lines: if they shared one id the
 * receiver's dedup store would drop every line after the first and a burst would
 * arrive as a BEGIN and nothing else. One id per line is what makes the records
 * individually deduped, and it is also why a REPLAYED burst is expensive rather
 * than invisible -- the replay's records are all dropped as duplicates, so the
 * replayed terminator's counts match nothing and the transaction is discarded
 * with the previous state left standing. That is the correct answer to a replay
 * and it is a consequence of the format rather than a rule bolted onto it. */
static int stage_line(burst_stage_t *st, server_t *s, const char *origin,
                      const char *verb, const char *const *params, int nparams)
{
    char block[IRC_MAX_TAG_OVERHEAD];
    char line[IRC_MAX_LINE + 2];
    irc_serve_tags_t tags;
    message_t m;
    size_t blen;
    size_t len;
    size_t need;

    memset(&tags, 0, sizeof tags);
    /* 2.4's outbound half, from fanout.h: this node is ORIGINATING, so origin
     * and epoch are this node's own and the id comes from the per-SERVER
     * counter. hops is 0 because every line of a burst is born on this node --
     * a burst is not a relayed thing, which is the reason one line per record is
     * affordable. */
    if (!burst_copy(tags.origin, sizeof tags.origin, origin)) {
        return -1;
    }
    tags.epoch = s->epoch;
    tags.id = server_next_msg_id(s);
    tags.hops = 0u;
    if (!irc_serve_tags_valid(&tags)) {
        return -1;
    }
    blen = irc_serve_tags_format(&tags, block, sizeof block);
    if (blen == 0u) {
        return -1;
    }
    if (message_build(&m, block, origin, verb, params, nparams) != 0) {
        return -1;
    }
    len = message_format(&m, line, sizeof line - 2u);
    message_free(&m);
    if (len == 0u) {
        return -1;
    }
    /* RFC 1459 2.3: CRLF. message_format() terminates nothing. */
    line[len] = '\r';
    line[len + 1u] = '\n';

    /* THE BUDGET CHECK, and it is before the append for the reason the whole
     * staging buffer exists: once a byte is in the buffer it is a byte this node
     * intends to send, and a burst that stops half way is the truncated
     * transaction the format exists to prevent. */
    need = st->len + len + 2u;
    if (need > g_max_bytes) {
        return -1;
    }
    if (stage_grow(st, need) != 0) {
        return -1;
    }
    if (stage_note(st, st->len, len + 2u) != 0) {
        return -1;
    }
    memcpy(st->buf + st->len, line, len + 2u);
    st->len = need;
    return 0;
}

/* Push the staged transaction at the peer. 0 on success, -1 when the link
 * saturated.
 *
 * A saturation HERE is a different event from a budget refusal and the two are
 * reported differently on purpose. The budget check happens before anything is
 * queued, so a burst that does not fit never reaches this function. A link that
 * saturates with a whole burst in front of it has already been sent most of a
 * transaction, and server_queue() has marked it CLOSING (3.4) so the reaper will
 * drop it; the peer sees a burst with no terminator and discards it, by exactly
 * the rule that catches a lost line. Returning -1 without rolling anything back
 * is correct: there is nothing to roll back. */
static int stage_flush(burst_stage_t *st, server_t *s, conn_t *peer)
{
    for (size_t i = 0; i < st->n; i++) {
        if (server_queue(s, peer, st->buf + st->at[i], st->sz[i]) != 0) {
            /* Already counted and already marked CLOSING by server_queue(); not
             * counted a second time here, and nothing is closed here. */
            return -1;
        }
    }
    return 0;
}

/* An empty MIDDLE parameter as the one byte that means "there is none of it here".
 *
 * 3.2 forces a literal rather than a convention: an empty middle parameter is not
 * representable at all, because message_parse() drops an empty uncolonned token
 * and message_format() renders the ':' marker only in the final position -- so
 * message_format() REFUSES the whole line, and a burst is a transaction, so one
 * unrenderable record would abort every one of them. `-` is what 4.3's SJOIN flag
 * token already uses for exactly this (see fed_flag_token() in
 * federation/verbs.c) and reusing it means the format has ONE empty-middle
 * convention rather than one per field.
 *
 * IT IS NOT COSMETIC, and the case that made it so is worth naming: a connection
 * that has sent NICK and not yet USER is in the nick registry, and 4.3 says a
 * burst carries ALL nicks. Its `user` field is therefore empty, and a sender that
 * put it on the wire as an empty token refused to render its own burst -- which
 * aborted the resync and, because the abort was a REFUSAL rather than a partial
 * send, left the peer with the state it had. A half-registered client is
 * ordinary: it is what every connection is for a few milliseconds.
 *
 * WHAT THE RECEIVER DOES WITH A `-` IS NOTHING, and that is the other half of why
 * this is cheap: of the four fields this is applied to, the shadow keeps only the
 * host, and a host is never empty for a connection that has been accepted. The
 * placeholder is on the wire so the line can be rendered, not because anything
 * downstream is waiting for a value. */
static const char *burst_mid_or_dash(const char *v)
{
    return ((v != NULL && v[0] != '\0') ? v : "-");
}

/* SBURSTN's <modes> is `-` ALWAYS on this build, and that is a property of the
 * node rather than of the format: commands.c says in terms that this node evaluates
 * neither umodes nor cmodes, and lists "i" only so 004 has something in it. The
 * field is on the wire because 4.3 names it, so a node that does evaluate user
 * modes fills it in without a format change. */
#define burst_modes_token(v) burst_mid_or_dash(v)

/* The member's flags, bare: '-', "o", "v" or "ov". The plus is the SJOIN token's
 * and not this one's. */
static int burst_flags_token(unsigned flags, char *out, size_t cap)
{
    size_t used = 0;

    if (cap < 3u) {
        return -1;
    }
    if (flags == 0u) {
        out[0] = '-';
        out[1] = '\0';
        return 0;
    }
    if ((flags & CHAN_MEMBER_OP) != 0u) {
        out[used++] = 'o';
    }
    if ((flags & CHAN_MEMBER_VOICE) != 0u) {
        out[used++] = 'v';
    }
    out[used] = '\0';
    return 0;
}

/* Is this local member a record the burst will actually carry?
 *
 * IT IS A FUNCTION BECAUSE THE COUNT AND THE RENDER MUST AGREE, and the receiver
 * is what notices when they do not: SBURSTE's counts are ASSERTED against what
 * arrived, so a member counted here and skipped there is a burst this node sends
 * that every peer discards. The member that differs is one whose connection the
 * loop has already marked CONN_CLOSING -- it is mid-teardown, it cannot be written
 * to, and chan_member_leave() will take it out of the list a moment later.
 *
 * So the predicate is asked in the counting pass AND in the rendering pass, from
 * one definition, and the cost of that is a function call per member per burst
 * where a duplicated condition would have cost nothing. That is the right trade:
 * the two copies of this condition are the ones that would drift. */
static int burst_member_reportable(const chan_t *ch, size_t i)
{
    return chan_member_live(&ch->members[i]);
}

/* ---------------------------------------------------------------------------
 * THE SIDE THAT SENDS
 * ---------------------------------------------------------------------------
 * Three things are counted BEFORE anything is rendered, and they are counted from
 * the same walks the render does -- through the same predicates, which is the part
 * that matters. They are not estimates: the receiver asserts the terminator's
 * against what arrived, so a sender that got them wrong would have every burst it
 * sent discarded by a node running this very code.
 */
int fed_burst_send(server_t *s, server_link_t *link)
{
    burst_stage_t st;
    conn_t *peer;
    size_t nnicks;
    size_t nchans = 0u;
    size_t nmembers = 0u;

    if (s == NULL || link == NULL) {
        return -1;
    }
    /* Only an ESTABLISHED link with a live connection is a route (2.3), and a
     * burst onto anything else is a caller's bug rather than a protocol event --
     * so it is refused and counted, not sent at a descriptor that may not be
     * there. */
    if (link->state != (int)ESTABLISHED) {
        s->n_burst_refused++;
        printf("[observable] fed_burst_refused: peer=%s state=%d "
               "reason=NOT_ESTABLISHED\n",
               link->name, link->state);
        return -1;
    }
    peer = server_link_conn(s, link);
    if (peer == NULL) {
        s->n_burst_refused++;
        printf("[observable] fed_burst_refused: peer=%s reason=NO_CONN\n",
               link->name);
        return -1;
    }

    nnicks = server_nick_count(s);
    for (size_t i = 0; i < server_chan_count(s); i++) {
        const chan_t *ch = server_chan_at(s, i);

        if (ch == NULL) {
            continue;
        }
        nchans++;
        for (size_t k = 0; k < ch->nmembers; k++) {
            if (burst_member_reportable(ch, k) != 0) {
                nmembers++;
            }
        }
        nmembers += ch->nremotes;
    }

    memset(&st, 0, sizeof st);

    /* --- the BEGIN ------------------------------------------------------ */
    {
        const char *params[2];
        char epoch[24];
        char nis[24];

        burst_render_u64(epoch, sizeof epoch, s->epoch);
        burst_render_u64(nis, sizeof nis, (uint64_t)nnicks);
        params[0] = epoch;
        params[1] = nis;
        if (stage_line(&st, s, s->name, "SBURST", params, 2) != 0) {
            goto refused;
        }
    }

    /* --- every nick ------------------------------------------------------ */
    /* The enumeration is the nick registry's, which is one entry per CONNECTION
     * and so a count of people rather than a count of names (see server.h), and
     * every one of them is registered: an unregistered connection holds no name
     * and is therefore not in it. */
    for (size_t i = 0; i < nnicks; i++) {
        const conn_t *c = server_nick_at(s, i);
        const char *params[6];
        char signon[24];

        if (c == NULL) {
            continue;
        }
        burst_render_u64(signon, sizeof signon, (uint64_t)c->signon_at);
        params[0] = c->nick;
        /* The two fields a connection may not have filled in yet, through the same
         * placeholder as the rest. `nick` needs none: a connection is in the
         * registry only because it claimed a name. */
        params[1] = burst_mid_or_dash(c->user);
        params[2] = burst_mid_or_dash(c->host);
        params[3] = burst_modes_token(NULL);
        params[4] = signon;
        /* The trailing value. An empty away renders as a bare `:`, which is
         * 3.2's one representation of "there is no text here" and the reason
         * this field needs no escape of its own. */
        params[5] = c->away;
        if (stage_line(&st, s, s->name, "SBURSTN", params, 6) != 0) {
            goto refused;
        }
    }

    /* --- every channel, and its members immediately after it -------------- */
    for (size_t i = 0; i < server_chan_count(s); i++) {
        const chan_t *ch = server_chan_at(s, i);
        const char *params[6];
        char when[24];

        if (ch == NULL) {
            continue;
        }
        burst_render_u64(when, sizeof when, (uint64_t)ch->topic_when);
        params[0] = ch->name;
        params[1] = ch->origin;
        /* topic_who is a MIDDLE parameter, so a channel with no topic set has to
         * say so with the `-` literal rather than with an empty token. */
        params[2] = burst_modes_token(ch->topic_who);
        params[3] = when;
        params[4] = burst_modes_token(ch->modes);
        params[5] = ch->topic;
        if (stage_line(&st, s, s->name, "SBURSTC", params, 6) != 0) {
            goto refused;
        }
        for (size_t k = 0; k < ch->nmembers; k++) {
            char flags[4];

            if (burst_member_reportable(ch, k) == 0) {
                continue;
            }
            if (burst_flags_token(ch->members[k].flags, flags, sizeof flags) != 0) {
                goto refused;
            }
            params[0] = ch->name;
            params[1] = ch->members[k].c->nick;
            params[2] = flags;
            if (stage_line(&st, s, s->name, "SBURSTM", params, 3) != 0) {
                goto refused;
            }
        }
        for (size_t k = 0; k < ch->nremotes; k++) {
            const chan_remote_t *r = chan_remote_at(ch, k);
            char flags[4];

            if (r == NULL || r->nick[0] == '\0') {
                continue;
            }
            if (burst_flags_token(r->flags, flags, sizeof flags) != 0) {
                goto refused;
            }
            params[0] = ch->name;
            params[1] = r->nick;
            params[2] = flags;
            if (stage_line(&st, s, s->name, "SBURSTM", params, 3) != 0) {
                goto refused;
            }
        }
    }

    /* --- the COMMIT ------------------------------------------------------ */
    {
        const char *params[4];
        char epoch[24];
        char cn[24];
        char cc[24];
        char cm[24];

        burst_render_u64(epoch, sizeof epoch, s->epoch);
        burst_render_u64(cn, sizeof cn, (uint64_t)nnicks);
        burst_render_u64(cc, sizeof cc, (uint64_t)nchans);
        burst_render_u64(cm, sizeof cm, (uint64_t)nmembers);
        params[0] = epoch;
        params[1] = cn;
        params[2] = cc;
        params[3] = cm;
        if (stage_line(&st, s, s->name, "SBURSTE", params, 4) != 0) {
            goto refused;
        }
    }

    if (stage_flush(&st, s, peer) != 0) {
        size_t was = st.len;

        stage_free(&st);
        printf("[observable] fed_burst_saturated: peer=%s bytes=%zu\n", link->name,
               was);
        return -1;
    }
    printf("[observable] fed_burst_sent: peer=%s epoch=%llu nicks=%zu chans=%zu "
           "members=%zu bytes=%zu budget=%zu\n",
           link->name, (unsigned long long)s->epoch, nnicks, nchans, nmembers,
           st.len, g_max_bytes);
    stage_free(&st);
    return 0;

refused:
    /* NOTHING WAS QUEUED. The whole transaction is still in a staging buffer
     * that is about to be freed, the link has not been touched, and this node's
     * own state is exactly what it was. That difference from a saturation
     * mid-flush is the entire reason the burst is rendered before it is sent. */
    {
        size_t was = st.len;

        stage_free(&st);
        s->n_burst_refused++;
        printf("[observable] fed_burst_refused: peer=%s bytes=%zu budget=%zu "
               "reason=TOO_LARGE\n",
               link->name, was, g_max_bytes);
    }
    return -1;
}

int federation_resync(server_t *s, server_link_t *link)
{
    if (s == NULL || link == NULL) {
        return -1;
    }
    /* Both callers of this have a legitimate reason to reach it -- a link that
     * has just been established, and a link Phase 9 has decided is worth
     * re-syncing -- so a link that is not up is a no-op rather than a refusal.
     * Counting it would put a number on a caller's ordering mistake. */
    if (link->state != (int)ESTABLISHED) {
        return -1;
    }
    return fed_burst_send(s, link);
}

/* ---------------------------------------------------------------------------
 * THE SIDE THAT RECEIVES
 * ---------------------------------------------------------------------------
 * Everything below is the half of 4.3 that says "replaces, never merges". The
 * three properties that make that more than a phrase:
 *
 *   1. NOTHING IS VISIBLE UNTIL THE TERMINATOR. Every record goes into a SHADOW,
 *      and the shadow is installed over this node's live state in one step at
 *      SBURSTE. A burst that stops half way is therefore invisible, which is the
 *      only way "there is no partial burst" is true of a format on a stream that
 *      can stop at any byte.
 *   2. THE TERMINATOR'S COUNTS ARE ASSERTED. A receiver cannot know a burst has
 *      ended unless it is told, so what it is told is checked against what
 *      arrived rather than believed.
 *   3. THE INSTALL IS A REPLACEMENT PER ORIGIN, not an addition: the entries that
 *      origin contributed are dropped before its new ones arrive.
 */

/* Empty the shadow and close it. The arrays are RELEASED rather than merely
 * reset, and that is a deliberate choice against the obvious one: a node that
 * bursts on every link establishment would otherwise hold the peak of the
 * largest burst it has ever applied for the life of the process, and a node
 * whose peak burst is set by one client's away message has no business doing
 * that.
 *
 * THE COST, and it is the only leak-shaped thing in this file: a process that
 * exits MID-TRANSACTION leaves at most one bounded allocation behind -- the
 * records of a burst whose terminator never arrived. It is bounded by
 * IRC_BURST_MAX_BYTES, and it is released by fed_burst_abandon() the moment the
 * link carrying it goes down, which is the only way a transaction can still be
 * open when a node stops. The alternative -- a module teardown called from
 * server_shutdown() -- is a new arm on the node's shutdown for one bounded
 * allocation, and on this platform it could not be checked anyway:
 * LeakSanitizer is not supported on Darwin (see the hygiene note in 7/Phase 1),
 * so the claim would be asserted and not verified, which is a worse thing to
 * add a symbol for than a bounded residual. */
static void shadow_release(void)
{
    free(g_shadow.nicks);
    g_shadow.nicks = NULL;
    g_shadow.nnick_cap = 0u;
    g_shadow.nnicks = 0u;
    for (size_t i = 0; i < g_shadow.nchan_used; i++) {
        free(g_shadow.chans[i].members);
        g_shadow.chans[i].members = NULL;
        g_shadow.chans[i].nmembers = 0u;
        g_shadow.chans[i].mcap = 0u;
    }
    free(g_shadow.chans);
    g_shadow.chans = NULL;
    g_shadow.nchan_cap = 0u;
    g_shadow.nchan_used = 0u;
    g_shadow.nchans = 0u;
    g_shadow.cur = NULL;
    g_shadow.open = 0;
    g_shadow.origin[0] = '\0';
    g_shadow.epoch = 0u;
    g_shadow.expect_nnicks = 0u;
    g_shadow.nmembers = 0u;
    g_shadow.bytes = 0u;
}

/* Every discard in this file goes through here, so the counter and the
 * `[observable]` line cannot disagree about which rule fired. The previous
 * transaction's origin is printed because it is the thing an operator needs: a
 * node whose peer is discarding bursts is a node whose view of THAT peer is
 * stale. */
static void shadow_discard(server_t *s, const char *why, const char *origin,
                           size_t nnicks, size_t nchans, size_t nmembers)
{
    printf("[observable] fed_burst_abandon: origin=%s reason=%s nicks=%zu "
           "chans=%zu members=%zu bytes=%zu budget=%zu\n",
           (origin != NULL) ? origin : "?", (why != NULL) ? why : "?", nnicks,
           nchans, nmembers, g_shadow.bytes, g_max_bytes);
    s->n_burst_abandoned++;
    shadow_release();
}

void fed_burst_abandon(server_link_t *link)
{
    if (link == NULL || g_shadow.open == 0) {
        return;
    }
    printf("[observable] fed_burst_abandon: origin=%s reason=LINK_DOWN nicks=%zu "
           "chans=%zu members=%zu bytes=%zu\n",
           g_shadow.origin, g_shadow.nnicks, g_shadow.nchans, g_shadow.nmembers,
           g_shadow.bytes);
    shadow_release();
}

/* Charge a record's WIRE size against the same budget the sender charges, and
 * abandon the transaction if the peer exceeds it.
 *
 * THE RECEIVER ENFORCES THE SENDER'S BOUND, and the reason is that the bound
 * exists to bound this node's MEMORY and not to be polite about a peer's. The
 * shadow is a per-record heap allocation made out of what a peer said, which is
 * exactly the situation CHAN_MAX_REMOTE_MEMBERS and CHAN_MAX_MEMBER_SERVERS
 * exist for one level up; a peer that ignored the sender-side check could
 * describe an unbounded roster and this node would believe it.
 *
 * THE ACCOUNTING IS THE RENDERED SIZE rather than the record's own footprint, so
 * the two ends measure the same thing: a peer cannot make this node's shadow
 * larger than the budget by sending records that are cheap on the wire and
 * expensive in memory, and the budget in the header can be checked by hand
 * against a line in a log rather than against a struct. */
static int shadow_charge(server_t *s, const char *why, size_t wire_bytes)
{
    if (g_shadow.bytes + wire_bytes > g_max_bytes) {
        shadow_discard(s, why, g_shadow.origin, g_shadow.nnicks, g_shadow.nchans,
                       g_shadow.nmembers);
        return -1;
    }
    g_shadow.bytes += wire_bytes;
    return 0;
}

/* A record's wire size, computed the way stage_line() measures it: the tag block
 * at its FROZEN worst case, the prefix, the verb, and the parameters with their
 * separators. Using the frozen constant rather than this node's actual block is
 * deliberate -- a peer cannot shrink its charge by having a short server name,
 * and the receiver's bound and the sender's bound stay the same number. */
static size_t wire_size(const char *origin, const char *verb, char *const *p,
                        int nparams)
{
    size_t n = (size_t)IRC_MAX_TAG_OVERHEAD + strlen(origin) + strlen(verb);

    for (int i = 0; i < nparams; i++) {
        n += strlen(p[i]) + 1u;
    }
    return n + 4u; /* the CRLF, the colons, and the two spaces around the verb */
}

/* SBURST <epoch> <nnicks>: the BEGIN. */
static int apply_begin(server_t *s, server_link_t *link, const message_t *m)
{
    irc_serve_tags_t tags;
    uint64_t epoch = 0u;
    uint64_t nnicks = 0u;

    if (m->nparams != 2 || burst_parse_u64(m->params[0], &epoch) != 0 ||
        burst_parse_u64(m->params[1], &nnicks) != 0) {
        s->n_fed_malformed++;
        printf("[observable] fed_malformed: fd=%d command=SBURST field=begin "
               "nparams=%d\n",
               link->fd, m->nparams);
        return -1;
    }
    /* A transaction that is already open is REPLACED, not resumed. That is 4.3's
     * own rule arriving from the other direction: a BEGIN is a statement that
     * everything after it is the whole truth, and a truth that starts twice
     * without ending once has no reading. This is also the guard a peer that
     * opened a transaction and then sent a second BEGIN cannot use to make this
     * node hold two shadows' worth of state. */
    if (g_shadow.open != 0) {
        shadow_discard(s, "SUPERSEDED", g_shadow.origin, g_shadow.nnicks,
                       g_shadow.nchans, g_shadow.nmembers);
    }
    /* The transaction is about the PEER, and the peer is the link. A burst whose
     * tag block names a third server is a RELAYED burst, and this protocol has
     * no use for one: a burst is the full state of one origin, sent to the node
     * that needs it, and a node relaying it would be claiming to be the origin.
     * Refusing is one line here rather than a rule in the format. */
    if (irc_serve_tags_parse(m, &tags) != 0) {
        s->n_fed_malformed++;
        printf("[observable] fed_malformed: fd=%d command=SBURST field=tags\n",
               link->fd);
        return -1;
    }
    if (!chan_same_name(tags.origin, link->name)) {
        s->n_fed_malformed++;
        printf("[observable] fed_burst_refused: peer=%s origin=%s "
               "reason=RELAYED_BURST\n",
               link->name, tags.origin);
        return -1;
    }
    if (!burst_copy(g_shadow.origin, sizeof g_shadow.origin, link->name)) {
        return -1;
    }
    g_shadow.epoch = epoch;
    g_shadow.expect_nnicks = nnicks;
    g_shadow.open = 1;
    /* A peer that restarts and says so is the one case the epoch is FOR: the
     * ids this node will accept from that peer after the commit belong to the
     * boot the burst described, and leaving link->epoch at the old value would
     * pair them with the wrong one. It is applied at the COMMIT rather than here,
     * because a burst that never commits changed nothing and a link's epoch must
     * not move on a transaction that was thrown away. */
    (void)shadow_charge(s, "BEGIN_TOO_LARGE", wire_size(link->name, "SBURST",
                                                        m->params, 2));
    return 0;
}

/* SBURSTN <nick> <user> <host> <modes> <signon> :<away>. */
static int apply_nick(server_t *s, server_link_t *link, const message_t *m)
{
    burst_nick_t *slot;
    uint64_t signon = 0u;

    /* THE ARITY IS THE FORMAT'S, not the S-verb table's, and the nickname is
     * validated with 2.1's rule here for the reason channel.h's
     * chan_remote_add() gives: this is the first point in the tree where a
     * nickname arrives from a network rather than from a client, and a roster
     * entry that failed the charset would be a name the node could not qualify,
     * compare or render. `signon` is grammar-checked because the terminator's
     * counts are about records this node ACCEPTED, and accepting a record whose
     * numeric field is not a number would make that count a count of lines rather
     * than of records.
     *
     * <user>, <modes> and <away> ARE NOT VALIDATED, and the reason is that
     * nothing on this side uses them: the shadow keeps the host alone (see
     * burst_nick_t), and 3.2's formatter has already guaranteed that a
     * non-final parameter is neither empty nor colon-bearing by the time a line
     * parses. A second implementation that put a mode letter in there and
     * this one that did not is not a disagreement about anything this node
     * stores. */
    if (m->nparams != 6 || !valid_nick(m->params[0]) ||
        burst_parse_u64(m->params[4], &signon) != 0) {
        s->n_fed_malformed++;
        printf("[observable] fed_malformed: fd=%d command=SBURSTN nick=%s\n",
               link->fd, (m->nparams > 0) ? m->params[0] : "?");
        shadow_discard(s, "BAD_NICK_RECORD", g_shadow.origin, g_shadow.nnicks,
                       g_shadow.nchans, g_shadow.nmembers);
        return -1;
    }
    if (shadow_charge(s, "TOO_LARGE", wire_size(link->name, "SBURSTN", m->params,
                                                6)) != 0) {
        return -1;
    }
    if (g_shadow.nnicks == g_shadow.nnick_cap) {
        size_t want = (g_shadow.nnick_cap == 0u) ? 8u : g_shadow.nnick_cap * 2u;
        burst_nick_t *grown =
            (burst_nick_t *)realloc(g_shadow.nicks, want * sizeof *grown);

        if (grown == NULL) {
            s->n_fed_malformed++;
            shadow_discard(s, "NO_MEMORY", g_shadow.origin, g_shadow.nnicks,
                           g_shadow.nchans, g_shadow.nmembers);
            return -1;
        }
        g_shadow.nicks = grown;
        g_shadow.nnick_cap = want;
    }
    slot = &g_shadow.nicks[g_shadow.nnicks];
    (void)burst_copy(slot->nick, sizeof slot->nick, m->params[0]);
    /* A host longer than conn_t::host is TRUNCATED rather than refused, and that
     * is the one place in this file where a value is cut. The alternative -- a
     * refusal -- would abandon the whole transaction over a field the receiver
     * has one slot for, and the slot is the width this node would render the
     * hostmask at anyway. What is stored is what this node could have shown a
     * client, which is the honest bound on a cache. */
    (void)snprintf(slot->host, sizeof slot->host, "%s", m->params[2]);
    g_shadow.nnicks++;
    return 0;
}

/* SBURSTC <chan> <origin> <topic_who> <topic_when> <modes> :<topic>. */
static int apply_chan(server_t *s, server_link_t *link, const message_t *m)
{
    burst_chan_t *sc;
    uint64_t when = 0u;
    char canonical[CHAN_MAX_NAME + 1];

    if (m->nparams != 6 || !chan_name_valid(m->params[0]) ||
        !irc_serve_server_name_valid(m->params[1]) ||
        burst_parse_u64(m->params[3], &when) != 0) {
        s->n_fed_malformed++;
        printf("[observable] fed_malformed: fd=%d command=SBURSTC channel=%s\n",
               link->fd, (m->nparams > 0) ? m->params[0] : "?");
        shadow_discard(s, "BAD_CHAN_RECORD", g_shadow.origin, g_shadow.nnicks,
                       g_shadow.nchans, g_shadow.nmembers);
        return -1;
    }
    if (shadow_charge(s, "TOO_LARGE",
                      wire_size(link->name, "SBURSTC", m->params, 6)) != 0) {
        return -1;
    }
    if (g_shadow.nchan_used == g_shadow.nchan_cap) {
        size_t want = (g_shadow.nchan_cap == 0u) ? 8u : g_shadow.nchan_cap * 2u;
        burst_chan_t *grown =
            (burst_chan_t *)realloc(g_shadow.chans, want * sizeof *grown);

        if (grown == NULL) {
            s->n_fed_malformed++;
            shadow_discard(s, "NO_MEMORY", g_shadow.origin, g_shadow.nnicks,
                           g_shadow.nchans, g_shadow.nmembers);
            return -1;
        }
        memset(grown + g_shadow.nchan_cap, 0,
               (want - g_shadow.nchan_cap) * sizeof *grown);
        g_shadow.chans = grown;
        g_shadow.nchan_cap = want;
    }
    sc = &g_shadow.chans[g_shadow.nchan_used++];
    (void)chan_name_upper(canonical, sizeof canonical, m->params[0]);
    (void)burst_copy(sc->name, sizeof sc->name, canonical);
    (void)burst_copy(sc->origin, sizeof sc->origin, m->params[1]);
    (void)burst_copy(sc->topic, sizeof sc->topic, m->params[5]);
    (void)burst_copy(sc->topic_who, sizeof sc->topic_who,
                     ((m->params[2][0] == '-') ? "" : m->params[2]));
    (void)burst_copy(sc->modes, sizeof sc->modes,
                     ((m->params[4][0] == '-') ? "" : m->params[4]));
    sc->topic_when = when;
    g_shadow.cur = sc;
    g_shadow.nchans++;
    return 0;
}

/* SBURSTM <chan> <nick> <flags>: one member of the PRECEDING channel.
 *
 * THE <chan> FIELD IS CHECKED AGAINST THE SHADOW'S CURRENT CHANNEL, and the
 * check is redundant with the format and worth having anyway: a member line that
 * names a different channel is a peer whose writer is broken, and installing it
 * on the wrong channel is a roster this node cannot explain. Redundant rules are
 * cheap when the alternative is a divergence, which is the same argument
 * verbs.c's G6 makes for a hop ceiling the dedup store would also have caught. */
static int apply_member(server_t *s, server_link_t *link, const message_t *m)
{
    burst_member_t *slot;
    burst_chan_t *sc = g_shadow.cur;
    unsigned flags = 0u;

    if (sc == NULL || m->nparams != 3 || !valid_nick(m->params[1]) ||
        !chan_name_valid(m->params[0])) {
        s->n_fed_malformed++;
        printf("[observable] fed_malformed: fd=%d command=SBURSTM member=%s\n",
               link->fd, (m->nparams > 1) ? m->params[1] : "?");
        shadow_discard(s, "BAD_MEMBER_RECORD", g_shadow.origin, g_shadow.nnicks,
                       g_shadow.nchans, g_shadow.nmembers);
        return -1;
    }
    {
        char canonical[CHAN_MAX_NAME + 1];

        (void)chan_name_upper(canonical, sizeof canonical, m->params[0]);
        if (strcmp(canonical, sc->name) != 0) {
            s->n_fed_malformed++;
            printf("[observable] fed_malformed: fd=%d command=SBURSTM member=%s "
                   "reason=CHANNEL_MISMATCH\n",
                   link->fd, m->params[1]);
            shadow_discard(s, "CHANNEL_MISMATCH", g_shadow.origin, g_shadow.nnicks,
                           g_shadow.nchans, g_shadow.nmembers);
            return -1;
        }
    }
    /* The flags run: '-', or distinct letters from {o, v} in any order. Lenient on
     * receipt and strict on send, which is the right way round -- the canonical
     * form is this node's (see burst_flags_token) and a second implementation
     * that ordered the letters the other way is not a peer running a different
     * protocol, it is a peer whose two letters are the same two letters. */
    if (strcmp(m->params[2], "-") != 0) {
        if (m->params[2][0] == '\0') {
            s->n_fed_malformed++;
            shadow_discard(s, "BAD_FLAGS", g_shadow.origin, g_shadow.nnicks,
                           g_shadow.nchans, g_shadow.nmembers);
            return -1;
        }
        for (size_t i = 0; m->params[2][i] != '\0'; i++) {
            if (m->params[2][i] == 'o' && (flags & CHAN_MEMBER_OP) == 0u) {
                flags |= CHAN_MEMBER_OP;
            } else if (m->params[2][i] == 'v' &&
                       (flags & CHAN_MEMBER_VOICE) == 0u) {
                flags |= CHAN_MEMBER_VOICE;
            } else {
                s->n_fed_malformed++;
                shadow_discard(s, "BAD_FLAGS", g_shadow.origin, g_shadow.nnicks,
                               g_shadow.nchans, g_shadow.nmembers);
                return -1;
            }
        }
    }
    if (shadow_charge(s, "TOO_LARGE",
                      wire_size(link->name, "SBURSTM", m->params, 3)) != 0) {
        return -1;
    }
    if (sc->nmembers == sc->mcap) {
        size_t want = (sc->mcap == 0u) ? 8u : sc->mcap * 2u;
        burst_member_t *grown =
            (burst_member_t *)realloc(sc->members, want * sizeof *grown);

        if (grown == NULL) {
            s->n_fed_malformed++;
            shadow_discard(s, "NO_MEMORY", g_shadow.origin, g_shadow.nnicks,
                           g_shadow.nchans, g_shadow.nmembers);
            return -1;
        }
        sc->members = grown;
        sc->mcap = want;
    }
    slot = &sc->members[sc->nmembers++];
    (void)burst_copy(slot->nick, sizeof slot->nick, m->params[1]);
    slot->flags = flags;
    g_shadow.nmembers++;
    return 0;
}

/* ---------------------------------------------------------------------------
 * THE COMMIT -- the one moment this node's state changes
 * ---------------------------------------------------------------------------
 */

/* The host a burst's nick record announced, or NULL. A member whose nick was
 * never announced -- because the peer sent the member line and not the nick line,
 * or in the other order -- gets no host, and that is NOT an error: it is the
 * state a live SJOIN leaves a member in, and treating it as one would make a
 * perfectly correct peer look broken. */
static const char *shadow_host(const char *nick)
{
    for (size_t i = 0; i < g_shadow.nnicks; i++) {
        if (chan_same_name(g_shadow.nicks[i].nick, nick)) {
            return g_shadow.nicks[i].host;
        }
    }
    return NULL;
}

/* Does this node already know a member by that name in this channel, as a LOCAL
 * member or in the remote roster?
 *
 * IT IS WHAT STOPS A BURST FROM ADDING A NICK TWICE, and the duplicate it
 * prevents is not theoretical. A channel's membership is per (nick, server) and
 * 4.3's SBURSTM does not carry the server -- the burst is about the origin, so
 * the origin is the key. That is exact on the two-node mesh this phase's
 * acceptance criteria are about, and on a larger mesh it is a cache, because a
 * member sitting on a third node would be reported by the origin under the
 * origin's key. Installing it anyway would give the channel two entries for one
 * person, and 353 renders one line per member: the client would be shown the
 * same nickname twice and nothing on the node could explain it.
 *
 * So a name this node already knows is left exactly as it is, and only a name it
 * does not know is installed. The cost, and it is the same cost 2.1 already
 * names for duplicate nicks across servers: a member the origin reports and this
 * node already attributes to somebody else keeps the attribution it had, and
 * Phase 9's rename-the-loser is what resolves that. The rule is checked in
 * BOTH directions -- a local member counts -- so the common two-node case, where
 * the origin reports a member this node itself hosts, does not become a
 * self-membership. */
static int member_known(const chan_t *ch, const char *nick)
{
    if (chan_find_nick(ch, nick) != NULL) {
        return 1;
    }
    for (size_t i = 0; i < ch->nremotes; i++) {
        if (chan_same_name(ch->remotes[i].nick, nick)) {
            return 1;
        }
    }
    return 0;
}

/* Replace the mode set wholesale. Clearing through a COPY of the old value,
 * because chan_mode_set() compacts modes[] as it removes a letter and reading
 * ch->modes[i] out of the same string it is editing would skip letters. */
static void replace_modes(chan_t *ch, const char *modes)
{
    char old[CHAN_MAX_MODES + 1];

    (void)burst_copy(old, sizeof old, ch->modes);
    for (size_t i = 0; old[i] != '\0'; i++) {
        (void)chan_mode_set(ch, old[i], 0);
    }
    for (size_t i = 0; modes[i] != '\0'; i++) {
        (void)chan_mode_set(ch, modes[i], 1);
    }
}

/* The channel a shadow record is about: the one this node already has, or a new
 * one owned by the origin the record names.
 *
 * A channel this node does not have is CREATED, with the record's origin as its
 * origin and the BURST'S epoch as its creation epoch. That epoch is a stand-in
 * and is named as one: 2.2's tie-break is over (creation_epoch, server_name) and
 * the creation epoch of a channel is not on the wire, because a channel's
 * creation epoch is only meaningful next to the (epoch, name) of the FIRST
 * creator and a burst carries one epoch -- the origin's boot, which is the right
 * family and the wrong pair. 2.2's re-key is NOT attempted from here, and the
 * reason is the same one: re-keying on a value that cannot win the tie-break
 * honestly is a second, weaker rule for the same decision. Phase 9 owns it. The
 * cost, in this phase's mesh, is nothing observable: on a two-node mesh a
 * channel's origin is the only server that can report it, so the origin this
 * node already recorded is the origin the record names. */
static chan_t *resolve_shadow_chan(server_t *s, const burst_chan_t *sc,
                                   uint64_t epoch)
{
    chan_t *ch = server_chan_get(s, sc->name);

    if (ch != NULL) {
        return ch;
    }
    ch = chan_new(sc->name, sc->origin, epoch);
    if (ch == NULL || server_chan_attach(s, ch) != 0) {
        chan_free(ch);
        return NULL;
    }
    printf("[observable] chan_create: channel=%s origin=%s epoch=%llu "
           "creator=%s reason=BURST\n",
           ch->name, ch->origin, (unsigned long long)ch->origin_epoch, sc->origin);
    return ch;
}

/* The topic, from the origin's own record and not from this node's clock. 333 is
 * protocol-visible, so the value has to be the origin's: a receiver that stamped
 * it locally would show a client a time the origin never claimed, and the two
 * nodes would disagree about a number the protocol published. This is what
 * federation/verbs.h forward-references when it says the receiver "reads
 * topic_when from the origin's own record" -- before a burst existed there was no
 * such record on the wire, so that sentence described an intention rather than
 * the code. It is the code now. */
static void apply_topic(chan_t *ch, const burst_chan_t *sc)
{
    if (chan_set_topic(ch, sc->topic, sc->topic_who) != 0) {
        printf("[observable] fed_burst_topic_ignored: channel=%s reason=too_long\n",
               ch->name);
        return;
    }
    if ((uint64_t)(time_t)sc->topic_when != sc->topic_when) {
        return; /* a value this platform's time_t cannot hold: keep our own */
    }
    ch->topic_when = (time_t)sc->topic_when;
}

/* SBURSTE <epoch> <nnicks> <nchans> <nmembers>. */
static int apply_end(server_t *s, server_link_t *link, const message_t *m)
{
    const char *origin = g_shadow.origin;
    uint64_t epoch = 0u;
    uint64_t nn = 0u;
    uint64_t nch = 0u;
    uint64_t nmb = 0u;
    size_t installed = 0u;
    size_t purged = 0u;
    size_t dropped = 0u;

    if (g_shadow.open == 0) {
        /* A COMMIT with nothing open. Counted, not applied: a terminator on its
         * own is a peer that has lost track, and honouring it would mean this
         * node purging a peer's state on the strength of a line that claims to
         * replace it and names no records. */
        s->n_fed_malformed++;
        printf("[observable] fed_malformed: fd=%d command=SBURSTE "
               "reason=NO_TRANSACTION\n",
               link->fd);
        return -1;
    }
    if (m->nparams != 4 || burst_parse_u64(m->params[0], &epoch) != 0 ||
        burst_parse_u64(m->params[1], &nn) != 0 ||
        burst_parse_u64(m->params[2], &nch) != 0 ||
        burst_parse_u64(m->params[3], &nmb) != 0) {
        s->n_fed_malformed++;
        shadow_discard(s, "BAD_COMMIT", origin, g_shadow.nnicks, g_shadow.nchans,
                       g_shadow.nmembers);
        return -1;
    }
    /* THE COUNT ASSERTION, and it is the whole of "there is no partial burst".
     * Four equalities and nothing is visible: a lost SBURSTN, a SBURSTC refused
     * for an illegal channel name, a member line dropped as a duplicate at the
     * dedup guard, a link that saturated mid-flush -- every one of them is a
     * count that does not match, and every one of them leaves this node holding
     * exactly what it held before. A roster missing a member is worse than a
     * roster that is stale, because nothing downstream can tell them apart. */
    if (epoch != g_shadow.epoch || nn != g_shadow.expect_nnicks ||
        nch != (uint64_t)g_shadow.nchans || nmb != (uint64_t)g_shadow.nmembers) {
        /* NOT COUNTED AS n_fed_malformed, and the distinction is the point of
         * having two counters. That counter is documented as "arity or field
         * validation refused it", and every line of a transaction that reaches here
         * passed both -- what failed is the transaction, not a line, and it is
         * n_burst_abandoned that says so. Counting it twice would make one event
         * visible under two names whose meanings an operator has to keep apart, and
         * the "one counter per guard, one event" property server.h states for the
         * chain would stop being true. */
        printf("[observable] fed_burst_truncated: peer=%s epoch=%llu/%llu "
               "nicks=%llu/%llu chans=%llu/%zu members=%llu/%zu\n",
               link->name, (unsigned long long)epoch,
               (unsigned long long)g_shadow.epoch, (unsigned long long)nn,
               (unsigned long long)g_shadow.expect_nnicks,
               (unsigned long long)nch, g_shadow.nchans,
               (unsigned long long)nmb, g_shadow.nmembers);
        shadow_discard(s, "COUNT_MISMATCH", origin, g_shadow.nnicks,
                       g_shadow.nchans, g_shadow.nmembers);
        return -1;
    }

    /* The peer RESTARTED, and said so. 2.4's dedup key is (origin, epoch, id) and
     * a key whose epoch belongs to a different boot than its id is a key that
     * ALIASES, so link->epoch has to follow the burst: the ids this node will
     * accept from that peer after this commit belong to the boot the burst
     * described. Adopting it is not a security decision to be made lightly, and
     * it needs none: a peer that could lie about its epoch could already send an
     * arbitrary roster, which is strictly more power, and a peer that cannot is
     * reporting a real restart. Refusing would mean a genuine restart never
     * re-converges, and there is no other path that would fix it. */
    if (link->epoch != epoch) {
        printf("[observable] fed_burst_peer_restart: peer=%s epoch=%llu was=%llu\n",
               link->name, (unsigned long long)epoch,
               (unsigned long long)link->epoch);
        link->epoch = epoch;
    }

    /* --- the install, channel by channel --------------------------------- */
    for (size_t i = 0; i < g_shadow.nchan_used; i++) {
        const burst_chan_t *sc = &g_shadow.chans[i];
        chan_t *ch = resolve_shadow_chan(s, sc, g_shadow.epoch);

        if (ch == NULL) {
            dropped++;
            continue;
        }
        /* THE REPLACEMENT. Everything the origin contributed to this channel
         * goes, and only then does the new roster arrive. Without the purge a
         * member who left at the origin would stay in this node's 353 for ever,
         * because SPART is a per-member line and a burst is the only thing that
         * can say "none of them are here any more" -- and 4.3's replace-never-
         * merge is precisely that sentence. Entries from OTHER servers are not
         * touched, which is what makes the operation per-origin. */
        purged += chan_remote_purge(ch, origin);
        /* THE BURST ORIGIN'S OWN NAME GOES IN EVEN WHEN THE ORIGIN HAS NO LOCAL
         * MEMBERS OF THIS CHANNEL, and this is the single most load-bearing line
         * in the file.
         *
         * chan_dispose_if_empty() keeps a channel whose servers[] is non-empty,
         * and that is exactly what lets a node with ZERO local members of a
         * channel keep it -- and therefore keep relaying it, which is 3.1's
         * amended `message` row and 7/Phase 6's fifth acceptance criterion. A
         * burst that recorded members and no origin would install a roster and
         * then let the channel be freed the first time anything emptied it, and
         * the relay test would pass for the wrong reason until a later teardown
         * removed it. */
        (void)chan_server_add(ch, origin);
        if (chan_same_name(sc->origin, origin)) {
            /* The topic and the modes are the ORIGIN's authority and nothing
             * else's, which is 2.2's single-writer rule read from the other side:
             * on a mesh of three, node A reports channels it does not own, and
             * its copy of their topic is a cache exactly as it is for a relayed
             * STOPIC. Taking it from a line that merely passed through would make
             * every relay an authority. */
            apply_topic(ch, sc);
            replace_modes(ch, sc->modes);
        }
        for (size_t k = 0; k < sc->nmembers; k++) {
            const char *host;

            if (member_known(ch, sc->members[k].nick) != 0) {
                continue;
            }
            if (chan_remote_add(ch, origin, sc->members[k].nick,
                                sc->members[k].flags) != 0) {
                dropped++;
                continue;
            }
            host = shadow_host(sc->members[k].nick);
            if (host != NULL) {
                (void)chan_remote_set_host(ch, origin, sc->members[k].nick, host);
            }
            installed++;
        }
    }

    /* --- and the channels this origin no longer has ------------------------ */
    /* THE OTHER HALF OF REPLACE, and the half a per-channel purge cannot reach.
     * A channel the origin reported in its last burst and not in this one is a
     * channel the origin has given up, and this node's knowledge of what THAT
     * ORIGIN holds for it is stale. Only channels whose OWN origin is the burst
     * origin are touched: a channel this node created locally, or one owned by a
     * third server, is a different origin's state and a burst about someone else
     * is not evidence about it. */
    for (size_t i = 0; i < server_chan_count(s); i++) {
        chan_t *ch = server_chan_at(s, i);
        int named = 0;

        if (ch == NULL || !chan_same_name(ch->origin, origin)) {
            continue;
        }
        for (size_t k = 0; k < g_shadow.nchan_used; k++) {
            if (strcmp(g_shadow.chans[k].name, ch->name) == 0) {
                named = 1;
                break;
            }
        }
        if (named != 0) {
            continue;
        }
        purged += chan_remote_purge(ch, origin);
        (void)chan_server_remove(ch, origin);
        (void)chan_dispose_if_empty(s, ch);
    }

    link->burst_done = 1;
    printf("[observable] fed_burst_applied: peer=%s epoch=%llu nicks=%zu chans=%zu "
           "members=%zu installed=%zu purged=%zu dropped=%zu bytes=%zu\n",
           origin, (unsigned long long)g_shadow.epoch, g_shadow.nnicks,
           g_shadow.nchans, g_shadow.nmembers, installed, purged, dropped,
           g_shadow.bytes);
    shadow_release();
    return 0;
}

int fed_burst_apply(server_t *s, server_link_t *link, const message_t *m)
{
    if (s == NULL || link == NULL || m == NULL || m->command == NULL) {
        return -1;
    }
    /* THE FIVE ARMS, and none of them is reached for a transaction this node is
     * not already in: a record that arrives with nothing open is a peer out of
     * order with itself, and the alternative -- creating a shadow on a stray
     * SBURSTN -- would let a peer build this node's state without ever sending a
     * BEGIN. The count assertion cannot catch that, because a transaction that
     * never started has nothing whose counts could disagree. */
    if (strcmp(m->command, "SBURST") == 0) {
        return apply_begin(s, link, m);
    }
    if (strcmp(m->command, "SBURSTN") == 0) {
        if (g_shadow.open == 0) {
            s->n_fed_malformed++;
            printf("[observable] fed_malformed: fd=%d command=SBURSTN "
                   "reason=NO_TRANSACTION\n",
                   link->fd);
            return -1;
        }
        return apply_nick(s, link, m);
    }
    if (strcmp(m->command, "SBURSTC") == 0) {
        if (g_shadow.open == 0) {
            s->n_fed_malformed++;
            printf("[observable] fed_malformed: fd=%d command=SBURSTC "
                   "reason=NO_TRANSACTION\n",
                   link->fd);
            return -1;
        }
        return apply_chan(s, link, m);
    }
    if (strcmp(m->command, "SBURSTM") == 0) {
        if (g_shadow.open == 0) {
            s->n_fed_malformed++;
            printf("[observable] fed_malformed: fd=%d command=SBURSTM "
                   "reason=NO_TRANSACTION\n",
                   link->fd);
            return -1;
        }
        return apply_member(s, link, m);
    }
    if (strcmp(m->command, "SBURSTE") == 0) {
        return apply_end(s, link, m);
    }
    /* Unreachable: fed_burst_verb() is the only way here. It is a BUG REPORT
     * rather than a silent return, for the reason the guard chain's unreachable
     * arm gives: a table row with no arm is a verb this node advertises by
     * handling and does not do. */
    printf("[observable] fed_burst_unhandled: command=%s\n", m->command);
    return -1;
}
