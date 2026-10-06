/* burst.c -- see burst.h. The 4.3 resync: the wire format, the staged send, and
 * the transaction that replaces rather than merges. */
#include "federation/burst.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/channel.h"
#include "account_store.h"
#include "core/account.h"
#include "core/connection.h"
#include "federation/link.h"
/* Phase 9: the COMMIT installs this transaction's nick records into 2.1's
 * remote-nick registry, which is what the four fields Phase 6 kept on the wire
 * and discarded were for. See the comment at apply_end()'s registry loop. */
#include "federation/nickreg.h"
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
 * the shadow stores TWO of the six: the nick it keys the record by, and the
 * host. Only the host is interesting, and that is not a shortcut -- it is the
 * whole of what there is somewhere to put, and burst.h now says so at the point
 * a reader would actually look for it: `user`, `modes`, `signon` and `away` are
 * DISCARDED on purpose, because 2.1's "which server holds the user called X"
 * registry -- the thing they exist for -- is Phase 9's work and has no home on
 * server_t yet. They are on the wire anyway: 4.3 names them, and a format that
 * omitted them would have to be EXTENDED the moment that registry arrives, which
 * is exactly what 4.3's "a wire format cannot be invented later" is about. The
 * count of accepted nick records is what SBURSTE's first count is compared
 * against, and a counter does not need the records themselves to do that. */
typedef struct {
    char nick[IRC_MAX_NICK + 1];
    /* The four fields Phase 6 kept on the wire and DISCARDED, kept now because
     * 2.1's remote-nick registry arrived and they are what it stores. `user` and
     * `host` are what a rendered hostmask is made of; `signon` is 317's
     * <signon time> for a user this node has no conn_t for; `away` is 301's text.
     *
     * `away` is stored and NOT YET RENDERED, and the cost of that decision is
     * stated where it is made: it is 256 bytes on every shadow entry, so a
     * thousand-nick burst's shadow grows by 256 KiB to carry a field nothing reads
     * yet. It is kept because 4.3.1's argument for having it on the wire at all
     * was that a format which omitted it would have to be EXTENDED the moment the
     * registry arrived -- and the registry has now arrived, so a receiver that
     * threw it away would be the one that needed a format change. The renderer
     * that would use it is future work and the comment at fed_nickreg_render()
     * says so where a reader would otherwise assume the field is dead. */
    char user[64];
    char host[CHAN_MAX_REMOTE_HOST + 1];
    uint64_t signon;
    char away[CONN_MAX_AWAY + 1];
} burst_nick_t;

/* One member line. The flags word is the wire's: '-', "o", "v" or "ov". It is
 * NOT the SJOIN token, which carries a leading '+' -- see the header on why the
 * two differ.
 *
 * `server` is the field 4.3's SBURSTM gained before a second implementation
 * existed: the server that HOLDS the member, which is neither the burst origin
 * nor derivable from it. It is CHAN_MAX_SERVER rather than a written-out
 * IRC_MAX_SERVER_NAME because it is the same number (63) and this is where a
 * channel-h bound belongs; the header's arithmetic charges the field on the wire
 * at IRC_MAX_SERVER_NAME, which is the same 63. */
typedef struct {
    char     nick[IRC_MAX_NICK + 1];
    char     server[CHAN_MAX_SERVER + 1];
    /* The member's account, or "" when the origin did not say. See the header on
     * WHY THIS IS ON THE MEMBER RECORD AND NOT ON THE NICK RECORD, which is the
     * argument for 4.3's SJOIN and SBURSTM carrying the same fact in the same
     * place. */
    char     account[CONN_MAX_ACCOUNT + 1];
    unsigned flags;
} burst_member_t;

typedef struct {
    char            name[CHAN_MAX_NAME + 1];
    char            origin[CHAN_MAX_SERVER + 1];
    char            topic[CHAN_MAX_TOPIC + 1];
    char            topic_who[CHAN_MAX_TOPIC_WHO + 1];
    uint64_t        topic_when; /* the ORIGIN's clock, which is what 333 wants */
    char            modes[CHAN_MAX_MODES + 1];
    /* WHICH FIELDS OF THIS RECORD DID NOT FIT (#122), as a bitmask rather than a
     * boolean, because the three have different widths and a reader asking "what
     * did this node lose" needs to be told which one.
     *
     * IT IS NOT "the record was refused". The record is KEPT, counted in nchans,
     * and installed -- its roster is the origin's and a topic the receiver could
     * not store says nothing about who is on the channel. What is withheld is the
     * origin's PRESENTATION of the channel: the topic and the modes. See
     * apply_chan() for why those two travel together, and apply_end() for what
     * does with this. */
    unsigned        refused;
    burst_member_t *members;
    size_t          nmembers;
    size_t          mcap;
} burst_chan_t;

/* The three fields of a SBURSTC this node may not be able to store, named as a
 * bitmask so the refusal is reported as a list rather than as "something". */
enum {
    BURST_CHAN_REFUSED_TOPIC     = 1u << 0,
    BURST_CHAN_REFUSED_TOPIC_WHO = 1u << 1,
    BURST_CHAN_REFUSED_MODES     = 1u << 2
};

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

/* An account name, or `*`, for the wire. `c` is the LOCAL member whose account is
 * wanted, and NULL means "use the roster entry's instead", which is the remote
 * half of the same question.
 *
 * IT IS A SEPARATE FUNCTION FROM federation/verbs.c's fed_account_token() and
 * that duplication is deliberate and small: verbs.c builds the account for a LIVE
 * SJOIN and has the membership in hand, while this builds it for a RESYNC from
 * either a local conn_t or a roster entry, and threading one of them into the other
 * would make burst.c depend on the S-verb shaper for a record that is not an
 * S-verb. The two agree because both call account_name()/account_logged_in() and
 * both render the empty case as `*` -- and the tests assert that, because two
 * renderers of one protocol token is precisely the thing to check. */
static const char *burst_account_token(const conn_t *c, const char *roster)
{
    if (c != NULL) {
        return (account_logged_in(c) != 0) ? c->account : "*";
    }
    return ((roster != NULL && roster[0] != '\0') ? roster : "*");
}

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

/* SBURSTM's <server> field for a REMOTE entry: where the member actually is.
 *
 * THE FALLBACK IS THE POINT, and it is not defensive padding. `member_server` is
 * empty for every entry this node learned from a LIVE SJOIN, because 4.3's SJOIN
 * carries no server field and the only answer available at the time was the
 * sending link's name -- which is what `server`, the attribution key, holds. So
 * on a two-node mesh, and for any member learned before this node has been
 * resynced, the key IS the holder and falling back to it is EXACT rather than an
 * approximation. The alternative -- sending "-" and having the receiver guess --
 * would put a guess on the wire where a correct answer was sitting in the struct
 * one field away.
 *
 * A local member does not come through here at all: it is held by this node, and
 * fed_burst_send() passes `s->name` for it directly, because a LOCAL member has
 * no conn_t on any peer and saying so from the roster would be a fiction.
 *
 * The `self` argument is the last-ditch guard and it is unreachable in practice:
 * an entry's key is validated on the way in by chan_remote_add(), so it is never
 * empty. It is here because an empty MIDDLE parameter is not representable at
 * all (3.2) and message_format() would REFUSE the whole line -- aborting every
 * burst this node ever sends -- over one malformed roster entry. */
static const char *burst_member_server(const chan_remote_t *r, const char *self)
{
    if (r->member_server[0] != '\0') {
        return r->member_server;
    }
    return (r->server[0] != '\0') ? r->server : self;
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
        /* SIX, not four: SBURSTC needs six and SBURSTM now needs five, and one
         * array sized for the smaller of two shapes would be the kind of
         * arithmetic that is right until it is not. */
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
            /* THIS NODE holds its own local members, so the <server> field is
             * this node's own name. It is not derivable from the prefix either --
             * both happen to be the burst origin here -- and writing it is what
             * makes the field mean the same thing to a receiver on the record it
             * is about. */
            params[1] = s->name;
            params[2] = ch->members[k].c->nick;
            params[3] = flags;
            /* AND <account>, WHICH IS 4.3's SJOIN's FOURTH PARAMETER AGAIN. The
             * two records MUST carry the same fact, or a resync would restore a
             * roster that disagrees with the live path about who a member is --
             * and the disagreement would only show up after a link drop, which is
             * the moment 2.2 says a stale roster is least acceptable. `*` for a
             * member who is not identified, which is the protocol's spelling of
             * the absence and the same value a live SJOIN would carry. */
            params[4] = burst_account_token(ch->members[k].c, NULL);
            if (stage_line(&st, s, s->name, "SBURSTM", params, 5) != 0) {
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
            params[1] = burst_member_server(r, s->name);
            params[2] = r->nick;
            params[3] = flags;
            params[4] = burst_account_token(NULL, r->account);
            if (stage_line(&st, s, s->name, "SBURSTM", params, 5) != 0) {
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
 * that. */
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

/* ---------------------------------------------------------------------------
 * THE TEARDOWN ARM
 * ---------------------------------------------------------------------------
 * The shadow is a MODULE GLOBAL, so it is the one allocation on a node whose
 * owner cannot be reached from server_shutdown() by freeing a field. This is the
 * arm, and its contract is the one in burst.h: release, count nothing, say
 * whether there was anything to release.
 *
 * WHY IT IS HERE NOW RATHER THAN NEVER, which is what C4 concluded and got
 * backwards. C4's reasoning was that the arm is unverifiable on this platform --
 * LeakSanitizer does not run on Darwin (see the hygiene note in 7/Phase 1) -- and
 * an unverifiable arm is a worse thing to add a symbol for than a bounded
 * residual. That reasoning inverts the rule: an arm that is unverifiable LOCALLY
 * is precisely the arm worth adding, because LSan *does* run on the CachyOS Linux
 * CI runner, so this is the class of change the platform limitation makes hard
 * and the CI makes free. Leaving the shadow to the kernel meant a node that
 * stopped mid-transaction -- a SIGTERM while a peer is bursting -- leaked up to
 * IRC_BURST_MAX_BYTES, and the only evidence was a build nobody ran locally.
 *
 * The `[observable]` line is what makes the arm testable where LSan is not: it
 * reports whether a shadow was OPEN at teardown, so a test can assert the arm ran
 * on Darwin and Linux CI can assert the same fact alongside the leak check. It
 * prints the counts rather than just a boolean because a reader looking at the
 * last line a node printed wants to know what it was holding.
 *
 * Safe on a node that never called fed_open(): g_shadow is a file-scope static,
 * so it is already zero and shadow_release() on it frees two NULL pointers. */
void fed_burst_close(server_t *s)
{
    int open = g_shadow.open;

    /* The node is not touched today and the parameter is not dropped. The shadow
     * is a module global, but a teardown that may one day need to walk the node
     * should not have its signature changed underneath the caller, and every
     * other teardown in this tree takes the node it is tearing down. */
    (void)s;
    printf("[observable] fed_burst_close: shadow=%s origin=%s nicks=%zu chans=%zu "
           "members=%zu bytes=%zu\n",
           (open != 0) ? "OPEN" : "NONE", g_shadow.origin, g_shadow.nnicks,
           g_shadow.nchans, g_shadow.nmembers, g_shadow.bytes);
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
        /* MEASURED, AND THE REASON IS THE `nparams > 0` GUARD (#135). The nickname
         * in the log line is `m->params[0]` precisely when the shape check FAILED,
         * which is to say exactly when `valid_nick()` above has not run on it -- so
         * this is the one place in this file where a peer string is printed without
         * having been validated, and it is reachable with a single parameter whose
         * value no predicate has touched. `fed_obs()` renders it, and the length
         * and the bad-byte count beside it are what a reader needs in order to tell
         * "a peer sent a nickname with a control byte in it" from "a peer sent a
         * 400-byte nickname", which are different findings and look identical as a
         * `nick=-`. */
        {
            const char *raw = (m->nparams > 0) ? m->params[0] : "?";

            fed_obs("[observable] fed_malformed: fd=%d command=SBURSTN nick=%s "
                    "nick_len=%zu nick_bad_bytes=%zu\n",
                    link->fd, raw, strlen(raw), conn_text_bad_count(raw));
        }
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
    memset(slot, 0, sizeof *slot);
    (void)burst_copy(slot->nick, sizeof slot->nick, m->params[0]);
    /* A host longer than conn_t::host is TRUNCATED rather than refused, and that
     * is the one place in this file where a value is cut. The alternative -- a
     * refusal -- would abandon the whole transaction over a field the receiver
     * has one slot for, and the slot is the width this node would render the
     * hostmask at anyway. What is stored is what this node could have shown a
     * client, which is the honest bound on a cache.
     *
     * THE OTHER THREE FIELDS ARE COPIED NOW rather than discarded, which is the
     * deferral this struct's comment above described being paid: `user` and
     * `signon` are what fed_nickreg_learn() stores, and 4.3.1's argument for
     * their being on the wire at all was that a receiver which threw them away
     * would need the format EXTENDED the moment a registry wanted them. The
     * memory is charged at the top of this struct and the shadow is already
     * bounded by IRC_BURST_MAX_BYTES, so the cost is inside a budget that
     * exists. */
    (void)snprintf(slot->user, sizeof slot->user, "%s", m->params[1]);
    (void)snprintf(slot->host, sizeof slot->host, "%s", m->params[2]);
    (void)snprintf(slot->away, sizeof slot->away, "%s", m->params[5]);
    /* signon was already parsed and validated above -- the terminator's counts are
     * about records this node ACCEPTED, so a record whose numeric field is not a
     * number would make that a count of lines rather than of records -- so the
     * value is in hand and this is a copy rather than a second parse. A second
     * parse of the same field would be a second opinion about it, and this file
     * is explicit that the parse belongs with the shape check. */
    slot->signon = signon;
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
        /* The same argument as apply_nick()'s, for the same reason: this line
         * prints `m->params[0]` on the branch where `chan_name_valid()` has NOT
         * run, so the value is whatever the peer sent. Measured rather than
         * withheld, because a channel name is short enough to be worth reading and
         * a length plus a bad-byte count is what distinguishes a malformed channel
         * name from a channel name carrying a control byte. */
        {
            const char *raw = (m->nparams > 0) ? m->params[0] : "?";

            fed_obs("[observable] fed_malformed: fd=%d command=SBURSTC channel=%s "
                    "channel_len=%zu channel_bad_bytes=%zu\n",
                    link->fd, raw, strlen(raw), conn_text_bad_count(raw));
        }
        shadow_discard(s, "BAD_CHAN_RECORD", g_shadow.origin, g_shadow.nnicks,
                       g_shadow.nchans, g_shadow.nmembers);
        return -1;
    }
    if (shadow_charge(s, "TOO_LARGE",
                      wire_size(link->name, "SBURSTC", m->params, 6)) != 0) {
        return -1;
    }
    /* THE EXPLICIT CEILING (#122), and it is checked BEFORE the realloc rather
     * than after it so that the refusal costs no allocation. See
     * IRC_BURST_MAX_CHANS for why this is not the bound: the charge above already
     * caps the count at 642 at the shipped budget, and this arm exists so that
     * the day that arithmetic moves, the count this node will allocate for is a
     * number somebody wrote down rather than a quotient. */
    if (g_shadow.nchan_used >= IRC_BURST_MAX_CHANS) {
        s->n_fed_malformed++;
        shadow_discard(s, "TOO_MANY_CHANS", g_shadow.origin, g_shadow.nnicks,
                       g_shadow.nchans, g_shadow.nmembers);
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
    /* THE TWO FIELDS THAT CANNOT FAIL ARE NOT `(void)`-ED (#122). Both are
     * validated above -- chan_name_valid() against the width chan_name_upper()
     * writes, irc_serve_server_name_valid() against the width burst_copy() is
     * given -- so a refusal here would mean one of those two predicates had
     * started accepting something the other rejects. That is a divergence between
     * two rules rather than a peer input, and it is reported here for the reason
     * account_store.c's note about this same helper gives: a discarded result on a
     * copy whose source is already validated is a way for the field to keep
     * whatever the realloc left in it, with nothing on the wire or in the log to
     * say so. */
    if (!burst_copy(sc->name, sizeof sc->name, canonical) ||
        !burst_copy(sc->origin, sizeof sc->origin, m->params[1])) {
        shadow_discard(s, "BAD_CHAN_RECORD", g_shadow.origin, g_shadow.nnicks,
                       g_shadow.nchans, g_shadow.nmembers);
        return -1;
    }
    /* ------------------------------------------------------------------------
     * THE THREE FIELDS THAT CAN, AND NOW THAT THE RESULT IS READ (#122).
     *
     * REFUSE THE FIELD, KEEP THE RECORD. The two alternatives were both wrong and
     * it is worth saying why, because the choice is the whole of this fix:
     *
     *   TRUNCATE. Excluded by this tree's own rule for this exact field.
     *   chan_set_topic() refuses rather than truncates, and the reason it gives is
     *   that "a topic cut mid-word is a different topic, and a client would have
     *   no way to tell" -- with 331/332/333 named as where it shows. A truncated
     *   topic in the shadow would be stored, and send_topic() hands ch->topic to
     *   every member on the next 332 and 333, so the cut sentence would be shown
     *   to the channel and replayed to every member who joined afterwards. That is
     *   the failure the existing refusal exists to prevent, and 3.2's "never
     *   deliver a silently shortened parameter" is the rule it cites.
     *
     *   REFUSE THE RECORD. Excluded on blast radius, and this is the part that is
     *   not obvious. A record refusal here is not a local drop: the terminator
     *   asserts nchans, so refusing the record without counting it makes the
     *   COMMIT mismatch, which discards the WHOLE transaction. One over-long topic
     *   on one channel out of five hundred would then leave this node stale about
     *   four hundred and ninety-nine healthy channels -- trading a cosmetic loss
     *   that is visible on one numeric for a total loss that is visible only as
     *   fed_burst_truncated. The header's "there is no partial burst" rule is
     *   about not losing records WITHOUT SAYING SO, and a counted refusal says so.
     *
     * So the record installs: the roster is the origin's and is unaffected by a
     * topic this node could not store, and the transaction commits with the
     * channel counted. What is withheld is the topic AND the modes, together,
     * because replace_modes() clears through the old value before setting the new
     * one -- handing it the zeroed field a refusal leaves behind would strip the
     * channel of every mode letter it has on the strength of a record whose modes
     * this node refused to store. apply_end() reads this mask, and the loss is
     * counted in dropped= and named on the wire.
     *
     * THE MASK, NOT A BOOLEAN, because the three widths are different and a reader
     * asking what was lost needs the answer to name it. The `[observable]` line
     * below prints the three as separate numbers rather than the mask for the
     * same reason: a mask on the wire is a number only this file can decode. */
    if (!burst_copy(sc->topic, sizeof sc->topic, m->params[5])) {
        sc->refused |= BURST_CHAN_REFUSED_TOPIC;
    }
    if (!burst_copy(sc->topic_who, sizeof sc->topic_who,
                    ((m->params[2][0] == '-') ? "" : m->params[2]))) {
        sc->refused |= BURST_CHAN_REFUSED_TOPIC_WHO;
    }
    if (!burst_copy(sc->modes, sizeof sc->modes,
                    ((m->params[4][0] == '-') ? "" : m->params[4]))) {
        sc->refused |= BURST_CHAN_REFUSED_MODES;
    }
    if (sc->refused != 0u) {
        /* THE MASK AS THREE NUMBERS RATHER THAN ONE, and the reason is that a
         * reader of a log is not reading this file: `refused=3` needs a decoder and
         * `refused_topic=1` does not. The three INDEPENDENT lengths are printed
         * beside them because the interesting fact is not only that a field was
         * too wide but HOW wide, and a peer sending a 300-byte topic on a node
         * with a 255-byte cache is a peer whose sender does not check its own
         * bound -- which is a thing an operator can act on and a bare flag is
         * not. */
        printf("[observable] fed_burst_chan_refused: fd=%d channel=%s "
               "refused_topic=%d refused_topic_who=%d refused_modes=%d "
               "topic_len=%zu topic_who_len=%zu modes_len=%zu "
               "reason=FIELD_TOO_WIDE\n",
               link->fd, sc->name,
               (sc->refused & BURST_CHAN_REFUSED_TOPIC) != 0u ? 1 : 0,
               (sc->refused & BURST_CHAN_REFUSED_TOPIC_WHO) != 0u ? 1 : 0,
               (sc->refused & BURST_CHAN_REFUSED_MODES) != 0u ? 1 : 0,
               strlen(m->params[5]), strlen(m->params[2]), strlen(m->params[4]));
    }
    sc->topic_when = when;
    g_shadow.cur = sc;
    g_shadow.nchans++;
    return 0;
}

/* SBURSTM <chan> <server> <nick> <flags>: one member of the PRECEDING channel.
 *
 * THE <server> FIELD IS VALIDATED, and it is validated here rather than being
 * copied in blind for the reason the other two fields are: it is 2.4's server-name
 * grammar, it arrives from a network, and a roster entry carrying a string the
 * node cannot compare case-insensitively or render is a member this node cannot
 * reason about. It is a MIDDLE parameter and therefore not representable empty
 * (3.2), so a peer has no way to send "I do not know" -- the wire says a burst
 * always knows, and this node holds it to that.
 *
 * IT IS ALSO NOT USED FOR THE KEY, and that is the load-bearing part. The key
 * stays the BURST ORIGIN, because that is what 4.3's replace-never-merge
 * replaces AGAINST: a resync has to be able to name exactly the entries the
 * previous resync from the same origin installed, and that set is "everything
 * keyed by the origin that is now re-reporting". Keying by the member's own
 * server would make a relay's resync unable to replace what the relay installed,
 * and a member the origin dropped would linger. See channel.h's chan_remote_t.
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

    /* FIVE PARAMETERS NOW: <chan> <server> <nick> <flags> <account>. The arity is
     * the FORMAT's and is enforced here rather than defaulted, for the reason the
     * 4.3.1 `<server>` paragraph gives: a member record that is missing a field is
     * a peer running a different format, and the safe direction is to refuse it
     * rather than install a member whose account this node cannot tell.
     *
     * `<account>` GOES THROUGH account_name_wire_safe(), and that is the SECOND
     * bound on it: the predicate refuses a name wider than the field it is about
     * to be copied into, so the burst_copy() of it below cannot fail. That is the
     * half of the rule that makes this function's own slot well-defined -- with
     * only a byte check here, a value too long for the field reached a copy whose
     * result is discarded, and the field kept whatever the realloc left in it. */
    if (sc == NULL || m->nparams != 5 || !irc_serve_server_name_valid(m->params[1]) ||
        !valid_nick(m->params[2]) || !chan_name_valid(m->params[0]) ||
        (m->params[4][0] != '*' && account_name_wire_safe(m->params[4]) == 0)) {
        s->n_fed_malformed++;
        /* THIRD MEMBER SITE, THIRD INSTANCE OF THE SAME ARGUMENT: `m->params[2]`
         * is the nickname and this line is on the branch where `valid_nick()` has
         * not run. Three sites in one file printing the same unvalidated field on
         * three different guards is what makes a sweep of the file worth having
         * rather than a fix of whichever one a reader happened to look at. */
        {
            const char *raw = (m->nparams > 2) ? m->params[2] : "?";

            fed_obs("[observable] fed_malformed: fd=%d command=SBURSTM member=%s "
                    "member_len=%zu member_bad_bytes=%zu\n",
                    link->fd, raw, strlen(raw), conn_text_bad_count(raw));
        }
        shadow_discard(s, "BAD_MEMBER_RECORD", g_shadow.origin, g_shadow.nnicks,
                       g_shadow.nchans, g_shadow.nmembers);
        return -1;
    }
    {
        char canonical[CHAN_MAX_NAME + 1];

        (void)chan_name_upper(canonical, sizeof canonical, m->params[0]);
        if (strcmp(canonical, sc->name) != 0) {
            s->n_fed_malformed++;
            /* FILTERED EVEN THOUGH `valid_nick()` HAS ALREADY RUN on params[2],
             * and the reason is the sweep rather than the value (#135). This arm
             * sits BELOW the shape check, so the nickname here really has been
             * through `valid_nick()` and a control byte cannot be in it -- which is
             * exactly the reasoning that let the three arms ABOVE this one keep
             * printing raw, and it was wrong there: the reason they were wrong is
             * that they are not below the check. Once the sweep states the rule as
             * "no `m->params[...]` in a `%s` argument anywhere in the peer path",
             * the honest way to satisfy it here is to filter rather than to argue,
             * because the argument a future reader has to re-derive ("is this arm
             * really below the check?") is exactly the class of reasoning that
             * produced the defect. One pass over at most IRC_MAX_NICK bytes on a
             * malformed-record path. */
            fed_obs("[observable] fed_malformed: fd=%d command=SBURSTM member=%s "
                    "member_len=%zu member_bad_bytes=%zu reason=CHANNEL_MISMATCH\n",
                    link->fd, m->params[2], strlen(m->params[2]),
                    conn_text_bad_count(m->params[2]));
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
    if (strcmp(m->params[3], "-") != 0) {
        if (m->params[3][0] == '\0') {
            s->n_fed_malformed++;
            shadow_discard(s, "BAD_FLAGS", g_shadow.origin, g_shadow.nnicks,
                           g_shadow.nchans, g_shadow.nmembers);
            return -1;
        }
        for (size_t i = 0; m->params[3][i] != '\0'; i++) {
            if (m->params[3][i] == 'o' && (flags & CHAN_MEMBER_OP) == 0u) {
                flags |= CHAN_MEMBER_OP;
            } else if (m->params[3][i] == 'v' &&
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
                      wire_size(link->name, "SBURSTM", m->params, 5)) != 0) {
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
    /* THE SLOT IS ZEROED BEFORE IT IS WRITTEN, and this is the third of the three
     * record functions in this file that does it -- apply_nick() memsets, and
     * apply_chan() zeroes the region it grows into. It is here because
     * realloc() does not, and because the three burst_copy() calls below are all
     * `(void)`: <nick> and <server> are bounded by their own validators, so those
     * two always land, but the pattern of "a copy whose failure is discarded
     * writes into a field nothing has initialised" is exactly the one that turns a
     * refusal into an uninitialised READ rather than into an absent value.
     *
     * The two siblings say the same thing in their own words at their own lines:
     * a RECYCLED element carrying the previous member's field is impersonation
     * wearing a memory bug's clothes. `account` is the field that can be left
     * unwritten, and channel.c's chan_remote_add() is where a garbage value read
     * out of here becomes a roster entry. */
    slot = &sc->members[sc->nmembers++];
    memset(slot, 0, sizeof *slot);
    (void)burst_copy(slot->nick, sizeof slot->nick, m->params[2]);
    (void)burst_copy(slot->server, sizeof slot->server, m->params[1]);
    /* `*` BECOMES "" on the way in, for the reason channel.h's chan_remote_add()
     * gives: `*` is a rendering of the absence, and storing it would make an
     * account named "*" representable in a roster. */
    (void)burst_copy(slot->account, sizeof slot->account,
                     (m->params[4][0] == '*') ? "" : m->params[4]);
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

/* The IDENT a burst's nick record announced, or NULL on the same rule
 * shadow_host() has.
 *
 * IT IS A SECOND WALK RATHER THAN A THIRD FIELD RETURNED BY THE FIRST, and the
 * reason is that the two answers are asked separately and may be asked in either
 * order relative to each other -- `apply_nick()` fills the shadow before the
 * member loop runs, but nothing in this file promises that a future caller will
 * keep that order, and a function that returned both would be wrong the moment one
 * of them was wanted without the other. The walk is O(n) over the nicks a burst
 * announced, once per member of the burst, and a burst is a resync rather than a
 * hot path; the honest cost is O(n*m) on a large burst and it is paid once.
 *
 * WHY IT EXISTS AT ALL: 4.3's SBURSTN carries `<user>`, the shadow below has
 * stored it since Phase 6, and this file copied only the HOST out of it. Half a
 * hostmask was being discarded, which cost nothing until Phase 10.5's
 * `userhost-in-names` needed to draw `nick!user@host` for a member this node does
 * not host -- a remote member has no conn_t to read the pair from. */
static const char *shadow_ident(const char *nick)
{
    for (size_t i = 0; i < g_shadow.nnicks; i++) {
        if (chan_same_name(g_shadow.nicks[i].nick, nick)) {
            return g_shadow.nicks[i].user;
        }
    }
    return NULL;
}

/* Does this node already know a member by that name in this channel, as a LOCAL
 * member or in the remote roster?
 *
 * IT IS WHAT STOPS A BURST FROM ADDING A NICK TWICE, and the duplicate it
 * prevents is not theoretical. A channel's membership is per (nick, server), and
 * 4.3's SBURSTM does not carry the key -- the key is the BURST ORIGIN, because
 * that is the origin whose state the transaction replaces. The record's OWN
 * <server> field says where the member lives and is stored in
 * chan_remote_t::member_server, but it is deliberately NOT the key: keying by it
 * would make this burst unable to replace what the origin's PREVIOUS burst
 * installed, and a member the origin has dropped would linger for ever.
 *
 * So the duplicate the rule prevents is a node that already knows a NAME, under
 * any key: installing it again would give the channel two entries for one person,
 * and 353 renders one line per member, so the client would be shown the same
 * nickname twice with nothing on the node able to explain it. That is exact on
 * the two-node mesh this phase's acceptance criteria are about, and it is a
 * heuristic on a larger one, where a relay reporting a member of a third node
 * will find that node's own report of the same person already present and leave
 * the existing attribution alone -- the same cost 2.1 already names for duplicate
 * nicks across servers, and the same deferral: Phase 9's rename-the-loser is what
 * resolves it.
 *
 * The rule is checked in BOTH directions -- a local member counts -- so the common
 * two-node case, where the origin reports a member this node itself hosts, does
 * not become a self-membership. */
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
 * the code. It is the code now.
 *
 * THE `too_long` ARM BELOW CANNOT BE REACHED FROM THE BURST PATH, and the reason
 * is worth recording because it is not the one it looks like (#122). It is not
 * that a refused copy left the field empty -- that WAS true until apply_chan()
 * started reading burst_copy()'s result, and it is why this function's arm was
 * thought to be the reporting point for a field the receiver could not store. It
 * is that `sc->topic` is char[CHAN_MAX_TOPIC + 1] and burst_copy() enforces
 * strlen(src) < sizeof dst, so the value handed to chan_set_topic() can never
 * exceed what chan_set_topic() accepts. The shadow field and the setter's bound
 * are the same width BY CONSTRUCTION, which is the right relationship for a cache
 * and is also what makes the refusal invisible here: there is nothing for this
 * function to catch, because the node never holds an over-long topic -- it holds
 * either the origin's topic or no record of one at all.
 *
 * So the refusal is reported where it is detected, in apply_chan(), and the arm
 * stays because chan_set_topic() is not this file's to change: if that width ever
 * diverged from CHAN_MAX_TOPIC this is where it would show, and an arm that
 * cannot fire is cheaper than a behaviour with no reporting at all. */
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
    /* WHEN THE TRANSACTION WAS COMMITTED, and it is read HERE rather than inside
     * the registry call because 4.3.1's rule is that a burst's effect is dated by
     * the moment it was COMMITTED and not by any stamp a record carried. A record
     * that arrived ten minutes ago and a transaction that committed a moment ago
     * are the same age to the receiver, and dating the registry entries by their
     * arrival would make one long burst look like a set of fresh reports and
     * defeat the TTL's job of measuring how long this node has believed them. */
    const uint64_t applied_ms = server_now_ms();

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
         * having more than one counter. That counter is documented as "arity or
         * field validation refused it", and every line of a transaction that
         * reaches here passed both -- what failed is the transaction, not a
         * line. It IS ALSO NOT COUNTED AS ITSELF, i.e. shadow_discard() below
         * increments n_burst_abandoned and this increments n_burst_truncated
         * separately: the one names WHICH RULE threw the transaction away, and
         * the other says the transaction was discarded AT ALL. Counting it twice
         * under two names whose meanings an operator has to keep apart would make
         * one event visible under two counter pairs, and the "one guard, one
         * event" property server.h states for the chain would stop being true.
         *
         * THE NEW COUNTER IS NOT OPTIONAL, and the thing it replaces is worth
         * naming: before it, a truncation was visible only as this log line. A
         * node whose peer is truncating bursts has a quietly stale view of that
         * peer, and a counter is the only thing that says so without a log
         * reader. Its whole cost is one uint64_t on server_t and one increment on
         * a branch that is already discarding. */
        s->n_burst_truncated++;
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

    /* --- the nick records, into 2.1's registry ---------------------------- */
    /* 2.1's "which server holds the user called X", and it is HERE rather than at
     * the record because of 4.3.1's replace-never-merge: a resync is a
     * statement about an origin, and a registry entry written per record would
     * accumulate the nicks of every PREVIOUS resync from the same origin with no
     * way to tell them from this one's. The purge below is therefore a purge of
     * the ORIGIN's entries as well as of its roster entries, and the two are the
     * same operation on different tables.
     *
     * THE SERVER IS THE BURST ORIGIN for every nick record, and that is right
     * rather than a shortcut: 4.3's SBURSTN is about the ORIGIN's own users
     * (its prefix names the origin, and the sender's enumeration is
     * server_nick_at() over its own connections), so the holder of a nick record
     * IS the origin. The member lines below are the ones that can name a third
     * server, which is why fed_nickreg_learn_member() exists separately and why
     * it can correct a record this pass already wrote. */
    fed_nickreg_purge_server(s, origin);
    for (size_t i = 0; i < g_shadow.nnicks; i++) {
        const burst_nick_t *n = &g_shadow.nicks[i];

        if (n->nick[0] == '\0') {
            continue;
        }
        fed_nickreg_learn(s, n->nick, origin, n->user, n->host, n->signon,
                          applied_ms);
        /* 2.1's POLICY, PER RECORD, and the reason this loop is the third call
         * site of fed_nickreg_resolve_local(): a burst is how a node learns what
         * a peer holds, and a user who registered a name this node had never
         * heard of is a duplicate that only this loop can discover. The resolve
         * is inside the loop rather than after it because a rename changes the
         * node's LOCAL registry, and doing them all at the end would let a nick
         * be claimed by a rename and then re-learned from a record the burst had
         * already passed. */
        (void)fed_nickreg_resolve_local(s, n->nick, applied_ms);
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
            /* THE ORIGIN'S PRESENTATION FIELDS, AND WHEN THEY ARE WITHHELD (#122).
             *
             * The topic and the modes are the ORIGIN's authority and nothing
             * else's, which is 2.2's single-writer rule read from the other side:
             * on a mesh of three, node A reports channels it does not own, and its
             * copy of their topic is a cache exactly as it is for a relayed
             * STOPIC. Taking it from a line that merely passed through would make
             * every relay an authority.
             *
             * AND THEY ARE SKIPPED TOGETHER WHEN THE RECORD DECLARED EITHER ONE
             * UNSTORABLE, which is the other half of apply_chan()'s argument and
             * the reason the mask covers both. Two separate reasons, one rule:
             *   - the topic is refused, so there is nothing truthful to set. Left
             *     alone, this node keeps the topic it already had, which is a
             *     cache of the origin's last statement rather than a new one --
             *     the honest answer to a record this node could not read.
             *   - apply_topic() with the zeroed field a refusal leaves behind would
             *     CLEAR the topic, and replace_modes() with the zeroed modes would
             *     CLEAR every mode letter. A record whose topic this node could not
             *     store would strip the channel of its presentation, which is a
             *     worse and less honest outcome than not updating it.
             *
             * The roster below still installs either way: it is the origin's, and a
             * topic the receiver could not keep says nothing about who is on the
             * channel. `dropped` counts the record so the loss is in the number an
             * operator reads rather than only in the log line above. */
            if (sc->refused == 0u) {
                apply_topic(ch, sc);
                replace_modes(ch, sc->modes);
            } else {
                dropped++;
                /* THE WITHHELD LINE, AND THE TWO LENGTHS ARE THE NUMBERS THAT
                 * MATTER. Nothing else in this file reports what the channel's
                 * topic or modes ended up as after a burst, which is why a defect
                 * that CLEARED either of them, or cut the topic to CHAN_MAX_TOPIC,
                 * was invisible: the record still applied, the counts still
                 * matched, and the only symptom was a client asking 332 for a topic
                 * it had already been shown. So the report names what the node is
                 * LEFT holding -- 31 if it kept the topic it had, 0 if something
                 * cleared it, 255 if something truncated the peer's -- which is the
                 * difference between the three outcomes and the only thing an
                 * operator reading this log can act on.
                 *
                 * THE MODES ARE REPORTED FOR THE SAME REASON AND BECAUSE OF THE RULE
                 * ABOVE: `kept_modes_len` is 0 on a channel that had no modes even
                 * when the record's <modes> FIT, because a fitting field is withheld
                 * when a different field was refused. That is the half of the rule
                 * with no other evidence, and it is the half worth making visible --
                 * a node that applied the modes of a record whose topic it could not
                 * read would be reporting half a channel from half a record. */
                printf("[observable] fed_burst_chan_withheld: channel=%s "
                       "kept_topic_len=%zu kept_modes_len=%zu refused_topic=%d "
                       "refused_topic_who=%d refused_modes=%d reason=FIELD_TOO_WIDE\n",
                       ch->name, strlen(ch->topic), strlen(ch->modes),
                       (sc->refused & BURST_CHAN_REFUSED_TOPIC) != 0u ? 1 : 0,
                       (sc->refused & BURST_CHAN_REFUSED_TOPIC_WHO) != 0u ? 1 : 0,
                       (sc->refused & BURST_CHAN_REFUSED_MODES) != 0u ? 1 : 0);
            }
        }

        for (size_t k = 0; k < sc->nmembers; k++) {
            const char *host;

            if (member_known(ch, sc->members[k].nick) != 0) {
                continue;
            }
            if (chan_remote_add(ch, origin, sc->members[k].server,
                                sc->members[k].nick, sc->members[k].account,
                                sc->members[k].flags) != 0) {
                dropped++;
                continue;
            }
            /* THE MEMBER'S HOLDER, into 2.1's registry. This is the one place a
             * nick can be attributed to a server that is NOT the burst origin --
             * 4.3.1's SBURSTM <server> field exists for exactly that -- and it is
             * the correction to the entry apply_nick's loop wrote above, which
             * attributed every nick record to the origin because that is what a
             * nick record is about. A member living on a third node is reachable
             * through THAT node, and a registry that answered `bob@<origin>` for
             * it would forward the message to a server that does not hold bob. */
            fed_nickreg_learn_member(s, sc->members[k].nick, origin,
                                     sc->members[k].server, applied_ms);
            host = shadow_host(sc->members[k].nick);
            if (host != NULL) {
                (void)chan_remote_set_host(ch, origin, sc->members[k].nick, host);
            }
            /* AND THE IDENT, from the same shadow record and by the same lookup,
             * for the reason shadow_ident() gives. It is set SEPARATELY rather than
             * as a second half of the host setter because the two have different
             * failure modes on the wire -- 4.3's SJOIN carries neither, and a burst
             * may announce a member line for a nick whose nick record arrived in a
             * different order or not at all -- so one of them being absent must not
             * cost the other. */
            {
                const char *ident = shadow_ident(sc->members[k].nick);

                if (ident != NULL) {
                    (void)chan_remote_set_user(ch, origin, sc->members[k].nick,
                                               ident);
                }
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
    /* `m->command` OFF THE WIRE, ON A BRANCH THE COMMENT ABOVE CALLS UNREACHABLE
     * (#135), and both halves of that are why it is filtered rather than printed.
     * The unreachability is real -- `fed_burst_verb()` is the only caller and it
     * tests this same string against the table -- and it is exactly the situation
     * #134 was filed about: a branch nobody can reach is a branch nobody reviews
     * with the change that would make it reachable, and the value is a peer string
     * that reached this point without a predicate. A filter here costs one pass on
     * a path that does not execute, which is the cheapest possible insurance, and
     * the alternative -- leaving a bare `%s` on a peer string in a file with
     * twenty-seven other log lines -- is the state #135 is filed about. */
    fed_obs("[observable] fed_burst_unhandled: command=%s\n", m->command);
    return -1;
}
